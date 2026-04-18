"""HTTP request parsing and response helpers for the proxy server.

Contributor: Adam - request parser, header rewriting, and error responses.
External code: none; standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


CRLF = "\r\n"
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


@dataclass
class HTTPRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes
    host: str
    port: int
    path: str
    scheme: str
    display_url: str

    @property
    def is_connect(self) -> bool:
        return self.method.upper() == "CONNECT"

    def header(self, name: str, default: str = "") -> str:
        expected = name.lower()
        for header_name, value in self.headers:
            if header_name.lower() == expected:
                return value
        return default


class BadRequest(ValueError):
    """Raised when a client sends malformed HTTP request data."""


def parse_http_request(raw_header: bytes, body: bytes) -> HTTPRequest:
    """Parse the request line and headers received from a proxy client."""

    try:
        text = raw_header.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise BadRequest("request headers are not valid ISO-8859-1") from exc

    lines = text.split(CRLF)
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) != 3:
        raise BadRequest("request line must contain method, target, and version")

    method, target, version = parts
    if not version.startswith("HTTP/"):
        raise BadRequest("unsupported request version")

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise BadRequest(f"malformed header: {line}")
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))

    method_upper = method.upper()
    if method_upper == "CONNECT":
        host, port = _parse_host_port(target, default_port=443)
        return HTTPRequest(
            method=method_upper,
            target=target,
            version=version,
            headers=headers,
            body=body,
            host=host,
            port=port,
            path="",
            scheme="https",
            display_url=f"https://{host}:{port}",
        )

    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc:
        scheme = parsed.scheme.lower()
        default_port = 443 if scheme == "https" else 80
        host, port = _parse_host_port(parsed.netloc, default_port=default_port)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    else:
        scheme = "http"
        host_header = _header_value(headers, "Host")
        if not host_header:
            raise BadRequest("HTTP requests must include Host header")
        host, port = _parse_host_port(host_header, default_port=80)
        path = target or "/"

    display_url = f"{scheme}://{host}:{port}{path}"
    return HTTPRequest(
        method=method_upper,
        target=target,
        version=version,
        headers=headers,
        body=body,
        host=host,
        port=port,
        path=path,
        scheme=scheme,
        display_url=display_url,
    )


def build_forward_request(request: HTTPRequest) -> bytes:
    """Rewrite proxy-style absolute requests into origin-server requests."""

    host_header = request.host if request.port in (80, 443) else f"{request.host}:{request.port}"
    rewritten: list[tuple[str, str]] = []
    wrote_host = False
    for name, value in request.headers:
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS:
            continue
        if lower_name == "host":
            if not wrote_host:
                rewritten.append(("Host", host_header))
                wrote_host = True
            continue
        rewritten.append((name, value))

    if not wrote_host:
        rewritten.append(("Host", host_header))
    rewritten.append(("Connection", "close"))

    lines = [f"{request.method} {request.path or '/'} {request.version}"]
    lines.extend(f"{name}: {value}" for name, value in rewritten)
    header_bytes = (CRLF.join(lines) + CRLF + CRLF).encode("iso-8859-1")
    return header_bytes + request.body


def build_simple_response(status_code: int, reason: str, body: str, content_type: str = "text/plain") -> bytes:
    body_bytes = body.encode("utf-8")
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        f"Content-Length: {len(body_bytes)}",
        f"Content-Type: {content_type}; charset=utf-8",
        "Connection: close",
    ]
    return (CRLF.join(headers) + CRLF + CRLF).encode("iso-8859-1") + body_bytes


def parse_status_code(response: bytes) -> int:
    first_line = response.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    parts = first_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0


def _header_value(headers: list[tuple[str, str]], name: str) -> str:
    expected = name.lower()
    for header_name, value in headers:
        if header_name.lower() == expected:
            return value
    return ""


def _parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    value = value.strip()
    if not value:
        raise BadRequest("missing target host")
    if value.startswith("[") and "]" in value:
        host = value[1 : value.index("]")]
        remainder = value[value.index("]") + 1 :]
        if remainder.startswith(":"):
            return host, int(remainder[1:])
        return host, default_port
    if ":" in value and value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if not port_text.isdigit():
            raise BadRequest(f"invalid port: {port_text}")
        return host, int(port_text)
    return value, default_port
