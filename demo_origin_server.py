"""Small local origin server and browser demo tool for proxy tests.

Contributor: Adam - demo endpoints and UI for forwarding, caching, and POST testing.
External code: none; standard library only.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counters: dict[str, int] = {}
    proxy_host = "127.0.0.1"
    proxy_port = 8888
    mitm_ca_path = Path("data/mitm/ca.cert.pem")
    mitm_target_host = "example.com"
    mitm_target_path = "/"

    def handle(self) -> None:
        """Ignore browser connection resets so the demo log stays readable."""

        try:
            super().handle()
        except ConnectionResetError:
            return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            self._send_html(self._render_home())
            return
        if path == "/favicon.ico":
            self._send_empty("image/x-icon")
            return
        if path == "/api/proxy-test":
            self._handle_proxy_test(parse_qs(parsed.query))
            return
        if path == "/api/mitm-test":
            self._handle_mitm_test(parse_qs(parsed.query))
            return

        self.counters[path] = self.counters.get(path, 0) + 1
        count = self.counters[path]
        if path == "/cache":
            self._send_text(200, f"cacheable response count={count}\n", {"Cache-Control": "max-age=120"})
        elif path == "/nocache":
            self._send_text(200, f"non-cacheable response count={count}\n", {"Cache-Control": "no-store"})
        else:
            self._send_text(
                200,
                (
                    "CSC 430 demo origin server\n"
                    "Open / in the browser for the demo UI.\n"
                    "Try /cache twice through the proxy to see caching.\n"
                    "Try /nocache twice through the proxy to see no-store behavior.\n"
                ),
                {"Cache-Control": "max-age=60"},
            )

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/proxy-test":
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            self._handle_proxy_test(parse_qs(body))
            return
        if parsed.path == "/api/mitm-test":
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            self._handle_mitm_test(parse_qs(body))
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._send_bytes(200, b"echo body: " + body + b"\n", {"Cache-Control": "no-store"})

    def _handle_proxy_test(self, query: dict[str, list[str]]) -> None:
        target_path = query.get("path", ["/cache"])[0] or "/cache"
        if not target_path.startswith("/"):
            target_path = "/" + target_path
        repeat = self._safe_int(query.get("repeat", ["1"])[0], default=1, minimum=1, maximum=5)
        method = query.get("method", ["GET"])[0].upper()
        if method not in {"GET", "POST"}:
            method = "GET"
        body = query.get("body", ["network-demo"])[0].encode("utf-8")

        results = []
        for _ in range(repeat):
            results.append(self._request_through_proxy(method, target_path, body if method == "POST" else b""))
        self._send_json({"results": results})

    def _handle_mitm_test(self, query: dict[str, list[str]]) -> None:
        target_host = query.get("host", [self.mitm_target_host])[0] or self.mitm_target_host
        target_path = query.get("path", [self.mitm_target_path])[0] or self.mitm_target_path
        if not target_path.startswith("/"):
            target_path = "/" + target_path
        result = self._request_https_through_mitm(target_host, 443, target_path)
        self._send_json({"results": [result]})

    def _request_through_proxy(self, method: str, target_path: str, body: bytes) -> dict[str, Any]:
        origin_host, origin_port = self.server.server_address
        target_url = f"http://{origin_host}:{origin_port}{target_path}"
        command = f"curl.exe -x http://{self.proxy_host}:{self.proxy_port} {target_url}"
        if method == "POST":
            command += f" -d {body.decode('utf-8', errors='replace')!r}"

        request_lines = [
            f"{method} {target_url} HTTP/1.1",
            f"Host: {origin_host}:{origin_port}",
            "User-Agent: CSC430-demo-ui",
            "Connection: close",
        ]
        if method == "POST":
            request_lines.extend(
                [
                    "Content-Type: text/plain; charset=utf-8",
                    f"Content-Length: {len(body)}",
                ]
            )
        request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("iso-8859-1") + body

        try:
            with socket.create_connection((self.proxy_host, self.proxy_port), timeout=8) as proxy:
                proxy.sendall(request)
                raw = self._recv_all(proxy)
        except OSError as exc:
            return {
                "command": command,
                "ok": False,
                "status_line": "",
                "body": "",
                "bytes": 0,
                "error": str(exc),
            }

        header, _, response_body = raw.partition(b"\r\n\r\n")
        status_line = header.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
        display_body = self._decode_http_body(header, response_body)
        return {
            "command": command,
            "ok": status_line.startswith("HTTP/1.1 200") or status_line.startswith("HTTP/1.0 200"),
            "status_line": status_line,
            "body": display_body.decode("utf-8", errors="replace"),
            "bytes": len(raw),
            "error": "",
        }

    def _request_https_through_mitm(self, target_host: str, target_port: int, target_path: str) -> dict[str, Any]:
        target_url = f"https://{target_host}{target_path}"
        command = (
            f"curl.exe -x http://{self.proxy_host}:{self.proxy_port} "
            f"--cacert {self.mitm_ca_path} {target_url}"
        )
        if not self.mitm_ca_path.exists():
            return {
                "command": command,
                "ok": False,
                "status_line": "",
                "body": "",
                "bytes": 0,
                "error": (
                    f"MITM CA file not found at {self.mitm_ca_path}. "
                    "Restart the proxy with: python run_proxy.py --mitm"
                ),
                "mitm_detected": False,
                "certificate_issuer": "",
            }

        try:
            with socket.create_connection((self.proxy_host, self.proxy_port), timeout=10) as raw_proxy:
                raw_proxy.sendall(
                    (
                        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                        f"Host: {target_host}:{target_port}\r\n"
                        "User-Agent: CSC430-demo-ui\r\n\r\n"
                    ).encode("ascii")
                )
                connect_header = self._recv_until(raw_proxy, b"\r\n\r\n")
                if b"200 Connection Established" not in connect_header:
                    return {
                        "command": command,
                        "ok": False,
                        "status_line": connect_header.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace"),
                        "body": "",
                        "bytes": len(connect_header),
                        "error": "Proxy did not establish the HTTPS tunnel.",
                        "mitm_detected": False,
                        "certificate_issuer": "",
                    }

                context = ssl.create_default_context()
                context.load_verify_locations(cafile=str(self.mitm_ca_path))
                with context.wrap_socket(raw_proxy, server_hostname=target_host) as tls_proxy:
                    peer_cert = tls_proxy.getpeercert()
                    issuer_text = self._certificate_name_text(peer_cert.get("issuer", ()))
                    subject_text = self._certificate_name_text(peer_cert.get("subject", ()))
                    mitm_detected = "CSC 430 Proxy Local Root CA" in issuer_text
                    tls_proxy.sendall(
                        (
                            f"GET {target_path} HTTP/1.1\r\n"
                            f"Host: {target_host}\r\n"
                            "User-Agent: CSC430-demo-ui\r\n"
                            "Connection: close\r\n\r\n"
                        ).encode("ascii")
                    )
                    raw = self._recv_all(tls_proxy)
        except (OSError, ssl.SSLError) as exc:
            return {
                "command": command,
                "ok": False,
                "status_line": "",
                "body": "",
                "bytes": 0,
                "error": str(exc),
                "mitm_detected": False,
                "certificate_issuer": "",
            }

        header, _, response_body = raw.partition(b"\r\n\r\n")
        status_line = header.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
        display_body = self._decode_http_body(header, response_body)
        return {
            "command": command,
            "ok": bool(raw) and status_line.startswith(("HTTP/1.1 200", "HTTP/1.0 200")),
            "status_line": status_line,
            "body": display_body.decode("utf-8", errors="replace")[:3000],
            "bytes": len(raw),
            "error": "",
            "mitm_detected": mitm_detected,
            "certificate_subject": subject_text,
            "certificate_issuer": issuer_text,
        }

    @staticmethod
    def _recv_all(sock: socket.socket) -> bytes:
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _recv_until(sock: socket.socket, marker: bytes) -> bytes:
        sock.settimeout(10)
        data = bytearray()
        while marker not in data:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def _decode_http_body(header: bytes, body: bytes) -> bytes:
        header_text = header.decode("iso-8859-1", errors="replace").lower()
        if "transfer-encoding: chunked" not in header_text:
            return body
        decoded = bytearray()
        remaining = body
        while remaining:
            size_text, separator, after_size = remaining.partition(b"\r\n")
            if not separator:
                return body
            try:
                size = int(size_text.split(b";", 1)[0], 16)
            except ValueError:
                return body
            if size == 0:
                return bytes(decoded)
            chunk = after_size[:size]
            decoded.extend(chunk)
            remaining = after_size[size + 2 :]
        return bytes(decoded)

    @staticmethod
    def _certificate_name_text(name_parts: object) -> str:
        values: list[str] = []
        for group in name_parts:
            for key, value in group:
                values.append(f"{key}={value}")
        return ", ".join(values)

    @staticmethod
    def _safe_int(value: str, default: int, minimum: int, maximum: int) -> int:
        try:
            number = int(value)
        except ValueError:
            return default
        return min(max(number, minimum), maximum)

    def _send_text(self, status: int, body: str, headers: dict[str, str] | None = None) -> None:
        self._send_bytes(status, body.encode("utf-8"), headers or {}, "text/plain; charset=utf-8")

    def _send_html(self, body: str) -> None:
        self._send_bytes(200, body.encode("utf-8"), {"Cache-Control": "no-store"}, "text/html; charset=utf-8")

    def _send_json(self, payload: Any) -> None:
        self._send_bytes(
            200,
            json.dumps(payload, indent=2).encode("utf-8"),
            {"Cache-Control": "no-store"},
            "application/json; charset=utf-8",
        )

    def _send_empty(self, content_type: str) -> None:
        self.send_response(204)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        headers: dict[str, str] | None = None,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _render_home(self) -> str:
        host, port = self.server.server_address
        config = json.dumps(
            {
                "origin": f"http://{host}:{port}",
                "proxy": f"http://{self.proxy_host}:{self.proxy_port}",
                "mitmTarget": f"https://{self.mitm_target_host}{self.mitm_target_path}",
                "mitmCa": str(self.mitm_ca_path),
            }
        )
        page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CSC 430 Proxy Demo</title>
  <style>
    :root {
      --page: #eef2f6;
      --surface: #ffffff;
      --ink: #111827;
      --muted: #64748b;
      --line: #d9e0ea;
      --accent: #0b7a75;
      --accent-strong: #075e5a;
      --danger: #b42318;
      --ok: #087443;
      --row: #f8fafc;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Arial, Helvetica, sans-serif;
      background: var(--page);
      color: var(--ink);
    }
    header {
      background: #16202f;
      color: white;
      border-bottom: 4px solid var(--accent);
    }
    .wrap {
      width: min(1100px, calc(100vw - 32px));
      margin: 0 auto;
    }
    header .wrap {
      padding: 24px 0;
    }
    h1 {
      margin: 0 0 6px;
      font-size: 28px;
      letter-spacing: 0;
    }
    header p {
      margin: 0;
      color: #cbd5e1;
    }
    main.wrap {
      padding: 22px 0 36px;
      display: grid;
      gap: 18px;
    }
    section {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    .head {
      padding: 15px 16px;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    h2 {
      margin: 0;
      font-size: 18px;
    }
    .body {
      padding: 16px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }
    button {
      min-height: 42px;
      border: 0;
      border-radius: 6px;
      padding: 9px 12px;
      background: var(--accent);
      color: white;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    button:hover { background: var(--accent-strong); }
    button.secondary {
      background: #e7edf3;
      color: var(--ink);
    }
    .command {
      margin: 0;
      padding: 12px;
      border-radius: 7px;
      background: #172033;
      color: #e5edf7;
      overflow-wrap: anywhere;
      font-family: Consolas, "Courier New", monospace;
      line-height: 1.45;
    }
    .results {
      display: grid;
      gap: 12px;
    }
    .result {
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      background: white;
    }
    .result-head {
      padding: 10px 12px;
      background: var(--row);
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .badge {
      border-radius: 999px;
      padding: 3px 9px;
      font-weight: 700;
      font-size: 12px;
      background: #dcfae6;
      color: var(--ok);
    }
    .badge.error {
      background: #fee4e2;
      color: var(--danger);
    }
    pre {
      margin: 0;
      padding: 12px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font-family: Consolas, "Courier New", monospace;
    }
    .muted { color: var(--muted); }
    @media (max-width: 820px) {
      .grid { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 560px) {
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <h1>CSC 430 Proxy Demo</h1>
      <p id="service-line"></p>
    </div>
  </header>
  <main class="wrap">
    <section>
      <div class="head">
        <h2>Run Proxy Tests</h2>
        <button class="secondary" type="button" id="clear">Clear Results</button>
      </div>
      <div class="body">
        <div class="grid">
          <button data-path="/cache" data-repeat="1">Run /cache</button>
          <button data-path="/cache" data-repeat="2">Run /cache Twice</button>
          <button data-path="/nocache" data-repeat="2">Run /nocache Twice</button>
          <button data-path="/post" data-method="POST" data-repeat="1">Run POST</button>
          <button id="mitm-test" type="button">Run MITM HTTPS</button>
        </div>
      </div>
    </section>
    <section>
      <div class="head">
        <h2>Equivalent Command</h2>
      </div>
      <div class="body">
        <p class="command" id="command">curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/cache</p>
      </div>
    </section>
    <section>
      <div class="head">
        <h2>Results</h2>
        <span class="muted" id="status">Waiting</span>
      </div>
      <div class="body">
        <div class="results" id="results"></div>
      </div>
    </section>
  </main>
  <script>
    window.DEMO_CONFIG = __DEMO_CONFIG__;
    const results = document.getElementById("results");
    const status = document.getElementById("status");
    const command = document.getElementById("command");

    document.getElementById("service-line").textContent =
      `Origin ${DEMO_CONFIG.origin} | Proxy ${DEMO_CONFIG.proxy}`;

    document.querySelectorAll("button[data-path]").forEach((button) => {
      button.addEventListener("click", () => runTest(button));
    });

    document.getElementById("mitm-test").addEventListener("click", () => runMitmTest());

    document.getElementById("clear").addEventListener("click", () => {
      results.innerHTML = "";
      status.textContent = "Waiting";
    });

    async function runTest(button) {
      const path = button.dataset.path;
      const repeat = button.dataset.repeat || "1";
      const method = button.dataset.method || "GET";
      const targetPath = method === "POST" ? "/" : path;
      command.textContent =
        method === "POST"
          ? `curl.exe -x ${DEMO_CONFIG.proxy} -d 'network-demo' ${DEMO_CONFIG.origin}/`
          : `curl.exe -x ${DEMO_CONFIG.proxy} ${DEMO_CONFIG.origin}${path}`;
      status.textContent = "Running";
      const form = new URLSearchParams({ path: targetPath, repeat, method, body: "network-demo" });
      const response = await fetch("/api/proxy-test", {
        method: "POST",
        body: form,
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
      });
      const payload = await response.json();
      renderResults(payload.results);
      status.textContent = `Finished ${new Date().toLocaleTimeString()}`;
    }

    async function runMitmTest() {
      command.textContent =
        `curl.exe -x ${DEMO_CONFIG.proxy} --cacert ${DEMO_CONFIG.mitmCa} ${DEMO_CONFIG.mitmTarget}`;
      status.textContent = "Running MITM HTTPS";
      const response = await fetch("/api/mitm-test", { method: "POST" });
      const payload = await response.json();
      renderResults(payload.results);
      status.textContent = `Finished ${new Date().toLocaleTimeString()}`;
    }

    function renderResults(items) {
      results.innerHTML = items.map((item, index) => `
        <article class="result">
          <div class="result-head">
            <strong>Run ${index + 1}</strong>
            <span class="badge ${item.ok ? "" : "error"}">${escapeHtml(item.status_line || item.error || "No response")}</span>
          </div>
          <pre>${escapeHtml(resultText(item))}</pre>
        </article>
      `).join("");
    }

    function resultText(item) {
      const lines = [item.command, ""];
      if (Object.prototype.hasOwnProperty.call(item, "mitm_detected")) {
        lines.push(`MITM detected: ${item.mitm_detected ? "yes" : "no"}`);
        if (item.certificate_issuer) {
          lines.push(`Certificate issuer: ${item.certificate_issuer}`);
        }
        if (item.certificate_subject) {
          lines.push(`Certificate subject: ${item.certificate_subject}`);
        }
        lines.push("");
      }
      lines.push(item.body || item.error || "");
      return lines.join("\\n");
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }
  </script>
</body>
</html>"""
        return page.replace("__DEMO_CONFIG__", config)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.client_address[0]}:{self.client_address[1]} - {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Local origin server for proxy demos")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8888)
    parser.add_argument("--mitm-ca", default="data/mitm/ca.cert.pem")
    parser.add_argument("--mitm-target", default="example.com")
    args = parser.parse_args()
    DemoHandler.proxy_host = args.proxy_host
    DemoHandler.proxy_port = args.proxy_port
    DemoHandler.mitm_ca_path = Path(args.mitm_ca)
    DemoHandler.mitm_target_host = args.mitm_target
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"Demo origin UI listening at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down demo origin server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
