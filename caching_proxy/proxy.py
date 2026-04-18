"""Threaded socket proxy with HTTP caching and HTTPS CONNECT tunneling.

Contributor: Adam - socket server, request forwarding, HTTPS tunneling, and errors.
External code: none; standard library only.
"""

from __future__ import annotations

import select
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .access_control import AccessController
from .cache import ResponseCache
from .config import ProxyConfig
from .http_utils import (
    BadRequest,
    HTTPRequest,
    build_forward_request,
    build_simple_response,
    parse_http_request,
    parse_status_code,
)
from .logger import RequestLogger
from .stats import ProxyStats


class ProxyServer:
    """Accepts browser/client requests and dispatches each connection to a thread."""

    def __init__(
        self,
        config: ProxyConfig,
        access: AccessController,
        cache: ResponseCache,
        logger: RequestLogger,
        stats: ProxyStats,
    ) -> None:
        self.config = config
        self.access = access
        self.cache = cache
        self.logger = logger
        self.stats = stats
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._server_socket: socket.socket | None = None
        self.bound_port: int | None = None

    def serve_forever(self) -> None:
        """Bind the listening socket and accept clients until shutdown."""

        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.bind((self.config.listen_host, self.config.proxy_port))
        listen_socket.listen(100)
        listen_socket.settimeout(0.5)
        self._server_socket = listen_socket
        self.bound_port = listen_socket.getsockname()[1]
        self._ready_event.set()
        self.logger.log("proxy-started", host=self.config.listen_host, port=self.bound_port)

        try:
            while not self._stop_event.is_set():
                try:
                    client_socket, client_address = listen_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                worker = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address),
                    daemon=True,
                )
                worker.start()
        finally:
            self.logger.log("proxy-stopped", host=self.config.listen_host, port=self.bound_port)
            try:
                listen_socket.close()
            except OSError:
                pass

    def start_in_thread(self) -> threading.Thread:
        """Start the proxy in a daemon thread; useful for tests and demos."""

        thread = threading.Thread(target=self.serve_forever, name="ProxyServer", daemon=True)
        thread.start()
        self._ready_event.wait(timeout=5)
        return thread

    def shutdown(self) -> None:
        self._stop_event.set()
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def _handle_client(self, client_socket: socket.socket, client_address: tuple[str, int]) -> None:
        self.stats.connection_started()
        request_timestamp = datetime.now(timezone.utc).isoformat()
        request: HTTPRequest | None = None
        try:
            client_socket.settimeout(self.config.socket_timeout)
            raw_header, body = self._read_client_request(client_socket)
            request = parse_http_request(raw_header, body)
            if self._is_self_proxy_request(request):
                self._send_self_proxy_loop(client_socket, client_address, request, request_timestamp)
                return
            allowed, reason = self.access.check(request.host, request.display_url)
            if not allowed:
                self._send_blocked(client_socket, client_address, request, reason, request_timestamp)
                return

            if request.is_connect:
                self._handle_connect(client_socket, client_address, request, request_timestamp)
            elif request.scheme == "http":
                self._handle_http(client_socket, client_address, request, request_timestamp)
            else:
                response = build_simple_response(
                    501,
                    "Not Implemented",
                    "Use HTTP CONNECT for HTTPS traffic so encryption remains end-to-end.",
                )
                client_socket.sendall(response)
                self.stats.record_error()
        except BadRequest as exc:
            self._handle_error(client_socket, client_address, request, request_timestamp, 400, "Bad Request", str(exc))
        except OSError as exc:
            self._handle_error(client_socket, client_address, request, request_timestamp, 502, "Bad Gateway", str(exc))
        except Exception as exc:  # Defensive final guard so a worker thread cannot crash the server.
            self._handle_error(client_socket, client_address, request, request_timestamp, 500, "Internal Server Error", str(exc))
        finally:
            try:
                client_socket.close()
            except OSError:
                pass
            self.stats.connection_finished()

    def _handle_http(
        self,
        client_socket: socket.socket,
        client_address: tuple[str, int],
        request: HTTPRequest,
        request_timestamp: str,
    ) -> None:
        cache_key = self.cache.make_key(request.method, request.scheme, request.host, request.port, request.path)
        cache_result = "BYPASS"
        if request.method == "GET":
            cached = self.cache.get(cache_key)
            if cached is not None:
                client_socket.sendall(cached)
                self.stats.record_http("HIT", bytes_from_origin=0, bytes_to_client=len(cached))
                self._log_complete(
                    client_address,
                    request,
                    request_timestamp,
                    status_code=parse_status_code(cached),
                    cache_result="HIT",
                    bytes_from_origin=0,
                    bytes_to_client=len(cached),
                    extra={"cache_key": cache_key},
                )
                return
            cache_result = "MISS"

        outbound = build_forward_request(request)
        with socket.create_connection((request.host, request.port), timeout=self.config.socket_timeout) as origin:
            origin.settimeout(self.config.socket_timeout)
            origin.sendall(outbound)
            response = self._read_origin_response(origin)

        stored = False
        if request.method == "GET":
            stored = self.cache.put(cache_key, request.method, request.display_url, response)

        client_socket.sendall(response)
        self.stats.record_http(cache_result, bytes_from_origin=len(response), bytes_to_client=len(response))
        self._log_complete(
            client_address,
            request,
            request_timestamp,
            status_code=parse_status_code(response),
            cache_result=cache_result,
            bytes_from_origin=len(response),
            bytes_to_client=len(response),
            extra={"cache_key": cache_key if request.method == "GET" else "", "cache_stored": stored},
        )

    def _handle_connect(
        self,
        client_socket: socket.socket,
        client_address: tuple[str, int],
        request: HTTPRequest,
        request_timestamp: str,
    ) -> None:
        with socket.create_connection((request.host, request.port), timeout=self.config.socket_timeout) as origin:
            origin.settimeout(None)
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: CSC430Proxy\r\n\r\n")
            client_socket.settimeout(None)
            client_to_origin, origin_to_client = self._tunnel(client_socket, origin)

        self.stats.record_tunnel(bytes_from_origin=origin_to_client, bytes_to_client=origin_to_client)
        self._log_complete(
            client_address,
            request,
            request_timestamp,
            status_code=200,
            cache_result="BYPASS",
            bytes_from_origin=origin_to_client,
            bytes_to_client=origin_to_client,
            extra={"client_to_origin_bytes": client_to_origin, "origin_to_client_bytes": origin_to_client},
        )

    def _tunnel(self, client_socket: socket.socket, origin: socket.socket) -> tuple[int, int]:
        """Forward encrypted bytes in both directions without decrypting HTTPS."""

        sockets = [client_socket, origin]
        client_to_origin = 0
        origin_to_client = 0
        last_activity = time.monotonic()

        while not self._stop_event.is_set():
            if time.monotonic() - last_activity > self.config.tunnel_timeout:
                break
            readable, _, exceptional = select.select(sockets, [], sockets, 1.0)
            if exceptional:
                break
            if not readable:
                continue
            for source in readable:
                try:
                    data = source.recv(self.config.buffer_size)
                except OSError:
                    return client_to_origin, origin_to_client
                if not data:
                    return client_to_origin, origin_to_client
                destination = origin if source is client_socket else client_socket
                destination.sendall(data)
                last_activity = time.monotonic()
                if source is client_socket:
                    client_to_origin += len(data)
                else:
                    origin_to_client += len(data)
        return client_to_origin, origin_to_client

    def _send_blocked(
        self,
        client_socket: socket.socket,
        client_address: tuple[str, int],
        request: HTTPRequest,
        reason: str,
        request_timestamp: str,
    ) -> None:
        body = (
            "Access denied by CSC 430 proxy.\n\n"
            f"URL: {request.display_url}\n"
            f"Reason: {reason}\n"
        )
        response = build_simple_response(403, "Forbidden", body)
        client_socket.sendall(response)
        self.stats.record_blocked()
        self.logger.log(
            "request-blocked",
            client_ip=client_address[0],
            client_port=client_address[1],
            target_host=request.host,
            target_port=request.port,
            method=request.method,
            url=request.display_url,
            reason=reason,
            request_timestamp=request_timestamp,
            response_timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _send_self_proxy_loop(
        self,
        client_socket: socket.socket,
        client_address: tuple[str, int],
        request: HTTPRequest,
        request_timestamp: str,
    ) -> None:
        body = (
            "Loop detected by CSC 430 proxy.\n\n"
            f"You requested the proxy listener itself: {request.display_url}\n"
            f"Open the admin panel on port {self.config.admin_port} instead.\n"
        )
        response = build_simple_response(508, "Loop Detected", body)
        client_socket.sendall(response)
        self.stats.record_error()
        self.logger.log(
            "request-error",
            client_ip=client_address[0],
            client_port=client_address[1],
            target_host=request.host,
            target_port=request.port,
            method=request.method,
            url=request.display_url,
            status_code=508,
            reason="Loop Detected",
            error="client requested the proxy listener itself",
            request_timestamp=request_timestamp,
            response_timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _handle_error(
        self,
        client_socket: socket.socket,
        client_address: tuple[str, int],
        request: HTTPRequest | None,
        request_timestamp: str,
        status_code: int,
        reason: str,
        message: str,
    ) -> None:
        self.stats.record_error()
        try:
            client_socket.sendall(build_simple_response(status_code, reason, message))
        except OSError:
            pass
        log_fields: dict[str, Any] = {
            "client_ip": client_address[0],
            "client_port": client_address[1],
            "status_code": status_code,
            "reason": reason,
            "error": message,
            "request_timestamp": request_timestamp,
            "response_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if request is not None:
            log_fields.update(
                target_host=request.host,
                target_port=request.port,
                method=request.method,
                url=request.display_url,
            )
        self.logger.log("request-error", **log_fields)

    def _log_complete(
        self,
        client_address: tuple[str, int],
        request: HTTPRequest,
        request_timestamp: str,
        status_code: int,
        cache_result: str,
        bytes_from_origin: int,
        bytes_to_client: int,
        extra: dict[str, Any] | None = None,
    ) -> None:
        fields: dict[str, Any] = {
            "client_ip": client_address[0],
            "client_port": client_address[1],
            "target_host": request.host,
            "target_port": request.port,
            "method": request.method,
            "url": request.display_url,
            "status_code": status_code,
            "cache_result": cache_result,
            "bytes_from_origin": bytes_from_origin,
            "bytes_to_client": bytes_to_client,
            "request_timestamp": request_timestamp,
            "response_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            fields.update(extra)
        self.logger.log("request-complete", **fields)

    def _read_client_request(self, client_socket: socket.socket) -> tuple[bytes, bytes]:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = client_socket.recv(self.config.buffer_size)
            if not chunk:
                raise BadRequest("client closed connection before sending headers")
            data.extend(chunk)
            if len(data) > self.config.max_header_size:
                raise BadRequest("request headers are too large")

        raw_header, remaining = bytes(data).split(b"\r\n\r\n", 1)
        content_length = self._content_length(raw_header)
        body = bytearray(remaining[:content_length])
        while len(body) < content_length:
            chunk = client_socket.recv(min(self.config.buffer_size, content_length - len(body)))
            if not chunk:
                raise BadRequest("client closed connection before sending full body")
            body.extend(chunk)
        return raw_header, bytes(body)

    def _read_origin_response(self, origin: socket.socket) -> bytes:
        chunks: list[bytes] = []
        while True:
            try:
                data = origin.recv(self.config.buffer_size)
            except socket.timeout:
                if chunks:
                    break
                raise
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)

    @staticmethod
    def _content_length(raw_header: bytes) -> int:
        text = raw_header.decode("iso-8859-1", errors="replace")
        for line in text.split("\r\n")[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            if name.strip().lower() == "content-length":
                try:
                    return max(0, int(value.strip()))
                except ValueError as exc:
                    raise BadRequest("invalid Content-Length header") from exc
        return 0

    def _is_self_proxy_request(self, request: HTTPRequest) -> bool:
        proxy_port = self.bound_port or self.config.proxy_port
        if request.port != proxy_port:
            return False
        host = request.host.strip().lower()
        local_names = {
            self.config.listen_host.lower(),
            "127.0.0.1",
            "localhost",
            "::1",
        }
        return host in local_names
