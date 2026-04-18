"""Automated tests for the CSC 430 proxy implementation.

Contributor: Adam - proxy forwarding, cache, filter, POST, and CONNECT tests.
External code: none; standard library only.
"""

from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from caching_proxy.access_control import AccessController
from caching_proxy.cache import ResponseCache
from caching_proxy.config import ProxyConfig
from caching_proxy.logger import RequestLogger
from caching_proxy.proxy import ProxyServer
from caching_proxy.stats import ProxyStats


class CountingOriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counters: dict[str, int] = {}

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        self.counters[path] = self.counters.get(path, 0) + 1
        count = self.counters[path]
        if path == "/cache":
            body = f"cache-count-{count}".encode("utf-8")
            self._send(200, body, {"Cache-Control": "max-age=60"})
        elif path == "/nocache":
            body = f"nocache-count-{count}".encode("utf-8")
            self._send(200, body, {"Cache-Control": "no-store"})
        else:
            self._send(200, b"origin-ok", {"Cache-Control": "max-age=60"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._send(200, b"echo:" + body, {"Cache-Control": "no-store"})

    def _send(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class ProxyIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        CountingOriginHandler.counters = {}
        self.origin = ThreadingHTTPServer(("127.0.0.1", 0), CountingOriginHandler)
        self.origin_thread = threading.Thread(target=self.origin.serve_forever, daemon=True)
        self.origin_thread.start()
        self.origin_port = self.origin.server_address[1]

        self.temp_dir = tempfile.TemporaryDirectory()
        data_dir = Path(self.temp_dir.name) / "data"
        self.config = ProxyConfig(
            proxy_port=0,
            admin_port=0,
            socket_timeout=3,
            tunnel_timeout=3,
            cache_default_ttl=30,
            data_dir=data_dir,
        )
        self.config.ensure_directories()
        self.access = AccessController(self.config.filters_file)
        self.cache = ResponseCache(self.config.cache_dir, default_ttl=self.config.cache_default_ttl)
        self.logger = RequestLogger(self.config.log_file)
        self.stats = ProxyStats()
        self.proxy = ProxyServer(self.config, self.access, self.cache, self.logger, self.stats)
        self.proxy_thread = self.proxy.start_in_thread()
        self.proxy_port = self.proxy.bound_port
        self.assertIsNotNone(self.proxy_port)

    def tearDown(self) -> None:
        self.proxy.shutdown()
        self.proxy_thread.join(timeout=2)
        self.origin.shutdown()
        self.origin.server_close()
        self.origin_thread.join(timeout=2)
        self.temp_dir.cleanup()

    def test_forwards_basic_http_get(self) -> None:
        response = self._proxy_http("GET", "/hello")
        self.assertIn(b"HTTP/1.1 200", response)
        self.assertIn(b"origin-ok", response)
        self.assertEqual(CountingOriginHandler.counters["/hello"], 1)

    def test_caches_repeated_get_when_headers_allow_it(self) -> None:
        first = self._proxy_http("GET", "/cache")
        second = self._proxy_http("GET", "/cache")
        self.assertIn(b"cache-count-1", first)
        self.assertIn(b"cache-count-1", second)
        self.assertNotIn(b"cache-count-2", second)
        self.assertEqual(CountingOriginHandler.counters["/cache"], 1)
        self.assertEqual(self.stats.snapshot()["cache_hits"], 1)

    def test_does_not_cache_no_store_response(self) -> None:
        first = self._proxy_http("GET", "/nocache")
        second = self._proxy_http("GET", "/nocache")
        self.assertIn(b"nocache-count-1", first)
        self.assertIn(b"nocache-count-2", second)
        self.assertEqual(CountingOriginHandler.counters["/nocache"], 2)

    def test_blacklist_rejects_request_before_origin_server(self) -> None:
        self.access.add("blacklist", "127.0.0.1")
        response = self._proxy_http("GET", "/blocked")
        self.assertIn(b"HTTP/1.1 403", response)
        self.assertIn(b"Access denied", response)
        self.assertNotIn("/blocked", CountingOriginHandler.counters)

    def test_self_proxy_request_is_rejected_without_recursive_timeout(self) -> None:
        request = (
            f"GET http://127.0.0.1:{self.proxy_port}/ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.proxy_port}\r\n\r\n"
        ).encode("ascii")
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3) as client:
            client.sendall(request)
            response = _recv_all(client)
        self.assertIn(b"HTTP/1.1 508 Loop Detected", response)
        self.assertIn(b"proxy listener itself", response)

    def test_post_body_is_forwarded(self) -> None:
        response = self._proxy_http("POST", "/echo", body=b"network-test")
        self.assertIn(b"HTTP/1.1 200", response)
        self.assertIn(b"echo:network-test", response)

    def test_https_connect_tunnels_bytes_without_decrypting(self) -> None:
        echo_server = _EchoServer()
        try:
            echo_server.start()
            with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3) as client:
                connect = (
                    f"CONNECT 127.0.0.1:{echo_server.port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{echo_server.port}\r\n\r\n"
                ).encode("ascii")
                client.sendall(connect)
                header = _recv_until(client, b"\r\n\r\n")
                self.assertIn(b"200 Connection Established", header)
                client.sendall(b"secret-bytes")
                tunneled = client.recv(1024)
                self.assertEqual(tunneled, b"echo:secret-bytes")
        finally:
            echo_server.stop()

    def _proxy_http(self, method: str, path: str, body: bytes = b"") -> bytes:
        headers = [
            f"{method} http://127.0.0.1:{self.origin_port}{path} HTTP/1.1",
            f"Host: 127.0.0.1:{self.origin_port}",
            "User-Agent: unittest",
        ]
        if body:
            headers.append(f"Content-Length: {len(body)}")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3) as client:
            client.sendall(request)
            return _recv_all(client)


class _EchoServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self._stop = threading.Event()

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            with client:
                data = client.recv(1024)
                if data:
                    client.sendall(b"echo:" + data)


def _recv_all(sock: socket.socket) -> bytes:
    sock.settimeout(3)
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


def _recv_until(sock: socket.socket, marker: bytes) -> bytes:
    sock.settimeout(3)
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


if __name__ == "__main__":
    unittest.main()
