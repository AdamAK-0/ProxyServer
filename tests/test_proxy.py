"""Automated tests for the CSC 430 proxy implementation.

Contributor: Adam - proxy forwarding, cache, filter, POST, and CONNECT tests.
External code: none; standard library only.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
import threading
import time
import unittest
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from caching_proxy.access_control import AccessController
from caching_proxy.cache import ResponseCache
from caching_proxy.config import ProxyConfig
from caching_proxy.logger import RequestLogger
from caching_proxy.mitm import CertificateAuthority, MitmDependencyError
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

    def test_blacklist_host_port_rule_rejects_request(self) -> None:
        self.access.add("blacklist", f"127.0.0.1:{self.origin_port}")
        response = self._proxy_http("GET", "/blocked-by-port")
        self.assertIn(b"HTTP/1.1 403", response)
        self.assertIn(b"blocked by blacklist rule", response)
        self.assertNotIn("/blocked-by-port", CountingOriginHandler.counters)

    def test_blacklist_host_port_rule_does_not_match_different_port(self) -> None:
        self.access.add("blacklist", "127.0.0.1:1")
        response = self._proxy_http("GET", "/different-port")
        self.assertIn(b"HTTP/1.1 200", response)
        self.assertIn(b"origin-ok", response)
        self.assertEqual(CountingOriginHandler.counters["/different-port"], 1)

    def test_whitelist_only_accepts_matching_host_port_rule(self) -> None:
        self.access.set_whitelist_enabled(True)
        blocked = self._proxy_http("GET", "/blocked-without-whitelist")
        self.assertIn(b"HTTP/1.1 403", blocked)
        self.assertNotIn("/blocked-without-whitelist", CountingOriginHandler.counters)

        self.access.add("whitelist", f"127.0.0.1:{self.origin_port}")
        allowed = self._proxy_http("GET", "/allowed-by-port")
        self.assertIn(b"HTTP/1.1 200", allowed)
        self.assertIn(b"origin-ok", allowed)
        self.assertEqual(CountingOriginHandler.counters["/allowed-by-port"], 1)

    def test_whitelist_host_port_rule_does_not_allow_different_port(self) -> None:
        self.access.set_whitelist_enabled(True)
        self.access.add("whitelist", "127.0.0.1:1")
        response = self._proxy_http("GET", "/wrong-whitelist-port")
        self.assertIn(b"HTTP/1.1 403", response)
        self.assertNotIn("/wrong-whitelist-port", CountingOriginHandler.counters)

    def test_manual_filter_file_edit_is_reloaded(self) -> None:
        self.config.filters_file.write_text(
            json.dumps(
                {
                    "blacklist": [f"127.0.0.1:{self.origin_port}"],
                    "whitelist": [],
                    "whitelist_enabled": False,
                }
            ),
            encoding="utf-8",
        )
        response = self._proxy_http("GET", "/manual-filter-edit")
        self.assertIn(b"HTTP/1.1 403", response)
        self.assertNotIn("/manual-filter-edit", CountingOriginHandler.counters)

    def test_admin_mutation_reloads_manual_filter_file_edit_first(self) -> None:
        self.access.add("whitelist", "127.0.0.1")
        self.config.filters_file.write_text(
            json.dumps({"blacklist": [], "whitelist": [], "whitelist_enabled": False}),
            encoding="utf-8",
        )
        self.access.add("blacklist", f"127.0.0.1:{self.origin_port}")
        snapshot = self.access.snapshot()
        self.assertEqual(snapshot["whitelist"], [])
        self.assertEqual(snapshot["blacklist"], [f"127.0.0.1:{self.origin_port}"])

    def test_snapshot_reflects_manual_whitelist_mode_change(self) -> None:
        self.access.set_whitelist_enabled(True)
        self.config.filters_file.write_text(
            json.dumps({"blacklist": [], "whitelist": [], "whitelist_enabled": False}),
            encoding="utf-8",
        )
        self.assertFalse(self.access.snapshot()["whitelist_enabled"])

    def test_manual_filter_file_edit_accepts_utf8_bom(self) -> None:
        self.access.set_whitelist_enabled(True)
        self.config.filters_file.write_text(
            "\ufeff" + json.dumps({"blacklist": [], "whitelist": [], "whitelist_enabled": False}),
            encoding="utf-8",
        )
        self.assertFalse(self.access.snapshot()["whitelist_enabled"])

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

    def test_empty_browser_preconnect_is_ignored(self) -> None:
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3):
            pass

        records = self.logger.tail(20)
        self.assertFalse(
            any(
                record.get("event") == "request-error"
                and record.get("error") == "client closed connection before sending headers"
                for record in records
            )
        )
        self.assertEqual(self.stats.snapshot()["errors"], 0)
        for _ in range(20):
            if self.logger.excluded_log_file.exists():
                break
            time.sleep(0.05)
        excluded = [
            json.loads(line)
            for line in self.logger.excluded_log_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(excluded[-1]["event"], "empty-client-connection")
        self.assertEqual(excluded[-1]["reason"], "client closed connection before sending headers")

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

    def test_optional_mitm_decrypts_and_forwards_https_request(self) -> None:
        try:
            origin_server = _TLSOriginServer()
        except MitmDependencyError as exc:
            self.skipTest(str(exc))

        with tempfile.TemporaryDirectory() as mitm_temp:
            try:
                origin_server.start()
                mitm_config = ProxyConfig(
                    proxy_port=0,
                    admin_port=0,
                    socket_timeout=3,
                    tunnel_timeout=3,
                    cache_default_ttl=30,
                    data_dir=Path(mitm_temp) / "data",
                    mitm_enabled=True,
                    mitm_verify_origin_tls=False,
                )
                mitm_config.ensure_directories()
                mitm_proxy = ProxyServer(
                    mitm_config,
                    AccessController(mitm_config.filters_file),
                    ResponseCache(mitm_config.cache_dir, default_ttl=mitm_config.cache_default_ttl),
                    RequestLogger(mitm_config.log_file),
                    ProxyStats(),
                )
                mitm_thread = mitm_proxy.start_in_thread()
                try:
                    response = self._mitm_get(mitm_proxy.bound_port, mitm_config.mitm_dir / "ca.cert.pem", origin_server.port)
                    self.assertIn(b"HTTP/1.1 200 OK", response)
                    self.assertIn(b"secure-origin-count-1", response)
                    self.assertEqual(mitm_proxy.stats.snapshot()["mitm_intercepts"], 1)
                finally:
                    mitm_proxy.shutdown()
                    mitm_thread.join(timeout=2)
            finally:
                origin_server.stop()

    def _mitm_get(self, proxy_port: int, ca_cert_path: Path, origin_port: int) -> bytes:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as raw_client:
            raw_client.sendall(
                (
                    f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{origin_port}\r\n\r\n"
                ).encode("ascii")
            )
            header = _recv_until(raw_client, b"\r\n\r\n")
            self.assertIn(b"200 Connection Established", header)
            client_context = ssl.create_default_context(cafile=str(ca_cert_path))
            with client_context.wrap_socket(raw_client, server_hostname="127.0.0.1") as tls_client:
                tls_client.sendall(
                    (
                        "GET /secure HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{origin_port}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                )
                return _recv_all(tls_client)

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


class _TLSOriginServer:
    def __init__(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        ca = CertificateAuthority(Path(self.temp_dir.name) / "origin-ca")
        cert_path, key_path = ca.certificate_for_host("127.0.0.1")
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self._stop = threading.Event()
        self.count = 0

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                raw_client, _ = self.listener.accept()
            except OSError:
                return
            try:
                with self.context.wrap_socket(raw_client, server_side=True) as tls_client:
                    _recv_until(tls_client, b"\r\n\r\n")
                    self.count += 1
                    body = f"secure-origin-count-{self.count}".encode("utf-8")
                    tls_client.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode("ascii")
                        + b"Cache-Control: max-age=60\r\n"
                        + b"Connection: close\r\n\r\n"
                        + body
                    )
            except OSError:
                raw_client.close()


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
