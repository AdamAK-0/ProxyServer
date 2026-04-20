"""Small local origin server and PyQt demo tool for proxy tests.

Contributor: Adam - demo endpoints and desktop UI for forwarding, caching, POST, and MITM testing.
External code: PyQt5 for the desktop demo UI.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse


class ProxyDemoClient:
    """Runs the same proxy requests that the old web demo buttons triggered."""

    def __init__(
        self,
        origin_host: str,
        origin_port: int,
        proxy_host: str,
        proxy_port: int,
        mitm_ca_path: Path,
        mitm_target_host: str,
        mitm_target_path: str,
    ) -> None:
        self.origin_host = _connectable_host(origin_host)
        self.origin_port = origin_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.mitm_ca_path = mitm_ca_path
        self.mitm_target_host = mitm_target_host
        self.mitm_target_path = mitm_target_path if mitm_target_path.startswith("/") else f"/{mitm_target_path}"

    @property
    def origin_url(self) -> str:
        return f"http://{self.origin_host}:{self.origin_port}"

    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy_host}:{self.proxy_port}"

    @property
    def mitm_target_url(self) -> str:
        return f"https://{self.mitm_target_host}{self.mitm_target_path}"

    def proxy_command(self, method: str, target_path: str, body: bytes = b"") -> str:
        target_path = self._normalize_path(target_path)
        target_url = f"{self.origin_url}{target_path}"
        command = f"curl.exe -x {self.proxy_url} {target_url}"
        if method.upper() == "POST":
            command = f"curl.exe -x {self.proxy_url} -d {body.decode('utf-8', errors='replace')!r} {target_url}"
        return command

    def mitm_command(self) -> str:
        return f"curl.exe -x {self.proxy_url} --cacert {self.mitm_ca_path} {self.mitm_target_url}"

    def proxy_test(self, target_path: str, repeat: int, method: str, body_text: str) -> list[dict[str, Any]]:
        target_path = self._normalize_path(target_path)
        repeat = min(max(repeat, 1), 5)
        method = method.upper()
        if method not in {"GET", "POST"}:
            method = "GET"
        body = body_text.encode("utf-8")
        return [
            self.request_through_proxy(method, target_path, body if method == "POST" else b"")
            for _ in range(repeat)
        ]

    def mitm_test(self) -> list[dict[str, Any]]:
        return [self.request_https_through_mitm(self.mitm_target_host, 443, self.mitm_target_path)]

    def request_through_proxy(self, method: str, target_path: str, body: bytes) -> dict[str, Any]:
        target_path = self._normalize_path(target_path)
        target_url = f"{self.origin_url}{target_path}"
        command = self.proxy_command(method, target_path, body)
        request_lines = [
            f"{method} {target_url} HTTP/1.1",
            f"Host: {self.origin_host}:{self.origin_port}",
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

    def request_https_through_mitm(self, target_host: str, target_port: int, target_path: str) -> dict[str, Any]:
        target_path = self._normalize_path(target_path)
        command = self.mitm_command()
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
    def _normalize_path(path: str) -> str:
        return path if path.startswith("/") else f"/{path}"

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


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counters: dict[str, int] = {}
    proxy_host = "127.0.0.1"
    proxy_port = 8888
    mitm_ca_path = Path("data/mitm/ca.cert.pem")
    mitm_target_host = "example.com"
    mitm_target_path = "/"

    def handle(self) -> None:
        try:
            super().handle()
        except ConnectionResetError:
            return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            self._send_text(
                200,
                (
                    "CSC 430 demo origin server\n"
                    "The PyQt demo panel is the interactive UI.\n"
                    "Try /cache twice through the proxy to see caching.\n"
                    "Try /nocache twice through the proxy to see no-store behavior.\n"
                ),
                {"Cache-Control": "no-store"},
            )
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
                    "Try /cache twice through the proxy to see caching.\n"
                    "Try /nocache twice through the proxy to see no-store behavior.\n"
                ),
                {"Cache-Control": "max-age=60"},
            )

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/proxy-test":
            body = self._read_body_text()
            self._handle_proxy_test(parse_qs(body))
            return
        if parsed.path == "/api/mitm-test":
            body = self._read_body_text()
            self._handle_mitm_test(parse_qs(body))
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._send_bytes(200, b"echo body: " + body + b"\n", {"Cache-Control": "no-store"})

    def _handle_proxy_test(self, query: dict[str, list[str]]) -> None:
        target_path = query.get("path", ["/cache"])[0] or "/cache"
        repeat = self._safe_int(query.get("repeat", ["1"])[0], default=1, minimum=1, maximum=5)
        method = query.get("method", ["GET"])[0].upper()
        body = query.get("body", ["network-demo"])[0]
        self._send_json({"results": self._client().proxy_test(target_path, repeat, method, body)})

    def _handle_mitm_test(self, query: dict[str, list[str]]) -> None:
        target_host = query.get("host", [self.mitm_target_host])[0] or self.mitm_target_host
        target_path = query.get("path", [self.mitm_target_path])[0] or self.mitm_target_path
        client = self._client()
        self._send_json({"results": [client.request_https_through_mitm(target_host, 443, target_path)]})

    def _client(self) -> ProxyDemoClient:
        origin_host, origin_port = self.server.server_address
        return ProxyDemoClient(
            _connectable_host(origin_host),
            int(origin_port),
            self.proxy_host,
            self.proxy_port,
            self.mitm_ca_path,
            self.mitm_target_host,
            self.mitm_target_path,
        )

    def _read_body_text(self) -> str:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length).decode("utf-8", errors="replace")

    @staticmethod
    def _safe_int(value: str, default: int, minimum: int, maximum: int) -> int:
        try:
            number = int(value)
        except ValueError:
            return default
        return min(max(number, minimum), maximum)

    def _send_text(self, status: int, body: str, headers: dict[str, str] | None = None) -> None:
        self._send_bytes(status, body.encode("utf-8"), headers or {}, "text/plain; charset=utf-8")

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

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.client_address[0]}:{self.client_address[1]} - {format % args}")


def run_demo_panel(
    server: ThreadingHTTPServer,
    proxy_host: str,
    proxy_port: int,
    mitm_ca_path: Path,
    mitm_target_host: str,
    mitm_target_path: str,
) -> int:
    QtCore, QtWidgets = _load_pyqt()
    if QtWidgets.QApplication.instance() is None:
        try:
            QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
            QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
        except AttributeError:
            pass
        app = QtWidgets.QApplication(sys.argv[:1])
    else:
        app = QtWidgets.QApplication.instance()

    origin_host, origin_port = server.server_address
    client = ProxyDemoClient(
        _connectable_host(origin_host),
        int(origin_port),
        proxy_host,
        proxy_port,
        mitm_ca_path,
        mitm_target_host,
        mitm_target_path,
    )
    app.setApplicationName("CSC 430 Proxy Demo")
    window_class = _create_demo_window_class(QtCore, QtWidgets)
    window = window_class(client)
    window.show()
    window.raise_()
    window.activateWindow()
    return app.exec_()


def _load_pyqt() -> tuple[Any, Any]:
    try:
        from PyQt5 import QtCore, QtWidgets
    except ImportError as exc:
        raise RuntimeError(
            "PyQt5 is required for the demo panel. Install it with: "
            "python -m pip install -r requirements.txt"
        ) from exc
    return QtCore, QtWidgets


def _create_demo_window_class(QtCore: Any, QtWidgets: Any) -> type[Any]:
    class RequestWorker(QtCore.QObject):
        finished = QtCore.pyqtSignal(object)
        failed = QtCore.pyqtSignal(str)

        def __init__(self, job: Callable[[], list[dict[str, Any]]]) -> None:
            super().__init__()
            self.job = job

        @QtCore.pyqtSlot()
        def run(self) -> None:
            try:
                self.finished.emit(self.job())
            except Exception as exc:
                self.failed.emit(str(exc))

    class DemoWindow(QtWidgets.QMainWindow):
        def __init__(self, client: ProxyDemoClient) -> None:
            super().__init__()
            self.client = client
            self._workers: list[tuple[Any, Any]] = []
            self._active_thread: Any | None = None
            self._active_worker: Any | None = None
            self.action_buttons: list[Any] = []
            self.setWindowTitle("CSC 430 Proxy Demo")
            self.resize(980, 700)
            self._build_ui()

        def _build_ui(self) -> None:
            central = QtWidgets.QWidget(self)
            root = QtWidgets.QVBoxLayout(central)
            root.setContentsMargins(16, 14, 16, 14)
            root.setSpacing(12)
            self.setCentralWidget(central)

            title = QtWidgets.QLabel("CSC 430 Proxy Demo")
            title.setObjectName("title")
            service = QtWidgets.QLabel(f"Origin {self.client.origin_url} | Proxy {self.client.proxy_url}")
            service.setObjectName("muted")
            root.addWidget(title)
            root.addWidget(service)

            controls = QtWidgets.QGroupBox("Run Proxy Tests")
            controls_layout = QtWidgets.QGridLayout(controls)
            controls_layout.setContentsMargins(12, 16, 12, 12)
            controls_layout.setSpacing(10)
            self._add_action_button(controls_layout, "Run /cache", 0, 0, lambda: self._run_proxy_test("/cache", 1))
            self._add_action_button(controls_layout, "Run /cache Twice", 0, 1, lambda: self._run_proxy_test("/cache", 2))
            self._add_action_button(controls_layout, "Run /nocache Twice", 0, 2, lambda: self._run_proxy_test("/nocache", 2))
            self._add_action_button(
                controls_layout,
                "Run POST",
                1,
                0,
                lambda: self._run_proxy_test("/", 1, method="POST", body_text="network-demo"),
            )
            self._add_action_button(controls_layout, "Run MITM HTTPS", 1, 1, self._run_mitm_test)
            clear_button = QtWidgets.QPushButton("Clear Results")
            clear_button.clicked.connect(self._clear_results)
            controls_layout.addWidget(clear_button, 1, 2)
            root.addWidget(controls)

            command_box = QtWidgets.QGroupBox("Equivalent Command")
            command_layout = QtWidgets.QVBoxLayout(command_box)
            self.command_text = QtWidgets.QPlainTextEdit()
            self.command_text.setReadOnly(True)
            self.command_text.setMaximumHeight(78)
            self.command_text.setPlainText(self.client.proxy_command("GET", "/cache"))
            command_layout.addWidget(self.command_text)
            root.addWidget(command_box)

            results_box = QtWidgets.QGroupBox("Results")
            results_layout = QtWidgets.QVBoxLayout(results_box)
            self.status_label = QtWidgets.QLabel("Waiting")
            self.status_label.setObjectName("muted")
            self.results_text = QtWidgets.QPlainTextEdit()
            self.results_text.setReadOnly(True)
            results_layout.addWidget(self.status_label)
            results_layout.addWidget(self.results_text, 1)
            root.addWidget(results_box, 1)
            self.setStyleSheet(_demo_stylesheet())

        def _add_action_button(
            self,
            layout: Any,
            label: str,
            row: int,
            column: int,
            action: Callable[[], None],
        ) -> None:
            button = QtWidgets.QPushButton(label)
            button.clicked.connect(action)
            layout.addWidget(button, row, column)
            self.action_buttons.append(button)

        def _run_proxy_test(
            self,
            target_path: str,
            repeat: int,
            method: str = "GET",
            body_text: str = "network-demo",
        ) -> None:
            body = body_text.encode("utf-8")
            self.command_text.setPlainText(self.client.proxy_command(method, target_path, body))
            self._run_job(lambda: self.client.proxy_test(target_path, repeat, method, body_text), "Running proxy test")

        def _run_mitm_test(self) -> None:
            self.command_text.setPlainText(self.client.mitm_command())
            self._run_job(self.client.mitm_test, "Running MITM HTTPS test")

        def _run_job(self, job: Callable[[], list[dict[str, Any]]], status: str) -> None:
            self._set_buttons_enabled(False)
            self.status_label.setText(status)
            thread = QtCore.QThread(self)
            worker = RequestWorker(job)
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.finished.connect(self._job_finished)
            worker.failed.connect(self._job_failed)
            thread.finished.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)
            self._active_thread = thread
            self._active_worker = worker
            self._workers.append((thread, worker))
            thread.start()

        def _job_finished(self, payload: list[dict[str, Any]]) -> None:
            self._render_results(payload)
            self.status_label.setText(f"Finished { _time_text() }")
            self._set_buttons_enabled(True)
            self._finish_thread()

        def _job_failed(self, message: str) -> None:
            self.results_text.setPlainText(message)
            self.status_label.setText(f"Failed { _time_text() }")
            self._set_buttons_enabled(True)
            self._finish_thread()

        def _finish_thread(self) -> None:
            thread = self._active_thread
            worker = self._active_worker
            if thread is None or worker is None:
                return
            self._workers = [(t, w) for (t, w) in self._workers if t is not thread and w is not worker]
            self._active_thread = None
            self._active_worker = None
            thread.quit()

        def _set_buttons_enabled(self, enabled: bool) -> None:
            for button in self.action_buttons:
                button.setEnabled(enabled)

        def _render_results(self, items: list[dict[str, Any]]) -> None:
            chunks: list[str] = []
            for index, item in enumerate(items, start=1):
                chunks.append(f"Run {index}")
                chunks.append(item.get("status_line") or item.get("error") or "No response")
                chunks.append(item.get("command", ""))
                if "mitm_detected" in item:
                    chunks.append(f"MITM detected: {'yes' if item.get('mitm_detected') else 'no'}")
                    if item.get("certificate_issuer"):
                        chunks.append(f"Certificate issuer: {item['certificate_issuer']}")
                    if item.get("certificate_subject"):
                        chunks.append(f"Certificate subject: {item['certificate_subject']}")
                chunks.append("")
                chunks.append(item.get("body") or item.get("error") or "")
                chunks.append("")
            self.results_text.setPlainText("\n".join(chunks).strip())

        def _clear_results(self) -> None:
            self.results_text.clear()
            self.status_label.setText("Waiting")

    return DemoWindow


def _connectable_host(host: str) -> str:
    return "127.0.0.1" if host in {"", "0.0.0.0", "::"} else host


def _time_text() -> str:
    from datetime import datetime

    return datetime.now().strftime("%H:%M:%S")


def _demo_stylesheet() -> str:
    return """
        QMainWindow, QWidget {
            background: #eef2f6;
            color: #111827;
            font-family: Segoe UI, Arial, sans-serif;
            font-size: 10pt;
        }
        QLabel#title {
            color: #0f172a;
            font-size: 20pt;
            font-weight: 700;
        }
        QLabel#muted {
            color: #64748b;
        }
        QGroupBox {
            background: white;
            border: 1px solid #d9e0ea;
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 8px;
            font-weight: 700;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
        }
        QPushButton {
            background: #0b7a75;
            color: white;
            border: 0;
            border-radius: 6px;
            padding: 9px 12px;
            font-weight: 700;
            min-height: 30px;
        }
        QPushButton:hover {
            background: #075e5a;
        }
        QPushButton:disabled {
            background: #cbd5e1;
            color: #64748b;
        }
        QPlainTextEdit {
            background: #172033;
            color: #e5edf7;
            border: 0;
            border-radius: 6px;
            padding: 8px;
            font-family: Consolas, Courier New, monospace;
        }
    """


def main() -> None:
    parser = argparse.ArgumentParser(description="Local origin server and PyQt demo panel for proxy demos")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8888)
    parser.add_argument("--mitm-ca", default="data/mitm/ca.cert.pem")
    parser.add_argument("--mitm-target", default="example.com")
    parser.add_argument("--mitm-path", default="/")
    args = parser.parse_args()

    DemoHandler.counters = {}
    DemoHandler.proxy_host = args.proxy_host
    DemoHandler.proxy_port = args.proxy_port
    DemoHandler.mitm_ca_path = Path(args.mitm_ca)
    DemoHandler.mitm_target_host = args.mitm_target
    DemoHandler.mitm_target_path = args.mitm_path

    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    thread = threading.Thread(target=server.serve_forever, name="DemoOriginServer", daemon=True)
    thread.start()
    origin_host, origin_port = server.server_address
    print(f"Demo origin server listening at http://{_connectable_host(origin_host)}:{origin_port}")
    print("PyQt demo panel opened on this machine.")

    try:
        run_demo_panel(
            server,
            args.proxy_host,
            args.proxy_port,
            Path(args.mitm_ca),
            args.mitm_target,
            args.mitm_path,
        )
    except KeyboardInterrupt:
        print("\nShutting down demo origin server...")
    except RuntimeError as exc:
        print(f"\n{exc}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
