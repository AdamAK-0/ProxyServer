"""PyQt admin panel for logs, cache entries, filters, and usage stats.

Contributor: Adam - desktop admin panel and live dashboard wiring.
External code: PyQt5 for the desktop UI.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from .access_control import AccessController
from .cache import ResponseCache
from .config import ProxyConfig
from .logger import RequestLogger
from .stats import ProxyStats


class AdminServer:
    """Controller shared by the PyQt admin panel and the live proxy runtime."""

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
        self.bound_port: int | None = None
        self._window: Any | None = None
        self._api_server: _AdminHTTPServer | None = None

    def run(self) -> int:
        """Open the native admin panel and block until the window closes."""

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

        app.setApplicationName("CSC 430 Proxy Admin")
        window_class = _create_admin_window_class(QtCore, QtWidgets)
        self._window = window_class(self)
        self._window.show()
        self._window.raise_()
        self._window.activateWindow()
        return app.exec_()

    def serve_forever(self) -> None:
        """Run the lightweight compatibility JSON API."""

        self._ensure_api_server()
        if self._api_server is not None:
            self._api_server.serve_forever(poll_interval=0.5)

    def start_in_thread(self) -> threading.Thread:
        """Start the compatibility JSON API in a daemon thread."""

        self._ensure_api_server()
        thread = threading.Thread(target=self.serve_forever, name="AdminApiServer", daemon=True)
        thread.start()
        return thread

    def shutdown(self) -> None:
        if self._api_server is not None:
            self._api_server.shutdown()
            self._api_server.server_close()
            self._api_server = None
        if self._window is not None:
            try:
                self._window.close()
            except RuntimeError:
                pass

    def dashboard_payload(self) -> dict[str, Any]:
        """Return all data needed for one UI refresh."""

        return {
            "stats": self.stats.snapshot(),
            "filters": self.access.snapshot(),
            "cache": self.cache.entries(),
            "logs": self.logger.tail(80),
        }

    def add_filter(self, list_name: str, pattern: str) -> None:
        if list_name not in {"blacklist", "whitelist"}:
            list_name = "blacklist"
        self.access.add(list_name, pattern)

    def remove_filter(self, list_name: str, pattern: str) -> None:
        if list_name in {"blacklist", "whitelist"}:
            self.access.remove(list_name, pattern)

    def set_whitelist_enabled(self, enabled: bool) -> None:
        self.access.set_whitelist_enabled(enabled)

    def clear_cache(self) -> None:
        self.cache.clear()

    def cleanup_cache(self) -> int:
        return self.cache.cleanup_expired()

    def delete_cache_entry(self, key: str) -> None:
        self.cache.delete(key)

    def clear_logs(self) -> None:
        self.logger.clear()

    def reset_stats(self) -> None:
        self.stats.reset_counters()

    def loop_warning(self, records: list[dict[str, Any]]) -> str:
        proxy_port = int(self.config.proxy_port)
        proxy_host = self.config.listen_host
        matches = [
            record
            for record in records
            if record.get("target_host") == proxy_host and int(record.get("target_port") or 0) == proxy_port
        ]
        if not matches:
            return ""
        return (
            f"{len(matches)} recent request(s) targeted the proxy itself at {proxy_host}:{proxy_port}. "
            "Use the PyQt admin panel for management, and bypass the proxy for local addresses."
        )

    def _ensure_api_server(self) -> None:
        if self._api_server is None:
            self._api_server = _AdminHTTPServer((self.config.admin_host, self.config.admin_port), _AdminApiHandler, self)
            self.bound_port = self._api_server.server_address[1]


class _AdminHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], handler_class: type[BaseHTTPRequestHandler], app: AdminServer) -> None:
        self.app = app
        super().__init__(server_address, handler_class)


class _AdminApiHandler(BaseHTTPRequestHandler):
    """Small compatibility API for tests and scripts; the UI itself is PyQt."""

    server: _AdminHTTPServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            self._send_text("CSC 430 admin API is running. Use the PyQt admin panel for the dashboard.\n")
            return
        if path == "/favicon.ico":
            self._send_empty("image/x-icon")
            return
        if path == "/api/dashboard":
            self._send_json(self.app.dashboard_payload())
            return
        if path == "/api/stats":
            self._send_json(self.app.stats.snapshot())
            return
        if path == "/api/logs":
            limit = self._safe_int(query.get("limit", ["200"])[0], default=200, minimum=1, maximum=500)
            self._send_json(self.app.logger.tail(limit))
            return
        if path == "/api/cache":
            self._send_json(self.app.cache.entries())
            return
        if path == "/api/filters":
            self._send_json(self.app.access.snapshot())
            return
        self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        form = self._read_form()
        path = urlparse(self.path).path
        if path == "/filters/add":
            self.app.add_filter(form.get("list", ["blacklist"])[0], form.get("pattern", [""])[0])
            self._finish_mutation()
            return
        if path == "/filters/remove":
            self.app.remove_filter(form.get("list", ["blacklist"])[0], form.get("pattern", [""])[0])
            self._finish_mutation()
            return
        if path == "/filters/toggle":
            self.app.set_whitelist_enabled(form.get("enabled", ["off"])[0] == "on")
            self._finish_mutation()
            return
        if path == "/cache/clear":
            self.app.clear_cache()
            self._finish_mutation()
            return
        if path == "/cache/cleanup":
            self.app.cleanup_cache()
            self._finish_mutation()
            return
        if path == "/cache/delete":
            self.app.delete_cache_entry(form.get("key", [""])[0])
            self._finish_mutation()
            return
        if path == "/logs/clear":
            self.app.clear_logs()
            self._finish_mutation()
            return
        if path == "/stats/reset":
            self.app.reset_stats()
            self._finish_mutation()
            return
        self.send_error(404, "Not Found")

    @property
    def app(self) -> AdminServer:
        return self.server.app

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _read_form(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return parse_qs(raw)

    def _finish_mutation(self) -> None:
        if self.headers.get("X-Requested-With") == "admin-fetch":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._redirect("/")

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_json(self, payload: Any) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_empty(self, content_type: str) -> None:
        self.send_response(204)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()

    @staticmethod
    def _safe_int(value: str, default: int, minimum: int, maximum: int) -> int:
        try:
            number = int(value)
        except ValueError:
            return default
        return min(max(number, minimum), maximum)


def _load_pyqt() -> tuple[Any, Any]:
    try:
        from PyQt5 import QtCore, QtWidgets
    except ImportError as exc:
        raise RuntimeError(
            "PyQt5 is required for the admin panel. Install it with: "
            "python -m pip install -r requirements.txt"
        ) from exc
    return QtCore, QtWidgets


def _create_admin_window_class(QtCore: Any, QtWidgets: Any) -> type[Any]:
    class AdminWindow(QtWidgets.QMainWindow):
        metric_order = [
            ("active_connections", "Active", "open sockets"),
            ("total_requests", "Total", "requests"),
            ("http_requests", "HTTP", "forwarded"),
            ("https_tunnels", "HTTPS", "CONNECT tunnels"),
            ("mitm_intercepts", "MITM", "decrypted HTTPS"),
            ("cache_hits", "Hits", "cache"),
            ("cache_misses", "Misses", "cache"),
            ("blocked_requests", "Blocked", "filters"),
            ("errors", "Errors", "logged"),
        ]

        def __init__(self, admin: AdminServer) -> None:
            super().__init__()
            self.admin = admin
            self.metric_values: dict[str, Any] = {}
            self._refreshing = False
            self._cache_keys: list[str] = []

            self.setWindowTitle("CSC 430 Proxy Admin")
            self.resize(1220, 820)
            self._build_ui()
            self._timer = QtCore.QTimer(self)
            self._timer.timeout.connect(self.refresh)
            self._timer.start(1500)
            self.refresh()

        def _build_ui(self) -> None:
            central = QtWidgets.QWidget(self)
            root = QtWidgets.QVBoxLayout(central)
            root.setContentsMargins(18, 16, 18, 12)
            root.setSpacing(14)
            self.setCentralWidget(central)

            title = QtWidgets.QLabel("CSC 430 Proxy Admin")
            title.setObjectName("title")
            service = QtWidgets.QLabel(
                f"Proxy {self.admin.config.listen_host}:{self.admin.config.proxy_port} | "
                f"Data {self.admin.config.data_dir}"
            )
            service.setObjectName("muted")
            header_text = QtWidgets.QVBoxLayout()
            header_text.addWidget(title)
            header_text.addWidget(service)

            self._pulse_on = False
            self.live_pill = QtWidgets.QFrame()
            self.live_pill.setObjectName("livePill")
            self.live_pill.setMaximumHeight(46)
            live_layout = QtWidgets.QHBoxLayout(self.live_pill)
            live_layout.setContentsMargins(12, 7, 12, 7)
            live_layout.setSpacing(9)
            self.live_dot = QtWidgets.QFrame()
            self.live_dot.setObjectName("pulseDot")
            self.live_dot.setProperty("pulseOn", True)
            self.live_dot.setFixedSize(10, 10)
            self.live_label = QtWidgets.QLabel("Live | Starting")
            self.live_label.setObjectName("liveText")
            live_layout.addWidget(self.live_dot)
            live_layout.addWidget(self.live_label)

            header = QtWidgets.QHBoxLayout()
            header.addLayout(header_text, 1)
            header.addWidget(self.live_pill, 0)
            root.addLayout(header)

            self.warning_label = QtWidgets.QLabel("")
            self.warning_label.setObjectName("warning")
            self.warning_label.setWordWrap(True)
            self.warning_label.hide()
            root.addWidget(self.warning_label)

            metrics = QtWidgets.QGridLayout()
            metrics.setSpacing(8)
            metric_columns = len(self.metric_order)
            for index, (key, label, detail) in enumerate(self.metric_order):
                card = QtWidgets.QFrame()
                card.setObjectName("metricCard")
                card.setMinimumHeight(58)
                card.setMaximumHeight(64)
                card_layout = QtWidgets.QVBoxLayout(card)
                card_layout.setContentsMargins(10, 6, 10, 6)
                card_layout.setSpacing(1)
                label_widget = QtWidgets.QLabel(label.upper())
                label_widget.setObjectName("metricLabel")
                value_widget = QtWidgets.QLabel("0")
                value_widget.setObjectName("metricValue")
                detail_widget = QtWidgets.QLabel(detail)
                detail_widget.setObjectName("metricDetail")
                card_layout.addWidget(label_widget)
                card_layout.addWidget(value_widget)
                card_layout.addWidget(detail_widget)
                self.metric_values[key] = value_widget
                metrics.addWidget(card, index // metric_columns, index % metric_columns)
            root.addLayout(metrics)

            splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
            splitter.addWidget(self._build_access_panel())
            splitter.addWidget(self._build_cache_panel())
            splitter.setStretchFactor(0, 1)
            splitter.setStretchFactor(1, 2)
            splitter.setChildrenCollapsible(False)
            root.addWidget(splitter, 3)
            root.addWidget(self._build_logs_panel(), 2)

            self.statusBar().showMessage("Ready")
            self.setStyleSheet(_admin_stylesheet())
            self._pulse_timer = QtCore.QTimer(self)
            self._pulse_timer.timeout.connect(self._toggle_live_pulse)
            self._pulse_timer.start(650)

        def _build_access_panel(self) -> Any:
            panel, layout = self._panel("Access Control")
            panel.setMinimumWidth(560)
            panel.setMinimumHeight(270)

            self.whitelist_check = QtWidgets.QCheckBox("Whitelist-only mode")
            self.whitelist_check.stateChanged.connect(self._toggle_whitelist)
            layout.addWidget(self.whitelist_check)

            add_row = QtWidgets.QHBoxLayout()
            add_row.setSpacing(8)
            self.rule_group = QtWidgets.QButtonGroup(self)
            self.rule_group.setExclusive(True)
            rule_picker = QtWidgets.QFrame()
            rule_picker.setObjectName("segmentedControl")
            rule_picker_layout = QtWidgets.QHBoxLayout(rule_picker)
            rule_picker_layout.setContentsMargins(2, 2, 2, 2)
            rule_picker_layout.setSpacing(2)
            self.blacklist_button = self._filter_choice_button("Blacklist", "blacklist")
            self.whitelist_button = self._filter_choice_button("Whitelist", "whitelist")
            self.blacklist_button.setChecked(True)
            self.rule_group.addButton(self.blacklist_button)
            self.rule_group.addButton(self.whitelist_button)
            rule_picker_layout.addWidget(self.blacklist_button)
            rule_picker_layout.addWidget(self.whitelist_button)
            self.rule_input = QtWidgets.QLineEdit()
            self.rule_input.setPlaceholderText("example.com, example.com:443, *.example.com, or 127.0.0.1:9000")
            add_button = QtWidgets.QPushButton("Add")
            add_button.clicked.connect(self._add_filter)
            self.rule_input.returnPressed.connect(self._add_filter)
            add_row.addWidget(rule_picker)
            add_row.addWidget(self.rule_input, 1)
            add_row.addWidget(add_button)
            layout.addLayout(add_row)

            hint = QtWidgets.QLabel("Rules accept domains, host:port, IP:port, wildcard domains, or full URL text.")
            hint.setObjectName("muted")
            hint.setWordWrap(True)
            layout.addWidget(hint)

            self.rules_tabs = QtWidgets.QTabWidget()
            self.blacklist_table = QtWidgets.QTableWidget()
            self.whitelist_table = QtWidgets.QTableWidget()
            self._setup_table(self.blacklist_table, ["Pattern", ""])
            self._setup_table(self.whitelist_table, ["Pattern", ""])
            self._size_rule_table(self.blacklist_table)
            self._size_rule_table(self.whitelist_table)
            self.blacklist_table.setMinimumHeight(150)
            self.whitelist_table.setMinimumHeight(150)
            self.rules_tabs.addTab(self.blacklist_table, "Blacklist")
            self.rules_tabs.addTab(self.whitelist_table, "Whitelist")
            self.blacklist_button.clicked.connect(lambda: self.rules_tabs.setCurrentIndex(0))
            self.whitelist_button.clicked.connect(lambda: self.rules_tabs.setCurrentIndex(1))
            self.rules_tabs.currentChanged.connect(self._sync_filter_choice_from_tab)
            layout.addWidget(self.rules_tabs, 1)
            return panel

        def _build_cache_panel(self) -> Any:
            panel, layout = self._panel("Cache")
            buttons = QtWidgets.QHBoxLayout()
            cleanup_button = QtWidgets.QPushButton("Clean Expired")
            cleanup_button.clicked.connect(self._cleanup_cache)
            self.delete_cache_button = QtWidgets.QPushButton("Delete Selected")
            self.delete_cache_button.clicked.connect(self._delete_selected_cache)
            self.delete_cache_button.setEnabled(False)
            clear_button = QtWidgets.QPushButton("Clear")
            clear_button.setObjectName("dangerButton")
            clear_button.clicked.connect(self._clear_cache)
            buttons.addWidget(cleanup_button)
            buttons.addWidget(self.delete_cache_button)
            buttons.addStretch(1)
            buttons.addWidget(clear_button)
            layout.addLayout(buttons)

            self.cache_table = QtWidgets.QTableWidget()
            self._setup_table(self.cache_table, ["Method", "Status", "Bytes", "Expires", "URL"])
            self.cache_table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
            self.cache_table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
            self.cache_table.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
            self.cache_table.horizontalHeader().setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
            self.cache_table.itemSelectionChanged.connect(self._update_cache_delete_button)
            layout.addWidget(self.cache_table, 1)
            return panel

        def _build_logs_panel(self) -> Any:
            panel, layout = self._panel("Recent Logs")
            buttons = QtWidgets.QHBoxLayout()
            refresh_button = QtWidgets.QPushButton("Refresh")
            refresh_button.clicked.connect(self.refresh)
            clear_button = QtWidgets.QPushButton("Clear Log")
            clear_button.setObjectName("dangerButton")
            clear_button.clicked.connect(self._clear_logs)
            reset_button = QtWidgets.QPushButton("Reset Counters")
            reset_button.clicked.connect(self._reset_stats)
            buttons.addWidget(refresh_button)
            buttons.addWidget(reset_button)
            buttons.addStretch(1)
            buttons.addWidget(clear_button)
            layout.addLayout(buttons)

            self.log_table = QtWidgets.QTableWidget()
            self._setup_table(
                self.log_table,
                ["Time", "Event", "Client", "Method", "URL", "Status", "Cache", "Message"],
            )
            self.log_table.setMinimumHeight(170)
            self._size_log_columns()
            layout.addWidget(self.log_table, 1)
            return panel

        def _panel(self, title: str) -> tuple[Any, Any]:
            group = QtWidgets.QGroupBox(title)
            layout = QtWidgets.QVBoxLayout(group)
            layout.setContentsMargins(12, 14, 12, 12)
            layout.setSpacing(10)
            return group, layout

        def _filter_choice_button(self, text: str, list_name: str) -> Any:
            button = QtWidgets.QPushButton(text)
            button.setObjectName("segmentButton")
            button.setCheckable(True)
            button.setProperty("filterList", list_name)
            button.setMinimumWidth(88)
            button.setCursor(QtCore.Qt.PointingHandCursor)
            return button

        def _sync_filter_choice_from_tab(self, index: int) -> None:
            if index == 0:
                self.blacklist_button.setChecked(True)
            elif index == 1:
                self.whitelist_button.setChecked(True)

        def _size_rule_table(self, table: Any) -> None:
            header = table.horizontalHeader()
            header.setStretchLastSection(False)
            header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
            header.setSectionResizeMode(1, QtWidgets.QHeaderView.Fixed)
            table.setColumnWidth(1, 86)

        def _toggle_live_pulse(self) -> None:
            self._pulse_on = not self._pulse_on
            self.live_dot.setProperty("pulseOn", self._pulse_on)
            self.live_dot.style().unpolish(self.live_dot)
            self.live_dot.style().polish(self.live_dot)
            self.live_dot.update()

        def _setup_table(self, table: Any, columns: list[str]) -> None:
            table.setColumnCount(len(columns))
            table.setHorizontalHeaderLabels(columns)
            table.setAlternatingRowColors(True)
            table.setShowGrid(False)
            table.setWordWrap(False)
            table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
            table.verticalHeader().setVisible(False)
            table.verticalHeader().setDefaultSectionSize(34)
            table.horizontalHeader().setStretchLastSection(True)
            table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
            table.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
            table.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)

        def _size_log_columns(self) -> None:
            header = self.log_table.horizontalHeader()
            widths = {
                0: 86,
                1: 148,
                2: 132,
                3: 76,
                5: 72,
                6: 74,
                7: 260,
            }
            for column, width in widths.items():
                header.setSectionResizeMode(column, QtWidgets.QHeaderView.Interactive)
                self.log_table.setColumnWidth(column, width)
            header.setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)

        def refresh(self) -> None:
            self._refreshing = True
            payload = self.admin.dashboard_payload()
            self._render_stats(payload["stats"])
            self._render_filters(payload["filters"])
            self._render_cache(payload["cache"])
            self._render_logs(payload["logs"])
            self._render_loop_warning(payload["logs"])
            self.live_label.setText(f"Live | {datetime.now().strftime('%H:%M:%S')}")
            self.statusBar().showMessage("Dashboard refreshed")
            self._refreshing = False

        def _render_stats(self, stats: dict[str, Any]) -> None:
            for key, value_widget in self.metric_values.items():
                value_widget.setText(_format_number(stats.get(key, 0)))

        def _render_filters(self, filters: dict[str, Any]) -> None:
            self.whitelist_check.blockSignals(True)
            self.whitelist_check.setChecked(bool(filters.get("whitelist_enabled")))
            self.whitelist_check.blockSignals(False)
            self._render_rule_table(self.blacklist_table, "blacklist", filters.get("blacklist", []))
            self._render_rule_table(self.whitelist_table, "whitelist", filters.get("whitelist", []))
            self.rules_tabs.setTabText(0, f"Blacklist ({len(filters.get('blacklist', []))})")
            self.rules_tabs.setTabText(1, f"Whitelist ({len(filters.get('whitelist', []))})")

        def _render_rule_table(self, table: Any, list_name: str, rules: list[str]) -> None:
            table.setRowCount(0)
            table.clearSpans()
            if not rules:
                table.setRowCount(1)
                item = QtWidgets.QTableWidgetItem("No rules yet")
                table.setItem(0, 0, item)
                table.setSpan(0, 0, 1, 2)
                table.setRowHeight(0, 42)
                table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
                table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.Fixed)
                table.setColumnWidth(1, 86)
                return

            table.setRowCount(len(rules))
            for row, rule in enumerate(rules):
                item = QtWidgets.QTableWidgetItem(rule)
                item.setToolTip(rule)
                table.setItem(row, 0, item)
                button = QtWidgets.QPushButton("Remove")
                button.setObjectName("removeRuleButton")
                button.setFixedSize(70, 26)
                button.clicked.connect(
                    lambda _checked=False, selected_list=list_name, selected_rule=rule: self._remove_filter(
                        selected_list,
                        selected_rule,
                    )
                )
                table.setCellWidget(row, 1, self._centered_table_widget(button))
                table.setRowHeight(row, 34)
            table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
            table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.Fixed)
            table.setColumnWidth(1, 86)

        def _centered_table_widget(self, widget: Any) -> Any:
            wrapper = QtWidgets.QWidget()
            wrapper.setObjectName("cellButtonWrap")
            layout = QtWidgets.QHBoxLayout(wrapper)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)
            layout.addWidget(widget, 0, QtCore.Qt.AlignCenter)
            return wrapper

        def _render_cache(self, entries: list[dict[str, Any]]) -> None:
            self._cache_keys = [str(entry.get("key", "")) for entry in entries]
            self.cache_table.setRowCount(len(entries))
            for row, entry in enumerate(entries):
                values = [
                    entry.get("method", ""),
                    entry.get("status_code", ""),
                    _format_number(entry.get("size", 0)),
                    f"{entry.get('expires_in_seconds', 0)}s",
                    entry.get("url", ""),
                ]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(str(value))
                    item.setToolTip(str(value))
                    self.cache_table.setItem(row, column, item)
                self.cache_table.setRowHeight(row, 34)
            self.cache_table.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
            self._update_cache_delete_button()

        def _render_logs(self, records: list[dict[str, Any]]) -> None:
            rows = list(reversed(records))[:80]
            self.log_table.setRowCount(len(rows))
            for row, record in enumerate(rows):
                values = [
                    _format_time(record.get("timestamp")),
                    record.get("event", ""),
                    self._client_text(record),
                    record.get("method", ""),
                    record.get("url") or record.get("target_host", ""),
                    record.get("status_code", ""),
                    record.get("cache_result", ""),
                    record.get("error") or record.get("reason", ""),
                ]
                for column, value in enumerate(values):
                    text = str(value)
                    item = QtWidgets.QTableWidgetItem(text)
                    item.setToolTip(text)
                    self.log_table.setItem(row, column, item)
                event_text = str(record.get("event", ""))
                cache_text = str(record.get("cache_result", ""))
                status_text = str(record.get("status_code", ""))
                self.log_table.setCellWidget(row, 1, self._badge_label(event_text, self._event_tone(event_text)))
                self.log_table.setCellWidget(row, 5, self._badge_label(status_text, self._status_tone(status_text)))
                self.log_table.setCellWidget(row, 6, self._badge_label(cache_text, self._cache_tone(cache_text)))
                self.log_table.setRowHeight(row, 34)
            self._size_log_columns()

        def _badge_label(self, text: str, tone: str) -> Any:
            label = QtWidgets.QLabel(text)
            label.setAlignment(QtCore.Qt.AlignCenter)
            label.setToolTip(text)
            label.setObjectName(f"{tone}Badge")
            label.setMinimumHeight(22)
            label.setContentsMargins(6, 2, 6, 2)
            return label

        @staticmethod
        def _event_tone(event: str) -> str:
            if event == "request-error" or event == "corrupt-log-line":
                return "error"
            if event == "request-blocked":
                return "warn"
            if event == "request-complete":
                return "ok"
            if event == "proxy-started":
                return "info"
            if event == "proxy-stopped":
                return "neutral"
            return "neutral"

        @staticmethod
        def _cache_tone(cache_result: str) -> str:
            if cache_result == "HIT":
                return "ok"
            if cache_result == "MISS":
                return "warn"
            if cache_result == "BYPASS":
                return "neutral"
            return "empty"

        @staticmethod
        def _status_tone(status_code: str) -> str:
            try:
                status = int(status_code)
            except ValueError:
                return "empty"
            if status >= 500:
                return "error"
            if status >= 400:
                return "warn"
            if status >= 200:
                return "ok"
            return "neutral"

        def _render_loop_warning(self, records: list[dict[str, Any]]) -> None:
            warning = self.admin.loop_warning(records)
            self.warning_label.setText(warning)
            self.warning_label.setVisible(bool(warning))

        def _add_filter(self) -> None:
            pattern = self.rule_input.text().strip()
            if not pattern:
                self.statusBar().showMessage("Enter a filter rule first")
                return
            selected_button = self.rule_group.checkedButton()
            list_name = str(selected_button.property("filterList") if selected_button is not None else "blacklist")
            self._run_action(lambda: self.admin.add_filter(list_name, pattern), "Filter rule added")
            self.rule_input.clear()

        def _remove_filter(self, list_name: str, pattern: str) -> None:
            self._run_action(lambda: self.admin.remove_filter(list_name, pattern), "Filter rule removed")

        def _toggle_whitelist(self, state: int) -> None:
            if self._refreshing:
                return
            enabled = state == QtCore.Qt.Checked
            self._run_action(lambda: self.admin.set_whitelist_enabled(enabled), "Whitelist mode updated")

        def _cleanup_cache(self) -> None:
            try:
                removed = self.admin.cleanup_cache()
                self.refresh()
                self.statusBar().showMessage(f"Removed {removed} expired cache entr{'y' if removed == 1 else 'ies'}")
            except Exception as exc:
                self.statusBar().showMessage(f"Cache cleanup failed: {exc}")

        def _clear_cache(self) -> None:
            if self._confirm("Clear all cached responses?"):
                self._run_action(self.admin.clear_cache, "Cache cleared")

        def _delete_selected_cache(self) -> None:
            selected = self.cache_table.selectionModel().selectedRows()
            if not selected:
                return
            row = selected[0].row()
            if 0 <= row < len(self._cache_keys):
                key = self._cache_keys[row]
                self._run_action(lambda: self.admin.delete_cache_entry(key), "Cache entry deleted")

        def _clear_logs(self) -> None:
            if self._confirm("Clear the proxy log?"):
                self._run_action(self.admin.clear_logs, "Log cleared")

        def _reset_stats(self) -> None:
            self._run_action(self.admin.reset_stats, "Counters reset")

        def _update_cache_delete_button(self) -> None:
            self.delete_cache_button.setEnabled(bool(self.cache_table.selectionModel().selectedRows()))

        def _run_action(self, action: Callable[[], Any], success: str) -> None:
            try:
                action()
                self.refresh()
                self.statusBar().showMessage(success)
            except Exception as exc:
                self.statusBar().showMessage(f"Action failed: {exc}")

        def _confirm(self, message: str) -> bool:
            reply = QtWidgets.QMessageBox.question(
                self,
                "Confirm",
                message,
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            return reply == QtWidgets.QMessageBox.Yes

        @staticmethod
        def _client_text(record: dict[str, Any]) -> str:
            if not record.get("client_ip"):
                return ""
            return f"{record.get('client_ip')}:{record.get('client_port', '')}"

    return AdminWindow


def _format_number(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def _format_time(value: Any) -> str:
    if not value:
        return ""
    try:
        return datetime.fromisoformat(str(value)).strftime("%H:%M:%S")
    except ValueError:
        return str(value)


def _admin_stylesheet() -> str:
    return """
        QMainWindow, QWidget {
            background: #eef2f6;
            color: #111827;
            font-family: Segoe UI, Arial, sans-serif;
            font-size: 10pt;
        }
        QLabel {
            background: transparent;
        }
        QLabel#title {
            color: #0f172a;
            font-size: 20pt;
            font-weight: 700;
        }
        QLabel#muted, QLabel#metricDetail, QLabel#metricLabel {
            color: #64748b;
        }
        QFrame#livePill {
            background: #0b7a75;
            border-radius: 6px;
        }
        QLabel#liveText {
            color: white;
            font-size: 9pt;
            font-weight: 700;
        }
        QFrame#pulseDot {
            background: #9ee7ff;
            border: 2px solid rgba(255, 255, 255, 0.70);
            border-radius: 5px;
        }
        QFrame#pulseDot[pulseOn="true"] {
            background: #38bdf8;
            border: 2px solid rgba(255, 255, 255, 0.92);
        }
        QFrame#pulseDot[pulseOn="false"] {
            background: #7dd3fc;
            border: 2px solid rgba(255, 255, 255, 0.45);
        }
        QLabel#warning {
            background: #fff8e6;
            border: 1px solid #f7d57a;
            border-radius: 6px;
            color: #633f04;
            padding: 10px;
        }
        QFrame#metricCard, QGroupBox {
            background: white;
            border: 1px solid #d9e0ea;
            border-radius: 8px;
        }
        QFrame#metricCard QLabel, QGroupBox QLabel, QCheckBox {
            background: transparent;
        }
        QWidget#cellButtonWrap {
            background: transparent;
        }
        QLabel#metricLabel {
            font-size: 7pt;
            font-weight: 700;
        }
        QLabel#metricValue {
            color: #111827;
            font-size: 13pt;
            font-weight: 700;
        }
        QLabel#metricDetail {
            font-size: 8pt;
        }
        QGroupBox {
            margin-top: 10px;
            padding-top: 8px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
            font-weight: 700;
        }
        QPushButton {
            background: #0b7a75;
            color: white;
            border: 0;
            border-radius: 6px;
            padding: 8px 12px;
            font-weight: 700;
            min-height: 28px;
        }
        QPushButton:hover {
            background: #075e5a;
        }
        QPushButton:disabled {
            background: #cbd5e1;
            color: #64748b;
        }
        QPushButton#dangerButton {
            background: #b42318;
        }
        QPushButton#dangerButton:hover {
            background: #911c13;
        }
        QPushButton#removeRuleButton {
            background: #b42318;
            color: white;
            border: 0;
            border-radius: 5px;
            padding: 3px 8px;
            font-size: 8pt;
            font-weight: 700;
            min-height: 0;
        }
        QPushButton#removeRuleButton:hover {
            background: #911c13;
        }
        QFrame#segmentedControl {
            background: #e7edf3;
            border: 1px solid #cbd5e1;
            border-radius: 7px;
        }
        QPushButton#segmentButton {
            background: transparent;
            color: #475467;
            border: 0;
            border-radius: 5px;
            padding: 7px 11px;
            min-height: 30px;
            font-weight: 700;
        }
        QPushButton#segmentButton:hover {
            background: #dbe5ef;
            color: #111827;
        }
        QPushButton#segmentButton:checked {
            background: white;
            color: #0b7a75;
            border: 1px solid #b6c6d6;
        }
        QLineEdit {
            background: white;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 7px 9px;
            min-height: 28px;
        }
        QTableWidget {
            background: white;
            alternate-background-color: #f7fafc;
            border: 1px solid #d9e0ea;
            border-radius: 6px;
            gridline-color: #d9e0ea;
            selection-background-color: #dbeafe;
            selection-color: #111827;
        }
        QTableWidget::item {
            padding: 6px 4px;
            border-bottom: 1px solid #edf2f7;
        }
        QTableWidget::item:selected {
            background: #dbeafe;
            color: #111827;
        }
        QLabel#okBadge {
            background: #dcfae6;
            color: #087443;
            border: 1px solid #a6efc4;
            border-radius: 10px;
            font-size: 8pt;
            font-weight: 700;
        }
        QLabel#warnBadge {
            background: #fff4d6;
            color: #b54708;
            border: 1px solid #f7d57a;
            border-radius: 10px;
            font-size: 8pt;
            font-weight: 700;
        }
        QLabel#errorBadge {
            background: #fee4e2;
            color: #b42318;
            border: 1px solid #fecdca;
            border-radius: 10px;
            font-size: 8pt;
            font-weight: 700;
        }
        QLabel#infoBadge {
            background: #dbeafe;
            color: #175cd3;
            border: 1px solid #bfdbfe;
            border-radius: 10px;
            font-size: 8pt;
            font-weight: 700;
        }
        QLabel#neutralBadge {
            background: #e7edf3;
            color: #475467;
            border: 1px solid #cbd5e1;
            border-radius: 10px;
            font-size: 8pt;
            font-weight: 700;
        }
        QLabel#emptyBadge {
            background: transparent;
            color: #94a3b8;
            border: 0;
            font-size: 8pt;
            font-weight: 700;
        }
        QHeaderView::section {
            background: #e7edf3;
            color: #344054;
            padding: 7px 8px;
            border: 0;
            border-right: 1px solid #d9e0ea;
            font-weight: 700;
        }
        QScrollBar:vertical {
            background: #f1f5f9;
            width: 12px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background: #94a3b8;
            border-radius: 5px;
            min-height: 24px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }
        QScrollBar:horizontal {
            background: #f1f5f9;
            height: 12px;
            margin: 0;
        }
        QScrollBar::handle:horizontal {
            background: #94a3b8;
            border-radius: 5px;
            min-width: 24px;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0;
        }
        QTabWidget::pane {
            border: 1px solid #d9e0ea;
            background: white;
            border-radius: 6px;
        }
        QTabBar::tab {
            background: #e7edf3;
            padding: 7px 12px;
            margin-right: 2px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
        }
        QTabBar::tab:selected {
            background: white;
            color: #0b7a75;
        }
    """
