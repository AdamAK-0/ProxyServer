"""Web admin interface for logs, cache entries, filters, and usage stats.

Contributor: Adam - admin HTTP server and live dashboard.
External code: none; standard library only.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .access_control import AccessController
from .cache import ResponseCache
from .config import ProxyConfig
from .logger import RequestLogger
from .stats import ProxyStats


class AdminServer:
    """Small web server that exposes proxy management pages and JSON endpoints."""

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
        self._server = _AdminHTTPServer((config.admin_host, config.admin_port), AdminHandler, self)
        self.bound_port = self._server.server_address[1]

    def serve_forever(self) -> None:
        self._server.serve_forever(poll_interval=0.5)

    def start_in_thread(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="AdminServer", daemon=True)
        thread.start()
        return thread

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class _AdminHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], handler_class: type[BaseHTTPRequestHandler], app: AdminServer) -> None:
        self.app = app
        super().__init__(server_address, handler_class)


class AdminHandler(BaseHTTPRequestHandler):
    """Handles HTML pages, JSON APIs, and dashboard form posts."""

    server: _AdminHTTPServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            self._send_html(self._render_dashboard())
            return
        if path == "/favicon.ico":
            self._send_empty("image/x-icon")
            return
        if path == "/api/dashboard":
            self._send_json(self._dashboard_payload())
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
            list_name = form.get("list", ["blacklist"])[0]
            pattern = form.get("pattern", [""])[0]
            if list_name not in {"blacklist", "whitelist"}:
                list_name = "blacklist"
            self.app.access.add(list_name, pattern)
            self._finish_mutation()
            return
        if path == "/filters/remove":
            list_name = form.get("list", ["blacklist"])[0]
            pattern = form.get("pattern", [""])[0]
            if list_name in {"blacklist", "whitelist"}:
                self.app.access.remove(list_name, pattern)
            self._finish_mutation()
            return
        if path == "/filters/toggle":
            self.app.access.set_whitelist_enabled(form.get("enabled", ["off"])[0] == "on")
            self._finish_mutation()
            return
        if path == "/cache/clear":
            self.app.cache.clear()
            self._finish_mutation()
            return
        if path == "/cache/cleanup":
            self.app.cache.cleanup_expired()
            self._finish_mutation()
            return
        if path == "/cache/delete":
            self.app.cache.delete(form.get("key", [""])[0])
            self._finish_mutation()
            return
        if path == "/logs/clear":
            self.app.logger.clear()
            self._finish_mutation()
            return
        if path == "/stats/reset":
            self.app.stats.reset_counters()
            self._finish_mutation()
            return
        self.send_error(404, "Not Found")

    @property
    def app(self) -> AdminServer:
        return self.server.app

    def log_message(self, format: str, *args: Any) -> None:
        """Silence default access logging; proxy logs are shown in the dashboard."""

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

    def _send_html(self, page: str) -> None:
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_empty(self, content_type: str) -> None:
        self.send_response(204)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "max-age=86400")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dashboard_payload(self) -> dict[str, Any]:
        return {
            "stats": self.app.stats.snapshot(),
            "filters": self.app.access.snapshot(),
            "cache": self.app.cache.entries(),
            "logs": self.app.logger.tail(80),
        }

    @staticmethod
    def _safe_int(value: str, default: int, minimum: int, maximum: int) -> int:
        try:
            number = int(value)
        except ValueError:
            return default
        return min(max(number, minimum), maximum)

    def _render_dashboard(self) -> str:
        config_json = json.dumps(
            {
                "proxyHost": self.app.config.listen_host,
                "proxyPort": self.app.config.proxy_port,
                "adminHost": self.app.config.admin_host,
                "adminPort": self.app.bound_port,
            }
        )
        page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CSC 430 Proxy Admin</title>
  <style>
    :root {
      color-scheme: light;
      --page: #eef2f6;
      --surface: #ffffff;
      --ink: #111827;
      --muted: #667085;
      --line: #d9e0ea;
      --accent: #0b7a75;
      --accent-strong: #075e5a;
      --danger: #b42318;
      --warn: #b54708;
      --ok: #087443;
      --code: #172033;
      --row: #f8fafc;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Arial, Helvetica, sans-serif;
      color: var(--ink);
      background: var(--page);
    }
    button, input, select {
      font: inherit;
    }
    button {
      min-height: 36px;
      border: 0;
      border-radius: 6px;
      padding: 8px 12px;
      background: var(--accent);
      color: white;
      font-weight: 700;
      cursor: pointer;
    }
    button:hover { background: var(--accent-strong); }
    button.secondary {
      background: #e7edf3;
      color: var(--ink);
    }
    button.secondary:hover { background: #d7e1eb; }
    button.danger { background: var(--danger); }
    button.danger:hover { background: #911c13; }
    input, select {
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      background: white;
      color: var(--ink);
    }
    .shell {
      min-height: 100vh;
    }
    .topbar {
      background: #16202f;
      color: white;
      border-bottom: 4px solid var(--accent);
    }
    .topbar-inner {
      width: min(1280px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 22px 0;
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: center;
    }
    .brand h1 {
      margin: 0 0 5px;
      font-size: 26px;
      letter-spacing: 0;
    }
    .brand p {
      margin: 0;
      color: #cbd5e1;
      font-size: 14px;
    }
    .live-pill {
      display: flex;
      align-items: center;
      gap: 10px;
      border: 1px solid rgba(255, 255, 255, 0.22);
      border-radius: 999px;
      padding: 9px 12px;
      min-width: 230px;
      justify-content: center;
      color: #dbeafe;
      background: rgba(255, 255, 255, 0.08);
    }
    .pulse {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: #38bdf8;
      box-shadow: 0 0 0 5px rgba(56, 189, 248, 0.14);
      flex: 0 0 auto;
    }
    main {
      width: min(1280px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 22px 0 34px;
      display: grid;
      gap: 18px;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }
    .metric {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 15px;
      min-height: 98px;
      display: grid;
      align-content: space-between;
    }
    .metric span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.03em;
    }
    .metric strong {
      display: block;
      margin-top: 8px;
      font-size: 28px;
      letter-spacing: 0;
      overflow-wrap: anywhere;
    }
    .metric small {
      display: block;
      margin-top: 6px;
      color: var(--muted);
      overflow-wrap: anywhere;
    }
    .panel-grid {
      display: grid;
      grid-template-columns: minmax(320px, 0.75fr) minmax(0, 1.25fr);
      gap: 18px;
      align-items: start;
    }
    .panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    .panel-head {
      min-height: 58px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .panel-head h2 {
      margin: 0;
      font-size: 18px;
      letter-spacing: 0;
    }
    .panel-body {
      padding: 16px;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .add-rule {
      display: grid;
      grid-template-columns: 145px minmax(160px, 1fr) auto;
      gap: 8px;
      margin-bottom: 14px;
    }
    .toggle-line {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--row);
    }
    .switch {
      position: relative;
      width: 52px;
      height: 28px;
      flex: 0 0 52px;
    }
    .switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }
    .slider {
      position: absolute;
      cursor: pointer;
      inset: 0;
      background: #cbd5e1;
      border-radius: 999px;
      transition: background 0.15s ease;
    }
    .slider::before {
      content: "";
      position: absolute;
      width: 22px;
      height: 22px;
      left: 3px;
      top: 3px;
      background: white;
      border-radius: 50%;
      transition: transform 0.15s ease;
      box-shadow: 0 1px 4px rgba(15, 23, 42, 0.28);
    }
    .switch input:checked + .slider {
      background: var(--accent);
    }
    .switch input:checked + .slider::before {
      transform: translateX(24px);
    }
    .rules {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    .rule-list h3 {
      margin: 0 0 8px;
      font-size: 14px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .rule-item {
      min-height: 42px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 7px 8px;
      margin-bottom: 8px;
      background: white;
    }
    .rule-item code {
      color: var(--code);
      overflow-wrap: anywhere;
    }
    .empty {
      margin: 0;
      min-height: 42px;
      display: grid;
      align-items: center;
      color: var(--muted);
      border: 1px dashed var(--line);
      border-radius: 7px;
      padding: 10px;
    }
    .table-wrap {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px 9px;
      vertical-align: top;
      text-align: left;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      background: var(--row);
    }
    td {
      overflow-wrap: anywhere;
    }
    .badge {
      display: inline-flex;
      min-height: 24px;
      align-items: center;
      border-radius: 999px;
      padding: 3px 8px;
      background: #e7edf3;
      color: #344054;
      font-weight: 700;
      font-size: 12px;
      white-space: nowrap;
    }
    .badge.hit, .badge.ok { background: #dcfae6; color: var(--ok); }
    .badge.miss, .badge.warn { background: #fff4d6; color: var(--warn); }
    .badge.error { background: #fee4e2; color: var(--danger); }
    .log-url {
      max-width: 420px;
    }
    .system-note {
      background: #fff8e6;
      border: 1px solid #f7d57a;
      color: #633f04;
      border-radius: 8px;
      padding: 12px 14px;
      display: none;
    }
    .system-note.show {
      display: block;
    }
    @media (max-width: 980px) {
      .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .panel-grid { grid-template-columns: 1fr; }
      .topbar-inner { align-items: flex-start; flex-direction: column; }
      .live-pill { min-width: 0; }
    }
    @media (max-width: 680px) {
      .summary-grid { grid-template-columns: 1fr; }
      .add-rule { grid-template-columns: 1fr; }
      .rules { grid-template-columns: 1fr; }
      .panel-head { align-items: flex-start; flex-direction: column; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="topbar-inner">
        <div class="brand">
          <h1>CSC 430 Proxy Admin</h1>
          <p id="service-line"></p>
        </div>
        <div class="live-pill">
          <span class="pulse" aria-hidden="true"></span>
          <span id="live-status">Connecting</span>
        </div>
      </div>
    </header>
    <main>
      <div id="loop-warning" class="system-note"></div>
      <section class="panel">
        <div class="panel-head">
          <h2>Traffic Counters</h2>
          <div class="toolbar">
            <form class="js-action" action="/stats/reset" method="post">
              <button class="secondary" type="submit">Reset Counters</button>
            </form>
          </div>
        </div>
        <div class="panel-body">
          <div class="summary-grid" id="metrics"></div>
        </div>
      </section>
      <section class="panel-grid">
        <div class="panel">
          <div class="panel-head">
            <h2>Access Control</h2>
          </div>
          <div class="panel-body">
            <form class="toggle-line js-action" action="/filters/toggle" method="post">
              <strong>Whitelist-only mode</strong>
              <label class="switch">
                <input id="whitelist-enabled" type="checkbox" name="enabled" value="on">
                <span class="slider"></span>
              </label>
            </form>
            <form class="add-rule js-action" action="/filters/add" method="post">
              <select name="list" aria-label="Filter list">
                <option value="blacklist">Blacklist</option>
                <option value="whitelist">Whitelist</option>
              </select>
              <input type="text" name="pattern" placeholder="example.com or 127.0.0.1" required>
              <button type="submit">Add</button>
            </form>
            <div class="rules">
              <div class="rule-list">
                <h3>Blacklist</h3>
                <div id="blacklist"></div>
              </div>
              <div class="rule-list">
                <h3>Whitelist</h3>
                <div id="whitelist"></div>
              </div>
            </div>
          </div>
        </div>
        <div class="panel">
          <div class="panel-head">
            <h2>Cache</h2>
            <div class="toolbar">
              <form class="js-action" action="/cache/cleanup" method="post">
                <button class="secondary" type="submit">Clean Expired</button>
              </form>
              <form class="js-action" action="/cache/clear" method="post">
                <button class="danger" type="submit">Clear</button>
              </form>
            </div>
          </div>
          <div class="panel-body" id="cache"></div>
        </div>
      </section>
      <section class="panel">
        <div class="panel-head">
          <h2>Recent Logs</h2>
          <div class="toolbar">
            <button class="secondary" type="button" id="refresh-now">Refresh</button>
            <form class="js-action" action="/logs/clear" method="post">
              <button class="danger" type="submit">Clear Log</button>
            </form>
          </div>
        </div>
        <div class="panel-body" id="logs"></div>
      </section>
    </main>
  </div>
  <script>
    window.ADMIN_CONFIG = __ADMIN_CONFIG__;

    const state = {
      refreshMs: 1500,
      timer: null,
      busy: false,
      lastPayload: null
    };

    const metricOrder = [
      ["active_connections", "Active", "open sockets"],
      ["total_requests", "Total", "requests"],
      ["http_requests", "HTTP", "forwarded"],
      ["https_tunnels", "HTTPS", "CONNECT tunnels"],
      ["mitm_intercepts", "MITM", "decrypted HTTPS"],
      ["cache_hits", "Hits", "cache"],
      ["cache_misses", "Misses", "cache"],
      ["blocked_requests", "Blocked", "filters"],
      ["errors", "Errors", "logged"]
    ];

    document.getElementById("service-line").textContent =
      `Proxy ${ADMIN_CONFIG.proxyHost}:${ADMIN_CONFIG.proxyPort} | Admin ${ADMIN_CONFIG.adminHost}:${ADMIN_CONFIG.adminPort}`;

    document.addEventListener("submit", async (event) => {
      const form = event.target.closest(".js-action");
      if (!form) {
        return;
      }
      event.preventDefault();
      await submitAction(form);
    });

    document.getElementById("whitelist-enabled").addEventListener("change", async (event) => {
      await submitAction(event.target.closest("form"));
    });

    document.getElementById("refresh-now").addEventListener("click", () => refreshDashboard());

    async function submitAction(form) {
      const body = new FormData(form);
      await fetch(form.action, {
        method: "POST",
        body,
        headers: { "X-Requested-With": "admin-fetch" }
      });
      if (form.classList.contains("add-rule")) {
        form.reset();
      }
      await refreshDashboard();
    }

    async function refreshDashboard() {
      if (state.busy) {
        return;
      }
      state.busy = true;
      try {
        const response = await fetch("/api/dashboard", { cache: "no-store" });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const payload = await response.json();
        state.lastPayload = payload;
        render(payload);
        setLiveStatus("Live", false);
      } catch (error) {
        setLiveStatus(`Offline: ${error.message}`, true);
      } finally {
        state.busy = false;
      }
    }

    function render(payload) {
      renderMetrics(payload.stats);
      renderFilters(payload.filters);
      renderCache(payload.cache);
      renderLogs(payload.logs);
      renderLoopWarning(payload.logs);
    }

    function renderMetrics(stats) {
      const metrics = document.getElementById("metrics");
      metrics.innerHTML = metricOrder.map(([key, label, detail]) => `
        <article class="metric">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(formatNumber(stats[key] ?? 0))}</strong>
          <small>${escapeHtml(detail)}</small>
        </article>
      `).join("");
    }

    function renderFilters(filters) {
      document.getElementById("whitelist-enabled").checked = Boolean(filters.whitelist_enabled);
      renderRuleList("blacklist", filters.blacklist || []);
      renderRuleList("whitelist", filters.whitelist || []);
    }

    function renderRuleList(id, rules) {
      const target = document.getElementById(id);
      if (!rules.length) {
        target.innerHTML = `<p class="empty">No ${escapeHtml(id)} rules</p>`;
        return;
      }
      target.innerHTML = rules.map((rule) => `
        <div class="rule-item">
          <code>${escapeHtml(rule)}</code>
          <form class="js-action" action="/filters/remove" method="post">
            <input type="hidden" name="list" value="${escapeAttr(id)}">
            <input type="hidden" name="pattern" value="${escapeAttr(rule)}">
            <button class="danger" type="submit">Remove</button>
          </form>
        </div>
      `).join("");
    }

    function renderCache(entries) {
      const cache = document.getElementById("cache");
      if (!entries.length) {
        cache.innerHTML = `<p class="empty">Cache is empty</p>`;
        return;
      }
      const rows = entries.map((entry) => `
        <tr>
          <td><span class="badge ok">${escapeHtml(entry.method)}</span></td>
          <td>${escapeHtml(String(entry.status_code))}</td>
          <td>${escapeHtml(formatNumber(entry.size))}</td>
          <td>${escapeHtml(String(entry.expires_in_seconds))}s</td>
          <td>${escapeHtml(entry.url)}</td>
          <td>
            <form class="js-action" action="/cache/delete" method="post">
              <input type="hidden" name="key" value="${escapeAttr(entry.key)}">
              <button class="danger" type="submit">Delete</button>
            </form>
          </td>
        </tr>
      `).join("");
      cache.innerHTML = `
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Method</th><th>Status</th><th>Bytes</th><th>Expires</th><th>URL</th><th></th></tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
    }

    function renderLogs(records) {
      const logs = document.getElementById("logs");
      if (!records.length) {
        logs.innerHTML = `<p class="empty">No log records yet</p>`;
        return;
      }
      const rows = [...records].reverse().slice(0, 80).map((record) => {
        const eventClass = record.event === "request-error" ? "error" : "ok";
        const cacheClass = record.cache_result === "HIT" ? "hit" : record.cache_result === "MISS" ? "miss" : "";
        return `
          <tr>
            <td>${escapeHtml(formatTime(record.timestamp))}</td>
            <td><span class="badge ${eventClass}">${escapeHtml(record.event || "")}</span></td>
            <td>${escapeHtml(clientText(record))}</td>
            <td>${escapeHtml(record.method || "")}</td>
            <td class="log-url">${escapeHtml(record.url || record.target_host || "")}</td>
            <td>${escapeHtml(String(record.status_code || ""))}</td>
            <td><span class="badge ${cacheClass}">${escapeHtml(record.cache_result || "")}</span></td>
            <td>${escapeHtml(record.error || record.reason || "")}</td>
          </tr>
        `;
      }).join("");
      logs.innerHTML = `
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Time</th><th>Event</th><th>Client</th><th>Method</th><th>URL</th><th>Status</th><th>Cache</th><th>Message</th></tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
    }

    function renderLoopWarning(records) {
      const warning = document.getElementById("loop-warning");
      const selfRequests = records.filter((record) =>
        record.target_host === ADMIN_CONFIG.proxyHost &&
        Number(record.target_port) === Number(ADMIN_CONFIG.proxyPort)
      );
      if (!selfRequests.length) {
        warning.classList.remove("show");
        warning.textContent = "";
        return;
      }
      warning.textContent =
        `Log check: ${selfRequests.length} recent request(s) targeted the proxy itself at ${ADMIN_CONFIG.proxyHost}:${ADMIN_CONFIG.proxyPort}. Open the admin panel on port ${ADMIN_CONFIG.adminPort}, and bypass the proxy for local addresses.`;
      warning.classList.add("show");
    }

    function setLiveStatus(text, failed) {
      const status = document.getElementById("live-status");
      status.textContent = `${text} | ${new Date().toLocaleTimeString()}`;
      document.querySelector(".pulse").style.background = failed ? "#f97316" : "#38bdf8";
    }

    function clientText(record) {
      if (!record.client_ip) {
        return "";
      }
      return `${record.client_ip}:${record.client_port || ""}`;
    }

    function formatTime(value) {
      if (!value) {
        return "";
      }
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {
        return value;
      }
      return date.toLocaleTimeString();
    }

    function formatNumber(value) {
      return Number(value || 0).toLocaleString();
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function escapeAttr(value) {
      return escapeHtml(value);
    }

    refreshDashboard();
    state.timer = setInterval(refreshDashboard, state.refreshMs);
  </script>
</body>
</html>"""
        return page.replace("__ADMIN_CONFIG__", config_json)
