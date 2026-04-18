# CSC 430 Computer Networks Design Project Report

## Project Information

Project: Caching Proxy Server  
Course: CSC 430 Computer Networks, Spring 2025-2026  
Institution: Lebanese American University  
Contributor: Adam  
External code used: The default proxy uses Python standard library modules only. Optional MITM mode uses the third-party `cryptography` package for local CA and certificate generation.

Submission due date from assignment: Sunday, April 26, 2026, end of day.

## High-Level Approach

The project implements a threaded caching proxy server in Python. The proxy listens for client TCP connections, parses the first HTTP request, applies blacklist/whitelist rules, then either forwards the request to an HTTP origin server or creates an HTTPS tunnel using the `CONNECT` method.

For HTTP requests, the proxy rewrites proxy-style absolute URLs into origin-server request paths, removes hop-by-hop headers, sets the correct `Host` header, and forces `Connection: close` so the full response can be read and relayed cleanly. Cacheable GET responses are stored on disk and reused until invalidated by response headers or by the custom cache timeout.

For HTTPS requests, the default proxy mode supports secure forwarding through `CONNECT`. It returns `200 Connection Established` and then relays encrypted bytes between the client and target server without decrypting or inspecting them. An optional educational MITM mode can also be enabled with `--mitm`. In that mode, the proxy creates a local root CA, generates per-host certificates, decrypts one HTTPS request after the CONNECT handshake, forwards it to the real server over TLS, and relays the response back to the client.

A web admin interface runs beside the proxy. It displays logs, cache entries, runtime statistics, and forms for editing blacklist/whitelist rules.

## Requirement Mapping

### A. Basic Proxy Functionality

Implemented in `caching_proxy/proxy.py`.

- Accepts client connections on the configured proxy port.
- Forwards HTTP requests to the target server.
- Relays target responses back to the client.
- Supports HTTPS through `CONNECT` tunneling without decrypting traffic.

### B. Socket Programming

Implemented in `caching_proxy/proxy.py`.

- Uses Python `socket` to listen for clients.
- Uses `socket.create_connection` to connect to target servers.
- Uses `select.select` to relay HTTPS tunnel bytes in both directions.
- Does not depend on Flask, Requests, or any third-party networking library.

### C. Request Parsing

Implemented in `caching_proxy/http_utils.py`.

- Parses method, URL/target, HTTP version, headers, body, host, port, path, and scheme.
- Handles absolute proxy URLs such as `GET http://example.com/path HTTP/1.1`.
- Handles origin-form requests with a `Host` header.
- Handles `CONNECT host:port HTTP/1.1`.
- Rewrites headers for forwarding by removing hop-by-hop headers and setting `Host`.

### D. Threading

Implemented in `caching_proxy/proxy.py`.

- The main thread accepts connections.
- Each client connection is handled by a daemon worker thread.
- Shared cache, logs, filters, and stats use locks where needed.

### E. Logging

Implemented in `caching_proxy/logger.py` and used by `caching_proxy/proxy.py`.

Each log record is written as JSON to `data/proxy.log` and includes:

- Client IP address and port.
- Target host and port.
- HTTP method and URL.
- Request timestamp and response timestamp.
- Response status code.
- Cache result (`HIT`, `MISS`, or `BYPASS`).
- Byte counts.
- Error messages for failed requests.

### F. Content Caching

Implemented in `caching_proxy/cache.py`.

- Caches successful `GET` responses with status `200`.
- Stores complete HTTP responses on disk in `data/cache/`.
- Uses SHA-256 cache IDs derived from method, scheme, host, port, and path.
- Honors `Cache-Control: max-age`.
- Does not cache `Cache-Control: no-store` or `private`.
- Does not cache responses containing `Set-Cookie`.
- Honors `Expires` when present.
- Falls back to the configured custom timeout, default `120` seconds.
- Admin page can list, delete, clean expired, or clear cache entries.

### G. Blacklist / Whitelist

Implemented in `caching_proxy/access_control.py`.

- Rules are stored in `data/filters.json`.
- Supports blacklist mode.
- Supports whitelist-only mode.
- Supports exact domains, subdomains, wildcard domains such as `*.example.com`, IP addresses, and URL text patterns.
- Supports host-and-port rules such as `example.com:443` and `127.0.0.1:9000`.
- Reloads `data/filters.json` during runtime so manual file edits are reflected.
- Accepts UTF-8 files with or without a BOM, which helps when editing JSON from Windows tools.
- Blacklist rules take priority over whitelist rules.
- Blocked requests receive a custom `403 Forbidden` response.

### H. HTTPS Proxy Bonus

Implemented in `caching_proxy/proxy.py`.

- Supports HTTPS forwarding using the standard proxy `CONNECT` method by default.
- The default mode establishes a TCP connection to the target server and relays encrypted bytes without inspecting contents.
- Optional MITM inspection is available with `python run_proxy.py --mitm`.
- MITM mode uses `cryptography` to create `data/mitm/ca.cert.pem` and per-host certificates.
- A client must trust `data/mitm/ca.cert.pem` before MITM traffic will pass certificate validation.
- MITM mode decrypts one HTTPS request, logs the HTTPS method/URL/status, forwards upstream over TLS, and returns the response.
- This mode is documented as educational and privacy-sensitive.

### I. Admin Interface Bonus

Implemented in `caching_proxy/admin.py`.

The admin dashboard provides:

- Runtime usage stats.
- Active connection count.
- HTTP request count.
- HTTPS tunnel count.
- Cache hits and misses.
- Error and blocked request counters.
- Recent log viewer.
- Live updates without manual browser refresh.
- Log clearing for clean demonstrations.
- Counter reset for HTTP, HTTPS, cache, blocked, byte, and error counters.
- Loop warning when a client accidentally requests the proxy listener itself.
- Cache entry viewer and cache management.
- Blacklist/whitelist add, remove, and mode controls.

## Design Properties

- Standard-library only: easy to run on lab machines.
- Optional MITM mode: requires the `cryptography` package only when enabled.
- Threaded: supports concurrent clients.
- Disk-backed cache: survives proxy restart until entries expire or are cleared.
- Privacy-conscious HTTPS: encrypted data remains encrypted.
- Demo-friendly admin UI: shows behavior live during testing.
- JSON-lines logs: easy to read manually or parse programmatically.
- Testable design: proxy services can run on port `0` during tests for automatic free-port selection.

## Challenges Faced

One challenge was handling HTTP and HTTPS differently. Normal HTTP proxy requests can be parsed and rewritten, but HTTPS traffic must not be read as HTTP after the `CONNECT` handshake. The solution was to use two separate code paths: HTTP forwarding with caching, and CONNECT tunneling with raw byte relay.

Another challenge was caching safely. The proxy should not cache every response blindly. The implementation checks `Cache-Control`, `Expires`, status code, method, and `Set-Cookie` before storing a response.

A third challenge was keeping shared state safe while multiple worker threads run. The cache, logs, filters, and stats use locks around shared data structures and file writes.

## Testing Overview

Automated tests are in `tests/test_proxy.py` and `tests/test_admin_ui.py`. They start local throwaway servers and do not require the public internet.

Run:

```powershell
python -m unittest discover -v
```

Test cases:

- `test_forwards_basic_http_get`: verifies HTTP GET forwarding.
- `test_caches_repeated_get_when_headers_allow_it`: verifies GET caching and cache hits.
- `test_does_not_cache_no_store_response`: verifies `Cache-Control: no-store`.
- `test_blacklist_rejects_request_before_origin_server`: verifies filtering before origin contact.
- `test_blacklist_host_port_rule_rejects_request`: verifies exact host:port blacklist matching.
- `test_blacklist_host_port_rule_does_not_match_different_port`: verifies one blocked port does not block another port.
- `test_whitelist_only_accepts_matching_host_port_rule`: verifies whitelist-only mode allows matching targets.
- `test_whitelist_host_port_rule_does_not_allow_different_port`: verifies whitelist host:port rules are exact.
- `test_manual_filter_file_edit_is_reloaded`: verifies manual `filters.json` changes are picked up while running.
- `test_admin_mutation_reloads_manual_filter_file_edit_first`: verifies admin edits preserve manual file changes.
- `test_snapshot_reflects_manual_whitelist_mode_change`: verifies the admin snapshot reflects whitelist mode changes.
- `test_manual_filter_file_edit_accepts_utf8_bom`: verifies UTF-8 BOM filter files still load correctly.
- `test_post_body_is_forwarded`: verifies POST body forwarding.
- `test_https_connect_tunnels_bytes_without_decrypting`: verifies CONNECT tunnel byte relay.
- `test_self_proxy_request_is_rejected_without_recursive_timeout`: verifies accidental self-proxy requests are rejected immediately.
- `test_optional_mitm_decrypts_and_forwards_https_request`: verifies optional MITM decrypt-forward-reencrypt behavior.
- `test_dashboard_submits_forms_as_urlencoded_data`: verifies admin forms send data in the format the server parses.
- `test_filter_add_and_toggle_mutations_update_state`: verifies admin blacklist/whitelist add and whitelist toggle actions.

Latest test result:

```text
Ran 18 tests in 9.901s

OK
```

## Manual Demo Plan

Start the proxy:

```powershell
python run_proxy.py
```

Start the local origin server:

```powershell
python demo_origin_server.py --port 9000
```

Open the browser demo UI:

```text
http://127.0.0.1:9000
```

The demo UI includes buttons that run the equivalent of `curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/cache` through the proxy and display the result.

When the proxy is running with `--mitm`, the demo UI also includes a `Run MITM HTTPS` button. It performs the equivalent of `curl.exe -x http://127.0.0.1:8888 --cacert data\mitm\ca.cert.pem https://example.com/` server-side and reports whether the proxy CA was detected.

Show HTTP forwarding:

```powershell
curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/
```

Show caching:

```powershell
curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/cache
curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/cache
```

Show no-store invalidation:

```powershell
curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/nocache
curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/nocache
```

Show HTTPS CONNECT:

```powershell
curl.exe -x http://127.0.0.1:8888 https://example.com/ -I
```

Show blacklist:

1. Open `http://127.0.0.1:8081`.
2. Add `127.0.0.1:9000` to the blacklist.
3. Run the local origin curl command again.
4. Confirm the proxy returns `403 Forbidden`.

## Detailed Workflow and Oral Defense Explanation

This section explains the project from the first run command to the final testing process. It is written in detail because the live demo may include questions about which function is called first, why the design was implemented this way, and how every major feature works internally.

### Full Run Sequence

The normal run command is:

```powershell
python run_proxy.py
```

The bonus MITM run command is:

```powershell
python run_proxy.py --mitm
```

The local demo server is started separately:

```powershell
python demo_origin_server.py --port 9000
```

The admin dashboard is opened at:

```text
http://127.0.0.1:8081
```

The browser demo page is opened at:

```text
http://127.0.0.1:9000
```

The automated tests are run with:

```powershell
python -m unittest discover -v
```

The latest test result is:

```text
Ran 18 tests in 9.901s

OK
```

### First Function Called by `python run_proxy.py`

The first project file executed is `run_proxy.py`. It is intentionally small and only delegates to the real application entry point.

Call order:

1. `run_proxy.py`
2. `if __name__ == "__main__":`
3. `main()` imported from `caching_proxy.app`
4. `caching_proxy.app.main()`
5. `parse_args()`
6. `ProxyConfig(...)`
7. `config.ensure_directories()`
8. `build_runtime(config)`
9. `admin.start_in_thread()`
10. `proxy.serve_forever()`

`parse_args()` reads command-line options such as the proxy port, admin port, cache timeout, whitelist-only mode, and MITM mode. `ProxyConfig` stores those settings in one object. `ensure_directories()` creates the runtime folders used for logs, cache entries, filters, and MITM certificates. `build_runtime()` creates all shared objects. The admin server starts in a background thread. The proxy then runs in the main thread and waits for client connections.

This design keeps startup clean. `run_proxy.py` is only the launcher, `app.py` wires the application together, and `proxy.py` focuses on networking instead of command-line parsing.

### Objects Created During Startup

`build_runtime(config)` creates these objects:

- `AccessController`: manages blacklist, whitelist, whitelist-only mode, and `data/filters.json`.
- `ResponseCache`: manages cache keys, response files, metadata, expiration, deletion, cleanup, and clear operations.
- `RequestLogger`: writes JSON log records to `data/proxy.log` and reads recent logs for the admin dashboard.
- `ProxyStats`: stores thread-safe counters for active connections, HTTP requests, HTTPS tunnels, MITM interceptions, cache hits, cache misses, blocked requests, errors, and byte counts.
- `ProxyServer`: owns the proxy listening socket and request handling.
- `AdminServer`: owns the web admin dashboard and admin API endpoints.

The proxy and admin server receive the same object instances. This is important because admin changes are applied to the live proxy. For example, when the admin panel adds a blacklist rule, it updates the same `AccessController` used by `_handle_client()`.

### Proxy Socket Startup

The main proxy loop is `ProxyServer.serve_forever()`.

Its order is:

1. Create a TCP socket using `socket.socket(socket.AF_INET, socket.SOCK_STREAM)`.
2. Set `SO_REUSEADDR`.
3. Bind to the configured host and port, usually `127.0.0.1:8888`.
4. Listen for incoming clients.
5. Store the actual bound port.
6. Log the `proxy-started` event.
7. Repeatedly call `accept()`.
8. For every accepted client, start a worker thread.
9. Each worker thread calls `_handle_client(client_socket, client_address)`.

Raw sockets are used because the assignment requires socket programming and because a proxy must control TCP behavior directly, especially for HTTPS `CONNECT` tunneling. A web framework would hide too much of this behavior and would not be appropriate for raw byte tunneling.

Threading is used because the assignment requires handling multiple clients concurrently. One worker thread per client is simple to understand and fits network I/O well because a waiting client does not block other clients. Shared state is protected with locks in the cache, logger, filters, and stats classes.

### Client Request Handling

Every client request enters:

```text
ProxyServer._handle_client()
```

The order inside `_handle_client()` is:

1. `stats.connection_started()`
2. Save the request timestamp.
3. Set a socket timeout.
4. Read the raw request using `_read_client_request(client_socket)`.
5. Parse it using `parse_http_request(raw_header, body)`.
6. Check whether the client accidentally requested the proxy listener itself using `_is_self_proxy_request(request)`.
7. Apply blacklist and whitelist rules using `access.check(request.host, request.display_url)`.
8. If blocked, call `_send_blocked(...)` and stop.
9. If the request is `CONNECT`, call `_handle_connect(...)`.
10. If the request scheme is HTTP, call `_handle_http(...)`.
11. If unsupported, return `501 Not Implemented`.
12. If parsing or network errors occur, call `_handle_error(...)`.
13. Close the client socket.
14. Call `stats.connection_finished()`.

This order is important. The proxy must parse first because it needs the target host and port. It checks access rules before contacting the target server so blocked requests never reach the origin. It separates `CONNECT` from HTTP because after `CONNECT`, the bytes are TLS encrypted data, not normal HTTP text. The `finally` block closes sockets and updates the active connection count even when errors happen.

### Reading and Parsing Requests

`_read_client_request()` reads bytes until it finds `\r\n\r\n`, which marks the end of HTTP headers. It then checks `Content-Length` and reads the request body when needed, such as for POST.

`parse_http_request()` in `http_utils.py` extracts:

- method
- target
- HTTP version
- headers
- body
- host
- port
- path
- scheme
- display URL

For this request:

```text
GET http://127.0.0.1:9000/cache HTTP/1.1
```

the parser extracts:

- method: `GET`
- scheme: `http`
- host: `127.0.0.1`
- port: `9000`
- path: `/cache`
- display URL: `http://127.0.0.1:9000/cache`

For this request:

```text
CONNECT example.com:443 HTTP/1.1
```

the parser extracts:

- method: `CONNECT`
- scheme: `https`
- host: `example.com`
- port: `443`
- display URL: `https://example.com:443`

Manual parsing was chosen because the project is about networking. It makes method, host, port, path, and headers visible instead of hiding them inside a third-party library.

### Header Rewriting

For normal HTTP forwarding, `build_forward_request(request)` rewrites the request before sending it to the origin server.

It:

- changes an absolute proxy URL into an origin-server path
- removes hop-by-hop headers such as `Connection`, `Proxy-Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, and `Upgrade`
- sets the correct `Host` header
- adds `Connection: close`
- rebuilds the request bytes

This is needed because clients send proxy-style requests to proxies, while origin servers usually expect origin-form requests such as `GET /cache HTTP/1.1`. `Connection: close` makes response reading easier because the proxy can read until the origin closes the connection.

### HTTP Forwarding Flow

When `_handle_client()` sees a normal HTTP request, it calls `_handle_http(...)`.

For a GET request, the order is:

1. Build a cache key with `cache.make_key(...)`.
2. Call `cache.get(cache_key)`.
3. If cached bytes exist and are not expired, send them to the client.
4. Record an HTTP cache `HIT`.
5. Log request completion.
6. If there is no cache hit, mark the request as `MISS`.
7. Rewrite the request with `build_forward_request(request)`.
8. Connect to the origin using `socket.create_connection((request.host, request.port), ...)`.
9. Send the rewritten request.
10. Read the origin response with `_read_origin_response(origin)`.
11. Try to store it with `cache.put(...)`.
12. Send the response to the client.
13. Record HTTP stats.
14. Log request completion.

For POST, the request body is forwarded, but the response is not cached. POST requests may change server state, so caching them in a simple project proxy would be unsafe.

### Cache Design

The cache is implemented by `ResponseCache`.

Important functions:

- `make_key(...)`: builds a SHA-256 key from method, scheme, host, port, and path.
- `get(key)`: returns cached response bytes only if the entry exists and is not expired.
- `put(key, method, url, response, default_ttl)`: stores cacheable responses.
- `entries()`: returns cache metadata for the admin dashboard.
- `delete(key)`: deletes one cache entry.
- `cleanup_expired()`: removes expired entries.
- `clear()`: clears all entries.

The cache stores full HTTP responses on disk and keeps metadata beside them. It caches only successful `GET` responses with status `200`. It does not cache `no-store`, `private`, `Set-Cookie`, non-GET, or non-200 responses. It honors `Cache-Control: max-age`, honors `Expires`, and otherwise uses the configured fallback timeout.

The cache key includes the port because the same host can run different services on different ports. For example, `127.0.0.1:9000/cache` and `127.0.0.1:9001/cache` should not share a cache entry.

### Blacklist and Whitelist Flow

Filtering is implemented in `AccessController`.

Before forwarding traffic, `_handle_client()` calls:

```text
access.check(request.host, request.display_url)
```

The order inside `check()` is:

1. Reload `data/filters.json` using `reload_if_changed()`.
2. Normalize the host and URL.
3. Copy blacklist, whitelist, and whitelist mode under a lock.
4. Check blacklist rules first.
5. If any blacklist rule matches, block.
6. If whitelist-only mode is enabled, check whitelist rules.
7. If whitelist-only mode is enabled and no whitelist rule matches, block.
8. Otherwise allow.

Blacklist rules have priority because deny rules should override allow rules. This prevents a broad whitelist from accidentally allowing a target that was explicitly blocked.

Supported rule types include:

- `example.com`
- `*.example.com`
- `example.com:443`
- `127.0.0.1`
- `127.0.0.1:9000`
- full URL text such as `http://example.com/private`

Host-and-port rules are exact. Blocking `127.0.0.1:9001` does not block `127.0.0.1:9000`. Blocking only `127.0.0.1` blocks the IP on all ports.

If a request is blocked, `_send_blocked(...)` sends a custom `403 Forbidden`, logs `request-blocked`, increments the blocked counter, and does not contact the origin server.

### Normal HTTPS CONNECT Flow

Default HTTPS support uses `CONNECT`.

The client sends:

```text
CONNECT example.com:443 HTTP/1.1
```

The order is:

1. `_handle_client()` parses the CONNECT request.
2. `access.check(...)` applies filters to the target host and port.
3. `_handle_connect(...)` is called.
4. If MITM mode is disabled, the proxy opens a TCP connection to the target server.
5. The proxy sends `HTTP/1.1 200 Connection Established` to the client.
6. `_tunnel(client_socket, origin)` relays bytes in both directions using `select.select(...)`.
7. The tunnel continues until one side closes.
8. The proxy records tunnel stats and logs completion.

In this mode, the proxy does not decrypt HTTPS. It can see the target host, port, byte counts, and timing, but it cannot see HTTPS paths, headers, bodies, or response contents. This is the privacy-preserving default and follows the standard proxy model.

### Optional HTTPS MITM Flow

MITM mode is enabled with:

```powershell
python run_proxy.py --mitm
```

This mode is educational and should only be used in a controlled demo.

Startup order:

1. `parse_args()` reads `--mitm`.
2. `ProxyConfig.mitm_enabled` becomes `True`.
3. `ProxyServer.__init__()` creates a `CertificateAuthority`.
4. The certificate authority creates or loads `data/mitm/ca.cert.pem` and `data/mitm/ca.key.pem`.

Request order:

1. Client sends `CONNECT host:443`.
2. `_handle_client()` parses it and applies filters.
3. `_handle_connect(...)` sees that MITM mode is enabled.
4. `_handle_mitm_connect(...)` is called.
5. `certificate_for_host(host)` returns or generates a certificate for that host.
6. The proxy sends `HTTP/1.1 200 Connection Established`.
7. The proxy wraps the client socket with a TLS server context.
8. The client performs TLS with the proxy.
9. The client must trust `data/mitm/ca.cert.pem`.
10. The proxy reads the decrypted HTTPS request.
11. The proxy parses the decrypted request with `parse_http_request(...)`.
12. The proxy sets scheme, host, port, and display URL based on the original CONNECT target.
13. Filters are checked again against the real decrypted HTTPS URL.
14. The proxy checks cache for cacheable HTTPS GET responses.
15. The proxy opens a new TLS connection to the real origin server.
16. The proxy forwards the request upstream over TLS.
17. The origin returns a response.
18. The proxy optionally caches it.
19. The proxy sends the response back to the client over the client TLS connection.
20. The proxy logs the real HTTPS method, URL, status, and MITM mode.
21. MITM counters are updated.

MITM is optional because it breaks the normal end-to-end privacy model of HTTPS. It is useful for showing how HTTPS inspection works, but the client must explicitly trust the proxy CA certificate. The project uses the `cryptography` package for this because certificate and key generation are not conveniently provided by the Python standard library.

### Admin Dashboard Flow

The admin interface is implemented in `caching_proxy/admin.py`.

Startup order:

1. `AdminServer(config, access, cache, logger, stats)` is created.
2. `admin.start_in_thread()` starts the admin server.
3. The admin server uses `ThreadingHTTPServer`.
4. It listens on `127.0.0.1:8081`.

Important routes:

- `GET /`: dashboard page.
- `GET /api/dashboard`: combined JSON payload for stats, logs, cache, filters, and config.
- `GET /api/logs`: recent logs.
- `GET /api/cache`: cache entries.
- `GET /api/filters`: filter state.
- `POST /filters/add`: add blacklist or whitelist rule.
- `POST /filters/remove`: remove blacklist or whitelist rule.
- `POST /filters/toggle`: toggle whitelist-only mode.
- `POST /cache/clear`: clear cache.
- `POST /cache/cleanup`: clean expired cache entries.
- `POST /cache/delete`: delete one cache entry.
- `POST /logs/clear`: clear log file.
- `POST /stats/reset`: reset counters.

When a user adds a rule in the admin UI:

1. Browser JavaScript sends a URL-encoded POST request.
2. `AdminHandler.do_POST()` receives it.
3. `_read_form()` parses the form body.
4. `access.add(...)` updates the shared access controller.
5. The controller saves `data/filters.json`.
6. `_finish_mutation()` returns `204` for JavaScript requests.
7. The dashboard refreshes from `/api/dashboard`.
8. The running proxy immediately uses the new rule.

The admin interface uses a separate port because the proxy port is for proxied client traffic, while the admin port is a normal web interface. This prevents admin requests from being confused with proxy requests.

### Logging Flow

Logging is implemented by `RequestLogger`.

For successful requests:

1. `_log_complete(...)` builds a dictionary.
2. The dictionary includes client IP/port, target host/port, method, URL, timestamps, status, cache result, and byte counts.
3. `logger.log("request-complete", **fields)` writes one JSON object to `data/proxy.log`.

For blocked requests:

1. `_send_blocked(...)` sends the custom `403 Forbidden`.
2. It logs `request-blocked`.
3. It includes the blocking reason.
4. It increments blocked stats.

For errors:

1. `_handle_error(...)` sends an error response if possible.
2. It logs `request-error`.
3. It increments the error counter.

JSON-lines logging was chosen because each line is one complete event, which is easy to append, easy to read, and easy for the admin dashboard to parse.

### Demo Origin Server Flow

The demo server is implemented in `demo_origin_server.py`.

It runs with:

```powershell
python demo_origin_server.py --port 9000
```

Important endpoints:

- `/`: browser demo UI.
- `/cache`: cacheable response with `Cache-Control: max-age=120`.
- `/nocache`: non-cacheable response with `Cache-Control: no-store`.
- `/api/proxy-test`: helper used by UI buttons to make proxy requests.
- `/api/mitm-test`: helper used by the MITM demo button.
- `POST /`: echoes the POST body.

The local demo server makes testing predictable. It avoids relying on public websites for cache and blacklist demonstrations.

### Manual Demo Script

Recommended live demo order:

1. Start the proxy with MITM enabled:

```powershell
python run_proxy.py --mitm
```

2. Start the demo origin:

```powershell
python demo_origin_server.py --port 9000
```

3. Open `http://127.0.0.1:8081`.
4. Open `http://127.0.0.1:9000`.
5. Click `/cache` twice. The first request should be a cache miss and the second should be a cache hit.
6. Click `/nocache` twice. The body should change because `no-store` prevents caching.
7. Add blacklist rule `127.0.0.1:9000`.
8. Click `/cache` again. The proxy should return `403 Forbidden`.
9. Remove the blacklist rule.
10. Toggle whitelist-only mode.
11. Without a whitelist rule, requests should be blocked.
12. Add whitelist rule `127.0.0.1:9000`.
13. Requests to the demo origin should be allowed again.
14. Run HTTPS CONNECT:

```powershell
curl.exe -x http://127.0.0.1:8888 https://example.com/ -I
```

15. Click `Run MITM HTTPS`, or run:

```powershell
curl.exe -x http://127.0.0.1:8888 --cacert data\mitm\ca.cert.pem https://example.com/
```

16. Run the automated test suite:

```powershell
python -m unittest discover -v
```

### Main Design Questions and Answers

Why use raw sockets? Because the assignment requires socket programming and because raw sockets are needed for TCP-level HTTPS tunneling.

Why use threads? Because the assignment requires multithreading and one worker thread per client is simple and effective for network I/O.

Why not use `requests` for forwarding? Because it would hide the socket-level forwarding required by the assignment.

Why not use Flask for the proxy? Flask is for HTTP route handling, not raw TCP tunneling. The admin page can be a normal HTTP server, but the proxy itself needs sockets.

Why cache only GET? GET is safe and cacheable. POST can change server state and should not be cached by this simple proxy.

Why not cache every GET? Some GET responses explicitly say not to cache through `Cache-Control: no-store`, `private`, cookies, or expiration headers.

Why force `Connection: close`? It gives a clear end to the origin response and simplifies reliable response reading.

Why is HTTPS not decrypted by default? The default should preserve privacy and follow standard proxy behavior. `CONNECT` relays encrypted bytes without reading content.

Why implement MITM? It is a bonus educational feature that demonstrates TLS interception when a client explicitly trusts a local CA.

Why is MITM risky? It breaks end-to-end encryption, so the proxy can see HTTPS URLs, headers, and content. That is why it is optional and documented as educational only.

Why blacklist before whitelist? A specific deny rule should override a broad allow rule.

Why support host:port rules? Different services can run on the same host at different ports, so `127.0.0.1:9000` and `127.0.0.1:9001` must be different targets.

Why keep `data/` out of git? It contains generated logs, cache files, certificates, PID files, and local filter state. These are runtime artifacts, not source code.

### Short End-to-End Explanation

When `python run_proxy.py` runs, the launcher calls `caching_proxy.app.main()`. That parses command-line options, creates the configuration, creates shared runtime objects for filters, cache, logs, and stats, starts the admin dashboard in a background thread, and starts the proxy server. The proxy creates a TCP listening socket on port `8888`. For every client connection, it starts a worker thread. The worker reads the HTTP request, parses method, host, port, and path, checks blacklist and whitelist rules, and then chooses the correct handling path. For HTTP, it checks the cache, rewrites headers, connects to the origin with a socket, forwards the request, reads the response, optionally caches it, sends it to the client, logs the result, and updates counters. For HTTPS in normal mode, it handles `CONNECT` by opening a TCP connection to the target and relaying encrypted bytes with `select`, so the proxy does not decrypt HTTPS. For the bonus MITM mode, the client must trust the generated CA certificate. The proxy then presents a generated certificate, decrypts the HTTPS request, forwards it to the real server over TLS, sends the response back, logs it, and updates MITM stats. The admin dashboard uses the same cache, filter, logger, and stats objects, so changes and counters update live.

## Screenshot Checklist

Add screenshots to the final submitted report:

- Proxy terminal showing `Proxy listening on 127.0.0.1:8888`.
- Admin dashboard home page.
- Automated test output showing all tests passing.
- Repeated `/cache` request showing same cached response.
- `/nocache` request showing changing response.
- Blacklist demo showing `403 Forbidden`.
- HTTPS CONNECT curl command.
- Optional MITM demo button or curl command showing decrypted HTTPS mode.

## Individual Contribution Notes

Current code comments list Adam as the contributor. For a group submission, update this section and the top comments in source files to clearly state which student contributed to which part.
