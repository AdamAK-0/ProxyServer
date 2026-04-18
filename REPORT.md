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

Automated tests are in `tests/test_proxy.py`. They start local throwaway servers and do not require the public internet.

Run:

```powershell
python -m unittest discover -v
```

Test cases:

- `test_forwards_basic_http_get`: verifies HTTP GET forwarding.
- `test_caches_repeated_get_when_headers_allow_it`: verifies GET caching and cache hits.
- `test_does_not_cache_no_store_response`: verifies `Cache-Control: no-store`.
- `test_blacklist_rejects_request_before_origin_server`: verifies filtering before origin contact.
- `test_post_body_is_forwarded`: verifies POST body forwarding.
- `test_https_connect_tunnels_bytes_without_decrypting`: verifies CONNECT tunnel byte relay.
- `test_self_proxy_request_is_rejected_without_recursive_timeout`: verifies accidental self-proxy requests are rejected immediately.
- `test_optional_mitm_decrypts_and_forwards_https_request`: verifies optional MITM decrypt-forward-reencrypt behavior.

Latest test result:

```text
Ran 14 tests in 7.851s

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

## Screenshot Checklist

Add screenshots to the final submitted report:

- Proxy terminal showing `Proxy listening on 127.0.0.1:8888`.
- Admin dashboard home page.
- Automated test output showing all tests passing.
- Repeated `/cache` request showing same cached response.
- `/nocache` request showing changing response.
- Blacklist demo showing `403 Forbidden`.
- HTTPS CONNECT curl command.

## Individual Contribution Notes

Current code comments list Adam as the contributor. For a group submission, update this section and the top comments in source files to clearly state which student contributed to which part.
