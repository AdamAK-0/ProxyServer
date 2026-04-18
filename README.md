# CSC 430 Caching Proxy Server

Contributor: Adam  
Course: CSC 430 Computer Networks, Spring 2025-2026  
External code: the default proxy uses only the Python standard library. Optional `--mitm` mode uses the third-party `cryptography` package for certificate generation.

## What This Project Implements

This project is a multithreaded caching proxy server written in Python. It supports:

- HTTP proxy forwarding using raw sockets.
- HTTPS forwarding through the `CONNECT` method without decrypting user traffic.
- Request parsing for method, target host, port, URL, headers, and body.
- Header rewriting for origin-server forwarding.
- Concurrent clients using one worker thread per client connection.
- JSON-lines logging of request, response, client, target, status, cache, and error details.
- Disk-backed GET response caching with `Cache-Control`, `Expires`, and fallback timeout support.
- Blacklist and whitelist filtering for domains, IP addresses, wildcard domains, and URL text.
- Web admin interface for logs, stats, cache entries, and filter management.
- Automated integration tests for forwarding, caching, blocking, POST forwarding, HTTPS tunneling, and optional MITM interception.

## Files

- `run_proxy.py` - launcher for the proxy and admin interface.
- `caching_proxy/proxy.py` - threaded socket proxy and HTTPS tunnel implementation.
- `caching_proxy/http_utils.py` - HTTP parsing, header rewriting, and response helpers.
- `caching_proxy/cache.py` - disk cache and invalidation logic.
- `caching_proxy/access_control.py` - blacklist/whitelist logic.
- `caching_proxy/admin.py` - web admin dashboard.
- `caching_proxy/logger.py` - JSON-lines request logging.
- `caching_proxy/stats.py` - thread-safe runtime counters.
- `demo_origin_server.py` - local demo server for cache and blacklist testing.
- `tests/test_proxy.py` - automated integration tests.
- `REPORT.md` - report draft for submission.

## Requirements

Python 3.10 or newer is recommended. No third-party packages are required.

The normal proxy mode uses only the standard library. The optional educational MITM mode requires:

```powershell
python -m pip install -r requirements.txt
```

## Run the Proxy

From `c:\Users\Adam\ComputerNetworksProject`:

```powershell
python run_proxy.py
```

Default services:

- Proxy: `127.0.0.1:8888`
- Admin dashboard: `http://127.0.0.1:8081`

Optional ports:

```powershell
python run_proxy.py --port 8888 --admin-port 8081 --cache-ttl 120
```

Runtime files are created in `data/`:

- `data/proxy.log`
- `data/filters.json`
- `data/cache/`

## Configure a Client

For a browser demo, set the browser/system HTTP proxy to:

- Host: `127.0.0.1`
- Port: `8888`

For command-line testing on Windows PowerShell, use `curl.exe`:

```powershell
curl.exe -x http://127.0.0.1:8888 http://example.com/
curl.exe -x http://127.0.0.1:8888 https://example.com/ -I
```

The HTTPS command uses a CONNECT tunnel. The proxy forwards encrypted bytes and does not decrypt the traffic.

## Optional HTTPS MITM Mode

By default, HTTPS is tunneled securely without decryption. For educational inspection only, you can enable MITM mode:

```powershell
python run_proxy.py --mitm
```

On first run, the proxy creates a local root CA certificate:

```text
data/mitm/ca.cert.pem
```

To let a browser or command-line client trust intercepted HTTPS traffic, import/trust that CA certificate for the client you are testing. For `curl.exe`, pass the CA file explicitly:

```powershell
curl.exe -x http://127.0.0.1:8888 --cacert data\mitm\ca.cert.pem https://example.com/
```

MITM mode behavior:

- The client still sends `CONNECT host:443`.
- The proxy replies `200 Connection Established`.
- The proxy presents a generated certificate for the requested host, signed by `data/mitm/ca.cert.pem`.
- The proxy decrypts one HTTPS request, logs the real HTTPS URL/method/status, forwards the request to the real server over TLS, and returns the response.
- Cacheable intercepted HTTPS `GET` responses can be cached using the same cache logic.

Privacy warning: only use `--mitm` in a controlled educational/demo environment. Do not use it on other people's traffic or accounts.

The demo UI at `http://127.0.0.1:9000` also has a `Run MITM HTTPS` button. When the proxy is running with `--mitm`, that button performs the same trust-and-request flow as the `curl.exe --cacert` command from the server side and prints whether the proxy CA was detected in the HTTPS certificate chain.

For local HTTPS test servers with self-signed upstream certificates only, you can add:

```powershell
python run_proxy.py --mitm --mitm-insecure-origin
```

Do not use `--mitm-insecure-origin` for normal internet browsing because it disables upstream certificate verification.

## Local Demo Server

Open one terminal and start the proxy:

```powershell
python run_proxy.py
```

Open a second terminal and start the demo origin server:

```powershell
python demo_origin_server.py --port 9000
```

Then open the browser demo UI:

```text
http://127.0.0.1:9000
```

The page has buttons that run proxy requests equivalent to the curl commands below and prints the returned body. This is useful for the live demo because you can click `/cache` twice and watch the admin panel update at the same time.

If the proxy is running with `--mitm`, click `Run MITM HTTPS` to demonstrate HTTPS interception without typing the `curl.exe --cacert ...` command manually.

Then test through the proxy:

```powershell
curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/cache
curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/cache
curl.exe -x http://127.0.0.1:8888 http://127.0.0.1:9000/nocache
```

Expected behavior:

- `/cache` returns the same cached body on repeated requests during its cache lifetime.
- `/nocache` changes on repeated requests because the origin sends `Cache-Control: no-store`.

## Admin Interface

Visit:

```text
http://127.0.0.1:8081
```

The admin page shows:

- Active connections.
- Total HTTP requests and HTTPS tunnels.
- Cache hits and misses.
- Blocked requests and errors.
- Recent logs.
- Current cache entries.
- Blacklist and whitelist rules.
- Live updates every 1.5 seconds without refreshing the browser.
- A loop warning if a client accidentally requests the proxy port through the proxy.
- A clear-log action for preparing a clean demo.
- A reset-counters action for clearing HTTP/cache/error counters before screenshots.

Important: open the admin page at `http://127.0.0.1:8081`, not `http://127.0.0.1:8888`. If your browser is configured to use the proxy, bypass the proxy for local addresses such as `127.0.0.1` and `localhost`.

Filter examples:

- `example.com` blocks/allows the domain and subdomains.
- `*.example.com` blocks/allows wildcard subdomains.
- `127.0.0.1` blocks/allows an IP address.
- `http://example.com/private` matches URL text.

## Run Automated Tests

```powershell
python -m unittest discover -v
```

Current passing test coverage:

- Basic HTTP GET forwarding.
- GET response caching.
- `Cache-Control: no-store` invalidation.
- Blacklist rejection before contacting the origin server.
- POST request body forwarding.
- HTTPS CONNECT byte tunneling without decryption.
- Optional HTTPS MITM decrypt-forward-reencrypt flow.
- Self-proxy loop rejection.

## Notes for Submission

The source files include contributor comments as required by the assignment. If this is a group submission, update those comments and `REPORT.md` so each team member's actual contribution is clear.

For the final Blackboard report, add screenshots of:

- Proxy terminal running.
- Admin dashboard.
- Automated test output.
- Cache hit demo.
- Blacklist 403 demo.
- HTTPS CONNECT demo using `curl.exe`.
