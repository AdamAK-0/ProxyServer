"""Command-line entry point for running the proxy and PyQt admin panel.

Contributor: Adam - application wiring and CLI options.
External code: PyQt5 for the desktop admin panel.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .access_control import AccessController
from .admin import AdminServer
from .cache import ResponseCache
from .config import ProxyConfig
from .logger import RequestLogger
from .proxy import ProxyServer
from .stats import ProxyStats


def build_runtime(config: ProxyConfig) -> tuple[ProxyServer, AdminServer]:
    config.ensure_directories()
    access = AccessController(config.filters_file, whitelist_enabled=config.whitelist_enabled)
    cache = ResponseCache(config.cache_dir, default_ttl=config.cache_default_ttl)
    logger = RequestLogger(config.log_file)
    stats = ProxyStats()
    proxy = ProxyServer(config, access, cache, logger, stats)
    admin = AdminServer(config, access, cache, logger, stats)
    return proxy, admin


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CSC 430 caching proxy server")
    parser.add_argument("--host", default="127.0.0.1", help="Proxy listen host")
    parser.add_argument("--port", type=int, default=8888, help="Proxy listen port")
    parser.add_argument("--admin-host", default="127.0.0.1", help="Compatibility option; PyQt admin does not bind HTTP")
    parser.add_argument("--admin-port", type=int, default=8081, help="Compatibility option; PyQt admin does not bind HTTP")
    parser.add_argument("--cache-ttl", type=int, default=120, help="Fallback cache timeout in seconds")
    parser.add_argument("--data-dir", default="data", help="Directory for cache, logs, and filters")
    parser.add_argument("--whitelist-only", action="store_true", help="Only allow whitelist matches")
    parser.add_argument("--mitm", action="store_true", help="Enable educational HTTPS MITM interception")
    parser.add_argument(
        "--mitm-insecure-origin",
        action="store_true",
        help="Do not verify upstream HTTPS certificates in MITM mode; useful only for local tests",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = ProxyConfig(
        listen_host=args.host,
        proxy_port=args.port,
        admin_host=args.admin_host,
        admin_port=args.admin_port,
        cache_default_ttl=args.cache_ttl,
        data_dir=Path(args.data_dir),
        whitelist_enabled=args.whitelist_only,
        mitm_enabled=args.mitm,
        mitm_verify_origin_tls=not args.mitm_insecure_origin,
    )
    proxy, admin = build_runtime(config)
    proxy_thread = proxy.start_in_thread()
    if proxy.bound_port is not None:
        config.proxy_port = proxy.bound_port
    print(f"Proxy listening on {config.listen_host}:{config.proxy_port}")
    print("PyQt admin panel opened on this machine.")
    if config.mitm_enabled:
        print("MITM mode enabled for educational HTTPS inspection.")
        print(f"Install/trust this local CA certificate for clients: {config.mitm_dir / 'ca.cert.pem'}")
    try:
        admin.run()
    except KeyboardInterrupt:
        print("\nShutting down proxy...")
    except RuntimeError as exc:
        print(f"\n{exc}")
    finally:
        proxy.shutdown()
        proxy_thread.join(timeout=2)
        admin.shutdown()


if __name__ == "__main__":
    main()
