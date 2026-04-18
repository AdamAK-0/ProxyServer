"""Thread-safe runtime statistics for the admin interface.

Contributor: Adam - counters for requests, cache, errors, and active tunnels.
External code: none; standard library only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any


class ProxyStats:
    """Collects counters that are safe to update from worker threads."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._started_at = datetime.now(timezone.utc)
        self._active_connections = 0
        self._total_requests = 0
        self._http_requests = 0
        self._https_tunnels = 0
        self._mitm_intercepts = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._blocked_requests = 0
        self._errors = 0
        self._bytes_from_origin = 0
        self._bytes_to_clients = 0

    def connection_started(self) -> None:
        with self._lock:
            self._active_connections += 1

    def connection_finished(self) -> None:
        with self._lock:
            if self._active_connections > 0:
                self._active_connections -= 1

    def record_http(self, cache_result: str, bytes_from_origin: int, bytes_to_client: int) -> None:
        with self._lock:
            self._total_requests += 1
            self._http_requests += 1
            if cache_result == "HIT":
                self._cache_hits += 1
            elif cache_result == "MISS":
                self._cache_misses += 1
            self._bytes_from_origin += bytes_from_origin
            self._bytes_to_clients += bytes_to_client

    def record_tunnel(self, bytes_from_origin: int, bytes_to_client: int) -> None:
        with self._lock:
            self._total_requests += 1
            self._https_tunnels += 1
            self._bytes_from_origin += bytes_from_origin
            self._bytes_to_clients += bytes_to_client

    def record_mitm(self, cache_result: str, bytes_from_origin: int, bytes_to_client: int) -> None:
        with self._lock:
            self._total_requests += 1
            self._mitm_intercepts += 1
            if cache_result == "HIT":
                self._cache_hits += 1
            elif cache_result == "MISS":
                self._cache_misses += 1
            self._bytes_from_origin += bytes_from_origin
            self._bytes_to_clients += bytes_to_client

    def record_blocked(self) -> None:
        with self._lock:
            self._total_requests += 1
            self._blocked_requests += 1

    def record_error(self) -> None:
        with self._lock:
            self._errors += 1

    def reset_counters(self) -> None:
        """Reset demo counters while preserving current active connections."""

        with self._lock:
            self._total_requests = 0
            self._http_requests = 0
            self._https_tunnels = 0
            self._mitm_intercepts = 0
            self._cache_hits = 0
            self._cache_misses = 0
            self._blocked_requests = 0
            self._errors = 0
            self._bytes_from_origin = 0
            self._bytes_to_clients = 0

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            uptime = datetime.now(timezone.utc) - self._started_at
            return {
                "started_at": self._started_at.isoformat(),
                "uptime_seconds": int(uptime.total_seconds()),
                "active_connections": self._active_connections,
                "total_requests": self._total_requests,
                "http_requests": self._http_requests,
                "https_tunnels": self._https_tunnels,
                "mitm_intercepts": self._mitm_intercepts,
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "blocked_requests": self._blocked_requests,
                "errors": self._errors,
                "bytes_from_origin": self._bytes_from_origin,
                "bytes_to_clients": self._bytes_to_clients,
            }
