"""Blacklist and whitelist filtering for domains, IPs, and URL patterns.

Contributor: Adam - filtering rules and persistent admin-editable config.
External code: none; standard library only.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from threading import Lock
from typing import Any


class AccessController:
    """Checks each target host/URL against blacklist and whitelist rules."""

    def __init__(self, path: Path, whitelist_enabled: bool = False) -> None:
        self.path = path
        self._lock = Lock()
        self.blacklist: set[str] = set()
        self.whitelist: set[str] = set()
        self.whitelist_enabled = whitelist_enabled
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.save()
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        with self._lock:
            self.blacklist = {self._normalize_pattern(item) for item in data.get("blacklist", [])}
            self.whitelist = {self._normalize_pattern(item) for item in data.get("whitelist", [])}
            self.whitelist_enabled = bool(data.get("whitelist_enabled", self.whitelist_enabled))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = {
                "blacklist": sorted(self.blacklist),
                "whitelist": sorted(self.whitelist),
                "whitelist_enabled": self.whitelist_enabled,
            }
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def add(self, list_name: str, pattern: str) -> None:
        pattern = self._normalize_pattern(pattern)
        if not pattern:
            return
        with self._lock:
            target = self.blacklist if list_name == "blacklist" else self.whitelist
            target.add(pattern)
        self.save()

    def remove(self, list_name: str, pattern: str) -> None:
        pattern = self._normalize_pattern(pattern)
        with self._lock:
            target = self.blacklist if list_name == "blacklist" else self.whitelist
            target.discard(pattern)
        self.save()

    def set_whitelist_enabled(self, enabled: bool) -> None:
        with self._lock:
            self.whitelist_enabled = enabled
        self.save()

    def check(self, host: str, url: str) -> tuple[bool, str]:
        """Return (allowed, reason). Blacklist takes priority."""

        normalized_host = self._normalize_host(host)
        normalized_url = url.lower()
        with self._lock:
            blacklist = set(self.blacklist)
            whitelist = set(self.whitelist)
            whitelist_enabled = self.whitelist_enabled

        for pattern in blacklist:
            if self._matches(pattern, normalized_host, normalized_url):
                return False, f"blocked by blacklist rule: {pattern}"

        if whitelist_enabled:
            for pattern in whitelist:
                if self._matches(pattern, normalized_host, normalized_url):
                    return True, "allowed by whitelist"
            return False, "blocked because whitelist mode is enabled"

        return True, "allowed"

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "blacklist": sorted(self.blacklist),
                "whitelist": sorted(self.whitelist),
                "whitelist_enabled": self.whitelist_enabled,
            }

    @classmethod
    def _normalize_pattern(cls, pattern: str) -> str:
        return pattern.strip().lower().rstrip("/")

    @classmethod
    def _normalize_host(cls, host: str) -> str:
        host = host.strip().lower()
        if host.startswith("[") and "]" in host:
            return host[1 : host.index("]")]
        if ":" in host and host.count(":") == 1:
            return host.split(":", 1)[0]
        return host

    @classmethod
    def _matches(cls, pattern: str, host: str, url: str) -> bool:
        if not pattern:
            return False
        if "://" in pattern or "/" in pattern:
            return pattern in url
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host == suffix or host.endswith("." + suffix)
        if cls._is_ip(pattern) or cls._is_ip(host):
            return host == pattern
        return host == pattern or host.endswith("." + pattern)

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
