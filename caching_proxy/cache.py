"""Disk-backed HTTP response cache for GET requests.

Contributor: Adam - cache keying, expiration, and response-header invalidation.
External code: none; standard library only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass
class CacheRecord:
    key: str
    cache_id: str
    method: str
    url: str
    created_at: float
    expires_at: float
    status_code: int
    size: int

    @property
    def expired(self) -> bool:
        return datetime.now(timezone.utc).timestamp() >= self.expires_at

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "cache_id": self.cache_id,
            "method": self.method,
            "url": self.url,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status_code": self.status_code,
            "size": self.size,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "CacheRecord":
        return cls(
            key=str(data["key"]),
            cache_id=str(data["cache_id"]),
            method=str(data["method"]),
            url=str(data["url"]),
            created_at=float(data["created_at"]),
            expires_at=float(data["expires_at"]),
            status_code=int(data["status_code"]),
            size=int(data["size"]),
        )


class ResponseCache:
    """Stores complete HTTP responses and removes expired entries."""

    def __init__(self, cache_dir: Path, default_ttl: int = 120) -> None:
        self.cache_dir = cache_dir
        self.default_ttl = default_ttl
        self._lock = Lock()
        self._records: dict[str, CacheRecord] = {}
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._load_records()

    def make_key(self, method: str, scheme: str, host: str, port: int, path: str) -> str:
        return f"{method.upper()} {scheme.lower()}://{host.lower()}:{port}{path}"

    def get(self, key: str) -> bytes | None:
        with self._lock:
            record = self._records.get(key)
            if not record:
                return None
            if record.expired:
                self._delete_locked(key)
                return None
            response_path = self._response_path(record.cache_id)
            try:
                return response_path.read_bytes()
            except OSError:
                self._delete_locked(key)
                return None

    def put(self, key: str, method: str, url: str, response: bytes, default_ttl: int | None = None) -> bool:
        status_code, headers = self._parse_response_headers(response)
        ttl = self._ttl_from_headers(headers, default_ttl if default_ttl is not None else self.default_ttl)
        if method.upper() != "GET" or status_code != 200 or ttl <= 0:
            return False

        now = datetime.now(timezone.utc).timestamp()
        cache_id = hashlib.sha256(key.encode("utf-8")).hexdigest()
        record = CacheRecord(
            key=key,
            cache_id=cache_id,
            method=method.upper(),
            url=url,
            created_at=now,
            expires_at=now + ttl,
            status_code=status_code,
            size=len(response),
        )
        with self._lock:
            self._response_path(cache_id).write_bytes(response)
            self._metadata_path(cache_id).write_text(json.dumps(record.to_json(), indent=2), encoding="utf-8")
            self._records[key] = record
        return True

    def clear(self) -> None:
        with self._lock:
            for record in list(self._records.values()):
                self._delete_locked(record.key)
            self._records.clear()

    def delete(self, key: str) -> None:
        with self._lock:
            self._delete_locked(key)

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            records = list(self._records.values())
        output = []
        now = datetime.now(timezone.utc).timestamp()
        for record in records:
            data = record.to_json()
            data["expires_in_seconds"] = max(0, int(record.expires_at - now))
            data["expired"] = record.expired
            output.append(data)
        return sorted(output, key=lambda item: item["url"])

    def cleanup_expired(self) -> int:
        removed = 0
        with self._lock:
            for key, record in list(self._records.items()):
                if record.expired:
                    self._delete_locked(key)
                    removed += 1
        return removed

    def _load_records(self) -> None:
        with self._lock:
            self._records.clear()
            for metadata_path in self.cache_dir.glob("*.json"):
                try:
                    record = CacheRecord.from_json(json.loads(metadata_path.read_text(encoding="utf-8")))
                except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                    continue
                if not record.expired and self._response_path(record.cache_id).exists():
                    self._records[record.key] = record

    def _delete_locked(self, key: str) -> None:
        record = self._records.pop(key, None)
        if not record:
            return
        for path in (self._response_path(record.cache_id), self._metadata_path(record.cache_id)):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _response_path(self, cache_id: str) -> Path:
        return self.cache_dir / f"{cache_id}.bin"

    def _metadata_path(self, cache_id: str) -> Path:
        return self.cache_dir / f"{cache_id}.json"

    @classmethod
    def _parse_response_headers(cls, response: bytes) -> tuple[int, dict[str, str]]:
        header_block = response.split(b"\r\n\r\n", 1)[0]
        text = header_block.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")
        status_parts = lines[0].split()
        status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        return status_code, headers

    @classmethod
    def _ttl_from_headers(cls, headers: dict[str, str], default_ttl: int) -> int:
        cache_control = headers.get("cache-control", "").lower()
        if "no-store" in cache_control or "private" in cache_control:
            return 0
        if "set-cookie" in headers:
            return 0
        for directive in cache_control.split(","):
            directive = directive.strip()
            if directive.startswith("max-age="):
                try:
                    return max(0, int(directive.split("=", 1)[1]))
                except ValueError:
                    return default_ttl
        expires = headers.get("expires")
        if expires:
            try:
                expires_at = parsedate_to_datetime(expires)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                delta = expires_at.timestamp() - datetime.now(timezone.utc).timestamp()
                return max(0, int(delta))
            except (TypeError, ValueError, OverflowError):
                return default_ttl
        return default_ttl
