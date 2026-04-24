"""JSON-lines request logging for the proxy and admin dashboard.

Contributor: Adam - request/response/error logging implementation.
External code: none; standard library only.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


class RequestLogger:
    """Writes one JSON object per proxy event to a log file."""

    def __init__(self, log_file: Path) -> None:
        self.log_file = log_file
        self.excluded_log_file = log_file.with_name("excluded_log.txt")
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def log(self, event: str, **fields: Any) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        line = json.dumps(record, sort_keys=True)
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def log_excluded(self, event: str, **fields: Any) -> None:
        """Write intentionally hidden/noisy events outside the admin dashboard log."""

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        line = json.dumps(record, sort_keys=True)
        with self._lock:
            with self.excluded_log_file.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def tail(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the last log records for display in the admin interface."""

        if not self.log_file.exists():
            return []
        with self._lock:
            lines = self._read_tail_lines(limit)
        records: list[dict[str, Any]] = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append({"event": "corrupt-log-line", "raw": line})
        return records

    def clear(self) -> None:
        """Clear the current log file from the admin interface."""

        with self._lock:
            self.log_file.write_text("", encoding="utf-8")

    def _read_tail_lines(self, limit: int) -> list[str]:
        if limit <= 0:
            return []
        block_size = 8192
        with self.log_file.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            buffer = b""
            lines: list[bytes] = []
            while position > 0 and len(lines) <= limit:
                read_size = min(block_size, position)
                position -= read_size
                handle.seek(position)
                buffer = handle.read(read_size) + buffer
                lines = buffer.splitlines()
            return [line.decode("utf-8", errors="replace") for line in lines[-limit:]]
