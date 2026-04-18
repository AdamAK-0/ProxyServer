"""Runtime configuration for the CSC 430 proxy project.

Contributor: Adam - configuration model and directory setup.
External code: none; standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProxyConfig:
    """Stores ports, paths, and timeout settings used by the proxy server."""

    listen_host: str = "127.0.0.1"
    proxy_port: int = 8888
    admin_host: str = "127.0.0.1"
    admin_port: int = 8081
    socket_timeout: float = 15.0
    tunnel_timeout: float = 60.0
    buffer_size: int = 65536
    max_header_size: int = 65536
    cache_default_ttl: int = 120
    data_dir: Path = Path("data")
    whitelist_enabled: bool = False

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def filters_file(self) -> Path:
        return self.data_dir / "filters.json"

    @property
    def log_file(self) -> Path:
        return self.data_dir / "proxy.log"

    def ensure_directories(self) -> None:
        """Create data folders before sockets begin accepting traffic."""

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
