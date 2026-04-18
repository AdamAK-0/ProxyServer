"""Admin dashboard integration tests.

Contributor: Adam - admin form and JSON endpoint tests.
External code: none; standard library only.
"""

from __future__ import annotations

import json
import tempfile
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

from caching_proxy.app import build_runtime
from caching_proxy.config import ProxyConfig


class AdminUITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = ProxyConfig(proxy_port=0, admin_port=0, data_dir=Path(self.temp_dir.name) / "data")
        self.proxy, self.admin = build_runtime(self.config)
        self.thread = self.admin.start_in_thread()
        self.base_url = f"http://127.0.0.1:{self.admin.bound_port}"

    def tearDown(self) -> None:
        self.admin.shutdown()
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def test_dashboard_submits_forms_as_urlencoded_data(self) -> None:
        html = urllib.request.urlopen(f"{self.base_url}/", timeout=5).read().decode("utf-8")
        self.assertIn("new URLSearchParams(new FormData(form))", html)
        self.assertIn('"Content-Type": "application/x-www-form-urlencoded"', html)

    def test_filter_add_and_toggle_mutations_update_state(self) -> None:
        self._post("/filters/add", {"list": "blacklist", "pattern": "example.com:443"})
        self._post("/filters/toggle", {"enabled": "on"})
        filters = json.loads(urllib.request.urlopen(f"{self.base_url}/api/filters", timeout=5).read())
        self.assertEqual(filters["blacklist"], ["example.com:443"])
        self.assertTrue(filters["whitelist_enabled"])

    def _post(self, path: str, data: dict[str, str]) -> int:
        body = urllib.parse.urlencode(data).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "admin-fetch",
            },
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status


if __name__ == "__main__":
    unittest.main()
