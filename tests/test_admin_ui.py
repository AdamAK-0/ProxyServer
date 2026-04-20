"""PyQt admin controller tests.

Contributor: Adam - admin state mutation and dashboard payload tests.
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

    def tearDown(self) -> None:
        self.admin.shutdown()
        self.temp_dir.cleanup()

    def test_dashboard_payload_contains_runtime_sections(self) -> None:
        payload = self.admin.dashboard_payload()
        self.assertIn("stats", payload)
        self.assertIn("filters", payload)
        self.assertIn("cache", payload)
        self.assertIn("logs", payload)

    def test_filter_add_and_toggle_mutations_update_state(self) -> None:
        self.admin.add_filter("blacklist", "example.com:443")
        self.admin.set_whitelist_enabled(True)
        filters = self.admin.dashboard_payload()["filters"]
        self.assertEqual(filters["blacklist"], ["example.com:443"])
        self.assertTrue(filters["whitelist_enabled"])

    def test_compatibility_api_updates_filter_state(self) -> None:
        thread = self.admin.start_in_thread()
        try:
            base_url = f"http://127.0.0.1:{self.admin.bound_port}"
            body = urllib.parse.urlencode({"list": "blacklist", "pattern": "example.com"}).encode("utf-8")
            request = urllib.request.Request(
                f"{base_url}/filters/add",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "admin-fetch",
                },
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 204)
            filters = json.loads(urllib.request.urlopen(f"{base_url}/api/filters", timeout=5).read())
            self.assertEqual(filters["blacklist"], ["example.com"])
        finally:
            self.admin.shutdown()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
