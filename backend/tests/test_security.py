import os
import unittest
from unittest.mock import patch

from app.security import (
    allowed_hosts,
    allowed_web_origins,
    is_loopback_client,
    origin_is_allowed,
)


class LocalSecurityPolicyTests(unittest.TestCase):
    def test_default_origins_and_hosts_are_local_only(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MSF_WEB_CORS_ORIGINS", None)
            os.environ.pop("MSF_WEB_ALLOWED_HOSTS", None)
            self.assertEqual(
                allowed_web_origins(),
                ["http://localhost:5173", "http://127.0.0.1:5173"],
            )
            self.assertEqual(allowed_hosts(), ["localhost", "127.0.0.1", "::1"])

    def test_browser_origin_allowlist_accepts_local_frontend(self):
        with patch.dict(os.environ, {"MSF_WEB_CORS_ORIGINS": "http://localhost:5173, https://lab.example"}):
            self.assertTrue(origin_is_allowed("http://localhost:5173"))
            self.assertTrue(origin_is_allowed("https://lab.example"))
            self.assertFalse(origin_is_allowed("https://attacker.example"))

    def test_origin_comparison_normalizes_host_case_and_trailing_slash(self):
        with patch.dict(os.environ, {"MSF_WEB_CORS_ORIGINS": "http://localhost:5173"}):
            self.assertTrue(origin_is_allowed("HTTP://LOCALHOST:5173/"))

    def test_malformed_or_non_origin_urls_are_rejected(self):
        with patch.dict(os.environ, {"MSF_WEB_CORS_ORIGINS": "http://localhost:5173"}):
            self.assertFalse(origin_is_allowed("javascript:alert(1)"))
            self.assertFalse(origin_is_allowed("http://localhost:5173/path"))
            self.assertFalse(origin_is_allowed("not a url"))

    def test_missing_origin_is_allowed_for_local_non_browser_clients(self):
        self.assertTrue(origin_is_allowed(None))
        self.assertTrue(origin_is_allowed(""))

    def test_loopback_addresses_are_allowed_but_remote_addresses_are_not(self):
        for address in ("127.0.0.1", "::1", "127.0.0.2"):
            with self.subTest(address=address):
                self.assertTrue(is_loopback_client(address))
        for address in ("192.0.2.10", "203.0.113.5", None, "localhost"):
            with self.subTest(address=address):
                self.assertFalse(is_loopback_client(address))

    def test_host_allowlist_can_be_explicitly_configured_without_wildcard_default(self):
        with patch.dict(os.environ, {"MSF_WEB_ALLOWED_HOSTS": "localhost,console.example"}):
            self.assertEqual(allowed_hosts(), ["localhost", "console.example"])
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MSF_WEB_ALLOWED_HOSTS", None)
            self.assertNotIn("*", allowed_hosts())


if __name__ == "__main__":
    unittest.main()
