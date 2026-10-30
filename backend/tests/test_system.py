import socket
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routes.system import network_context


class NetworkContextTests(unittest.TestCase):
    def test_network_context_rejects_empty_target(self):
        with self.assertRaises(HTTPException) as raised:
            network_context(" ")
        self.assertEqual(raised.exception.status_code, 400)

    def test_network_context_returns_os_selected_source_address(self):
        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def connect(self, _address):
                return None

            def getsockname(self):
                return ("192.0.2.5", 49152)

        address = ("192.0.2.10", 1)
        with patch(
            "app.routes.system.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", address)],
        ), patch("app.routes.system.socket.socket", return_value=FakeSocket()):
            result = network_context("192.0.2.10")

        self.assertEqual(result["local_ip"], "192.0.2.5")
        self.assertEqual(result["resolved_target"], "192.0.2.10")
        self.assertEqual(result["method"], "os-route-selection")

    def test_network_context_reports_route_lookup_failure_without_raising(self):
        with patch(
            "app.routes.system.socket.getaddrinfo",
            side_effect=OSError("name or service not known"),
        ):
            result = network_context("unresolvable.invalid")

        self.assertIsNone(result["local_ip"])
        self.assertIn("name or service not known", result["error"])


if __name__ == "__main__":
    unittest.main()
