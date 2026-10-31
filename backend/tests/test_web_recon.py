import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.routes.web_recon import (
    ToolRunRequest, WebProbeRequest, _build_tool_command, _normalise_url,
    _parse_tool_output, _technology_hints, probe_web_service, run_recon_tool,
)

class WebReconTests(unittest.TestCase):
    def test_adds_https_scheme(self):
        self.assertEqual(_normalise_url("example.test"), "https://example.test")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(HTTPException):
            _normalise_url("ftp://example.test")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(HTTPException):
            _normalise_url("https://user:pass@example.test")

    def test_rejects_whitespace_and_invalid_port(self):
        for value in ("https://example.test/a b", "https://example.test:99999"):
            with self.subTest(value=value), self.assertRaises(HTTPException):
                _normalise_url(value)

    def test_detects_common_web_technologies(self):
        found = _technology_hints({"server":"nginx","x-powered-by":"PHP/8.2"}, '<title>Site</title><script src="/wp-content/app.js"></script>')
        self.assertIn("WordPress", found)
        self.assertIn("Nginx", found)
        self.assertIn("PHP/8.2", found)

    def test_probe_requires_authorization_confirmation(self):
        with self.assertRaises(HTTPException) as raised:
            probe_web_service(WebProbeRequest(url="https://example.test", authorized=False))
        self.assertEqual(raised.exception.status_code, 400)

    @patch("app.routes.web_recon.requests.Session")
    def test_probe_does_not_follow_redirects(self, session_factory):
        response = MagicMock()
        response.status_code = 302
        response.reason = "Found"
        response.url = "https://example.test/"
        response.encoding = "utf-8"
        response.headers = {"Location":"https://other.example/","Content-Type":"text/html"}
        response.iter_content.return_value = [b"<title>Redirect</title>"]
        session = session_factory.return_value
        session.get.return_value.__enter__.return_value = response
        result = probe_web_service(WebProbeRequest(url="https://example.test", authorized=True))
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(result["redirect_location"], "https://other.example/")
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertFalse(session.trust_env)


if __name__ == "__main__":
    unittest.main()
