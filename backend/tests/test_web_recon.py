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
            probe_web_service(WebProbeRequest(assessment_id=1, url="https://example.test", authorized=False))
        self.assertEqual(raised.exception.status_code, 400)

    @patch("app.routes.assessments.record_tool_execution", return_value={"id": 11})
    @patch("app.routes.assessments.assert_target_in_scope", return_value={"assessment_id": 1, "target_id": 2})
    @patch("app.routes.web_recon.requests.Session")
    def test_probe_does_not_follow_redirects(self, session_factory, _scope, _record):
        response = MagicMock()
        response.status_code = 302
        response.reason = "Found"
        response.url = "https://example.test/"
        response.encoding = "utf-8"
        response.headers = {"Location":"https://other.example/","Content-Type":"text/html"}
        response.iter_content.return_value = [b"<title>Redirect</title>"]
        session = session_factory.return_value
        session.get.return_value.__enter__.return_value = response
        result = probe_web_service(WebProbeRequest(assessment_id=1, url="https://example.test", authorized=True))
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(result["redirect_location"], "https://other.example/")
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertFalse(session.trust_env)



class ReconToolExecutionGuardTests(unittest.TestCase):
    def test_run_requires_explicit_authorization(self):
        request = ToolRunRequest(assessment_id=1, tool_id="httpx", url="https://example.test", authorized=False)
        with self.assertRaises(HTTPException) as raised:
            run_recon_tool(request)
        self.assertEqual(raised.exception.status_code, 400)

    @patch("app.routes.assessments.assert_target_in_scope", side_effect=HTTPException(403, "out of scope"))
    def test_scanner_execution_rejects_target_outside_assessment_scope(self, _scope):
        request = ToolRunRequest(assessment_id=4, tool_id="httpx", url="https://outside.test", authorized=True)
        with self.assertRaises(HTTPException) as raised:
            run_recon_tool(request)
        self.assertEqual(raised.exception.status_code, 403)
    @patch("app.routes.assessments.record_tool_execution")
    @patch("app.routes.assessments.assert_target_in_scope", return_value={"assessment_id": 1, "target_id": 2})
    @patch("app.routes.web_recon.shutil.which", return_value="/usr/bin/httpx")
    @patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired(cmd="httpx", timeout=30))
    def test_scanner_timeout_is_persisted(self, _run, _which, _scope, record):
        request = ToolRunRequest(assessment_id=1, tool_id="httpx", url="https://example.test", authorized=True)
        with self.assertRaises(HTTPException) as raised:
            run_recon_tool(request)
        self.assertEqual(raised.exception.status_code, 504)
        self.assertEqual(record.call_args.args[5], 124)
    @patch("app.routes.assessments.assert_target_in_scope", return_value={"assessment_id": 1, "target_id": 2})
    @patch("app.routes.web_recon.shutil.which", return_value=None)
    def test_run_reports_missing_binary(self, _which, _scope):
        request = ToolRunRequest(assessment_id=1, tool_id="httpx", url="https://example.test", authorized=True)
        with self.assertRaises(HTTPException) as raised:
            run_recon_tool(request)
        self.assertEqual(raised.exception.status_code, 409)

class ReconToolAdapterTests(unittest.TestCase):
    def test_httpx_command_uses_fixed_arguments(self):
        command = _build_tool_command("httpx", "/usr/bin/httpx", "https://example.test")
        self.assertEqual(command[0], "/usr/bin/httpx")
        self.assertIn("-json", command)
        self.assertIn("-nfs", command)
        self.assertEqual(command[-1], "https://example.test")

    def test_whatweb_command_uses_json_output(self):
        command = _build_tool_command("whatweb", "/usr/bin/whatweb", "https://example.test")
        self.assertEqual(command[0], "/usr/bin/whatweb")
        self.assertIn("--log-json=/dev/stdout", command)
        self.assertIn("--max-redirects=0", command)
        self.assertIn("--follow-redirect=never", command)
        self.assertEqual(command[-1], "https://example.test")

    def test_parser_normalises_httpx_json(self):
        records = _parse_tool_output("httpx", '{"url":"https://example.test","status_code":200,"tech":["nginx"]}')
        self.assertEqual(records[0]["status_code"], 200)
        self.assertEqual(records[0]["technologies"], ["nginx"])

    def test_parser_normalises_whatweb_plugins(self):
        records = _parse_tool_output("whatweb", '{"target":"https://example.test","http_status":200,"plugins":{"Apache":{"version":["2.4"]},"title":{"string":["Example"]}}}')
        self.assertEqual(records[0]["http_status"], 200)
        self.assertIn("Apache", records[0]["technologies"])

    def test_whatweb_parser_accepts_json_array_output(self):
        records = _parse_tool_output("whatweb", '[{"target":"https://example.test","http_status":200,"plugins":{"title":{"string":["Example"]},"Apache":{}}}]')
        self.assertEqual(records[0]["title"], "Example")
        self.assertIn("Apache", records[0]["technologies"])
    def test_parser_keeps_unstructured_output_as_evidence(self):
        self.assertEqual(_parse_tool_output("whatweb", "not-json"), [{"raw": "not-json"}])


    def test_subfinder_command_is_passive_and_rate_limited(self):
        command = _build_tool_command("subfinder", "/usr/bin/subfinder", "https://example.test/path")
        self.assertEqual(command[0], "/usr/bin/subfinder")
        self.assertEqual(command[command.index("-d") + 1], "example.test")
        self.assertIn("-silent", command)
        self.assertIn("-json", command)
        self.assertIn("-cs", command)
        self.assertEqual(command[command.index("-rl") + 1], "5")
        self.assertNotIn("-active", command)
        self.assertNotIn("-recursive", command)

    def test_subfinder_parser_extracts_hostname_and_sources(self):
        records = _parse_tool_output(
            "subfinder",
            '{"host":"WWW.Example.test.","sources":["crtsh","wayback"]}',
        )
        self.assertEqual(records[0]["host"], "www.example.test")
        self.assertEqual(records[0]["sources"], ["crtsh", "wayback"])

    def test_subfinder_request_is_an_allowed_tool_id(self):
        request = ToolRunRequest(
            assessment_id=1, tool_id="subfinder",
            url="https://example.test", authorized=True,
        )
        self.assertEqual(request.tool_id, "subfinder")

    def test_rejects_unknown_adapter(self):
        with self.assertRaises(HTTPException):
            _build_tool_command("nmap", "/usr/bin/nmap", "https://example.test")

if __name__ == "__main__":
    unittest.main()
