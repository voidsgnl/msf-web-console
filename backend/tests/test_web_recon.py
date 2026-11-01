import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.routes.web_recon import (
    ToolRunRequest, WebProbeRequest, _build_tool_command, _normalise_url,
    _parse_tool_output, _technology_hints, _filter_katana_records, _classify_katana_records, _resolve_same_origin_redirects,
    probe_web_service, run_recon_tool,
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
        self.assertIn("-duc", command)
        self.assertEqual(command[command.index("-mr") + 1], "100")
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

    def test_katana_command_is_bounded_and_exact_origin_scoped(self):
        command = _build_tool_command("katana", "/usr/bin/katana", "https://example.test:8443/start")
        self.assertEqual(command[0], "/usr/bin/katana")
        self.assertIn("-dr", command)
        self.assertIn("-jc", command)
        self.assertIn("-iqp", command)
        self.assertIn("-or", command)
        self.assertIn("-ob", command)
        self.assertIn("-fr", command)
        self.assertEqual(command[command.index("-fr") + 1], r"(%5[cC]|\\)")
        self.assertNotIn("-ns", command)
        self.assertIn("-cs", command)
        scope = command[command.index("-cs") + 1]
        self.assertIn(r"example\.test:8443", scope)
        self.assertNotIn("(?:", scope)
        self.assertIn("-mdp", command)
        self.assertEqual(command[command.index("-mdp") + 1], "100")
        self.assertEqual(command[command.index("-rl") + 1], "2")
        self.assertEqual(command[command.index("-d") + 1], "3")
        self.assertIn("90s", command)

    def test_katana_default_port_scope_regex_is_re2_compatible(self):
        command = _build_tool_command("katana", "/usr/bin/katana", "https://example.test/")
        scope = command[command.index("-cs") + 1]
        self.assertIn(r"(:443)?", scope)
        self.assertNotIn("(?:", scope)

    def test_katana_parser_extracts_endpoint_metadata(self):
        records = _parse_tool_output(
            "katana",
            '{"request":{"method":"GET","endpoint":"https://example.test/login",'
            '"source":"https://example.test/","tag":"a","attribute":"href"},'
            '"response":{"status_code":200,"headers":{"location":"/next","content-type":"text/html"}}}',
        )
        self.assertEqual(records[0]["url"], "https://example.test/login")
        self.assertEqual(records[0]["method"], "GET")
        self.assertEqual(records[0]["status_code"], 200)
        self.assertEqual(records[0]["tag"], "a")
        self.assertEqual(records[0]["attribute"], "href")
        self.assertEqual(records[0]["source"], "https://example.test/")
        self.assertEqual(records[0]["redirect_location"], "/next")
        self.assertEqual(records[0]["content_type"], "text/html")

    def test_katana_classifies_pages_assets_api_redirects_and_unverified(self):
        records = _classify_katana_records([
            {"url":"https://example.test/login","method":"GET","status_code":200},
            {"url":"https://example.test/app.js","method":"GET","status_code":200},
            {"url":"https://example.test/api/users","method":"GET","status_code":None},
            {"url":"https://example.test/old","method":"GET","status_code":308,"redirect_location":"/new"},
            {"url":"https://example.test/linked-page","method":"GET","status_code":None},
        ])
        self.assertEqual([item["resource_type"] for item in records], ["page", "static_asset", "api_candidate", "redirect", "page"])
        self.assertFalse(records[1]["display_default"])
        self.assertEqual(records[2]["fetch_state"], "discovered_unverified")
        self.assertEqual(records[4]["fetch_state"], "discovered_unverified")

    def test_katana_flags_encoded_backslash_and_deduplicates_canonical_url(self):
        records = _classify_katana_records([
            {"url":"https://example.test/path%5C","method":"GET","status_code":None},
            {"url":"https://EXAMPLE.test:443/login","method":"GET","status_code":200},
            {"url":"https://example.test/login","method":"GET","status_code":200},
            {"url":"https://example.test/campaigns?sort=recent","method":"GET","status_code":200},
            {"url":"https://example.test/campaigns?sort=popular","method":"GET","status_code":200},
        ])
        self.assertEqual(records[0]["resource_type"], "malformed")
        self.assertFalse(records[0]["display_default"])
        self.assertEqual(len(records), 4)
        self.assertEqual(records[1]["observations"], 2)
        self.assertEqual(records[2]["endpoint_group"], records[3]["endpoint_group"])
        self.assertNotEqual(records[2]["canonical_url"], records[3]["canonical_url"])

    def test_katana_classifies_next_static_and_image_routes_as_hidden_assets(self):
        records = _classify_katana_records([
            {"url":"https://example.test/_next/image?url=%2Flogo.png&w=256&q=75","method":"GET"},
            {"url":"https://example.test/_next/static/chunks/app.js","method":"GET","status_code":200},
        ])
        self.assertEqual([item["resource_type"] for item in records], ["static_asset", "static_asset"])
        self.assertTrue(all(not item["display_default"] for item in records))
        self.assertIn("image optimization", records[0]["classification_reason"])
        self.assertIn(".png", records[0]["classification_reason"])

    def test_katana_classifies_script_text_candidates_without_promoting_malformed_urls(self):
        records = _classify_katana_records([
            {"url":"https://example.test/reciva.jpg%5C%5C%5C","method":"GET","status_code":200,
             "tag":"script","attribute":"text","source":"https://example.test/"},
            {"url":"https://example.test/api/session","method":"GET","status_code":None,
             "tag":"script","attribute":"text","source":"https://example.test/app.js"},
        ])
        self.assertEqual(records[0]["resource_type"], "malformed")
        self.assertFalse(records[0]["display_default"])
        self.assertIn("script text", records[0]["classification_reason"])
        self.assertEqual(records[0]["source"], "https://example.test/")
        self.assertEqual(records[1]["resource_type"], "api_candidate")
        self.assertTrue(records[1]["display_default"])

    def test_katana_classifies_next_framework_redirect_separately(self):
        records = _classify_katana_records([
            {"url":"https://example.test/_next/","method":"GET","status_code":308,
             "redirect_location":"/_next"},
        ])
        self.assertEqual(records[0]["resource_type"], "framework_redirect")
        self.assertFalse(records[0]["display_default"])
        self.assertIn("Next.js", records[0]["classification_reason"])
    def test_katana_parser_discards_incomplete_json_response(self):
        complete = (
            '{"request":{"method":"GET","endpoint":"https://example.test/login"},'
            '"response":{"status_code":200}}\n'
        )
        incomplete = (
            '{"request":{"method":"GET","endpoint":"https://example.test/admin"},'
            '"response":{"status_code":'
        )
        records = _parse_tool_output("katana", complete + incomplete)
        self.assertEqual([record["url"] for record in records], ["https://example.test/login"])


    def test_katana_follows_only_same_origin_entry_redirects(self):
        first = MagicMock()
        first.__enter__.return_value = first
        first.status_code = 308
        first.headers = {"Location": "/app"}
        second = MagicMock()
        second.__enter__.return_value = second
        second.status_code = 200
        second.headers = {}
        session = MagicMock()
        session.get.side_effect = [first, second]
        with patch("app.routes.web_recon.requests.Session", return_value=session):
            resolved, chain, blocked = _resolve_same_origin_redirects("https://example.test/")
        self.assertEqual(resolved, "https://example.test/app")
        self.assertEqual(len(chain), 1)
        self.assertTrue(chain[0]["followed"])
        self.assertIsNone(blocked)
        self.assertFalse(session.trust_env)
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])

    def test_katana_blocks_cross_origin_entry_redirect(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 308
        response.headers = {"Location": "https://www.example.test/"}
        session = MagicMock()
        session.get.return_value = response
        with patch("app.routes.web_recon.requests.Session", return_value=session):
            resolved, chain, blocked = _resolve_same_origin_redirects("https://example.test/")
        self.assertEqual(resolved, "https://example.test/")
        self.assertFalse(chain[0]["followed"])
        self.assertIn("outside the approved", blocked["reason"])
        self.assertEqual(session.get.call_count, 1)

    def test_katana_request_is_an_allowed_tool_id(self):
        request = ToolRunRequest(
            assessment_id=1, tool_id="katana",
            url="https://example.test", authorized=True,
        )
        self.assertEqual(request.tool_id, "katana")

    def test_katana_retains_only_exact_origin_endpoints(self):
        records = [
            {"url": "https://example.test/login"},
            {"url": "https://example.test:8443/admin"},
            {"url": "https://other.example/admin"},
            {"url": "http://example.test/insecure"},
            {"url": "https://user:pass@example.test/private"},
            {"url": "https://example.test/path#fragment"},
        ]
        retained = _filter_katana_records(records, "https://example.test/")
        self.assertEqual([item["url"] for item in retained], ["https://example.test/login"])

    def test_katana_scope_filter_accepts_explicit_default_port(self):
        records = [{"url": "https://example.test:443/login"}]
        self.assertEqual(
            _filter_katana_records(records, "https://example.test/"),
            records,
        )

    def test_rejects_unknown_adapter(self):
        with self.assertRaises(HTTPException):
            _build_tool_command("nmap", "/usr/bin/nmap", "https://example.test")

if __name__ == "__main__":
    unittest.main()
