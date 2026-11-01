import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.routes.web_recon import (
    ToolRunRequest, WebProbeRequest, ManualPathCheckRequest, _normalise_manual_path, _check_manual_path,
    check_manual_directories, _build_tool_command, _normalise_url,
    _parse_tool_output, _technology_hints, _filter_katana_records, _classify_katana_records, _resolve_same_origin_redirects,
    _parse_gobuster_output, _normalise_gobuster_extensions, _probe_gobuster_wildcard_length, _gobuster_body_signature, _extract_html_response_features, _classify_gobuster_records, _fetch_gobuster_candidate_body, _resolve_wordlist, _list_wordlists, _wordlist_roots, _classify_manual_path_records, _collect_manual_path_baseline,
    _parse_content_discovery_json, _parse_nuclei_output, _parse_specialist_tool_output, _fingerprint_html_page,
    probe_web_service, run_recon_tool, queue_recon_tool, _run_bounded_process, list_tools,
)

class WebReconTests(unittest.TestCase):
    @patch("app.routes.web_recon.shutil.which", side_effect=lambda name: "/usr/bin/" + name)
    def test_tool_catalog_distinguishes_ready_and_not_integrated_adapters(self, _which):
        tools = {item["id"]: item for item in list_tools()["tools"]}
        self.assertTrue(tools["httpx"]["execution_enabled"])
        self.assertEqual(tools["httpx"]["status"], "ready")
        self.assertTrue(tools["nuclei"]["execution_enabled"])
        self.assertEqual(tools["nuclei"]["status"], "ready")
        self.assertTrue(tools["nuclei"]["installed"])

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



class ManualPathCheckTests(unittest.TestCase):
    @patch("app.routes.web_recon._check_manual_path")
    def test_baseline_reports_successful_and_failed_random_probes(self, check_path):
        check_path.side_effect = [
            {"status_code": 200, "_body_signature": {"content_type": "text/html", "fingerprint": "a", "shingles": {"one"}, "soft_404_markers": []}},
            {"fetch_state": "unverified", "classification_reason": "Request timed out after 5 seconds."},
            {"fetch_state": "unverified", "classification_reason": "TLS negotiation failed."},
        ]
        result = _collect_manual_path_baseline("https://example.test/")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["attempted"], 3)
        self.assertEqual(result["successful"], 1)
        self.assertEqual(result["failed"], 2)
        self.assertEqual(len(result["failures"]), 2)
        self.assertEqual(result["failures"][0]["reason"], "Request timed out after 5 seconds.")

    @patch("app.routes.web_recon._check_manual_path")
    def test_baseline_reports_unavailable_when_all_probes_fail(self, check_path):
        check_path.return_value = {
            "fetch_state": "unverified",
            "classification_reason": "Request timed out after 5 seconds.",
        }
        result = _collect_manual_path_baseline("https://example.test/")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["attempted"], 3)
        self.assertEqual(result["successful"], 0)
        self.assertEqual(result["failed"], 3)
        self.assertEqual(len(result["failures"]), 3)


    def test_manual_path_matching_random_baseline_is_labelled_likely_soft_404(self):
        baseline = {
            "status_code": 200, "content_type": "text/html",
            "fingerprint": "same", "shingles": {"profile not found", "page unavailable"},
            "soft_404_markers": ["profile not found"],
        }
        candidate = {
            "url": "https://example.test/unknown", "status_code": 200,
            "_body_signature": {
                "fingerprint": "same", "content_type": "text/html",
                "shingles": {"profile not found", "page unavailable"},
                "soft_404_markers": ["profile not found"],
            },
        }
        result = _classify_manual_path_records([candidate], [baseline])[0]
        self.assertEqual(result["response_classification"], "likely_soft_404")
        self.assertEqual(result["body_similarity"], 1.0)
        self.assertIn("not a confirmed endpoint", result["classification_reason"])

    @patch("app.routes.web_recon._gobuster_body_similarity", return_value=0.25)
    def test_single_baseline_marker_is_not_trusted_at_low_similarity(self, _similarity):
        baseline = {
            "status_code": 200, "content_type": "text/html",
            "fingerprint": "baseline", "shingles": {"generic page", "not found"},
            "soft_404_markers": ["page not found"],
        }
        candidate = {
            "url": "https://example.test/register", "status_code": 200,
            "_body_signature": {
                "fingerprint": "candidate", "content_type": "text/html",
                "shingles": {"create account", "email address"},
                "soft_404_markers": ["page not found"],
            },
        }
        result = _classify_manual_path_records([candidate], [baseline])[0]
        self.assertEqual(result["response_classification"], "distinct_response")
        self.assertEqual(result["body_similarity"], 0.25)
        self.assertEqual(result["shared_not_found_marker_count"], 0)
        self.assertEqual(result["shared_not_found_markers"], [])

    @patch("app.routes.web_recon._gobuster_body_similarity", return_value=0.60)
    def test_two_stable_markers_and_review_similarity_can_classify_soft_404(self, _similarity):
        baseline = {
            "status_code": 200, "content_type": "text/html",
            "fingerprint": "baseline", "shingles": {"generic page", "not found"},
            "soft_404_markers": ["page not found", "resource unavailable"],
        }
        candidate = {
            "url": "https://example.test/missing", "status_code": 200,
            "_body_signature": {
                "fingerprint": "candidate", "content_type": "text/html",
                "shingles": {"generic page", "resource unavailable"},
                "soft_404_markers": ["page not found", "resource unavailable"],
            },
        }
        result = _classify_manual_path_records([candidate], [baseline, baseline.copy()])[0]
        self.assertEqual(result["response_classification"], "likely_soft_404")
        self.assertEqual(result["body_similarity"], 0.60)
        self.assertEqual(result["shared_not_found_marker_count"], 2)
        self.assertEqual(
            result["shared_not_found_markers"],
            ["page not found", "resource unavailable"],
        )

    @patch("app.routes.web_recon._gobuster_body_similarity", return_value=0.60)
    def test_one_shared_marker_is_not_enough_for_marker_based_soft_404(self, _similarity):
        baseline = {
            "status_code": 200, "content_type": "text/html",
            "fingerprint": "baseline", "shingles": {"generic page", "not found"},
            "soft_404_markers": ["page not found"],
        }
        candidate = {
            "url": "https://example.test/register", "status_code": 200,
            "_body_signature": {
                "fingerprint": "candidate", "content_type": "text/html",
                "shingles": {"generic page", "email address"},
                "soft_404_markers": ["page not found"],
            },
        }
        result = _classify_manual_path_records([candidate], [baseline, baseline.copy()])[0]
        self.assertEqual(result["response_classification"], "needs_verification")
        self.assertEqual(result["shared_not_found_marker_count"], 1)

    def test_manual_path_distinct_response_is_not_confirmed_as_endpoint(self):
        baseline = {
            "status_code": 200, "content_type": "text/html",
            "fingerprint": "baseline", "shingles": {"profile not found", "page unavailable"},
            "soft_404_markers": ["profile not found"],
        }
        candidate = {
            "url": "https://example.test/register", "status_code": 200,
            "_body_signature": {
                "fingerprint": "registration", "content_type": "text/html",
                "shingles": {"create account", "email address", "submit form"},
                "soft_404_markers": [],
            },
        }
        result = _classify_manual_path_records([candidate], [baseline])[0]
        self.assertEqual(result["response_classification"], "distinct_response")
        self.assertIn("not proof of a functional endpoint", result["classification_reason"])


    def test_manual_paths_are_relative_and_reject_traversal_or_query_components(self):
        self.assertEqual(_normalise_manual_path(" /owa "), "owa")
        self.assertEqual(_normalise_manual_path("api/v1/health"), "api/v1/health")
        for value in ("https://outside.example/admin", "//outside.example/admin", "../admin", "%2e%2e/admin", "admin?debug=1", r"admin\\login"):
            with self.subTest(value=value), self.assertRaises(HTTPException):
                _normalise_manual_path(value)

    def test_extract_html_response_features_counts_controls_without_values(self):
        body = b"""<html><form action="/login"><input type="email" value="private@example.test">
        <input type="password" value="secret"><button>Sign in</button></form>
        <a href="/register">Register</a><script src="/app.js"></script></html>"""
        features = _extract_html_response_features(body)
        self.assertEqual(features, {
            "form_count": 1, "input_count": 2, "password_input_count": 1,
            "email_input_count": 1, "link_count": 1, "script_count": 1,
            "button_count": 1,
            "forms": [{
                "method": "GET", "action": "/login",
                "inputs": [
                    {"type": "email", "name": None, "autocomplete": None, "required": False},
                    {"type": "password", "name": None, "autocomplete": None, "required": False},
                ],
            }],
        })
        self.assertNotIn("private@example.test", str(features))
        self.assertNotIn("secret", str(features))

    def test_extract_html_response_features_includes_safe_form_metadata(self):
        body = b"""<form method="post" action="/session/create?token=private#top">
        <input type="email" name="email" autocomplete="username" required value="secret@example.test">
        <input type="password" name="password" autocomplete="current-password" value="hunter2">
        <input type="hidden" name="csrf_token" value="private-token"></form>
        <form action="https://identity.example.test/submit"><input name="display_name"></form>"""
        features = _extract_html_response_features(body)
        self.assertEqual(features["form_count"], 2)
        self.assertEqual(features["forms"][0]["method"], "POST")
        self.assertEqual(features["forms"][0]["action"], "/session/create")
        self.assertEqual(features["forms"][0]["inputs"][0], {
            "type": "email", "name": "email", "autocomplete": "username", "required": True,
        })
        self.assertEqual(features["forms"][0]["inputs"][1]["autocomplete"], "current-password")
        self.assertEqual(features["forms"][1]["action"], "external destination")
        serialized = str(features)
        for private_value in ("secret@example.test", "hunter2", "private-token", "token=private"):
            self.assertNotIn(private_value, serialized)

    def test_page_fingerprint_identifies_registration_form(self):
        features = {"form_count": 1, "input_count": 5, "password_input_count": 2,
                    "email_input_count": 1, "script_count": 4,
                    "forms": [{"inputs": [{"name": "email", "type": "email"}, {"name": "password", "type": "password"}]}]}
        result = _fingerprint_html_page("Create your account", "Register to get started", features)
        self.assertEqual(result["page_type"], "registration")
        self.assertIn(result["confidence"], ("medium", "high"))

    def test_page_fingerprint_identifies_login_form(self):
        features = {"form_count": 1, "input_count": 2, "password_input_count": 1,
                    "email_input_count": 1, "script_count": 2, "forms": [{"inputs": []}]}
        result = _fingerprint_html_page("Sign in", "Welcome back", features)
        self.assertEqual(result["page_type"], "login")

    def test_page_fingerprint_identifies_missing_resource(self):
        result = _fingerprint_html_page("Profile not found", "This profile doesn't exist", {})
        self.assertEqual(result["page_type"], "error_or_not_found")

    def test_page_fingerprint_marks_script_heavy_shell_as_possible_spa(self):
        features = {"form_count": 0, "input_count": 0, "password_input_count": 0,
                    "email_input_count": 0, "script_count": 12, "forms": []}
        result = _fingerprint_html_page("Application", "Loading...", features)
        self.assertEqual(result["page_type"], "possible_spa_shell")

    def test_extract_html_response_features_handles_malformed_html(self):
        features = _extract_html_response_features(b"<form><input type=password><button>Login")
        self.assertEqual(features["form_count"], 1)
        self.assertEqual(features["password_input_count"], 1)

    @patch("app.routes.web_recon.requests.Session")
    def test_manual_path_probe_does_not_follow_redirects_and_reads_response_metadata(self, session_factory):
        response = MagicMock()
        response.status_code = 302
        response.reason = "Found"
        response.encoding = "utf-8"
        response.headers = {"Location": "/login", "Content-Type": "text/html; charset=utf-8", "Content-Length": "31"}
        response.iter_content.return_value = [b"<html><title>Moved</title></html>"]
        session = session_factory.return_value
        session.get.return_value.__enter__.return_value = response
        result = _check_manual_path("https://example.test/owa")
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(result["response_title"], "Moved")
        self.assertEqual(result["response_content_type"], "text/html")
        self.assertIn("Moved", result["response_preview"])
        self.assertEqual(result["redirect_location"], "/login")
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertFalse(session.trust_env)

    @patch("app.routes.assessments.record_tool_execution", return_value={"id": 27})
    @patch("app.routes.assessments.assert_target_in_scope", return_value={"assessment_id": 1, "target_id": 2})
    @patch("app.routes.web_recon._check_manual_path")
    def test_manual_directory_checks_are_scoped_persisted_and_deduplicated(self, check_path, _scope, record):
        check_path.side_effect = lambda url: {"url": url, "status_code": 200, "classification_reason": "Observed"}
        result = check_manual_directories(ManualPathCheckRequest(
            assessment_id=1, url="https://example.test", paths=["/owa", "ecp", "/owa"], authorized=True
        ))
        self.assertEqual(result["execution_id"], 27)
        self.assertEqual([item["url"] for item in result["records"]], [
            "https://example.test/owa", "https://example.test/ecp"
        ])
        record.assert_called_once()
        self.assertEqual(record.call_args.args[1], "manual-path-check")

    def test_manual_directory_checks_require_authorization(self):
        with self.assertRaises(HTTPException) as raised:
            check_manual_directories(ManualPathCheckRequest(
                assessment_id=1, url="https://example.test", paths=["owa"], authorized=False
            ))
        self.assertEqual(raised.exception.status_code, 400)


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
    @patch("app.routes.web_recon._run_bounded_process", side_effect=subprocess.TimeoutExpired(cmd="httpx", timeout=30))
    def test_scanner_timeout_is_persisted(self, _run, _which, _scope, record):
        request = ToolRunRequest(assessment_id=1, tool_id="httpx", url="https://example.test", authorized=True)
        with self.assertRaises(HTTPException) as raised:
            run_recon_tool(request)
        self.assertEqual(raised.exception.status_code, 504)
        self.assertEqual(record.call_args.args[5], 124)

    def test_scanner_output_is_capped_and_process_is_stopped(self):
        result = _run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 200000)"],
            {"timeout": 5, "max_output": 4096},
            {"PATH": os.environ.get("PATH", "")},
        )
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(len(result["stdout"].encode("utf-8")), 4096)
        self.assertLessEqual(result["output_size"], 4096)
        self.assertIn("process group was terminated", result["stderr"])

    def test_scanner_wall_clock_timeout_raises_after_stopping_process_group(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            _run_bounded_process(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                {"timeout": 0.1, "max_output": 4096},
                {"PATH": os.environ.get("PATH", "")},
            )

    def test_scanner_cancellation_stops_process_and_preserves_partial_output(self):
        cancel_event = threading.Event()
        timer = threading.Timer(0.2, cancel_event.set)
        timer.start()
        try:
            result = _run_bounded_process(
                [sys.executable, "-u", "-c", "import sys,time; print('started', flush=True); time.sleep(5)"],
                {"timeout": 5, "max_output": 4096},
                {"PATH": os.environ.get("PATH", "")},
                cancel_event=cancel_event,
            )
        finally:
            timer.cancel()
        self.assertTrue(result["cancelled"])
        self.assertIn("started", result["stdout"])
    @patch("app.routes.assessments.create_execution_job", return_value={"id": "job-123", "assessment_id": 1, "tool_id": "httpx", "target_url": "https://example.test", "state": "queued"})
    @patch("app.routes.assessments.assert_target_in_scope", return_value={"assessment_id": 1, "target_id": 2})
    @patch("app.routes.web_recon.shutil.which", return_value="/usr/bin/httpx")
    def test_queue_route_returns_persistent_job_and_schedules_worker(self, _which, _scope, create_job):
        from fastapi import BackgroundTasks
        background = BackgroundTasks()
        request = ToolRunRequest(
            assessment_id=1, tool_id="httpx", url="https://example.test", authorized=True,
        )
        result = queue_recon_tool(request, background)
        self.assertEqual(result["id"], "job-123")
        self.assertEqual(result["state"], "queued")
        self.assertEqual(len(background.tasks), 1)
        self.assertEqual(background.tasks[0].args[0], "job-123")
        create_job.assert_called_once_with(1, "httpx", "https://example.test")

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
        self.assertIn("-cos", command)
        self.assertEqual(command[command.index("-cos") + 1], r"(%5[cC]|\\)")
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
            _build_tool_command("not-a-tool", "/usr/bin/not-a-tool", "https://example.test")

if __name__ == "__main__":
    unittest.main()


class GobusterAdapterTests(unittest.TestCase):
    def test_gobuster_command_is_directory_only_bounded_and_does_not_follow_redirects(self):
        command = _build_tool_command(
            "gobuster", "/usr/bin/gobuster", "https://example.test/app",
            "/usr/share/wordlists/common.txt", "php,html",
        )
        self.assertEqual(command[:3], ["/usr/bin/gobuster", "dir", "-u"])
        self.assertIn("-w", command)
        self.assertEqual(command[command.index("-w") + 1], "/usr/share/wordlists/common.txt")
        self.assertEqual(command[command.index("-t") + 1], "2")
        self.assertEqual(command[command.index("--delay") + 1], "500ms")
        self.assertEqual(command[command.index("--timeout") + 1], "8s")
        self.assertNotIn("-l", command)  # Not supported by all packaged Gobuster versions.
        self.assertEqual(command[command.index("-s") + 1], "200,204,301,302,307,401,403")
        self.assertEqual(command[command.index("--status-codes-blacklist") + 1], "")
        self.assertNotIn("--exclude-length", command)
        self.assertEqual(command[command.index("-x") + 1], "php,html")
        self.assertNotIn("-r", command)
        self.assertNotIn("dns", command)
        self.assertNotIn("vhost", command)

    def test_gobuster_command_excludes_measured_wildcard_length(self):
        command = _build_tool_command(
            "gobuster", "/usr/bin/gobuster", "https://example.test",
            "/usr/share/wordlists/common.txt", "", 37900,
        )
        self.assertEqual(command[command.index("--exclude-length") + 1], "37900")

    @patch("app.routes.web_recon.requests.Session")
    def test_gobuster_wildcard_probe_measures_decoded_body_without_following_redirects(self, session_factory):
        response = MagicMock()
        response.__enter__.return_value = response
        response.headers = {"Content-Length": "100"}
        response.status_code = 200
        response.iter_content.return_value = [b"x" * 37900]
        session = session_factory.return_value
        session.get.return_value = response
        profile = _probe_gobuster_wildcard_length("https://example.test/")
        self.assertEqual(profile["exclude_length"], 37900)
        self.assertEqual(profile["status_codes"], [200])
        self.assertEqual(profile["reference_length"], 37900)
        self.assertEqual(profile["length_tolerance"], 379)
        self.assertEqual(len(profile["body_signatures"]), 5)
        self.assertIn("fingerprint", profile["body_signatures"][0])
        self.assertFalse(session.trust_env)
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertRegex(session.get.call_args.args[0], r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        self.assertEqual(session.get.call_count, 5)

    @patch("app.routes.web_recon.requests.Session")
    def test_gobuster_wildcard_probe_keeps_variable_lengths(self, session_factory):
        responses = []
        for length in (37892, 37894, 37892, 37894, 37900):
            response = MagicMock()
            response.__enter__.return_value = response
            response.status_code = 200
            response.iter_content.return_value = [b"x" * length]
            responses.append(response)
        session = session_factory.return_value
        session.get.side_effect = responses
        profile = _probe_gobuster_wildcard_length("https://example.test/")
        self.assertEqual(profile["exclude_length"], "37892-37900")
        self.assertEqual(profile["min_length"], 37892)
        self.assertEqual(profile["max_length"], 37900)

    @patch("app.routes.web_recon.requests.Session")
    def test_gobuster_candidate_fetch_is_bounded_and_does_not_follow_redirects(self, session_factory):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.encoding = "utf-8"
        response.iter_content.return_value = [b"<html><body>generic missing page</body></html>"]
        session = session_factory.return_value
        session.get.return_value = response
        result = _fetch_gobuster_candidate_body("https://example.test/admin")
        self.assertEqual(result[0], 200)
        self.assertIn("fingerprint", result[1])
        self.assertFalse(session.trust_env)
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
        self.assertEqual(session.get.call_args.kwargs["timeout"], (3.0, 5.0))
        session.close.assert_called_once()

    @patch("app.routes.web_recon._fetch_gobuster_candidate_body")
    def test_gobuster_classifies_near_baseline_using_body_fingerprints_without_dropping_records(self, fetch_body):
        baseline = _gobuster_body_signature(b"<html><body>generic missing page not found</body></html>")
        fetch_body.return_value = (200, baseline)
        records = [
            {"url": "https://example.test/owa", "status_code": 200, "content_length": 37860},
            {"url": "https://example.test/admin", "status_code": 200, "content_length": 41000},
            {"url": "https://example.test/login", "status_code": 302, "content_length": 0},
        ]
        summary = _classify_gobuster_records(records, {
            "status_codes": [200], "min_length": 37858, "max_length": 37880,
            "reference_length": 37870, "length_tolerance": 128,
            "body_signatures": [{"status_code": 200, **baseline}],
        }, "https://example.test/")
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["response_classification"], "suspected_wildcard")
        self.assertEqual(records[1]["response_classification"], "distinct_response")
        self.assertEqual(records[2]["response_classification"], "distinct_response")
        self.assertEqual(summary["suspected_wildcard"], 1)
        self.assertEqual(summary["distinct_response"], 2)
        self.assertEqual(records[0]["body_similarity"], 1.0)
        fetch_body.assert_called_once_with("https://example.test/owa")

    @patch("app.routes.web_recon._fetch_gobuster_candidate_body")
    def test_gobuster_same_size_different_body_is_distinct(self, fetch_body):
        baseline = _gobuster_body_signature(b"<html><body>generic missing page not found</body></html>")
        actual = _gobuster_body_signature(b"<html><body>administrative portal sign in dashboard</body></html>")
        fetch_body.return_value = (200, actual)
        records = [{"url": "https://example.test/admin", "status_code": 200, "content_length": 37860}]
        summary = _classify_gobuster_records(records, {
            "status_codes": [200], "min_length": 37860, "max_length": 37860,
            "reference_length": 37860, "length_tolerance": 128,
            "body_signatures": [{"status_code": 200, **baseline}],
        }, "https://example.test/")
        self.assertEqual(records[0]["response_classification"], "distinct_response")
        self.assertLess(records[0]["body_similarity"], 0.92)
        self.assertEqual(summary["distinct_response"], 1)

    @patch("app.routes.web_recon._fetch_gobuster_candidate_body")
    def test_gobuster_marks_profile_not_found_shared_with_random_paths_as_soft_404(self, fetch_body):
        body = (
            b"<html><title>Profile not found</title><body>"
            b"<h1>Profile not found</h1>"
            b"<p>This profile doesn't exist or has been removed.</p>"
            b"<footer>Support information</footer></body></html>"
        )
        baseline = _gobuster_body_signature(body)
        candidate = _gobuster_body_signature(
            body.replace(b"Support information", b"Requested profile: owa")
        )
        fetch_body.return_value = (200, candidate)
        records = [{"url": "https://example.test/owa", "status_code": 200, "content_length": 37860}]
        summary = _classify_gobuster_records(records, {
            "status_codes": [200], "min_length": 37860, "max_length": 37860,
            "reference_length": 37860, "length_tolerance": 128,
            "body_signatures": [
                {"status_code": 200, **baseline},
                {"status_code": 200, **baseline},
                {"status_code": 200, **baseline},
            ],
        }, "https://example.test/")
        self.assertEqual(records[0]["response_classification"], "likely_soft_404")
        self.assertIn("profile not found", records[0]["soft_404_markers"])
        self.assertEqual(summary["likely_soft_404"], 1)
        self.assertEqual(summary["distinct_response"], 0)

    @patch("app.routes.web_recon._fetch_gobuster_candidate_body")
    def test_gobuster_soft_404_groups_require_matching_status_title_type_and_markers(self, fetch_body):
        baseline_body = b"<html><title>Profile not found</title><body>Profile not found</body></html>"
        baseline = _gobuster_body_signature(baseline_body)
        same_group = _gobuster_body_signature(
            b"<html><title>Profile not found</title><body>Profile not found for this path</body></html>"
        )
        different_title = _gobuster_body_signature(
            b"<html><title>Account unavailable</title><body>Profile not found</body></html>"
        )
        different_type = dict(same_group, content_type="application/json")
        fetch_body.side_effect = [
            (200, same_group),
            (200, same_group),
            (200, different_title),
            (200, different_type),
        ]
        records = [
            {"url": f"https://example.test/{path}", "status_code": 200, "content_length": 100}
            for path in ("one", "two", "three", "four")
        ]
        _classify_gobuster_records(records, {
            "status_codes": [200], "min_length": 100, "max_length": 100,
            "reference_length": 100, "length_tolerance": 128,
            "body_signatures": [
                {"status_code": 200, **baseline},
                {"status_code": 200, **baseline},
            ],
        }, "https://example.test/")
        self.assertEqual(records[0]["response_group_id"], records[1]["response_group_id"])
        self.assertNotEqual(records[0]["response_group_id"], records[2]["response_group_id"])
        self.assertNotEqual(records[0]["response_group_id"], records[3]["response_group_id"])

    @patch("app.routes.web_recon._gobuster_body_similarity", return_value=0.905)
    @patch("app.routes.web_recon._fetch_gobuster_candidate_body")
    def test_gobuster_borderline_body_similarity_needs_verification(self, fetch_body, _similarity):
        baseline = _gobuster_body_signature(b"<html><body>generic random response content</body></html>")
        candidate = _gobuster_body_signature(b"<html><body>different response content</body></html>")
        fetch_body.return_value = (200, candidate)
        records = [{"url": "https://example.test/ecp", "status_code": 200, "content_length": 37860}]
        summary = _classify_gobuster_records(records, {
            "status_codes": [200], "min_length": 37860, "max_length": 37860,
            "reference_length": 37860, "length_tolerance": 128,
            "body_signatures": [
                {"status_code": 200, **baseline},
                {"status_code": 200, **baseline},
            ],
        }, "https://example.test/")
        self.assertEqual(records[0]["response_classification"], "needs_verification")
        self.assertEqual(summary["needs_verification"], 1)
        self.assertEqual(summary["distinct_response"], 0)

    def test_gobuster_body_signature_normalizes_common_dynamic_values(self):
        first = _gobuster_body_signature(
            b"<p>Request 123e4567-e89b-12d3-a456-426614174000 at 2026-11-01T12:00:00Z</p>"
            b'<input name="csrf" value="abcdefgh12345678">'
        )
        second = _gobuster_body_signature(
            b"<p>Request 123e4567-e89b-12d3-a456-426614174999 at 2026-11-02T13:30:00Z</p>"
            b'<input name="csrf" value="zyxwvuts87654321">'
        )
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    @patch("app.routes.web_recon._fetch_gobuster_candidate_body")
    def test_gobuster_rejects_cross_origin_fingerprint_followup(self, fetch_body):
        baseline = _gobuster_body_signature(b"<html><body>generic missing page</body></html>")
        records = [{"url": "https://outside.example/admin", "status_code": 200, "content_length": 100}]
        summary = _classify_gobuster_records(records, {
            "status_codes": [200], "min_length": 100, "max_length": 100,
            "reference_length": 100, "length_tolerance": 128,
            "body_signatures": [{"status_code": 200, **baseline}],
        }, "https://example.test/")
        self.assertEqual(records[0]["response_classification"], "unverified")
        self.assertEqual(summary["unverified"], 1)
        fetch_body.assert_not_called()

    def test_gobuster_marks_missing_response_metadata_unverified(self):
        records = [{"url": "https://example.test/unknown", "status_code": 200, "content_length": None}]
        summary = _classify_gobuster_records(records, {
            "status_codes": [200], "min_length": 100, "max_length": 100,
            "reference_length": 100, "length_tolerance": 128,
            "body_signatures": [],
        }, "https://example.test/")
        self.assertEqual(records[0]["response_classification"], "unverified")
        self.assertEqual(summary["unverified"], 1)

    def test_gobuster_parser_supports_legacy_and_current_output_and_deduplicates(self):
        output = (
            "/admin (Status: 200) [Size: 123]\n"
            "[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 2ms] https://example.test/login\n"
            "/admin (Status: 200) [Size: 123]\n"
        )
        records = _parse_gobuster_output(output, "https://example.test/")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["url"], "https://example.test/admin")
        self.assertEqual(records[0]["status_code"], 200)
        self.assertEqual(records[0]["content_length"], 123)
        self.assertEqual(records[0]["observations"], 2)
        self.assertEqual(records[1]["url"], "https://example.test/login")
        self.assertEqual(records[1]["status_code"], 301)

    def test_gobuster_parser_rejects_cross_origin_and_unstructured_lines(self):
        output = (
            "https://other.example/admin (Status: 200) [Size: 1]\n"
            "https://user@example.test/private (Status: 200) [Size: 1]\n"
            "https://example.test/path#fragment (Status: 200) [Size: 1]\n"
            "/safe (Status: 200) [Size: 2]\n"
            "Progress: 100 / 100\n"
        )
        records = _parse_gobuster_output(output, "https://example.test/")
        self.assertEqual([record["url"] for record in records], ["https://example.test/safe"])

    def test_gobuster_extensions_are_normalised_and_validated(self):
        self.assertEqual(_normalise_gobuster_extensions(" .PHP,html,php "), "php,html")
        for invalid in ("php,../etc", "x" * 11, ",".join(["txt"] * 11)):
            with self.subTest(invalid=invalid), self.assertRaises(HTTPException):
                _normalise_gobuster_extensions(invalid)

    def test_wordlist_catalog_only_exposes_supported_text_lists(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "common.txt"), "w", encoding="utf-8") as handle:
                handle.write("admin\\n")
            with open(os.path.join(directory, "notes.md"), "w", encoding="utf-8") as handle:
                handle.write("not a wordlist")
            with patch.dict(os.environ, {"MSF_WEB_WORDLIST_DIRS": directory}):
                lists = _list_wordlists()
        self.assertEqual([item["name"] for item in lists], ["common.txt"])
        self.assertEqual(lists[0]["id"], "0:common.txt")

    def test_wordlist_catalog_discovers_standard_nested_seclists_web_content_path(self):
        with tempfile.TemporaryDirectory() as directory:
            nested = os.path.join(directory, "SecLists", "Discovery", "Web-Content")
            os.makedirs(nested)
            wordlist = os.path.join(nested, "raft-medium-directories.txt")
            with open(wordlist, "w", encoding="utf-8") as handle:
                handle.write("admin\\nlogin\\n")
            with patch.dict(os.environ, {"MSF_WEB_WORDLIST_DIRS": directory}):
                lists = _list_wordlists()
                selected = _resolve_wordlist("0:SecLists/Discovery/Web-Content/raft-medium-directories.txt")
        self.assertEqual(len(lists), 1)
        self.assertEqual(lists[0]["name"], "SecLists/Discovery/Web-Content/raft-medium-directories.txt")
        self.assertEqual(str(selected), wordlist)

    def test_wordlist_roots_include_project_local_wordlists_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("app.routes.web_recon._project_wordlist_root", return_value=__import__("pathlib").Path(directory)):
                with patch.dict(os.environ, {}, clear=True):
                    roots = _wordlist_roots()
        self.assertEqual(str(roots[0]), os.path.realpath(directory))

    def test_wordlist_resolution_is_limited_to_configured_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.realpath(directory)
            wordlist = os.path.join(root, "common.txt")
            with open(wordlist, "w", encoding="utf-8") as handle:
                handle.write("admin\nlogin\n")
            with patch.dict(os.environ, {"MSF_WEB_WORDLIST_DIRS": root}):
                self.assertEqual(str(_resolve_wordlist("0:common.txt")), wordlist)
                with self.assertRaises(HTTPException):
                    _resolve_wordlist("0:../outside.txt")
                with self.assertRaises(HTTPException):
                    _resolve_wordlist("/etc/passwd")

    @patch("app.routes.assessments.record_tool_execution", return_value={"id": 77})
    @patch("app.routes.assessments.assert_target_in_scope", return_value={"assessment_id": 1, "target_id": 2})
    @patch("app.routes.web_recon.shutil.which", return_value="/usr/bin/gobuster")
    @patch("app.routes.web_recon._probe_gobuster_wildcard_length", return_value={
        "exclude_length": 37900, "status_codes": [200], "min_length": 37900,
        "max_length": 37900, "reference_length": 37900, "length_tolerance": 379,
    })
    @patch("app.routes.web_recon._run_bounded_process")
    def test_gobuster_run_persists_parsed_same_origin_results(self, run_process, _probe, _which, _scope, record):
        run_process.return_value = {
            "returncode": 0,
            "stdout": "/admin (Status: 200) [Size: 123]\n",
            "stderr": "",
            "output_size": 35,
            "output_truncated": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            wordlist = os.path.join(directory, "common.txt")
            with open(wordlist, "w", encoding="utf-8") as handle:
                handle.write("admin\n")
            with patch.dict(os.environ, {"MSF_WEB_WORDLIST_DIRS": directory}):
                result = run_recon_tool(ToolRunRequest(
                    assessment_id=1, tool_id="gobuster", url="https://example.test",
                    authorized=True, wordlist_id="0:common.txt", extensions="php,html",
                ))
        self.assertEqual(result["execution_id"], 77)
        self.assertEqual(result["records"][0]["url"], "https://example.test/admin")
        self.assertEqual(result["records"][0]["status_code"], 200)
        self.assertEqual(record.call_args.args[1], "gobuster")
        command = run_process.call_args.args[0]
        self.assertEqual(command[1], "dir")
        self.assertNotIn("-r", command)
        self.assertEqual(command[command.index("--exclude-length") + 1], "37900")

    def test_gobuster_is_an_allowed_request_tool(self):
        request = ToolRunRequest(
            assessment_id=1, tool_id="gobuster", url="https://example.test",
            authorized=True, wordlist_id="0:common.txt", extensions="php,html",
        )
        self.assertEqual(request.tool_id, "gobuster")


class SpecialistAdapterTests(unittest.TestCase):
    def test_tool_request_accepts_specialist_adapters(self):
        for tool_id in ("nikto", "wpscan", "amass", "testssl.sh", "nmap"):
            request = ToolRunRequest(
                assessment_id=1, tool_id=tool_id,
                url="https://example.test", authorized=True,
            )
            self.assertEqual(request.tool_id, tool_id)

    def test_specialist_commands_are_fixed_and_bounded(self):
        nikto = _build_tool_command("nikto", "/usr/bin/nikto", "https://example.test")
        self.assertIn("-maxtime", nikto)
        self.assertIn("90s", nikto)
        self.assertIn("-nointeractive", nikto)

        wpscan = _build_tool_command("wpscan", "/usr/bin/wpscan", "https://example.test")
        self.assertIn("--detection-mode", wpscan)
        self.assertIn("passive", wpscan)
        self.assertIn("--max-threads", wpscan)
        self.assertIn("1", wpscan)

        amass = _build_tool_command("amass", "/usr/bin/amass", "https://example.test")
        self.assertEqual(amass[1:4], ["enum", "-passive", "-d"])

        tls = _build_tool_command("testssl.sh", "/usr/bin/testssl.sh", "https://example.test:8443")
        self.assertEqual(tls[-1], "example.test:8443")
        with self.assertRaises(HTTPException):
            _build_tool_command("testssl.sh", "/usr/bin/testssl.sh", "http://example.test")

        nmap = _build_tool_command("nmap", "/usr/bin/nmap", "https://example.test")
        self.assertIn("--top-ports", nmap)
        self.assertIn("100", nmap)
        self.assertIn("-sT", nmap)
        self.assertNotIn("-sC", nmap)
        self.assertNotIn("-sU", nmap)

    def test_nmap_parser_keeps_open_tcp_service_evidence_only(self):
        xml = """<?xml version="1.0"?>
        <nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports>
          <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.2"/></port>
          <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
        </ports></host></nmaprun>"""
        records = _parse_specialist_tool_output("nmap", xml, "https://example.test")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["port"], 443)
        self.assertEqual(records[0]["service"], "https")
        self.assertEqual(records[0]["product"], "nginx")
        self.assertEqual(records[0]["evidence_type"], "open_service")

    def test_amass_parser_restricts_results_to_approved_hostname_suffix(self):
        output = (
            '{"name":"api.example.test","sources":["crtsh"]}\n'
            '{"name":"example.test.evil.test","sources":["other"]}\n'
            '{"name":"outside.test","sources":["other"]}'
        )
        records = _parse_specialist_tool_output("amass", output, "https://example.test")
        self.assertEqual([item["host"] for item in records], ["api.example.test"])
        self.assertEqual(records[0]["evidence_type"], "passive_subdomain")

    def test_wpscan_parser_returns_bounded_summary_without_raw_credentials(self):
        output = '{"version":{"number":"6.8"},"plugins":{"plugin-a":{},"plugin-b":{}},"themes":{"theme-a":{}},"interesting_findings":[{"url":"https://example.test/readme.html"}]}'
        records = _parse_specialist_tool_output("wpscan", output, "https://example.test")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["wordpress_version"], "6.8")
        self.assertEqual(records[0]["plugin_count"], 2)
        self.assertEqual(records[0]["theme_count"], 1)

    def test_testssl_parser_normalizes_json_findings(self):
        output = '[{"id":"TLS1_0","severity":"LOW","finding":"offered"}]'
        records = _parse_specialist_tool_output("testssl.sh", output, "https://example.test")
        self.assertEqual(records[0]["severity"], "LOW")
        self.assertEqual(records[0]["source"], "testssl.sh")

    def test_nikto_parser_normalizes_json_observations(self):
        output = '{"vulnerabilities":[{"id":"test-1","msg":"Header missing","url":"https://example.test/"}]}'
        records = _parse_specialist_tool_output("nikto", output, "https://example.test")
        self.assertEqual(records[0]["finding"], "Header missing")
        self.assertEqual(records[0]["source"], "nikto")


class ContentDiscoveryAdapterTests(unittest.TestCase):
    def test_nuclei_command_is_http_only_bounded_and_does_not_follow_redirects(self):
        command = _build_tool_command("nuclei", "/usr/bin/nuclei", "https://example.test")
        self.assertIn("-jsonl", command)
        self.assertIn("-dr", command)
        self.assertIn("-ni", command)
        self.assertEqual(command[command.index("-pt") + 1], "http")
        self.assertEqual(command[command.index("-rl") + 1], "2")
        self.assertEqual(command[command.index("-c") + 1], "1")
        self.assertEqual(command[command.index("-timeout") + 1], "8")
        self.assertNotIn("-t", command)
        self.assertNotIn("-fr", command)

    def test_nuclei_parser_keeps_same_origin_findings_and_deduplicates(self):
        output = (
            '{"template-id":"exposed-panel","type":"http","matched-at":"https://example.test/admin",'
            '"info":{"name":"Exposed panel","severity":"medium"},"matcher-name":"title",'
            '"extracted-results":["panel"]}\n'
            '{"template-id":"exposed-panel","type":"http","matched-at":"https://example.test/admin",'
            '"info":{"name":"Exposed panel","severity":"medium"},"matcher-name":"title"}\n'
            '{"template-id":"other","type":"http","matched-at":"https://other.example/admin",'
            '"info":{"name":"Other","severity":"high"}}\n'
            'not json\n'
        )
        records = _parse_nuclei_output(output, "https://example.test/")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["severity"], "medium")
        self.assertEqual(records[0]["observations"], 2)
        self.assertEqual(records[0]["assessment"].startswith("Nuclei template match"), True)

    def test_ffuf_command_is_fixed_and_bounded(self):
        command = _build_tool_command(
            "ffuf", "/usr/bin/ffuf", "https://example.test/app",
            "/wordlists/common.txt",
        )
        self.assertIn("https://example.test/app/FUZZ", command)
        self.assertIn("-json", command)
        self.assertIn("-noninteractive", command)
        self.assertEqual(command[command.index("-t") + 1], "1")
        self.assertEqual(command[command.index("-rate") + 1], "2")
        self.assertEqual(command[command.index("-timeout") + 1], "8")
        self.assertNotIn("-recursion", command)
        self.assertNotIn("-x", command)

    def test_feroxbuster_command_is_fixed_and_bounded(self):
        command = _build_tool_command(
            "feroxbuster", "/usr/bin/feroxbuster", "https://example.test/app",
            "/wordlists/common.txt",
        )
        self.assertEqual(command[command.index("--url") + 1], "https://example.test/app/")
        self.assertIn("--json", command)
        self.assertIn("--no-recursion", command)
        self.assertEqual(command[command.index("--threads") + 1], "1")
        self.assertEqual(command[command.index("--rate-limit") + 1], "2")
        self.assertEqual(command[command.index("--timeout") + 1], "8")
        self.assertNotIn("--redirects", command)

    def test_content_discovery_parsers_keep_same_origin_results(self):
        ffuf = _parse_content_discovery_json(
            "ffuf",
            '{"url":"https://example.test/admin","status":200,"length":123}\n'
            '{"url":"https://other.example/admin","status":200,"length":123}\n',
            "https://example.test/",
        )
        ferox = _parse_content_discovery_json(
            "feroxbuster",
            '{"type":"configuration"}\n'
            '{"type":"response","url":"https://example.test/login","path":"/login","status":302,"content_length":42}\n',
            "https://example.test/",
        )
        self.assertEqual(ffuf[0]["url"], "https://example.test/admin")
        self.assertEqual(ffuf[0]["content_length"], 123)
        self.assertEqual(ferox[0]["status_code"], 302)
        self.assertEqual(ferox[0]["source"], "feroxbuster")
