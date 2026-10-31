import unittest

from app.banner_parsing import parse_service_banner
from app.routes.modules import _check_failure_details, _check_verdict


class ScanDetectionRegressionTests(unittest.TestCase):
    def test_apache_coyote_is_tomcat_not_apache_httpd(self):
        parsed = parse_service_banner("Apache-Coyote/1.1", 8080)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.product, "Apache Tomcat")
        self.assertEqual(parsed.version, "unknown")

    def test_tomcat_version_is_parsed_before_apache_signature(self):
        parsed = parse_service_banner("Apache Tomcat/9.0.80", 8080)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.product, "Apache Tomcat")
        self.assertEqual(parsed.version, "9.0.80")

    def test_apache_httpd_version_still_parses(self):
        parsed = parse_service_banner("Apache/2.4.49 (Unix)", 80)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.product, "Apache httpd")
        self.assertEqual(parsed.version, "2.4.49")

    def test_running_service_is_not_a_negative_vulnerability_verdict(self):
        self.assertEqual(_check_verdict("The target service is running."), "unknown")

    def test_metasploit_checkcode_safe_is_not_vulnerable(self):
        self.assertEqual(_check_verdict("CheckCode::Safe"), "not_vulnerable")

    def test_metaspoloit_checkcode_vulnerable_is_vulnerable(self):
        self.assertEqual(_check_verdict("CheckCode::Vulnerable"), "vulnerable")

    def test_unsupported_check_is_distinguished(self):
        self.assertEqual(_check_verdict("CheckCode::Unsupported"), "unsupported")

    def test_connection_failure_remains_unknown(self):
        self.assertEqual(_check_verdict("Connection refused"), "unknown")
        self.assertEqual(_check_failure_details("Connection refused")["failure_kind"], "connection_failure")

    def test_tls_handshake_failure_is_not_reported_as_unreachable(self):
        output = (
            "Exploit failed [unreachable]: OpenSSL::SSL::SSLError "
            "SSL_connect returned=1 peeraddr=192.0.2.10:443 "
            "state=error: unexpected eof while reading"
        )
        self.assertEqual(_check_verdict(output), "unknown")
        details = _check_failure_details(output)
        self.assertEqual(details["failure_kind"], "tls_failure")
        self.assertIn("TLS negotiation failed", details["failure_message"])

    def test_http_error_is_classified_separately(self):
        details = _check_failure_details("Received HTTP/1.1 503 Service Unavailable")
        self.assertEqual(details["failure_kind"], "http_error")

    def test_cloudflare_is_classified_as_edge_not_origin_product(self):
        from app.routes.modules import _classify_service_observation

        result = _classify_service_observation("cloudflare (403-Forbidden)", 80)
        self.assertEqual(result["protocol"], "http")
        self.assertEqual(result["edge_provider"], "cloudflare")
        self.assertEqual(result["http_status"], 403)
        self.assertEqual(result["access_state"], "forbidden")
        self.assertEqual(result["origin_visibility"], "edge_proxy")
        self.assertIn("not a vulnerability verdict", result["summary"])

    def test_plain_http_403_is_classified_without_cloudflare_claim(self):
        from app.routes.modules import _classify_service_observation

        result = _classify_service_observation("HTTP/1.1 403 Forbidden", 8080)
        self.assertIsNone(result["edge_provider"])
        self.assertEqual(result["http_status"], 403)
        self.assertEqual(result["access_state"], "forbidden")

    def test_cloudflare_suggestions_fall_back_to_generic_http_modules(self):
        from unittest.mock import patch

        from app.routes.modules import suggest_modules

        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[
                {"modules": ["scanner/http/http_version", "scanner/http/apache_userdir_enum", "auxiliary/admin/http/accellion_fta_getstatus_oauth"]},
                {"rank": 300, "description": "HTTP service fingerprint"},
                {"rank": 200, "description": "Apache user directory enumeration"},
            ],
        ) as rpc_call:
            result = suggest_modules("cloudflare (403-Forbidden)", port=80, types="auxiliary")

        self.assertEqual(result["query"], "http")
        self.assertEqual(result["service_assessment"]["edge_provider"], "cloudflare")
        self.assertEqual(result["service_assessment"]["http_status"], 403)
        self.assertEqual(
            [item["name"] for item in result["candidates"]],
            ["scanner/http/http_version", "scanner/http/apache_userdir_enum"],
        )
        self.assertTrue(all(item["type"] == "auxiliary" for item in result["candidates"]))
        self.assertIn("Cloudflare", result["note"])
        self.assertNotIn(
            "cloudflare",
            [call.args[-1].lower() for call in rpc_call.call_args_list
             if len(call.args) > 1 and call.args[0] == "module.info"],
        )
        self.assertFalse(any(call.args[0] == "module.exploits" for call in rpc_call.call_args_list))

    def test_apache_coyote_suggestions_search_tomcat_not_apache_projects(self):
        from unittest.mock import patch

        from app.routes.modules import suggest_modules

        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[
                {"modules": ["scanner/http/tomcat_mgr_login", "scanner/http/apache_userdir_enum"]},
                {"rank": 300, "description": "Tomcat manager login scanner"},
            ],
        ) as rpc_call:
            result = suggest_modules("Apache-Coyote/1.1", port=8080, types="auxiliary")

        self.assertEqual(result["query"], "tomcat")
        self.assertEqual([item["name"] for item in result["candidates"]], ["scanner/http/tomcat_mgr_login"])
        self.assertEqual(rpc_call.call_args_list[1].args, ("module.info", "auxiliary", "scanner/http/tomcat_mgr_login"))


if __name__ == "__main__":
    unittest.main()
