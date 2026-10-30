import unittest

from app.banner_parsing import parse_service_banner
from app.routes.modules import _check_verdict


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

    def test_metaspoloit_checkcode_safe_is_not_vulnerable(self):
        self.assertEqual(_check_verdict("CheckCode::Safe"), "not_vulnerable")

    def test_metaspoloit_checkcode_vulnerable_is_vulnerable(self):
        self.assertEqual(_check_verdict("CheckCode::Vulnerable"), "vulnerable")

    def test_unsupported_check_is_distinguished(self):
        self.assertEqual(_check_verdict("CheckCode::Unsupported"), "unsupported")

    def test_connection_failure_remains_unknown(self):
        self.assertEqual(_check_verdict("Connection refused"), "unknown")


if __name__ == "__main__":
    unittest.main()
