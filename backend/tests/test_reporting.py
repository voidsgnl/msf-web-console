import unittest
from unittest.mock import patch

from fastapi import Response

from app.reporting import build_assessment_report
from app.routes.db import download_assessment_report


class AssessmentReportTests(unittest.TestCase):
    def test_report_contains_workspace_summary_and_sections(self):
        report = build_assessment_report(
            "default",
            {
                "hosts": [{"address": "192.0.2.10"}],
                "services": [{"host": "192.0.2.10", "port": 443}],
                "vulns": [],
                "creds": [{"username": "tester"}],
                "loot": [{"name": "capture.txt"}],
            },
        )

        self.assertIn("Workspace Assessment", report)
        self.assertIn("Workspace:</strong> default", report)
        self.assertIn("Hosts", report)
        self.assertIn("Services", report)
        self.assertIn("Vulnerabilities", report)
        self.assertIn("Credentials (secrets omitted)", report)
        self.assertIn("Loot &amp; Evidence", report)
        self.assertIn("192.0.2.10", report)
        self.assertIn("capture.txt", report)

    def test_report_escapes_untrusted_html(self):
        report = build_assessment_report(
            '<script>alert("x")</script>',
            {"hosts": [{"address": '<img src=x onerror="alert(1)">'}]},
        )

        self.assertNotIn('<script>alert("x")</script>', report)
        self.assertNotIn('<img src=x onerror="alert(1)">', report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("&lt;img", report)

    def test_report_does_not_include_credential_secrets_or_filesystem_paths(self):
        report = build_assessment_report(
            "default",
            {
                "creds": [{
                    "username": "tester",
                    "password": "DO-NOT-REPORT-PASSWORD",
                    "private_data": "DO-NOT-REPORT-SECRET",
                }],
                "loot": [{
                    "name": "artifact.txt",
                    "path": "/tmp/private/artifact.txt",
                    "data": b"DO-NOT-REPORT-BYTES",
                }],
            },
        )

        self.assertIn("tester", report)
        self.assertIn("artifact.txt", report)
        self.assertNotIn("DO-NOT-REPORT-PASSWORD", report)
        self.assertNotIn("DO-NOT-REPORT-SECRET", report)
        self.assertNotIn("/tmp/private/artifact.txt", report)
        self.assertNotIn("DO-NOT-REPORT-BYTES", report)

    def test_report_endpoint_collects_active_workspace_and_downloads_html(self):
        rpc_responses = [
            {"workspace": "test-lab"},
            {"hosts": [{"address": "192.0.2.15"}]},
            {"services": [{"host": "192.0.2.15", "port": 8080}]},
            {"vulns": []},
            {"creds": [{"username": "tester", "private_data": "DO-NOT-REPORT"}]},
            {"loots": [{"name": "evidence.txt", "path": "/tmp/evidence.txt"}]},
        ]
        with patch("app.routes.db.rpc.call", side_effect=rpc_responses) as rpc_call:
            response = download_assessment_report()

        self.assertIsInstance(response, Response)
        self.assertEqual(response.media_type, "text/html")
        self.assertIn("attachment; filename=\"msf-assessment-test-lab-", response.headers["content-disposition"])
        self.assertIn("192.0.2.15", response.body.decode("utf-8"))
        self.assertNotIn("DO-NOT-REPORT", response.body.decode("utf-8"))
        self.assertEqual(rpc_call.call_count, 6)

    def test_empty_report_has_empty_state_for_each_section(self):
        report = build_assessment_report("empty-workspace", {})

        self.assertEqual(report.count("No records in this workspace."), 5)
        self.assertIn("empty-workspace", report)


if __name__ == "__main__":
    unittest.main()
