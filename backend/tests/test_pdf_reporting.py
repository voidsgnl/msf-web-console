import unittest
from unittest.mock import patch

from fastapi import Response

from app.pdf_reporting import build_assessment_report_pdf
from app.routes.db import download_assessment_report_pdf


class PdfAssessmentReportTests(unittest.TestCase):
    def test_pdf_renderer_returns_searchable_pdf_and_applies_redactions(self):
        pdf = build_assessment_report_pdf(
            "pdf-lab",
            {
                "hosts": [{"address": "192.0.2.25", "name": "lab-host"}],
                "services": [{"host": "192.0.2.25", "port": 443, "proto": "tcp", "name": "https", "state": "open"}],
                "vulns": [{
                    "name": "Example vulnerability",
                    "host": "192.0.2.25",
                    "port": 443,
                    "severity": "high",
                    "info": "password=hunter2 found in /tmp/private/evidence.txt",
                    "refs": ["CVE-2021-41773"],
                }],
                "creds": [{
                    "username": "lab-user",
                    "password": "DO-NOT-REPORT-PASSWORD",
                    "private_data": "DO-NOT-REPORT-SECRET",
                }],
                "loot": [{
                    "name": "evidence.txt",
                    "path": "/tmp/private/evidence.txt",
                    "data": b"DO-NOT-REPORT-BYTES",
                }],
            },
        )

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn(b"Assessment Report", pdf)
        self.assertIn(b"192.0.2.25", pdf)
        self.assertIn(b"Prioritized Vulnerability Findings", pdf)
        self.assertIn(b"Open-Service Exposure Observations", pdf)
        self.assertNotIn(b"DO-NOT-REPORT-PASSWORD", pdf)
        self.assertNotIn(b"DO-NOT-REPORT-SECRET", pdf)
        self.assertNotIn(b"DO-NOT-REPORT-BYTES", pdf)
        self.assertNotIn(b"hunter2", pdf)
        self.assertNotIn(b"/tmp/private/evidence.txt", pdf)

    def test_pdf_endpoint_collects_snapshot_and_sets_download_headers(self):
        rpc_responses = [
            {"workspace": "test-lab"},
            {"hosts": [{"address": "192.0.2.15"}]},
            {"services": [{"host": "192.0.2.15", "port": 8080, "state": "open"}]},
            {"vulns": [{"name": "Example issue", "severity": "high", "host": "192.0.2.15"}]},
            {"creds": [{"username": "tester", "private_data": "DO-NOT-REPORT"}]},
            {"loots": [{"name": "evidence.txt", "path": "/tmp/evidence.txt", "data": b"file-bytes"}]},
        ]
        with patch("app.routes.db.rpc.call", side_effect=rpc_responses) as rpc_call:
            response = download_assessment_report_pdf()

        self.assertIsInstance(response, Response)
        self.assertEqual(response.media_type, "application/pdf")
        self.assertTrue(response.body.startswith(b"%PDF-"))
        self.assertIn('attachment; filename="msf-assessment-test-lab-', response.headers["content-disposition"])
        self.assertTrue(response.headers["content-disposition"].endswith('.pdf"'))
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn(b"192.0.2.15", response.body)
        self.assertNotIn(b"DO-NOT-REPORT", response.body)
        self.assertEqual(rpc_call.call_count, 6)


if __name__ == "__main__":
    unittest.main()
