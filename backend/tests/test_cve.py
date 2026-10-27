import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.nvd_client import NvdClient, NvdError, extract_cve_ids
from app.routes.cve import lookup_cve, workspace_enrichment


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "published": "2021-10-05T00:00:00.000",
                "lastModified": "2022-01-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "en", "value": "A path traversal flaw was found in Apache HTTP Server."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "references": [{"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}],
            }
        }
    ]
}


class ExtractCveIdsTests(unittest.TestCase):
    def test_extracts_from_plain_string_refs(self):
        record = {"refs": ["CVE-2021-41773", "URL-https://example.com"]}
        self.assertEqual(extract_cve_ids(record), {"CVE-2021-41773"})

    def test_extracts_from_nested_ref_hashes_case_insensitively(self):
        record = {"refs": [{"ctx_id": "CVE", "ctx_val": "2023-1234"}], "name": "cve-2023-1234 found"}
        self.assertEqual(extract_cve_ids(record), {"CVE-2023-1234"})

    def test_returns_empty_set_when_no_cve_present(self):
        self.assertEqual(extract_cve_ids({"refs": ["URL-https://example.com"]}), set())


class NvdClientTests(unittest.TestCase):
    def setUp(self):
        self.client = NvdClient()
        self.client._min_interval_seconds = 0  # don't slow down tests

    def test_get_cve_rejects_malformed_id_without_a_request(self):
        with patch("app.nvd_client.requests.get") as get:
            with self.assertRaises(NvdError):
                self.client.get_cve("not-a-cve")
        get.assert_not_called()

    def test_get_cve_returns_summarized_record_and_caches_it(self):
        response = MagicMock(status_code=200)
        response.json.return_value = SAMPLE_NVD_RESPONSE
        with patch("app.nvd_client.requests.get", return_value=response) as get:
            first = self.client.get_cve("cve-2021-41773")
            second = self.client.get_cve("CVE-2021-41773")

        self.assertEqual(first["cve_id"], "CVE-2021-41773")
        self.assertEqual(first["cvss"]["base_score"], 9.8)
        self.assertEqual(first["cvss"]["base_severity"], "CRITICAL")
        self.assertEqual(first, second)
        get.assert_called_once()  # second call served from cache

    def test_get_cve_returns_none_and_caches_miss_on_empty_nvd_result(self):
        response = MagicMock(status_code=200)
        response.json.return_value = {"vulnerabilities": []}
        with patch("app.nvd_client.requests.get", return_value=response) as get:
            first = self.client.get_cve("CVE-1999-0001")
            second = self.client.get_cve("CVE-1999-0001")
        self.assertIsNone(first)
        self.assertIsNone(second)
        get.assert_called_once()  # miss is cached too

    def test_get_cve_raises_on_rate_limit_response(self):
        response = MagicMock(status_code=429, text="rate limited")
        with patch("app.nvd_client.requests.get", return_value=response):
            with self.assertRaises(NvdError):
                self.client.get_cve("CVE-2021-41773")

    def test_get_cve_raises_on_network_failure(self):
        import requests as requests_module

        with patch("app.nvd_client.requests.get", side_effect=requests_module.exceptions.ConnectionError("boom")):
            with self.assertRaises(NvdError):
                self.client.get_cve("CVE-2021-41773")


class CveRouteTests(unittest.TestCase):
    def test_lookup_cve_rejects_bad_format_before_any_lookup(self):
        with patch("app.routes.cve.nvd_client.get_cve") as get_cve:
            with self.assertRaises(HTTPException) as raised:
                lookup_cve("definitely-not-a-cve")
        self.assertEqual(raised.exception.status_code, 400)
        get_cve.assert_not_called()

    def test_lookup_cve_returns_404_when_nvd_has_no_record(self):
        with patch("app.routes.cve.nvd_client.get_cve", return_value=None):
            with self.assertRaises(HTTPException) as raised:
                lookup_cve("CVE-1999-0001")
        self.assertEqual(raised.exception.status_code, 404)

    def test_lookup_cve_returns_summary_on_success(self):
        summary = {"cve_id": "CVE-2021-41773"}
        with patch("app.routes.cve.nvd_client.get_cve", return_value=summary):
            result = lookup_cve("cve-2021-41773")
        self.assertEqual(result, summary)

    def test_workspace_enrichment_extracts_and_enriches_cves_from_vulns(self):
        vulns_response = {
            "vulns": [
                {"host": "192.0.2.10", "name": "Apache Path Traversal", "refs": ["CVE-2021-41773"]},
                {"host": "192.0.2.11", "name": "No CVE here", "refs": ["URL-https://example.com"]},
            ]
        }
        with patch("app.routes.cve.rpc.call", return_value=vulns_response), \
             patch("app.routes.cve.nvd_client.get_cve", return_value={"cve_id": "CVE-2021-41773"}) as get_cve:
            result = workspace_enrichment(limit=25)

        self.assertEqual(result["total_cves_found"], 1)
        self.assertIn("CVE-2021-41773", result["enriched"])
        self.assertEqual(result["matched_records"]["CVE-2021-41773"][0]["host"], "192.0.2.10")
        self.assertEqual(result["remaining_cves"], [])
        get_cve.assert_called_once_with("CVE-2021-41773")

    def test_workspace_enrichment_pages_when_more_cves_than_limit(self):
        vulns_response = {
            "vulns": [
                {"host": "h1", "name": "a", "refs": ["CVE-2020-0001"]},
                {"host": "h2", "name": "b", "refs": ["CVE-2020-0002"]},
                {"host": "h3", "name": "c", "refs": ["CVE-2020-0003"]},
            ]
        }
        with patch("app.routes.cve.rpc.call", return_value=vulns_response), \
             patch("app.routes.cve.nvd_client.get_cve", return_value=None):
            result = workspace_enrichment(limit=2)

        self.assertEqual(result["total_cves_found"], 3)
        self.assertEqual(len(result["enriched"]), 2)
        self.assertEqual(result["remaining_cves"], ["CVE-2020-0003"])

    def test_workspace_enrichment_records_per_cve_errors_without_failing_the_call(self):
        vulns_response = {"vulns": [{"host": "h1", "name": "a", "refs": ["CVE-2021-41773"]}]}
        with patch("app.routes.cve.rpc.call", return_value=vulns_response), \
             patch("app.routes.cve.nvd_client.get_cve", side_effect=NvdError("rate limited")):
            result = workspace_enrichment(limit=25)

        self.assertEqual(result["errors"]["CVE-2021-41773"], "rate limited")
        self.assertEqual(result["enriched"], {})

    def test_workspace_enrichment_rejects_out_of_range_limit(self):
        with patch("app.routes.cve.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                workspace_enrichment(limit=0)
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
