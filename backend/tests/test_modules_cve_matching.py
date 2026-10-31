import unittest
from unittest.mock import patch

from app.nvd_client import NvdError
from app.routes.modules import suggest_modules


class SuggestModulesCveMatchingTests(unittest.TestCase):
    """
    Covers the NVD CVE cross-reference added to GET /modules/suggest:
    a candidate module is only marked cve_matches when its own declared
    CVE references overlap with the CVEs NVD independently reports for
    the confirmed product/version.
    """

    def test_candidate_with_overlapping_cve_is_boosted_and_flagged(self):
        module_list = {"modules": ["unix/ftp/vsftpd_234_backdoor"]}
        module_info = {
            "rank": 600,
            "fullname": "exploit/unix/ftp/vsftpd_234_backdoor",
            "description": "This module exploits a malicious backdoor in vsftpd.",
            "references": [["CVE", "2011-2523"], ["URL", "https://example.com"]],
        }
        with patch("app.routes.modules.rpc.call", side_effect=[module_list, module_info]), \
             patch(
                 "app.routes.modules.nvd_client.search_cve_ids_by_keyword",
                 return_value={"CVE-2011-2523"},
             ) as nvd_search:
            result = suggest_modules(service_info="vsftpd 2.3.4", port=21, types="exploit")

        nvd_search.assert_called_once_with("vsftpd", "2.3.4")
        self.assertEqual(len(result["candidates"]), 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["cve_matches"], ["CVE-2011-2523"])
        self.assertGreaterEqual(candidate["rank_weight"], 1000)
        self.assertIn("CVE-to-module match", result["note"])

    def test_candidate_without_overlapping_cve_is_not_flagged(self):
        module_list = {"modules": ["unix/ftp/vsftpd_234_backdoor"]}
        module_info = {
            "rank": 600,
            "fullname": "exploit/unix/ftp/vsftpd_234_backdoor",
            "description": "This module exploits a malicious backdoor in vsftpd.",
            "references": [["CVE", "1999-9999"]],
        }
        with patch("app.routes.modules.rpc.call", side_effect=[module_list, module_info]), \
             patch(
                 "app.routes.modules.nvd_client.search_cve_ids_by_keyword",
                 return_value={"CVE-2011-2523"},
             ):
            result = suggest_modules(service_info="vsftpd 2.3.4", port=21, types="exploit")

        candidate = result["candidates"][0]
        self.assertEqual(candidate["cve_matches"], [])
        self.assertLess(candidate["rank_weight"], 1000)

    def test_nvd_failure_degrades_to_name_matching_without_raising(self):
        module_list = {"modules": ["unix/ftp/vsftpd_234_backdoor"]}
        module_info = {
            "rank": 600,
            "fullname": "exploit/unix/ftp/vsftpd_234_backdoor",
            "description": "This module exploits a malicious backdoor in vsftpd.",
            "references": [["CVE", "2011-2523"]],
        }
        with patch("app.routes.modules.rpc.call", side_effect=[module_list, module_info]), \
             patch(
                 "app.routes.modules.nvd_client.search_cve_ids_by_keyword",
                 side_effect=NvdError("Could not reach the NVD API: boom"),
             ):
            result = suggest_modules(service_info="vsftpd 2.3.4", port=21, types="exploit")

        candidate = result["candidates"][0]
        self.assertEqual(candidate["cve_matches"], [])
        self.assertIn("NVD CVE cross-check unavailable", result["note"])

    def test_nvd_lookup_is_skipped_when_there_are_no_name_matches(self):
        with patch("app.routes.modules.rpc.call", return_value={"modules": []}), \
             patch("app.routes.modules.nvd_client.search_cve_ids_by_keyword") as nvd_search:
            result = suggest_modules(service_info="vsftpd 2.3.4", port=21, types="exploit")

        nvd_search.assert_not_called()
        self.assertEqual(result["candidates"], [])


if __name__ == "__main__":
    unittest.main()
