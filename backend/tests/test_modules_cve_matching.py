import unittest
from unittest.mock import patch

from app.nvd_client import NvdError
from app.routes.modules import suggest_modules


class SuggestModulesCveMatchingTests(unittest.TestCase):
    """
    Covers the NVD keyword cross-reference added to GET /modules/suggest.
    A shared identifier is evidence of overlapping references only; it
    does not prove that the detected version is in an affected CPE range.
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
        self.assertEqual(candidate["rank_weight"], 600)  # native Metasploit rank is preserved
        self.assertIn("does not validate", result["note"])

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
        self.assertEqual(candidate["rank_weight"], 600)


    def test_shared_cve_reference_sorts_a_candidate_first_without_changing_native_rank(self):
        module_list = {
            "modules": [
                "unix/ftp/vsftpd_generic",
                "unix/ftp/vsftpd_234_backdoor",
            ]
        }
        generic_info = {
            "rank": 600,
            "fullname": "exploit/unix/ftp/vsftpd_generic",
            "description": "Generic vsftpd module.",
            "references": [["URL", "https://example.com"]],
        }
        cve_info = {
            "rank": 300,
            "fullname": "exploit/unix/ftp/vsftpd_234_backdoor",
            "description": "vsftpd backdoor module.",
            "references": [["CVE", "2011-2523"]],
        }
        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[module_list, generic_info, cve_info],
        ), patch(
            "app.routes.modules.nvd_client.search_cve_ids_by_keyword",
            return_value={"CVE-2011-2523"},
        ):
            result = suggest_modules(service_info="vsftpd 2.3.4", port=21, types="exploit")

        self.assertEqual(
            [candidate["name"] for candidate in result["candidates"]],
            ["unix/ftp/vsftpd_234_backdoor", "unix/ftp/vsftpd_generic"],
        )
        self.assertEqual(result["candidates"][0]["rank_weight"], 300)
        self.assertEqual(result["candidates"][1]["rank_weight"], 600)

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
