import unittest
from unittest.mock import patch

from app.nvd_client import NvdClient, NvdError, _summarize, extract_cve_ids
from app.routes.modules import _missing_required_check_options, suggest_modules


class CveReferenceExtractionTests(unittest.TestCase):
    def test_extracts_split_metaspoloit_reference_pairs(self):
        self.assertEqual(
            extract_cve_ids([["CVE", "2011-2523"], ["URL", "https://example.com"]]),
            {"CVE-2011-2523"},
        )

    def test_extracts_context_value_reference_records(self):
        self.assertEqual(
            extract_cve_ids({"ctx_id": "CVE", "ctx_val": "2021-41773"}),
            {"CVE-2021-41773"},
        )

    def test_extracts_full_cve_identifiers_from_nested_text(self):
        self.assertEqual(
            extract_cve_ids({"description": "Related issue CVE-2024-12345"}),
            {"CVE-2024-12345"},
        )


class NvdCpeVersionAssessmentTests(unittest.TestCase):
    def _record(self, criteria, **bounds):
        match = {"criteria": criteria, "vulnerable": True, **bounds}
        return {"configurations": [{"cpe_matches": [match]}]}

    def test_detected_version_inside_matching_product_range_is_affected(self):
        record = self._record(
            "cpe:2.3:a:vsftpd:vsftpd:*:*:*:*:*:*:*:*",
            version_start_including="2.3.0",
            version_end_excluding="2.3.5",
        )
        with patch.object(NvdClient, "get_cve", return_value=record):
            client = NvdClient()
            self.assertEqual(
                client.assess_product_version("CVE-2011-2523", "vsftpd", "2.3.4"),
                "affected",
            )

    def test_detected_version_outside_matching_product_range_is_not_affected(self):
        record = self._record(
            "cpe:2.3:a:vsftpd:vsftpd:*:*:*:*:*:*:*:*",
            version_start_including="2.3.0",
            version_end_excluding="2.3.5",
        )
        with patch.object(NvdClient, "get_cve", return_value=record):
            self.assertEqual(
                NvdClient().assess_product_version("CVE-2011-2523", "vsftpd", "2.3.5"),
                "not_affected",
            )

    def test_product_mismatch_is_indeterminate_not_not_affected(self):
        record = self._record(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            version_start_including="2.4.0",
            version_end_excluding="2.5.0",
        )
        with patch.object(NvdClient, "get_cve", return_value=record):
            self.assertEqual(
                NvdClient().assess_product_version("CVE-2024-0001", "vsftpd", "2.3.4"),
                "indeterminate",
            )

    def test_exact_cpe_version_is_compared_without_range_bounds(self):
        record = self._record("cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*")
        with patch.object(NvdClient, "get_cve", return_value=record):
            client = NvdClient()
            self.assertEqual(
                client.assess_product_version("CVE-2011-2523", "vsftpd", "2.3.4"),
                "affected",
            )
            self.assertEqual(
                client.assess_product_version("CVE-2011-2523", "vsftpd", "2.3.5"),
                "not_affected",
            )

    def test_nested_configuration_children_are_included(self):
        record = _summarize({
            "configurations": [{
                "nodes": [{
                    "operator": "AND",
                    "children": [{
                        "operator": "OR",
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:a:vsftpd:vsftpd:*:*:*:*:*:*:*:*",
                            "vulnerable": True,
                            "versionStartIncluding": "2.3.0",
                            "versionEndExcluding": "2.3.5",
                        }],
                    }],
                }],
            }],
        })
        with patch.object(NvdClient, "get_cve", return_value=record):
            self.assertEqual(
                NvdClient().assess_product_version("CVE-2011-2523", "vsftpd", "2.3.4"),
                "affected",
            )

    def test_unparseable_published_bound_is_indeterminate(self):
        record = self._record(
            "cpe:2.3:a:vsftpd:vsftpd:*:*:*:*:*:*:*:*",
            version_start_including="not-a-version",
        )
        with patch.object(NvdClient, "get_cve", return_value=record):
            self.assertEqual(
                NvdClient().assess_product_version("CVE-2011-2523", "vsftpd", "2.3.4"),
                "indeterminate",
            )



class ModuleCheckOptionPreflightTests(unittest.TestCase):
    def test_required_option_with_default_does_not_block_check(self):
        declared = {
            "RHOSTS": {"required": True, "default": None},
            "TARGETURI": {"required": True, "default": "/"},
        }
        self.assertEqual(
            _missing_required_check_options(declared, {"RHOSTS": "192.0.2.10"}),
            [],
        )

    def test_required_option_without_value_or_default_is_reported(self):
        declared = {
            "RHOSTS": {"required": True, "default": None},
            "TARGETURI": {"required": True, "default": None},
            "SSL": {"required": False, "default": False},
        }
        self.assertEqual(
            _missing_required_check_options(declared, {"RHOSTS": "192.0.2.10"}),
            ["TARGETURI"],
        )

    def test_unavailable_option_metadata_does_not_block_check(self):
        self.assertEqual(_missing_required_check_options(None, {}), [])


class SuggestModulesCveMatchingTests(unittest.TestCase):
    """
    Covers the NVD keyword cross-reference added to GET /modules/suggest.
    A shared identifier is evidence of overlapping references only; it
    does not prove that the detected version is in an affected CPE range.
    """

    @patch("app.routes.modules.nvd_client.assess_product_version", return_value="affected")
    def test_candidate_with_overlapping_cve_is_flagged_without_changing_rank(self, _assessment):
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
        self.assertEqual(
            candidate["cve_version_assessments"],
            [{"cve_id": "CVE-2011-2523", "status": "affected"}],
        )
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


    @patch("app.routes.modules.nvd_client.assess_product_version", return_value="affected")
    def test_shared_cve_reference_sorts_a_candidate_first_without_changing_native_rank(self, _assessment):
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
            side_effect=[module_list, cve_info, generic_info],
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
