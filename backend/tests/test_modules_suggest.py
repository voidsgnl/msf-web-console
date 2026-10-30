import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routes.modules import suggest_modules


class SuggestModulesTests(unittest.TestCase):
    def test_suggests_candidates_matching_the_confirmed_banner(self):
        exploit_names = {
            "modules": [
                "unix/ftp/vsftpd_234_backdoor",
                "windows/smb/ms17_010_eternalblue",
                "multi/http/apache_mod_cgi_bash_env_exec",
            ]
        }
        vsftpd_info = {
            "rank": "excellent",
            "description": "This module exploits a malicious backdoor in vsftpd 2.3.4.",
            "references": [["CVE", "2011-2523"]],
        }
        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[exploit_names, vsftpd_info],
        ) as rpc_call:
            result = suggest_modules(detection_module="scanner/ftp/ftp_version", info="220 (vsFTPd 3.0.3)")

        self.assertEqual(result["product"], "vsftpd")
        self.assertEqual(result["version"], "3.0.3")
        self.assertEqual(len(result["suggestions"]), 1)
        suggestion = result["suggestions"][0]
        self.assertEqual(suggestion["name"], "unix/ftp/vsftpd_234_backdoor")
        self.assertEqual(suggestion["rank"], "excellent")
        self.assertEqual(suggestion["cve_ids"], ["CVE-2011-2523"])
        rpc_call.assert_any_call("module.exploits")
        rpc_call.assert_any_call("module.info", "exploit", "unix/ftp/vsftpd_234_backdoor")

    def test_unparseable_banner_returns_empty_suggestions_without_rpc(self):
        with patch("app.routes.modules.rpc.call") as rpc_call:
            result = suggest_modules(detection_module="scanner/ftp/ftp_version", info="220 some-custom-ftpd ready")
        self.assertIsNone(result["product"])
        self.assertEqual(result["suggestions"], [])
        self.assertIn("note", result)
        rpc_call.assert_not_called()

    def test_non_scanner_module_path_returns_empty_suggestions_without_rpc(self):
        with patch("app.routes.modules.rpc.call") as rpc_call:
            result = suggest_modules(detection_module="exploit/windows/smb/ms17_010_eternalblue", info="anything")
        self.assertIsNone(result["product"])
        rpc_call.assert_not_called()

    def test_results_sorted_by_rank_best_first(self):
        exploit_names = {"modules": ["a/vsftpd_one", "a/vsftpd_two"]}
        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[
                exploit_names,
                {"rank": "low", "description": ""},
                {"rank": "excellent", "description": ""},
            ],
        ):
            result = suggest_modules(detection_module="scanner/ftp/ftp_version", info="220 (vsFTPd 3.0.3)")
        names_in_order = [s["name"] for s in result["suggestions"]]
        self.assertEqual(names_in_order, ["a/vsftpd_two", "a/vsftpd_one"])

    def test_a_single_module_info_failure_does_not_abort_the_rest(self):
        from app.msf_rpc import MsfRpcError
        exploit_names = {"modules": ["a/vsftpd_one", "a/vsftpd_two"]}
        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[
                exploit_names,
                MsfRpcError("temporary RPC failure"),
                {"rank": "normal", "description": ""},
            ],
        ):
            result = suggest_modules(detection_module="scanner/ftp/ftp_version", info="220 (vsFTPd 3.0.3)")
        self.assertEqual(len(result["suggestions"]), 1)
        self.assertEqual(result["suggestions"][0]["name"], "a/vsftpd_two")

    def test_rejects_out_of_range_limit_without_rpc(self):
        with patch("app.routes.modules.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                suggest_modules(detection_module="scanner/ftp/ftp_version", info="220 (vsFTPd 3.0.3)", limit=100)
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()

    def test_description_is_truncated_at_a_word_boundary(self):
        long_description = "word " * 100
        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[{"modules": ["a/vsftpd_one"]}, {"rank": "good", "description": long_description}],
        ):
            result = suggest_modules(detection_module="scanner/ftp/ftp_version", info="220 (vsFTPd 3.0.3)")
        description = result["suggestions"][0]["description"]
        self.assertLessEqual(len(description), 301)
        self.assertTrue(description.endswith("…"))


if __name__ == "__main__":
    unittest.main()
