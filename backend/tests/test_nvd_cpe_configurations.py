import unittest
from unittest.mock import patch

from app.nvd_client import NvdClient, _summarize

VSFTPD_RANGE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.3.0",
    "versionEndExcluding": "2.3.5",
}
VSFTPD_OLD_RANGE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.0.0",
    "versionEndExcluding": "2.1.0",
}
APACHE_RANGE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.0",
    "versionEndExcluding": "2.5.0",
}
LINUX_PLATFORM = {
    "vulnerable": False,
    "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
}


def node(*matches, operator="OR", negate=False):
    return {"operator": operator, "negate": negate, "cpeMatch": list(matches)}


def assess(configurations, version="2.3.4", product="vsftpd"):
    record = _summarize({"configurations": configurations})
    with patch.object(NvdClient, "get_cve", return_value=record):
        return NvdClient().assess_product_version("CVE-2011-2523", product, version)


class ConfigurationExtractionTests(unittest.TestCase):
    def test_operators_negate_and_flat_matches_are_preserved(self):
        record = _summarize({
            "configurations": [{
                "operator": "AND",
                "nodes": [node(VSFTPD_RANGE), node(LINUX_PLATFORM)],
            }],
        })
        config = record["configurations"][0]
        self.assertEqual(config["operator"], "AND")
        self.assertEqual(len(config["nodes"]), 2)
        self.assertEqual(config["nodes"][0]["operator"], "OR")
        self.assertEqual(
            [match["criteria"] for match in config["cpe_matches"]],
            [VSFTPD_RANGE["criteria"], LINUX_PLATFORM["criteria"]],
        )
        self.assertFalse(config["cpe_matches"][1]["vulnerable"])


class CpeAndOrAssessmentTests(unittest.TestCase):
    def test_and_with_unconfirmable_platform_is_indeterminate(self):
        config = {"operator": "AND", "nodes": [node(VSFTPD_RANGE), node(LINUX_PLATFORM)]}
        self.assertEqual(assess([config]), "indeterminate")

    def test_and_with_version_out_of_range_is_not_affected_whatever_the_platform(self):
        config = {"operator": "AND", "nodes": [node(VSFTPD_RANGE), node(LINUX_PLATFORM)]}
        self.assertEqual(assess([config], version="2.3.5"), "not_affected")

    def test_multi_node_configuration_without_operator_is_treated_as_and(self):
        config = {"nodes": [node(VSFTPD_RANGE), node(LINUX_PLATFORM)]}
        self.assertEqual(assess([config]), "indeterminate")

    def test_or_node_is_affected_when_any_match_is_in_range(self):
        config = {"nodes": [node(VSFTPD_OLD_RANGE, VSFTPD_RANGE)]}
        self.assertEqual(assess([config]), "affected")

    def test_negated_node_inverts_a_definite_result(self):
        config = {"nodes": [node(VSFTPD_RANGE, negate=True)]}
        self.assertEqual(assess([config]), "not_affected")

    def test_negated_node_keeps_an_unknown_result_unknown(self):
        unparseable = {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "not-a-version",
        }
        config = {"nodes": [node(unparseable, negate=True)]}
        self.assertEqual(assess([config]), "indeterminate")

    def test_and_with_a_second_vulnerable_product_cannot_confirm(self):
        config = {"operator": "AND", "nodes": [node(VSFTPD_RANGE), node(APACHE_RANGE)]}
        self.assertEqual(assess([config]), "indeterminate")

    def test_other_product_configuration_does_not_hide_not_affected(self):
        configs = [
            {"nodes": [node(VSFTPD_RANGE)]},
            {"nodes": [node(APACHE_RANGE)]},
        ]
        self.assertEqual(assess(configs, version="2.3.5"), "not_affected")


if __name__ == "__main__":
    unittest.main()
