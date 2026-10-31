import unittest

from app.nvd_client import _compare_versions, _cpe_version_in_range


class VersionSuffixComparisonTests(unittest.TestCase):
    def test_openssh_patch_suffixes_are_compared_numerically(self):
        self.assertEqual(_compare_versions("9.6p2", "9.6p1"), 1)
        self.assertEqual(_compare_versions("9.6p1", "9.6p2"), -1)

    def test_openssh_patch_release_is_after_unsuffixed_base(self):
        self.assertEqual(_compare_versions("9.6p1", "9.6"), 1)
        self.assertEqual(_compare_versions("9.6", "9.6p1"), -1)

    def test_proftpd_lettered_release_suffixes_are_preserved(self):
        self.assertEqual(_compare_versions("1.3.5e", "1.3.5"), 1)
        self.assertEqual(_compare_versions("1.3.5f", "1.3.5e"), 1)

    def test_unknown_distro_suffix_is_not_silently_discarded(self):
        self.assertIsNone(_compare_versions("2.4.49-7ubuntu4", "2.4.49"))

    def test_suffix_aware_range_comparison(self):
        cpe_match = {
            "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            "version_start_including": "9.6p1",
            "version_end_excluding": "9.6p3",
        }
        self.assertTrue(_cpe_version_in_range(cpe_match, "9.6p2"))
        self.assertFalse(_cpe_version_in_range(cpe_match, "9.6p3"))

    def test_unrecognized_suffix_in_range_bound_is_indeterminate(self):
        cpe_match = {
            "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            "version_start_including": "9.6ubuntu1",
        }
        self.assertIsNone(_cpe_version_in_range(cpe_match, "9.6p2"))


if __name__ == "__main__":
    unittest.main()
