import unittest

from app.routes.db import (
    _loot_bytes,
    _loot_download_id,
    _public_loot_record,
    _safe_content_type,
    _safe_loot_filename,
)


class LootHelperTests(unittest.TestCase):
    def test_loot_bytes_preserves_binary_and_encodes_text(self):
        self.assertEqual(_loot_bytes(bytes([0, 255])), bytes([0, 255]))
        self.assertEqual(_loot_bytes("evidence"), b"evidence")
        self.assertIsNone(_loot_bytes(None))

    def test_download_reference_is_stable_and_changes_with_content(self):
        record = {
            "name": "capture.bin",
            "ltype": "capture",
            "ctype": "application/octet-stream",
            "host": "192.0.2.10",
            "created_at": 100,
            "data": b"first content",
        }
        self.assertEqual(_loot_download_id(record), _loot_download_id(dict(record)))
        changed = dict(record, data=b"different content")
        self.assertNotEqual(_loot_download_id(record), _loot_download_id(changed))

    def test_public_record_omits_artifact_bytes_and_server_paths(self):
        record = {
            "name": "capture.bin",
            "path": "/srv/metasploit/loot/capture.bin",
            "data": b"secret evidence",
            "ctype": "application/octet-stream",
        }
        public = _public_loot_record(record)
        self.assertNotIn("data", public)
        self.assertNotIn("path", public)
        self.assertTrue(public["has_data"])
        self.assertEqual(public["size"], len(b"secret evidence"))
        self.assertRegex(public["download_id"], r"^0\.[a-f0-9]{64}$")

    def test_filename_is_reduced_to_safe_basename(self):
        self.assertEqual(_safe_loot_filename(r"..\\..\\capture file.bin"), "capture_file.bin")
        self.assertEqual(_safe_loot_filename("../../.hidden"), "hidden")
        self.assertEqual(_safe_loot_filename(""), "loot-artifact.bin")

    def test_content_type_rejects_header_injection(self):
        self.assertEqual(_safe_content_type("application/octet-stream"), "application/octet-stream")
        self.assertEqual(_safe_content_type("text/plain\r\nX-Test: invalid"), "application/octet-stream")


if __name__ == "__main__":
    unittest.main()
