import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app.routes import assessment_msf, assessments


class AssessmentMetasploitLinkTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path_patch = patch(
            "app.routes.assessments._database_path",
            return_value=Path(self.tempdir.name) / "assessments.sqlite3",
        )
        self.path_patch.start()
        assessment_msf._initialise_activity_store()
        self.assessment = assessments.create_assessment(
            assessments.AssessmentCreate(name="MSF linkage")
        )
        self.target = assessments.add_assessment_target(
            self.assessment["id"],
            assessments.TargetCreate(url="https://approved.example", authorized=True),
        )

    def tearDown(self):
        self.path_patch.stop()
        self.tempdir.cleanup()

    def test_links_module_run_to_operator_selected_approved_target(self):
        reference = "yJWES2Y6d4MRyfFLWjqhqvon"
        with patch(
            "app.routes.assessment_msf.rpc.call",
            return_value={"status": "completed", "job_id": 17, "result": {"hosts": ["192.0.2.10"]}},
        ) as rpc_call:
            linked = assessment_msf.link_msf_activity(
                self.assessment["id"],
                assessment_msf.ActivityCreate(
                    kind="module_run", reference=reference, target_id=self.target["id"],
                    analyst_note="Operator reviewed the target association.",
                ),
            )
        self.assertEqual(linked["external_state"], "completed")
        self.assertEqual(linked["attribution"], "operator_assigned")
        self.assertNotIn("hosts", linked["snapshot"])
        rpc_call.assert_called_once_with("module.results", reference)
        listed = assessment_msf.list_linked_msf_activity(self.assessment["id"])
        self.assertEqual(len(listed["activity"]), 1)
        self.assertIn("not independent proof", listed["notice"])

    def test_rejects_target_outside_assessment(self):
        with patch("app.routes.assessment_msf.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                assessment_msf.link_msf_activity(
                    self.assessment["id"],
                    assessment_msf.ActivityCreate(
                        kind="module_run", reference="yJWES2Y6d4MRyfFLWjqhqvon",
                        target_id=999,
                    ),
                )
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()

    def test_rejects_unknown_session(self):
        with patch("app.routes.assessment_msf.rpc.call", return_value={}):
            with self.assertRaises(HTTPException) as raised:
                assessment_msf.link_msf_activity(
                    self.assessment["id"],
                    assessment_msf.ActivityCreate(
                        kind="session", reference="42", target_id=self.target["id"]
                    ),
                )
        self.assertEqual(raised.exception.status_code, 404)

    def test_session_snapshot_excludes_sensitive_fields(self):
        with patch(
            "app.routes.assessment_msf.rpc.call",
            return_value={"42": {
                "type": "meterpreter", "session_host": "192.0.2.10",
                "session_port": 443, "username": "secret-user",
                "password": "secret-password", "datastore": {"RHOSTS": "192.0.2.10"},
            }},
        ):
            linked = assessment_msf.link_msf_activity(
                self.assessment["id"],
                assessment_msf.ActivityCreate(
                    kind="session", reference="42", target_id=self.target["id"]
                ),
            )
        self.assertEqual(linked["snapshot"]["type"], "meterpreter")
        self.assertNotIn("username", linked["snapshot"])
        self.assertNotIn("password", linked["snapshot"])
        self.assertNotIn("datastore", linked["snapshot"])

    def test_activity_review_is_analyst_controlled(self):
        reference = "yJWES2Y6d4MRyfFLWjqhqvon"
        with patch("app.routes.assessment_msf.rpc.call", return_value={"status": "completed"}):
            linked = assessment_msf.link_msf_activity(
                self.assessment["id"],
                assessment_msf.ActivityCreate(
                    kind="module_run", reference=reference, target_id=self.target["id"]
                ),
            )
        reviewed = assessment_msf.review_linked_msf_activity(
            self.assessment["id"], linked["id"],
            assessment_msf.ActivityReview(review_state="reviewed", analyst_note="Checked."),
        )
        self.assertEqual(reviewed["review_state"], "reviewed")
        self.assertEqual(reviewed["analyst_note"], "Checked.")


    def test_unified_report_includes_linked_metasploit_activity(self):
        reference = "yJWES2Y6d4MRyfFLWjqhqvon"
        with patch(
            "app.routes.assessment_msf.rpc.call",
            return_value={"status": "completed", "job_id": 21, "result": {"hosts": ["192.0.2.5"]}},
        ):
            assessment_msf.link_msf_activity(
                self.assessment["id"],
                assessment_msf.ActivityCreate(
                    kind="module_run", reference=reference, target_id=self.target["id"]
                ),
            )
        with patch("app.routes.assessments.correlate_software_cves") as nvd:
            report = assessments.build_assessment_report(self.assessment["id"], include_nvd=False)
        self.assertEqual(len(report["metasploit_activity"]), 1)
        self.assertEqual(report["executive_summary"]["metasploit_activity"], 1)
        self.assertEqual(report["metasploit_activity"][0]["attribution"], "operator_assigned")
        self.assertIn("not independent proof", report["metasploit_notice"])
        nvd.assert_not_called()


    def test_links_registered_loot_with_hash_and_includes_it_in_report(self):
        payload = b"sample evidence artifact"
        record = {
            "name": "loot.txt", "ltype": "text/plain", "ctype": "text/plain",
            "host": "192.0.2.10", "service": "http", "created_at": "2026-11-02T10:00:00",
            "path": "/private/server/path/loot.txt",
        }
        download_id = "0." + "a" * 64
        with patch("app.routes.assessment_msf.rpc.call", return_value={"loots": [record]}), \
             patch("app.routes.assessment_msf.msf_db._loot_fingerprint", return_value="a" * 64), \
             patch("app.routes.assessment_msf.msf_db._loot_payload", return_value=payload):
            linked = assessment_msf.link_msf_loot(
                self.assessment["id"],
                assessment_msf.LootLinkCreate(
                    download_id=download_id, target_id=self.target["id"],
                    analyst_note="Collected during the approved assessment.",
                ),
            )
        import hashlib
        self.assertEqual(linked["artifact_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(linked["artifact_size"], len(payload))
        self.assertNotIn("path", linked["snapshot"])
        self.assertEqual(linked["snapshot"]["name"], "loot.txt")
        reviewed = assessment_msf.review_linked_msf_loot(
            self.assessment["id"], linked["id"],
            assessment_msf.LootLinkReview(review_state="reviewed", analyst_note="Hash recorded."),
        )
        self.assertEqual(reviewed["review_state"], "reviewed")
        with patch("app.routes.assessment_msf.rpc.call", return_value={"loots": [record]}), \
             patch("app.routes.assessment_msf.msf_db._loot_fingerprint", return_value="a" * 64), \
             patch("app.routes.assessment_msf.msf_db._loot_payload", return_value=payload), \
             patch("app.routes.assessments.correlate_software_cves"):
            report = assessments.build_assessment_report(self.assessment["id"], include_nvd=False)
        self.assertEqual(len(report["metasploit_loot"]), 1)
        self.assertEqual(report["executive_summary"]["metasploit_loot"], 1)
        self.assertEqual(report["metasploit_loot"][0]["artifact_sha256"], hashlib.sha256(payload).hexdigest())

    def test_rejects_loot_for_target_outside_assessment(self):
        with patch("app.routes.assessment_msf.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                assessment_msf.link_msf_loot(
                    self.assessment["id"],
                    assessment_msf.LootLinkCreate(
                        download_id="0." + "a" * 64, target_id=999
                    ),
                )
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()


    def test_rejects_stale_or_changed_loot_reference(self):
        record = {"name": "loot.txt", "path": "/private/loot.txt"}
        with patch("app.routes.assessment_msf.rpc.call", return_value={"loots": [record]}), \
             patch("app.routes.assessment_msf.msf_db._loot_fingerprint", return_value="b" * 64):
            with self.assertRaises(HTTPException) as raised:
                assessment_msf.link_msf_loot(
                    self.assessment["id"],
                    assessment_msf.LootLinkCreate(
                        download_id="0." + "a" * 64, target_id=self.target["id"]
                    ),
                )
        self.assertEqual(raised.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
