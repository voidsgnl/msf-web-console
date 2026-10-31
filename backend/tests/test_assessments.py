import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app.routes import assessments


class AssessmentStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "assessments.sqlite3"
        self.path_patch = patch("app.routes.assessments._database_path", return_value=self.path)
        self.path_patch.start()
        assessments._initialise()

    def tearDown(self):
        self.path_patch.stop()
        self.tempdir.cleanup()

    def test_create_assessment_and_list_it(self):
        created = assessments.create_assessment(
            assessments.AssessmentCreate(name="External web review", description="Approved test")
        )
        self.assertEqual(created["name"], "External web review")
        listed = assessments.list_assessments()["assessments"]
        self.assertEqual(listed[0]["id"], created["id"])
        self.assertEqual(listed[0]["target_count"], 0)

    def test_target_requires_explicit_authorization(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Scope test"))
        with self.assertRaises(HTTPException) as raised:
            assessments.add_assessment_target(
                created["id"],
                assessments.TargetCreate(url="https://example.test", authorized=False),
            )
        self.assertEqual(raised.exception.status_code, 400)

    def test_scope_allows_same_origin_and_rejects_other_origin(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Scope test"))
        target = assessments.add_assessment_target(
            created["id"],
            assessments.TargetCreate(url="https://example.test", authorized=True),
        )
        self.assertEqual(target["hostname"], "example.test")
        match = assessments.assert_target_in_scope(created["id"], "https://example.test/login")
        self.assertEqual(match["target_id"], target["id"])
        with self.assertRaises(HTTPException) as raised:
            assessments.assert_target_in_scope(created["id"], "https://other.example/")
        self.assertEqual(raised.exception.status_code, 403)

    def test_scope_distinguishes_ports(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Port test"))
        assessments.add_assessment_target(
            created["id"],
            assessments.TargetCreate(url="https://example.test:8443", authorized=True),
        )
        with self.assertRaises(HTTPException):
            assessments.assert_target_in_scope(created["id"], "https://example.test/")

    def test_completed_assessment_cannot_accept_or_execute_targets(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Lifecycle test"))
        assessments.update_assessment_status(
            created["id"], assessments.AssessmentStatusUpdate(status="completed")
        )
        with self.assertRaises(HTTPException) as add_error:
            assessments.add_assessment_target(
                created["id"],
                assessments.TargetCreate(url="https://example.test", authorized=True),
            )
        self.assertEqual(add_error.exception.status_code, 409)
        with self.assertRaises(HTTPException) as run_error:
            assessments.assert_target_in_scope(created["id"], "https://example.test")
        self.assertEqual(run_error.exception.status_code, 409)

    def test_execution_records_persist_and_return_evidence(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Evidence test"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test/path")
        saved = assessments.record_tool_execution(
            scope, "httpx", "https://example.test/path", "2026-10-31T10:00:00+00:00",
            "2026-10-31T10:00:02+00:00", 0, False, [{"status_code": 200}], "",
        )
        history = assessments.list_assessment_executions(created["id"])["executions"]
        self.assertEqual(history[0]["id"], saved["id"])
        detail = assessments.get_assessment_execution(created["id"], saved["id"])
        self.assertEqual(detail["records"], [{"status_code": 200}])
        self.assertEqual(detail["target_id"], target["id"])
    def test_duplicate_target_is_rejected(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Duplicate test"))
        request = assessments.TargetCreate(url="https://example.test", authorized=True)
        assessments.add_assessment_target(created["id"], request)
        with self.assertRaises(HTTPException) as raised:
            assessments.add_assessment_target(created["id"], request)
        self.assertEqual(raised.exception.status_code, 409)

    def test_execution_populates_in_scope_and_out_of_scope_assets_without_expanding_scope(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Asset inventory"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        saved = assessments.record_tool_execution(
            scope, "httpx", "https://example.test",
            "2026-10-31T10:00:00+00:00", "2026-10-31T10:00:02+00:00", 0, False,
            [
                {"url": "https://example.test/login", "status_code": 200},
                {"url": "https://external.test/admin", "status_code": 200},
                {"host": "external.test"},
            ], "",
        )
        assets = assessments.list_assessment_assets(created["id"])
        by_value = {(item["asset_type"], item["value"]): item for item in assets["assets"]}
        self.assertEqual(by_value[("url", "https://example.test/login")]["scope_state"], "in_scope")
        self.assertEqual(by_value[("url", "https://external.test/admin")]["scope_state"], "out_of_scope")
        self.assertEqual(by_value[("host", "external.test")]["scope_state"], "out_of_scope")
        detail = assessments.get_assessment(created["id"])
        self.assertEqual([item["id"] for item in detail["targets"]], [target["id"]])
        self.assertEqual(saved["tool_id"], "httpx")
        self.assertEqual(assets["counts"], {"total": 4, "in_scope": 2, "out_of_scope": 2})

    def test_asset_inventory_deduplicates_and_updates_last_seen(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Asset dedupe"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        assessments.record_tool_execution(
            scope, "httpx", "https://example.test", "2026-10-31T10:00:00+00:00",
            "2026-10-31T10:00:02+00:00", 0, False, [{"url": "https://example.test/login"}], "",
        )
        first = assessments.list_assessment_assets(created["id"])["assets"]
        original_first_seen = next(item["first_seen"] for item in first if item["value"] == "https://example.test/login")
        assessments.record_tool_execution(
            scope, "whatweb", "https://example.test", "2026-10-31T11:00:00+00:00",
            "2026-10-31T11:00:02+00:00", 0, False, [{"url": "https://example.test/login"}], "",
        )
        second = assessments.list_assessment_assets(created["id"])["assets"]
        login = next(item for item in second if item["value"] == "https://example.test/login")
        self.assertEqual(login["first_seen"], original_first_seen)
        self.assertEqual(login["last_seen"], "2026-10-31T11:00:02+00:00")
        self.assertEqual(login["source_tool"], "whatweb")


if __name__ == "__main__":
    unittest.main()
