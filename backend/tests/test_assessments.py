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


if __name__ == "__main__":
    unittest.main()
