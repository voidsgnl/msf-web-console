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
        self.assertEqual(detail["records"][0]["status_code"], 200)
        self.assertTrue(detail["records"][0]["record_id"])
        self.assertEqual(detail["records"][0]["review_state"], "active")
        self.assertEqual(detail["records"][0]["notes"], "")
        self.assertEqual(detail["target_id"], target["id"])
    def test_execution_records_receive_common_non_verdict_evidence_envelope(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Evidence schema"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        saved = assessments.record_tool_execution(
            scope, "nmap", "https://example.test",
            "2026-11-02T00:00:00+00:00", "2026-11-02T00:00:10+00:00", 0, False,
            [
                {"host": "example.test", "port": 443, "service": "https", "severity": "CRITICAL"},
                {"host": "api.example.test", "evidence_type": "passive_subdomain",
                 "source_tool": "untrusted-parser-value", "verification_state": "verified"},
                {"finding": "TLS configuration observation", "severity": "not-a-severity"},
            ],
            "",
        )
        records = assessments.get_assessment_execution(created["id"], saved["id"])["records"]
        service, discovered_host, observation = records

        for record in records:
            self.assertEqual(record["evidence_schema_version"], 1)
            self.assertEqual(record["source_tool"], "nmap")
            self.assertEqual(record["target_url"], "https://example.test")
            self.assertEqual(record["observed_at"], "2026-11-02T00:00:10+00:00")
            self.assertEqual(record["confidence"], "unassessed")
            self.assertEqual(record["verification_state"], "unverified")
            self.assertTrue(record["summary"])

        self.assertEqual(service["observation_type"], "open_service")
        self.assertEqual(service["severity"], "critical")
        self.assertEqual(discovered_host["observation_type"], "passive_subdomain")
        self.assertEqual(discovered_host["source_tool"], "nmap")
        self.assertEqual(observation["severity"], "unknown")

    def test_nmap_open_tcp_services_are_indexed_without_expanding_scope(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Service inventory"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        saved = assessments.record_tool_execution(
            scope, "nmap", "https://example.test",
            "2026-11-02T00:00:00+00:00", "2026-11-02T00:00:10+00:00", 0, False,
            [
                {"host": "192.0.2.10", "hostnames": ["example.test"], "port": 443,
                 "protocol": "tcp", "state": "open", "service": "https",
                 "product": "nginx", "version": "1.2"},
                {"host": "other.example.test", "port": 22, "protocol": "tcp", "state": "open",
                 "service": "ssh"},
                {"host": "example.test", "port": 23, "protocol": "tcp", "state": "closed",
                 "service": "telnet"},
                {"host": "example.test", "port": 53, "protocol": "udp", "state": "open",
                 "service": "domain"},
                {"host": "example.test", "port": 70000, "protocol": "tcp", "state": "open",
                 "service": "invalid"},
            ],
            "",
        )
        inventory = assessments.list_assessment_services(created["id"])
        self.assertEqual(inventory["counts"], {"total": 2, "in_scope": 1, "out_of_scope": 1})
        by_endpoint = {(item["hostname"], item["port"]): item for item in inventory["services"]}
        self.assertEqual(by_endpoint[("192.0.2.10", 443)]["product"], "nginx")
        self.assertEqual(by_endpoint[("192.0.2.10", 443)]["scope_state"], "in_scope")
        self.assertEqual(by_endpoint[("other.example.test", 22)]["scope_state"], "out_of_scope")
        self.assertEqual(
            assessments.list_assessment_assets(created["id"])["counts"]["out_of_scope"], 1
        )
        self.assertEqual(assessments.get_assessment_execution(created["id"], saved["id"])["tool_id"], "nmap")

    def test_persistent_job_state_and_restart_recovery(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Job lifecycle"))
        job = assessments.create_execution_job(created["id"], "nuclei", "https://example.test")
        self.assertEqual(job["state"], "queued")
        running = assessments.update_execution_job(job["id"], "running")
        self.assertEqual(running["state"], "running")
        self.assertIsNotNone(running["started_at"])
        self.assertEqual(assessments.get_execution_job(created["id"], job["id"])["id"], job["id"])
        self.assertEqual(assessments.list_execution_jobs(created["id"])["jobs"][0]["id"], job["id"])
        self.assertEqual(assessments.recover_stale_execution_jobs(), 1)
        recovered = assessments.get_execution_job(created["id"], job["id"])
        self.assertEqual(recovered["state"], "interrupted")
        self.assertIsNotNone(recovered["finished_at"])

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


    def test_discovered_subdomains_remain_out_of_scope_until_approved(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Passive discovery"))
        approved = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        assessments.record_tool_execution(
            scope, "subfinder", "https://example.test", "2026-10-31T12:00:00+00:00",
            "2026-10-31T12:00:20+00:00", 0, False,
            [{"host": "api.example.test", "sources": ["crtsh"]}], "",
        )
        inventory = assessments.list_assessment_assets(created["id"])
        discovered = next(item for item in inventory["assets"] if item["value"] == "api.example.test")
        self.assertEqual(discovered["asset_type"], "host")
        self.assertEqual(discovered["scope_state"], "out_of_scope")
        detail = assessments.get_assessment(created["id"])
        self.assertEqual([item["id"] for item in detail["targets"]], [approved["id"]])

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


    def test_manual_path_checks_remain_evidence_without_promoting_paths_to_assets(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Manual path observations"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        saved = assessments.record_tool_execution(
            scope, "manual-path-check", "https://example.test/",
            "2026-11-01T10:00:00+00:00", "2026-11-01T10:00:05+00:00", 0, False,
            [
                {"url": "https://example.test/admin", "status_code": 200,
                 "classification_reason": "HTTP response observed; endpoint validity is unverified."},
                {"url": "https://example.test/xxxxxx", "status_code": 200,
                 "classification_reason": "Generic application response."},
            ],
            "",
        )

        inventory = assessments.list_assessment_assets(created["id"])
        values = {item["value"] for item in inventory["assets"]}
        self.assertIn("https://example.test", values)
        self.assertNotIn("https://example.test/admin", values)
        self.assertNotIn("https://example.test/xxxxxx", values)

        execution = assessments.get_assessment_execution(created["id"], saved["id"])
        self.assertEqual(len(execution["records"]), 2)
        self.assertEqual(
            {record["url"] for record in execution["records"]},
            {"https://example.test/admin", "https://example.test/xxxxxx"},
        )

    def test_record_review_dismiss_restore_and_notes_persist(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Record lifecycle"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        saved = assessments.record_tool_execution(
            scope, "katana", "https://example.test", "2026-11-01T10:00:00+00:00",
            "2026-11-01T10:00:02+00:00", 0, False,
            [{"url": "https://example.test/login", "status_code": 200}], "",
        )
        record = assessments.get_assessment_execution(created["id"], saved["id"])["records"][0]
        record_id = record["record_id"]
        dismissed = assessments.update_execution_record(
            created["id"], saved["id"], record_id,
            assessments.ExecutionRecordUpdate(review_state="dismissed", reviewed=True, notes="Expected login route."),
        )
        self.assertEqual(dismissed["review_state"], "dismissed")
        self.assertIsNotNone(dismissed["reviewed_at"])
        self.assertEqual(dismissed["notes"], "Expected login route.")
        restored = assessments.update_execution_record(
            created["id"], saved["id"], record_id,
            assessments.ExecutionRecordUpdate(review_state="active", reviewed=False),
        )
        self.assertEqual(restored["review_state"], "active")
        self.assertIsNone(restored["reviewed_at"])
        detail = assessments.get_assessment_execution(created["id"], saved["id"])
        self.assertEqual(detail["records"][0]["notes"], "Expected login route.")

    def test_permanent_record_delete_retains_run_and_rebuilds_asset_inventory(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Record deletion"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        saved = assessments.record_tool_execution(
            scope, "katana", "https://example.test", "2026-11-01T10:00:00+00:00",
            "2026-11-01T10:00:02+00:00", 0, False,
            [{"url": "https://example.test/login", "status_code": 200},
             {"url": "https://example.test/admin", "status_code": 200}], "",
        )
        records = assessments.get_assessment_execution(created["id"], saved["id"])["records"]
        assessments.delete_execution_record(created["id"], saved["id"], records[0]["record_id"])
        detail = assessments.get_assessment_execution(created["id"], saved["id"])
        self.assertEqual(len(detail["records"]), 1)
        self.assertEqual(detail["records"][0]["url"], "https://example.test/admin")
        assets = assessments.list_assessment_assets(created["id"])["assets"]
        values = {item["value"] for item in assets}
        self.assertNotIn("https://example.test/login", values)
        self.assertIn("https://example.test/admin", values)
        self.assertEqual(
            [item["id"] for item in assessments.list_assessment_executions(created["id"])["executions"]],
            [saved["id"]],
        )

    def test_record_management_rejects_unknown_record(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Unknown record"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], target["url"])
        saved = assessments.record_tool_execution(
            scope, "httpx", target["url"], "2026-11-01T10:00:00+00:00",
            "2026-11-01T10:00:02+00:00", 0, False, [{"status_code": 200}], "",
        )
        with self.assertRaises(HTTPException) as raised:
            assessments.update_execution_record(
                created["id"], saved["id"], "missing",
                assessments.ExecutionRecordUpdate(notes="no"),
            )
        self.assertEqual(raised.exception.status_code, 404)


    def test_assessment_wide_record_management_comparison_and_history(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Evidence workspace"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], target["url"])
        first = assessments.record_tool_execution(
            scope, "httpx", target["url"], "2026-11-01T10:00:00+00:00",
            "2026-11-01T10:00:02+00:00", 0, False,
            [{"url": "https://example.test/a", "status_code": 200},
             {"url": "https://example.test/same", "status_code": 200}], "",
        )
        second = assessments.record_tool_execution(
            scope, "httpx", target["url"], "2026-11-01T11:00:00+00:00",
            "2026-11-01T11:00:02+00:00", 0, False,
            [{"url": "https://example.test/b", "status_code": 200},
             {"url": "https://example.test/same", "status_code": 200}], "",
        )
        first_records = assessments.get_assessment_execution(created["id"], first["id"])["records"]
        chosen = first_records[0]["record_id"]
        bulk = assessments.bulk_update_assessment_records(
            created["id"], {"record_ids": [chosen], "record_type": "finding", "reviewed": True}
        )
        self.assertEqual(bulk["updated"], 1)
        listed = assessments.list_assessment_records(created["id"])
        classified = next(item for item in listed["records"] if item["record_id"] == chosen)
        self.assertEqual(classified["record_type"], "finding")
        self.assertIsNotNone(classified["reviewed_at"])
        filtered = assessments.list_assessment_records(created["id"], q="/same")
        self.assertEqual(len(filtered["records"]), 2)
        compared = assessments.compare_assessment_runs(created["id"], first["id"], second["id"])
        self.assertEqual(len(compared["added"]), 1)
        self.assertEqual(len(compared["removed"]), 1)
        self.assertEqual(len(compared["unchanged"]), 1)
        history = assessments.assessment_history_report(created["id"])
        self.assertEqual(history["total_runs"], 2)
        self.assertEqual(history["total_records"], 4)
        self.assertEqual(history["findings"], 1)
        self.assertEqual(history["evidence"], 3)
        deleted = assessments.bulk_delete_assessment_records(
            created["id"], {"record_ids": [chosen]}
        )
        self.assertEqual(deleted["deleted"], 1)
        self.assertEqual(assessments.list_assessment_records(created["id"])["total"], 3)



if __name__ == "__main__":
    unittest.main()
