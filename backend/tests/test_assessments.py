import json
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

    def test_asset_relationships_link_url_ip_hostname_and_service_evidence(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Relationship map"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        assessments.record_tool_execution(
            scope, "nmap", "https://example.test",
            "2026-11-02T01:00:00+00:00", "2026-11-02T01:00:10+00:00", 0, False,
            [
                {"host": "192.0.2.10", "hostnames": ["example.test"], "port": 443,
                 "protocol": "tcp", "state": "open", "service": "https", "product": "nginx"},
                {"host": "example.test", "port": 443, "protocol": "tcp", "state": "open",
                 "service": "https", "product": "nginx"},
            ], "",
        )
        inventory = assessments.list_assessment_relationships(created["id"])
        edges = {(item["source"], item["relationship"], item["target"]) for item in inventory["relationships"]}
        self.assertIn(("https://example.test", "hosted_on", "example.test"), edges)
        self.assertIn(("example.test", "resolves_to", "192.0.2.10"), edges)
        self.assertIn(("example.test", "exposes", "example.test:443/tcp"), edges)
        self.assertEqual(inventory["counts"]["out_of_scope"], 0)

    def test_relationships_do_not_infer_ip_aliases_without_nmap_evidence(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="No inferred DNS"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        assessments.record_tool_execution(
            scope, "httpx", "https://example.test",
            "2026-11-02T02:00:00+00:00", "2026-11-02T02:00:02+00:00", 0, False,
            [{"url": "https://example.test/login", "host": "example.test"}], "",
        )
        inventory = assessments.list_assessment_relationships(created["id"])
        self.assertTrue(any(item["relationship"] == "hosted_on" for item in inventory["relationships"]))
        self.assertFalse(any(item["relationship"] == "resolves_to" for item in inventory["relationships"]))

    def test_software_inventory_correlates_product_versions_and_sources(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Software inventory"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        assessments.record_tool_execution(
            scope, "httpx", "https://example.test",
            "2026-11-02T03:00:00+00:00", "2026-11-02T03:00:02+00:00", 0, False,
            [{"url": "https://example.test", "host": "example.test",
              "webserver": "nginx/1.24.0", "technologies": ["nginx:1.24.0", "WordPress"]}], "",
        )
        assessments.record_tool_execution(
            scope, "whatweb", "https://example.test",
            "2026-11-02T03:01:00+00:00", "2026-11-02T03:01:02+00:00", 0, False,
            [{"target": "https://example.test", "technologies": ["Apache"],
              "plugin_details": {"Apache": {"version": ["2.4.58"]}}}], "",
        )
        assessments.record_tool_execution(
            scope, "nmap", "https://example.test",
            "2026-11-02T03:02:00+00:00", "2026-11-02T03:02:10+00:00", 0, False,
            [{"host": "example.test", "port": 443, "protocol": "tcp", "state": "open",
              "service": "https", "product": "nginx", "version": "1.24.0"}], "",
        )
        inventory = assessments.list_assessment_software(created["id"])
        products = {(item["product"].lower(), item["version"]) : item for item in inventory["software"]}
        nginx = products[("nginx", "1.24.0")]
        self.assertEqual(set(nginx["sources"]), {"httpx", "nmap"})
        self.assertEqual(nginx["scope_state"], "in_scope")
        self.assertIn(("apache", "2.4.58"), products)
        self.assertIn(("wordpress", ""), products)
        self.assertEqual(inventory["counts"]["versioned"], 2)
        self.assertIn("explicit, separate analyst action", inventory["notice"])

    def test_software_inventory_does_not_invent_versions(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Unknown version"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        assessments.record_tool_execution(
            scope, "whatweb", "https://example.test",
            "2026-11-02T04:00:00+00:00", "2026-11-02T04:00:02+00:00", 0, False,
            [{"target": "https://example.test", "technologies": ["nginx"],
              "plugin_details": {"nginx": {"version": []}}}], "",
        )
        inventory = assessments.list_assessment_software(created["id"])
        self.assertEqual(len(inventory["software"]), 1)
        self.assertEqual(inventory["software"][0]["version"], "")
        self.assertEqual(inventory["counts"]["versioned"], 0)

    @patch("app.routes.assessments.nvd_client.get_cve", return_value={
        "description": "Example advisory", "published": "2025-01-01",
        "cvss": {"base_score": 8.1, "base_severity": "HIGH"}, "references": [],
    })
    @patch("app.routes.assessments.nvd_client.assess_product_version", side_effect=["affected", "not_affected", "indeterminate"])
    @patch("app.routes.assessments.nvd_client.search_cve_ids_by_keyword", return_value={
        "CVE-2025-1001", "CVE-2025-1002", "CVE-2025-1003",
    })
    def test_software_cve_correlation_uses_nvd_cpe_version_assessment(
        self, _search, _assess, _get
    ):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="CVE correlation"))
        assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], "https://example.test")
        assessments.record_tool_execution(
            scope, "nmap", "https://example.test",
            "2026-11-02T05:00:00+00:00", "2026-11-02T05:00:10+00:00", 0, False,
            [{"host": "example.test", "port": 443, "protocol": "tcp", "state": "open",
              "service": "https", "product": "nginx", "version": "1.24.0"}], "",
        )
        result = assessments.correlate_software_cves(created["id"])
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["results"][0]["affected_count"], 1)
        self.assertEqual(result["results"][0]["indeterminate_count"], 1)
        statuses = {item["cve_id"]: item["status"] for item in result["results"][0]["candidates"]}
        self.assertEqual(statuses["CVE-2025-1001"], "affected")
        self.assertEqual(statuses["CVE-2025-1002"], "not_affected")
        self.assertEqual(statuses["CVE-2025-1003"], "indeterminate")
        _search.assert_called_once_with("nginx", "1.24.0")

    def test_software_cve_correlation_rejects_oversized_batch(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="CVE limit"))
        with self.assertRaises(HTTPException) as raised:
            assessments.correlate_software_cves(created["id"], limit=4)
        self.assertEqual(raised.exception.status_code, 400)

    def test_correlated_findings_merge_cross_tool_cve_and_preserve_review_state(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Finding correlation"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], target["url"])
        nuclei = assessments.record_tool_execution(
            scope, "nuclei", target["url"], "2026-11-02T06:00:00+00:00",
            "2026-11-02T06:00:02+00:00", 0, False,
            [{
                "url": "https://example.test/login", "template_id": "cve-2025-1234",
                "template_name": "Example CVE check", "severity": "high",
                "matched_at": "https://example.test/login",
            }], "",
        )
        nikto = assessments.record_tool_execution(
            scope, "nikto", target["url"], "2026-11-02T06:01:00+00:00",
            "2026-11-02T06:01:02+00:00", 0, False,
            [{
                "target": "https://example.test/login",
                "finding": "Potential exposure CVE-2025-1234",
                "severity": "medium",
            }], "",
        )
        result = assessments.list_correlated_findings(created["id"])
        self.assertEqual(result["counts"]["total"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["title"], "CVE-2025-1234")
        self.assertEqual(set(finding["sources"]), {"nuclei", "nikto"})
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["scope_state"], "in_scope")
        self.assertEqual(finding["verification_state"], "unverified")
        self.assertEqual(len(finding["observations"]), 2)

        nuclei_record = assessments.get_assessment_execution(created["id"], nuclei["id"])["records"][0]
        assessments.update_execution_record(
            created["id"], nuclei["id"], nuclei_record["record_id"],
            assessments.ExecutionRecordUpdate(review_state="dismissed"),
        )
        refreshed = assessments.list_correlated_findings(created["id"])
        self.assertEqual(refreshed["counts"]["total"], 1)
        self.assertEqual(refreshed["findings"][0]["sources"], ["nikto"])

    def test_wpscan_interesting_findings_join_cve_correlation_and_include_remediation(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="WPScan finding correlation"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], target["url"])
        wpscan_raw = json.dumps({
            "interesting_findings": [{
                "type": "CVE-2025-23456",
                "url": "https://example.test/wp-content/plugins/example/",
                "found_by": "Passive detection",
            }]
        })
        assessments.record_tool_execution(
            scope, "wpscan", target["url"], "2026-11-02T08:00:00+00:00",
            "2026-11-02T08:00:02+00:00", 0, False,
            [{"target": target["url"], "source": "wpscan", "raw": wpscan_raw}], "",
        )
        assessments.record_tool_execution(
            scope, "nuclei", target["url"], "2026-11-02T08:01:00+00:00",
            "2026-11-02T08:01:02+00:00", 0, False,
            [{
                "url": "https://example.test/wp-content/plugins/example/",
                "template_id": "wordpress-plugin-check",
                "template_name": "Plugin advisory match CVE-2025-23456",
                "severity": "high",
            }], "",
        )
        result = assessments.list_correlated_findings(created["id"])
        self.assertEqual(result["counts"]["total"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["title"], "CVE-2025-23456")
        self.assertEqual(set(finding["sources"]), {"wpscan", "nuclei"})
        self.assertEqual(finding["scope_state"], "in_scope")
        self.assertEqual(finding["verification_state"], "unverified")
        self.assertIn("recommendation", finding["remediation"])
        self.assertTrue(finding["remediation"]["validation_steps"])
        self.assertEqual(len(finding["observations"]), 2)

    def test_correlated_finding_status_persists_and_enforces_transitions(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="Finding lifecycle"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], target["url"])
        assessments.record_tool_execution(
            scope, "nuclei", target["url"], "2026-11-02T09:00:00+00:00",
            "2026-11-02T09:00:02+00:00", 0, False,
            [{
                "url": "https://example.test/login", "template_id": "test-login-check",
                "template_name": "Login response check", "severity": "medium",
            }], "",
        )
        finding = assessments.list_correlated_findings(created["id"])["findings"][0]
        self.assertEqual(finding["finding_status"], "unverified")
        updated = assessments.update_correlated_finding_status(
            created["id"], finding["id"], {"finding_status": "validated"}
        )
        self.assertEqual(updated["finding_status"], "validated")
        self.assertEqual(assessments.list_correlated_findings(created["id"])["findings"][0]["finding_status"], "validated")
        with self.assertRaises(HTTPException) as raised:
            assessments.update_correlated_finding_status(
                created["id"], finding["id"], {"finding_status": "retested"}
            )
        self.assertEqual(raised.exception.status_code, 409)
        assessments.update_correlated_finding_status(
            created["id"], finding["id"], {"finding_status": "remediated"}
        )
        assessments.update_correlated_finding_status(
            created["id"], finding["id"], {"finding_status": "retested"}
        )
        self.assertEqual(assessments.list_correlated_findings(created["id"])["findings"][0]["finding_status"], "retested")

    def test_wpscan_lifecycle_update_does_not_change_sibling_findings(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="WPScan independent triage"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], target["url"])
        assessments.record_tool_execution(
            scope, "wpscan", target["url"], "2026-11-02T10:00:00+00:00",
            "2026-11-02T10:00:02+00:00", 0, False,
            [
                {"target": "https://example.test/readme.html", "finding": "Readme exposed", "raw": "{}"},
                {"target": "https://example.test/wp-content/plugins/a/", "finding": "Plugin advisory", "raw": "{}"},
            ], "",
        )
        findings = assessments.list_correlated_findings(created["id"])["findings"]
        self.assertEqual(len(findings), 2)
        chosen = next(item for item in findings if item["title"] == "Readme exposed")
        assessments.update_correlated_finding_status(
            created["id"], chosen["id"], {"finding_status": "validated"}
        )
        refreshed = assessments.list_correlated_findings(created["id"])["findings"]
        states = {item["title"]: item["finding_status"] for item in refreshed}
        self.assertEqual(states["Readme exposed"], "validated")
        self.assertEqual(states["Plugin advisory"], "unverified")

    def test_correlated_findings_exclude_generic_and_non_scanner_evidence(self):
        created = assessments.create_assessment(assessments.AssessmentCreate(name="No finding noise"))
        target = assessments.add_assessment_target(
            created["id"], assessments.TargetCreate(url="https://example.test", authorized=True)
        )
        scope = assessments.assert_target_in_scope(created["id"], target["url"])
        assessments.record_tool_execution(
            scope, "nikto", target["url"], "2026-11-02T07:00:00+00:00",
            "2026-11-02T07:00:02+00:00", 0, False,
            [{"target": target["url"], "source": "nikto", "raw": "{...}",
              "assessment": "Nikto output retained for review; a scanner message is not a confirmed vulnerability."}], "",
        )
        assessments.record_tool_execution(
            scope, "httpx", target["url"], "2026-11-02T07:01:00+00:00",
            "2026-11-02T07:01:02+00:00", 0, False,
            [{"url": target["url"], "status_code": 200}], "",
        )
        self.assertEqual(assessments.list_correlated_findings(created["id"])["counts"]["total"], 0)

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
