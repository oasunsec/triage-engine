"""API test coverage using FastAPI TestClient.

Validates all REST endpoints in server.py without requiring a live server
or real EVTX files.  Tests cover:

  1. /api/health
  2. /api/cases
  3. /api/cases/{case_name}
  4. /api/cases/{case_name}/status
  5. /api/cases/{case_name}/timeline
  6. /api/cases/{case_name}/graph
  7. /api/cases/{case_name}/report
  8. /api/cases/{case_name}/summary
  9. /api/cases/{case_name}/brief
 10. DELETE /api/cases/{case_name}
 11. /api/jobs
 12. /api/jobs/{job_id}
 13. POST /api/investigate (upload)
 14. POST /api/investigate/path
 15. Dashboard (/)
 16. Input validation / security
"""

from __future__ import annotations

import json
import os
import sqlite3
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers to build a synthetic case folder
# ---------------------------------------------------------------------------

def _create_case(cases_root: str, name: str) -> str:
    """Create a minimal synthetic case folder for testing."""
    case_dir = os.path.join(cases_root, name)
    os.makedirs(case_dir, exist_ok=True)

    # run_status.json
    run_status = {
        "case_name": name,
        "input_source": "test.evtx",
        "status": "completed",
        "started_at": "2026-03-10T10:00:00+00:00",
        "completed_at": "2026-03-10T10:01:30+00:00",
        "current_stage": "done",
        "message": "Investigation completed",
        "metadata": {
            "case_metrics": {
                "signal_count": 5,
                "finding_count": 2,
                "incident_count": 1,
            },
            "response_priority": "P2",
            "stage_timings": {
                "parse_ms": 125,
                "detect_ms": 420,
                "suppress_ms": 18,
                "correlate_ms": 95,
                "report_ms": 140,
                "total_ms": 798,
            },
            "detector_timings": {
                "behavioral_ms": 112,
                "credential_access_ms": 88,
                "persistence_ms": 63,
            },
        },
    }
    with open(os.path.join(case_dir, "run_status.json"), "w") as f:
        json.dump(run_status, f)

    # findings.json
    findings = {
        "case": {
            "case_name": name,
            "input_source": "test.evtx",
            "primary_host": "WORKSTATION1",
            "primary_user": "corp\\analyst",
            "primary_source_ip": "10.10.10.5",
            "response_priority": "P2",
            "first_seen": "2026-03-10T10:00:00+00:00",
            "last_seen": "2026-03-10T10:01:00+00:00",
        },
        "summary": {
            "signal_count": 5,
            "finding_count": 2,
            "incident_count": 1,
        },
        "signals": [{"id": f"sig-{i}", "title": f"Signal {i}"} for i in range(5)],
        "findings": [{"id": f"fnd-{i}", "title": f"Finding {i}"} for i in range(2)],
        "incidents": [{"id": "inc-0", "title": "Incident 0", "severity": "high"}],
    }
    with open(os.path.join(case_dir, "findings.json"), "w") as f:
        json.dump(findings, f)

    # timeline.json
    timeline = {
        "timeline": [
            {
                "timestamp": "2026-03-10T10:00:00+00:00",
                "display_label": "SIG-001",
                "title": "Signal 0",
                "type": "signal",
            }
        ]
    }
    with open(os.path.join(case_dir, "timeline.json"), "w") as f:
        json.dump(timeline, f)

    # graph.json
    graph = {"nodes": [{"id": "host1", "type": "host"}], "edges": []}
    with open(os.path.join(case_dir, "graph.json"), "w") as f:
        json.dump(graph, f)

    # report.html
    with open(os.path.join(case_dir, "report.html"), "w") as f:
        f.write("<html><body><h1>Test Report</h1></body></html>")

    # summary.txt
    with open(os.path.join(case_dir, "summary.txt"), "w") as f:
        f.write("Case: test\nSignals: 5\nFindings: 2\nIncidents: 1\n")

    # incident_brief.md
    with open(os.path.join(case_dir, "incident_brief.md"), "w") as f:
        f.write("# Incident Brief: test\n\n## Key Incidents\n- INC-001\n")

    return case_dir


def _create_evtx_stub(directory: str, filename: str = "test.evtx") -> str:
    """Create a fake .evtx file for upload testing."""
    path = os.path.join(directory, filename)
    with open(path, "wb") as f:
        f.write(b"\x00" * 128)
    return path


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class APITests(unittest.TestCase):
    """Tests for the Triage Engine REST API."""

    @classmethod
    def setUpClass(cls):
        """Create a temp directory structure and import the app with overridden paths."""
        cls._temp_root = tempfile.mkdtemp(prefix="triage-api-test-")
        cls._cases_dir = os.path.join(cls._temp_root, "cases")
        cls._upload_dir = os.path.join(cls._temp_root, "uploads")
        cls._static_dir = os.path.join(cls._temp_root, "static")
        os.makedirs(cls._cases_dir, exist_ok=True)
        os.makedirs(cls._upload_dir, exist_ok=True)
        os.makedirs(cls._static_dir, exist_ok=True)

        # Copy dashboard.html into our temp static dir
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        real_dashboard = os.path.join(project_root, "static", "dashboard.html")
        if os.path.isfile(real_dashboard):
            shutil.copy2(real_dashboard, os.path.join(cls._static_dir, "dashboard.html"))
        else:
            with open(os.path.join(cls._static_dir, "dashboard.html"), "w") as f:
                f.write("<html><body>Test Dashboard</body></html>")

        # Create two synthetic cases for testing
        _create_case(cls._cases_dir, "test-case-alpha")
        _create_case(cls._cases_dir, "test-case-beta")

        # Patch server module constants before importing app
        import server
        cls._orig_cases_root = server.CASES_ROOT
        cls._orig_upload_root = server.UPLOAD_ROOT
        cls._orig_static_dir = server.STATIC_DIR
        server.CASES_ROOT = cls._cases_dir
        server.UPLOAD_ROOT = cls._upload_dir
        server.STATIC_DIR = cls._static_dir
        server._reset_security_state_for_tests()

        import triage_engine.review_store as rs
        cls._orig_review_db = rs._DB_PATH
        rs._DB_PATH = os.path.join(cls._temp_root, "test_api_reviews.db")
        rs._init_db()

        import triage_engine.auth_store as auth
        cls._orig_auth_db = auth._DB_PATH
        auth._DB_PATH = os.path.join(cls._temp_root, "test_api_auth.db")
        auth._init_db()

        cls.client = TestClient(server.app, raise_server_exceptions=False)
        bootstrap = cls.client.post(
            "/api/auth/bootstrap",
            json={"username": "admin", "password": "Password123!"},
        )
        if bootstrap.status_code != 200:
            raise RuntimeError(f"Failed to bootstrap test auth: {bootstrap.status_code} {bootstrap.text}")
        me = cls.client.get("/api/auth/me")
        if me.status_code == 200:
            token = me.json().get("csrf_token", "")
            if token:
                cls.client.headers["X-CSRF-Token"] = token

    @classmethod
    def tearDownClass(cls):
        """Restore patched constants and remove temp directory."""
        import server
        server.CASES_ROOT = cls._orig_cases_root
        server.UPLOAD_ROOT = cls._orig_upload_root
        server.STATIC_DIR = cls._orig_static_dir
        import triage_engine.review_store as rs
        rs._DB_PATH = cls._orig_review_db
        import triage_engine.auth_store as auth
        auth._DB_PATH = cls._orig_auth_db
        shutil.rmtree(cls._temp_root, ignore_errors=True)

    def setUp(self):
        import server

        server._reset_security_state_for_tests()
        me = self.client.get("/api/auth/me")
        if me.status_code != 200:
            return
        payload = me.json()
        if payload.get("authenticated"):
            token = payload.get("csrf_token", "")
            if token:
                self.client.headers["X-CSRF-Token"] = token
            return
        if not payload.get("bootstrap_required"):
            login = self.client.post("/api/auth/login", json={"username": "admin", "password": "Password123!"})
            if login.status_code == 200:
                token = login.json().get("csrf_token", "")
                if token:
                    self.client.headers["X-CSRF-Token"] = token

    # -----------------------------------------------------------------------
    # 1. Health
    # -----------------------------------------------------------------------
    def test_health_returns_ok(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertEqual(data["engine"], "triage-engine")
        self.assertIn("db_writable", data)
        self.assertIn("cases_dir_writable", data)
        self.assertIn("disk_free_bytes", data)
        self.assertIn("by_db", data["db_writable"])
        self.assertIn("all", data["db_writable"])
        self.assertIsInstance(data["db_writable"]["by_db"], dict)
        self.assertIsInstance(data["cases_dir_writable"], bool)
        self.assertIsInstance(data["disk_free_bytes"], int)

    def test_health_response_includes_generated_request_id_header(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        request_id = resp.headers.get("X-Request-ID", "")
        self.assertTrue(request_id)

    def test_health_response_echoes_client_request_id_header(self):
        request_id = "api-test-request-id-123"
        resp = self.client.get("/api/health", headers={"X-Request-ID": request_id})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Request-ID"), request_id)

    def test_api_docs_routes_are_accessible(self):
        docs = self.client.get("/docs")
        self.assertEqual(docs.status_code, 200)
        self.assertIn("text/html", docs.headers.get("content-type", ""))

        redoc = self.client.get("/redoc")
        self.assertEqual(redoc.status_code, 200)
        self.assertIn("text/html", redoc.headers.get("content-type", ""))

    def test_cors_origin_normalization_expands_localhost(self):
        import server

        origins = server._cors_origins_from_env("localhost", default_port=8123)
        self.assertEqual(origins, ["http://localhost:8123", "http://127.0.0.1:8123"])

    def test_cors_origin_normalization_accepts_explicit_origins(self):
        import server

        origins = server._cors_origins_from_env("https://soc.example.com,localhost:3000", default_port=8000)
        self.assertEqual(origins, ["https://soc.example.com", "http://localhost:3000"])

    def test_runtime_dir_resolution_uses_repo_root_for_relative_paths(self):
        import server

        with patch.dict(os.environ, {"TRIAGE_TEST_RUNTIME_DIR": "relative-data-dir"}):
            resolved = server._resolve_runtime_dir("TRIAGE_TEST_RUNTIME_DIR", "data")
        expected = os.path.abspath(os.path.join(server.ROOT_DIR, "relative-data-dir"))
        self.assertEqual(resolved, expected)

    def test_env_int_clamps_out_of_range_values(self):
        import server

        with patch.dict(os.environ, {"TRIAGE_TEST_INT": "-1"}):
            self.assertEqual(server._env_int("TRIAGE_TEST_INT", default=10, minimum=1), 1)
        with patch.dict(os.environ, {"TRIAGE_TEST_INT": "999"}):
            self.assertEqual(server._env_int("TRIAGE_TEST_INT", default=10, maximum=100), 100)

    def test_startup_validation_flags_missing_dashboard(self):
        import server

        with (
            patch.object(server, "_probe_directory_writable", side_effect=[True, True]),
            patch.object(server, "_state_db_paths", return_value={"auth_db": "a.db", "reviews_db": "b.db", "jobs_db": "c.db"}),
            patch.object(server, "_probe_sqlite_writable", return_value=True),
            patch.object(server, "_disk_free_bytes", return_value=2 * 1024 * 1024 * 1024),
            patch.object(server, "_dashboard_path", return_value="C:/missing/dashboard.html"),
            patch("server.os.path.isfile", return_value=False),
        ):
            validation = server._collect_startup_validation()

        self.assertTrue(any("Dashboard HTML not found" in item for item in validation["errors"]))

    def test_startup_validation_warns_when_disk_below_recommended_threshold(self):
        import server

        with (
            patch.object(server, "_probe_directory_writable", side_effect=[True, True]),
            patch.object(server, "_state_db_paths", return_value={"auth_db": "a.db", "reviews_db": "b.db", "jobs_db": "c.db"}),
            patch.object(server, "_probe_sqlite_writable", return_value=True),
            patch.object(server, "_disk_free_bytes", return_value=500 * 1024 * 1024),
            patch.object(server, "_dashboard_path", return_value="C:/ok/dashboard.html"),
            patch("server.os.path.isfile", return_value=True),
        ):
            validation = server._collect_startup_validation()

        self.assertEqual(validation["errors"], [])
        self.assertTrue(any("recommended threshold" in item for item in validation["warnings"]))

    def test_startup_validation_fails_when_disk_below_hard_minimum(self):
        import server

        with (
            patch.object(server, "_probe_directory_writable", side_effect=[True, True]),
            patch.object(server, "_state_db_paths", return_value={"auth_db": "a.db", "reviews_db": "b.db", "jobs_db": "c.db"}),
            patch.object(server, "_probe_sqlite_writable", return_value=True),
            patch.object(server, "_disk_free_bytes", return_value=50 * 1024 * 1024),
            patch.object(server, "_dashboard_path", return_value="C:/ok/dashboard.html"),
            patch("server.os.path.isfile", return_value=True),
        ):
            with self.assertRaises(RuntimeError):
                server._validate_startup_or_raise()

    def test_openapi_schema_includes_phase_5_2_groups_and_models(self):
        resp = self.client.get("/openapi.json")
        self.assertEqual(resp.status_code, 200)
        schema = resp.json()

        tag_names = {tag.get("name", "") for tag in schema.get("tags", [])}
        self.assertTrue({"Auth", "Cases", "Investigate", "Jobs", "Reviews", "Admin"}.issubset(tag_names))

        admin_backup = schema["paths"]["/api/admin/backup"]["post"]
        self.assertEqual(admin_backup.get("summary"), "Create Backup")
        backup_schema = admin_backup["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(backup_schema.get("$ref"), "#/components/schemas/BackupCreateResponse")

        live_health = schema["paths"]["/api/live/health"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(live_health.get("$ref"), "#/components/schemas/LiveHealthResponse")

        queue_schema = schema["paths"]["/api/review/queue"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(queue_schema.get("items", {}).get("$ref"), "#/components/schemas/ReviewQueueItemResponse")

        history_schema = schema["paths"]["/api/review/history"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(history_schema.get("items", {}).get("$ref"), "#/components/schemas/ReviewHistoryItemResponse")

        self.assertIn("/api/cases/export", schema["paths"])
        self.assertIn("/api/cases/{case_name}/export", schema["paths"])
        self.assertIn("/api/review/queue/export", schema["paths"])

    # -----------------------------------------------------------------------
    # 2. Dashboard
    # -----------------------------------------------------------------------
    def test_dashboard_returns_html(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["content-type"])

    # -----------------------------------------------------------------------
    # 3. List cases
    # -----------------------------------------------------------------------
    def test_list_cases_returns_array(self):
        resp = self.client.get("/api/cases")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 2)

    def test_list_cases_includes_metadata(self):
        resp = self.client.get("/api/cases")
        data = resp.json()
        case_names = [c["name"] for c in data]
        self.assertIn("test-case-alpha", case_names)
        alpha = next(c for c in data if c["name"] == "test-case-alpha")
        self.assertEqual(alpha["signal_count"], 5)
        self.assertEqual(alpha["finding_count"], 2)
        self.assertEqual(alpha["incident_count"], 1)
        self.assertEqual(alpha["response_priority"], "P2")
        self.assertEqual(alpha["status"], "completed")
        self.assertTrue(alpha["has_report"])
        self.assertTrue(alpha["has_findings"])

    def test_cases_export_csv(self):
        resp = self.client.get("/api/cases/export?format=csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers.get("content-type", ""))
        self.assertIn("attachment;", resp.headers.get("content-disposition", "").lower())
        self.assertIn("name,status,response_priority", resp.text)
        self.assertIn("test-case-alpha", resp.text)

    def test_cases_export_rejects_non_csv_format(self):
        resp = self.client.get("/api/cases/export?format=json")
        self.assertEqual(resp.status_code, 400)

    # -----------------------------------------------------------------------
    # 4. Get case details
    # -----------------------------------------------------------------------
    def test_get_case_returns_findings(self):
        resp = self.client.get("/api/cases/test-case-alpha")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("case", data)
        self.assertIn("signals", data)
        self.assertIn("findings", data)
        self.assertIn("incidents", data)
        self.assertEqual(data["case"]["case_name"], "test-case-alpha")

    def test_get_case_export_returns_json_attachment(self):
        resp = self.client.get("/api/cases/test-case-alpha/export")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp.headers.get("content-type", ""))
        self.assertIn("attachment;", resp.headers.get("content-disposition", "").lower())
        payload = resp.json()
        self.assertEqual(payload.get("case", {}).get("case_name"), "test-case-alpha")

    def test_get_case_not_found(self):
        resp = self.client.get("/api/cases/nonexistent-case-xyz")
        self.assertEqual(resp.status_code, 404)

    def test_get_case_export_not_found(self):
        resp = self.client.get("/api/cases/nonexistent-case-xyz/export")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # 5. Get case status
    # -----------------------------------------------------------------------
    def test_get_case_status_returns_run_status(self):
        resp = self.client.get("/api/cases/test-case-alpha/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "completed")
        self.assertIn("metadata", data)
        stage_timings = data.get("metadata", {}).get("stage_timings", {})
        self.assertIn("parse_ms", stage_timings)
        self.assertIn("detect_ms", stage_timings)
        self.assertIn("correlate_ms", stage_timings)
        self.assertIn("report_ms", stage_timings)

    def test_get_case_status_not_found(self):
        resp = self.client.get("/api/cases/nonexistent/status")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # 6. Timeline
    # -----------------------------------------------------------------------
    def test_get_timeline_returns_json(self):
        resp = self.client.get("/api/cases/test-case-alpha/timeline")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("timeline", data)
        self.assertIsInstance(data["timeline"], list)

    def test_get_timeline_not_found(self):
        resp = self.client.get("/api/cases/nonexistent/timeline")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # 7. Graph
    # -----------------------------------------------------------------------
    def test_get_graph_returns_json(self):
        resp = self.client.get("/api/cases/test-case-alpha/graph")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

    def test_get_graph_not_found(self):
        resp = self.client.get("/api/cases/nonexistent/graph")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # 8. Report
    # -----------------------------------------------------------------------
    def test_get_report_returns_html(self):
        resp = self.client.get("/api/cases/test-case-alpha/report")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["content-type"])

    def test_get_report_not_found(self):
        resp = self.client.get("/api/cases/nonexistent/report")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # 9. Summary
    # -----------------------------------------------------------------------
    def test_get_summary_returns_text(self):
        resp = self.client.get("/api/cases/test-case-alpha/summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("summary", data)
        self.assertIn("Case:", data["summary"])

    def test_get_summary_not_found(self):
        resp = self.client.get("/api/cases/nonexistent/summary")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # 10. Brief
    # -----------------------------------------------------------------------
    def test_get_brief_returns_markdown(self):
        resp = self.client.get("/api/cases/test-case-alpha/brief")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("brief", data)
        self.assertIn("# Incident Brief", data["brief"])

    def test_get_brief_not_found(self):
        resp = self.client.get("/api/cases/nonexistent/brief")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # 11. Delete case
    # -----------------------------------------------------------------------
    def test_delete_case_removes_folder(self):
        # Create a disposable case
        _create_case(self._cases_dir, "delete-me")
        self.assertTrue(os.path.isdir(os.path.join(self._cases_dir, "delete-me")))

        resp = self.client.delete("/api/cases/delete-me")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["deleted"], "delete-me")
        self.assertFalse(os.path.isdir(os.path.join(self._cases_dir, "delete-me")))

    def test_delete_case_not_found(self):
        resp = self.client.delete("/api/cases/nonexistent-for-delete")
        self.assertEqual(resp.status_code, 404)

    # -----------------------------------------------------------------------
    # 12. Jobs
    # -----------------------------------------------------------------------
    def test_list_jobs_returns_array(self):
        resp = self.client.get("/api/jobs")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_get_job_not_found(self):
        resp = self.client.get("/api/jobs/nonexistent-job-id")
        self.assertEqual(resp.status_code, 404)

    def test_list_jobs_includes_case_availability_metadata(self):
        resp = self.client.get("/api/jobs")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        if data:
            self.assertIn("case_available", data[0])
            self.assertIn("case_missing_reason", data[0])

    def test_bulk_job_delete_removes_completed_and_skips_running(self):
        from triage_engine.job_store import create_job, update_job, get_job, delete_job
        complete_id = "job-delete-complete-api"
        running_id = "job-delete-running-api"
        delete_job(complete_id)
        delete_job(running_id)
        create_job(complete_id, case_name="delete-complete")
        update_job(complete_id, status="completed", stage="done", message="Complete")
        create_job(running_id, case_name="delete-running")
        update_job(running_id, status="running", stage="detect", message="Running")

        resp = self.client.post("/api/jobs/delete", json={"job_ids": [complete_id, running_id]})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(complete_id, data["deleted"])
        self.assertTrue(any(item["job_id"] == running_id and item["reason"] == "active_job" for item in data["skipped"]))
        self.assertIsNone(get_job(complete_id))
        self.assertIsNotNone(get_job(running_id))
        delete_job(running_id)

    # -----------------------------------------------------------------------
    # 13. Investigation via upload — validation checks
    # -----------------------------------------------------------------------
    def test_upload_rejects_non_evtx_file(self):
        resp = self.client.post(
            "/api/investigate",
            files=[("files", ("malware.exe", b"\x00" * 64, "application/octet-stream"))],
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("evtx", resp.json()["detail"].lower())

    def test_upload_rejects_oversized_file(self):
        import server
        original_max = server.MAX_UPLOAD_BYTES
        server.MAX_UPLOAD_BYTES = 64  # Temporarily set very small limit
        try:
            resp = self.client.post(
                "/api/investigate",
                files=[("files", ("test.evtx", b"\x00" * 128, "application/octet-stream"))],
            )
            self.assertEqual(resp.status_code, 413)
        finally:
            server.MAX_UPLOAD_BYTES = original_max

    def test_upload_starts_investigation(self):
        """Upload a valid .evtx stub — verify job is created (investigation will fail
        because the file isn't real EVTX, but the API should accept it and return a job)."""
        resp = self.client.post(
            "/api/investigate",
            files=[("files", ("test.evtx", b"\x00" * 64, "application/octet-stream"))],
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("job_id", data)
        self.assertIn("case_name", data)
        self.assertEqual(data["status"], "queued")

        # Verify job exists in the store
        job_resp = self.client.get(f"/api/jobs/{data['job_id']}")
        self.assertEqual(job_resp.status_code, 200)
        job = job_resp.json()
        self.assertEqual(job["job_id"], data["job_id"])

    # -----------------------------------------------------------------------
    # 14. Investigation via path — validation checks
    # -----------------------------------------------------------------------
    def test_path_investigation_rejects_missing_path(self):
        resp = self.client.post(
            "/api/investigate/path",
            params={"evtx_path": r"C:\nonexistent\path\test.evtx"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_path_investigation_rejects_non_evtx_extension(self):
        # Create a temp file with wrong extension
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        tmp.write(b"not evtx")
        tmp.close()
        try:
            resp = self.client.post(
                "/api/investigate/path",
                params={"evtx_path": tmp.name},
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("evtx", resp.json()["detail"].lower())
        finally:
            os.unlink(tmp.name)

    def test_path_investigation_starts_with_valid_evtx(self):
        """Point at a .evtx stub file — investigation starts (will fail internally
        because file isn't real EVTX, but the API accepts it)."""
        evtx_path = _create_evtx_stub(self._temp_root, "path-test.evtx")
        resp = self.client.post(
            "/api/investigate/path",
            params={"evtx_path": evtx_path},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("job_id", data)
        self.assertEqual(data["status"], "queued")
        os.unlink(evtx_path)

    def test_path_investigation_with_partial_parse_failure_completes(self):
        batch_dir = os.path.join(self._temp_root, "partial-parse-batch")
        os.makedirs(batch_dir, exist_ok=True)
        good_path = os.path.join(batch_dir, "good.evtx")
        bad_path = os.path.join(batch_dir, "broken.evtx")
        with open(good_path, "wb") as fh:
            fh.write(b"\x00" * 32)
        with open(bad_path, "wb") as fh:
            fh.write(b"\x00" * 32)

        def fake_read_evtx(filepath, start_date=None, end_date=None, progress_callback=None):
            if os.path.basename(filepath).lower() == "broken.evtx":
                raise ValueError("corrupt evtx payload")
            if progress_callback:
                progress_callback({"status": "file_started", "file_path": filepath})
                progress_callback(
                    {
                        "status": "file_progress",
                        "file_path": filepath,
                        "records_scanned": 1,
                        "parsed_events": 0,
                        "skipped_records": 0,
                    }
                )
            return []

        with patch("parser.evtx_reader.read_evtx", side_effect=fake_read_evtx):
            start = self.client.post(
                "/api/investigate/path",
                params={"evtx_path": batch_dir, "case_name": "partial-parse-case"},
            )
            self.assertEqual(start.status_code, 200)
            payload = start.json()
            job_id = payload["job_id"]
            case_name = payload["case_name"]

            final_job = None
            for _ in range(80):
                job_resp = self.client.get(f"/api/jobs/{job_id}")
                self.assertEqual(job_resp.status_code, 200)
                final_job = job_resp.json()
                if final_job.get("status") not in {"queued", "running"}:
                    break
                time.sleep(0.05)

        self.assertIsNotNone(final_job)
        self.assertEqual(final_job.get("status"), "completed")

        case_status = self.client.get(f"/api/cases/{case_name}/status")
        self.assertEqual(case_status.status_code, 200)
        metadata = case_status.json().get("metadata", {})
        partial_failures = metadata.get("partial_failures", [])
        self.assertTrue(any(item.get("component") == "parser" for item in partial_failures))
        self.assertTrue(any(item.get("name") == "broken.evtx" for item in partial_failures))

        parse_progress = metadata.get("parse_progress", {})
        self.assertGreaterEqual(int(parse_progress.get("warning_count", 0)), 1)
        self.assertIn("broken.evtx", list(parse_progress.get("failed_files", []) or []))
        stage_timings = metadata.get("stage_timings", {})
        for key in ("parse_ms", "detect_ms", "suppress_ms", "correlate_ms", "report_ms", "total_ms"):
            self.assertIn(key, stage_timings)
            self.assertGreaterEqual(int(stage_timings.get(key, 0)), 0)

    def test_path_investigation_with_detector_timeout_completes_with_partial_failures(self):
        evtx_path = _create_evtx_stub(self._temp_root, "detector-timeout.evtx")

        def fake_read_evtx(filepath, start_date=None, end_date=None, progress_callback=None):
            if progress_callback:
                progress_callback({"status": "file_started", "file_path": filepath})
                progress_callback(
                    {
                        "status": "file_progress",
                        "file_path": filepath,
                        "records_scanned": 1,
                        "parsed_events": 0,
                        "skipped_records": 0,
                    }
                )
            return []

        def slow_behavioral_detector(_events):
            time.sleep(1.5)
            return []

        with patch.dict(os.environ, {"TRIAGE_DETECTOR_TIMEOUT_SECONDS": "1"}, clear=False):
            with patch("parser.evtx_reader.read_evtx", side_effect=fake_read_evtx):
                with patch("triage_engine.service.behavioral.detect", side_effect=slow_behavioral_detector):
                    start = self.client.post(
                        "/api/investigate/path",
                        params={"evtx_path": evtx_path, "case_name": "detector-timeout-case"},
                    )
                    self.assertEqual(start.status_code, 200)
                    payload = start.json()
                    job_id = payload["job_id"]
                    case_name = payload["case_name"]

                    final_job = None
                    for _ in range(120):
                        job_resp = self.client.get(f"/api/jobs/{job_id}")
                        self.assertEqual(job_resp.status_code, 200)
                        final_job = job_resp.json()
                        if final_job.get("status") not in {"queued", "running"}:
                            break
                        time.sleep(0.05)

        self.assertIsNotNone(final_job)
        self.assertEqual(final_job.get("status"), "completed")

        case_status = self.client.get(f"/api/cases/{case_name}/status")
        self.assertEqual(case_status.status_code, 200)
        metadata = case_status.json().get("metadata", {})
        partial_failures = metadata.get("partial_failures", [])
        self.assertTrue(any(item.get("component") == "detector" for item in partial_failures))
        self.assertTrue(any(item.get("name") == "behavioral" for item in partial_failures))
        self.assertTrue(any(item.get("reason") == "timeout" for item in partial_failures))
        stage_timings = metadata.get("stage_timings", {})
        for key in ("parse_ms", "detect_ms", "suppress_ms", "correlate_ms", "report_ms", "total_ms"):
            self.assertIn(key, stage_timings)

    def test_path_investigation_timeout_marks_job_failed(self):
        evtx_path = _create_evtx_stub(self._temp_root, "investigation-timeout.evtx")

        def slow_read_evtx(filepath, start_date=None, end_date=None, progress_callback=None):
            if progress_callback:
                progress_callback({"status": "file_started", "file_path": filepath})
            time.sleep(1.2)
            return []

        with patch.dict(os.environ, {"TRIAGE_INVESTIGATION_TIMEOUT_SECONDS": "1"}, clear=False):
            with patch("parser.evtx_reader.read_evtx", side_effect=slow_read_evtx):
                start = self.client.post(
                    "/api/investigate/path",
                    params={"evtx_path": evtx_path, "case_name": "investigation-timeout-case"},
                )
                self.assertEqual(start.status_code, 200)
                payload = start.json()
                job_id = payload["job_id"]

                final_job = None
                for _ in range(120):
                    job_resp = self.client.get(f"/api/jobs/{job_id}")
                    self.assertEqual(job_resp.status_code, 200)
                    final_job = job_resp.json()
                    if final_job.get("status") not in {"queued", "running"}:
                        break
                    time.sleep(0.05)

        self.assertIsNotNone(final_job)
        self.assertEqual(final_job.get("status"), "failed")
        self.assertIn("exceeded timeout", str(final_job.get("message", "")).lower())

    def test_investigate_worker_dispatches_completion_and_priority_webhooks(self):
        import server
        from triage_engine.service import InvestigationRequest, InvestigationResult

        case_name = "webhook-case-p1"
        case_path = os.path.join(self._cases_dir, case_name)
        os.makedirs(case_path, exist_ok=True)
        with open(os.path.join(case_path, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump({"findings": [{"id": "f-1"}], "incidents": [{"id": "inc-1"}]}, fh)

        fake_result = InvestigationResult(
            case_name=case_name,
            case_path=case_path,
            input_source="test.evtx",
            signal_count=3,
            finding_count=1,
            incident_count=1,
            response_priority="P1",
        )
        request = InvestigationRequest(
            input_source="test.evtx",
            input_mode="evtx_path",
            case_name=case_name,
            requested_by="admin",
            request_id="req-webhook-1",
        )

        with patch.object(server, "run_investigation", return_value=fake_result):
            with patch.object(server, "dispatch_webhook_event", return_value={"attempted": 0, "sent": 0, "failed": 0}) as dispatch_mock:
                with patch.object(server, "update_job"):
                    with patch.object(server, "sync_queue_index_from_case_payload"):
                        with patch.object(server, "carry_forward_reviews"):
                            server._investigate_worker("job-webhook-1", request)

        events = [call.args[0] for call in dispatch_mock.call_args_list]
        self.assertIn("investigation_completed", events)
        self.assertIn("incident_p1", events)
        completion_call = next(call for call in dispatch_mock.call_args_list if call.args[0] == "investigation_completed")
        completion_payload = completion_call.args[1]
        self.assertEqual(completion_payload["case_name"], case_name)
        self.assertEqual(completion_payload["response_priority"], "P1")
        self.assertEqual(completion_payload["incident_count"], 1)
        self.assertIn("incident_ids", completion_payload)

    def test_investigate_worker_sends_only_completion_for_lower_priority(self):
        import server
        from triage_engine.service import InvestigationRequest, InvestigationResult

        case_name = "webhook-case-p3"
        case_path = os.path.join(self._cases_dir, case_name)
        os.makedirs(case_path, exist_ok=True)
        with open(os.path.join(case_path, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump({"findings": [{"id": "f-1"}], "incidents": [{"id": "inc-1"}]}, fh)

        fake_result = InvestigationResult(
            case_name=case_name,
            case_path=case_path,
            input_source="test.evtx",
            signal_count=2,
            finding_count=1,
            incident_count=1,
            response_priority="P3",
        )
        request = InvestigationRequest(
            input_source="test.evtx",
            input_mode="evtx_path",
            case_name=case_name,
            requested_by="admin",
            request_id="req-webhook-2",
        )

        with patch.object(server, "run_investigation", return_value=fake_result):
            with patch.object(server, "dispatch_webhook_event", return_value={"attempted": 0, "sent": 0, "failed": 0}) as dispatch_mock:
                with patch.object(server, "update_job"):
                    with patch.object(server, "sync_queue_index_from_case_payload"):
                        with patch.object(server, "carry_forward_reviews"):
                            server._investigate_worker("job-webhook-2", request)

        events = [call.args[0] for call in dispatch_mock.call_args_list]
        self.assertIn("investigation_completed", events)
        self.assertNotIn("incident_p1", events)
        self.assertNotIn("incident_p2", events)

    def test_live_investigation_starts_with_recommended_channels(self):
        resp = self.client.post(
            "/api/investigate/live",
            json={
                "case_name": "live-ui-case",
                "since_minutes": 30,
                "channels": ["Security", "System", "Microsoft-Windows-PowerShell/Operational"],
            },
        )
        if os.name != "nt":
            self.assertEqual(resp.status_code, 400)
            return
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "queued")
        self.assertEqual(data["input_mode"], "live")
        self.assertEqual(data["case_name"], "live-ui-case")
        self.assertIn("Security", data["channels"])

    def test_live_investigation_rejects_invalid_channel_name(self):
        resp = self.client.post(
            "/api/investigate/live",
            json={"channels": ["Security", "Bad|Channel"], "since_minutes": 30},
        )
        if os.name != "nt":
            self.assertEqual(resp.status_code, 400)
            return
        self.assertEqual(resp.status_code, 400)

    def test_live_health_returns_snapshot(self):
        import server

        snapshot = {
            "os_name": "nt",
            "is_windows": True,
            "pywin32_available": True,
            "is_elevated": False,
            "readiness": "degraded",
            "recommended_channels": ["Security", "System"],
            "readable_channel_count": 1,
            "channels": [
                {"channel": "Security", "readable": False, "status": "access_denied", "message": "Access is denied."},
                {"channel": "System", "readable": True, "status": "ready", "message": "Channel query succeeded"},
            ],
            "guidance": ["Restart the server from an Administrator PowerShell for full Security and Sysmon coverage."],
        }
        with patch.object(server, "_collect_live_health", return_value=snapshot):
            resp = self.client.get("/api/live/health")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["readiness"], "degraded")
        self.assertEqual(data["channels"][0]["status"], "access_denied")
        self.assertEqual(data["readable_channel_count"], 1)

    # -----------------------------------------------------------------------
    # 15. Case name validation (security)
    # -----------------------------------------------------------------------
    def test_case_name_rejects_path_traversal(self):
        resp = self.client.post(
            "/api/investigate/path",
            params={
                "evtx_path": _create_evtx_stub(self._temp_root, "sec-test.evtx"),
                "case_name": "../../../etc/passwd",
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_case_name_rejects_special_characters(self):
        resp = self.client.post(
            "/api/investigate/path",
            params={
                "evtx_path": _create_evtx_stub(self._temp_root, "sec-test2.evtx"),
                "case_name": "test<script>alert(1)</script>",
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_case_name_accepts_valid_name(self):
        evtx_path = _create_evtx_stub(self._temp_root, "sec-test3.evtx")
        resp = self.client.post(
            "/api/investigate/path",
            params={
                "evtx_path": evtx_path,
                "case_name": "valid-case-name.2026",
            },
        )
        self.assertEqual(resp.status_code, 200)
        os.unlink(evtx_path)

    # -----------------------------------------------------------------------
    # 16. Findings fallback for older cases without metadata
    # -----------------------------------------------------------------------
    def test_list_cases_falls_back_to_findings_json(self):
        """Cases with empty run_status metadata should fall back to findings.json counts."""
        case_dir = os.path.join(self._cases_dir, "old-case-no-meta")
        os.makedirs(case_dir, exist_ok=True)

        # Write run_status with empty metadata (simulates old case)
        with open(os.path.join(case_dir, "run_status.json"), "w") as f:
            json.dump({"status": "completed", "metadata": {}}, f)

        # Write findings.json with actual counts
        with open(os.path.join(case_dir, "findings.json"), "w") as f:
            json.dump({
                "summary": {"signal_count": 10, "finding_count": 3, "incident_count": 2},
                "case": {"response_priority": "P1"},
            }, f)

        resp = self.client.get("/api/cases")
        data = resp.json()
        old_case = next((c for c in data if c["name"] == "old-case-no-meta"), None)
        self.assertIsNotNone(old_case)
        self.assertEqual(old_case["signal_count"], 10)
        self.assertEqual(old_case["finding_count"], 3)
        self.assertEqual(old_case["incident_count"], 2)

        # Cleanup
        shutil.rmtree(case_dir, ignore_errors=True)


class AuthAPITests(unittest.TestCase):
    """Test auth bootstrap, login, logout, and role-based access."""

    def setUp(self):
        self._temp_root = tempfile.mkdtemp(prefix="triage-auth-api-test-")
        self._cases_dir = os.path.join(self._temp_root, "cases")
        self._upload_dir = os.path.join(self._temp_root, "uploads")
        self._static_dir = os.path.join(self._temp_root, "static")
        os.makedirs(self._cases_dir, exist_ok=True)
        os.makedirs(self._upload_dir, exist_ok=True)
        os.makedirs(self._static_dir, exist_ok=True)
        _create_case(self._cases_dir, "auth-case")

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        real_dashboard = os.path.join(project_root, "static", "dashboard.html")
        if os.path.isfile(real_dashboard):
            shutil.copy2(real_dashboard, os.path.join(self._static_dir, "dashboard.html"))

        import server
        self._orig_cases_root = server.CASES_ROOT
        self._orig_upload_root = server.UPLOAD_ROOT
        self._orig_static_dir = server.STATIC_DIR
        self._orig_data_root = server.DATA_ROOT
        self._orig_backups_root = server.BACKUPS_ROOT
        server.CASES_ROOT = self._cases_dir
        server.UPLOAD_ROOT = self._upload_dir
        server.STATIC_DIR = self._static_dir
        server.DATA_ROOT = os.path.join(self._temp_root, "data")
        server.BACKUPS_ROOT = os.path.join(server.DATA_ROOT, "backups")
        os.makedirs(server.DATA_ROOT, exist_ok=True)
        os.makedirs(server.BACKUPS_ROOT, exist_ok=True)

        import triage_engine.review_store as rs
        self._orig_review_db = rs._DB_PATH
        rs._DB_PATH = os.path.join(self._temp_root, "test_auth_reviews.db")
        rs._init_db()

        import triage_engine.auth_store as auth
        self._orig_auth_db = auth._DB_PATH
        auth._DB_PATH = os.path.join(self._temp_root, "test_auth.db")
        auth._init_db()

        self.client = TestClient(server.app, raise_server_exceptions=False)
        server._reset_security_state_for_tests()

    def tearDown(self):
        import server
        server.CASES_ROOT = self._orig_cases_root
        server.UPLOAD_ROOT = self._orig_upload_root
        server.STATIC_DIR = self._orig_static_dir
        server.DATA_ROOT = self._orig_data_root
        server.BACKUPS_ROOT = self._orig_backups_root
        import triage_engine.review_store as rs
        rs._DB_PATH = self._orig_review_db
        import triage_engine.auth_store as auth
        auth._DB_PATH = self._orig_auth_db
        shutil.rmtree(self._temp_root, ignore_errors=True)

    def _sync_csrf_header(self):
        me = self.client.get("/api/auth/me")
        if me.status_code != 200:
            return
        token = me.json().get("csrf_token", "")
        if token:
            self.client.headers["X-CSRF-Token"] = token
        else:
            self.client.headers.pop("X-CSRF-Token", None)

    def _bootstrap(self, username="admin", password="Password123!"):
        resp = self.client.post("/api/auth/bootstrap", json={"username": username, "password": password})
        if resp.status_code == 200:
            self._sync_csrf_header()
        return resp

    def _login(self, username: str, password: str):
        resp = self.client.post("/api/auth/login", json={"username": username, "password": password})
        if resp.status_code == 200:
            self._sync_csrf_header()
        return resp

    def _logout(self):
        resp = self.client.post("/api/auth/logout")
        if resp.status_code == 200:
            self.client.headers.pop("X-CSRF-Token", None)
        return resp

    def _seed_backup_state_files(self):
        import server

        for filename, marker in (
            ("auth.db", "auth"),
            ("reviews.db", "reviews"),
            ("jobs.db", "jobs"),
        ):
            path = os.path.join(server.DATA_ROOT, filename)
            con = sqlite3.connect(path)
            try:
                con.execute("CREATE TABLE IF NOT EXISTS marker (value TEXT NOT NULL)")
                con.execute("DELETE FROM marker")
                con.execute("INSERT INTO marker (value) VALUES (?)", (marker,))
                con.commit()
            finally:
                con.close()

    def test_auth_me_reports_bootstrap_required_when_empty(self):
        resp = self.client.get("/api/auth/me")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["authenticated"])
        self.assertTrue(data["bootstrap_required"])

    def test_password_policy_rejects_missing_uppercase(self):
        resp = self.client.post(
            "/api/auth/bootstrap",
            json={"username": "admin", "password": "lowercase123!"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("uppercase", resp.json()["detail"].lower())

    def test_password_policy_rejects_missing_special_character(self):
        resp = self.client.post(
            "/api/auth/bootstrap",
            json={"username": "admin", "password": "NoSpecial1234"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("special", resp.json()["detail"].lower())

    def test_password_policy_rejects_common_password(self):
        resp = self.client.post(
            "/api/auth/bootstrap",
            json={"username": "admin", "password": "Password1!"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("common", resp.json()["detail"].lower())

    def test_password_policy_rejects_username_substring(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "agent47", "password": "Agent47!SafePass", "role": "analyst"},
        )
        self.assertEqual(create.status_code, 400)
        self.assertIn("username", create.json()["detail"].lower())

    def test_change_password_rejects_common_password(self):
        self._bootstrap()
        changed = self.client.post(
            "/api/auth/change-password",
            json={"current_password": "Password123!", "new_password": "Password1!"},
        )
        self.assertEqual(changed.status_code, 400)
        self.assertIn("common", changed.json()["detail"].lower())

    def test_csrf_required_for_state_changing_requests(self):
        self._bootstrap()
        current_token = self.client.headers.pop("X-CSRF-Token", "")

        denied = self.client.post(
            "/api/auth/users",
            json={"username": "csrf-user-a", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertIn("csrf", denied.json()["detail"].lower())

        if current_token:
            self.client.headers["X-CSRF-Token"] = current_token
        allowed = self.client.post(
            "/api/auth/users",
            json={"username": "csrf-user-b", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(allowed.status_code, 200)

    def test_all_protected_endpoints_require_authentication(self):
        evtx_path = _create_evtx_stub(self._temp_root, "unauth-protected.evtx")
        protected_requests = [
            ("get", "/api/metrics", {}),
            ("get", "/api/auth/users", {}),
            ("post", "/api/auth/users", {"json": {"username": "unauth-user", "password": "Password123!", "role": "viewer"}}),
            ("patch", "/api/auth/users/unauth-user", {"json": {"active": False}}),
            ("get", "/api/auth/sessions", {}),
            ("delete", "/api/auth/sessions/unauth-session", {}),
            ("get", "/api/auth/audit", {}),
            ("get", "/api/auth/preferences", {}),
            ("patch", "/api/auth/preferences", {"json": {"preferences": {"queue_sort": "updated_desc"}}}),
            ("post", "/api/auth/change-password", {"json": {"current_password": "Password123!", "new_password": "NewPassword123!"}}),
            ("get", "/api/auth/audit/export?format=csv", {}),
            ("post", "/api/admin/backup", {}),
            ("get", "/api/admin/backups", {}),
            ("get", "/api/cases", {}),
            ("get", "/api/cases/export?format=csv", {}),
            ("get", "/api/cases/auth-case", {}),
            ("get", "/api/cases/auth-case/export", {}),
            ("get", "/api/cases/auth-case/status", {}),
            ("get", "/api/cases/auth-case/timeline", {}),
            ("get", "/api/cases/auth-case/graph", {}),
            ("get", "/api/cases/auth-case/report", {}),
            ("get", "/api/cases/auth-case/summary", {}),
            ("get", "/api/cases/auth-case/brief", {}),
            ("delete", "/api/cases/auth-case", {}),
            ("post", "/api/investigate", {"files": [("files", ("unauth-protected.evtx", b"\x00" * 32, "application/octet-stream"))]}),
            ("post", "/api/investigate/path", {"params": {"evtx_path": evtx_path, "case_name": "unauth-case"}}),
            ("post", "/api/investigate/live", {"json": {"channels": ["Security"], "since_minutes": 15, "case_name": "unauth-live-case"}}),
            ("get", "/api/live/health", {}),
            ("get", "/api/jobs", {}),
            ("get", "/api/jobs/nonexistent-job", {}),
            ("post", "/api/jobs/delete", {"json": {"job_ids": ["nonexistent-job"]}}),
            ("get", "/api/cases/auth-case/findings/fnd-0/review", {}),
            ("get", "/api/cases/auth-case/incidents/inc-0/review", {}),
            ("patch", "/api/cases/auth-case/findings/fnd-0/review", {"json": {"status": "In Review", "owner": "unauth-owner"}}),
            ("patch", "/api/cases/auth-case/incidents/inc-0/review", {"json": {"status": "In Review", "owner": "unauth-owner"}}),
            ("post", "/api/cases/auth-case/findings/fnd-0/notes", {"json": {"content": "unauth note"}}),
            ("post", "/api/cases/auth-case/incidents/inc-0/notes", {"json": {"content": "unauth note"}}),
            ("get", "/api/review/queue", {}),
            ("get", "/api/review/queue/export?format=csv", {}),
            ("get", "/api/review/history", {}),
            ("get", "/api/review/history/export?format=csv", {}),
            ("post", "/api/cases/auth-case/reviews/carry-forward", {}),
            ("get", "/api/review/enums", {}),
        ]

        for method, path, kwargs in protected_requests:
            with self.subTest(endpoint=f"{method.upper()} {path}"):
                response = getattr(self.client, method)(path, **kwargs)
                self.assertEqual(response.status_code, 401)

    def test_request_id_propagates_into_investigation_request_context(self):
        self._bootstrap()
        evtx_path = _create_evtx_stub(self._temp_root, "request-id-propagation.evtx")
        captured: dict = {}

        class _ImmediateThread:
            def __init__(self, target=None, args=(), daemon=None, **_kwargs):
                self._target = target
                self._args = args
                self._daemon = daemon

            def start(self):
                captured["target"] = self._target
                captured["args"] = self._args

        request_id = "auth-request-id-propagation"
        with patch("server.Thread", _ImmediateThread):
            resp = self.client.post(
                "/api/investigate/path",
                params={"evtx_path": evtx_path, "case_name": "request-id-case"},
                headers={"X-Request-ID": request_id},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Request-ID"), request_id)
        self.assertIn("args", captured)
        investigation_request = captured["args"][1]
        self.assertEqual(investigation_request.request_id, request_id)
        self.assertEqual(investigation_request.requested_by, "admin")

    def test_login_rate_limit_enforced_by_username(self):
        self._bootstrap()
        self._logout()
        attempts = [self._login("admin", "wrong-pass") for _ in range(6)]
        self.assertTrue(all(resp.status_code == 401 for resp in attempts[:5]))
        self.assertEqual(attempts[-1].status_code, 429)
        self.assertIn("Retry-After", attempts[-1].headers)

    def test_login_rate_limit_counter_resets_after_window(self):
        import server

        self._bootstrap()
        self._logout()
        attempts = [self._login("admin", "wrong-pass") for _ in range(6)]
        self.assertTrue(all(resp.status_code == 401 for resp in attempts[:5]))
        self.assertEqual(attempts[5].status_code, 429)

        # Simulate passage of the rate-limit window by aging bucket entries.
        with server._RATE_LIMIT_LOCK:
            server._RATE_LIMIT_BUCKETS["login-user:admin"] = server.deque([-1_000_000_000.0] * 5)

        after_window = self._login("admin", "wrong-pass")
        self.assertEqual(after_window.status_code, 401)

    def test_session_cookie_marks_secure_on_forwarded_https(self):
        with patch.dict(os.environ, {"TRIAGE_SESSION_TTL_HOURS": "6"}, clear=False):
            resp = self.client.post(
                "/api/auth/bootstrap",
                headers={"X-Forwarded-Proto": "https"},
                json={"username": "secure-admin", "password": "Password123!"},
            )
        self.assertEqual(resp.status_code, 200)
        set_cookie = resp.headers.get("set-cookie", "")
        lowered = set_cookie.lower()
        self.assertIn("secure", lowered)
        self.assertIn("httponly", lowered)
        self.assertIn("samesite=lax", lowered)
        self.assertIn("path=/", lowered)
        self.assertIn("max-age=21600", lowered)

    def test_session_activity_touch_is_debounced_to_one_minute(self):
        import triage_engine.auth_store as auth

        self._bootstrap()
        session_id = self.client.cookies.get("triage_session")
        self.assertTrue(session_id)
        stale_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        with auth._conn() as con:
            con.execute("UPDATE sessions SET last_active_at = ? WHERE session_id = ?", (stale_time, session_id))

        first_me = self.client.get("/api/auth/me")
        self.assertEqual(first_me.status_code, 200)
        with auth._conn() as con:
            first_last_active = con.execute(
                "SELECT last_active_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()["last_active_at"]
        self.assertNotEqual(first_last_active, stale_time)

        second_me = self.client.get("/api/auth/me")
        self.assertEqual(second_me.status_code, 200)
        with auth._conn() as con:
            second_last_active = con.execute(
                "SELECT last_active_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()["last_active_at"]
        self.assertEqual(second_last_active, first_last_active)

    def test_idle_timeout_invalidates_stale_session_on_next_request(self):
        import triage_engine.auth_store as auth

        with patch.dict(os.environ, {"TRIAGE_SESSION_IDLE_HOURS": "1"}, clear=False):
            self._bootstrap()
            session_id = self.client.cookies.get("triage_session")
            self.assertTrue(session_id)
            now = datetime.now(timezone.utc)
            stale_last_active = (now - timedelta(hours=3)).isoformat()
            still_valid_expiry = (now + timedelta(hours=3)).isoformat()
            with auth._conn() as con:
                con.execute(
                    "UPDATE sessions SET last_active_at = ?, expires_at = ? WHERE session_id = ?",
                    (stale_last_active, still_valid_expiry, session_id),
                )

            me = self.client.get("/api/auth/me")
            self.assertEqual(me.status_code, 200)
            self.assertFalse(me.json()["authenticated"])

            denied = self.client.get("/api/cases")
            self.assertEqual(denied.status_code, 401)

            with auth._conn() as con:
                remaining = con.execute(
                    "SELECT COUNT(*) AS c FROM sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()["c"]
            self.assertEqual(remaining, 0)

    def test_expired_session_returns_401_for_protected_read_write_endpoints(self):
        import triage_engine.auth_store as auth

        self._bootstrap()
        session_id = self.client.cookies.get("triage_session")
        self.assertTrue(session_id)
        expired = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with auth._conn() as con:
            con.execute(
                "UPDATE sessions SET expires_at = ?, last_active_at = ? WHERE session_id = ?",
                (expired, expired, session_id),
            )

        probes = [
            ("get", "/api/cases", {}),
            ("get", "/api/review/queue", {}),
            ("patch", "/api/cases/auth-case/findings/fnd-0/review", {"json": {"status": "In Review", "owner": "admin"}}),
            ("post", "/api/cases/auth-case/findings/fnd-0/notes", {"json": {"content": "expired session note"}}),
            ("post", "/api/jobs/delete", {"json": {"job_ids": ["expired-session-job"]}}),
        ]
        for method, path, kwargs in probes:
            with self.subTest(endpoint=f"{method.upper()} {path}"):
                resp = getattr(self.client, method)(path, **kwargs)
                self.assertEqual(resp.status_code, 401)

    def test_admin_can_list_and_revoke_sessions(self):
        import server

        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "session-analyst", "password": "Password123!", "role": "analyst"},
        )
        self.assertEqual(create.status_code, 200)

        with TestClient(server.app, raise_server_exceptions=False) as analyst_client:
            analyst_login = analyst_client.post(
                "/api/auth/login",
                json={"username": "session-analyst", "password": "Password123!"},
            )
            self.assertEqual(analyst_login.status_code, 200)

            listed = self.client.get("/api/auth/sessions")
            self.assertEqual(listed.status_code, 200)
            sessions = listed.json()["sessions"]
            analyst_session = next((row for row in sessions if row["username"] == "session-analyst"), None)
            self.assertIsNotNone(analyst_session)
            self.assertIn("created_at", analyst_session)
            self.assertIn("last_active_at", analyst_session)
            self.assertIn("ip", analyst_session)

            revoked = self.client.delete(f"/api/auth/sessions/{analyst_session['session_id']}")
            self.assertEqual(revoked.status_code, 200)
            self.assertTrue(revoked.json()["revoked"])

            denied = analyst_client.get("/api/cases")
            self.assertEqual(denied.status_code, 401)

    def test_non_admin_cannot_manage_sessions(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "session-viewer", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(create.status_code, 200)
        self._logout()
        login = self._login("session-viewer", "Password123!")
        self.assertEqual(login.status_code, 200)

        denied_list = self.client.get("/api/auth/sessions")
        self.assertEqual(denied_list.status_code, 403)
        denied_delete = self.client.delete("/api/auth/sessions/not-a-real-session")
        self.assertEqual(denied_delete.status_code, 403)

    def test_admin_can_access_metrics_snapshot(self):
        self._bootstrap()
        resp = self.client.get("/api/metrics")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for key in (
            "uptime_seconds",
            "total_jobs",
            "active_jobs",
            "completed_jobs",
            "failed_jobs",
            "total_cases",
            "total_users",
            "active_sessions",
            "queue_size",
            "db_sizes",
        ):
            self.assertIn(key, data)
        self.assertIsInstance(data["uptime_seconds"], int)
        self.assertIsInstance(data["db_sizes"], dict)
        self.assertIn("auth_db", data["db_sizes"])
        self.assertIn("reviews_db", data["db_sizes"])
        self.assertIn("jobs_db", data["db_sizes"])

    def test_non_admin_cannot_access_metrics_snapshot(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "metrics-viewer", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(create.status_code, 200)
        self._logout()
        login = self._login("metrics-viewer", "Password123!")
        self.assertEqual(login.status_code, 200)

        denied = self.client.get("/api/metrics")
        self.assertEqual(denied.status_code, 403)

    def test_viewer_cannot_investigate_delete_cases_or_modify_reviews(self):
        self._bootstrap()
        created = self.client.post(
            "/api/auth/users",
            json={"username": "locked-viewer", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(created.status_code, 200)
        self._logout()
        login = self._login("locked-viewer", "Password123!")
        self.assertEqual(login.status_code, 200)

        evtx_path = _create_evtx_stub(self._temp_root, "viewer-denied.evtx")
        denied_investigate = self.client.post(
            "/api/investigate/path",
            params={"evtx_path": evtx_path, "case_name": "viewer-denied-case"},
        )
        self.assertEqual(denied_investigate.status_code, 403)

        denied_delete_case = self.client.delete("/api/cases/auth-case")
        self.assertEqual(denied_delete_case.status_code, 403)

        denied_review_patch = self.client.patch(
            "/api/cases/auth-case/findings/fnd-0/review",
            json={"status": "Closed"},
        )
        self.assertEqual(denied_review_patch.status_code, 403)

        denied_note = self.client.post(
            "/api/cases/auth-case/findings/fnd-0/notes",
            json={"content": "viewer note"},
        )
        self.assertEqual(denied_note.status_code, 403)

        denied_incident_review = self.client.patch(
            "/api/cases/auth-case/incidents/inc-0/review",
            json={"status": "Closed"},
        )
        self.assertEqual(denied_incident_review.status_code, 403)

        denied_incident_note = self.client.post(
            "/api/cases/auth-case/incidents/inc-0/notes",
            json={"content": "viewer incident note"},
        )
        self.assertEqual(denied_incident_note.status_code, 403)

        denied_carry_forward = self.client.post("/api/cases/auth-case/reviews/carry-forward")
        self.assertEqual(denied_carry_forward.status_code, 403)

    def test_review_owner_and_note_xss_payloads_round_trip_as_json_data(self):
        self._bootstrap()
        owner_payload = "<img src=x onerror=alert('owner-xss')>"
        note_payload = "<script>alert('note-xss')</script>"

        updated = self.client.patch(
            "/api/cases/auth-case/findings/fnd-0/review",
            json={"status": "In Review", "owner": owner_payload},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertIn("application/json", updated.headers.get("content-type", ""))
        self.assertEqual(updated.json()["owner"], owner_payload)

        noted = self.client.post(
            "/api/cases/auth-case/findings/fnd-0/notes",
            json={"content": note_payload},
        )
        self.assertEqual(noted.status_code, 200)
        self.assertIn("application/json", noted.headers.get("content-type", ""))
        self.assertEqual(noted.json()["content"], note_payload)

        review = self.client.get("/api/cases/auth-case/findings/fnd-0/review")
        self.assertEqual(review.status_code, 200)
        self.assertIn("application/json", review.headers.get("content-type", ""))
        payload = review.json()
        self.assertEqual(payload["owner"], owner_payload)
        self.assertTrue(any(note.get("content") == note_payload for note in payload.get("notes", [])))

    def test_review_queue_filters_resist_sql_injection_payloads(self):
        self._bootstrap()
        seeded = self.client.patch(
            "/api/cases/auth-case/findings/fnd-0/review",
            json={"status": "In Review", "owner": "filter-safe-owner"},
        )
        self.assertEqual(seeded.status_code, 200)

        normal = self.client.get("/api/review/queue", params={"owner": "filter-safe-owner", "status": "In Review"})
        self.assertEqual(normal.status_code, 200)
        self.assertTrue(any(item["item_id"] == "fnd-0" for item in normal.json()))

        injected_owner = self.client.get(
            "/api/review/queue",
            params={"owner": "filter-safe-owner' OR '1'='1", "status": "In Review"},
        )
        self.assertEqual(injected_owner.status_code, 200)
        self.assertEqual(injected_owner.json(), [])

        injected_status = self.client.get(
            "/api/review/queue",
            params={"status": "Open' OR 1=1 --"},
        )
        self.assertEqual(injected_status.status_code, 200)
        self.assertEqual(injected_status.json(), [])

        after = self.client.get("/api/review/queue", params={"owner": "filter-safe-owner", "status": "In Review"})
        self.assertEqual(after.status_code, 200)
        self.assertTrue(any(item["item_id"] == "fnd-0" for item in after.json()))

    def test_case_access_and_review_changes_are_audited(self):
        self._bootstrap()

        case_resp = self.client.get("/api/cases/auth-case")
        self.assertEqual(case_resp.status_code, 200)
        status_resp = self.client.get("/api/cases/auth-case/status")
        self.assertEqual(status_resp.status_code, 200)
        review_get = self.client.get("/api/cases/auth-case/findings/fnd-0/review")
        self.assertEqual(review_get.status_code, 200)

        review_patch = self.client.patch(
            "/api/cases/auth-case/findings/fnd-0/review",
            json={"status": "In Review", "owner": "admin"},
        )
        self.assertEqual(review_patch.status_code, 200)

        note_add = self.client.post(
            "/api/cases/auth-case/findings/fnd-0/notes",
            json={"content": "audit trail note", "author": "admin"},
        )
        self.assertEqual(note_add.status_code, 200)

        access_audit = self.client.get("/api/auth/audit?action=access_case_detail&target_username=auth-case")
        self.assertEqual(access_audit.status_code, 200)
        access_events = access_audit.json()["events"]
        self.assertTrue(any(event["action"] == "access_case_detail" for event in access_events))
        self.assertTrue(any(event.get("details", {}).get("endpoint") == "/api/cases/{case_name}" for event in access_events))
        self.assertTrue(any(event.get("details", {}).get("endpoint") == "/api/cases/{case_name}/status" for event in access_events))

        review_audit = self.client.get("/api/auth/audit?action=update_review&target_username=auth-case")
        self.assertEqual(review_audit.status_code, 200)
        review_events = review_audit.json()["events"]
        self.assertTrue(any(event.get("details", {}).get("item_id") == "fnd-0" for event in review_events))

        note_audit = self.client.get("/api/auth/audit?action=add_review_note&target_username=auth-case")
        self.assertEqual(note_audit.status_code, 200)
        note_events = note_audit.json()["events"]
        self.assertTrue(any(event.get("details", {}).get("item_id") == "fnd-0" for event in note_events))

    def test_error_message_redacts_missing_path_details(self):
        self._bootstrap()
        missing_path = os.path.join(self._temp_root, "missing-path.evtx")
        resp = self.client.post("/api/investigate/path", params={"evtx_path": missing_path})
        self.assertEqual(resp.status_code, 400)
        detail = str(resp.json().get("detail", ""))
        self.assertNotIn(missing_path, detail)
        self.assertNotIn(self._temp_root, detail)

    def test_admin_can_create_and_list_backups(self):
        self._bootstrap()
        self._seed_backup_state_files()

        created = self.client.post("/api/admin/backup")
        self.assertEqual(created.status_code, 200)
        payload = created.json()
        self.assertTrue(payload["backup_id"].startswith("backup-"))
        self.assertTrue(os.path.isdir(payload["backup_path"]))
        self.assertEqual(len(payload["files"]), 3)
        self.assertGreater(payload["total_bytes"], 0)
        self.assertTrue(os.path.isfile(os.path.join(payload["backup_path"], "manifest.json")))

        listed = self.client.get("/api/admin/backups")
        self.assertEqual(listed.status_code, 200)
        backups = listed.json()["backups"]
        self.assertTrue(any(item["backup_id"] == payload["backup_id"] for item in backups))

        audit = self.client.get("/api/auth/audit?action=create_backup")
        self.assertEqual(audit.status_code, 200)
        self.assertTrue(any(event["action"] == "create_backup" for event in audit.json()["events"]))

    def test_non_admin_cannot_access_backup_endpoints(self):
        self._bootstrap()
        self._seed_backup_state_files()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "backup-analyst", "password": "Password123!", "role": "analyst"},
        )
        self.assertEqual(create.status_code, 200)
        self._logout()
        login = self._login("backup-analyst", "Password123!")
        self.assertEqual(login.status_code, 200)

        denied_create = self.client.post("/api/admin/backup")
        self.assertEqual(denied_create.status_code, 403)
        denied_list = self.client.get("/api/admin/backups")
        self.assertEqual(denied_list.status_code, 403)

    def test_bootstrap_sets_session_and_me_returns_user(self):
        resp = self._bootstrap()
        self.assertEqual(resp.status_code, 200)
        me = self.client.get("/api/auth/me")
        self.assertEqual(me.status_code, 200)
        data = me.json()
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["user"]["username"], "admin")
        self.assertEqual(data["user"]["role"], "admin")

    def test_logout_revokes_session_and_protected_route_returns_401(self):
        self._bootstrap()
        logout = self._logout()
        self.assertEqual(logout.status_code, 200)
        resp = self.client.get("/api/cases")
        self.assertEqual(resp.status_code, 401)

    def test_login_and_admin_user_creation(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "analyst1", "password": "Password123!", "role": "analyst"},
        )
        self.assertEqual(create.status_code, 200)
        logout = self._logout()
        self.assertEqual(logout.status_code, 200)
        bad = self._login("analyst1", "wrong-pass")
        self.assertEqual(bad.status_code, 401)
        good = self._login("analyst1", "Password123!")
        self.assertEqual(good.status_code, 200)
        cases = self.client.get("/api/cases")
        self.assertEqual(cases.status_code, 200)
        forbidden = self.client.post(
            "/api/auth/users",
            json={"username": "viewer1", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(forbidden.status_code, 403)

    def test_admin_can_deactivate_and_reactivate_user(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "analyst2", "password": "Password123!", "role": "analyst"},
        )
        self.assertEqual(create.status_code, 200)
        deactivate = self.client.patch("/api/auth/users/analyst2", json={"active": False})
        self.assertEqual(deactivate.status_code, 200)
        self.assertEqual(deactivate.json()["user"]["active"], 0)
        self._logout()
        denied = self._login("analyst2", "Password123!")
        self.assertEqual(denied.status_code, 401)
        admin_login = self._login("admin", "Password123!")
        self.assertEqual(admin_login.status_code, 200)
        reactivate = self.client.patch("/api/auth/users/analyst2", json={"active": True})
        self.assertEqual(reactivate.status_code, 200)
        self.assertEqual(reactivate.json()["user"]["active"], 1)
        self._logout()
        restored = self._login("analyst2", "Password123!")
        self.assertEqual(restored.status_code, 200)

    def test_admin_can_reset_password_and_change_role(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "viewer2", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(create.status_code, 200)
        update = self.client.patch(
            "/api/auth/users/viewer2",
            json={"password": "ChangedPassword123!", "role": "analyst"},
        )
        self.assertEqual(update.status_code, 200)
        self.assertEqual(update.json()["user"]["role"], "analyst")
        self._logout()
        old_login = self._login("viewer2", "Password123!")
        self.assertEqual(old_login.status_code, 401)
        new_login = self._login("viewer2", "ChangedPassword123!")
        self.assertEqual(new_login.status_code, 200)
        cases = self.client.get("/api/cases")
        self.assertEqual(cases.status_code, 200)

    def test_user_can_change_own_password(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "analyst-self", "password": "Password123!", "role": "analyst"},
        )
        self.assertEqual(create.status_code, 200)
        self._logout()
        login = self._login("analyst-self", "Password123!")
        self.assertEqual(login.status_code, 200)
        bad = self.client.post(
            "/api/auth/change-password",
            json={"current_password": "wrong-pass", "new_password": "BetterPassword123!"},
        )
        self.assertEqual(bad.status_code, 401)
        changed = self.client.post(
            "/api/auth/change-password",
            json={"current_password": "Password123!", "new_password": "BetterPassword123!"},
        )
        self.assertEqual(changed.status_code, 200)
        self.assertTrue(changed.json()["changed"])
        self._logout()
        old_login = self._login("analyst-self", "Password123!")
        self.assertEqual(old_login.status_code, 401)
        new_login = self._login("analyst-self", "BetterPassword123!")
        self.assertEqual(new_login.status_code, 200)

    def test_admin_cannot_deactivate_self(self):
        self._bootstrap()
        resp = self.client.patch("/api/auth/users/admin", json={"active": False})
        self.assertEqual(resp.status_code, 400)

    def test_admin_audit_events_include_user_management_actions(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "audited", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(create.status_code, 200)
        update = self.client.patch("/api/auth/users/audited", json={"role": "analyst"})
        self.assertEqual(update.status_code, 200)
        audit = self.client.get("/api/auth/audit")
        self.assertEqual(audit.status_code, 200)
        events = audit.json()["events"]
        self.assertTrue(any(e["action"] == "create_user" and e["target_username"] == "audited" for e in events))
        self.assertTrue(any(e["action"] == "update_user" and e["target_username"] == "audited" for e in events))

    def test_admin_audit_filters_support_actor_action_and_search(self):
        self._bootstrap()
        create = self.client.post(
            "/api/auth/users",
            json={"username": "filterme", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(create.status_code, 200)
        update = self.client.patch("/api/auth/users/filterme", json={"role": "analyst"})
        self.assertEqual(update.status_code, 200)
        by_action = self.client.get("/api/auth/audit?action=update_user")
        self.assertEqual(by_action.status_code, 200)
        self.assertTrue(all(event["action"] == "update_user" for event in by_action.json()["events"]))
        by_actor = self.client.get("/api/auth/audit?actor_username=admin")
        self.assertEqual(by_actor.status_code, 200)
        self.assertTrue(any(event["target_username"] == "filterme" for event in by_actor.json()["events"]))
        by_search = self.client.get("/api/auth/audit?search=filterme")
        self.assertEqual(by_search.status_code, 200)
        self.assertTrue(any(event["target_username"] == "filterme" for event in by_search.json()["events"]))

    def test_preferences_round_trip(self):
        self._bootstrap()
        get_default = self.client.get("/api/auth/preferences")
        self.assertEqual(get_default.status_code, 200)
        self.assertEqual(get_default.json()["preferences"], {})
        update = self.client.patch(
            "/api/auth/preferences",
            json={
                "preferences": {
                    "queue_sort": "priority_asc",
                    "case_density": "compact",
                    "dashboardTemplates": {
                        "Morning Triage": {
                            "landingPage": "queue",
                            "dashboardFocus": "open",
                            "dashboardWidgets": ["review-focus", "priority-watch"],
                            "compactDensity": True,
                        }
                    },
                    "activeDashboardTemplate": "Morning Triage",
                }
            },
        )
        self.assertEqual(update.status_code, 200)
        data = update.json()
        self.assertEqual(data["preferences"]["queue_sort"], "priority_asc")
        self.assertEqual(data["preferences"]["activeDashboardTemplate"], "Morning Triage")
        reread = self.client.get("/api/auth/preferences")
        self.assertEqual(reread.status_code, 200)
        self.assertEqual(reread.json()["preferences"]["case_density"], "compact")
        self.assertIn("Morning Triage", reread.json()["preferences"]["dashboardTemplates"])
        audit = self.client.get("/api/auth/audit?action=update_preferences")
        self.assertEqual(audit.status_code, 200)
        self.assertTrue(any(e["target_username"] == "admin" for e in audit.json()["events"]))

    def test_admin_can_export_audit_csv(self):
        self._bootstrap()
        self.client.post(
            "/api/auth/users",
            json={"username": "exported", "password": "Password123!", "role": "viewer"},
        )
        resp = self.client.get("/api/auth/audit/export?format=csv&search=exported")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers["content-type"])
        self.assertIn("Content-Disposition", resp.headers)
        body = resp.text
        self.assertIn("actor_username", body)
        self.assertIn("exported", body)

    def test_analyst_end_to_end_acceptance_flow(self):
        self._bootstrap(username="chief-admin", password="Password123!")
        create = self.client.post(
            "/api/auth/users",
            json={"username": "analyst-e2e", "password": "Password123!", "role": "analyst"},
        )
        self.assertEqual(create.status_code, 200)

        logout = self._logout()
        self.assertEqual(logout.status_code, 200)

        login = self._login("analyst-e2e", "Password123!")
        self.assertEqual(login.status_code, 200)

        me = self.client.get("/api/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertTrue(me.json()["authenticated"])
        self.assertEqual(me.json()["user"]["username"], "analyst-e2e")
        self.assertEqual(me.json()["user"]["role"], "analyst")

        prefs = self.client.patch(
            "/api/auth/preferences",
            json={
                "preferences": {
                    "landingPage": "queue",
                    "themeMode": "system",
                    "dashboardFocus": "my_queue",
                    "compactDensity": True,
                }
            },
        )
        self.assertEqual(prefs.status_code, 200)
        self.assertEqual(prefs.json()["preferences"]["landingPage"], "queue")
        self.assertEqual(prefs.json()["preferences"]["themeMode"], "system")

        live_health = self.client.get("/api/live/health")
        self.assertEqual(live_health.status_code, 200)
        self.assertIn("readiness", live_health.json())

        evtx_path = _create_evtx_stub(self._temp_root, "analyst-flow.evtx")
        start = self.client.post(
            "/api/investigate/path",
            params={"evtx_path": evtx_path, "case_name": "analyst-path-case"},
        )
        self.assertEqual(start.status_code, 200)
        job_id = start.json()["job_id"]

        final_job = None
        for _ in range(50):
            job_resp = self.client.get(f"/api/jobs/{job_id}")
            self.assertEqual(job_resp.status_code, 200)
            final_job = job_resp.json()
            if final_job.get("status") not in {"queued", "running"}:
                break
            time.sleep(0.1)
        self.assertIsNotNone(final_job)
        self.assertNotIn(final_job.get("status"), {"queued", "running"})
        self.assertIn(final_job.get("status"), {"completed", "failed"})

        cases = self.client.get("/api/cases")
        self.assertEqual(cases.status_code, 200)
        self.assertTrue(any(case["name"] == "auth-case" for case in cases.json()))

        review = self.client.patch(
            "/api/cases/auth-case/findings/fnd-0/review",
            json={
                "status": "In Review",
                "owner": "analyst-e2e",
                "disposition": "Suspicious - Needs More Investigation",
                "priority": "P2",
            },
        )
        self.assertEqual(review.status_code, 200)
        self.assertEqual(review.json()["owner"], "analyst-e2e")
        self.assertEqual(review.json()["status"], "In Review")

        note = self.client.post(
            "/api/cases/auth-case/findings/fnd-0/notes",
            json={"content": "Analyst acceptance note"},
        )
        self.assertEqual(note.status_code, 200)
        self.assertEqual(note.json()["author"], "analyst-e2e")

        queue = self.client.get("/api/review/queue?owner=analyst-e2e&status=In%20Review")
        self.assertEqual(queue.status_code, 200)
        self.assertTrue(any(item["item_id"] == "fnd-0" for item in queue.json()))

        case_detail = self.client.get("/api/cases/auth-case")
        self.assertEqual(case_detail.status_code, 200)
        finding = next(item for item in case_detail.json()["findings"] if item["id"] == "fnd-0")
        self.assertEqual(finding["review"]["owner"], "analyst-e2e")
        self.assertEqual(finding["review"]["status"], "In Review")

        history_export = self.client.get(
            "/api/review/history/export?format=csv&case_name=auth-case&item_type=finding&item_id=fnd-0"
        )
        self.assertEqual(history_export.status_code, 200)
        self.assertIn("text/csv", history_export.headers["content-type"])
        self.assertIn("note_added", history_export.text)
        self.assertIn("Analyst acceptance note", history_export.text)

        queue_export = self.client.get("/api/review/queue/export?format=csv&owner=analyst-e2e")
        self.assertEqual(queue_export.status_code, 200)
        self.assertIn("text/csv", queue_export.headers["content-type"])
        self.assertIn("auth-case", queue_export.text)

        case_export = self.client.get("/api/cases/auth-case/export")
        self.assertEqual(case_export.status_code, 200)
        self.assertIn("application/json", case_export.headers["content-type"])
        self.assertEqual(case_export.json()["case"]["case_name"], "auth-case")

        cases_export = self.client.get("/api/cases/export?format=csv")
        self.assertEqual(cases_export.status_code, 200)
        self.assertIn("text/csv", cases_export.headers["content-type"])
        self.assertIn("auth-case", cases_export.text)

        carry_forward = self.client.post("/api/cases/auth-case/reviews/carry-forward")
        self.assertEqual(carry_forward.status_code, 200)
        carry_forward_payload = carry_forward.json()
        self.assertIn("findings_carried", carry_forward_payload)
        self.assertIn("findings_created", carry_forward_payload)

        delete_jobs = self.client.post("/api/jobs/delete", json={"job_ids": [job_id]})
        self.assertEqual(delete_jobs.status_code, 200)
        self.assertIn(job_id, delete_jobs.json()["deleted"])

        missing_job = self.client.get(f"/api/jobs/{job_id}")
        self.assertEqual(missing_job.status_code, 404)

        logout = self._logout()
        self.assertEqual(logout.status_code, 200)
        after_logout = self.client.get("/api/cases")
        self.assertEqual(after_logout.status_code, 401)
        queue_after_logout = self.client.get("/api/review/queue")
        self.assertEqual(queue_after_logout.status_code, 401)

    def test_multi_user_review_flow_with_admin_forced_logout(self):
        import server

        self._bootstrap(username="phase73-admin", password="Password123!")
        analyst_create = self.client.post(
            "/api/auth/users",
            json={"username": "phase73-analyst", "password": "Password123!", "role": "analyst"},
        )
        self.assertEqual(analyst_create.status_code, 200)
        viewer_create = self.client.post(
            "/api/auth/users",
            json={"username": "phase73-viewer", "password": "Password123!", "role": "viewer"},
        )
        self.assertEqual(viewer_create.status_code, 200)

        with TestClient(server.app, raise_server_exceptions=False) as analyst_client, TestClient(
            server.app, raise_server_exceptions=False
        ) as viewer_client:
            analyst_login = analyst_client.post(
                "/api/auth/login",
                json={"username": "phase73-analyst", "password": "Password123!"},
            )
            self.assertEqual(analyst_login.status_code, 200)
            analyst_me = analyst_client.get("/api/auth/me")
            self.assertEqual(analyst_me.status_code, 200)
            analyst_token = analyst_me.json().get("csrf_token", "")
            self.assertTrue(analyst_token)
            analyst_client.headers["X-CSRF-Token"] = analyst_token

            viewer_login = viewer_client.post(
                "/api/auth/login",
                json={"username": "phase73-viewer", "password": "Password123!"},
            )
            self.assertEqual(viewer_login.status_code, 200)
            viewer_me = viewer_client.get("/api/auth/me")
            self.assertEqual(viewer_me.status_code, 200)
            viewer_token = viewer_me.json().get("csrf_token", "")
            self.assertTrue(viewer_token)
            viewer_client.headers["X-CSRF-Token"] = viewer_token

            analyst_review = analyst_client.patch(
                "/api/cases/auth-case/findings/fnd-0/review",
                json={"status": "In Review", "owner": "phase73-analyst", "priority": "P1"},
            )
            self.assertEqual(analyst_review.status_code, 200)
            analyst_note = analyst_client.post(
                "/api/cases/auth-case/findings/fnd-0/notes",
                json={"content": "phase 7.3 analyst note"},
            )
            self.assertEqual(analyst_note.status_code, 200)

            viewer_case = viewer_client.get("/api/cases/auth-case")
            self.assertEqual(viewer_case.status_code, 200)
            viewer_finding = next(item for item in viewer_case.json()["findings"] if item["id"] == "fnd-0")
            self.assertEqual(viewer_finding["review"]["owner"], "phase73-analyst")
            self.assertEqual(viewer_finding["review"]["status"], "In Review")

            viewer_review = viewer_client.get("/api/cases/auth-case/findings/fnd-0/review")
            self.assertEqual(viewer_review.status_code, 200)
            self.assertEqual(viewer_review.json()["owner"], "phase73-analyst")

            viewer_patch_denied = viewer_client.patch(
                "/api/cases/auth-case/findings/fnd-0/review",
                json={"status": "Closed", "owner": "phase73-viewer"},
            )
            self.assertEqual(viewer_patch_denied.status_code, 403)
            viewer_note_denied = viewer_client.post(
                "/api/cases/auth-case/findings/fnd-0/notes",
                json={"content": "viewer should be denied"},
            )
            self.assertEqual(viewer_note_denied.status_code, 403)

            listed = self.client.get("/api/auth/sessions")
            self.assertEqual(listed.status_code, 200)
            sessions = listed.json()["sessions"]
            analyst_session = next((row for row in sessions if row["username"] == "phase73-analyst"), None)
            self.assertIsNotNone(analyst_session)

            revoked = self.client.delete(f"/api/auth/sessions/{analyst_session['session_id']}")
            self.assertEqual(revoked.status_code, 200)
            self.assertTrue(revoked.json()["revoked"])

            analyst_after_revoke = analyst_client.get("/api/cases")
            self.assertEqual(analyst_after_revoke.status_code, 401)
            viewer_still_reads = viewer_client.get("/api/cases")
            self.assertEqual(viewer_still_reads.status_code, 200)


# ---------------------------------------------------------------------------
# Job store unit tests
# ---------------------------------------------------------------------------

class JobStoreTests(unittest.TestCase):
    """Test durable SQLite job persistence."""

    def test_create_and_get_job(self):
        from triage_engine.job_store import create_job, get_job, delete_job
        job = create_job("test-job-001", case_name="test-case")
        self.assertEqual(job["job_id"], "test-job-001")
        self.assertEqual(job["status"], "queued")
        self.assertEqual(job["case_name"], "test-case")

        fetched = get_job("test-job-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["job_id"], "test-job-001")

        # Cleanup
        delete_job("test-job-001")

    def test_update_job(self):
        from triage_engine.job_store import create_job, update_job, get_job, delete_job
        create_job("test-job-002", case_name="update-test")
        update_job("test-job-002", status="running", stage="detect", message="Running detectors")

        job = get_job("test-job-002")
        self.assertEqual(job["status"], "running")
        self.assertEqual(job["stage"], "detect")
        self.assertEqual(job["message"], "Running detectors")

        delete_job("test-job-002")

    def test_update_job_with_results_dict(self):
        from triage_engine.job_store import create_job, update_job, get_job, delete_job
        create_job("test-job-003", case_name="results-test")
        update_job("test-job-003", results={"signal_count": 5, "finding_count": 2})

        job = get_job("test-job-003")
        self.assertIsInstance(job["results"], dict)
        self.assertEqual(job["results"]["signal_count"], 5)

        delete_job("test-job-003")

    def test_list_jobs(self):
        from triage_engine.job_store import create_job, list_jobs, delete_job
        create_job("test-job-list-a", case_name="list-a")
        create_job("test-job-list-b", case_name="list-b")

        jobs = list_jobs()
        job_ids = [j["job_id"] for j in jobs]
        self.assertIn("test-job-list-a", job_ids)
        self.assertIn("test-job-list-b", job_ids)

        delete_job("test-job-list-a")
        delete_job("test-job-list-b")

    def test_delete_job(self):
        from triage_engine.job_store import create_job, delete_job, get_job
        create_job("test-job-delete", case_name="delete-test")
        result = delete_job("test-job-delete")
        self.assertTrue(result)
        self.assertIsNone(get_job("test-job-delete"))

    def test_delete_nonexistent_job(self):
        from triage_engine.job_store import delete_job
        result = delete_job("nonexistent-job-id-xyz")
        self.assertFalse(result)

    def test_get_nonexistent_job(self):
        from triage_engine.job_store import get_job
        self.assertIsNone(get_job("absolutely-does-not-exist"))


# ---------------------------------------------------------------------------
# Store migration tests
# ---------------------------------------------------------------------------

class StoreMigrationTests(unittest.TestCase):
    def test_auth_store_migrates_legacy_schema_with_defaults(self):
        import triage_engine.auth_store as auth
        tmp = tempfile.mkdtemp(prefix="auth-migrate-test-")
        db_path = os.path.join(tmp, "auth_legacy.db")
        original_db_path = auth._DB_PATH
        try:
            auth._DB_PATH = db_path
            con = sqlite3.connect(db_path)
            con.executescript(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE sessions (
                    session_id TEXT PRIMARY KEY
                );
                CREATE TABLE auth_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL
                );
                CREATE TABLE user_preferences (
                    username TEXT PRIMARY KEY
                );
                """
            )
            now = datetime.now(timezone.utc).isoformat()
            con.execute(
                "INSERT INTO users (username, password_hash, role, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                ("legacy-admin", "legacy-hash", "admin", 1, now, now),
            )
            con.execute("INSERT INTO sessions (session_id) VALUES (?)", ("legacy-session",))
            con.execute("INSERT INTO auth_audit_events (action) VALUES (?)", ("legacy-login",))
            con.execute("INSERT INTO user_preferences (username) VALUES (?)", ("legacy-admin",))
            con.commit()
            con.close()

            auth._init_db()

            with auth._conn() as migrated:
                user_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(users)").fetchall()
                }
                self.assertIn("last_login_at", user_columns)

                session_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(sessions)").fetchall()
                }
                for column in ("user_id", "username", "role", "created_at", "expires_at", "last_active_at", "last_ip"):
                    self.assertIn(column, session_columns)

                audit_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(auth_audit_events)").fetchall()
                }
                for column in ("actor_username", "target_username", "details_json", "created_at"):
                    self.assertIn(column, audit_columns)

                prefs_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(user_preferences)").fetchall()
                }
                for column in ("preferences_json", "updated_at"):
                    self.assertIn(column, prefs_columns)

                user_row = migrated.execute(
                    "SELECT last_login_at FROM users WHERE username = ?",
                    ("legacy-admin",),
                ).fetchone()
                self.assertEqual(user_row["last_login_at"], "")

                session_row = migrated.execute(
                    "SELECT user_id, username, role, created_at, expires_at, last_active_at, last_ip FROM sessions WHERE session_id = ?",
                    ("legacy-session",),
                ).fetchone()
                self.assertEqual(session_row["user_id"], 0)
                self.assertEqual(session_row["username"], "")
                self.assertEqual(session_row["role"], "viewer")
                self.assertEqual(session_row["created_at"], "")
                self.assertEqual(session_row["expires_at"], "")
                self.assertEqual(session_row["last_active_at"], "")
                self.assertEqual(session_row["last_ip"], "")

                audit_row = migrated.execute(
                    "SELECT actor_username, target_username, details_json, created_at FROM auth_audit_events WHERE action = ?",
                    ("legacy-login",),
                ).fetchone()
                self.assertEqual(audit_row["actor_username"], "")
                self.assertEqual(audit_row["target_username"], "")
                self.assertEqual(audit_row["details_json"], "{}")
                self.assertEqual(audit_row["created_at"], "")

                prefs_row = migrated.execute(
                    "SELECT preferences_json, updated_at FROM user_preferences WHERE username = ?",
                    ("legacy-admin",),
                ).fetchone()
                self.assertEqual(prefs_row["preferences_json"], "{}")
                self.assertEqual(prefs_row["updated_at"], "")

                migrations = [
                    row["name"]
                    for row in migrated.execute(
                        "SELECT name FROM migrations WHERE name LIKE 'auth_store:%' ORDER BY name ASC"
                    ).fetchall()
                ]
                self.assertEqual(
                    migrations,
                    [
                        "auth_store:001_initial_schema",
                        "auth_store:002_add_missing_columns",
                        "auth_store:003_session_activity_columns",
                    ],
                )
        finally:
            auth._DB_PATH = original_db_path
            shutil.rmtree(tmp, ignore_errors=True)

    def test_job_store_migrates_legacy_schema_with_defaults(self):
        import triage_engine.job_store as js
        tmp = tempfile.mkdtemp(prefix="job-migrate-test-")
        db_path = os.path.join(tmp, "jobs_legacy.db")
        original_db_path = js._DB_PATH
        try:
            js._DB_PATH = db_path
            con = sqlite3.connect(db_path)
            con.executescript(
                """
                CREATE TABLE jobs (
                    job_id      TEXT PRIMARY KEY,
                    status      TEXT NOT NULL DEFAULT 'queued',
                    stage       TEXT NOT NULL DEFAULT 'init',
                    message     TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );
                """
            )
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            con.execute(
                "INSERT INTO jobs (job_id, status, stage, message, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                ("legacy-job-1", "queued", "init", "legacy", now, now),
            )
            con.commit()
            con.close()

            js._init_db()

            with js._conn() as migrated:
                job_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(jobs)").fetchall()
                }
                for column in ("case_name", "case_path", "error", "results", "upload_path"):
                    self.assertIn(column, job_columns)

                job_row = migrated.execute(
                    "SELECT case_name, case_path, error, results, upload_path FROM jobs WHERE job_id = ?",
                    ("legacy-job-1",),
                ).fetchone()
                self.assertEqual(job_row["case_name"], "")
                self.assertEqual(job_row["case_path"], "")
                self.assertEqual(job_row["error"], "")
                self.assertEqual(job_row["results"], "{}")
                self.assertEqual(job_row["upload_path"], "")

                migrations = [
                    row["name"]
                    for row in migrated.execute(
                        "SELECT name FROM migrations WHERE name LIKE 'job_store:%' ORDER BY name ASC"
                    ).fetchall()
                ]
                self.assertEqual(
                    migrations,
                    [
                        "job_store:001_initial_schema",
                        "job_store:002_add_missing_columns",
                    ],
                )

            job = js.get_job("legacy-job-1")
            self.assertIsNotNone(job)
            self.assertEqual(job["results"], {})
        finally:
            js._DB_PATH = original_db_path
            shutil.rmtree(tmp, ignore_errors=True)

    def test_review_store_migrates_legacy_schema_with_defaults(self):
        import triage_engine.review_store as rs
        tmp = tempfile.mkdtemp(prefix="review-migrate-test-")
        db_path = os.path.join(tmp, "reviews_legacy.db")
        original_db_path = rs._DB_PATH
        try:
            rs._DB_PATH = db_path
            con = sqlite3.connect(db_path)
            con.executescript(
                """
                CREATE TABLE finding_reviews (
                    case_name   TEXT NOT NULL,
                    finding_id  TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'Open',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    PRIMARY KEY (case_name, finding_id)
                );
                CREATE TABLE incident_reviews (
                    case_name   TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'Open',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    PRIMARY KEY (case_name, incident_id)
                );
                CREATE TABLE review_notes (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_name   TEXT NOT NULL,
                    item_type   TEXT NOT NULL,
                    item_id     TEXT NOT NULL,
                    content     TEXT NOT NULL
                );
                CREATE TABLE review_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_name   TEXT NOT NULL,
                    item_type   TEXT NOT NULL,
                    item_id     TEXT NOT NULL,
                    field       TEXT NOT NULL,
                    changed_at  TEXT NOT NULL
                );
                CREATE TABLE review_queue_index (
                    case_name   TEXT NOT NULL,
                    item_type   TEXT NOT NULL,
                    item_id     TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    PRIMARY KEY (case_name, item_type, item_id)
                );
                CREATE TABLE queue_materialization_state (
                    case_name   TEXT PRIMARY KEY,
                    synced_at   TEXT NOT NULL
                );
                """
            )
            now = datetime.now(timezone.utc).isoformat()
            con.execute(
                "INSERT INTO finding_reviews (case_name, finding_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                ("legacy-case", "legacy-fnd", "Open", now, now),
            )
            con.execute(
                "INSERT INTO incident_reviews (case_name, incident_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                ("legacy-case", "legacy-inc", "Open", now, now),
            )
            con.execute(
                "INSERT INTO review_notes (case_name, item_type, item_id, content) VALUES (?, ?, ?, ?)",
                ("legacy-case", "finding", "legacy-fnd", "legacy note"),
            )
            con.execute(
                "INSERT INTO review_history (case_name, item_type, item_id, field, changed_at) VALUES (?, ?, ?, ?, ?)",
                ("legacy-case", "finding", "legacy-fnd", "status", now),
            )
            con.execute(
                "INSERT INTO review_queue_index (case_name, item_type, item_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                ("legacy-case", "finding", "legacy-fnd", now, now),
            )
            con.execute(
                "INSERT INTO queue_materialization_state (case_name, synced_at) VALUES (?, ?)",
                ("legacy-case", now),
            )
            con.commit()
            con.close()

            rs._init_db()

            with rs._conn() as migrated:
                finding_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(finding_reviews)").fetchall()
                }
                for column in ("disposition", "owner", "priority", "recommended_tuning_action", "reviewed_at"):
                    self.assertIn(column, finding_columns)

                incident_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(incident_reviews)").fetchall()
                }
                for column in ("disposition", "owner", "priority", "recommended_tuning_action", "reviewed_at"):
                    self.assertIn(column, incident_columns)

                notes_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(review_notes)").fetchall()
                }
                for column in ("author", "created_at"):
                    self.assertIn(column, notes_columns)

                history_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(review_history)").fetchall()
                }
                for column in ("old_value", "new_value", "changed_by"):
                    self.assertIn(column, history_columns)

                queue_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(review_queue_index)").fetchall()
                }
                for column in ("item_title", "response_priority", "last_seen_at"):
                    self.assertIn(column, queue_columns)

                materialization_columns = {
                    row["name"] for row in migrated.execute("PRAGMA table_info(queue_materialization_state)").fetchall()
                }
                self.assertIn("findings_mtime", materialization_columns)

                finding_row = migrated.execute(
                    "SELECT disposition, owner, priority, recommended_tuning_action, reviewed_at FROM finding_reviews WHERE case_name = ? AND finding_id = ?",
                    ("legacy-case", "legacy-fnd"),
                ).fetchone()
                self.assertEqual(finding_row["disposition"], "")
                self.assertEqual(finding_row["owner"], "")
                self.assertEqual(finding_row["priority"], "")
                self.assertEqual(finding_row["recommended_tuning_action"], "")
                self.assertEqual(finding_row["reviewed_at"], "")

                note_row = migrated.execute(
                    "SELECT author, created_at FROM review_notes WHERE case_name = ? AND item_id = ?",
                    ("legacy-case", "legacy-fnd"),
                ).fetchone()
                self.assertEqual(note_row["author"], "")
                self.assertEqual(note_row["created_at"], "")

                history_row = migrated.execute(
                    "SELECT old_value, new_value, changed_by FROM review_history WHERE case_name = ? AND item_id = ?",
                    ("legacy-case", "legacy-fnd"),
                ).fetchone()
                self.assertEqual(history_row["old_value"], "")
                self.assertEqual(history_row["new_value"], "")
                self.assertEqual(history_row["changed_by"], "")

                queue_row = migrated.execute(
                    "SELECT item_title, response_priority, last_seen_at FROM review_queue_index WHERE case_name = ? AND item_id = ?",
                    ("legacy-case", "legacy-fnd"),
                ).fetchone()
                self.assertEqual(queue_row["item_title"], "")
                self.assertEqual(queue_row["response_priority"], "")
                self.assertEqual(queue_row["last_seen_at"], "")

                materialization_row = migrated.execute(
                    "SELECT findings_mtime FROM queue_materialization_state WHERE case_name = ?",
                    ("legacy-case",),
                ).fetchone()
                self.assertEqual(float(materialization_row["findings_mtime"]), 0.0)

                migrations = [
                    row["name"]
                    for row in migrated.execute(
                        "SELECT name FROM migrations WHERE name LIKE 'review_store:%' ORDER BY name ASC"
                    ).fetchall()
                ]
                self.assertEqual(
                    migrations,
                    [
                        "review_store:001_initial_schema",
                        "review_store:002_add_missing_columns",
                    ],
                )

            queue = rs.get_review_queue(case_name="legacy-case")
            self.assertGreaterEqual(len(queue), 1)
            self.assertEqual(queue[0]["item_id"], "legacy-fnd")
        finally:
            rs._DB_PATH = original_db_path
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Backup/restore script tests
# ---------------------------------------------------------------------------

class BackupRestoreScriptTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="backup-restore-script-test-")
        self._data_dir = os.path.join(self._tmp, "data")
        self._backups_dir = os.path.join(self._data_dir, "backups")
        os.makedirs(self._data_dir, exist_ok=True)
        self._seed_state_dbs()

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _seed_state_dbs(self):
        for filename, marker in (
            ("auth.db", "auth"),
            ("reviews.db", "reviews"),
            ("jobs.db", "jobs"),
        ):
            path = os.path.join(self._data_dir, filename)
            con = sqlite3.connect(path)
            try:
                con.execute("CREATE TABLE IF NOT EXISTS marker (value TEXT NOT NULL)")
                con.execute("DELETE FROM marker")
                con.execute("INSERT INTO marker (value) VALUES (?)", (marker,))
                con.commit()
            finally:
                con.close()

    def test_backup_and_restore_round_trip(self):
        from scripts.backup_restore import create_backup, list_backups, restore_backup

        backup = create_backup(data_dir=self._data_dir, backups_dir=self._backups_dir)
        self.assertTrue(backup["backup_id"].startswith("backup-"))
        self.assertEqual(len(backup["files"]), 3)
        self.assertTrue(os.path.isfile(os.path.join(backup["backup_path"], "manifest.json")))

        listed = list_backups(data_dir=self._data_dir, backups_dir=self._backups_dir)
        self.assertGreaterEqual(len(listed), 1)
        self.assertEqual(listed[0]["backup_id"], backup["backup_id"])

        auth_db = os.path.join(self._data_dir, "auth.db")
        con = sqlite3.connect(auth_db)
        try:
            con.execute("UPDATE marker SET value = 'mutated'")
            con.commit()
        finally:
            con.close()

        restored = restore_backup(backup["backup_path"], data_dir=self._data_dir)
        self.assertEqual(restored["backup_id"], backup["backup_id"])
        self.assertEqual(len(restored["files"]), 3)

        con = sqlite3.connect(auth_db)
        try:
            row = con.execute("SELECT value FROM marker").fetchone()
        finally:
            con.close()
        self.assertEqual(row[0], "auth")

    def test_restore_rejects_tampered_backup(self):
        from scripts.backup_restore import create_backup, restore_backup

        backup = create_backup(data_dir=self._data_dir, backups_dir=self._backups_dir)
        tampered_jobs = os.path.join(backup["backup_path"], "jobs.db")
        with open(tampered_jobs, "ab") as fh:
            fh.write(b"tampered")

        with self.assertRaises(ValueError):
            restore_backup(backup["backup_path"], data_dir=self._data_dir)


# ---------------------------------------------------------------------------
# Service contract tests
# ---------------------------------------------------------------------------

class ServiceContractTests(unittest.TestCase):
    """Test the shared investigation service contract types."""

    def test_investigation_request_defaults(self):
        from triage_engine.service import InvestigationRequest
        req = InvestigationRequest(input_source="test.evtx")
        self.assertEqual(req.input_mode, "evtx_path")
        self.assertIsNone(req.case_name)
        self.assertEqual(req.request_id, "")
        self.assertEqual(req.requested_by, "")
        self.assertFalse(req.overwrite)
        self.assertFalse(req.resume)
        self.assertFalse(req.enable_sigma)
        self.assertFalse(req.no_fp_filter)
        self.assertEqual(req.tuning_paths, [])
        self.assertEqual(req.sigma_rule_paths, [])

    def test_investigation_result_defaults(self):
        from triage_engine.service import InvestigationResult
        result = InvestigationResult(
            case_name="test",
            case_path="/tmp/test",
            input_source="test.evtx",
        )
        self.assertEqual(result.signal_count, 0)
        self.assertEqual(result.finding_count, 0)
        self.assertEqual(result.incident_count, 0)
        self.assertEqual(result.response_priority, "P4")
        self.assertEqual(result.artifacts, {})

    def test_null_reporter_satisfies_protocol(self):
        from triage_engine.service import NullReporter, ProgressReporter
        reporter = NullReporter()
        self.assertIsInstance(reporter, ProgressReporter)
        # Should not raise
        reporter.on_stage("test", "message")
        reporter.on_metadata("key", "value")
        reporter.on_artifact("/path")
        reporter.on_diagnostic("diag")
        reporter.on_complete("done")
        reporter.on_failed("stage", "error")
        reporter.on_parse_progress({})

    def test_progress_reporter_protocol(self):
        from triage_engine.service import ProgressReporter

        class CustomReporter:
            def on_stage(self, stage, message): pass
            def on_metadata(self, key, value): pass
            def on_artifact(self, path): pass
            def on_diagnostic(self, message): pass
            def on_complete(self, message): pass
            def on_failed(self, stage, error, traceback_text=None): pass
            def on_parse_progress(self, update): pass

        reporter = CustomReporter()
        self.assertIsInstance(reporter, ProgressReporter)


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------

class InputValidationTests(unittest.TestCase):
    """Test security validation helpers."""

    def test_validate_case_name_accepts_valid(self):
        from server import _validate_case_name
        self.assertEqual(_validate_case_name("valid-case"), "valid-case")
        self.assertEqual(_validate_case_name("case.2026.03"), "case.2026.03")
        self.assertEqual(_validate_case_name("CaseName_01"), "CaseName_01")

    def test_validate_case_name_rejects_traversal(self):
        from server import _validate_case_name
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            _validate_case_name("../etc/passwd")

    def test_validate_case_name_rejects_spaces(self):
        from server import _validate_case_name
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            _validate_case_name("case with spaces")

    def test_validate_case_name_rejects_long_names(self):
        from server import _validate_case_name
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            _validate_case_name("a" * 200)

    def test_validate_case_name_returns_none_for_empty(self):
        from server import _validate_case_name
        self.assertIsNone(_validate_case_name(None))
        self.assertIsNone(_validate_case_name(""))
        self.assertIsNone(_validate_case_name("   "))

    def test_validate_evtx_path_rejects_missing(self):
        from server import _validate_evtx_path
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            _validate_evtx_path(r"C:\nonexistent\path.evtx")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_evtx_path_rejects_non_evtx(self):
        from server import _validate_evtx_path
        from fastapi import HTTPException
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        tmp.close()
        try:
            with self.assertRaises(HTTPException) as ctx:
                _validate_evtx_path(tmp.name)
            self.assertEqual(ctx.exception.status_code, 400)
        finally:
            os.unlink(tmp.name)

    def test_validate_evtx_path_accepts_evtx_file(self):
        from server import _validate_evtx_path
        tmp = tempfile.NamedTemporaryFile(suffix=".evtx", delete=False)
        tmp.write(b"\x00" * 64)
        tmp.close()
        try:
            result = _validate_evtx_path(tmp.name)
            self.assertEqual(result, os.path.abspath(tmp.name))
        finally:
            os.unlink(tmp.name)

    def test_validate_evtx_path_accepts_directory(self):
        from server import _validate_evtx_path
        tmpdir = tempfile.mkdtemp()
        try:
            result = _validate_evtx_path(tmpdir)
            self.assertEqual(result, os.path.abspath(tmpdir))
        finally:
            os.rmdir(tmpdir)


# ---------------------------------------------------------------------------
# Review store unit tests
# ---------------------------------------------------------------------------

class ReviewStoreTests(unittest.TestCase):
    """Test the analyst review SQLite persistence layer."""

    def setUp(self):
        # Use a fresh DB for each test by patching path
        import triage_engine.review_store as rs
        self._orig_path = rs._DB_PATH
        self._tmp = tempfile.mkdtemp(prefix="review-test-")
        rs._DB_PATH = os.path.join(self._tmp, "test_reviews.db")
        rs._init_db()

    def tearDown(self):
        import triage_engine.review_store as rs
        rs._DB_PATH = self._orig_path
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_finding_review_create_and_get(self):
        from triage_engine.review_store import upsert_finding_review, get_finding_review
        rv = upsert_finding_review("case-a", "fnd-001", status="Open")
        self.assertEqual(rv["case_name"], "case-a")
        self.assertEqual(rv["finding_id"], "fnd-001")
        self.assertEqual(rv["status"], "Open")
        fetched = get_finding_review("case-a", "fnd-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["finding_id"], "fnd-001")

    def test_finding_review_update_records_history(self):
        from triage_engine.review_store import upsert_finding_review, get_history
        upsert_finding_review("case-a", "fnd-002", status="Open")
        upsert_finding_review("case-a", "fnd-002", status="In Review", changed_by="analyst1")
        history = get_history("case-a", "finding", "fnd-002")
        self.assertGreaterEqual(len(history), 1)
        self.assertEqual(history[0]["field"], "status")
        self.assertEqual(history[0]["old_value"], "Open")
        self.assertEqual(history[0]["new_value"], "In Review")
        self.assertEqual(history[0]["changed_by"], "analyst1")

    def test_incident_review_create_and_get(self):
        from triage_engine.review_store import upsert_incident_review, get_incident_review
        rv = upsert_incident_review("case-b", "inc-001", status="Open", owner="analyst2")
        self.assertEqual(rv["incident_id"], "inc-001")
        self.assertEqual(rv["owner"], "analyst2")
        fetched = get_incident_review("case-b", "inc-001")
        self.assertIsNotNone(fetched)

    def test_incident_review_update(self):
        from triage_engine.review_store import upsert_incident_review
        upsert_incident_review("case-b", "inc-002", status="Open")
        rv = upsert_incident_review("case-b", "inc-002", status="Escalated", disposition="True Positive")
        self.assertEqual(rv["status"], "Escalated")
        self.assertEqual(rv["disposition"], "True Positive")

    def test_add_and_get_notes(self):
        from triage_engine.review_store import add_note, get_notes
        note = add_note("case-c", "finding", "fnd-010", "This looks suspicious", author="analyst3")
        self.assertEqual(note["content"], "This looks suspicious")
        self.assertEqual(note["author"], "analyst3")
        notes = get_notes("case-c", "finding", "fnd-010")
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["content"], "This looks suspicious")

    def test_review_queue_returns_items(self):
        from triage_engine.review_store import upsert_finding_review, upsert_incident_review, get_review_queue
        upsert_finding_review("case-q", "fnd-q1", status="Open")
        upsert_incident_review("case-q", "inc-q1", status="In Review")
        queue = get_review_queue()
        ids = [q["item_id"] for q in queue]
        self.assertIn("fnd-q1", ids)
        self.assertIn("inc-q1", ids)

    def test_review_queue_filters_by_status(self):
        from triage_engine.review_store import upsert_finding_review, get_review_queue
        upsert_finding_review("case-qf", "fnd-qf1", status="Open")
        upsert_finding_review("case-qf", "fnd-qf2", status="Closed")
        queue = get_review_queue(status="Open")
        ids = [q["item_id"] for q in queue]
        self.assertIn("fnd-qf1", ids)
        self.assertNotIn("fnd-qf2", ids)

    def test_review_queue_filters_by_type(self):
        from triage_engine.review_store import upsert_finding_review, upsert_incident_review, get_review_queue
        upsert_finding_review("case-qt", "fnd-qt1", status="Open")
        upsert_incident_review("case-qt", "inc-qt1", status="Open")
        queue = get_review_queue(item_type="incident")
        types = [q["item_type"] for q in queue]
        self.assertTrue(all(t == "incident" for t in types))

    def test_carry_forward_creates_missing_reviews(self):
        from triage_engine.review_store import upsert_finding_review, carry_forward_reviews, get_finding_review
        upsert_finding_review("case-cf", "fnd-existing", status="In Review", owner="analyst1")
        result = carry_forward_reviews("case-cf", ["fnd-existing", "fnd-new"], ["inc-new"])
        self.assertEqual(result["findings_carried"], 1)
        self.assertEqual(result["findings_created"], 1)
        self.assertEqual(result["incidents_created"], 1)
        # Existing review should keep its state
        existing = get_finding_review("case-cf", "fnd-existing")
        self.assertEqual(existing["status"], "In Review")
        self.assertEqual(existing["owner"], "analyst1")
        # New review should be Open
        new_rv = get_finding_review("case-cf", "fnd-new")
        self.assertEqual(new_rv["status"], "Open")

    def test_carry_forward_does_not_delete_stale_reviews(self):
        from triage_engine.review_store import upsert_finding_review, carry_forward_reviews, get_finding_review
        upsert_finding_review("case-cf2", "fnd-old", status="Closed", disposition="False Positive")
        carry_forward_reviews("case-cf2", [], [])
        # Old review should still exist
        old = get_finding_review("case-cf2", "fnd-old")
        self.assertIsNotNone(old)
        self.assertEqual(old["status"], "Closed")

    def test_get_nonexistent_review_returns_none(self):
        from triage_engine.review_store import get_finding_review, get_incident_review
        self.assertIsNone(get_finding_review("nonexistent", "nonexistent"))
        self.assertIsNone(get_incident_review("nonexistent", "nonexistent"))

    def test_bulk_overlay_methods(self):
        from triage_engine.review_store import upsert_finding_review, upsert_incident_review, get_all_finding_reviews, get_all_incident_reviews
        upsert_finding_review("case-bulk", "fnd-b1", status="Open")
        upsert_finding_review("case-bulk", "fnd-b2", status="Closed")
        upsert_incident_review("case-bulk", "inc-b1", status="Escalated")
        frevs = get_all_finding_reviews("case-bulk")
        self.assertEqual(len(frevs), 2)
        self.assertIn("fnd-b1", frevs)
        irevs = get_all_incident_reviews("case-bulk")
        self.assertEqual(len(irevs), 1)
        self.assertIn("inc-b1", irevs)

    def test_history_global_retrieval(self):
        from triage_engine.review_store import upsert_finding_review, get_all_history
        upsert_finding_review("case-hist", "fnd-h1", status="Open")
        upsert_finding_review("case-hist", "fnd-h1", status="Closed", changed_by="analyst")
        history = get_all_history()
        self.assertGreaterEqual(len(history), 1)

    def test_note_addition_records_history(self):
        from triage_engine.review_store import add_note, get_history
        add_note("case-nh", "finding", "fnd-nh1", "Important observation", author="analyst5")
        history = get_history("case-nh", "finding", "fnd-nh1")
        self.assertGreaterEqual(len(history), 1)
        note_event = next((h for h in history if h["field"] == "note_added"), None)
        self.assertIsNotNone(note_event, "note_added event missing from history")
        self.assertEqual(note_event["new_value"], "Important observation")
        self.assertEqual(note_event["changed_by"], "analyst5")

    def test_note_addition_records_history_for_incident(self):
        from triage_engine.review_store import add_note, get_history
        add_note("case-nh2", "incident", "inc-nh1", "Escalating to IR team", author="analyst6")
        history = get_history("case-nh2", "incident", "inc-nh1")
        note_event = next((h for h in history if h["field"] == "note_added"), None)
        self.assertIsNotNone(note_event)
        self.assertEqual(note_event["item_type"], "incident")
        self.assertEqual(note_event["changed_by"], "analyst6")

    def test_materialize_reviews_for_completed_cases(self):
        from triage_engine.review_store import materialize_reviews_for_completed_cases, get_finding_review, get_incident_review
        # Create a synthetic case directory with findings.json
        cases_dir = os.path.join(self._tmp, "mat-cases")
        case_dir = os.path.join(cases_dir, "mat-test-case")
        os.makedirs(case_dir, exist_ok=True)
        findings = {
            "findings": [{"id": "fnd-mat-1"}, {"id": "fnd-mat-2"}],
            "incidents": [{"id": "inc-mat-1"}],
        }
        with open(os.path.join(case_dir, "findings.json"), "w") as f:
            json.dump(findings, f)
        # Materialize
        created = materialize_reviews_for_completed_cases(cases_dir)
        self.assertEqual(created, 3)
        # Verify reviews exist
        self.assertIsNotNone(get_finding_review("mat-test-case", "fnd-mat-1"))
        self.assertIsNotNone(get_finding_review("mat-test-case", "fnd-mat-2"))
        self.assertIsNotNone(get_incident_review("mat-test-case", "inc-mat-1"))
        # Second call should create 0 (idempotent)
        created2 = materialize_reviews_for_completed_cases(cases_dir)
        self.assertEqual(created2, 0)
        # Cleanup
        shutil.rmtree(cases_dir, ignore_errors=True)

    def test_materialize_reviews_nonexistent_dir(self):
        from triage_engine.review_store import materialize_reviews_for_completed_cases
        self.assertEqual(materialize_reviews_for_completed_cases("/nonexistent/path"), 0)


# ---------------------------------------------------------------------------
# Review API endpoint tests
# ---------------------------------------------------------------------------

class ReviewAPITests(unittest.TestCase):
    """Test review API endpoints via TestClient."""

    @classmethod
    def setUpClass(cls):
        cls._temp_root = tempfile.mkdtemp(prefix="triage-review-api-test-")
        cls._cases_dir = os.path.join(cls._temp_root, "cases")
        cls._upload_dir = os.path.join(cls._temp_root, "uploads")
        cls._static_dir = os.path.join(cls._temp_root, "static")
        os.makedirs(cls._cases_dir, exist_ok=True)
        os.makedirs(cls._upload_dir, exist_ok=True)
        os.makedirs(cls._static_dir, exist_ok=True)

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        real_dashboard = os.path.join(project_root, "static", "dashboard.html")
        if os.path.isfile(real_dashboard):
            shutil.copy2(real_dashboard, os.path.join(cls._static_dir, "dashboard.html"))
        else:
            with open(os.path.join(cls._static_dir, "dashboard.html"), "w") as f:
                f.write("<html><body>Test Dashboard</body></html>")

        _create_case(cls._cases_dir, "review-test-case")

        import server
        cls._orig_cases_root = server.CASES_ROOT
        cls._orig_upload_root = server.UPLOAD_ROOT
        cls._orig_static_dir = server.STATIC_DIR
        server.CASES_ROOT = cls._cases_dir
        server.UPLOAD_ROOT = cls._upload_dir
        server.STATIC_DIR = cls._static_dir

        # Use a separate review DB for API tests
        import triage_engine.review_store as rs
        cls._orig_review_db = rs._DB_PATH
        rs._DB_PATH = os.path.join(cls._temp_root, "test_api_reviews.db")
        rs._init_db()

        import triage_engine.auth_store as auth
        cls._orig_auth_db = auth._DB_PATH
        auth._DB_PATH = os.path.join(cls._temp_root, "test_api_auth.db")
        auth._init_db()

        cls.client = TestClient(server.app, raise_server_exceptions=False)
        bootstrap = cls.client.post(
            "/api/auth/bootstrap",
            json={"username": "review-admin", "password": "Password123!"},
        )
        if bootstrap.status_code != 200:
            raise RuntimeError(f"Failed to bootstrap review API auth: {bootstrap.status_code} {bootstrap.text}")
        me = cls.client.get("/api/auth/me")
        if me.status_code == 200:
            token = me.json().get("csrf_token", "")
            if token:
                cls.client.headers["X-CSRF-Token"] = token

    @classmethod
    def tearDownClass(cls):
        import server
        server.CASES_ROOT = cls._orig_cases_root
        server.UPLOAD_ROOT = cls._orig_upload_root
        server.STATIC_DIR = cls._orig_static_dir
        import triage_engine.review_store as rs
        rs._DB_PATH = cls._orig_review_db
        import triage_engine.auth_store as auth
        auth._DB_PATH = cls._orig_auth_db
        shutil.rmtree(cls._temp_root, ignore_errors=True)

    def setUp(self):
        import server

        server._reset_security_state_for_tests()
        me = self.client.get("/api/auth/me")
        if me.status_code == 200 and me.json().get("authenticated"):
            token = me.json().get("csrf_token", "")
            if token:
                self.client.headers["X-CSRF-Token"] = token

    def test_get_finding_review_default(self):
        resp = self.client.get("/api/cases/review-test-case/findings/fnd-no-review-yet/review")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "Open")
        self.assertIn("notes", data)
        self.assertIn("history", data)

    def test_patch_finding_review(self):
        resp = self.client.patch(
            "/api/cases/review-test-case/findings/fnd-0/review",
            json={"status": "In Review", "owner": "analyst1"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "In Review")
        self.assertEqual(data["owner"], "analyst1")

    def test_patch_finding_review_invalid_status(self):
        resp = self.client.patch(
            "/api/cases/review-test-case/findings/fnd-0/review",
            json={"status": "InvalidStatus"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_patch_finding_review_invalid_disposition(self):
        resp = self.client.patch(
            "/api/cases/review-test-case/findings/fnd-0/review",
            json={"disposition": "Not A Real Disposition"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_get_incident_review_default(self):
        resp = self.client.get("/api/cases/review-test-case/incidents/inc-0/review")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "Open")

    def test_patch_incident_review(self):
        resp = self.client.patch(
            "/api/cases/review-test-case/incidents/inc-0/review",
            json={"status": "Escalated", "disposition": "True Positive"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "Escalated")
        self.assertEqual(data["disposition"], "True Positive")

    def test_add_finding_note(self):
        resp = self.client.post(
            "/api/cases/review-test-case/findings/fnd-0/notes",
            json={"content": "Needs further investigation", "author": "analyst1"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["content"], "Needs further investigation")
        self.assertEqual(data["author"], "analyst1")

    def test_add_empty_note_rejected(self):
        resp = self.client.post(
            "/api/cases/review-test-case/findings/fnd-0/notes",
            json={"content": "   "},
        )
        self.assertEqual(resp.status_code, 400)

    def test_add_incident_note(self):
        resp = self.client.post(
            "/api/cases/review-test-case/incidents/inc-0/notes",
            json={"content": "Escalated to senior analyst"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["content"], "Escalated to senior analyst")

    def test_review_queue_returns_items(self):
        # Create some reviews first
        self.client.patch(
            "/api/cases/review-test-case/findings/fnd-1/review",
            json={"status": "Open"},
        )
        resp = self.client.get("/api/review/queue")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_review_queue_filters(self):
        self.client.patch(
            "/api/cases/review-test-case/findings/fnd-filter-test/review",
            json={"status": "Closed", "owner": "filter-test-owner"},
        )
        resp = self.client.get("/api/review/queue?status=Closed&owner=filter-test-owner")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for item in data:
            self.assertEqual(item["status"], "Closed")

    def test_review_queue_export_csv(self):
        self.client.patch(
            "/api/cases/review-test-case/findings/fnd-export-queue/review",
            json={"status": "In Review", "owner": "queue-export-owner"},
        )
        resp = self.client.get("/api/review/queue/export?format=csv&owner=queue-export-owner")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers.get("content-type", ""))
        self.assertIn("attachment;", resp.headers.get("content-disposition", "").lower())
        self.assertIn("case_name,item_type,item_id", resp.text)
        self.assertIn("queue-export-owner", resp.text)

    def test_review_queue_export_rejects_non_csv_format(self):
        resp = self.client.get("/api/review/queue/export?format=json")
        self.assertEqual(resp.status_code, 400)

    def test_review_history_endpoint(self):
        self.client.patch(
            "/api/cases/review-test-case/findings/fnd-hist/review",
            json={"status": "Open"},
        )
        self.client.patch(
            "/api/cases/review-test-case/findings/fnd-hist/review",
            json={"status": "Closed"},
        )
        resp = self.client.get("/api/review/history?case_name=review-test-case")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_review_history_export_csv_for_item(self):
        self.client.patch(
            "/api/cases/review-test-case/findings/fnd-export/review",
            json={"status": "In Review", "owner": "review-admin"},
        )
        self.client.post(
            "/api/cases/review-test-case/findings/fnd-export/notes",
            json={"content": "Export me", "author": "review-admin"},
        )
        resp = self.client.get(
            "/api/review/history/export?format=csv&case_name=review-test-case&item_type=finding&item_id=fnd-export"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers["content-type"])
        self.assertIn("review-test-case", resp.text)
        self.assertIn("note_added", resp.text)

    def test_review_enums_endpoint(self):
        resp = self.client.get("/api/review/enums")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("statuses", data)
        self.assertIn("dispositions", data)
        self.assertIn("Open", data["statuses"])
        self.assertIn("True Positive", data["dispositions"])

    def test_case_detail_overlays_review_state(self):
        # Set review on a finding
        self.client.patch(
            "/api/cases/review-test-case/findings/fnd-0/review",
            json={"status": "Escalated", "owner": "overlay-test"},
        )
        # Fetch case detail — findings should have review overlay
        resp = self.client.get("/api/cases/review-test-case")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        findings = data.get("findings", [])
        fnd0 = next((f for f in findings if f.get("id") == "fnd-0"), None)
        self.assertIsNotNone(fnd0)
        self.assertIn("review", fnd0)
        self.assertEqual(fnd0["review"]["status"], "Escalated")

    def test_carry_forward_endpoint(self):
        # Set a review before carry-forward
        self.client.patch(
            "/api/cases/review-test-case/findings/fnd-0/review",
            json={"status": "In Review"},
        )
        resp = self.client.post("/api/cases/review-test-case/reviews/carry-forward")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("findings_carried", data)
        self.assertIn("findings_created", data)

    def test_carry_forward_not_found(self):
        resp = self.client.post("/api/cases/nonexistent-case-xyz/reviews/carry-forward")
        self.assertEqual(resp.status_code, 404)

    # -- Fix 1: note_added history via API --
    def test_note_creates_history_event(self):
        self.client.post(
            "/api/cases/review-test-case/findings/fnd-0/notes",
            json={"content": "History check note", "author": "hist-author"},
        )
        resp = self.client.get("/api/cases/review-test-case/findings/fnd-0/review")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        history = data.get("history", [])
        note_events = [h for h in history if h.get("field") == "note_added"]
        self.assertGreaterEqual(len(note_events), 1)
        latest = note_events[0]
        self.assertEqual(latest["new_value"], "History check note")
        self.assertEqual(latest["changed_by"], "hist-author")

    # -- Fix 2: case existence validation --
    def test_get_finding_review_nonexistent_case_404(self):
        resp = self.client.get("/api/cases/totally-fake-case/findings/fnd-0/review")
        self.assertEqual(resp.status_code, 404)

    def test_patch_finding_review_nonexistent_case_404(self):
        resp = self.client.patch(
            "/api/cases/totally-fake-case/findings/fnd-0/review",
            json={"status": "Open"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_get_incident_review_nonexistent_case_404(self):
        resp = self.client.get("/api/cases/totally-fake-case/incidents/inc-0/review")
        self.assertEqual(resp.status_code, 404)

    def test_patch_incident_review_nonexistent_case_404(self):
        resp = self.client.patch(
            "/api/cases/totally-fake-case/incidents/inc-0/review",
            json={"status": "Open"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_add_finding_note_nonexistent_case_404(self):
        resp = self.client.post(
            "/api/cases/totally-fake-case/findings/fnd-0/notes",
            json={"content": "orphan note"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_add_incident_note_nonexistent_case_404(self):
        resp = self.client.post(
            "/api/cases/totally-fake-case/incidents/inc-0/notes",
            json={"content": "orphan note"},
        )
        self.assertEqual(resp.status_code, 404)

    # -- Fix 3: queue materializes from completed cases --
    def test_queue_shows_items_without_manual_carry_forward(self):
        """A new completed case with findings should appear in the queue
        without anyone explicitly calling carry-forward first."""
        # Create a fresh case that has never been touched by review endpoints
        _create_case(self._cases_dir, "queue-auto-mat-case")
        resp = self.client.get("/api/review/queue")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        # The synthetic case has findings fnd-0 and fnd-1, and incident inc-0
        case_items = [q for q in data if q.get("case_name") == "queue-auto-mat-case"]
        self.assertGreaterEqual(len(case_items), 1, "Queue should contain materialized items from the new case")
        item_ids = [q["item_id"] for q in case_items]
        self.assertIn("fnd-0", item_ids)
        self.assertIn("inc-0", item_ids)
        # Cleanup
        shutil.rmtree(os.path.join(self._cases_dir, "queue-auto-mat-case"), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
