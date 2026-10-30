"""Focused regression tests for backend path and state invariants."""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient

from triage_engine.case_utils import resolve_case_path


class CaseResolutionTests(unittest.TestCase):
    def test_case_resolution_rejects_paths_outside_managed_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "cases"
            inside = root / "case-001"
            outside = Path(temp_dir) / "outside"
            inside.mkdir(parents=True)
            outside.mkdir()

            self.assertEqual(resolve_case_path(str(root), "case-001"), str(inside.resolve()))
            for reference in (str(outside), "..", os.path.join("..", "outside")):
                with self.assertRaises(FileNotFoundError):
                    resolve_case_path(str(root), reference)

    def test_case_resolution_never_returns_the_managed_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "cases"
            (root / "case-001").mkdir(parents=True)
            for reference in (".", str(root), os.path.join("case-001", "..")):
                with self.assertRaises(FileNotFoundError):
                    resolve_case_path(str(root), reference)


class ClientAddressTests(unittest.TestCase):
    def _request(self, peer: str, forwarded: str = ""):
        from starlette.requests import Request

        headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
        return Request({"type": "http", "headers": headers, "client": (peer, 1234)})

    def test_forwarded_header_ignored_without_trusted_proxy(self):
        import server

        original = set(server.TRUSTED_PROXIES)
        server.TRUSTED_PROXIES.clear()
        try:
            self.assertEqual(server._client_ip(self._request("203.0.113.9", "127.0.0.1")), "203.0.113.9")
        finally:
            server.TRUSTED_PROXIES.update(original)

    def test_forwarded_header_uses_first_untrusted_hop_from_trusted_proxy(self):
        import server

        original = set(server.TRUSTED_PROXIES)
        server.TRUSTED_PROXIES.clear()
        server.TRUSTED_PROXIES.update({"10.0.0.2", "10.0.0.3"})
        try:
            request = self._request("10.0.0.2", "1.1.1.1, 198.51.100.7, 10.0.0.3")
            self.assertEqual(server._client_ip(request), "198.51.100.7")
        finally:
            server.TRUSTED_PROXIES.clear()
            server.TRUSTED_PROXIES.update(original)

    def test_rate_limit_table_prunes_idle_identities(self):
        import server

        server._reset_security_state_for_tests()
        original_max = server._RATE_LIMIT_MAX_KEYS
        server._RATE_LIMIT_MAX_KEYS = 5
        try:
            for index in range(20):
                server._consume_rate_limit(f"k{index}", limit=5, now=float(index * 1000))
            self.assertLessEqual(len(server._RATE_LIMIT_BUCKETS), 7)
        finally:
            server._RATE_LIMIT_MAX_KEYS = original_max
            server._reset_security_state_for_tests()


class IntegrationEndpointValidationTests(unittest.TestCase):
    def test_ai_endpoint_is_allowlisted_and_http_is_loopback_only(self):
        import server

        self.assertEqual(server._validate_ai_endpoint("https://api.openai.com/v1/"), "https://api.openai.com/v1")
        self.assertEqual(server._validate_ai_endpoint("http://127.0.0.1:1234/v1"), "http://127.0.0.1:1234/v1")
        for endpoint in (
            "http://169.254.169.254/latest/meta-data",
            "https://attacker.example/v1",
            "https://user:secret@api.openai.com/v1",
        ):
            with self.assertRaises(HTTPException):
                server._validate_ai_endpoint(endpoint)


class BackendApiStateTests(unittest.TestCase):
    def setUp(self):
        import server
        import triage_engine.auth_store as auth_store
        import triage_engine.review_store as review_store

        self.server = server
        self.auth_store = auth_store
        self.review_store = review_store
        self.temp_root = tempfile.mkdtemp(prefix="triage-backend-hardening-")
        self.cases_root = os.path.join(self.temp_root, "cases")
        self.data_root = os.path.join(self.temp_root, "data")
        self.upload_root = os.path.join(self.temp_root, "uploads")
        os.makedirs(self.cases_root)
        os.makedirs(self.data_root)
        os.makedirs(self.upload_root)

        self.originals = {
            "cases_root": server.CASES_ROOT,
            "data_root": server.DATA_ROOT,
            "upload_root": server.UPLOAD_ROOT,
            "auth_db": auth_store._DB_PATH,
            "review_db": review_store._DB_PATH,
        }
        server.CASES_ROOT = self.cases_root
        server.DATA_ROOT = self.data_root
        server.UPLOAD_ROOT = self.upload_root
        auth_store._DB_PATH = os.path.join(self.data_root, "auth.db")
        review_store._DB_PATH = os.path.join(self.data_root, "reviews.db")
        auth_store._init_db()
        review_store._init_db()
        server._reset_security_state_for_tests()
        self.client = TestClient(server.app, raise_server_exceptions=False)

        response = self.client.post(
            "/api/auth/bootstrap",
            json={"username": "backend-admin", "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.client.headers["X-CSRF-Token"] = response.json()["csrf_token"]

    def tearDown(self):
        self.client.close()
        self.server.CASES_ROOT = self.originals["cases_root"]
        self.server.DATA_ROOT = self.originals["data_root"]
        self.server.UPLOAD_ROOT = self.originals["upload_root"]
        self.auth_store._DB_PATH = self.originals["auth_db"]
        self.review_store._DB_PATH = self.originals["review_db"]
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def test_case_prefix_uses_resolved_name_for_review_writes_and_deletion(self):
        older = Path(self.cases_root) / "incident-20260826-1"
        newer = Path(self.cases_root) / "incident-20260826-2"
        older.mkdir()
        newer.mkdir()
        now = time.time()
        os.utime(older, (now - 5, now - 5))
        os.utime(newer, (now, now))

        updated = self.client.patch(
            "/api/cases/incident/findings/fnd-1/review",
            json={"status": "In Review"},
        )

        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["case_name"], newer.name)
        self.assertIsNotNone(self.review_store.get_finding_review(newer.name, "fnd-1"))
        self.assertIsNone(self.review_store.get_finding_review("incident", "fnd-1"))

        deleted = self.client.delete("/api/cases/incident")
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertEqual(deleted.json()["deleted"], newer.name)
        self.assertFalse(newer.exists())
        self.assertIsNone(self.review_store.get_finding_review(newer.name, "fnd-1"))

    def test_deleting_dot_case_reference_cannot_remove_all_cases(self):
        keep = Path(self.cases_root) / "keep-me"
        keep.mkdir()
        for reference in ("%2E", "."):
            response = self.client.delete(f"/api/cases/{reference}")
            self.assertIn(response.status_code, {404, 405}, response.text)
        self.assertTrue(keep.exists())

    def test_case_list_exposes_evidence_scope_summary(self):
        import json as _json

        case_path = Path(self.cases_root) / "scope-case"
        case_path.mkdir()
        scope = {"host_count": 3, "span_days": 12.5, "needs_scope_review": True, "split_verdict": True,
                 "host_verdict_counts": {"Escalate": 1, "No promoted incident": 2}}
        (case_path / "run_status.json").write_text(
            _json.dumps({"status": "completed", "metadata": {"evidence_scope": scope, "case_metrics": {"signal_count": 1}}}),
            encoding="utf-8",
        )
        response = self.client.get("/api/cases")
        self.assertEqual(response.status_code, 200, response.text)
        row = next(item for item in response.json() if item["name"] == "scope-case")
        self.assertEqual(row["scope"], scope)

    def test_served_report_is_sandboxed(self):
        case_path = Path(self.cases_root) / "report-case"
        case_path.mkdir()
        (case_path / "report.html").write_text("<html><body>report</body></html>", encoding="utf-8")
        response = self.client.get("/api/cases/report-case/report")
        self.assertEqual(response.status_code, 200, response.text)
        csp = response.headers.get("content-security-policy", "")
        self.assertIn("sandbox allow-scripts", csp)
        self.assertNotIn("allow-same-origin", csp)

    def test_review_attribution_uses_authenticated_identity(self):
        case_path = Path(self.cases_root) / "attribution-case"
        case_path.mkdir()

        initial = self.client.patch(
            "/api/cases/attribution-case/findings/fnd-1/review",
            json={"status": "Open"},
        )
        self.assertEqual(initial.status_code, 200, initial.text)
        review = self.client.patch(
            "/api/cases/attribution-case/findings/fnd-1/review",
            json={"status": "In Review", "changed_by": "spoofed-user"},
        )
        self.assertEqual(review.status_code, 200, review.text)
        history = self.review_store.get_history("attribution-case", "finding", "fnd-1")
        self.assertTrue(history)
        self.assertTrue(all(row["changed_by"] == "backend-admin" for row in history))

        note = self.client.post(
            "/api/cases/attribution-case/findings/fnd-1/notes",
            json={"content": "audit note", "author": "spoofed-user"},
        )
        self.assertEqual(note.status_code, 200, note.text)
        self.assertEqual(note.json()["author"], "backend-admin")


class BootstrapTransactionTests(unittest.TestCase):
    def test_bootstrap_admin_only_creates_one_user(self):
        import triage_engine.auth_store as auth_store

        with tempfile.TemporaryDirectory() as temp_dir:
            original_db_path = auth_store._DB_PATH
            auth_store._DB_PATH = os.path.join(temp_dir, "auth.db")
            try:
                auth_store._init_db()
                created = auth_store.bootstrap_admin("first-admin", "Password123!")

                self.assertEqual(created["role"], "admin")
                with self.assertRaises(ValueError):
                    auth_store.bootstrap_admin("second-admin", "Password123!")
                self.assertEqual([user["username"] for user in auth_store.list_users()], ["first-admin"])
            finally:
                auth_store._DB_PATH = original_db_path


class DetectorIsolationTests(unittest.TestCase):
    def test_builtin_detector_uses_cancellable_process_executor(self):
        from detectors import behavioral
        from triage_engine.service import _run_detector_with_timeout

        result = _run_detector_with_timeout("behavioral", behavioral.detect, [], 10)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["executor"], "process")
        self.assertFalse(result.get("isolation_fallback", False))

    def test_detector_list_reuses_one_spawn_pool_for_nonempty_input(self):
        from datetime import datetime, timezone
        from models.event_model import NormalizedEvent
        from triage_engine.service import _run_detectors

        partial_failures = []
        alerts, timings = _run_detectors(
            [NormalizedEvent(event_id=1, timestamp=datetime.now(timezone.utc), computer="host", channel="Sysmon")],
            timeout_seconds=10,
            partial_failures=partial_failures,
        )

        self.assertIsInstance(alerts, list)
        self.assertEqual(set(timings), {
            "credential_access_ms",
            "persistence_ms",
            "lateral_movement_ms",
            "defense_evasion_ms",
            "execution_impact_ms",
            "powershell_script_ms",
            "behavioral_ms",
            "telemetry_context_ms",
        })
        self.assertEqual(partial_failures, [])

if __name__ == "__main__":
    unittest.main()


class BootstrapTokenTests(unittest.TestCase):
    def setUp(self):
        import server
        import triage_engine.auth_store as auth_store

        self.server = server
        self.auth_store = auth_store
        self.temp_root = tempfile.mkdtemp(prefix="triage-bootstrap-token-")
        self.original_db = auth_store._DB_PATH
        self.original_token = server.BOOTSTRAP_TOKEN
        auth_store._DB_PATH = os.path.join(self.temp_root, "auth.db")
        auth_store._init_db()
        server._reset_security_state_for_tests()
        server.BOOTSTRAP_TOKEN = "setup-secret-123"
        self.client = TestClient(server.app, raise_server_exceptions=False)

    def tearDown(self):
        self.client.close()
        self.server.BOOTSTRAP_TOKEN = self.original_token
        self.auth_store._DB_PATH = self.original_db
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def test_bootstrap_requires_configured_token(self):
        me = self.client.get("/api/auth/me").json()
        self.assertTrue(me["bootstrap_token_required"])
        body = {"username": "first-admin", "password": "Password123!"}
        self.assertEqual(self.client.post("/api/auth/bootstrap", json=body).status_code, 403)
        wrong = self.client.post("/api/auth/bootstrap", json={**body, "bootstrap_token": "nope"})
        self.assertEqual(wrong.status_code, 403)
        self.assertFalse(self.auth_store.has_users())
        ok = self.client.post("/api/auth/bootstrap", json={**body, "bootstrap_token": "setup-secret-123"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertFalse(self.client.get("/api/auth/me").json()["bootstrap_token_required"])
