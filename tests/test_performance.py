"""Phase 7.2 performance and concurrency API coverage."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch

from fastapi.testclient import TestClient


def _create_case(cases_root: str, name: str) -> str:
    """Create a small synthetic case directory used for API tests."""
    case_dir = os.path.join(cases_root, name)
    os.makedirs(case_dir, exist_ok=True)

    run_status = {
        "case_name": name,
        "input_source": "perf.evtx",
        "status": "completed",
        "started_at": "2026-03-17T10:00:00+00:00",
        "completed_at": "2026-03-17T10:00:01+00:00",
        "current_stage": "done",
        "message": "Performance seed case completed",
        "metadata": {
            "case_metrics": {"signal_count": 3, "finding_count": 1, "incident_count": 0},
            "response_priority": "P3",
        },
    }
    with open(os.path.join(case_dir, "run_status.json"), "w", encoding="utf-8") as fh:
        json.dump(run_status, fh)

    findings = {
        "case": {
            "case_name": name,
            "input_source": "perf.evtx",
            "response_priority": "P3",
            "first_seen": "2026-03-17T10:00:00+00:00",
            "last_seen": "2026-03-17T10:00:01+00:00",
        },
        "summary": {"signal_count": 3, "finding_count": 1, "incident_count": 0},
        "signals": [{"id": "sig-0", "title": "Synthetic Signal"}],
        "findings": [{"id": "fnd-0", "title": "Synthetic Finding"}],
        "incidents": [],
    }
    with open(os.path.join(case_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh)

    with open(os.path.join(case_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write("<html><body><h1>Performance Seed</h1></body></html>")

    return case_dir


class PerformanceAPITests(unittest.TestCase):
    """Phase 7.2 performance tests for queue, case listing, and concurrency."""

    def setUp(self):
        self._temp_root = tempfile.mkdtemp(prefix="triage-performance-test-")
        self._cases_dir = os.path.join(self._temp_root, "cases")
        self._upload_dir = os.path.join(self._temp_root, "uploads")
        self._static_dir = os.path.join(self._temp_root, "static")
        os.makedirs(self._cases_dir, exist_ok=True)
        os.makedirs(self._upload_dir, exist_ok=True)
        os.makedirs(self._static_dir, exist_ok=True)
        _create_case(self._cases_dir, "perf-base-case")

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
        self._orig_last_queue_sync_at = server._last_queue_sync_at

        server.CASES_ROOT = self._cases_dir
        server.UPLOAD_ROOT = self._upload_dir
        server.STATIC_DIR = self._static_dir
        server.DATA_ROOT = os.path.join(self._temp_root, "data")
        server.BACKUPS_ROOT = os.path.join(server.DATA_ROOT, "backups")
        server._last_queue_sync_at = os.path.getmtime(self._cases_dir)
        os.makedirs(server.DATA_ROOT, exist_ok=True)
        os.makedirs(server.BACKUPS_ROOT, exist_ok=True)

        import triage_engine.review_store as rs
        import triage_engine.auth_store as auth

        self._orig_review_db = rs._DB_PATH
        self._orig_auth_db = auth._DB_PATH
        rs._DB_PATH = os.path.join(self._temp_root, "performance_reviews.db")
        auth._DB_PATH = os.path.join(self._temp_root, "performance_auth.db")
        rs._init_db()
        auth._init_db()

        self.client = TestClient(server.app, raise_server_exceptions=False)
        server._reset_security_state_for_tests()

        boot = self.client.post("/api/auth/bootstrap", json={"username": "admin", "password": "Password123!"})
        self.assertEqual(boot.status_code, 200)
        self._sync_csrf_header()

    def tearDown(self):
        import server
        import triage_engine.review_store as rs
        import triage_engine.auth_store as auth

        server.CASES_ROOT = self._orig_cases_root
        server.UPLOAD_ROOT = self._orig_upload_root
        server.STATIC_DIR = self._orig_static_dir
        server.DATA_ROOT = self._orig_data_root
        server.BACKUPS_ROOT = self._orig_backups_root
        server._last_queue_sync_at = self._orig_last_queue_sync_at
        rs._DB_PATH = self._orig_review_db
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

    def test_queue_query_under_500ms_with_1000_items(self):
        import server
        from triage_engine.review_store import upsert_finding_review

        case_name = "perf-queue-case"
        _create_case(self._cases_dir, case_name)
        server._last_queue_sync_at = os.path.getmtime(self._cases_dir)

        for idx in range(1000):
            upsert_finding_review(
                case_name,
                f"fnd-perf-{idx}",
                status="In Review",
                owner="perf-owner",
                priority="P2",
                changed_by="perf-seed",
            )

        params = {"status": "In Review", "owner": "perf-owner", "limit": 1000}
        with patch.object(server, "_sync_queue_index_if_stale", return_value=0):
            warm = self.client.get("/api/review/queue", params=params)
            self.assertEqual(warm.status_code, 200)

            started = time.perf_counter()
            resp = self.client.get("/api/review/queue", params=params)
            elapsed_ms = (time.perf_counter() - started) * 1000.0

        self.assertEqual(resp.status_code, 200)
        rows = resp.json()
        self.assertEqual(len(rows), 1000)
        self.assertLess(
            elapsed_ms,
            500.0,
            f"Queue query exceeded 500ms target: {elapsed_ms:.2f}ms for {len(rows)} rows",
        )

    def test_case_list_under_2s_with_100_synthetic_cases(self):
        for idx in range(100):
            _create_case(self._cases_dir, f"perf-case-{idx:03d}")

        warm = self.client.get("/api/cases")
        self.assertEqual(warm.status_code, 200)

        started = time.perf_counter()
        resp = self.client.get("/api/cases")
        elapsed_s = time.perf_counter() - started

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertGreaterEqual(len(payload), 100)
        self.assertLess(
            elapsed_s,
            2.0,
            f"/api/cases exceeded 2s target: {elapsed_s:.3f}s for {len(payload)} cases",
        )

    def test_twenty_concurrent_review_updates_succeed_without_sqlite_lock_errors(self):
        import server

        case_name = "perf-concurrency-case"
        finding_id = "fnd-concurrent-0"
        _create_case(self._cases_dir, case_name)
        server._last_queue_sync_at = os.path.getmtime(self._cases_dir)

        # Seed the review row once to force concurrent requests onto UPDATE paths.
        seeded = self.client.patch(
            f"/api/cases/{case_name}/findings/{finding_id}/review",
            json={"status": "Open", "owner": "seed-owner"},
        )
        self.assertEqual(seeded.status_code, 200)

        users: list[tuple[str, str, int]] = []
        for idx in range(20):
            username = f"perf-analyst-{idx:02d}"
            password = f"PerfPass{idx:02d}!Strong"
            created = self.client.post(
                "/api/auth/users",
                json={"username": username, "password": password, "role": "analyst"},
            )
            self.assertEqual(created.status_code, 200)
            users.append((username, password, idx))

        def _update_as_user(identity: tuple[str, str, int]) -> tuple[int, int, str]:
            username, password, idx = identity
            with TestClient(server.app, raise_server_exceptions=False) as local_client:
                login = local_client.post(
                    "/api/auth/login",
                    json={"username": username, "password": password},
                )
                if login.status_code != 200:
                    return idx, login.status_code, login.text

                me = local_client.get("/api/auth/me")
                if me.status_code != 200:
                    return idx, me.status_code, me.text
                token = me.json().get("csrf_token", "")
                if token:
                    local_client.headers["X-CSRF-Token"] = token

                updated = local_client.patch(
                    f"/api/cases/{case_name}/findings/{finding_id}/review",
                    json={"status": "In Review", "owner": f"perf-owner-{idx:02d}"},
                )
                return idx, updated.status_code, updated.text

        results: list[tuple[int, int, str]] = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(_update_as_user, identity) for identity in users]
            for future in as_completed(futures):
                results.append(future.result())

        self.assertEqual(len(results), 20)
        for idx, status_code, body in results:
            with self.subTest(worker=idx):
                self.assertEqual(status_code, 200, body)
                lowered = body.lower()
                self.assertFalse(
                    "database is locked" in lowered,
                    f"SQLite lock detected for worker {idx}: {body}",
                )
