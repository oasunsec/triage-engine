"""Focused API coverage for case metadata, retention, export and investigation safety contracts."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient


class CaseApiSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server
        import triage_engine.auth_store as auth
        import triage_engine.review_store as reviews

        cls.root = tempfile.mkdtemp(prefix="triage-case-api-")
        cls.cases = os.path.join(cls.root, "cases")
        cls.uploads = os.path.join(cls.root, "uploads")
        cls.data = os.path.join(cls.root, "data")
        os.makedirs(cls.cases)
        os.makedirs(cls.uploads)
        os.makedirs(cls.data)
        cls.originals = (server.CASES_ROOT, server.UPLOAD_ROOT, server.DATA_ROOT, auth._DB_PATH, reviews._DB_PATH)
        server.CASES_ROOT, server.UPLOAD_ROOT, server.DATA_ROOT = cls.cases, cls.uploads, cls.data
        auth._DB_PATH = os.path.join(cls.data, "auth.db")
        reviews._DB_PATH = os.path.join(cls.data, "reviews.db")
        auth._init_db()
        reviews._init_db()
        server._reset_security_state_for_tests()
        cls.client = TestClient(server.app, raise_server_exceptions=False)
        response = cls.client.post("/api/auth/bootstrap", json={"username": "admin", "password": "Password123!"})
        if response.status_code != 200:
            raise RuntimeError(response.text)
        cls.client.headers["X-CSRF-Token"] = response.json()["csrf_token"]

    @classmethod
    def tearDownClass(cls):
        import server
        import triage_engine.auth_store as auth
        import triage_engine.review_store as reviews

        server.CASES_ROOT, server.UPLOAD_ROOT, server.DATA_ROOT, auth._DB_PATH, reviews._DB_PATH = cls.originals
        shutil.rmtree(cls.root, ignore_errors=True)

    def setUp(self):
        import server
        server._reset_security_state_for_tests()

    def _case(self, name="metadata-case"):
        path = os.path.join(self.cases, name)
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump({"case": {"case_name": name}, "findings": [], "incidents": []}, fh)
        return path

    def test_case_metadata_payload_and_bundle(self):
        self._case()
        updated = self.client.patch(
            "/api/cases/metadata-case/metadata",
            json={"acquisition_method": "upload", "collection_manifest": {"files": []}},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["collection_manifest"]["method"], "upload")
        self.assertNotIn("client_id", updated.json())
        payload = self.client.get("/api/cases/metadata-case")
        self.assertEqual(payload.status_code, 200)
        self.assertEqual(payload.json()["case"]["acquisition_method"], "upload")
        bundle = self.client.post("/api/cases/metadata-case/bundle")
        self.assertEqual(bundle.status_code, 200)
        self.assertIn("application/zip", bundle.headers.get("content-type", ""))

    def test_client_profile_and_capability_endpoints_are_gone(self):
        for method, path in (("get", "/api/clients"), ("post", "/api/clients"), ("get", "/api/capabilities")):
            self.assertIn(getattr(self.client, method)(path).status_code, (404, 405))

    def test_delete_reports_files_it_could_not_remove_and_keeps_review_state(self):
        import server
        self._case("stuck-case")
        with patch("server.delete_case_review_state") as review_cleanup, patch("server.shutil.rmtree"), \
                patch("server.time.sleep"):
            response = self.client.delete("/api/cases/stuck-case")
        self.assertEqual(response.status_code, 409)
        self.assertIn("findings.json", response.json()["detail"])
        review_cleanup.assert_not_called()
        self.assertTrue(os.path.isdir(os.path.join(self.cases, "stuck-case")))

    @unittest.skipUnless(os.name == "nt", "Windows refuses to delete open files")
    def test_delete_with_a_file_open_elsewhere_is_not_reported_as_deleted(self):
        path = self._case("open-file-case")
        with open(os.path.join(path, "findings.json"), "rb"), patch("server.time.sleep"):
            response = self.client.delete("/api/cases/open-file-case")
        self.assertEqual(response.status_code, 409)
        retry = self.client.delete("/api/cases/open-file-case")
        self.assertEqual(retry.status_code, 200)
        self.assertFalse(os.path.exists(path))

    def test_delete_removes_folder_and_metadata(self):
        import server
        self._case("gone-case")
        self.assertEqual(self.client.patch("/api/cases/gone-case/metadata", json={"acquisition_method": "upload"}).status_code, 200)
        self.assertIsNotNone(server._product_store().get_case_metadata("gone-case"))
        response = self.client.delete("/api/cases/gone-case")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(os.path.exists(os.path.join(self.cases, "gone-case")))
        self.assertIsNone(server._product_store().get_case_metadata("gone-case"))

    def test_explicit_purge_requires_elapsed_retention(self):
        self._case("expired-case")
        past = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0).isoformat()
        response = self.client.patch("/api/cases/expired-case/metadata", json={"retention_until": past})
        self.assertEqual(response.status_code, 200)
        purged = self.client.delete("/api/cases/expired-case/purge")
        self.assertEqual(purged.status_code, 200)
        self.assertFalse(os.path.exists(os.path.join(self.cases, "expired-case")))

    def test_local_path_uses_resolved_containment(self):
        import server
        allowed = os.path.join(self.root, "evidence")
        sibling = os.path.join(self.root, "evidence-other")
        os.makedirs(allowed)
        os.makedirs(sibling)
        candidate = os.path.join(sibling, "outside.evtx")
        with open(candidate, "wb") as fh:
            fh.write(b"x")
        previous = server.ALLOWED_PATH_ROOTS
        server.ALLOWED_PATH_ROOTS = [allowed]
        try:
            with self.assertRaises(server.HTTPException) as raised:
                server._validate_evtx_path(candidate)
            self.assertEqual(raised.exception.status_code, 403)
        finally:
            server.ALLOWED_PATH_ROOTS = previous

    def test_upload_request_metadata_reaches_investigation_request(self):
        import server
        captured = {}

        class ImmediateThread:
            def __init__(self, target=None, args=(), **_kwargs):
                captured["args"] = args
            def start(self):
                pass

        with patch("server.Thread", ImmediateThread):
            response = self.client.post(
                "/api/investigate?acquisition_method=upload&collection_manifest=%7B%22files%22%3A%5B%5D%7D",
                files=[("files", ("sample.evtx", b"EVTX", "application/octet-stream"))],
            )
        self.assertEqual(response.status_code, 200)
        request = captured["args"][1]
        self.assertEqual(request.collection_manifest["method"], "upload")

    def test_live_elevation_returns_already_elevated_without_launching_process(self):
        import server

        with patch("server._is_loopback_client", return_value=True), patch("server._is_windows_admin", return_value=True), patch("server._launch_elevated_local_server") as launch:
            response = self.client.post("/api/live/elevate")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["already_elevated"])
        self.assertFalse(response.json()["elevation_requested"])
        launch.assert_not_called()

    def test_unauthenticated_quick_check_requires_local_token_and_rejects_non_loopback(self):
        import server

        anonymous = TestClient(
            server.app,
            base_url="http://127.0.0.1:8000",
            raise_server_exceptions=False,
        )
        with patch("server._is_loopback_client", return_value=True), patch("server._collect_live_health", return_value={
            "os_name": "nt", "is_windows": True, "pywin32_available": True, "is_elevated": False,
            "readiness": "degraded", "recommended_channels": [], "readable_channel_count": 0,
            "channels": [], "guidance": [],
        }):
            issued = anonymous.get("/api/quick/session")
            self.assertEqual(issued.status_code, 200)
            token = issued.json()["token"]
            self.assertEqual(anonymous.get("/api/quick/live/health").status_code, 403)
            allowed = anonymous.get("/api/quick/live/health", headers={"X-Triage-Quick-Token": token})
            self.assertEqual(allowed.status_code, 200)
        with patch("server._is_loopback_client", return_value=False):
            self.assertEqual(anonymous.get("/api/quick/session").status_code, 403)
