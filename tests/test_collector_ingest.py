"""Collector ingest: safe archive intake, hash re-verification and token-authenticated upload."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from triage_engine.ingest import IngestError, extract_collection


def _collection_zip(files: dict[str, bytes], *, manifest: dict | None = None, extra: dict[str, bytes] | None = None) -> bytes:
    listed = [{"path": name.replace("/", "\\"), "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
              for name, data in files.items()]
    manifest = manifest if manifest is not None else {
        "schema_version": "1.0", "kind": "windows_evidence_collection", "host": "LAB-01",
        "collected_at": "2026-10-31T10:00:00+00:00", "steps": [{"step": "ntfs", "status": "failed", "error": "x"}],
        "files": listed,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("collection_manifest.json", "\ufeff" + json.dumps(manifest))
        for name, data in {**files, **(extra or {})}.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class ExtractCollectionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ingest-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def _extract(self, payload: bytes, max_bytes: int = 10_000_000) -> dict:
        archive = self.root / "upload.zip"
        archive.write_bytes(payload)
        return extract_collection(archive, self.root / "out", max_bytes=max_bytes)

    def test_verified_collection_reports_logs_and_failed_steps(self):
        summary = self._extract(_collection_zip({"logs/Security.evtx": b"ElfFile\x00data", "tasks/T.xml": b"<Task/>"}))
        self.assertEqual(summary["host"], "LAB-01")
        self.assertEqual(summary["files_verified"], 2)
        self.assertTrue(summary["logs"].endswith("logs"))
        self.assertEqual(summary["bundle"], "")
        self.assertEqual([step["step"] for step in summary["failed_steps"]], ["ntfs"])
        self.assertEqual(summary["files"][0]["path"], "logs/Security.evtx")

    def test_rejects_path_traversal_and_unexpected_entries(self):
        for name in ("../evil.evtx", "logs/../../evil.evtx", "/abs/x.evtx", "C:/x.evtx", "scripts/run.ps1"):
            with self.subTest(name=name):
                shutil.rmtree(self.root / "out", ignore_errors=True)
                with self.assertRaises(IngestError):
                    self._extract(_collection_zip({"logs/a.evtx": b"x"}, extra={name: b"x"}))
        self.assertFalse((self.root.parent / "evil.evtx").exists())

    def test_rejects_symlink_members(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            info = zipfile.ZipInfo("logs/link.evtx")
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, "/etc/passwd")
        with self.assertRaisesRegex(IngestError, "Links"):
            self._extract(buffer.getvalue())

    def test_rejects_hash_mismatch_and_missing_file(self):
        good = {"logs/a.evtx": b"original"}
        listed = [{"path": "logs/a.evtx", "sha256": hashlib.sha256(b"original").hexdigest()}]
        tampered = _collection_zip({}, manifest={"kind": "windows_evidence_collection", "files": listed},
                                   extra={"logs/a.evtx": b"tampered"})
        with self.assertRaisesRegex(IngestError, "SHA-256 mismatch"):
            self._extract(tampered)
        shutil.rmtree(self.root / "out")
        missing = _collection_zip({}, manifest={"kind": "windows_evidence_collection", "files": listed},
                                  extra={"tasks/T.xml": b"x"})
        with self.assertRaisesRegex(IngestError, "missing"):
            self._extract(missing)
        shutil.rmtree(self.root / "out")
        self.assertTrue(self._extract(_collection_zip(good))["logs"])

    def test_rejects_non_collection_and_oversized_archives(self):
        with self.assertRaisesRegex(IngestError, "not a ZIP"):
            self._extract(b"not a zip")
        shutil.rmtree(self.root / "out")
        with self.assertRaisesRegex(IngestError, "Windows evidence collection"):
            self._extract(_collection_zip({"logs/a.evtx": b"x"}, manifest={"kind": "other", "files": []}))
        shutil.rmtree(self.root / "out")
        with self.assertRaisesRegex(IngestError, "size limit"):
            self._extract(_collection_zip({"logs/a.evtx": b"x" * 5000}), max_bytes=1000)


class IngestEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server
        import triage_engine.auth_store as auth
        import triage_engine.review_store as reviews

        cls.root = tempfile.mkdtemp(prefix="triage-ingest-api-")
        cls.cases, cls.uploads, cls.data = (os.path.join(cls.root, name) for name in ("cases", "uploads", "data"))
        for path in (cls.cases, cls.uploads, cls.data):
            os.makedirs(path)
        cls.originals = (server.CASES_ROOT, server.UPLOAD_ROOT, server.DATA_ROOT, auth._DB_PATH, reviews._DB_PATH)
        server.CASES_ROOT, server.UPLOAD_ROOT, server.DATA_ROOT = cls.cases, cls.uploads, cls.data
        auth._DB_PATH = os.path.join(cls.data, "auth.db")
        reviews._DB_PATH = os.path.join(cls.data, "reviews.db")
        auth._init_db()
        reviews._init_db()
        server._reset_security_state_for_tests()
        cls.admin = TestClient(server.app, raise_server_exceptions=False)
        response = cls.admin.post("/api/auth/bootstrap", json={"username": "admin", "password": "Password123!"})
        if response.status_code != 200:
            raise RuntimeError(response.text)
        cls.admin.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        cls.collector = TestClient(server.app, raise_server_exceptions=False)

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

    def _token(self, name="lab collector") -> dict:
        created = self.admin.post("/api/ingest-tokens", json={"name": name})
        self.assertEqual(created.status_code, 200, created.text)
        return created.json()

    def _post(self, payload: bytes, token: str, query: str = ""):
        return self.collector.post(f"/api/ingest/collection{query}", content=payload,
                                   headers={"Authorization": f"Bearer {token}", "Content-Type": "application/zip"})

    def test_upload_without_a_valid_token_is_refused(self):
        payload = _collection_zip({"logs/a.evtx": b"x"})
        self.assertEqual(self.collector.post("/api/ingest/collection", content=payload).status_code, 401)
        self.assertEqual(self._post(payload, "tri_not-a-real-token").status_code, 401)
        self.assertEqual(os.listdir(self.uploads), [])

    def test_token_management_requires_an_admin_session(self):
        self.assertEqual(self.collector.post("/api/ingest-tokens", json={"name": "x"}).status_code, 401)
        self.assertEqual(self.collector.get("/api/ingest-tokens").status_code, 401)

    def test_token_is_shown_once_and_stored_hashed(self):
        created = self._token("shown-once")
        self.assertTrue(created["token"].startswith("tri_"))
        listed = self.admin.get("/api/ingest-tokens").json()["tokens"]
        record = next(item for item in listed if item["token_id"] == created["token_id"])
        self.assertNotIn("token", record)
        self.assertNotIn(created["token"], json.dumps(listed))

    def test_verified_upload_queues_investigation_with_logs_and_manifest(self):
        captured = {}

        class ImmediateThread:
            def __init__(self, target=None, args=(), **_kwargs):
                captured["args"] = args
            def start(self):
                pass

        token = self._token()
        payload = _collection_zip({"logs/Security.evtx": b"ElfFile\x00x", "hives/SYSTEM": b"regf"})
        with patch("server.Thread", ImmediateThread):
            response = self._post(payload, token["token"], "?case_name=lab-01-ingest")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual((body["case_name"], body["status"], body["files_verified"]), ("lab-01-ingest", "queued", 2))
        job_id, request, staging = captured["args"]
        self.assertEqual(request.input_mode, "evtx_path")
        self.assertTrue(request.input_source.startswith(staging))
        self.assertTrue(request.allow_large_ntfs)
        self.assertEqual(request.requested_by, "ingest:lab collector")
        self.assertEqual(request.collection_manifest["source_host"], "LAB-01")
        self.assertEqual(len(request.collection_manifest["files"]), 2)
        self.assertFalse(os.path.exists(os.path.join(staging, "collection.zip")))
        listed = self.admin.get("/api/ingest-tokens").json()["tokens"]
        self.assertEqual(next(item for item in listed if item["token_id"] == token["token_id"])["use_count"], 1)

    def test_rejected_archive_leaves_no_staging_and_revoked_token_stops_working(self):
        token = self._token("revocable")
        tampered = _collection_zip({}, manifest={"kind": "windows_evidence_collection",
                                                 "files": [{"path": "logs/a.evtx", "sha256": "0" * 64}]},
                                   extra={"logs/a.evtx": b"x"})
        response = self._post(tampered, token["token"])
        self.assertEqual(response.status_code, 400)
        self.assertIn("SHA-256 mismatch", response.json()["detail"])
        self.assertEqual(os.listdir(self.uploads), [])
        self.assertEqual(self.admin.delete(f"/api/ingest-tokens/{token['token_id']}").status_code, 200)
        self.assertEqual(self._post(_collection_zip({"logs/a.evtx": b"x"}), token["token"]).status_code, 401)
        self.assertEqual(self.admin.delete(f"/api/ingest-tokens/{token['token_id']}").status_code, 404)


if __name__ == "__main__":
    unittest.main()
