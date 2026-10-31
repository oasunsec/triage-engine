import json
from datetime import datetime
import tempfile
import unittest
import zipfile
from pathlib import Path

from triage_engine.product import (
    CaseMetadata,
    CaseMetadataStore,
    CollectionManifest,
    derive_disposition,
    export_case_bundle,
    verify_case_bundle,
)


class ProductWorkflowTests(unittest.TestCase):
    def test_case_metadata_retains_manifest_and_uses_retention(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as data_dir, patch.dict("os.environ", {"TRIAGE_CASE_RETENTION_DAYS": "14"}):
            store = CaseMetadataStore(data_dir)
            manifest = {"method": "local_live", "files": [{"path": "events.evtx"}]}
            metadata = store.save_case_metadata(
                CaseMetadata("case-001", acquisition_method="local_live", collection_manifest=manifest))
            loaded = store.get_case_metadata("case-001")
            self.assertEqual(loaded.collection_manifest, manifest)
            self.assertEqual(loaded.acquisition_method, "local_live")
            self.assertEqual(loaded.client_id, "default")
            days = (datetime.fromisoformat(loaded.retention_until) - datetime.fromisoformat(metadata.created_at)).days
            self.assertIn(days, (13, 14))
            self.assertTrue(store.purge_case_metadata("case-001"))
            self.assertIsNone(store.get_case_metadata("case-001"))

    def test_case_metadata_rejects_invalid_acquisition_method(self):
        with tempfile.TemporaryDirectory() as data_dir:
            store = CaseMetadataStore(data_dir)
            with self.assertRaises(ValueError):
                store.save_case_metadata(CaseMetadata("bad", acquisition_method="not-a-method"))

    def test_dispositions_are_deterministic_and_explainable(self):
        cases = [
            ((1, 0, "P1", 0, []), "Escalate"),
            ((1, 0, "P4", 75, []), "Escalate"),
            ((1, 0, "P4", 74, []), "Investigate"),
            ((0, 1, "P4", 0, []), "Investigate"),
            ((0, 0, "P4", 0, ["process telemetry missing"]), "Monitor"),
            ((0, 0, "P4", 0, []), "No promoted incident"),
        ]
        for (incident_count, finding_count, priority, score, gaps), expected in cases:
            result = derive_disposition(
                incident_count=incident_count,
                finding_count=finding_count,
                response_priority=priority,
                confidence_score=score,
                telemetry_gaps=gaps,
            )
            self.assertEqual(result.disposition, expected)
            self.assertEqual(result, derive_disposition(
                incident_count=incident_count,
                finding_count=finding_count,
                response_priority=priority,
                confidence_score=score,
                telemetry_gaps=gaps,
            ))
            self.assertEqual(result.source, "deterministic")

        self.assertEqual(derive_disposition(incident_count=0, finding_count=0, response_priority="P4", confidence_score=150).confidence_score, 100)

    def test_collection_manifest_validation(self):
        CollectionManifest(method="upload", files=[{"path": "nested/events.evtx"}]).validate()
        with self.assertRaisesRegex(ValueError, "Unsupported acquisition"):
            CollectionManifest(method="stream").validate()
        with self.assertRaisesRegex(ValueError, "objects"):
            CollectionManifest(method="upload", files=["events.evtx"]).validate()
        with self.assertRaisesRegex(ValueError, "escape"):
            CollectionManifest(method="upload", files=[{"path": "../events.evtx"}]).validate()
        with self.assertRaisesRegex(ValueError, "escape"):
            CollectionManifest(method="upload", files=[{"path": "/etc/events.evtx"}]).validate()

    def test_bundle_export_manifest_contains_sha256_hashes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            case_dir = Path(temp_dir) / "case-001"
            case_dir.mkdir()
            (case_dir / "report.html").write_text("<h1>Report</h1>", encoding="utf-8")
            (case_dir / "findings.json").write_text('{"findings": []}', encoding="utf-8")
            outside = Path(temp_dir) / "outside.txt"
            outside.write_text("not part of case", encoding="utf-8")
            bundle_path = export_case_bundle(str(case_dir), extra_files=[str(outside)])

            with zipfile.ZipFile(bundle_path) as bundle:
                self.assertEqual(set(bundle.namelist()), {"report.html", "findings.json", "export_manifest.json"})
                manifest = json.loads(bundle.read("export_manifest.json"))
                self.assertEqual(manifest["case_name"], "case-001")
                for entry in manifest["files"]:
                    data = bundle.read(entry["path"])
                    self.assertEqual(entry["size"], len(data))
                    import hashlib
                    self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertTrue(verify_case_bundle(bundle_path)["valid"])

    def test_bundle_verifier_rejects_tampering_duplicates_and_unlisted_members(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            case_dir = Path(temp_dir) / "case-001"
            case_dir.mkdir()
            (case_dir / "report.html").write_text("original", encoding="utf-8")
            bundle_path = Path(export_case_bundle(str(case_dir)))

            tampered = Path(temp_dir) / "tampered.zip"
            with zipfile.ZipFile(bundle_path, "r") as source, zipfile.ZipFile(tampered, "w") as target:
                for info in source.infolist():
                    target.writestr(info.filename, b"changed" if info.filename == "report.html" else source.read(info))
            tampered_result = verify_case_bundle(str(tampered))
            self.assertFalse(tampered_result["valid"])
            self.assertTrue(any(item["reason"] == "hash_or_size_mismatch" for item in tampered_result["failures"]))

            extra = Path(temp_dir) / "extra.zip"
            with zipfile.ZipFile(bundle_path, "r") as source, zipfile.ZipFile(extra, "w") as target:
                for info in source.infolist():
                    target.writestr(info.filename, source.read(info))
                target.writestr("unlisted.txt", b"not in manifest")
            extra_result = verify_case_bundle(str(extra))
            self.assertFalse(extra_result["valid"])
            self.assertTrue(any(item["reason"] == "unlisted_archive_member" for item in extra_result["failures"]))

            duplicate = Path(temp_dir) / "duplicate.zip"
            with zipfile.ZipFile(bundle_path, "r") as source, zipfile.ZipFile(duplicate, "w") as target:
                for info in source.infolist():
                    target.writestr(info.filename, source.read(info))
                target.writestr("report.html", b"second copy")
            duplicate_result = verify_case_bundle(str(duplicate))
            self.assertFalse(duplicate_result["valid"])
            self.assertTrue(any(item["reason"] == "duplicate_archive_member" for item in duplicate_result["failures"]))

    def test_bundle_export_rejects_reserved_or_unsafe_payload_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            case_dir = Path(temp_dir) / "case-001"
            case_dir.mkdir()
            (case_dir / "findings.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "reserved"):
                export_case_bundle(str(case_dir), extra_payloads={"export_manifest.json": b"bad"})
            with self.assertRaisesRegex(ValueError, "parent"):
                export_case_bundle(str(case_dir), extra_payloads={"../escape.txt": b"bad"})
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                export_case_bundle(str(case_dir), extra_payloads={"findings.json": b"duplicate"})
if __name__ == "__main__":
    unittest.main()
