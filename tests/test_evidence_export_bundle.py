"""Explicit evidence inclusion and export provenance regression tests."""

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from triage_engine.product import export_case_bundle, verify_case_bundle


class EvidenceExportBundleTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1] / "runtime/temp/forensic-foundation-export"
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=parent)
        self.root = Path(self.temp.name)
        self.case = self.root / "case"
        self.case.mkdir()
        self.output = self.root / "bundle.zip"
        self.original = b"Original source with private username and exact evidence bytes"
        self.raw = b'{"event_id": 1, "username": "private-user"}\n'
        self.source = self.case / "evidence/original.evtx"
        self.source.parent.mkdir()
        self.source.write_bytes(self.original)
        (self.case / "raw_events.jsonl").write_bytes(self.raw)
        self.manifest = {"schema_version": "1.0", "sources": [{
            "path": "evidence/original.evtx", "sha256": hashlib.sha256(self.original).hexdigest(),
            "size_bytes": len(self.original), "original_name": "original.evtx",
        }]}
        self.write_manifest()
        for name in ("case_identity.json", "analysis_manifest.json", "forensic_observations.json", "findings.json"):
            (self.case / name).write_text("{}", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def write_manifest(self):
        (self.case / "evidence_manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def export(self, **kwargs):
        return export_case_bundle(str(self.case), str(self.output), **kwargs)

    def test_default_contains_provenance_without_raw_sources(self):
        self.export()
        with zipfile.ZipFile(self.output) as bundle:
            self.assertEqual(set(bundle.namelist()), {
                "case_identity.json", "evidence_manifest.json", "analysis_manifest.json",
                "forensic_observations.json", "findings.json", "export_manifest.json",
            })
            policy = json.loads(bundle.read("export_manifest.json"))["source_policy"]
            self.assertFalse(policy["include_sources"])
            self.assertEqual(policy["original_sources"], "excluded")
            self.assertEqual(policy["raw_events"], "excluded")
        self.assertTrue(verify_case_bundle(str(self.output))["valid"])

    def test_explicit_source_export_preserves_bytes_and_hashes(self):
        (self.case / "evidence/unlisted.evtx").write_bytes(b"must not export")
        self.export(include_sources=True)
        with zipfile.ZipFile(self.output) as bundle:
            self.assertEqual(bundle.read("evidence/original.evtx"), self.original)
            self.assertEqual(bundle.read("raw_events.jsonl"), self.raw)
            self.assertNotIn("evidence/unlisted.evtx", bundle.namelist())
            metadata = json.loads(bundle.read("export_manifest.json"))
            self.assertTrue(metadata["source_policy"]["include_sources"])
            self.assertEqual(metadata["source_policy"]["original_sources"], "unredacted")
            self.assertEqual(metadata["source_policy"]["raw_events"], "unredacted")
            for entry in metadata["files"]:
                self.assertEqual(entry["sha256"], hashlib.sha256(bundle.read(entry["path"])).hexdigest())
        self.assertTrue(verify_case_bundle(str(self.output))["valid"])

    def test_source_metadata_rejects_unsafe_paths_and_tampering_before_output(self):
        cases = [
            {"path": "../outside.evtx"}, {"path": "/absolute.evtx"},
            {"path": "evidence/../../outside.evtx"}, {"path": "findings.json"},
            {"sha256": "0" * 64}, {"size_bytes": len(self.original) + 1},
            {"size_bytes": True}, {"sha256": "bad"},
        ]
        original_entry = dict(self.manifest["sources"][0])
        for changes in cases:
            with self.subTest(changes=changes):
                self.manifest["sources"] = [dict(original_entry, **changes)]
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.export(include_sources=True)
                self.assertFalse(self.output.exists())

    def test_extra_files_and_payloads_cannot_bypass_source_policy(self):
        for path in (self.source, self.case / "raw_events.jsonl"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "include_sources"):
                self.export(extra_files=[str(path)])
        for name in ("evidence/injected.evtx", "raw_events.jsonl"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "extra_payloads"):
                self.export(extra_payloads={name: b"injected"}, include_sources=True)

    def test_source_symlink_is_rejected(self):
        self.source.unlink()
        target = self.root / "outside.evtx"
        target.write_bytes(self.original)
        try:
            self.source.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"Symlink creation unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "links"):
            self.export(include_sources=True)

    def test_source_directory_link_is_rejected(self):
        linked = self.case / "linked"
        try:
            linked.symlink_to(self.source.parent, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Symlink creation unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "links"):
            self.export(extra_files=[str(linked / self.source.name)])

    def test_source_option_requires_a_valid_evidence_manifest(self):
        self.manifest = {"sources": "invalid"}
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "sources list"):
            self.export(include_sources=True)

    def completed_run(self):
        run_id = "completed-run"
        self.manifest["run_id"] = run_id
        self.write_manifest()
        (self.case / "forensic_observations.json").write_text(json.dumps({"run_id": run_id}), encoding="utf-8")
        (self.case / "findings.json").write_text(json.dumps({"case": {"run_id": run_id}}), encoding="utf-8")
        (self.case / "run_status.json").write_text(json.dumps({"status": "completed", "metadata": {"run_id": run_id}}), encoding="utf-8")
        outputs = []
        for name in ("findings.json", "evidence_manifest.json", "forensic_observations.json"):
            data = (self.case / name).read_bytes()
            outputs.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
        (self.case / "analysis_manifest.json").write_text(json.dumps({"run_id": run_id, "outputs": outputs}), encoding="utf-8")

    def test_changed_output_bytes_cannot_be_published_with_old_analysis(self):
        self.completed_run()
        self.output.write_bytes(b"previous archive")
        read_bytes = Path.read_bytes
        findings = self.case / "findings.json"
        reads = 0

        def concurrent_rerun(path):
            nonlocal reads
            data = read_bytes(path)
            if path == findings:
                reads += 1
                if reads == 1:
                    findings.write_bytes(b'{"case":{"run_id":"new-running-run"}}')
            return data

        with patch.object(Path, "read_bytes", concurrent_rerun):
            with self.assertRaisesRegex(ValueError, "changed during export"):
                self.export()
        self.assertEqual(self.output.read_bytes(), b"previous archive")
        self.assertFalse(list(self.root.glob(".bundle-*.partial")))

    def test_rerun_started_during_zip_write_does_not_publish_archive(self):
        self.completed_run()
        write = zipfile.ZipFile.writestr

        def concurrent_rerun(archive, name, data, *args, **kwargs):
            result = write(archive, name, data, *args, **kwargs)
            if name == "findings.json":
                (self.case / "run_status.json").write_text(json.dumps({"status": "running", "metadata": {"run_id": "new-run"}}), encoding="utf-8")
            return result

        with patch.object(zipfile.ZipFile, "writestr", concurrent_rerun):
            with self.assertRaisesRegex(ValueError, "different analysis run during export"):
                self.export()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".bundle-*.partial")))

    def test_bundle_destination_cannot_destroy_retained_evidence_or_outputs(self):
        snapshot = self.case / "runs/retained-run/outputs/raw_events.jsonl"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_bytes(self.raw)
        for output in (self.source, snapshot, self.case / "raw_events.jsonl", self.case / "findings.json"):
            with self.subTest(output=output):
                original = output.read_bytes()
                with self.assertRaisesRegex(ValueError, "overwrite case evidence"):
                    export_case_bundle(str(self.case), str(output))
                self.assertEqual(output.read_bytes(), original)

    def test_source_policy_cannot_be_bypassed_by_case_variants_or_historical_paths(self):
        snapshot = self.case / "runs/retained-run/outputs/raw_events.jsonl"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_bytes(self.raw)
        upper_raw = self.case / "RAW_EVENTS.jsonl"
        if not upper_raw.exists():
            upper_raw.write_bytes(self.raw)
        for source in (upper_raw, snapshot):
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.export(extra_files=[str(source)])
        for member in ("RAW_EVENTS.jsonl", "Evidence/injected.evtx", "runs/a/outputs/raw_events.jsonl"):
            with self.subTest(member=member), self.assertRaises(ValueError):
                self.export(extra_payloads={member: self.raw})


if __name__ == "__main__":
    unittest.main()
