"""Tests for the repository-local coverage audit utility."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "coverage_audit.py"
SPEC = importlib.util.spec_from_file_location("coverage_audit", MODULE_PATH)
assert SPEC and SPEC.loader
coverage_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage_audit)


class CoverageAuditTests(unittest.TestCase):
    def _fixture_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "detectors").mkdir()
        (root / "tests").mkdir()
        (root / "config" / "benchmark").mkdir(parents=True)
        (root / "detectors" / "example.py").write_text(
            """
def detect(event):
    if event.event_id in {1, 4688}:
        return Finding(mitre_technique=\"t1059.001\")
""".strip(),
            encoding="utf-8",
        )
        (root / "tests" / "test_example.py").write_text(
            """
def test_t1059_001_synthetic():
    assert \"T1059.001\"

def test_t1059_001_benign_regression():
    assert \"T1059.001\"

@unittest.skipUnless(False, \"public EVTX absent\")
def test_public_evtx_sample_T1003():
    pass
""".strip(),
            encoding="utf-8",
        )
        public_root = root / "repo_cache" / "EVTX-ATTACK-SAMPLES"
        public_root.mkdir(parents=True)
        public_sample = public_root / "T1059.001-demo.evtx"
        public_sample.write_bytes(b"not parsed by audit")
        (public_root / "T1486-corpus-only.evtx").write_bytes(b"not parsed by audit")
        synthetic = root / "synthetic.evtx"
        synthetic.write_bytes(b"not parsed by audit")
        manifest = root / "config" / "benchmark" / "corpus.json"
        manifest.write_text(
            json.dumps(
                {
                    "samples": [
                        {
                            "id": "synthetic",
                            "path": "./synthetic.evtx",
                            "expected": "malicious",
                            "synthetic": True,
                            "attack_techniques": ["t1059.001"],
                        },
                        {
                            "id": "public",
                            "path": "./repo_cache/EVTX-ATTACK-SAMPLES/T1059.001-demo.evtx",
                            "expected": "malicious",
                            "attack_techniques": ["T1059.001"],
                        },
                        {
                            "id": "missing-required",
                            "path": "./missing.evtx",
                            "expected": "benign",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        return temporary, root, manifest, public_root

    def test_normalization_extracts_uppercase_attack_ids(self) -> None:
        self.assertEqual(coverage_audit.normalize_technique("t1059.001"), "T1059.001")
        self.assertEqual(coverage_audit.normalize_technique("invalid"), "")
        self.assertEqual(
            coverage_audit.technique_ids({"techniques": ["t1003", "see T1059.001"]}),
            {"T1003", "T1059.001"},
        )

    def test_report_distinguishes_mapping_availability_and_validation(self) -> None:
        temporary, root, manifest, public_root = self._fixture_root()
        self.addCleanup(temporary.cleanup)
        validation = root / "completed-eval.json"
        validation.write_text(
            json.dumps(
                {
                    "samples": [
                        {
                            "id": "public",
                            "path": str(public_root / "T1059.001-demo.evtx"),
                            "expected": "malicious",
                            "techniques": ["t1059.001"],
                            "expectation": {"passed": True},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        report = coverage_audit.build_report(
            root=root,
            manifest_paths=[manifest],
            external_evtx_roots=[public_root],
            validation_report_paths=[validation],
        )
        row = next(item for item in report["techniques"] if item["technique"] == "T1059.001")
        self.assertTrue(row["states"]["mapped"])
        self.assertTrue(row["states"]["telemetry_supported"])
        self.assertTrue(row["states"]["validated_synthetic"])
        self.assertTrue(row["states"]["validated_public_EVTX"])
        self.assertTrue(row["states"]["benign_regression"])
        self.assertEqual(row["evidence"]["event_ids"], [1, 4688])
        self.assertEqual(report["benchmark"]["missing_required_paths"][0]["id"], "missing-required")
        self.assertEqual(report["external_EVTX_corpus"]["evtx_file_count"], 2)
        corpus_only = next(item for item in report["techniques"] if item["technique"] == "T1486")
        self.assertFalse(corpus_only["states"]["mapped"])
        self.assertEqual(
            corpus_only["evidence"]["external_corpus_samples"],
            ["repo_cache/EVTX-ATTACK-SAMPLES/T1486-corpus-only.evtx"],
        )
        self.assertEqual(report["skipped_public_sample_tests"][0]["test"], "tests/test_example.py:test_public_evtx_sample_T1003")

    def test_cli_strict_fails_for_missing_required_benchmark_file(self) -> None:
        temporary, root, manifest, public_root = self._fixture_root()
        self.addCleanup(temporary.cleanup)
        json_out = root / "out" / "coverage.json"
        markdown_out = root / "out" / "coverage.md"
        result = coverage_audit.main(
            [
                "--root",
                str(root),
                "--benchmark",
                str(manifest),
                "--external-evtx-root",
                str(public_root),
                "--json-out",
                str(json_out),
                "--markdown-out",
                str(markdown_out),
                "--strict",
            ]
        )
        self.assertEqual(result, 2)
        self.assertTrue(json_out.is_file())
        self.assertIn("Detection coverage audit", markdown_out.read_text(encoding="utf-8"))

    def test_annotation_note_explains_declared_telemetry_gap(self) -> None:
        temporary, root, manifest, public_root = self._fixture_root()
        self.addCleanup(temporary.cleanup)
        annotations = root / "coverage-limitations.json"
        annotations.write_text(
            json.dumps(
                {
                    "techniques": {
                        "T1486": {
                            "telemetry_gap": True,
                            "note": "Encryption telemetry alone does not prove ransomware intent.",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        report = coverage_audit.build_report(
            root=root,
            manifest_paths=[manifest],
            external_evtx_roots=[public_root],
            annotations_path=annotations,
        )
        row = next(item for item in report["techniques"] if item["technique"] == "T1486")
        self.assertTrue(row["states"]["telemetry_gap"])
        self.assertIn("does not prove ransomware", row["limitations"][0])

    def test_event_ids_resolve_named_module_constants(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "detectors").mkdir()
        (root / "tests").mkdir()
        snippet = '''
_EVENT_IDS = frozenset({768, 775, 780})
_START_EVENT_IDS = frozenset({768})


def detect(events):
    for event in events:
        if event.event_id not in _START_EVENT_IDS:
            return None
        if event.event_id in _EVENT_IDS:
            return Finding(mitre_technique="T1486")
'''
        (root / "detectors" / "example.py").write_text(snippet.strip(), encoding="utf-8")
        report = coverage_audit.build_report(
            root=root,
            manifest_paths=[],
            external_evtx_roots=[],
        )
        row = next(item for item in report["techniques"] if item["technique"] == "T1486")
        self.assertTrue(row["states"]["telemetry_supported"])
        self.assertEqual(row["evidence"]["event_ids"], [768, 775, 780])



if __name__ == '__main__':
    unittest.main()

