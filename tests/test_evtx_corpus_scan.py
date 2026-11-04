"""Focused tests for the local EVTX corpus scanner.

These tests avoid invoking the live engine.  They cover enumeration,
provenance handling, hint inference, worklist aggregation, and Markdown
rendering.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.evtx_corpus_scan import (  # noqa: E402
    Sample,
    SampleResult,
    SCHEMA_VERSION,
    _infer_path_hints,
    _normalise_technique,
    _provenance_token,
    analyse_sample,
    build_worklist,
    enumerate_samples,
    render_markdown,
)


def _make_sample(tmpdir: Path, name: str, *, body: bytes = b"x") -> Path:
    path = tmpdir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return path


class NormalisationTests(unittest.TestCase):
    def test_technique_normalisation_uppercases_and_validates(self):
        self.assertEqual(_normalise_technique("t1003.001"), "T1003.001")
        self.assertEqual(_normalise_technique("T1003.001"), "T1003.001")
        self.assertEqual(_normalise_technique(""), "")
        self.assertEqual(_normalise_technique(None), "")
        self.assertEqual(_normalise_technique("T1003"), "T1003")
        self.assertEqual(_normalise_technique("T1003.001 extra"), "")


class ProvenanceTests(unittest.TestCase):
    def test_recognises_curated_allowlist(self):
        self.assertEqual(
            _provenance_token("repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES/x.evtx"),
            "sbousseaden_evtx-attack-samples",
        )
        self.assertEqual(
            _provenance_token("repo_cache/mdecrevoisier_EVTX-to-MITRE-Attack/x.evtx"),
            "mdecrevoisier_evtx-to-mitre-attack",
        )
        self.assertEqual(_provenance_token("random/path/no_match.evtx", ""), "")

    def test_falls_back_to_absolute_path(self):
        # Relative path alone does not match, but absolute path does.
        token = _provenance_token("x.evtx", "C:/Users/me/repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES/x.evtx")
        self.assertEqual(token, "sbousseaden_evtx-attack-samples")


class PathHintTests(unittest.TestCase):
    def test_dcsync_path_maps_to_correct_subtechniques(self):
        hints = _infer_path_hints("repo_cache/sbousseaden/Credential Access/dcsync_4662.evtx")
        self.assertIn("T1003.006", hints)
        self.assertIn("T1003.002", hints)

    def test_winlogon_helper_maps_to_persistence_techniques(self):
        hints = _infer_path_hints("repo_cache/sigma/windows/registry/winlogon_helper_dll_modification.evtx")
        self.assertIn("T1547.004", hints)
        self.assertIn("T1546.015", hints)

    def test_unrelated_path_produces_no_hints(self):
        self.assertEqual(_infer_path_hints("repo_cache/random_noise.evtx"), [])

    def test_generic_collection_folder_names_do_not_create_false_hints(self):
        lateral_winrm = _infer_path_hints(
            "repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES/Lateral Movement/LM_winrm_exec_sysmon_1_winrshost.evtx"
        )
        cdpsshims_hijack = _infer_path_hints(
            "repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES/Defense Evasion/Sysmon 7 dllhijack_cdpsshims_CDPSvc.evtx"
        )
        discovery_bloodhound = _infer_path_hints(
            "repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES/Discovery/discovery_bloodhound.evtx"
        )
        privilege_uacme = _infer_path_hints(
            "repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_22.evtx"
        )
        kerberos_spray = _infer_path_hints(
            "repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES/Credential Access/kerberos_pwd_spray_4771.evtx"
        )
        guest_rid_hijack = _infer_path_hints(
            "repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES/Persistence/persist_valid_account_guest_rid_hijack.evtx"
        )

        self.assertIn("T1021.006", lateral_winrm)
        self.assertNotIn("T1021.004", lateral_winrm)
        self.assertNotIn("T1021.004", cdpsshims_hijack)
        self.assertNotIn("T1046", discovery_bloodhound)
        self.assertNotIn("T1068", privilege_uacme)
        self.assertNotIn("T1558", kerberos_spray)
        self.assertNotIn("T1078", guest_rid_hijack)

    def test_explicit_technique_directory_still_creates_hints(self):
        hints = _infer_path_hints(
            "repo_cache/mdecrevoisier_EVTX-to-MITRE-Attack/TA0004-Privilege Escalation/T1068-Exploitation for Privilege Escalation/ID1.evtx"
        )
        self.assertIn("T1068", hints)


class EnumerationTests(unittest.TestCase):
    def test_wrong_extension_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_sample(root, "good.evtx")
            _make_sample(root, "ignore.evt")
            _make_sample(root, "notes.txt")
            samples = enumerate_samples([root])
            self.assertEqual([s.path.name for s in samples], ["good.evtx"])

    def test_missing_root_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "missing"
            self.assertEqual(enumerate_samples([root]), [])

    def test_deterministic_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["z.evtx", "a.evtx", "m.evtx"]:
                _make_sample(root, name)
            samples = enumerate_samples([root])
            self.assertEqual([s.path.name for s in samples], ["a.evtx", "m.evtx", "z.evtx"])

    def test_limit_truncates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for i in range(5):
                _make_sample(root, f"s{i}.evtx")
            samples = enumerate_samples([root], limit=3)
            self.assertEqual(len(samples), 3)

    def test_provenance_from_subdirectory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sub = root / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Credential Access"
            sub.mkdir(parents=True)
            _make_sample(sub, "dcsync.evtx")
            samples = enumerate_samples([sub])
            self.assertEqual(len(samples), 1)
            self.assertEqual(samples[0].provenance, "sbousseaden_evtx-attack-samples")


class WorklistTests(unittest.TestCase):
    def _sample(self, *, sha: str, hints, signals, findings, status="completed", provenance="sbousseaden_evtx-attack-samples", relative="x/y.evtx"):
        sample = Sample(
            path=Path(relative),
            relative_path=relative,
            provenance=provenance,
            size_bytes=1,
            sha256=sha,
            path_hints=hints,
        )
        return SampleResult(
            sample=sample,
            status=status,
            technique_signals=signals,
            technique_findings=findings,
            finding_count=len(findings),
            signal_count=len(signals),
            incident_count=len(findings),
            severity_counter=Counter(),
        )

    def test_missed_techniques_surface_in_worklist(self):
        sample = self._sample(sha="a", hints=["T1003", "T1018"], signals=["T1003"], findings=["T1003"])
        payload = build_worklist([sample.sample], [sample])
        techniques = {row["technique"]: row for row in payload["worklist"]}
        self.assertEqual(techniques["T1003"]["status"], "covered")
        self.assertEqual(techniques["T1018"]["status"], "missed")
        self.assertEqual(payload["summary"]["techniques_missed"], 1)

    def test_parent_technique_detection_counts_in_summary(self):
        sample = self._sample(
            sha="subtech",
            hints=["T1021"],
            signals=["T1021.004"],
            findings=["T1021.004"],
        )
        payload = build_worklist([sample.sample], [sample])

        row = next(item for item in payload["worklist"] if item["technique"] == "T1021")
        self.assertEqual(row["status"], "covered")
        self.assertEqual(payload["summary"]["techniques_missed"], 0)
        self.assertEqual(payload["summary"]["techniques_detected"], 2)
    def test_unprovenanced_samples_are_excluded(self):
        sample = self._sample(sha="a", hints=["T1003"], signals=["T1003"], findings=[], provenance="")
        payload = build_worklist([sample.sample], [sample])
        self.assertEqual(payload["summary"]["samples_skipped_unprovenanced"], 1)
        self.assertEqual(payload["worklist"], [])

    def test_failed_samples_are_recorded(self):
        sample = self._sample(sha="a", hints=["T1003"], signals=[], findings=[], status="engine_error")
        sample.error = "boom"
        payload = build_worklist([sample.sample], [sample])
        self.assertEqual(payload["summary"]["samples_failed"], 1)
        self.assertEqual(len(payload["failed_samples"]), 1)

    def test_schema_version_is_emitted(self):
        sample = self._sample(sha="a", hints=[], signals=[], findings=[])
        payload = build_worklist([sample.sample], [sample])
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertEqual(payload["scanner"], "evtx-corpus-scan")

    def test_analyse_sample_uses_in_memory_summary_when_artifact_read_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = Sample(
                path=root / "sample.evtx",
                relative_path="sbousseaden_evtx-attack-samples/sample.evtx",
                provenance="sbousseaden_evtx-attack-samples",
                size_bytes=1,
                sha256="abc123",
                path_hints=["T1574.002"],
            )
            payload = {
                "runtime_seconds": 0.1,
                "case_path": str(root / "findings.json"),
                "analysis_summary": {
                    "schema_version": "1.0",
                    "signal_count": 2,
                    "finding_count": 1,
                    "incident_count": 1,
                    "parsed_event_count": 4,
                    "signal_techniques": ["T1574.002"],
                    "finding_techniques": ["T1574.002"],
                    "severity_counter": {"high": 3},
                },
            }
            with patch("scripts.evtx_corpus_scan._run_engine_for_sample", return_value=(payload, "completed", "")):
                result = analyse_sample(sample, cases_root=root)

            self.assertEqual(result.status, "completed")
            self.assertEqual(result.signal_count, 2)
            self.assertEqual(result.finding_count, 1)
            self.assertEqual(result.technique_findings, ["T1574.002"])
            self.assertIn("in-memory analysis summary", result.error)


class RenderTests(unittest.TestCase):
    def test_markdown_contains_summary_and_table(self):
        sample = Sample(
            path=Path("a.evtx"),
            relative_path="a.evtx",
            provenance="sbousseaden_evtx-attack-samples",
            size_bytes=1,
            sha256="h",
            path_hints=["T1003"],
        )
        result = SampleResult(
            sample=sample,
            status="completed",
            technique_signals=[],
            technique_findings=[],
            finding_count=0,
            signal_count=0,
            incident_count=0,
            severity_counter=Counter(),
        )
        payload = build_worklist([sample], [result])
        md = render_markdown(payload)
        self.assertIn("EVTX corpus coverage scan", md)
        self.assertIn("| Technique | Status |", md)
        self.assertIn("T1003", md)


class SampleSerializationTests(unittest.TestCase):
    def test_to_dict_is_json_safe(self):
        sample = Sample(
            path=Path("a.evtx"),
            relative_path="a.evtx",
            provenance="sbousseaden_evtx-attack-samples",
            size_bytes=1,
            sha256="abc",
            path_hints=["T1003"],
        )
        payload = sample.to_dict()
        # Should be JSON-roundtrippable.
        json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
