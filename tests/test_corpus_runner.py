"""Focused tests for the batched competitive corpus runner."""

from __future__ import annotations

import importlib.util
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "competitive_eval.py"
SPEC = importlib.util.spec_from_file_location("competitive_eval", MODULE_PATH)
assert SPEC and SPEC.loader
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


def _sample_row(
    *,
    returncode: int = 0,
    findings_present: bool = True,
    expectation: dict | None = None,
    expected: str = "informational",
    timed_out: bool = False,
) -> dict:
    return {
        "id": "sample-a",
        "path": "sample.evtx",
        "expected": expected,
        "triage": {
            "returncode": returncode,
            "timed_out": timed_out,
            "metrics": {"findings_present": findings_present, "case_path": "cases/sample-a"},
        },
        "expectation": expectation or {"expected": expected, "passed": True},
    }


class CorpusRunnerModelTests(unittest.TestCase):
    def test_output_is_bounded(self):
        value = corpus._cap_output("x" * 250_000)
        self.assertIn("truncated", value)
        self.assertLess(len(value), 210_000)

    def test_timeout_is_recorded_as_retryable_failure(self):
        row = _sample_row(returncode=-9, timed_out=True)
        self.assertFalse(corpus._sample_is_complete(row))
        self.assertTrue(corpus._sample_needs_retry(row))

    def test_completed_expected_sample_requires_passed_expectation(self):
        row = _sample_row(expected="malicious", expectation={"passed": False})
        self.assertFalse(corpus._sample_is_complete(row))
        self.assertTrue(corpus._sample_needs_retry(row))

    def test_informational_sample_with_findings_is_complete(self):
        row = _sample_row(expected="informational")
        self.assertTrue(corpus._sample_is_complete(row))
        self.assertFalse(corpus._sample_needs_retry(row))

    def test_missing_findings_is_not_complete(self):
        row = _sample_row(findings_present=False)
        self.assertFalse(corpus._sample_is_complete(row))


def _empty_evtx() -> bytes:
    """A structurally valid EVTX with zero chunks; unreadable bytes now fail runs by design."""
    header = b"ElfFile\x00" + struct.pack("<QQQIHHHH", 0, 0, 1, 128, 1, 3, 4096, 0) + b"\x00" * 76
    header += struct.pack("<I", 0)
    header += struct.pack("<I", zlib.crc32(header[:120]) & 0xFFFFFFFF)
    return header + b"\x00" * (4096 - len(header))


class CorpusRunnerFixtureTests(unittest.TestCase):
    def test_runner_writes_expected_report_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            sample = root / "sample.evtx"
            sample.write_bytes(_empty_evtx())
            manifest.write_text(
                json.dumps(
                    {
                        "name": "unit-fixture",
                        "triage": {"cases_dir": str(root / "cases")},
                        "samples": [
                            {
                                "id": "fixture-sample",
                                "path": str(sample),
                                "expected": "informational",
                                "tags": ["unit"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = root / "report.json"
            exit_code = corpus.main(
                [
                    "--manifest",
                    str(manifest),
                    "--report",
                    str(report),
                    "--run-name",
                    "corpus-unit-fixture",
                    "--cases-dir",
                    str(root / "fixture-cases"),
                    "--job-dir",
                    str(root / "jobs"),
                    "--skip-hayabusa",
                    "--id",
                    "fixture-sample",
                ]
            )
            self.assertEqual(exit_code, 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(payload["complete"])
            self.assertEqual(payload["scorecard"]["sample_count"], 1)
            self.assertEqual(payload["runner"]["selected_sample_count"], 1)
            self.assertEqual(payload["samples"][0]["expectation"]["expected"], "informational")

    def test_filter_by_id_skips_other_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            first = root / "first.evtx"
            second = root / "second.evtx"
            first.write_bytes(_empty_evtx())
            second.write_bytes(_empty_evtx())
            manifest.write_text(
                json.dumps(
                    {
                        "name": "unit-filter",
                        "triage": {"cases_dir": str(root / "cases")},
                        "samples": [
                            {"id": "keep-me", "path": str(first), "expected": "informational"},
                            {"id": "skip-me", "path": str(second), "expected": "informational"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = root / "filtered.json"
            exit_code = corpus.main(
                [
                    "--manifest",
                    str(manifest),
                    "--report",
                    str(report),
                    "--run-name",
                    "corpus-unit-filter",
                    "--cases-dir",
                    str(root / "fixture-cases"),
                    "--job-dir",
                    str(root / "jobs"),
                    "--skip-hayabusa",
                    "--id",
                    "keep-me",
                ]
            )
            self.assertEqual(exit_code, 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual([item["id"] for item in payload["samples"]], ["keep-me"])

    def test_unexpected_sample_exception_records_its_own_case_name(self):
        captured = {}

        def failing_run_sample(*args, **kwargs):
            index = args[0] if args else kwargs.get("index")
            sample = args[2] if len(args) > 2 else kwargs.get("sample")
            captured["index"] = index
            captured["sample_id"] = sample.get("id") if isinstance(sample, dict) else None
            raise RuntimeError("forced runner failure")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            first = root / "first.evtx"
            second = root / "second.evtx"
            first.write_bytes(_empty_evtx())
            second.write_bytes(_empty_evtx())
            manifest.write_text(
                json.dumps(
                    {
                        "name": "unit-failure-index",
                        "triage": {"cases_dir": str(root / "cases")},
                        "samples": [
                            {"id": "first-sample", "path": str(first), "expected": "informational"},
                            {"id": "second-sample", "path": str(second), "expected": "informational"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = root / "failure.json"
            original = corpus._run_sample
            corpus._run_sample = failing_run_sample
            try:
                exit_code = corpus.main(
                    [
                        "--manifest",
                        str(manifest),
                        "--report",
                        str(report),
                        "--run-name",
                        "corpus-unit-failure-index",
                        "--cases-dir",
                        str(root / "fixture-cases"),
                        "--job-dir",
                        str(root / "jobs"),
                        "--skip-hayabusa",
                        "--id",
                        "second-sample",
                    ]
                )
            finally:
                corpus._run_sample = original

            self.assertEqual(exit_code, 1)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(payload["complete"])
            self.assertEqual(payload["samples"][0]["id"], "second-sample")
            self.assertTrue(payload["samples"][0]["case_name"].endswith("second-sample"))
            self.assertEqual(captured["index"], 1)
            self.assertEqual(captured["sample_id"], "second-sample")


if __name__ == "__main__":
    unittest.main()
