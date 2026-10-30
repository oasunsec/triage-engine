import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from models.event_model import Alert, NormalizedEvent
from parser import evtx_reader
from triage_engine.adapters import alerts_to_signals_findings


ROOT = Path(__file__).resolve().parents[1]
TEST_OUTPUT = ROOT / "runtime" / "test-output"


class EventSourceBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TEST_OUTPUT.mkdir(parents=True, exist_ok=True)

    def _event(self):
        return NormalizedEvent(event_id=1, timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))

    def test_retained_source_files_are_parsed_and_bound_without_changing_input_mode(self):
        with tempfile.TemporaryDirectory(dir=TEST_OUTPUT) as folder:
            original = Path(folder) / "original.evtx"
            retained = Path(folder) / "retained.evtx"
            original.touch()
            retained.touch()
            event = self._event()
            updates = []
            with patch.object(evtx_reader, "read_evtx", return_value=[event]) as mocked:
                result = evtx_reader.read_evtx_path(
                    str(original), progress_callback=updates.append, source_files=[str(retained)]
                )

        self.assertEqual(result, [event])
        mocked.assert_called_once()
        self.assertEqual(Path(mocked.call_args.args[0]), retained.resolve())
        self.assertEqual(event.source_file, str(retained.resolve()))
        self.assertEqual(updates[0]["mode"], "file")
        self.assertEqual(updates[0]["path"], str(original.resolve()))
        self.assertEqual(updates[0]["files"], [str(retained.resolve())])

    def test_original_directory_files_are_bound_and_string_mocks_are_preserved(self):
        with tempfile.TemporaryDirectory(dir=TEST_OUTPUT) as folder:
            source = Path(folder) / "one.evtx"
            source.touch()
            event = self._event()
            with patch.object(evtx_reader, "read_evtx", return_value=[event]):
                parsed = evtx_reader.read_evtx_path(folder)
            self.assertEqual(parsed, [event])
            self.assertEqual(event.source_file, str(source.resolve()))

            with patch.object(evtx_reader, "read_evtx", return_value=["mock-event"]):
                mocked_events = evtx_reader.read_evtx_path(
                    str(source), source_files=[str(source)]
                )
            self.assertEqual(mocked_events, ["mock-event"])


class AdapterProvenanceTests(unittest.TestCase):
    def _alert(self, event=None, evidence=None):
        return Alert(
            rule_name="Source provenance test",
            severity="high",
            mitre_tactic="Execution",
            mitre_technique="T1059",
            description="test",
            explanation="test explanation",
            event=event,
            evidence=evidence or {},
            confidence="high",
            promotion_policy="standalone",
        )

    def test_source_references_flow_to_signal_and_finding_evidence_and_identity(self):
        event = NormalizedEvent(
            event_id=4688,
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            source_file="evidence/a.evtx",
            source_sha256="a" * 64,
            record_id="42",
            observation_id="obs_abc",
        )
        signals, findings, _ = alerts_to_signals_findings([self._alert(event)])

        expected = {
            "observation_id": "obs_abc",
            "source_file": "evidence/a.evtx",
            "source_sha256": "a" * 64,
            "record_id": "42",
        }
        self.assertEqual({key: signals[0].evidence[key] for key in expected}, expected)
        self.assertEqual({key: findings[0].evidence[key] for key in expected}, expected)
        self.assertEqual(signals[0].command_line, "")

        event.observation_id = "obs_other"
        changed_signals, _, _ = alerts_to_signals_findings([self._alert(event)])
        self.assertNotEqual(signals[0].id, changed_signals[0].id)

    def test_legacy_eventless_command_line_uses_evidence_and_has_no_added_refs(self):
        alert = self._alert(evidence={"command_line": "whoami /all"})
        self.assertEqual(alert.to_dict()["command_line"], "whoami /all")
        signals, _, _ = alerts_to_signals_findings([alert])
        self.assertEqual(signals[0].command_line, "whoami /all")
        self.assertNotIn("source_file", signals[0].evidence)
        self.assertNotIn("observation_id", signals[0].evidence)


if __name__ == "__main__":
    unittest.main()
