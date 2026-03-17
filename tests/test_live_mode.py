import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from parser import live_reader
from triage_engine import service
from triage_engine.service import (
    InvestigationRequest,
    _apply_live_progress_update,
    _public_live_progress,
    run_investigation,
)

from tests.test_regressions import make_event


class _CollectingReporter:
    def __init__(self):
        self.metadata = {}
        self.stages = []

    def on_stage(self, stage, message):
        self.stages.append((stage, message))

    def on_metadata(self, key, value):
        self.metadata[key] = value

    def on_artifact(self, path):
        pass

    def on_diagnostic(self, message):
        pass

    def on_complete(self, message):
        pass

    def on_failed(self, stage, error, traceback_text=None):
        pass

    def on_parse_progress(self, update):
        pass


class LiveModeTests(unittest.TestCase):
    def test_read_live_raises_runtime_error_without_pywin32(self):
        with mock.patch.object(live_reader, "HAS_WIN32", False):
            with self.assertRaisesRegex(RuntimeError, "pywin32"):
                live_reader.read_live(["Security"])

    def test_read_live_reports_progress_and_defaults_to_30_minutes(self):
        updates = []
        synthetic_event = make_event(
            4634,
            computer="workstation1",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
        )
        fake_evt = mock.Mock()

        with mock.patch.object(live_reader, "HAS_WIN32", True):
            with mock.patch.object(live_reader, "_parse_record", return_value=synthetic_event):
                with mock.patch.object(live_reader, "win32evtlog", create=True) as mock_evt:
                    mock_evt.EvtQueryChannelPath = 1
                    mock_evt.EvtQueryReverseDirection = 2
                    mock_evt.EvtRenderEventXml = 3
                    mock_evt.EvtQuery.return_value = "qh"
                    mock_evt.EvtNext.side_effect = [[fake_evt], []]
                    mock_evt.EvtRender.return_value = "<Event />"

                    events = live_reader.read_live(["Security"], progress_callback=updates.append)

        self.assertEqual(len(events), 1)
        self.assertEqual([update["status"] for update in updates], ["start", "channel_started", "channel_complete", "complete"])
        self.assertEqual(updates[0]["since_minutes"], 30)
        self.assertEqual(updates[1]["channel"], "Security")
        self.assertEqual(updates[2]["parsed_events"], 1)
        self.assertEqual(updates[3]["event_count"], 1)

    def test_read_live_emits_channel_warning_on_evtquery_fallback(self):
        updates = []

        with mock.patch.object(live_reader, "HAS_WIN32", True):
            with mock.patch.object(live_reader, "_read_legacy", return_value=[]):
                with mock.patch.object(live_reader, "win32evtlog", create=True) as mock_evt:
                    mock_evt.EvtQueryChannelPath = 1
                    mock_evt.EvtQueryReverseDirection = 2
                    mock_evt.EvtQuery.side_effect = RuntimeError("Access is denied.")

                    events = live_reader.read_live(["Security"], progress_callback=updates.append)

        self.assertEqual(events, [])
        statuses = [update["status"] for update in updates]
        self.assertIn("channel_warning", statuses)
        warning = next(update for update in updates if update["status"] == "channel_warning")
        self.assertEqual(warning["channel"], "Security")
        self.assertIn("trying legacy API", warning["message"])

    def test_live_progress_helpers_track_channel_counts(self):
        live_progress = {
            "completed_channels": 0,
            "channel_count": 0,
            "parsed_event_count": 0,
            "last_channel": "",
            "active_channel": "",
            "fallback_channels": 0,
            "warning_count": 0,
            "warning_channels": [],
            "last_warning": "",
            "channels": [],
            "since_minutes": 30,
        }

        _apply_live_progress_update(
            live_progress,
            {
                "status": "start",
                "channel_count": 2,
                "channels": ["Security", "System"],
                "since_minutes": 45,
            },
        )
        _apply_live_progress_update(
            live_progress,
            {"status": "channel_started", "channel": "Security", "channel_index": 1, "channel_count": 2},
        )
        _apply_live_progress_update(
            live_progress,
            {
                "status": "channel_warning",
                "channel": "Security",
                "message": "EvtQuery failed for 'Security', trying legacy API: Access is denied.",
            },
        )
        _apply_live_progress_update(
            live_progress,
            {
                "status": "channel_complete",
                "channel": "Security",
                "completed_channels": 1,
                "channel_count": 2,
                "parsed_events": 7,
                "fallback": True,
            },
        )
        _apply_live_progress_update(
            live_progress,
            {
                "status": "complete",
                "event_count": 7,
                "channel_count": 2,
                "channels": ["Security", "System"],
                "since_minutes": 45,
            },
        )

        public_progress = _public_live_progress(live_progress)
        self.assertEqual(public_progress["completed_channels"], 1)
        self.assertEqual(public_progress["channel_count"], 2)
        self.assertEqual(public_progress["parsed_event_count"], 7)
        self.assertEqual(public_progress["last_channel"], "Security")
        self.assertEqual(public_progress["fallback_channels"], 1)
        self.assertEqual(public_progress["warning_count"], 1)
        self.assertEqual(public_progress["warning_channels"], ["Security"])
        self.assertIn("trying legacy API", public_progress["last_warning"])
        self.assertEqual(public_progress["since_minutes"], 45)

    def test_run_investigation_live_defaults_since_minutes_and_persists_metadata(self):
        temp_root = Path(tempfile.mkdtemp(prefix="triage-live-service-"))
        self.addCleanup(shutil.rmtree, temp_root, True)
        reporter = _CollectingReporter()

        def fake_read_live(channels, since_minutes, progress_callback=None):
            self.assertEqual(channels, ["Security", "System"])
            self.assertEqual(since_minutes, 30)
            if progress_callback:
                progress_callback(
                    {
                        "status": "start",
                        "channel_count": 2,
                        "channels": ["Security", "System"],
                        "since_minutes": since_minutes,
                    }
                )
                progress_callback(
                    {
                        "status": "channel_started",
                        "channel": "Security",
                        "channel_index": 1,
                        "channel_count": 2,
                    }
                )
                progress_callback(
                    {
                        "status": "channel_warning",
                        "channel": "Security",
                        "message": "EvtQuery failed for 'Security', trying legacy API: Access is denied.",
                    }
                )
                progress_callback(
                    {
                        "status": "channel_complete",
                        "channel": "Security",
                        "completed_channels": 1,
                        "channel_count": 2,
                        "parsed_events": 0,
                        "fallback": False,
                    }
                )
                progress_callback(
                    {
                        "status": "channel_started",
                        "channel": "System",
                        "channel_index": 2,
                        "channel_count": 2,
                    }
                )
                progress_callback(
                    {
                        "status": "channel_complete",
                        "channel": "System",
                        "completed_channels": 2,
                        "channel_count": 2,
                        "parsed_events": 0,
                        "fallback": False,
                    }
                )
                progress_callback(
                    {
                        "status": "complete",
                        "event_count": 0,
                        "channel_count": 2,
                        "channels": ["Security", "System"],
                        "since_minutes": since_minutes,
                    }
                )
            return []

        request = InvestigationRequest(
            input_source="live",
            input_mode="live",
            case_name="live-defaults",
            cases_dir=str(temp_root),
            channels=["Security", "System"],
            since_minutes=None,
        )

        with mock.patch.object(service, "read_live", side_effect=fake_read_live):
            result = run_investigation(request, reporter)

        self.assertEqual(result.case_name, "live-defaults")
        self.assertEqual(result.signal_count, 0)
        self.assertEqual(result.finding_count, 0)
        self.assertEqual(result.incident_count, 0)
        self.assertEqual(result.collection_quality_summary["mode"], "live")
        self.assertEqual(result.collection_quality_summary["warning_sources"], ["Security"])
        self.assertEqual(reporter.metadata["live_profile"]["since_minutes"], 30)
        self.assertEqual(reporter.metadata["live_progress"]["completed_channels"], 2)
        self.assertEqual(reporter.metadata["live_progress"]["last_channel"], "System")
        self.assertEqual(reporter.metadata["live_progress"]["warning_count"], 1)
        self.assertEqual(reporter.metadata["live_progress"]["warning_channels"], ["Security"])
        self.assertIn("Live collection scanned 2 channel(s)", reporter.metadata["live_collection_summary"]["summary"])
        self.assertIn("Live collection scanned 2 channel(s)", reporter.metadata["collection_quality_summary"]["summary"])
        self.assertTrue(any("elevated privileges" in item for item in reporter.metadata["live_collection_summary"]["recommendations"]))
        self.assertTrue(any("Sysmon telemetry" in item for item in reporter.metadata["live_collection_summary"]["recommendations"]))
        self.assertTrue(any("PowerShell Operational logging" in item for item in reporter.metadata["live_collection_summary"]["recommendations"]))

        run_status = json.loads((temp_root / "live-defaults" / "run_status.json").read_text(encoding="utf-8"))
        self.assertEqual(run_status["status"], "completed")
        self.assertEqual(run_status["metadata"]["live_profile"]["since_minutes"], 30)
        self.assertEqual(run_status["metadata"]["live_progress"]["channel_count"], 2)
        self.assertEqual(run_status["metadata"]["live_progress"]["completed_channels"], 2)
        self.assertEqual(run_status["metadata"]["live_progress"]["warning_count"], 1)
        self.assertEqual(len(run_status["diagnostics"]), 1)
        self.assertIn("trying legacy API", run_status["diagnostics"][0]["message"])
        self.assertEqual(run_status["metadata"]["live_collection_summary"]["warning_channels"], ["Security"])
        self.assertEqual(run_status["metadata"]["collection_quality_summary"]["warning_sources"], ["Security"])

        findings_json = json.loads((temp_root / "live-defaults" / "findings.json").read_text(encoding="utf-8"))
        live_summary = findings_json["summary"]["live_collection_summary"]
        collection_summary = findings_json["summary"]["collection_quality_summary"]
        self.assertEqual(live_summary["warning_channels"], ["Security"])
        self.assertEqual(live_summary["permission_denied_channels"], ["Security"])
        self.assertIn("Live collection scanned 2 channel(s)", live_summary["summary"])
        self.assertEqual(len(live_summary["recommendations"]), 3)
        self.assertEqual(collection_summary["warning_sources"], ["Security"])
        self.assertEqual(collection_summary["permission_denied_sources"], ["Security"])
        self.assertEqual(collection_summary["telemetry_missing"], ["Security", "Sysmon", "PowerShell"])

        summary_txt = (temp_root / "live-defaults" / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("Collection Quality Summary:", summary_txt)
        self.assertIn("Collection Warning Sources: Security", summary_txt)
        self.assertIn("Collection Recommendations:", summary_txt)

        brief_md = (temp_root / "live-defaults" / "incident_brief.md").read_text(encoding="utf-8")
        self.assertIn("## Collection Quality", brief_md)
        self.assertIn("Permission denied sources: Security", brief_md)
        self.assertIn("Recommendation:", brief_md)
        self.assertNotIn("Isolate impacted hosts and preserve volatile evidence.", brief_md)
        self.assertIn("Enable or collect Sysmon telemetry", brief_md)


if __name__ == "__main__":
    unittest.main()
