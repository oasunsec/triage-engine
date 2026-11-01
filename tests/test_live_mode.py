import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from parser import live_reader
from parser.live_reader import classify_live_channel_error
import server
from corrobora import service
from corrobora.service import (
    InvestigationRequest,
    _apply_live_progress_update,
    _build_live_collection_summary,
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
    def test_channel_error_classifier_handles_real_win32_message_forms(self):
        self.assertEqual(classify_live_channel_error("The required privilege is not held by the client."), "access_denied")
        self.assertEqual(classify_live_channel_error("Access is denied."), "access_denied")
        self.assertEqual(classify_live_channel_error("pywintypes.error: (5, 'EvtQuery', 'Access is denied.')"), "access_denied")
        self.assertEqual(classify_live_channel_error("WinError 5: Access is denied"), "access_denied")
        self.assertEqual(classify_live_channel_error(type("Err", (OSError,), {"args": (5, "EvtQuery", "Foo")})(
            (5, "EvtQuery", "Foo")
        )), "access_denied")
        self.assertEqual(classify_live_channel_error(type("Err2", (OSError,), {"args": (2, "EvtQuery", "Foo")})(
            (2, "EvtQuery", "Foo")
        )), "not_found")
        self.assertEqual(classify_live_channel_error("The specified channel could not be found."), "not_found")
        self.assertEqual(classify_live_channel_error("WinError 2: The system cannot find the file specified"), "not_found")
        self.assertEqual(classify_live_channel_error("A transient service timeout occurred"), "error")

    def test_server_probe_classifies_localized_win32_denied_error_by_code(self):
        localized_error = type("LocalizedDeniedError", (Exception,), {})
        fake_evt = mock.Mock()
        fake_evt.EvtQueryChannelPath = 1
        fake_evt.EvtQueryReverseDirection = 2
        fake_evt.EvtQuery.side_effect = localized_error(5, "EvtQuery", "Accès refusé.")

        with mock.patch.object(server.os, "name", "nt"):
            with mock.patch.dict(sys.modules, {"win32evtlog": fake_evt}):
                result = server._probe_live_channel("Security")

        self.assertEqual(result["status"], "access_denied")
        self.assertFalse(result["readable"])

    def test_read_live_emits_numeric_code_with_terminal_localized_failure(self):
        updates = []
        localized_error = type("LocalizedDeniedError", (Exception,), {})

        with mock.patch.object(live_reader, "HAS_WIN32", True):
            with mock.patch.object(
                live_reader,
                "_read_legacy",
                side_effect=localized_error(5, "EvtQuery", "Accès refusé."),
            ):
                with mock.patch.object(live_reader, "win32evtlog", create=True) as mock_evt:
                    mock_evt.EvtQueryChannelPath = 1
                    mock_evt.EvtQueryReverseDirection = 2
                    mock_evt.EvtQuery.return_value = "qh"
                    mock_evt.EvtNext.side_effect = RuntimeError("query stopped")
                    mock_evt.EvtRenderEventXml = 3

                    live_reader.read_live(["Security"], progress_callback=updates.append)

        terminal = next(update for update in updates if update["status"] == "channel_error")
        self.assertEqual(terminal["win32_code"], 5)
        self.assertIn("Accès refusé", terminal["error"])

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

    def test_read_live_emits_numeric_code_on_denied_evtquery_fallback(self):
        updates = []
        localized_error = type("LocalizedDeniedError", (Exception,), {})

        with mock.patch.object(live_reader, "HAS_WIN32", True):
            with mock.patch.object(live_reader, "_read_legacy", return_value=[]) as legacy:
                with mock.patch.object(live_reader, "win32evtlog", create=True) as mock_evt:
                    mock_evt.EvtQueryChannelPath = 1
                    mock_evt.EvtQueryReverseDirection = 2
                    mock_evt.EvtQuery.side_effect = localized_error(5, "EvtQuery", "Accès refusé.")

                    live_reader.read_live(["Security"], progress_callback=updates.append)

        legacy.assert_called_once()
        warning = next(update for update in updates if update["status"] == "channel_warning")
        self.assertEqual(warning["win32_code"], 5)

    def test_read_live_uses_legacy_when_first_evtnext_poll_fails(self):
        updates = []

        with mock.patch.object(live_reader, "HAS_WIN32", True):
            with mock.patch.object(live_reader, "_read_legacy", return_value=[]) as legacy:
                with mock.patch.object(live_reader, "win32evtlog", create=True) as mock_evt:
                    mock_evt.EvtQueryChannelPath = 1
                    mock_evt.EvtQueryReverseDirection = 2
                    mock_evt.EvtQuery.return_value = "qh"
                    mock_evt.EvtNext.side_effect = RuntimeError("query stopped")
                    mock_evt.EvtRenderEventXml = 3
                    mock_evt.EvtClose.return_value = None

                    events = live_reader.read_live(["Security"], progress_callback=updates.append)

        self.assertEqual(events, [])
        legacy.assert_called_once()
        statuses = [update["status"] for update in updates]
        self.assertIn("channel_warning", statuses)
        complete = next(update for update in updates if update["status"] == "channel_complete")
        self.assertEqual(complete["fallback"], True)
        self.assertEqual(complete["failed"], False)
        self.assertEqual(complete["completed_channels"], 1)

    def test_read_live_marks_partial_when_poll_stops_after_successful_batch(self):
        updates = []
        synthetic_event = make_event(
            4634,
            computer="workstation1",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
        )

        with mock.patch.object(live_reader, "HAS_WIN32", True):
            with mock.patch.object(live_reader, "_parse_record", return_value=synthetic_event):
                with mock.patch.object(live_reader, "win32evtlog", create=True) as mock_evt:
                    mock_evt.EvtQueryChannelPath = 1
                    mock_evt.EvtQueryReverseDirection = 2
                    mock_evt.EvtRenderEventXml = 3
                    mock_evt.EvtQuery.return_value = "qh"
                    mock_evt.EvtNext.side_effect = [[mock.Mock()], RuntimeError("query reset")]
                    mock_evt.EvtRender.return_value = "<Event />"

                    events = live_reader.read_live(["Security"], progress_callback=updates.append)

        self.assertEqual(len(events), 1)
        statuses = [update["status"] for update in updates]
        self.assertIn("channel_warning", statuses)
        warning = next(update for update in updates if update["status"] == "channel_warning")
        self.assertIn("stopped early", warning["message"])
        complete = next(update for update in updates if update["status"] == "channel_complete")
        self.assertTrue(complete["partial"])
        self.assertFalse(complete["failed"])
        self.assertEqual(complete["completed_channels"], 1)

    def test_read_live_does_not_count_failed_channel_as_completed_or_fallback(self):
        updates = []

        with mock.patch.object(live_reader, "HAS_WIN32", True):
            with mock.patch.object(live_reader, "_read_legacy", side_effect=RuntimeError("denied")) as legacy:
                with mock.patch.object(live_reader, "win32evtlog", create=True) as mock_evt:
                    mock_evt.EvtQueryChannelPath = 1
                    mock_evt.EvtQueryReverseDirection = 2
                    mock_evt.EvtQuery.return_value = "qh"
                    mock_evt.EvtNext.side_effect = RuntimeError("denied")
                    mock_evt.EvtRenderEventXml = 3

                    events = live_reader.read_live(["System"], progress_callback=updates.append)

        self.assertEqual(events, [])
        legacy.assert_called_once()
        statuses = [update["status"] for update in updates]
        self.assertIn("channel_error", statuses)
        complete = next(update for update in updates if update["status"] == "channel_complete")
        self.assertEqual(complete["failed"], True)
        self.assertEqual(complete["fallback"], False)
        self.assertEqual(complete["completed_channels"], 0)

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
            "failed_channels": [],
            "failed_errors": {},
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

    def test_failed_channel_is_not_counted_as_successful_fallback(self):
        live_progress = {
            "completed_channels": 0,
            "channel_count": 0,
            "parsed_event_count": 0,
            "last_channel": "",
            "active_channel": "",
            "fallback_channels": 0,
            "warning_count": 0,
            "warning_channels": [],
            "failed_channels": [],
            "failed_errors": {},
            "last_warning": "",
            "channels": [],
            "since_minutes": 30,
        }
        _apply_live_progress_update(
            live_progress,
            {
                "status": "channel_complete",
                "channel": "Security",
                "completed_channels": 0,
                "channel_count": 1,
                "parsed_events": 0,
                "fallback": True,
                "failed": True,
            },
        )
        self.assertEqual(live_progress["fallback_channels"], 0)
        self.assertEqual(live_progress["failed_channels"], ["Security"])

    def test_failed_channel_localized_error_classifies_by_numeric_code(self):
        live_progress = {
            "completed_channels": 0,
            "channel_count": 1,
            "parsed_event_count": 0,
            "last_channel": "",
            "active_channel": "",
            "fallback_channels": 0,
            "warning_count": 1,
            "warning_channels": ["Security"],
            "partial_channels": [],
            "failed_channels": [],
            "failed_errors": {},
            "failed_codes": {},
            "last_warning": "",
            "channels": ["Security"],
            "since_minutes": 30,
        }
        _apply_live_progress_update(
            live_progress,
            {
                "status": "channel_error",
                "channel": "Security",
                "message": "Event log channel 'Security' could not be read (Accès refusé.)",
                "error": "Accès refusé.",
                "win32_code": 5,
            },
        )
        summary = _build_live_collection_summary(live_progress, [])
        self.assertEqual(summary["permission_denied_channels"], ["Security"])
        self.assertEqual(summary["unavailable_channels"], [])
        self.assertIn("Permission issues detected on: Security", summary["summary"])
        self.assertTrue(any("elevated privileges" in item for item in summary["recommendations"]))

    def test_partial_channel_is_tracked_but_not_failed_or_fallback(self):
        live_progress = {
            "completed_channels": 0,
            "channel_count": 0,
            "parsed_event_count": 0,
            "last_channel": "",
            "active_channel": "",
            "fallback_channels": 0,
            "warning_count": 0,
            "warning_channels": [],
            "partial_channels": [],
            "failed_channels": [],
            "failed_errors": {},
            "last_warning": "",
            "channels": [],
            "since_minutes": 30,
        }
        _apply_live_progress_update(
            live_progress,
            {
                "status": "channel_complete",
                "channel": "System",
                "completed_channels": 1,
                "channel_count": 1,
                "parsed_events": 3,
                "partial": True,
                "failed": False,
            },
        )
        self.assertEqual(live_progress["partial_channels"], ["System"])
        self.assertEqual(live_progress["fallback_channels"], 0)
        self.assertEqual(live_progress["failed_channels"], [])
        self.assertEqual(live_progress["completed_channels"], 1)

    def test_denied_api_fallbacks_are_reported_as_permission_limited(self):
        live_progress = {
            "completed_channels": 1,
            "channel_count": 1,
            "parsed_event_count": 0,
            "last_channel": "",
            "active_channel": "",
            "fallback_channels": 1,
            "warning_count": 1,
            "warning_channels": ["Security"],
            "partial_channels": [],
            "failed_channels": [],
            "failed_errors": {},
            "failed_codes": {},
            "fallback_failed_codes": {},
            "last_warning": "",
            "channels": ["Security"],
            "since_minutes": 30,
        }
        _apply_live_progress_update(
            live_progress,
            {
                "status": "channel_warning",
                "channel": "Security",
                "message": "EvtQuery failed for 'Security', trying legacy API",
                "win32_code": 5,
            },
        )
        summary = _build_live_collection_summary(live_progress, [])
        self.assertEqual(summary["fallback_permission_channels"], ["Security"])
        self.assertIn("Legacy fallback used after denied API access", summary["summary"])
        self.assertTrue(any("elevation" in item for item in summary["recommendations"]))

        public = _public_live_progress(live_progress)
        self.assertNotIn("fallback_failed_codes", public)
        self.assertNotIn("failed_codes", public)
        self.assertNotIn("failed_errors", public)

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
        self.assertFalse(any("elevated privileges" in item for item in reporter.metadata["live_collection_summary"]["recommendations"]))
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
        self.assertEqual(live_summary["permission_denied_channels"], [])
        self.assertEqual(live_summary["unavailable_channels"], [])
        self.assertIn("Live collection scanned 2 channel(s)", live_summary["summary"])
        self.assertEqual(len(live_summary["recommendations"]), 3)
        self.assertEqual(collection_summary["warning_sources"], ["Security"])
        self.assertEqual(collection_summary["permission_denied_sources"], [])
        self.assertEqual(collection_summary["telemetry_missing"], ["Sysmon", "PowerShell"])

        summary_txt = (temp_root / "live-defaults" / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("Collection Quality Summary:", summary_txt)
        self.assertIn("Collection Warning Sources: Security", summary_txt)
        self.assertIn("Collection Recommendations:", summary_txt)

        brief_md = (temp_root / "live-defaults" / "incident_brief.md").read_text(encoding="utf-8")
        self.assertIn("## Collection Quality", brief_md)
        self.assertIn("Permission denied sources: None", brief_md)
        self.assertIn("Recommendation:", brief_md)
        self.assertNotIn("Isolate impacted hosts and preserve volatile evidence.", brief_md)
        self.assertIn("Enable or collect Sysmon telemetry", brief_md)


class LivePartialReadTests(unittest.TestCase):
    """A channel that stops after a successful batch is partial, not failed."""

    def test_partial_read_is_surfaced_and_does_not_hide_telemetry(self):
        temp_root = Path(tempfile.mkdtemp(prefix="triage-live-partial-"))
        self.addCleanup(shutil.rmtree, temp_root, True)
        reporter = _CollectingReporter()

        def fake_read_live(channels, since_minutes, progress_callback=None):
            if progress_callback:
                progress_callback({"status": "start", "channel_count": 1, "channels": ["Security"], "since_minutes": 30})
                progress_callback({"status": "channel_started", "channel": "Security", "channel_index": 1, "channel_count": 1})
                progress_callback({"status": "channel_warning", "channel": "Security", "message": "Live channel 'Security' stopped early after 2 parsed event(s): query reset"})
                progress_callback({"status": "channel_complete", "channel": "Security", "channel_index": 1, "completed_channels": 1, "channel_count": 1, "parsed_events": 2, "partial": True, "failed": False})
                progress_callback({"status": "complete", "event_count": 2, "channel_count": 1, "channels": ["Security"], "since_minutes": 30})
            return []

        request = InvestigationRequest(
            input_source="live",
            input_mode="live",
            case_name="live-partial",
            cases_dir=str(temp_root),
            channels=["Security"],
            since_minutes=30,
        )

        with mock.patch.object(service, "read_live", side_effect=fake_read_live):
            result = run_investigation(request, reporter)

        live_summary = result.collection_quality_summary
        self.assertEqual(live_summary["completed_source_count"], 1)
        self.assertEqual(live_summary["partial_sources"], ["Security"])
        self.assertIn("Security", live_summary["warning_sources"])
        self.assertNotIn("Security", live_summary["telemetry_missing"])
        self.assertIn("Sysmon", live_summary["telemetry_missing"])
        self.assertIn("Partial reads: Security", live_summary["summary"])

        summary_txt = (temp_root / "live-partial" / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("Collection Partial Sources: Security", summary_txt)

        brief_md = (temp_root / "live-partial" / "incident_brief.md").read_text(encoding="utf-8")
        self.assertIn("- Partial sources: Security", brief_md)


class LiveFailureChannelTests(unittest.TestCase):
    """A channel that fails both modern and legacy APIs is truly unreadable."""

    def test_dual_failure_is_tracked_as_failed_and_missing(self):
        temp_root = Path(tempfile.mkdtemp(prefix="triage-live-failed-"))
        self.addCleanup(shutil.rmtree, temp_root, True)
        reporter = _CollectingReporter()

        def fake_read_live(channels, since_minutes, progress_callback=None):
            if progress_callback:
                progress_callback(
                    {
                        "status": "start",
                        "channel_count": 1,
                        "channels": ["Security"],
                        "since_minutes": 30,
                    }
                )
                progress_callback(
                    {
                        "status": "channel_started",
                        "channel": "Security",
                        "channel_index": 1,
                        "channel_count": 1,
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
                        "status": "channel_error",
                        "channel": "Security",
                        "message": "Event log channel 'Security' could not be read (Access is denied.)",
                        "error": "Access is denied.",
                    }
                )
                progress_callback(
                    {
                        "status": "channel_complete",
                        "channel": "Security",
                        "channel_index": 1,
                        "completed_channels": 0,
                        "channel_count": 1,
                        "parsed_events": 0,
                        "fallback": True,
                        "failed": True,
                    }
                )
                progress_callback(
                    {
                        "status": "complete",
                        "event_count": 0,
                        "channel_count": 1,
                        "channels": ["Security"],
                        "since_minutes": 30,
                    }
                )
            return []

        request = InvestigationRequest(
            input_source="live",
            input_mode="live",
            case_name="live-failed",
            cases_dir=str(temp_root),
            channels=["Security"],
            since_minutes=30,
        )

        with mock.patch.object(service, "read_live", side_effect=fake_read_live):
            result = run_investigation(request, reporter)

        live_summary = result.collection_quality_summary
        self.assertEqual(live_summary["permission_denied_sources"], ["Security"])
        self.assertEqual(live_summary["unavailable_sources"], [])
        self.assertEqual(live_summary["telemetry_missing"], ["Security", "Sysmon", "PowerShell"])
        self.assertEqual(result.collection_quality_summary["completed_source_count"], 0)
        self.assertTrue(any("elevated privileges" in item for item in live_summary["recommendations"]))


    def test_non_permission_failure_is_reported_as_unavailable(self):
        temp_root = Path(tempfile.mkdtemp(prefix="triage-live-unavailable-"))
        self.addCleanup(shutil.rmtree, temp_root, True)
        reporter = _CollectingReporter()

        def fake_read_live(channels, since_minutes, progress_callback=None):
            if progress_callback:
                progress_callback({"status": "start", "channel_count": 1, "channels": ["System"], "since_minutes": 30})
                progress_callback({"status": "channel_started", "channel": "System", "channel_index": 1, "channel_count": 1})
                progress_callback({"status": "channel_warning", "channel": "System", "message": "EvtQuery failed for 'System', trying legacy API: Channel not found."})
                progress_callback({"status": "channel_error", "channel": "System", "message": "Event log channel 'System' could not be read (Channel not found.)", "error": "The specified channel could not be found."})
                progress_callback({"status": "channel_complete", "channel": "System", "channel_index": 1, "completed_channels": 0, "channel_count": 1, "parsed_events": 0, "fallback": True, "failed": True})
                progress_callback({"status": "complete", "event_count": 0, "channel_count": 1, "channels": ["System"], "since_minutes": 30})
            return []

        request = InvestigationRequest(input_source="live", input_mode="live", case_name="live-unavailable", cases_dir=str(temp_root), channels=["System"], since_minutes=30)
        with mock.patch.object(service, "read_live", side_effect=fake_read_live):
            result = run_investigation(request, reporter)

        live_summary = result.collection_quality_summary
        self.assertEqual(live_summary["permission_denied_sources"], [])
        self.assertEqual(live_summary["unavailable_sources"], ["System"])
        self.assertIn("Unreadable channels", live_summary["summary"])
        self.assertTrue(any("could not be read" in item for item in live_summary["recommendations"]))
        summary_txt = (temp_root / "live-unavailable" / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("Collection Unavailable Sources: System", summary_txt)
        brief_md = (temp_root / "live-unavailable" / "incident_brief.md").read_text(encoding="utf-8")
        self.assertIn("Unavailable sources: System", brief_md)


if __name__ == "__main__":
    unittest.main()
