import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from parser import evtx_reader
from triage_engine.cli import _apply_parse_progress_update, _public_parse_progress


class ParserParallelTests(unittest.TestCase):
    def test_directory_parse_preserves_sorted_file_order_with_parallel_workers(self):
        temp_dir = tempfile.mkdtemp(prefix="triage-evtx-dir-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        root = Path(temp_dir)
        (root / "b.evtx").write_text("", encoding="utf-8")
        (root / "a.evtx").write_text("", encoding="utf-8")
        (root / "notes.txt").write_text("ignore", encoding="utf-8")

        calls = []

        def fake_read_evtx(filepath, start_date=None, end_date=None, progress_callback=None):
            calls.append(Path(filepath).name)
            if progress_callback:
                progress_callback({"status": "file_started", "file_path": filepath})
                progress_callback({"status": "file_progress", "file_path": filepath, "records_scanned": 1, "parsed_events": 1, "skipped_records": 0})
            return [Path(filepath).stem]

        with mock.patch.object(evtx_reader, "read_evtx", side_effect=fake_read_evtx):
            with mock.patch.dict(
                os.environ,
                {
                    evtx_reader.PARSE_WORKERS_ENV: "2",
                    evtx_reader.PARSE_EXECUTOR_ENV: "thread",
                },
                clear=False,
            ):
                events = evtx_reader.read_evtx_path(str(root))

        self.assertEqual(calls, ["a.evtx", "b.evtx"])
        self.assertEqual(events, ["a", "b"])

    def test_invalid_worker_override_falls_back_to_default(self):
        with mock.patch.dict(os.environ, {evtx_reader.PARSE_WORKERS_ENV: "invalid"}, clear=False):
            workers = evtx_reader._parse_worker_count(3)
        self.assertGreaterEqual(workers, 1)
        self.assertLessEqual(workers, 3)

    def test_describe_evtx_path_reports_executor_settings(self):
        temp_dir = tempfile.mkdtemp(prefix="triage-evtx-describe-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        root = Path(temp_dir)
        (root / "one.evtx").write_text("", encoding="utf-8")
        (root / "two.evtx").write_text("", encoding="utf-8")

        with mock.patch.dict(
            os.environ,
            {
                evtx_reader.PARSE_WORKERS_ENV: "2",
                evtx_reader.PARSE_EXECUTOR_ENV: "thread",
            },
            clear=False,
        ):
            profile = evtx_reader.describe_evtx_path(str(root))

        self.assertEqual(profile["mode"], "directory")
        self.assertEqual(profile["file_count"], 2)
        self.assertEqual(profile["worker_count"], 2)
        self.assertEqual(profile["executor_kind"], "thread")

    def test_describe_evtx_path_defaults_to_serial_for_directories(self):
        temp_dir = tempfile.mkdtemp(prefix="triage-evtx-describe-default-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        root = Path(temp_dir)
        (root / "one.evtx").write_text("", encoding="utf-8")
        (root / "two.evtx").write_text("", encoding="utf-8")

        with mock.patch.dict(
            os.environ,
            {
                evtx_reader.PARSE_WORKERS_ENV: "",
                evtx_reader.PARSE_EXECUTOR_ENV: "",
            },
            clear=False,
        ):
            profile = evtx_reader.describe_evtx_path(str(root))

        self.assertEqual(profile["mode"], "directory")
        self.assertEqual(profile["file_count"], 2)
        self.assertEqual(profile["executor_kind"], "serial")
        self.assertEqual(profile["worker_count"], 1)

    def test_describe_evtx_path_prioritizes_high_signal_channels_before_application(self):
        temp_dir = tempfile.mkdtemp(prefix="triage-evtx-priority-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        root = Path(temp_dir)
        for name in ["Application.evtx", "System.evtx", "Security.evtx", "PowerShell-Operational.evtx"]:
            (root / name).write_text("", encoding="utf-8")

        profile = evtx_reader.describe_evtx_path(str(root))
        ordered = [Path(path).name for path in profile["files"]]

        self.assertEqual(
            ordered,
            ["Security.evtx", "PowerShell-Operational.evtx", "System.evtx", "Application.evtx"],
        )

    def test_parse_record_preserves_raw_xml_only_for_targeted_rules(self):
        generic_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>4688</EventID>
                <TimeCreated SystemTime="2026-03-11T08:00:00.0000000Z"/>
                <Computer>ws01</Computer>
                <Channel>Security</Channel>
            </System>
            <EventData>
                <Data Name="CommandLine">cmd.exe /c whoami</Data>
            </EventData>
        </Event>"""
        sql_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="MSSQL$LAB"/>
                <EventID>33205</EventID>
                <TimeCreated SystemTime="2026-03-11T08:00:00.0000000Z"/>
                <Computer>sql01</Computer>
                <Channel>Application</Channel>
            </System>
            <EventData>
                <Data>&lt;string&gt;statement: EXEC xp_cmdshell 'whoami'&lt;/string&gt;</Data>
            </EventData>
        </Event>"""

        generic_event = evtx_reader._parse_record(generic_xml)
        sql_event = evtx_reader._parse_record(sql_xml)

        self.assertIsNotNone(generic_event)
        self.assertIsNotNone(sql_event)
        self.assertEqual(generic_event.raw_xml, "")
        self.assertIn("xp_cmdshell", sql_event.raw_xml)

    def test_progress_callback_receives_file_updates_in_order(self):
        temp_dir = tempfile.mkdtemp(prefix="triage-evtx-progress-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        root = Path(temp_dir)
        (root / "b.evtx").write_text("", encoding="utf-8")
        (root / "a.evtx").write_text("", encoding="utf-8")
        updates = []

        def fake_read_evtx(filepath, start_date=None, end_date=None, progress_callback=None):
            if Path(filepath).name == "a.evtx":
                time.sleep(0.05)
            if progress_callback:
                progress_callback({"status": "file_started", "file_path": filepath})
                progress_callback({"status": "file_progress", "file_path": filepath, "records_scanned": 1, "parsed_events": 1, "skipped_records": 0})
            return [Path(filepath).stem]

        with mock.patch.object(evtx_reader, "read_evtx", side_effect=fake_read_evtx):
            with mock.patch.dict(
                os.environ,
                {
                    evtx_reader.PARSE_WORKERS_ENV: "2",
                    evtx_reader.PARSE_EXECUTOR_ENV: "thread",
                },
                clear=False,
            ):
                events = evtx_reader.read_evtx_path(str(root), progress_callback=updates.append)

        file_updates = [update for update in updates if update.get("status") == "file_complete"]
        progress_updates = [update for update in updates if update.get("status") == "file_progress"]
        self.assertEqual(events, ["a", "b"])
        self.assertEqual({Path(update["file_path"]).name for update in file_updates}, {"a.evtx", "b.evtx"})
        self.assertEqual(file_updates[-1]["completed_files"], 2)
        self.assertEqual({Path(update["file_path"]).name for update in progress_updates}, {"a.evtx", "b.evtx"})

    def test_directory_parse_continues_when_one_file_fails(self):
        temp_dir = tempfile.mkdtemp(prefix="triage-evtx-partial-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        root = Path(temp_dir)
        (root / "good.evtx").write_text("", encoding="utf-8")
        (root / "broken.evtx").write_text("", encoding="utf-8")
        updates = []

        def fake_read_evtx(filepath, start_date=None, end_date=None, progress_callback=None):
            if Path(filepath).name == "broken.evtx":
                raise ValueError("corrupt evtx payload")
            return [Path(filepath).stem]

        with mock.patch.object(evtx_reader, "read_evtx", side_effect=fake_read_evtx):
            with mock.patch.dict(
                os.environ,
                {
                    evtx_reader.PARSE_EXECUTOR_ENV: "serial",
                },
                clear=False,
            ):
                events = evtx_reader.read_evtx_path(str(root), progress_callback=updates.append)

        self.assertEqual(events, ["good"])
        error_updates = [update for update in updates if update.get("status") == "file_error"]
        self.assertEqual(len(error_updates), 1)
        self.assertEqual(Path(error_updates[0]["file_path"]).name, "broken.evtx")
        self.assertIn("corrupt evtx payload", str(error_updates[0].get("error", "")))

    def test_parse_progress_counts_active_file_events_before_completion(self):
        parse_progress = {
            "completed_files": 0,
            "file_count": 2,
            "parsed_event_count": 0,
            "_completed_parsed_events": 0,
            "last_file": "",
            "active_file": "",
            "active_records_scanned": 0,
            "active_parsed_events": 0,
            "active_skipped_records": 0,
            "fallback_used": False,
        }

        _apply_parse_progress_update(parse_progress, {"status": "file_started", "file_path": r"C:\logs\a.evtx"})
        _apply_parse_progress_update(
            parse_progress,
            {
                "status": "file_progress",
                "file_path": r"C:\logs\a.evtx",
                "records_scanned": 120,
                "parsed_events": 100,
                "skipped_records": 20,
            },
        )
        self.assertEqual(parse_progress["parsed_event_count"], 100)
        self.assertEqual(_public_parse_progress(parse_progress)["parsed_event_count"], 100)

        _apply_parse_progress_update(
            parse_progress,
            {
                "status": "file_complete",
                "file_path": r"C:\logs\a.evtx",
                "file_index": 1,
                "completed_files": 1,
                "file_count": 2,
                "parsed_events": 100,
            },
        )
        self.assertEqual(parse_progress["parsed_event_count"], 100)

        _apply_parse_progress_update(parse_progress, {"status": "file_started", "file_path": r"C:\logs\b.evtx"})
        _apply_parse_progress_update(
            parse_progress,
            {
                "status": "file_progress",
                "file_path": r"C:\logs\b.evtx",
                "records_scanned": 25,
                "parsed_events": 20,
                "skipped_records": 5,
            },
        )
        public_progress = _public_parse_progress(parse_progress)
        self.assertEqual(public_progress["parsed_event_count"], 120)
        self.assertNotIn("_completed_parsed_events", public_progress)


if __name__ == "__main__":
    unittest.main()
