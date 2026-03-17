import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from triage_engine import cli
from triage_engine.service import InvestigationResult


class CliUsabilityTests(unittest.TestCase):
    def test_investigate_without_input_defaults_to_live_on_windows(self):
        parser = cli.build_parser()
        args = parser.parse_args(["investigate"])

        fake_result = InvestigationResult(
            case_name="auto-live",
            case_path=r"C:\cases\auto-live",
            input_source="live:Security,System",
        )

        with mock.patch.object(cli, "_is_windows_host", return_value=True):
            with mock.patch.object(cli, "run_investigation", return_value=fake_result) as run_mock:
                with mock.patch("builtins.print") as print_mock:
                    rc = cli.cmd_investigate(args)

        self.assertEqual(rc, 0)
        request = run_mock.call_args[0][0]
        self.assertEqual(request.input_mode, "live")
        self.assertEqual(request.input_source, "live")
        self.assertEqual(request.channels, ["Security", "System"])
        self.assertEqual(request.since_minutes, 30)
        auto_messages = [" ".join(str(part) for part in call.args) for call in print_mock.call_args_list]
        self.assertTrue(any("No --evtx or --live specified" in message for message in auto_messages))

    def test_investigate_without_input_errors_on_non_windows(self):
        parser = cli.build_parser()
        args = parser.parse_args(["investigate"])

        with mock.patch.object(cli, "_is_windows_host", return_value=False):
            with self.assertRaisesRegex(SystemExit, "No input source specified"):
                cli.cmd_investigate(args)

    def test_explicit_live_mode_still_works_without_auto_message(self):
        parser = cli.build_parser()
        args = parser.parse_args(["investigate", "--live", "--channels", "Security,System", "--since", "2h"])

        fake_result = InvestigationResult(
            case_name="explicit-live",
            case_path=r"C:\cases\explicit-live",
            input_source="live:Security,System",
        )

        with mock.patch.object(cli, "run_investigation", return_value=fake_result) as run_mock:
            with mock.patch("builtins.print") as print_mock:
                rc = cli.cmd_investigate(args)

        self.assertEqual(rc, 0)
        request = run_mock.call_args[0][0]
        self.assertEqual(request.input_mode, "live")
        self.assertEqual(request.channels, ["Security", "System"])
        self.assertEqual(request.since_minutes, 120)
        auto_messages = [" ".join(str(part) for part in call.args) for call in print_mock.call_args_list]
        self.assertFalse(any("No --evtx or --live specified" in message for message in auto_messages))

    def test_main_without_args_defaults_to_investigate(self):
        fake_result = InvestigationResult(
            case_name="auto-main",
            case_path=r"C:\cases\auto-main",
            input_source="live:Security,System",
        )

        with mock.patch.object(cli, "_is_windows_host", return_value=True):
            with mock.patch.object(cli, "run_investigation", return_value=fake_result) as run_mock:
                rc = cli.main([])

        self.assertEqual(rc, 0)
        request = run_mock.call_args[0][0]
        self.assertEqual(request.input_mode, "live")
        self.assertEqual(request.channels, ["Security", "System"])

    def test_list_cases_flag_runs_without_subcommand(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_dir = root / "case-alpha"
            case_dir.mkdir()
            (case_dir / "run_status.json").write_text(json.dumps({"status": "completed"}), encoding="utf-8")
            (case_dir / "findings.json").write_text(
                json.dumps(
                    {
                        "case": {
                            "response_priority": "P2",
                            "first_seen": "2026-03-16T10:00:00Z",
                            "last_seen": "2026-03-16T10:15:00Z",
                        },
                        "summary": {"signal_count": 1, "finding_count": 1, "incident_count": 1},
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch("builtins.print") as print_mock:
                rc = cli.main(["--list-cases", "--cases-dir", str(root), "--no-color"])

        self.assertEqual(rc, 0)
        messages = [" ".join(str(part) for part in call.args) for call in print_mock.call_args_list]
        joined = "\n".join(messages)
        self.assertIn("Case Inventory", joined)
        self.assertIn("case-alpha", joined)
        self.assertIn("1/1/1", joined)

    def test_show_tuning_flag_runs_without_subcommand(self):
        with tempfile.TemporaryDirectory() as tmp:
            tuning_path = Path(tmp) / "extra.json"
            tuning_path.write_text(
                json.dumps({"allowlists": {"hosts": ["alpha-host"]}, "rule_suppressions": []}),
                encoding="utf-8",
            )

            with mock.patch("builtins.print") as print_mock:
                rc = cli.main(["--show-tuning", "--tuning", str(tuning_path), "--no-color"])

        self.assertEqual(rc, 0)
        messages = [" ".join(str(part) for part in call.args) for call in print_mock.call_args_list]
        joined = "\n".join(messages)
        self.assertIn("Merged Tuning Configuration", joined)
        self.assertIn("alpha-host", joined)

    def test_help_shows_examples_and_phase_43_flags(self):
        help_text = cli.build_parser().format_help()
        self.assertIn("Examples:", help_text)
        self.assertIn("--list-cases", help_text)
        self.assertIn("--show-tuning", help_text)

    def test_colorize_includes_ansi_when_enabled(self):
        value = cli._colorize("ok", cli.ANSI_GREEN, use_color=True)
        self.assertEqual(value, f"{cli.ANSI_GREEN}ok{cli.ANSI_RESET}")


if __name__ == "__main__":
    unittest.main()
