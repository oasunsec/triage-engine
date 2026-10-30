"""main.py must keep legacy flags working without swallowing global options."""

from __future__ import annotations

import unittest

from main import _translate_legacy_args


class LegacyArgTranslationTests(unittest.TestCase):
    def test_legacy_investigate_flags_gain_subcommand(self):
        self.assertEqual(_translate_legacy_args(["--evtx", "logs"]), ["investigate", "--evtx", "logs"])

    def test_global_color_flag_stays_before_subcommand(self):
        self.assertEqual(
            _translate_legacy_args(["--no-color", "--evtx", "logs"]),
            ["--no-color", "investigate", "--evtx", "logs"],
        )

    def test_modern_and_global_only_usage_passes_through(self):
        for argv in (
            ["--no-color", "investigate", "--evtx", "logs"],
            ["--list-cases", "--cases-dir", "cases"],
            ["--show-tuning"],
            ["summarize", "--case", "x"],
        ):
            self.assertEqual(_translate_legacy_args(list(argv)), argv)


if __name__ == "__main__":
    unittest.main()
