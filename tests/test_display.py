import unittest

from triage_engine.display import display_input_source, sanitize_display_path, sanitize_display_values


class DisplayHelperTests(unittest.TestCase):
    def test_display_input_source_sanitizes_windows_file_path(self):
        self.assertEqual(
            display_input_source(r"C:\Users\oasun\Downloads\logs\Security.evtx"),
            "Security.evtx",
        )

    def test_display_input_source_sanitizes_directory_path(self):
        self.assertEqual(
            display_input_source(r"C:\Users\oasun\Downloads\logs"),
            "logs",
        )

    def test_display_input_source_formats_live_channels(self):
        self.assertEqual(
            display_input_source("live:Security,System,Microsoft-Windows-PowerShell/Operational"),
            "Live Windows (Security, System, Microsoft-Windows-PowerShell/Operational)",
        )

    def test_sanitize_display_values_preserves_non_path_text(self):
        self.assertEqual(
            sanitize_display_values(["Security.evtx", "Access denied"]),
            ["Security.evtx", "Access denied"],
        )

    def test_sanitize_display_path_handles_relative_paths(self):
        self.assertEqual(sanitize_display_path("./uploads/example.evtx"), "example.evtx")


if __name__ == "__main__":
    unittest.main()
