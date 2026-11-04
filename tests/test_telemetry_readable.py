import unittest
from corrobora.telemetry import summarize_telemetry


class TelemetryReadableChannelTests(unittest.TestCase):
    def test_readable_quiet_security_is_present(self):
        """A successfully-read but quiet Security channel is not 'missing'.

        A healthy host with an empty lookback window must not be escalated to a
        misleading Monitor disposition due to inferred-missing telemetry.
        """
        summary = summarize_telemetry([], readable_channels=["Security"])
        self.assertEqual(summary["present"], ["Security"])
        self.assertEqual(summary["missing"], ["Sysmon", "PowerShell"])

    def test_no_readable_channels_preserves_missing(self):
        """Without readable-channel context, all required sources stay missing."""
        summary = summarize_telemetry([])
        self.assertEqual(summary["missing"], ["Security", "Sysmon", "PowerShell"])

    def test_readable_sysmon_and_shell_are_present(self):
        """Reading non-Security channels does not fabricate a Security read."""
        summary = summarize_telemetry(
            [],
            readable_channels=["Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational"],
        )
        self.assertEqual(sorted(summary["present"]), ["PowerShell", "Sysmon"])
        self.assertEqual(summary["missing"], ["Security"])

    def test_readable_channels_do_not_mask_access_denied(self):
        """A permission-denied channel is never counted as present."""
        summary = summarize_telemetry([], readable_channels=["System"])
        self.assertEqual(summary["missing"], ["Security", "Sysmon", "PowerShell"])


if __name__ == "__main__":
    unittest.main()
