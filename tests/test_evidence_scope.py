"""Evidence scope must flag mixed hosts and stale windows consistently."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from corrobora.evidence_scope import build_evidence_scope

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def _event(host: str, offset_days: float = 0.0):
    return SimpleNamespace(computer=host, timestamp=T0 + timedelta(days=offset_days))


class EvidenceScopeTests(unittest.TestCase):
    def test_single_host_short_window_needs_no_review(self):
        scope = build_evidence_scope([_event("WS01.corp.local"), _event("WS01.corp.local", 0.5)])
        self.assertEqual(scope["host_count"], 1)
        self.assertFalse(scope["needs_scope_review"])
        self.assertEqual(scope["warnings"], [])
        self.assertEqual(scope["hosts"][0]["event_count"], 2)

    def test_mixed_hosts_and_long_window_are_flagged_with_per_host_detections(self):
        events = [_event("WS01.corp.local"), _event("DC01.corp.local", 40)]
        findings = [SimpleNamespace(host="DC01", severity="high"), SimpleNamespace(host="DC01", severity="medium")]
        incidents = [SimpleNamespace(host="dc01.corp.local", severity="critical", confidence_score=0, evidence_chain=[])]

        scope = build_evidence_scope(events, findings, incidents)

        self.assertTrue(scope["mixed_hosts"])
        self.assertTrue(scope["long_window"])
        self.assertEqual(scope["host_count"], 2)
        self.assertEqual(len(scope["warnings"]), 2)
        self.assertIn("detections on 1 of them", scope["warnings"][0])
        top = scope["hosts"][0]
        # Short "DC01" findings fold into the FQDN seen in events.
        self.assertEqual(top["host"], "DC01.corp.local")
        self.assertEqual((top["finding_count"], top["incident_count"], top["max_severity"]), (2, 1, "critical"))

    def test_each_host_gets_its_own_verdict(self):
        events = [_event("WS01.corp.local"), _event("DC01.corp.local"), _event("PRN01.corp.local")]
        findings = [
            SimpleNamespace(host="DC01", severity="high", confidence_score=80, title="LSASS access"),
            SimpleNamespace(host="WS01", severity="low", confidence_score=20, title="Odd login"),
        ]
        incidents = [SimpleNamespace(host="DC01", severity="critical", confidence_score=90,
                                     title="Credential dumping", evidence_chain=[])]

        scope = build_evidence_scope(events, findings, incidents)
        verdicts = {row["host"]: row["verdict"] for row in scope["hosts"]}

        self.assertEqual(scope["hosts"][0]["host"], "DC01.corp.local")
        self.assertEqual(verdicts["DC01.corp.local"]["disposition"], "Escalate")
        self.assertIn("Credential dumping", verdicts["DC01.corp.local"]["reasons"][0])
        self.assertEqual(verdicts["WS01.corp.local"]["disposition"], "Investigate")
        self.assertEqual(verdicts["WS01.corp.local"]["response_priority"], "P4")
        self.assertEqual(verdicts["PRN01.corp.local"]["disposition"], "No promoted incident")
        self.assertTrue(scope["split_verdict"])
        self.assertEqual(scope["host_verdict_counts"], {"Escalate": 1, "Investigate": 1, "No promoted incident": 1})
        self.assertTrue(any("Escalation applies to DC01.corp.local" in w for w in scope["warnings"]))

    def test_telemetry_gaps_turn_quiet_host_into_monitor(self):
        scope = build_evidence_scope([_event("WS01")], telemetry_gaps=["PowerShell"])
        self.assertEqual(scope["hosts"][0]["verdict"]["disposition"], "Monitor")
        self.assertFalse(scope["split_verdict"])

    def test_events_without_host_or_time_do_not_break_scope(self):
        scope = build_evidence_scope([SimpleNamespace(computer="", timestamp=None)])
        self.assertEqual(scope["host_count"], 0)
        self.assertEqual(scope["first_seen"], "")
        self.assertFalse(scope["needs_scope_review"])


if __name__ == "__main__":
    unittest.main()
