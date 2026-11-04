import unittest
from datetime import datetime, timedelta

from detectors.credential_access import _openssh_brute_force
from models.event_model import NormalizedEvent


def ev(ts, payload, channel="OpenSSH/Operational"):
    return NormalizedEvent(
        event_id=4,
        timestamp=ts,
        computer="WS1",
        channel=channel,
        provider="OpenSSH",
        event_data={"payload": payload},
    )


class OpenSSHBruteForceTests(unittest.TestCase):
    def test_rejects_few_failures(self):
        base = datetime(2026, 8, 30, 12, 0, 0)
        evs = [ev(base + timedelta(seconds=i*30), "Failed password for root from 10.0.0.5 port 41234 ssh2") for i in range(3)]
        alerts = _openssh_brute_force(evs)
        self.assertEqual(len(alerts), 0)

    def test_promotes_brute_force(self):
        base = datetime(2026, 8, 30, 12, 0, 0)
        evs = [ev(base + timedelta(seconds=i*15), "Failed password for root from 10.0.0.5 port 41234 ssh2") for i in range(8)]
        alerts = _openssh_brute_force(evs)
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual(a.rule_name, "OpenSSH Brute Force")
        self.assertEqual(a.evidence["source_ip"], "10.0.0.5")
        self.assertIn("root", a.evidence["accounts"])

    def test_rejects_non_openssh_channel(self):
        base = datetime(2026, 8, 30, 12, 0, 0)
        evs = [ev(base + timedelta(seconds=i), "Failed password for root from 10.0.0.5 port 41234 ssh2", channel="Security") for i in range(15)]
        alerts = _openssh_brute_force(evs)
        self.assertEqual(len(alerts), 0)

    def test_multiple_targets_separately(self):
        base = datetime(2026, 8, 30, 12, 0, 0)
        evs = [ev(base + timedelta(seconds=i), "Failed password for root from 10.0.0.5 port 41234 ssh2") for i in range(8)]
        evs += [ev(base + timedelta(seconds=i), "Failed password for admin from 10.0.0.9 port 44444 ssh2") for i in range(8)]
        alerts = _openssh_brute_force(evs)
        self.assertEqual(len(alerts), 2)


    def test_preauth_disconnect_lines_count(self):
        base = datetime(2026, 8, 30, 12, 0, 0)
        evs = []
        for i in range(6):
            evs.append(ev(base + timedelta(seconds=i), "Disconnecting authenticating user root {ip} port {port}: Too many authentication failures [preauth]".format(ip="203.0.113.5", port=50000 + i)))
        for i in range(6):
            evs.append(ev(base + timedelta(seconds=i), "Connection closed by authenticating user root 203.0.113.5 port {port} [preauth]".format(port=51000 + i)))
        alerts = _openssh_brute_force(evs)
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual(a.evidence["source_ip"], "203.0.113.5")
        self.assertGreaterEqual(a.evidence["preauth_count"], 5)
        self.assertGreaterEqual(a.evidence["count"], 5)
        self.assertIn("root", a.evidence["accounts"])



    def test_real_world_mixed_preauth_promotes(self):
        base = datetime(2026, 8, 30, 12, 0, 0)
        evs = []
        for i in range(4):
            evs.append(ev(base + timedelta(seconds=i), "Failed password for admmig from 10.23.23.9 port 51234 ssh2"))
        evs.append(ev(base + timedelta(seconds=10), "Disconnecting authenticating user admmig 10.23.23.9 port 51260: Too many authentication failures [preauth]"))
        alerts = _openssh_brute_force(evs)
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual(a.evidence["promotion_policy"], "standalone")
        self.assertEqual(a.evidence["evidence_strength"], "high")



if __name__ == "__main__":
    unittest.main()
