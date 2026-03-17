import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from triage_engine.webhooks import dispatch_webhook_event, load_webhook_endpoints


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getcode(self):
        return self.status


class WebhookTests(unittest.TestCase):
    def test_load_webhook_endpoints_skips_invalid_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps(
                    {
                        "endpoints": [
                            {"url": "https://example.test/a", "events": ["investigation_completed"]},
                            {"url": "", "events": ["investigation_completed"]},
                            {"url": "https://example.test/b", "events": []},
                            "bad-entry",
                        ]
                    }
                ),
                encoding="utf-8",
            )

            endpoints, diagnostics, resolved_path = load_webhook_endpoints(tmp, config_path=str(config_path))

        self.assertEqual(resolved_path, str(config_path))
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["url"], "https://example.test/a")
        self.assertGreaterEqual(len(diagnostics), 3)

    def test_dispatch_webhook_event_sends_only_subscribed_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps(
                    {
                        "endpoints": [
                            {"url": "https://hooks.test/a", "events": ["investigation_completed"], "timeout_seconds": 3},
                            {"url": "https://hooks.test/b", "events": ["incident_p1"]},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            calls = []

            def _fake_urlopen(req, timeout=0):
                calls.append((req.full_url, timeout, req.data, dict(req.headers)))
                return _FakeResponse(status=200)

            with patch("triage_engine.webhooks.urllib_request.urlopen", side_effect=_fake_urlopen):
                stats = dispatch_webhook_event(
                    "investigation_completed",
                    {"case_name": "case-a", "incident_count": 1},
                    root_dir=tmp,
                    config_path=str(config_path),
                )

        self.assertEqual(stats["attempted"], 1)
        self.assertEqual(stats["sent"], 1)
        self.assertEqual(stats["failed"], 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "https://hooks.test/a")
        self.assertEqual(calls[0][1], 3)
        body = json.loads(calls[0][2].decode("utf-8"))
        self.assertEqual(body["event"], "investigation_completed")
        self.assertEqual(body["case_name"], "case-a")
        self.assertIn("timestamp", body)

    def test_dispatch_webhook_event_records_failures_without_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({"endpoints": [{"url": "https://hooks.test/a", "events": ["incident_p1"]}]}),
                encoding="utf-8",
            )

            with patch("triage_engine.webhooks.urllib_request.urlopen", side_effect=URLError("network down")):
                stats = dispatch_webhook_event(
                    "incident_p1",
                    {"case_name": "case-fail"},
                    root_dir=tmp,
                    config_path=str(config_path),
                )

        self.assertEqual(stats["attempted"], 1)
        self.assertEqual(stats["sent"], 0)
        self.assertEqual(stats["failed"], 1)


if __name__ == "__main__":
    unittest.main()
