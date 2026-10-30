import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from triage_engine.webhooks import (
    MAX_CONFIGURED_TIMEOUT_SECONDS,
    MAX_TOTAL_WEBHOOK_DISPATCH_SECONDS,
    WEBHOOK_SCHEMA_VERSION,
    build_event_id,
    dispatch_webhook_event,
    load_webhook_endpoints,
    matches_event,
    resolve_webhook_config_path,
)


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

    def test_webhook_config_path_override_is_resolved_from_project_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            default_path = Path(tmp) / "config" / "webhooks.json"
            default_path.parent.mkdir()

            original = os.environ.get("TRIAGE_WEBHOOK_CONFIG")
            os.environ.pop("TRIAGE_WEBHOOK_CONFIG", None)
            try:
                self.assertEqual(
                    resolve_webhook_config_path(tmp),
                    str(default_path),
                )
                self.assertEqual(
                    resolve_webhook_config_path(tmp, config_path=str(Path(tmp) / "custom.json")),
                    str(Path(tmp) / "custom.json"),
                )
                os.environ["TRIAGE_WEBHOOK_CONFIG"] = "config/custom-webhooks.json"
                self.assertEqual(
                    resolve_webhook_config_path(tmp),
                    str(Path(tmp) / "config" / "custom-webhooks.json"),
                )
                os.environ["TRIAGE_WEBHOOK_CONFIG"] = os.path.abspath("custom-absolute.json")
                self.assertEqual(
                    resolve_webhook_config_path(tmp),
                    os.path.abspath("custom-absolute.json"),
                )
            finally:
                if original is None:
                    os.environ.pop("TRIAGE_WEBHOOK_CONFIG", None)
                else:
                    os.environ["TRIAGE_WEBHOOK_CONFIG"] = original

    def test_load_webhook_endpoints_rejects_unsafe_urls_and_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({
                    "endpoints": [
                        {
                            "url": "https://user:secret@hooks.test/bad-credentials",
                            "events": ["case.completed"],
                        },
                        {
                            "url": "ftp://hooks.test/not-http",
                            "events": ["case.completed"],
                        },
                        {
                            "url": "https://[::1/path",
                            "events": ["case.completed"],
                        },
                        {
                            "url": "https://hooks.test:not-a-port/path",
                            "events": ["case.completed"],
                        },
                        {
                            "url": "https://[::1]:99999/path",
                            "events": ["case.completed"],
                        },
                        {
                            "url": "https://hooks.test/headers",
                            "events": ["case.completed"],
                            "headers": {
                                "X-Triage-Event-ID": "spoofed",
                                "X-Triage-Schema-Version": "9.9",
                                "Bad Header": "rejected",
                                "X-Custom": "line-break\ninjected",
                            },
                        },
                    ],
                }),
                encoding="utf-8",
            )

            endpoints, diagnostics, _ = load_webhook_endpoints(tmp, config_path=str(config_path))

        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["url"], "https://hooks.test/headers")
        self.assertEqual(
            endpoints[0]["headers"],
            {"X-Triage-Event-ID": "spoofed", "X-Triage-Schema-Version": "9.9"},
        )
        self.assertEqual(len([entry for entry in diagnostics if "invalid or missing required field 'url'" in entry]), 5)

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

    def test_dispatch_webhook_event_adds_versioned_idempotency_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({"endpoints": [{"url": "https://hooks.test/a", "events": ["case.completed"]}]}),
                encoding="utf-8",
            )
            calls = []

            def _fake_urlopen(req, timeout=0):
                calls.append((req.full_url, timeout, req.data, dict(req.headers)))
                return _FakeResponse(status=200)

            with patch("triage_engine.webhooks.urllib_request.urlopen", side_effect=_fake_urlopen):
                stats = dispatch_webhook_event(
                    "case.completed",
                    {"case_name": "case-a", "job_id": "job-1", "event_id": "case-a:job-1:case.completed"},
                    root_dir=tmp,
                    config_path=str(config_path),
                )

        body = json.loads(calls[0][2].decode("utf-8"))
        self.assertEqual(stats["event_id"], "case-a:job-1:case.completed")
        self.assertEqual(body["schema_version"], WEBHOOK_SCHEMA_VERSION)
        self.assertEqual(body["event_id"], "case-a:job-1:case.completed")
        sent_headers = {key.lower(): value for key, value in calls[0][3].items()}
        self.assertEqual(sent_headers["x-triage-event-id"], "case-a:job-1:case.completed")
        self.assertEqual(sent_headers["x-triage-schema-version"], WEBHOOK_SCHEMA_VERSION)

    def test_dispatch_webhook_event_retries_bounded_then_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({
                    "endpoints": [{
                        "url": "https://hooks.test/a",
                        "events": ["case.completed"],
                        "max_attempts": 3,
                        "retry_delay_seconds": 0,
                    }],
                }),
                encoding="utf-8",
            )
            responses = [_FakeResponse(status=503), _FakeResponse(status=200)]

            with patch("triage_engine.webhooks.urllib_request.urlopen", side_effect=responses) as urlopen_mock:
                stats = dispatch_webhook_event(
                    "case.completed",
                    {"case_name": "case-retry", "job_id": "job-1"},
                    root_dir=tmp,
                    config_path=str(config_path),
                )

        self.assertEqual(urlopen_mock.call_count, 2)
        self.assertEqual(stats["attempted"], 1)
        self.assertEqual(stats["sent"], 1)
        self.assertEqual(stats["failed"], 0)

    def test_retry_configuration_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({
                    "endpoints": [{
                        "url": "https://hooks.test/a",
                        "events": ["case.completed"],
                        "max_attempts": 99,
                        "retry_delay_seconds": 999,
                    }],
                }),
                encoding="utf-8",
            )
            endpoints, _, _ = load_webhook_endpoints(tmp, config_path=str(config_path))

        self.assertEqual(endpoints[0]["max_attempts"], 5)
        self.assertLessEqual(endpoints[0]["retry_delay_seconds"], 3.75)

    def test_timeout_and_retry_values_reject_non_finite_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({
                    "endpoints": [{
                        "url": "https://hooks.test/a",
                        "events": ["case.completed"],
                        "timeout_seconds": float("inf"),
                        "max_attempts": float("inf"),
                        "retry_delay_seconds": float("inf"),
                    }],
                }),
                encoding="utf-8",
            )
            endpoints, _, _ = load_webhook_endpoints(tmp, config_path=str(config_path))

        self.assertEqual(endpoints[0]["timeout_seconds"], 5)
        self.assertEqual(endpoints[0]["max_attempts"], 1)
        self.assertEqual(endpoints[0]["retry_delay_seconds"], 0)

    def test_huge_configured_timeout_is_bounded_without_overflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({
                    "endpoints": [{
                        "url": "https://hooks.test/a",
                        "events": ["case.completed"],
                        "timeout_seconds": 10 ** 1000,
                    }],
                }),
                encoding="utf-8",
            )
            endpoints, _, _ = load_webhook_endpoints(tmp, config_path=str(config_path))

        self.assertEqual(endpoints[0]["timeout_seconds"], MAX_CONFIGURED_TIMEOUT_SECONDS)

    def test_reserved_headers_cannot_be_overridden_by_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({
                    "endpoints": [{
                        "url": "https://hooks.test/a",
                        "events": ["case.completed"],
                        "headers": {"X-Triage-Event-ID": "spoofed", "X-Triage-Schema-Version": "9.9"},
                    }],
                }),
                encoding="utf-8",
            )
            calls = []

            def _fake_urlopen(req, timeout=0):
                calls.append(dict(req.headers))
                return _FakeResponse(status=200)

            with patch("triage_engine.webhooks.urllib_request.urlopen", side_effect=_fake_urlopen):
                dispatch_webhook_event(
                    "case.completed",
                    {"case_name": "reserved-headers", "job_id": "job-1"},
                    root_dir=tmp,
                    config_path=str(config_path),
                )

        sent = {key.lower(): value for key, value in calls[0].items()}
        self.assertEqual(sent["x-triage-event-id"], "reserved-headers:job-1:case.completed")
        self.assertEqual(sent["x-triage-schema-version"], "1.0")

    def test_dispatch_respects_event_wide_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({
                    "endpoints": [
                        {"url": "https://hooks.test/first", "events": ["case.completed"], "timeout_seconds": 1},
                        {"url": "https://hooks.test/second", "events": ["case.completed"], "timeout_seconds": 1},
                    ],
                }),
                encoding="utf-8",
            )
            calls = []

            def _slow(req, timeout=0):
                calls.append((req.full_url, timeout))
                time.sleep(0.03)
                return _FakeResponse(status=200)

            with patch(
                "triage_engine.webhooks.MAX_TOTAL_WEBHOOK_DISPATCH_SECONDS",
                0.01,
            ), patch("triage_engine.webhooks.urllib_request.urlopen", side_effect=_slow):
                stats = dispatch_webhook_event(
                    "case.completed",
                    {"case_name": "deadline-case", "job_id": "job-1"},
                    root_dir=tmp,
                    config_path=str(config_path),
                )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "https://hooks.test/first")
        self.assertLessEqual(calls[0][1], 0.01)
        self.assertEqual(stats["attempted"], 1)
        self.assertEqual(stats["sent"], 1)
        self.assertEqual(stats["skipped"], 1)
        self.assertLessEqual(MAX_TOTAL_WEBHOOK_DISPATCH_SECONDS, 60)

    def test_dispatch_webhook_event_respects_legacy_aliases_without_duplicate_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({
                    "endpoints": [
                        {"url": "https://hooks.test/canonical", "events": ["case.escalated"]},
                        {"url": "https://hooks.test/legacy-p1", "events": ["incident_p1"]},
                        {"url": "https://hooks.test/legacy-p2", "events": ["incident_p2"]},
                    ],
                }),
                encoding="utf-8",
            )
            calls = []

            def _fake_urlopen(req, timeout=0):
                calls.append(req.full_url)
                return _FakeResponse(status=200)

            with patch("triage_engine.webhooks.urllib_request.urlopen", side_effect=_fake_urlopen):
                stats = dispatch_webhook_event(
                    "case.escalated",
                    {"case_name": "case-alias", "job_id": "job-1", "response_priority": "P1"},
                    root_dir=tmp,
                    config_path=str(config_path),
                )

        self.assertEqual(len(calls), 2)
        self.assertIn("https://hooks.test/canonical", calls)
        self.assertIn("https://hooks.test/legacy-p1", calls)
        self.assertNotIn("https://hooks.test/legacy-p2", calls)
        self.assertEqual(stats["attempted"], 2)
        self.assertEqual(stats["sent"], 2)

    def test_event_aliases_and_identifier_helpers_are_stable(self):
        payload = {"case_name": "case-a", "job_id": "job-1"}
        self.assertEqual(build_event_id("case.completed", payload), "case-a:job-1:case.completed")
        injected = build_event_id(
            "case.completed",
            {"case_name": "case-a", "job_id": "job-1", "event_id": "safe" + chr(13) + chr(10) + "X-Injected: yes"},
        )
        self.assertTrue(injected.startswith("case.completed-"))
        self.assertNotIn("\r", injected)
        self.assertNotIn("\n", injected)
        bundle_first = build_event_id("bundle.exported", {"case_name": "case-a", "job_id": "export-1"})
        bundle_repeat = build_event_id("bundle.exported", {"case_name": "case-a", "job_id": "export-1"})
        bundle_second = build_event_id("bundle.exported", {"case_name": "case-a", "job_id": "export-2"})
        self.assertEqual(bundle_first, bundle_repeat)
        self.assertNotEqual(bundle_first, bundle_second)
        self.assertEqual(bundle_first, "case-a:export-1:bundle.exported")
        self.assertTrue(matches_event("bundle.exported", ["case_bundle_exported"], payload))
        self.assertFalse(matches_event("case.escalated", ["incident_p2"], {"response_priority": "P1"}))
        self.assertTrue(matches_event("case.escalated", ["incident_p2"], {"response_priority": "P2"}))

    def test_event_identifier_header_injection_is_sanitized_when_dispatching(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "webhooks.json"
            config_path.write_text(
                json.dumps({"endpoints": [{"url": "https://hooks.test/a", "events": ["case.completed"]}]}),
                encoding="utf-8",
            )
            calls = []

            def _fake_urlopen(req, timeout=0):
                calls.append(dict(req.headers))
                return _FakeResponse(status=200)

            injected_id = "safe" + chr(13) + chr(10) + "X-Injected: yes"
            with patch("triage_engine.webhooks.urllib_request.urlopen", side_effect=_fake_urlopen):
                stats = dispatch_webhook_event(
                    "case.completed",
                    {"case_name": "case-a", "job_id": "job-1", "event_id": injected_id},
                    root_dir=tmp,
                    config_path=str(config_path),
                )

        self.assertEqual(stats["sent"], 1)
        sent = {key.lower(): value for key, value in calls[0].items()}
        self.assertNotIn("\r", sent["x-triage-event-id"])
        self.assertNotIn("\n", sent["x-triage-event-id"])
        self.assertNotIn("x-injected", sent)

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
