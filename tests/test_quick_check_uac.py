"""Focused contracts for the guided Quick Check and safe UAC launcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import server


ROOT = Path(__file__).resolve().parents[1]


def test_quick_check_uses_persisted_triage_disposition_fields_first():
    dashboard = "\n".join(
        (ROOT / "static" / name).read_text(encoding="utf-8")
        for name in ("dashboard.html", "dashboard.js", "dashboard.css", "workspace.js", "workspace.css")
    )

    assert "disposition.reasons" in dashboard
    assert "disposition.telemetry_gaps" in dashboard
    assert "disposition.recommended_next" in dashboard
    assert "disposition.supporting_factors" in dashboard
    assert "disposition.missing_telemetry" in dashboard
    assert "disposition.next_steps" in dashboard
    assert "quick_check') === '1'" in dashboard
    assert "?quick_check=1" in dashboard
    assert "/api/quick/investigate/live" in dashboard
    assert "action-required" in dashboard
    assert "no-promoted-incident" in dashboard
    assert "function confidencePercent(value)" in dashboard
    assert "data.triage_disposition || data.summary?.triage_disposition" in dashboard
    assert ".map(esc).join(', ')" in dashboard
    assert "confidencePercent(disposition.confidence_score)" in dashboard
    assert "['Permission denied', cq.permission_denied_sources]" in dashboard
    assert "['Unreadable channels', cq.unavailable_sources]" in dashboard
    assert "['Partial reads', cq.partial_sources]" in dashboard
    assert "['Fallback after denied access', cq.fallback_permission_sources]" in dashboard
    assert "cq.partial_sources" in dashboard
    assert "cq.fallback_permission_sources" in dashboard


def test_elevated_server_launch_is_localhost_only_and_uses_uac():
    with patch.object(server.os, "name", "nt"), patch("server.subprocess.Popen") as popen:
        redirect_url = server._launch_elevated_local_server(41234)

    assert redirect_url == "http://127.0.0.1:41234"
    command = popen.call_args.args[0]
    assert command[:2] == ["powershell.exe", "-NoProfile"]
    script = command[-1]
    assert "TRIAGE_HOST = '127.0.0.1'" in script
    assert "TRIAGE_PORT = '41234'" in script
    assert "-Verb RunAs" in script


def test_powershell_quote_does_not_allow_literal_termination():
    assert server._powershell_quote("C:\\safe path\\it's.exe") == "'C:\\safe path\\it''s.exe'"


def test_quick_check_rejects_dns_rebinding_host_and_cross_origin():
    with TestClient(server.app) as client, patch.object(server, "_is_loopback_client", return_value=True):
        rebound = client.get(
            "/api/quick/session",
            headers={"Host": "attacker.example:8000", "Origin": "http://attacker.example:8000"},
        )
        assert rebound.status_code == 400

        cross_origin = client.get(
            "/api/quick/session",
            headers={"Host": "127.0.0.1:8000", "Origin": "https://attacker.example"},
        )
        assert cross_origin.status_code == 403

        local = client.get(
            "/api/quick/session",
            headers={"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8000"},
        )
        assert local.status_code == 200
        assert local.json()["token"]
