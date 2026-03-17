import os
import shutil
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

from correlation.incident_builder import build_incidents
from models.event_model import Alert, Incident
from reporting.json_export import export_case, export_raw_events_stream
from triage_engine.adapters import alerts_to_signals_findings
from triage_engine.campaigns import build_campaign_summary
from triage_engine.cli import _write_incident_brief, _write_summary_txt
from triage_engine.rule_metrics import build_rule_metrics, build_tuning_recommendations
from triage_engine.service import _build_collection_quality_summary
from triage_engine.telemetry import summarize_telemetry

from tests.test_regressions import make_event


def _make_correlate_alert(timestamp, *, rule_name="Suspicious Admin Tool Staging"):
    event = make_event(
        4688,
        timestamp=timestamp,
        computer="host1",
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        subject_user="analyst",
        subject_domain="corp",
        process_name_value=r"C:\Windows\System32\notepad.exe",
        parent_process_value=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        command_line_value=r"notepad.exe readme.txt",
        event_data={
            "NewProcessName": r"C:\Windows\System32\notepad.exe",
            "ParentProcessName": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "CommandLine": r"notepad.exe readme.txt",
        },
    )
    return Alert(
        rule_name=rule_name,
        severity="medium",
        mitre_tactic="Execution",
        mitre_technique="T1059",
        description="Synthetic command execution used to validate correlate-only promotion.",
        explanation="Synthetic correlate-only alert.",
        event=event,
        confidence="medium",
        promotion_policy="correlate",
        investigate_next="Review whether the process ancestry belongs to an admin workflow.",
        recommended_pivots=["host:host1", r"user:corp\analyst"],
        evidence={"evidence_strength": "medium"},
    )


def _make_remote_credential_events(base, *, host="host1", src="10.20.30.40", user="analyst", domain="corp"):
    remote_logon = make_event(
        4624,
        timestamp=base,
        computer=host,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        source_ip=src,
        logon_type="3",
        target_user=user,
        target_domain=domain,
        event_data={
            "TargetUserName": user,
            "TargetDomainName": domain,
            "IpAddress": src,
            "LogonType": "3",
        },
    )
    explicit = make_event(
        4648,
        timestamp=base + timedelta(seconds=1),
        computer=host,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        source_ip=src,
        subject_user="svc-host",
        subject_domain=host,
        target_user=user,
        target_domain=domain,
        process_name_value=r"C:\Windows\System32\svchost.exe",
        event_data={
            "SubjectUserName": "svc-host",
            "SubjectDomainName": host,
            "TargetUserName": user,
            "TargetDomainName": domain,
            "IpAddress": src,
            "ProcessName": r"C:\Windows\System32\svchost.exe",
        },
    )
    privileged = make_event(
        4672,
        timestamp=base + timedelta(seconds=2),
        computer=host,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        subject_user=user,
        subject_domain=domain,
        event_data={
            "SubjectUserName": user,
            "SubjectDomainName": domain,
        },
    )
    return remote_logon, explicit, privileged


class CaseMetricTests(unittest.TestCase):
    def test_correlate_policy_requires_corroboration(self):
        base = datetime(2026, 3, 11, 15, 0, tzinfo=timezone.utc)
        single_alert = _make_correlate_alert(base)

        signals, findings, _ = alerts_to_signals_findings([single_alert], telemetry_gaps=["Sysmon"])
        self.assertEqual(len(signals), 1)
        self.assertEqual(len(findings), 0)

        corroborated_alerts = [single_alert, _make_correlate_alert(base + timedelta(minutes=5))]
        signals, findings, _ = alerts_to_signals_findings(corroborated_alerts, telemetry_gaps=["Sysmon"])
        self.assertEqual(len(signals), 2)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("corroborated_by_related_alerts" in finding.promotion_reasons for finding in findings))
        self.assertTrue(all("missing_required_telemetry" in finding.confidence_factors for finding in findings))

    def test_correlate_policy_does_not_promote_on_high_confidence_alone(self):
        base = datetime(2026, 3, 11, 15, 2, tzinfo=timezone.utc)
        single_alert = _make_correlate_alert(base, rule_name="Local Account Enumeration")
        single_alert.confidence = "high"

        signals, findings, _ = alerts_to_signals_findings([single_alert], telemetry_gaps=["Sysmon"])

        self.assertEqual(len(signals), 1)
        self.assertEqual(len(findings), 0)

    def test_local_account_enumeration_promotes_when_paired_with_local_group_enumeration(self):
        base = datetime(2026, 3, 11, 15, 4, tzinfo=timezone.utc)
        account_alert = _make_correlate_alert(base, rule_name="Local Account Enumeration")
        account_alert.confidence = "high"
        group_alert = _make_correlate_alert(base + timedelta(minutes=1), rule_name="Local Group Enumeration")
        group_alert.confidence = "high"

        signals, findings, _ = alerts_to_signals_findings([account_alert, group_alert], telemetry_gaps=["Sysmon"])

        self.assertEqual(len(signals), 2)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("corroborated_by_related_alerts" in finding.promotion_reasons for finding in findings))

    def test_remote_credential_sequence_requires_correlated_remote_credential_artifacts(self):
        base = datetime(2026, 3, 11, 15, 6, tzinfo=timezone.utc)
        events = list(_make_remote_credential_events(base))

        incidents = build_incidents(events, [], [], [])

        self.assertEqual(
            [incident for incident in incidents if incident.incident_type == "remote_credential_sequence"],
            [],
        )

    def test_remote_credential_sequence_emits_with_context_finding(self):
        base = datetime(2026, 3, 11, 15, 8, tzinfo=timezone.utc)
        events = list(_make_remote_credential_events(base))
        alert = Alert(
            rule_name="RunAs Different User",
            severity="high",
            mitre_tactic="Credential Access",
            mitre_technique="T1134.001",
            description="Synthetic RunAs activity used to validate incident correlation.",
            explanation="Synthetic remote credential context finding.",
            event=events[1],
            confidence="high",
            user=r"corp\analyst",
            evidence={"evidence_strength": "high"},
        )

        signals, findings, _ = alerts_to_signals_findings([alert], telemetry_gaps=[])
        incidents = build_incidents(events, signals, findings, [])
        remote = [incident for incident in incidents if incident.incident_type == "remote_credential_sequence"]

        self.assertEqual(len(findings), 1)
        self.assertEqual(len(remote), 1)
        self.assertEqual(remote[0].finding_ids, [findings[0].id])
        self.assertEqual(remote[0].signal_ids, [signals[0].id])

    def test_lsass_memory_access_findings_group_into_one_incident(self):
        base = datetime(2026, 3, 14, 21, 0, tzinfo=timezone.utc)
        events = [
            make_event(
                10,
                timestamp=base,
                computer="IEWIN7",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                event_data={
                    "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "TargetImage": r"C:\Windows\System32\lsass.exe",
                    "GrantedAccess": "0x1010",
                },
            ),
            make_event(
                10,
                timestamp=base + timedelta(minutes=2),
                computer="IEWIN7",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                event_data={
                    "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "TargetImage": r"C:\Windows\System32\lsass.exe",
                    "GrantedAccess": "0x1010",
                },
            ),
        ]
        alerts = [
            Alert(
                rule_name="LSASS Memory Access",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"LSASS accessed by {event.event_data['SourceImage']} (mask: 0x1010) on IEWIN7",
                explanation="Synthetic repeated LSASS access used to validate incident grouping.",
                event=event,
                confidence="high",
                process=event.event_data["SourceImage"],
                evidence={
                    "source_image": event.event_data["SourceImage"],
                    "target_image": event.event_data["TargetImage"],
                    "access_mask": "0x1010",
                    "evidence_strength": "high",
                },
            )
            for event in events
        ]

        signals, findings, _ = alerts_to_signals_findings(alerts, telemetry_gaps=["Security", "PowerShell"])
        incidents = build_incidents(events, signals, findings, [])
        lsass_incidents = [incident for incident in incidents if incident.incident_type == "lsass_memory_access"]

        self.assertEqual(len(findings), 2)
        self.assertEqual(len(lsass_incidents), 1)
        self.assertEqual(len(lsass_incidents[0].finding_ids), 2)
        self.assertEqual(len(lsass_incidents[0].signal_ids), 2)

    def test_export_case_includes_precision_metadata(self):
        base = datetime(2026, 3, 11, 15, 10, tzinfo=timezone.utc)
        alerts = [_make_correlate_alert(base), _make_correlate_alert(base + timedelta(minutes=5))]
        signals, findings, _ = alerts_to_signals_findings(alerts, telemetry_gaps=["Sysmon", "PowerShell"])

        incident = Incident(
            id="inc-synthetic",
            display_label="INC-001",
            incident_type="correlated_attack_chain",
            title="Synthetic Correlated Activity",
            severity="high",
            confidence="high",
            confidence_score=88,
            summary="Synthetic incident for export validation.",
            first_seen=base,
            last_seen=base + timedelta(minutes=5),
            confidence_factors=["multi_signal"],
            finding_ids=[finding.id for finding in findings],
            signal_ids=[signal.id for signal in signals],
            host="host1",
            user=r"corp\analyst",
            source_ip="10.10.10.5",
            recommended_pivots=["host:host1", r"user:corp\analyst", "ip:10.10.10.5"],
            promotion_reasons=["correlated_findings:2", "correlated_signals:2"],
            telemetry_gaps=["Sysmon", "PowerShell"],
            why_flagged="Two corroborating signals were promoted into a single synthetic incident.",
            containment_guidance=["Confirm the process ancestry is expected before suppressing."],
            scope_next=["Pivot on host1 and the analyst account across the rest of the case."],
            validation_steps=["Verify whether this sequence matches a sanctioned admin procedure."],
        )
        case_meta = {
            "case_name": "synthetic-case",
            "input_source": "unit-test",
            "primary_host": "host1",
            "primary_user": r"corp\analyst",
            "primary_source_ip": "10.10.10.5",
            "response_priority": "P2",
            "telemetry_summary": {
                "present": ["Security"],
                "missing": ["Sysmon", "PowerShell"],
            },
            "telemetry_gap_summary": {
                "present": ["Security"],
                "missing": ["Sysmon", "PowerShell"],
            },
            "suppression_summary": {
                "suppressed_total": 1,
                "by_reason": {"allowlist_processes": 1},
                "by_rule": {"Environment Inventory Tool": 1},
                "samples": [],
            },
            "case_metrics": {
                "raw_alert_count": 3,
                "suppressed_alert_count": 1,
                "post_filter_alert_count": 2,
                "deduplicated_alert_count": 0,
                "post_dedup_alert_count": 2,
                "signal_count": len(signals),
                "finding_count": len(findings),
                "incident_count": 1,
                "finding_promotion_rate": 1.0,
                "incident_promotion_rate": 0.5,
            },
            "rule_metrics": [
                {
                    "rule": "Suspicious Admin Tool Staging",
                    "raw_alert_count": 3,
                    "suppressed_alert_count": 1,
                    "post_filter_alert_count": 2,
                    "deduplicated_alert_count": 0,
                    "post_dedup_alert_count": 2,
                    "signal_count": len(signals),
                    "finding_count": len(findings),
                    "incident_count": 1,
                    "suppression_rate": 0.3333,
                    "deduplication_rate": 0.0,
                    "finding_promotion_rate": 1.0,
                    "incident_promotion_rate": 0.5,
                }
            ],
            "tuning_recommendations": [
                {
                    "rule": "Suspicious Admin Tool Staging",
                    "suggestion": "review_incident_correlation_coverage",
                    "reason": "This rule promotes strongly into findings but rarely contributes to an incident narrative.",
                    "metrics": {
                        "raw_alert_count": 3,
                        "suppressed_alert_count": 1,
                        "post_filter_alert_count": 2,
                        "deduplicated_alert_count": 0,
                        "post_dedup_alert_count": 2,
                        "finding_count": len(findings),
                        "incident_count": 1,
                    },
                }
            ],
            "campaign_summary": [
                {
                    "key_type": "user",
                    "key_value": r"corp\analyst",
                    "display_value": r"corp\analyst",
                    "host_count": 2,
                    "hosts": ["host1", "host2"],
                    "artifact_count": 2,
                    "finding_count": 0,
                    "incident_count": 1,
                    "finding_ids": [],
                    "incident_ids": ["inc-synthetic"],
                    "titles": ["Synthetic Correlated Activity"],
                    "first_seen": base.isoformat(),
                    "last_seen": (base + timedelta(minutes=5)).isoformat(),
                    "summary": r"Shared user corp\analyst appears across 2 hosts with 2 related artifacts.",
                }
            ],
            "collection_quality_summary": {
                "mode": "offline",
                "source_kind": "files",
                "source_count": 1,
                "completed_source_count": 1,
                "source_names": ["Security.evtx"],
                "parsed_event_count": 2,
                "warning_count": 0,
                "warning_sources": [],
                "permission_denied_sources": [],
                "fallback_used": False,
                "telemetry_present": ["Security"],
                "telemetry_missing": ["Sysmon", "PowerShell"],
                "recommendations": ["Enable or collect Sysmon telemetry for stronger process, network, and image-load context."],
                "summary": "Offline collection parsed 1 EVTX file(s) and produced 2 normalized event(s). Missing telemetry: Sysmon, PowerShell.",
            },
        }

        temp_dir = tempfile.mkdtemp(prefix="triage-case-metrics-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        output_path = Path(temp_dir) / "findings.json"
        data = export_case(
            signals=signals,
            findings=findings,
            incidents=[incident],
            filepath=str(output_path),
            legacy_alerts=alerts,
            case_meta=case_meta,
            raw_events=[alert.event for alert in alerts if alert.event],
            raw_event_artifact_path=str(Path(temp_dir) / "raw_events.jsonl"),
        )

        self.assertTrue(output_path.is_file())
        self.assertEqual(data["summary"]["raw_alert_count"], 3)
        self.assertEqual(data["summary"]["suppressed_alert_count"], 1)
        self.assertEqual(data["summary"]["deduplicated_alert_count"], 0)
        self.assertEqual(data["summary"]["post_dedup_alert_count"], 2)
        self.assertEqual(data["summary"]["response_priority"], "P2")
        self.assertEqual(data["summary"]["telemetry_gap_summary"]["missing"], ["Sysmon", "PowerShell"])
        self.assertEqual(data["summary"]["collection_quality_summary"]["mode"], "offline")
        self.assertEqual(data["summary"]["collection_quality_summary"]["source_count"], 1)
        self.assertEqual(data["summary"]["raw_event_summary"]["total_count"], 2)
        self.assertFalse(data["summary"]["raw_event_summary"]["truncated"])
        self.assertEqual(data["summary"]["rule_metrics"][0]["rule"], "Suspicious Admin Tool Staging")
        self.assertEqual(data["summary"]["tuning_recommendations"][0]["suggestion"], "review_incident_correlation_coverage")
        self.assertEqual(data["summary"]["campaign_summary"][0]["key_type"], "user")
        self.assertIn("promotion_reasons", data["findings"][0])
        self.assertIn("telemetry_gaps", data["findings"][0])
        self.assertEqual(data["incidents"][0]["why_flagged"], incident.why_flagged)

    def test_raw_event_preview_can_truncate_and_stream_full_sidecar(self):
        base = datetime(2026, 3, 11, 15, 12, tzinfo=timezone.utc)
        raw_events = [
            make_event(
                4688,
                timestamp=base + timedelta(seconds=offset),
                computer="host1",
                channel="Security",
                provider="Microsoft-Windows-Security-Auditing",
                subject_user="analyst",
                subject_domain="corp",
                process_name_value=rf"C:\Tools\tool{offset}.exe",
                command_line_value=rf"tool{offset}.exe /run",
                event_data={"NewProcessName": rf"C:\Tools\tool{offset}.exe", "CommandLine": rf"tool{offset}.exe /run"},
            )
            for offset in range(5)
        ]
        temp_dir = tempfile.mkdtemp(prefix="triage-raw-preview-")
        self.addCleanup(shutil.rmtree, temp_dir, True)
        findings_path = Path(temp_dir) / "findings.json"
        raw_events_path = Path(temp_dir) / "raw_events.jsonl"

        data = export_case(
            signals=[],
            findings=[],
            incidents=[],
            filepath=str(findings_path),
            raw_events=raw_events,
            case_meta={"case_name": "raw-preview"},
            raw_event_preview_limit=2,
            raw_event_artifact_path=str(raw_events_path),
        )
        raw_export = export_raw_events_stream(raw_events, str(raw_events_path))

        self.assertEqual(len(data["raw_events"]), 2)
        self.assertTrue(data["summary"]["raw_event_summary"]["truncated"])
        self.assertEqual(data["summary"]["raw_event_summary"]["preview_count"], 2)
        self.assertEqual(data["summary"]["raw_event_summary"]["total_count"], 5)
        self.assertEqual(raw_export["total_count"], 5)
        self.assertTrue(raw_events_path.is_file())
        self.assertEqual(len(raw_events_path.read_text(encoding="utf-8").splitlines()), 5)

    def test_rule_metrics_capture_promotion_and_recommendations(self):
        base = datetime(2026, 3, 11, 15, 20, tzinfo=timezone.utc)
        raw_alerts = [
            _make_correlate_alert(base),
            _make_correlate_alert(base + timedelta(minutes=1)),
            _make_correlate_alert(base + timedelta(minutes=2)),
        ]
        alerts = raw_alerts[:2]
        signals, findings, _ = alerts_to_signals_findings(alerts, telemetry_gaps=["Sysmon"])

        incident = Incident(
            id="inc-synthetic-2",
            display_label="INC-002",
            incident_type="correlated_attack_chain",
            title="Synthetic Correlated Activity",
            severity="medium",
            confidence="medium",
            confidence_score=70,
            summary="Synthetic incident for rule-metric validation.",
            first_seen=base,
            last_seen=base + timedelta(minutes=1),
            finding_ids=[findings[0].id],
            signal_ids=[signals[0].id],
        )

        rule_metrics = build_rule_metrics(raw_alerts, alerts, alerts, signals, findings, [incident])
        self.assertEqual(rule_metrics[0]["rule"], "Suspicious Admin Tool Staging")
        self.assertEqual(rule_metrics[0]["raw_alert_count"], 3)
        self.assertEqual(rule_metrics[0]["suppressed_alert_count"], 1)
        self.assertEqual(rule_metrics[0]["deduplicated_alert_count"], 0)
        self.assertEqual(rule_metrics[0]["finding_count"], 2)
        self.assertEqual(rule_metrics[0]["incident_count"], 1)

        recommendations = build_tuning_recommendations(
            [
                {
                    "rule": "Suspicious Admin Tool Staging",
                    "raw_alert_count": 3,
                    "suppressed_alert_count": 1,
                    "post_filter_alert_count": 2,
                    "deduplicated_alert_count": 0,
                    "post_dedup_alert_count": 2,
                    "signal_count": 2,
                    "finding_count": 0,
                    "incident_count": 0,
                    "suppression_rate": 0.3333,
                    "deduplication_rate": 0.0,
                    "finding_promotion_rate": 0.0,
                    "incident_promotion_rate": 0.0,
                }
            ]
        )
        self.assertEqual(recommendations[0]["rule"], "Suspicious Admin Tool Staging")
        self.assertEqual(recommendations[0]["suggestion"], "review_signal_only_or_correlate_policy")

    def test_campaign_summary_highlights_shared_user_across_hosts(self):
        base = datetime(2026, 3, 11, 15, 30, tzinfo=timezone.utc)
        incident_a = Incident(
            id="inc-host1",
            display_label="INC-101",
            incident_type="correlated_attack_chain",
            title="Synthetic Host 1 Incident",
            severity="high",
            confidence="high",
            confidence_score=85,
            summary="Synthetic multi-host activity.",
            first_seen=base,
            last_seen=base + timedelta(minutes=2),
            host="host1",
            user=r"corp\alice",
            source_ip="10.10.10.5",
        )
        incident_b = Incident(
            id="inc-host2",
            display_label="INC-102",
            incident_type="correlated_attack_chain",
            title="Synthetic Host 2 Incident",
            severity="high",
            confidence="high",
            confidence_score=87,
            summary="Synthetic multi-host activity.",
            first_seen=base + timedelta(minutes=5),
            last_seen=base + timedelta(minutes=7),
            host="host2",
            user=r"corp\alice",
            source_ip="10.10.10.5",
        )

        campaigns = build_campaign_summary([], [], [incident_a, incident_b])
        self.assertEqual(len(campaigns), 2)
        user_campaign = next(item for item in campaigns if item["key_type"] == "user")
        ip_campaign = next(item for item in campaigns if item["key_type"] == "ip")
        self.assertEqual(user_campaign["host_count"], 2)
        self.assertEqual(user_campaign["display_value"], "corp\\alice")
        self.assertEqual(ip_campaign["key_value"], "10.10.10.5")
        self.assertEqual(sorted(user_campaign["incident_ids"]), ["inc-host1", "inc-host2"])

    def test_summary_and_brief_include_campaign_and_tuning_context(self):
        base = datetime(2026, 3, 11, 15, 40, tzinfo=timezone.utc)
        incident = Incident(
            id="inc-brief",
            display_label="INC-201",
            incident_type="correlated_attack_chain",
            title="Synthetic Brief Incident",
            severity="high",
            confidence="high",
            confidence_score=91,
            summary="Synthetic incident used to validate short artifacts.",
            first_seen=base,
            last_seen=base + timedelta(minutes=4),
            host="host1",
            user=r"corp\alice",
            source_ip="10.10.10.5",
            confidence_factors=["multi_signal"],
            recommended_pivots=["host:host1", r"user:corp\alice"],
            why_flagged="The same account appeared across multiple suspicious hosts.",
            containment_guidance=["Isolate host1 before broader scoping."],
            scope_next=["Pivot on corp\\alice across the rest of the case."],
            validation_steps=["Confirm whether corp\\alice owns both hosts."],
        )
        case_meta = {
            "case_name": "brief-case",
            "input_source": "unit-test",
            "primary_host": "host1",
            "primary_user": r"corp\alice",
            "primary_source_ip": "10.10.10.5",
            "response_priority": "P1",
            "first_seen": base.isoformat(),
            "last_seen": (base + timedelta(minutes=4)).isoformat(),
            "hosts": ["host1", "host2"],
            "users": [r"corp\alice"],
            "ips": ["10.10.10.5"],
            "telemetry_summary": {
                "present": ["Security", "Sysmon"],
                "missing": ["PowerShell"],
            },
            "suppression_summary": {
                "suppressed_total": 1,
                "by_reason": {"allowlist_processes": 1},
            },
            "case_metrics": {
                "raw_alert_count": 4,
                "suppressed_alert_count": 1,
                "post_filter_alert_count": 3,
                "deduplicated_alert_count": 1,
                "post_dedup_alert_count": 2,
                "signal_count": 2,
                "finding_count": 1,
                "incident_count": 1,
                "finding_promotion_rate": 0.5,
                "incident_promotion_rate": 1.0,
            },
            "campaign_summary": [
                {
                    "summary": r"Shared user corp\alice appears across 2 hosts with 2 related artifacts.",
                }
            ],
            "rule_metrics": [
                {
                    "rule": "Synthetic Rule",
                    "raw_alert_count": 4,
                    "suppressed_alert_count": 1,
                    "deduplicated_alert_count": 1,
                    "finding_count": 1,
                    "incident_count": 1,
                }
            ],
            "tuning_recommendations": [
                {
                    "rule": "Synthetic Rule",
                    "suggestion": "review_signal_only_or_correlate_policy",
                    "reason": "Synthetic recommendation for short artifact validation.",
                }
            ],
            "collection_quality_summary": {
                "mode": "offline",
                "source_kind": "files",
                "source_count": 2,
                "completed_source_count": 2,
                "source_names": ["Security.evtx", "System.evtx"],
                "parsed_event_count": 42,
                "warning_count": 0,
                "warning_sources": [],
                "permission_denied_sources": [],
                "fallback_used": False,
                "telemetry_present": ["Security", "Sysmon"],
                "telemetry_missing": ["PowerShell"],
                "recommendations": ["Include PowerShell Operational logging for better script-based detection coverage."],
                "summary": "Offline collection parsed 2 EVTX file(s) and produced 42 normalized event(s). Missing telemetry: PowerShell.",
            },
        }
        timeline_rows = [
            {
                "timestamp": base.isoformat(),
                "display_label": "INC-201",
                "title": "Synthetic Brief Incident",
                "type": "incident",
            }
        ]

        temp_dir = tempfile.mkdtemp(prefix="triage-short-artifacts-")
        self.addCleanup(shutil.rmtree, temp_dir, True)

        summary_path = _write_summary_txt(temp_dir, case_meta, [], [], [incident])
        brief_path = _write_incident_brief(temp_dir, case_meta, [incident], timeline_rows)

        summary_text = Path(summary_path).read_text(encoding="utf-8")
        brief_text = Path(brief_path).read_text(encoding="utf-8")

        self.assertIn("Campaign Summary:", summary_text)
        self.assertIn(r"Shared user corp\alice appears across 2 hosts", summary_text)
        self.assertIn("Top Rule Metrics:", summary_text)
        self.assertIn("Tuning Recommendations:", summary_text)
        self.assertIn("Deduplicated Alert Count: 1", summary_text)
        self.assertIn("Collection Quality Summary:", summary_text)
        self.assertIn("Collection Source Kind: files", summary_text)
        self.assertIn("Collection Recommendations:", summary_text)

        self.assertIn("## Campaign Summary", brief_text)
        self.assertIn("## Collection Quality", brief_text)
        self.assertIn("Source kind: files", brief_text)
        self.assertIn(r"Shared user corp\alice appears across 2 hosts", brief_text)
        self.assertIn("## Detection Quality Notes", brief_text)
        self.assertIn("Synthetic Rule: raw 4, suppressed 1, findings 1, incidents 1", brief_text)
        self.assertIn("- Deduplicated alerts: 1", brief_text)
        self.assertIn("Tune: Synthetic Rule: review_signal_only_or_correlate_policy", brief_text)

    def test_offline_collection_quality_summary_highlights_fallback_and_missing_telemetry(self):
        summary = _build_collection_quality_summary(
            input_mode="evtx_path",
            telemetry_summary={"present": ["Security"], "missing": ["Sysmon", "PowerShell"]},
            telemetry_gaps=["Sysmon", "PowerShell"],
            parse_profile={
                "file_count": 2,
                "files": [
                    r"C:\cases\Security.evtx",
                    r"C:\cases\System.evtx",
                ],
            },
            parse_progress={
                "completed_files": 2,
                "parsed_event_count": 0,
                "fallback_used": True,
            },
        )

        self.assertEqual(summary["mode"], "offline")
        self.assertEqual(summary["source_kind"], "files")
        self.assertEqual(summary["source_count"], 2)
        self.assertEqual(summary["completed_source_count"], 2)
        self.assertTrue(summary["fallback_used"])
        self.assertEqual(summary["telemetry_missing"], ["Sysmon", "PowerShell"])
        self.assertIn("Parser fallback was used", summary["summary"])
        self.assertTrue(any("Sysmon telemetry" in item for item in summary["recommendations"]))
        self.assertTrue(any("PowerShell Operational logging" in item for item in summary["recommendations"]))
        self.assertTrue(any("Verify the EVTX path" in item for item in summary["recommendations"]))

    def test_brief_uses_calm_no_incident_actions_when_collection_is_healthy(self):
        base = datetime(2026, 3, 12, 15, 0, tzinfo=timezone.utc)
        case_meta = {
            "case_name": "healthy-live-case",
            "input_source": "live:Security,System,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-Sysmon/Operational",
            "primary_host": "host1",
            "primary_user": r"corp\alice",
            "primary_source_ip": "10.0.0.5",
            "response_priority": "P4",
            "first_seen": base.isoformat(),
            "last_seen": (base + timedelta(minutes=30)).isoformat(),
            "hosts": ["host1"],
            "users": [r"corp\alice"],
            "ips": ["10.0.0.5"],
            "telemetry_summary": {
                "present": ["Security", "Sysmon", "PowerShell"],
                "missing": [],
            },
            "suppression_summary": {
                "suppressed_total": 0,
                "by_reason": {},
            },
            "case_metrics": {
                "raw_alert_count": 0,
                "suppressed_alert_count": 0,
                "post_filter_alert_count": 0,
                "deduplicated_alert_count": 0,
                "post_dedup_alert_count": 0,
                "signal_count": 0,
                "finding_count": 0,
                "incident_count": 0,
                "finding_promotion_rate": 0.0,
                "incident_promotion_rate": 0.0,
            },
            "collection_quality_summary": {
                "mode": "live",
                "source_kind": "channels",
                "source_count": 4,
                "completed_source_count": 4,
                "source_names": ["Security", "System", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational"],
                "parsed_event_count": 20704,
                "warning_count": 0,
                "warning_sources": [],
                "permission_denied_sources": [],
                "fallback_used": False,
                "telemetry_present": ["Security", "Sysmon", "PowerShell"],
                "telemetry_missing": [],
                "recommendations": [],
                "summary": "Live collection scanned 4 channel(s) over the last 30 minute(s) and parsed 20704 event(s).",
            },
        }

        temp_dir = tempfile.mkdtemp(prefix="triage-healthy-live-brief-")
        self.addCleanup(shutil.rmtree, temp_dir, True)

        brief_path = _write_incident_brief(temp_dir, case_meta, [], [])
        brief_text = Path(brief_path).read_text(encoding="utf-8")

        self.assertIn("Collection coverage looked healthy for this window", brief_text)
        self.assertIn("Keep Sysmon, Security, and PowerShell logging enabled", brief_text)
        self.assertNotIn("Review collection quality and telemetry gaps", brief_text)

    def test_collection_quality_uses_observed_supplemental_live_telemetry(self):
        events = [
            make_event(
                5007,
                timestamp=datetime(2026, 3, 14, 20, 6, tzinfo=timezone.utc),
                computer="host1",
                channel="Microsoft-Windows-Windows Defender/Operational",
                provider="Microsoft-Windows-Windows Defender",
            ),
            make_event(
                5857,
                timestamp=datetime(2026, 3, 14, 20, 10, tzinfo=timezone.utc),
                computer="host1",
                channel="Microsoft-Windows-WMI-Activity/Operational",
                provider="Microsoft-Windows-WMI-Activity",
            ),
            make_event(
                3033,
                timestamp=datetime(2026, 3, 14, 20, 12, tzinfo=timezone.utc),
                computer="host1",
                channel="Microsoft-Windows-CodeIntegrity/Operational",
                provider="Microsoft-Windows-CodeIntegrity",
            ),
            make_event(
                21,
                timestamp=datetime(2026, 3, 14, 20, 16, tzinfo=timezone.utc),
                computer="host1",
                channel="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                provider="Microsoft-Windows-TerminalServices-LocalSessionManager",
            ),
        ]
        telemetry_summary = summarize_telemetry(events)
        summary = _build_collection_quality_summary(
            input_mode="live",
            telemetry_summary=telemetry_summary,
            telemetry_gaps=list(telemetry_summary.get("missing", [])),
            live_collection_summary={
                "channel_count": 4,
                "completed_channels": 4,
                "channels": [
                    "Microsoft-Windows-Windows Defender/Operational",
                    "Microsoft-Windows-WMI-Activity/Operational",
                    "Microsoft-Windows-CodeIntegrity/Operational",
                    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                ],
                "parsed_event_count": 41,
                "warning_count": 0,
                "warning_channels": [],
                "permission_denied_channels": [],
                "fallback_channels": 0,
                "summary": "Live collection scanned 4 channel(s) over the last 60 minute(s) and parsed 41 event(s).",
            },
        )

        self.assertEqual(
            summary["telemetry_present"],
            ["Windows Defender", "WMI-Activity", "CodeIntegrity", "TerminalServices"],
        )
        self.assertEqual(summary["telemetry_missing"], ["Security", "Sysmon", "PowerShell"])

    def test_summary_and_brief_prefer_collection_telemetry_display(self):
        base = datetime(2026, 3, 14, 20, 0, tzinfo=timezone.utc)
        case_meta = {
            "case_name": "live-secondary-telemetry",
            "input_source": "live:Microsoft-Windows-Windows Defender/Operational",
            "primary_host": "host1",
            "primary_user": "",
            "primary_source_ip": "",
            "response_priority": "P4",
            "first_seen": base.isoformat(),
            "last_seen": (base + timedelta(minutes=20)).isoformat(),
            "hosts": ["host1"],
            "users": [],
            "ips": [],
            "telemetry_summary": {
                "present": [],
                "missing": ["Security", "Sysmon", "PowerShell"],
                "observed": ["Windows Defender", "WMI-Activity"],
            },
            "suppression_summary": {"suppressed_total": 0, "by_reason": {}},
            "case_metrics": {
                "raw_alert_count": 0,
                "suppressed_alert_count": 0,
                "post_filter_alert_count": 0,
                "deduplicated_alert_count": 0,
                "post_dedup_alert_count": 0,
                "signal_count": 0,
                "finding_count": 0,
                "incident_count": 0,
                "finding_promotion_rate": 0.0,
                "incident_promotion_rate": 0.0,
            },
            "collection_quality_summary": {
                "mode": "live",
                "source_kind": "channels",
                "source_count": 2,
                "completed_source_count": 2,
                "source_names": [
                    "Microsoft-Windows-Windows Defender/Operational",
                    "Microsoft-Windows-WMI-Activity/Operational",
                ],
                "parsed_event_count": 41,
                "warning_count": 0,
                "warning_sources": [],
                "permission_denied_sources": [],
                "fallback_used": False,
                "telemetry_present": ["Windows Defender", "WMI-Activity"],
                "telemetry_missing": ["Security", "Sysmon", "PowerShell"],
                "recommendations": ["Collect Security telemetry for stronger authentication, privilege, and account-management coverage."],
                "summary": "Live collection scanned 2 channel(s) over the last 60 minute(s) and parsed 41 event(s).",
            },
        }

        temp_dir = tempfile.mkdtemp(prefix="triage-secondary-telemetry-")
        self.addCleanup(shutil.rmtree, temp_dir, True)

        summary_path = _write_summary_txt(temp_dir, case_meta, [], [], [])
        brief_path = _write_incident_brief(temp_dir, case_meta, [], [])
        summary_text = Path(summary_path).read_text(encoding="utf-8")
        brief_text = Path(brief_path).read_text(encoding="utf-8")

        self.assertIn("Telemetry Present: Windows Defender, WMI-Activity", summary_text)
        self.assertIn("- Telemetry present: Windows Defender, WMI-Activity", brief_text)

    def test_summary_and_brief_apply_demo_redaction_when_enabled(self):
        case_meta = {
            "case_name": "Codex review",
            "input_source_display": r"C:\Users\CodexSandbox\Downloads\demo.evtx",
            "primary_host": "demo-host",
            "primary_user": "CodexSandboxOffline",
            "primary_source_ip": "10.0.0.4",
            "response_priority": "P3",
            "first_seen": "2024-11-20T09:00:00+00:00",
            "last_seen": "2024-11-20T09:05:00+00:00",
            "case_metrics": {},
            "suppression_summary": {"by_reason": {}},
            "telemetry_summary": {"present": ["Security"], "missing": []},
            "collection_quality_summary": {
                "summary": "Offline collection parsed 1 EVTX file.",
                "source_kind": "files",
                "source_count": 1,
                "parsed_event_count": 12,
                "warning_count": 0,
                "warning_sources": [],
                "permission_denied_sources": [],
                "fallback_used": False,
                "telemetry_present": ["Security"],
                "telemetry_missing": [],
                "recommendations": [],
            },
            "hosts": ["demo-host"],
            "users": ["CodexSandboxOffline"],
            "ips": ["10.0.0.4"],
        }

        temp_dir = tempfile.mkdtemp(prefix="triage-demo-redaction-")
        self.addCleanup(shutil.rmtree, temp_dir, True)

        with mock.patch.dict(os.environ, {"TRIAGE_DEMO_REDACTION": "1"}, clear=False):
            summary_path = _write_summary_txt(temp_dir, case_meta, [], [], [])
            brief_path = _write_incident_brief(temp_dir, case_meta, [], [])

        summary_text = Path(summary_path).read_text(encoding="utf-8")
        brief_text = Path(brief_path).read_text(encoding="utf-8")

        self.assertNotIn("CodexSandbox", summary_text)
        self.assertNotIn("CodexSandbox", brief_text)
        self.assertIn("DemoUser", summary_text)
        self.assertIn("DemoUser", brief_text)
        self.assertIn("DemoAgent review", summary_text)
        self.assertIn("DemoAgent review", brief_text)


if __name__ == "__main__":
    unittest.main()
