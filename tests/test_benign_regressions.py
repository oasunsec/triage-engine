import unittest
from datetime import datetime, timedelta, timezone

from correlation.incident_builder import build_incidents
from detectors import credential_access, defense_evasion
from detectors.fp_filter import FPFilter
from models.event_model import Alert
from triage_engine.adapters import alerts_to_signals_findings

from tests.test_regressions import make_event


def _make_alert(rule_name, event, **kwargs):
    return Alert(
        rule_name=rule_name,
        severity=kwargs.pop("severity", "medium"),
        mitre_tactic=kwargs.pop("mitre_tactic", "Execution"),
        mitre_technique=kwargs.pop("mitre_technique", "T1059"),
        description=kwargs.pop("description", rule_name),
        explanation=kwargs.pop("explanation", f"{rule_name} matched synthetic benchmark input."),
        event=event,
        confidence=kwargs.pop("confidence", "medium"),
        evidence=kwargs.pop("evidence", {"evidence_strength": "medium"}),
        **kwargs,
    )


class BenignBenchmarkTests(unittest.TestCase):
    def test_benign_service_and_task_noise_is_suppressed(self):
        base = datetime(2026, 3, 11, 14, 0, tzinfo=timezone.utc)
        alerts = [
            _make_alert(
                "Scheduled Task Created",
                make_event(
                    4698,
                    timestamp=base,
                    subject_user="alice",
                    subject_domain="corp",
                    target_user="alice",
                    target_domain="corp",
                    event_data={"TaskName": r"\Microsoft\Windows\Defrag\ScheduledDefrag"},
                ),
                user=r"corp\alice",
            ),
            _make_alert(
                "Service Installed",
                make_event(
                    7045,
                    timestamp=base,
                    channel="System",
                    provider="Service Control Manager",
                    subject_user="alice",
                    subject_domain="corp",
                    target_user="alice",
                    target_domain="corp",
                    event_data={
                        "ServiceName": "Windows Event Log",
                        "ImagePath": r"C:\WindowsAzure\Packages\WaAppAgent.exe",
                    },
                ),
                user=r"corp\alice",
                service="Windows Event Log",
            ),
        ]

        fp = FPFilter()
        filtered = fp.apply(alerts)
        summary = fp.summary_dict()

        self.assertEqual(len(filtered), 0)
        self.assertEqual(summary["suppressed_total"], 2)
        self.assertEqual(summary["by_reason"].get("benign_task"), 1)
        self.assertEqual(summary["by_reason"].get("benign_service"), 1)

        signals, findings, _ = alerts_to_signals_findings(filtered, telemetry_gaps=["Sysmon"])
        incidents = build_incidents([], signals, findings, [])
        self.assertEqual(len(signals), 0)
        self.assertEqual(len(findings), 0)
        self.assertEqual(len(incidents), 0)

    def test_allowlist_tuning_reduces_alerts_predictably(self):
        event = make_event(
            1,
            timestamp=datetime(2026, 3, 11, 14, 5, tzinfo=timezone.utc),
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Program Files\CorpAdmin\agent.exe",
            command_line_value=r"C:\Program Files\CorpAdmin\agent.exe --inventory",
            event_data={
                "Image": r"C:\Program Files\CorpAdmin\agent.exe",
                "CommandLine": r"C:\Program Files\CorpAdmin\agent.exe --inventory",
                "User": r"corp\alice",
            },
            subject_user="alice",
            subject_domain="corp",
            target_user="alice",
            target_domain="corp",
        )
        alert = _make_alert(
            "Environment Inventory Tool",
            event,
            user=r"corp\alice",
            process=r"C:\Program Files\CorpAdmin\agent.exe",
            evidence={"evidence_strength": "medium"},
        )

        baseline_filter = FPFilter()
        baseline_filtered = baseline_filter.apply([alert])
        self.assertEqual(len(baseline_filtered), 1)

        tuned_filter = FPFilter(
            tuning={
                "allowlists": {
                    "hosts": [],
                    "users": [],
                    "processes": [r"C:\Program Files\CorpAdmin\*.exe"],
                    "services": [],
                    "tasks": [],
                    "ips": [],
                }
            }
        )
        tuned_filtered = tuned_filter.apply([alert])
        summary = tuned_filter.summary_dict()

        self.assertEqual(len(tuned_filtered), 0)
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("allowlist_processes"), 1)
        self.assertEqual(summary["by_rule"].get("Environment Inventory Tool"), 1)

    def test_rule_suppression_can_match_service_and_command_line_patterns(self):
        event = make_event(
            7045,
            timestamp=datetime(2026, 3, 11, 14, 10, tzinfo=timezone.utc),
            channel="System",
            provider="Service Control Manager",
            event_data={
                "ServiceName": "LenovoDiagnosticsDriver",
                "ImagePath": r"C:\ProgramData\Lenovo\Vantage\Addins\LenovoHardwareScanAddin\4.6.0.19\LenovoDiagnosticsDriver.sys",
            },
        )
        alert = _make_alert(
            "Suspicious Service Execution",
            event,
            severity="critical",
            mitre_tactic="Persistence",
            mitre_technique="T1543.003",
            service="LenovoDiagnosticsDriver",
        )

        fp = FPFilter(
            tuning={
                "rule_suppressions": [
                    {
                        "rule": "Suspicious Service Execution",
                        "service": "LenovoDiagnosticsDriver",
                        "command_line": r"*\ProgramData\Lenovo\Vantage\Addins\LenovoHardwareScanAddin\*",
                        "reason": "expected_lenovo_vantage_driver_path",
                    }
                ]
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("expected_lenovo_vantage_driver_path"), 1)
        self.assertEqual(summary["by_rule"].get("Suspicious Service Execution"), 1)

    def test_rule_suppression_can_match_user_wildcards(self):
        event = make_event(
            4738,
            timestamp=datetime(2026, 3, 11, 14, 12, tzinfo=timezone.utc),
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="oasun",
            subject_domain="Shollypoppi",
            target_user="CodexSandboxOffline",
            target_domain="Shollypoppi",
            event_data={
                "TargetUserName": "CodexSandboxOffline",
                "TargetDomainName": "Shollypoppi",
            },
        )
        alert = _make_alert(
            "Password Never Expires Enabled",
            event,
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            user=r"Shollypoppi\CodexSandboxOffline",
            evidence={"evidence_strength": "high"},
        )

        fp = FPFilter(
            tuning={
                "rule_suppressions": [
                    {
                        "rule": "Password Never Expires Enabled",
                        "user": r"*\CodexSandbox*",
                        "reason": "expected_codex_sandbox_service_account",
                    }
                ]
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("expected_codex_sandbox_service_account"), 1)
        self.assertEqual(summary["by_rule"].get("Password Never Expires Enabled"), 1)

    def test_rule_suppression_can_match_evidence_fields(self):
        event = make_event(
            4720,
            timestamp=datetime(2026, 3, 11, 14, 13, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="oasun",
            subject_domain="Shollypoppi",
            target_user="CodexSandboxOffline",
            target_domain="Shollypoppi",
            event_data={
                "TargetUserName": "CodexSandboxOffline",
                "TargetDomainName": "Shollypoppi",
                "SamAccountName": "CodexSandboxOffline",
            },
        )
        alert = _make_alert(
            "User Account Created",
            event,
            severity="medium",
            mitre_tactic="Persistence",
            mitre_technique="T1136.001",
            user=r"Shollypoppi\oasun",
            evidence={
                "new_account": "CodexSandboxOffline",
                "created_by": "oasun",
                "evidence_strength": "medium",
            },
        )

        fp = FPFilter(
            tuning={
                "rule_suppressions": [
                    {
                        "rule": "User Account Created",
                        "host": "Shollypoppi",
                        "evidence_new_account": "CodexSandbox*",
                        "evidence_created_by": "oasun",
                        "reason": "expected_codex_sandbox_account_bootstrap",
                    }
                ]
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("expected_codex_sandbox_account_bootstrap"), 1)
        self.assertEqual(summary["by_rule"].get("User Account Created"), 1)

    def test_rule_suppression_can_match_evidence_list_fields(self):
        event = make_event(
            4798,
            timestamp=datetime(2026, 3, 11, 14, 14, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="oasun",
            subject_domain="Shollypoppi",
            target_user="CodexSandboxOffline",
            target_domain="Shollypoppi",
            event_data={
                "TargetUserName": "CodexSandboxOffline",
                "TargetDomainName": "Shollypoppi",
            },
        )
        alert = _make_alert(
            "Local Account Enumeration",
            event,
            severity="medium",
            mitre_tactic="Discovery",
            mitre_technique="T1087.001",
            user=r"Shollypoppi\oasun",
            evidence={
                "actor_user": r"Shollypoppi\oasun",
                "enumerated_accounts": [r"Shollypoppi\CodexSandboxOffline", r"Shollypoppi\CodexSandboxOnline"],
                "evidence_strength": "medium",
            },
        )

        fp = FPFilter(
            tuning={
                "rule_suppressions": [
                    {
                        "rule": "Local Account Enumeration",
                        "host": "Shollypoppi",
                        "evidence_actor_user": r"*\oasun",
                        "evidence_enumerated_accounts": r"*\CodexSandbox*",
                        "reason": "expected_codex_sandbox_account_bootstrap",
                    }
                ]
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("expected_codex_sandbox_account_bootstrap"), 1)
        self.assertEqual(summary["by_rule"].get("Local Account Enumeration"), 1)

    def test_service_allowlist_supports_wildcards_for_versioned_services(self):
        event = make_event(
            7045,
            timestamp=datetime(2026, 3, 11, 14, 15, tzinfo=timezone.utc),
            channel="System",
            provider="Service Control Manager",
            event_data={
                "ServiceName": "GoogleUpdaterService147.0.7703.0",
                "ImagePath": r"C:\Program Files (x86)\Google\GoogleUpdater\147.0.7703.0\updater.exe",
            },
        )
        alert = _make_alert(
            "Service Installed",
            event,
            severity="critical",
            mitre_tactic="Persistence",
            mitre_technique="T1543.003",
            service="GoogleUpdaterService147.0.7703.0",
        )

        fp = FPFilter(
            tuning={
                "allowlists": {
                    "hosts": [],
                    "users": [],
                    "processes": [],
                    "services": ["GoogleUpdaterService*"],
                    "tasks": [],
                    "ips": [],
                }
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("allowlist_services"), 1)
        self.assertEqual(summary["by_rule"].get("Service Installed"), 1)

    def test_service_allowlist_matches_parenthetical_service_alias(self):
        event = make_event(
            7045,
            timestamp=datetime(2026, 3, 11, 14, 16, tzinfo=timezone.utc),
            channel="System",
            provider="Service Control Manager",
            event_data={
                "ServiceName": "Google Updater Internal Service (GoogleUpdaterInternalService147.0.7703.0)",
                "ImagePath": r"C:\Program Files (x86)\Google\GoogleUpdater\147.0.7703.0\updater.exe",
            },
        )
        alert = _make_alert(
            "Service Installed",
            event,
            severity="critical",
            mitre_tactic="Persistence",
            mitre_technique="T1543.003",
            service="Google Updater Internal Service (GoogleUpdaterInternalService147.0.7703.0)",
        )

        fp = FPFilter(
            tuning={
                "allowlists": {
                    "hosts": [],
                    "users": [],
                    "processes": [],
                    "services": ["GoogleUpdaterInternalService*"],
                    "tasks": [],
                    "ips": [],
                }
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("allowlist_services"), 1)
        self.assertEqual(summary["by_rule"].get("Service Installed"), 1)

    def test_rule_suppression_matches_exact_microsoft_defender_driver_path(self):
        event = make_event(
            7045,
            timestamp=datetime(2026, 3, 11, 14, 17, tzinfo=timezone.utc),
            channel="System",
            provider="Service Control Manager",
            event_data={
                "ServiceName": "KslD",
                "ImagePath": r"system32\drivers\wd\KslD.sys",
            },
        )
        alert = _make_alert(
            "Service Installed",
            event,
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1543.003",
            service="KslD",
        )

        fp = FPFilter(
            tuning={
                "rule_suppressions": [
                    {
                        "rule": "Service Installed",
                        "service": "KslD",
                        "command_line": r"*system32\drivers\wd\KslD.sys",
                        "reason": "expected_microsoft_defender_ksld_driver",
                    }
                ]
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("expected_microsoft_defender_ksld_driver"), 1)
        self.assertEqual(summary["by_rule"].get("Service Installed"), 1)

    def test_rule_suppression_matches_lenovo_tempinst_driver_path(self):
        event = make_event(
            7045,
            timestamp=datetime(2026, 3, 11, 14, 18, tzinfo=timezone.utc),
            channel="System",
            provider="Service Control Manager",
            event_data={
                "ServiceName": "TDKLIMIT",
                "ImagePath": r"c:\windows\TempInst\\TdkLimit64.sys",
            },
        )
        alert = _make_alert(
            "Service Installed",
            event,
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1543.003",
            service="TDKLIMIT",
        )

        fp = FPFilter(
            tuning={
                "rule_suppressions": [
                    {
                        "rule": "Service Installed",
                        "service": "TDKLIMIT",
                        "command_line": r"*\windows\tempinst\tdklimit64.sys",
                        "reason": "expected_lenovo_winflash_tempinst_driver",
                    }
                ]
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("expected_lenovo_winflash_tempinst_driver"), 1)
        self.assertEqual(summary["by_rule"].get("Service Installed"), 1)

    def test_benign_vault_churn_stays_signal_only(self):
        base = datetime(2026, 3, 11, 14, 20, tzinfo=timezone.utc)
        target_names = [
            "Adobe App Info (Part1)",
            "Adobe App Prefetched Info (Part1)",
            "Adobe Proxy Password(Part1)",
            "LenovoSsoSdkDidToken",
            "MicrosoftAccount:user=alice@example.com",
            "WindowsLive:target=virtualapp/didlogical",
        ]
        events = []
        for idx, target_name in enumerate(target_names):
            events.append(
                make_event(
                    5382 if idx == 0 else 5379,
                    timestamp=base + timedelta(seconds=idx),
                    computer="workstation1",
                    channel="Security",
                    provider="Microsoft-Windows-Security-Auditing",
                    subject_user="alice",
                    subject_domain="corp",
                    event_data={
                        "SubjectLogonId": "0x12345",
                        "Resource": "SnapshotEncryptionIV" if idx % 2 == 0 else "SnapshotEncryptionKey",
                        "Identity": "MicrosoftStore-Installs",
                        "TargetName": target_name,
                        "CountOfCredentialsReturned": "1",
                        "SchemaFriendlyName": "Windows Credentials",
                        "ReturnCode": "0",
                    },
                )
            )

        alerts = credential_access.detect(events)
        vault_alerts = [alert for alert in alerts if alert.rule_name == "Windows Credential Manager Access"]

        self.assertEqual(len(vault_alerts), 1)
        self.assertEqual(vault_alerts[0].promotion_policy, "correlate")
        self.assertEqual(vault_alerts[0].severity, "medium")
        self.assertEqual(vault_alerts[0].evidence.get("vault_access_profile"), "application_vault_churn")

        signals, findings, _ = alerts_to_signals_findings(vault_alerts, telemetry_gaps=["Sysmon"])
        self.assertEqual(len(signals), 1)
        self.assertEqual(len(findings), 0)

        fp = FPFilter()
        filtered_alerts = fp.apply(vault_alerts)
        summary = fp.summary_dict()
        self.assertEqual(filtered_alerts, [])
        self.assertEqual(summary["by_reason"].get("benign_vault_churn"), 1)

    def test_vault_export_activity_stays_finding_worthy(self):
        base = datetime(2026, 3, 11, 14, 25, tzinfo=timezone.utc)
        events = [
            make_event(
                5376,
                timestamp=base,
                computer="workstation1",
                channel="Security",
                provider="Microsoft-Windows-Security-Auditing",
                subject_user="alice",
                subject_domain="corp",
                event_data={
                    "SubjectLogonId": "0x12345",
                    "BackupFileName": r"C:\Windows\TEMP\CRD46C3.tmp",
                },
            ),
            make_event(
                5382,
                timestamp=base + timedelta(seconds=1),
                computer="workstation1",
                channel="Security",
                provider="Microsoft-Windows-Security-Auditing",
                subject_user="alice",
                subject_domain="corp",
                event_data={
                    "SubjectLogonId": "0x12345",
                    "Resource": "https://login.live.com/",
                    "Identity": "alice@example.com",
                    "TargetName": "MicrosoftOffice16_Data:live:cid=*",
                    "CountOfCredentialsReturned": "9",
                    "SchemaFriendlyName": "Windows Credentials",
                    "ReturnCode": "0",
                },
            ),
        ]

        alerts = credential_access.detect(events)
        vault_alerts = [alert for alert in alerts if alert.rule_name == "Windows Credential Manager Access"]

        self.assertEqual(len(vault_alerts), 1)
        self.assertEqual(vault_alerts[0].promotion_policy, "standalone")
        self.assertEqual(vault_alerts[0].severity, "high")
        self.assertEqual(vault_alerts[0].evidence.get("vault_access_profile"), "credential_export_or_retrieval")

        signals, findings, _ = alerts_to_signals_findings(vault_alerts, telemetry_gaps=["Sysmon"])
        self.assertEqual(len(signals), 1)
        self.assertEqual(len(findings), 1)

    def test_lsass_memory_access_ignores_low_signal_svchost_system_query(self):
        event = make_event(
            10,
            timestamp=datetime(2026, 3, 12, 15, 1, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            event_data={
                "SourceImage": r"C:\WINDOWS\system32\svchost.exe",
                "TargetImage": r"C:\WINDOWS\system32\lsass.exe",
                "GrantedAccess": "0x1000",
                "SourceUser": r"NT AUTHORITY\SYSTEM",
                "TargetUser": r"NT AUTHORITY\SYSTEM",
            },
        )

        alerts = credential_access.detect([event])
        lsass_alerts = [alert for alert in alerts if alert.rule_name == "LSASS Memory Access"]

        self.assertEqual(lsass_alerts, [])

    def test_lsass_memory_access_ignores_edgeupdate_system_query(self):
        event = make_event(
            10,
            timestamp=datetime(2026, 3, 12, 15, 2, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            event_data={
                "SourceImage": r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
                "TargetImage": r"C:\WINDOWS\system32\lsass.exe",
                "GrantedAccess": "0x1000",
                "SourceUser": r"NT AUTHORITY\SYSTEM",
                "TargetUser": r"NT AUTHORITY\SYSTEM",
            },
        )

        alerts = credential_access.detect([event])
        lsass_alerts = [alert for alert in alerts if alert.rule_name == "LSASS Memory Access"]

        self.assertEqual(lsass_alerts, [])

    def test_lsass_memory_access_ignores_defender_system_query_with_mpengine_calltrace(self):
        event = make_event(
            10,
            timestamp=datetime(2026, 3, 12, 15, 3, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe",
            event_data={
                "SourceImage": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe",
                "TargetImage": r"C:\WINDOWS\system32\lsass.exe",
                "GrantedAccess": "0x101000",
                "SourceUser": r"NT AUTHORITY\SYSTEM",
                "TargetUser": r"NT AUTHORITY\SYSTEM",
                "CallTrace": r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{ABCDEF01-1111-2222-3333-444455556666}\mpengine.dll+257ae",
            },
        )

        alerts = credential_access.detect([event])
        lsass_alerts = [alert for alert in alerts if alert.rule_name == "LSASS Memory Access"]

        self.assertEqual(lsass_alerts, [])

    def test_lsass_memory_access_ignores_sysmain_system_query_from_svchost(self):
        event = make_event(
            10,
            timestamp=datetime(2026, 3, 14, 20, 50, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\WINDOWS\system32\svchost.exe",
            event_data={
                "SourceImage": r"C:\WINDOWS\system32\svchost.exe",
                "TargetImage": r"C:\WINDOWS\system32\lsass.exe",
                "GrantedAccess": "0x2000",
                "SourceUser": r"NT AUTHORITY\SYSTEM",
                "TargetUser": r"NT AUTHORITY\SYSTEM",
                "CallTrace": r"C:\WINDOWS\SYSTEM32\ntdll.dll+161f54|C:\WINDOWS\System32\KERNELBASE.dll+42e76|c:\windows\system32\sysmain.dll+440e0",
            },
        )

        alerts = credential_access.detect([event])
        lsass_alerts = [alert for alert in alerts if alert.rule_name == "LSASS Memory Access"]

        self.assertEqual(lsass_alerts, [])

    def test_lsass_memory_access_still_detects_suspicious_procdump_access(self):
        event = make_event(
            10,
            timestamp=datetime(2026, 3, 12, 15, 4, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Tools\procdump.exe",
            event_data={
                "SourceImage": r"C:\Tools\procdump.exe",
                "TargetImage": r"C:\WINDOWS\system32\lsass.exe",
                "GrantedAccess": "0x1410",
                "SourceUser": r"CORP\alice",
                "TargetUser": r"NT AUTHORITY\SYSTEM",
            },
        )

        alerts = credential_access.detect([event])
        lsass_alert = next((alert for alert in alerts if alert.rule_name == "LSASS Memory Access"), None)

        self.assertIsNotNone(lsass_alert)
        self.assertEqual(lsass_alert.severity, "critical")
        self.assertEqual(lsass_alert.evidence.get("access_mask"), "0x1410")

    def test_remote_thread_injection_ignores_csrss_control_routine_into_python(self):
        event = make_event(
            8,
            timestamp=datetime(2026, 3, 14, 21, 35, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            event_data={
                "SourceImage": r"C:\Windows\System32\csrss.exe",
                "TargetImage": r"C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.13_3.13.3312.0_x64__qbz5n2kfra8p0\python3.13.exe",
                "StartModule": r"C:\Windows\System32\KERNELBASE.dll",
                "StartFunction": "CtrlRoutine",
                "SourceUser": r"NT AUTHORITY\SYSTEM",
                "TargetUser": r"Shollypoppi\oasun",
            },
        )

        alerts = defense_evasion.detect([event])
        injection_alert = next((alert for alert in alerts if alert.rule_name == "Remote Thread Injection"), None)

        self.assertIsNone(injection_alert)

    def test_remote_thread_injection_still_detects_non_control_routine_injection(self):
        event = make_event(
            8,
            timestamp=datetime(2026, 3, 14, 21, 36, tzinfo=timezone.utc),
            computer="host1",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            event_data={
                "SourceImage": r"C:\Tools\injector.exe",
                "TargetImage": r"C:\Windows\explorer.exe",
                "StartModule": r"C:\Windows\System32\ntdll.dll",
                "StartFunction": "RtlUserThreadStart",
                "SourceUser": r"CORP\alice",
                "TargetUser": r"CORP\bob",
            },
        )

        alerts = defense_evasion.detect([event])
        injection_alert = next((alert for alert in alerts if alert.rule_name == "Remote Thread Injection"), None)

        self.assertIsNotNone(injection_alert)
        self.assertEqual(injection_alert.evidence.get("source"), r"C:\Tools\injector.exe")
        self.assertEqual(injection_alert.evidence.get("target"), r"C:\Windows\explorer.exe")

    def test_rule_suppression_matches_exact_codex_encoded_powershell_chain(self):
        event = make_event(
            1,
            timestamp=datetime(2026, 3, 12, 15, 5, tzinfo=timezone.utc),
            computer="Shollypoppi",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Program Files\PowerShell\7\pwsh.exe",
            command_line_value="powershell [sanitized encoded payload]",
            parent_process_value=r"C:\Program Files\WindowsApps\OpenAI.Codex_26.309.3504.0_x64__2p2nqsd0c76g0\app\resources\codex.exe",
            event_data={
                "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
                "CommandLine": "powershell [sanitized encoded payload]",
                "ParentImage": r"C:\Program Files\WindowsApps\OpenAI.Codex_26.309.3504.0_x64__2p2nqsd0c76g0\app\resources\codex.exe",
                "ParentCommandLine": r"\"C:\Program Files\WindowsApps\OpenAI.Codex_26.309.3504.0_x64__2p2nqsd0c76g0\app\resources\codex.exe\" app-server --analytics-default-enabled",
            },
        )
        alert = _make_alert(
            "Suspicious: PowerShell Encoded Command",
            event,
            severity="high",
            mitre_tactic="Defense Evasion",
            mitre_technique="T1059",
            process=r"C:\Program Files\PowerShell\7\pwsh.exe",
            parent_process=r"C:\Program Files\WindowsApps\OpenAI.Codex_26.309.3504.0_x64__2p2nqsd0c76g0\app\resources\codex.exe",
        )

        fp = FPFilter(
            tuning={
                "rule_suppressions": [
                    {
                        "rule": "Suspicious: PowerShell Encoded Command",
                        "host": "Shollypoppi",
                        "process": r"C:\Program Files\PowerShell\7\pwsh.exe",
                        "parent_process": r"C:\Program Files\WindowsApps\OpenAI.Codex_*\app\resources\codex.exe",
                        "command_line": "*encoded payload*",
                        "reason": "expected_codex_encoded_powershell_execution",
                    }
                ]
            }
        )

        filtered = fp.apply([alert])
        summary = fp.summary_dict()

        self.assertEqual(filtered, [])
        self.assertEqual(summary["suppressed_total"], 1)
        self.assertEqual(summary["by_reason"].get("expected_codex_encoded_powershell_execution"), 1)
        self.assertEqual(summary["by_rule"].get("Suspicious: PowerShell Encoded Command"), 1)


if __name__ == "__main__":
    unittest.main()
