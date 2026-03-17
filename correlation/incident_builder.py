"""Incident construction from findings/signals and event correlation patterns."""

from __future__ import annotations

from collections import Counter
import os
from datetime import datetime, timedelta
import re
from typing import Dict, List, Optional, Sequence, Tuple

from models.event_model import AttackChain, Finding, Incident, NormalizedEvent, Signal
from triage_engine.id_utils import stable_id

BENIGN_IPS = {"", "-", "127.0.0.1", "::1", "0.0.0.0", "fe80::1"}
REMOTE_CREDENTIAL_FINDINGS = {"Brute Force Attack", "Password Spray Attack", "MSSQL Password Spray", "Explicit Credential Use"}
REMOTE_CREDENTIAL_CONTEXT_FINDINGS = REMOTE_CREDENTIAL_FINDINGS | {
    "Pass-the-Hash Logon",
    "RunAs Different User",
    "Token Manipulation Activity",
}
POWERSHELL_SCRIPT_FINDINGS = {"PowerShell Download Cradle", "PowerShell Backdoor Provisioning"}
SPECIFIC_FINDING_TITLES = {
    "PetitPotam RPC Coercion",
    "Zerologon RPC Activity",
    "Machine Account Secret Modified",
    "Remote SAM Registry Hive Access",
    "Kerberos Password Spray",
    "MSSQL Password Spray",
    "NTDS.dit Snapshot Export",
    "LSASS Remote Thread Injection",
    "Protected Storage RPC Access",
    "TeamViewer Credential Memory Access",
    "Kekeo TSSSP Named Pipe",
    "Browser Logon Process Abuse",
    "DirectInput Keylogger Registration",
    "PowerShell Constrained Language Mode Disabled",
    "PowerShell Execution Policy Weakened",
    "PowerShell ScriptBlockLogging Disabled",
    "Windows Event Log Service Crash",
    "Remote Event Log Service Crash",
    "xp_cmdshell Enabled",
    "MSSQL xp_cmdshell Execution",
    "MSSQL xp_cmdshell Execution Attempt",
    "Pass-the-Hash Logon",
    "AS-REP Roasting",
    "DCSync Directory Replication",
    "Golden Ticket Forgery Tooling",
    "Golden Ticket Use Pattern",
    "Silver Ticket Forgery Tooling",
    "MSHTA HTA Execution",
    "Regsvr32 Scriptlet Execution",
    "WMIC XSL Script Processing",
    "Certutil Remote Download",
    "COM Hijacking Persistence",
    "WMI Remote Execution",
    "WMI Event Subscription Persistence",
    "Application Shim Persistence",
    "Accessibility Features Backdoor",
    "New Privileged Account Provisioned",
    "Shadow Credentials Modified",
    "AD CS Suspicious Certificate Request",
    "AD CS Vulnerable Template Change",
    "Delegation Configuration Changed",
    "Group Policy Object Modified",
    "Domain Policy Changed",
    "Cross-Account Password Change",
    "Privileged Account Password Reset",
    "Remote SAMR Password Reset",
    "Sensitive and Not Delegatable Enabled",
    "Kerberos Preauthentication Disabled",
    "Kerberos DES-Only Encryption Enabled",
    "Reversible Password Encryption Enabled",
    "User Renamed to Admin-Like Name",
    "Computer Account Spoofing Kerberos Abuse",
    "Computer Account Renamed Without Trailing Dollar",
    "SQL Database Role Membership Added",
    "SQL Server Role Membership Added",
    "SQL User Linked to Login",
    "Mass Group Membership Change",
    "Self-Added to Group",
    "Member Added to Sensitive Group",
    "AdminSDHolder Permissions Changed",
    "AdminSDHolder Rights Obfuscation",
    "SPN Added to User Account",
    "SPN Added to Computer Account",
    "AD Object Owner Changed",
    "AD CS OCSP Configuration Tampering",
    "Sensitive User Right Assigned",
    "System Security Access Granted",
    "SID History Added",
    "Windows Event Log Service Disabled",
    "Mimikatz Credential Dumping",
    "DCShadow Computer Object Staging",
    "Suspicious .NET Compilation from User Temp",
    "Security Audit LSASS Access",
    "Mimikatz LSASS Access",
    "LSASS Dump via RdrLeakDiag",
    "LSASS Dump via SilentProcessExit",
    "MemSSP Credential Log File",
    "PowerShell WER LSASS Dump",
    "PowerShell Credential Prompt Harvesting",
    "Suspicious: LSASS Dump (comsvcs)",
    "Task Manager LSASS Dump",
    "InstallUtil Proxy Execution",
    "DesktopImgDownldr Remote Download",
    "Netsh PortProxy RDP Tunnel",
    "Kerberos Loopback Administrator Logon",
    "Unmanaged PowerShell Injection",
    "Rundll32 Wermgr Hollowing",
    "DSRM Password Changed",
    "WDigest Logon Credential Storage Enabled",
    "Windows Credential Manager Access",
    "Service Failure Command Abuse",
    "Service ImagePath Command Abuse",
    "Windows Update UScheduler Command Hijack",
    "Service Creation Command",
    "Remote Service Creation Command",
    "PPLdump LSASS Dump",
    "IIS Webshell Command Execution",
    "DCOM MSHTA Remote Execution",
    "Potato-Style Named Pipe Impersonation",
    "Renamed PsExec Service Pipes",
    "DCOM Internet Explorer Execution",
    "WMI Permanent Event Subscription",
    "KeePass Master Key Theft",
    "Msiexec Package Proxy Execution",
    "UAC Bypass via Auto-Elevated Registry Hijack",
    "CMSTP UAC Bypass",
    "Volatile SYSTEMROOT UAC Bypass",
    "UAC Bypass via DLL Side-Loading",
    "WScript Manifest UAC Bypass",
    "Browser Credential Store Access",
    "TSCLIENT Startup Folder Drop",
    "Print Spooler Exploitation",
    "Service Account to SYSTEM Impersonation",
    "Office VBA Object Model Access Enabled",
    "FTP Script Command Execution",
    "Scheduled Task SYSTEM Elevation",
    "BITSAdmin Transfer",
    "PowerShell BITS Download",
    "PowerShell Archive Staging",
    "COR_PROFILER System Environment Hijack",
    "Guest Account Enabled",
    "Password Not Required Enabled",
    "Password Never Expires Enabled",
    "WMI Remote Registry Modification",
    "Registry Run Key Persistence",
    "BITS Notify Command Execution",
    "Windows Defender Service Tampering",
    "Windows Defender Malware Detection",
    "Windows Firewall Rule Added",
    "RDP Shadowing Enabled",
    "Service ImagePath Registry Hijack",
    "SIP Trust Provider Registration",
    "OpenSSH Server Installed",
    "OpenSSH Server Enabled",
    "OpenSSH Server Listening",
    "New SMB Share Added",
    "Remote Service Payload Staging",
    "PsExec Service Binary Drop",
}
LOCAL_SAM_SIGNAL_RULE = "Local SAM Account Created"
LOCAL_ADMIN_GROUP_FINDING = "Local Administrators Group Modified"
HIDDEN_USER_FINDING = "Hidden User Registry Value"
FAKE_COMPUTER_ACCOUNT_FINDING = "Fake Computer Account Created"
CLUSTERABLE_SIGNAL_RULES = SPECIFIC_FINDING_TITLES | {"Audit Log Cleared", "Explicit Credential Use"}


def build_incidents(
    events: List[NormalizedEvent],
    signals: List[Signal],
    findings: List[Finding],
    chains: List[AttackChain],
) -> List[Incident]:
    incidents: List[Incident] = []
    incidents.extend(_detect_powershell_backdoor_sequence(signals, findings))
    incidents.extend(_detect_local_admin_account_persistence(signals, findings))
    incidents.extend(_detect_hidden_local_account_persistence(signals, findings))
    incidents.extend(_detect_rundll32_mshta_scheduled_task_sequence(signals, findings))
    incidents.extend(_detect_wmi_remote_registry_persistence(findings))
    incidents.extend(_detect_sensitive_user_rights_assignment(findings))
    incidents.extend(_detect_bits_notify_execution(findings))
    incidents.extend(_detect_bits_client_job_clusters(findings))
    incidents.extend(_detect_remote_credential_sequence(events, signals, findings))
    incidents.extend(_detect_remote_service_execution(events, signals, findings))
    incidents.extend(_detect_pre_log_wipe(events, signals, findings))
    incidents.extend(_promote_audit_log_clear(findings))
    incidents.extend(_promote_high_priority_findings(findings, incidents))
    incidents.extend(_promote_clustered_signals(signals, findings, incidents))
    incidents.extend(_from_attack_chains(chains, signals, findings))

    unique: Dict[str, Incident] = {}
    for incident in incidents:
        if incident.id in unique:
            continue
        unique[incident.id] = incident

    return sorted(unique.values(), key=lambda i: (_ts_sort_key(i.first_seen or i.last_seen), i.id))


def _from_attack_chains(chains: List[AttackChain], signals: List[Signal], findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    for chain in chains:
        if not chain.alerts or len(chain.alerts) < 3:
            continue
        if _looks_like_specific_sequence(chain):
            continue

        signal_ids, finding_ids = _collect_related_ids(
            signals,
            findings,
            host=chain.host,
            start=chain.start_time,
            end=chain.end_time,
        )
        if not signal_ids and not finding_ids:
            continue

        entities = _entities_from_alerts(chain.alerts)
        title, technique_summary = _chain_title_and_summary(chain)
        recommended_next = _chain_recommended_next(chain)
        evidence_chain = [
            {
                "rule": a.rule_name,
                "severity": a.severity,
                "tactic": a.mitre_tactic,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "description": a.description,
                "host": a.host,
                "user": a.user,
                "source_ip": a.source_ip,
                "process": a.process,
                "command_line": a.event.command_line if a.event else "",
                "recommended_next": a.investigate_next,
            }
            for a in chain.alerts
        ]

        payload = {
            "incident_type": "correlated_attack_chain",
            "host": chain.host,
            "tactics": sorted(chain.tactics),
            "users": entities["users"],
            "ips": entities["ips"],
            "start": chain.start_time,
            "end": chain.end_time,
            "finding_ids": sorted(finding_ids),
            "signal_ids": sorted(signal_ids),
        }
        incident_id = stable_id("inc", payload)
        incidents.append(
            Incident(
                id=incident_id,
                display_label="",
                incident_type="correlated_attack_chain",
                title=title,
                severity=_incident_severity(signal_ids, finding_ids, findings),
                confidence="high" if chain.risk_score >= 60 else "medium",
                confidence_score=min(100, max(45, chain.risk_score)),
                summary=_chain_story(chain, entities),
                first_seen=chain.start_time,
                last_seen=chain.end_time,
                finding_ids=sorted(finding_ids),
                signal_ids=sorted(signal_ids),
                evidence_chain=evidence_chain,
                host=chain.host,
                user=entities["primary_user"],
                source_ip=entities["primary_ip"],
                process=entities["primary_process"],
                service=entities["primary_service"],
                command_line=entities["primary_command"],
                technique_summary=technique_summary,
                recommended_next=recommended_next,
            )
        )
    return incidents


def _detect_powershell_backdoor_sequence(signals: List[Signal], findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    download_findings = [f for f in findings if (f.title or "") == "PowerShell Download Cradle"]
    backdoor_findings = [f for f in findings if (f.title or "") == "PowerShell Backdoor Provisioning"]

    for download in download_findings:
        for backdoor in backdoor_findings:
            if download.host != backdoor.host:
                continue
            if not download.first_seen or not backdoor.first_seen:
                continue
            if abs((backdoor.first_seen - download.first_seen).total_seconds()) > 300:
                continue

            remote_url = backdoor.evidence.get("remote_url", "") or download.evidence.get("remote_url", "")
            remote_ip = backdoor.source_ip or download.source_ip or backdoor.evidence.get("remote_ip", "") or download.evidence.get("remote_ip", "")
            actor = backdoor.user or backdoor.evidence.get("actor_user", "") or download.user or download.evidence.get("actor_user", "")
            task_name = backdoor.evidence.get("task_name", "")
            created_username = backdoor.evidence.get("created_username", "")
            group_name = backdoor.evidence.get("group_name", "")
            group_member = backdoor.evidence.get("group_member", "")
            script_excerpt = backdoor.evidence.get("script_excerpt", "") or download.evidence.get("script_excerpt", "")
            first_seen = min(download.first_seen, backdoor.first_seen)
            last_seen = max(download.last_seen or download.first_seen, backdoor.last_seen or backdoor.first_seen)
            signal_ids = sorted(set(download.signal_ids + backdoor.signal_ids))
            finding_ids = sorted({download.id, backdoor.id})

            payload = {
                "incident_type": "powershell_backdoor_provisioning",
                "host": download.host,
                "user": actor,
                "remote_ip": remote_ip,
                "remote_url": remote_url,
                "task_name": task_name,
                "created_username": created_username,
                "finding_ids": finding_ids,
                "signal_ids": signal_ids,
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
            incident_id = stable_id("inc", payload)
            incidents.append(
                Incident(
                    id=incident_id,
                    display_label="",
                    incident_type="powershell_backdoor_provisioning",
                    title="Malicious PowerShell backdoor provisioning",
                    severity="critical",
                    confidence="high",
                    confidence_score=96,
                    summary=(
                        f"PowerShell on {download.host} fetched a remote payload from {remote_ip or remote_url or 'unknown source'} "
                        f"and provisioned persistence as {actor or 'unknown user'} by registering task {task_name or 'unknown'}, "
                        f"creating local user {created_username or 'unknown'}, and adding it to {group_name or 'Administrators'}."
                    ),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    finding_ids=finding_ids,
                    signal_ids=signal_ids,
                    evidence_chain=[
                        {
                            "type": "finding",
                            "id": download.id,
                            "label": download.display_label or download.id,
                            "title": download.title,
                            "timestamp": download.first_seen.isoformat() if download.first_seen else None,
                            "description": download.description,
                            "remote_url": remote_url,
                            "remote_ip": remote_ip,
                            "script_excerpt": download.evidence.get("script_excerpt", ""),
                        },
                        {
                            "type": "finding",
                            "id": backdoor.id,
                            "label": backdoor.display_label or backdoor.id,
                            "title": backdoor.title,
                            "timestamp": backdoor.first_seen.isoformat() if backdoor.first_seen else None,
                            "description": backdoor.description,
                            "task_name": task_name,
                            "created_username": created_username,
                            "group_name": group_name,
                            "group_member": group_member,
                            "script_excerpt": backdoor.evidence.get("script_excerpt", ""),
                        },
                    ],
                    host=download.host,
                    user=actor,
                    source_ip=remote_ip,
                    process="powershell.exe",
                    command_line=script_excerpt,
                    technique_summary="PowerShell -> Remote Payload Fetch -> Scheduled Task Persistence -> Local Backdoor User",
                    recommended_next=(
                        f"Isolate {download.host}, block outbound access to {remote_ip or remote_url or 'the remote source'}, remove task {task_name or '(unknown)'}, "
                        f"disable local user {created_username or '(unknown)'}, and reset credentials associated with {actor or 'the executing user'}."
                    ),
                )
            )

    return incidents


def _detect_local_admin_account_persistence(signals: List[Signal], findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    account_signals = [s for s in signals if s.source_rule == LOCAL_SAM_SIGNAL_RULE and s.timestamp]
    admin_findings = [f for f in findings if (f.title or "") == LOCAL_ADMIN_GROUP_FINDING and f.first_seen]

    for finding in admin_findings:
        related_signals = [
            signal
            for signal in account_signals
            if (signal.host or "") == (finding.host or "")
            and signal.timestamp
            and abs((finding.first_seen - signal.timestamp).total_seconds()) <= 7200
        ]
        if not related_signals:
            continue

        created_users = sorted(
            {
                (signal.evidence.get("created_username", "") or signal.user or "").strip()
                for signal in related_signals
                if (signal.evidence.get("created_username", "") or signal.user or "").strip()
            }
        )
        sam_paths = sorted(
            {
                path
                for signal in related_signals
                for path in signal.evidence.get("registry_paths", []) or []
                if path
            }
        )
        alias_paths = sorted(
            {
                path
                for path in finding.evidence.get("alias_paths", []) or []
                if path
            }
        ) or ([finding.evidence.get("registry_key", "")] if finding.evidence.get("registry_key", "") else [])

        first_seen = min([signal.timestamp for signal in related_signals if signal.timestamp] + [finding.first_seen])
        last_seen = max([signal.last_seen or signal.timestamp for signal in related_signals if signal.timestamp] + [finding.last_seen or finding.first_seen])
        signal_ids = sorted({signal.id for signal in related_signals})
        finding_ids = [finding.id]
        payload = {
            "incident_type": "local_admin_account_persistence",
            "host": finding.host,
            "created_users": created_users,
            "sam_paths": sam_paths,
            "alias_paths": alias_paths,
            "signal_ids": signal_ids,
            "finding_ids": finding_ids,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
        incident_id = stable_id("inc", payload)
        summary_users = ", ".join(created_users) if created_users else "unknown local account(s)"
        incidents.append(
            Incident(
                id=incident_id,
                display_label="",
                incident_type="local_admin_account_persistence",
                title="Local administrator account persistence",
                severity="critical",
                confidence="high",
                confidence_score=92,
                summary=(
                    f"{finding.host or 'Unknown host'} showed SAM-based local account provisioning for {summary_users} "
                    "followed by a local Administrators alias modification, indicating local administrator persistence."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
                finding_ids=finding_ids,
                signal_ids=signal_ids,
                evidence_chain=[
                    {
                        "type": "signal",
                        "id": signal.id,
                        "label": signal.display_label or signal.id,
                        "rule": signal.source_rule,
                        "timestamp": signal.timestamp.isoformat() if signal.timestamp else None,
                        "created_username": signal.evidence.get("created_username", "") or signal.user,
                        "registry_paths": signal.evidence.get("registry_paths", []),
                        "collapsed_event_count": signal.evidence.get("collapsed_event_count", 0),
                    }
                    for signal in related_signals
                ]
                + [
                    {
                        "type": "finding",
                        "id": finding.id,
                        "label": finding.display_label or finding.id,
                        "title": finding.title,
                        "timestamp": finding.first_seen.isoformat() if finding.first_seen else None,
                        "alias_paths": alias_paths,
                        "modification_count": finding.evidence.get("modification_count", 0),
                    }
                ],
                host=finding.host,
                user=created_users[0] if created_users else "",
                process=finding.process or next((signal.process for signal in related_signals if signal.process), ""),
                technique_summary="Local SAM Account Creation -> Local Administrators Alias Modification",
                recommended_next=(
                    "Enumerate local users and local Administrators membership on the host, disable unauthorized accounts, "
                    "and inspect how the SAM registry activity was initiated."
                ),
            )
        )

    return incidents


def _detect_hidden_local_account_persistence(signals: List[Signal], findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    account_signals = [
        signal
        for signal in signals
        if signal.timestamp and (signal.source_rule or "") in {LOCAL_SAM_SIGNAL_RULE, "Hidden Local Account Registry Entry"}
    ]
    account_findings = [
        finding
        for finding in findings
        if finding.first_seen and (finding.title or "") == FAKE_COMPUTER_ACCOUNT_FINDING
    ]
    hidden_findings = [
        finding
        for finding in findings
        if finding.first_seen and (finding.title or "") == HIDDEN_USER_FINDING
    ]

    def _coerce_list(value) -> List[str]:
        if isinstance(value, (list, tuple, set)):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value or "").strip()
        return [text] if text else []

    for hidden in hidden_findings:
        hidden_user = (
            hidden.evidence.get("hidden_username", "")
            or hidden.target_user
            or hidden.user
            or ""
        ).strip()
        if not hidden_user:
            continue
        hidden_norm = hidden_user.lower()

        related_signals = [
            signal
            for signal in account_signals
            if (signal.host or "") == (hidden.host or "")
            and signal.timestamp
            and abs((hidden.first_seen - signal.timestamp).total_seconds()) <= 7200
            and (
                (
                    signal.evidence.get("created_username", "")
                    or signal.target_user
                    or signal.user
                    or ""
                ).strip().lower()
                == hidden_norm
            )
        ]
        related_findings = [
            finding
            for finding in account_findings
            if (finding.host or "") == (hidden.host or "")
            and finding.first_seen
            and abs((hidden.first_seen - finding.first_seen).total_seconds()) <= 7200
            and (
                (
                    finding.evidence.get("new_account", "")
                    or finding.target_user
                    or finding.user
                    or ""
                ).strip().lower()
                == hidden_norm
            )
        ]
        if not related_signals and not related_findings:
            continue

        related_finding_ids = sorted({hidden.id, *[finding.id for finding in related_findings]})
        related_signal_ids = sorted(
            {
                *hidden.signal_ids,
                *[signal.id for signal in related_signals],
                *[signal_id for finding in related_findings for signal_id in finding.signal_ids],
            }
        )
        registry_paths = sorted(
            {
                *[
                    path
                    for signal in related_signals
                    for path in signal.evidence.get("registry_paths", []) or []
                    if path
                ],
                *[
                    path
                    for finding in related_findings
                    for path in finding.evidence.get("registry_paths", []) or []
                    if path
                ],
                *[
                    path
                    for path in hidden.evidence.get("registry_paths", []) or []
                    if path
                ],
            }
        )
        actors = sorted(
            {
                actor
                for finding in related_findings
                for actor in (
                    _coerce_list(finding.subject_user)
                    or _coerce_list(finding.evidence.get("created_by", ""))
                )
            }
            | {
                actor
                for signal in related_signals
                for actor in (
                    _coerce_list(signal.subject_user)
                    or _coerce_list(signal.evidence.get("created_by", ""))
                )
            }
            | {
                actor
                for actor in (
                    _coerce_list(hidden.subject_user)
                    or _coerce_list(hidden.evidence.get("modified_by", ""))
                )
            }
        )
        commands = [
            *[
                command
                for finding in related_findings
                for command in finding.evidence.get("command_lines", []) or []
                if command
            ],
            *[
                command
                for command in hidden.evidence.get("command_lines", []) or []
                if command
            ],
        ]
        first_seen = min(
            [hidden.first_seen]
            + [signal.timestamp for signal in related_signals if signal.timestamp]
            + [finding.first_seen for finding in related_findings if finding.first_seen]
        )
        last_seen = max(
            [hidden.last_seen or hidden.first_seen]
            + [signal.last_seen or signal.timestamp for signal in related_signals if signal.timestamp]
            + [finding.last_seen or finding.first_seen for finding in related_findings if finding.first_seen]
        )
        payload = {
            "incident_type": "hidden_local_account_persistence",
            "host": hidden.host,
            "username": hidden_user,
            "registry_paths": registry_paths,
            "finding_ids": related_finding_ids,
            "signal_ids": related_signal_ids,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
        incident_id = stable_id("inc", payload)
        incidents.append(
            Incident(
                id=incident_id,
                display_label="",
                incident_type="hidden_local_account_persistence",
                title="Hidden local account persistence",
                severity="critical" if related_findings else "high",
                confidence="high",
                confidence_score=91 if related_findings else 84,
                summary=(
                    f"{hidden.host or 'Unknown host'} showed local account provisioning for {hidden_user} "
                    "followed by Winlogon UserList hiding, indicating hidden-account persistence."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
                finding_ids=related_finding_ids,
                signal_ids=related_signal_ids,
                evidence_chain=[
                    *[
                        {
                            "type": "signal",
                            "id": signal.id,
                            "label": signal.display_label or signal.id,
                            "rule": signal.source_rule,
                            "timestamp": signal.timestamp.isoformat() if signal.timestamp else None,
                            "created_username": signal.evidence.get("created_username", "") or signal.user,
                            "registry_paths": signal.evidence.get("registry_paths", []),
                            "command_line": signal.command_line,
                        }
                        for signal in related_signals
                    ],
                    *[
                        {
                            "type": "finding",
                            "id": finding.id,
                            "label": finding.display_label or finding.id,
                            "title": finding.title,
                            "timestamp": finding.first_seen.isoformat() if finding.first_seen else None,
                            "created_username": finding.evidence.get("new_account", "") or finding.user,
                            "command_lines": finding.evidence.get("command_lines", []),
                            "processes": finding.evidence.get("processes", []),
                        }
                        for finding in related_findings
                    ],
                    {
                        "type": "finding",
                        "id": hidden.id,
                        "label": hidden.display_label or hidden.id,
                        "title": hidden.title,
                        "timestamp": hidden.first_seen.isoformat() if hidden.first_seen else None,
                        "hidden_username": hidden_user,
                        "registry_paths": hidden.evidence.get("registry_paths", []),
                        "command_lines": hidden.evidence.get("command_lines", []),
                    },
                ],
                host=hidden.host,
                user=hidden_user,
                process=hidden.process or next((finding.process for finding in related_findings if finding.process), ""),
                command_line=commands[0] if commands else hidden.command_line,
                technique_summary="Local Account Creation -> Winlogon SpecialAccounts UserList Hide",
                recommended_next=(
                    f"Enumerate local users on {hidden.host or 'the host'}, remove or disable unauthorized account {hidden_user}, "
                    "inspect SpecialAccounts\\UserList, and review the remote-management session or process chain that created and hid the account."
                ),
            )
        )

    return incidents


def _detect_rundll32_mshta_scheduled_task_sequence(signals: List[Signal], findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    rundll_findings = [finding for finding in findings if finding.first_seen and (finding.title or "") == "Rundll32 Proxy Execution"]
    mshta_findings = [finding for finding in findings if finding.first_seen and (finding.title or "") == "MSHTA HTA Execution"]
    task_findings = [finding for finding in findings if finding.first_seen and (finding.title or "") == "Suspicious Scheduled Task Command"]

    def _task_name(command: str) -> str:
        match = re.search(r"/tn\s+\"?([^\"/]+?)\"?(?:\s|$)", command or "", re.IGNORECASE)
        return (match.group(1) or "").strip() if match else ""

    for mshta in mshta_findings:
        related_rundll = next(
            (
                finding
                for finding in rundll_findings
                if (finding.host or "") == (mshta.host or "")
                and (not mshta.user or not finding.user or finding.user == mshta.user)
                and abs((mshta.first_seen - finding.first_seen).total_seconds()) <= 180
            ),
            None,
        )
        related_task = next(
            (
                finding
                for finding in task_findings
                if (finding.host or "") == (mshta.host or "")
                and (not mshta.user or not finding.user or finding.user == mshta.user)
                and 0 <= (finding.first_seen - mshta.first_seen).total_seconds() <= 600
            ),
            None,
        )
        if not related_rundll or not related_task:
            continue

        remote_url = (
            mshta.evidence.get("remote_url", "")
            or related_task.evidence.get("remote_url", "")
            or ""
        )
        task_command = related_task.evidence.get("command_line", "") or related_task.command_line
        task_name = _task_name(task_command)
        signal_ids = sorted({*related_rundll.signal_ids, *mshta.signal_ids, *related_task.signal_ids})
        finding_ids = sorted({related_rundll.id, mshta.id, related_task.id})
        first_seen = min(related_rundll.first_seen, mshta.first_seen, related_task.first_seen)
        last_seen = max(
            related_rundll.last_seen or related_rundll.first_seen,
            mshta.last_seen or mshta.first_seen,
            related_task.last_seen or related_task.first_seen,
        )
        payload = {
            "incident_type": "rundll32_mshta_scheduled_task_persistence",
            "host": mshta.host,
            "user": mshta.user or related_rundll.user or related_task.user,
            "remote_url": remote_url,
            "task_name": task_name,
            "finding_ids": finding_ids,
            "signal_ids": signal_ids,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
        incidents.append(
            Incident(
                id=stable_id("inc", payload),
                display_label="",
                incident_type="rundll32_mshta_scheduled_task_persistence",
                title="Rundll32 to MSHTA scheduled task persistence",
                severity="critical",
                confidence="high",
                confidence_score=93,
                summary=(
                    f"{mshta.user or 'Unknown user'} on {mshta.host or 'unknown host'} used rundll32.exe to launch mshta.exe"
                    f"{f' against {remote_url}' if remote_url else ''} and then created scheduled task {task_name or '(unknown)'} for persistence."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
                finding_ids=finding_ids,
                signal_ids=signal_ids,
                evidence_chain=[
                    {
                        "type": "finding",
                        "id": related_rundll.id,
                        "label": related_rundll.display_label or related_rundll.id,
                        "title": related_rundll.title,
                        "timestamp": related_rundll.first_seen.isoformat() if related_rundll.first_seen else None,
                        "command_line": _finding_command_line(related_rundll),
                        "proxy_marker": related_rundll.evidence.get("proxy_marker", ""),
                    },
                    {
                        "type": "finding",
                        "id": mshta.id,
                        "label": mshta.display_label or mshta.id,
                        "title": mshta.title,
                        "timestamp": mshta.first_seen.isoformat() if mshta.first_seen else None,
                        "remote_url": remote_url,
                        "command_line": _finding_command_line(mshta),
                    },
                    {
                        "type": "finding",
                        "id": related_task.id,
                        "label": related_task.display_label or related_task.id,
                        "title": related_task.title,
                        "timestamp": related_task.first_seen.isoformat() if related_task.first_seen else None,
                        "task_name": task_name,
                        "command_line": task_command,
                    },
                ],
                host=mshta.host,
                user=mshta.user or related_rundll.user or related_task.user,
                source_ip=mshta.source_ip,
                process=mshta.process,
                command_line=_finding_command_line(mshta),
                technique_summary="Rundll32 Proxy Execution -> MSHTA Remote Payload -> Scheduled Task Persistence",
                recommended_next=(
                    "Block the remote HTA source, remove the scheduled task, recover the HTA content, "
                    "and review whether the same user or host launched follow-on payloads."
                ),
            )
        )

    return incidents


def _detect_wmi_remote_registry_persistence(findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    registry_findings = [
        finding for finding in findings if finding.first_seen and (finding.title or "") == "WMI Remote Registry Modification"
    ]
    run_key_findings = [
        finding for finding in findings if finding.first_seen and (finding.title or "") == "Registry Run Key Persistence"
    ]

    for registry_finding in registry_findings:
        related_run_key = next(
            (
                finding
                for finding in run_key_findings
                if (finding.host or "") == (registry_finding.host or "")
                and abs((finding.first_seen - registry_finding.first_seen).total_seconds()) <= 600
            ),
            None,
        )
        if not related_run_key:
            continue

        signal_ids = sorted({*registry_finding.signal_ids, *related_run_key.signal_ids})
        finding_ids = sorted({registry_finding.id, related_run_key.id})
        first_seen = min(registry_finding.first_seen, related_run_key.first_seen)
        last_seen = max(
            registry_finding.last_seen or registry_finding.first_seen,
            related_run_key.last_seen or related_run_key.first_seen,
        )
        registry_key = related_run_key.evidence.get("registry_key", "") or ""
        payload = {
            "incident_type": "wmi_remote_registry_persistence",
            "host": registry_finding.host,
            "user": registry_finding.user or related_run_key.user,
            "source_ip": registry_finding.source_ip or registry_finding.evidence.get("remote_peer_ip", ""),
            "registry_key": registry_key,
            "finding_ids": finding_ids,
            "signal_ids": signal_ids,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
        incidents.append(
            Incident(
                id=stable_id("inc", payload),
                display_label="",
                incident_type="wmi_remote_registry_persistence",
                title="WMI remote registry persistence",
                severity="critical",
                confidence="high",
                confidence_score=92,
                summary=(
                    f"WMI registry modification on {registry_finding.host or 'unknown host'} "
                    f"was followed by Run-key persistence at {registry_key or 'an autorun key'}, "
                    "which is consistent with remote persistence staging."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
                finding_ids=finding_ids,
                signal_ids=signal_ids,
                evidence_chain=[
                    {
                        "type": "finding",
                        "id": registry_finding.id,
                        "label": registry_finding.display_label or registry_finding.id,
                        "title": registry_finding.title,
                        "timestamp": registry_finding.first_seen.isoformat() if registry_finding.first_seen else None,
                        "registry_key": registry_finding.evidence.get("target_object", "") or "",
                        "remote_peer_ip": registry_finding.evidence.get("remote_peer_ip", "") or registry_finding.source_ip,
                    },
                    {
                        "type": "finding",
                        "id": related_run_key.id,
                        "label": related_run_key.display_label or related_run_key.id,
                        "title": related_run_key.title,
                        "timestamp": related_run_key.first_seen.isoformat() if related_run_key.first_seen else None,
                        "registry_key": registry_key,
                        "command_line": _finding_command_line(related_run_key),
                    },
                ],
                host=registry_finding.host,
                user=registry_finding.user or related_run_key.user,
                source_ip=registry_finding.source_ip or registry_finding.evidence.get("remote_peer_ip", ""),
                process=registry_finding.process or related_run_key.process,
                command_line=_finding_command_line(related_run_key) or _finding_command_line(registry_finding),
                technique_summary="Windows Management Instrumentation -> Modify Registry -> Run Key Persistence",
                recommended_next=(
                    "Confirm the remote operator or management source, remove the Run key, inspect the referenced payload, "
                    "and review nearby WMI activity for additional persistence or execution steps."
                ),
            )
        )

    return incidents


def _detect_sensitive_user_rights_assignment(findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    grouped: Dict[Tuple[str, str, str], List[Finding]] = {}

    for finding in findings:
        if (finding.title or "") != "Sensitive User Right Assigned" or not finding.first_seen:
            continue
        actor = finding.evidence.get("actor_user", "") or finding.user or "unknown"
        target_sid = finding.evidence.get("target_sid", "") or "unknown"
        key = (finding.host or "unknown", actor.lower(), target_sid.lower())
        grouped.setdefault(key, []).append(finding)

    for (host, actor_lower, target_sid), cluster in grouped.items():
        ordered = sorted(cluster, key=lambda item: item.first_seen or datetime.min)
        current: List[Finding] = [ordered[0]]

        def _emit(cluster_findings: Sequence[Finding]) -> None:
            if not cluster_findings:
                return
            privileges = sorted(
                {
                    (finding.evidence.get("privilege", "") or "").strip()
                    for finding in cluster_findings
                    if (finding.evidence.get("privilege", "") or "").strip()
                }
            )
            signal_ids = sorted({signal_id for finding in cluster_findings for signal_id in finding.signal_ids})
            finding_ids = sorted({finding.id for finding in cluster_findings})
            first_seen = cluster_findings[0].first_seen
            last_seen = cluster_findings[-1].last_seen or cluster_findings[-1].first_seen
            actor = cluster_findings[0].evidence.get("actor_user", "") or cluster_findings[0].user or actor_lower
            payload = {
                "incident_type": "sensitive_user_rights_assignment",
                "host": host,
                "actor": actor,
                "target_sid": target_sid,
                "privileges": privileges,
                "finding_ids": finding_ids,
                "signal_ids": signal_ids,
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
            incidents.append(
                Incident(
                    id=stable_id("inc", payload),
                    display_label="",
                    incident_type="sensitive_user_rights_assignment",
                    title="Sensitive user rights assigned",
                    severity="critical" if any((f.severity or "").lower() == "critical" for f in cluster_findings) else "high",
                    confidence="high",
                    confidence_score=90 if any((f.severity or "").lower() == "critical" for f in cluster_findings) else 84,
                    summary=(
                        f"{actor} assigned {', '.join(privileges) or 'sensitive rights'} to {target_sid} on {host}, "
                        "which materially expands token and privilege abuse options for that principal."
                    ),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    finding_ids=finding_ids,
                    signal_ids=signal_ids,
                    evidence_chain=[
                        {
                            "type": "finding",
                            "id": finding.id,
                            "label": finding.display_label or finding.id,
                            "title": finding.title,
                            "timestamp": finding.first_seen.isoformat() if finding.first_seen else None,
                            "privilege": finding.evidence.get("privilege", ""),
                            "target_sid": finding.evidence.get("target_sid", ""),
                        }
                        for finding in cluster_findings
                    ],
                    host=host,
                    user=actor,
                    technique_summary="Privilege Escalation -> Access Token Manipulation / Account Rights",
                    recommended_next=(
                        "Resolve the target SID to a principal, validate whether each granted right was authorized, "
                        "and review subsequent logons or privileged actions performed by that principal."
                    ),
                )
            )

        for finding in ordered[1:]:
            previous = current[-1]
            if previous.first_seen and finding.first_seen and finding.first_seen - previous.first_seen <= timedelta(hours=1):
                current.append(finding)
            else:
                _emit(current)
                current = [finding]
        _emit(current)

    return incidents


def _detect_bits_notify_execution(findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    notify_findings = [finding for finding in findings if finding.first_seen and (finding.title or "") == "BITS Notify Command Execution"]
    follow_on_titles = {"Regsvr32 Scriptlet Execution", "MSHTA HTA Execution", "PowerShell Encoded Payload", "PowerShell Obfuscated Script"}
    follow_on_findings = [finding for finding in findings if finding.first_seen and (finding.title or "") in follow_on_titles]

    for notify in notify_findings:
        related = next(
            (
                finding
                for finding in follow_on_findings
                if (finding.host or "") == (notify.host or "")
                and 0 <= (finding.first_seen - notify.first_seen).total_seconds() <= 900
            ),
            None,
        )
        if not related:
            continue

        signal_ids = sorted({*notify.signal_ids, *related.signal_ids})
        finding_ids = sorted({notify.id, related.id})
        first_seen = min(notify.first_seen, related.first_seen)
        last_seen = max(notify.last_seen or notify.first_seen, related.last_seen or related.first_seen)
        payload = {
            "incident_type": "bits_notify_execution",
            "host": notify.host,
            "user": notify.user or related.user,
            "command_line": _finding_command_line(notify),
            "follow_on_title": related.title,
            "finding_ids": finding_ids,
            "signal_ids": signal_ids,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
        incidents.append(
            Incident(
                id=stable_id("inc", payload),
                display_label="",
                incident_type="bits_notify_execution",
                title="BITS notify command execution",
                severity="critical",
                confidence="high",
                confidence_score=91,
                summary=(
                    f"A BITS notify job on {notify.host or 'unknown host'} launched follow-on activity via "
                    f"{related.title.lower()} as {notify.user or related.user or 'unknown user'}."
                ),
                first_seen=first_seen,
                last_seen=last_seen,
                finding_ids=finding_ids,
                signal_ids=signal_ids,
                evidence_chain=[
                    {
                        "type": "finding",
                        "id": notify.id,
                        "label": notify.display_label or notify.id,
                        "title": notify.title,
                        "timestamp": notify.first_seen.isoformat() if notify.first_seen else None,
                        "command_line": _finding_command_line(notify),
                    },
                    {
                        "type": "finding",
                        "id": related.id,
                        "label": related.display_label or related.id,
                        "title": related.title,
                        "timestamp": related.first_seen.isoformat() if related.first_seen else None,
                        "command_line": _finding_command_line(related),
                    },
                ],
                host=notify.host,
                user=notify.user or related.user,
                process=related.process or notify.process,
                command_line=_finding_command_line(related) or _finding_command_line(notify),
                technique_summary="BITS Job -> Notify Command Execution",
                recommended_next=(
                    "Enumerate the BITS job configuration, recover the notify command payload, and inspect the child process or script for persistence or follow-on execution."
                ),
            )
        )

    return incidents


def _detect_bits_client_job_clusters(findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    grouped: Dict[Tuple[str, str], List[Finding]] = {}

    for finding in findings:
        if (finding.title or "") != "BITS Client Suspicious Job" or not finding.first_seen:
            continue
        key = (finding.host or "unknown", (finding.user or "unknown").lower())
        grouped.setdefault(key, []).append(finding)

    for (host, _user_key), cluster in grouped.items():
        ordered = sorted(cluster, key=lambda item: item.first_seen or datetime.min)
        current: List[Finding] = [ordered[0]]

        def _emit(cluster_findings: Sequence[Finding]) -> None:
            if not cluster_findings:
                return
            signal_ids = sorted({signal_id for finding in cluster_findings for signal_id in finding.signal_ids})
            finding_ids = sorted({finding.id for finding in cluster_findings})
            first_seen = cluster_findings[0].first_seen
            last_seen = cluster_findings[-1].last_seen or cluster_findings[-1].first_seen
            urls = sorted(
                {
                    (finding.evidence.get("remote_url", "") or "").strip()
                    for finding in cluster_findings
                    if (finding.evidence.get("remote_url", "") or "").strip()
                }
            )
            job_names = sorted(
                {
                    (finding.evidence.get("job_name", "") or "").strip()
                    for finding in cluster_findings
                    if (finding.evidence.get("job_name", "") or "").strip()
                }
            )
            actor = cluster_findings[0].user or "unknown user"
            payload = {
                "incident_type": "bits_suspicious_job",
                "host": host,
                "user": actor,
                "job_names": job_names,
                "urls": urls,
                "finding_ids": finding_ids,
                "signal_ids": signal_ids,
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
            incidents.append(
                Incident(
                    id=stable_id("inc", payload),
                    display_label="",
                    incident_type="bits_suspicious_job",
                    title="Suspicious BITS job activity",
                    severity="critical" if any((f.severity or "").lower() == "critical" for f in cluster_findings) else "high",
                    confidence="high",
                    confidence_score=88,
                    summary=(
                        f"{actor} created or modified suspicious BITS jobs on {host}"
                        f"{f' contacting {urls[0]}' if urls else ''}, which may support staged download or persistence."
                    ),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    finding_ids=finding_ids,
                    signal_ids=signal_ids,
                    evidence_chain=[
                        {
                            "type": "finding",
                            "id": finding.id,
                            "label": finding.display_label or finding.id,
                            "title": finding.title,
                            "timestamp": finding.first_seen.isoformat() if finding.first_seen else None,
                            "job_name": finding.evidence.get("job_name", ""),
                            "remote_url": finding.evidence.get("remote_url", ""),
                        }
                        for finding in cluster_findings
                    ],
                    host=host,
                    user=actor,
                    technique_summary="Background Intelligent Transfer Service -> Download / Persistence",
                    recommended_next=(
                        "List and remove the suspicious BITS jobs, recover any downloaded payloads, and review notify actions or persistence tied to the same user and host."
                    ),
                )
            )

        for finding in ordered[1:]:
            previous = current[-1]
            if previous.first_seen and finding.first_seen and finding.first_seen - previous.first_seen <= timedelta(hours=1):
                current.append(finding)
            else:
                _emit(current)
                current = [finding]
        _emit(current)

    return incidents


def _detect_remote_credential_sequence(
    events: List[NormalizedEvent], signals: List[Signal], findings: List[Finding]
) -> List[Incident]:
    incidents: List[Incident] = []
    timed_events = sorted((e for e in events if e.timestamp), key=lambda e: e.timestamp)
    emitted: Dict[Tuple[str, str, str], datetime] = {}

    for ev in timed_events:
        if ev.event_id != 4624 or ev.logon_type not in ("3", "10"):
            continue
        src = (ev.source_ip or "").strip()
        user = ev.target_domain_user or ev.domain_user
        if src in BENIGN_IPS or not user:
            continue
        emit_key = (ev.computer or "", src, user)
        if emit_key in emitted and ev.timestamp - emitted[emit_key] <= timedelta(minutes=5):
            continue

        window_start = ev.timestamp - timedelta(minutes=10)
        window_end = ev.timestamp + timedelta(minutes=10)
        failed = [
            item for item in timed_events
            if item.event_id == 4625
            and item.timestamp
            and window_start <= item.timestamp <= ev.timestamp
            and (item.source_ip or "").strip() == src
            and (item.target_domain_user or item.target_user) == user
        ]
        explicit = _first_match(
            timed_events,
            ev.timestamp,
            window_end,
            lambda item: item.event_id == 4648
            and (item.source_ip or "").strip() == src
            and (item.target_domain_user or item.target_user) == user,
        )
        privileged = _first_match(
            timed_events,
            ev.timestamp,
            window_end,
            lambda item: item.event_id == 4672 and (item.subject_domain_user or item.subject_user) == user,
        )

        if not failed and not explicit and not privileged:
            continue

        sequence = [*failed[-3:], ev]
        if explicit:
            sequence.append(explicit)
        if privileged:
            sequence.append(privileged)
        sequence = sorted(sequence, key=lambda item: item.timestamp or datetime.min)

        start = sequence[0].timestamp
        end = sequence[-1].timestamp
        signal_ids, finding_ids = _collect_related_ids(signals, findings, ev.computer, start, end)
        specific_remote_sam = any(
            finding.host == ev.computer
            and (finding.title or "") == "Remote SAM Registry Hive Access"
            and finding.first_seen
            and start <= finding.first_seen <= end
            and (not finding.user or finding.user == user)
            for finding in findings
        )
        if specific_remote_sam:
            emitted[emit_key] = ev.timestamp
            continue
        signal_ids = sorted(
            {
                signal.id
                for signal in signals
                if signal.id in signal_ids and (signal.source_rule or "") in REMOTE_CREDENTIAL_CONTEXT_FINDINGS
            }
        )
        finding_ids = sorted(
            {
                finding.id
                for finding in findings
                if finding.id in finding_ids and (finding.title or "") in REMOTE_CREDENTIAL_CONTEXT_FINDINGS
            }
        )
        if not signal_ids and not finding_ids:
            continue
        payload = {
            "incident_type": "remote_credential_sequence",
            "host": ev.computer,
            "source_ip": src,
            "user": user,
            "event_ids": [item.event_id for item in sequence],
            "finding_ids": sorted(finding_ids),
            "signal_ids": sorted(signal_ids),
            "start": start,
            "end": end,
        }
        incident_id = stable_id("inc", payload)
        summary_parts = []
        if failed:
            summary_parts.append(f"{len(failed)} failed logons preceded the successful access")
        summary_parts.append(f"{user} logged onto {ev.computer} from {src}")
        if explicit:
            summary_parts.append(
                f"explicit credentials were then used via {explicit.process_name or 'unknown process'}"
            )
        if privileged:
            summary_parts.append("the session received special privileges shortly after logon")

        incidents.append(
            Incident(
                id=incident_id,
                display_label="",
                incident_type="remote_credential_sequence",
                title="Remote credential attack followed by privileged access",
                severity="critical" if explicit or privileged else "high",
                confidence="high",
                confidence_score=88 if explicit or privileged else 80,
                summary=". ".join(summary_parts) + ".",
                first_seen=start,
                last_seen=end,
                finding_ids=sorted(finding_ids),
                signal_ids=sorted(signal_ids),
                evidence_chain=[
                    {
                        "event_id": item.event_id,
                        "timestamp": item.timestamp.isoformat() if item.timestamp else None,
                        "description": _event_description(item),
                        "user": item.domain_user or item.target_domain_user or item.subject_domain_user,
                        "source_ip": item.source_ip,
                        "process": item.process_name,
                    }
                    for item in sequence
                ],
                host=ev.computer,
                user=user,
                source_ip=src,
                process=explicit.process_name if explicit else "",
                command_line=explicit.command_line if explicit else "",
                technique_summary="Credential Access -> Lateral Movement -> Valid Accounts",
                recommended_next=(
                    f"Treat {src} and account {user} as potentially compromised. Review all activity on {ev.computer} "
                    "after the successful logon, validate whether the explicit credential use was expected, and reset the affected credentials."
                ),
            )
        )
        emitted[emit_key] = ev.timestamp

    return incidents


def _detect_remote_service_execution(
    events: List[NormalizedEvent], signals: List[Signal], findings: List[Finding]
) -> List[Incident]:
    incidents: List[Incident] = []
    by_host: Dict[str, List[NormalizedEvent]] = {}

    for ev in sorted((e for e in events if e.timestamp), key=lambda e: e.timestamp):
        by_host.setdefault(ev.computer or "unknown", []).append(ev)

    for host, host_events in by_host.items():
        for ev in host_events:
            if ev.event_id != 4624 or ev.logon_type not in ("3", "10"):
                continue
            src = (ev.source_ip or "").strip()
            if src in BENIGN_IPS:
                continue

            win_end = ev.timestamp + timedelta(minutes=10)
            sequence = [ev]
            share = _first_match(
                host_events,
                ev.timestamp,
                win_end,
                lambda e: e.event_id == 5140 and (e.source_ip or e.event_data.get("IpAddress", "")) == src,
            )
            if not share:
                continue
            sequence.append(share)

            service = _first_match(host_events, ev.timestamp, win_end, lambda e: e.event_id in (7045, 4697))
            if not service:
                continue
            sequence.append(service)

            process = _first_match(host_events, ev.timestamp, win_end, lambda e: e.event_id in (4688, 1))
            if not process:
                continue
            sequence.append(process)

            service_name = service.event_data.get("ServiceName", "") or service.service_name
            command = process.command_line
            user = ev.target_domain_user or ev.domain_user

            signal_ids, finding_ids = _collect_related_ids(
                signals,
                findings,
                host=host,
                start=ev.timestamp,
                end=process.timestamp,
            )
            payload = {
                "incident_type": "remote_service_execution",
                "host": host,
                "source_ip": src,
                "user": user,
                "service": service_name,
                "command": command,
                "timestamps": [x.timestamp for x in sequence],
                "finding_ids": sorted(finding_ids),
                "signal_ids": sorted(signal_ids),
            }
            incident_id = stable_id("inc", payload)
            incidents.append(
                Incident(
                    id=incident_id,
                    display_label="",
                    incident_type="remote_service_execution",
                    title="Remote service execution",
                    severity="critical",
                    confidence="high",
                    confidence_score=90,
                    summary=(
                        f"{user or 'Unknown user'} accessed {host} from {src}, touched an admin share, installed "
                        f"service {service_name or '(unknown)'}, and spawned {process.process_name or 'an unknown process'}."
                    ),
                    first_seen=ev.timestamp,
                    last_seen=process.timestamp,
                    finding_ids=sorted(finding_ids),
                    signal_ids=sorted(signal_ids),
                    evidence_chain=[
                        {
                            "event_id": item.event_id,
                            "timestamp": item.timestamp.isoformat() if item.timestamp else None,
                            "description": _event_description(item),
                        }
                        for item in sequence
                    ],
                    host=host,
                    user=user,
                    source_ip=src,
                    service=service_name,
                    process=process.process_name,
                    command_line=command,
                    share_name=share.share_name,
                    technique_summary="Lateral Movement -> SMB/Admin Share -> Service Execution",
                    recommended_next=(
                        f"Identify the source host behind {src}, inspect the installed service {service_name or '(unknown)'}, "
                        "and recover the executed payload or command line from endpoint telemetry."
                    ),
                )
            )

    return incidents


def _detect_pre_log_wipe(
    events: List[NormalizedEvent], signals: List[Signal], findings: List[Finding]
) -> List[Incident]:
    incidents: List[Incident] = []
    clear_events = [e for e in events if e.event_id == 1102 and e.timestamp]

    for clear in sorted(clear_events, key=lambda e: e.timestamp):
        start = clear.timestamp - timedelta(minutes=10)
        host = clear.computer or "unknown"

        related_signals = [
            s
            for s in signals
            if s.timestamp
            and (not host or not s.host or s.host == host)
            and start <= s.timestamp < clear.timestamp
            and _is_precursor_signal(s)
        ]
        related_findings = [
            f
            for f in findings
            if f.first_seen
            and (not host or not f.host or f.host == host)
            and start <= f.first_seen < clear.timestamp
            and _is_precursor_finding(f)
        ]

        if not related_signals and not related_findings:
            continue

        signal_ids = sorted({s.id for s in related_signals})
        finding_ids = sorted({f.id for f in related_findings})
        payload = {
            "incident_type": "pre_log_wipe_activity",
            "host": host,
            "clear_time": clear.timestamp,
            "signal_ids": signal_ids,
            "finding_ids": finding_ids,
        }
        incident_id = stable_id("inc", payload)

        incidents.append(
            Incident(
                id=incident_id,
                display_label="",
                incident_type="pre_log_wipe_activity",
                title="Pre-log-wipe suspicious activity",
                severity="critical",
                confidence="high",
                confidence_score=90,
                summary=f"Suspicious activity was observed on {host} in the 10 minutes before the audit log was cleared.",
                first_seen=min([s.timestamp for s in related_signals if s.timestamp] + [clear.timestamp]),
                last_seen=clear.timestamp,
                finding_ids=finding_ids,
                signal_ids=signal_ids,
                evidence_chain=[
                    {"id": s.id, "type": "signal", "label": s.display_label or s.id, "rule": s.source_rule}
                    for s in related_signals
                ]
                + [
                    {"id": f.id, "type": "finding", "label": f.display_label or f.id, "title": f.title}
                    for f in related_findings
                ]
                + [
                    {
                        "type": "event",
                        "event_id": 1102,
                        "timestamp": clear.timestamp.isoformat() if clear.timestamp else None,
                        "description": "Audit log cleared",
                    }
                ],
                host=host,
                user=clear.domain_user,
                technique_summary="Defense Evasion -> Indicator Removal",
                recommended_next=(
                    "Preserve alternate telemetry immediately, review the precursor activity for executed commands or service creation, "
                    "and verify whether the user who cleared the logs was authorized."
                ),
            )
        )

    return incidents


def _promote_audit_log_clear(findings: List[Finding]) -> List[Incident]:
    incidents: List[Incident] = []
    for finding in findings:
        if (finding.title or "").lower() != "audit log cleared":
            continue
        payload = {
            "incident_type": "audit_log_clear",
            "host": finding.host,
            "user": finding.user,
            "timestamp": finding.first_seen,
            "finding_ids": [finding.id],
        }
        incident_id = stable_id("inc", payload)
        incidents.append(
            Incident(
                id=incident_id,
                display_label="",
                incident_type="audit_log_clear",
                title="Audit log cleared",
                severity=finding.severity,
                confidence=finding.confidence,
                confidence_score=finding.confidence_score,
                summary=f"{finding.user or 'Unknown user'} cleared the audit log on {finding.host or 'unknown host'}.",
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                finding_ids=[finding.id],
                signal_ids=list(finding.signal_ids),
                evidence_chain=[
                    {
                        "type": "finding",
                        "id": finding.id,
                        "label": finding.display_label or finding.id,
                        "title": finding.title,
                    }
                ],
                host=finding.host,
                user=finding.user,
                technique_summary="Defense Evasion -> Indicator Removal",
                recommended_next=(
                    "Confirm whether the log clear was authorized, collect alternate telemetry from EDR/PowerShell/network sources, "
                    "and investigate the immediately preceding activity on the host."
                ),
            )
        )
    return incidents


def _covered_ids(incidents: Sequence[Incident]) -> Tuple[set[str], set[str]]:
    finding_ids = set()
    signal_ids = set()
    for incident in incidents:
        finding_ids.update(incident.finding_ids or [])
        signal_ids.update(incident.signal_ids or [])
    return finding_ids, signal_ids


GROUPABLE_HIGH_PRIORITY_INCIDENT_TYPES = {
    "lsass_memory_access",
    "lsass_memory_dump_activity",
    "procdump_lsass_dump",
    "task_manager_lsass_dump",
    "ppldump_lsass_dump",
    "custom_lsass_dump_tool",
    "service_installation_abuse",
    "suspicious_service_execution",
    "policy_modification",
}


def _high_priority_group_key(incident_type: str, finding: Finding) -> Optional[Tuple[str, str, str, str, str]]:
    if incident_type not in GROUPABLE_HIGH_PRIORITY_INCIDENT_TYPES:
        return None
    if incident_type in {"service_installation_abuse", "suspicious_service_execution"}:
        command = (
            _finding_command_line(finding)
            or finding.evidence.get("binary", "")
            or finding.evidence.get("image_path", "")
            or ""
        ).strip().lower()
        return (
            incident_type,
            (finding.host or "").strip().lower(),
            command,
            (finding.user or finding.account_name or "").strip().lower(),
            (finding.source_ip or "").strip().lower(),
        )
    process = (finding.process or finding.evidence.get("source_image", "") or "").strip().lower()
    return (
        incident_type,
        (finding.host or "").strip().lower(),
        process,
        (finding.user or "").strip().lower(),
        (finding.source_ip or "").strip().lower(),
    )


def _incident_evidence_entry_from_finding(finding: Finding) -> Dict[str, object]:
    return {
        "type": "finding",
        "id": finding.id,
        "label": finding.display_label or finding.id,
        "title": finding.title,
        "description": finding.description,
        "timestamp": finding.first_seen.isoformat() if finding.first_seen else None,
        "logon_id": finding.evidence.get("logon_id", ""),
        "related_events": finding.evidence.get("related_events", []),
    }


def _promote_high_priority_findings(findings: List[Finding], existing_incidents: Sequence[Incident]) -> List[Incident]:
    incidents: List[Incident] = []
    covered_finding_ids, _ = _covered_ids(existing_incidents)
    grouped_incidents: Dict[Tuple[str, str, str, str, str], Incident] = {}

    for finding in findings:
        if finding.id in covered_finding_ids:
            continue

        title = (finding.title or "").strip()
        severity = (finding.severity or "").lower()
        should_promote = title in SPECIFIC_FINDING_TITLES or severity == "critical"
        if not should_promote:
            continue

        incident_type, incident_title, summary, technique_summary = _incident_details_from_finding(finding)
        group_key = _high_priority_group_key(incident_type, finding)
        payload = (
            {
                "incident_type": incident_type,
                "host": finding.host,
                "user": finding.user,
                "source_ip": finding.source_ip,
                "process": finding.process or finding.evidence.get("source_image", ""),
            }
            if group_key
            else {
                "incident_type": incident_type,
                "host": finding.host,
                "user": finding.user,
                "source_ip": finding.source_ip,
                "finding_ids": [finding.id],
                "signal_ids": sorted(finding.signal_ids),
                "timestamp": finding.first_seen or finding.last_seen,
            }
        )
        evidence_entry = _incident_evidence_entry_from_finding(finding)

        if group_key and group_key in grouped_incidents:
            existing = grouped_incidents[group_key]
            existing.finding_ids = sorted(set(existing.finding_ids + [finding.id]))
            existing.signal_ids = sorted(set(existing.signal_ids + list(finding.signal_ids)))
            if not any(step.get("id") == finding.id for step in existing.evidence_chain):
                existing.evidence_chain.append(evidence_entry)
                existing.evidence_chain.sort(key=lambda step: step.get("timestamp") or "")
            if finding.first_seen and (existing.first_seen is None or finding.first_seen < existing.first_seen):
                existing.first_seen = finding.first_seen
            if finding.last_seen and (existing.last_seen is None or finding.last_seen > existing.last_seen):
                existing.last_seen = finding.last_seen
            existing.confidence_score = max(existing.confidence_score, finding.confidence_score)
            continue

        incident = Incident(
            id=stable_id("inc", payload),
            display_label="",
            incident_type=incident_type,
            title=incident_title,
            severity="critical" if title == "Pass-the-Hash Logon" and finding.evidence.get("privileged_followup") else finding.severity,
            confidence=finding.confidence,
            confidence_score=max(finding.confidence_score, 85 if title in SPECIFIC_FINDING_TITLES else finding.confidence_score),
            summary=summary,
            first_seen=finding.first_seen,
            last_seen=finding.last_seen,
            finding_ids=[finding.id],
            signal_ids=sorted(finding.signal_ids),
            evidence_chain=[evidence_entry],
            host=finding.host,
            user=finding.user,
            source_ip=finding.source_ip,
            process=finding.process,
            service=finding.service,
            command_line=_finding_command_line(finding),
            technique_summary=technique_summary,
            recommended_next=finding.recommended_next,
        )
        incidents.append(incident)
        if group_key:
            grouped_incidents[group_key] = incident

    return incidents


def _incident_details_from_finding(finding: Finding) -> Tuple[str, str, str, str]:
    title = (finding.title or "").strip()
    if title == "PetitPotam RPC Coercion":
        network_address = finding.evidence.get("network_address", "") or finding.source_ip or "an unknown remote peer"
        endpoints = ", ".join(finding.evidence.get("endpoints", [])[:3]) or "lsarpc/lsass named pipes"
        summary = (
            f"Anonymous EFSRPC coercion traffic targeted {finding.host or 'unknown host'} via {network_address} "
            f"using {endpoints}, which is consistent with PetitPotam-style forced authentication."
        )
        return (
            "petitpotam_rpc_coercion",
            "PetitPotam RPC coercion",
            summary,
            "Credential Access -> Forced Authentication",
        )
    if title == "Zerologon RPC Activity":
        endpoint = finding.evidence.get("endpoint", "") or "an unknown Netlogon endpoint"
        proc_nums = ", ".join(finding.evidence.get("proc_nums", [])[:5]) or "multiple procedure calls"
        summary = (
            f"Weakly authenticated Netlogon RPC calls hit {finding.host or 'unknown host'} on endpoint {endpoint} "
            f"using procedure numbers {proc_nums}, which is consistent with Zerologon exploitation attempts."
        )
        return (
            "zerologon_rpc_activity",
            "Zerologon RPC activity",
            summary,
            "Lateral Movement -> Exploitation of Remote Services",
        )
    if title == "Machine Account Secret Modified":
        paths = ", ".join(finding.evidence.get("registry_paths", [])[:2]) or "LSA secret paths"
        summary = (
            f"Machine-account secret material was written under {paths} on {finding.host or 'unknown host'}, "
            "indicating direct modification of the LSA secret backing the machine password."
        )
        return (
            "machine_account_secret_modified",
            "Machine account secret modified",
            summary,
            "Credential Access -> LSA Secrets",
        )
    if title == "Remote SAM Registry Hive Access":
        hives = ", ".join(finding.evidence.get("staged_hives", [])[:3]) or "SAM-related hives"
        source_ip = finding.evidence.get("primary_source_ip", "") or finding.source_ip or "an unknown source"
        summary = (
            f"{finding.user or 'Unknown user'} remotely accessed winreg on {finding.host or 'unknown host'} from {source_ip} "
            f"and staged {hives} hive material for offline credential extraction."
        )
        return (
            "remote_sam_registry_hive_access",
            "Remote SAM registry hive access",
            summary,
            "Credential Access -> Security Account Manager",
        )
    if title == "Kerberos Password Spray":
        source_ip = finding.evidence.get("source_ip", "") or finding.source_ip or "an unknown source"
        accounts = ", ".join(finding.evidence.get("target_accounts", [])[:5]) or "multiple accounts"
        summary = (
            f"Kerberos authentication failures from {source_ip} targeted {accounts} on "
            f"{finding.host or 'unknown host'} in a spray-like pattern."
        )
        return (
            "kerberos_password_spray",
            "Kerberos password spray",
            summary,
            "Credential Access -> Brute Force",
        )
    if title == "MSSQL Password Spray":
        source_ip = finding.evidence.get("source_ip", "") or finding.source_ip or "an unknown source"
        accounts = ", ".join(finding.evidence.get("target_accounts", [])[:5]) or "multiple SQL logins"
        summary = (
            f"Repeated SQL authentication failures from {source_ip} targeted {accounts} on "
            f"{finding.host or 'unknown host'} in a spray-like pattern."
        )
        return (
            "mssql_password_spray",
            "MSSQL password spray",
            summary,
            "Credential Access -> Brute Force",
        )
    if title == "NTDS.dit Snapshot Export":
        source_paths = ", ".join(finding.evidence.get("source_paths", [])[:2]) or r"C:\Windows\NTDS\ntds.dit"
        export_path = finding.evidence.get("export_path", "") or "an exported ntds.dit path"
        summary = (
            f"ESENT events on {finding.host or 'unknown host'} show NTDS.dit being copied from {source_paths} "
            f"into {export_path}, which is consistent with offline Active Directory database export."
        )
        return (
            "ntds_snapshot_export",
            "NTDS.dit snapshot export",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "LSASS Remote Thread Injection":
        source = finding.evidence.get("source_image", "") or finding.process or "an unknown process"
        access_masks = ", ".join((finding.evidence.get("access_masks", []) or [])[:3]) or "credential-dumping access rights"
        summary = (
            f"{source} created a remote thread in lsass.exe on {finding.host or 'unknown host'} and then accessed "
            f"LSASS with {access_masks}, which is strong evidence of in-memory credential theft activity."
        )
        return (
            "lsass_remote_thread_injection",
            "LSASS remote thread injection",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "Protected Storage RPC Access":
        relative_target = finding.evidence.get("relative_target", "") or "protected_storage"
        source_ip = finding.source_ip or "an unknown source"
        summary = (
            f"{finding.user or 'Unknown user'} accessed {relative_target} over IPC$ on "
            f"{finding.host or 'unknown host'} from {source_ip}."
        )
        return (
            "protected_storage_rpc_access",
            "Protected storage RPC access",
            summary,
            "Credential Access -> Credentials from Password Stores",
        )
    if title == "TeamViewer Credential Memory Access":
        source = finding.evidence.get("source_image", "") or finding.process or "an unknown process"
        summary = (
            f"{source} accessed TeamViewer.exe memory on {finding.host or 'unknown host'}, which is consistent with "
            "theft of TeamViewer credential or session material."
        )
        return (
            "teamviewer_credential_memory_access",
            "TeamViewer credential memory access",
            summary,
            "Credential Access -> Credentials from Password Stores",
        )
    if title == "Kekeo TSSSP Named Pipe":
        pipe_name = finding.evidence.get("pipe_name", "") or r"\kekeo_tsssp_endpoint"
        process = finding.evidence.get("process_images", ["kekeo.exe"])[0]
        summary = (
            f"{process} interacted with named pipe {pipe_name} on {finding.host or 'unknown host'}, which is consistent "
            "with Kekeo-based credential or ticket abuse."
        )
        return (
            "kekeo_tsssp_named_pipe",
            "Kekeo TSSSP named pipe",
            summary,
            "Credential Access -> Alternate Authentication Material",
        )
    if title == "Browser Logon Process Abuse":
        process_name = finding.evidence.get("browser_process", "") or finding.process or "a browser process"
        logon_process_name = finding.evidence.get("logon_process_name", "") or "an unexpected browser logon process"
        target_user = finding.evidence.get("target_user", "") or finding.user or "an unknown user"
        summary = (
            f"{process_name} registered interactive logon activity for {target_user} on {finding.host or 'unknown host'} "
            f"using LogonProcessName {logon_process_name}, which is consistent with browser-backed credential prompting "
            "or authentication-process abuse."
        )
        return (
            "browser_logon_process_abuse",
            "Browser logon process abuse",
            summary,
            "Credential Access -> Modify Authentication Process",
        )
    if title == "Netsh PortProxy RDP Tunnel":
        listen_address = finding.evidence.get("listen_address", "") or "0.0.0.0"
        listen_port = finding.evidence.get("listen_port", "") or "an unknown port"
        connect_address = finding.evidence.get("connect_address", "") or "an unknown destination"
        connect_port = finding.evidence.get("connect_port", "") or "3389"
        summary = (
            f"{finding.user or 'Unknown user'} configured a netsh portproxy listener on {finding.host or 'unknown host'} "
            f"at {listen_address}:{listen_port} forwarding to {connect_address}:{connect_port}, which is consistent "
            "with RDP tunneling through a compromised Windows host."
        )
        return (
            "netsh_portproxy_rdp_tunnel",
            "Netsh portproxy RDP tunnel",
            summary,
            "Command and Control -> Protocol Tunneling",
        )
    if title == "Unmanaged PowerShell Injection":
        source = finding.evidence.get("source_image", "") or finding.process or "an unknown process"
        target = finding.evidence.get("target_image", "") or "an unknown target process"
        remote_thread_count = finding.evidence.get("remote_thread_count", 0) or 0
        summary = (
            f"{source} injected {target} on {finding.host or 'unknown host'} and loaded unmanaged PowerShell components "
            f"into the target ({remote_thread_count} remote-thread events observed)."
        )
        return (
            "unmanaged_powershell_injection",
            "Unmanaged PowerShell injection",
            summary,
            "Defense Evasion -> Process Injection",
        )
    if title == "DirectInput Keylogger Registration":
        process_name = finding.evidence.get("process_path", "") or finding.process or "an unknown executable"
        keys = ", ".join((finding.evidence.get("registry_keys_modified", []) or [])[:4]) or "DirectInput MostRecentApplication values"
        summary = (
            f"{process_name} modified {keys} under the DirectInput MostRecentApplication registry path on "
            f"{finding.host or 'unknown host'}, which is consistent with DirectInput-based keylogger registration."
        )
        return (
            "directinput_keylogger_registration",
            "DirectInput keylogger registration",
            summary,
            "Credential Access -> Input Capture",
        )
    if title == "Rundll32 Wermgr Hollowing":
        payload_path = finding.evidence.get("payload_path", "") or "an untrusted DLL path"
        target = finding.evidence.get("target_image", "") or finding.process or "wermgr.exe"
        summary = (
            f"rundll32 launched {target} on {finding.host or 'unknown host'} using payload {payload_path}, then accessed "
            "the target with hollowing-like permissions and follow-on registry activity."
        )
        return (
            "rundll32_wermgr_hollowing",
            "Rundll32 wermgr hollowing",
            summary,
            "Defense Evasion -> Process Hollowing",
        )
    if title == "Pass-the-Hash Logon":
        logon_id = finding.evidence.get("logon_id", "") or "(unknown)"
        privileged = finding.evidence.get("privileged_followup")
        summary = (
            f"{finding.user or 'Unknown user'} established a NewCredentials session on {finding.host or 'unknown host'} "
            f"using seclogo (logon ID {logon_id})."
        )
        if privileged:
            summary += " Special privileges were assigned to the same session."
        if finding.evidence.get("suspicious_processes"):
            summary += f" Related process activity: {', '.join(finding.evidence.get('suspicious_processes', []))}."
        return (
            "pass_the_hash_activity",
            "Pass-the-Hash activity",
            summary,
            "Credential Access -> Use Alternate Authentication Material",
        )
    if title == "Security Audit LSASS Access":
        source = finding.evidence.get("source_image", "") or finding.process or "an unknown process"
        summary = (
            f"{source} requested high-privilege access to lsass.exe on {finding.host or 'unknown host'}, "
            "which is consistent with direct credential dumping through audited handle access."
        )
        return (
            "security_audit_lsass_access",
            "Security-audited LSASS access",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "Mimikatz LSASS Access":
        source = finding.evidence.get("source_image", "") or finding.process or "mimikatz.exe"
        summary = (
            f"{source} accessed lsass.exe on {finding.host or 'unknown host'}, which is strong evidence of Mimikatz credential dumping."
        )
        return (
            "mimikatz_lsass_access",
            "Mimikatz LSASS access",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "LSASS Dump via RdrLeakDiag":
        dump_path = finding.evidence.get("dump_path", "") or "a dump file"
        summary = (
            f"rdrleakdiag.exe dumped lsass.exe on {finding.host or 'unknown host'} and wrote {dump_path}."
        )
        return (
            "lsass_dump_via_rdrleakdiag",
            "LSASS dump via RdrLeakDiag",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "LSASS Dump via SilentProcessExit":
        monitor_process = finding.evidence.get("monitor_process", "") or finding.process or "an unknown monitor process"
        summary = (
            f"{monitor_process} was configured to monitor lsass.exe termination on {finding.host or 'unknown host'}, "
            "which is consistent with SilentProcessExit-style LSASS dump collection."
        )
        return (
            "silent_process_exit_lsass_dump",
            "LSASS dump via SilentProcessExit",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "MemSSP Credential Log File":
        target = finding.evidence.get("target_filename", "") or "a credential log file"
        summary = (
            f"lsass.exe created {target} on {finding.host or 'unknown host'}, which is consistent with MemSSP-style credential logging."
        )
        return (
            "memssp_credential_logging",
            "MemSSP credential logging",
            summary,
            "Persistence -> Authentication Package",
        )
    if title == "PPLdump LSASS Dump":
        dump_path = finding.evidence.get("dump_path", "") or "an LSASS dump file"
        summary = (
            f"PPLdump targeted lsass.exe on {finding.host or 'unknown host'}"
            f" and produced {dump_path}."
        )
        return (
            "ppldump_lsass_dump",
            "PPLdump LSASS dump",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "InstallUtil Proxy Execution":
        payload = finding.evidence.get("payload_path", "") or "an untrusted payload"
        summary = f"InstallUtil executed {payload} on {finding.host or 'unknown host'}, which is consistent with signed-binary proxy execution."
        return ("installutil_proxy_execution", "InstallUtil proxy execution", summary, "Defense Evasion -> Signed Binary Proxy Execution")
    if title == "DesktopImgDownldr Remote Download":
        remote_url = finding.evidence.get("remote_url", "") or "an unknown remote URL"
        download_path = finding.evidence.get("download_path", "") or "a personalization cache file"
        summary = f"desktopimgdownldr.exe fetched {remote_url} on {finding.host or 'unknown host'} and wrote {download_path}."
        return ("desktopimgdownldr_remote_download", "DesktopImgDownldr remote download", summary, "Command and Control -> Ingress Tool Transfer")
    if title == "DSRM Password Changed":
        summary = f"{finding.user or finding.evidence.get('actor_user', 'Unknown actor')} changed the DSRM password on {finding.host or 'unknown host'}."
        return ("dsrm_password_changed", "DSRM password changed", summary, "Persistence -> Account Manipulation")
    if title == "WDigest Logon Credential Storage Enabled":
        summary = f"WDigest cleartext credential caching was enabled on {finding.host or 'unknown host'} by {finding.user or finding.evidence.get('actor_user', 'an unknown actor')}."
        return ("wdigest_credential_storage_enabled", "WDigest credential storage enabled", summary, "Credential Access -> OS Credential Dumping")
    if title == "Windows Credential Manager Access":
        actor = finding.user or finding.evidence.get("actor_user", "an unknown actor")
        summary = f"{actor} accessed Windows Credential Manager or Vault data on {finding.host or 'unknown host'}."
        return ("credential_manager_access", "Windows Credential Manager access", summary, "Credential Access -> Credentials from Password Stores")
    if title == "Service Failure Command Abuse":
        service_name = finding.service or finding.evidence.get("service_name", "unknown")
        payload = next(iter(finding.evidence.get("payloads", []) or []), "an unknown command")
        summary = f"{finding.user or finding.evidence.get('actor_user', 'Unknown actor')} configured {service_name} to execute {payload} on service failure on {finding.host or 'unknown host'}."
        return ("service_failure_command_abuse", "Service failure command abuse", summary, "Persistence -> Service Modification")
    if title == "Service ImagePath Command Abuse":
        service_name = finding.service or finding.evidence.get("service_name", "unknown")
        payload = next(iter(finding.evidence.get("payloads", []) or []), "an unknown payload")
        summary = f"{finding.user or finding.evidence.get('actor_user', 'Unknown actor')} changed {service_name} to run {payload} on {finding.host or 'unknown host'}."
        return ("service_imagepath_command_abuse", "Service ImagePath command abuse", summary, "Persistence -> Service Modification")
    if title == "Windows Update UScheduler Command Hijack":
        scheduler_id = finding.evidence.get("scheduler_id", "") or "unknown"
        cmd_line = finding.evidence.get("cmd_line", "") or "an unknown command"
        start_arg = finding.evidence.get("start_arg", "") or finding.evidence.get("pause_arg", "")
        arg_text = f" {start_arg}" if start_arg else ""
        summary = (
            f"Windows Update Orchestrator UScheduler {scheduler_id} was modified on {finding.host or 'unknown host'} "
            f"to run {cmd_line}{arg_text}."
        )
        return (
            "windows_update_uscheduler_command_hijack",
            "Windows Update UScheduler command hijack",
            summary,
            "Privilege Escalation -> Hijack Execution Flow",
        )
    if title == "Service Creation Command":
        service_name = finding.service or finding.evidence.get("service_name", "unknown")
        payload = next(iter(finding.evidence.get("payloads", []) or []), "an unknown payload")
        summary = f"{finding.user or finding.evidence.get('actor_user', 'Unknown actor')} created service {service_name} with payload {payload} on {finding.host or 'unknown host'}."
        return ("service_creation_command", "Service creation command", summary, "Persistence -> Create or Modify System Process")
    if title == "Remote Service Creation Command":
        service_name = finding.service or finding.evidence.get("service_name", "unknown")
        remote_target = finding.evidence.get("remote_target", "") or "an unknown remote host"
        payload = next(iter(finding.evidence.get("payloads", []) or []), "an unknown payload")
        summary = f"{finding.user or finding.evidence.get('actor_user', 'Unknown actor')} created remote service {service_name} on {remote_target} with payload {payload}."
        return ("remote_service_creation_command", "Remote service creation command", summary, "Lateral Movement -> Remote Services")
    if title == "Task Manager LSASS Dump":
        dump_path = finding.evidence.get("dump_path", "") or "an LSASS dump file"
        summary = (
            f"Task Manager accessed or dumped lsass.exe on {finding.host or 'unknown host'}"
            f" and wrote {dump_path}."
        )
        return (
            "task_manager_lsass_dump",
            "Task Manager LSASS dump",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "LSASS Memory Access":
        source = finding.evidence.get("source_image", "") or finding.process or "an unknown process"
        source_base = os.path.basename(source.replace("\\", "/")).lower()
        dump_path = finding.evidence.get("dump_path", "") or ""
        if source_base == "procdump.exe":
            summary = f"Procdump accessed lsass.exe on {finding.host or 'unknown host'} and created {dump_path or 'an LSASS dump file'}."
            return ("procdump_lsass_dump", "Procdump LSASS dump", summary, "Credential Access -> OS Credential Dumping")
        if source_base == "taskmgr.exe":
            summary = f"Task Manager accessed lsass.exe on {finding.host or 'unknown host'} and created {dump_path or 'an LSASS dump file'}."
            return ("task_manager_lsass_dump", "Task Manager LSASS dump", summary, "Credential Access -> OS Credential Dumping")
        if source_base == "ppldump.exe":
            summary = f"PPLdump accessed lsass.exe on {finding.host or 'unknown host'} and contributed to {dump_path or 'an LSASS dump file'}."
            return ("ppldump_lsass_dump", "PPLdump LSASS dump", summary, "Credential Access -> OS Credential Dumping")
        if "dumpert" in source_base or source_base == "andrewspecial.exe":
            summary = f"{source} accessed lsass.exe on {finding.host or 'unknown host'} and created {dump_path or 'an LSASS dump file'}."
            return ("custom_lsass_dump_tool", "Custom LSASS dump tool", summary, "Credential Access -> OS Credential Dumping")
        if dump_path:
            summary = f"{source} accessed lsass.exe on {finding.host or 'unknown host'} and created {dump_path}."
            return ("lsass_memory_dump_activity", "LSASS memory dump activity", summary, "Credential Access -> OS Credential Dumping")
        summary = f"{source} accessed lsass.exe on {finding.host or 'unknown host'}, which is consistent with credential-dumping activity."
        return ("lsass_memory_access", "LSASS memory access", summary, "Credential Access -> OS Credential Dumping")
    if title == "PowerShell WER LSASS Dump":
        summary = (
            f"PowerShell on {finding.host or 'unknown host'} invoked Windows Error Reporting MiniDumpWriteDump against lsass.exe."
        )
        return (
            "powershell_wer_lsass_dump",
            "PowerShell WER LSASS dump",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "PowerShell Credential Prompt Harvesting":
        prompt_title = finding.evidence.get("prompt_title", "") or "Windows Security"
        summary = (
            f"PowerShell on {finding.host or 'unknown host'} displayed the '{prompt_title}' credential prompt, "
            "captured plaintext credentials from the returned NetworkCredential object, and exposed the harvested values."
        )
        return (
            "powershell_credential_prompt_harvesting",
            "PowerShell credential prompt harvesting",
            summary,
            "Credential Access -> Input Capture",
        )
    if title == "AS-REP Roasting":
        summary = (
            f"{finding.user or 'Unknown user'} requested a Kerberos AS-REP on {finding.host or 'unknown host'} "
            "without pre-authentication, creating offline-crackable credential material."
        )
        return (
            "asrep_roasting",
            "AS-REP roasting activity",
            summary,
            "Credential Access -> Steal or Forge Kerberos Tickets",
        )
    if title == "DCSync Directory Replication":
        rights = ", ".join(finding.evidence.get("replication_rights", [])[:3]) or "directory replication rights"
        summary = (
            f"{finding.user or 'Unknown user'} accessed {rights} on {finding.host or 'unknown host'}, "
            "which is consistent with DCSync-style replication abuse."
        )
        return (
            "dcsync_directory_replication",
            "DCSync directory replication",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title in {"Golden Ticket Forgery Tooling", "Silver Ticket Forgery Tooling"}:
        summary = (
            f"{finding.user or 'Unknown user'} executed forged Kerberos ticket tooling on {finding.host or 'unknown host'}."
        )
        return (
            "forged_kerberos_ticket_tooling",
            "Forged Kerberos ticket tooling",
            summary,
            "Credential Access -> Steal or Forge Kerberos Tickets",
        )
    if title == "MSHTA HTA Execution":
        remote_url = finding.evidence.get("remote_url", "") or "an HTA payload"
        summary = (
            f"{finding.user or 'Unknown user'} executed mshta.exe on {finding.host or 'unknown host'} "
            f"to load {remote_url}."
        )
        return (
            "mshta_hta_execution",
            "MSHTA HTA execution",
            summary,
            "Defense Evasion -> Signed Binary Proxy Execution",
        )
    if title == "Regsvr32 Scriptlet Execution":
        target = finding.evidence.get("scriptlet_target", "") or "a scriptlet payload"
        summary = (
            f"{finding.user or 'Unknown user'} used regsvr32.exe on {finding.host or 'unknown host'} "
            f"to load {target}."
        )
        return (
            "regsvr32_scriptlet_execution",
            "Regsvr32 scriptlet execution",
            summary,
            "Defense Evasion -> Signed Binary Proxy Execution",
        )
    if title == "WMIC XSL Script Processing":
        summary = (
            f"{finding.user or 'Unknown user'} used WMIC on {finding.host or 'unknown host'} "
            "with XSL/script processing behavior."
        )
        return (
            "wmic_xsl_script_processing",
            "WMIC XSL script processing",
            summary,
            "Defense Evasion -> Signed Binary Proxy Execution",
        )
    if title == "Certutil Remote Download":
        remote_url = finding.evidence.get("remote_url", "") or "a remote payload"
        summary = (
            f"{finding.user or 'Unknown user'} used certutil.exe on {finding.host or 'unknown host'} "
            f"to download from {remote_url}."
        )
        return (
            "certutil_remote_download",
            "Certutil remote download",
            summary,
            "Command and Control -> Ingress Tool Transfer",
        )
    if title == "Print Spooler Exploitation":
        child = finding.evidence.get("child_process", "") or finding.process or "unknown child process"
        parent = finding.evidence.get("parent_process", "") or finding.parent_process or "spoolsv.exe"
        execution_user = finding.evidence.get("execution_user", "") or finding.user or "NT AUTHORITY\\SYSTEM"
        summary = (
            f"{parent} launched {child} as {execution_user} on {finding.host or 'unknown host'}, "
            "which is consistent with PrintNightmare-style print spooler exploitation."
        )
        return (
            "print_spooler_exploitation",
            "Print spooler exploitation",
            summary,
            "Privilege Escalation -> Exploitation for Privilege Escalation",
        )
    if title == "DCOM MSHTA Remote Execution":
        remote_peer = finding.evidence.get("remote_peer_ip", "") or finding.source_ip or "an unknown remote peer"
        summary = (
            f"svchost/dllhost launched mshta.exe with DCOM-style embedding on {finding.host or 'unknown host'} "
            f"after communication with {remote_peer}."
        )
        return (
            "dcom_mshta_remote_execution",
            "DCOM MSHTA remote execution",
            summary,
            "Lateral Movement -> Distributed Component Object Model",
        )
    if title == "Service Account to SYSTEM Impersonation":
        service_account = finding.evidence.get("service_account", "") or finding.user or "unknown service account"
        elevated_user = finding.evidence.get("elevated_user", "") or finding.target_user or "NT AUTHORITY\\SYSTEM"
        source_image = finding.evidence.get("source_image", "") or "unknown source process"
        target_image = finding.evidence.get("target_image", "") or finding.process or "unknown target process"
        summary = (
            f"{service_account} injected from {source_image} into {target_image} on {finding.host or 'unknown host'}, "
            f"followed by execution as {elevated_user}, consistent with Potato-style SYSTEM impersonation."
        )
        return (
            "service_account_system_impersonation",
            "Service account escalated to SYSTEM",
            summary,
            "Privilege Escalation -> Access Token Manipulation",
        )
    if title == "Potato-Style Named Pipe Impersonation":
        process_image = finding.evidence.get("process_image", "") or finding.process or "unknown process"
        pipe_name = finding.evidence.get("pipe_name", "") or "a rogue named pipe"
        child_processes = [item for item in finding.evidence.get("child_processes", []) if item]
        child_text = ", ".join(child_processes[:2]) if child_processes else "follow-on execution"
        if finding.evidence.get("detection_variant") == "rogue_epmapper":
            summary = (
                f"{process_image} created {pipe_name} on {finding.host or 'unknown host'}, then SYSTEM consumed that pipe "
                f"before {child_text}, matching RoguePotato-style named-pipe impersonation."
            )
        else:
            summary = (
                f"{process_image} created {pipe_name} on {finding.host or 'unknown host'}, then SYSTEM consumed that pipe "
                f"and \\\\lsass before {child_text}, matching Potato-style named-pipe impersonation."
            )
        return (
            "potato_named_pipe_impersonation",
            "Potato-style named pipe impersonation",
            summary,
            "Privilege Escalation -> Access Token Manipulation",
        )
    if title == "Renamed PsExec Service Pipes":
        server_process = finding.evidence.get("server_process", "") or finding.process or "unknown process"
        base_pipe = finding.evidence.get("base_pipe", "") or "an unnamed pipe"
        client_processes = [item for item in finding.evidence.get("client_processes", []) if item]
        client_text = ", ".join(client_processes[:2]) if client_processes else "PsExec.exe"
        summary = (
            f"{server_process} exposed {base_pipe} and PsExec-style stdio pipes on {finding.host or 'unknown host'}, "
            f"and {client_text} connected to them, matching a renamed PsExec service pattern."
        )
        return (
            "renamed_psexec_service_pipes",
            "Renamed PsExec service pipes",
            summary,
            "Lateral Movement -> Remote Services",
        )
    if title == "Office VBA Object Model Access Enabled":
        office_app = finding.evidence.get("office_app", "") or "Office"
        summary = (
            f"{finding.user or 'Unknown user'} enabled AccessVBOM for {office_app.title()} on {finding.host or 'unknown host'}, "
            "weakening Office macro security settings."
        )
        return (
            "office_vba_object_model_enabled",
            "Office VBA object model access enabled",
            summary,
            "Defense Evasion -> Modify Registry",
        )
    if title == "FTP Script Command Execution":
        child = finding.evidence.get("child_process", "") or finding.process or "unknown child process"
        summary = (
            f"ftp.exe launched {child} on {finding.host or 'unknown host'} for local command execution as {finding.user or 'unknown user'}."
        )
        return (
            "ftp_script_command_execution",
            "FTP script command execution",
            summary,
            "Execution -> Indirect Command Execution",
        )
    if title == "Scheduled Task SYSTEM Elevation":
        task_name = finding.evidence.get("task_name", "") or finding.scheduled_task or "unknown task"
        target_user = finding.target_user or finding.evidence.get("target_user", "") or "NT AUTHORITY\\SYSTEM"
        summary = (
            f"{finding.user or 'Unknown user'} created and ran task {task_name} on {finding.host or 'unknown host'}, "
            f"which spawned {finding.process or 'a process'} as {target_user}."
        )
        return (
            "scheduled_task_system_elevation",
            "Scheduled task elevated execution",
            summary,
            "Privilege Escalation -> Scheduled Task",
        )
    if title == "BITSAdmin Transfer":
        remote_url = finding.evidence.get("remote_url", "") or "a remote source"
        summary = (
            f"{finding.user or 'Unknown user'} created a BITS transfer on {finding.host or 'unknown host'} "
            f"to fetch content from {remote_url}."
        )
        return (
            "bitsadmin_transfer",
            "BITSAdmin transfer",
            summary,
            "Persistence -> Background Intelligent Transfer Service",
        )
    if title == "PowerShell BITS Download":
        remote_url = finding.evidence.get("remote_url", "") or "a remote source"
        summary = (
            f"{finding.user or 'Unknown user'} used PowerShell BITS commands on {finding.host or 'unknown host'} "
            f"to fetch content from {remote_url}."
        )
        return (
            "powershell_bits_download",
            "PowerShell BITS download",
            summary,
            "Persistence -> Background Intelligent Transfer Service",
        )
    if title == "Suspicious: LSASS Dump (comsvcs)":
        summary = (
            f"A comsvcs.dll MiniDump command was executed on {finding.host or 'unknown host'}, which is consistent with LSASS dumping through rundll32.exe."
        )
        return (
            "lsass_dump_via_comsvcs",
            "LSASS dump via comsvcs MiniDump",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "PowerShell Archive Staging":
        archive_path = finding.evidence.get("archive_path", "") or "a ZIP archive"
        summary = (
            f"{finding.user or 'Unknown user'} staged data into {archive_path} on {finding.host or 'unknown host'}, "
            "which is consistent with archive creation before exfiltration."
        )
        return (
            "powershell_archive_staging",
            "PowerShell archive staging",
            summary,
            "Collection -> Archive Collected Data",
        )
    if title == "COR_PROFILER System Environment Hijack":
        dll_path = finding.evidence.get("dll_path", "") or "an unknown profiler DLL"
        summary = (
            f"{finding.user or 'Unknown user'} configured system-wide COR_PROFILER values on {finding.host or 'unknown host'} "
            f"to load {dll_path} into future .NET processes."
        )
        return (
            "cor_profiler_environment_hijack",
            "COR_PROFILER environment hijack",
            summary,
            "Persistence -> Hijack Execution Flow",
        )
    if title == "BITS Notify Command Execution":
        summary = (
            f"{finding.user or 'Unknown user'} configured a BITS notify command on {finding.host or 'unknown host'}, "
            "allowing job completion to launch follow-on execution."
        )
        return (
            "bits_notify_command_execution",
            "BITS notify command execution",
            summary,
            "Persistence -> Background Intelligent Transfer Service",
        )
    if title == "Golden Ticket Use Pattern":
        services = ", ".join(finding.evidence.get("service_names", [])[:4]) or "multiple machine services"
        summary = (
            f"{finding.user or 'Unknown user'} requested Kerberos service tickets for {services} from "
            f"{finding.source_ip or 'an unknown source'} without a matching AS-REQ."
        )
        return (
            "golden_ticket_use",
            "Golden Ticket use pattern",
            summary,
            "Credential Access -> Steal or Forge Kerberos Tickets",
        )
    if title == "COM Hijacking Persistence":
        dll_path = finding.evidence.get("dll_path", "") or finding.evidence.get("linked_dll_path", "")
        clsid = finding.evidence.get("clsid", "") or "unknown CLSID"
        summary = (
            f"COM hijacking persistence was established on {finding.host or 'unknown host'} by modifying {clsid} "
            f"to load {dll_path or 'a user-controlled DLL'}."
        )
        return (
            "com_hijack_persistence",
            "COM hijacking persistence",
            summary,
            "Persistence -> Event Triggered Execution",
        )
    if title == "WMI Remote Registry Modification":
        registry_key = finding.evidence.get("target_object", "") or "an unknown registry path"
        summary = (
            f"WMI on {finding.host or 'unknown host'} modified {registry_key} "
            f"from {finding.source_ip or finding.evidence.get('remote_peer_ip', '') or 'an unknown remote source'}."
        )
        return (
            "wmi_remote_registry_modification",
            "WMI remote registry modification",
            summary,
            "Lateral Movement -> Windows Management Instrumentation",
        )
    if title == "Registry Run Key Persistence":
        registry_key = finding.evidence.get("registry_key", "") or "a Run key"
        summary = (
            f"A Run-key autorun value was set at {registry_key} on {finding.host or 'unknown host'}, "
            "creating logon persistence."
        )
        return (
            "registry_run_key_persistence",
            "Registry Run key persistence",
            summary,
            "Persistence -> Registry Run Keys / Startup Folder",
        )
    if title == "Windows Defender Service Tampering":
        summary = (
            f"{finding.user or 'Unknown user'} tampered with the WinDefend service on {finding.host or 'unknown host'}, "
            "which can disable Microsoft Defender before follow-on activity."
        )
        return (
            "windows_defender_service_tampering",
            "Windows Defender service tampering",
            summary,
            "Defense Evasion -> Impair Defenses",
        )
    if title == "Windows Defender Malware Detection":
        threat_names = ", ".join(finding.evidence.get("threat_names", [])[:4]) or "one or more malware families"
        summary = (
            f"Windows Defender reported malware detections on {finding.host or 'unknown host'} for {threat_names}, "
            "indicating malicious file or payload activity requiring containment."
        )
        return (
            "windows_defender_malware_detection",
            "Windows Defender malware detection",
            summary,
            "Execution -> User Execution",
        )
    if title == "Windows Firewall Rule Added":
        display_name = finding.evidence.get("display_name", "") or "an inbound allow rule"
        port = finding.evidence.get("local_port", "") or "unknown"
        summary = (
            f"{finding.user or 'Unknown user'} added firewall rule {display_name} on {finding.host or 'unknown host'} "
            f"to allow inbound access on port {port}."
        )
        return (
            "windows_firewall_rule_added",
            "Windows firewall rule added",
            summary,
            "Defense Evasion -> Modify Firewall",
        )
    if title == "RDP Shadowing Enabled":
        summary = (
            f"{finding.user or 'Unknown user'} enabled RDP shadowing on {finding.host or 'unknown host'} by modifying "
            "the Terminal Services shadow policy and opening the shadow firewall rule."
        )
        return (
            "rdp_shadowing_enabled",
            "RDP shadowing enabled",
            summary,
            "Lateral Movement -> Remote Desktop Protocol",
        )
    if title == "Kerberos Loopback Administrator Logon":
        source_ip = finding.source_ip or finding.evidence.get("source_ip", "") or "loopback"
        target_user = finding.evidence.get("target_user", "") or finding.user or "an administrator account"
        summary = (
            f"{target_user} authenticated to {finding.host or 'unknown host'} via loopback Kerberos network logon from "
            f"{source_ip} with null-subject characteristics, consistent with local Kerberos relay privilege escalation."
        )
        return (
            "kerberos_loopback_admin_logon",
            "Kerberos loopback administrator logon",
            summary,
            "Privilege Escalation -> Adversary-in-the-Middle",
        )
    if title == "Service ImagePath Registry Hijack":
        service_name = finding.evidence.get("service_name", "") or finding.service or "an unknown service"
        image_path = finding.evidence.get("image_path", "") or "an unknown command"
        summary = (
            f"{finding.user or 'Unknown user'} changed the ImagePath for {service_name} on {finding.host or 'unknown host'} "
            f"to {image_path}, hijacking future service execution."
        )
        return (
            "service_imagepath_registry_hijack",
            "Service ImagePath registry hijack",
            summary,
            "Persistence -> Hijack Execution Flow",
        )
    if title == "SIP Trust Provider Registration":
        dll_path = finding.evidence.get("dll_path", "") or "an unknown DLL"
        summary = (
            f"{finding.user or 'Unknown user'} registered SIP trust-provider DLL {dll_path} on {finding.host or 'unknown host'}, "
            "which can subvert Windows trust verification."
        )
        return (
            "sip_trust_provider_registration",
            "SIP trust provider registration",
            summary,
            "Defense Evasion -> Subvert Trust Controls",
        )
    if title == "OpenSSH Server Installed":
        capability = finding.evidence.get("capability_name", "") or "OpenSSH.Server"
        summary = (
            f"{finding.user or 'Unknown user'} installed {capability} on {finding.host or 'unknown host'}, "
            "adding SSH remote-service capability to the Windows host."
        )
        return (
            "openssh_server_installed",
            "OpenSSH server installed",
            summary,
            "Lateral Movement -> Remote Services: SSH",
        )
    if title == "OpenSSH Server Enabled":
        summary = (
            f"{finding.user or 'Unknown user'} started sshd and configured automatic startup on {finding.host or 'unknown host'}, "
            "leaving SSH remote access persistently enabled."
        )
        return (
            "openssh_server_enabled",
            "OpenSSH server enabled",
            summary,
            "Lateral Movement -> Remote Services: SSH",
        )
    if title == "OpenSSH Server Listening":
        port = finding.evidence.get("listening_port", "") or "22"
        summary = (
            f"sshd was listening on port {port} on {finding.host or 'unknown host'}, confirming that SSH remote service exposure is active."
        )
        return (
            "openssh_server_listening",
            "OpenSSH server listening",
            summary,
            "Lateral Movement -> Remote Services: SSH",
        )
    if title == "New SMB Share Added":
        share_name = finding.evidence.get("share_name", "") or "an unknown share"
        summary = (
            f"Share {share_name} was added on {finding.host or 'unknown host'}, exposing new SMB content that could be used for staging or remote access."
        )
        return (
            "new_smb_share_added",
            "New SMB share added",
            summary,
            "Lateral Movement -> SMB/Windows Admin Shares",
        )
    if title == "Remote Service Payload Staging":
        paths = ", ".join((finding.evidence.get("staged_paths", []) or [])[:3]) or "suspicious staged paths"
        summary = (
            f"{finding.user or 'Unknown user'} staged suspicious payloads over SMB to {finding.host or 'unknown host'} from "
            f"{finding.source_ip or 'an unknown source'}, including {paths}."
        )
        return (
            "remote_service_payload_staging",
            "Remote service payload staging",
            summary,
            "Lateral Movement -> SMB/Windows Admin Shares",
        )
    if title == "PsExec Service Binary Drop":
        summary = (
            f"PSEXESVC.exe was dropped and/or launched on {finding.host or 'unknown host'}, which is consistent with PsExec-style "
            "remote service execution on the target host."
        )
        return (
            "psexec_service_binary_drop",
            "PsExec service binary drop",
            summary,
            "Lateral Movement -> SMB/Windows Admin Shares",
        )
    if title == "WMI Remote Execution":
        processes = finding.evidence.get("processes", []) or [finding.process]
        summary = (
            f"WMI provider host launched {', '.join([p for p in processes if p]) or 'remote commands'} on "
            f"{finding.host or 'unknown host'} as {finding.user or 'unknown user'}."
        )
        return (
            "wmi_remote_execution",
            "WMI remote execution",
            summary,
            "Lateral Movement -> Windows Management Instrumentation",
        )
    if title == "WMI Event Subscription Persistence":
        summary = (
            f"WMI subscription persistence was created on {finding.host or 'unknown host'} with binding details that "
            "indicate an active filter-to-consumer chain."
        )
        return (
            "wmi_event_subscription_persistence",
            "WMI event subscription persistence",
            summary,
            "Persistence -> Event Triggered Execution",
        )
    if title == "WMI Permanent Event Subscription":
        consumers = ", ".join(finding.evidence.get("consumer_names", [])[:3]) or "unknown consumer"
        summary = (
            f"{finding.user or 'Unknown user'} created a permanent WMI subscription on {finding.host or 'unknown host'} "
            f"using {consumers}."
        )
        return (
            "wmi_permanent_subscription",
            "WMI permanent event subscription",
            summary,
            "Persistence -> Event Triggered Execution",
        )
    if title == "Application Shim Persistence":
        targets = ", ".join(finding.evidence.get("target_binaries", [])[:3]) or "application targets"
        summary = (
            f"Application compatibility shim data was installed on {finding.host or 'unknown host'} targeting {targets}."
        )
        return (
            "application_shim_persistence",
            "Application shim persistence",
            summary,
            "Persistence -> Application Shimming",
        )
    if title == "Accessibility Features Backdoor":
        image = finding.evidence.get("launched_image", "") or finding.process or "an accessibility binary"
        summary = (
            f"An accessibility binary backdoor launched {image} from the Windows logon path on {finding.host or 'unknown host'}."
        )
        return (
            "accessibility_features_backdoor",
            "Accessibility features backdoor",
            summary,
            "Persistence -> Accessibility Features",
        )
    if title == "Shadow Credentials Modified":
        target = finding.evidence.get("object_dn", "") or finding.user or "an identity object"
        summary = (
            f"Shadow credential material was added or changed for {target} on {finding.host or 'unknown host'}, "
            "enabling certificate-based authentication abuse."
        )
        return (
            "shadow_credentials_abuse",
            "Shadow credentials modified",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title in {"AD CS Suspicious Certificate Request", "AD CS Vulnerable Template Change"}:
        template = finding.evidence.get("template", "") or "an AD CS template"
        summary = (
            f"AD CS activity involving {template} on {finding.host or 'unknown host'} looked consistent with certificate-based identity abuse."
        )
        return (
            "adcs_certificate_abuse",
            "AD CS certificate abuse",
            summary,
            "Credential Access -> Steal or Forge Authentication Certificates",
        )
    if title == "Delegation Configuration Changed":
        change = finding.evidence.get("delegation_change", "") or "delegation settings"
        summary = (
            f"Delegation settings for {finding.user or 'an identity object'} were changed on {finding.host or 'unknown host'}: {change}."
        )
        return (
            "delegation_configuration_change",
            "Delegation configuration changed",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title in {"Group Policy Object Modified", "Domain Policy Changed"}:
        summary = (
            f"Directory policy settings were modified on {finding.host or 'unknown host'}, which can distribute persistence or weaken security controls broadly."
        )
        return (
            "policy_modification",
            "Directory policy modification",
            summary,
            "Persistence -> Domain or Tenant Policy Modification",
        )
    if title == "Privileged Account Password Reset":
        summary = (
            f"{finding.subject_user or 'Unknown actor'} reset the password for {finding.user or 'a privileged account'} on {finding.host or 'unknown host'}."
        )
        return (
            "privileged_password_reset",
            "Privileged account password reset",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Cross-Account Password Change":
        summary = (
            f"{finding.subject_user or 'Unknown actor'} changed the password for "
            f"{finding.user or 'another account'} on {finding.host or 'unknown host'}."
        )
        return (
            "cross_account_password_change",
            "Cross-account password change",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Sensitive and Not Delegatable Enabled":
        summary = (
            f"{finding.subject_user or finding.evidence.get('actor_user', '') or 'Unknown actor'} marked "
            f"{finding.user or 'an account'} as sensitive and not delegatable on {finding.host or 'unknown host'}."
        )
        return (
            "account_not_delegatable_enabled",
            "Sensitive and not delegatable enabled",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Kerberos Preauthentication Disabled":
        summary = (
            f"{finding.subject_user or finding.evidence.get('actor_user', '') or 'Unknown actor'} disabled Kerberos preauthentication "
            f"for {finding.user or 'an account'} on {finding.host or 'unknown host'}."
        )
        return (
            "kerberos_preauth_disabled",
            "Kerberos preauthentication disabled",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Kerberos DES-Only Encryption Enabled":
        summary = (
            f"{finding.subject_user or finding.evidence.get('actor_user', '') or 'Unknown actor'} enabled DES-only Kerberos encryption "
            f"for {finding.user or 'an account'} on {finding.host or 'unknown host'}."
        )
        return (
            "kerberos_des_only_enabled",
            "Kerberos DES-only encryption enabled",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Reversible Password Encryption Enabled":
        summary = (
            f"{finding.subject_user or finding.evidence.get('actor_user', '') or 'Unknown actor'} enabled reversible password encryption "
            f"for {finding.user or 'an account'} on {finding.host or 'unknown host'}."
        )
        return (
            "reversible_password_encryption_enabled",
            "Reversible password encryption enabled",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Remote SAMR Password Reset":
        summary = (
            f"{finding.subject_user or 'Unknown actor'} reset the password for {finding.user or 'an account'} on "
            f"{finding.host or 'unknown host'} from {finding.source_ip or 'an unknown source'} through SAMR."
        )
        return (
            "remote_password_reset",
            "Remote SAMR password reset",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "AdminSDHolder Permissions Changed":
        summary = (
            f"{finding.subject_user or 'Unknown actor'} modified AdminSDHolder permissions on "
            f"{finding.host or 'unknown host'}, which can backdoor protected AD objects."
        )
        return (
            "adminsdholder_backdoor",
            "AdminSDHolder permissions changed",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "AdminSDHolder Rights Obfuscation":
        summary = (
            f"{finding.subject_user or 'Unknown actor'} altered protected extended-right metadata on "
            f"{finding.host or 'unknown host'}, which can conceal AdminSDHolder abuse."
        )
        return (
            "adminsdholder_rights_obfuscation",
            "AdminSDHolder rights obfuscation",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title in {"SPN Added to User Account", "SPN Added to Computer Account"}:
        spn_value = finding.evidence.get("spn_value", "") or "an SPN"
        summary = (
            f"{finding.subject_user or 'Unknown actor'} assigned {spn_value} to "
            f"{finding.user or 'an AD object'} on {finding.host or 'unknown host'}."
        )
        return (
            "spn_assignment",
            "Suspicious SPN assignment",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "AD Object Owner Changed":
        summary = (
            f"{finding.subject_user or 'Unknown actor'} changed the owner of "
            f"{finding.user or 'an AD object'} on {finding.host or 'unknown host'}."
        )
        return (
            "ad_object_owner_change",
            "AD object owner changed",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "AD CS OCSP Configuration Tampering":
        summary = (
            f"{finding.subject_user or 'Unknown actor'} modified OCSP responder configuration on "
            f"{finding.host or 'unknown host'}, including audit or access-control changes."
        )
        return (
            "adcs_ocsp_tampering",
            "AD CS OCSP configuration tampering",
            summary,
            "Defense Evasion -> Impair Defenses",
        )
    if title == "Sensitive User Right Assigned":
        privilege = finding.evidence.get("privilege", "") or "a sensitive privilege"
        target_sid = finding.evidence.get("target_sid", "") or "an unknown SID"
        summary = (
            f"{finding.evidence.get('actor_user', '') or finding.user or 'Unknown actor'} assigned {privilege} to {target_sid} "
            f"on {finding.host or 'unknown host'}."
        )
        return (
            "sensitive_user_right_assignment",
            "Sensitive user right assigned",
            summary,
            "Privilege Escalation -> Access Token Manipulation",
        )
    if title == "System Security Access Granted":
        target_sid = finding.evidence.get("target_sid", "") or "an unknown SID"
        summary = (
            f"{finding.evidence.get('actor_user', '') or finding.user or 'Unknown actor'} granted system security access to {target_sid} "
            f"on {finding.host or 'unknown host'}."
        )
        return (
            "system_security_access_granted",
            "System security access granted",
            summary,
            "Privilege Escalation -> Account Rights Manipulation",
        )
    if title == "SID History Added":
        source_user = finding.evidence.get("source_user", "") or "an unknown source identity"
        summary = (
            f"{finding.subject_user or finding.evidence.get('actor_user', '') or 'Unknown actor'} added SID history from {source_user} "
            f"to {finding.user or 'an account'} on {finding.host or 'unknown host'}."
        )
        return (
            "sid_history_added",
            "SID history added",
            summary,
            "Privilege Escalation -> SID-History Injection",
        )
    if title == "New Privileged Account Provisioned":
        account = finding.evidence.get("new_account", "") or finding.user or "a new account"
        groups = ", ".join(finding.evidence.get("sensitive_groups", [])[:3]) or "a sensitive group"
        summary = (
            f"{account} was created on {finding.host or 'unknown host'} and then added to {groups}, indicating privileged account persistence."
        )
        return (
            "new_privileged_account_provisioning",
            "New privileged account provisioned",
            summary,
            "Persistence -> Create Account / Additional Group Membership",
        )
    if title == "Windows Event Log Service Disabled":
        summary = (
            f"The Windows Event Log service startup mode was altered on {finding.host or 'unknown host'}, reducing future logging visibility."
        )
        return (
            "event_log_service_tampering",
            "Windows Event Log service tampering",
            summary,
            "Defense Evasion -> Impair Defenses",
        )
    if title == "PowerShell Constrained Language Mode Disabled":
        summary = (
            f"PowerShell Constrained Language Mode enforcement was disabled on {finding.host or 'unknown host'} by "
            f"{finding.evidence.get('actor_user', '') or finding.user or 'an unknown actor'}."
        )
        return (
            "powershell_clm_disabled",
            "PowerShell Constrained Language Mode disabled",
            summary,
            "Defense Evasion -> Impair Defenses",
        )
    if title == "PowerShell Execution Policy Weakened":
        policy_value = finding.evidence.get("policy_value", "") or "an insecure execution policy"
        summary = (
            f"{finding.evidence.get('actor_user', '') or finding.user or 'An unknown actor'} set PowerShell execution policy "
            f"to {policy_value} on {finding.host or 'unknown host'}, weakening script execution controls."
        )
        return (
            "powershell_execution_policy_weakened",
            "PowerShell execution policy weakened",
            summary,
            "Defense Evasion -> Impair Defenses",
        )
    if title == "PowerShell ScriptBlockLogging Disabled":
        summary = (
            f"ScriptBlockLogging was disabled on {finding.host or 'unknown host'}, reducing PowerShell telemetry for "
            f"{finding.evidence.get('actor_user', '') or finding.user or 'an unknown actor'}."
        )
        return (
            "powershell_scriptblocklogging_disabled",
            "PowerShell ScriptBlockLogging disabled",
            summary,
            "Defense Evasion -> Impair Defenses",
        )
    if title == "Windows Event Log Service Crash":
        summary = (
            f"The Windows Event Log service crashed on {finding.host or 'unknown host'}, interrupting host logging visibility."
        )
        return (
            "event_log_service_crash",
            "Windows Event Log service crash",
            summary,
            "Defense Evasion -> Impair Defenses",
        )
    if title == "Remote Event Log Service Crash":
        source_ips = ", ".join(finding.evidence.get("source_ips", [])[:3]) or finding.source_ip or "an unknown remote source"
        summary = (
            f"Remote activity from {source_ips} preceded an Event Log service crash on {finding.host or 'unknown host'}."
        )
        return (
            "remote_event_log_service_crash",
            "Remote Event Log service crash",
            summary,
            "Defense Evasion -> Impair Defenses",
        )
    if title == "xp_cmdshell Enabled":
        summary = (
            f"xp_cmdshell was enabled on {finding.host or 'unknown host'}"
            f"{f' by {finding.user}' if finding.user else ''}, allowing operating-system command execution through SQL Server."
        )
        return (
            "mssql_xp_cmdshell_enabled",
            "xp_cmdshell enabled",
            summary,
            "Execution -> SQL Stored Procedures",
        )
    if title == "MSSQL xp_cmdshell Execution":
        statement = finding.evidence.get("statement", "") or "an operating-system command"
        source = finding.evidence.get("client_ip", "") or finding.source_ip or "an unknown client"
        summary = (
            f"{finding.user or 'An unknown principal'} executed xp_cmdshell on {finding.host or 'unknown host'} from {source}: {statement}"
        )
        return (
            "mssql_xp_cmdshell_execution",
            "MSSQL xp_cmdshell execution",
            summary,
            "Execution -> SQL Stored Procedures",
        )
    if title == "MSSQL xp_cmdshell Execution Attempt":
        summary = (
            f"An xp_cmdshell execution attempt was blocked on {finding.host or 'unknown host'}, indicating attempted operating-system command execution through SQL Server."
        )
        return (
            "mssql_xp_cmdshell_execution_attempt",
            "MSSQL xp_cmdshell execution attempt",
            summary,
            "Execution -> SQL Stored Procedures",
        )
    if title == "Mimikatz Credential Dumping":
        summary = (
            f"{finding.user or 'Unknown user'} executed Mimikatz-associated privilege operations on {finding.host or 'unknown host'}."
        )
        return (
            "mimikatz_credential_dumping",
            "Mimikatz credential dumping",
            summary,
            "Credential Access -> OS Credential Dumping",
        )
    if title == "Guest Account Enabled":
        summary = (
            f"{finding.subject_user or finding.evidence.get('actor_user', '') or 'Unknown actor'} enabled the Guest account "
            f"on {finding.host or 'unknown host'}."
        )
        return (
            "guest_account_enabled",
            "Guest account enabled",
            summary,
            "Persistence -> Create Account",
        )
    if title == "Password Not Required Enabled":
        summary = (
            f"{finding.subject_user or finding.evidence.get('actor_user', '') or 'Unknown actor'} enabled Password Not Required "
            f"for {finding.user or 'an account'} on {finding.host or 'unknown host'}."
        )
        return (
            "password_not_required_enabled",
            "Password Not Required enabled",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Password Never Expires Enabled":
        summary = (
            f"{finding.subject_user or finding.evidence.get('actor_user', '') or 'Unknown actor'} disabled password expiry "
            f"for {finding.user or 'an account'} on {finding.host or 'unknown host'}."
        )
        return (
            "password_never_expires_enabled",
            "Password Never Expires enabled",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "User Renamed to Admin-Like Name":
        old_name = finding.evidence.get("old_name", "") or "an existing user"
        new_name = finding.evidence.get("new_name", "") or finding.user or "an admin-like name"
        summary = (
            f"{finding.subject_user or 'Unknown actor'} renamed {old_name} to {new_name} on "
            f"{finding.host or 'unknown host'}, making the account appear privileged."
        )
        return (
            "user_renamed_admin_like",
            "User renamed to admin-like name",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Computer Account Spoofing Kerberos Abuse":
        old_name = finding.evidence.get("old_name", "") or "a computer account"
        new_name = finding.evidence.get("new_name", "") or finding.user or "a spoofed machine identity"
        source_ips = [item for item in finding.evidence.get("source_ips", []) if item]
        services = [item for item in finding.evidence.get("service_names", []) if item]
        source_text = ", ".join(source_ips[:2]) if source_ips else "an unknown source"
        service_text = ", ".join(services[:2]) if services else "the spoofed host service"
        summary = (
            f"{finding.subject_user or 'Unknown actor'} renamed {old_name} to {new_name} on "
            f"{finding.host or 'unknown host'} and immediately requested Kerberos tickets from {source_text} "
            f"for {service_text}, matching sAMAccountName spoofing abuse."
        )
        return (
            "computer_account_spoofing_kerberos_abuse",
            "Computer account spoofing Kerberos abuse",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Computer Account Renamed Without Trailing Dollar":
        old_name = finding.evidence.get("old_name", "") or "a computer account"
        new_name = finding.evidence.get("new_name", "") or finding.user or "a dollarless machine name"
        summary = (
            f"{finding.subject_user or 'Unknown actor'} renamed {old_name} to {new_name} on "
            f"{finding.host or 'unknown host'}, matching sAMAccountName spoofing behavior."
        )
        return (
            "computer_account_rename_without_trailing_dollar",
            "Computer account renamed without trailing dollar",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "SQL Database Role Membership Added":
        role_name = finding.evidence.get("role_name", "") or "a database role"
        database_name = finding.evidence.get("database_name", "") or "an unknown database"
        principal = finding.evidence.get("target_principal", "") or finding.user or "a principal"
        summary = (
            f"{finding.subject_user or 'Unknown actor'} added {principal} to SQL database role {role_name} "
            f"in {database_name} on {finding.host or 'unknown host'}."
        )
        return (
            "sql_database_role_membership_added",
            "SQL database role membership added",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "SQL Server Role Membership Added":
        role_name = finding.evidence.get("role_name", "") or "a server role"
        principal = finding.evidence.get("target_principal", "") or finding.user or "a principal"
        summary = (
            f"{finding.subject_user or 'Unknown actor'} added {principal} to SQL Server role {role_name} "
            f"on {finding.host or 'unknown host'}."
        )
        return (
            "sql_server_role_membership_added",
            "SQL Server role membership added",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "SQL User Linked to Login":
        database_name = finding.evidence.get("database_name", "") or "an unknown database"
        principal = finding.evidence.get("target_principal", "") or finding.user or "a SQL principal"
        summary = (
            f"{finding.subject_user or 'Unknown actor'} linked SQL principal {principal} to a login in "
            f"{database_name} on {finding.host or 'unknown host'}."
        )
        return (
            "sql_user_linked_to_login",
            "SQL user linked to login",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Mass Group Membership Change":
        member = finding.evidence.get("member", "") or finding.user or "an account"
        group_count = finding.evidence.get("group_count", 0) or len(finding.evidence.get("groups", []))
        summary = (
            f"{finding.subject_user or 'Unknown actor'} added {member} to {group_count} groups on "
            f"{finding.host or 'unknown host'}."
        )
        return (
            "mass_group_membership_change",
            "Mass group membership change",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Self-Added to Group":
        group_name = finding.evidence.get("group", "") or "a group"
        summary = (
            f"{finding.subject_user or finding.user or 'An account'} added themselves to {group_name} on "
            f"{finding.host or 'unknown host'}."
        )
        return (
            "self_added_to_group",
            "Self-added to group",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "Member Added to Sensitive Group":
        group_name = finding.evidence.get("group", "") or "a sensitive group"
        member = finding.evidence.get("member", "") or finding.user or "an account"
        summary = (
            f"{finding.subject_user or finding.evidence.get('changed_by', '') or 'Unknown actor'} added "
            f"{member} to {group_name} on {finding.host or 'unknown host'}."
        )
        return (
            "sensitive_group_membership_added",
            "Sensitive group membership added",
            summary,
            "Persistence -> Account Manipulation",
        )
    if title == "DCShadow Computer Object Staging":
        target = finding.evidence.get("target_computer_account", "") or "a computer account"
        summary = (
            f"{finding.user or 'Unknown user'} staged rogue domain-controller style SPNs for {target} on {finding.host or 'unknown host'}."
        )
        return (
            "dcshadow_staging",
            "DCShadow computer-object staging",
            summary,
            "Defense Evasion -> Rogue Domain Controller",
        )
    if title == "Suspicious .NET Compilation from User Temp":
        summary = (
            f"Temporary .NET compilation activity consistent with offensive scripting or PSAttack-style payload staging occurred on {finding.host or 'unknown host'}."
        )
        return (
            "suspicious_dotnet_temp_compilation",
            "Suspicious temporary .NET compilation",
            summary,
            "Defense Evasion -> Trusted Developer Utilities Proxy Execution",
        )
    if title == "IIS Webshell Command Execution":
        processes = ", ".join(finding.evidence.get("processes", [])[:4]) or finding.process or "w3wp.exe child processes"
        summary = (
            f"IIS worker process execution on {finding.host or 'unknown host'} spawned {processes} as "
            f"{finding.user or 'an unknown application-pool identity'}."
        )
        return (
            "iis_webshell_execution",
            "IIS webshell command execution",
            summary,
            "Persistence -> Server Software Component",
        )
    if title == "DCOM Internet Explorer Execution":
        summary = (
            f"Internet Explorer was launched with DCOM embedding semantics on {finding.host or 'unknown host'} "
            f"for {finding.user or 'an unknown user'}."
        )
        return (
            "dcom_internet_explorer_execution",
            "DCOM Internet Explorer execution",
            summary,
            "Lateral Movement -> Distributed Component Object Model",
        )
    if title == "KeePass Master Key Theft":
        source = finding.evidence.get("source_image", "") or finding.process or "an unknown process"
        summary = (
            f"{source} accessed KeePass process memory on {finding.host or 'unknown host'}, which is consistent with "
            "KeePass master key theft."
        )
        return (
            "keepass_master_key_theft",
            "KeePass master key theft",
            summary,
            "Credential Access -> Credentials from Password Stores",
        )
    if title == "Msiexec Package Proxy Execution":
        temp_installer = finding.evidence.get("temp_installer", "") or "a temporary installer binary"
        summary = (
            f"msiexec launched {temp_installer} on {finding.host or 'unknown host'}, and the temporary installer spawned shell activity."
        )
        return (
            "msiexec_proxy_execution",
            "Msiexec package proxy execution",
            summary,
            "Defense Evasion -> Signed Binary Proxy Execution",
        )
    if title == "UAC Bypass via Auto-Elevated Registry Hijack":
        trigger = finding.evidence.get("trigger_binary", "") or "an auto-elevated binary"
        summary = (
            f"{finding.user or 'Unknown user'} hijacked {trigger} on {finding.host or 'unknown host'} via a per-user registry override "
            "to bypass UAC."
        )
        return (
            "uac_bypass_registry_hijack",
            "UAC bypass via registry hijack",
            summary,
            "Privilege Escalation -> Abuse Elevation Control Mechanism",
        )
    if title == "CMSTP UAC Bypass":
        summary = (
            f"{finding.user or 'Unknown user'} abused CMSTP profile installation on {finding.host or 'unknown host'} "
            "to trigger an elevated shell through DllHost."
        )
        return (
            "cmstp_uac_bypass",
            "CMSTP UAC bypass",
            summary,
            "Privilege Escalation -> Abuse Elevation Control Mechanism",
        )
    if title == "Volatile SYSTEMROOT UAC Bypass":
        redirected = finding.evidence.get("redirected_systemroot", "") or "a temp directory"
        summary = (
            f"{finding.user or 'Unknown user'} redirected SYSTEMROOT to {redirected} on {finding.host or 'unknown host'} "
            "and triggered elevated MMC execution through perfmon."
        )
        return (
            "volatile_systemroot_uac_bypass",
            "Volatile SYSTEMROOT UAC bypass",
            summary,
            "Privilege Escalation -> Abuse Elevation Control Mechanism",
        )
    if title == "UAC Bypass via DLL Side-Loading":
        target_binary = finding.evidence.get("target_binary", "") or finding.process or "an auto-elevated binary"
        loaded_module = finding.evidence.get("loaded_module", "") or "a side-loaded module"
        summary = (
            f"{target_binary} on {finding.host or 'unknown host'} loaded {loaded_module}, which is consistent with "
            "a UAC bypass through DLL side-loading."
        )
        return (
            "uac_bypass_dll_sideload",
            "UAC bypass via DLL side-loading",
            summary,
            "Privilege Escalation -> Abuse Elevation Control Mechanism",
        )
    if title == "WScript Manifest UAC Bypass":
        manifest_path = finding.evidence.get("manifest_path", "") or "a crafted wscript.exe.manifest"
        summary = (
            f"{finding.user or 'Unknown user'} staged {manifest_path} on {finding.host or 'unknown host'} and extracted it into C:\\Windows "
            "to abuse auto-elevation."
        )
        return (
            "wscript_manifest_uac_bypass",
            "WScript manifest UAC bypass",
            summary,
            "Privilege Escalation -> Abuse Elevation Control Mechanism",
        )
    if title == "Browser Credential Store Access":
        process_name = finding.evidence.get("process_name", "") or finding.process or "an unknown process"
        families = ", ".join(finding.evidence.get("browser_families", [])[:3]) or "multiple browsers"
        summary = (
            f"{process_name} accessed {families} credential stores on {finding.host or 'unknown host'}, which is consistent with "
            "saved browser password theft."
        )
        return (
            "browser_credential_store_access",
            "Browser credential store access",
            summary,
            "Credential Access -> Credentials from Password Stores",
        )
    if title == "TSCLIENT Startup Folder Drop":
        target_file = finding.evidence.get("target_file", "") or "a startup payload"
        summary = (
            f"mstsc.exe wrote {target_file} into a remote Startup folder on {finding.host or 'unknown host'}, "
            "indicating RDP drive-redirection abuse for persistence or follow-on execution."
        )
        return (
            "tsclient_startup_drop",
            "TSCLIENT startup folder drop",
            summary,
            "Lateral Movement -> Remote Services",
        )
    if title == "Service Installed":
        service_name = finding.service or finding.evidence.get("service_name", "") or "an unknown service"
        binary = finding.evidence.get("binary", "") or _finding_command_line(finding) or "an unknown binary"
        account = finding.account_name or finding.evidence.get("account", "") or "an unknown account"
        summary = (
            f"Service {service_name} was installed on {finding.host or 'unknown host'} to run {binary} "
            f"as {account}, which is consistent with malicious service-based persistence or lateral movement."
        )
        return (
            "service_installation_abuse",
            "Service installed",
            summary,
            "Persistence -> Create or Modify System Process / Windows Service",
        )
    if title == "Suspicious Service Execution":
        service_name = finding.service or finding.evidence.get("service_name", "") or "an unknown service"
        command = _finding_command_line(finding) or finding.evidence.get("binary", "") or "an unknown command"
        summary = (
            f"Service {service_name} on {finding.host or 'unknown host'} points to {command}, "
            "which is consistent with service-based payload execution."
        )
        return (
            "suspicious_service_execution",
            "Suspicious service execution",
            summary,
            "Lateral Movement -> Service Execution",
        )
    return (
        "critical_finding_promotion",
        finding.title or "Critical finding promoted to incident",
        finding.summary or finding.description,
        " -> ".join(
            part for part in [finding.evidence.get("source_rule", ""), finding.evidence.get("source_technique", "")]
            if part
        ),
    )


def _finding_command_line(finding: Finding) -> str:
    if finding.command_line:
        return finding.command_line
    commands = finding.evidence.get("suspicious_commands", [])
    if commands:
        return commands[0]
    return ""


def _promote_clustered_signals(
    signals: Sequence[Signal],
    findings: Sequence[Finding],
    existing_incidents: Sequence[Incident],
) -> List[Incident]:
    incidents: List[Incident] = []
    _, covered_signal_ids = _covered_ids(existing_incidents)
    finding_by_signal: Dict[str, List[Finding]] = {}
    for finding in findings:
        for signal_id in finding.signal_ids:
            finding_by_signal.setdefault(signal_id, []).append(finding)

    grouped: Dict[Tuple[str, str], List[Signal]] = {}
    for signal in signals:
        if signal.id in covered_signal_ids:
            continue
        if not signal.host or not signal.user or not signal.timestamp:
            continue
        if (signal.source_rule or "") not in CLUSTERABLE_SIGNAL_RULES and (signal.severity or "").lower() != "critical":
            continue
        grouped.setdefault((signal.host, signal.user), []).append(signal)

    for (host, user), user_signals in grouped.items():
        ordered = sorted(user_signals, key=lambda item: item.timestamp or datetime.min)
        if len(ordered) < 2:
            continue

        cluster = [ordered[0]]
        for signal in ordered[1:]:
            previous = cluster[-1]
            if not previous.timestamp or not signal.timestamp:
                continue
            if signal.timestamp - previous.timestamp <= timedelta(minutes=10):
                cluster.append(signal)
            else:
                incidents.extend(_emit_signal_cluster(host, user, cluster, finding_by_signal))
                cluster = [signal]
        incidents.extend(_emit_signal_cluster(host, user, cluster, finding_by_signal))

    return incidents


def _emit_signal_cluster(
    host: str,
    user: str,
    cluster: Sequence[Signal],
    finding_by_signal: Dict[str, List[Finding]],
) -> List[Incident]:
    if len(cluster) < 2:
        return []

    rules = sorted({signal.source_rule for signal in cluster if signal.source_rule})
    if len(rules) < 2:
        return []

    finding_ids = sorted({finding.id for signal in cluster for finding in finding_by_signal.get(signal.id, [])})
    signal_ids = sorted({signal.id for signal in cluster})
    severity = "critical" if any((signal.severity or "").lower() == "critical" for signal in cluster) else "high"
    first_seen = cluster[0].timestamp
    last_seen = cluster[-1].timestamp
    payload = {
        "incident_type": "clustered_high_risk_activity",
        "host": host,
        "user": user,
        "rules": rules,
        "signal_ids": signal_ids,
        "finding_ids": finding_ids,
        "start": first_seen,
        "end": last_seen,
    }

    return [
        Incident(
            id=stable_id("inc", payload),
            display_label="",
            incident_type="clustered_high_risk_activity",
            title="Clustered high-risk activity",
            severity=severity,
            confidence="high",
            confidence_score=82 if severity == "high" else 90,
            summary=(
                f"{user} triggered multiple high-risk detections on {host} within a short time window: "
                f"{', '.join(rules[:4])}."
            ),
            first_seen=first_seen,
            last_seen=last_seen,
            finding_ids=finding_ids,
            signal_ids=signal_ids,
            evidence_chain=[
                {
                    "type": "signal",
                    "id": signal.id,
                    "label": signal.display_label or signal.id,
                    "rule": signal.source_rule,
                    "timestamp": signal.timestamp.isoformat() if signal.timestamp else None,
                    "description": signal.description,
                }
                for signal in cluster
            ],
            host=host,
            user=user,
            source_ip=_dominant_value([signal.source_ip for signal in cluster if signal.source_ip]),
            process=_dominant_value([signal.process for signal in cluster if signal.process]),
            command_line=_dominant_value([signal.command_line for signal in cluster if signal.command_line]),
            technique_summary="Correlated credential / persistence / lateral movement activity",
            recommended_next=(
                f"Review the correlated detections for {user} on {host}, reconstruct the session timeline, "
                "and validate whether the activity maps to authorized administration."
            ),
        )
    ]


def _collect_related_ids(
    signals: Sequence[Signal],
    findings: Sequence[Finding],
    host: str,
    start,
    end,
) -> Tuple[List[str], List[str]]:
    if start and end and end < start:
        start, end = end, start

    signal_ids = []
    finding_ids = []

    for signal in signals:
        if host and signal.host and signal.host != host:
            continue
        if signal.timestamp and start and signal.timestamp < start - timedelta(minutes=5):
            continue
        if signal.timestamp and end and signal.timestamp > end + timedelta(minutes=5):
            continue
        signal_ids.append(signal.id)

    for finding in findings:
        if host and finding.host and finding.host != host:
            continue
        ts = finding.first_seen or finding.last_seen
        if ts and start and ts < start - timedelta(minutes=5):
            continue
        if ts and end and ts > end + timedelta(minutes=5):
            continue
        finding_ids.append(finding.id)

    return sorted(set(signal_ids)), sorted(set(finding_ids))


def _incident_severity(signal_ids: List[str], finding_ids: List[str], findings: Sequence[Finding]) -> str:
    if not finding_ids:
        return "high" if signal_ids else "medium"

    by_id = {f.id: f for f in findings}
    severities = {(by_id[fid].severity or "").lower() for fid in finding_ids if fid in by_id}
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


def _first_match(events: Sequence[NormalizedEvent], start, end, predicate) -> Optional[NormalizedEvent]:
    for ev in events:
        if not ev.timestamp:
            continue
        if ev.timestamp < start or ev.timestamp > end:
            continue
        if predicate(ev):
            return ev
    return None


def _event_description(ev: NormalizedEvent) -> str:
    if ev.event_id == 4624:
        if ev.logon_type == "9":
            return (
                f"Successful NewCredentials logon by {ev.target_domain_user or ev.domain_user or 'unknown'} "
                f"via {(ev.event_data.get('LogonProcessName', '') or 'unknown process')} "
                f"from {ev.source_ip or 'local context'}"
            )
        return f"Successful {ev.logon_type_name or 'remote'} logon by {ev.target_domain_user or ev.domain_user or 'unknown'} from {ev.source_ip or 'unknown'}"
    if ev.event_id == 4625:
        return f"Failed logon for {ev.target_domain_user or ev.target_user or 'unknown'} from {ev.source_ip or 'unknown'}"
    if ev.event_id == 4648:
        return f"Explicit credentials used for {ev.target_domain_user or ev.target_user or 'unknown'} via {ev.process_name or 'unknown process'}"
    if ev.event_id == 4672:
        return f"Special privileges assigned to {ev.subject_domain_user or ev.subject_user or 'unknown'}"
    if ev.event_id == 5140:
        return f"Share access {ev.share_name or ev.event_data.get('ShareName', '')} from {ev.source_ip or ev.event_data.get('IpAddress', 'unknown')}"
    if ev.event_id in (7045, 4697):
        return f"Service installed: {ev.service_name or 'unknown'}"
    if ev.event_id in (4688, 1):
        return f"Process executed: {(ev.command_line or ev.process_name or 'unknown')[:140]}"
    if ev.event_id == 1102:
        return f"Audit log cleared by {ev.domain_user or 'unknown'}"
    return f"Event {ev.event_id}"


def _is_precursor_signal(signal: Signal) -> bool:
    name = (signal.source_rule or "").lower()
    return any(token in name for token in ("powershell", "lsass", "service", "pre-log-wipe", "audit log"))


def _is_precursor_finding(finding: Finding) -> bool:
    name = (finding.title or "").lower()
    return any(token in name for token in ("powershell", "lsass", "service", "audit log", "log"))


def _ts_sort_key(ts) -> tuple[int, float]:
    if ts is None:
        return (1, float("inf"))
    if isinstance(ts, datetime):
        dt = ts.astimezone() if ts.tzinfo else ts
        return (0, dt.timestamp())
    return (1, float("inf"))


def _looks_like_specific_sequence(chain: AttackChain) -> bool:
    rule_names = {alert.rule_name for alert in chain.alerts}
    if rule_names & REMOTE_CREDENTIAL_FINDINGS:
        return True
    if rule_names & POWERSHELL_SCRIPT_FINDINGS:
        return True
    if rule_names & SPECIFIC_FINDING_TITLES:
        return True
    if "Audit Log Cleared" in rule_names:
        return True
    return False


def _entities_from_alerts(alerts) -> Dict[str, object]:
    users = [a.user for a in alerts if a.user]
    ips = [a.source_ip for a in alerts if a.source_ip and a.source_ip not in BENIGN_IPS]
    processes = [a.process for a in alerts if a.process]
    services = [a.service for a in alerts if a.service]
    commands = [a.event.command_line for a in alerts if a.event and a.event.command_line]
    return {
        "users": sorted(set(users)),
        "ips": sorted(set(ips)),
        "processes": sorted(set(processes)),
        "services": sorted(set(services)),
        "commands": sorted(set(commands)),
        "primary_user": _dominant_value(users),
        "primary_ip": _dominant_value(ips),
        "primary_process": _dominant_value(processes),
        "primary_service": _dominant_value(services),
        "primary_command": _dominant_value(commands),
    }


def _dominant_value(values: Sequence[str]) -> str:
    filtered = [value for value in values if value]
    if not filtered:
        return ""
    return Counter(filtered).most_common(1)[0][0]


def _chain_title_and_summary(chain: AttackChain) -> Tuple[str, str]:
    tactics = set(chain.tactics)
    if {"Credential Access", "Lateral Movement"} <= tactics:
        return "Credential attack followed by remote access", "Credential Access -> Lateral Movement"
    if "Persistence" in tactics and "Defense Evasion" in tactics:
        return "Persistence and defense-evasion sequence", "Persistence -> Defense Evasion"
    if "Persistence" in tactics:
        return "Persistence sequence", "Persistence"
    if "Defense Evasion" in tactics:
        return "Defense-evasion sequence", "Defense Evasion"
    return "Correlated suspicious activity", " -> ".join(chain.tactics)


def _chain_story(chain: AttackChain, entities: Dict[str, object]) -> str:
    parts = [f"Suspicious activity on {chain.host or 'unknown host'}"]
    if entities["primary_user"]:
        parts.append(f"involving {entities['primary_user']}")
    if entities["primary_ip"]:
        parts.append(f"from {entities['primary_ip']}")
    if entities["primary_process"]:
        parts.append(f"using {entities['primary_process']}")
    parts.append(f"across {len(chain.alerts)} alerts and {len(chain.tactics)} tactics")
    return " ".join(parts) + "."


def _chain_recommended_next(chain: AttackChain) -> str:
    recommendations = []
    for alert in chain.alerts:
        text = (alert.investigate_next or "").strip()
        if text and text not in recommendations:
            recommendations.append(text)
        if len(recommendations) == 2:
            break
    if recommendations:
        return " ".join(recommendations)
    return "Review the evidence chain in order, validate the affected account and host activity, and scope related telemetry for follow-on actions."

