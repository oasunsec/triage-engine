"""Detections for server abuse, traffic capture, access changes, and encryption.

These signals are intentionally conservative: the events are useful pivots for an
investigator, but none of them alone proves compromise (especially BitLocker).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from models.event_model import Alert, NormalizedEvent


_INTERPRETER_COTAG_RULES = (
    ("scheduled-task", re.compile(r"\bschtasks\b.*?[/-](?:create|run)\b")),
    ("service-config", re.compile(r"\b(?:sc|sc\.exe)\b.*\b(?:create|config|failure)\b")),
    ("wmi-exec", re.compile(r"\bwmic\b.*\bprocess\s+call\s+create\b")),
    ("encoded-command", re.compile(r"(?:-enc(?:odedcommand)?\b|-e\b\s+[a-z0-9+/=]{20,})")),
    ("downloader", re.compile(r"\b(?:certutil|bitsadmin|wget|curl|powershell|cmd)\b.*(?:https?://|\burl\b|\-download|/download)")),
    ("proxy-exec", re.compile(r"\b(?:regsvr32|rundll32|mshta)\b")),
)
_SUSPICIOUS_INTERPRETER_PARENTS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "winword.exe", "excel.exe", "outlook.exe", "wmiprvse.exe"}

_SCRIPT_CHILDREN = {
    "cmd.exe": "T1059.003",
    "powershell.exe": "T1059.001",
    "pwsh.exe": "T1059.001",
    "cscript.exe": "T1059.007",
    "wscript.exe": "T1059.007",
}
_TEMP_MARKERS = ("\\temp\\", "/temp/", "\\tmp\\", "/tmp/", "appdata\\local\\temp")
_PKTMON_ACTIONS = (" start", " filter", " etl2pcapng", " pcapng", " reset")
_BROAD_PRINCIPALS = ("everyone", "\u0432\u0441\u0435", "s-1-1-0", ";;;wd", "wd:")
_TRUST_CORRELATION_WINDOW = timedelta(minutes=10)
_RECOVERY_PATTERNS = (
    ("vssadmin-delete-shadows", re.compile(r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b")),
    ("wmic-shadowcopy-delete", re.compile(r"\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b")),
    ("powershell-win32-shadowcopy-delete", re.compile(
        r"\bwin32_shadowcopy\b.*(?:\.delete\s*\(|remove-(?:wmiobject|ciminstance)\b|invoke-cimmethod\b.*\bdelete\b)"
    )),
    ("wbadmin-delete-recovery-data", re.compile(
        r"\bwbadmin(?:\.exe)?\b.*\bdelete\s+(?:backup|catalog|systemstatebackup)\b"
    )),
    ("diskshadow-delete-shadows", re.compile(r"\bdiskshadow(?:\.exe)?\b.*\bdelete\s+shadows\b")),
    ("bcdedit-disable-recovery", re.compile(
        r"\bbcdedit(?:\.exe)?\b.*(?:\brecoveryenabled\s+no\b|\bbootstatuspolicy\s+ignoreallfailures\b)"
    )),
)


def _basename(value: str) -> str:
    return (value or "").replace("/", "\\").rstrip("\\").split("\\")[-1].lower()


def _field(ev: NormalizedEvent, *names: str) -> str:
    values = {str(k).lower(): str(v or "") for k, v in (ev.event_data or {}).items()}
    for name in names:
        value = values.get(name.lower(), "").strip()
        if value:
            return value
    return ""


def _same_time_bucket(timestamp: Optional[datetime]) -> str:
    if not timestamp:
        return "unknown"
    return timestamp.replace(second=0, microsecond=0).isoformat()


def _append_once(alerts: List[Alert], seen: Set[Tuple[str, ...]], key: Tuple[str, ...], alert: Alert) -> None:
    if key not in seen:
        seen.add(key)
        alerts.append(alert)


def _detect_bitlocker_lifecycle(events: List[NormalizedEvent]) -> List[Alert]:
    """Surface a full BitLocker encryption lifecycle as supporting evidence.

    A single 768 start event is routine. When several distinct lifecycle
    phases (start, protector add, key/WPR, suspend, resume, recovery, drive
    ready) cluster on one volume in a short window, that ladder is worth
    surfacing as a pivot -- without ever implying a ransomware verdict.
    """
    phases: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
    samples: Dict[Tuple[str, str], NormalizedEvent] = {}
    for ev in events:
        if not _is_bitlocker_event(ev) or ev.event_id not in _BITLOCKER_LIFECYCLE_EVENT_IDS:
            continue
        volume = (_field(ev, "Volume", "Drive", "MountPoint", "VolumeMountPoint", "Device") or "unknown volume").lower()
        key = (ev.computer or "").lower(), volume
        phases[key].add(ev.event_id)
        samples.setdefault(key, ev)
    alerts: List[Alert] = []
    for (computer, volume), phase_ids in phases.items():
        if len(phase_ids) < 3:
            continue
        ordered = sorted(phase_ids)
        sample = samples[(computer, volume)]
        alerts.append(Alert(
            rule_name="BitLocker Volume Encryption Lifecycle",
            # High severity so the signal survives system-account suppression;
            # confidence stays medium and evidence remains supporting-only.
            severity="high",
            mitre_tactic="Impact",
            mitre_technique="T1486",
            description=f"BitLocker lifecycle activity observed on {volume} on {computer or 'unknown host'}: {', '.join(map(str, ordered))}",
            explanation="Multiple distinct BitLocker lifecycle phases on one volume can indicate an administrative rollout or an attacker attempting encryption. Supporting evidence only; it does not prove coercion or data destruction.",
            confidence="medium",
            confidence_factors=[
                f"{len(phase_ids)} distinct BitLocker lifecycle event types observed",
                "BitLocker API telemetry present",
            ],
            investigate_next="Confirm the encryption was planned and policy-driven, identify the initiating account, and correlate with recovery-key escrow, file activity, and process telemetry.",
            event=sample,
            evidence={
                "volume": _field(sample, "VolumeMountPoint", "Volume") or volume,
                "lifecycle_phases": sorted(ordered),
                "phase_count": len(phase_ids),
                "supporting_evidence_only": True,
                "evidence_strength": "medium",
            },
        ))
    return alerts


def detect(events: List[NormalizedEvent]) -> List[Alert]:
    """Return explainable, low-noise alerts for execution-impact telemetry."""
    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    alerts.extend(_detect_repeated_service_execution(events))
    alerts.extend(_detect_cross_host_rdp_valid_accounts(events))
    alerts.extend(_detect_domain_trust_creation(events))
    alerts.extend(_detect_bitlocker_lifecycle(events))
    for ev in events:
        _detect_sqlservr_spawn(ev, alerts, seen)
        _detect_interpreter_cotag(ev, alerts, seen)
        _detect_pktmon(ev, alerts, seen)
        _detect_share_security_descriptor(ev, alerts, seen)
        _detect_capi_private_key_access(ev, alerts, seen)
        _detect_wininet_proxy(ev, alerts, seen)
        _detect_bitlocker(ev, alerts, seen)
        _detect_inhibit_system_recovery(ev, alerts, seen)
        _detect_special_group_domain_logon(ev, alerts, seen)
    return alerts


def _event_value(ev: NormalizedEvent, *names: str) -> str:
    return _field(ev, *names)


def _trust_identity(ev: NormalizedEvent) -> Set[str]:
    values = {
        _event_value(ev, "SubjectLogonId", "TargetLogonId", "LogonId").lower(),
        _event_value(ev, "SubjectUserName", "TargetUserName", "UserName").lower(),
        (ev.domain_user or ev.user or "").lower(),
    }
    return {value for value in values if value and value not in {"-", "unknown", "unknown user"}}


def _detect_domain_trust_creation(events: List[NormalizedEvent]) -> List[Alert]:
    """Detect AD trust creation and strengthen it with paired 4865 telemetry."""

    trust_events = [event for event in events if event.event_id == 4706 and event.timestamp]
    confirmations = [event for event in events if event.event_id == 4865 and event.timestamp]
    alerts: List[Alert] = []
    for event in trust_events:
        identity = _trust_identity(event)
        paired = [
            candidate for candidate in confirmations
            if candidate.computer.lower() == event.computer.lower()
            and abs(candidate.timestamp - event.timestamp) <= _TRUST_CORRELATION_WINDOW
            and identity.intersection(_trust_identity(candidate))
        ]
        paired.sort(key=lambda candidate: abs(candidate.timestamp - event.timestamp))
        confirmation = paired[0] if paired else None
        trust_name = _event_value(event, "TrustPartner", "DomainName", "TargetDomainName", "DomainTrustName") or "unknown domain"
        subject = event.domain_user or _event_value(event, "SubjectUserName") or "unknown user"
        confidence = "high" if confirmation else "medium"
        evidence = {
            "trust_partner": trust_name,
            "creation_event_id": 4706,
            "confirmation_event_id": 4865 if confirmation else None,
            "correlation_window_minutes": int(_TRUST_CORRELATION_WINDOW.total_seconds() / 60),
            "evidence_strength": confidence,
            "known_ambiguity": "A planned forest or domain integration can generate these events; validate the change owner and approved topology.",
        }
        if confirmation:
            evidence["paired_event_timestamp"] = confirmation.timestamp.isoformat()
            evidence["paired_event_identity"] = sorted(identity.intersection(_trust_identity(confirmation)))
        alerts.append(Alert(
            rule_name="Active Directory Domain Trust Created",
            severity="critical" if confirmation else "high",
            mitre_tactic="Privilege Escalation",
            mitre_technique="T1484",
            description=f"A domain trust with {trust_name} was created on {event.computer}",
            explanation=(
                "Security 4706 recorded trust creation and matching 4865 trust-object telemetry was observed for the same host and identity within ten minutes. "
                "Together these events strongly support an unauthorized AD trust change."
                if confirmation else
                "Security 4706 recorded domain trust creation. This can be legitimate infrastructure work, so it is medium-confidence evidence until the change is correlated with the operator and approved topology."
            ),
            confidence=confidence,
            confidence_factors=["Security event 4706 recorded a new trust"] + (["matching 4865 trust telemetry on the same host and identity within ten minutes"] if confirmation else []),
            investigate_next="Verify the trust partner, direction, and change ticket; identify the operator from 4624/4672 and review adjacent directory-service changes. If unauthorized, disable the trust and investigate cross-domain authentication.",
            event=event,
            evidence=evidence,
        ))
    return alerts


def _detect_inhibit_system_recovery(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    """Detect exact recovery-destruction commands without flagging generic backups."""

    if ev.event_id not in (1, 4688, 4103, 4104):
        return
    command = " ".join((ev.command_line, _field(ev, "ScriptBlockText", "Message", "Payload"))).strip()
    normalized = re.sub(r"\s+", " ", command.lower())
    if not normalized:
        return
    matched_name = ""
    for name, pattern in _RECOVERY_PATTERNS:
        if pattern.search(normalized):
            matched_name = name
            break
    if not matched_name:
        return
    key = ("inhibit-recovery", ev.computer, matched_name, normalized[:300], _same_time_bucket(ev.timestamp))
    _append_once(alerts, seen, key, Alert(
        rule_name="Inhibit System Recovery Command",
        severity="critical",
        mitre_tactic="Impact",
        mitre_technique="T1490",
        description=f"A recovery-destruction command was observed on {ev.computer}",
        explanation="The command explicitly deletes shadow copies or backup catalogs, or disables Windows recovery behavior. This is a high-confidence impact signal, although an authorized recovery or storage operation must still be ruled out.",
        confidence="high",
        confidence_factors=["exact recovery-destruction command pattern matched", f"matched pattern: {matched_name}", f"Windows event {ev.event_id}"],
        investigate_next="Preserve the complete command and parent process chain, identify the initiating account, verify whether a recovery-change ticket exists, and inspect for ransomware, mass file changes, or follow-on persistence.",
        event=ev,
        evidence={
            "matched_pattern": matched_name,
            "command_line": command[:1000],
            "event_id": ev.event_id,
            "evidence_strength": "high",
            "known_ambiguity": "Backup administrators may intentionally remove snapshots or catalogs; validate authorization and scope before declaring malicious impact.",
        },
    ))


def _detect_special_group_domain_logon(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    """Surface audited special-group domain logons without declaring account abuse."""

    if ev.event_id != 4964:
        return
    provider_context = f"{ev.provider} {ev.channel}".lower()
    if "security" not in provider_context:
        return
    user = _field(ev, "TargetUserName") or ev.target_user
    domain = _field(ev, "TargetDomainName") or ev.target_domain
    sid_list = _field(ev, "SidList")
    target_logon_id = _field(ev, "TargetLogonId")
    if not user or user.endswith("$") or not sid_list:
        return
    identity = f"{domain}\\{user}" if domain else user
    key = ("special-group-logon", ev.computer, identity.lower(), target_logon_id or _same_time_bucket(ev.timestamp))
    _append_once(alerts, seen, key, Alert(
        rule_name="Special Group Domain Account Logon",
        severity="high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1078.002",
        description=f"Special-group auditing recorded a logon for {identity} on {ev.computer}",
        explanation="Security 4964 shows that a monitored special-group member received a logon session. It identifies a high-value domain account session but does not, by itself, prove account compromise.",
        confidence="medium",
        confidence_factors=["Security event 4964", "monitored special-group SID present", "domain account logon session"],
        investigate_next="Resolve the monitored group SID, correlate the TargetLogonId with 4624/4672 and process activity, verify the source host and operator, and escalate only if the session is unauthorized or followed by suspicious actions.",
        event=ev,
        user=identity,
        promotion_policy="signal_only",
        evidence={
            "target_user": identity,
            "target_logon_id": target_logon_id,
            "special_group_sids": sid_list.strip(),
            "supporting_evidence_only": True,
            "evidence_strength": "medium",
            "known_ambiguity": "Approved administrators and service workflows can legitimately generate special-group logons.",
        },
    ))


def _detect_cross_host_rdp_valid_accounts(events: List[NormalizedEvent]) -> List[Alert]:
    """Detect one account/source authenticating to several RDP hosts quickly."""

    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
    for ev in events:
        if ev.event_id != 1149 or not ev.timestamp:
            continue
        provider_context = f"{ev.provider} {ev.channel}".lower()
        if "terminalservices-remoteconnectionmanager" not in provider_context:
            continue
        actor = (_field(ev, "Param1") or ev.domain_user or ev.target_domain_user).strip()
        source_ip = (_field(ev, "Param3") or ev.source_ip).strip()
        if not actor or not source_ip or source_ip in {"-", "127.0.0.1", "::1"}:
            continue
        grouped[(actor.lower(), source_ip)].append(ev)

    alerts: List[Alert] = []
    for (_, source_ip), candidates in grouped.items():
        ordered = sorted(candidates, key=lambda item: item.timestamp)
        for start in ordered:
            window_end = start.timestamp + timedelta(hours=2)
            window = [item for item in ordered if start.timestamp <= item.timestamp <= window_end]
            hosts = sorted({item.computer for item in window if item.computer})
            if len(hosts) < 3:
                continue
            actor = (_field(start, "Param1") or start.domain_user or start.target_domain_user).strip()
            alerts.append(
                Alert(
                    rule_name="Cross-Host RDP Valid Account Activity",
                    severity="critical",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1078",
                    description=f"{actor} authenticated over RDP from {source_ip} to {len(hosts)} hosts",
                    explanation="The same account and source authenticated successfully to several RDP hosts in a short period. This is strong evidence of valid-account reuse or lateral traversal, although an approved administration session remains possible.",
                    confidence="high",
                    confidence_factors=["successful RDP authentication telemetry", "same account and source", "three or more destination hosts within two hours"],
                    investigate_next="Validate the source host and operator, correlate with 4624 LogonType 10 and process creation on every destination, and disable or reset the account if the activity is unauthorized.",
                    event=start,
                    user=actor,
                    source_ip=source_ip,
                    evidence={
                        "destination_hosts": hosts,
                        "destination_host_count": len(hosts),
                        "authentication_count": len(window),
                        "evidence_strength": "high",
                    },
                )
            )
            break
    return alerts


def _detect_repeated_service_execution(events: List[NormalizedEvent]) -> List[Alert]:
    """Detect bursty service creation followed by startup failures.

    A single service install or timeout is common administration noise. Two or
    more installs plus two or more 7000/7009 failures in five minutes is a much
    stronger service-execution pattern and matches tools that repeatedly stage
    payload fragments through short-lived services.
    """

    grouped: Dict[str, List[NormalizedEvent]] = defaultdict(list)
    for ev in events:
        if ev.timestamp and ev.event_id in {7000, 7009, 7045}:
            grouped[ev.computer or "unknown"].append(ev)

    alerts: List[Alert] = []
    for host, host_events in grouped.items():
        ordered = sorted(host_events, key=lambda item: item.timestamp)
        consumed_until: Optional[datetime] = None
        for start in ordered:
            if start.event_id != 7045 or (consumed_until and start.timestamp <= consumed_until):
                continue
            window_end = start.timestamp + timedelta(minutes=5)
            window = [item for item in ordered if start.timestamp <= item.timestamp <= window_end]
            installs = [item for item in window if item.event_id == 7045]
            failures = [item for item in window if item.event_id in {7000, 7009}]
            if len(installs) < 2 or len(failures) < 2:
                continue
            consumed_until = max(item.timestamp for item in window)
            services = [
                item.service_name or _field(item, "ServiceName", "param1")
                for item in installs
            ]
            alerts.append(
                Alert(
                    rule_name="Repeated Service Execution Failures",
                    severity="critical",
                    mitre_tactic="Execution",
                    mitre_technique="T1569.002",
                    description=f"{len(installs)} services were created with repeated startup failures on {host}",
                    explanation="Bursty service creation followed by service start failures is consistent with remote service-execution tooling repeatedly staging or launching payloads.",
                    confidence="high",
                    confidence_factors=["multiple service-install events", "multiple service startup failures", "events occurred within five minutes"],
                    investigate_next="Review the service names and image paths, identify the creating account and source host, and recover any staged binaries or command content.",
                    event=start,
                    service=services[0] if services else "",
                    evidence={
                        "service_names": services[:20],
                        "install_count": len(installs),
                        "failure_count": len(failures),
                        "event_ids": sorted({item.event_id for item in window}),
                        "evidence_strength": "high",
                    },
                )
            )
    return alerts


def _detect_sqlservr_spawn(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    if ev.event_id not in (1, 4688) or _basename(ev.parent_process_value or ev.parent_process) != "sqlservr.exe":
        return
    child = _basename(ev.process_name_value or ev.process_name)
    if child not in _SCRIPT_CHILDREN and not any(marker in (ev.process_name_value or ev.process_name).lower() for marker in _TEMP_MARKERS):
        return
    technique = _SCRIPT_CHILDREN.get(child, "T1059.003")
    key = ("sqlservr", ev.computer, child, _same_time_bucket(ev.timestamp), (ev.command_line or "")[:160].lower())
    _append_once(alerts, seen, key, Alert(
        rule_name="SQL Server Spawned Interpreter or Temp Executable",
        severity="critical",
        mitre_tactic="Execution",
        mitre_technique=technique,
        description=f"sqlservr.exe spawned {child or 'a temporary executable'} on {ev.computer}",
        explanation="SQL Server spawning a shell, script interpreter, or executable from a temporary path is unusual server-side execution and can indicate abuse of SQL Server execution features.",
        confidence="high",
        confidence_factors=["SQL Server is the recorded parent process", "child is a shell/script interpreter or temporary-path executable"],
        investigate_next="Review SQL Server audit records, the complete child command line, service account activity, and any network connections or files created by the child.",
        event=ev,
        evidence={"parent_process": ev.parent_process, "child_process": ev.process_name, "command_line": ev.command_line[:500], "server_abuse": True, "evidence_strength": "high"},
    ))


def _detect_interpreter_cotag(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    """Co-tag command/script interpreter execution that drives an administrative or proxy action.

    Detectors run independently, so this function cannot observe alerts from other
    detector modules. Instead it recognizes the same well-understood abusive
    interpreter contexts they flag: an interpreter used to schedule tasks, configure
    services, run WMI process creation, encode or download payloads, or execute via a
    signed proxy binary.  The scheduled-task and service chains that persistence rules
    tag with T1053.005 / T1543.003 are almost always driven by cmd.exe or
    powershell.exe, so this rule adds the interpreter execution technique (T1059.003 /
    T1059.001 / T1059.007) to the same event.

    Parent suspects are intentionally narrow: ms office / WMI / proxy binaries that
    launch an interpreter.  Plain explorer.exe or svchost.exe parenting an
    interactive console session is normal and must not fire.
    """
    if ev.event_id not in (1, 4688):
        return
    child = _basename(ev.process_name_value or ev.process_name)
    technique = _SCRIPT_CHILDREN.get(child)
    if not technique:
        return
    parent = _basename(ev.parent_process_value or ev.parent_process)
    if parent == "sqlservr.exe":
        return
    command = " ".join((ev.command_line or "", _field(ev, "ScriptBlockText", "Message", "Payload"))).lower()
    matched = ""
    for name, pattern in _INTERPRETER_COTAG_RULES:
        if pattern.search(command):
            matched = name
            break
    parent_suspicious = parent in _SUSPICIOUS_INTERPRETER_PARENTS
    if not matched and not parent_suspicious:
        return
    key = ("interpreter-cotag", ev.computer, child, technique, _same_time_bucket(ev.timestamp), command[:200])
    _append_once(alerts, seen, key, Alert(
        rule_name="Interpreter Executed Administrative or Proxy Command",
        severity="high",
        mitre_tactic="Execution",
        mitre_technique=technique,
        description=f"{child} executed an administrative or proxy command on {ev.computer}",
        explanation="A command or scripting interpreter was used to drive scheduled-task creation, service configuration, payload staging, or signed-binary proxy execution. These are the same contexts that persistence and defense-evasion rules flag, and this rule adds the interpreter execution technique so the wrapped chain is fully tagged.",
        confidence="high",
        confidence_factors=["interpreter process telemetry present", "parent or command matches a known abusive execution context"],
        investigate_next="Recover the full command line and parent chain, identify the launching account, and inspect any script, download, or scheduled-task payload referenced by the command.",
        event=ev,
        evidence={
            "process": ev.process_name,
            "parent_process": ev.parent_process,
            "command_line": (ev.command_line or "")[:500],
            "matched_context": matched or "suspicious_parent",
            "evidence_strength": "high",
        },
    ))


def _detect_capi_private_key_access(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    provider = (ev.provider or "").lower()
    if ev.event_id != 70 or "capi2" not in provider:
        return
    process = ev.process_name or _field(ev, "ProcessName", "EventAuxInfo_ProcessName")
    process_base = _basename(process)
    if process_base not in {"mimikatz.exe", "nanodump.exe", "rubeus.exe"}:
        return
    subject = _field(ev, "subjectName", "Certificate_subjectName")
    key = ("capi-private-key", ev.computer, process_base, subject, _same_time_bucket(ev.timestamp))
    _append_once(alerts, seen, key, Alert(
        rule_name="Suspicious CAPI Private Key Access",
        severity="critical",
        mitre_tactic="Credential Access",
        mitre_technique="T1552.004",
        description=f"{process_base} accessed a certificate private key on {ev.computer}",
        explanation="CAPI2 Event 70 records private-key acquisition. Access by a credential-theft tool is strong evidence of attempted certificate or private-key theft.",
        confidence="high",
        confidence_factors=["CAPI2 private-key acquisition event", "known credential-access process name"],
        investigate_next="Identify the certificate and account, preserve the process and memory evidence, revoke or rotate the affected certificate, and review subsequent authentication activity.",
        event=ev,
        process=process,
        evidence={
            "process": process,
            "certificate_subject": subject,
            "certificate_file_reference": _field(ev, "fileRef", "Certificate_fileRef"),
            "evidence_strength": "high",
        },
    ))


def _detect_pktmon(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    process = _basename(ev.process_name_value or ev.process_name)
    command = (ev.command_line or "").lower()
    if ev.event_id not in (1, 4688) or process != "pktmon.exe" or not any(action in f" {command}" for action in _PKTMON_ACTIONS):
        return
    key = ("pktmon", ev.computer, command[:240], _same_time_bucket(ev.timestamp))
    _append_once(alerts, seen, key, Alert(
        rule_name="Pktmon Traffic Capture or Configuration",
        severity="high",
        mitre_tactic="Credential Access",
        mitre_technique="T1040",
        description=f"pktmon.exe performed a packet capture/configuration action on {ev.computer}",
        explanation="Pktmon can capture host network traffic. Capture activity may be legitimate troubleshooting, but can also expose credentials or sensitive protocols and should be tied to an approved change.",
        confidence="medium",
        confidence_factors=["pktmon.exe was observed", "capture or filter action was present in the command line"],
        investigate_next="Confirm the operator and change ticket, inspect capture output and filters, and correlate with nearby logons and outbound connections.",
        event=ev,
        evidence={"process": ev.process_name, "command_line": ev.command_line[:500], "capture_action": command, "evidence_strength": "medium"},
    ))


def _detect_share_security_descriptor(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    if ev.event_id != 5143:
        return
    old_sd = _field(ev, "OldSD", "OldSecurityDescriptor")
    new_sd = _field(ev, "NewSD", "NewSecurityDescriptor")
    if not old_sd or not new_sd or old_sd == new_sd:
        return
    combined = new_sd.lower()
    broad = any(marker in combined for marker in _BROAD_PRINCIPALS) and any(token in combined for token in ("full", "0x1f01ff", "0x1f01ff", "fa", "2032127"))
    key = ("share-sd", ev.computer, ev.share_name or _field(ev, "ShareName"), new_sd, _same_time_bucket(ev.timestamp))
    _append_once(alerts, seen, key, Alert(
        rule_name="Network Share Security Descriptor Changed",
        severity="critical" if broad else "high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1222.001",
        description=f"Security descriptor changed for share {ev.share_name or _field(ev, 'ShareName') or 'unknown'} on {ev.computer}",
        explanation="A network share security descriptor changed. Broad Everyone/WD full access is especially risky because it can expose or enable tampering with shared data.",
        confidence="high" if broad else "medium",
        confidence_factors=["5143 recorded different old and new descriptors"] + (["new descriptor contains a broad principal with full access"] if broad else []),
        investigate_next="Compare the old and new ACLs, identify the modifying account, verify the share owner approved the change, and review subsequent access to the share.",
        event=ev,
        share_name=ev.share_name or _field(ev, "ShareName"),
        evidence={"old_security_descriptor": old_sd, "new_security_descriptor": new_sd, "broad_full_access": broad, "evidence_strength": "high" if broad else "medium"},
    ))


def _detect_wininet_proxy(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    if ev.event_id != 5600 or "wininet-config" not in provider and "wininet-config" not in channel:
        return
    proxy = _field(
        ev,
        "Proxy",
        "ProxyServer",
        "ProxyName",
        "AutoConfigURL",
        "PACUrl",
        "PacUrl",
        "pwszProxy",
        "pwszAutoConfigUrl",
    )
    if not proxy:
        return
    key = ("wininet", ev.computer, proxy.lower(), _same_time_bucket(ev.timestamp))
    _append_once(alerts, seen, key, Alert(
        rule_name="WinINet Proxy or PAC Configuration",
        # Keep the telemetry visible even when the event does not identify a
        # user; the generic FP filter suppresses lower-severity unknown-user
        # events. Confidence remains medium because proxy changes can be valid.
        severity="high",
        mitre_tactic="Command and Control",
        mitre_technique="T1090",
        description=f"WinINet proxy/PAC configuration changed on {ev.computer}",
        explanation="A non-empty WinINet proxy or PAC setting was recorded. Proxies can be legitimate, but unexpected configuration can redirect traffic or obscure command-and-control paths.",
        confidence="medium",
        confidence_factors=["WinINet-Config event 5600 was observed", "proxy/PAC configuration was non-empty"],
        investigate_next="Validate the proxy/PAC URL against approved configuration, identify the modifying user or process, and review traffic routed through it.",
        event=ev,
        evidence={"proxy_configuration": proxy, "evidence_strength": "medium"},
    ))


# BitLocker API events that mark distinct phases of the volume-encryption
# lifecycle. 768 = encryption started, 775 = key protector added, 780 = encryption
# paused, 793 = driver mount, 796 = read/write state transition, 817 = TPM info
# published, 840 = encryption finished. 4122 is routine volume-state churn and is
# intentionally not a lifecycle phase marker on its own.
_BITLOCKER_LIFECYCLE_EVENT_IDS = frozenset({768, 775, 780, 793, 796, 817, 840})
_BITLOCKER_START_EVENT_IDS = frozenset({768})


def _is_bitlocker_event(ev: NormalizedEvent) -> bool:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    return "bitlocker" in provider or "bitlocker" in channel


def _detect_bitlocker(ev: NormalizedEvent, alerts: List[Alert], seen: Set[Tuple[str, ...]]) -> None:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    if not _is_bitlocker_event(ev) or ev.event_id not in _BITLOCKER_START_EVENT_IDS:
        return
    volume = _field(ev, "Volume", "Drive", "MountPoint", "VolumeMountPoint", "Device") or "unknown volume"
    key = ("bitlocker", ev.computer, volume.lower(), _same_time_bucket(ev.timestamp))
    _append_once(alerts, seen, key, Alert(
        rule_name="BitLocker Volume Encryption Started",
        severity="high",
        mitre_tactic="Impact",
        mitre_technique="T1486",
        description=f"BitLocker reported encryption starting for {volume} on {ev.computer}",
        explanation="BitLocker encryption activity can be routine administration. It is supporting evidence only and is not, by itself, a ransomware verdict.",
        confidence="medium",
        confidence_factors=["BitLocker API event 768 was observed", "volume encryption start was reported"],
        investigate_next="Confirm the encryption was authorized, identify the initiating account and policy, and correlate with file-access, recovery-key, and process telemetry.",
        event=ev,
        evidence={"volume": volume, "supporting_evidence_only": True, "evidence_strength": "medium"},
    ))
