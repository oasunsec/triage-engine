"""Conservative detections for Windows telemetry that is easy to miss.

This module intentionally handles *context-rich but sometimes incomplete* EVTX
patterns.  Several public samples contain only a registry event, a lifecycle
event, or a partial process tree.  We keep those observations visible as
``signal_only`` unless the event chain is strong enough to support a finding.

The rules here do not treat a filename/path hint as proof.  They require
provider-aware event IDs and preserve the original event fields in evidence so
an analyst can verify the observation in the exported case.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from datetime import timedelta
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from models.event_model import Alert, NormalizedEvent


LOCAL_IPS = {"", "-", "0.0.0.0", "127.0.0.1", "127.0.0.2", "::1", "0:0:0:0:0:0:0:1", "fe80::1"}
USER_PATH_MARKERS = (
    "\\users\\",
    "\\programdata\\",
    "\\public\\",
    "\\temp\\",
    "\\downloads\\",
    "\\appdata\\",
)
SYSTEM_PATH_MARKERS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\")
SHELL_NAMES = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
SENSITIVE_PROCESS_NAMES = {
    "lsass.exe",
    "winlogon.exe",
    "services.exe",
    "spoolsv.exe",
    "svchost.exe",
    "csrss.exe",
    "wininit.exe",
    "explorer.exe",
}
OFFENSIVE_SOURCE_NAMES = {
    "mimikatz.exe",
    "ppldump.exe",
    "nanodump.exe",
    "procdump.exe",
    "rundll32.exe",
    "psexec.exe",
    "wmiexec.exe",
    "wmic.exe",
}
PIPE_DISCOVERY_NAMES = {
    "lsass",
    "samr",
    "srvsvc",
    "wkssvc",
    "browser",
    "atsvc",
    "epmapper",
    "eventlog",
    "ntsvcs",
    "scerpc",
    "tapsrv",
    "trkwks",
}
DRIVER_EXTENSIONS = (".sys", ".dll")
EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta")
FILE_DELETE_EVENT_IDS = {23, 26}  # Sysmon FileDelete / FileDeleteDetected
AD_GROUP_CLASS_GUID = "bf967a9c-0de6-11d0-a285-00aa003049e2"
FILE_DELETE_COMMAND_RE = re.compile(
    r"\b(?:del|erase|remove-item|rmdir|rd)\b(?P<args>[^\r\n]*)",
    re.IGNORECASE,
)


def _basename(value: str) -> str:
    return os.path.basename((value or "").replace("/", "\\").rstrip("\\")).lower()


def _value(event: NormalizedEvent, *names: str) -> str:
    data = event.event_data or {}
    lowered = {str(key).lower(): str(value or "") for key, value in data.items()}
    for name in names:
        result = lowered.get(name.lower(), "").strip()
        if result:
            return result
    return ""


def _provider_text(event: NormalizedEvent) -> str:
    return f"{event.provider or ''} {event.channel or ''}".lower()


def _is_sysmon(event: NormalizedEvent) -> bool:
    text = _provider_text(event)
    return "sysmon" in text


def _is_security(event: NormalizedEvent) -> bool:
    text = _provider_text(event)
    return "security-auditing" in text or text.strip() == "security"


def _actor(event: NormalizedEvent) -> str:
    return (
        event.domain_user
        or event.subject_domain_user
        or _value(event, "User", "DetectionUser", "SubjectUserName", "TargetUserName")
        or "unknown"
    )


def _user_path(value: str) -> bool:
    lowered = (value or "").lower().replace("/", "\\")
    return any(marker in lowered for marker in USER_PATH_MARKERS)


def _system_path(value: str) -> bool:
    lowered = (value or "").lower().replace("/", "\\")
    return any(marker in lowered for marker in SYSTEM_PATH_MARKERS)


def _is_external_peer(value: str) -> bool:
    return (value or "").strip().lower() not in LOCAL_IPS


def _timestamped(events: Iterable[NormalizedEvent]) -> List[NormalizedEvent]:
    return sorted((event for event in events if event.timestamp), key=lambda event: event.timestamp)


def _within(left: Optional[NormalizedEvent], right: Optional[NormalizedEvent], seconds: int) -> bool:
    return bool(left and right and left.timestamp and right.timestamp and abs((left.timestamp - right.timestamp).total_seconds()) <= seconds)


def _dedupe_key(event: NormalizedEvent, *parts: str) -> Tuple[str, ...]:
    return (
        (event.computer or "unknown").lower(),
        str(event.timestamp or ""),
        *[(part or "").strip().lower() for part in parts],
    )


def _audit_log_cleared(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Catch EventLog provider event 104 in addition to Security 1102.

    Event 104 is emitted when a non-Security channel (often System) is
    cleared.  It is just as important for timeline integrity as 1102, but the
    old detector only handled the Security event.
    """

    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for event in _timestamped(events):
        if event.event_id != 104:
            continue
        provider = (event.provider or "").lower()
        if "eventlog" not in provider and "event log" not in provider and "system" not in (event.channel or "").lower():
            continue
        channel = _value(event, "Channel") or event.channel or "unknown channel"
        actor = _actor(event)
        key = _dedupe_key(event, channel)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="Windows Event Log Cleared",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1070.001",
                description=f"The {channel} event log was cleared on {event.computer or 'the host'}",
                explanation=(
                    "Windows EventLog recorded a log-clear operation (event 104). Clearing a channel removes historical evidence and can be an anti-forensics step; verify whether maintenance or an authorized reset explains it."
                ),
                confidence="high",
                confidence_factors=["EventLog provider emitted event 104", f"cleared channel: {channel}"],
                investigate_next=(
                    "Preserve remaining Security, Sysmon, and PowerShell logs, identify the operator, and inspect events immediately before the clear for process or service activity."
                ),
                event=event,
                user=actor,
                evidence={
                    "event_id": 104,
                    "channel": channel,
                    "actor_user": actor,
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _hidden_file_attribute(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Detect ``attrib +h``/``+s`` applied to executable payloads."""

    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for event in _timestamped(events):
        if event.event_id not in (1, 4688, 4104):
            continue
        command = " ".join(
            value
            for value in (event.command_line, _value(event, "ScriptBlockText", "Message", "Payload"))
            if value
        ).strip()
        match = re.search(r"\battrib(?:\.exe)?\b[^\r\n]*?\+(?:h|s|hs|sh)\b\s+([\"']?[^\s\"']+[\"']?)", command, re.IGNORECASE)
        if not match:
            continue
        target = match.group(1).strip("\"'")
        rule_name = _value(event, "RuleName")
        target_lower = target.lower().replace("/", "\\")
        if not (
            target_lower.endswith(EXECUTABLE_EXTENSIONS)
            or _user_path(target)
            or "hidden" in rule_name.lower()
            or "t1158" in rule_name.lower()
        ):
            continue
        key = _dedupe_key(event, target, command[:240])
        if key in seen:
            continue
        seen.add(key)
        actor = _actor(event)
        alerts.append(
            Alert(
                rule_name="Hidden Executable Attribute Set",
                severity="high",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1564.001",
                description=f"Hidden/system attributes were applied to {target} on {event.computer or 'the host'}",
                explanation=(
                    "attrib.exe changed hidden or system attributes on an executable or user-controlled path. Attackers commonly hide payloads this way, although deployment and packaging tools can also do it."
                ),
                confidence="high",
                confidence_factors=["attrib hidden/system flag matched", "target is executable or user-controlled", f"Windows event {event.event_id}"],
                investigate_next=(
                    "Recover the target file and hash it, inspect who launched attrib.exe, and check for execution, persistence, or archive staging of the hidden payload."
                ),
                event=event,
                user=actor,
                process=event.process_name,
                parent_process=event.parent_process,
                evidence={
                    "command_line": command[:500],
                    "target": target,
                    "attribute_operation": "+h/+s",
                    "rule_name": rule_name,
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _uac_policy_disabled(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Detect EnableLUA=0 in registry telemetry or an equivalent reg command."""

    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    marker = r"\software\microsoft\windows\currentversion\policies\system"
    for event in _timestamped(events):
        if event.event_id not in (1, 4688, 12, 13, 4657):
            continue
        if event.event_id in (12, 13, 4657) and not _is_sysmon(event) and not _is_security(event):
            continue
        target = _value(event, "TargetObject", "ObjectName")
        details = _value(event, "Details", "NewValue", "Value")
        command = event.command_line or _value(event, "ScriptBlockText", "Message")
        combined = f"{target} {details} {command}".lower()
        if marker not in combined or "enablelua" not in combined:
            continue
        disabled = bool(re.search(r"(?:details|newvalue|value)\s*[:=]?\s*(?:dword\s*\()?0x?0+\)?", combined))
        # Sysmon commonly renders the value as ``DWORD (0x00000000)`` without
        # retaining the field name in the combined text.
        disabled = disabled or bool(re.search(r"\b(?:0x)?0+\b", details.lower()))
        disabled = disabled or bool(re.search(r"/v\s+enablelua\b.*(?:/d\s+)?(?:0x0+|\b0\b)", combined))
        if not disabled:
            continue
        key = _dedupe_key(event, target or "enablelua", details or command[:200])
        if key in seen:
            continue
        seen.add(key)
        actor = _actor(event)
        alerts.append(
            Alert(
                rule_name="UAC Protections Disabled",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1548.002",
                description=f"UAC EnableLUA was disabled on {event.computer or 'the host'}",
                explanation=(
                    "The EnableLUA policy was set to zero. Disabling UAC removes a key elevation boundary and is a high-risk configuration change, but confirm whether an image-build or administrative workflow made the change."
                ),
                confidence="high",
                confidence_factors=["EnableLUA value resolved to zero", f"Windows event {event.event_id}"],
                investigate_next=(
                    "Restore EnableLUA, identify the modifying account and process, and review subsequent elevated process creation for a bypass payload."
                ),
                event=event,
                user=actor,
                process=event.process_name,
                parent_process=event.parent_process,
                registry_key=target,
                evidence={
                    "registry_key": target,
                    "details": details,
                    "command_line": command[:500],
                    "enablelua_disabled": True,
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _kernel_debug_or_test_signing(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Surface Security 4826 when debug/test-signing is enabled."""

    alerts: List[Alert] = []
    # A BCD update can produce several 4826 records with the same settings.
    # Collapse them to one host/settings observation so a single change does
    # not become a burst of identical critical findings.
    representatives: Dict[Tuple[str, Tuple[str, ...]], NormalizedEvent] = {}
    enabled_tokens = {"%%1842", "enabled", "true", "1", "yes"}
    for event in _timestamped(events):
        if event.event_id != 4826 or not _is_security(event):
            continue
        debug = _value(event, "KernelDebug")
        signing = _value(event, "TestSigning")
        enabled_fields = [name for name, value in (("KernelDebug", debug), ("TestSigning", signing)) if value.lower() in enabled_tokens]
        if not enabled_fields:
            continue
        key = ((event.computer or "unknown").lower(), tuple(sorted(enabled_fields)))
        representatives.setdefault(key, event)

    for (_host_key, enabled_fields_tuple), event in representatives.items():
        debug = _value(event, "KernelDebug")
        signing = _value(event, "TestSigning")
        enabled_fields = list(enabled_fields_tuple)
        actor = _actor(event)
        alerts.append(
            Alert(
                rule_name="Kernel Debug or Test Signing Enabled",
                severity="high",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.001",
                description=f"Boot debug/signing controls were enabled on {event.computer or 'the host'}",
                explanation=(
                    "Security event 4826 reports kernel debugging or test-signing enabled. These settings weaken code-integrity protections and are commonly used to load unsigned or vulnerable drivers."
                ),
                confidence="high",
                confidence_factors=[f"enabled fields: {', '.join(enabled_fields)}", "Security event 4826"],
                investigate_next=(
                    "Verify the BCD change, restore code-integrity settings if unauthorized, and inspect driver loads and boot-time persistence around the change."
                ),
                event=event,
                user=actor,
                evidence={
                    "kernel_debug": debug,
                    "test_signing": signing,
                    "enabled_fields": enabled_fields,
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _process_access_injection(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Catch suspicious Sysmon 10 access when richer injection events are absent."""

    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for event in _timestamped(events):
        if event.event_id != 10 or not _is_sysmon(event):
            continue
        source = _value(event, "SourceImage") or event.process_name
        target = _value(event, "TargetImage")
        access = _value(event, "GrantedAccess")
        if not source or not target:
            continue
        source_base = _basename(source)
        target_base = _basename(target)
        rule_name = _value(event, "RuleName")
        suspicious_source = _user_path(source) or source_base in OFFENSIVE_SOURCE_NAMES
        suspicious_rule = any(token in rule_name.lower() for token in ("suspicious", "evasion", "inject", "process access"))
        sensitive_target = target_base in SENSITIVE_PROCESS_NAMES
        high_access = access.lower().replace("0x", "") in {"1fffff", "1f1fff", "1f0fff", "1fffff"}
        if not (suspicious_source and (suspicious_rule or sensitive_target or high_access)):
            continue
        key = _dedupe_key(event, source, target, access)
        if key in seen:
            continue
        seen.add(key)
        confidence = "high" if sensitive_target or suspicious_rule else "medium"
        alerts.append(
            Alert(
                rule_name="Suspicious Process Access",
                severity="high" if confidence == "high" else "medium",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1055",
                description=f"{source_base} opened {target_base} with suspicious process-access rights on {event.computer or 'the host'}",
                explanation=(
                    "Sysmon process-access telemetry shows a user-controlled or offensive-named source opening another process. This is a supporting injection signal; validate the call trace and target behavior before treating it as code injection."
                ),
                confidence=confidence,
                promotion_policy="signal_only",
                confidence_factors=["Sysmon event 10", "source process is user-controlled or offensive-named"] + (["sensitive target process"] if sensitive_target else []),
                investigate_next=(
                    "Inspect the Sysmon call trace, source and target hashes, and any paired remote-thread or image-load events. Memory analysis may be required to confirm injection."
                ),
                event=event,
                user=_actor(event),
                process=source,
                evidence={
                    "source_image": source,
                    "target_image": target,
                    "granted_access": access,
                    "call_trace": _value(event, "CallTrace")[:800],
                    "rule_name": rule_name,
                    "supporting_evidence_only": True,
                    "evidence_strength": "medium" if confidence == "medium" else "high",
                },
            )
        )
    return alerts


def _process_herpaderping(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Correlate file creation, execution, and image-load of one payload."""

    timed = _timestamped(events)
    creations = [
        event
        for event in timed
        if event.event_id == 11 and _is_sysmon(event) and _value(event, "TargetFilename") and _user_path(_value(event, "TargetFilename"))
    ]
    executions = [event for event in timed if event.event_id in (1, 4688) and _is_sysmon(event) and _value(event, "Image")]
    loads = [event for event in timed if event.event_id == 7 and _is_sysmon(event) and _value(event, "ImageLoaded")]
    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for creation in creations:
        target = _value(creation, "TargetFilename")
        if not target.lower().endswith(EXECUTABLE_EXTENSIONS):
            continue
        creator_image = _value(creation, "Image") or creation.process_name
        creator_context = f"{creator_image} {_value(creation, 'RuleName')}".lower()
        # A generic create -> execute -> image-load sequence is common for
        # installers and UAC helpers.  Claim the herpaderping/doppelgänging
        # technique only when the source telemetry identifies that behavior;
        # otherwise leave the event to the broader process/path rules.
        if not any(marker in creator_context for marker in ("herpaderp", "doppelg", "image replacement")):
            continue
        matching_exec = next(
            (
                event
                for event in executions
                if (event.computer or "") == (creation.computer or "")
                and _within(creation, event, 120)
                and _value(event, "Image").lower().rstrip("\\") == target.lower().rstrip("\\")
                and _value(event, "Image").lower() != creator_image.lower()
            ),
            None,
        )
        if matching_exec is None:
            continue
        matching_load = next(
            (
                event
                for event in loads
                if (event.computer or "") == (creation.computer or "")
                and _within(matching_exec, event, 120)
                and _value(event, "ImageLoaded").lower().rstrip("\\") == target.lower().rstrip("\\")
            ),
            None,
        )
        if matching_load is None:
            continue
        key = _dedupe_key(matching_exec, target)
        if key in seen:
            continue
        seen.add(key)
        actor = _actor(matching_exec)
        alerts.append(
            Alert(
                rule_name="Process Image Replacement Pattern",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1055.013",
                description=f"A newly created executable was executed and loaded from a user path on {matching_exec.computer or 'the host'}",
                explanation=(
                    "The same user-controlled image was created, executed, and loaded shortly after a different process wrote it. This three-event chain is consistent with process herpaderping/doppelgänging-style image replacement and merits memory and file validation."
                ),
                confidence="high",
                confidence_factors=["Sysmon file-create event 11", "matching process-create event 1", "matching image-load event 7"],
                investigate_next=(
                    "Preserve the original file and hashes, inspect the creating process, and use memory forensics to compare the on-disk image with the image mapped into the process."
                ),
                event=matching_exec,
                user=actor,
                process=_value(matching_exec, "Image") or matching_exec.process_name,
                parent_process=_value(matching_exec, "ParentImage") or matching_exec.parent_process,
                evidence={
                    "target_image": target,
                    "creating_image": _value(creation, "Image") or creation.process_name,
                    "execution_image": _value(matching_exec, "Image") or matching_exec.process_name,
                    "loaded_image": _value(matching_load, "ImageLoaded"),
                    "event_ids": [11, matching_exec.event_id, 7],
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _byovd_driver_staging(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Detect a user-controlled process staging/loading a kernel driver."""

    timed = _timestamped(events)
    driver_loads = [
        event
        for event in timed
        if event.event_id == 6 and _is_sysmon(event) and _value(event, "ImageLoaded").lower().endswith(DRIVER_EXTENSIONS)
    ]
    process_events = [event for event in timed if event.event_id in (1, 4688) and _is_sysmon(event)]
    service_events = [
        event
        for event in timed
        if event.event_id in (12, 13, 7045) and ("service" in _value(event, "TargetObject", "ServiceName", "ImagePath").lower() or event.event_id == 7045)
    ]
    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for driver in driver_loads:
        image = _value(driver, "ImageLoaded")
        related_processes = [
            event
            for event in process_events
            if (event.computer or "") == (driver.computer or "")
            and _within(driver, event, 180)
            and _user_path(_value(event, "Image") or event.process_name)
        ]
        related_services = [event for event in service_events if (event.computer or "") == (driver.computer or "") and _within(driver, event, 180)]
        if not related_processes or not related_services:
            continue
        process = related_processes[0]
        key = _dedupe_key(driver, image, _value(process, "Image") or process.process_name)
        if key in seen:
            continue
        seen.add(key)
        actor = _actor(process)
        alerts.append(
            Alert(
                rule_name="User-Controlled Driver Load",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1068",
                description=f"A user-controlled process staged a kernel driver ({_basename(image)}) on {driver.computer or 'the host'}",
                explanation=(
                    "A driver was loaded while a user-controlled process and service configuration were active on the same host. This pattern is consistent with Bring Your Own Vulnerable Driver activity, though approved hardware/virtualization installs must be ruled out."
                ),
                confidence="high",
                confidence_factors=["Sysmon driver-load event 6", "user-controlled process in the same time window", "service configuration/install telemetry present"],
                investigate_next=(
                    "Identify the driver signer and vulnerability, preserve the driver and loader hashes, and inspect the service start configuration and follow-on privileged activity."
                ),
                event=driver,
                user=actor,
                process=_value(process, "Image") or process.process_name,
                service=_value(related_services[0], "ServiceName", "TargetObject"),
                evidence={
                    "driver_image": image,
                    "loader_image": _value(process, "Image") or process.process_name,
                    "service_evidence": [_value(event, "ServiceName", "TargetObject", "ImagePath") for event in related_services[:5]],
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _silent_process_exit_hijack(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Detect IFEO GlobalFlag + SilentProcessExit MonitorProcess pairs."""

    grouped: Dict[Tuple[str, str], Dict[str, object]] = defaultdict(lambda: {"global": [], "monitor": []})
    for event in _timestamped(events):
        if event.event_id not in (1, 12, 13, 4657) or not (_is_sysmon(event) or _is_security(event)):
            continue
        target = _value(event, "TargetObject", "ObjectName")
        lower = target.lower()
        match = re.search(r"\\(?:image file execution options|silentprocessexit)\\([^\\]+)", lower)
        if not match:
            continue
        image_name = match.group(1)
        key = ((event.computer or "unknown").lower(), image_name)
        details = _value(event, "Details", "NewValue", "Value")
        bucket = grouped[key]
        if "image file execution options" in lower and "globalflag" in lower and re.search(r"(?:0x)?200\b", details.lower()):
            bucket["global"].append(event)
        if "silentprocessexit" in lower and "monitorprocess" in lower and details:
            bucket["monitor"].append(event)

    alerts: List[Alert] = []
    for (host_key, image_name), bucket in grouped.items():
        global_events = bucket["global"]
        monitor_events = bucket["monitor"]
        if not global_events or not monitor_events:
            continue
        monitor = next((event for event in monitor_events if _user_path(_value(event, "Details", "NewValue", "Value")) or _basename(_value(event, "Details", "NewValue", "Value")) not in SHELL_NAMES), monitor_events[0])
        first = sorted(global_events + monitor_events, key=lambda event: event.timestamp)[0]
        monitor_path = _value(monitor, "Details", "NewValue", "Value")
        alerts.append(
            Alert(
                rule_name="SilentProcessExit Image Hijack",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1546.012",
                description=f"SilentProcessExit monitoring was configured for {image_name} on {first.computer or 'the host'}",
                explanation=(
                    "Image File Execution Options GlobalFlag 0x200 was paired with a SilentProcessExit MonitorProcess. This causes a monitor executable to run when the target process exits and is a known persistence/injection path."
                ),
                confidence="high",
                confidence_factors=["IFEO GlobalFlag 0x200", "SilentProcessExit MonitorProcess configured", "registry events share the target image"],
                investigate_next=(
                    "Remove the unauthorized IFEO/SilentProcessExit values, preserve the monitor binary, and inspect executions of the target and monitor processes."
                ),
                event=first,
                user=_actor(first),
                process=monitor_path,
                registry_key=_value(monitor, "TargetObject", "ObjectName"),
                evidence={
                    "target_process": image_name,
                    "monitor_process": monitor_path,
                    "globalflag_events": len(global_events),
                    "monitor_events": len(monitor_events),
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _winlogon_shell_persistence(events: Sequence[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for event in _timestamped(events):
        if event.event_id not in (12, 13, 4657) or not (_is_sysmon(event) or _is_security(event)):
            continue
        target = _value(event, "TargetObject", "ObjectName")
        if r"\winlogon\shell" not in target.lower():
            continue
        details = _value(event, "Details", "NewValue", "Value")
        # explorer.exe alone is the normal value; flag only an additional
        # executable/script or a user-controlled path.
        if not details or details.strip('" ').lower() in {"explorer.exe", "explorer"}:
            continue
        payloads = [item.strip('" ,') for item in re.split(r"[,;]", details) if item.strip() and item.strip('" ').lower() not in {"explorer.exe", "explorer"}]
        suspicious = any(_user_path(item) or item.lower().endswith(EXECUTABLE_EXTENSIONS) for item in payloads)
        if not suspicious:
            continue
        key = _dedupe_key(event, target, details)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="Winlogon Shell Persistence",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1547.004",
                description=f"Winlogon Shell was modified to launch {payloads[0] if payloads else 'an additional process'} on {event.computer or 'the host'}",
                explanation=(
                    "The Winlogon Shell value contains an executable in addition to the normal explorer.exe shell. A user-controlled or nonstandard shell payload runs at interactive logon and is a high-value persistence indicator."
                ),
                confidence="high",
                confidence_factors=["Winlogon\\Shell registry value changed", "value includes non-default executable"],
                investigate_next=(
                    "Preserve the payload and hash it, restore the expected shell value, and review the modifying process and the next logon session."
                ),
                event=event,
                user=_actor(event),
                process=event.process_name,
                registry_key=target,
                evidence={
                    "registry_key": target,
                    "shell_value": details,
                    "payloads": payloads,
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _pending_gpo_registry(events: Sequence[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for event in _timestamped(events):
        if event.event_id not in (12, 13, 4657) or not (_is_sysmon(event) or _is_security(event)):
            continue
        target = _value(event, "TargetObject", "ObjectName")
        if "\\pendinggpos\\" not in target.lower():
            continue
        details = _value(event, "Details", "NewValue", "Value")
        key = _dedupe_key(event, target, details)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="Pending Group Policy Registry Change",
                severity="medium",
                mitre_tactic="Persistence",
                mitre_technique="T1112",
                promotion_policy="signal_only",
                description=f"Pending Group Policy registry state changed on {event.computer or 'the host'}",
                explanation=(
                    "A PendingGPOs registry value was changed. This is useful persistence/configuration context, but a legitimate IEAK or policy deployment can produce the same event."
                ),
                confidence="medium",
                confidence_factors=["registry path contains PendingGPOs", "Sysmon/security registry telemetry"],
                investigate_next=(
                    "Validate the GPO or INF path, identify the modifying account, and compare the change to an approved policy deployment."
                ),
                event=event,
                user=_actor(event),
                process=event.process_name,
                registry_key=target,
                evidence={
                    "registry_key": target,
                    "value": details,
                    "supporting_evidence_only": True,
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _sam_force_password_reset(events: Sequence[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for event in _timestamped(events):
        if event.event_id not in (12, 13, 4657) or not (_is_sysmon(event) or _is_security(event)):
            continue
        target = _value(event, "TargetObject", "ObjectName")
        if "\\sam\\sam\\domains\\account\\users\\" not in target.lower() or "forcepasswordreset" not in target.lower():
            continue
        key = _dedupe_key(event, target, _value(event, "Details", "NewValue", "Value"))
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="Local SAM Password Reset Flag Changed",
                severity="medium",
                mitre_tactic="Credential Access",
                mitre_technique="T1098",
                promotion_policy="signal_only",
                description=f"A local SAM ForcePasswordReset value changed on {event.computer or 'the host'}",
                explanation=(
                    "A registry write touched a local SAM ForcePasswordReset value. This can be part of account administration or credential manipulation; it is surfaced as supporting evidence until paired with account and logon telemetry."
                ),
                confidence="medium",
                confidence_factors=["SAM ForcePasswordReset registry path", "registry write telemetry"],
                investigate_next=(
                    "Identify the affected RID/account, correlate nearby 4720/4738/4624 events, and verify whether the password reset was authorized."
                ),
                event=event,
                user=_actor(event),
                process=event.process_name,
                registry_key=target,
                evidence={
                    "registry_key": target,
                    "details": _value(event, "Details", "NewValue", "Value"),
                    "supporting_evidence_only": True,
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _named_pipe_discovery(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Cluster Sysmon pipe enumeration so one normal pipe is not promoted."""

    grouped: Dict[str, List[NormalizedEvent]] = defaultdict(list)
    for event in _timestamped(events):
        if event.event_id != 18 or not _is_sysmon(event):
            continue
        pipe = _value(event, "PipeName").strip("\\").lower()
        if pipe not in PIPE_DISCOVERY_NAMES:
            continue
        grouped[event.computer or "unknown"].append(event)

    alerts: List[Alert] = []
    for host, cluster in grouped.items():
        ordered = sorted(cluster, key=lambda event: event.timestamp)
        windows: List[List[NormalizedEvent]] = []
        current: List[NormalizedEvent] = []
        for event in ordered:
            if current and event.timestamp - current[-1].timestamp > timedelta(minutes=5):
                windows.append(current)
                current = []
            current.append(event)
        if current:
            windows.append(current)
        for window in windows:
            names = sorted({_value(event, "PipeName").strip("\\").lower() for event in window})
            if len(names) < 3:
                continue
            first = window[0]
            alerts.append(
                Alert(
                    rule_name="Named Pipe Service Discovery",
                    severity="medium",
                    mitre_tactic="Discovery",
                    mitre_technique="T1018",
                    promotion_policy="signal_only",
                    description=f"Multiple service and security named pipes were enumerated on {host}",
                    explanation=(
                        "Sysmon ConnectPipe events show a short burst across several sensitive Windows service pipes. This is useful remote-system/service discovery context, but administrative tools can also enumerate these pipes."
                    ),
                    confidence="high",
                    confidence_factors=["three or more sensitive pipe names in five minutes", "Sysmon event 18"],
                    investigate_next=(
                        "Identify the process or source host responsible, correlate with SMB/RPC and logon events, and verify whether inventory or troubleshooting tooling explains the burst."
                    ),
                    event=first,
                    user=_actor(first),
                    process=first.process_name,
                    evidence={
                        "pipe_names": names,
                        "event_count": len(window),
                        "supporting_evidence_only": True,
                        "evidence_strength": "medium",
                    },
                )
            )
    return alerts


def _wmi_partial_process_tree(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Use remote logon + WmiPrvSE activity when parent IDs are absent."""

    timed = _timestamped(events)
    remote_logons = [
        event
        for event in timed
        if event.event_id == 4624 and event.logon_type == "3" and _is_security(event) and _is_external_peer(event.source_ip or _value(event, "IpAddress"))
    ]
    wmi_events = [
        event
        for event in timed
        if event.event_id in (1, 4688) and _basename(_value(event, "Image") or event.process_name) == "wmiprvse.exe"
    ]
    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for wmi in wmi_events:
        matches = [logon for logon in remote_logons if (logon.computer or "") == (wmi.computer or "") and _within(logon, wmi, 180)]
        if not matches:
            continue
        logon = matches[0]
        source = logon.source_ip or _value(logon, "IpAddress")
        key = _dedupe_key(wmi, source, "wmiprvse")
        if key in seen:
            continue
        seen.add(key)
        child_processes = [
            event
            for event in timed
            if event.event_id in (1, 4688)
            and (event.computer or "") == (wmi.computer or "")
            and _within(wmi, event, 180)
            and _basename(_value(event, "ParentImage") or event.parent_process) == "wmiprvse.exe"
        ]
        alerts.append(
            Alert(
                rule_name="WMI Remote Activity (Partial Process Tree)",
                severity="medium",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1047",
                promotion_policy="signal_only",
                description=f"Remote logon from {source} preceded WmiPrvSE activity on {wmi.computer or 'the host'}",
                explanation=(
                    "A remote network logon and WmiPrvSE process activity occurred on the same host within three minutes. The sample lacks a complete parent/child process ID, so this remains a supporting WMI execution signal rather than a standalone compromise finding."
                ),
                confidence="medium",
                confidence_factors=["Security 4624 LogonType 3", "WmiPrvSE process creation", "partial process tree"],
                investigate_next=(
                    "Recover WMI client and command-line telemetry if available, identify the source host and account, and correlate with child processes or RPC/135 traffic."
                ),
                event=wmi,
                user=wmi.domain_user or logon.target_domain_user or logon.domain_user,
                source_ip=source,
                process=_value(wmi, "Image") or wmi.process_name,
                evidence={
                    "source_ip": source,
                    "remote_logon_event_id": 4624,
                    "wmi_event_id": wmi.event_id,
                    "child_process_count": len(child_processes),
                    "supporting_evidence_only": True,
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _winrm_shell_lifecycle(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Surface WinRM shell lifecycle events when process creation is missing."""

    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for event in _timestamped(events):
        if event.event_id not in (91, 169, 142, 143):
            continue
        if "winrm" not in _provider_text(event) and "wsman" not in _provider_text(event):
            continue
        key = _dedupe_key(event, str(event.event_id))
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="WinRM Shell Lifecycle Activity",
                severity="medium",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.006",
                promotion_policy="signal_only",
                description=f"WinRM/WSMan shell lifecycle event {event.event_id} observed on {event.computer or 'the host'}",
                explanation=(
                    "WinRM recorded shell lifecycle activity, but this event does not include the remote client or command. It is retained as a pivot so an analyst can request the missing WinRM, Security, or PowerShell telemetry."
                ),
                confidence="medium",
                confidence_factors=[f"WinRM event {event.event_id}", "command/client fields unavailable"],
                investigate_next=(
                    "Collect WinRM Operational, Security 4624, and PowerShell 4104 telemetry, then identify the remote client and commands associated with the shell."
                ),
                event=event,
                user=_actor(event),
                evidence={
                    "event_id": event.event_id,
                    "provider": event.provider,
                    "supporting_evidence_only": True,
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _share_service_discovery(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Pair srvsvc pipe access with a remote network connection."""

    timed = _timestamped(events)
    pipes = [event for event in timed if event.event_id == 18 and _is_sysmon(event) and _value(event, "PipeName").strip("\\").lower() == "srvsvc"]
    network = [event for event in timed if event.event_id == 3 and _is_sysmon(event) and _is_external_peer(_value(event, "DestinationIp") or event.destination_ip)]
    alerts: List[Alert] = []
    for pipe in pipes:
        peers = [event for event in network if (event.computer or "") == (pipe.computer or "") and _within(pipe, event, 180)]
        if not peers:
            continue
        peer = peers[0]
        destination = _value(peer, "DestinationIp") or peer.destination_ip
        alerts.append(
            Alert(
                rule_name="Remote Share Service Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1135",
                promotion_policy="signal_only",
                description=f"srvsvc named-pipe discovery coincided with network activity to {destination}",
                explanation=(
                    "The srvsvc pipe (Server Service) was accessed near a remote Sysmon network event. This is consistent with share enumeration, but inventory and management tools can generate the same sequence."
                ),
                confidence="medium",
                confidence_factors=["Sysmon srvsvc ConnectPipe", "nearby remote network event"],
                investigate_next=(
                    "Identify the source process/host, inspect RPC and SMB activity, and verify whether a legitimate inventory or share-mapping tool initiated the query."
                ),
                event=pipe,
                user=_actor(pipe),
                source_ip=_value(peer, "SourceIp") or peer.source_ip,
                destination_ip=destination,
                evidence={
                    "pipe_name": _value(pipe, "PipeName"),
                    "destination_ip": destination,
                    "network_event_id": 3,
                    "supporting_evidence_only": True,
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _delete_access_requested(value: str) -> bool:
    """Return whether a Security object-access mask includes DELETE.

    Security 4663 records are rendered differently by Windows versions and
    collection tools.  Prefer the explicit 0x10000 DELETE bit and only fall
    back to a textual access list that names DELETE; generic access masks are
    deliberately not treated as file deletion.
    """

    text = (value or "").strip().lower()
    for token in re.findall(r"0x[0-9a-f]+|\b[0-9a-f]{4,}\b", text):
        try:
            if int(token, 16) & 0x00010000:
                return True
        except ValueError:
            continue
    return "delete" in text


def _file_deletion_activity(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Surface provider-aware file deletion telemetry as a supporting signal.

    Sysmon 23/26 are the most direct file-delete records.  Security 4663 can
    also expose a delete operation when Object Access auditing is enabled.
    A command-line delete is retained when a path is present, but all of these
    observations remain signal-only because installers, cleanup jobs, and
    software updaters legitimately delete files.
    """

    alerts: List[Alert] = []
    seen: Set[Tuple[str, ...]] = set()
    for event in _timestamped(events):
        target = _value(event, "TargetFilename", "ObjectName", "FileName", "Path")
        source = ""
        if event.event_id in FILE_DELETE_EVENT_IDS and _is_sysmon(event):
            source = f"Sysmon {event.event_id}"
        elif event.event_id == 4663 and _is_security(event):
            if not _delete_access_requested(_value(event, "AccessMask", "AccessList")):
                continue
            source = "Security 4663"
        elif event.event_id in (1, 4688, 4104):
            command = " ".join(
                value
                for value in (event.command_line, _value(event, "ScriptBlockText", "Message", "Payload"))
                if value
            ).strip()
            match = FILE_DELETE_COMMAND_RE.search(command)
            if not match:
                continue
            args = match.group("args") or ""
            path_match = re.search(r"(?:[A-Za-z]:\\|\\\\)[^\s\"']+", args)
            target = path_match.group(0).rstrip(".,;)") if path_match else ""
            if not target:
                continue
            source = f"command event {event.event_id}"
        else:
            continue

        if not target:
            continue
        target = target.strip().strip("\"'")
        target_lower = target.lower().replace("/", "\\")
        rule_name = _value(event, "RuleName")
        suspicious_context = (
            _user_path(target)
            or _system_path(target)
            or target_lower.endswith((".evtx", ".log", ".dmp", ".pf", ".ps1", ".bat", ".cmd"))
            or "t1070.004" in rule_name.lower()
            or "filedelete" in rule_name.lower()
        )
        key = _dedupe_key(event, target, source)
        if key in seen:
            continue
        seen.add(key)
        actor = _actor(event)
        severity = "high" if suspicious_context and source.startswith("Sysmon") else "medium"
        alerts.append(
            Alert(
                rule_name="File Deletion Activity",
                severity=severity,
                mitre_tactic="Defense Evasion",
                mitre_technique="T1070.004",
                promotion_policy="signal_only",
                description=f"A file deletion operation targeted {target} on {event.computer or 'the host'}",
                explanation=(
                    f"{source} recorded deletion of a file path. Deleting payloads, logs, or staging files can remove evidence, but normal cleanup and software maintenance can produce the same telemetry."
                ),
                confidence="high" if suspicious_context else "medium",
                confidence_factors=[source, "file target path captured"] + (["user/system or forensic-artifact path"] if suspicious_context else []),
                investigate_next=(
                    "Recover the deleted-file context from USN Journal, Volume Shadow Copy, or EDR telemetry, identify the deleting process and actor, and correlate the operation with nearby execution or log-clearing activity."
                ),
                event=event,
                user=actor,
                process=event.process_name,
                evidence={
                    "target": target,
                    "source": source,
                    "rule_name": rule_name,
                    "command_line": event.command_line[:500] if event.command_line else "",
                    "event_id": event.event_id,
                    "supporting_evidence_only": True,
                    "evidence_strength": "high" if suspicious_context else "medium",
                },
            )
        )
    return alerts


def _directory_object_enumeration(events: Sequence[NormalizedEvent]) -> List[Alert]:
    """Recognize bursty SAM/DS reads when command-line telemetry is absent.

    AD reconnaissance often leaves only 4661/4662 audit records.  One object
    read is common and ignored; a short burst by a non-system actor is kept as
    a signal-only domain-account or domain-group discovery observation.
    """

    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)
    for event in _timestamped(events):
        if event.event_id not in (4661, 4662) or not _is_security(event):
            continue
        object_server = _value(event, "ObjectServer").lower()
        object_type = _value(event, "ObjectType").lower()
        family = ""
        if event.event_id == 4661 and "security account manager" in object_server:
            if "sam_group" in object_type:
                family = "group"
            elif "sam_alias" in object_type:
                # SAM_ALIAS is the local/built-in group object class.  It is
                # emitted by 4661 when tools such as RID bruteforcers walk
                # local group membership, even when no process command line
                # is present in the bundle.  Keep it separate from
                # SAM_GROUP, which represents domain-group reads in the
                # public corpus.
                family = "local_group"
            elif "sam_domain" in object_type or "sam_user" in object_type:
                family = "account"
        elif event.event_id == 4662 and object_server == "ds":
            # The group class GUID is emitted by directory-service auditing
            # for LDAP group object reads.  Other DS reads are intentionally
            # left to the dedicated credential and persistence detectors.
            if AD_GROUP_CLASS_GUID in object_type:
                family = "group"
        if not family:
            continue
        actor = _actor(event)
        if actor.strip().lower() in {"system", "nt authority\\system", "local service", "nt authority\\local service", "anonymous logon"}:
            continue
        grouped[(event.computer or "unknown", actor, family)].append(event)

    alerts: List[Alert] = []
    for (host, actor, family), cluster in grouped.items():
        if len(cluster) < 3:
            continue
        ordered = sorted(cluster, key=lambda item: item.timestamp)
        first = ordered[0]
        objects = sorted(
            {
                _value(item, "ObjectName", "TargetObject")
                for item in ordered
                if _value(item, "ObjectName", "TargetObject")
            }
        )[:25]
        technique = "T1069.001" if family == "local_group" else "T1069.002" if family == "group" else "T1087.002"
        if family == "local_group":
            rule_name = "Local Group Enumeration (Directory Audit)"
            noun = "local-group membership"
        elif family == "group":
            rule_name = "Domain Group Enumeration (Directory Audit)"
            noun = "group membership"
        else:
            rule_name = "Domain Account Enumeration (Directory Audit)"
            noun = "account information"
        alerts.append(
            Alert(
                rule_name=rule_name,
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique=technique,
                promotion_policy="signal_only",
                description=f"{actor} generated a burst of domain {noun} reads on {host}",
                explanation=(
                    "A burst of Security directory-object reads is consistent with Active Directory reconnaissance, but directory services and inventory tools can generate similar access patterns."
                ),
                confidence="medium",
                confidence_factors=[f"{len(cluster)} Security {first.event_id} reads", "non-system directory actor", "command-line telemetry unavailable"],
                investigate_next=(
                    "Collect the actor's process and PowerShell telemetry, identify the client host and logon session, and correlate with account, group, LDAP, or Kerberos discovery in the same time window."
                ),
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "event_ids": sorted({item.event_id for item in ordered}),
                    "event_count": len(cluster),
                    "object_types": sorted({_value(item, "ObjectType") for item in ordered if _value(item, "ObjectType")}),
                    "objects": objects,
                    "supporting_evidence_only": True,
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def detect(events: List[NormalizedEvent]) -> List[Alert]:
    """Return conservative context alerts for partial/under-covered EVTX patterns."""

    alerts: List[Alert] = []
    alerts.extend(_audit_log_cleared(events))
    alerts.extend(_hidden_file_attribute(events))
    alerts.extend(_uac_policy_disabled(events))
    alerts.extend(_kernel_debug_or_test_signing(events))
    alerts.extend(_process_access_injection(events))
    alerts.extend(_process_herpaderping(events))
    alerts.extend(_byovd_driver_staging(events))
    alerts.extend(_silent_process_exit_hijack(events))
    alerts.extend(_winlogon_shell_persistence(events))
    alerts.extend(_pending_gpo_registry(events))
    alerts.extend(_sam_force_password_reset(events))
    alerts.extend(_named_pipe_discovery(events))
    alerts.extend(_wmi_partial_process_tree(events))
    alerts.extend(_winrm_shell_lifecycle(events))
    alerts.extend(_share_service_discovery(events))
    alerts.extend(_file_deletion_activity(events))
    alerts.extend(_directory_object_enumeration(events))
    return alerts
