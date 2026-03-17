"""Defense evasion detection rules with analyst guidance."""

import html
import os
import re
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List

from models.event_model import Alert, NormalizedEvent

URL_RE = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)
REGSVR32_SCRIPTLET_RE = re.compile(r"/i:([^\s]+)", re.IGNORECASE)
DOTNET_TEMP_COMPILERS = {"csc.exe", "cvtres.exe"}
EVENTLOG_SERVICE_NAMES = {"windows event log", "eventlog"}
POWERSHELL_CLM_MARKER = r"\system\currentcontrolset\control\session manager\environment\__pslockdownpolicy"
SCRIPTBLOCKLOGGING_MARKER = r"\policies\microsoft\windows\powershell\scriptblocklogging\enablescriptblocklogging"
POWERSHELL_EXEC_POLICY_MARKERS = (
    r"\powershell\1\shellids\microsoft.powershell\executionpolicy",
    r"\powershellcore\executionpolicy",
)
RISKY_EXEC_POLICY_VALUES = ("unrestricted", "bypass", "remotesigned")
EVENTLOG_PIPE_NAME = r"\eventlog"
XPCMDSHELL_RE = re.compile(r"\bxp_cmdshell\b", re.IGNORECASE)
SQL_CLIENT_IP_RE = re.compile(r"client_ip:([^\s<]+)", re.IGNORECASE)
SQL_SESSION_PRINCIPAL_RE = re.compile(r"session_server_principal_name:([^\s<]+)", re.IGNORECASE)
SQL_SERVER_PRINCIPAL_RE = re.compile(r"server_principal_name:([^\s<]+)", re.IGNORECASE)
SQL_STATEMENT_RE = re.compile(r"statement:(.*?)\s+additional_information:", re.IGNORECASE | re.DOTALL)
AUTO_ELEVATE_TRIGGERS = {
    "sdclt.exe": {
        "registry_markers": (r"\exefile\shell\runas\command\isolatedcommand", r"\app paths\control.exe\(default)"),
        "command_markers": ("/kickoffelev",),
    },
    "eventvwr.exe": {
        "registry_markers": (r"\mscfile\shell\open\command\(default)",),
        "command_markers": tuple(),
    },
    "compmgmtlauncher.exe": {
        "registry_markers": (r"\mscfile\shell\open\command\(default)",),
        "command_markers": tuple(),
    },
}
UAC_BYPASS_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "notepad.exe"}
MSI_TEMP_RE = re.compile(r"c:\\windows\\installer\\msi[a-z0-9]+\.tmp", re.IGNORECASE)
CMSTP_PROFILEINSTALL_MARKER = r"\app paths\cmmgr32.exe\profileinstallpath"
VOLATILE_SYSTEMROOT_MARKER = r"\volatile environment\systemroot"
UAC_SIDELOAD_TARGETS: Dict[str, Dict[str, tuple]] = {
    "sysprep.exe": {
        "dlls": ("cryptbase.dll",),
        "paths": (r"\windows\system32\sysprep",),
    },
    "mcx2prov.exe": {
        "dlls": ("cryptbase.dll",),
        "paths": (r"\windows\ehome",),
    },
    "migwiz.exe": {
        "dlls": ("cryptbase.dll",),
        "paths": (r"\windows\system32\migwiz",),
    },
    "cliconfg.exe": {
        "dlls": ("ntwdblib.dll",),
        "paths": (r"\windows\system32",),
    },
}
UAC_SUSPICIOUS_LAUNCHERS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "python.exe",
    "cscript.exe",
    "wscript.exe",
}
SERVICE_ACCOUNT_MARKERS = ("iis apppool\\", "nt authority\\network service", "nt authority\\local service", "local service", "network service")
FIREWALL_DISPLAY_RE = re.compile(r"-displayname\s+[\\\"]*([^\"\\\r\n]+)", re.IGNORECASE)
FIREWALL_PORT_RE = re.compile(r"-localport\s+[\\\"]*([0-9,\-]+)", re.IGNORECASE)
DLL_PATH_RE = re.compile(r"([A-Za-z]:\\[^\"'\r\n]+\.dll)", re.IGNORECASE)
PAYLOAD_PATH_RE = re.compile(r"([A-Za-z]:\\[^\"'\r\n]+\.(?:exe|dll))", re.IGNORECASE)
POWERSHELL_HOST_BASENAMES = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}
POTATO_PIPE_RE = re.compile(r"^\\[0-9a-f\-]{36}\\pipe\\srvsvc$", re.IGNORECASE)
ROGUE_POTATO_PIPE_RE = re.compile(r"^\\roguepotato\\pipe\\epmapper$", re.IGNORECASE)
LOOPBACK_IPS = {"127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}


def _is_sysmon_event(ev: NormalizedEvent) -> bool:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    return "sysmon" in provider or "sysmon" in channel


def _basename(path: str) -> str:
    text = (path or "").replace("\\", "/").strip()
    return os.path.basename(text).lower()


def _first_url(text: str) -> str:
    match = URL_RE.search(text or "")
    return match.group(0) if match else ""


def _extract_regsvr32_target(command: str) -> str:
    match = REGSVR32_SCRIPTLET_RE.search(command or "")
    return (match.group(1) or "").strip() if match else ""


def _extract_first_dll_path(text: str) -> str:
    match = DLL_PATH_RE.search(text or "")
    return (match.group(1) or "").strip() if match else ""


def _extract_payload_path(text: str) -> str:
    match = PAYLOAD_PATH_RE.search(text or "")
    return (match.group(1) or "").strip() if match else ""


def _event_actor(ev: NormalizedEvent) -> str:
    return (
        ev.domain_user
        or ev.subject_domain_user
        or ev.event_data.get("User", "")
        or ev.event_data.get("AccountName", "")
        or "unknown"
    )


def _embedded_eventdata_text(ev: NormalizedEvent) -> str:
    if not ev.raw_xml:
        return ""
    match = re.search(r"<Data[^>]*>(.*?)</Data>", ev.raw_xml, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return html.unescape(match.group(1)).strip()


def _embedded_string_values(ev: NormalizedEvent) -> List[str]:
    text = _embedded_eventdata_text(ev)
    if not text:
        return []
    return [item.strip() for item in re.findall(r"<string>(.*?)</string>", text, re.IGNORECASE | re.DOTALL) if item.strip()]


def _normalize_hex_mask(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    try:
        number = int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return text
    return f"0x{number:x}"


def _extract_sql_statement(payload: str) -> str:
    match = SQL_STATEMENT_RE.search(payload or "")
    if not match:
        return ""
    return re.sub(r"\s+", " ", (match.group(1) or "").strip())


def _extract_sql_principal(payload: str) -> str:
    for regex in (SQL_SESSION_PRINCIPAL_RE, SQL_SERVER_PRINCIPAL_RE):
        match = regex.search(payload or "")
        if match:
            return (match.group(1) or "").strip()
    return ""


def _extract_sql_client_ip(payload: str) -> str:
    match = SQL_CLIENT_IP_RE.search(payload or "")
    return (match.group(1) or "").strip() if match else ""


def _is_benign_csrss_control_routine(ev: NormalizedEvent) -> bool:
    if ev.event_id != 8 or not _is_sysmon_event(ev):
        return False

    event_data = ev.event_data or {}
    source = event_data.get("SourceImage", "") or ""
    start_function = (event_data.get("StartFunction", "") or "").strip().lower()
    start_module = event_data.get("StartModule", "") or ""
    source_user = (event_data.get("SourceUser", "") or "").strip().lower()

    return (
        _basename(source) == "csrss.exe"
        and start_function == "ctrlroutine"
        and _basename(start_module) == "kernelbase.dll"
        and source_user == "nt authority\\system"
    )


def detect(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    alerts.extend(_windows_defender_malware_detection(events))
    alerts.extend(_powershell_clm_disabled(events))
    alerts.extend(_powershell_execution_policy_weakened(events))
    alerts.extend(_powershell_scriptblocklogging_disabled(events))
    alerts.extend(_windows_event_log_service_crash(events))
    alerts.extend(_remote_event_log_service_crash(events))
    alerts.extend(_xp_cmdshell_enabled(events))
    alerts.extend(_mssql_xp_cmdshell_execution(events))
    alerts.extend(_mssql_xp_cmdshell_execution_attempt(events))
    alerts.extend(_windows_defender_service_tamper(events))
    alerts.extend(_suspicious_firewall_rule_creation(events))
    alerts.extend(_sip_trust_provider_registration(events))
    alerts.extend(_hosts_file_modified(events))
    alerts.extend(_uac_bypass_registry_hijack(events))
    alerts.extend(_cmstp_uac_bypass(events))
    alerts.extend(_volatile_systemroot_uac_bypass(events))
    alerts.extend(_uac_bypass_dll_sideload(events))
    alerts.extend(_wscript_manifest_uac_bypass(events))
    alerts.extend(_office_vba_object_model_access(events))
    alerts.extend(_ftp_script_command_execution(events))
    alerts.extend(_service_account_to_system_impersonation(events))
    alerts.extend(_potato_named_pipe_impersonation(events))
    alerts.extend(_msiexec_proxy_execution(events))
    alerts.extend(_installutil_proxy_execution(events))
    alerts.extend(_desktopimgdownldr_remote_download(events))
    alerts.extend(_temp_dotnet_compilation(events))
    alerts.extend(_unmanaged_powershell_injection(events))
    alerts.extend(_rundll32_wermgr_hollowing(events))
    for ev in events:
        alerts.extend(_check(ev))
    return alerts


def _windows_defender_malware_detection(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[tuple[str, str], List[NormalizedEvent]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 1116:
            continue

        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "windows defender" not in provider and "windows defender" not in channel:
            continue

        threat_name = (ev.event_data.get("Threat Name", "") or "").strip()
        threat_id = (ev.event_data.get("Threat ID", "") or "").strip()
        if not threat_name and not threat_id:
            continue

        actor = (
            ev.event_data.get("Detection User", "")
            or ev.domain_user
            or ev.subject_domain_user
            or "unknown"
        )
        key = (ev.computer or "unknown", actor)
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1].timestamp <= timedelta(minutes=30):
            existing.append(ev)
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}")] = [ev]
        else:
            grouped[key] = [ev]

    for (_, actor_key), cluster in grouped.items():
        actor = actor_key.split("::", 1)[0]
        first = cluster[0]
        host = first.computer or "unknown host"
        threat_names = sorted(
            {
                (item.event_data.get("Threat Name", "") or "").strip()
                for item in cluster
                if (item.event_data.get("Threat Name", "") or "").strip()
            }
        )
        detection_ids = sorted(
            {
                (item.event_data.get("Detection ID", "") or "").strip()
                for item in cluster
                if (item.event_data.get("Detection ID", "") or "").strip()
            }
        )
        severity_names = sorted(
            {
                (item.event_data.get("Severity Name", "") or "").strip()
                for item in cluster
                if (item.event_data.get("Severity Name", "") or "").strip()
            }
        )
        process_names = sorted(
            {
                (item.event_data.get("Process Name", "") or item.process_name or "").strip()
                for item in cluster
                if (item.event_data.get("Process Name", "") or item.process_name or "").strip()
            }
        )

        severity = "critical" if any(value.lower() in {"severe", "high"} for value in severity_names) else "high"
        primary_threat = threat_names[0] if threat_names else "malware"
        alerts.append(
            Alert(
                rule_name="Windows Defender Malware Detection",
                severity=severity,
                mitre_tactic="Execution",
                mitre_technique="T1204",
                description=(
                    f"Windows Defender flagged {len(cluster)} malware detection event(s) on {host} "
                    f"(example threat: {primary_threat})"
                ),
                explanation=(
                    "Windows Defender event 1116 indicates malware or potentially unwanted software was detected. "
                    "Multiple detections over a short window are strong evidence of malicious artifact execution or staging."
                ),
                confidence="high",
                investigate_next=(
                    "Contain the host, preserve the detected files and command lineage, and verify whether remediation "
                    "succeeded or malware remained active."
                ),
                event=first,
                user=actor,
                process=first.event_data.get("Process Name", "") or first.process_name,
                evidence={
                    "actor_user": actor,
                    "detection_count": len(cluster),
                    "threat_names": threat_names[:10],
                    "detection_ids": detection_ids[:20],
                    "severity_names": severity_names,
                    "process_names": process_names[:10],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _powershell_execution_policy_weakened(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 13 or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetObject", "") or "").lower()
        if not any(marker in target for marker in POWERSHELL_EXEC_POLICY_MARKERS):
            continue

        event_type = (ev.event_data.get("EventType", "") or "").lower()
        if event_type != "setvalue":
            continue

        details = (ev.event_data.get("Details", "") or "").strip()
        details_l = details.lower()
        if not any(value in details_l for value in RISKY_EXEC_POLICY_VALUES):
            continue

        actor = _event_actor(ev)
        key = (ev.computer or "unknown", actor)
        grouped[key].append(ev)

    for (host, actor), cluster in grouped.items():
        first = cluster[0]
        target_paths = sorted(
            {
                (item.event_data.get("TargetObject", "") or "").strip()
                for item in cluster
                if (item.event_data.get("TargetObject", "") or "").strip()
            }
        )
        policy_values = sorted(
            {
                (item.event_data.get("Details", "") or "").strip()
                for item in cluster
                if (item.event_data.get("Details", "") or "").strip()
            }
        )
        processes = sorted(
            {
                (item.event_data.get("Image", "") or item.process_name or "").strip()
                for item in cluster
                if (item.event_data.get("Image", "") or item.process_name or "").strip()
            }
        )
        primary_policy_value = policy_values[0] if policy_values else "unknown"

        alerts.append(
            Alert(
                rule_name="PowerShell Execution Policy Weakened",
                severity="high",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.001",
                description=(
                    f"{actor if actor != 'unknown' else 'An unknown actor'} set PowerShell execution policy to "
                    f"{primary_policy_value} on {host}"
                ),
                explanation=(
                    "Changing PowerShell execution policy to permissive values such as Unrestricted or Bypass weakens "
                    "script execution controls and can facilitate payload execution."
                ),
                confidence="high",
                investigate_next=(
                    "Restore a hardened execution-policy baseline, verify the originating process and actor, and inspect nearby "
                    "PowerShell/script activity for follow-on payload execution."
                ),
                event=first,
                user=actor if actor != "unknown" else "",
                process=first.event_data.get("Image", "") or first.process_name,
                evidence={
                    "actor_user": actor,
                    "registry_key": target_paths[0] if target_paths else "",
                    "registry_paths": target_paths,
                    "policy_values": policy_values,
                    "policy_value": primary_policy_value,
                    "processes": processes,
                    "collapsed_event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _unmanaged_powershell_injection(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    module_loads: Dict[tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)
    grouped_threads: Dict[tuple[str, str, str, str], List[NormalizedEvent]] = defaultdict(list)
    window = timedelta(seconds=30)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if not _is_sysmon_event(ev):
            continue

        if ev.event_id == 7:
            target_image = (ev.event_data.get("Image", "") or ev.process_name or "").strip()
            loaded_image = (ev.event_data.get("ImageLoaded", "") or "").strip().lower()
            process_id = (ev.event_data.get("ProcessId", "") or "").strip()
            if (
                target_image
                and process_id
                and "system.management.automation" in loaded_image
                and _basename(target_image) not in POWERSHELL_HOST_BASENAMES
            ):
                module_loads[((ev.computer or "").lower(), target_image.lower(), process_id)].append(ev)
            continue

        if ev.event_id != 8:
            continue

        source_image = (ev.event_data.get("SourceImage", "") or "").strip()
        target_image = (ev.event_data.get("TargetImage", "") or "").strip()
        target_process_id = (ev.event_data.get("TargetProcessId", "") or "").strip()
        if not source_image or not target_image or not target_process_id:
            continue
        if _basename(source_image) not in {"powershell.exe", "pwsh.exe"}:
            continue
        if _basename(target_image) in POWERSHELL_HOST_BASENAMES:
            continue
        grouped_threads[((ev.computer or "").lower(), source_image.lower(), target_image.lower(), target_process_id)].append(ev)

    for (host_key, source_key, target_key, target_process_id), thread_events in grouped_threads.items():
        related_loads = [
            module_event
            for module_event in module_loads.get((host_key, target_key, target_process_id), [])
            if module_event.timestamp and abs(module_event.timestamp - thread_events[0].timestamp) <= window
        ]
        if not related_loads or len(thread_events) < 3:
            continue

        first = thread_events[0]
        source_image = first.event_data.get("SourceImage", "") or source_key
        target_image = first.event_data.get("TargetImage", "") or target_key
        host = first.computer or "unknown host"
        loaded_modules = sorted(
            {
                (module_event.event_data.get("ImageLoaded", "") or "").strip()
                for module_event in related_loads
                if (module_event.event_data.get("ImageLoaded", "") or "").strip()
            }
        )
        alerts.append(
            Alert(
                rule_name="Unmanaged PowerShell Injection",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1055.003",
                description=f"{source_image} injected unmanaged PowerShell into {target_image} on {host}",
                explanation=(
                    "PowerShell injected a non-PowerShell host and the target loaded System.Management.Automation, which is a strong "
                    "indicator of unmanaged PowerShell execution through process injection."
                ),
                confidence="high",
                investigate_next=(
                    "Preserve the injected target process, recover the originating PowerShell content if possible, and determine "
                    "whether the injected host executed follow-on payloads or credential access actions."
                ),
                event=first,
                process=source_image,
                evidence={
                    "source_image": source_image,
                    "target_image": target_image,
                    "target_process_id": target_process_id,
                    "remote_thread_count": len(thread_events),
                    "loaded_modules": loaded_modules,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _rundll32_wermgr_hollowing(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    access_by_target: Dict[tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)
    registry_by_process: Dict[tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)
    window = timedelta(seconds=45)

    for ev in events:
        if not _is_sysmon_event(ev):
            continue
        if ev.event_id == 10:
            target_image = (ev.event_data.get("TargetImage", "") or "").strip()
            target_process_id = (ev.event_data.get("TargetProcessId", "") or "").strip()
            if _basename(target_image) != "wermgr.exe" or not target_process_id:
                continue
            access_by_target[((ev.computer or "").lower(), target_image.lower(), target_process_id)].append(ev)
        elif ev.event_id in (12, 13):
            process_image = (ev.event_data.get("Image", "") or ev.process_name or "").strip()
            process_id = (ev.event_data.get("ProcessId", "") or "").strip()
            if _basename(process_image) != "wermgr.exe" or not process_id:
                continue
            registry_by_process[((ev.computer or "").lower(), process_image.lower(), process_id)].append(ev)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 1 or not _is_sysmon_event(ev):
            continue
        image = (ev.event_data.get("Image", "") or ev.process_name or "").strip()
        parent = (ev.event_data.get("ParentImage", "") or ev.parent_process or "").strip()
        process_id = (ev.event_data.get("ProcessId", "") or "").strip()
        if _basename(image) != "wermgr.exe" or _basename(parent) != "rundll32.exe" or not process_id:
            continue

        parent_cmd = (ev.event_data.get("ParentCommandLine", "") or "").strip()
        payload_path = _extract_payload_path(parent_cmd)
        if not payload_path:
            continue

        access_matches = [
            item
            for item in access_by_target.get(((ev.computer or "").lower(), image.lower(), process_id), [])
            if item.timestamp and abs(item.timestamp - ev.timestamp) <= window
            if _normalize_hex_mask(item.event_data.get("GrantedAccess", "")) in {"0x1fffff", "0x1f1fff"}
        ]
        if not access_matches:
            continue

        registry_matches = [
            item
            for item in registry_by_process.get(((ev.computer or "").lower(), image.lower(), process_id), [])
            if item.timestamp and abs(item.timestamp - ev.timestamp) <= window
        ]
        if not registry_matches:
            continue

        host = ev.computer or "unknown host"
        registry_targets = sorted(
            {
                (item.event_data.get("TargetObject", "") or "").strip()
                for item in registry_matches
                if (item.event_data.get("TargetObject", "") or "").strip()
            }
        )
        alerts.append(
            Alert(
                rule_name="Rundll32 Wermgr Hollowing",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1055.012",
                description=f"{parent} hollowed wermgr.exe from {payload_path} on {host}",
                explanation=(
                    "rundll32 launched wermgr.exe from an external DLL registration path, obtained full access to the target process, "
                    "and the spawned wermgr.exe immediately touched registry state. This is consistent with process hollowing or masqueraded payload staging."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the DLL referenced by rundll32, inspect the hollowed wermgr.exe memory image, and determine whether "
                    "the registry activity was part of follow-on persistence or network proxy setup."
                ),
                event=ev,
                process=image,
                parent_process=parent,
                evidence={
                    "source_image": parent,
                    "target_image": image,
                    "target_process_id": process_id,
                    "payload_path": payload_path,
                    "parent_command_line": parent_cmd,
                    "access_masks": sorted(
                        {
                            _normalize_hex_mask(item.event_data.get("GrantedAccess", ""))
                            for item in access_matches
                            if _normalize_hex_mask(item.event_data.get("GrantedAccess", ""))
                        }
                    ),
                    "registry_targets": registry_targets,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _powershell_clm_disabled(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (12, 13) or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetObject", "") or "").lower()
        event_type = (ev.event_data.get("EventType", "") or "").lower()
        if POWERSHELL_CLM_MARKER not in target:
            continue
        if event_type not in {"deletevalue", "setvalue"}:
            continue

        actor = _event_actor(ev)
        process = ev.process_name or ev.event_data.get("Image", "") or "unknown"
        key = ((ev.computer or "unknown").lower(), target, process.lower(), event_type)
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="PowerShell Constrained Language Mode Disabled",
                severity="high",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.001",
                description=f"{actor} removed or changed the CLM enforcement value on {ev.computer}",
                explanation=(
                    "Deleting or changing __PSLockdownPolicy disables PowerShell Constrained Language Mode enforcement "
                    "and weakens a common anti-abuse control for script execution."
                ),
                confidence="high",
                investigate_next=(
                    "Restore the PowerShell lockdown policy, review who launched the modifying process, and inspect nearby script or LOLBin execution."
                ),
                event=ev,
                user=actor,
                process=process,
                evidence={
                    "actor_user": actor,
                    "registry_key": ev.event_data.get("TargetObject", ""),
                    "event_type": ev.event_data.get("EventType", ""),
                    "process_name": process,
                    "rule_name": ev.event_data.get("RuleName", ""),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _powershell_scriptblocklogging_disabled(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (12, 13) or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetObject", "") or "").lower()
        event_type = (ev.event_data.get("EventType", "") or "").lower()
        details = (ev.event_data.get("Details", "") or "").strip().lower()
        if SCRIPTBLOCKLOGGING_MARKER not in target:
            continue
        if not (
            event_type == "deletevalue"
            or (event_type == "setvalue" and any(marker in details for marker in ("0x00000000", "dword (0x00000000)", "0x0")))
        ):
            continue

        grouped[(ev.computer or "unknown", target)].append(ev)

    for (host, target), cluster in grouped.items():
        first = cluster[0]
        actor = next((_event_actor(item) for item in cluster if _event_actor(item) != "unknown"), "unknown")
        processes = sorted({item.process_name or item.event_data.get("Image", "") for item in cluster if item.process_name or item.event_data.get("Image", "")})
        actions = sorted({(item.event_data.get("EventType", "") or "").strip() for item in cluster if (item.event_data.get("EventType", "") or "").strip()})
        details = sorted({(item.event_data.get("Details", "") or "").strip() for item in cluster if (item.event_data.get("Details", "") or "").strip()})
        alerts.append(
            Alert(
                rule_name="PowerShell ScriptBlockLogging Disabled",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.001",
                description=f"{actor} disabled ScriptBlockLogging policy on {host}",
                explanation=(
                    "Disabling EnableScriptBlockLogging suppresses PowerShell 4104 telemetry and removes one of the most useful sources of script execution evidence."
                ),
                confidence="high",
                investigate_next=(
                    "Restore ScriptBlockLogging policy, review the modifying process and actor, and inspect adjacent PowerShell or registry activity for payload execution."
                ),
                event=first,
                user=actor,
                process=first.process_name or first.event_data.get("Image", ""),
                evidence={
                    "actor_user": actor,
                    "registry_key": first.event_data.get("TargetObject", ""),
                    "actions": actions,
                    "details": details,
                    "processes": processes,
                    "collapsed_event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _windows_event_log_service_crash(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[str, List[NormalizedEvent]] = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 1 or not _is_sysmon_event(ev):
            continue
        if _basename(ev.process_name) != "werfault.exe":
            continue
        parent = _basename(ev.parent_process)
        parent_command = (ev.event_data.get("ParentCommandLine", "") or "").lower()
        if parent != "svchost.exe" or "-s eventlog" not in parent_command:
            continue
        grouped[ev.computer or "unknown"].append(ev)

    for host, cluster in grouped.items():
        first = cluster[0]
        actor = next((_event_actor(item) for item in cluster if _event_actor(item) != "unknown"), "unknown")
        alerts.append(
            Alert(
                rule_name="Windows Event Log Service Crash",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.001",
                description=f"The Windows Event Log service crashed on {host}",
                explanation=(
                    "WerFault launched for the EventLog-hosting svchost instance, which strongly indicates the Windows Event Log service crashed rather than being cleanly reconfigured."
                ),
                confidence="high",
                investigate_next=(
                    "Review what preceded the crash, inspect any paired pipe/service abuse, and confirm logging resumed before trusting post-crash host telemetry."
                ),
                event=first,
                user=actor,
                process=first.process_name,
                parent_process=first.parent_process,
                service="Windows Event Log",
                evidence={
                    "actor_user": actor,
                    "parent_command_line": first.event_data.get("ParentCommandLine", ""),
                    "werfault_commands": [(item.command_line or "")[:300] for item in cluster if item.command_line],
                    "collapsed_event_count": len(cluster),
                    "service_name": "Windows Event Log",
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _remote_event_log_service_crash(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    seen = set()

    for ev in timed_events:
        if ev.event_id not in (17, 18) or not _is_sysmon_event(ev):
            continue
        pipe_name = (ev.event_data.get("PipeName", "") or "").lower()
        if pipe_name != EVENTLOG_PIPE_NAME:
            continue

        host = ev.computer or "unknown"
        window = [
            item
            for item in timed_events
            if (item.computer or "unknown") == host and abs((item.timestamp - ev.timestamp).total_seconds()) <= 300
        ]
        crash_events = [
            item
            for item in window
            if item.event_id == 1
            and _is_sysmon_event(item)
            and _basename(item.process_name) == "werfault.exe"
            and _basename(item.parent_process) == "svchost.exe"
            and "localservicenetworkrestricted" in (item.event_data.get("ParentCommandLine", "") or "").lower()
        ]
        remote_network = [
            item
            for item in window
            if item.event_id == 3
            and _is_sysmon_event(item)
            and (item.source_ip or "") not in {"", "-", "127.0.0.1", "::1", "0.0.0.0", "0:0:0:0:0:0:0:1"}
            and (item.event_data.get("DestinationPort", "") or "") == "445"
        ]
        if not crash_events or not remote_network:
            continue

        source_ips = sorted({item.source_ip for item in remote_network if item.source_ip})
        key = (host.lower(), tuple(source_ips))
        if key in seen:
            continue
        seen.add(key)

        first = crash_events[0]
        alerts.append(
            Alert(
                rule_name="Remote Event Log Service Crash",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.001",
                description=f"Remote activity preceded an Event Log service crash on {host}",
                explanation=(
                    "Eventlog named-pipe activity followed by a WerFault crash of the Event Log service and inbound SMB traffic is consistent with remote crash abuse to impair logging."
                ),
                confidence="high",
                investigate_next=(
                    "Identify the remote source system, isolate the target if needed, and review SMB, spooler, and Event Log service activity immediately before the crash."
                ),
                event=first,
                user=_event_actor(first),
                process=first.process_name,
                parent_process=first.parent_process,
                service="Windows Event Log",
                source_ip=source_ips[0] if source_ips else "",
                evidence={
                    "service_name": "Windows Event Log",
                    "pipe_name": ev.event_data.get("PipeName", ""),
                    "source_ips": source_ips,
                    "remote_network_count": len(remote_network),
                    "werfault_commands": [(item.command_line or "")[:300] for item in crash_events if item.command_line],
                    "parent_command_lines": [(item.event_data.get("ParentCommandLine", "") or "")[:300] for item in crash_events],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _xp_cmdshell_enabled(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)

    for ev in timed_events:
        if ev.event_id != 15457 or "mssql" not in (ev.provider or "").lower():
            continue
        values = _embedded_string_values(ev)
        if len(values) < 3:
            continue
        option_name, old_value, new_value = values[0].strip().lower(), values[1].strip(), values[2].strip()
        if option_name != "xp_cmdshell" or old_value != "0" or new_value != "1":
            continue
        grouped[(ev.computer or "unknown", ev.provider or "MSSQL")].append(ev)

    for (host, instance), cluster in grouped.items():
        first = cluster[0]
        context_window = [
            item
            for item in timed_events
            if (item.computer or "unknown") == host
            and abs((item.timestamp - first.timestamp).total_seconds()) <= 120
            and item.event_id in (15457, 18454, 33205)
            and "mssql" in (item.provider or "").lower()
        ]
        raw_payloads = [_embedded_eventdata_text(item) for item in context_window]
        principal = next((_extract_sql_principal(payload) for payload in raw_payloads if _extract_sql_principal(payload)), "")
        client_ip = next((_extract_sql_client_ip(payload) for payload in raw_payloads if _extract_sql_client_ip(payload)), "")
        show_advanced = any(
            len(_embedded_string_values(item)) >= 3
            and _embedded_string_values(item)[0].strip().lower() == "show advanced options"
            and _embedded_string_values(item)[1].strip() == "0"
            and _embedded_string_values(item)[2].strip() == "1"
            for item in context_window
            if item.event_id == 15457
        )
        alerts.append(
            Alert(
                rule_name="xp_cmdshell Enabled",
                severity="high",
                mitre_tactic="Execution",
                mitre_technique="T1505.001",
                description=f"xp_cmdshell was enabled on SQL Server {instance} at {host}",
                explanation=(
                    "Enabling xp_cmdshell turns on a dangerous SQL Server feature that allows operating-system command execution from SQL queries."
                ),
                confidence="high",
                investigate_next=(
                    "Determine who enabled xp_cmdshell, review whether it was used immediately afterward, and disable it if it was not explicitly required."
                ),
                event=first,
                user=principal or "unknown",
                source_ip=client_ip,
                evidence={
                    "sql_instance": instance,
                    "actor_user": principal or "unknown",
                    "client_ip": client_ip,
                    "option_name": "xp_cmdshell",
                    "old_value": "0",
                    "new_value": "1",
                    "show_advanced_options_enabled": show_advanced,
                    "collapsed_event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _mssql_xp_cmdshell_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 33205 or "mssql" not in (ev.provider or "").lower():
            continue
        payload = _embedded_eventdata_text(ev)
        if not payload:
            continue
        statement = _extract_sql_statement(payload)
        if not statement or "action_id:EX" not in payload or not XPCMDSHELL_RE.search(statement):
            continue
        principal = _extract_sql_principal(payload) or "unknown"
        client_ip = _extract_sql_client_ip(payload)
        key = (ev.computer or "unknown", principal.lower(), client_ip or "-")
        grouped[key].append(ev)

    for (host, principal_key, client_ip_key), cluster in grouped.items():
        first = cluster[0]
        payloads = [_embedded_eventdata_text(item) for item in cluster]
        statements = sorted({_extract_sql_statement(payload) for payload in payloads if _extract_sql_statement(payload)})
        principal = _extract_sql_principal(payloads[0]) or principal_key or "unknown"
        client_ip = _extract_sql_client_ip(payloads[0]) or ("" if client_ip_key == "-" else client_ip_key)
        alerts.append(
            Alert(
                rule_name="MSSQL xp_cmdshell Execution",
                severity="critical",
                mitre_tactic="Execution",
                mitre_technique="T1505.001",
                description=f"{principal} executed xp_cmdshell on {host}" + (f" from {client_ip}" if client_ip else ""),
                explanation=(
                    "SQL Audit execution records show xp_cmdshell running an operating-system command through SQL Server, which is high-confidence malicious or highly risky administration."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the SQL statement and spawned OS command, validate the client IP and SQL principal, and inspect whether the command led to persistence or lateral movement."
                ),
                event=first,
                user=principal,
                source_ip=client_ip,
                evidence={
                    "actor_user": principal,
                    "client_ip": client_ip,
                    "statements": statements[:10],
                    "statement": statements[0] if statements else "",
                    "sql_instance": first.provider,
                    "collapsed_event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _mssql_xp_cmdshell_execution_attempt(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 15281 or "mssql" not in (ev.provider or "").lower():
            continue
        payload = _embedded_eventdata_text(ev)
        if not payload or not XPCMDSHELL_RE.search(payload):
            continue
        key = ((ev.computer or "unknown").lower(), (ev.provider or "").lower(), ev.event_id)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="MSSQL xp_cmdshell Execution Attempt",
                severity="high",
                mitre_tactic="Execution",
                mitre_technique="T1505.001",
                description=f"An xp_cmdshell execution attempt was blocked on {ev.computer}",
                explanation=(
                    "SQL Server rejected an xp_cmdshell execution request, which still indicates an attempt to run operating-system commands through the database engine."
                ),
                confidence="high",
                investigate_next=(
                    "Identify the SQL login that attempted the command, review nearby SQL configuration changes, and determine whether the blocked attempt was part of a broader intrusion sequence."
                ),
                event=ev,
                user="unknown",
                evidence={
                    "raw_payload": re.sub(r"\s+", " ", payload)[:500],
                    "sql_instance": ev.provider,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _hosts_file_modified(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 11 or not _is_sysmon_event(ev):
            continue
        target = (ev.event_data.get("TargetFilename", "") or "").strip()
        if not target or not target.lower().endswith(r"\windows\system32\drivers\etc\hosts"):
            continue
        actor = ev.domain_user or ev.subject_domain_user or "unknown"
        process = ev.process_name or ev.event_data.get("Image", "") or "unknown"
        key = ((ev.computer or "unknown").lower(), target.lower(), process.lower(), actor.lower())
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="Hosts File Modified",
                severity="high",
                mitre_tactic="Impact",
                mitre_technique="T1565.001",
                description=f"{os.path.basename(process) or process} modified the hosts file on {ev.computer}",
                explanation="Changes to the Windows hosts file can redirect traffic, block security tooling, or manipulate name resolution for follow-on attacks.",
                confidence="medium",
                investigate_next="Review the new hosts file contents, identify which domains or IPs were added, and determine whether the editing process and user were expected.",
                event=ev,
                user=actor,
                process=process,
                evidence={
                    "target_file": target,
                    "process_name": process,
                    "actor_user": actor,
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _installutil_proxy_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)

    for ev in timed_events:
        if ev.event_id not in (4688, 1):
            continue
        if _basename(ev.process_name) != "installutil.exe":
            continue
        cmd = ev.command_line or ""
        cmd_l = cmd.lower()
        payload_path = _extract_payload_path(cmd)
        payload_l = payload_path.lower()
        user_controlled = any(
            marker in payload_l
            for marker in ("\\users\\", "\\programdata\\", "\\appdata\\", "\\temp\\", "\\desktop\\")
        )
        if "/u" not in cmd_l or not payload_path or not user_controlled:
            continue

        host = ev.computer or "unknown"
        actor = ev.domain_user or ev.subject_domain_user or ev.event_data.get("ParentUser", "") or "unknown"
        related_loads = [
            other
            for other in timed_events
            if other.event_id == 7
            and _is_sysmon_event(other)
            and (other.computer or "unknown") == host
            and _basename(other.process_name) == "installutil.exe"
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 120
            and "urlmon.dll" in (other.event_data.get("ImageLoaded", "") or "").lower()
        ]
        key = (host.lower(), actor.lower(), payload_l)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="InstallUtil Proxy Execution",
                severity="high",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1218.004",
                description=f"InstallUtil executed an untrusted payload on {host}: {payload_path}",
                explanation="InstallUtil.exe is a signed .NET utility that attackers abuse to proxy execution of user-controlled assemblies and binaries.",
                confidence="high",
                investigate_next="Inspect the supplied payload, recover any child processes or network activity, and confirm whether the binary was launched as part of approved administration.",
                event=ev,
                user=actor,
                process=ev.process_name,
                evidence={
                    "actor_user": actor,
                    "payload_path": payload_path,
                    "command_line": cmd[:300],
                    "parent_image": ev.parent_process,
                    "urlmon_loaded": bool(related_loads),
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _desktopimgdownldr_remote_download(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)

    for ev in timed_events:
        if ev.event_id not in (4688, 1):
            continue
        if _basename(ev.process_name) != "desktopimgdownldr.exe":
            continue
        cmd = ev.command_line or ""
        remote_url = _first_url(cmd)
        if not remote_url:
            continue

        host = ev.computer or "unknown"
        related_files = [
            other
            for other in timed_events
            if other.event_id == 11
            and _is_sysmon_event(other)
            and (other.computer or "unknown") == host
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 180
            and "lockscreenimage" in (other.event_data.get("TargetFilename", "") or "").lower()
        ]
        download_path = next(((other.event_data.get("TargetFilename", "") or "").strip() for other in related_files if (other.event_data.get("TargetFilename", "") or "").strip()), "")
        key = (host.lower(), remote_url.lower())
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="DesktopImgDownldr Remote Download",
                severity="high",
                mitre_tactic="Command and Control",
                mitre_technique="T1105",
                description=f"desktopimgdownldr.exe fetched remote content on {host}: {remote_url}",
                explanation="desktopimgdownldr.exe is a signed Windows binary that can be abused to download attacker-controlled content through the lock-screen personalization path.",
                confidence="high",
                investigate_next="Recover the downloaded file, inspect the remote host, and determine whether the downloaded content was subsequently executed or staged.",
                event=ev,
                process=ev.process_name,
                source_ip=remote_url,
                evidence={
                    "remote_url": remote_url,
                    "download_path": download_path,
                    "command_line": cmd[:300],
                    "event_name": "desktopimgdownldr",
                    "evidence_strength": "high" if download_path else "medium",
                },
            )
        )
    return alerts


def _temp_dotnet_compilation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1):
            continue
        proc = _basename(ev.process_name)
        cmd = ev.command_line or ""
        cmd_l = cmd.lower()
        is_psattack = proc == "psattack.exe"
        is_temp_compile = proc in DOTNET_TEMP_COMPILERS and "\\appdata\\local\\temp\\" in cmd_l and (
            ".cmdline" in cmd_l or "\\temp\\res" in cmd_l or "\\temp\\csc" in cmd_l
        )
        if not (is_psattack or is_temp_compile):
            continue

        actor = ev.domain_user or ev.subject_domain_user or "unknown"
        key = (ev.computer or "unknown", actor)
        clusters = grouped[key]
        if clusters and ev.timestamp - clusters[-1][-1].timestamp <= timedelta(minutes=15):
            clusters[-1].append(ev)
        else:
            clusters.append([ev])

    for (host, actor), clusters in grouped.items():
        for cluster in clusters:
            process_names = sorted({_basename(item.process_name) or "unknown" for item in cluster})
            if "psattack.exe" not in process_names and len(cluster) < 2:
                continue

            first_event = cluster[0]
            temp_commands = [item.command_line[:300] for item in cluster if item.command_line]
            alerts.append(
                Alert(
                    rule_name="Suspicious .NET Compilation from User Temp",
                    severity="critical" if "psattack.exe" in process_names else "high",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1127",
                    description=f"{actor} triggered temporary .NET compilation activity on {host}",
                    explanation=(
                        "Repeated csc.exe / cvtres.exe execution from a user's temporary directory, especially when paired with PSAttack.exe, "
                        "is consistent with staged payload compilation used by offensive PowerShell and post-exploitation tooling."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Recover the generated .cmdline and temporary compiler outputs, inspect the launching script or binary, "
                        "and determine whether the compilation produced a payload that executed afterward."
                    ),
                event=first_event,
                user=actor,
                process=first_event.process_name,
                evidence={
                    "actor_user": actor,
                    "processes": process_names,
                        "command_lines": temp_commands[:10],
                        "temp_compilation_count": len(cluster),
                        "psattack_present": "psattack.exe" in process_names,
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _uac_bypass_registry_hijack(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    seen = set()

    for ev in timed_events:
        if ev.event_id != 13 or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetObject", "") or "").lower()
        details = (ev.event_data.get("Details", "") or "").strip()
        if not target or not details:
            continue

        candidate_triggers = [
            binary
            for binary, matchers in AUTO_ELEVATE_TRIGGERS.items()
            if any(marker in target for marker in matchers["registry_markers"])
        ]
        if not candidate_triggers:
            continue

        actor = ev.domain_user or ev.subject_domain_user or ev.event_data.get("User", "") or "unknown"
        host = ev.computer or "unknown"
        window = [
            other
            for other in timed_events
            if other.event_id in (4688, 1)
            and (other.computer or "unknown") == host
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 180
        ]

        trigger_name = ""
        trigger_events = []
        spawned = []
        for candidate in candidate_triggers:
            current_trigger_events = []
            current_spawned = []
            for other in window:
                proc = _basename(other.process_name)
                parent = _basename(other.parent_process)
                cmd_l = (other.command_line or "").lower()
                registry_markers = AUTO_ELEVATE_TRIGGERS[candidate]["registry_markers"]
                marker_match = any(marker in target for marker in registry_markers)
                command_markers = AUTO_ELEVATE_TRIGGERS[candidate]["command_markers"]
                command_match = all(marker in cmd_l for marker in command_markers)
                if proc == candidate and (
                    command_match
                    or (candidate == "sdclt.exe" and marker_match and r"\app paths\control.exe\(default)" in target)
                ):
                    current_trigger_events.append(other)
                if parent == candidate and proc in UAC_BYPASS_CHILDREN:
                    current_spawned.append(other)
            if current_trigger_events or current_spawned:
                trigger_name = candidate
                trigger_events = current_trigger_events
                spawned = current_spawned
                break

        if not trigger_name or (not trigger_events and not spawned):
            continue

        first = trigger_events[0] if trigger_events else spawned[0]
        hijack_target = trigger_name.replace(".exe", "")
        key = (host, actor.lower(), target, details.lower(), hijack_target)
        if key in seen:
            continue
        seen.add(key)

        spawned_processes = [other.process_name for other in spawned if other.process_name]
        alerts.append(
            Alert(
                rule_name="UAC Bypass via Auto-Elevated Registry Hijack",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1548.002",
                description=f"{actor} hijacked {hijack_target} auto-elevation on {host} using a per-user registry override",
                explanation=(
                    "Per-user registry overrides for auto-elevated binaries such as sdclt.exe and eventvwr.exe are a well-known UAC bypass technique."
                ),
                confidence="high",
                investigate_next=(
                    f"Remove the hijacked registry value for {hijack_target}, inspect the payload command, and review whether the spawned child process executed with elevated rights."
                ),
                event=first,
                user=actor,
                process=first.process_name,
                parent_process=first.parent_process,
                evidence={
                    "actor_user": actor,
                    "registry_key": ev.event_data.get("TargetObject", ""),
                    "hijack_command": details[:400],
                    "trigger_binary": trigger_name,
                    "trigger_command_lines": [(item.command_line or "")[:300] for item in trigger_events],
                    "spawned_processes": spawned_processes,
                    "spawned_commands": [(item.command_line or "")[:300] for item in spawned if item.command_line],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _cmstp_uac_bypass(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    seen = set()

    for ev in timed_events:
        if ev.event_id != 13 or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetObject", "") or "").lower()
        details = (ev.event_data.get("Details", "") or "").strip()
        if CMSTP_PROFILEINSTALL_MARKER not in target or not details:
            continue

        host = ev.computer or "unknown"
        window = [
            other
            for other in timed_events
            if (other.computer or "unknown") == host
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 300
        ]

        cmstp_events = []
        spawned = []
        for other in window:
            if other.event_id not in (1, 4688):
                continue
            proc = _basename(other.process_name)
            parent = _basename(other.parent_process)
            cmd_l = (other.command_line or "").lower()
            if proc == "cmstp.exe" and "/au" in cmd_l and ".ini" in cmd_l:
                cmstp_events.append(other)
            if parent in {"dllhost.exe", "cmmgr32.exe"} and proc in {"cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe"}:
                spawned.append(other)

        if not cmstp_events or not spawned:
            continue

        actor = next(
            (
                item.domain_user
                or item.subject_domain_user
                or item.event_data.get("User", "")
                for item in cmstp_events + spawned
                if item.domain_user or item.subject_domain_user or item.event_data.get("User", "")
            ),
            "unknown",
        )
        key = (host, target, details.lower(), actor.lower(), spawned[0].process_name.lower())
        if key in seen:
            continue
        seen.add(key)

        first = cmstp_events[0]
        alerts.append(
            Alert(
                rule_name="CMSTP UAC Bypass",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1548.002",
                description=f"cmstp.exe abused cmmgr32 profile-install handling to spawn elevated activity on {host}",
                explanation=(
                    "CMSTP can abuse cmmgr32 profile installation paths to trigger elevated execution through COM and DllHost. "
                    "This sequence is a known UAC bypass pattern."
                ),
                confidence="high",
                investigate_next=(
                    "Review the temporary CMSTP INI file, inspect the profile-install path under App Paths\\cmmgr32.exe, "
                    "and determine whether the spawned shell executed with elevated rights."
                ),
                event=first,
                user=actor,
                process=first.process_name,
                parent_process=first.parent_process,
                registry_key=ev.event_data.get("TargetObject", ""),
                evidence={
                    "actor_user": actor,
                    "registry_key": ev.event_data.get("TargetObject", ""),
                    "profile_install_path": details,
                    "cmstp_commands": [(item.command_line or "")[:300] for item in cmstp_events if item.command_line],
                    "spawned_processes": [item.process_name for item in spawned if item.process_name],
                    "spawned_commands": [(item.command_line or "")[:300] for item in spawned if item.command_line],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _volatile_systemroot_uac_bypass(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    seen = set()

    for ev in timed_events:
        if ev.event_id != 13 or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetObject", "") or "").lower()
        details = (ev.event_data.get("Details", "") or "").strip()
        if VOLATILE_SYSTEMROOT_MARKER not in target:
            continue
        if not details or "\\appdata\\local\\temp" not in details.lower():
            continue

        host = ev.computer or "unknown"
        window = [
            other
            for other in timed_events
            if (other.computer or "unknown") == host
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 900
        ]

        perfmon_exec = []
        cleanup = []
        for other in window:
            if other.event_id in (1, 4688):
                proc = _basename(other.process_name)
                parent = _basename(other.parent_process)
                proc_l = (other.process_name or "").lower()
                if proc == "mmc.exe" and "\\temp\\system32\\mmc.exe" in proc_l and parent == "perfmon.exe":
                    perfmon_exec.append(other)
            elif other.event_id == 12 and _is_sysmon_event(other):
                if VOLATILE_SYSTEMROOT_MARKER in (other.event_data.get("TargetObject", "") or "").lower():
                    cleanup.append(other)

        if not perfmon_exec:
            continue

        actor = next(
            (
                item.domain_user
                or item.subject_domain_user
                or item.event_data.get("User", "")
                for item in perfmon_exec
                if item.domain_user or item.subject_domain_user or item.event_data.get("User", "")
            ),
            "unknown",
        )
        key = (host, details.lower(), perfmon_exec[0].process_name.lower())
        if key in seen:
            continue
        seen.add(key)

        first = perfmon_exec[0]
        alerts.append(
            Alert(
                rule_name="Volatile SYSTEMROOT UAC Bypass",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1548.002",
                description=f"Perfmon launched a temporary mmc.exe after SYSTEMROOT was redirected to a temp directory on {host}",
                explanation=(
                    "Redirecting HKU\\...\\Volatile Environment\\SYSTEMROOT to a user-controlled temp directory and then launching perfmon.exe "
                    "is a known UAC bypass technique that causes elevated MMC loading from the attacker-controlled path."
                ),
                confidence="high",
                investigate_next=(
                    "Inspect the temporary system32 directory, recover the dropped mmc.exe and related MSC content, and confirm whether the environment hijack executed with elevated rights."
                ),
                event=first,
                user=actor,
                process=first.process_name,
                parent_process=first.parent_process,
                registry_key=ev.event_data.get("TargetObject", ""),
                evidence={
                    "actor_user": actor,
                    "systemroot_key": ev.event_data.get("TargetObject", ""),
                    "redirected_systemroot": details,
                    "perfmon_processes": [item.process_name for item in perfmon_exec if item.process_name],
                    "perfmon_commands": [(item.command_line or "")[:300] for item in perfmon_exec if item.command_line],
                    "cleanup_observed": bool(cleanup),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _uac_bypass_dll_sideload(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    process_events = [item for item in timed_events if item.event_id in (1, 4688)]
    seen = set()

    for ev in timed_events:
        if ev.event_id != 7 or not _is_sysmon_event(ev):
            continue

        image = (ev.process_name or ev.event_data.get("Image", "") or "").strip()
        image_base = _basename(image)
        if image_base not in UAC_SIDELOAD_TARGETS:
            continue

        image_loaded = (ev.event_data.get("ImageLoaded", "") or "").strip()
        image_loaded_base = _basename(image_loaded)
        rule_name = (ev.event_data.get("RuleName", "") or "").lower()
        config = UAC_SIDELOAD_TARGETS[image_base]
        image_l = image.lower()
        if image_loaded_base not in config["dlls"] and "uac bypass" not in rule_name:
            continue
        if not any(path in image_l for path in config["paths"]):
            continue

        host = ev.computer or "unknown"
        launcher_events = [
            other
            for other in process_events
            if (other.computer or "unknown") == host
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 600
            and _basename(other.process_name) == image_base
        ]
        suspicious_launchers = [
            other
            for other in launcher_events
            if _basename(other.parent_process) in UAC_SUSPICIOUS_LAUNCHERS
        ]
        prep_events = [
            other
            for other in process_events
            if (other.computer or "unknown") == host
            and 0 <= (ev.timestamp - other.timestamp).total_seconds() <= 900
            and (
                (_basename(other.process_name) == "makecab.exe" and image_loaded_base in (other.command_line or "").lower())
                or (
                    _basename(other.process_name) == "wusa.exe"
                    and "/extract:" in (other.command_line or "").lower()
                    and any(path in (other.command_line or "").lower() for path in config["paths"])
                )
            )
        ]

        if not suspicious_launchers and not prep_events and "uac bypass" not in rule_name:
            continue

        actor = next(
            (
                item.domain_user
                or item.subject_domain_user
                or item.event_data.get("User", "")
                for item in suspicious_launchers + prep_events
                if item.domain_user or item.subject_domain_user or item.event_data.get("User", "")
            ),
            "unknown",
        )
        key = (host, image_base, image_loaded_base, actor.lower())
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="UAC Bypass via DLL Side-Loading",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1548.002",
                description=f"{image_base} loaded suspicious side-loaded content on {host}",
                explanation=(
                    "Known auto-elevated binaries such as sysprep.exe, Mcx2Prov.exe, migwiz.exe, and cliconfg.exe can be abused by placing attacker-controlled DLLs "
                    "where the elevated process will load them."
                ),
                confidence="high",
                investigate_next=(
                    f"Recover {image_loaded or image_loaded_base}, inspect any makecab/wusa preparation steps, and determine whether {image_base} ran under an elevated context."
                ),
                event=suspicious_launchers[0] if suspicious_launchers else ev,
                user=actor,
                process=image,
                parent_process=suspicious_launchers[0].parent_process if suspicious_launchers else "",
                evidence={
                    "actor_user": actor,
                    "target_binary": image,
                    "loaded_module": image_loaded,
                    "sysmon_rule_name": ev.event_data.get("RuleName", ""),
                    "launcher_commands": [(item.command_line or "")[:300] for item in suspicious_launchers if item.command_line],
                    "preparation_commands": [(item.command_line or "")[:300] for item in prep_events if item.command_line],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _wscript_manifest_uac_bypass(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    seen = set()

    for ev in timed_events:
        if ev.event_id != 11 or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetFilename", "") or "").strip()
        target_l = target.lower()
        if not target_l.endswith("wscript.exe.manifest"):
            continue

        host = ev.computer or "unknown"
        window = [
            other
            for other in timed_events
            if (other.computer or "unknown") == host
            and 0 <= (other.timestamp - ev.timestamp).total_seconds() <= 600
        ]
        wusa_events = []
        script_stagers = []
        for other in window:
            if other.event_id not in (1, 4688):
                continue
            proc = _basename(other.process_name)
            cmd_l = (other.command_line or "").lower()
            if proc == "wusa.exe" and "/extract:c:\\windows" in cmd_l:
                wusa_events.append(other)
            if proc == "cmd.exe" and ("echo dim objshell" in cmd_l or ".vbs" in cmd_l):
                script_stagers.append(other)

        if not wusa_events:
            continue

        actor = next(
            (
                item.domain_user
                or item.subject_domain_user
                or item.event_data.get("User", "")
                for item in wusa_events + script_stagers
                if item.domain_user or item.subject_domain_user or item.event_data.get("User", "")
            ),
            "unknown",
        )
        key = (host, target_l, actor.lower())
        if key in seen:
            continue
        seen.add(key)

        first = wusa_events[0]
        alerts.append(
            Alert(
                rule_name="WScript Manifest UAC Bypass",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1548.002",
                description=f"A temporary wscript.exe manifest was staged and extracted into C:\\Windows on {host}",
                explanation=(
                    "Dropping a crafted wscript.exe.manifest and extracting it into C:\\Windows with wusa.exe is a known way to abuse auto-elevation behavior for UAC bypass."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the manifest and staged script content, inspect the wusa extraction path, and review whether wscript.exe or child processes executed with elevated rights."
                ),
                event=first,
                user=actor,
                process=first.process_name,
                parent_process=first.parent_process,
                evidence={
                    "actor_user": actor,
                    "manifest_path": target,
                    "wusa_commands": [(item.command_line or "")[:300] for item in wusa_events if item.command_line],
                    "script_stager_commands": [(item.command_line or "")[:300] for item in script_stagers if item.command_line],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _service_account_to_system_impersonation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    process_events = [item for item in timed_events if item.event_id in (1, 4688)]
    seen = set()

    def _event_user_text(ev: NormalizedEvent) -> str:
        return (
            ev.domain_user
            or ev.subject_domain_user
            or ev.event_data.get("User", "")
            or ""
        ).strip()

    for ev in timed_events:
        if ev.event_id != 8 or not _is_sysmon_event(ev):
            continue

        src = (ev.event_data.get("SourceImage", "") or "").strip()
        tgt = (ev.event_data.get("TargetImage", "") or "").strip()
        if not src or not tgt:
            continue

        host = ev.computer or "unknown"
        src_base = _basename(src)
        tgt_base = _basename(tgt)
        prior_launches = [
            item
            for item in process_events
            if (item.computer or "unknown") == host
            and 0 <= (ev.timestamp - item.timestamp).total_seconds() <= 180
            and _basename(item.process_name) == tgt_base
            and _basename(item.parent_process) == src_base
            and any(marker in _event_user_text(item).lower() for marker in SERVICE_ACCOUNT_MARKERS)
        ]
        if not prior_launches:
            continue

        access_events = [
            item
            for item in timed_events
            if item.event_id == 10
            and (item.computer or "unknown") == host
            and 0 <= (ev.timestamp - item.timestamp).total_seconds() <= 60
            and _basename(item.event_data.get("SourceImage", "")) == src_base
            and _basename(item.event_data.get("TargetImage", "")) == tgt_base
        ]
        system_followup = next(
            (
                item
                for item in process_events
                if (item.computer or "unknown") == host
                and 0 <= (item.timestamp - ev.timestamp).total_seconds() <= 300
                and _basename(item.process_name) == tgt_base
                and "system" in _event_user_text(item).lower()
            ),
            None,
        )
        if not system_followup:
            continue

        service_actor = _event_user_text(prior_launches[0]) or "unknown"
        system_actor = _event_user_text(system_followup) or "NT AUTHORITY\\SYSTEM"
        key = (host, src.lower(), tgt.lower(), service_actor.lower(), system_actor.lower())
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="Service Account to SYSTEM Impersonation",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1134.001",
                description=f"{service_actor} escalated from {src_base} into SYSTEM via {tgt_base} on {host}",
                explanation=(
                    "A service-context process launched a target binary, injected a remote thread into it, and a SYSTEM instance of the same target appeared shortly after. "
                    "This pattern is consistent with Potato-style impersonation and token-theft privilege escalation."
                ),
                confidence="high",
                investigate_next=(
                    "Inspect the service account process tree, recover the injected target binary and any follow-on commands, "
                    "and verify whether SeImpersonatePrivilege abuse or a Potato-style exploit was used to obtain SYSTEM."
                ),
                event=system_followup,
                user=service_actor,
                subject_user=service_actor,
                target_user=system_actor,
                process=system_followup.process_name,
                parent_process=system_followup.parent_process,
                evidence={
                    "service_account": service_actor,
                    "elevated_user": system_actor,
                    "source_image": src,
                    "target_image": tgt,
                    "thread_injection_timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                    "process_access_count": len(access_events),
                    "initial_launch_timestamp": prior_launches[0].timestamp.isoformat() if prior_launches[0].timestamp else None,
                    "system_followup_timestamp": system_followup.timestamp.isoformat() if system_followup.timestamp else None,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _office_vba_object_model_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in events:
        if ev.event_id != 13 or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetObject", "") or "").strip()
        details = (ev.event_data.get("Details", "") or "").strip().lower()
        lowered = target.lower()
        if "\\software\\microsoft\\office\\" not in lowered:
            continue
        if r"\security\accessvbom" not in lowered:
            continue
        if details not in {"1", "dword (0x00000001)", "0x00000001"} and "0x00000001" not in details:
            continue

        actor = ev.domain_user or ev.subject_domain_user or ev.event_data.get("User", "") or "unknown"
        office_app = "office"
        for app in ("excel", "word", "powerpoint", "access", "outlook"):
            if f"\\{app}\\security\\accessvbom" in lowered:
                office_app = app
                break
        key = (ev.computer or "unknown", lowered, actor.lower())
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="Office VBA Object Model Access Enabled",
                severity="high",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1112",
                description=f"{actor} enabled AccessVBOM for {office_app.title()} on {ev.computer}",
                explanation=(
                    "Enabling AccessVBOM weakens Office macro protections and allows VBA to interact with the project object model, "
                    "which is commonly changed to facilitate malicious macro staging or tampering."
                ),
                confidence="high",
                investigate_next="Review nearby Office macro activity, inspect who changed the registry value, and determine whether macro security settings were weakened for execution or persistence.",
                event=ev,
                user=actor,
                process=ev.process_name,
                registry_key=target,
                evidence={
                    "actor_user": actor,
                    "office_app": office_app,
                    "registry_key": target,
                    "details": ev.event_data.get("Details", ""),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _potato_named_pipe_impersonation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)

    for ev in timed_events:
        if ev.event_id != 1 or not _is_sysmon_event(ev):
            continue

        process_image = (ev.process_name or ev.event_data.get("Image", "") or "").strip()
        command_line = (ev.command_line or ev.event_data.get("CommandLine", "") or "").strip()
        if "potato" not in process_image.lower() and "potato" not in command_line.lower():
            continue

        host = ev.computer or "unknown"
        proc_base = _basename(process_image)
        pipe_creates = [
            item
            for item in timed_events
            if item.event_id == 17
            and _is_sysmon_event(item)
            and (item.computer or "unknown") == host
            and 0 <= (item.timestamp - ev.timestamp).total_seconds() <= 60
            and _basename(item.process_name) == proc_base
            and (
                POTATO_PIPE_RE.match((item.event_data.get("PipeName", "") or "").strip())
                or ROGUE_POTATO_PIPE_RE.match((item.event_data.get("PipeName", "") or "").strip())
            )
        ]
        if not pipe_creates:
            continue

        for pipe_create in pipe_creates:
            pipe_name = (pipe_create.event_data.get("PipeName", "") or "").strip()
            rule_name = (pipe_create.event_data.get("RuleName", "") or "").strip().lower()
            variant = (
                "rogue_epmapper"
                if ROGUE_POTATO_PIPE_RE.match(pipe_name) or ("roguepotato" in rule_name and "epmapper" in rule_name)
                else "guid_srvsvc"
            )
            window = [
                item
                for item in timed_events
                if (item.computer or "unknown") == host and 0 <= (item.timestamp - pipe_create.timestamp).total_seconds() <= 120
            ]
            system_pipe_connects = [
                item
                for item in window
                if item.event_id == 18
                and _is_sysmon_event(item)
                and _basename(item.process_name) == "system"
                and (item.event_data.get("PipeName", "") or "").strip().lower() == pipe_name.lower()
            ]
            lsass_pipe_connects = [
                item
                for item in window
                if item.event_id == 18
                and _is_sysmon_event(item)
                and _basename(item.process_name) == "system"
                and (item.event_data.get("PipeName", "") or "").strip().lower() == r"\lsass"
            ]
            loopback_network = [
                item
                for item in window
                if item.event_id == 3
                and _is_sysmon_event(item)
                and _basename(item.process_name) == "system"
                and (item.source_ip or "") in LOOPBACK_IPS
                and (item.destination_ip or "") in LOOPBACK_IPS
            ]
            direct_children = [
                item
                for item in window
                if item.event_id == 1
                and _is_sysmon_event(item)
                and _basename(item.parent_process) == proc_base
                and (item.process_name or "").lower() != process_image.lower()
            ]
            child_basenames = {_basename(item.process_name) for item in direct_children if item.process_name}
            descendant_children = [
                item
                for item in window
                if item.event_id == 1
                and _is_sysmon_event(item)
                and _basename(item.parent_process) in child_basenames
                and (item.process_name or "").lower() != process_image.lower()
            ]
            child_processes = direct_children + [
                item for item in descendant_children if item not in direct_children
            ]
            if not system_pipe_connects:
                continue
            if variant == "guid_srvsvc" and not lsass_pipe_connects:
                continue
            if variant == "rogue_epmapper" and not child_processes:
                continue

            child_images = sorted({item.process_name for item in child_processes if item.process_name})
            key = (host.lower(), process_image.lower(), pipe_name.lower())
            if key in seen:
                continue
            seen.add(key)

            if variant == "rogue_epmapper":
                description = f"{process_image} staged a RoguePotato epmapper pipe and SYSTEM consumed it on {host}"
                explanation = (
                    "A Potato-family process created the RoguePotato epmapper named pipe, SYSTEM connected back to that "
                    "pipe, and SYSTEM child-process execution followed. This is strong evidence of named-pipe token "
                    "impersonation used to obtain SYSTEM."
                )
            else:
                description = f"{process_image} staged a rogue srvsvc named pipe and SYSTEM consumed it on {host}"
                explanation = (
                    "A Potato-family process created a GUID-based srvsvc named pipe, SYSTEM connected back to that same "
                    "pipe and to \\\\lsass, and local loopback/child-process activity followed. This is strong evidence of "
                    "named-pipe token impersonation used to obtain SYSTEM."
                )

            alerts.append(
                Alert(
                    rule_name="Potato-Style Named Pipe Impersonation",
                    severity="critical",
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1134.001",
                    description=description,
                    explanation=explanation,
                    confidence="high",
                    investigate_next=(
                        "Preserve the Potato-family binary, inspect nearby child processes and loopback traffic, and verify "
                        "whether SeImpersonatePrivilege abuse led to SYSTEM execution on the affected host."
                    ),
                    event=ev,
                    user=_event_actor(ev),
                    process=process_image,
                    parent_process=ev.parent_process,
                    source_ip=loopback_network[0].source_ip if loopback_network else "",
                    evidence={
                        "process_image": process_image,
                        "command_line": command_line,
                        "pipe_name": pipe_name,
                        "detection_variant": variant,
                        "system_pipe_connect_count": len(system_pipe_connects),
                        "lsass_pipe_connect_count": len(lsass_pipe_connects),
                        "loopback_network_count": len(loopback_network),
                        "child_processes": child_images,
                        "evidence_strength": "high",
                    },
                )
            )
            break

    return alerts


def _ftp_script_command_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in events:
        if ev.event_id not in (1, 4688):
            continue

        parent = _basename(ev.parent_process)
        child = _basename(ev.process_name)
        cmd = (ev.command_line or "").strip()
        if parent != "ftp.exe":
            continue
        if child not in {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
            continue

        actor = ev.domain_user or ev.subject_domain_user or ev.event_data.get("User", "") or "unknown"
        key = (ev.computer or "unknown", actor.lower(), child, cmd.lower())
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="FTP Script Command Execution",
                severity="high",
                mitre_tactic="Execution",
                mitre_technique="T1202",
                description=f"ftp.exe spawned {child} for local command execution on {ev.computer}",
                explanation=(
                    "ftp.exe script files can proxy local command execution through the ! command and similar script-driven behavior. "
                    "A shell or script interpreter launched directly from ftp.exe is strongly suspicious."
                ),
                confidence="high",
                investigate_next="Review the ftp script file or prior command history, inspect what local commands were executed, and determine whether the LOLBin was used to bypass execution controls.",
                event=ev,
                user=actor,
                process=ev.process_name,
                parent_process=ev.parent_process,
                evidence={
                    "actor_user": actor,
                    "parent_process": ev.parent_process,
                    "child_process": ev.process_name,
                    "command_line": cmd[:400],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _msiexec_proxy_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    process_events = sorted(
        (item for item in events if item.timestamp and item.event_id in (4688, 1)),
        key=lambda item: item.timestamp,
    )
    registry_events = [
        item
        for item in events
        if item.timestamp and item.event_id == 13 and _is_sysmon_event(item)
    ]
    seen = set()

    for ev in process_events:
        image = (ev.process_name or "").strip()
        image_l = image.lower()
        if not MSI_TEMP_RE.search(image_l):
            continue
        if _basename(ev.parent_process) != "msiexec.exe":
            continue

        host = ev.computer or "unknown"
        actor = ev.domain_user or ev.subject_domain_user or ev.event_data.get("User", "") or "unknown"
        logon_id = ev.event_data.get("LogonId", "") or ""
        child_events = [
            other
            for other in process_events
            if (other.computer or "unknown") == host
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 300
            and (
                _basename(other.parent_process) == _basename(ev.process_name)
                or (
                    logon_id
                    and (other.event_data.get("LogonId", "") or "") == logon_id
                    and _basename(other.process_name) in {"cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe"}
                )
            )
        ]
        if not child_events:
            continue

        installer_state = [
            item
            for item in registry_events
            if (item.computer or "unknown") == host
            and abs((item.timestamp - ev.timestamp).total_seconds()) <= 120
            and _basename(item.process_name) == "msiexec.exe"
            and "\\installer\\inprogress\\" in (item.event_data.get("TargetObject", "") or "").lower()
        ]

        key = (host, image_l, actor.lower(), child_events[0].process_name.lower())
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="Msiexec Package Proxy Execution",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1218.007",
                description=f"msiexec launched a temporary installer payload that spawned shell activity on {host}",
                explanation=(
                    "Temporary binaries dropped under C:\\Windows\\Installer and launched by msiexec.exe are consistent with malicious MSI package execution used as signed-binary proxy execution."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the MSI package and temporary installer binary, inspect the parent msiexec command line, and review spawned shell activity for payload execution."
                ),
                event=ev,
                user=actor,
                process=ev.process_name,
                parent_process=ev.parent_process,
                evidence={
                    "actor_user": actor,
                    "temp_installer": image,
                    "parent_command_line": ev.event_data.get("ParentCommandLine", ""),
                    "spawned_processes": [item.process_name for item in child_events if item.process_name],
                    "spawned_commands": [(item.command_line or "")[:300] for item in child_events if item.command_line],
                    "installer_state_files": [item.event_data.get("Details", "") for item in installer_state if item.event_data.get("Details", "")],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _windows_defender_service_tamper(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[tuple[str, str], List[NormalizedEvent]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1):
            continue

        cmd = ev.command_line or ""
        cmd_l = cmd.lower()
        if "windefend" not in cmd_l or ("sc " not in cmd_l and "sc.exe" not in cmd_l):
            continue
        if not any(marker in cmd_l for marker in (" stop ", " config ", "start=disabled", " start= disabled")):
            continue

        actor = ev.domain_user or ev.subject_domain_user or ev.event_data.get("User", "") or "unknown"
        key = (ev.computer or "unknown", actor)
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1].timestamp <= timedelta(minutes=5):
            existing.append(ev)
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}")] = [ev]
        else:
            grouped[key] = [ev]

    for (_, actor_key), cluster in grouped.items():
        actor = actor_key.split("::", 1)[0]
        first_event = cluster[0]
        commands = [item.command_line[:300] for item in cluster if item.command_line]
        actions = sorted(
            {
                action
                for item in cluster
                for action in ("stop", "disable", "query")
                if (action != "disable" and f" {action} " in (item.command_line or "").lower())
                or (action == "disable" and "start=disabled" in (item.command_line or "").lower())
            }
        )
        alerts.append(
            Alert(
                rule_name="Windows Defender Service Tampering",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.001",
                description=f"{actor} tampered with the WinDefend service on {first_event.computer}",
                explanation=(
                    "Stopping or disabling the WinDefend service through sc.exe is a direct attempt to tamper with Microsoft Defender "
                    "before follow-on payload execution."
                ),
                confidence="high",
                investigate_next=(
                    "Confirm whether WinDefend was stopped or disabled successfully, restore the service configuration, and review adjacent commands for payload delivery."
                ),
                event=first_event,
                user=actor,
                process=first_event.process_name,
                evidence={
                    "actor_user": actor,
                    "service_name": "WinDefend",
                    "actions": actions,
                    "command_lines": commands[:5],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _suspicious_firewall_rule_creation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[tuple[str, str, str], List[NormalizedEvent]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1, 4104):
            continue

        command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        command_l = command.lower()
        if "new-netfirewallrule" not in command_l and "netsh advfirewall firewall add rule" not in command_l:
            continue
        if "allow" not in command_l or ("inbound" not in command_l and "dir=in" not in command_l):
            continue
        if "-localport" not in command_l and "localport=" not in command_l:
            continue

        display_match = FIREWALL_DISPLAY_RE.search(command)
        port_match = FIREWALL_PORT_RE.search(command)
        display_name = (display_match.group(1) or "").strip() if display_match else "unnamed firewall rule"
        port = (port_match.group(1) or "").strip() if port_match else "unknown"
        key = (ev.computer or "unknown", display_name.lower(), port)
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1].timestamp <= timedelta(minutes=15):
            existing.append(ev)
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}", key[2])] = [ev]
        else:
            grouped[key] = [ev]

    for (_, display_key, port), cluster in grouped.items():
        first_event = cluster[0]
        actor = first_event.domain_user or first_event.subject_domain_user or first_event.event_data.get("User", "") or "unknown"
        display_name = display_key.split("::", 1)[0]
        parent = _basename(first_event.parent_process)
        evidence_strength = "high" if parent in {"wsmprovhost.exe", "winrshost.exe"} else "medium"
        alerts.append(
            Alert(
                rule_name="Windows Firewall Rule Added",
                severity="high",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.004",
                description=f"{actor} added inbound firewall rule '{display_name}' on {first_event.computer} for port {port}",
                explanation=(
                    "Creating a new inbound allow rule exposes a local service or payload to the network and is a common precursor to remote access or defense impairment."
                ),
                confidence=evidence_strength,
                investigate_next=(
                    "Verify whether the firewall exception was approved, identify what service listens on the opened port, and review how the rule was delivered."
                ),
                event=first_event,
                user=actor,
                process=first_event.process_name,
                parent_process=first_event.parent_process,
                evidence={
                    "actor_user": actor,
                    "display_name": display_name,
                    "local_port": port,
                    "parent_process": first_event.parent_process,
                    "command_lines": [item.command_line[:300] for item in cluster if item.command_line][:5],
                    "evidence_strength": evidence_strength,
                },
            )
        )

    return alerts


def _sip_trust_provider_registration(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[tuple[str, str], List[NormalizedEvent]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1):
            continue

        proc = _basename(ev.process_name)
        cmd = ev.command_line or ""
        cmd_l = cmd.lower()
        if proc != "regsvr32.exe" and "regsvr32" not in cmd_l:
            continue

        dll_path = _extract_first_dll_path(cmd)
        dll_name = _basename(dll_path)
        if not dll_path:
            continue
        if not any(marker in dll_name for marker in ("sip", "trustprovider")) and "cryptsip" not in cmd_l and "gtsipprovider" not in cmd_l:
            continue
        if not any(marker in dll_path.lower() for marker in ("\\users\\", "\\programdata\\", "\\temp\\")):
            continue

        key = (ev.computer or "unknown", dll_path.lower())
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1].timestamp <= timedelta(minutes=15):
            existing.append(ev)
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}")] = [ev]
        else:
            grouped[key] = [ev]

    for (_, dll_key), cluster in grouped.items():
        first_event = cluster[0]
        actor = first_event.domain_user or first_event.subject_domain_user or first_event.event_data.get("User", "") or "unknown"
        dll_path = dll_key.split("::", 1)[0]
        alerts.append(
            Alert(
                rule_name="SIP Trust Provider Registration",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1553.003",
                description=f"{actor} registered SIP provider DLL {dll_path} on {first_event.computer}",
                explanation=(
                    "Registering a user-controlled SIP or trust-provider DLL with regsvr32 can subvert Windows trust verification "
                    "and redirect signed-file validation through attacker code."
                ),
                confidence="high",
                investigate_next=(
                    "Inspect the registered DLL, confirm whether any trust-provider registration changed, and review follow-on signed-binary validation activity."
                ),
                event=first_event,
                user=actor,
                process=first_event.process_name,
                evidence={
                    "actor_user": actor,
                    "dll_path": dll_path,
                    "command_lines": [item.command_line[:300] for item in cluster if item.command_line][:5],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _check(ev: NormalizedEvent) -> List[Alert]:
    alerts = []
    ed = ev.event_data

    if ev.event_id in (4688, 1):
        cmd = ev.command_line or ""
        cmd_l = cmd.lower()
        proc = _basename(ev.process_name)

        if proc == "mshta.exe":
            remote_url = _first_url(cmd)
            cached_hta = any(marker in cmd_l for marker in ("temporary internet files", ".hta"))
            inline_script = any(marker in cmd_l for marker in ("vbscript:", "javascript:"))
            if remote_url or cached_hta or inline_script:
                alerts.append(Alert(
                    rule_name="MSHTA HTA Execution", severity="critical" if (remote_url or inline_script) else "high",
                    mitre_tactic="Defense Evasion", mitre_technique="T1218.005",
                    description=f"mshta.exe executed HTML application content on {ev.computer}: {cmd[:200]}",
                    explanation="mshta.exe is frequently abused to execute remote or cached HTA content as a signed Microsoft proxy binary.",
                    confidence="high",
                    investigate_next="Recover the HTA content, inspect the parent process or browser source, and review any child processes launched by mshta.exe.",
                    event=ev,
                    process=ev.process_name,
                    parent_process=ev.parent_process,
                    evidence={
                        "command_line": cmd[:500],
                        "remote_url": remote_url,
                        "cached_hta": cached_hta,
                        "inline_script": inline_script,
                        "evidence_strength": "high",
                    },
                ))
                return alerts

        if proc == "regsvr32.exe":
            scriptlet_target = _extract_regsvr32_target(cmd)
            if "scrobj.dll" in cmd_l and (scriptlet_target or ".sct" in cmd_l):
                alerts.append(Alert(
                    rule_name="Regsvr32 Scriptlet Execution", severity="critical",
                    mitre_tactic="Defense Evasion", mitre_technique="T1218.010",
                    description=f"regsvr32.exe executed a scriptlet on {ev.computer}: {scriptlet_target or cmd[:180]}",
                    explanation="regsvr32.exe with scrobj.dll and /i: is a classic signed-binary proxy execution pattern used to fetch or execute SCT scriptlets.",
                    confidence="high",
                    investigate_next="Retrieve the scriptlet target, determine whether it was remote or local, and inspect follow-on child processes or network connections.",
                    event=ev,
                    process=ev.process_name,
                    parent_process=ev.parent_process,
                    evidence={
                        "command_line": cmd[:500],
                        "scriptlet_target": scriptlet_target,
                        "remote_url": scriptlet_target if scriptlet_target.lower().startswith(("http://", "https://")) else "",
                        "evidence_strength": "high",
                    },
                ))
                return alerts

        if proc == "rundll32.exe":
            proxy_markers = (
                "url.dll,openurl",
                "url.dll,fileprotocolhandler",
                "ieframe.dll,openurl",
                "shdocvw.dll,openurl",
                "zipfldr.dll,routethecall",
                "advpack.dll,registerocx",
                "mshtml,runhtmlapplication",
            )
            matched = next((marker for marker in proxy_markers if marker in cmd_l), "")
            if matched:
                target = ""
                if "," in cmd:
                    target = cmd.split(",", 1)[1].strip()
                alerts.append(Alert(
                    rule_name="Rundll32 Proxy Execution", severity="high",
                    mitre_tactic="Defense Evasion", mitre_technique="T1218.011",
                    description=f"rundll32.exe invoked {matched} on {ev.computer}: {cmd[:200]}",
                    explanation="rundll32.exe can proxy execution of URLs, files, or COM-style handlers through signed DLL exports, which attackers abuse to evade controls.",
                    confidence="high",
                    investigate_next="Inspect the DLL export and target passed to rundll32.exe, then review the spawned child process and payload location.",
                    event=ev,
                    process=ev.process_name,
                    parent_process=ev.parent_process,
                    evidence={
                        "command_line": cmd[:500],
                        "proxy_marker": matched,
                        "target": target[:300],
                        "evidence_strength": "high",
                    },
                ))
                return alerts

        if proc == "wmic.exe" and "/format:" in cmd_l and (".xsl" in cmd_l or "http://" in cmd_l or "https://" in cmd_l):
            remote_url = _first_url(cmd)
            alerts.append(Alert(
                rule_name="WMIC XSL Script Processing", severity="critical" if remote_url else "high",
                mitre_tactic="Defense Evasion", mitre_technique="T1220",
                description=f"wmic.exe processed an XSL script on {ev.computer}: {cmd[:200]}",
                explanation="WMIC can load local or remote XSL stylesheets and is commonly abused to execute script content through XSL script processing.",
                confidence="high",
                investigate_next="Recover the XSL resource, inspect any network retrieval tied to the command, and review child processes spawned by WMIC.",
                event=ev,
                process=ev.process_name,
                parent_process=ev.parent_process,
                evidence={
                    "command_line": cmd[:500],
                    "remote_url": remote_url,
                    "xsl_processing": True,
                    "evidence_strength": "high",
                },
            ))
            return alerts

        if proc == "certutil.exe":
            remote_url = _first_url(cmd)
            if "-urlcache" in cmd_l and remote_url:
                alerts.append(Alert(
                    rule_name="Certutil Remote Download", severity="high",
                    mitre_tactic="Command and Control", mitre_technique="T1105",
                    description=f"certutil.exe downloaded remote content on {ev.computer}: {remote_url}",
                    explanation="certutil.exe is frequently abused as a living-off-the-land binary to download payloads from remote locations.",
                    confidence="high",
                    investigate_next="Retrieve the downloaded file, inspect the output path and follow-on execution, and determine whether the remote host is trusted.",
                    event=ev,
                    process=ev.process_name,
                    parent_process=ev.parent_process,
                    evidence={
                        "command_line": cmd[:500],
                        "remote_url": remote_url,
                        "evidence_strength": "high",
                    },
                ))
                return alerts
            if "-decode" in cmd_l or "-decodehex" in cmd_l:
                alerts.append(Alert(
                    rule_name="Certutil Decode Utility", severity="high",
                    mitre_tactic="Defense Evasion", mitre_technique="T1140",
                    description=f"certutil.exe decoded content on {ev.computer}: {cmd[:200]}",
                    explanation="certutil.exe is commonly abused to decode payloads or transform content into an executable form before execution.",
                    confidence="medium",
                    investigate_next="Inspect the source and destination files, recover the decoded payload, and determine whether it was executed afterward.",
                    event=ev,
                    process=ev.process_name,
                    parent_process=ev.parent_process,
                    evidence={"command_line": cmd[:500], "evidence_strength": "medium"},
                ))
                return alerts

    if ev.event_id == 1102:
        user = (ed.get("SubjectUserName", "") or ev.subject_user or ed.get("param1", "") or "(unknown)")
        domain = ed.get("SubjectDomainName", "") or ev.subject_domain or ""
        if domain and domain != "-":
            user = f"{domain}\\{user}"
        alerts.append(Alert(
            rule_name="Audit Log Cleared", severity="critical",
            mitre_tactic="Defense Evasion", mitre_technique="T1070.001",
            description=f"Security log cleared by {user} on {ev.computer}",
            explanation="Clearing the security log destroys forensic evidence. This is a strong indicator the attacker is covering their tracks.",
            confidence="high",
            investigate_next=f"Identify {user} and whether this was authorized. Check other log sources (Sysmon, PowerShell) that may not have been cleared. Examine events immediately before the clear.",
            event=ev, evidence={"user": user, "evidence_strength": "high"},
        ))

    if ev.event_id == 7040:
        service_name = (ed.get("ServiceName", "") or ed.get("param1", "") or "").strip()
        service_key = (ed.get("param4", "") or service_name).strip().lower()
        previous_state = (ed.get("param2", "") or "").strip()
        new_state = (ed.get("param3", "") or "").strip()
        if service_key in EVENTLOG_SERVICE_NAMES or service_name.lower() in EVENTLOG_SERVICE_NAMES:
            new_state_l = new_state.lower()
            if any(token in new_state_l for token in ("disabled", "manual", "demand start")):
                rule_name = "Windows Event Log Service Disabled" if "disabled" in new_state_l else "Windows Event Log Service Reconfigured"
                alerts.append(
                    Alert(
                        rule_name=rule_name,
                        severity="critical" if "disabled" in new_state_l else "high",
                        mitre_tactic="Defense Evasion",
                        mitre_technique="T1562.001",
                        description=f"Windows Event Log service startup changed from {previous_state or 'unknown'} to {new_state or 'unknown'} on {ev.computer}",
                        explanation=(
                            "Changing the Windows Event Log service startup mode can suppress future logging and is a strong sign of anti-forensics or log tampering."
                        ),
                        confidence="high",
                        investigate_next=(
                            "Confirm whether the service change was authorized, re-enable Windows Event Log if it was disabled, "
                            "and review adjacent service-control and log-clearing events for attacker cleanup."
                        ),
                        event=ev,
                        service=service_name or "Windows Event Log",
                        evidence={
                            "service_name": service_name or "Windows Event Log",
                            "previous_start_type": previous_state,
                            "new_start_type": new_state,
                            "evidence_strength": "high",
                        },
                    )
                )

    if ev.event_id == 2:
        if not _is_sysmon_event(ev):
            return alerts
        target = ed.get("TargetFilename", "")
        process = ed.get("Image", "") or ev.process_name
        previous_creation = ed.get("PreviousCreationUtcTime", "")
        current_creation = ed.get("CreationUtcTime", "")
        if not target or not process or not (previous_creation or current_creation):
            return alerts
        alerts.append(Alert(
            rule_name="Timestomping", severity="high",
            mitre_tactic="Defense Evasion", mitre_technique="T1070.006",
            description=f"File timestamp changed on {ev.computer}: {target} by {os.path.basename(process)}",
            explanation="Modifying file timestamps hides when malware was actually dropped.",
            confidence="high",
            investigate_next=f"Check the actual creation time vs modified time of '{target}'. Examine what process ({process}) changed it.",
            event=ev,
            evidence={
                "file": target,
                "process": process,
                "previous_creation": previous_creation,
                "current_creation": current_creation,
                "evidence_strength": "high",
            },
        ))

    if ev.event_id in (5001, 5010, 5012):
        desc_map = {5001: "Real-time protection disabled", 5010: "Scanning disabled", 5012: "Virus scanning disabled"}
        alerts.append(Alert(
            rule_name="Security Software Disabled", severity="critical",
            mitre_tactic="Defense Evasion", mitre_technique="T1562.001",
            description=f"{desc_map.get(ev.event_id, 'Defender disabled')} on {ev.computer}",
            explanation="Disabling security software allows malware to execute undetected.",
            confidence="high",
            investigate_next="Check if this was done by policy (GPO) or manually. Re-enable protection immediately. Scan the host for malware.",
            event=ev,
            evidence={"evidence_strength": "high"},
        ))

    if ev.event_id == 25:
        if not _is_sysmon_event(ev):
            return alerts
        image = ed.get("Image", "")
        ttype = ed.get("Type", "")
        if not image or not ttype:
            return alerts
        alerts.append(Alert(
            rule_name="Process Tampering", severity="critical",
            mitre_tactic="Defense Evasion", mitre_technique="T1055",
            description=f"Process tampering ({ttype}) on {ev.computer}: {image}",
            explanation="Process hollowing or herpaderping replaces legitimate process memory with malicious code to evade detection.",
            confidence="high",
            investigate_next=f"Analyze the process {image}. Check its hash against known good. Memory forensics may be needed.",
            event=ev, evidence={"image": image, "type": ttype, "evidence_strength": "high"},
        ))

    if ev.event_id == 4104:
        script = (ed.get("ScriptBlockText", "") or "").lower()
        for pat in ["amsiutils", "amsiscanbuffer", "amsicontext", "amsiinitfailed"]:
            if pat in script:
                alerts.append(Alert(
                    rule_name="AMSI Bypass", severity="critical",
                    mitre_tactic="Defense Evasion", mitre_technique="T1562.001",
                    description=f"AMSI bypass pattern '{pat}' in PowerShell on {ev.computer}",
                    explanation="AMSI bypass disables script scanning, allowing malicious PowerShell to execute without detection.",
                    confidence="high",
                    investigate_next="Review the full script block (Event 4104). Check what was executed after the bypass. The bypass is always followed by the actual payload.",
                    event=ev, evidence={"pattern": pat, "script_snippet": script[:300], "evidence_strength": "high"},
                ))
                break

    if ev.event_id == 8:
        src = ed.get("SourceImage", "")
        tgt = ed.get("TargetImage", "")
        if not src or not tgt:
            return alerts
        if _is_benign_csrss_control_routine(ev):
            return alerts
        alerts.append(Alert(
            rule_name="Remote Thread Injection", severity="high",
            mitre_tactic="Defense Evasion", mitre_technique="T1055.003",
            description=f"Injection on {ev.computer}: {os.path.basename(src)} -> {os.path.basename(tgt)}",
            explanation="Remote thread creation injects code into another process to evade detection or steal data.",
            confidence="medium",
            investigate_next=f"Check if {src} is legitimate. Check if {tgt} is a security-sensitive process. Look for anomalous behavior from {tgt} after injection.",
            event=ev, evidence={"source": src, "target": tgt, "evidence_strength": "medium"},
        ))

    if ev.event_id == 4616:
        user = (ev.subject_user or "").lower().strip()
        if user not in ("local service", "network service", ""):
            actor = ev.domain_user or "unknown"
            process = ev.process_name or "unknown"
            is_machine_context = user.endswith("$")
            alerts.append(Alert(
                rule_name="System Time Changed", severity="medium" if is_machine_context else "high",
                mitre_tactic="Defense Evasion", mitre_technique="T1070.006",
                description=f"Time changed by {actor} on {ev.computer} via {os.path.basename(process)}",
                explanation="Manually changing system time disrupts log timeline analysis.",
                confidence="low" if is_machine_context else "medium",
                investigate_next="Check if this correlates with known maintenance. Review what happened around the original and modified timestamps.",
                event=ev, evidence={"user": actor, "process": process, "evidence_strength": "low" if is_machine_context else "medium"},
            ))

    if ev.event_id == 4719:
        alerts.append(Alert(
            rule_name="Audit Policy Changed", severity="high",
            mitre_tactic="Defense Evasion", mitre_technique="T1562.002",
            description=f"Audit policy modified by {ev.domain_user or 'unknown'} on {ev.computer}",
            explanation="Attackers modify audit policies to stop generating evidence of their activity.",
            confidence="medium",
            investigate_next=f"Compare current audit policy to the baseline. Check if {ev.domain_user or 'unknown'} is authorized to change auditing.",
            event=ev, evidence={"user": ev.domain_user, "evidence_strength": "medium"},
        ))

    if ev.event_id in (4688, 1, 4104):
        cmd = ev.command_line.lower()
        if not cmd:
            return alerts
        patterns = [
            (r"(powershell|pwsh).*(?:-|/)(?:e|enc|encodedcommand)\b", "PowerShell Encoded Command", "high", "high"),
            (r"(powershell|pwsh).*(frombase64string|\[convert\]::frombase64string)", "PowerShell Encoded Command", "high", "high"),
            (r"powershell.*downloadstring", "PowerShell Download Cradle", "critical", "high"),
            (r"(namedpipe(client|server)stream|system\.io\.pipes|\\\\\.\\pipe\\|\\\\localhost\\pipe\\)", "Named Pipe PowerShell", "critical", "high"),
            (r"powershell.*reflection\.assembly", "Reflective Loading", "critical", "high"),
            (r"vssadmin\s+delete\s+shadows", "Shadow Copy Deletion", "critical", "high"),
            (r"wmic\s+shadow" + r"copy\s+delete", "Shadow Copy Deletion", "critical", "high"),
            (r"(get-wmiobject|get-ciminstance)\s+win32_" + r"shadowcopy.*delete\(", "Shadow Copy Deletion", "critical", "high"),
            (r"wbadmin\s+delete", "Backup Deletion", "critical", "high"),
            (r"bcdedit.*recoveryenabled.*no", "Recovery Disabled", "critical", "high"),
            (r"mshta.*(vbscript|javascript)", "MSHTA Execution", "critical", "high"),
            (r"procdump.*lsass", "LSASS Dump (Procdump)", "critical", "high"),
            (r"comsvcs.*minidump", "LSASS Dump (comsvcs)", "critical", "high"),
        ]
        for pat, name, sev, conf in patterns:
            if name == "Named Pipe PowerShell":
                is_powershell_context = (
                    ev.event_id == 4104
                    or _basename(ev.process_name) in POWERSHELL_HOST_BASENAMES
                    or bool(re.search(r"\b(powershell|pwsh)\b", cmd, re.IGNORECASE))
                )
                if not is_powershell_context:
                    continue
            if re.search(pat, cmd, re.IGNORECASE):
                alerts.append(Alert(
                    rule_name=f"Suspicious: {name}", severity=sev,
                    mitre_tactic="Defense Evasion", mitre_technique="T1059",
                    description=f"{name} by {ev.domain_user or 'unknown'} on {ev.computer} via {os.path.basename(ev.process_name or '') or 'unknown'}: {cmd[:200]}",
                    explanation=f"'{name}' is a known attacker technique. Review the full command line and determine the intent.",
                    confidence=conf,
                    investigate_next="Review the full command. Check the parent process. Check what was downloaded or executed. Look for follow-on activity.",
                    event=ev, evidence={"command_line": cmd[:500], "evidence_strength": "high"},
                ))
                break

    return alerts
