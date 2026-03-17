"""Credential access detection rules."""

import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple

from models.event_model import NormalizedEvent, Alert

BENIGN_IPS = frozenset({"127.0.0.1", "::1", "-", "", "0.0.0.0"})
DCSYNC_REPLICATION_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
}
BROWSER_CREDENTIAL_MARKERS = {
    "chrome": ("\\google\\chrome\\", "login data"),
    "edge": ("\\microsoft\\edge\\", "login data"),
    "opera": ("\\opera software\\", "login data"),
    "firefox": ("\\mozilla\\firefox\\", "key4.db", "logins.json"),
}
BENIGN_BROWSER_PROCESSES = {"chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "iexplore.exe", "browser_broker.exe"}
BROWSER_LOGON_PROCESS_MARKERS = {
    "chrome.exe": {"chrome"},
    "msedge.exe": {"edge", "msedge", "microsoftedge", "microsoft edge"},
    "firefox.exe": {"firefox"},
    "opera.exe": {"opera"},
    "iexplore.exe": {"iexplore", "internet explorer"},
}
LSASS_ACCESS_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x001f3fff", "0x00001010", "0x00001410", "0x00001438", "0x0000143a", "0x001fffff"}
LSASS_LOW_SIGNAL_QUERY_MASKS = {"0x1000", "0x00001000"}
LSASS_SYSMAIN_QUERY_MASKS = {"0x2000", "0x00002000"}
DEFENDER_LSASS_QUERY_MASKS = {"0x1000", "0x00001000", "0x101000", "0x00101000"}
LSASS_AUDIT_SUSPICIOUS_PROCESSES = {
    "cscript.exe",
    "wscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "rundll32.exe",
    "mimikatz.exe",
    "rdrleakdiag.exe",
    "taskmgr.exe",
    "procdump.exe",
}
MEMSSP_LOG_MARKERS = ("mimilsa.log", "kiwissp.log", "memssp")
POWERSHELL_CONTEXT_USER_RE = re.compile(r"^\s*User\s*=\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
DISCOVERY_MODIFIER_MARKERS = ("/add", "/delete", "/del", "/active:", "/comment:", "/passwordchg", "/expires:")
TRUST_DISCOVERY_MARKERS = (
    "[system.directoryservices.activedirectory.forest]::getcurrentforest()",
    "get-adforest",
    "get-adtrust",
    "get-addomaintrust",
    "/domain_trusts",
    "/all_trusts",
)
SPN_DISCOVERY_POWERSHELL_MARKERS = (
    "serviceprincipalname",
    "get-aduser",
    "get-adcomputer",
    "setspn -q",
)
PETITPOTAM_EFSRPC_UUID = "{c681d488-d850-11d0-8c52-00c04fd90f7e}"
ZEROLOGON_NETLOGON_UUID = "{12345678-1234-abcd-ef00-01234567cffb}"
MACHINE_ACCOUNT_SECRET_MARKER = r"hklm\security\policy\secrets\$machine.acc\currval"
REMOTE_SAM_HIVE_NAMES = {
    "psam": "SAM",
    "psystem": "SYSTEM",
    "psecurity": "SECURITY",
}
REMOTE_SAM_REQUIRED_PRIVILEGES = {"sebackupprivilege", "serestoreprivilege"}
KERBEROS_SPRAY_FAILURE_STATUSES = {"0x6", "0x18", "0xc0000064", "0xc000006a", "0xc000006d", "0xc0000234"}
TEAMVIEWER_SUSPICIOUS_ACCESS_MASKS = {"0x147a", "0x143a", "0x1438", "0x1fffff"}
KEKEO_DEFAULT_PIPE = r"\kekeo_tsssp_endpoint"
MSSQL_EVENTDATA_STRING_RE = re.compile(r"<string>(.*?)</string>", re.IGNORECASE | re.DOTALL)
NTDS_DIT_PATH_RE = re.compile(r"[a-zA-Z]:\\[^<>\r\n]*?ntds\.dit", re.IGNORECASE)
DIRECTINPUT_MOSTRECENT_MARKER = "\\software\\microsoft\\directinput\\mostrecentapplication\\"
DIRECTINPUT_REQUIRED_KEYS = {"version", "name", "id", "mostrecentstart"}
BENIGN_VAULT_RESOURCES = {"snapshotencryptioniv", "snapshotencryptionkey"}
BENIGN_VAULT_IDENTITIES = {"microsoftstore-installs"}
BENIGN_VAULT_TARGET_PREFIXES = (
    "adobe app info",
    "adobe app prefetched info",
    "adobe package info",
    "adobe profile info",
    "adobe proxy password",
    "adobe proxy username",
    "adobe user info",
    "adobe user os info",
    "lenovossosdk",
    "microsoftaccount:",
    "microsoftoffice16_data:",
    "windowslive:",
)
BENIGN_LSASS_QUERY_SOURCES = {
    r"c:\windows\system32\svchost.exe",
}
BENIGN_LSASS_QUERY_PATHS = {
    r"c:\program files (x86)\microsoft\edgeupdate\microsoftedgeupdate.exe",
}
SYSTEM_IDENTITY_ALIASES = {
    "nt authority\\system",
    "localsystem",
}


def _is_security_audit(ev: NormalizedEvent) -> bool:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    return "security-auditing" in provider or channel == "security"


def _is_sysmon_event(ev: NormalizedEvent) -> bool:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    return "sysmon" in provider or "sysmon" in channel


def _normalize_hex_mask(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("0x"):
        try:
            return hex(int(raw, 16))
        except ValueError:
            return raw
    return raw


def _is_benign_microsoft_lsass_query(
    *,
    source: str,
    normalized_access: str,
    source_user: str,
    target_user: str,
    dump_path: str,
    call_trace: str,
) -> bool:
    source_lower = (source or "").strip().lower()
    if dump_path:
        return False
    if source_user not in SYSTEM_IDENTITY_ALIASES or target_user not in SYSTEM_IDENTITY_ALIASES:
        return False

    if source_lower in BENIGN_LSASS_QUERY_PATHS and normalized_access in LSASS_LOW_SIGNAL_QUERY_MASKS:
        return True

    if (
        source_lower in BENIGN_LSASS_QUERY_SOURCES
        and normalized_access in LSASS_SYSMAIN_QUERY_MASKS
        and "sysmain.dll" in (call_trace or "").lower()
    ):
        return True

    if (
        source_lower.startswith("c:\\programdata\\microsoft\\windows defender\\platform\\")
        and source_lower.endswith(r"\msmpeng.exe")
        and normalized_access in DEFENDER_LSASS_QUERY_MASKS
        and "mpengine.dll" in (call_trace or "").lower()
    ):
        return True

    return False


def _int_value(value: str) -> int:
    try:
        return int(str(value or "").strip())
    except ValueError:
        return 0


def _extract_powershell_context_user(context_info: str) -> str:
    match = POWERSHELL_CONTEXT_USER_RE.search(context_info or "")
    return (match.group(1) or "").strip() if match else ""


def _looks_like_benign_vault_target(target_name: str) -> bool:
    lowered = (target_name or "").strip().lower()
    if not lowered:
        return True
    return any(lowered.startswith(prefix) for prefix in BENIGN_VAULT_TARGET_PREFIXES)


def _is_benign_vault_churn(
    *,
    backup_files: List[str],
    resources: List[str],
    identities: List[str],
    target_names: List[str],
    max_returned: int,
    event_count: int,
) -> bool:
    if backup_files or max_returned > 1:
        return False
    if event_count < 25 and len(target_names) < 5:
        return False
    if resources and any((resource or "").strip().lower() not in BENIGN_VAULT_RESOURCES for resource in resources):
        return False
    if identities and any((identity or "").strip().lower() not in BENIGN_VAULT_IDENTITIES for identity in identities):
        return False
    return bool(target_names) and all(_looks_like_benign_vault_target(target_name) for target_name in target_names)


def _resolve_discovery_actor(events: List[NormalizedEvent], ev: NormalizedEvent) -> str:
    actor = ev.subject_domain_user or ev.domain_user or ev.target_domain_user or "unknown"
    if actor and actor.lower() != "unknown":
        return actor
    if ev.event_id != 4104 or not ev.timestamp:
        return actor or "unknown"

    host = ev.computer or "unknown"
    for other in events:
        if other.event_id != 4103 or not other.timestamp:
            continue
        if (other.computer or "unknown") != host:
            continue
        if abs((other.timestamp - ev.timestamp).total_seconds()) > 180:
            continue
        context_user = _extract_powershell_context_user(other.event_data.get("ContextInfo", ""))
        if context_user:
            return context_user
    return actor or "unknown"


def _is_rpc_trace(ev: NormalizedEvent) -> bool:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    return "rpc" in provider or "rpc" in channel


def _clean_rpc_text(value: str) -> str:
    text = (value or "").strip()
    return "" if text.upper() == "NULL" else text


def _extract_mssql_failed_logon_details(ev: NormalizedEvent) -> Tuple[str, str, str]:
    payload = (
        (ev.event_data.get("EventDataText", "") or "").strip()
        or (ev.event_data.get("Data_1", "") or "").strip()
    )
    if not payload:
        return "", "", ""
    parts = [part.strip() for part in MSSQL_EVENTDATA_STRING_RE.findall(payload)]
    if not parts:
        return "", "", ""
    login = parts[0] if len(parts) >= 1 else ""
    reason = parts[1] if len(parts) >= 2 else ""
    client_blob = parts[2] if len(parts) >= 3 else ""
    match = re.search(r"\[CLIENT:\s*([^\]]+)\]", client_blob, re.IGNORECASE)
    client_ip = (match.group(1) or "").strip() if match else ""
    return login, reason, client_ip


def _extract_eventdata_strings(payload: str) -> List[str]:
    return [part.strip() for part in MSSQL_EVENTDATA_STRING_RE.findall(payload or "")]


def _extract_ntds_paths(payload: str) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for match in NTDS_DIT_PATH_RE.findall(payload or ""):
        cleaned = match.strip()
        lowered = cleaned.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(cleaned)
    return ordered


def _is_ntds_snapshot_source_path(path: str) -> bool:
    lowered = (path or "").strip().lower().replace("/", "\\")
    return "\\$snap_" in lowered or lowered.endswith("\\windows\\ntds\\ntds.dit")


def _is_user_writable_process_path(path: str) -> bool:
    lowered = (path or "").strip().lower().replace("/", "\\")
    return (
        lowered.startswith("c:\\users\\")
        or lowered.startswith("c:\\programdata\\")
        or lowered.startswith("c:\\windows\\temp\\")
        or lowered.startswith("c:\\temp\\")
        or lowered.startswith(r"\\")
    )


def _is_benign_mssql_internal_login(login: str) -> bool:
    lowered = (login or "").strip().lower()
    return not lowered or lowered.startswith("##ms_")


def _extract_remote_sam_hive_name(relative_target: str) -> str:
    tail = (relative_target or "").strip().replace("/", "\\").split("\\")[-1].lower()
    return REMOTE_SAM_HIVE_NAMES.get(tail, "")


def detect(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    browser_alerts, suppressed_browser_event_ids = _browser_credential_store_access(events)
    alerts.extend(browser_alerts)
    alerts.extend(_petitpotam_rpc_coercion(events))
    alerts.extend(_zerologon_rpc_activity(events))
    alerts.extend(_machine_account_secret_modified(events))
    alerts.extend(_remote_sam_registry_hive_access(events))
    alerts.extend(_kerberos_password_spray(events))
    alerts.extend(_mssql_password_spray(events))
    alerts.extend(_esent_ntds_snapshot_export(events))
    alerts.extend(_protected_storage_rpc_access(events))
    alerts.extend(_teamviewer_credential_memory_access(events))
    alerts.extend(_kekeo_tsssp_named_pipe(events))
    alerts.extend(_keepass_master_key_theft(events))
    alerts.extend(_security_audit_lsass_access(events))
    alerts.extend(_mimikatz_lsass_access(events))
    alerts.extend(_lsass_remote_thread_injection(events))
    alerts.extend(_rdrleakdiag_lsass_dump(events))
    alerts.extend(_silent_process_exit_lsass_dump(events))
    alerts.extend(_memssp_credential_log_file(events))
    alerts.extend(_taskmgr_lsass_dump(events))
    alerts.extend(_ppldump_lsass_dump(events))
    alerts.extend(_browser_logon_process_abuse(events))
    alerts.extend(_directinput_keylogger_registration(events))
    alerts.extend(_runas_different_user(events))
    alerts.extend(_token_manipulation(events))
    alerts.extend(_sensitive_user_right_assignment(events))
    alerts.extend(_system_security_granted(events))
    alerts.extend(_sid_history_added(events))
    alerts.extend(_mimikatz_privileged_execution(events))
    alerts.extend(_dcshadow_computer_object_staging(events))
    alerts.extend(_dcsync_directory_replication(events))
    alerts.extend(_pass_the_hash(events))
    alerts.extend(_dsrm_password_changed(events))
    alerts.extend(_wdigest_logon_credential_storage_enabled(events))
    alerts.extend(_credential_manager_vault_access(events))
    alerts.extend(_password_policy_enumeration(events))
    alerts.extend(_password_policy_discovery_command(events))
    alerts.extend(_user_account_discovery(events))
    alerts.extend(_group_discovery(events))
    alerts.extend(_network_share_discovery(events))
    alerts.extend(_domain_trust_discovery(events))
    alerts.extend(_spn_discovery(events))
    alerts.extend(_audit_policy_discovery(events))
    alerts.extend(_firewall_configuration_discovery(events))
    alerts.extend(_scheduled_task_configuration_discovery(events))
    alerts.extend(_dns_zone_transfer_attempt(events))
    alerts.extend(_local_account_enumeration(events))
    alerts.extend(_local_group_enumeration(events))
    alerts.extend(_remote_rpc_discovery(events))
    alerts.extend(_asrep_roasting(events))
    alerts.extend(_forged_kerberos_ticket_tooling(events))
    alerts.extend(_golden_ticket_use_pattern(events))
    alerts.extend(_brute_force(events))
    alerts.extend(_password_spray(events))
    alerts.extend(_lsass_access(events))
    alerts.extend(_credential_dump(events))
    alerts.extend(_kerberoasting(events))
    alerts.extend(_credential_files(events, suppressed_browser_event_ids))
    alerts.extend(_lockout(events))
    return alerts


def _petitpotam_rpc_coercion(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[str, List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in (5, 6) or not ev.timestamp or not _is_rpc_trace(ev):
            continue
        uuid = ((_first_present(ev.event_data, "InterfaceUuid", "InterfaceUUID")) or "").lower()
        if uuid != PETITPOTAM_EFSRPC_UUID:
            continue
        if (_first_present(ev.event_data, "ProcNum") or "").strip() != "0":
            continue
        if (_first_present(ev.event_data, "Protocol") or "").strip() != "2":
            continue
        if (_first_present(ev.event_data, "AuthenticationLevel") or "").strip() != "1":
            continue
        if (_first_present(ev.event_data, "AuthenticationService") or "").strip() != "0":
            continue
        grouped[ev.computer or "unknown"].append(ev)

    for host, host_events in grouped.items():
        host_events = sorted(host_events, key=lambda item: item.timestamp or datetime.min)
        windows: List[List[NormalizedEvent]] = []
        current: List[NormalizedEvent] = []
        for ev in host_events:
            if current and ev.timestamp - current[-1].timestamp > timedelta(seconds=30):
                windows.append(current)
                current = []
            current.append(ev)
        if current:
            windows.append(current)

        for cluster in windows:
            event_ids = {item.event_id for item in cluster}
            endpoints = sorted(
                {
                    (_first_present(item.event_data, "Endpoint") or "").strip()
                    for item in cluster
                    if (_first_present(item.event_data, "Endpoint") or "").strip()
                }
            )
            lowered_endpoints = {endpoint.lower() for endpoint in endpoints}
            network_addresses = sorted(
                {
                    _clean_rpc_text(_first_present(item.event_data, "NetworkAddress"))
                    for item in cluster
                    if _clean_rpc_text(_first_present(item.event_data, "NetworkAddress"))
                }
            )
            if 5 not in event_ids or 6 not in event_ids:
                continue
            if "\\pipe\\lsarpc" not in lowered_endpoints or "\\pipe\\lsass" not in lowered_endpoints:
                continue
            if not any(address.startswith("\\\\") or address.startswith("//") for address in network_addresses):
                continue

            first = cluster[0]
            network_address = next(
                (address for address in network_addresses if address.startswith("\\\\") or address.startswith("//")),
                network_addresses[0],
            )
            alerts.append(
                Alert(
                    rule_name="PetitPotam RPC Coercion",
                    severity="critical",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1187",
                    description=f"Anonymous EFSRPC coercion activity targeted {host} via {network_address}.",
                    explanation=(
                        "A paired RPC bind/request sequence against the EFSRPC interface used anonymous weak authentication "
                        "over lsarpc/lsass named pipes. This is consistent with PetitPotam-style forced authentication coercion."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Validate whether the remote peer is authorized to trigger EFSRPC operations, inspect subsequent NTLM relay "
                        "or certificate enrollment activity, and isolate the coercion source if the behavior is unexpected."
                    ),
                    event=first,
                    source_ip=network_address.lstrip("\\"),
                    evidence={
                        "interface_uuid": PETITPOTAM_EFSRPC_UUID,
                        "network_address": network_address,
                        "network_addresses": network_addresses,
                        "endpoints": endpoints,
                        "proc_nums": sorted(
                            {
                                (_first_present(item.event_data, "ProcNum") or "").strip()
                                for item in cluster
                                if (_first_present(item.event_data, "ProcNum") or "").strip()
                            }
                        ),
                        "event_ids": sorted(event_ids),
                        "event_count": len(cluster),
                        "authentication_level": "1",
                        "authentication_service": "0",
                        "evidence_strength": "high",
                    },
                )
            )
    return alerts


def _zerologon_rpc_activity(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id != 6 or not ev.timestamp or not _is_rpc_trace(ev):
            continue
        uuid = ((_first_present(ev.event_data, "InterfaceUuid", "InterfaceUUID")) or "").lower()
        if uuid != ZEROLOGON_NETLOGON_UUID:
            continue
        if (_first_present(ev.event_data, "Protocol") or "").strip() != "1":
            continue
        if (_first_present(ev.event_data, "AuthenticationLevel") or "").strip() != "1":
            continue
        if (_first_present(ev.event_data, "AuthenticationService") or "").strip() != "0":
            continue
        endpoint = (_first_present(ev.event_data, "Endpoint") or "").strip()
        grouped[(ev.computer or "unknown", endpoint)].append(ev)

    for (host, endpoint), cluster in grouped.items():
        cluster = sorted(cluster, key=lambda item: item.timestamp or datetime.min)
        windows: List[List[NormalizedEvent]] = []
        current: List[NormalizedEvent] = []
        for ev in cluster:
            if current and ev.timestamp - current[-1].timestamp > timedelta(seconds=30):
                windows.append(current)
                current = []
            current.append(ev)
        if current:
            windows.append(current)

        for window in windows:
            if len(window) < 5:
                continue
            proc_nums = sorted(
                {
                    (_first_present(item.event_data, "ProcNum") or "").strip()
                    for item in window
                    if (_first_present(item.event_data, "ProcNum") or "").strip()
                }
            )
            first = window[0]
            alerts.append(
                Alert(
                    rule_name="Zerologon RPC Activity",
                    severity="critical",
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1210",
                    description=f"Weakly authenticated Netlogon RPC calls were burst against {host} on endpoint {endpoint or '(unknown)'}.",
                    explanation=(
                        "Multiple Netlogon RPC requests used protocol 1 with authentication level 1 and authentication service 0. "
                        "This weak-authentication burst is consistent with Zerologon exploitation attempts."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Inspect the source of the Netlogon calls, review nearby machine-account password resets or anomalous domain-controller "
                        "authentication events, and patch/isolate systems that are still vulnerable to Zerologon-style abuse."
                    ),
                    event=first,
                    evidence={
                        "interface_uuid": ZEROLOGON_NETLOGON_UUID,
                        "endpoint": endpoint,
                        "proc_nums": proc_nums,
                        "protocol": "1",
                        "authentication_level": "1",
                        "authentication_service": "0",
                        "event_count": len(window),
                        "evidence_strength": "high",
                    },
                )
            )
    return alerts


def _machine_account_secret_modified(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[str, List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in (12, 13) or not ev.timestamp or not _is_sysmon_event(ev):
            continue
        target = (_first_present(ev.event_data, "TargetObject") or "").strip().lower()
        if MACHINE_ACCOUNT_SECRET_MARKER not in target:
            continue
        event_type = (_first_present(ev.event_data, "EventType") or "").strip().lower()
        if ev.event_id == 12 and event_type != "createkey":
            continue
        if ev.event_id == 13 and event_type != "setvalue":
            continue
        process_name = (ev.process_name or _first_present(ev.event_data, "Image") or "").strip().lower()
        rule_name = (_first_present(ev.event_data, "RuleName") or "").strip().lower()
        if "lsass.exe" not in process_name and "machine account saved password set" not in rule_name:
            continue
        grouped[ev.computer or "unknown"].append(ev)

    for host, cluster in grouped.items():
        cluster = sorted(cluster, key=lambda item: item.timestamp or datetime.min)
        windows: List[List[NormalizedEvent]] = []
        current: List[NormalizedEvent] = []
        for ev in cluster:
            if current and ev.timestamp - current[-1].timestamp > timedelta(minutes=10):
                windows.append(current)
                current = []
            current.append(ev)
        if current:
            windows.append(current)

        for window in windows:
            if not any(item.event_id == 12 for item in window) or not any(item.event_id == 13 for item in window):
                continue
            first = window[0]
            alerts.append(
                Alert(
                    rule_name="Machine Account Secret Modified",
                    severity="high",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1003.004",
                    description=f"Machine account secret material was updated in LSA secrets on {host}.",
                    explanation=(
                        "Sysmon registry events recorded a create/set sequence under SECURITY\\Policy\\Secrets\\$MACHINE.ACC\\CurrVal, "
                        "which indicates the machine-account password secret was written in the LSA secrets store."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Validate whether the machine-account password rotation or secret write was expected, inspect nearby LSA secret access, "
                        "and review whether the machine account was abused for relay, delegation, or replication activity."
                    ),
                    event=first,
                    process=first.process_name,
                    registry_key=_first_present(first.event_data, "TargetObject"),
                    evidence={
                        "registry_paths": sorted(
                            {
                                (_first_present(item.event_data, "TargetObject") or "").strip()
                                for item in window
                                if (_first_present(item.event_data, "TargetObject") or "").strip()
                            }
                        ),
                        "event_types": sorted(
                            {
                                (_first_present(item.event_data, "EventType") or "").strip()
                                for item in window
                                if (_first_present(item.event_data, "EventType") or "").strip()
                            }
                        ),
                        "rule_names": sorted(
                            {
                                (_first_present(item.event_data, "RuleName") or "").strip()
                                for item in window
                                if (_first_present(item.event_data, "RuleName") or "").strip()
                            }
                        ),
                        "processes": sorted({item.process_name for item in window if item.process_name}),
                        "collapsed_event_count": len(window),
                        "evidence_strength": "high",
                    },
                )
            )
    return alerts


def _remote_sam_registry_hive_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    logons: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
    privileges: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
    winreg_events: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
    hive_events: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if not ev.timestamp or not _is_security_audit(ev):
            continue
        host = ev.computer or "unknown"
        actor = ev.subject_domain_user or ev.target_domain_user or ev.domain_user or _first_present(ev.event_data, "SubjectUserName", "TargetUserName")
        actor = (actor or "").strip()

        if ev.event_id == 4624 and ev.logon_type == "3":
            actor = (ev.target_domain_user or ev.domain_user or actor).strip()
            src = (ev.source_ip or _first_present(ev.event_data, "IpAddress")).strip()
            if actor and src and src not in BENIGN_IPS:
                logons[(host, actor)].append(ev)
            continue

        if not actor:
            continue

        if ev.event_id == 4672:
            privilege_list = (_first_present(ev.event_data, "PrivilegeList") or "").strip().lower()
            if any(priv in privilege_list for priv in REMOTE_SAM_REQUIRED_PRIVILEGES):
                privileges[(host, actor)].append(ev)
            continue

        if ev.event_id != 5145:
            continue

        share_name = (_first_present(ev.event_data, "ShareName") or "").strip().lower()
        relative_target = (_first_present(ev.event_data, "RelativeTargetName") or "").strip()
        if "ipc$" in share_name and relative_target.lower() == "winreg":
            winreg_events[(host, actor)].append(ev)
            continue

        hive_name = _extract_remote_sam_hive_name(relative_target)
        if "c$" in share_name and hive_name:
            hive_events[(host, actor)].append(ev)

    seen: Set[Tuple[str, str, Tuple[str, ...]]] = set()
    for (host, actor), reg_cluster in winreg_events.items():
        reg_cluster = sorted(reg_cluster, key=lambda item: item.timestamp or datetime.min)
        related_logons = logons.get((host, actor), [])
        related_privs = privileges.get((host, actor), [])
        related_hives = hive_events.get((host, actor), [])

        for reg_ev in reg_cluster:
            window_start = reg_ev.timestamp - timedelta(minutes=2)
            window_end = reg_ev.timestamp + timedelta(minutes=10)

            hive_cluster = [
                item for item in related_hives
                if window_start <= item.timestamp <= window_end
            ]
            unique_hives = sorted(
                {
                    _extract_remote_sam_hive_name(_first_present(item.event_data, "RelativeTargetName"))
                    for item in hive_cluster
                    if _extract_remote_sam_hive_name(_first_present(item.event_data, "RelativeTargetName"))
                }
            )
            if len(unique_hives) < 2:
                continue

            privilege_cluster = [
                item for item in related_privs
                if window_start <= item.timestamp <= window_end
            ]
            if not privilege_cluster:
                continue

            logon_cluster = [
                item for item in related_logons
                if window_start <= item.timestamp <= window_end
            ]
            source_ips: List[str] = []
            for item in [*logon_cluster, reg_ev, *hive_cluster]:
                candidate = (item.source_ip or _first_present(item.event_data, "IpAddress")).strip()
                if candidate and candidate not in BENIGN_IPS and candidate not in source_ips:
                    source_ips.append(candidate)
            primary_source_ip = ""
            if logon_cluster:
                primary_source_ip = (logon_cluster[0].source_ip or _first_present(logon_cluster[0].event_data, "IpAddress")).strip()
            if not primary_source_ip or primary_source_ip in BENIGN_IPS:
                primary_source_ip = source_ips[0] if source_ips else ""

            key = (host, actor.lower(), tuple(unique_hives))
            if key in seen:
                continue
            seen.add(key)

            privilege_names = sorted(
                {
                    part
                    for item in privilege_cluster
                    for part in (_first_present(item.event_data, "PrivilegeList") or "").split()
                    if part
                }
            )
            alerts.append(
                Alert(
                    rule_name="Remote SAM Registry Hive Access",
                    severity="critical",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1003.002",
                    description=(
                        f"{actor} remotely accessed winreg on {host}"
                        f"{' from ' + primary_source_ip if primary_source_ip else ''} and staged {', '.join(unique_hives)} hive material."
                    ),
                    explanation=(
                        "A network logon with backup/restore privileges accessed IPC$\\\\winreg and then copied PSAM/PSYSTEM/PSECURITY-style "
                        "hive files over C$. This is consistent with remote SAM/LSA hive collection for offline credential extraction."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Treat the source and account as compromised, preserve the copied hive files if present, and review nearby use of backup privileges, "
                        "registry access, and hash extraction tooling from the same actor."
                    ),
                    event=reg_ev,
                    user=actor,
                    source_ip=primary_source_ip,
                    share_name=_first_present(reg_ev.event_data, "ShareName"),
                    evidence={
                        "actor_user": actor,
                        "source_ips": source_ips,
                        "primary_source_ip": primary_source_ip,
                        "share_names": sorted(
                            {
                                (_first_present(item.event_data, "ShareName") or "").strip()
                                for item in [reg_ev, *hive_cluster]
                                if (_first_present(item.event_data, "ShareName") or "").strip()
                            }
                        ),
                        "rpc_targets": ["winreg"],
                        "staged_hives": unique_hives,
                        "relative_targets": sorted(
                            {
                                (_first_present(item.event_data, "RelativeTargetName") or "").strip()
                                for item in hive_cluster
                                if (_first_present(item.event_data, "RelativeTargetName") or "").strip()
                            }
                        ),
                        "privileges": privilege_names,
                        "event_count": 1 + len(hive_cluster) + len(privilege_cluster) + len(logon_cluster),
                        "evidence_strength": "high",
                    },
                )
            )
    return alerts


def _keepass_master_key_theft(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    suspicious_sources = {"powershell.exe", "python.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe"}

    for ev in events:
        if ev.event_id not in (8, 10):
            continue
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "sysmon" not in provider and "sysmon" not in channel:
            continue

        source = (ev.event_data.get("SourceImage", "") or ev.process_name or "").strip()
        target = (ev.event_data.get("TargetImage", "") or "").strip()
        if "keepass.exe" not in target.lower():
            continue
        if not source or os.path.basename(source).lower() == "keepass.exe":
            continue

        source_base = os.path.basename(source).lower()
        if source_base not in suspicious_sources and ev.event_id != 8:
            continue

        access = (ev.event_data.get("GrantedAccess", "") or "").strip()
        key = ((ev.computer or "").lower(), source.lower(), target.lower(), access, str(ev.timestamp))
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="KeePass Master Key Theft",
                severity="critical" if source_base in {"powershell.exe", "python.exe"} else "high",
                mitre_tactic="Credential Access",
                mitre_technique="T1555.005",
                description=f"{source} accessed KeePass process memory on {ev.computer}",
                explanation=(
                    "Remote thread creation or suspicious process access targeting KeePass.exe is consistent with KeeThief-style theft of KeePass master key material."
                ),
                confidence="high",
                investigate_next=(
                    "Inspect the source process and script content, determine whether the KeePass database and master key were exposed, and rotate any credentials stored in the affected vault."
                ),
                event=ev,
                user=ev.domain_user or ev.subject_domain_user or ev.event_data.get("User", ""),
                process=source,
                evidence={
                    "source_image": source,
                    "target_image": target,
                    "granted_access": access,
                    "event_type": "create_remote_thread" if ev.event_id == 8 else "process_access",
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _security_audit_lsass_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4656, 4663) or not _is_security_audit(ev):
            continue
        if (ev.event_data.get("ObjectType", "") or "").strip().lower() != "process":
            continue
        object_name = (ev.event_data.get("ObjectName", "") or "").strip().lower()
        if not object_name.endswith("lsass.exe"):
            continue

        process_name = (ev.event_data.get("ProcessName", "") or ev.process_name or "").strip()
        if not process_name:
            continue
        process_base = _basename(process_name)
        if process_base not in LSASS_AUDIT_SUSPICIOUS_PROCESSES and "\\users\\" not in process_name.lower():
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        logon_id = (ev.event_data.get("SubjectLogonId", "") or "").strip()
        grouped[(ev.computer or "unknown", actor, process_name.lower(), logon_id or "(unknown)")].append(ev)

    for (host, actor, process_name, logon_id), cluster in grouped.items():
        access_masks = {
            (item.event_data.get("AccessMask", "") or "").strip().lower()
            for item in cluster
            if (item.event_data.get("AccessMask", "") or "").strip()
        }
        if not (access_masks & LSASS_ACCESS_MASKS):
            continue

        first = cluster[0]
        object_names = sorted(
            {
                (item.event_data.get("ObjectName", "") or "").strip()
                for item in cluster
                if (item.event_data.get("ObjectName", "") or "").strip()
            }
        )
        alerts.append(
            Alert(
                rule_name="Security Audit LSASS Access",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"{process_name} requested sensitive access to lsass.exe on {host}",
                explanation=(
                    "Security auditing recorded a suspicious process requesting high-privilege access to lsass.exe. "
                    "This is a strong credential-dumping indicator when the accessor is a script host, shell, or offensive tooling."
                ),
                confidence="high",
                investigate_next=(
                    "Inspect the accessing process and its parent chain, determine whether memory or handle duplication followed, "
                    "and rotate any credentials that may have been exposed."
                ),
                event=first,
                user=actor,
                process=process_name,
                evidence={
                    "actor_user": actor,
                    "source_image": process_name,
                    "access_masks": sorted(access_masks),
                    "object_names": object_names,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "event_ids": [item.event_id for item in cluster],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _mimikatz_lsass_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in events:
        if ev.event_id != 10 or not _is_sysmon_event(ev):
            continue
        target = (ev.event_data.get("TargetImage", "") or "").lower()
        source = (ev.event_data.get("SourceImage", "") or "").strip()
        if "lsass.exe" not in target or "mimikatz" not in source.lower():
            continue

        access = (ev.event_data.get("GrantedAccess", "") or "").strip()
        key = ((ev.computer or "").lower(), source.lower(), access, str(ev.timestamp))
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="Mimikatz LSASS Access",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"Mimikatz accessed lsass.exe on {ev.computer}",
                explanation=(
                    "Sysmon recorded mimikatz.exe opening lsass.exe. This is high-confidence credential dumping or credential extraction preparation."
                ),
                confidence="high",
                investigate_next=(
                    "Preserve the mimikatz binary and related command history, review any dumped credential use that followed, "
                    "and assume local secrets were exposed."
                ),
                event=ev,
                user=ev.domain_user or ev.subject_domain_user or ev.target_domain_user or "",
                process=source,
                evidence={
                    "source_image": source,
                    "target_image": ev.event_data.get("TargetImage", ""),
                    "granted_access": access,
                    "call_trace": (ev.event_data.get("CallTrace", "") or "")[:600],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _rdrleakdiag_lsass_dump(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    process_events = [
        ev
        for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
        if ev.event_id in (1, 4688)
        if _is_sysmon_event(ev)
        if _basename(ev.process_name) == "rdrleakdiag.exe"
        if "/fullmemdmp" in (ev.command_line or "").lower()
    ]

    for ev in process_events:
        proc_id = (ev.event_data.get("ProcessId", "") or "").strip()
        host = ev.computer or "unknown"
        window_end = ev.timestamp + timedelta(minutes=2)
        related_access = [
            other
            for other in events
            if other.timestamp
            and other.timestamp >= ev.timestamp
            and other.timestamp <= window_end
            and (other.computer or "") == host
            and other.event_id == 8
            and _is_sysmon_event(other)
            and (other.event_data.get("TargetImage", "") or "").lower().endswith("lsass.exe")
            and ((other.event_data.get("SourceProcessId", "") or "").strip() == proc_id or not proc_id)
        ]
        dump_files = [
            other
            for other in events
            if other.timestamp
            and other.timestamp >= ev.timestamp
            and other.timestamp <= window_end
            and (other.computer or "") == host
            and other.event_id == 11
            and _is_sysmon_event(other)
            and _basename(other.process_name) == "rdrleakdiag.exe"
            and ((other.event_data.get("ProcessId", "") or "").strip() == proc_id or not proc_id)
            and (other.event_data.get("TargetFilename", "") or "").lower().endswith(".dmp")
        ]
        if not related_access and not dump_files:
            continue

        dump_path = next(
            (
                (item.event_data.get("TargetFilename", "") or "").strip()
                for item in dump_files
                if (item.event_data.get("TargetFilename", "") or "").strip()
            ),
            "",
        )
        alerts.append(
            Alert(
                rule_name="LSASS Dump via RdrLeakDiag",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"rdrleakdiag.exe dumped lsass.exe on {host}",
                explanation=(
                    "rdrleakdiag.exe was launched with full-memory dump arguments and then interacted with lsass.exe and a .dmp output file. "
                    "This is strong evidence of credential dumping through a built-in Microsoft binary."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the dump file, inspect the launching shell or script, and review whether the dump was copied off-host or parsed by follow-on tooling."
                ),
                event=ev,
                user=ev.domain_user or ev.subject_domain_user or "",
                process=ev.process_name,
                evidence={
                    "command_line": (ev.command_line or "")[:500],
                    "dump_path": dump_path,
                    "source_process_id": proc_id,
                    "lsass_access_observed": bool(related_access),
                    "dump_file_created": bool(dump_files),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _silent_process_exit_lsass_dump(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen: Set[Tuple[str, str, str]] = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 3001:
            continue
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "processexitmonitor" not in provider and "processexitmonitor" not in channel:
            continue

        monitored_process = (
            ev.event_data.get("param1", "")
            or ev.event_data.get("ProcessName", "")
            or ev.process_name
            or ""
        ).strip()
        monitor_process = (
            ev.event_data.get("param2", "")
            or ev.event_data.get("MonitorProcess", "")
            or ""
        ).strip()
        if not monitored_process.lower().endswith(r"\lsass.exe"):
            continue
        if not monitor_process:
            continue

        key = (
            (ev.computer or "").strip().lower(),
            monitored_process.lower(),
            monitor_process.lower(),
        )
        if key in seen:
            continue
        seen.add(key)

        host = ev.computer or "unknown host"
        alerts.append(
            Alert(
                rule_name="LSASS Dump via SilentProcessExit",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"SilentProcessExit monitoring targeted lsass.exe on {host}",
                explanation=(
                    "ProcessExitMonitor recorded lsass.exe with a configured monitor process, which is consistent "
                    "with SilentProcessExit-style LSASS dump collection."
                ),
                confidence="high",
                investigate_next=(
                    "Preserve the monitor binary and any dump artifacts, confirm how SilentProcessExit monitoring "
                    "was configured, and treat LSASS-resident credentials as exposed."
                ),
                event=ev,
                process=monitor_process,
                evidence={
                    "monitored_process": monitored_process,
                    "monitor_process": monitor_process,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _memssp_credential_log_file(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in events:
        if ev.event_id != 11 or not _is_sysmon_event(ev):
            continue
        target = (ev.event_data.get("TargetFilename", "") or "").strip()
        if not target:
            continue
        target_l = target.lower()
        if not any(marker in target_l for marker in MEMSSP_LOG_MARKERS):
            continue
        if _basename(ev.process_name) != "lsass.exe":
            continue

        key = ((ev.computer or "").lower(), target_l, str(ev.timestamp))
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="MemSSP Credential Log File",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1547.002",
                description=f"lsass.exe created a credential log artifact on {ev.computer}: {target}",
                explanation=(
                    "lsass.exe writing mimilsa-style log output is consistent with MemSSP or similar authentication-package abuse that captures cleartext credentials."
                ),
                confidence="high",
                investigate_next=(
                    "Preserve the credential log artifact, inspect authentication-package configuration on the host, and rotate credentials that may have been written to disk."
                ),
                event=ev,
                process=ev.process_name,
                evidence={
                    "target_filename": target,
                    "process_name": ev.process_name,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _extract_target_logon_id(ev: NormalizedEvent) -> str:
    return (ev.event_data.get("TargetLogonId", "") or "").strip()


def _extract_subject_logon_id(ev: NormalizedEvent) -> str:
    return (
        ev.event_data.get("SubjectLogonId", "")
        or ev.event_data.get("LogonId", "")
        or ev.event_data.get("TargetLogonId", "")
    ).strip()


def _parse_runas_target(command_line: str) -> str:
    match = re.search(r"/user:([^\s]+)", command_line or "", re.IGNORECASE)
    return (match.group(1) or "").strip() if match else ""


def _browser_families_for_target(target: str) -> Set[str]:
    target_l = (target or "").lower()
    families: Set[str] = set()
    if "\\google\\chrome\\" in target_l and "login data" in target_l:
        families.add("chrome")
    if "\\microsoft\\edge\\" in target_l and "login data" in target_l:
        families.add("edge")
    if "\\opera software\\" in target_l and "login data" in target_l:
        families.add("opera")
    if "\\mozilla\\firefox\\" in target_l and ("key4.db" in target_l or "logins.json" in target_l):
        families.add("firefox")
    return families


def _taskmgr_lsass_dump(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    clusters: Dict[str, Dict[str, object]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        process_name = (
            ev.process_name
            or ev.event_data.get("ProcessName", "")
            or ev.event_data.get("SourceImage", "")
            or ev.event_data.get("Image", "")
            or ""
        ).strip()
        if _basename(process_name) != "taskmgr.exe":
            continue

        host = ev.computer or "unknown"
        key = host.lower()
        bucket = clusters.setdefault(
            key,
            {
                "host": host,
                "event": ev,
                "access_masks": set(),
                "dump_paths": set(),
                "event_ids": set(),
                "users": set(),
            },
        )
        bucket["event_ids"].add(ev.event_id)
        actor = ev.subject_domain_user or ev.domain_user or ""
        if actor:
            bucket["users"].add(actor)
        if ev.timestamp and ev.timestamp < bucket["event"].timestamp:
            bucket["event"] = ev

        if ev.event_id in (4656, 4663):
            object_name = (ev.event_data.get("ObjectName", "") or "").lower()
            object_type = (ev.event_data.get("ObjectType", "") or "").lower()
            if object_type == "process" and object_name.endswith("lsass.exe"):
                mask = _normalize_hex_mask(ev.event_data.get("AccessMask", ""))
                if mask:
                    bucket["access_masks"].add(mask)
        elif ev.event_id == 10 and _is_sysmon_event(ev):
            target = (ev.event_data.get("TargetImage", "") or "").lower()
            if "lsass.exe" in target:
                mask = _normalize_hex_mask(ev.event_data.get("GrantedAccess", ""))
                if mask:
                    bucket["access_masks"].add(mask)
        elif ev.event_id == 11 and _is_sysmon_event(ev):
            target_file = (ev.event_data.get("TargetFilename", "") or "").strip()
            target_lower = target_file.lower()
            if target_file and target_lower.endswith(".dmp") and "lsass" in target_lower:
                bucket["dump_paths"].add(target_file)

    for bucket in clusters.values():
        if not bucket["access_masks"] and not bucket["dump_paths"]:
            continue
        actor = next(iter(sorted(bucket["users"])), "")
        dump_path = next(iter(sorted(bucket["dump_paths"])), "")
        alerts.append(
            Alert(
                rule_name="Task Manager LSASS Dump",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"Task Manager accessed or dumped lsass.exe on {bucket['host']}",
                explanation="Taskmgr.exe accessed lsass.exe and/or wrote an LSASS dump file, which is consistent with manual credential dumping via Task Manager.",
                confidence="high",
                investigate_next="Preserve the dump file if present, identify who launched Task Manager, and review any immediate credential use from exposed accounts.",
                event=bucket["event"],
                user=actor,
                process="C:\\Windows\\System32\\Taskmgr.exe",
                evidence={
                    "actor_user": actor,
                    "source_image": "C:\\Windows\\System32\\Taskmgr.exe",
                    "access_masks": sorted(bucket["access_masks"]),
                    "dump_path": dump_path,
                    "dump_paths": sorted(bucket["dump_paths"]),
                    "event_ids": sorted(bucket["event_ids"]),
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _ppldump_lsass_dump(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    process_events = [item for item in events if item.event_id == 1 and _is_sysmon_event(item)]
    dump_events = [
        item
        for item in events
        if item.event_id == 11
        and _is_sysmon_event(item)
        and (item.event_data.get("TargetFilename", "") or "").strip().lower().endswith(".dmp")
    ]

    for ev in process_events:
        image = (ev.process_name or ev.event_data.get("Image", "") or "").strip()
        parent = (ev.parent_process or ev.event_data.get("ParentImage", "") or "").strip()
        cmd = (ev.command_line or ev.event_data.get("CommandLine", "") or "").strip()
        image_base = _basename(image)
        parent_base = _basename(parent)
        low_cmd = cmd.lower()
        is_primary = image_base == "ppldump.exe" and "lsass" in low_cmd
        is_helper = image_base == "services.exe" and parent_base == "ppldump.exe" and "lsass.dmp" in low_cmd
        if not is_primary and not is_helper:
            continue

        dump_path = ""
        for other in dump_events:
            if (other.computer or "") != (ev.computer or ""):
                continue
            other_proc = _basename(other.process_name or other.event_data.get("ProcessName", "") or other.event_data.get("Image", "") or "")
            if other_proc not in {"ppldump.exe", "services.exe"}:
                continue
            if ev.timestamp and other.timestamp and abs(other.timestamp - ev.timestamp) > timedelta(minutes=2):
                continue
            target_file = (other.event_data.get("TargetFilename", "") or "").strip()
            if target_file:
                dump_path = target_file
                break
        if not dump_path and not is_helper:
            continue

        actor = ev.subject_domain_user or ev.domain_user or ""
        alerts.append(
            Alert(
                rule_name="PPLdump LSASS Dump",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"PPLdump targeted lsass.exe on {ev.computer or 'unknown host'}",
                explanation="PPLdump launched with lsass targeting and produced an LSASS dump artifact through its helper execution flow.",
                confidence="high",
                investigate_next="Preserve the dump artifact, validate whether protected process light bypass succeeded, and treat all LSASS-resident credentials as exposed.",
                event=ev,
                user=actor,
                process=image or "C:\\Users\\IEUser\\Desktop\\PPLdump.exe",
                evidence={
                    "actor_user": actor,
                    "source_image": image or "C:\\Users\\IEUser\\Desktop\\PPLdump.exe",
                    "parent_image": parent,
                    "command_line": cmd,
                    "dump_path": dump_path,
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _runas_different_user(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((ev for ev in events if ev.timestamp), key=lambda ev: ev.timestamp)

    for ev in timed_events:
        if ev.event_id not in (4688, 1):
            continue
        if _basename(ev.process_name) != "runas.exe":
            continue

        cmd = ev.command_line or ""
        if "/user:" not in cmd.lower():
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        requested_target = _parse_runas_target(cmd) or ""
        actor_logon_id = _extract_subject_logon_id(ev)
        window_end = ev.timestamp + timedelta(minutes=5)
        explicit = None
        seclogo_events: List[NormalizedEvent] = []
        privileged = None
        follow_on = []

        for other in timed_events:
            if other.timestamp < ev.timestamp or other.timestamp > window_end:
                continue
            if (other.computer or "") != (ev.computer or ""):
                continue

            if other.event_id == 4648 and _extract_subject_logon_id(other) == actor_logon_id:
                explicit = other
            elif other.event_id == 4624 and (other.event_data.get("LogonProcessName", "") or "").strip().lower() == "seclogo":
                if requested_target and requested_target.lower() not in {
                    (other.target_domain_user or "").lower(),
                    (other.target_user or "").lower(),
                }:
                    continue
                seclogo_events.append(other)

        if not explicit or not seclogo_events:
            continue

        target_user = explicit.target_domain_user or explicit.target_user or requested_target or "unknown"
        if target_user.lower() == actor.lower():
            continue

        target_logon_ids = {_extract_target_logon_id(item) for item in seclogo_events if _extract_target_logon_id(item)}
        for other in timed_events:
            if other.timestamp < ev.timestamp or other.timestamp > window_end:
                continue
            if (other.computer or "") != (ev.computer or ""):
                continue
            if other.event_id == 4672 and _extract_logon_id(other) in target_logon_ids:
                privileged = other
            elif other.event_id in (4688, 1) and (
                _extract_logon_id(other) in target_logon_ids
                or _extract_target_logon_id(other) in target_logon_ids
            ):
                follow_on.append(other)

        alerts.append(
            Alert(
                rule_name="RunAs Different User",
                severity="critical" if privileged or follow_on else "high",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1134",
                description=(
                    f"{actor} launched runas to execute as {target_user} on {ev.computer}. "
                    "A seclogo-backed alternate-user session was created."
                ),
                explanation=(
                    "RunAs with explicit credentials can create a separate token and execution context. "
                    "When used to pivot into another user context, it may indicate access token manipulation or unauthorized privilege escalation."
                ),
                confidence="high",
                investigate_next=(
                    f"Review the full RunAs command, validate whether {actor} is authorized to execute as {target_user}, "
                    "and inspect the child processes launched in the alternate logon session."
                ),
                event=ev,
                user=target_user,
                subject_user=actor,
                target_user=target_user,
                evidence={
                    "actor_user": actor,
                    "target_user": target_user,
                    "runas_command": cmd[:400],
                    "actor_logon_id": actor_logon_id,
                    "target_logon_ids": sorted(target_logon_ids),
                    "explicit_credential_event": explicit.timestamp.isoformat() if explicit and explicit.timestamp else None,
                    "seclogo_logons": [
                        {
                            "logon_type": item.logon_type,
                            "target_logon_id": _extract_target_logon_id(item),
                            "timestamp": item.timestamp.isoformat() if item.timestamp else None,
                        }
                        for item in seclogo_events
                    ],
                    "privileged_followup": bool(privileged),
                    "follow_on_processes": [item.process_name for item in follow_on if item.process_name],
                    "follow_on_commands": [item.command_line[:300] for item in follow_on if item.command_line],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _token_manipulation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((ev for ev in events if ev.timestamp), key=lambda ev: ev.timestamp)

    for ev in timed_events:
        if ev.event_id != 4624 or (ev.event_data.get("LogonProcessName", "") or "").strip().lower() != "seclogo":
            continue
        if ev.logon_type not in ("2", "9"):
            continue
        if not _is_security_audit(ev):
            continue

        host = ev.computer or ""
        target_user = ev.target_domain_user or ev.target_user or "unknown"
        window_start = ev.timestamp - timedelta(minutes=5)
        window_end = ev.timestamp + timedelta(minutes=5)
        consent = []
        tcb_events = []
        follow_on = []

        for other in timed_events:
            if other.timestamp < window_start or other.timestamp > window_end:
                continue
            if (other.computer or "") != host:
                continue

            if other.event_id == 4611 and (other.event_data.get("LogonProcessName", "") or "").strip().lower() == "consentui":
                consent.append(other)
            elif other.event_id == 4673:
                privilege_list = (other.event_data.get("PrivilegeList", "") or "").lower()
                service = (other.event_data.get("Service", "") or "").lower()
                if "setcbprivilege" in privilege_list or "lsaregisterlogonprocess" in service:
                    tcb_events.append(other)
            elif other.event_id in (4688, 1):
                proc = _basename(other.process_name)
                if proc in {"dllhost.exe", "cmd.exe", "consent.exe", "wusa.exe"}:
                    follow_on.append(other)

        if not tcb_events or not consent:
            continue

        alerts.append(
            Alert(
                rule_name="Token Manipulation Activity",
                severity="critical" if follow_on else "high",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1134",
                description=(
                    f"Seclogo logon activity for {target_user} on {host} coincided with ConsentUI and SeTcbPrivilege token operations."
                ),
                explanation=(
                    "The combination of seclogo authentication context, ConsentUI registration, and SeTcbPrivilege use "
                    "is consistent with token manipulation or alternate logon token abuse."
                ),
                confidence="high",
                investigate_next=(
                    f"Inspect the processes tied to the seclogo session for {target_user}, verify whether ConsentUI/token operations were expected, "
                    "and review subsequent commands executed under the new token."
                ),
                event=ev,
                user=target_user,
                evidence={
                    "logon_id": _extract_target_logon_id(ev),
                    "logon_type": ev.logon_type,
                    "logon_process_name": ev.event_data.get("LogonProcessName", ""),
                    "consentui_events": len(consent),
                    "setcb_events": len(tcb_events),
                    "follow_on_processes": [item.process_name for item in follow_on if item.process_name],
                    "follow_on_commands": [item.command_line[:300] for item in follow_on if item.command_line],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


SENSITIVE_PRIVILEGES = {
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeDebugPrivilege",
    "SeImpersonatePrivilege",
    "SeLoadDriverPrivilege",
    "SeTcbPrivilege",
    "SeRestorePrivilege",
    "SeBackupPrivilege",
    "SeTakeOwnershipPrivilege",
}


def _sensitive_user_right_assignment(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.event_id != 4704 or not _is_security_audit(ev):
            continue

        privilege = (ev.event_data.get("PrivilegeList", "") or "").strip()
        if privilege not in SENSITIVE_PRIVILEGES:
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        target_sid = ev.event_data.get("TargetSid", "") or "unknown"
        alerts.append(
            Alert(
                rule_name="Sensitive User Right Assigned",
                severity="critical" if privilege in {"SeCreateTokenPrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege", "SeTcbPrivilege"} else "high",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1134",
                description=f"{actor} assigned {privilege} to {target_sid} on {ev.computer}",
                explanation="Granting powerful user rights such as token creation, debug, impersonation, or TCB privileges can directly enable token abuse or privileged execution.",
                confidence="high",
                investigate_next="Resolve the target SID to an account, verify whether this rights assignment was authorized, and review subsequent logons or privileged activity for the affected principal.",
                event=ev,
                user=actor,
                evidence={
                    "actor_user": actor,
                    "target_sid": target_sid,
                    "privilege": privilege,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _system_security_granted(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.event_id != 4717 or not _is_security_audit(ev):
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        target_sid = ev.event_data.get("TargetSid", "") or "unknown"
        alerts.append(
            Alert(
                rule_name="System Security Access Granted",
                severity="high",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1134",
                description=f"{actor} granted system security access to {target_sid} on {ev.computer}",
                explanation="Granting system security access expands what an account can inspect or modify in security-sensitive areas and can support broader privilege abuse.",
                confidence="medium",
                investigate_next="Resolve the target SID, confirm why the right was granted, and review whether the account subsequently changed auditing, privileges, or authentication material.",
                event=ev,
                user=actor,
                evidence={
                    "actor_user": actor,
                    "target_sid": target_sid,
                    "evidence_strength": "medium",
                },
            )
        )

    return alerts


def _sid_history_added(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.event_id != 4765 or not _is_security_audit(ev):
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        target_user = ev.target_domain_user or ev.target_user or ev.event_data.get("TargetUserName", "") or "unknown"
        source_user = ev.event_data.get("SourceUserName", "") or "unknown"
        source_sid = ev.event_data.get("SourceSid", "") or "unknown"
        target_sid = ev.event_data.get("TargetSid", "") or "unknown"
        alerts.append(
            Alert(
                rule_name="SID History Added",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1134.005",
                description=f"{actor} added SID history from {source_user} to {target_user} on {ev.computer}",
                explanation="SID history injection can grant an account the effective privileges of another security principal and is a high-risk sign of account manipulation.",
                confidence="high",
                investigate_next="Validate whether SID history should exist for this account, inspect directory changes made by the actor, and treat the affected account as potentially privilege-escalated.",
                event=ev,
                user=target_user,
                subject_user=actor,
                target_user=target_user,
                evidence={
                    "actor_user": actor,
                    "target_user": target_user,
                    "target_sid": target_sid,
                    "source_user": source_user,
                    "source_sid": source_sid,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _extract_guid_values(text: str) -> Set[str]:
    return {match.lower() for match in re.findall(r"\{([0-9a-fA-F\-]{36})\}", text or "")}


def _dcsync_directory_replication(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[Tuple[NormalizedEvent, List[str]]]] = defaultdict(list)

    for ev in events:
        if ev.event_id != 4662 or not ev.timestamp or not _is_security_audit(ev):
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        if actor.lower().endswith("$"):
            continue

        props = (ev.event_data.get("Properties", "") or "").strip()
        matched_rights = sorted(
            {
                right_name
                for guid_value in _extract_guid_values(props)
                for guid, right_name in DCSYNC_REPLICATION_RIGHTS.items()
                if guid_value == guid
            }
        )
        if not matched_rights:
            continue

        access_mask = (ev.event_data.get("AccessMask", "") or "").lower()
        if access_mask and access_mask not in {"0x00000100", "0x100"}:
            continue

        logon_id = _extract_subject_logon_id(ev) or _extract_logon_id(ev) or ""
        host = ev.computer or "unknown"
        grouped[(host, actor, logon_id)].append((ev, matched_rights))

    for (host, actor, logon_id), grouped_events in grouped.items():
        unique_rights = sorted({right for _, rights in grouped_events for right in rights})
        if len(unique_rights) < 2 and "DS-Replication-Get-Changes-In-Filtered-Set" not in unique_rights:
            continue

        first_event = min((ev for ev, _ in grouped_events), key=lambda item: item.timestamp)
        object_types = sorted(
            {
                value
                for ev, _ in grouped_events
                for value in ((ev.event_data.get("ObjectType", "") or "").strip(),)
                if value
            }
        )
        object_names = sorted(
            {
                value
                for ev, _ in grouped_events
                for value in ((ev.event_data.get("ObjectName", "") or "").strip(),)
                if value
            }
        )

        alerts.append(
            Alert(
                rule_name="DCSync Directory Replication",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.006",
                description=(
                    f"{actor} exercised directory replication rights on {host}. "
                    "This pattern matches DCSync-style credential replication."
                ),
                explanation=(
                    "Security Event 4662 with domain replication rights indicates an account accessed directory replication "
                    "permissions that are commonly abused by DCSync to pull password data from Active Directory."
                ),
                confidence="high",
                investigate_next=(
                    "Identify whether the actor account is authorized for directory replication, review the full 4662 sequence, "
                    "and assume credential exposure until privileged passwords and krbtgt rotation are evaluated."
                ),
                event=first_event,
                user=actor,
                evidence={
                    "actor_user": actor,
                    "host": host,
                    "logon_id": logon_id,
                    "replication_rights": unique_rights,
                    "event_count": len(grouped_events),
                    "object_types": object_types,
                    "object_names": object_names,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _mimikatz_privileged_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id != 4673 or not ev.timestamp or not _is_security_audit(ev):
            continue

        process_name = (ev.process_name or ev.event_data.get("ProcessName", "") or "").strip()
        if "mimikatz" not in process_name.lower():
            continue

        privilege_list = (ev.event_data.get("PrivilegeList", "") or "").lower()
        if not any(token in privilege_list for token in ("setcbprivilege", "sedebugprivilege", "seimpersonateprivilege")):
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        logon_id = _extract_subject_logon_id(ev) or _extract_logon_id(ev) or ""
        grouped[(ev.computer or "unknown", actor, process_name.lower(), logon_id)].append(ev)

    timed_events = sorted((ev for ev in events if ev.timestamp), key=lambda ev: ev.timestamp)
    for (host, actor, process_name, logon_id), grouped_events in grouped.items():
        first_event = min(grouped_events, key=lambda item: item.timestamp)
        user_enumeration = []
        for other in timed_events:
            if other.timestamp < first_event.timestamp or other.timestamp > first_event.timestamp + timedelta(minutes=10):
                continue
            if (other.computer or "") != host:
                continue
            if other.event_id != 4798:
                continue
            if logon_id and _extract_subject_logon_id(other) not in {"", logon_id}:
                continue
            user_enumeration.append(other)

        privilege_values = sorted(
            {
                (ev.event_data.get("PrivilegeList", "") or "").strip()
                for ev in grouped_events
                if (ev.event_data.get("PrivilegeList", "") or "").strip()
            }
        )
        alerts.append(
            Alert(
                rule_name="Mimikatz Credential Dumping",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"{actor} executed Mimikatz privilege operations on {host}",
                explanation=(
                    "Security Event 4673 from mimikatz.exe requesting SeTcbPrivilege or SeDebugPrivilege is strongly associated "
                    "with credential dumping and token abuse activity."
                ),
                confidence="high",
                investigate_next=(
                    "Treat the host as potentially credential compromised, recover the exact Mimikatz command line if available, "
                    "and review nearby LSASS access, account enumeration, and follow-on privileged logons."
                ),
                event=first_event,
                user=actor,
                process=grouped_events[0].process_name,
                evidence={
                    "actor_user": actor,
                    "process_name": grouped_events[0].process_name,
                    "logon_id": logon_id,
                    "privileges": privilege_values,
                    "privilege_event_count": len(grouped_events),
                    "related_user_enumeration_count": len(user_enumeration),
                    "related_process_ids": sorted(
                        {
                            ev.event_data.get("ProcessId", "")
                            for ev in grouped_events
                            if ev.event_data.get("ProcessId", "")
                        }
                    ),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _dcshadow_computer_object_staging(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((ev for ev in events if ev.timestamp), key=lambda ev: ev.timestamp)

    for ev in timed_events:
        if ev.event_id != 4742 or not _is_security_audit(ev):
            continue

        target_user = ev.target_domain_user or ev.target_user or ev.event_data.get("TargetUserName", "") or ""
        if not target_user.endswith("$"):
            continue

        spns = (ev.event_data.get("ServicePrincipalNames", "") or "").strip()
        spns_lower = spns.lower()
        if "e3514235-4b06-11d1-ab04-00c04fc2dcd2/" not in spns_lower and not ("gc/" in spns_lower and "wsman/" in spns_lower):
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        logon_id = _extract_subject_logon_id(ev)
        window_end = ev.timestamp + timedelta(minutes=15)
        related_4662 = []
        replication_rights = set()

        for other in timed_events:
            if other.timestamp < ev.timestamp or other.timestamp > window_end:
                continue
            if (other.computer or "") != (ev.computer or ""):
                continue
            if other.event_id != 4662 or not _is_security_audit(other):
                continue
            if (other.subject_domain_user or other.domain_user or "unknown") != actor:
                continue
            if logon_id and _extract_subject_logon_id(other) not in {"", logon_id}:
                continue

            props = (other.event_data.get("Properties", "") or "").strip()
            rights = {
                right_name
                for guid_value in _extract_guid_values(props)
                for guid, right_name in DCSYNC_REPLICATION_RIGHTS.items()
                if guid_value == guid
            }
            if "DS-Install-Replica" not in rights:
                continue
            related_4662.append(other)
            replication_rights.update(rights)

        alerts.append(
            Alert(
                rule_name="DCShadow Computer Object Staging",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1207",
                description=f"{actor} staged rogue domain-controller style SPNs for {target_user} on {ev.computer}",
                explanation=(
                    "Computer account changes that add rogue DCShadow-style replication SPNs, especially alongside DS-Install-Replica access, "
                    "indicate preparation for rogue domain controller replication and directory manipulation."
                ),
                confidence="high" if related_4662 else "medium",
                investigate_next=(
                    "Inspect the modified computer object, review all SPN changes, and validate whether DS-Install-Replica style access and DCShadow behavior were expected."
                ),
                event=ev,
                user=actor,
                target_user=target_user,
                evidence={
                    "actor_user": actor,
                    "target_computer_account": target_user,
                    "service_principal_names": spns,
                    "logon_id": logon_id,
                    "related_4662_count": len(related_4662),
                    "replication_rights": sorted(replication_rights),
                    "evidence_strength": "high" if related_4662 else "medium",
                },
            )
        )

    return alerts


def _extract_logon_id(ev: NormalizedEvent) -> str:
    return (
        ev.event_data.get("TargetLogonId", "")
        or ev.event_data.get("SubjectLogonId", "")
        or ev.event_data.get("LogonId", "")
    ).strip()


def _basename(path: str) -> str:
    text = (path or "").replace("\\", "/").strip()
    return os.path.basename(text).lower()


def _simple_account_name(value: str) -> str:
    text = (value or "").strip().lower()
    if "\\" in text:
        text = text.split("\\", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text


def _is_suspicious_process(ev: NormalizedEvent) -> bool:
    if ev.event_id not in (4688, 1):
        return False
    proc = _basename(ev.process_name)
    cmd = (ev.command_line or "").lower()
    if proc in {"cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "rundll32.exe"}:
        return True
    return any(token in cmd for token in ("sekurlsa", "pth", "mimikatz", "invoke-command", "wmic"))


def _dsrm_password_changed(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    seen = set()

    for ev in timed_events:
        if ev.event_id != 4794 or not _is_security_audit(ev):
            continue
        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        host = ev.computer or "unknown"
        logon_id = (ev.event_data.get("SubjectLogonId", "") or "").strip()
        related_ntdsutil = [
            other
            for other in timed_events
            if other.event_id == 4688
            and _is_security_audit(other)
            and (other.computer or "unknown") == host
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 300
            and _basename(other.process_name) == "ntdsutil.exe"
            and ((other.event_data.get("SubjectLogonId", "") or "").strip() == logon_id or not logon_id)
        ]
        key = (host.lower(), actor.lower(), logon_id or str(ev.timestamp))
        if key in seen:
            continue
        seen.add(key)
        command_line = next((item.command_line for item in related_ntdsutil if item.command_line), "")
        alerts.append(
            Alert(
                rule_name="DSRM Password Changed",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1098",
                description=f"{actor} changed the DSRM password on {host}",
                explanation="Event 4794 records a Directory Services Restore Mode password change, which can be abused to maintain privileged access to a domain controller.",
                confidence="high",
                investigate_next="Validate whether the DSRM reset was authorized, review who launched ntdsutil if present, and rotate the DSRM password if the change is suspicious.",
                event=ev,
                user=actor,
                process=related_ntdsutil[0].process_name if related_ntdsutil else "",
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id,
                    "related_process": related_ntdsutil[0].process_name if related_ntdsutil else "",
                    "command_line": command_line[:300],
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _password_policy_enumeration(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id != 4661 or not _is_security_audit(ev):
            continue
        if (ev.event_data.get("ObjectServer", "") or "").strip() != "Security Account Manager":
            continue
        obj_type = (ev.event_data.get("ObjectType", "") or "").strip().upper()
        if obj_type not in {"SAM_SERVER", "SAM_DOMAIN"}:
            continue
        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        logon_id = (ev.event_data.get("SubjectLogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        object_types = {(item.event_data.get("ObjectType", "") or "").strip().upper() for item in cluster}
        if not ({"SAM_SERVER", "SAM_DOMAIN"} <= object_types):
            continue
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        object_names = sorted({(item.event_data.get("ObjectName", "") or "").strip() for item in cluster if (item.event_data.get("ObjectName", "") or "").strip()})
        access_masks = sorted({(item.event_data.get("AccessMask", "") or "").strip() for item in cluster if (item.event_data.get("AccessMask", "") or "").strip()})
        alerts.append(
            Alert(
                rule_name="Password Policy Enumeration",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1201",
                description=f"{actor} enumerated password policy data on {host}",
                explanation="Security 4661 events show SAM server and domain object access consistent with password policy discovery.",
                confidence="high",
                investigate_next="Review what account performed the enumeration and whether it was expected administrative discovery on the domain controller.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "object_names": object_names,
                    "access_masks": access_masks,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _browser_logon_process_abuse(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in (4624, 4625) or not _is_security_audit(ev):
            continue
        if ev.logon_type != "2":
            continue

        proc_base = _basename(ev.process_name)
        if proc_base not in BROWSER_LOGON_PROCESS_MARKERS:
            continue

        logon_process = (ev.event_data.get("LogonProcessName", "") or "").strip().lower()
        normalized_logon_process = logon_process.replace(" ", "")
        if normalized_logon_process not in BROWSER_LOGON_PROCESS_MARKERS[proc_base]:
            continue

        host = ev.computer or "unknown"
        target_user = ev.target_domain_user or ev.domain_user or ev.target_user or "unknown"
        grouped[(host, target_user, ev.process_name or proc_base, normalized_logon_process)].append(ev)

    for (host, target_user, process_name, logon_process), cluster in grouped.items():
        successes = [item for item in cluster if item.event_id == 4624]
        failures = [item for item in cluster if item.event_id == 4625]
        if len(cluster) < 2 and not failures:
            continue

        ordered_cluster = sorted(cluster, key=lambda item: item.timestamp or datetime.min)
        first = ordered_cluster[0]
        browser_name = _basename(process_name) or process_name or logon_process
        alerts.append(
            Alert(
                rule_name="Browser Logon Process Abuse",
                severity="high" if failures else "medium",
                mitre_tactic="Credential Access",
                mitre_technique="T1556",
                description=(
                    f"{browser_name} registered interactive logon activity for {target_user} on {host} "
                    f"using LogonProcessName {first.event_data.get('LogonProcessName', '') or logon_process}"
                ),
                explanation=(
                    "Security logons were recorded with a browser-backed LogonProcessName and the browser executable as the "
                    "originating process. Legitimate browsers do not normally act as Windows interactive logon processes."
                ),
                confidence="high" if failures else "medium",
                investigate_next=(
                    "Review the browser process tree, any credential-prompting behavior, and adjacent authentication events "
                    "to determine whether credentials were harvested or replayed locally."
                ),
                event=first,
                user=target_user,
                process=process_name,
                evidence={
                    "target_user": target_user,
                    "browser_process": process_name,
                    "browser_family": browser_name,
                    "logon_process_name": first.event_data.get("LogonProcessName", ""),
                    "logon_type": first.logon_type,
                    "success_count": len(successes),
                    "failure_count": len(failures),
                    "status_codes": sorted(
                        {
                            (item.event_data.get("Status", "") or "").lower()
                            for item in failures
                            if (item.event_data.get("Status", "") or "").strip()
                        }
                    ),
                    "sub_status_codes": sorted(
                        {
                            (item.event_data.get("SubStatus", "") or "").lower()
                            for item in failures
                            if (item.event_data.get("SubStatus", "") or "").strip()
                        }
                    ),
                    "event_ids": [item.event_id for item in ordered_cluster],
                    "evidence_strength": "high" if failures else "medium",
                },
            )
        )

    return alerts


def _directinput_keylogger_registration(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str], List[Tuple[NormalizedEvent, str]]] = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 13 or not _is_sysmon_event(ev):
            continue
        target = (ev.event_data.get("TargetObject", "") or "").strip()
        lowered_target = target.lower()
        if DIRECTINPUT_MOSTRECENT_MARKER not in lowered_target:
            continue

        process = (ev.event_data.get("Image", "") or ev.process_name or "").strip()
        if not process or not _is_user_writable_process_path(process):
            continue

        registry_leaf = lowered_target.rsplit("\\", 1)[-1]
        if registry_leaf not in DIRECTINPUT_REQUIRED_KEYS:
            continue

        grouped[((ev.computer or "").lower(), process.lower())].append((ev, registry_leaf))

    for (host_key, process_key), grouped_events in grouped.items():
        unique_keys = {leaf for _, leaf in grouped_events}
        if len(unique_keys) < 3:
            continue

        first_event = grouped_events[0][0]
        host = first_event.computer or host_key or "unknown host"
        process = first_event.event_data.get("Image", "") or first_event.process_name or process_key
        alerts.append(
            Alert(
                rule_name="DirectInput Keylogger Registration",
                severity="high",
                mitre_tactic="Credential Access",
                mitre_technique="T1056.001",
                description=f"{process} registered DirectInput MostRecentApplication keys on {host}",
                explanation=(
                    "A user-writable executable updated multiple DirectInput MostRecentApplication registry values, which is consistent "
                    "with DirectInput-based keylogger registration or setup."
                ),
                confidence="high",
                investigate_next=(
                    "Preserve the executable, review nearby file writes and user-session activity, and determine whether the process was "
                    "intended software or an input-capture implant."
                ),
                event=first_event,
                process=process,
                evidence={
                    "process_path": process,
                    "registry_keys_modified": sorted(unique_keys),
                    "registry_key_count": len(unique_keys),
                    "event_count": len(grouped_events),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _kerberos_password_spray(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
    window = timedelta(minutes=15)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4768, 4771) or not _is_security_audit(ev):
            continue
        src = (ev.source_ip or _first_present(ev.event_data, "IpAddress")).strip()
        if not src or src in BENIGN_IPS:
            continue
        target = (ev.target_user or _first_present(ev.event_data, "TargetUserName")).strip()
        if not target:
            continue
        target_simple = _simple_account_name(target)
        if not target_simple or target_simple in {"system", "local service", "network service"} or target_simple.endswith("$"):
            continue
        if ev.event_id == 4768:
            service_name = (_first_present(ev.event_data, "ServiceName") or "").strip().lower()
            if "krbtgt" not in service_name:
                continue
        status = _normalize_hex_mask(_first_present(ev.event_data, "Status", "FailureCode"))
        if not status or status in {"0x0", "0x00000000", "0"}:
            continue
        if status not in KERBEROS_SPRAY_FAILURE_STATUSES:
            continue

        host = ev.computer or "unknown"
        grouped[(host, src)].append(ev)

    for (host, src), cluster in grouped.items():
        cluster = sorted(cluster, key=lambda item: item.timestamp or datetime.min)
        windows: List[List[NormalizedEvent]] = []
        current: List[NormalizedEvent] = []
        for ev in cluster:
            if current and ev.timestamp - current[-1].timestamp > window:
                windows.append(current)
                current = []
            current.append(ev)
        if current:
            windows.append(current)

        for window_events in windows:
            unique_users = sorted(
                {
                    _simple_account_name(item.target_user or _first_present(item.event_data, "TargetUserName"))
                    for item in window_events
                    if _simple_account_name(item.target_user or _first_present(item.event_data, "TargetUserName"))
                }
            )
            if len(unique_users) < 5:
                continue

            statuses = sorted(
                {
                    _normalize_hex_mask(_first_present(item.event_data, "Status", "FailureCode"))
                    for item in window_events
                    if _normalize_hex_mask(_first_present(item.event_data, "Status", "FailureCode"))
                }
            )
            ports = sorted(
                {
                    (_first_present(item.event_data, "IpPort") or "").strip()
                    for item in window_events
                    if (_first_present(item.event_data, "IpPort") or "").strip()
                }
            )
            first = window_events[0]
            count = len(window_events)
            alerts.append(
                Alert(
                    rule_name="Kerberos Password Spray",
                    severity="critical" if len(unique_users) >= 8 else "high",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110.003",
                    description=(
                        f"Kerberos authentication failures from {src} targeted {len(unique_users)} accounts on {host}."
                    ),
                    explanation=(
                        "Multiple failed Kerberos AS-REQ and pre-authentication attempts from one source targeted many different "
                        "accounts in a short window, which is consistent with password spraying rather than a single-user typo."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Review whether any of the sprayed accounts later authenticated successfully from the same source, "
                        "and contain or block the source system if it is not an approved administration host."
                    ),
                    event=first,
                    source_ip=src,
                    evidence={
                        "source_ip": src,
                        "target_accounts": unique_users,
                        "status_codes": statuses,
                        "event_count": count,
                        "host": host,
                        "ip_ports": ports[:10],
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _mssql_password_spray(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    tracker: Dict[Tuple[str, str], List[Tuple[datetime, NormalizedEvent, str, str]]] = defaultdict(list)
    alerted: Set[Tuple[str, str]] = set()
    window = timedelta(minutes=5)

    for ev in events:
        if ev.event_id != 18456 or not ev.timestamp:
            continue
        if "mssql" not in (ev.provider or "").lower():
            continue

        login, reason, client_ip = _extract_mssql_failed_logon_details(ev)
        if not client_ip or client_ip in BENIGN_IPS:
            continue

        host = ev.computer or "unknown"
        key = (host, client_ip)
        tracker[key].append((ev.timestamp, ev, login, reason))
        tracker[key] = [(ts, item, acct, msg) for ts, item, acct, msg in tracker[key] if ev.timestamp - ts <= window]

        window_events = tracker[key]
        if len(window_events) < 5 or key in alerted:
            continue

        unique_logins = {
            (acct or "").strip().lower()
            for _, _, acct, _ in window_events
            if (acct or "").strip()
        }
        non_system_logins = {acct for acct in unique_logins if not _is_benign_mssql_internal_login(acct)}
        if len(non_system_logins) < 2:
            continue

        alerted.add(key)
        total = len(window_events)
        logins = sorted(non_system_logins)[:8]
        reasons = sorted(
            {
                (msg or "").strip()
                for _, _, acct, msg in window_events
                if (acct or "").strip().lower() in non_system_logins and (msg or "").strip()
            }
        )
        severity = "critical" if total >= 10 or len(non_system_logins) >= 5 else "high"
        confidence = "high" if total >= 8 else "medium"

        alerts.append(
            Alert(
                rule_name="MSSQL Password Spray",
                severity=severity,
                mitre_tactic="Credential Access",
                mitre_technique="T1110.003",
                description=f"{total} SQL authentication failures from {client_ip} on {host} targeted {len(non_system_logins)} login(s)",
                explanation=(
                    "Repeated SQL Server Event ID 18456 failures from the same client targeted multiple non-system logins in a short window, "
                    "which is consistent with password spraying or credential guessing against SQL authentication."
                ),
                confidence=confidence,
                investigate_next=(
                    f"Review successful SQL logons from {client_ip}, validate whether the client is an approved admin workstation, "
                    "and investigate whether any of the targeted SQL logins were later used successfully."
                ),
                event=ev,
                source_ip=client_ip,
                evidence={
                    "source_ip": client_ip,
                    "target_accounts": logins,
                    "target_account_count": len(non_system_logins),
                    "failure_count": total,
                    "failure_reasons": reasons,
                    "provider": ev.provider,
                    "channel": ev.channel,
                    "evidence_strength": "high" if confidence == "high" else "medium",
                },
            )
        )

    return alerts


def _esent_ntds_snapshot_export(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    source_candidates: List[Tuple[NormalizedEvent, str]] = []
    export_candidates: List[Tuple[NormalizedEvent, str]] = []
    window = timedelta(minutes=5)
    seen: Set[Tuple[str, str, str]] = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in {325, 326, 327}:
            continue
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "esent" not in provider and "esent" not in channel:
            continue

        payload = " ".join(str(value) for value in (ev.event_data or {}).values() if value)
        strings = _extract_eventdata_strings(payload)
        if not strings or "ntds" not in {item.lower() for item in strings}:
            continue

        paths = _extract_ntds_paths(" ".join(strings))
        if not paths:
            continue

        for path in paths:
            if _is_ntds_snapshot_source_path(path):
                source_candidates.append((ev, path))
            else:
                export_candidates.append((ev, path))

    for export_event, export_path in export_candidates:
        host = export_event.computer or "unknown host"
        matches = [
            (source_event, source_path)
            for source_event, source_path in source_candidates
            if (source_event.computer or "") == (export_event.computer or "")
            if abs(export_event.timestamp - source_event.timestamp) <= window
        ]
        if not matches:
            continue

        source_paths = sorted({path for _, path in matches})
        related_event_ids = sorted(
            {
                other.event_id
                for other, other_path in source_candidates + export_candidates
                if (other.computer or "") == (export_event.computer or "")
                if abs(export_event.timestamp - other.timestamp) <= window
                if other_path.lower() == export_path.lower() or _is_ntds_snapshot_source_path(other_path)
            }
        )
        key = ((export_event.computer or "").lower(), export_path.lower(), "|".join(source_paths).lower())
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="NTDS.dit Snapshot Export",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.003",
                description=f"ESENT recorded NTDS.dit snapshot export activity on {host}",
                explanation=(
                    "ESENT application events recorded NTDS.dit being read from a snapshot-style source path and written to "
                    "a second destination path, which is consistent with NTDSUtil IFM or offline Active Directory database export."
                ),
                confidence="high",
                investigate_next=(
                    "Preserve the exported NTDS.dit copy and adjacent SYSTEM/SECURITY hive material, identify who ran the export "
                    "workflow, and review neighboring 4688, 4794, VSS, and backup-related activity on the host."
                ),
                event=export_event,
                evidence={
                    "source_paths": source_paths,
                    "export_path": export_path,
                    "event_ids": related_event_ids,
                    "provider": export_event.provider,
                    "channel": export_event.channel,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _lsass_remote_thread_injection(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    access_events: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)
    window = timedelta(seconds=10)
    seen: Set[Tuple[str, str, str]] = set()

    for ev in events:
        if ev.event_id != 10 or not _is_sysmon_event(ev):
            continue
        target_image = (ev.event_data.get("TargetImage", "") or "").strip().lower()
        if not target_image.endswith(r"\lsass.exe"):
            continue
        source_image = (ev.event_data.get("SourceImage", "") or "").strip()
        if not source_image:
            continue
        source_process_id = (ev.event_data.get("SourceProcessId", "") or "").strip()
        access_events[((ev.computer or "").lower(), source_image.lower(), source_process_id)].append(ev)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 8 or not _is_sysmon_event(ev):
            continue
        target_image = (ev.event_data.get("TargetImage", "") or "").strip().lower()
        if not target_image.endswith(r"\lsass.exe"):
            continue

        source_image = (ev.event_data.get("SourceImage", "") or "").strip()
        source_process_id = (ev.event_data.get("SourceProcessId", "") or "").strip()
        if not source_image:
            continue

        matches = [
            other
            for other in access_events.get(((ev.computer or "").lower(), source_image.lower(), source_process_id), [])
            if other.timestamp and abs(other.timestamp - ev.timestamp) <= window
            if _normalize_hex_mask(other.event_data.get("GrantedAccess", "")) not in LSASS_LOW_SIGNAL_QUERY_MASKS
        ]
        if not matches:
            continue

        key = ((ev.computer or "").lower(), source_image.lower(), source_process_id or "unknown")
        if key in seen:
            continue
        seen.add(key)

        access_masks = sorted(
            {
                _normalize_hex_mask(other.event_data.get("GrantedAccess", ""))
                for other in matches
                if _normalize_hex_mask(other.event_data.get("GrantedAccess", ""))
            }
        )
        host = ev.computer or "unknown host"
        alerts.append(
            Alert(
                rule_name="LSASS Remote Thread Injection",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"{source_image} injected into and accessed lsass.exe on {host}",
                explanation=(
                    "Sysmon recorded remote thread creation into lsass.exe followed by direct LSASS handle access from the same process, "
                    "which is strong evidence of credential-dumping or in-memory secret extraction activity."
                ),
                confidence="high",
                investigate_next=(
                    "Preserve the source binary, inspect any credential material or dump artifacts that followed, and treat LSASS-resident "
                    "credentials on the host as exposed until proven otherwise."
                ),
                event=ev,
                process=source_image,
                evidence={
                    "source_image": source_image,
                    "target_image": ev.event_data.get("TargetImage", ""),
                    "source_process_id": source_process_id,
                    "access_masks": access_masks,
                    "thread_start_address": ev.event_data.get("StartAddress", ""),
                    "thread_start_module": ev.event_data.get("StartModule", ""),
                    "thread_start_function": ev.event_data.get("StartFunction", ""),
                    "matched_access_event_count": len(matches),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _protected_storage_rpc_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen: Set[Tuple[str, str, str]] = set()

    for ev in events:
        if ev.event_id != 5145 or not _is_security_audit(ev):
            continue
        share_name = (_first_present(ev.event_data, "ShareName") or "").strip().lower()
        relative_target = (_first_present(ev.event_data, "RelativeTargetName") or "").strip()
        if "ipc$" not in share_name or relative_target.lower() != "protected_storage":
            continue
        actor = ev.subject_domain_user or ev.domain_user or _first_present(ev.event_data, "SubjectUserName")
        host = ev.computer or "unknown"
        src = (ev.source_ip or _first_present(ev.event_data, "IpAddress")).strip()
        key = (host.lower(), actor.lower(), src)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="Protected Storage RPC Access",
                severity="high",
                mitre_tactic="Credential Access",
                mitre_technique="T1555",
                description=(
                    f"{actor or 'Unknown user'} accessed protected_storage over IPC$ on {host}"
                    f"{' from ' + src if src else ''}."
                ),
                explanation=(
                    "Remote access to the protected_storage RPC target over IPC$ is consistent with attempts to reach stored "
                    "credential or DPAPI-related material rather than routine file-share activity."
                ),
                confidence="high",
                investigate_next=(
                    "Review adjacent RPC, DPAPI, and credential-theft activity from the same source and account, and "
                    "determine whether stored secrets or masterkey material were exposed."
                ),
                event=ev,
                user=actor,
                source_ip=src,
                share_name=_first_present(ev.event_data, "ShareName"),
                evidence={
                    "relative_target": relative_target,
                    "share_name": _first_present(ev.event_data, "ShareName"),
                    "access_mask": _first_present(ev.event_data, "AccessMask"),
                    "logon_id": _first_present(ev.event_data, "SubjectLogonId"),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _teamviewer_credential_memory_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen: Set[Tuple[str, str, str, str]] = set()

    for ev in events:
        if ev.event_id != 10 or not _is_sysmon_event(ev):
            continue
        source = (_first_present(ev.event_data, "SourceImage") or ev.process_name or "").strip()
        target = (_first_present(ev.event_data, "TargetImage") or "").strip()
        if "teamviewer.exe" not in target.lower() or not source:
            continue
        if _basename(source) == "teamviewer.exe":
            continue
        rule_name = (_first_present(ev.event_data, "RuleName") or "").strip().lower()
        access = _normalize_hex_mask(_first_present(ev.event_data, "GrantedAccess"))
        source_lower = source.lower()
        if (
            "teamviewer memaccess" not in rule_name
            and "frida" not in source_lower
            and access not in TEAMVIEWER_SUSPICIOUS_ACCESS_MASKS
        ):
            continue
        key = ((ev.computer or "").lower(), source.lower(), target.lower(), access or str(ev.timestamp))
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="TeamViewer Credential Memory Access",
                severity="high",
                mitre_tactic="Credential Access",
                mitre_technique="T1555",
                description=f"{source} accessed TeamViewer.exe memory on {ev.computer}.",
                explanation=(
                    "Direct process-memory access targeting TeamViewer.exe is consistent with theft of TeamViewer session "
                    "or credential material and should not appear during normal remote-support use."
                ),
                confidence="high",
                investigate_next=(
                    "Inspect the source process and adjacent TeamViewer activity, and rotate any credentials or unattended-access "
                    "secrets that may have been exposed from the affected host."
                ),
                event=ev,
                process=source,
                evidence={
                    "source_image": source,
                    "target_image": target,
                    "granted_access": access or _first_present(ev.event_data, "GrantedAccess"),
                    "rule_name": _first_present(ev.event_data, "RuleName"),
                    "call_trace": (_first_present(ev.event_data, "CallTrace") or "")[:500],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _kekeo_tsssp_named_pipe(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[str, List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in (17, 18) or not ev.timestamp or not _is_sysmon_event(ev):
            continue
        pipe_name = (_first_present(ev.event_data, "PipeName") or "").strip().lower()
        if pipe_name != KEKEO_DEFAULT_PIPE:
            continue
        image = (_first_present(ev.event_data, "Image", "ProcessName") or ev.process_name or "").strip()
        rule_name = (_first_present(ev.event_data, "RuleName") or "").strip().lower()
        if "kekeo" not in image.lower() and "keko default np" not in rule_name:
            continue
        grouped[ev.computer or "unknown"].append(ev)

    for host, cluster in grouped.items():
        cluster = sorted(cluster, key=lambda item: item.timestamp or datetime.min)
        windows: List[List[NormalizedEvent]] = []
        current: List[NormalizedEvent] = []
        for ev in cluster:
            if current and ev.timestamp - current[-1].timestamp > timedelta(minutes=5):
                windows.append(current)
                current = []
            current.append(ev)
        if current:
            windows.append(current)

        for window in windows:
            event_ids = {item.event_id for item in window}
            if not ({17, 18} & event_ids):
                continue
            first = window[0]
            images = sorted(
                {
                    (_first_present(item.event_data, "Image", "ProcessName") or item.process_name or "").strip()
                    for item in window
                    if (_first_present(item.event_data, "Image", "ProcessName") or item.process_name or "").strip()
                }
            )
            alerts.append(
                Alert(
                    rule_name="Kekeo TSSSP Named Pipe",
                    severity="high",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1550",
                    description=f"Kekeo created or connected to {KEKEO_DEFAULT_PIPE} on {host}.",
                    explanation=(
                        "Sysmon recorded Kekeo interacting with its default TSSSP named-pipe endpoint, which is strong evidence "
                        "of Kekeo-based credential or ticket abuse rather than normal Windows named-pipe activity."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Review adjacent Kerberos, NTLM, and ticket-manipulation activity from the same host, and preserve the "
                        "Kekeo binary or scripts that created the named pipe."
                    ),
                    event=first,
                    process=images[0] if images else first.process_name,
                    evidence={
                        "pipe_name": KEKEO_DEFAULT_PIPE,
                        "process_images": images,
                        "event_ids": sorted(event_ids),
                        "event_count": len(window),
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _wdigest_logon_credential_storage_enabled(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)

    for ev in timed_events:
        if ev.event_id != 13 or not _is_sysmon_event(ev):
            continue
        target = (ev.event_data.get("TargetObject", "") or "").lower()
        details = (ev.event_data.get("Details", "") or "").lower()
        if not target.endswith(r"\securityproviders\wdigest\uselogoncredential"):
            continue
        if "0x00000001" not in details and details.strip() not in {"1", "dword (0x00000001)"}:
            continue

        host = ev.computer or "unknown"
        process_guid = (ev.event_data.get("ProcessGuid", "") or "").strip()
        related_proc = next(
            (
                other
                for other in timed_events
                if other.event_id == 1
                and _is_sysmon_event(other)
                and (other.computer or "unknown") == host
                and (
                    ((other.event_data.get("ProcessGuid", "") or "").strip() == process_guid and process_guid)
                    or abs((other.timestamp - ev.timestamp).total_seconds()) <= 30
                )
                and _basename(other.process_name) == "reg.exe"
            ),
            None,
        )
        actor = (
            ((related_proc.event_data.get("User", "") or "").strip() if related_proc else "")
            or (related_proc.domain_user if related_proc else "")
            or ev.domain_user
            or ev.subject_domain_user
            or "unknown"
        )
        key = (host.lower(), actor.lower(), target)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_name="WDigest Logon Credential Storage Enabled",
                severity="high",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"WDigest credential caching was enabled on {host}",
                explanation="Setting WDigest UseLogonCredential to 1 stores cleartext credentials in memory, which attackers commonly enable before dumping LSASS.",
                confidence="high",
                investigate_next="Confirm whether WDigest was intentionally enabled, review the reg.exe parent chain, and inspect the host for follow-on LSASS access or credential dumping.",
                event=ev,
                user=actor,
                process=related_proc.process_name if related_proc else ev.process_name,
                evidence={
                    "actor_user": actor,
                    "target_object": ev.event_data.get("TargetObject", ""),
                    "details": ev.event_data.get("Details", ""),
                    "command_line": (related_proc.command_line if related_proc else "")[:300],
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _credential_manager_vault_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {5376, 5379, 5381, 5382} or not _is_security_audit(ev):
            continue
        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        logon_id = (ev.event_data.get("SubjectLogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        backup_files = sorted(
            {
                (item.event_data.get("BackupFileName", "") or "").strip()
                for item in cluster
                if (item.event_data.get("BackupFileName", "") or "").strip()
            }
        )
        resources = sorted(
            {
                (item.event_data.get("Resource", "") or "").strip()
                for item in cluster
                if (item.event_data.get("Resource", "") or "").strip()
            }
        )
        identities = sorted(
            {
                (item.event_data.get("Identity", "") or "").strip()
                for item in cluster
                if (item.event_data.get("Identity", "") or "").strip()
            }
        )
        target_names = sorted(
            {
                (item.event_data.get("TargetName", "") or "").strip()
                for item in cluster
                if (item.event_data.get("TargetName", "") or "").strip()
            }
        )
        max_returned = max((_int_value(item.event_data.get("CountOfCredentialsReturned", "0")) for item in cluster), default=0)
        successful_schema_reads = [
            item
            for item in cluster
            if item.event_id == 5382
            and (item.event_data.get("ReturnCode", "") or "").strip() in {"0", "0x0"}
            and "credential" in (item.event_data.get("SchemaFriendlyName", "") or "").lower()
        ]
        if not backup_files and not successful_schema_reads:
            continue
        if max_returned <= 0 and not resources and not target_names:
            continue

        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        benign_vault_churn = _is_benign_vault_churn(
            backup_files=backup_files,
            resources=resources,
            identities=identities,
            target_names=target_names,
            max_returned=max_returned,
            event_count=len(cluster),
        )
        alerts.append(
            Alert(
                rule_name="Windows Credential Manager Access",
                severity="medium" if benign_vault_churn else "high",
                mitre_tactic="Credential Access",
                mitre_technique="T1555.004",
                description=f"{actor} accessed Windows Credential Manager or Vault data on {host}",
                explanation="Security vault events show credential enumeration or retrieval activity consistent with Windows Credential Manager access.",
                confidence="medium" if benign_vault_churn else "high",
                promotion_policy="correlate" if benign_vault_churn else "standalone",
                investigate_next="Review the client process context, determine whether credentials were exported or viewed, and rotate any exposed secrets if the access was not expected.",
                event=first,
                user=actor,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "backup_files": backup_files,
                    "resources": resources,
                    "identities": identities,
                    "target_names": target_names,
                    "max_credentials_returned": max_returned,
                    "event_count": len(cluster),
                    "evidence_strength": "medium" if benign_vault_churn else "high",
                    "vault_access_profile": "application_vault_churn" if benign_vault_churn else "credential_export_or_retrieval",
                },
            )
        )
    return alerts


def _password_policy_discovery_command(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1}:
            continue
        cmd = (ev.command_line or "").lower()
        if not cmd:
            continue
        is_net_accounts = ("accounts" in cmd and "/domain" in cmd and _basename(ev.process_name) in {"net.exe", "net1.exe"})
        is_ad_cmdlet = "get-addefaultdomainpasswordpolicy" in cmd or "get-addomainpasswordpolicy" in cmd
        if not is_net_accounts and not is_ad_cmdlet:
            continue
        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        commands = sorted({(item.command_line or "").strip() for item in cluster if (item.command_line or "").strip()})
        alerts.append(
            Alert(
                rule_name="Command-Line Password Policy Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1201",
                description=f"{actor} queried password policy settings on {host}",
                explanation="Process creation events show command-line password policy discovery such as 'net accounts /domain' or AD password policy cmdlets.",
                confidence="high",
                investigate_next="Confirm whether the actor was performing expected administration and review adjacent discovery or credential-access activity from the same logon session.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "command_line": first.command_line,
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _user_account_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1, 4104}:
            continue
        command = (ev.command_line or ev.event_data.get("ScriptBlockText", "") or "").strip()
        if not command:
            continue
        command_l = command.lower()
        if any(marker in command_l for marker in DISCOVERY_MODIFIER_MARKERS):
            continue

        base = _basename(ev.process_name)
        is_net_user = base in {"net.exe", "net1.exe"} and " user " in f" {command_l} "
        is_ad_user = "get-aduser" in command_l or "get-localuser" in command_l
        if not is_net_user and not is_ad_user:
            continue

        actor = _resolve_discovery_actor(events, ev)
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        commands = sorted({(item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip() for item in cluster if (item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip()})
        alerts.append(
            Alert(
                rule_name="User Account Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1087",
                description=f"{actor} enumerated user-account information on {host}",
                explanation="Command-line or PowerShell user queries such as net user, Get-ADUser, or Get-LocalUser were observed and are consistent with account discovery.",
                confidence="high",
                investigate_next="Confirm whether the actor was performing approved administration and review nearby credential-access or privilege-escalation activity from the same session.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _group_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1, 4104}:
            continue
        command = (ev.command_line or ev.event_data.get("ScriptBlockText", "") or "").strip()
        if not command:
            continue
        command_l = command.lower()
        if any(marker in command_l for marker in DISCOVERY_MODIFIER_MARKERS):
            continue

        base = _basename(ev.process_name)
        is_net_group = base in {"net.exe", "net1.exe"} and any(token in f" {command_l} " for token in (" group ", " localgroup "))
        is_ps_group = any(token in command_l for token in ("get-adgroup", "get-adgroupmember", "get-localgroup", "get-localgroupmember", "whoami /groups"))
        if not is_net_group and not is_ps_group:
            continue

        actor = _resolve_discovery_actor(events, ev)
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        commands = sorted({(item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip() for item in cluster if (item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip()})
        alerts.append(
            Alert(
                rule_name="Group Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1069",
                description=f"{actor} enumerated local or domain groups on {host}",
                explanation="Group-query commands such as net group, net localgroup, Get-ADGroup, or Get-LocalGroup were observed and are consistent with permission-group discovery.",
                confidence="high",
                investigate_next="Validate whether the group enumeration was expected and correlate it with nearby account-discovery or privilege-targeting activity from the same session.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _network_share_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1, 4104}:
            continue
        command = (ev.command_line or ev.event_data.get("ScriptBlockText", "") or "").strip()
        if not command:
            continue
        command_l = command.lower()
        if " net use " in f" {command_l} " and "/delete" in command_l:
            continue

        base = _basename(ev.process_name)
        is_net_share = base in {"net.exe", "net1.exe"} and bool(re.search(r"\b(view|use)\b", command_l))
        is_dir_share = base in {"cmd.exe", "powershell.exe", "pwsh.exe"} and ("dir \\\\" in command_l or "get-childitem \\\\" in command_l)
        if not is_net_share and not is_dir_share:
            continue

        actor = _resolve_discovery_actor(events, ev)
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        commands = sorted({(item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip() for item in cluster if (item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip()})
        if not any((re.search(r"\bview\b", cmd.lower()) or "dir \\\\" in cmd.lower() or "get-childitem \\\\" in cmd.lower()) for cmd in commands):
            continue
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        alerts.append(
            Alert(
                rule_name="Network Share Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1135",
                description=f"{actor} enumerated network shares on {host}",
                explanation="Network-share discovery commands such as net view, dir \\\\host\\share, or related share connection probes were observed.",
                confidence="high",
                investigate_next="Determine whether the share enumeration was expected, then review nearby lateral-movement or file-collection activity from the same session.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _domain_trust_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1, 4104}:
            continue
        command = (ev.command_line or ev.event_data.get("ScriptBlockText", "") or "").strip()
        if not command:
            continue
        command_l = command.lower()
        base = _basename(ev.process_name)
        is_nltest = base == "nltest.exe" and any(token in command_l for token in ("/domain_trusts", "/all_trusts"))
        is_ad_trust = any(marker in command_l for marker in TRUST_DISCOVERY_MARKERS)
        if not is_nltest and not is_ad_trust:
            continue

        actor = _resolve_discovery_actor(events, ev)
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        commands = sorted({(item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip() for item in cluster if (item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip()})
        alerts.append(
            Alert(
                rule_name="Domain Trust Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1482",
                description=f"{actor} enumerated domain or forest trust information on {host}",
                explanation="PowerShell forest queries or nltest trust commands were observed and are consistent with Active Directory trust discovery.",
                confidence="high",
                investigate_next="Review whether the actor was expected to enumerate domain trusts and correlate the activity with broader AD reconnaissance or lateral-movement planning.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _spn_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1, 4104}:
            continue
        command = (ev.command_line or ev.event_data.get("ScriptBlockText", "") or "").strip()
        if not command:
            continue
        command_l = command.lower()
        base = _basename(ev.process_name)
        is_setspn_query = "setspn" in command_l and "-q" in command_l
        is_ps_spn = any(marker in command_l for marker in SPN_DISCOVERY_POWERSHELL_MARKERS)
        if not is_setspn_query and not is_ps_spn:
            continue
        if any(marker in command_l for marker in DISCOVERY_MODIFIER_MARKERS):
            continue

        actor = _resolve_discovery_actor(events, ev)
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        commands = sorted({(item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip() for item in cluster if (item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip()})
        if not any("-q" in cmd.lower() or "serviceprincipalname" in cmd.lower() for cmd in commands):
            continue
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        alerts.append(
            Alert(
                rule_name="SPN Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1087",
                description=f"{actor} queried service principal names on {host}",
                explanation="setspn query commands or PowerShell SPN enumeration were observed and are consistent with service-principal-name discovery ahead of Kerberos targeting.",
                confidence="high",
                investigate_next="Confirm whether the SPN query was expected administration and review nearby Kerberos-ticket or account-targeting activity from the same session.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _audit_policy_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1}:
            continue
        command = (ev.command_line or "").strip()
        command_l = command.lower()
        if _basename(ev.process_name) != "auditpol.exe":
            continue
        if "/get" not in command_l:
            continue

        actor = _resolve_discovery_actor(events, ev)
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        commands = sorted({(item.command_line or "").strip() for item in cluster if (item.command_line or "").strip()})
        alerts.append(
            Alert(
                rule_name="Audit Policy Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1016",
                description=f"{actor} enumerated audit policy settings on {host}",
                explanation="auditpol /get command execution was observed and is consistent with Windows audit policy discovery.",
                confidence="high",
                investigate_next="Determine whether the actor was expected to inspect audit policy and review adjacent defense-evasion or log-tampering behavior from the same session.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _firewall_configuration_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1, 4104}:
            continue
        command = (ev.command_line or ev.event_data.get("ScriptBlockText", "") or "").strip()
        if not command:
            continue
        command_l = command.lower()
        base = _basename(ev.process_name)
        is_netsh = base == "netsh.exe" and "advfirewall" in command_l and "show" in command_l
        is_powershell = any(token in command_l for token in ("get-netfirewallprofile", "get-netfirewallrule"))
        if not is_netsh and not is_powershell:
            continue

        actor = _resolve_discovery_actor(events, ev)
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        commands = sorted({(item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip() for item in cluster if (item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip()})
        lowered = [cmd.lower() for cmd in commands]
        if any("start-service sshd" in cmd or "set-service -name sshd" in cmd for cmd in lowered):
            continue

        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        alerts.append(
            Alert(
                rule_name="Firewall Configuration Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1016",
                description=f"{actor} enumerated firewall configuration on {host}",
                explanation="netsh advfirewall show or Get-NetFirewall* discovery commands were observed and are consistent with firewall configuration reconnaissance.",
                confidence="high",
                investigate_next="Confirm whether the firewall inspection was expected and review nearby remote-service enablement or ingress-tool-transfer activity from the same session.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _scheduled_task_configuration_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id not in {4688, 1, 4104}:
            continue
        command = (ev.command_line or ev.event_data.get("ScriptBlockText", "") or "").strip()
        if not command:
            continue
        command_l = command.lower()
        base = _basename(ev.process_name)
        is_schtasks = base == "schtasks.exe" and "/query" in command_l
        is_powershell = "get-scheduledtask" in command_l
        if ev.event_id == 4104 and is_powershell:
            noisy_markers = ("function get-scheduledtask", "export-modulemember", "cmdletization", "microsoft.management.infrastructure.ciminstance#msft_scheduledtask")
            if any(marker in command_l for marker in noisy_markers):
                is_powershell = False
        if not is_schtasks and not is_powershell:
            continue

        actor = _resolve_discovery_actor(events, ev)
        logon_id = (ev.event_data.get("SubjectLogonId", "") or ev.event_data.get("LogonId", "") or "").strip() or "(unknown)"
        grouped[(ev.computer or "unknown", actor, logon_id)].append(ev)

    for (host, actor, logon_id), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        commands = sorted({(item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip() for item in cluster if (item.command_line or item.event_data.get("ScriptBlockText", "") or "").strip()})
        alerts.append(
            Alert(
                rule_name="Scheduled Task Configuration Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1016",
                description=f"{actor} enumerated scheduled-task configuration on {host}",
                explanation="schtasks /query or Get-ScheduledTask activity was observed and is consistent with scheduled-task discovery.",
                confidence="high",
                investigate_next="Determine whether the actor was expected to inspect task configuration and review nearby persistence or elevated-task abuse from the same session.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "subject_logon_id": logon_id if logon_id != "(unknown)" else "",
                    "commands": commands,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _dns_zone_transfer_attempt(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id != 6004:
            continue
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "dns-server-service" not in provider and "dns server" not in channel:
            continue
        source_ip = (ev.event_data.get("param1", "") or "").strip()
        grouped[(ev.computer or "unknown", source_ip or "(unknown)")].append(ev)

    for (host, source_ip), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        zones = sorted({(item.event_data.get("param2", "") or "").strip() for item in cluster if (item.event_data.get("param2", "") or "").strip()})
        alerts.append(
            Alert(
                rule_name="DNS Zone Transfer Attempt",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1016",
                description=f"{source_ip or 'An unknown source'} attempted DNS zone transfer discovery against {host}",
                explanation="DNS Server event 6004 recorded failed zone-transfer requests, which are consistent with DNS configuration and zone reconnaissance.",
                confidence="high",
                investigate_next="Review whether the source is authorized to request zone transfers and inspect the source host or IP for follow-on DNS or AD discovery activity.",
                event=first,
                user="unknown",
                source_ip="" if source_ip == "(unknown)" else source_ip,
                evidence={
                    "source_ip": "" if source_ip == "(unknown)" else source_ip,
                    "zones": zones,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _local_account_enumeration(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id != 4798 or not _is_security_audit(ev):
            continue
        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        grouped[(ev.computer or "unknown", actor)].append(ev)

    for (host, actor), cluster in grouped.items():
        actor_name = (actor.split("\\")[-1] if actor else "").lower()
        if actor_name in {"administrator", "admin"} and len(cluster) < 2:
            continue
        first = sorted(cluster, key=lambda item: item.timestamp or datetime.min)[0]
        enumerated_accounts = sorted(
            {
                (
                    ev.target_domain_user
                    or ev.event_data.get("TargetAccount", "")
                    or ev.event_data.get("TargetUserName", "")
                    or ""
                ).strip()
                for ev in cluster
                if (
                    ev.target_domain_user
                    or ev.event_data.get("TargetAccount", "")
                    or ev.event_data.get("TargetUserName", "")
                    or ""
                ).strip()
            }
        )
        if enumerated_accounts and all((account.split("\\")[-1].lower() == actor_name) for account in enumerated_accounts):
            continue
        alerts.append(
            Alert(
                rule_name="Local Account Enumeration",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1087.001",
                description=f"{actor} enumerated local account details on {host}",
                explanation="Security event 4798 indicates local-account enumeration, which is commonly used to identify privileged or interactive accounts before follow-on activity.",
                confidence="high",
                investigate_next="Validate whether the account lookup was expected and review nearby privilege escalation or credential access from the same user and host.",
                event=first,
                user=actor,
                evidence={
                    "actor_user": actor,
                    "enumerated_accounts": enumerated_accounts,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _local_group_enumeration(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id != 4799 or not _is_security_audit(ev):
            continue
        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        grouped[(ev.computer or "unknown", actor)].append(ev)

    for (host, actor), cluster in grouped.items():
        actor_name = (actor.split("\\")[-1] if actor else "").lower()
        if actor_name in {"administrator", "admin"} and len(cluster) < 2:
            continue
        first = sorted(cluster, key=lambda item: item.timestamp or datetime.min)[0]
        enumerated_groups = sorted(
            {
                (
                    ev.target_domain_user
                    or ev.event_data.get("TargetGroupName", "")
                    or ev.event_data.get("TargetUserName", "")
                    or ""
                ).strip()
                for ev in cluster
                if (
                    ev.target_domain_user
                    or ev.event_data.get("TargetGroupName", "")
                    or ev.event_data.get("TargetUserName", "")
                    or ""
                ).strip()
            }
        )
        alerts.append(
            Alert(
                rule_name="Local Group Enumeration",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1069.001",
                description=f"{actor} enumerated local group membership on {host}",
                explanation="Security event 4799 records local-group membership enumeration and is commonly used to identify administrator and operator groups before lateral movement.",
                confidence="high",
                investigate_next="Confirm whether the local group lookup was expected and correlate it with nearby user discovery, share discovery, or privilege-targeting activity.",
                event=first,
                user=actor,
                evidence={
                    "actor_user": actor,
                    "enumerated_groups": enumerated_groups,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _remote_rpc_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    suspicious_targets = {"samr", "lsarpc", "srvsvc", "winreg", "wkssvc", "netlogon"}
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_id != 5145 or not _is_security_audit(ev):
            continue
        share_name = (ev.event_data.get("ShareName", "") or "").strip().lower()
        if "ipc$" not in share_name:
            continue
        relative_target = (ev.event_data.get("RelativeTargetName", "") or "").strip().lower()
        if relative_target not in suspicious_targets:
            continue
        src = (ev.source_ip or ev.event_data.get("IpAddress", "") or "").strip()
        if src in BENIGN_IPS:
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        grouped[(ev.computer or "unknown", actor, src)].append(ev)

    for (host, actor, src), cluster in grouped.items():
        unique_targets = sorted(
            {
                (ev.event_data.get("RelativeTargetName", "") or "").strip()
                for ev in cluster
                if (ev.event_data.get("RelativeTargetName", "") or "").strip()
            }
        )
        if len(unique_targets) < 2:
            continue
        first = sorted(cluster, key=lambda item: item.timestamp or datetime.min)[0]
        alerts.append(
            Alert(
                rule_name="Remote RPC Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1018",
                description=f"{actor} probed remote IPC/RPC endpoints on {host} from {src}",
                explanation="Repeated IPC$ accesses to RPC endpoints such as samr, lsarpc, srvsvc, winreg, or netlogon indicate remote account, session, or host discovery across Windows RPC interfaces.",
                confidence="high",
                investigate_next="Review whether the source host should be querying remote RPC services, then correlate the activity with follow-on remote execution, account targeting, or BloodHound-style AD reconnaissance.",
                event=first,
                user=actor,
                source_ip=src,
                evidence={
                    "actor_user": actor,
                    "source_ip": src,
                    "share_name": first.event_data.get("ShareName", ""),
                    "rpc_targets": unique_targets,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )
    return alerts


def _pass_the_hash(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((ev for ev in events if ev.timestamp), key=lambda ev: ev.timestamp)

    for ev in timed_events:
        if ev.event_id != 4624 or ev.logon_type != "9":
            continue
        if not _is_security_audit(ev):
            continue

        logon_process = (ev.event_data.get("LogonProcessName", "") or "").strip().lower()
        if logon_process != "seclogo":
            continue

        logon_id = _extract_logon_id(ev)
        user = ev.target_domain_user or ev.domain_user or "unknown"
        related = []
        privileged = False
        suspicious_processes = []

        if logon_id:
            window_end = ev.timestamp + timedelta(minutes=10)
            for other in timed_events:
                if other.timestamp <= ev.timestamp or other.timestamp > window_end:
                    continue
                if (other.computer or "") != (ev.computer or ""):
                    continue
                if _extract_logon_id(other) != logon_id:
                    continue

                if other.event_id == 4672:
                    privileged = True
                    related.append(
                        {
                            "event_id": 4672,
                            "timestamp": other.timestamp.isoformat() if other.timestamp else None,
                            "description": f"Special privileges assigned to {other.subject_domain_user or other.subject_user or user}",
                        }
                    )
                elif _is_suspicious_process(other):
                    suspicious_processes.append(other)
                    related.append(
                        {
                            "event_id": other.event_id,
                            "timestamp": other.timestamp.isoformat() if other.timestamp else None,
                            "process": other.process_name,
                            "command_line": other.command_line[:300],
                        }
                    )

        description = (
            "A logon using LogonType 9 (NewCredentials) was observed. "
            "This logon type is commonly used by Pass-the-Hash tools such as Mimikatz."
        )
        if privileged:
            description += " Special privileges were assigned to the same logon session."
        if suspicious_processes:
            procs = ", ".join(sorted({_basename(item.process_name) or "unknown" for item in suspicious_processes}))
            description += f" Suspicious follow-on process activity was also observed: {procs}."

        alerts.append(
            Alert(
                rule_name="Pass-the-Hash Logon",
                severity="critical" if privileged or suspicious_processes else "high",
                mitre_tactic="Credential Access",
                mitre_technique="T1550.002",
                description=description,
                explanation=(
                    "LogonType 9 with LogonProcessName seclogo indicates a NewCredentials session, "
                    "which is strongly associated with pass-the-hash and token-based credential abuse."
                ),
                confidence="high",
                investigate_next=(
                    f"Review all activity tied to logon ID {logon_id or '(unknown)'} on {ev.computer}. "
                    f"Validate whether {user} legitimately initiated a NewCredentials session and inspect follow-on privileged actions."
                ),
                event=ev,
                user=user,
                source_ip="" if ev.source_ip in BENIGN_IPS else ev.source_ip,
                evidence={
                    "logon_id": logon_id,
                    "logon_type": ev.logon_type,
                    "logon_type_name": ev.logon_type_name,
                    "logon_process_name": logon_process,
                    "privileged_followup": privileged,
                    "related_events": related,
                    "related_event_ids": [item["event_id"] for item in related],
                    "suspicious_processes": [item.process_name for item in suspicious_processes if item.process_name],
                    "suspicious_commands": [item.command_line[:300] for item in suspicious_processes if item.command_line],
                    "source_process": ev.process_name,
                    "source_process_basename": _basename(ev.process_name),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _brute_force(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    tracker: Dict[str, List[Tuple[datetime, NormalizedEvent]]] = defaultdict(list)
    alerted: Set[str] = set()
    window = timedelta(minutes=10)

    for ev in events:
        if ev.event_id != 4625 or not ev.timestamp:
            continue
        if not _is_security_audit(ev) or not ev.target_user:
            continue
        user = (ev.target_user or "").lower()
        if user in ("-", "", "system", "local service", "network service") or user.endswith("$"):
            continue

        src = ev.source_ip or "(local)"
        tracker[src].append((ev.timestamp, ev))
        tracker[src] = [(t, e) for t, e in tracker[src] if ev.timestamp - t <= window]

        if len(tracker[src]) >= 5 and src not in alerted:
            alerted.add(src)
            accounts = set(e.target_user for _, e in tracker[src] if e.target_user)
            count = len(tracker[src])
            reason = ev.failure_reason
            alerts.append(Alert(
                rule_name="Brute Force Attack",
                severity="critical" if count >= 15 else "high",
                mitre_tactic="Credential Access", mitre_technique="T1110.001",
                description=f"{count} failed logons from {src} in 10 min targeting: {', '.join(list(accounts)[:5])}",
                explanation="Multiple failed logon attempts from the same source indicate a brute force attack attempting to guess credentials.",
                confidence="high" if count >= 10 else "medium",
                investigate_next=f"Check if {src} is an authorized admin workstation. Review successful logons from this IP. If external, block immediately.",
                event=ev,
                evidence={"source_ip": src, "count": count, "accounts": list(accounts), "failure_reason": reason, "evidence_strength": "high" if count >= 10 else "medium"},
            ))
    return alerts


def _password_spray(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    tracker: Dict[str, Set[str]] = defaultdict(set)
    alerted: Set[str] = set()

    for ev in events:
        if ev.event_id != 4625:
            continue
        if not _is_security_audit(ev):
            continue
        src = ev.source_ip or ""
        target = ev.target_user or ""
        if not src or src in BENIGN_IPS or not target:
            continue
        tracker[src].add(target.lower())

        if len(tracker[src]) >= 3 and src not in alerted:
            alerted.add(src)
            alerts.append(Alert(
                rule_name="Password Spray Attack",
                severity="critical", mitre_tactic="Credential Access",
                mitre_technique="T1110.003",
                description=f"Password spray from {src}: {len(tracker[src])} unique accounts targeted",
                explanation="One source trying many different accounts suggests password spray — one common password tested across many accounts to avoid lockout.",
                confidence="high",
                investigate_next=f"Check if any logon succeeded from {src} after the spray. Block the IP if external. Review targeted accounts for compromise.",
                event=ev, evidence={"source_ip": src, "accounts": list(tracker[src]), "evidence_strength": "high"},
            ))
    return alerts


def _lsass_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    suspicious_masks = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff"}
    dump_events = [
        item
        for item in events
        if item.event_id == 11
        and _is_sysmon_event(item)
        and (item.event_data.get("TargetFilename", "") or "").strip().lower().endswith(".dmp")
    ]
    for ev in events:
        if ev.event_id != 10:
            continue
        if not _is_sysmon_event(ev):
            continue
        target = (ev.event_data.get("TargetImage", "") or "").lower()
        if "lsass.exe" not in target:
            continue
        source = (ev.event_data.get("SourceImage", "") or "").strip()
        if not source:
            continue
        normalized_access = _normalize_hex_mask(ev.event_data.get("GrantedAccess", ""))
        source_base = _basename(source)
        source_user = (ev.event_data.get("SourceUser", "") or "").strip().lower()
        target_user = (ev.event_data.get("TargetUser", "") or "").strip().lower()
        call_trace = (ev.event_data.get("CallTrace", "") or "").strip()
        dump_path = ""
        if ev.timestamp:
            for other in dump_events:
                if (other.computer or "") != (ev.computer or ""):
                    continue
                other_proc = _basename(other.process_name or other.event_data.get("ProcessName", "") or other.event_data.get("Image", "") or "")
                if other_proc != source_base:
                    continue
                if other.timestamp and abs(other.timestamp - ev.timestamp) > timedelta(minutes=5):
                    continue
                dump_path = (other.event_data.get("TargetFilename", "") or "").strip()
                if dump_path:
                    break

        is_low_signal_system_query = (
            normalized_access in LSASS_LOW_SIGNAL_QUERY_MASKS
            and source.lower() in BENIGN_LSASS_QUERY_SOURCES
            and source_user in SYSTEM_IDENTITY_ALIASES
            and target_user in SYSTEM_IDENTITY_ALIASES
            and not dump_path
        )
        if is_low_signal_system_query:
            continue

        if _is_benign_microsoft_lsass_query(
            source=source,
            normalized_access=normalized_access,
            source_user=source_user,
            target_user=target_user,
            dump_path=dump_path,
            call_trace=call_trace,
        ):
            continue

        is_suspicious = normalized_access in suspicious_masks or bool(dump_path)
        evidence = {
            "source_image": source,
            "access_mask": normalized_access or (ev.event_data.get("GrantedAccess", "") or "").strip(),
            "evidence_strength": "high" if is_suspicious else "medium",
        }
        if dump_path:
            evidence["dump_path"] = dump_path
        alerts.append(Alert(
            rule_name="LSASS Memory Access",
            severity="critical" if is_suspicious else "high",
            mitre_tactic="Credential Access", mitre_technique="T1003.001",
            description=f"LSASS accessed by {source} (mask: {evidence['access_mask']}) on {ev.computer}",
            explanation="LSASS holds credential material in memory. This access pattern matches credential dumping tools like Mimikatz.",
            confidence="high" if is_suspicious else "medium",
            investigate_next=f"Identify the process {source}. Check if it's a known security tool or malicious. Look for credential use from dumped accounts.",
            event=ev, evidence=evidence,
        ))
    return alerts


def _credential_dump(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.event_id not in (4688, 1):
            continue
        cmd = ev.command_line.lower()
        if not cmd:
            continue
        # SAM/SYSTEM/SECURITY hive dump
        if "reg" in cmd and "save" in cmd:
            for hive in ["sam", "system", "security"]:
                if hive in cmd:
                    alerts.append(Alert(
                        rule_name=f"{hive.upper()} Hive Dump", severity="critical",
                        mitre_tactic="Credential Access", mitre_technique="T1003.002",
                        description=f"{hive.upper()} hive exported by {ev.domain_user} on {ev.computer}",
                        explanation=f"The {hive.upper()} hive contains credential data. Exporting it enables offline cracking.",
                        confidence="high",
                        investigate_next=f"Check for SYSTEM hive export in the same timeframe (both needed to decrypt SAM). Identify where the file was saved.",
                        event=ev, evidence={"command_line": cmd[:500], "hive": hive, "evidence_strength": "high"},
                    ))
                    break
        # DCSync
        for pat in ["dcsync", "lsadump::dcsync", "secretsdump", "ntdsutil"]:
            if pat in cmd:
                if pat == "ntdsutil" and any(
                    other.event_id == 4794
                    and _is_security_audit(other)
                    and (other.computer or "") == (ev.computer or "")
                    and abs((other.timestamp - ev.timestamp).total_seconds()) <= 300
                    and ((other.event_data.get("SubjectLogonId", "") or "").strip() == (ev.event_data.get("SubjectLogonId", "") or "").strip() or not (ev.event_data.get("SubjectLogonId", "") or "").strip())
                    for other in events
                    if other.timestamp and ev.timestamp
                ):
                    break
                alerts.append(Alert(
                    rule_name="DCSync / NTDS Dump", severity="critical",
                    mitre_tactic="Credential Access", mitre_technique="T1003.006",
                    description=f"DCSync by {ev.domain_user} on {ev.computer}: {cmd[:150]}",
                    explanation="DCSync replicates all domain password hashes from a DC. This gives the attacker every credential in the domain.",
                    confidence="high",
                    investigate_next="Immediately check which accounts were replicated. Reset krbtgt and all privileged account passwords. Assume full domain compromise.",
                    event=ev, evidence={"command_line": cmd[:500], "evidence_strength": "high"},
                ))
                break
    return alerts


def _kerberoasting(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.event_id != 4769:
            continue
        if not _is_security_audit(ev):
            continue
        enc = ev.event_data.get("TicketEncryptionType", "")
        svc = ev.event_data.get("ServiceName", "")
        if enc == "0x17" and "krbtgt" not in (svc or "").lower():
            client = ev.target_user or ""
            alerts.append(Alert(
                rule_name="Kerberoasting", severity="high",
                mitre_tactic="Credential Access", mitre_technique="T1558.003",
                description=f"RC4 TGS request for '{svc}' by {client}",
                explanation="RC4 tickets are crackable offline. Attackers request them to extract service account passwords without triggering lockout.",
                confidence="medium",
                investigate_next=f"Check if '{svc}' is a service account with a weak password. Review if the requesting user '{client}' normally accesses this service.",
                event=ev, evidence={"service": svc, "encryption": enc, "client": client, "evidence_strength": "medium"},
            ))
    return alerts


def _asrep_roasting(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 4768:
            continue
        if not _is_security_audit(ev):
            continue

        preauth = _first_present(
            ev.event_data,
            "PreAuthType",
            "PreAuthenticationType",
            "Pre-AuthenticationType",
        ).lower()
        if preauth not in {"0", "0x0"}:
            continue

        user = ev.target_domain_user or ev.target_user or ev.account_name or ""
        if not user or user.rstrip().endswith("$"):
            continue

        ticket_encryption = _first_present(ev.event_data, "TicketEncryptionType", "TicketEncryption")
        source_ip = ev.source_ip or _first_present(ev.event_data, "IpAddress", "ClientAddress")
        service = _first_present(ev.event_data, "ServiceName") or "krbtgt"
        key = (ev.computer or "", user.lower(), source_ip or "", ticket_encryption or "")
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="AS-REP Roasting",
                severity="high",
                mitre_tactic="Credential Access",
                mitre_technique="T1558.004",
                description=(
                    f"Kerberos AS-REQ for {user} on {ev.computer} completed without pre-authentication"
                    f"{' from ' + source_ip if source_ip else ''}."
                ),
                explanation=(
                    "Accounts with Kerberos pre-authentication disabled can be targeted for AS-REP roasting. "
                    "The returned AS-REP can be cracked offline without knowing the user's password."
                ),
                confidence="high",
                investigate_next=(
                    f"Confirm whether {user} is intentionally configured without pre-authentication, capture nearby Kerberos activity, "
                    "and reset the account if the request was unexpected."
                ),
                event=ev,
                user=user,
                source_ip="" if source_ip in BENIGN_IPS else source_ip,
                evidence={
                    "preauth_type": preauth,
                    "ticket_encryption": ticket_encryption,
                    "service": service,
                    "source_ip": source_ip,
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _golden_ticket_use_pattern(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    asreq_users = set()
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if not _is_security_audit(ev):
            continue

        source_ip = (ev.source_ip or _first_present(ev.event_data, "IpAddress", "ClientAddress")).strip()
        if not source_ip or source_ip in BENIGN_IPS:
            continue

        status = (_first_present(ev.event_data, "Status") or "0x0").lower()
        if status not in {"0x0", "0x00000000"}:
            continue

        user = _first_present(ev.event_data, "TargetUserName", "AccountName") or ev.target_domain_user or ev.target_user
        simple_user = _simple_account_name(user)
        if not simple_user or simple_user.endswith("$"):
            continue

        if ev.event_id == 4768:
            asreq_users.add((simple_user, source_ip))
            continue

        if ev.event_id != 4769:
            continue

        grouped[(ev.computer or "", source_ip, simple_user)].append(ev)

    for (host, source_ip, simple_user), cluster in grouped.items():
        if len(cluster) < 3 or (simple_user, source_ip) in asreq_users:
            continue

        windows: List[List[NormalizedEvent]] = []
        current: List[NormalizedEvent] = []
        for ev in cluster:
            if not current:
                current = [ev]
                continue
            if (ev.timestamp - current[-1].timestamp) <= timedelta(minutes=10):
                current.append(ev)
            else:
                windows.append(current)
                current = [ev]
        if current:
            windows.append(current)

        for window in windows:
            if len(window) < 3:
                continue

            services = [(_first_present(ev.event_data, "ServiceName") or "").strip() for ev in window]
            service_names = {svc.lower() for svc in services if svc}
            machine_services = {svc for svc in service_names if svc.endswith("$")}
            if "krbtgt" not in service_names or len(machine_services) < 2:
                continue

            ticket_options = sorted(
                {
                    (_first_present(ev.event_data, "TicketOptions") or "").strip()
                    for ev in window
                    if (_first_present(ev.event_data, "TicketOptions") or "").strip()
                }
            )
            ticket_users = sorted(
                {
                    (_first_present(ev.event_data, "TargetUserName") or ev.target_domain_user or ev.target_user or "").strip()
                    for ev in window
                    if (_first_present(ev.event_data, "TargetUserName") or ev.target_domain_user or ev.target_user or "").strip()
                }
            )
            first = window[0]
            alerts.append(
                Alert(
                    rule_name="Golden Ticket Use Pattern",
                    severity="critical",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1558.001",
                    description=(
                        f"Kerberos service-ticket requests for {ticket_users[0] if ticket_users else simple_user} on {host or 'unknown host'} "
                        f"used multiple machine services from {source_ip} without a matching AS-REQ."
                    ),
                    explanation=(
                        "A burst of successful 4769 requests to krbtgt and multiple machine services without a corresponding 4768 "
                        "AS-REQ from the same source is consistent with forged Kerberos ticket use."
                    ),
                    confidence="high",
                    investigate_next=(
                        f"Validate whether {ticket_users[0] if ticket_users else simple_user} should be requesting service tickets from {source_ip}, "
                        "review the TGT source on the originating workstation, and invalidate suspicious Kerberos tickets."
                    ),
                    event=first,
                    user=ticket_users[0] if ticket_users else simple_user,
                    source_ip=source_ip,
                    evidence={
                        "target_users": ticket_users,
                        "service_names": sorted(service_names),
                        "ticket_options": ticket_options,
                        "event_count": len(window),
                        "no_prior_as_req": True,
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


GOLDEN_TICKET_PATTERNS = (
    re.compile(r"kerberos::" + r"golden", re.IGNORECASE),
    re.compile(r"rubeus(?:\.exe)?\b.*\bgolden\b", re.IGNORECASE),
)
SILVER_TICKET_PATTERNS = (
    re.compile(r"kerberos::" + r"silver", re.IGNORECASE),
    re.compile(r"rubeus(?:\.exe)?\b.*\bsilver\b", re.IGNORECASE),
)


def _forged_kerberos_ticket_tooling(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    ticket_tokens = ("kerberos::", "rubeus", ".kirbi", "/ptt", "ticket")
    golden_marker = "kerberos::" + "golden"
    silver_marker = "kerberos::" + "silver"
    for ev in events:
        if ev.event_id not in (4688, 1, 4104):
            continue

        text = " ".join(
            part
            for part in [
                ev.command_line or "",
                " ".join(str(value or "") for value in (ev.event_data or {}).values()),
            ]
            if part
        )
        if not text.strip():
            continue
        lowered = text.lower()
        if not any(token in lowered for token in ticket_tokens):
            continue

        patterns = []
        if any(pattern.search(text) for pattern in GOLDEN_TICKET_PATTERNS):
            patterns.append(("Golden Ticket Forgery Tooling", "T1558.001", "krbtgt-backed forged TGT activity"))
        if any(pattern.search(text) for pattern in SILVER_TICKET_PATTERNS):
            patterns.append(("Silver Ticket Forgery Tooling", "T1558.002", "forged service-ticket activity"))

        if not patterns:
            continue

        for rule_name, technique, summary in patterns:
            key = (rule_name, ev.computer or "", (ev.user or ev.domain_user or "").lower(), lowered[:220])
            if key in seen:
                continue
            seen.add(key)
            alerts.append(
                Alert(
                    rule_name=rule_name,
                    severity="critical",
                    mitre_tactic="Credential Access",
                    mitre_technique=technique,
                    description=f"{summary.capitalize()} detected on {ev.computer}",
                    explanation=(
                        "The command or script content contains explicit forged-ticket tooling references. "
                        "This is strong evidence of Kerberos ticket forgery or preparation to inject forged tickets."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Preserve the command, inspect nearby Kerberos logons and service-ticket activity, and assume the affected identity may already be impersonated."
                    ),
                    event=ev,
                    user=ev.domain_user or ev.subject_domain_user or ev.target_domain_user,
                    process=ev.process_name,
                    evidence={
                        "command_line": text[:500],
                        "process_name": ev.process_name,
                        "tool_markers": sorted(
                            {
                                marker
                                for marker in [golden_marker, silver_marker, "rubeus", ".kirbi", "/ptt"]
                                if marker in lowered
                            }
                        ),
                        "evidence_strength": "high",
                    },
                )
            )
    return alerts


def _credential_files(events: List[NormalizedEvent], suppressed_event_ids: Set[int] | None = None) -> List[Alert]:
    alerts = []
    suppressed = suppressed_event_ids or set()
    cred_files = ["ntds.dit", ".kdbx", "unattend.xml", "sysprep.xml",
                  "web credentials", "login data", "groups.xml"]
    for ev in events:
        if id(ev) in suppressed:
            continue
        if ev.event_id not in (11, 4663):
            continue
        target = (ev.event_data.get("TargetFilename", "")
                  or ev.event_data.get("ObjectName", "") or "").lower()
        for cf in cred_files:
            if cf in target:
                alerts.append(Alert(
                    rule_name="Credential File Access", severity="high",
                    mitre_tactic="Credential Access", mitre_technique="T1552.001",
                    description=f"Credential file accessed on {ev.computer}: {target}",
                    explanation=f"'{cf}' stores credentials. Accessing it suggests credential theft.",
                    confidence="medium",
                    investigate_next=f"Check which process accessed this file. Determine if the file was copied or exfiltrated.",
                    event=ev, evidence={"file": target, "evidence_strength": "medium"},
                ))
                break
    return alerts


def _browser_credential_store_access(events: List[NormalizedEvent]) -> Tuple[List[Alert], Set[int]]:
    alerts: List[Alert] = []
    suppressed_ids: Set[int] = set()
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (11, 4663):
            continue

        target = (ev.event_data.get("TargetFilename", "") or ev.event_data.get("ObjectName", "") or "").strip()
        target_l = target.lower()
        families = _browser_families_for_target(target_l)
        if not families:
            continue

        proc = (ev.process_name or ev.event_data.get("ProcessName", "") or ev.event_data.get("Image", "") or "").strip()
        proc_base = os.path.basename(proc.replace("\\", "/")).lower()
        if not proc_base or proc_base in BENIGN_BROWSER_PROCESSES:
            continue

        actor = ev.domain_user or ev.subject_domain_user or ev.target_domain_user or ev.event_data.get("User", "") or "unknown"
        key = (ev.computer or "unknown", actor, proc.lower())
        grouped[key].append(ev)

    for (host, actor, proc), items in grouped.items():
        cluster: List[NormalizedEvent] = []
        clusters: List[List[NormalizedEvent]] = []
        for ev in items:
            if cluster and ev.timestamp - cluster[-1].timestamp > timedelta(minutes=20):
                clusters.append(cluster)
                cluster = []
            cluster.append(ev)
        if cluster:
            clusters.append(cluster)

        for cluster in clusters:
            accessed_files = []
            browser_families = set()
            for ev in cluster:
                target = (ev.event_data.get("TargetFilename", "") or ev.event_data.get("ObjectName", "") or "").strip()
                target_l = target.lower()
                matched = _browser_families_for_target(target_l)
                browser_families.update(matched)
                if target:
                    accessed_files.append(target)

            unique_files = sorted(set(accessed_files))
            if len(unique_files) < 2 and len(browser_families) < 2:
                continue

            suppressed_ids.update(id(ev) for ev in cluster)
            first = cluster[0]
            alerts.append(
                Alert(
                    rule_name="Browser Credential Store Access",
                    severity="critical" if len(browser_families) >= 2 or len(unique_files) >= 3 else "high",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1555.003",
                    description=f"{os.path.basename(proc)} accessed browser credential stores on {host}",
                    explanation=(
                        "A non-browser process accessed multiple browser password-store files. This is consistent with tooling that steals saved browser credentials."
                    ),
                    confidence="high",
                    investigate_next=(
                        f"Inspect {proc} on {host}, recover the accessed browser store files, and determine whether saved credentials for {actor or 'the affected user'} were copied or exfiltrated."
                    ),
                    event=first,
                    user=actor,
                    process=proc,
                    evidence={
                        "actor_user": actor,
                        "process_name": proc,
                        "browser_families": sorted(browser_families),
                        "credential_files": unique_files[:25],
                        "file_access_count": len(cluster),
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts, suppressed_ids


def _lockout(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 4740:
            continue
        if not _is_security_audit(ev):
            continue
        account = ev.target_user or ""
        key = f"{account}:{ev.computer}"
        if key not in seen:
            seen.add(key)
            alerts.append(Alert(
                rule_name="Account Locked Out", severity="high",
                mitre_tactic="Credential Access", mitre_technique="T1110",
                description=f"Account '{account}' locked out on {ev.computer}",
                explanation="Account lockout follows excessive failed logons. This is often the result of a brute force or spray attack.",
                confidence="high",
                investigate_next=f"Review failed logon events (4625) for '{account}' to identify the source IP. Check if the account was compromised before lockout.",
                event=ev, evidence={"account": account, "evidence_strength": "high"},
            ))
    return alerts


def _first_present(values: Dict[str, str], *names: str) -> str:
    for name in names:
        value = (values.get(name, "") or "").strip()
        if value:
            return value
    return ""


