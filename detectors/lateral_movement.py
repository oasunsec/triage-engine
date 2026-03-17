"""Lateral movement detection with evidence chains and guidance."""

import os
import re
from collections import defaultdict
from datetime import timedelta
from typing import List, Set, Tuple
from models.event_model import NormalizedEvent, Alert

BENIGN_IPS = frozenset({"127.0.0.1", "::1", "-", "", "0.0.0.0", "fe80::1"})
WINRM_HOST_PROCESSES = {"wsmprovhost.exe", "winrshost.exe", "wsmhost.exe"}
SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe"}
SUSPICIOUS_PIPE_NAMES = ("atsvc", "svcctl", "task", "remcom", "paexec")
REMOTE_EXEC_COMMAND_MARKERS = ("\\\\", "admin$", "/s ", "/node:", "winrs", "invoke-command", "psexec", "paexec")
LOCALHOST_TARGETS = {"", "-", "localhost", "127.0.0.1", "::1"}
LOOPBACK_NETWORK_TARGETS = {"127.0.0.1", "127.0.0.2", "::1"}
OPENSSH_CAPABILITY_RE = re.compile(r"openssh\.server[~0-9.]*", re.IGNORECASE)
OPENSSH_LISTEN_RE = re.compile(r"server listening on\s+(.+?)\s+port\s+(\d+)\.", re.IGNORECASE)
POWERSHELL_CONTEXT_USER_RE = re.compile(r"^\s*User\s*=\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
NETSH_LISTEN_PORT_RE = re.compile(r"\b(?:l|listenport)\s*=\s*(\d+)", re.IGNORECASE)
NETSH_LISTEN_ADDRESS_RE = re.compile(r"\blistena(?:ddress)?\s*=\s*([^\s]+)", re.IGNORECASE)
NETSH_CONNECT_PORT_RE = re.compile(r"\bconnectp(?:ort)?\s*=\s*(\d+)", re.IGNORECASE)
NETSH_CONNECT_ADDRESS_RE = re.compile(r"\b(?:c|connecta(?:ddress)?)\s*=\s*([^\s]+)", re.IGNORECASE)
IIS_SUSPICIOUS_CHILDREN = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "cscript.exe",
    "wscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "net.exe",
    "net1.exe",
    "whoami.exe",
}
PSEXEC_PIPE_RE = re.compile(
    r"cmd\.exe\s+/c\s+echo\s+([A-Za-z0-9_-]{4,})\s*>\s*\\\\\.\\pipe\\([A-Za-z0-9_-]{4,})",
    re.IGNORECASE,
)
PSEXEC_STDIO_PIPE_RE = re.compile(r"^\\([^\\]+)-([A-Za-z0-9._-]+)-(\d+)-(stdin|stdout|stderr)$", re.IGNORECASE)
SERVICE_IMAGEPATH_REGISTRY_RE = re.compile(r"\\services\\([^\\]+)\\imagepath$", re.IGNORECASE)
TUNNELING_PROCESS_NAMES = {"plink.exe", "w3wp.exe", "ssh.exe", "putty.exe", "ngrok.exe"}
SUSPICIOUS_REMOTE_FILE_EXTENSIONS = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta")
SUSPICIOUS_REMOTE_FILE_NAMES = {"malwr.exe", "wodcmdterm.exe", "psexesvc.exe", "swdrm.dll"}
SUSPICIOUS_REMOTE_PATH_MARKERS = ("\\start menu\\programs\\startup", "mimikatz")


def _is_security_audit(ev: NormalizedEvent) -> bool:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    return "security-auditing" in provider or channel == "security"


def detect(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    spray_alerts, explicit_spray_event_ids = _explicit_credential_password_spray(events)
    alerts.extend(spray_alerts)
    alerts.extend(_iis_webshell_execution(events))
    alerts.extend(_dcom_internet_explorer_execution(events))
    alerts.extend(_dcom_mshta_remote_execution(events))
    alerts.extend(_rdp_shadowing_enabled(events))
    alerts.extend(_openssh_server_installed(events))
    alerts.extend(_openssh_server_enabled(events))
    alerts.extend(_openssh_server_listening(events))
    alerts.extend(_wmi_remote_registry_modification(events))
    alerts.extend(_wmi_remote_execution(events))
    alerts.extend(_winrm_remote_execution(events))
    alerts.extend(_remote_hosts_file_discovery(events))
    alerts.extend(_anonymous_smb_service_probe(events))
    alerts.extend(_rdp_authentication_accepted(events))
    alerts.extend(_rdp_logon_via_loopback(events))
    alerts.extend(_kerberos_loopback_admin_logon(events))
    alerts.extend(_netsh_portproxy_tunnel(events))
    alerts.extend(_plink_rdp_tunnel(events))
    alerts.extend(_loopback_rdp_tunnel(events))
    alerts.extend(_loopback_smb_tunnel(events))
    alerts.extend(_remote_print_spooler_pipe_access(events))
    alerts.extend(_remote_named_pipe_execution(events))
    alerts.extend(_remote_service_payload_staging(events))
    alerts.extend(_psexec_service_binary_drop(events))
    alerts.extend(_renamed_psexec_service_pipes(events))
    alerts.extend(_psexec_named_pipe_stager(events))
    alerts.extend(_explicit_credentials_remote_sequence(events))
    alerts.extend(_psexec_remote_execution_sequence(events))
    alerts.extend(_smbexec_remote_execution_sequence(events))
    alerts.extend(_atexec_remote_task_sequence(events))
    for ev in events:
        alerts.extend(_check(ev, explicit_spray_event_ids))
    return alerts


def _rdp_shadowing_enabled(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1, 4104):
            continue

        text = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        text_l = text.lower()
        if "remote desktop - shadow (tcp-in)" not in text_l:
            continue
        if "setdwordvalue" not in text_l or "terminal services" not in text_l or "shadow" not in text_l:
            continue
        if "uvalue=[uint32]2" not in text_l and "uvalue = [uint32]2" not in text_l and "uvalue=2" not in text_l:
            continue

        actor = ev.domain_user or ev.subject_domain_user or ev.event_data.get("User", "") or "unknown"
        key = (ev.computer or "unknown", actor)
        clusters = grouped[key]
        if clusters and ev.timestamp - clusters[-1][-1].timestamp <= timedelta(minutes=20):
            clusters[-1].append(ev)
        else:
            clusters.append([ev])

    for (host, actor), clusters in grouped.items():
        for cluster in clusters:
            first_event = cluster[0]
            alerts.append(
                Alert(
                    rule_name="RDP Shadowing Enabled",
                    severity="critical",
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021.001",
                    description=f"{actor} enabled RDP shadowing on {host}",
                    explanation=(
                        "Enabling the Remote Desktop - Shadow firewall rule and setting the Terminal Services shadow policy allows interactive "
                        "RDP session shadowing or remote control with reduced user visibility."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Review who enabled shadowing, confirm whether the host should allow remote session control, and inspect for follow-on RDP or remote assistance activity."
                    ),
                    event=first_event,
                    user=actor,
                    process=first_event.process_name,
                    evidence={
                        "actor_user": actor,
                        "firewall_rule": "Remote Desktop - Shadow (TCP-In)",
                        "registry_subkey": r"Software\Policies\Microsoft\Windows NT\Terminal Services",
                        "registry_value": "shadow",
                        "shadow_value": 2,
                        "command_lines": [item.command_line[:500] for item in cluster if item.command_line][:5],
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _explicit_credential_password_spray(events: List[NormalizedEvent]) -> Tuple[List[Alert], Set[int]]:
    alerts: List[Alert] = []
    suppressed_ids: Set[int] = set()
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 4648 or not _is_security_audit(ev):
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        if actor.lower().endswith("$"):
            continue
        target_user = ev.target_domain_user or ev.event_data.get("TargetUserName", "") or ""
        if not target_user:
            continue

        src = (ev.source_ip or ev.event_data.get("IpAddress", "") or "").strip()
        target_server = (
            ev.event_data.get("TargetServerName", "")
            or ev.event_data.get("TargetInfo", "")
            or ev.computer
            or "unknown"
        ).strip()
        key = (
            ev.computer or "unknown",
            actor,
            src or "(unknown)",
            target_server or "(unknown)",
            _extract_logon_id(ev) or "(unknown)",
        )
        grouped[key].append(ev)

    for (host, actor, src, target_server, logon_id), items in grouped.items():
        cluster = []
        clusters = []
        for ev in items:
            if cluster and ev.timestamp - cluster[-1].timestamp > timedelta(minutes=10):
                clusters.append(cluster)
                cluster = []
            cluster.append(ev)
        if cluster:
            clusters.append(cluster)

        for cluster in clusters:
            accounts = sorted(
                {
                    (ev.target_domain_user or ev.event_data.get("TargetUserName", "") or "").strip()
                    for ev in cluster
                    if (ev.target_domain_user or ev.event_data.get("TargetUserName", "") or "").strip()
                }
            )
            if len(accounts) < 8:
                continue

            first_event = cluster[0]
            suppressed_ids.update(id(ev) for ev in cluster)
            alerts.append(
                Alert(
                    rule_name="Password Spray Attack",
                    severity="critical",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110.003",
                    description=f"{actor} used explicit credentials against {len(accounts)} accounts from {src or host} targeting {target_server}",
                    explanation=(
                        "Repeated Event 4648 explicit-credential attempts against many different accounts indicate password spraying via explicit logon APIs "
                        "rather than isolated administrative RunAs usage."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Review whether any of the targeted accounts authenticated successfully afterward, block the spraying source if untrusted, "
                        "and reset credentials for accounts that show follow-on access."
                    ),
                    event=first_event,
                    user=actor,
                    source_ip="" if src in {"(unknown)", ""} else src,
                    evidence={
                        "actor_user": actor,
                        "source_host": host,
                        "source_ip": "" if src in {"(unknown)", ""} else src,
                        "target_server": target_server,
                        "subject_logon_id": logon_id,
                        "targeted_accounts": accounts[:100],
                        "unique_account_count": len(accounts),
                        "event_count": len(cluster),
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts, suppressed_ids


def _basename(path: str) -> str:
    text = (path or "").replace("\\", "/").strip()
    return os.path.basename(text).lower()


def _extract_logon_id(ev: NormalizedEvent) -> str:
    return (
        ev.event_data.get("SubjectLogonId", "")
        or ev.event_data.get("TargetLogonId", "")
        or ev.event_data.get("LogonId", "")
    ).strip()


def _process_user(ev: NormalizedEvent) -> str:
    return (
        ev.event_data.get("User", "")
        or ev.domain_user
        or ev.target_domain_user
        or ev.subject_domain_user
        or "unknown"
    )


def _extract_powershell_context_user(context_info: str) -> str:
    match = POWERSHELL_CONTEXT_USER_RE.search(context_info or "")
    return (match.group(1) or "").strip() if match else ""


def _resolve_powershell_actor(events: List[NormalizedEvent], ev: NormalizedEvent) -> str:
    actor = _process_user(ev)
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


def _extract_pipe_name(command: str) -> str:
    match = PSEXEC_PIPE_RE.search(command or "")
    if not match:
        return ""
    left, right = match.groups()
    return right if left.lower() == right.lower() else ""


def _extract_psexec_stdio_pipe(pipe_name: str) -> Tuple[str, str, str, str] | None:
    match = PSEXEC_STDIO_PIPE_RE.match((pipe_name or "").strip())
    if not match:
        return None
    return (
        (match.group(1) or "").strip(),
        (match.group(2) or "").strip(),
        (match.group(3) or "").strip(),
        (match.group(4) or "").strip().lower(),
    )


def _normalize_command_text(value: str) -> str:
    text = (value or "").strip().replace('\\"', '"').replace("`\"", '"')
    while len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text


def _extract_service_binary(ev: NormalizedEvent) -> str:
    return (
        ev.event_data.get("ImagePath", "")
        or ev.event_data.get("ServiceFileName", "")
        or ""
    )


def _parse_service_imagepath_registry_write(ev: NormalizedEvent) -> Tuple[str, str] | None:
    provider_context = f"{ev.provider} {ev.channel}".lower()
    if "sysmon" not in provider_context or ev.event_id != 13:
        return None
    if (ev.event_data.get("EventType", "") or "").strip().lower() != "setvalue":
        return None
    target_object = (ev.event_data.get("TargetObject", "") or ev.event_data.get("ObjectName", "") or "").strip()
    match = SERVICE_IMAGEPATH_REGISTRY_RE.search(target_object)
    if not match:
        return None
    payload = _normalize_command_text(ev.event_data.get("Details", "") or ev.event_data.get("NewValue", "") or "")
    if not payload:
        return None
    return (match.group(1) or "").strip(), payload


def _looks_like_local_service_pipe_stager(events: List[NormalizedEvent], stager_event: NormalizedEvent, command: str) -> bool:
    if not stager_event.timestamp:
        return False

    host = stager_event.computer or "unknown"
    normalized_command = _normalize_command_text(command).lower()
    matching_services = set()

    for other in events:
        if (other.computer or "unknown") != host or not other.timestamp:
            continue
        if abs((other.timestamp - stager_event.timestamp).total_seconds()) > 120:
            continue
        parsed = _parse_service_imagepath_registry_write(other)
        if not parsed:
            continue
        service_name, payload = parsed
        if payload.lower() != normalized_command:
            continue
        matching_services.add(service_name.lower())

    if not matching_services:
        return False

    for other in events:
        if other.event_id not in (4697, 7045) or not other.timestamp:
            continue
        if (other.computer or "unknown") != host:
            continue
        if abs((other.timestamp - stager_event.timestamp).total_seconds()) > 120:
            continue
        service_name = (other.event_data.get("ServiceName", "") or other.service_name or "").strip().lower()
        service_binary = _normalize_command_text(_extract_service_binary(other)).lower()
        if service_name in matching_services or service_binary == normalized_command:
            return False

    return True


def _normalize_binary_basename(value: str) -> str:
    text = (value or "").strip().lower().replace("%systemroot%", r"c:\windows")
    return _basename(text)


def _normalize_windows_path(value: str) -> str:
    return (value or "").strip().replace("/", "\\")


def _is_suspicious_remote_payload_path(relative_target: str) -> bool:
    normalized = _normalize_windows_path(relative_target).lower()
    if not normalized:
        return False

    basename = _basename(normalized)
    if normalized.endswith(".exe"):
        return True
    if basename in SUSPICIOUS_REMOTE_FILE_NAMES:
        return True
    if any(marker in normalized for marker in SUSPICIOUS_REMOTE_PATH_MARKERS):
        return True
    if normalized.endswith(SUSPICIOUS_REMOTE_FILE_EXTENSIONS):
        if "\\windows\\temp\\" in normalized or "\\users\\public\\" in normalized:
            return True
    return False


def _is_non_system_account(user: str) -> bool:
    value = (user or "").strip().lower()
    if not value:
        return False
    if value.endswith("$"):
        return False
    return value not in {
        "system",
        "nt authority\\system",
        "local service",
        "nt authority\\local service",
        "network service",
        "nt authority\\network service",
        "anonymous logon",
        "nt authority\\anonymous logon",
    }


def _rdp_authentication_accepted(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 1149:
            continue
        channel = (ev.channel or "").lower()
        provider = (ev.provider or "").lower()
        if "terminalservices-remoteconnectionmanager" not in channel and "terminalservices-remoteconnectionmanager" not in provider:
            continue

        actor = (ev.event_data.get("Param1", "") or ev.domain_user or ev.target_domain_user or "").strip()
        src = (ev.event_data.get("Param3", "") or ev.source_ip or "").strip()
        source_host = (ev.event_data.get("Param2", "") or "").strip()
        if not actor or not src:
            continue
        if src in BENIGN_IPS or src.lower().startswith("fe80:"):
            continue

        key = (ev.computer or "unknown", actor.lower(), src)
        clusters = grouped[key]
        if clusters and ev.timestamp - clusters[-1][-1].timestamp <= timedelta(hours=2):
            clusters[-1].append(ev)
        else:
            clusters.append([ev])

    for (host, actor_key, src), clusters in grouped.items():
        for cluster in clusters:
            if len(cluster) < 2:
                continue
            first = cluster[0]
            actor = (first.event_data.get("Param1", "") or first.domain_user or first.target_domain_user or "unknown").strip()
            source_hosts = sorted(
                {
                    (item.event_data.get("Param2", "") or "").strip()
                    for item in cluster
                    if (item.event_data.get("Param2", "") or "").strip()
                }
            )
            alerts.append(
                Alert(
                    rule_name="Repeated RDP Authentication Accepted",
                    severity="high",
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021.001",
                    description=f"{actor} authenticated to {host} over RDP from {src} {len(cluster)} times",
                    explanation="Repeated TerminalServices 1149 success events from the same remote source indicate accepted interactive RDP access and can reflect hands-on lateral movement.",
                    confidence="medium",
                    investigate_next="Correlate these 1149 events with nearby 4624 LogonType 10 sessions, interactive process creation, and any tunnel or port-forwarding activity from the same source.",
                    event=first,
                    user=actor,
                    source_ip=src,
                    evidence={
                        "actor_user": actor,
                        "source_ip": src,
                        "source_host_values": source_hosts,
                        "auth_count": len(cluster),
                        "evidence_strength": "medium",
                    },
                )
            )

    return alerts


def _rdp_logon_via_loopback(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    seen = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 4624 or not _is_security_audit(ev):
            continue
        if (ev.logon_type or "") != "10":
            continue

        src = (ev.source_ip or ev.event_data.get("IpAddress", "") or "").strip()
        if src not in LOOPBACK_NETWORK_TARGETS:
            continue
        actor = (ev.target_domain_user or ev.domain_user or ev.target_user or "").strip()
        if not _is_non_system_account(actor):
            continue

        dedupe_key = (ev.computer or "unknown", actor.lower(), src, ev.timestamp.isoformat())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        alerts.append(
            Alert(
                rule_name="RDP Logon via Loopback",
                severity="high",
                mitre_tactic="Command and Control",
                mitre_technique="T1572",
                description=f"{actor} established an RDP session on {ev.computer} from loopback address {src}",
                explanation="An RDP LogonType 10 session sourced from 127.0.0.1 or ::1 is consistent with local port forwarding or a tunneled remote desktop session landing back on the host.",
                confidence="high",
                investigate_next="Correlate this loopback RDP session with portproxy, SSH/plink, or other local forwarding activity, then recover the real upstream source if possible.",
                event=ev,
                user=actor,
                source_ip=src,
                process=ev.process_name,
                evidence={
                    "actor_user": actor,
                    "source_ip": src,
                    "logon_type": ev.logon_type,
                    "workstation_name": (ev.event_data.get("WorkstationName", "") or "").strip(),
                    "process_name": ev.process_name,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _kerberos_loopback_admin_logon(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    seen = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 4624 or not _is_security_audit(ev):
            continue
        if (ev.logon_type or "") != "3":
            continue

        src = (ev.source_ip or ev.event_data.get("IpAddress", "") or "").strip()
        if src not in LOOPBACK_NETWORK_TARGETS:
            continue

        auth_package = (ev.event_data.get("AuthenticationPackageName", "") or "").strip().lower()
        logon_process = (ev.event_data.get("LogonProcessName", "") or "").strip().lower()
        if auth_package != "kerberos" or logon_process != "kerberos":
            continue

        target_user = (ev.target_domain_user or ev.target_user or ev.domain_user or "").strip()
        target_user_l = target_user.lower()
        if target_user_l not in {"administrator"} and not target_user_l.endswith("\\administrator"):
            continue

        subject_sid = (ev.event_data.get("SubjectUserSid", "") or "").strip().upper()
        subject_user = (ev.event_data.get("SubjectUserName", "") or ev.subject_user or "").strip()
        subject_domain = (ev.event_data.get("SubjectDomainName", "") or ev.subject_domain or "").strip()
        null_subject = subject_sid == "S-1-0-0" or (
            subject_user in {"", "-"} and subject_domain in {"", "-"}
        )
        if not null_subject:
            continue

        workstation = (ev.event_data.get("WorkstationName", "") or "").strip()
        if workstation not in {"", "-"}:
            continue

        key_length = (ev.event_data.get("KeyLength", "") or "").strip()
        if key_length and key_length != "0":
            continue

        dedupe_key = (ev.computer or "unknown", target_user.lower(), src, ev.timestamp.isoformat())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        alerts.append(
            Alert(
                rule_name="Kerberos Loopback Administrator Logon",
                severity="high",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1557",
                description=(
                    f"{target_user} authenticated to {ev.computer} via loopback Kerberos network logon "
                    f"from {src}"
                ),
                explanation=(
                    "A LogonType 3 Kerberos success from loopback with a null subject SID into an Administrator "
                    "account is consistent with local Kerberos relay behavior used by tooling such as KrbRelayUp."
                ),
                confidence="high",
                investigate_next=(
                    "Treat this as potential local privilege escalation: inspect nearby service and token activity, "
                    "review newly created privileged contexts, and collect process lineage around the logon timestamp."
                ),
                event=ev,
                user=target_user,
                source_ip=src,
                evidence={
                    "target_user": target_user,
                    "source_ip": src,
                    "logon_type": ev.logon_type,
                    "authentication_package": ev.event_data.get("AuthenticationPackageName", ""),
                    "logon_process_name": ev.event_data.get("LogonProcessName", ""),
                    "subject_user_sid": ev.event_data.get("SubjectUserSid", ""),
                    "subject_user_name": ev.event_data.get("SubjectUserName", ""),
                    "subject_domain_name": ev.event_data.get("SubjectDomainName", ""),
                    "workstation_name": ev.event_data.get("WorkstationName", ""),
                    "key_length": ev.event_data.get("KeyLength", ""),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _parse_netsh_portproxy_command(command: str) -> Tuple[str, str, str, str]:
    text = command or ""
    listen_port = (NETSH_LISTEN_PORT_RE.search(text).group(1) if NETSH_LISTEN_PORT_RE.search(text) else "").strip()
    listen_address = (NETSH_LISTEN_ADDRESS_RE.search(text).group(1) if NETSH_LISTEN_ADDRESS_RE.search(text) else "").strip()
    connect_port = (NETSH_CONNECT_PORT_RE.search(text).group(1) if NETSH_CONNECT_PORT_RE.search(text) else "").strip()
    connect_address = (NETSH_CONNECT_ADDRESS_RE.search(text).group(1) if NETSH_CONNECT_ADDRESS_RE.search(text) else "").strip()
    return listen_address, listen_port, connect_address, connect_port


def _netsh_portproxy_tunnel(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        listen_address = ""
        listen_port = ""
        connect_address = ""
        connect_port = ""

        if ev.event_id == 13:
            provider = (ev.provider or "").lower()
            channel = (ev.channel or "").lower()
            if "sysmon" not in provider and "sysmon" not in channel:
                continue
            target_object = (ev.event_data.get("TargetObject", "") or "").strip()
            if "\\services\\portproxy\\v4tov4\\tcp\\" not in target_object.lower():
                continue
            details = (ev.event_data.get("Details", "") or "").strip()
            listen_fragment = target_object.rsplit("\\", 1)[-1].replace("\\", "/")
            details_fragment = details.replace("\\", "/")
            if "/" in listen_fragment:
                listen_address, listen_port = listen_fragment.split("/", 1)
            if "/" in details_fragment:
                connect_address, connect_port = details_fragment.split("/", 1)
        elif ev.event_id in (1, 4688):
            command = (ev.command_line or ev.event_data.get("CommandLine", "") or "").strip()
            if "netsh" not in command.lower() or "portproxy" not in command.lower() and " connectp=" not in command.lower():
                continue
            listen_address, listen_port, connect_address, connect_port = _parse_netsh_portproxy_command(command)
        else:
            continue

        if connect_port not in {"3389", "445"}:
            continue

        actor = _process_user(ev)
        service_label = "RDP" if connect_port == "3389" else "SMB"
        key = (
            ev.computer or "unknown",
            listen_address.lower(),
            listen_port,
            connect_address.lower(),
            connect_port,
        )
        grouped[key].append((ev, actor))

    for (host, listen_address, listen_port, connect_address, connect_port), cluster in grouped.items():
        actor = next((candidate for _, candidate in cluster if candidate and candidate.lower() != "unknown"), "unknown")
        first = cluster[0][0]
        service_label = "RDP" if connect_port == "3389" else "SMB"
        alerts.append(
            Alert(
                rule_name=f"Netsh PortProxy {service_label} Tunnel",
                severity="high",
                mitre_tactic="Command and Control",
                mitre_technique="T1572",
                description=f"{actor} configured a netsh portproxy {service_label} listener on {host} forwarding {listen_address or '0.0.0.0'}:{listen_port or '?'} to {connect_address or 'unknown'}:{connect_port}",
                explanation="netsh interface portproxy can expose an internal RDP or SMB service through a forwarded listener, which is a common way to tunnel access through a compromised Windows host.",
                confidence="high",
                investigate_next="Confirm whether portproxy forwarding was authorized, identify who connected to the listener, and correlate the forwarded port with loopback logons or remote-service use.",
                event=first,
                user=actor,
                process=first.process_name,
                evidence={
                    "actor_user": actor,
                    "listen_address": listen_address,
                    "listen_port": listen_port,
                    "connect_address": connect_address,
                    "connect_port": connect_port,
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _openssh_server_installed(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    seen = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 4104:
            continue

        command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        command_l = command.lower()
        if "add-windowscapability" not in command_l or "openssh.server" not in command_l:
            continue

        host = ev.computer or "unknown"
        actor = _resolve_powershell_actor(events, ev)
        capability_match = OPENSSH_CAPABILITY_RE.search(command)
        capability_name = capability_match.group(0) if capability_match else "OpenSSH.Server"
        dedupe_key = (host, actor.lower(), capability_name.lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        alerts.append(
            Alert(
                rule_name="OpenSSH Server Installed",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.004",
                description=f"{actor} installed the OpenSSH server capability on {host}",
                explanation=(
                    "Installing the Windows OpenSSH.Server capability exposes the host to SSH-based remote access and is a common precursor to remote administration or persistence."
                ),
                confidence="high",
                investigate_next=(
                    "Confirm whether SSH server installation was approved, review who initiated the PowerShell session, and inspect whether sshd was started or left enabled afterward."
                ),
                event=ev,
                user=actor,
                process="powershell.exe",
                evidence={
                    "actor_user": actor,
                    "capability_name": capability_name,
                    "script_block_text": command[:500],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _openssh_server_enabled(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4104, 4688, 1):
            continue

        command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        command_l = command.lower()
        if "sshd" not in command_l:
            continue

        is_start = "start-service" in command_l and "sshd" in command_l
        is_auto = "set-service" in command_l and "sshd" in command_l and "startuptype" in command_l and "automatic" in command_l
        if not is_start and not is_auto:
            continue

        host = ev.computer or "unknown"
        actor = _resolve_powershell_actor(events, ev) if ev.event_id == 4104 else _process_user(ev)
        key = (host, actor)
        clusters = grouped[key]
        if clusters and ev.timestamp - clusters[-1][-1].timestamp <= timedelta(minutes=30):
            clusters[-1].append(ev)
        else:
            clusters.append([ev])

    for (host, actor), clusters in grouped.items():
        for cluster in clusters:
            commands = [item.command_line or item.event_data.get("ScriptBlockText", "") or "" for item in cluster]
            commands_l = [item.lower() for item in commands if item]
            if not any("start-service" in item and "sshd" in item for item in commands_l):
                continue
            if not any("set-service" in item and "sshd" in item and "startuptype" in item and "automatic" in item for item in commands_l):
                continue

            first_event = cluster[0]
            alerts.append(
                Alert(
                    rule_name="OpenSSH Server Enabled",
                    severity="high",
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021.004",
                    description=f"{actor} started sshd and configured it for automatic startup on {host}",
                    explanation=(
                        "Starting sshd and changing its startup type to Automatic enables persistent SSH-based remote access on the Windows host."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Review whether the host is approved to expose SSH, confirm who enabled the service, and inspect firewall or follow-on remote logon activity on port 22."
                    ),
                    event=first_event,
                    user=actor,
                    process="powershell.exe",
                    service="sshd",
                    evidence={
                        "actor_user": actor,
                        "service_name": "sshd",
                        "service_started": True,
                        "startup_type": "Automatic",
                        "command_lines": [item[:500] for item in commands if item][:6],
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _openssh_server_listening(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 4:
            continue
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "openssh" not in provider and "openssh" not in channel:
            continue

        payload = (ev.event_data.get("payload", "") or "").strip()
        process_name = (ev.event_data.get("process", "") or ev.process_name or "").strip()
        match = OPENSSH_LISTEN_RE.search(payload)
        if not match:
            continue

        port = match.group(2).strip()
        host = ev.computer or "unknown"
        key = (host, port)
        grouped[key].append(ev)

    for (host, port), cluster in grouped.items():
        addresses = []
        process_name = ""
        for item in cluster:
            payload = (item.event_data.get("payload", "") or "").strip()
            match = OPENSSH_LISTEN_RE.search(payload)
            if match:
                addr = match.group(1).strip()
                if addr not in addresses:
                    addresses.append(addr)
            if not process_name:
                process_name = (item.event_data.get("process", "") or item.process_name or "sshd").strip()

        first_event = cluster[0]
        alerts.append(
            Alert(
                rule_name="OpenSSH Server Listening",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.004",
                description=f"{process_name or 'sshd'} began listening for SSH connections on {host}:{port}",
                explanation=(
                    "OpenSSH Operational event 4 confirms that the Windows SSH daemon is actively listening for inbound remote-service connections."
                ),
                confidence="medium",
                investigate_next=(
                    "Confirm whether sshd should be running on this host, review recent installation or service-enable activity, and inspect inbound network exposure on port 22."
                ),
                event=first_event,
                process=process_name or "sshd",
                evidence={
                    "service_name": "sshd",
                    "listening_addresses": addresses,
                    "listening_port": port,
                    "payloads": [(item.event_data.get("payload", "") or "")[:300] for item in cluster][:6],
                    "evidence_strength": "medium",
                },
            )
        )

    return alerts


def _iis_webshell_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    process_events = sorted(
        (item for item in events if item.timestamp and item.event_id in (4688, 1)),
        key=lambda item: item.timestamp,
    )
    access_events = [
        item
        for item in events
        if item.timestamp and item.event_id == 10 and _basename(item.event_data.get("SourceImage", "")) == "w3wp.exe"
    ]
    seen = set()

    for ev in process_events:
        if _basename(ev.parent_process) != "w3wp.exe":
            continue

        child = _basename(ev.process_name)
        if child not in IIS_SUSPICIOUS_CHILDREN:
            continue

        actor = _process_user(ev)
        parent_cmd = (ev.event_data.get("ParentCommandLine", "") or "").lower()
        current_dir = (ev.event_data.get("CurrentDirectory", "") or "").lower()
        if not (
            actor.lower().startswith("iis apppool\\")
            or "\\inetsrv\\" in current_dir
            or "webengine4.dll" in parent_cmd
        ):
            continue

        logon_id = _extract_logon_id(ev)
        host = ev.computer or "unknown"
        session_events = [
            item
            for item in process_events
            if (item.computer or "unknown") == host
            and _extract_logon_id(item) == logon_id
            and abs((item.timestamp - ev.timestamp).total_seconds()) <= 180
            and (
                _basename(item.process_name) in IIS_SUSPICIOUS_CHILDREN
                or _basename(item.parent_process) in IIS_SUSPICIOUS_CHILDREN | {"w3wp.exe"}
            )
        ]
        if not session_events:
            session_events = [ev]

        access_match = any(
            abs((other.timestamp - ev.timestamp).total_seconds()) <= 30
            and (other.computer or "unknown") == host
            and _basename(other.event_data.get("TargetImage", "")) == child
            for other in access_events
        )
        commands = []
        processes = []
        for item in session_events:
            if item.process_name and item.process_name not in processes:
                processes.append(item.process_name)
            if item.command_line and item.command_line not in commands:
                commands.append(item.command_line[:300])

        severity = "critical" if access_match or child in {"cmd.exe", "powershell.exe", "pwsh.exe"} else "high"
        key = (host, actor.lower(), logon_id or "", child, commands[0] if commands else "")
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="IIS Webshell Command Execution",
                severity=severity,
                mitre_tactic="Persistence",
                mitre_technique="T1505.003",
                description=f"IIS worker process spawned command execution on {host} as {actor}",
                explanation=(
                    "w3wp.exe launching shells or discovery utilities is strong evidence of webshell-style command execution through IIS."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the HTTP request and web application content that triggered w3wp.exe, inspect the IIS site for webshell code, "
                    "and review follow-on commands executed under the application pool identity."
                ),
                event=ev,
                user=actor,
                process=ev.process_name,
                parent_process=ev.parent_process,
                evidence={
                    "actor_user": actor,
                    "processes": processes,
                    "command_lines": commands,
                    "current_directory": ev.event_data.get("CurrentDirectory", ""),
                    "parent_command_line": ev.event_data.get("ParentCommandLine", ""),
                    "app_pool_context": actor if actor.lower().startswith("iis apppool\\") else "",
                    "process_access_observed": access_match,
                    "event_count": len(session_events),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _dcom_internet_explorer_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in events:
        if ev.event_id not in (4688, 1):
            continue
        if _basename(ev.process_name) != "iexplore.exe":
            continue

        command = ev.command_line or ""
        if "-embedding" not in command.lower():
            continue

        if _basename(ev.parent_process) != "svchost.exe":
            continue

        parent_cmd = (ev.event_data.get("ParentCommandLine", "") or "").lower()
        if "dcomlaunch" not in parent_cmd:
            continue

        host = ev.computer or "unknown"
        actor = _process_user(ev)
        key = (host, actor.lower(), command.lower())
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="DCOM Internet Explorer Execution",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.003",
                description=f"Internet Explorer was launched via DCOM on {host} as {actor}",
                explanation=(
                    "iexplore.exe launched with -Embedding by svchost.exe running the DcomLaunch service is consistent with DCOM-based remote activation."
                ),
                confidence="high",
                investigate_next=(
                    "Identify the COM client that triggered Internet Explorer, inspect nearby network and child-process activity, "
                    "and determine whether the launch was part of remote execution or staged code delivery."
                ),
                event=ev,
                user=actor,
                process=ev.process_name,
                parent_process=ev.parent_process,
                evidence={
                    "command_line": command[:400],
                    "parent_command_line": ev.event_data.get("ParentCommandLine", ""),
                    "dcomlaunch_parent": True,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _dcom_mshta_remote_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    network_events = [
        ev for ev in events
        if ev.event_id == 3 and _basename(ev.process_name) == "mshta.exe" and ev.timestamp
    ]

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1):
            continue
        if _basename(ev.process_name) != "mshta.exe":
            continue
        if "-embedding" not in (ev.command_line or "").lower():
            continue
        if _basename(ev.parent_process) not in {"svchost.exe", "dllhost.exe"}:
            continue

        remote_peer = ""
        for net in network_events:
            if abs((net.timestamp - ev.timestamp).total_seconds()) > 180:
                continue
            if (net.computer or "") != (ev.computer or ""):
                continue
            if (net.event_data.get("ProcessId", "") or "") and (ev.event_data.get("ProcessId", "") or ""):
                if net.event_data.get("ProcessId", "") != ev.event_data.get("ProcessId", ""):
                    continue
            initiated = (net.event_data.get("Initiated", "") or "").lower() == "true"
            remote_peer = (net.destination_ip if initiated else net.event_data.get("DestinationIp", "") or net.destination_ip or net.source_ip).strip()
            if remote_peer:
                break

        alerts.append(
            Alert(
                rule_name="DCOM MSHTA Remote Execution",
                severity="critical" if remote_peer else "high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.003",
                description=f"DCOM-style service host launched mshta.exe on {ev.computer}",
                explanation="mshta.exe launched with -Embedding by svchost.exe or dllhost.exe is a strong sign of DCOM-driven remote execution using HTA content or scriptable COM abuse.",
                confidence="high",
                investigate_next="Identify the remote peer or COM client that activated mshta.exe, recover the HTA or script content, and review nearby network and child-process activity.",
                event=ev,
                user=_process_user(ev),
                process=ev.process_name,
                parent_process=ev.parent_process,
                source_ip=remote_peer,
                evidence={
                    "command_line": (ev.command_line or "")[:400],
                    "parent_process": ev.parent_process,
                    "remote_peer_ip": remote_peer,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _wmi_remote_registry_modification(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)

    for ev in timed_events:
        if ev.event_id not in (12, 13):
            continue
        if _basename(ev.process_name) != "wmiprvse.exe":
            continue

        target = (ev.event_data.get("TargetObject", "") or "").strip()
        if not target:
            continue
        target_l = target.lower()
        sensitive_path = any(marker in target_l for marker in ("\\currentversion\\run", "\\currentversion\\runonce", "\\services\\", "\\clsid\\"))
        if ev.event_id != 13 and not sensitive_path:
            continue

        window_start = ev.timestamp - timedelta(minutes=5)
        window_end = ev.timestamp + timedelta(minutes=2)
        host = ev.computer or "unknown"
        stdprov = False
        remote_peer = ""

        for other in timed_events:
            if other.timestamp < window_start or other.timestamp > window_end:
                continue
            if (other.computer or "") != host:
                continue
            if other.event_id == 7 and _basename(other.process_name) == "wmiprvse.exe":
                image_loaded = (other.event_data.get("ImageLoaded", "") or "").lower()
                if image_loaded.endswith("stdprov.dll"):
                    stdprov = True
            elif other.event_id == 3 and _basename(other.process_name) == "svchost.exe":
                dest_port = (other.event_data.get("DestinationPort", "") or "").strip()
                if dest_port == "135":
                    remote_peer = (other.event_data.get("DestinationIp", "") or other.destination_ip or "").strip()

        if not stdprov:
            continue

        alerts.append(
            Alert(
                rule_name="WMI Remote Registry Modification",
                severity="critical" if ev.event_id == 13 else "high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1047",
                description=f"WMI provider modified registry state on {host}: {target}",
                explanation="Remote WMI registry operations that load stdprov.dll and touch registry keys are consistent with WMI-driven remote registry manipulation or persistence staging.",
                confidence="high",
                investigate_next="Review the originating remote peer, inspect the modified registry path and values, and determine whether the WMI action was used to stage persistence or execute follow-on commands.",
                event=ev,
                process=ev.process_name,
                source_ip=remote_peer,
                registry_key=target,
                evidence={
                    "target_object": target,
                    "event_type": ev.event_data.get("EventType", ""),
                    "remote_peer_ip": remote_peer,
                    "stdprov_loaded": stdprov,
                    "details": ev.event_data.get("Details", ""),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _wmi_remote_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1):
            continue

        child = _basename(ev.process_name)
        parent = _basename(ev.parent_process)
        logon_id = _extract_logon_id(ev)
        user = _process_user(ev)
        host = ev.computer or "unknown"

        is_direct = parent == "wmiprvse.exe" and child in {"powershell.exe", "cmd.exe"}
        is_follow_on = parent == "powershell.exe" and child == "cmd.exe"
        if not is_direct and not is_follow_on:
            continue

        grouped[(host, user, logon_id)].append(ev)

    for (host, user, logon_id), session_events in grouped.items():
        session_events = sorted(session_events, key=lambda item: item.timestamp)
        direct_root = [
            item for item in session_events
            if _basename(item.parent_process) == "wmiprvse.exe" and _basename(item.process_name) in {"powershell.exe", "cmd.exe"}
        ]
        if not direct_root:
            continue

        has_chain = any(_basename(item.parent_process) == "powershell.exe" and _basename(item.process_name) == "cmd.exe" for item in session_events)
        first = direct_root[0]
        process_names = []
        command_lines = []
        for item in session_events:
            proc = item.process_name or item.event_data.get("Image", "")
            cmd = item.command_line
            if proc and proc not in process_names:
                process_names.append(proc)
            if cmd and cmd not in command_lines:
                command_lines.append(cmd[:300])

        description = (
            "wmiprvse.exe spawned remote execution activity. "
            "This process tree is commonly associated with WMI execution tools such as wmiexec and PowerShell WMI."
        )
        if has_chain:
            description = (
                "wmiprvse.exe spawned powershell.exe followed by cmd.exe. "
                "This process tree is commonly associated with WMI execution tools such as wmiexec and PowerShell WMI."
            )

        alerts.append(
            Alert(
                rule_name="WMI Remote Execution",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1047",
                description=description,
                explanation=(
                    f"WMI provider host on {host} launched {', '.join(os.path.basename(p) for p in process_names) or 'remote commands'} "
                    f"under session {logon_id or '(unknown)'}."
                ),
                confidence="high",
                investigate_next=(
                    f"Review the WMI client that initiated execution on {host}, inspect the command lines tied to logon ID {logon_id or '(unknown)'}, "
                    "and determine which remote source triggered the WMI provider."
                ),
                event=first,
                user=user,
                process=first.process_name,
                parent_process=first.parent_process,
                evidence={
                    "logon_id": logon_id,
                    "process_tree": [f"{_basename(item.parent_process)}->{_basename(item.process_name)}" for item in session_events],
                    "processes": process_names,
                    "command_lines": command_lines,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _winrm_remote_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1):
            continue

        parent = _basename(ev.parent_process)
        child = _basename(ev.process_name)
        if parent not in WINRM_HOST_PROCESSES or child not in SHELL_CHILDREN:
            continue

        user = _process_user(ev)
        host = ev.computer or "unknown"
        grouped[(host, user, _extract_logon_id(ev))].append(ev)

    for (host, user, logon_id), session_events in grouped.items():
        session_events = sorted(session_events, key=lambda item: item.timestamp)
        first = session_events[0]
        commands = [item.command_line[:300] for item in session_events if item.command_line]
        children = [item.process_name for item in session_events if item.process_name]
        alerts.append(
            Alert(
                rule_name="WinRM Remote Execution",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.006",
                description=f"WinRM host process spawned remote shell activity on {host}",
                explanation=(
                    f"WinRM host process {os.path.basename(first.parent_process or '') or 'unknown'} launched "
                    f"{', '.join(sorted({os.path.basename(item) for item in children if item})) or 'remote shell commands'}."
                ),
                confidence="high",
                investigate_next=(
                    f"Review the WinRM session on {host}, inspect commands tied to logon ID {logon_id or '(unknown)'}, "
                    "and determine which remote operator or automation initiated the shell."
                ),
                event=first,
                user=user,
                process=first.process_name,
                parent_process=first.parent_process,
                evidence={
                    "logon_id": logon_id,
                    "process_tree": [f"{_basename(item.parent_process)}->{_basename(item.process_name)}" for item in session_events],
                    "command_lines": commands,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _remote_hosts_file_discovery(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped = defaultdict(list)

    for ev in events:
        if ev.event_id != 5145 or not _is_security_audit(ev):
            continue

        share = (ev.share_name or ev.event_data.get("ShareName", "") or "").lower()
        relative = (ev.event_data.get("RelativeTargetName", "") or "").lower()
        src = ev.source_ip or ev.event_data.get("IpAddress", "") or ""
        if src in BENIGN_IPS:
            continue
        if "c$" not in share and "admin$" not in share:
            continue
        if not any(marker in relative for marker in (r"windows\system32\drivers\etc", r"windows\system32\drivers\etc\hosts", r"hosts:zone.identifier")):
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        logon_id = _extract_logon_id(ev) or "(unknown)"
        grouped[(ev.computer or "unknown", src, actor, logon_id)].append(ev)

    for (host, src, actor, logon_id), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp)[0]
        touched = sorted({(item.event_data.get("RelativeTargetName", "") or "").strip() for item in cluster if (item.event_data.get("RelativeTargetName", "") or "").strip()})
        if not any("hosts" in item.lower() or r"drivers\etc" in item.lower() for item in touched):
            continue

        alerts.append(
            Alert(
                rule_name="Remote Hosts File Discovery",
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1018",
                description=f"{actor} browsed the remote hosts file path over an admin share on {host} from {src}",
                explanation="Repeated 5145 file-share access into Windows\\System32\\Drivers\\etc over C$/ADMIN$ is consistent with remote system discovery targeting the hosts file or adjacent name-resolution paths.",
                confidence="high",
                investigate_next="Review whether the source host and account were expected to browse administrative shares, and correlate with nearby lateral-movement or name-resolution tampering activity.",
                event=first,
                user=actor,
                source_ip=src,
                share_name=first.share_name or first.event_data.get("ShareName", ""),
                evidence={
                    "actor_user": actor,
                    "source_ip": src,
                    "share_name": first.share_name or first.event_data.get("ShareName", ""),
                    "relative_targets": touched[:12],
                    "subject_logon_id": "" if logon_id == "(unknown)" else logon_id,
                    "event_count": len(cluster),
                    "evidence_strength": "medium",
                },
            )
        )

    return alerts


def _anonymous_smb_service_probe(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped = defaultdict(list)

    for ev in events:
        if ev.event_id != 4624 or ev.logon_type != "3" or not _is_security_audit(ev):
            continue

        src = ev.source_ip or ev.event_data.get("IpAddress", "") or ""
        if src in BENIGN_IPS:
            continue
        auth_package = (ev.event_data.get("AuthenticationPackageName", "") or "").strip().upper()
        logon_process = (ev.event_data.get("LogonProcessName", "") or "").strip().lower()
        if auth_package != "NTLM" or logon_process != "ntlmssp":
            continue

        user = ev.target_domain_user or ev.domain_user or "unknown"
        grouped[(ev.computer or "unknown", src)].append(ev)

    for (host, src), cluster in grouped.items():
        ordered = sorted(cluster, key=lambda item: item.timestamp)
        windows = []
        current = []
        for ev in ordered:
            if current and ev.timestamp and current[-1].timestamp and ev.timestamp - current[-1].timestamp > timedelta(minutes=10):
                windows.append(current)
                current = []
            current.append(ev)
        if current:
            windows.append(current)

        for window in windows:
            users = [item.target_domain_user or item.domain_user or "unknown" for item in window]
            anonymous = [user for user in users if "anonymous logon" in user.lower()]
            if not anonymous:
                continue
            if len(window) < 5:
                continue

            first = window[0]
            unique_users = sorted({user for user in users if user})
            alerts.append(
                Alert(
                    rule_name="Anonymous SMB Service Probe",
                    severity="medium",
                    mitre_tactic="Discovery",
                    mitre_technique="T1046",
                    description=f"{src} performed repeated NTLM network logons to {host}, including ANONYMOUS LOGON",
                    explanation="Repeated LogonType 3 NTLM network logons from one source, including ANONYMOUS LOGON, are consistent with SMB service probing, unauthenticated checks, or broad remote-enumeration tooling.",
                    confidence="high",
                    investigate_next="Inspect the source host for SMB enumeration tooling, review what shares or services were queried next, and confirm whether the repeated logons were expected from vulnerability scanning infrastructure.",
                    event=first,
                    user=next((user for user in unique_users if "anonymous logon" in user.lower()), unique_users[0] if unique_users else "unknown"),
                    source_ip=src,
                    evidence={
                        "source_ip": src,
                        "target_users": unique_users[:12],
                        "anonymous_present": True,
                        "event_count": len(window),
                        "authentication_package": "NTLM",
                        "logon_type": "3",
                        "evidence_strength": "medium",
                    },
                )
            )

    return alerts


def _remote_named_pipe_execution(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = defaultdict(list)

    for ev in events:
        if ev.event_id not in (5145, 5140):
            continue
        if not _is_security_audit(ev):
            continue

        relative_target = (ev.event_data.get("RelativeTargetName", "") or ev.event_data.get("ObjectName", "") or "").strip()
        relative_target_l = relative_target.lower()
        share = (ev.share_name or ev.event_data.get("ShareName", "") or "").strip()
        share_l = share.lower()
        src = (ev.source_ip or ev.event_data.get("IpAddress", "") or "").strip()
        if src in BENIGN_IPS:
            continue
        if "ipc$" not in share_l:
            continue

        matched = sorted({name for name in SUSPICIOUS_PIPE_NAMES if name in relative_target_l})
        if not matched:
            continue

        actor = ev.domain_user or ev.subject_domain_user or "unknown"
        grouped[(ev.computer or "unknown", src, actor)].append((ev, relative_target, matched))

    for (host, src, actor), cluster in grouped.items():
        first = sorted((item[0] for item in cluster), key=lambda item: item.timestamp.isoformat() if item.timestamp else "")[0]
        targets = sorted({item[1] for item in cluster if item[1]})
        markers = sorted({marker for _, _, matched in cluster for marker in matched})
        alerts.append(
            Alert(
                rule_name="Remote Service Control Pipe Access",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"{actor} accessed remote service-control pipes on {host} from {src}",
                explanation="Access to service-control or remote-task named pipes such as svcctl or atsvc is commonly associated with PsExec, SMBexec, ATexec, and similar remote execution tooling.",
                confidence="high",
                investigate_next="Correlate this pipe access with nearby service installs, task creation, or process creation to determine what remote execution path was used.",
                event=first,
                user=actor,
                source_ip=src,
                evidence={
                    "actor_user": actor,
                    "source_ip": src,
                    "share_name": first.event_data.get("ShareName", "") or first.share_name,
                    "relative_target_names": targets,
                    "pipe_markers": markers,
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _remote_print_spooler_pipe_access(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []

    for ev in events:
        if ev.event_id not in (5145, 5140):
            continue
        if not _is_security_audit(ev):
            continue

        relative_target = (ev.event_data.get("RelativeTargetName", "") or ev.event_data.get("ObjectName", "") or "").strip()
        relative_target_l = relative_target.lower()
        share = (ev.share_name or ev.event_data.get("ShareName", "") or "").strip()
        src = (ev.source_ip or ev.event_data.get("IpAddress", "") or "").strip()
        if src in BENIGN_IPS:
            continue
        if "ipc$" not in share.lower():
            continue
        if "spoolss" not in relative_target_l:
            continue

        actor = ev.domain_user or ev.subject_domain_user or "unknown"
        alerts.append(
            Alert(
                rule_name="Remote Print Spooler Pipe Access",
                severity="medium",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"{actor} accessed the remote spoolss pipe on {ev.computer} from {src}",
                explanation="Remote access to the spoolss named pipe can indicate print-spooler abuse, printer-based lateral movement, or PrintNightmare-style reconnaissance against the target host.",
                confidence="high",
                investigate_next="Validate whether the source host should interact with the target's print spooler, then review nearby spooler, driver-load, or remote-execution activity.",
                event=ev,
                user=actor,
                source_ip=src,
                evidence={
                    "actor_user": actor,
                    "source_ip": src,
                    "share_name": share,
                    "relative_target_name": relative_target,
                    "evidence_strength": "medium",
                },
            )
        )

    return alerts


def _remote_service_payload_staging(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = defaultdict(list)

    for ev in events:
        if ev.event_id != 5145 or not _is_security_audit(ev):
            continue
        share = (ev.share_name or ev.event_data.get("ShareName", "") or "").strip()
        share_l = share.lower()
        if "admin$" not in share_l and "c$" not in share_l:
            continue

        relative_target = _normalize_windows_path(ev.event_data.get("RelativeTargetName", "") or "")
        if not _is_suspicious_remote_payload_path(relative_target):
            continue
        src = (ev.source_ip or ev.event_data.get("IpAddress", "") or "").strip()
        if src in BENIGN_IPS:
            continue

        actor = ev.domain_user or ev.subject_domain_user or "unknown"
        grouped[(ev.computer or "unknown", src, actor)].append((ev, relative_target))

    for (host, src, actor), cluster in grouped.items():
        first = sorted((item[0] for item in cluster), key=lambda item: item.timestamp.isoformat() if item.timestamp else "")[0]
        targets = sorted({item[1] for item in cluster if item[1]})
        alerts.append(
            Alert(
                rule_name="Remote Service Payload Staging",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"{actor} staged suspicious payloads over SMB to {host} from {src}",
                explanation="Suspicious payload transfers over ADMIN$ or C$ to the target host are commonly used to stage PsExec, RemCom, credential-theft tooling, startup persistence, or other remote-execution payloads before execution.",
                confidence="high",
                investigate_next="Review the staged files and directories, correlate them with service creation or named-pipe access, and determine whether the source host should be deploying payloads or tooling to the target.",
                event=first,
                user=actor,
                source_ip=src,
                evidence={
                    "actor_user": actor,
                    "source_ip": src,
                    "share_name": first.event_data.get("ShareName", "") or first.share_name,
                    "staged_paths": targets,
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _psexec_service_binary_drop(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    file_events = defaultdict(list)
    process_events = defaultdict(list)

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "sysmon" not in provider and "sysmon" not in channel:
            continue

        if ev.event_id == 11:
            target_filename = _normalize_windows_path(ev.event_data.get("TargetFilename", "") or "")
            if target_filename.lower().endswith("\\psexesvc.exe"):
                file_events[ev.computer or "unknown"].append(ev)
        elif ev.event_id == 1:
            image = _normalize_windows_path(ev.event_data.get("Image", "") or ev.process_name or "")
            if image.lower().endswith("\\psexesvc.exe"):
                process_events[ev.computer or "unknown"].append(ev)

    for host in sorted(set(file_events) | set(process_events)):
        files = file_events.get(host, [])
        procs = process_events.get(host, [])
        if not files and not procs:
            continue

        first = sorted(files + procs, key=lambda item: item.timestamp.isoformat() if item.timestamp else "")[0]
        executed_binary = ""
        parent_processes = sorted(
            {
                _normalize_windows_path(item.parent_process or item.event_data.get("ParentImage", "") or "")
                for item in procs
                if _normalize_windows_path(item.parent_process or item.event_data.get("ParentImage", "") or "")
            }
        )
        process_users = sorted(
            {
                (item.event_data.get("User", "") or item.domain_user or item.target_domain_user or "").strip()
                for item in procs
                if (item.event_data.get("User", "") or item.domain_user or item.target_domain_user or "").strip()
            }
        )
        if procs:
            executed_binary = _normalize_windows_path(procs[0].event_data.get("Image", "") or procs[0].process_name or "")
        target_filenames = sorted(
            {
                _normalize_windows_path(item.event_data.get("TargetFilename", "") or "")
                for item in files
                if _normalize_windows_path(item.event_data.get("TargetFilename", "") or "")
            }
        )

        alerts.append(
            Alert(
                rule_name="PsExec Service Binary Drop",
                severity="critical" if files and procs else "high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"PsExec service binary PSEXESVC.exe was {'dropped and executed' if files and procs else 'written'} on {host}",
                explanation="PsExec commonly copies PSEXESVC.exe to the target host and launches it as a temporary service to execute commands remotely.",
                confidence="high",
                investigate_next="Correlate this target-side service binary with nearby 5145 admin-share access, 7045/4697 service creation, and the source host that initiated the remote service execution.",
                event=first,
                user=process_users[0] if process_users else "unknown",
                process=executed_binary or "C:\\Windows\\PSEXESVC.exe",
                evidence={
                    "target_filenames": target_filenames,
                    "executed_binary": executed_binary,
                    "parent_processes": parent_processes,
                    "process_users": process_users,
                    "file_event_count": len(files),
                    "process_event_count": len(procs),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _loopback_rdp_tunnel(events: List[NormalizedEvent]) -> List[Alert]:
    return _loopback_service_tunnel(events, port="3389", rule_name="RDP Tunnel via Loopback", service_label="RDP")


def _loopback_smb_tunnel(events: List[NormalizedEvent]) -> List[Alert]:
    return _loopback_service_tunnel(events, port="445", rule_name="SMB Tunnel via Loopback", service_label="SMB")


def _loopback_service_tunnel(
    events: List[NormalizedEvent], *, port: str, rule_name: str, service_label: str
) -> List[Alert]:
    alerts = []
    grouped = defaultdict(list)

    for ev in events:
        if ev.event_id != 3:
            continue
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "sysmon" not in provider and "sysmon" not in channel:
            continue

        initiated = (ev.event_data.get("Initiated", "") or "").strip().lower()
        if initiated != "true":
            continue

        image = (ev.event_data.get("Image", "") or ev.process_name or "").strip()
        image_base = _basename(image)
        if image_base not in TUNNELING_PROCESS_NAMES and "\\users\\" not in image.lower() and "\\inetsrv\\" not in image.lower():
            continue

        dest_ip = (
            ev.event_data.get("DestinationIp", "")
            or ev.event_data.get("DestAddress", "")
            or ev.destination_ip
            or ""
        ).strip()
        if dest_ip not in LOOPBACK_NETWORK_TARGETS:
            continue

        dest_port = (ev.event_data.get("DestinationPort", "") or ev.event_data.get("DestPort", "") or "").strip()
        if dest_port != port:
            continue

        grouped[(ev.computer or "unknown", image.lower(), dest_ip)].append(ev)

    for (host, image, dest_ip), cluster in grouped.items():
        first = sorted(cluster, key=lambda item: item.timestamp.isoformat() if item.timestamp else "")[0]
        source_ips = sorted(
            {
                (
                    ev.event_data.get("SourceAddress", "")
                    or ev.source_ip
                    or ""
                ).strip()
                for ev in cluster
                if (
                    ev.event_data.get("SourceAddress", "")
                    or ev.source_ip
                    or ""
                ).strip()
            }
        )
        alerts.append(
            Alert(
                rule_name=rule_name,
                severity="high",
                mitre_tactic="Command and Control",
                mitre_technique="T1572",
                description=f"{_basename(image)} tunneled {service_label} traffic to {dest_ip}:{port} on {host}",
                explanation=f"A non-service process forwarded {service_label} traffic to a loopback endpoint on the host, which is consistent with local port-forwarding or tunneling of remote services.",
                confidence="high",
                investigate_next=f"Inspect {_basename(image)} on {host}, review the remote peer and command line used to establish the tunnel, and determine whether {service_label} was exposed through a proxy or webshell.",
                event=first,
                user=first.domain_user or first.subject_domain_user or "unknown",
                process=image,
                source_ip=source_ips[0] if source_ips else "",
                destination_ip=dest_ip,
                evidence={
                    "process_image": image,
                    "destination_ip": dest_ip,
                    "destination_port": port,
                    "source_ips": source_ips,
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _plink_rdp_tunnel(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = defaultdict(list)
    loopback_logons = defaultdict(list)

    for ev in events:
        if ev.event_id == 4624 and _is_security_audit(ev):
            src = (ev.source_ip or ev.event_data.get("IpAddress", "") or "").strip()
            if src in {"127.0.0.1", "-"} and ev.logon_type in {"10", "11"}:
                loopback_logons[ev.computer or "unknown"].append(ev)

        if ev.event_id != 5156 or not _is_security_audit(ev):
            continue

        app = (ev.event_data.get("Application", "") or "").strip().lower()
        if not app.endswith("plink.exe"):
            continue
        src = (ev.event_data.get("SourceAddress", "") or ev.source_ip or "").strip()
        dest = (ev.event_data.get("DestAddress", "") or ev.destination_ip or "").strip()
        dest_port = (ev.event_data.get("DestPort", "") or ev.event_data.get("DestinationPort", "") or "").strip()
        if src in BENIGN_IPS or dest in BENIGN_IPS:
            continue
        if dest_port not in {"80", "443", "8080"}:
            continue

        grouped[(ev.computer or "unknown", src, dest, dest_port)].append(ev)

    for (host, src, dest, dest_port), cluster in grouped.items():
        related_logon = next(
            (
                logon
                for logon in loopback_logons.get(host, [])
                if any(
                    item.timestamp and logon.timestamp and abs((item.timestamp - logon.timestamp).total_seconds()) <= 300
                    for item in cluster
                )
            ),
            None,
        )
        if related_logon is None:
            continue

        first = sorted(cluster, key=lambda item: item.timestamp.isoformat() if item.timestamp else "")[0]
        alerts.append(
            Alert(
                rule_name="Plink RDP Tunnel",
                severity="high",
                mitre_tactic="Command and Control",
                mitre_technique="T1572",
                description=f"plink established a tunnel from {host} to {dest}:{dest_port} followed by loopback RDP logon activity",
                explanation="plink outbound connectivity combined with nearby localhost RDP logons is consistent with SSH-style remote desktop tunneling through a forwarded port.",
                confidence="high",
                investigate_next="Inspect the plink command line and parent process, determine who launched the tunnel, and review whether remote desktop access was proxied through the external endpoint.",
                event=first,
                user=related_logon.domain_user or related_logon.target_domain_user or "unknown",
                process=first.event_data.get("Application", "") or first.process_name,
                source_ip=src,
                destination_ip=dest,
                evidence={
                    "source_ip": src,
                    "destination_ip": dest,
                    "destination_port": dest_port,
                    "loopback_logon_type": related_logon.logon_type,
                    "loopback_user": related_logon.domain_user or related_logon.target_domain_user or "",
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _renamed_psexec_service_pipes(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    server_groups = defaultdict(list)
    client_groups = defaultdict(list)
    seen = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "sysmon" not in provider and "sysmon" not in channel:
            continue

        pipe_name = (ev.event_data.get("PipeName", "") or "").strip()
        if not pipe_name:
            continue

        host = ev.computer or "unknown"
        proc_base = os.path.splitext(_basename(ev.process_name))[0]
        if ev.event_id == 17:
            parsed = _extract_psexec_stdio_pipe(pipe_name)
            if parsed:
                base_name, remote_host, remote_pid, stream = parsed
                if proc_base != base_name.lower() or proc_base == "psexesvc":
                    continue
                server_groups[(host, (ev.process_name or "").strip(), base_name.lower())].append(
                    ("stdio", ev, pipe_name, remote_host, remote_pid, stream)
                )
                continue

            if pipe_name.startswith("\\") and pipe_name.count("\\") == 1:
                base_name = pipe_name.lstrip("\\").strip().lower()
                if proc_base != base_name or proc_base == "psexesvc":
                    continue
                server_groups[(host, (ev.process_name or "").strip(), base_name)].append(("base", ev, pipe_name, "", "", ""))
        elif ev.event_id == 18 and _basename(ev.process_name) == "psexec.exe":
            parsed = _extract_psexec_stdio_pipe(pipe_name)
            if not parsed:
                continue
            base_name, remote_host, remote_pid, stream = parsed
            process_id = (ev.event_data.get("ProcessId", "") or "").strip()
            if process_id and remote_pid and process_id != remote_pid:
                continue
            client_groups[(host, base_name.lower())].append((ev, pipe_name, remote_host, remote_pid, stream))

    for (host, server_process, base_name), entries in server_groups.items():
        base_events = [item[1] for item in entries if item[0] == "base"]
        stdio_entries = [item for item in entries if item[0] == "stdio"]
        if not base_events or not stdio_entries:
            continue

        server_streams = {item[5] for item in stdio_entries if item[5]}
        if len(server_streams) < 2:
            continue

        first_event = sorted(base_events + [item[1] for item in stdio_entries], key=lambda item: item.timestamp)[0]
        related_clients = [
            item
            for item in client_groups.get((host, base_name), [])
            if 0 <= (item[0].timestamp - first_event.timestamp).total_seconds() <= 120
        ]
        client_streams = {item[4] for item in related_clients if item[4]}
        if len(client_streams) < 2:
            continue

        key = (host.lower(), server_process.lower(), base_name)
        if key in seen:
            continue
        seen.add(key)

        stdio_pipe_names = sorted({item[2] for item in stdio_entries if item[2]})
        client_images = sorted({item[0].process_name for item in related_clients if item[0].process_name})
        client_hosts = sorted({item[2] for item in related_clients if item[2]})
        alerts.append(
            Alert(
                rule_name="Renamed PsExec Service Pipes",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"{server_process} exposed PsExec-style stdio pipes under renamed service {base_name} on {host}",
                explanation=(
                    "A non-standard service name created the PsExec-style base pipe and stdin/stdout/stderr pipes, and "
                    "PsExec.exe connected to them. This is consistent with a renamed PsExec service used to blend into the host."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the renamed service binary and service definition, correlate nearby remote logons or service creation, "
                    "and determine what command was executed through the PsExec channel."
                ),
                event=first_event,
                process=server_process,
                evidence={
                    "server_process": server_process,
                    "service_name": base_name,
                    "base_pipe": f"\\{base_name}",
                    "stdio_pipes": stdio_pipe_names[:5],
                    "server_stream_count": len(server_streams),
                    "client_stream_count": len(client_streams),
                    "client_processes": client_images[:3],
                    "client_hosts": client_hosts[:3],
                    "event_count": len(base_events) + len(stdio_entries) + len(related_clients),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _psexec_named_pipe_stager(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id not in (4688, 1):
            continue

        cmd = (ev.command_line or "").strip()
        if not cmd:
            continue

        pipe_name = _extract_pipe_name(cmd)
        if not pipe_name:
            continue
        if _looks_like_local_service_pipe_stager(events, ev, cmd):
            continue

        host = ev.computer or "unknown"
        dedupe_key = (host, pipe_name.lower(), _extract_logon_id(ev), _process_user(ev))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        alerts.append(
            Alert(
                rule_name="PsExec Named Pipe Stager",
                severity="critical",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"cmd.exe staged a PsExec-style named pipe payload ({pipe_name}) on {host}",
                explanation="PsExec-style payloads often echo a pipe name into \\\\.\\pipe\\<name> before handing off command execution through a temporary service or launcher.",
                confidence="high",
                investigate_next="Correlate this process with nearby service-install, logon, and admin-share events to identify the remote operator and executed payload.",
                event=ev,
                user=_process_user(ev),
                process=ev.process_name,
                evidence={
                    "pipe_name": pipe_name,
                    "command_line": cmd[:500],
                    "logon_id": _extract_logon_id(ev),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _explicit_credentials_remote_sequence(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)

    for ev in timed_events:
        if ev.event_id != 4648 or not _is_security_audit(ev):
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        target_user = ev.target_domain_user or ev.target_user or "unknown"
        target_server = (ev.event_data.get("TargetServerName", "") or "").strip()
        if target_server.lower() in LOCALHOST_TARGETS:
            continue

        window_end = ev.timestamp + timedelta(minutes=10)
        related = []
        for other in timed_events:
            if other.timestamp < ev.timestamp or other.timestamp > window_end:
                continue
            if (other.computer or "") != (ev.computer or ""):
                continue
            if other.event_id not in (4688, 1):
                continue

            cmd = (other.command_line or "").lower()
            if not cmd:
                continue
            if target_server.lower() not in cmd and not any(marker in cmd for marker in REMOTE_EXEC_COMMAND_MARKERS):
                continue
            if not any(token in cmd for token in ("sc", "schtasks", "wmic", "winrs", "powershell", "cmd.exe", "psexec", "paexec")):
                continue
            related.append(other)

        if not related:
            continue

        first = related[0]
        alerts.append(
            Alert(
                rule_name="Explicit Credentials Followed by Remote Execution",
                severity="critical",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1550.002",
                description=f"{actor} used explicit credentials for {target_user} and then launched remote execution tooling toward {target_server}",
                explanation="Explicit credentials followed by remote administration or execution commands is consistent with operators pivoting into a remote host using alternate credentials.",
                confidence="high",
                investigate_next="Review the full credential-use event, validate whether the actor was authorized to use alternate credentials, and inspect the remote host for resulting service, task, or process activity.",
                event=ev,
                user=target_user,
                source_ip=ev.source_ip,
                evidence={
                    "actor_user": actor,
                    "target_user": target_user,
                    "target_server": target_server,
                    "processes": [item.process_name for item in related if item.process_name],
                    "commands": [item.command_line[:400] for item in related if item.command_line],
                    "logon_id": _extract_logon_id(ev),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _psexec_remote_execution_sequence(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    service_events = []
    process_events = []

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id in (7045, 4697):
            binary = _extract_service_binary(ev)
            pipe_name = _extract_pipe_name(binary)
            binary_name = _normalize_binary_basename(binary)
            if pipe_name or binary_name.endswith(".exe"):
                service_events.append((ev, pipe_name, binary_name, binary))
        elif ev.event_id in (4688, 1):
            pipe_name = _extract_pipe_name(ev.command_line or "")
            proc_name = _normalize_binary_basename(ev.process_name)
            process_events.append((ev, pipe_name, proc_name))

    seen = set()
    for service_ev, pipe_name, binary_name, binary in service_events:
        host = service_ev.computer or "unknown"
        matches = []
        for proc_ev, proc_pipe, proc_name in process_events:
            if (proc_ev.computer or "") != host:
                continue
            if abs((proc_ev.timestamp - service_ev.timestamp).total_seconds()) > 600:
                continue
            if pipe_name and proc_pipe and pipe_name.lower() == proc_pipe.lower():
                matches.append(proc_ev)
                continue
            if binary_name and proc_name and binary_name == proc_name and proc_name != "cmd.exe":
                matches.append(proc_ev)

        if not matches:
            continue

        service_name = service_ev.event_data.get("ServiceName", "") or service_ev.service_name
        dedupe_key = (host, (service_name or "").lower(), pipe_name.lower() if pipe_name else "", binary_name)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        alerts.append(
            Alert(
                rule_name="PsExec Remote Execution Sequence",
                severity="critical",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"Temporary service activity and matching target-side execution indicate PsExec-style remote execution on {host}",
                explanation="The host recorded both a PsExec-style service payload and matching target-side execution activity, which is characteristic of PsExec or similar service-based lateral movement.",
                confidence="high",
                investigate_next="Identify the source host and account that deployed the temporary service, recover the executed payload, and review surrounding logons and admin-share activity.",
                event=service_ev,
                user=_process_user(matches[0]),
                process=matches[0].process_name,
                service=service_name,
                evidence={
                    "service_name": service_name,
                    "service_binary": binary,
                    "pipe_name": pipe_name,
                    "matched_processes": [item.process_name for item in matches if item.process_name],
                    "matched_commands": [item.command_line[:400] for item in matches if item.command_line],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _smbexec_remote_execution_sequence(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = defaultdict(list)

    for ev in events:
        if ev.event_id not in (7045, 4697):
            continue
        binary = _extract_service_binary(ev)
        binary_l = binary.lower()
        if "%comspec%" not in binary_l or "%temp%\\execute.bat" not in binary_l or "__output" not in binary_l:
            continue
        service_name = ev.event_data.get("ServiceName", "") or ev.service_name
        grouped[(ev.computer or "unknown", (service_name or "").lower(), binary_l)].append(ev)

    for (host, _, binary_l), group in grouped.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda item: item.timestamp.isoformat() if item.timestamp else "")
        first = ordered[0]
        service_name = first.event_data.get("ServiceName", "") or first.service_name
        alerts.append(
            Alert(
                rule_name="SMBexec Remote Execution Sequence",
                severity="critical",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"Multiple audit sources recorded an SMBexec-style service payload for {service_name or 'unknown service'} on {host}",
                explanation="SMBexec commonly installs a temporary service that builds a batch file under %TEMP%, runs it through COMSPEC, and writes output back to an admin share. Seeing the same payload in multiple service-install records is high-confidence remote execution evidence.",
                confidence="high",
                investigate_next="Recover the temporary batch contents, inspect the admin-share output file, and identify the remote operator and source host that created the service.",
                event=first,
                service=service_name,
                evidence={
                    "service_name": service_name,
                    "service_binary": _extract_service_binary(first),
                    "record_count": len(group),
                    "record_event_ids": [item.event_id for item in ordered],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _atexec_remote_task_sequence(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    created = [ev for ev in events if ev.event_id == 4698 and ev.timestamp]
    deleted = [ev for ev in events if ev.event_id == 4699 and ev.timestamp]

    for create in created:
        task_name = create.event_data.get("TaskName", "") or create.task_name
        if not task_name:
            continue
        content = create.event_data.get("TaskContent", "") or ""
        content_l = content.lower()
        if "cmd.exe" not in content_l or "%windir%\\temp" not in content_l:
            continue
        if "hidden" not in content_l and "<hidden>true" not in content_l:
            continue

        for remove in deleted:
            if (remove.computer or "") != (create.computer or ""):
                continue
            if (remove.event_data.get("TaskName", "") or remove.task_name) != task_name:
                continue
            if remove.timestamp < create.timestamp or remove.timestamp - create.timestamp > timedelta(minutes=5):
                continue

            alerts.append(
                Alert(
                    rule_name="ATexec Remote Task Execution",
                    severity="critical",
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1053.005",
                    description=f"Short-lived hidden task {task_name} on {create.computer} matches ATexec-style remote execution",
                    explanation="ATexec-style tooling commonly creates a hidden scheduled task that runs cmd.exe, writes output under %windir%\\Temp, and then deletes the task to reduce artifacts.",
                    confidence="high",
                    investigate_next="Extract the task XML, recover the output file if still present, and correlate with nearby remote logon or service-control events to identify the source host.",
                    event=create,
                    scheduled_task=task_name,
                    evidence={
                        "task_name": task_name,
                        "task_content": content[:800],
                        "created_at": create.timestamp.isoformat() if create.timestamp else None,
                        "deleted_at": remove.timestamp.isoformat() if remove.timestamp else None,
                        "evidence_strength": "high",
                    },
                )
            )
            break

    return alerts


def _check(ev: NormalizedEvent, explicit_spray_event_ids: Set[int] | None = None) -> List[Alert]:
    alerts = []
    ed = ev.event_data

    if ev.event_id == 4624 and ev.logon_type in ("3", "10"):
        if not _is_security_audit(ev):
            return alerts
        src = ev.source_ip
        if src and src not in BENIGN_IPS:
            if ev.is_machine_account and ev.logon_type == "3":
                return alerts
            lt = ev.logon_type_name
            user = ev.target_domain_user or ev.domain_user or "unknown"
            alerts.append(Alert(
                rule_name=f"Lateral Movement: {lt} Logon", severity="medium",
                mitre_tactic="Lateral Movement", mitre_technique="T1021",
                description=f"{lt} logon by {user} from {src} to {ev.computer}",
                explanation=f"A {lt} logon from a remote host. If the source is unexpected, this may be an attacker moving between systems.",
                confidence="medium" if ev.logon_type == "3" else "high",
                investigate_next=f"Verify that {src} is authorized to access {ev.computer}. Check what was done after logon. Look for process creation (4688) or service install (7045) within minutes.",
                event=ev,
                user=user,
                evidence={"source_ip": src, "source_host": src, "destination_host": ev.computer,
                          "logon_type": ev.logon_type, "logon_type_name": lt, "user": user, "evidence_strength": "high" if ev.logon_type == "10" else "medium"},
            ))

    if ev.event_id == 4648:
        if not _is_security_audit(ev):
            return alerts
        if explicit_spray_event_ids and id(ev) in explicit_spray_event_ids:
            return alerts
        target_srv = ed.get("TargetServerName", "")
        target_user = ev.target_domain_user or ed.get("TargetUserName", "")
        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        if target_user.lower().startswith(("font driver host\\umfd-", "window manager\\dwm-")):
            return alerts
        if not ev.is_machine_account or target_srv.lower() not in ("localhost", "") or ev.source_ip not in BENIGN_IPS:
            alerts.append(Alert(
                rule_name="Explicit Credential Use", severity="high",
                mitre_tactic="Lateral Movement", mitre_technique="T1550.002",
                description=f"Explicit credentials for {target_user or 'unknown'} used from {ev.computer} via {os.path.basename(ev.process_name or '') or 'unknown'} targeting {target_srv or ev.computer}",
                explanation="Explicit credential use (RunAs / pass-the-hash) allows an attacker to authenticate as another user, often to access a different system.",
                confidence="high",
                investigate_next=f"Check if {ev.domain_user} normally uses RunAs. Verify access to {target_srv} was authorized. Look for subsequent actions on {target_srv}.",
                event=ev,
                user=target_user or actor,
                evidence={"source_host": ev.computer, "destination_host": target_srv,
                          "target_user": target_user, "actor_user": actor, "process_name": ev.process_name, "source_ip": ev.source_ip, "evidence_strength": "high"},
            ))

    if ev.event_id in (7045, 4697):
        svc_file = (ed.get("ImagePath", "") or ed.get("ServiceFileName", "") or "").lower()
        svc_name = (ed.get("ServiceName", "") or "").lower()
        markers = ["psexe", "paexec", "remcom", "csexe"]
        if any(m in svc_file or m in svc_name for m in markers):
            alerts.append(Alert(
                rule_name="PsExec-Style Remote Service", severity="critical",
                mitre_tactic="Lateral Movement", mitre_technique="T1021.002",
                description=f"PsExec service '{svc_name}' on {ev.computer} | Binary: {svc_file}",
                explanation="PsExec deploys a temporary service on the target host to execute commands. This is one of the most common lateral movement tools.",
                confidence="high",
                investigate_next="Identify the source host that deployed this service. Check what commands were executed through it. Look for 4624 logon type 3 immediately before this event.",
                event=ev, service=svc_name,
                evidence={"source_host": "(check preceding 4624)", "destination_host": ev.computer,
                          "service": svc_name, "binary": svc_file, "evidence_strength": "high"},
            ))

    if ev.event_id in (4688, 1):
        cmd = ev.command_line.lower()
        if "wmic" in cmd and "/node:" in cmd:
            alerts.append(Alert(
                rule_name="WMI Remote Execution", severity="high",
                mitre_tactic="Lateral Movement", mitre_technique="T1047",
                description=f"WMI remote by {ev.domain_user} on {ev.computer}: {cmd[:200]}",
                explanation="WMI allows executing processes on remote machines. Check the /node: target.",
                confidence="high",
                investigate_next="Extract the target host from the /node: parameter. Check what was executed remotely.",
                event=ev, evidence={"command_line": cmd[:500], "source_host": ev.computer, "evidence_strength": "high"},
            ))

        if any(t in cmd for t in ["invoke-command", "enter-pssession", "winrs", "new-pssession"]):
            alerts.append(Alert(
                rule_name="WinRM Remote Execution", severity="high",
                mitre_tactic="Lateral Movement", mitre_technique="T1021.006",
                description=f"WinRM by {ev.domain_user} on {ev.computer}: {cmd[:200]}",
                explanation="WinRM/PowerShell Remoting enables remote command execution across the domain.",
                confidence="high",
                investigate_next="Identify the target host. Check what commands were sent. Review PowerShell script block logs (4104) on the target.",
                event=ev, evidence={"command_line": cmd[:500], "source_host": ev.computer, "evidence_strength": "high"},
            ))

    if ev.event_id == 5140:
        if not _is_security_audit(ev):
            return alerts
        share = ev.share_name or ed.get("ShareName", "")
        src = ev.source_ip or ed.get("IpAddress", "")
        if src and src not in BENIGN_IPS:
            is_admin = "admin$" in share.lower() or "c$" in share.lower()
            alerts.append(Alert(
                rule_name=f"Remote SMB Access{' (Admin Share)' if is_admin else ''}",
                severity="high" if is_admin else "medium",
                mitre_tactic="Lateral Movement", mitre_technique="T1021.002",
                description=f"{ev.target_domain_user or ev.domain_user or 'unknown'} accessed {share or 'unknown share'} on {ev.computer} from {src}",
                explanation=f"{'Admin share access from remote strongly indicates lateral movement or remote administration.' if is_admin else 'Remote share access. Verify this is authorized.'}",
                confidence="high" if is_admin else "low",
                investigate_next=f"Check what files were accessed on {share}. Look for data staging or tool deployment. Verify {src} is an authorized admin.",
                event=ev,
                evidence={"source_ip": src, "source_host": src, "destination_host": ev.computer,
                          "share": share, "user": ev.target_domain_user or ev.domain_user, "evidence_strength": "high" if is_admin else "low"},
            ))

    if ev.event_id == 4778:
        if not _is_security_audit(ev):
            return alerts
        src = ed.get("ClientAddress", "") or ev.source_ip
        client = ed.get("ClientName", "")
        if src and src not in BENIGN_IPS:
            alerts.append(Alert(
                rule_name="RDP Session Reconnected", severity="medium",
                mitre_tactic="Lateral Movement", mitre_technique="T1021.001",
                description=f"RDP reconnect by {ev.domain_user} from {src} ({client}) to {ev.computer}",
                explanation="Session reconnection may indicate an attacker resuming a previously established RDP session.",
                confidence="low",
                investigate_next=f"Check if {ev.domain_user} normally RDPs from {src}. Review session duration and activity.",
                event=ev,
                evidence={"source_ip": src, "source_host": src, "destination_host": ev.computer,
                          "client_name": client, "evidence_strength": "low"},
            ))

    return alerts
