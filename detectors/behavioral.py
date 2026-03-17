"""Behavioral detections that produce low-level suspicious signals."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List, Tuple

from models.event_model import Alert, NormalizedEvent


CHAIN_PATTERNS: set[Tuple[str, str]] = {
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    ("services.exe", "cmd.exe"),
    ("explorer.exe", "rundll32.exe"),
}

RARE_PROCESSES = {"certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe"}
SPECIFIC_PERSISTENCE_CHAIN_MARKERS = (
    ".sdb",
    "\\apppatch\\custom\\",
    "shell32.dll,openas_rundll",
    "malwr.vbs",
)



def detect(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    alerts.extend(_print_spooler_exploitation(events))
    alerts.extend(_spooler_spawned_shell(events))
    alerts.extend(_suspicious_process_chains(events))
    alerts.extend(_rare_processes(events))
    alerts.extend(_pre_log_wipe(events))
    return alerts


def _basename(path: str) -> str:
    text = (path or "").replace("\\", "/").lower()
    return text.split("/")[-1]


def _is_spooler_shell(ev: NormalizedEvent) -> bool:
    suspicious_children = {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"}
    parent = _basename(ev.parent_process)
    child = _basename(ev.process_name)
    return ev.event_id in (4688, 1) and parent == "spoolsv.exe" and child in suspicious_children


def _is_print_spooler_exploitation_context(ev: NormalizedEvent) -> bool:
    if not _is_spooler_shell(ev):
        return False

    user = " ".join(
        value.lower()
        for value in [
            ev.domain_user,
            ev.subject_domain_user,
            ev.event_data.get("User", ""),
            ev.event_data.get("IntegrityLevel", ""),
        ]
        if value
    )
    cmd = (ev.command_line or "").lower()
    return (
        "system" in user
        or "nt authority\\system" in user
        or "integritylevel" in user and "system" in user
        or cmd.strip().strip('"') in {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"}
    )


def _print_spooler_exploitation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    for ev in events:
        if not _is_print_spooler_exploitation_context(ev):
            continue

        child = _basename(ev.process_name)
        actor = ev.event_data.get("User", "") or ev.domain_user or "NT AUTHORITY\\SYSTEM"
        alerts.append(
            Alert(
                rule_name="Print Spooler Exploitation",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1068",
                description=f"Print spooler launched {child} as {actor} on {ev.computer}",
                explanation="spoolsv.exe launching a shell or script interpreter under SYSTEM context is strongly associated with PrintNightmare-style spooler exploitation and malicious printer-driver abuse.",
                confidence="high",
                investigate_next="Investigate recent printer-driver installs, Point and Print activity, spooler DLL loads, and any commands executed by the spawned child process.",
                event=ev,
                user=actor,
                process=ev.process_name,
                parent_process=ev.parent_process,
                evidence={
                    "parent_process": ev.parent_process,
                    "child_process": ev.process_name,
                    "command_line": ev.command_line[:400],
                    "execution_user": actor,
                    "evidence_strength": "high",
                },
            )
        )
    return alerts


def _specific_persistence_chain_context(ev: NormalizedEvent) -> bool:
    cmd = (ev.command_line or "").lower()
    if any(marker in cmd for marker in SPECIFIC_PERSISTENCE_CHAIN_MARKERS):
        return True

    parent = _basename(ev.parent_process)
    child = _basename(ev.process_name)
    normalized = cmd.strip().strip('"')
    if parent == "services.exe" and child == "cmd.exe" and normalized in {"cmd.exe", r"c:\windows\system32\cmd.exe"}:
        return True
    return False


def _spooler_spawned_shell(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []

    for ev in events:
        if not _is_spooler_shell(ev):
            continue
        if _is_print_spooler_exploitation_context(ev):
            continue
        child = _basename(ev.process_name)

        alerts.append(
            Alert(
                rule_name="Spooler Spawned Shell",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1574",
                description=f"Print spooler spawned {child} on {ev.computer}",
                explanation="spoolsv.exe should not normally launch shells or script interpreters. This lineage is strongly associated with spooler abuse such as PrintNightmare-style execution.",
                confidence="high",
                investigate_next="Investigate recent printer driver changes, spooler-related DLL loads, and whether the spawned child process executed attacker-controlled commands.",
                event=ev,
                process=ev.process_name,
                parent_process=ev.parent_process,
                evidence={
                    "parent_process": ev.parent_process,
                    "child_process": ev.process_name,
                    "command_line": ev.command_line[:400],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _suspicious_process_chains(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    for ev in events:
        if ev.event_id not in (4688, 1):
            continue
        parent = _basename(ev.parent_process)
        child = _basename(ev.process_name)
        if (parent, child) not in CHAIN_PATTERNS:
            continue
        if _specific_persistence_chain_context(ev):
            continue

        alerts.append(
            Alert(
                rule_name="Behavioral: Suspicious Process Chain",
                severity="high",
                mitre_tactic="Execution",
                mitre_technique="T1059",
                description=f"{parent} -> {child} on {ev.computer}",
                explanation="Unexpected parent/child process lineage indicates scripted or macro-driven execution.",
                confidence="high",
                investigate_next="Review command line and parent document source. Validate whether this execution chain is expected.",
                event=ev,
                evidence={"parent_process": parent, "process": child, "command_line": ev.command_line[:500], "evidence_strength": "high"},
            )
        )
    return alerts


def _rare_processes(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    per_host_counter: Dict[str, Counter] = defaultdict(Counter)
    host_totals: Counter = Counter()

    for ev in events:
        if ev.event_id not in (4688, 1):
            continue
        host = ev.computer or "unknown"
        proc = _basename(ev.process_name)
        if not proc:
            continue
        per_host_counter[host][proc] += 1
        host_totals[host] += 1

    for ev in events:
        if ev.event_id not in (4688, 1):
            continue
        host = ev.computer or "unknown"
        proc = _basename(ev.process_name)
        if proc not in RARE_PROCESSES:
            continue

        count = per_host_counter[host][proc]
        if count > 2:
            continue
        if host_totals[host] < 10:
            continue

        alerts.append(
            Alert(
                rule_name="Behavioral: Rare Process Execution",
                severity="medium",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1218",
                description=f"Rare process {proc} observed on {host} ({count} occurrence(s))",
                explanation="Low-frequency execution of LOLBins can indicate attacker tradecraft.",
                confidence="medium",
                investigate_next="Confirm business justification for this process on the host and review parent process lineage.",
                event=ev,
                evidence={"process": proc, "host_occurrences": count, "host_total_process_events": host_totals[host], "evidence_strength": "medium"},
            )
        )

    return alerts


def _pre_log_wipe(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    sorted_events = sorted([e for e in events if e.timestamp], key=lambda e: e.timestamp)
    if not sorted_events:
        return alerts

    for ev in sorted_events:
        if ev.event_id != 1102:
            continue

        window_start = ev.timestamp - timedelta(minutes=10)
        host = ev.computer
        precursors = []

        for prev in sorted_events:
            if prev.timestamp < window_start or prev.timestamp >= ev.timestamp:
                continue
            if host and prev.computer and prev.computer != host:
                continue

            cmd = prev.command_line.lower()
            if prev.event_id == 10 and "lsass.exe" in (prev.event_data.get("TargetImage", "").lower()):
                precursors.append({"type": "lsass_access", "event_id": prev.event_id, "timestamp": prev.timestamp.isoformat()})
            elif prev.event_id in (7045, 4697):
                precursors.append(
                    {
                        "type": "service_creation",
                        "event_id": prev.event_id,
                        "timestamp": prev.timestamp.isoformat(),
                        "service": prev.service_name,
                    }
                )
            elif prev.event_id in (4104, 4688, 1) and (
                "powershell" in cmd and ("-enc" in cmd or "downloadstring" in cmd or "invoke-expression" in cmd)
            ):
                precursors.append(
                    {
                        "type": "suspicious_powershell",
                        "event_id": prev.event_id,
                        "timestamp": prev.timestamp.isoformat(),
                    }
                )

        if not precursors:
            continue

        alerts.append(
            Alert(
                rule_name="Behavioral: Pre-Log-Wipe Activity",
                severity="critical",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1070.001",
                description=f"Suspicious activity observed before audit log clear on {host}",
                explanation="Activity in the minutes before Event 1102 suggests an attempt to execute and then erase evidence.",
                confidence="high",
                investigate_next="Prioritize containment and preserve alternate telemetry (Sysmon, EDR, network logs).",
                event=ev,
                evidence={"precursors": precursors, "precursor_count": len(precursors), "evidence_strength": "high"},
            )
        )

    return alerts
