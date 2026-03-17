"""Centralized false-positive suppression.

Applied after detection but before correlation and reporting.
Removes known-noisy patterns that waste analyst time.
"""

from collections import Counter
import fnmatch
import re
from typing import Dict, List

from models.event_model import Alert

SYSTEM_USERS = frozenset(
    {
        "-",
        "",
        "system",
        "local service",
        "network service",
        "trustedinstaller",
        "nt service\\trustedinstaller",
        "dwm-1",
        "dwm-2",
        "dwm-3",
        "umfd-0",
        "umfd-1",
        "anonymous logon",
        "font driver host\\umfd-0",
        "window manager\\dwm-1",
    }
)

BENIGN_IPS = frozenset({"127.0.0.1", "::1", "-", "", "0.0.0.0", "fe80::1"})

BENIGN_TASK_PREFIXES = (
    "\\microsoft\\windows\\",
    "\\microsoft\\office\\",
    "\\microsoft\\edgeupdate",
    "\\google\\update",
    "\\mozilla\\firefox",
)

BENIGN_SERVICES = frozenset(
    {
        "wuauserv",
        "bits",
        "trustedinstaller",
        "tiledatamodelsvc",
        "windows event log",
        "state repository service",
        "diagnostic policy service",
        "windows update",
        "windows modules installer",
        "background intelligent transfer",
        "rdagent",
        "windows azure guest agent",
        "mellanox winof-2 networking driver",
    }
)

BENIGN_SERVICE_PATH_MARKERS = (
    "\\windowsazure\\packages\\waappagent.exe",
    "\\system32\\drivers\\mlx5.sys",
)
LOOPBACK_EXEMPT_LATERAL_RULES = frozenset(
    {
        "WMI Remote Execution",
        "WinRM Remote Execution",
        "PsExec Named Pipe Stager",
        "PsExec Service Payload",
        "PsExec Remote Execution Sequence",
        "SMBexec Service Payload",
        "SMBexec Remote Execution Sequence",
        "ATexec Remote Task Execution",
        "Explicit Credentials Followed by Remote Execution",
        "DCOM MSHTA Remote Execution",
        "DCOM Internet Explorer Execution",
        "WMI Remote Registry Modification",
        "PsExec-Style Remote Service",
        "Renamed PsExec Service Pipes",
        "TSCLIENT Startup Folder Drop",
        "RDP Shadowing Enabled",
        "Remote Service Creation Command",
        "OpenSSH Server Installed",
        "OpenSSH Server Enabled",
        "OpenSSH Server Listening",
        "New SMB Share Added",
        "PsExec Service Binary Drop",
        "Repeated RDP Authentication Accepted",
        "Zerologon RPC Activity",
    }
)


class FPFilter:
    """Suppress false positives and track what was removed."""

    def __init__(self, tuning: dict | None = None):
        self.tuning = tuning or {}
        self.suppressed = 0
        self.by_rule: Counter = Counter()
        self.by_reason: Counter = Counter()
        self.samples: List[Dict[str, str]] = []

    def apply(self, alerts: List[Alert]) -> List[Alert]:
        """Filter alerts, returning only non-FP ones."""
        return [a for a in alerts if not self._is_fp(a)]

    def summary_lines(self) -> List[str]:
        if not self.suppressed:
            return ["  No false positives suppressed"]
        lines = [f"  Suppressed {self.suppressed} noisy alerts:"]
        for reason, count in self.by_reason.most_common():
            lines.append(f"    {reason}: {count}")
        return lines

    def summary_dict(self) -> Dict[str, object]:
        return {
            "suppressed_total": self.suppressed,
            "by_rule": dict(self.by_rule),
            "by_reason": dict(self.by_reason),
            "samples": list(self.samples[:25]),
        }

    def _suppress(self, reason: str, alert: Alert | None = None) -> bool:
        self.suppressed += 1
        if alert is not None and alert.rule_name:
            self.by_rule[alert.rule_name] += 1
        self.by_reason[reason] += 1
        if alert is not None and len(self.samples) < 25:
            self.samples.append(
                {
                    "reason": reason,
                    "rule_name": alert.rule_name,
                    "host": alert.host,
                    "user": alert.user,
                    "process": alert.process,
                    "source_ip": alert.source_ip,
                }
            )
        return True

    def _is_system_user(self, user_value: str) -> bool:
        user = (user_value or "").lower().strip()
        return user in SYSTEM_USERS or user.endswith("$")

    @staticmethod
    def _normalize_match_text(value: str) -> str:
        text = str(value or "").strip().lower()
        return re.sub(r"[\\/]+", r"\\", text)

    @staticmethod
    def _matches_pattern(value: str, pattern: str) -> bool:
        clean_value = FPFilter._normalize_match_text(value)
        clean_pattern = FPFilter._normalize_match_text(pattern)
        if not clean_value or not clean_pattern:
            return False
        if any(token in clean_pattern for token in "*?["):
            return fnmatch.fnmatchcase(clean_value, clean_pattern)
        return clean_value == clean_pattern

    @staticmethod
    def _service_aliases(value: str) -> List[str]:
        clean_value = str(value or "").strip()
        if not clean_value:
            return []
        aliases = [clean_value]
        aliases.extend(
            match.strip()
            for match in re.findall(r"\(([^()]+)\)", clean_value)
            if match.strip()
        )
        deduped = []
        seen = set()
        for alias in aliases:
            lowered = alias.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            deduped.append(alias)
        return deduped

    def _field_values(self, field: str, value: str) -> List[str]:
        if field in {"service", "services"}:
            return self._service_aliases(value)
        clean_value = str(value or "").strip()
        return [clean_value] if clean_value else []

    def _rule_field_values(self, field: str, alert: Alert) -> List[str]:
        if field.startswith("evidence_"):
            evidence_key = field[len("evidence_") :]
            value = (alert.evidence or {}).get(evidence_key, "")
            if isinstance(value, (list, tuple, set)):
                values = []
                for item in value:
                    values.extend(self._field_values(field, str(item or "")))
                deduped = []
                seen = set()
                for item in values:
                    lowered = item.lower()
                    if lowered in seen:
                        continue
                    seen.add(lowered)
                    deduped.append(item)
                return deduped
            return self._field_values(field, str(value or ""))
        if field == "command_line":
            values = []
            if alert.event:
                values.extend(
                    self._field_values(
                        field,
                        alert.event.command_line
                        or alert.event.command_line_value
                        or alert.event.event_data.get("ImagePath", "")
                        or alert.event.event_data.get("ServiceFileName", ""),
                    )
                )
            values.extend(self._field_values(field, str((alert.evidence or {}).get("binary", "") or "")))
            deduped = []
            seen = set()
            for item in values:
                lowered = item.lower()
                if lowered in seen:
                    continue
                seen.add(lowered)
                deduped.append(item)
            return deduped
        value_map = {
            "host": alert.host,
            "user": alert.user,
            "subject_user": alert.subject_user,
            "target_user": alert.target_user,
            "account_name": alert.account_name,
            "process": alert.process,
            "service": alert.service,
            "task": alert.scheduled_task,
            "ip": alert.source_ip,
            "parent_process": alert.parent_process,
            "description": alert.description,
        }
        return self._field_values(field, value_map.get(field, ""))

    def _allowlist_match(self, alert: Alert) -> str:
        allowlists = (self.tuning or {}).get("allowlists", {}) or {}
        checks = (
            ("hosts", alert.host),
            ("users", alert.user),
            ("processes", alert.process),
            ("services", alert.service),
            ("tasks", alert.scheduled_task),
            ("ips", alert.source_ip),
        )
        for key, value in checks:
            values = self._field_values(key, value)
            if not values:
                continue
            candidates = [str(item or "").strip() for item in allowlists.get(key, []) or []]
            if any(self._matches_pattern(field_value, candidate) for candidate in candidates for field_value in values):
                return f"allowlist_{key}"
        return ""

    def _rule_suppression_match(self, alert: Alert) -> str:
        for entry in (self.tuning or {}).get("rule_suppressions", []) or []:
            if not self._matches_pattern(alert.rule_name, str(entry.get("rule", "") or "")):
                continue
            matched = True
            entry_fields = [
                "host",
                "user",
                "subject_user",
                "target_user",
                "account_name",
                "process",
                "service",
                "task",
                "ip",
                "command_line",
                "parent_process",
                "description",
            ]
            entry_fields.extend(
                key for key in entry.keys()
                if str(key).startswith("evidence_")
            )
            for field in entry_fields:
                expected = str(entry.get(field, "") or "").strip()
                values = self._rule_field_values(field, alert)
                if expected and not any(self._matches_pattern(field_value, expected) for field_value in values):
                    matched = False
                    break
            if matched:
                return str(entry.get("reason", "") or f"tuning_rule:{entry.get('rule', '')}").strip()
        return ""

    def _is_fp(self, alert: Alert) -> bool:
        ev = alert.event
        if ev is None:
            return False

        allowlist_reason = self._allowlist_match(alert)
        if allowlist_reason:
            return self._suppress(allowlist_reason, alert)

        rule_suppression_reason = self._rule_suppression_match(alert)
        if rule_suppression_reason:
            return self._suppress(rule_suppression_reason, alert)

        if (
            (alert.rule_name or "") == "Windows Credential Manager Access"
            and str((alert.evidence or {}).get("vault_access_profile", "")).strip().lower() == "application_vault_churn"
        ):
            return self._suppress("benign_vault_churn", alert)

        if (alert.rule_name or "") in {
            "Password Policy Enumeration",
            "Command-Line Password Policy Discovery",
            "User Account Discovery",
            "Group Discovery",
            "Network Share Discovery",
            "Domain Trust Discovery",
            "SPN Discovery",
            "Audit Policy Discovery",
            "Firewall Configuration Discovery",
            "Scheduled Task Configuration Discovery",
            "DNS Zone Transfer Attempt",
            "Remote Hosts File Discovery",
            "Anonymous SMB Service Probe",
            "Local Account Enumeration",
            "Local Group Enumeration",
            "Remote RPC Discovery",
            "Remote Print Spooler Pipe Access",
        } and not self._is_system_user(alert.user):
            return False

        # Generic suppression for machine/service accounts.
        if self._is_system_user(ev.subject_user) or self._is_system_user(ev.target_user) or self._is_system_user(alert.user):
            if alert.severity.lower() not in {"critical", "high"}:
                return self._suppress("system_or_machine_account", alert)

        # -- Machine account ($) doing localhost explicit creds --
        if ev.event_id == 4648 and ev.is_machine_account:
            target = (ev.event_data.get("TargetServerName", "") or "").lower()
            if target in ("localhost", "127.0.0.1", "", "-"):
                return self._suppress("machine_localhost_4648", alert)

        # -- SYSTEM / service logon (type 0 or 5) --
        if ev.event_id == 4624 and ev.logon_type in ("0", "5"):
            return self._suppress("system_service_logon", alert)

        # -- DWM / UMFD window manager logons --
        if ev.event_id == 4624:
            user = (ev.target_user or "").lower()
            if user.startswith(("dwm-", "umfd-")):
                return self._suppress("dwm_umfd_logon", alert)

        # -- System account failed logon --
        if ev.event_id == 4625 and self._is_system_user(ev.target_user):
            return self._suppress("system_failed_logon", alert)

        # -- Lateral movement from loopback --
        if alert.mitre_tactic == "Lateral Movement":
            if alert.rule_name in LOOPBACK_EXEMPT_LATERAL_RULES:
                return False
            src = ev.source_ip or ""
            if src in BENIGN_IPS:
                return self._suppress("lateral_loopback", alert)

        # -- Privilege assigned to SYSTEM / machine accounts (4672) --
        if ev.event_id == 4672 and self._is_system_user(ev.subject_user):
            return self._suppress("system_privilege_4672", alert)

        # -- Benign Microsoft scheduled tasks --
        if ev.event_id in (4698, 4700, 4702):
            task = (ev.event_data.get("TaskName", "") or "").lower()
            for prefix in BENIGN_TASK_PREFIXES:
                if task.startswith(prefix):
                    return self._suppress("benign_task", alert)

        # -- Benign service installs --
        if ev.event_id in (7045, 4697):
            svc = (ev.event_data.get("ServiceName", "") or "").lower()
            image_path = (ev.event_data.get("ImagePath", "") or ev.event_data.get("ServiceFileName", "") or "").lower()
            if svc in BENIGN_SERVICES or any(marker in image_path for marker in BENIGN_SERVICE_PATH_MARKERS):
                return self._suppress("benign_service", alert)

        return False
