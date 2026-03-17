"""Normalized models shared across parser, detection, correlation, and reporting."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from triage_engine.user_utils import add_user_identity_fields


def _iso(ts: Optional[datetime]) -> Optional[str]:
    return ts.isoformat() if ts else None


def _clean(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text in {"-", "(null)", "None"} else text


def _coalesce(*values: Any) -> str:
    for value in values:
        clean = _clean(value)
        if clean:
            return clean
    return ""


def _domain_user(domain: Any, user: Any) -> str:
    domain_text = _clean(domain)
    user_text = _clean(user)
    if not user_text:
        return ""
    if "\\" in user_text:
        return user_text
    return f"{domain_text}\\{user_text}" if domain_text else user_text


def _account_display(value: Any) -> str:
    account = _clean(value)
    return account


@dataclass
class NormalizedEvent:
    """A single parsed Windows event, normalized for detection."""

    event_id: int
    timestamp: Optional[datetime]
    computer: str = ""
    channel: str = ""
    provider: str = ""
    target_user: str = ""
    target_domain: str = ""
    subject_user: str = ""
    subject_domain: str = ""
    account_name: str = ""
    logon_user: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    logon_type: str = ""
    status: str = ""
    sub_status: str = ""
    share_name_value: str = ""
    command_line_value: str = ""
    process_name_value: str = ""
    parent_process_value: str = ""
    service_name_value: str = ""
    event_data: Dict[str, str] = field(default_factory=dict)
    raw_xml: str = ""

    @property
    def subject_domain_user(self) -> str:
        return _domain_user(self.subject_domain, self.subject_user)

    @property
    def target_domain_user(self) -> str:
        return _domain_user(self.target_domain, self.target_user)

    @property
    def actor_user(self) -> str:
        if self.event_id in (4624, 4625, 4768, 4769, 4771, 4776, 4740):
            return _coalesce(self.target_user, self.subject_user, self.logon_user, self.account_name)
        if self.event_id == 4648:
            return _coalesce(self.subject_user, self.logon_user, self.target_user)
        if self.event_id in (4688, 1, 4698, 4702, 4672, 4616, 4719, 1102):
            return _coalesce(self.subject_user, self.logon_user, self.account_name, self.target_user)
        if self.event_id in (7045, 4697):
            return _coalesce(self.subject_user, self.logon_user)
        if self.event_id == 5140:
            return _coalesce(self.subject_user, self.account_name, self.target_user, self.logon_user)
        return _coalesce(self.subject_user, self.target_user, self.logon_user, self.account_name)

    @property
    def user(self) -> str:
        return self.actor_user

    @property
    def actor_domain_user(self) -> str:
        if self.event_id in (4624, 4625, 4768, 4769, 4771, 4776, 4740):
            return _coalesce(
                self.target_domain_user,
                self.subject_domain_user,
                _account_display(self.logon_user),
                _account_display(self.account_name),
            )
        if self.event_id == 4648:
            return _coalesce(
                self.subject_domain_user,
                _account_display(self.logon_user),
                self.target_domain_user,
            )
        if self.event_id in (4688, 1, 4698, 4702, 4672, 4616, 4719, 1102):
            return _coalesce(
                self.subject_domain_user,
                _account_display(self.logon_user),
                _account_display(self.account_name),
                self.target_domain_user,
            )
        if self.event_id in (7045, 4697):
            return _coalesce(self.subject_domain_user, _account_display(self.logon_user))
        if self.event_id == 5140:
            return _coalesce(
                self.subject_domain_user,
                _account_display(self.account_name),
                self.target_domain_user,
                _account_display(self.logon_user),
            )
        return _coalesce(
            self.subject_domain_user,
            self.target_domain_user,
            _account_display(self.logon_user),
            _account_display(self.account_name),
        )

    @property
    def domain_user(self) -> str:
        return self.actor_domain_user

    @property
    def command_line(self) -> str:
        return _coalesce(
            self.command_line_value,
            self.event_data.get("CommandLine", ""),
            self.event_data.get("ScriptBlockText", ""),
            self.event_data.get("CommandLineTemplate", ""),
            self.event_data.get("ImagePath", "") if self.event_id in (7045, 4697) else "",
        )

    @property
    def process_name(self) -> str:
        return _coalesce(
            self.process_name_value,
            self.event_data.get("NewProcessName", ""),
            self.event_data.get("ProcessName", ""),
            self.event_data.get("Image", ""),
            self.event_data.get("SourceImage", ""),
        )

    @property
    def parent_process(self) -> str:
        return _coalesce(
            self.parent_process_value,
            self.event_data.get("ParentProcessName", ""),
            self.event_data.get("ParentImage", ""),
        )

    @property
    def service_name(self) -> str:
        return _coalesce(self.service_name_value, self.event_data.get("ServiceName", ""))

    @property
    def share_name(self) -> str:
        return _coalesce(self.share_name_value, self.event_data.get("ShareName", ""))

    @property
    def task_name(self) -> str:
        return self.event_data.get("TaskName", "") or ""

    @property
    def registry_key(self) -> str:
        return self.event_data.get("TargetObject", "") or self.event_data.get("ObjectName", "") or ""

    @property
    def is_machine_account(self) -> bool:
        return _coalesce(self.subject_user, self.target_user, self.account_name, self.logon_user).rstrip().endswith("$")

    LOGON_TYPES = {
        "0": "System",
        "2": "Interactive",
        "3": "Network",
        "4": "Batch",
        "5": "Service",
        "7": "Unlock",
        "8": "NetworkCleartext",
        "9": "NewCredentials",
        "10": "RDP",
        "11": "CachedInteractive",
    }
    STATUS_NAMES = {
        "0xC0000064": "User does not exist",
        "0xC000006A": "Wrong password",
        "0xC000006D": "Bad username or password",
        "0xC0000072": "Disabled account",
        "0xC0000234": "Account locked out",
        "0xC0000193": "Expired account",
    }

    @property
    def logon_type_name(self) -> str:
        return self.LOGON_TYPES.get(self.logon_type, self.logon_type)

    @property
    def failure_reason(self) -> str:
        return self.STATUS_NAMES.get(self.sub_status, "") or self.STATUS_NAMES.get(self.status, "")


@dataclass
class Alert:
    """Legacy detection finding retained for backward compatibility."""

    rule_name: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    explanation: str
    event: Optional[NormalizedEvent]
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"
    confidence_factors: List[str] = field(default_factory=list)
    promotion_policy: str = ""
    investigate_next: str = ""
    recommended_pivots: List[str] = field(default_factory=list)
    rule_source: str = "native"
    timestamp: Optional[datetime] = None
    host: str = ""
    user: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    subject_user: str = ""
    target_user: str = ""
    account_name: str = ""
    process: str = ""
    parent_process: str = ""
    service: str = ""
    share_name: str = ""
    scheduled_task: str = ""
    registry_key: str = ""

    def __post_init__(self):
        if self.event:
            if not self.timestamp:
                self.timestamp = self.event.timestamp
            if not self.host:
                self.host = self.event.computer
            if not self.user:
                self.user = self.event.domain_user
            if not self.source_ip:
                self.source_ip = self.event.source_ip or ""
            if not self.destination_ip:
                self.destination_ip = self.event.destination_ip or ""
            if not self.subject_user:
                self.subject_user = self.event.subject_domain_user or self.event.subject_user
            if not self.target_user:
                self.target_user = self.event.target_domain_user or self.event.target_user
            if not self.account_name:
                self.account_name = self.event.account_name
            if not self.process:
                self.process = self.event.process_name
            if not self.parent_process:
                self.parent_process = self.event.parent_process
            if not self.service:
                self.service = self.event.service_name
            if not self.share_name:
                self.share_name = self.event.share_name
            if not self.scheduled_task:
                self.scheduled_task = self.event.task_name
            if not self.registry_key:
                self.registry_key = self.event.registry_key
            if not self.recommended_pivots:
                for etype, val in [
                    ("host", self.host),
                    ("user", self.user),
                    ("ip", self.source_ip),
                    ("ip", self.destination_ip),
                    ("process", self.process),
                    ("service", self.service),
                    ("share", self.share_name),
                ]:
                    if val and val != "-":
                        self.recommended_pivots.append(f"{etype}:{val}")

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "description": self.description,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "confidence_factors": self.confidence_factors,
            "promotion_policy": self.promotion_policy,
            "investigate_next": self.investigate_next,
            "recommended_pivots": self.recommended_pivots,
            "rule_source": self.rule_source,
            "timestamp": _iso(self.timestamp),
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "subject_user": self.subject_user,
            "target_user": self.target_user,
            "account_name": self.account_name,
            "process": self.process,
            "parent_process": self.parent_process,
            "service": self.service,
            "share_name": self.share_name,
            "scheduled_task": self.scheduled_task,
            "registry_key": self.registry_key,
            "event_id": self.event.event_id if self.event else None,
            "command_line": self.event.command_line if self.event else "",
            "logon_type": self.event.logon_type_name if self.event else "",
            "parent_process": self.event.parent_process if self.event else "",
            "evidence": self.evidence,
            "raw_event_data": dict(self.event.event_data) if self.event else {},
        }
        add_user_identity_fields(payload, "user", self.user, self.host)
        add_user_identity_fields(payload, "subject_user", self.subject_user, self.host)
        add_user_identity_fields(payload, "target_user", self.target_user, self.host)
        add_user_identity_fields(payload, "account_name", self.account_name, self.host)
        return payload


@dataclass
class AttackChain:
    """Legacy correlated sequence retained for backward compatibility."""

    chain_id: str
    host: str
    alerts: List[Alert] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    risk_score: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "host": self.host,
            "tactics": self.tactics,
            "risk_score": self.risk_score,
            "start_time": _iso(self.start_time),
            "end_time": _iso(self.end_time),
            "summary": self.summary,
            "alerts": [a.to_dict() for a in self.alerts],
        }


@dataclass
class Signal:
    """Low-level suspicious evidence event."""

    id: str
    display_label: str
    source_rule: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    confidence: str
    confidence_score: int
    timestamp: Optional[datetime]
    confidence_factors: List[str] = field(default_factory=list)
    host: str = ""
    user: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    subject_user: str = ""
    target_user: str = ""
    account_name: str = ""
    process: str = ""
    parent_process: str = ""
    service: str = ""
    share_name: str = ""
    command_line: str = ""
    recommended_next: str = ""
    promotion_policy: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    raw_event_data: Dict[str, Any] = field(default_factory=dict)
    ioc_matches: List[str] = field(default_factory=list)
    telemetry_gaps: List[str] = field(default_factory=list)
    rule_source: str = "native"

    @property
    def first_seen(self) -> Optional[datetime]:
        return self.timestamp

    @property
    def last_seen(self) -> Optional[datetime]:
        return self.timestamp

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "display_label": self.display_label,
            "source_rule": self.source_rule,
            "severity": self.severity,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "description": self.description,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "confidence_factors": self.confidence_factors,
            "timestamp": _iso(self.timestamp),
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "subject_user": self.subject_user,
            "target_user": self.target_user,
            "account_name": self.account_name,
            "process": self.process,
            "parent_process": self.parent_process,
            "service": self.service,
            "share_name": self.share_name,
            "command_line": self.command_line,
            "recommended_next": self.recommended_next,
            "promotion_policy": self.promotion_policy,
            "evidence": self.evidence,
            "raw_event_data": self.raw_event_data,
            "ioc_matches": self.ioc_matches,
            "telemetry_gaps": self.telemetry_gaps,
            "rule_source": self.rule_source,
        }
        add_user_identity_fields(payload, "user", self.user, self.host)
        add_user_identity_fields(payload, "subject_user", self.subject_user, self.host)
        add_user_identity_fields(payload, "target_user", self.target_user, self.host)
        add_user_identity_fields(payload, "account_name", self.account_name, self.host)
        return payload


@dataclass
class Finding:
    """Higher-confidence suspicious activity, often composed from one or more signals."""

    id: str
    display_label: str
    title: str
    severity: str
    confidence: str
    confidence_score: int
    description: str
    summary: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    confidence_factors: List[str] = field(default_factory=list)
    signal_ids: List[str] = field(default_factory=list)
    host: str = ""
    user: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    subject_user: str = ""
    target_user: str = ""
    account_name: str = ""
    process: str = ""
    parent_process: str = ""
    service: str = ""
    share_name: str = ""
    command_line: str = ""
    recommended_next: str = ""
    recommended_pivots: List[str] = field(default_factory=list)
    promotion_reasons: List[str] = field(default_factory=list)
    telemetry_gaps: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    ioc_matches: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "display_label": self.display_label,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "confidence_factors": self.confidence_factors,
            "description": self.description,
            "summary": self.summary,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "signal_ids": self.signal_ids,
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "subject_user": self.subject_user,
            "target_user": self.target_user,
            "account_name": self.account_name,
            "process": self.process,
            "parent_process": self.parent_process,
            "service": self.service,
            "share_name": self.share_name,
            "command_line": self.command_line,
            "recommended_next": self.recommended_next,
            "recommended_pivots": self.recommended_pivots,
            "promotion_reasons": self.promotion_reasons,
            "telemetry_gaps": self.telemetry_gaps,
            "evidence": self.evidence,
            "ioc_matches": self.ioc_matches,
        }
        add_user_identity_fields(payload, "user", self.user, self.host)
        add_user_identity_fields(payload, "subject_user", self.subject_user, self.host)
        add_user_identity_fields(payload, "target_user", self.target_user, self.host)
        add_user_identity_fields(payload, "account_name", self.account_name, self.host)
        return payload


@dataclass
class Incident:
    """Correlated case-level incident composed from findings and signals."""

    id: str
    display_label: str
    incident_type: str
    title: str
    severity: str
    confidence: str
    confidence_score: int
    summary: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    confidence_factors: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    signal_ids: List[str] = field(default_factory=list)
    evidence_chain: List[Dict[str, Any]] = field(default_factory=list)
    host: str = ""
    user: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    subject_user: str = ""
    target_user: str = ""
    account_name: str = ""
    process: str = ""
    parent_process: str = ""
    service: str = ""
    share_name: str = ""
    command_line: str = ""
    technique_summary: str = ""
    recommended_next: str = ""
    recommended_pivots: List[str] = field(default_factory=list)
    promotion_reasons: List[str] = field(default_factory=list)
    telemetry_gaps: List[str] = field(default_factory=list)
    why_flagged: str = ""
    containment_guidance: List[str] = field(default_factory=list)
    scope_next: List[str] = field(default_factory=list)
    validation_steps: List[str] = field(default_factory=list)
    ioc_matches: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "display_label": self.display_label,
            "incident_type": self.incident_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "confidence_factors": self.confidence_factors,
            "summary": self.summary,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "finding_ids": self.finding_ids,
            "signal_ids": self.signal_ids,
            "evidence_chain": self.evidence_chain,
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "subject_user": self.subject_user,
            "target_user": self.target_user,
            "account_name": self.account_name,
            "process": self.process,
            "parent_process": self.parent_process,
            "service": self.service,
            "share_name": self.share_name,
            "command_line": self.command_line,
            "technique_summary": self.technique_summary,
            "recommended_next": self.recommended_next,
            "recommended_pivots": self.recommended_pivots,
            "promotion_reasons": self.promotion_reasons,
            "telemetry_gaps": self.telemetry_gaps,
            "why_flagged": self.why_flagged,
            "containment_guidance": self.containment_guidance,
            "scope_next": self.scope_next,
            "validation_steps": self.validation_steps,
            "ioc_matches": self.ioc_matches,
        }
        add_user_identity_fields(payload, "user", self.user, self.host)
        add_user_identity_fields(payload, "subject_user", self.subject_user, self.host)
        add_user_identity_fields(payload, "target_user", self.target_user, self.host)
        add_user_identity_fields(payload, "account_name", self.account_name, self.host)
        return payload
