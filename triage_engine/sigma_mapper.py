"""Field mapping helpers for Sigma-like rule evaluation against normalized EVTX events."""

from __future__ import annotations

import re
from typing import List, Tuple

from models.event_model import NormalizedEvent


FIELD_ALIASES = {
    "eventid": "event_id",
    "channel": "channel",
    "provider_name": "provider",
    "providername": "provider",
    "provider": "provider",
    "computername": "computer",
    "computer": "computer",
    "image": "process_name",
    "newprocessname": "process_name",
    "processname": "process_name",
    "parentimage": "parent_process",
    "parentprocessname": "parent_process",
    "commandline": "command_line",
    "scriptblocktext": "command_line",
    "servicename": "service_name",
    "sharename": "share_name",
    "taskname": "task_name",
    "targetobject": "registry_key",
    "objectname": "registry_key",
    "subjectusername": "subject_user",
    "targetusername": "target_user",
    "accountname": "account_name",
    "user": "domain_user",
    "ipaddress": "source_ip",
    "sourceip": "source_ip",
    "destinationip": "destination_ip",
}


def split_modifier(field: str) -> Tuple[str, str]:
    parts = str(field or "").split("|", 1)
    base = parts[0].strip()
    modifier = parts[1].strip().lower() if len(parts) > 1 else ""
    return base, modifier


def supported_field(field: str) -> bool:
    base, _ = split_modifier(field)
    key = re.sub(r"[^a-z0-9_]", "", base.lower())
    return key in FIELD_ALIASES or bool(base)


def event_values(event: NormalizedEvent, field: str) -> List[str]:
    base, _ = split_modifier(field)
    key = re.sub(r"[^a-z0-9_]", "", base.lower())
    alias = FIELD_ALIASES.get(key)
    values: List[str] = []
    if alias == "event_id":
        values.append(str(event.event_id))
    elif alias == "channel":
        values.append(event.channel or "")
    elif alias == "provider":
        values.append(event.provider or "")
    elif alias == "computer":
        values.append(event.computer or "")
    elif alias == "process_name":
        values.extend([event.process_name or "", event.event_data.get("Image", ""), event.event_data.get("NewProcessName", "")])
    elif alias == "parent_process":
        values.extend([event.parent_process or "", event.event_data.get("ParentImage", ""), event.event_data.get("ParentProcessName", "")])
    elif alias == "command_line":
        values.extend([event.command_line or "", event.event_data.get("ScriptBlockText", "")])
    elif alias == "service_name":
        values.append(event.service_name or "")
    elif alias == "share_name":
        values.append(event.share_name or "")
    elif alias == "task_name":
        values.append(event.task_name or "")
    elif alias == "registry_key":
        values.append(event.registry_key or "")
    elif alias == "subject_user":
        values.extend([event.subject_domain_user or "", event.subject_user or ""])
    elif alias == "target_user":
        values.extend([event.target_domain_user or "", event.target_user or ""])
    elif alias == "account_name":
        values.append(event.account_name or "")
    elif alias == "domain_user":
        values.append(event.domain_user or "")
    elif alias == "source_ip":
        values.append(event.source_ip or "")
    elif alias == "destination_ip":
        values.append(event.destination_ip or "")
    else:
        values.append(event.event_data.get(base, ""))
    return [str(value or "") for value in values if str(value or "")]

