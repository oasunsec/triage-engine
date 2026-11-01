"""Native parser for raw Windows Task Scheduler definition files (Tasks\\<path>).

Each file is an XML task definition as stored under System32\\Tasks. The
parser reads text only: it never resolves entities, loads DTDs, or follows
references, and it rejects any document type or entity declaration. One
observation is produced per Exec action (or one for a task without one) so
the existing persistence correlation rules apply without special cases.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone

MAX_TASK_BYTES = 1024 * 1024
MAX_ACTIONS = 32
MAX_TRIGGERS = 64
MAX_TEXT = 8192
_DECLARATION = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.I)
_INTERPRETATION = ("Task definition present at collection; execution unconfirmed. "
                   "The registration date and author are written by whoever registered the task and are unverified.")


def _decode(content: bytes) -> str:
    if content.startswith(b"\xff\xfe") or content.startswith(b"\xfe\xff"):
        return content.decode("utf-16")
    if content.startswith(b"\xef\xbb\xbf"):
        return content[3:].decode("utf-8")
    # Task files are normally UTF-16LE with a BOM; accept BOM-less UTF-16LE too.
    if len(content) >= 4 and content[1] == 0 and content[3] == 0:
        return content.decode("utf-16-le")
    return content.decode("utf-8")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(element, name: str):
    if element is None:
        return None
    for child in element:
        if _local(child.tag) == name:
            return child
    return None


def _text(element, name: str) -> str:
    found = _child(element, name)
    value = (found.text or "").strip() if found is not None else ""
    if len(value) > MAX_TEXT:
        raise ValueError(f"Task field {name} exceeds {MAX_TEXT} characters")
    return value


def _bool(element, name: str, default: bool) -> bool:
    value = _text(element, name).lower()
    return default if not value else value == "true"


def _registration_date(raw: str) -> dict:
    if not raw:
        return {"raw": "", "utc": None, "timezone": "absent"}
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return {"raw": raw, "utc": None, "timezone": "unparsed"}
    if parsed.tzinfo is None:
        # Commonly local time with no offset; converting would invent a timezone.
        return {"raw": raw, "utc": None, "timezone": "unspecified"}
    return {"raw": raw, "utc": parsed.astimezone(timezone.utc).isoformat(), "timezone": "explicit"}


def parse_task_xml(content: bytes, *, source_name: str, source_sha256: str, host: str, observed_at: str,
                   collector: dict, original_name: str = "") -> tuple[list[dict], list[str]]:
    """Return (observations, warnings) for one raw task definition file."""
    if not isinstance(content, bytes) or not content or len(content) > MAX_TASK_BYTES:
        raise ValueError("Task definition must be 1 byte to 1 MiB")
    try:
        text = _decode(content)
    except UnicodeError as exc:
        raise ValueError("Task definition is not UTF-16 or UTF-8 text") from exc
    if "\x00" in text:
        raise ValueError("Task definition contains NUL characters")
    if _DECLARATION.search(text):
        raise ValueError("Task definition contains a DOCTYPE or ENTITY declaration")
    # The XML declaration names UTF-16, but the text is already decoded.
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1)
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ValueError(f"Malformed task definition XML: {exc}") from exc
    if _local(root.tag) != "Task":
        raise ValueError("Not a Task Scheduler definition (root element is not Task)")

    warnings: list[str] = []
    info = _child(root, "RegistrationInfo")
    uri = _text(info, "URI")
    if uri:
        task_path = uri if uri.startswith("\\") else "\\" + uri
    else:
        task_path = "\\" + (original_name or source_name).replace("/", "\\").lstrip("\\")
        warnings.append(f"Task {source_name} has no RegistrationInfo URI; its path was taken from the file name.")
    folder, _, name = task_path.rpartition("\\")
    principal = _child(_child(root, "Principals"), "Principal")
    settings = _child(root, "Settings")
    triggers_element = _child(root, "Triggers")
    triggers = []
    for trigger in list(triggers_element if triggers_element is not None else [])[:MAX_TRIGGERS + 1]:
        triggers.append({"type": _local(trigger.tag), "enabled": _bool(trigger, "Enabled", True),
                         "start_boundary_raw": _text(trigger, "StartBoundary"), "user_id": _text(trigger, "UserId")})
    if len(triggers) > MAX_TRIGGERS:
        raise ValueError(f"Task has more than {MAX_TRIGGERS} triggers")
    actions_element = _child(root, "Actions")
    actions = []
    for action in list(actions_element if actions_element is not None else [])[:MAX_ACTIONS + 1]:
        kind = _local(action.tag)
        if kind == "Exec":
            command, arguments = _text(action, "Command"), _text(action, "Arguments")
            # Task Scheduler stores the executable separately, often unquoted with spaces;
            # quote it so the combined command line keeps the path boundary.
            executable = f'"{command}"' if " " in command and not command.startswith('"') else command
            actions.append({"type": "Exec", "command": f"{executable} {arguments}".strip(), "executable": command, "arguments": arguments,
                            "working_directory": _text(action, "WorkingDirectory")})
        elif kind == "ComHandler":
            actions.append({"type": "ComHandler", "command": "", "class_id": _text(action, "ClassId"), "data": _text(action, "Data")})
        else:
            actions.append({"type": kind, "command": ""})
    if len(actions) > MAX_ACTIONS:
        raise ValueError(f"Task has more than {MAX_ACTIONS} actions")

    common = {
        "name": name, "location": folder or "\\", "task_path": task_path,
        "user": _text(principal, "UserId") or _text(principal, "GroupId"),
        "run_level": _text(principal, "RunLevel"), "logon_type": _text(principal, "LogonType"),
        "enabled": _bool(settings, "Enabled", True), "hidden": _bool(settings, "Hidden", False),
        "author": _text(info, "Author"), "registration_date": _registration_date(_text(info, "Date")),
        "description": _text(info, "Description")[:1024], "triggers": triggers,
        "source_format": "task_scheduler_xml", "original_name": original_name,
    }
    observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    observations = []
    for index, action in enumerate(actions or [{"type": "none", "command": ""}]):
        identity = json.dumps([source_sha256.lower(), index, host, observed], separators=(",", ":"))
        observations.append({
            "id": "obs_" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "kind": "scheduled_task", "host": host, "observed_at": observed,
            "time_semantics": "collection_snapshot", "interpretation": _INTERPRETATION,
            "source_id": "evi_" + source_sha256.lower(), "source_file": source_name, "source_record": index,
            "source_sha256": source_sha256.lower(), "collector": collector,
            "native_locator": {"task_path": task_path, "action_index": index},
            "details": {**common, "command": action.get("command", ""), "action": action},
        })
    return observations, warnings
