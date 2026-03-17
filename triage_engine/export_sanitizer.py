"""Sanitize exported artifacts so they remain readable and AV-safe."""

from __future__ import annotations

import os
import re
from typing import Any


URL_RE = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)
TASK_NAME_RE = re.compile(r"-TaskName\s+[\"']([^\"']+)[\"']", re.IGNORECASE)
NEW_LOCAL_USER_RE = re.compile(r"New-LocalUser\b.*?-Name\s+['\"]([^'\"]+)['\"]", re.IGNORECASE | re.DOTALL)
BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{120,}")

SCRIPT_FIELDS = {
    "scriptblocktext",
    "script_text",
    "scripttext",
    "decodedcommand",
    "decoded_script",
    "deobfuscatedscript",
}
COMMAND_FIELDS = {
    "commandline",
    "command_line",
    "commandlinetemplate",
    "commands",
    "command_lines",
    "matched_commands",
    "follow_on_commands",
    "suspicious_commands",
    "child_command_line",
    "parent_command_line",
}
SAFE_TEXT_FIELDS = {
    "remote_url",
    "remote_ip",
    "task_name",
    "created_username",
    "actor_user",
    "group_name",
    "group_member",
    "service_name",
    "binary",
    "process_name",
    "parent_process",
}
SUMMARY_FIELDS = {"script_excerpt", "script_summary", "raw_summary"}
POWERSHELL_MARKERS = (
    "powershell",
    "pwsh",
    "iex(",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "invoke-webrequest",
    "net.webclient",
    "frombase64string",
    "encodedcommand",
    "new-localuser",
    "register-scheduledtask",
    "add-localgroupmember",
    "administrators",
    "namedpipe",
    "add-type",
    "-enc",
    "-nop",
    "-w hidden",
    "hidden",
)
OBFUSCATION_MARKERS = (
    "$env:comspec",
    "comspec",
    "[char]",
    "[char[]]",
    "-join''",
    "-join ''",
    "bxor",
    "rot13",
    "toint16",
    "encodedarray",
)
LONG_TEXT_LIMIT = 280
DEMO_REDACTION_ENV = "TRIAGE_DEMO_REDACTION"
DEMO_REDACTION_VALUES_ENV = "TRIAGE_DEMO_REDACTION_VALUES"
DEMO_REDACTION_PATTERNS = (
    (re.compile(r"(?i)\bcodexsandbox[a-z0-9_-]*\b"), "DemoUser"),
    (re.compile(r"(?i)openai\.codex_[^\\/\s'\"`]+"), "DemoApp"),
    (re.compile(r"(?i)\bcodex\.exe\b"), "demo-agent.exe"),
    (re.compile(r"(?i)\bcodex\b"), "DemoAgent"),
)


def sanitize_export_data(data: Any) -> Any:
    """Return a recursively sanitized copy suitable for JSON artifacts."""
    return _sanitize_value(data, key_path=(), event_id=_discover_event_id(data))


def sanitize_export_text(value: str, *, field_name: str = "", event_id: Any = None) -> str:
    text = str(value or "")
    if not text:
        return text

    field = (field_name or "").strip().lower()
    if field in SAFE_TEXT_FIELDS:
        return apply_demo_redaction_text(_clip(text))
    if field in SUMMARY_FIELDS:
        if _should_sanitize(text, field, event_id):
            return apply_demo_redaction_text(_sanitized_summary(text))
        return apply_demo_redaction_text(_clip(text))
    if _should_sanitize(text, field, event_id):
        return apply_demo_redaction_text(_sanitized_summary(text))
    return apply_demo_redaction_text(_clip(text))


def apply_demo_redaction_data(data: Any) -> Any:
    """Recursively redact demo-sensitive labels without altering structure."""
    if not _demo_redaction_enabled():
        return data
    return _apply_demo_redaction_value(data)


def apply_demo_redaction_text(value: str) -> str:
    text = str(value or "")
    if not text or not _demo_redaction_enabled():
        return text

    redacted = text
    for pattern, replacement in DEMO_REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    for token in _demo_redaction_values():
        redacted = re.sub(re.escape(token), "DemoValue", redacted, flags=re.IGNORECASE)
    return redacted


def _apply_demo_redaction_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _apply_demo_redaction_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_apply_demo_redaction_value(item) for item in value]
    if isinstance(value, str):
        return apply_demo_redaction_text(value)
    return value


def _sanitize_value(value: Any, *, key_path: tuple[str, ...], event_id: Any) -> Any:
    if isinstance(value, dict):
        next_event_id = _discover_event_id(value) or event_id
        return {
            key: _sanitize_value(
                item,
                key_path=key_path + (str(key),),
                event_id=next_event_id,
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_value(item, key_path=key_path, event_id=event_id) for item in value]
    if isinstance(value, str):
        field = key_path[-1] if key_path else ""
        return sanitize_export_text(value, field_name=field, event_id=event_id)
    return value


def _discover_event_id(value: Any) -> Any:
    if not isinstance(value, dict):
        return None
    for key in ("event_id", "EventID"):
        candidate = value.get(key)
        if candidate not in (None, ""):
            return candidate
    return None


def _should_sanitize(text: str, field_name: str, event_id: Any) -> bool:
    low = text.lower()
    if field_name in SCRIPT_FIELDS:
        return True

    looks_like_powershell = any(marker in low for marker in POWERSHELL_MARKERS)
    looks_like_obfuscated_script = any(marker in low for marker in OBFUSCATION_MARKERS) or low.count("[char]") >= 3
    looks_like_code = any(token in text for token in ("\n", "\r", "{", "}", "$", ";"))
    has_long_blob = bool(BASE64_RE.search(text))
    event_id_text = str(event_id or "").strip()

    if field_name in SUMMARY_FIELDS:
        if looks_like_powershell or looks_like_obfuscated_script:
            return True
        if "powershell script block" in low and len(text) > 120:
            return True

    if field_name in COMMAND_FIELDS:
        if event_id_text == "4104":
            return True
        if (looks_like_powershell or looks_like_obfuscated_script) and (len(text) > 140 or looks_like_code or has_long_blob):
            return True
        if has_long_blob and len(text) > 160:
            return True

    if field_name in {"details", "message", "value"}:
        if (looks_like_powershell or looks_like_obfuscated_script) and len(text) > 220:
            return True

    if len(text) > 700 and (looks_like_powershell or looks_like_obfuscated_script or has_long_blob):
        return True

    return False


def _sanitized_summary(text: str) -> str:
    low = text.lower()
    summary = "[sanitized export content omitted]"
    if any(marker in low for marker in OBFUSCATION_MARKERS) or low.count("[char]") >= 3:
        summary = "powershell [sanitized obfuscated script]"
    elif "powershell" in low or "pwsh" in low or any(marker in low for marker in POWERSHELL_MARKERS):
        if "encodedcommand" in low or "-enc" in low or BASE64_RE.search(text):
            summary = "powershell [sanitized encoded payload]"
        elif any(marker in low for marker in ("downloadstring", "downloadfile", "invoke-webrequest", "net.webclient")):
            summary = "powershell [sanitized remote payload fetch]"
        else:
            summary = "powershell [sanitized script content]"
    elif "cmd.exe" in low and "powershell" in low:
        summary = "cmd.exe -> powershell [sanitized payload]"

    indicators = []
    remote_url = _first_match(URL_RE, text)
    if remote_url:
        indicators.append(f"url={remote_url}")
    task_name = _first_match(TASK_NAME_RE, text)
    if task_name:
        indicators.append(f"task={task_name}")
    created_user = _first_match(NEW_LOCAL_USER_RE, text)
    if created_user:
        indicators.append(f"user={created_user}")

    if indicators:
        summary = f"{summary} ({'; '.join(indicators)})"
    return summary


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text or "")
    if not match:
        return ""
    try:
        return (match.group(1) or "").strip()
    except IndexError:
        return (match.group(0) or "").strip()


def _clip(text: str) -> str:
    compact = " ".join((text or "").split())
    if len(compact) <= LONG_TEXT_LIMIT:
        return compact
    return f"{compact[: LONG_TEXT_LIMIT - 3]}..."


def _demo_redaction_enabled() -> bool:
    return str(os.environ.get(DEMO_REDACTION_ENV, "") or "").strip().lower() in {"1", "true", "yes", "on"}


def _demo_redaction_values() -> list[str]:
    raw = str(os.environ.get(DEMO_REDACTION_VALUES_ENV, "") or "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]
