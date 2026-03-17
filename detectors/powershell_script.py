"""Content-aware PowerShell 4104 detections."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List
from urllib.parse import urlparse

from models.event_model import Alert, NormalizedEvent

URL_RE = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)
TASK_NAME_RE = re.compile(r"-TaskName\s+[\"']([^\"']+)[\"']", re.IGNORECASE)
TASK_USER_RE = re.compile(r"-User\s+[\"']([^\"']+)[\"']", re.IGNORECASE)
NEW_LOCAL_USER_RE = re.compile(r"New-LocalUser\b.*?-Name\s+['\"]([^'\"]+)['\"]", re.IGNORECASE | re.DOTALL)
ADD_GROUP_RE = re.compile(
    r"Add-LocalGroupMember\b.*?-Group\s+['\"]([^'\"]+)['\"].*?-Member\s+['\"]([^'\"]+)['\"]",
    re.IGNORECASE | re.DOTALL,
)
ROT13_ASSIGN_RE = re.compile(r"\$(\w+)\s*=\s*ROT13\s+([A-Za-z0-9_]+)\s+13", re.IGNORECASE)
BASE64_ASSIGN_RE = re.compile(r"\$(\w+)\s*=\s*['\"]([A-Za-z0-9+/=\s]{16,})['\"]", re.IGNORECASE)
DOWNLOAD_CRADLE_RE = re.compile(
    r"(iex\s*\(|invoke-expression|downloadstring|downloadfile|invoke-webrequest|net\.webclient)",
    re.IGNORECASE,
)
ENCODED_PAYLOAD_RE = re.compile(
    r"(frombase64string|encodedcommand|\s-enc(?:odedcommand)?\b|system\.convert\]::frombase64string|\[convert\]::frombase64string)",
    re.IGNORECASE,
)
DIRECT_FROM_BASE64STRING_RE = re.compile(r"frombase64string\s*\(\s*['\"]([A-Za-z0-9+/=\s]{16,})['\"]\s*\)", re.IGNORECASE)
FROM_BASE64STRING_VAR_RE = re.compile(r"frombase64string\s*\(\s*(\$\w+)\s*\)", re.IGNORECASE)
ENCODED_COMMAND_VALUE_RE = re.compile(r"(?:-|/)(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)
NAMED_PIPE_RE = re.compile(
    r"(namedpipe(client|server)stream|system\.io\.pipes|\\\\\.\\pipe\\|\\\\localhost\\pipe\\|\\\\127\.0\.0\.1\\pipe\\|\\\\[^\\]+\\pipe\\)",
    re.IGNORECASE,
)
BITS_RE = re.compile(r"(start-bitstransfer|add-bitsfile|set-bits|resume-bits)", re.IGNORECASE)
SCRIPTBLOCK_CREATE_RE = re.compile(r"\[scriptblock\]\s*::\s*create", re.IGNORECASE)
PROMPT_ARGS_RE = re.compile(
    r"PromptForCredential\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
SELECT_PASSWORD_FIELDS_RE = re.compile(
    r"select-?object\b.*\busername\b.*\bdomain\b.*\bpassword\b",
    re.IGNORECASE | re.DOTALL,
)

NOISY_USERS = {"", "-", "system", "localsystem", "local service", "network service"}


def detect(events: List[NormalizedEvent]) -> List[Alert]:
    script_blocks = _reconstruct_script_blocks(events)
    analyzed = [_analyze_script_block(block) for block in script_blocks]
    suspicious = [item for item in analyzed if item.get("alerts")]
    _backfill_context(suspicious, events)

    alerts: List[Alert] = []
    for item in suspicious:
        alerts.extend(item["alerts"])
    return alerts


def _reconstruct_script_blocks(events: List[NormalizedEvent]) -> List[Dict]:
    grouped: Dict[tuple, Dict] = {}
    generated_idx = 0

    for ev in events:
        if ev.event_id != 4104:
            continue
        script_text = ev.event_data.get("ScriptBlockText", "") or ""
        if not script_text.strip():
            continue

        block_id = ev.event_data.get("ScriptBlockId", "") or f"generated-{generated_idx}"
        generated_idx += 1
        key = (ev.computer or "unknown", block_id)
        group = grouped.setdefault(
            key,
            {
                "event": ev,
                "host": ev.computer or "unknown",
                "script_block_id": block_id,
                "parts": [],
                "timestamp": ev.timestamp,
            },
        )
        try:
            part_no = int(ev.event_data.get("MessageNumber", "1"))
        except ValueError:
            part_no = len(group["parts"]) + 1
        group["parts"].append((part_no, script_text, ev))
        if ev.timestamp and (group["timestamp"] is None or ev.timestamp < group["timestamp"]):
            group["timestamp"] = ev.timestamp
            group["event"] = ev

    blocks = []
    for group in grouped.values():
        ordered = sorted(group["parts"], key=lambda item: item[0])
        full_script = "\n".join(part[1] for part in ordered if part[1].strip())
        blocks.append(
            {
                "event": group["event"],
                "host": group["host"],
                "timestamp": group["timestamp"],
                "script_block_id": group["script_block_id"],
                "script_text": full_script,
            }
        )
    return blocks


def _analyze_script_block(block: Dict) -> Dict:
    text = block["script_text"]
    low = text.lower()
    event = block["event"]
    alerts: List[Alert] = []

    decoded_vars = _extract_rot13_assignments(text)
    created_user = _resolve_value(_first_match(NEW_LOCAL_USER_RE, text), decoded_vars)
    group_name, group_member = _extract_group_membership(text, decoded_vars)
    task_name = _first_match(TASK_NAME_RE, text)
    task_user = _short_user(_first_match(TASK_USER_RE, text))
    urls = URL_RE.findall(text)
    remote_url = urls[0] if urls else ""
    remote_host = _remote_host(remote_url)
    obfuscation_hits = _obfuscation_hits(text, decoded_vars)
    comments = _interesting_comments(text)
    task_is_backdoor = bool(task_name and re.search(r"backdoor|persist|createbackdoor", task_name, re.IGNORECASE))
    encoded_payload = bool(ENCODED_PAYLOAD_RE.search(text))
    encoded_payload_preview, decoded_payload_excerpt = _extract_decoded_base64_preview(text) if encoded_payload else ("", "")
    encoded_execution = bool(
        SCRIPTBLOCK_CREATE_RE.search(text)
        or any(token in low for token in ("invoke-expression", "iex", "downloadstring", "invoke-command", "start-process"))
    )
    named_pipe_shell = bool(NAMED_PIPE_RE.search(text)) and any(
        token in low for token in ("invoke-expression", "iex", "cmd.exe", "powershell", "readtoend", "writeline")
    )
    bits_job = bool(BITS_RE.search(text))
    prompt_title, prompt_message = _extract_prompt_args(text)
    credential_prompt_harvest = _is_credential_prompt_harvest(low, text)

    if _is_download_cradle(low, remote_url):
        alerts.append(
            Alert(
                rule_name="PowerShell Download Cradle",
                severity="critical",
                mitre_tactic="Execution",
                mitre_technique="T1059.001",
                description=f"PowerShell fetched a remote payload on {block['host']}: {remote_url or 'unknown URL'}",
                explanation="A PowerShell download cradle fetched remote code or content for in-memory execution.",
                confidence="high",
                investigate_next="Retrieve the remote payload, review the full script block, and validate all follow-on PowerShell activity on the host.",
                event=event,
                process="powershell.exe",
                source_ip=remote_host,
                evidence={
                    "script_block_id": block["script_block_id"],
                    "remote_url": remote_url,
                    "remote_ip": remote_host,
                    "script_summary": "Remote payload fetch via PowerShell download cradle",
                    "script_excerpt": _summarize_script(text, 220),
                    "download_cradle": True,
                    "urls": urls[:3],
                    "evidence_strength": "high",
                },
            )
        )

    if encoded_payload and encoded_execution:
        alerts.append(
            Alert(
                rule_name="PowerShell Encoded Payload",
                severity="high",
                mitre_tactic="Execution",
                mitre_technique="T1059.001",
                description=f"PowerShell decoded and executed base64 content on {block['host']}",
                explanation="The script block decodes base64 content and combines it with execution behavior, which is common in obfuscated payload delivery.",
                confidence="high",
                investigate_next="Decode the payload, recover the executed script body, and review all related PowerShell and child-process activity.",
                event=event,
                process="powershell.exe",
                evidence={
                    "script_block_id": block["script_block_id"],
                    "script_summary": "PowerShell decoded and executed an encoded payload",
                    "script_excerpt": _summarize_script(text, 240),
                    "obfuscation_hits": obfuscation_hits,
                    "remote_url": remote_url,
                    "remote_ip": remote_host,
                    "encoded_payload": True,
                    "encoded_payload_preview": encoded_payload_preview,
                    "decoded_payload_excerpt": decoded_payload_excerpt,
                    "decoded_payload_present": bool(decoded_payload_excerpt),
                    "scriptblock_create": bool(SCRIPTBLOCK_CREATE_RE.search(text)),
                    "download_cradle": _is_download_cradle(low, remote_url),
                    "evidence_strength": "high",
                },
            )
        )

    if credential_prompt_harvest:
        alerts.append(
            Alert(
                rule_name="PowerShell Credential Prompt Harvesting",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1056",
                description=f"PowerShell credential prompt harvesting on {block['host']}",
                explanation=(
                    "The script block prompts the user for credentials, extracts the plaintext password from "
                    "GetNetworkCredential(), validates or loops on the submission, and exposes the captured values."
                ),
                confidence="high",
                investigate_next=(
                    "Treat the captured credentials as exposed, identify how the script was delivered, and review "
                    "follow-on authentication or privilege use from the same host and user."
                ),
                event=event,
                process="powershell.exe",
                evidence={
                    "script_block_id": block["script_block_id"],
                    "script_summary": "PowerShell prompted for Windows credentials and harvested plaintext password input",
                    "script_excerpt": _summarize_script(text, 280),
                    "prompt_title": prompt_title,
                    "prompt_message": prompt_message,
                    "credential_prompt": True,
                    "password_extraction": "getnetworkcredential().password" in low,
                    "credential_validation_loop": "validatecredentials" in low,
                    "credential_output": bool(SELECT_PASSWORD_FIELDS_RE.search(text)),
                    "evidence_strength": "high",
                },
            )
        )

    if named_pipe_shell:
        alerts.append(
            Alert(
                rule_name="PowerShell Named Pipe Shell",
                severity="critical",
                mitre_tactic="Execution",
                mitre_technique="T1059.001",
                description=f"PowerShell named-pipe shell behavior on {block['host']}",
                explanation="The script block uses named pipes alongside command execution patterns, which is consistent with interactive pipe shells and covert remote control.",
                confidence="high",
                investigate_next="Identify the pipe names involved, recover both ends of the shell if possible, and inspect related SMB or WinRM activity on the host.",
                event=event,
                process="powershell.exe",
                evidence={
                    "script_block_id": block["script_block_id"],
                    "script_summary": "PowerShell used named pipes for interactive shell behavior",
                    "script_excerpt": _summarize_script(text, 260),
                    "named_pipe_shell": True,
                    "obfuscation_hits": obfuscation_hits,
                    "remote_url": remote_url,
                    "remote_ip": remote_host,
                    "evidence_strength": "high",
                },
            )
        )

    if bits_job and remote_url:
        alerts.append(
            Alert(
                rule_name="PowerShell BITS Download",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1197",
                description=f"PowerShell started a BITS-based download on {block['host']}: {remote_url}",
                explanation="BITS jobs are commonly abused to fetch payloads or stage persistence with less obvious network activity.",
                confidence="medium",
                investigate_next="Review the BITS job details, recover the downloaded file, and confirm whether the transfer matches approved administration.",
                event=event,
                process="powershell.exe",
                source_ip=remote_host,
                evidence={
                    "script_block_id": block["script_block_id"],
                    "script_summary": "PowerShell initiated a BITS transfer for remote content",
                    "script_excerpt": _summarize_script(text, 240),
                    "remote_url": remote_url,
                    "remote_ip": remote_host,
                    "bits_job": True,
                    "evidence_strength": "medium",
                },
            )
        )

    persistence_markers = [
        "register-scheduledtask" in low,
        "new-localuser" in low,
        "add-localgroupmember" in low and "administrators" in low,
    ]
    if sum(1 for marker in persistence_markers if marker) >= 2:
        summary_bits = []
        if task_name:
            summary_bits.append(f"task {task_name}")
        if created_user:
            summary_bits.append(f"user {created_user}")
        if group_name and group_member:
            summary_bits.append(f"group membership {group_member} -> {group_name}")
        if not summary_bits:
            summary_bits.append("backdoor account and persistence behavior")

        alerts.append(
            Alert(
                rule_name="PowerShell Backdoor Provisioning",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1053.005",
                description=f"PowerShell backdoor provisioning on {block['host']}: {', '.join(summary_bits)}",
                explanation="The script block creates persistence and provisions a local backdoor account with administrative privileges.",
                confidence="high",
                investigate_next="Disable the scheduled task, remove the backdoor account, review all local admin changes, and preserve the full script for triage.",
                event=event,
                process="powershell.exe",
                user=task_user,
                source_ip=remote_host,
                evidence={
                    "script_block_id": block["script_block_id"],
                    "script_summary": "PowerShell created scheduled task persistence and provisioned a privileged local backdoor user",
                    "script_excerpt": _summarize_script(text, 320),
                    "task_name": task_name,
                    "task_user": task_user,
                    "created_username": created_user,
                    "group_name": group_name,
                    "group_member": group_member,
                    "remote_url": remote_url,
                    "remote_ip": remote_host,
                    "obfuscation_hits": obfuscation_hits,
                    "comments": comments,
                    "task_backdoor_hint": task_is_backdoor,
                    "download_cradle": _is_download_cradle(low, remote_url),
                    "register_scheduled_task": "register-scheduledtask" in low,
                    "new_local_user": "new-localuser" in low,
                    "admin_group_add": "add-localgroupmember" in low and "administrators" in low,
                    "evidence_strength": "high",
                },
            )
        )

    if _is_lsass_wer_dump(low):
        alerts.append(
            Alert(
                rule_name="PowerShell WER LSASS Dump",
                severity="critical",
                mitre_tactic="Credential Access",
                mitre_technique="T1003.001",
                description=f"PowerShell invoked WindowsErrorReporting MiniDumpWriteDump against lsass.exe on {block['host']}",
                explanation=(
                    "The script block reconstructs a MiniDumpWriteDump call through System.Management.Automation.WindowsErrorReporting while explicitly targeting Get-Process lsass. This is strong credential-dumping behavior."
                ),
                confidence="high",
                investigate_next="Preserve the script block and any generated dump file, review all follow-on credential use, and treat the host as a credential exposure event.",
                event=event,
                process="powershell.exe",
                evidence={
                    "script_block_id": block["script_block_id"],
                    "script_path": event.event_data.get("Path", ""),
                    "script_summary": "PowerShell used Windows Error Reporting internals to dump lsass.exe",
                    "script_excerpt": _summarize_script(text, 280),
                    "targets_lsass": True,
                    "minidump_method": "MiniDumpWriteDump",
                    "evidence_strength": "high",
                },
            )
        )

    if not alerts and obfuscation_hits:
        strong_obfuscation = {"numeric_char_encoding", "xor_obfuscation", "env_index_reconstruction", "securestring_reconstruction"}
        is_strong = len(set(obfuscation_hits) & strong_obfuscation) >= 1 and len(obfuscation_hits) >= 2
        alerts.append(
            Alert(
                rule_name="PowerShell Obfuscated Script",
                severity="high" if is_strong else "medium",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1027",
                description=f"Obfuscated PowerShell content on {block['host']}",
                explanation="The script reconstructs hidden names or uses decode helpers that can conceal malicious intent.",
                confidence="high" if is_strong else "medium",
                investigate_next="Review the decoded strings and determine whether the script resolves to persistence, credential abuse, or remote execution behavior.",
                event=event,
                process="powershell.exe",
                evidence={
                    "script_block_id": block["script_block_id"],
                    "script_summary": "PowerShell obfuscation and hidden-name reconstruction",
                    "script_excerpt": _summarize_script(text, 220),
                    "obfuscation_hits": obfuscation_hits,
                    "decoded_variables": decoded_vars,
                    "evidence_strength": "medium",
                },
            )
        )

    return {
        "host": block["host"],
        "timestamp": block["timestamp"],
        "remote_ip": remote_host,
        "task_user": task_user,
        "alerts": alerts,
    }


def _backfill_context(analyzed: List[Dict], events: List[NormalizedEvent]) -> None:
    for item in analyzed:
        host = item["host"]
        ts = item["timestamp"]
        if not ts:
            continue

        cluster_user = item["task_user"] or _user_from_nearby_blocks(analyzed, host, ts)
        inferred_user = cluster_user or _infer_user_from_security_context(events, host, ts)
        cluster_ip = item["remote_ip"] or _ip_from_nearby_blocks(analyzed, host, ts)

        for alert in item["alerts"]:
            if inferred_user and not alert.user:
                alert.user = inferred_user
                alert.evidence["actor_user"] = inferred_user
            if cluster_ip and not alert.source_ip:
                alert.source_ip = cluster_ip
                alert.evidence["remote_ip"] = cluster_ip
            if inferred_user:
                alert.evidence.setdefault("actor_user", inferred_user)


def _user_from_nearby_blocks(analyzed: List[Dict], host: str, ts) -> str:
    for other in analyzed:
        if other["host"] != host or other["timestamp"] is None:
            continue
        if abs((other["timestamp"] - ts).total_seconds()) > 120:
            continue
        if other.get("task_user"):
            return other["task_user"]
        for alert in other.get("alerts", []):
            if alert.user:
                return alert.user
    return ""


def _ip_from_nearby_blocks(analyzed: List[Dict], host: str, ts) -> str:
    for other in analyzed:
        if other["host"] != host or other["timestamp"] is None:
            continue
        if abs((other["timestamp"] - ts).total_seconds()) > 120:
            continue
        if other.get("remote_ip"):
            return other["remote_ip"]
    return ""


def _infer_user_from_security_context(events: List[NormalizedEvent], host: str, ts) -> str:
    candidates = []
    for ev in events:
        if ev.computer != host or not ev.timestamp:
            continue
        delta = abs((ev.timestamp - ts).total_seconds())
        if delta > 600:
            continue
        candidate = ""
        score = 0
        if ev.event_id == 4648:
            candidate = _short_user(ev.target_domain_user or ev.target_user)
            score = 5
        elif ev.event_id == 4624 and ev.logon_type in ("2", "3", "10"):
            candidate = _short_user(ev.target_domain_user or ev.target_user)
            score = 4
        elif ev.event_id == 4672:
            candidate = _short_user(ev.subject_domain_user or ev.subject_user)
            score = 4
        if not candidate or candidate.lower() in NOISY_USERS or candidate.endswith("$"):
            continue
        candidates.append((score, -delta, candidate))
    if not candidates:
        return ""
    return sorted(candidates, reverse=True)[0][2]


def _extract_rot13_assignments(text: str) -> Dict[str, str]:
    values = {}
    for var_name, encoded in ROT13_ASSIGN_RE.findall(text):
        try:
            decoded = codecs.decode(encoded, "rot_13")
        except Exception:
            decoded = ""
        if decoded:
            values[f"${var_name.lower()}"] = decoded
    return values


def _extract_base64_assignments(text: str) -> Dict[str, str]:
    values = {}
    for var_name, candidate in BASE64_ASSIGN_RE.findall(text):
        normalized = _normalize_base64_candidate(candidate)
        if _decode_base64_candidate(normalized):
            values[f"${var_name.lower()}"] = normalized
    return values


def _extract_decoded_base64_preview(text: str) -> tuple[str, str]:
    assignments = _extract_base64_assignments(text)
    candidates: List[str] = []
    candidates.extend(_normalize_base64_candidate(candidate) for candidate in DIRECT_FROM_BASE64STRING_RE.findall(text))
    for variable_name in FROM_BASE64STRING_VAR_RE.findall(text):
        resolved = assignments.get(variable_name.lower(), "")
        if resolved:
            candidates.append(resolved)
    candidates.extend(_normalize_base64_candidate(candidate) for candidate in ENCODED_COMMAND_VALUE_RE.findall(text))
    candidates.extend(assignments.values())

    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        decoded = _decode_base64_candidate(candidate)
        if decoded:
            return _preview_base64(candidate), _summarize_script(decoded, 220)
    return "", ""


def _extract_group_membership(text: str, decoded_vars: Dict[str, str]) -> tuple[str, str]:
    match = ADD_GROUP_RE.search(text)
    if not match:
        return "", ""
    return _resolve_value(match.group(1), decoded_vars), _resolve_value(match.group(2), decoded_vars)


def _resolve_value(value: str, decoded_vars: Dict[str, str]) -> str:
    clean = (value or "").strip()
    if not clean:
        return ""
    if clean.startswith("$"):
        return decoded_vars.get(clean.lower(), clean.lstrip("$"))
    return clean


def _obfuscation_hits(text: str, decoded_vars: Dict[str, str]) -> List[str]:
    low = text.lower()
    hits = []
    if "function rot13" in low:
        hits.append("rot13_helper")
    if decoded_vars:
        hits.append("hidden_name_reconstruction")
    if "[char]" in low and "substring" in low:
        hits.append("char_reconstruction")
    if "[char[]" in low or "::toint16" in low:
        hits.append("numeric_char_encoding")
    if "-bxor" in low:
        hits.append("xor_obfuscation")
    if "::securestringtobstr" in low:
        hits.append("securestring_reconstruction")
    if "-join''" in low or "-join '')" in low or "::join(''" in low:
        hits.append("join_reconstruction")
    if "$env:" in low and "[" in low and "]" in low and "-join" in low:
        hits.append("env_index_reconstruction")
    return sorted(set(hits))


def _interesting_comments(text: str) -> List[str]:
    comments = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(("#flag", "#note", "#comment")) or "backdoor" in stripped.lower():
            comments.append(stripped[:120])
    return comments[:5]


def _extract_prompt_args(text: str) -> tuple[str, str]:
    match = PROMPT_ARGS_RE.search(text)
    if not match:
        return "", ""
    return match.group(1).strip(), match.group(2).strip()


def _is_credential_prompt_harvest(low: str, text: str) -> bool:
    has_prompt = "promptforcredential" in low
    has_password_extraction = "getnetworkcredential().password" in low
    has_validation_or_output = "validatecredentials" in low or bool(SELECT_PASSWORD_FIELDS_RE.search(text))
    return has_prompt and has_password_extraction and has_validation_or_output


def _is_download_cradle(low: str, remote_url: str) -> bool:
    if not remote_url:
        return False
    remote_url_l = remote_url.lower().strip()
    if remote_url_l.startswith("http://go.microsoft.com/fwlink") or remote_url_l.startswith("https://go.microsoft.com/fwlink"):
        return False
    return bool(DOWNLOAD_CRADLE_RE.search(low))


def _is_lsass_wer_dump(low: str) -> bool:
    markers = ("get-process lsa" + "ss", "mini" + "dumpwritedump", "windowserrorreporting")
    return all(marker in low for marker in markers)


def _remote_host(url: str) -> str:
    if not url:
        return ""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _normalize_base64_candidate(candidate: str) -> str:
    return re.sub(r"\s+", "", str(candidate or "").strip())


def _preview_base64(candidate: str, limit: int = 96) -> str:
    normalized = _normalize_base64_candidate(candidate)
    if len(normalized) <= limit:
        return normalized
    return normalized[:limit] + "..."


def _decode_base64_candidate(candidate: str) -> str:
    normalized = _normalize_base64_candidate(candidate)
    if len(normalized) < 16:
        return ""
    padded = normalized + ("=" * (-len(normalized) % 4))
    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return ""
    if not decoded_bytes:
        return ""

    for encoding in ("utf-16-le", "utf-8", "utf-16-be", "latin-1"):
        try:
            decoded = decoded_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _looks_like_decoded_payload(decoded):
            return decoded.strip()
    return ""


def _looks_like_decoded_payload(text: str) -> bool:
    candidate = (text or "").replace("\x00", "").strip()
    if len(candidate) < 4:
        return False
    printable = sum(1 for ch in candidate if ch.isprintable() or ch in "\r\n\t")
    if printable / max(len(candidate), 1) < 0.85:
        return False

    low = candidate.lower()
    markers = (
        "powershell",
        "iex",
        "invoke-",
        "new-object",
        "download",
        "http",
        "net.webclient",
        "cmd.exe",
        "start-process",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
        "function ",
    )
    if any(marker in low for marker in markers):
        return True
    return bool(re.search(r"\b[a-z]{4,}\b", low)) and any(ch in candidate for ch in " ()[]$-;")


def _first_match(pattern, text: str) -> str:
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def _summarize_script(text: str, limit: int) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed if len(collapsed) <= limit else f"{collapsed[: limit - 3]}..."


def _short_user(value: str) -> str:
    user = (value or "").strip()
    if not user:
        return ""
    return user.split("\\")[-1]
