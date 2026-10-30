"""Local EVTX corpus scanner for triage-engine.

Walks one or more directories of `.evtx` files, applies a provenance
allowlist so we never run untrusted or unlicensed samples, and invokes the
real investigation pipeline on each sample to produce a deterministic
coverage worklist.

Why this exists
---------------
The engine advertises coverage over a curated public EVTX corpus, but
`repo_cache/` contains ~120 MB / 571 EVTX files across 5 provenance
sources that are not currently part of the regression harness.  This tool
lets us run the engine on every sample we trust and answer:

* which ATT&CK techniques are present in the corpus but never detected,
* which detectors succeed on a small handful of samples but never
  promote a finding, and
* which samples are missing required channels or fail to parse.

Output is a JSON + Markdown worklist with a stable `schema_version` so
follow-on tools (gap-driven detector tuning, re-run benchmarks) can
consume it.

Usage
-----
::

    python scripts/evtx_corpus_scan.py \
        --external-evtx-root repo_cache/sbousseaden_EVTX-ATTACK-SAMPLES \
        --external-evtx-root repo_cache/mdecrevoisier_EVTX-to-MITRE-Attack \
        --limit 25 --jobs 4 --output-json audit-artifacts/corpus-scan.json

Exit codes
----------
* 0 -- at least one sample ran and the worklist was written
* 2 -- every sample was skipped (no provenanced files found)
* 3 -- fatal configuration error
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sys
import time
import traceback
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "1.0"
SCANNER_NAME = "evtx-corpus-scan"

# Curated allowlist. Anything outside these tokens is treated as
# unprovenanced unless --allow-unprovenanced is set.
PROVENANCE_ALLOWLIST: Tuple[str, ...] = (
    "sbousseaden_evtx-attack-samples",
    "mdecrevoisier_evtx-to-mitre-attack",
    "sigma",
    "hayabusa",
    "elastic",
    "atomicredteam",
    "atomic-red-team",
    "evtx_att&ck_metadata",
    "evtx_attack_metadata",
    "security-datasets",
    "deepblue",
    "lichtsinnig",
    "otrf",
)

# A stable, conservative, public technique->path-token mapping. We use it as
# a path-side ATT&CK hint, not as evidence. Each token is matched
# case-insensitively against the normalised relative path.
PATH_TECHNIQUE_HINTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("T1003", ("t1003", "lsass", "mimikatz", "dcsync", "kerberoast")),
    ("T1003.001", ("lsass", "mimikatz")),
    ("T1003.002", ("dcsync", "lsadump", "secretsdump")),
    ("T1003.003", ("ntds", "ntdsutil", "vssadmin")),
    ("T1003.004", ("lsa_secrets", "lsa-secrets")),
    ("T1003.006", ("dcsync", "dcsync_4662")),
    ("T1016", ("network_config", "network-configuration", "ipconfig")),
    # Keep folder names such as ``Discovery`` advisory only; they are shared
    # by many unrelated techniques.  Prefer an explicit technique token or a
    # sample name that names the remote-system behavior.
    ("T1018", ("t1018", "remote_system", "remote-system")),
    ("T1021", ("lateral", "lateral_movement", "lateral-movement")),
    ("T1021.001", ("rdp", "remote_desktop", "remote-desktop")),
    ("T1021.002", ("smb", "admin_share", "admin-share")),
    ("T1021.003", ("dcom",)),
    ("T1021.004", ("t1021.004", "openssh", "remote_service_ssh", "remote-service-ssh")),
    ("T1021.006", ("winrm",)),
    ("T1027", ("obfuscated", "obfuscation", "encoded")),
    ("T1036", ("masquerade", "masquerading")),
    ("T1036.003", ("rundll32_rename",)),
    ("T1040", ("pktmon", "network_capture", "network-capture")),
    ("T1046", ("t1046", "network_scan", "network-scan", "network_service_scanning", "network-service-scanning")),
    ("T1047", ("wmi", "wmic")),
    ("T1053", ("scheduled_task", "scheduled-task", "schtasks")),
    ("T1053.005", ("schtasks", "scheduled_task")),
    ("T1055", ("process_injection", "process-injection")),
    ("T1059", ("execution", "command_line", "command-line", "shell")),
    ("T1059.001", ("powershell", "pwsh", "encoded_powershell")),
    ("T1059.003", ("cmd", "command_shell", "command-shell", "windows_command")),
    ("T1059.007", ("jscript", "javascript", "jse")),
    ("T1068", ("t1068", "exploit_for_privilege_escalation", "exploit-for-privilege-escalation")),
    ("T1069", ("permission_groups", "permission-groups", "account_discovery")),
    ("T1069.002", ("domain_group", "domain-group", "group_discovery")),
    ("T1070", ("indicator_removal", "indicator-removal", "log_clear", "log-clear")),
    ("T1070.001", ("log_clear", "log-clear", "eventlog_cleared", "audit_log_cleared", "cleared")),
    ("T1070.002", ("wevtutil", "log_cleared_wevtutil")),
    ("T1070.004", ("file_deletion", "file-deletion", "deleted", "sdelete")),
    ("T1078", ("t1078", "valid_accounts", "valid-accounts")),
    ("T1087", ("account_discovery", "account-discovery")),
    ("T1087.002", ("domain_account", "domain-account", "domain_user")),
    ("T1090", ("proxy", "connection_proxy")),
    ("T1098", ("account_manipulation", "account-manipulation", "dsrm", "password_change")),
    ("T1105", ("ingress_tool_transfer", "ingress-tool-transfer", "transfer")),
    ("T1110", ("brute_force", "brute-force", "password_spray")),
    ("T1110.001", ("password_spray", "password-spray")),
    ("T1110.003", ("password_spray", "kerbrute")),
    ("T1112", ("registry_mod", "registry-mod", "registry_modification")),
    ("T1127", ("t1127", "trusted_developer", "trusted-developer")),
    ("T1134", ("access_token", "access-token", "token_manipulation")),
    ("T1135", ("share_enumeration", "share-enumeration")),
    ("T1136", ("create_account", "create-account", "new_user")),
    ("T1136.001", ("create_account", "create-account", "new_user")),
    ("T1197", ("bits", "bitsadmin", "bits_jobs")),
    ("T1202", ("indirect_cmd", "indirect-command")),
    ("T1204", ("t1204", "user_execution", "user-execution")),
    ("T1207", ("rogue_dc", "rogue-dc", "dcshadow")),
    ("T1210", ("exploit_remote", "exploit-remote", "smb_exploit")),
    ("T1218", ("system_binary_proxy", "system-binary-proxy", "rundll32", "mshta", "certutil")),
    ("T1218.005", ("t1218.005", "mshta")),
    ("T1484", ("domain_policy", "group_policy", "gpo")),
    ("T1485", ("data_destruction", "data-destruction")),
    ("T1490", ("inhibit_recovery", "inhibit-recovery", "vss_delete", "shadow_copy", "shadowcopy")),
    ("T1505", ("server_software", "server-software-component", "iis")),
    ("T1505.001", ("iis", "web_shell", "web-shell", "sqlserver", "mssql")),
    ("T1543", ("create_service", "create-service", "service_install", "service-install")),
    ("T1543.003", ("service_install", "service-install", "7045")),
    ("T1546", ("event_triggered", "event-triggered", "winlogon")),
    ("T1546.015", ("winlogon_helper", "winlogon-helper")),
    ("T1547", ("boot_autostart", "boot-autostart", "registry_run", "run_key")),
    ("T1547.001", ("registry_run", "run-key", "hkcu_run")),
    ("T1547.004", ("winlogon_helper", "winlogon-helper")),
    ("T1550", ("use_alternate_auth", "alternate-auth")),
    ("T1550.003", ("pass_the_ticket", "pass-the-ticket", "ptt")),
    ("T1550.002", ("pass_the_hash", "pass-the-hash", "pth")),
    ("T1552", ("unsecured_credentials", "unsecured-credentials")),
    ("T1552.001", ("credentials_in_files", "credentials-in-files")),
    ("T1553", ("subvert_trust", "subvert-trust", "code_signing", "code-signing")),
    ("T1553.002", ("code_signing_bypass", "code-signing-bypass")),
    ("T1555", ("password_store", "password-store", "browser_credentials")),
    ("T1558", ("t1558", "steal_or_forge", "steal-or-forge")),
    ("T1558.001", ("golden_ticket", "golden-ticket")),
    ("T1558.003", ("kerberoast", "kerberoasting")),
    ("T1560", ("archive_collected", "archive-collected")),
    ("T1562", ("t1562", "impair_defenses", "impair-defenses")),
    ("T1562.001", ("disable_or_modify", "defender_disabled", "eventlog_crash", "crashed")),
    ("T1562.002", ("powershell_exec_policy", "exec_policy", "execpolicy")),
    ("T1562.004", ("firewall_disabled", "firewall-disabled")),
    ("T1564", ("hide_artifacts", "hide-artifacts")),
    ("T1564.001", ("hidden_files", "hidden-files", "hidden_file")),
    ("T1564.003", ("hidden_window", "hidden-window")),
    ("T1564.005", ("hidden_file", "alternate_data_stream", "ads")),
    ("T1569", ("system_services", "system-services")),
    ("T1570", ("lateral_tool_transfer", "lateral-tool-transfer")),
    ("T1571", ("non_std_port", "non-std-port")),
    ("T1573", ("encrypted_channel", "encrypted-channel")),
    ("T1574", ("hijack_exec", "hijack-execution")),
    ("T1574.002", ("dll_side_load", "dll-side-load", "dll_hijack")),
    ("T1574.005", ("service_dll", "service-dll")),
    ("T1574.006", ("dynamic_linker", "dynamic-linker")),
    ("T1574.007", ("path_interception", "path-interception")),
    ("T1574.008", ("services_path", "service-path")),
    ("T1574.010", ("services_registry", "services-registry")),
    ("T1588", ("obtain_capabilities", "obtain-capabilities")),
    ("T1588.002", ("tool_acquisition", "tool-acquisition")),
    ("T1589", ("gather_victim", "gather-victim")),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
ATTACK_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalise_technique(value: str) -> str:
    match = ATTACK_ID_RE.fullmatch(str(value or "").strip())
    return match.group(1).upper() if match else ""


def _relative_to_root(path: Path, roots: Sequence[Path]) -> str:
    abs_path = path.resolve()
    for root in roots:
        try:
            return abs_path.relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
    return abs_path.as_posix()


def _provenance_token(relative_path: str, absolute_path: str = "") -> str:
    """Return the first allowlist token found in either path string, or '' for unknown.

    The relative path is preferred so users passing deep subdirectories still
    get the right provenance token, but the absolute path is checked as a
    fallback so callers that only supply a leaf directory still benefit.
    """
    candidates = [relative_path, absolute_path]
    for candidate in candidates:
        if not candidate:
            continue
        lowered = candidate.lower()
        for token in PROVENANCE_ALLOWLIST:
            if token in lowered:
                return token
    return ""


def _infer_path_hints(relative_path: str) -> List[str]:
    lowered = relative_path.lower().replace("\\", "/").replace(" ", "_")
    hits: List[str] = []
    seen: set = set()
    for technique, tokens in PATH_TECHNIQUE_HINTS:
        if technique in seen:
            continue
        if any(token in lowered for token in tokens):
            hits.append(technique)
            seen.add(technique)
    return hits


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalise_techniques(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        norm = _normalise_technique(value)
        if norm and norm not in out:
            out.append(norm)
    return out


# ---------------------------------------------------------------------------
# Sample enumeration
# ---------------------------------------------------------------------------
@dataclass
class Sample:
    path: Path
    relative_path: str
    provenance: str
    size_bytes: int
    sha256: str
    path_hints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "provenance": self.provenance,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "path_hints": sorted(self.path_hints),
        }


def enumerate_samples(roots: Sequence[Path], *, limit: Optional[int] = None) -> List[Sample]:
    """Enumerate all *.evtx under *roots*, sorted by relative path for determinism."""
    samples: List[Sample] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.evtx")):
            if not path.is_file():
                continue
            relative = _relative_to_root(path, [root])
            provenance = _provenance_token(relative, str(path))
            samples.append(
                Sample(
                    path=path,
                    relative_path=relative,
                    provenance=provenance,
                    size_bytes=path.stat().st_size,
                    sha256=_sha256(path),
                    path_hints=_infer_path_hints(relative),
                )
            )
            if limit is not None and len(samples) >= limit:
                return samples
    return samples


# ---------------------------------------------------------------------------
# Per-sample engine run
# ---------------------------------------------------------------------------
@dataclass
class SampleResult:
    sample: Sample
    status: str  # "completed" | "parse_error" | "engine_error" | "timeout"
    technique_findings: List[str] = field(default_factory=list)
    technique_signals: List[str] = field(default_factory=list)
    finding_count: int = 0
    signal_count: int = 0
    incident_count: int = 0
    severity_counter: Counter = field(default_factory=Counter)
    parse_event_count: int = 0
    runtime_seconds: float = 0.0
    error: str = ""
    cases_root: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample": self.sample.to_dict(),
            "status": self.status,
            "technique_findings": sorted(set(self.technique_findings)),
            "technique_signals": sorted(set(self.technique_signals)),
            "finding_count": self.finding_count,
            "signal_count": self.signal_count,
            "incident_count": self.incident_count,
            "severity_counter": dict(self.severity_counter),
            "parse_event_count": self.parse_event_count,
            "runtime_seconds": round(self.runtime_seconds, 3),
            "error": self.error,
            "cases_root": self.cases_root,
        }


class _NullReporter:
    """No-op reporter that satisfies the ProgressReporter protocol."""

    def __init__(self):
        # The investigation service emits a compact analysis summary before
        # writing artifacts.  Keep it in memory so scans remain useful when
        # endpoint protection quarantines or blocks a findings.json read.
        self.metadata: Dict[str, Any] = {}

    def on_metadata(self, key: str, value: Any) -> None:
        self.metadata[str(key)] = value

    def __getattr__(self, name: str):
        return lambda *a, **k: None


def _safe_case_dir(parent: Path, sample: Sample) -> Path:
    """Build a deterministic, collision-free case directory for a sample.

    The sanitised relative path is human-readable but identical branches of a
    corpus (for example two samples whose paths share the same first 80
    characters) truncate to the same name.  Append a stable short hash shard
    from the sample so parallel workers never race on the same directory.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", sample.relative_path).strip("-")
    shard = sample.sha256[:8]
    safe = f"{safe[:70]}-{shard}" if safe else f"sample-{shard}"
    target = parent / safe
    target.mkdir(parents=True, exist_ok=True)
    return target


def _run_engine_for_sample(sample: Sample, *, cases_root: Path, timeout_seconds: int):
    """Execute the engine on a single sample.

    Returns (result_payload, status, error_message).  Engine-side exceptions
    are caught and reported as a status string instead of being raised.
    """
    from triage_engine.service import InvestigationRequest, run_investigation

    case_path = _safe_case_dir(cases_root, sample)
    request = InvestigationRequest(
        input_source=str(sample.path),
        input_mode="evtx_path",
        case_name=case_path.name,
        cases_dir=str(cases_root),
        request_id=f"corpus-scan:{sample.sha256[:12]}",
        requested_by=SCANNER_NAME,
        overwrite=True,
        resume=False,
    )

    started = time.perf_counter()
    reporter = _NullReporter()
    try:
        os.environ["TRIAGE_INVESTIGATION_TIMEOUT_SECONDS"] = str(max(60, int(timeout_seconds)))
        os.environ["TRIAGE_DETECTOR_TIMEOUT_SECONDS"] = str(min(60, max(15, timeout_seconds // 3)))
        run_investigation(request, reporter)
    except Exception as exc:  # noqa: BLE001
        runtime = round(time.perf_counter() - started, 3)
        message = f"{type(exc).__name__}: {exc}".strip()
        return (
            {
                "runtime_seconds": runtime,
                "case_path": str(case_path),
            },
            "engine_error",
            message,
        )

    runtime = round(time.perf_counter() - started, 3)
    findings_path = case_path / "findings.json"
    if not findings_path.is_file():
        return (
            {
                "runtime_seconds": runtime,
                "case_path": str(case_path),
            },
            "parse_error",
            "findings.json missing after run",
        )
    return (
        {
            "runtime_seconds": runtime,
            "case_path": str(findings_path),
            "analysis_summary": reporter.metadata.get("analysis_summary", {}),
        },
        "completed",
        "",
    )


def analyse_sample(sample: Sample, *, cases_root: Path, timeout_seconds: int = 300) -> SampleResult:
    payload, status, error = _run_engine_for_sample(sample, cases_root=cases_root, timeout_seconds=timeout_seconds)
    result = SampleResult(
        sample=sample,
        status=status,
        runtime_seconds=float(payload.get("runtime_seconds", 0.0)),
        cases_root=str(cases_root),
        error=error,
    )
    if status != "completed":
        return result

    findings_path = Path(payload["case_path"])
    try:
        with findings_path.open("r", encoding="utf-8") as handle:
            payload_json = json.load(handle)
    except Exception as exc:  # noqa: BLE001
        # Windows Defender and other endpoint controls can deny a read after
        # the engine successfully wrote an artifact containing malware-like
        # strings.  Prefer the service's compact in-memory summary in that
        # case; it preserves coverage accounting without weakening artifact
        # integrity checks for normal consumers.
        analysis_summary = payload.get("analysis_summary", {})
        if isinstance(analysis_summary, dict) and analysis_summary.get("schema_version") == "1.0":
            result.finding_count = int(analysis_summary.get("finding_count", 0) or 0)
            result.signal_count = int(analysis_summary.get("signal_count", 0) or 0)
            result.incident_count = int(analysis_summary.get("incident_count", 0) or 0)
            result.parse_event_count = int(analysis_summary.get("parsed_event_count", 0) or 0)
            result.severity_counter.update(
                {
                    str(key): int(value or 0)
                    for key, value in (analysis_summary.get("severity_counter", {}) or {}).items()
                    if str(key).strip()
                }
            )
            result.technique_signals.extend(
                _normalise_techniques(analysis_summary.get("signal_techniques", []) or [])
            )
            result.technique_findings.extend(
                _normalise_techniques(analysis_summary.get("finding_techniques", []) or [])
            )
            result.error = f"findings.json read blocked; used in-memory analysis summary ({type(exc).__name__})"
            return result
        result.status = "parse_error"
        result.error = f"findings.json read failed: {exc}"
        return result

    case_block = payload_json.get("case", {}) if isinstance(payload_json.get("case"), dict) else {}
    case_metrics = case_block.get("case_metrics", {}) if isinstance(case_block.get("case_metrics"), dict) else {}
    result.finding_count = int(case_metrics.get("finding_count", 0) or 0)
    result.signal_count = int(case_metrics.get("signal_count", 0) or 0)
    result.incident_count = int(case_metrics.get("incident_count", 0) or 0)
    quality = case_block.get("collection_quality_summary", {}) or {}
    if not isinstance(quality, dict):
        quality = {}
    result.parse_event_count = int(quality.get("parsed_event_count", 0) or 0)

    signals = payload_json.get("signals", []) if isinstance(payload_json.get("signals"), list) else []
    findings = payload_json.get("findings", []) if isinstance(payload_json.get("findings"), list) else []
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        severity = str(signal.get("severity", "")).strip().lower()
        if severity:
            result.severity_counter[severity] += 1
        for tech in _normalise_techniques([signal.get("mitre_technique", "")]):
            result.technique_signals.append(tech)

    finding_signal_ids = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "")).strip().lower()
        if severity:
            result.severity_counter[severity] += 1
        for tech in _normalise_techniques([finding.get("mitre_technique", "")]):
            result.technique_findings.append(tech)
        for sid in finding.get("signal_ids", []) or []:
            finding_signal_ids.add(str(sid))

    for signal in signals:
        if not isinstance(signal, dict):
            continue
        if str(signal.get("id", "")) in finding_signal_ids:
            for tech in _normalise_techniques([signal.get("mitre_technique", "")]):
                result.technique_findings.append(tech)

    if result.signal_count == 0 and result.parse_event_count == 0:
        # The engine ran but produced no parsed events.  Treat this as a parse
        # gap so it appears in the worklist even though the call did not raise.
        result.status = "parse_error"
        if not result.error:
            result.error = "no parsed events produced"

    return result


# ---------------------------------------------------------------------------
# Parent/child propagation
# ---------------------------------------------------------------------------
def _expand_with_parents(techniques):
    """Return a set that includes the parent technique for any sub-technique.

    A detection of T1003.001 implies coverage of T1003, so when we are
    deciding whether the corpus covers a parent technique we treat any
    sub-technique detection as evidence for the parent.
    """
    out = set(techniques)
    for technique in list(techniques):
        if "." in technique:
            out.add(technique.split(".")[0])
    return out


# ---------------------------------------------------------------------------
# Worklist aggregation + rendering
# ---------------------------------------------------------------------------
def build_worklist(
    samples: Sequence[Sample],
    results: Sequence[SampleResult],
    *,
    allow_unprovenanced: bool = False,
) -> Dict[str, Any]:
    """Aggregate per-technique worklist data from results."""
    technique_hints: Dict[str, set] = defaultdict(set)
    technique_detected: Dict[str, set] = defaultdict(set)
    technique_signals: Dict[str, set] = defaultdict(set)
    technique_findings: Dict[str, set] = defaultdict(set)
    technique_status: Dict[str, str] = {}
    sample_to_hints: Dict[str, set] = defaultdict(set)
    skipped_unprovenanced: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []
    completed_samples: List[Dict[str, Any]] = []

    for sample in samples:
        if not sample.provenance and not allow_unprovenanced:
            skipped_unprovenanced.append(sample.to_dict())
            continue
        for hint in sample.path_hints:
            technique_hints[hint].add(sample.sha256)
            sample_to_hints[sample.sha256].add(hint)

    for result in results:
        sample = result.sample
        if not sample.provenance and not allow_unprovenanced:
            continue
        if result.status != "completed":
            failed.append(result.to_dict())
            continue
        completed_samples.append(result.to_dict())
        for tech in result.technique_signals:
            technique_signals[tech].add(sample.sha256)
            technique_detected[tech].add(sample.sha256)
        for tech in result.technique_findings:
            technique_findings[tech].add(sample.sha256)
            technique_detected[tech].add(sample.sha256)
        if result.status == "completed":
            for hint in sample.path_hints:
                technique_status[hint] = "detected" if hint in technique_detected else "missed"

    # ATT&CK parent rule: a sub-technique detection counts as parent coverage.
    detected_with_parents: Dict[str, set] = {}
    for technique, samples_set in technique_detected.items():
        detected_with_parents[technique] = samples_set
        if "." in technique:
            parent = technique.split(".")[0]
            detected_with_parents.setdefault(parent, set()).update(samples_set)

    all_techniques = sorted(set(technique_hints) | set(detected_with_parents))
    worklist = []
    for technique in all_techniques:
        hint_count = len(technique_hints.get(technique, set()))
        signal_count = len(technique_signals.get(technique, set()))
        finding_count = len(technique_findings.get(technique, set()))
        detected = bool(detected_with_parents.get(technique))
        if hint_count == 0 and detected:
            status = "detected_no_hint"
        elif hint_count > 0 and detected:
            status = "covered"
        elif hint_count > 0 and not detected:
            status = "missed"
        else:
            status = "detected_unconfirmed_hint"
        worklist.append(
            {
                "technique": technique,
                "path_hint_samples": hint_count,
                "signal_samples": signal_count,
                "finding_samples": finding_count,
                "status": status,
            }
        )
    worklist.sort(
        key=lambda row: (
            0 if row["status"] == "missed" else 1 if row["status"] == "covered" else 2,
            -row["path_hint_samples"],
            row["technique"],
        )
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "scanner": SCANNER_NAME,
        "generated_at": _utc_now(),
        "summary": {
            "samples_total": len(samples),
            "samples_completed": len(completed_samples),
            "samples_failed": len(failed),
            "samples_skipped_unprovenanced": len(skipped_unprovenanced),
            "techniques_with_hints": len([t for t in all_techniques if technique_hints.get(t)]),
            "techniques_detected": len([t for t in all_techniques if detected_with_parents.get(t)]),
            "techniques_missed": len([t for t in all_techniques if technique_hints.get(t) and not detected_with_parents.get(t)]),
        },
        "worklist": worklist,
        "skipped_unprovenanced": skipped_unprovenanced,
        "failed_samples": failed,
    }



def render_markdown(worklist_payload, *, top: int = 25):
    lines = []
    summary = worklist_payload.get("summary", {}) or {}
    lines.append("# EVTX corpus coverage scan")
    lines.append("")
    lines.append(
        "- Samples total: **" + str(summary.get("samples_total", 0)) + "**  "
        "- Completed: **" + str(summary.get("samples_completed", 0)) + "**  "
        "- Failed: **" + str(summary.get("samples_failed", 0)) + "**  "
        "- Skipped (unprovenanced): **" + str(summary.get("samples_skipped_unprovenanced", 0)) + "**"
    )
    lines.append(
        "- Techniques with path hints: **" + str(summary.get("techniques_with_hints", 0)) + "**  "
        "- Techniques detected: **" + str(summary.get("techniques_detected", 0)) + "**  "
        "- Techniques missed: **" + str(summary.get("techniques_missed", 0)) + "**"
    )
    lines.append("")
    lines.append("## Top " + str(top) + " worklist rows")
    lines.append("")
    lines.append("| Technique | Status | Path hints | Signal samples | Finding samples |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for row in worklist_payload.get("worklist", [])[:top]:
        lines.append(
            "| " + row["technique"] + " | " + row["status"] + " | " + str(row["path_hint_samples"]) + " | "
            + str(row["signal_samples"]) + " | " + str(row["finding_samples"]) + " |"
        )
    lines.append("")
    failed = worklist_payload.get("failed_samples", []) or []
    if failed:
        lines.append("## Failed samples")
        lines.append("")
        for row in failed[:20]:
            sample = row.get("sample", {}) or {}
            rel = str(sample.get("relative_path", ""))
            lines.append("- " + rel + " -- " + str(row.get("status", "")) + " -- " + str(row.get("error", "")))
        lines.append("")
    return "\n".join(lines) + "\n"



# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog=SCANNER_NAME,
        description="Run the triage engine across a directory of EVTX samples and emit a coverage worklist.",
    )
    parser.add_argument(
        "--external-evtx-root",
        action="append",
        default=[],
        type=Path,
        help="Directory containing EVTX samples. Pass multiple times to scan more than one root.",
    )
    parser.add_argument(
        "--allow-unprovenanced",
        action="store_true",
        help="Process samples whose path does not match a curated provenance allowlist.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Process at most this many samples.")
    parser.add_argument("--jobs", type=int, default=1, help="Run samples in parallel (default: 1).")
    parser.add_argument("--timeout-seconds", type=int, default=300, help="Per-sample engine timeout.")
    parser.add_argument(
        "--cases-root",
        type=Path,
        default=Path("audit-cases-corpus-scan"),
        help="Where to write per-sample case directories.",
    )
    parser.add_argument("--output-json", type=Path, default=Path("audit-artifacts/corpus-scan.json"))
    parser.add_argument("--output-md", type=Path, default=Path("audit-artifacts/corpus-scan.md"))
    parser.add_argument(
        "--manifest-snapshot",
        action="store_true",
        help="Include full per-sample result payloads in the JSON output.",
    )
    return parser.parse_args(argv)


def _execute(args):
    if not args.external_evtx_root:
        print("error: at least one --external-evtx-root is required", file=sys.stderr)
        return 3

    samples = enumerate_samples(args.external_evtx_root, limit=args.limit)
    if not samples:
        print("error: no .evtx files found in any --external-evtx-root", file=sys.stderr)
        return 2

    cases_root = args.cases_root.resolve()
    cases_root.mkdir(parents=True, exist_ok=True)

    selected = []
    skipped_unprovenanced = 0
    for sample in samples:
        if not sample.provenance and not args.allow_unprovenanced:
            skipped_unprovenanced += 1
            continue
        selected.append(sample)

    if not selected:
        print("error: every sample was skipped because --allow-unprovenanced was not set", file=sys.stderr)
        return 2

    results = []
    jobs = max(1, int(args.jobs))
    if jobs == 1 or len(selected) == 1:
        for sample in selected:
            print("scanning " + sample.relative_path, file=sys.stderr)
            results.append(analyse_sample(sample, cases_root=cases_root, timeout_seconds=int(args.timeout_seconds)))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
            future_map = {
                executor.submit(
                    analyse_sample,
                    sample,
                    cases_root=cases_root,
                    timeout_seconds=int(args.timeout_seconds),
                ): sample
                for sample in selected
            }
            for future in concurrent.futures.as_completed(future_map):
                sample = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = SampleResult(
                        sample=sample,
                        status="engine_error",
                        error=type(exc).__name__ + ": " + str(exc),
                    )
                print("completed " + sample.relative_path + " -> " + result.status, file=sys.stderr)
                results.append(result)

    payload = build_worklist(samples, results, allow_unprovenanced=args.allow_unprovenanced)
    if args.manifest_snapshot:
        payload["samples"] = [
            next((r.to_dict() for r in results if r.sample.sha256 == sample.sha256), sample.to_dict())
            for sample in selected
        ]
    payload["skipped_unprovenanced_count"] = skipped_unprovenanced

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    with args.output_json.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    with args.output_md.open("w", encoding="utf-8") as handle:
        handle.write(render_markdown(payload))

    summary = payload["summary"]
    print(
        "wrote " + str(args.output_json) + " (" + str(summary["samples_total"]) + " samples, "
        + str(summary["techniques_missed"]) + " missed techniques)",
        file=sys.stderr,
    )
    print(
        json.dumps(
            {
                "samples_total": summary["samples_total"],
                "samples_completed": summary["samples_completed"],
                "samples_failed": summary["samples_failed"],
                "techniques_missed": summary["techniques_missed"],
            }
        )
    )
    return 0


def main(argv=None):
    args = _parse_args(argv)
    try:
        return _execute(args)
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:
        traceback.print_exc()
        print("fatal: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
