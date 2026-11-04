"""Case-based CLI for Corrobora.

This is a thin argument/console adapter.  All investigation logic lives
in ``corrobora.service``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import Any, List, Optional

# Allow running from source checkout without installation.
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from corrobora import __version__
from corrobora.case_utils import auto_case_name, resolve_case_path
from corrobora.service import (
    InvestigationRequest,
    InvestigationResult,
    ProgressReporter,
    _apply_parse_progress_update,
    _public_parse_progress,
    run_investigation,
    write_incident_brief as _write_incident_brief,
    write_summary_txt as _write_summary_txt,
)
from corrobora.product import export_case_bundle
from corrobora.tuning import load_tuning
from corrobora.tuning_bootstrap import build_local_tuning_profile, write_local_tuning_profile

DEFAULT_LIVE_CHANNELS = "Security,System"
ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"


# ---------------------------------------------------------------------------
# CLI-specific progress reporter — prints to console
# ---------------------------------------------------------------------------

class _ConsoleReporter:
    """Implements ProgressReporter for terminal output."""

    def __init__(self, use_color: bool = False) -> None:
        self.use_color = use_color

    def on_stage(self, stage: str, message: str) -> None:
        print(f"  {_format_stage(stage, use_color=self.use_color)} {message}")

    def on_metadata(self, key: str, value: Any) -> None:
        pass

    def on_artifact(self, path: str) -> None:
        pass

    def on_diagnostic(self, message: str) -> None:
        print(f"  {_colorize('[diag]', ANSI_YELLOW, use_color=self.use_color)} {message}")

    def on_complete(self, message: str) -> None:
        pass

    def on_failed(self, stage: str, error: str, traceback_text: Optional[str] = None) -> None:
        pass

    def on_parse_progress(self, update: dict) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_since(value: str) -> int:
    match = re.match(r"^(\d+)([mhd])$", (value or "").strip())
    if not match:
        raise ValueError(f"Invalid --since value '{value}'. Use 30m, 2h, or 1d")
    amount = int(match.group(1))
    unit = match.group(2)
    return amount * {"m": 1, "h": 60, "d": 1440}[unit]


def _sigma_rule_paths(args: argparse.Namespace) -> list[str]:
    paths = [os.path.abspath(path) for path in (args.sigma_rules or []) if path]
    default_dir = os.path.join(ROOT_DIR, "rules", "sigma")
    if not paths and os.path.isdir(default_dir):
        paths.append(default_dir)
    return paths


def _is_windows_host() -> bool:
    return os.name == "nt"


def _parse_channels(value: str) -> list[str]:
    return [c.strip() for c in (value or "").split(",") if c.strip()]


def _resolve_investigation_input(args: argparse.Namespace) -> tuple[str, str, list[str] | None, int | None, bool]:
    if args.evtx:
        return args.evtx, "evtx_path", None, None, False

    if args.live:
        channels = _parse_channels(args.channels)
        if not channels:
            raise SystemExit("Live mode requires at least one channel.")
        return "live", "live", channels, parse_since(args.since), False

    if getattr(args, "artifacts", None):
        return args.artifacts, "artifact_bundle", None, None, False

    if _is_windows_host():
        channels = _parse_channels(args.channels or DEFAULT_LIVE_CHANNELS)
        if not channels:
            channels = _parse_channels(DEFAULT_LIVE_CHANNELS)
        return "live", "live", channels, parse_since(args.since), True

    raise SystemExit(
        "No input source specified. Use --evtx PATH, --artifacts DIRECTORY, or run --live on a Windows machine."
    )


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _colorize(text: str, color: str, *, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{color}{text}{ANSI_RESET}"


def _format_stage(stage: str, *, use_color: bool) -> str:
    tag = f"[{stage}]"
    stage_lower = (stage or "").lower()
    if any(token in stage_lower for token in ("error", "fail")):
        return _colorize(tag, ANSI_RED, use_color=use_color)
    if any(token in stage_lower for token in ("warn", "diag")):
        return _colorize(tag, ANSI_YELLOW, use_color=use_color)
    if any(token in stage_lower for token in ("complete", "done", "success")):
        return _colorize(tag, ANSI_GREEN, use_color=use_color)
    return tag


def _truncate(value: str, width: int) -> str:
    text = str(value or "")
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _case_summary(case_path: str) -> dict:
    case_name = os.path.basename(case_path)
    findings_path = os.path.join(case_path, "findings.json")
    run_status_path = os.path.join(case_path, "run_status.json")

    row = {
        "case": case_name,
        "status": "unknown",
        "priority": "P4",
        "signals": 0,
        "findings": 0,
        "incidents": 0,
        "first_seen": "",
        "last_seen": "",
        "updated": datetime.fromtimestamp(os.path.getmtime(case_path)).strftime("%Y-%m-%d %H:%M"),
    }

    if os.path.isfile(run_status_path):
        try:
            with open(run_status_path, "r", encoding="utf-8") as handle:
                status_data = json.load(handle)
            row["status"] = str(status_data.get("status") or status_data.get("stage") or "unknown")
        except Exception:
            row["status"] = "status_error"

    if os.path.isfile(findings_path):
        try:
            with open(findings_path, "r", encoding="utf-8") as handle:
                findings_data = json.load(handle)
            case_data = findings_data.get("case", {}) or {}
            summary_data = findings_data.get("summary", {}) or {}
            row["priority"] = str(case_data.get("response_priority") or summary_data.get("response_priority") or "P4")
            row["signals"] = int(summary_data.get("signal_count", 0) or 0)
            row["findings"] = int(summary_data.get("finding_count", 0) or 0)
            row["incidents"] = int(summary_data.get("incident_count", 0) or 0)
            row["first_seen"] = str(case_data.get("first_seen") or "")
            row["last_seen"] = str(case_data.get("last_seen") or "")
        except Exception:
            row["status"] = "findings_error"

    return row


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_investigate(args: argparse.Namespace) -> int:
    input_source, input_mode, channels, since_minutes, auto_selected_live = _resolve_investigation_input(args)
    use_color = _supports_color() and not getattr(args, "no_color", False)

    start_date = datetime.strptime(args.start, "%Y-%m-%d").date() if args.start else None
    end_date = datetime.strptime(args.end, "%Y-%m-%d").date() if args.end else None

    request = InvestigationRequest(
        input_source=input_source,
        input_mode=input_mode,
        case_name=args.case,
        cases_dir=os.path.abspath(args.cases_dir),
        overwrite=args.overwrite,
        resume=args.resume,
        start_date=start_date,
        end_date=end_date,
        channels=channels,
        since_minutes=since_minutes,
        enable_sigma=args.enable_sigma,
        sigma_rule_paths=_sigma_rule_paths(args),
        tuning_paths=args.tuning or [],
        no_fp_filter=args.no_fp_filter,
        acquisition_method=getattr(args, "acquisition_method", "local_live" if input_mode == "live" else "upload"),
        collection_manifest=json.loads(args.collection_manifest) if getattr(args, "collection_manifest", "") else None,
        artifact_bundle=getattr(args, "artifacts", None),
        allow_large_ntfs=getattr(args, "allow_large_ntfs", False),
        collect_live_artifacts=input_mode == "live" and not getattr(args, "no_live_artifacts", False),
    )

    reporter = _ConsoleReporter(use_color=use_color)

    if auto_selected_live:
        print(
            f"  {_colorize('[auto]', ANSI_YELLOW, use_color=use_color)} No --evtx or --live specified. Running a live Windows scan for the last {since_minutes} minute(s) "
            f"across: {', '.join(channels or [])}"
        )

    try:
        result = run_investigation(request, reporter)
    except Exception as exc:
        print(_colorize(f"\n[ERROR] Investigation failed: {exc}", ANSI_RED, use_color=use_color))
        return 1

    print("\n" + "=" * 64)
    print(_colorize("Triage Investigation Complete", ANSI_GREEN, use_color=use_color))
    print("=" * 64)
    print(f"Case: {result.case_name}")
    print(f"Signals: {result.signal_count} | Findings: {result.finding_count} | Incidents: {result.incident_count}")
    if "observed_artifact_count" in result.collection_quality_summary:
        print(f"Forensic observations: {result.collection_quality_summary['observed_artifact_count']} (source meanings preserved)")
    if result.triage_disposition:
        print(f"Disposition: {result.triage_disposition.get('disposition', 'Unknown')} ({result.triage_disposition.get('confidence', 'unknown')} confidence)")
    print(f"Artifacts: {result.case_path}")
    for path in result.artifacts.values():
        print(f"- {os.path.basename(path)}")
    print("=" * 64 + "\n")
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    use_color = _supports_color() and not getattr(args, "no_color", False)
    case_path = resolve_case_path(os.path.abspath(args.cases_dir), args.case)
    findings_path = os.path.join(case_path, "findings.json")
    if not os.path.isfile(findings_path):
        print(_colorize(f"[ERROR] No findings.json found in {case_path}", ANSI_RED, use_color=use_color))
        return 1

    with open(findings_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    case = data.get("case", {})
    summary = data.get("summary", {})
    print("\n" + "=" * 64)
    print("Case Summary")
    print("=" * 64)
    print(f"Case Path: {case_path}")
    print(f"Case Name: {case.get('case_name', os.path.basename(case_path))}")
    print(f"Input Source: {case.get('input_source', '')}")
    print(f"Primary Host: {case.get('primary_host', '')}")
    print(f"Primary User: {case.get('primary_user', '')}")
    print(f"Primary Source IP: {case.get('primary_source_ip', '')}")
    print(f"Response Priority: {case.get('response_priority', 'P4')}")
    print(f"First Seen: {case.get('first_seen', '')}")
    print(f"Last Seen: {case.get('last_seen', '')}")
    print(f"Signal Count: {summary.get('signal_count', 0)}")
    print(f"Finding Count: {summary.get('finding_count', 0)}")
    print(f"Incident Count: {summary.get('incident_count', 0)}")
    telemetry = case.get("telemetry_summary", {}) or {}
    print(f"Telemetry Missing: {', '.join(telemetry.get('missing', [])) or 'None'}")
    suppression = case.get("suppression_summary", {}) or {}
    print(f"Suppressed Alerts: {suppression.get('suppressed_total', 0)}")
    print("=" * 64 + "\n")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    use_color = _supports_color() and not getattr(args, "no_color", False)
    case_path = resolve_case_path(os.path.abspath(args.cases_dir), args.case)
    case_name = os.path.basename(case_path)

    if not args.zip:
        print(f"Case path: {case_path}")
        print(_colorize("Use --zip to create a portable archive.", ANSI_YELLOW, use_color=use_color))
        return 0

    output_zip = args.output or os.path.join(os.path.dirname(case_path), f"{case_name}.zip")
    export_case_bundle(case_path, output_zip, include_sources=getattr(args, "include_sources", False))

    print(_colorize(f"Created archive: {output_zip}", ANSI_GREEN, use_color=use_color))
    return 0


def cmd_tuning_init(args: argparse.Namespace) -> int:
    use_color = _supports_color() and not getattr(args, "no_color", False)
    case_path = resolve_case_path(os.path.abspath(args.cases_dir), args.case)
    findings_path = os.path.join(case_path, "findings.json")
    if not os.path.isfile(findings_path):
        print(_colorize(f"[ERROR] No findings.json found in {case_path}", ANSI_RED, use_color=use_color))
        return 1

    with open(findings_path, "r", encoding="utf-8") as handle:
        case_data = json.load(handle)

    profile = build_local_tuning_profile(case_data, findings_path)
    try:
        output_path = write_local_tuning_profile(args.output, profile, force=args.force)
    except FileExistsError as exc:
        print(_colorize(str(exc), ANSI_YELLOW, use_color=use_color))
        print(_colorize("Use --force to overwrite the existing tuning file.", ANSI_YELLOW, use_color=use_color))
        return 1

    print("\n" + "=" * 64)
    print(_colorize("Local Tuning Profile Created", ANSI_GREEN, use_color=use_color))
    print("=" * 64)
    print(f"Source Case: {case_path}")
    print(f"Output: {output_path}")
    print("Next: review allowlists and suppressions before enabling them broadly.")
    print("=" * 64 + "\n")
    return 0


def cmd_list_cases(args: argparse.Namespace) -> int:
    use_color = _supports_color() and not getattr(args, "no_color", False)
    cases_dir = os.path.abspath(getattr(args, "cases_dir", os.path.join(ROOT_DIR, "cases")))
    if not os.path.isdir(cases_dir):
        print(_colorize(f"[warn] Cases directory does not exist: {cases_dir}", ANSI_YELLOW, use_color=use_color))
        return 0

    case_paths = [
        os.path.join(cases_dir, name)
        for name in os.listdir(cases_dir)
        if os.path.isdir(os.path.join(cases_dir, name))
    ]
    case_paths.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    if not case_paths:
        print(_colorize(f"[warn] No cases found in {cases_dir}", ANSI_YELLOW, use_color=use_color))
        return 0

    rows = [_case_summary(path) for path in case_paths]
    print("\n" + "=" * 110)
    print("Case Inventory")
    print("=" * 110)
    print(f"Cases root: {cases_dir}")
    print(f"Total cases: {len(rows)}")
    print("-" * 110)
    print(f"{'Case':<44} {'Status':<16} {'Priority':<8} {'S/F/I':<12} {'Updated':<16} {'Time Range'}")
    print("-" * 110)
    for row in rows:
        counts = f"{row['signals']}/{row['findings']}/{row['incidents']}"
        time_range = ""
        if row["first_seen"] or row["last_seen"]:
            time_range = f"{row['first_seen'] or '-'} -> {row['last_seen'] or '-'}"
        print(
            f"{_truncate(row['case'], 44):<44} "
            f"{_truncate(row['status'], 16):<16} "
            f"{_truncate(row['priority'], 8):<8} "
            f"{counts:<12} "
            f"{row['updated']:<16} "
            f"{_truncate(time_range, 48)}"
        )
    print("=" * 110 + "\n")
    return 0


def cmd_show_tuning(args: argparse.Namespace) -> int:
    use_color = _supports_color() and not getattr(args, "no_color", False)
    tuning_paths = getattr(args, "tuning", None) or []
    merged_config, diagnostics, loaded_paths = load_tuning(ROOT_DIR, tuning_paths)

    print("\n" + "=" * 64)
    print("Merged Tuning Configuration")
    print("=" * 64)
    print(json.dumps(merged_config, indent=2, sort_keys=True))

    if loaded_paths:
        print("\nLoaded files:")
        for path in loaded_paths:
            print(f"- {path}")
    else:
        print("\nLoaded files: none")

    if diagnostics:
        print(_colorize("\nDiagnostics:", ANSI_YELLOW, use_color=use_color))
        for line in diagnostics:
            print(_colorize(f"- {line}", ANSI_YELLOW, use_color=use_color))
    else:
        print(_colorize("\nDiagnostics: none", ANSI_GREEN, use_color=use_color))

    print("=" * 64 + "\n")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _expand_artifact_dirs(paths: list[str], suffix: str = "") -> list[str]:
    """Replace each folder with the regular files beneath it (sorted, links never followed)."""
    from pathlib import Path

    from corrobora.path_safety import is_link_or_reparse, reject_path_links
    expanded: list[str] = []
    for supplied in paths:
        folder = Path(supplied)
        if not folder.is_dir():
            expanded.append(supplied)
            continue
        reject_path_links(folder, "Artifact folder path cannot contain links or junctions")
        found = []
        for root, dirs, files in os.walk(folder, followlinks=False):
            dirs[:] = sorted(name for name in dirs if not is_link_or_reparse(Path(root) / name))
            for name in files:
                path = Path(root) / name
                if (not suffix or name.lower().endswith(suffix)) and not is_link_or_reparse(path) and path.is_file():
                    found.append(str(path))
        if not found:
            raise ValueError(f"Artifact folder contains no usable files: {folder.name}")
        expanded.extend(sorted(found))
    return expanded


def cmd_pack_artifacts(args) -> int:
    from corrobora.artifact_packager import pack_artifacts
    if len(args.registry_hive) != len(args.hive_type):
        print("Artifact packaging failed: give one --hive-type for each --registry-hive, in the same order", file=sys.stderr)
        return 1
    try:
        task_xml = _expand_artifact_dirs(args.task_xml)
        prefetch_source = _expand_artifact_dirs(args.prefetch_source, ".pf")
        manifest = pack_artifacts(args.output_dir, host=args.host, observed_at=args.observed_at,
                                  chromium_history=args.chromium_history, pecmd_jsonl=args.pecmd_jsonl,
                                  prefetch_source=prefetch_source, persistence_records=args.persistence_records,
                                  pecmd_version=args.pecmd_version, scheduled_task_xml=task_xml,
                                  registry_hives=list(zip(args.registry_hive, args.hive_type)),
                                  ntfs_mft=args.ntfs_mft, ntfs_usn_journal=args.ntfs_usn_journal,
                                  ntfs_volume=args.ntfs_volume, allow_large_ntfs=args.allow_large_ntfs)
    except (ValueError, OSError) as exc:
        print(f"Artifact packaging failed: {exc}", file=sys.stderr)
        return 1
    print(f"Artifact bundle: {manifest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Corrobora - Windows incident investigation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  corrobora investigate --evtx C:\\logs\\Security.evtx --case acme-ir\n"
            "  corrobora investigate --live --channels Security,System --since 2h\n"
            "  corrobora summarize --case acme-ir\n"
            "  corrobora export --case acme-ir --zip\n"
            "  triage --list-cases\n"
            "  triage --show-tuning --tuning C:\\triage\\local-overrides.json\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"triage {__version__}")
    parser.add_argument("--list-cases", action="store_true", help="List existing cases with summary and exit")
    parser.add_argument("--show-tuning", action="store_true", help="Print merged tuning configuration and exit")
    parser.add_argument("--cases-dir", default=os.path.join(ROOT_DIR, "cases"), help="Cases root directory for global flags")
    parser.add_argument("--tuning", action="append", default=[], help="Additional tuning JSON file(s) for global flags")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    sub = parser.add_subparsers(dest="command", required=False)

    inv = sub.add_parser("investigate", help="Run investigation and generate case artifacts")
    inp = inv.add_mutually_exclusive_group(required=False)
    inp.add_argument("--evtx", metavar="PATH", help="EVTX file or directory")
    inp.add_argument("--live", action="store_true", help="Read live Windows event channels")
    inv.add_argument("--artifacts", metavar="DIRECTORY", help="Verified offline forensic artifact bundle, alone or alongside event input")
    inv.add_argument("--allow-large-ntfs", action="store_true", help="Accept bundle $MFT/$J members above 64 MiB (up to 8 GiB each)")
    inv.add_argument("--channels", default=DEFAULT_LIVE_CHANNELS, help="Live channels (comma-separated)")
    inv.add_argument("--since", default="30m", help="Lookback for live mode (e.g., 30m, 2h, 1d)")
    inv.add_argument("--no-live-artifacts", action="store_true",
                     help="Live mode: skip copying Prefetch, scheduled tasks and registry hives (copied when elevated)")
    inv.add_argument("--start", help="Start date YYYY-MM-DD")
    inv.add_argument("--end", help="End date YYYY-MM-DD")
    inv.add_argument("--case", help="Case name (auto-generated when omitted)")
    inv.add_argument("--cases-dir", default=os.path.join(ROOT_DIR, "cases"), help="Cases root directory")
    inv.add_argument("--no-fp-filter", action="store_true", help="Disable false-positive filtering")
    inv.add_argument("--tuning", action="append", default=[], help="Additional tuning JSON file(s)")
    inv.add_argument("--enable-sigma", action="store_true", help="Enable optional Sigma rule evaluation")
    inv.add_argument("--sigma-rules", action="append", default=[], help="Sigma rule file or directory (repeatable)")
    inv.add_argument("--overwrite", action="store_true", help="Overwrite case directory when it exists")
    inv.add_argument("--resume", action="store_true", help="Resume existing/latest versioned case")
    inv.add_argument("--acquisition-method", choices=("upload", "local_live", "portable_collector", "remote_collection"), help="Evidence acquisition method")
    inv.add_argument("--collection-manifest", help="Collection manifest JSON object")
    inv.set_defaults(func=cmd_investigate)

    pack = sub.add_parser("pack-artifacts", help="Package explicitly supplied offline forensic copies with hashes")
    pack.add_argument("--output-dir", required=True, help="New bundle directory under an existing output parent")
    pack.add_argument("--host", required=True, help="Declared source host; not this workstation's identity")
    pack.add_argument("--observed-at", required=True, help="Source collection time with timezone, e.g. 2026-10-02T12:00:00Z")
    pack.add_argument("--chromium-history", action="append", default=[], help="Standalone offline Chromium History SQLite copy (repeatable)")
    pack.add_argument("--pecmd-jsonl", action="append", default=[], help="PECmd JSONL export (repeatable)")
    pack.add_argument("--pecmd-version", default="", help="Actual exporter version; required with --pecmd-jsonl")
    pack.add_argument("--prefetch-source", action="append", default=[], help="Original .pf evidence or a Prefetch folder (its .pf files), retained and parsed natively (repeatable)")
    pack.add_argument("--persistence-records", action="append", default=[], help="Existing schema 1.0/1.1 persistence record JSON (repeatable)")
    pack.add_argument("--task-xml", action="append", default=[], help="Raw Task Scheduler definition file, or a copied System32\\Tasks folder (every file beneath it) (repeatable)")
    pack.add_argument("--registry-hive", action="append", default=[], help="Offline registry hive copy: NTUSER.DAT, SOFTWARE, SYSTEM or Amcache.hve (repeatable)")
    pack.add_argument("--hive-type", action="append", default=[], choices=("ntuser", "software", "system", "amcache"),
                      help="Declared type of each --registry-hive, in the same order")
    pack.add_argument("--ntfs-mft", action="append", default=[], help="Offline copy of one volume's $MFT")
    pack.add_argument("--ntfs-usn-journal", action="append", default=[], help="Offline copy of the same volume's $UsnJrnl:$J")
    pack.add_argument("--ntfs-volume", default="", help="Drive letter the $MFT/$J came from, e.g. C:; otherwise recorded as an assumption")
    pack.add_argument("--allow-large-ntfs", action="store_true", help="Allow $MFT/$J copies above 64 MiB (up to 8 GiB each, streamed)")
    pack.set_defaults(func=cmd_pack_artifacts)

    sm = sub.add_parser("summarize", help="Summarize existing case artifacts")
    sm.add_argument("--case", required=True, help="Case folder name or prefix")
    sm.add_argument("--cases-dir", default=os.path.join(ROOT_DIR, "cases"), help="Cases root directory")
    sm.set_defaults(func=cmd_summarize)

    ex = sub.add_parser("export", help="Export case artifacts")
    ex.add_argument("--case", required=True, help="Case folder name or prefix")
    ex.add_argument("--cases-dir", default=os.path.join(ROOT_DIR, "cases"), help="Cases root directory")
    ex.add_argument("--zip", action="store_true", help="Create portable ZIP archive")
    ex.add_argument("--output", help="Output path for ZIP archive")
    ex.add_argument("--include-sources", action="store_true", help="Include retained original evidence and lossless records (unredacted; requires --zip)")
    ex.set_defaults(func=cmd_export)

    tune = sub.add_parser("tuning-init", help="Bootstrap a local tuning profile from a completed case")
    tune.add_argument("--case", required=True, help="Case folder name, prefix, or absolute case path")
    tune.add_argument("--cases-dir", default=os.path.join(ROOT_DIR, "cases"), help="Cases root directory")
    tune.add_argument(
        "--output",
        default=os.path.join(ROOT_DIR, "config", "tuning", "local.json"),
        help="Output path for the generated local tuning JSON",
    )
    tune.add_argument("--force", action="store_true", help="Overwrite the output tuning file when it exists")
    tune.set_defaults(func=cmd_tuning_init)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["investigate"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "list_cases", False):
        return cmd_list_cases(args)
    if getattr(args, "show_tuning", False):
        return cmd_show_tuning(args)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
