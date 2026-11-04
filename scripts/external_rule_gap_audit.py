"""Audit local external Windows detection-rule metadata without dependencies."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "1.0"
ATTACK_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
RULE_EXTENSIONS = {".yml", ".yaml", ".toml", ".txt", ".rule", ".conf", ".json"}
WINDOWS_TERMS = (
    "windows",
    "winlog",
    "sysmon",
    "eventid",
    "eventcode",
    "event_id",
    "event.code",
    "microsoft-windows",
    "powershell",
    "security",
    "application",
    "system",
)
TITLE_RE = re.compile(r"(?im)^\s*(?:title|name|rule_name)\s*[:=]\s*[\"']?([^\n\"'#]+)")
HINT_RE = re.compile(
    r"(?im)^\s*(?:product|service|channel|provider|category|log_name|os_list)\s*[:=]\s*(.+?)\s*$"
)
EVENT_KEY_RE = re.compile(r"(?i)(?:\beventid\b|\beventcode\b|\bevent_id\b|\bevent\.code\b)")
NUMBER_RE = re.compile(r"(?<!\d)(\d{1,5})(?!\d)")
MAX_SCAN_WORKERS = 16


def normalize_technique(value: str) -> str:
    match = ATTACK_ID_RE.fullmatch(str(value or "").strip())
    return match.group(1).upper() if match else ""


def technique_ids(value: str) -> list[str]:
    return sorted({match.group(1).upper() for match in ATTACK_ID_RE.finditer(value or "")})


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _title(text: str, path: Path) -> str:
    match = TITLE_RE.search(text)
    return (match.group(1).strip().strip("'\"") if match else "") or path.stem


def _hint_values(text: str) -> list[str]:
    hints: set[str] = set()
    for match in HINT_RE.finditer(text):
        key = match.group(0).split(":", 1)[0].split("=", 1)[0].strip().lower()
        value = match.group(1).strip().strip("[]{}\"'")
        if value:
            hints.add("{}={}".format(key, value))
    return sorted(hints)


def _event_ids(text: str) -> list[int]:
    """Extract numbers only from EventID/EventCode-oriented local blocks."""

    result: set[int] = set()
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not EVENT_KEY_RE.search(line):
            continue
        for raw in NUMBER_RE.findall(line):
            if 1 <= int(raw) <= 65535:
                result.add(int(raw))
        indentation = len(line) - len(line.lstrip())
        for child in lines[index + 1 : index + 13]:
            if not child.strip():
                continue
            child_indentation = len(child) - len(child.lstrip())
            stripped = child.lstrip()
            if child_indentation <= indentation:
                break
            if not stripped.startswith("-"):
                break
            for raw in NUMBER_RE.findall(stripped):
                if 1 <= int(raw) <= 65535:
                    result.add(int(raw))
    return sorted(result)


def _windows_relevant(text: str, path: Path) -> bool:
    material = "{}\n{}".format(path.name, text).lower()
    return any(term in material for term in WINDOWS_TERMS)


def _iter_rule_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
    elif path.is_dir():
        yield from (
            candidate
            for candidate in sorted(path.rglob("*"))
            if candidate.is_file() and candidate.suffix.lower() in RULE_EXTENSIONS
        )


def parse_source_spec(value: str, root: Path) -> tuple[str, Path]:
    """Parse a repeatable label=path input without evaluating shell text."""

    label, separator, raw_path = value.partition("=")
    if not separator or not label.strip() or not raw_path.strip():
        raise ValueError("source must use label=path")
    path = Path(raw_path.strip())
    return label.strip(), path.resolve() if path.is_absolute() else (root / path).resolve()


def _scan_rule_file(label: str, rule_path: Path, root: Path) -> dict[str, Any] | None:
    try:
        text = _read_text(rule_path)
    except OSError:
        return None
    techniques = technique_ids(text)
    if not techniques or not _windows_relevant(text, rule_path):
        return None
    return {
        "repository": label,
        "source_file": _relative(rule_path, root),
        "title": _title(text, rule_path),
        "techniques": techniques,
        "event_ids": _event_ids(text),
        "logsource_hints": _hint_values(text),
    }


def scan_sources(
    sources: Iterable[tuple[str, Path]], root: Path, required: bool = False
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Inventory local mirrors and extract metadata-only Windows references."""

    inventories: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for label, source_path in sorted(sources, key=lambda item: (item[0].lower(), str(item[1]))):
        exists = source_path.exists()
        inventory: dict[str, Any] = {
            "repository": label,
            "path": _relative(source_path, root),
            "required": required,
            "exists": exists,
            "files_scanned": 0,
            "windows_rule_files": 0,
            "references": 0,
        }
        if exists:
            rule_paths = list(_iter_rule_files(source_path))
            inventory["files_scanned"] = len(rule_paths)
            workers = min(MAX_SCAN_WORKERS, max(1, len(rule_paths)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                scanned = executor.map(lambda path: _scan_rule_file(label, path, root), rule_paths)
                for reference in scanned:
                    if reference is None:
                        continue
                    inventory["windows_rule_files"] += 1
                    key = (
                        label,
                        reference["source_file"],
                        tuple(reference["techniques"]),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    references.append(reference)
                    inventory["references"] += 1
        inventories.append(inventory)
    return inventories, sorted(
        references, key=lambda row: (row["repository"].lower(), row["source_file"], row["title"])
    )


def load_engine_coverage(path: Path | None, root: Path) -> dict[str, Any]:
    """Load documented coverage states, without inventing missing evidence."""

    result: dict[str, Any] = {
        "path": _relative(path, root) if path else None,
        "exists": bool(path and path.is_file()),
        "loaded": False,
        "error": None,
        "techniques": {},
    }
    if path is None or not path.is_file():
        return result
    try:
        payload = json.loads(_read_text(path))
    except (OSError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
        return result
    rows = payload.get("techniques") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        result["error"] = "engine coverage JSON must contain a techniques list"
        return result
    for row in rows:
        if not isinstance(row, dict):
            continue
        technique = normalize_technique(str(row.get("technique", "")))
        states = row.get("states")
        if technique and isinstance(states, dict):
            result["techniques"][technique] = {
                key: bool(states.get(key, False))
                for key in (
                    "mapped",
                    "telemetry_supported",
                    "validated_synthetic",
                    "validated_public_EVTX",
                    "telemetry_gap",
                    "not_event_log_observable",
                )
            }
    for technique, states in result["techniques"].items():
        if "." in technique or states.get("mapped"):
            continue
        prefix = technique + "."
        mapped_children = sorted(
            child for child, child_states in result["techniques"].items()
            if child.startswith(prefix) and child_states.get("mapped")
        )
        if mapped_children:
            states["mapped"] = True
            states["mapped_via_subtechnique"] = True
            states["mapped_subtechniques"] = mapped_children
    result["loaded"] = True
    return result


def _comparison(
    technique: str, references: list[dict[str, Any]], engine_states: dict[str, bool]
) -> dict[str, Any]:
    mapped = engine_states.get("mapped", False)
    engine_observed = bool(engine_states)
    validated = engine_states.get("validated_public_EVTX", False)
    repositories = sorted({item["repository"] for item in references})
    def source_family(repository: str) -> str:
        lowered = repository.lower()
        if "sigma" in lowered or "hayabusa" in lowered:
            return "sigma-family"
        return lowered
    source_families = sorted({source_family(item["repository"]) for item in references})
    external_event_ids = sorted(
        {event_id for item in references for event_id in item["event_ids"]}
    )
    declared_limit = engine_states.get("telemetry_gap", False) or engine_states.get(
        "not_event_log_observable", False
    )
    if declared_limit:
        classification, priority = "declared_event_log_limit", "medium"
        rationale = "Engine coverage declares an event-log observability or telemetry limitation."
    elif not mapped and not engine_observed:
        classification, priority = "external_only_research_candidate", "medium"
        rationale = (
            "External Windows rule metadata references this technique, but it is outside the engine's current code, test, benchmark, "
            "and EVTX-corpus inventory. Review observability and licensing before treating it as an implementation gap."
        )
    elif not mapped:
        classification = "unmapped_engine_gap"
        if len(source_families) >= 2 and external_event_ids:
            priority = "high"
            rationale = (
                "Two or more independent local Windows rule mirrors reference this technique with explicit event-ID evidence, "
                "but the engine coverage inventory has no mapping."
            )
        else:
            priority = "medium"
            rationale = (
                "A local Windows rule mirror references this technique, but independent-source or explicit event-ID corroboration "
                "is insufficient for a high-priority implementation claim."
            )
    elif not validated:
        classification, priority = "mapped_without_public_EVTX_validation", "medium"
        rationale = "The engine maps this technique, but no passed public-EVTX validation is recorded."
    else:
        classification, priority = "mapped_with_public_EVTX_validation", "low"
        rationale = (
            "The engine maps this technique and records passed public-EVTX validation; "
            "external rules remain reference evidence only."
        )
    return {
        "technique": technique,
        "classification": classification,
        "priority": priority,
        "rationale": rationale,
        "engine_states": engine_states,
        "engine_observed": engine_observed,
        "external_reference_count": len(references),
        "external_repository_count": len(repositories),
        "external_repositories": repositories,
        "external_source_family_count": len(source_families),
        "external_source_families": source_families,
        "external_event_ids": external_event_ids,
        "external_logsource_hints": sorted(
            {hint for item in references for hint in item["logsource_hints"]}
        ),
        "references": references,
    }


def build_report(
    *,
    root: Path = ROOT,
    sources: Iterable[tuple[str, Path]] = (),
    required_sources: Iterable[tuple[str, Path]] = (),
    engine_coverage_path: Path | None = None,
) -> dict[str, Any]:
    """Create deterministic comparison evidence from mirrors and engine states."""

    root = root.resolve()
    optional_inventory, optional_references = scan_sources(sources, root, required=False)
    required_inventory, required_references = scan_sources(required_sources, root, required=True)
    engine = load_engine_coverage(engine_coverage_path, root)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for reference in optional_references + required_references:
        for technique in reference["techniques"]:
            grouped[technique].append(reference)
    comparisons = [
        _comparison(
            technique,
            sorted(items, key=lambda item: (item["repository"], item["source_file"])),
            engine["techniques"].get(technique, {}),
        )
        for technique, items in sorted(grouped.items())
    ]
    priority_rank = {"high": 0, "medium": 1, "low": 2}
    gaps = sorted(
        (item for item in comparisons if item["priority"] != "low"),
        key=lambda item: (priority_rank[item["priority"]], item["technique"]),
    )
    missing_required = [item for item in required_inventory if not item["exists"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": {"root": str(root), "engine_coverage": engine["path"]},
        "engine_coverage": engine,
        "sources": sorted(
            optional_inventory + required_inventory,
            key=lambda item: (item["repository"].lower(), item["path"]),
        ),
        "references": sorted(
            optional_references + required_references,
            key=lambda row: (row["repository"].lower(), row["source_file"], row["title"]),
        ),
        "technique_comparison": comparisons,
        "prioritized_gaps": gaps,
        "summary": {
            "source_count": len(optional_inventory) + len(required_inventory),
            "reference_count": len(optional_references) + len(required_references),
            "techniques_referenced": len(comparisons),
            "high_priority_gaps": sum(item["priority"] == "high" for item in comparisons),
            "medium_priority_gaps": sum(item["priority"] == "medium" for item in comparisons),
            "missing_optional_sources": sum(not item["exists"] for item in optional_inventory),
            "missing_required_sources": len(missing_required),
        },
        "limitations": [
            "Third-party rule references are research evidence only; they never create a mapped, telemetry-supported, or validated engine state.",
            "No upstream rule content is copied into this report. Source licenses, provenance, and update policies remain the responsibility of the rule-source owner.",
            "Parsing is conservative text extraction for local YAML, TOML, and text files; nested structures and semantic rule logic are not evaluated.",
            "Strict mode fails only for paths supplied through --required-source. Missing optional --source mirrors and engine-coverage files are reported but do not fail the audit.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render a compact deterministic review document."""

    summary = report["summary"]
    lines = [
        "# External rule gap audit",
        "",
        "This report compares metadata references from local third-party rule mirrors with the engine coverage inventory. A reference is not a validation result and no upstream rule content is imported.",
        "",
        "- Sources: {} ({} optional missing; {} required missing)".format(
            summary["source_count"],
            summary["missing_optional_sources"],
            summary["missing_required_sources"],
        ),
        "- Windows rule references: {}".format(summary["reference_count"]),
        "- Techniques referenced: {}".format(summary["techniques_referenced"]),
        "- High-priority unmapped gaps: {}".format(summary["high_priority_gaps"]),
        "- Medium-priority review items: {}".format(summary["medium_priority_gaps"]),
        "",
        "## Prioritized gaps",
        "",
        "| Priority | Technique | Classification | External event IDs |",
        "| --- | --- | --- | --- |",
    ]
    if report["prioritized_gaps"]:
        for item in report["prioritized_gaps"]:
            event_ids = ", ".join(str(value) for value in item["external_event_ids"]) or "—"
            lines.append(
                "| {} | {} | {} | {} |".format(
                    item["priority"], item["technique"], item["classification"], event_ids
                )
            )
    else:
        lines.append("| — | — | No high- or medium-priority comparison items | — |")
    lines.extend(["", "## Source status", ""])
    for source in report["sources"]:
        state = "present" if source["exists"] else "missing"
        required = "required" if source["required"] else "optional"
        lines.append(
            "- {} ({}, {}): {}; files scanned: {}; Windows references: {}".format(
                source["repository"],
                required,
                state,
                source["path"],
                source["files_scanned"],
                source["references"],
            )
        )
    lines.extend(["", "## Guardrails", ""])
    lines.extend("- {}".format(item) for item in report["limitations"])
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare local external Windows detection rules with engine coverage."
    )
    parser.add_argument("--root", default=str(ROOT), help="Repository root used to resolve paths.")
    parser.add_argument(
        "--engine-coverage",
        default="audit-artifacts/detection-coverage-final.json",
        help="Coverage audit JSON to compare (optional).",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="LABEL=PATH",
        help="Optional local rule mirror; may be repeated.",
    )
    parser.add_argument(
        "--required-source",
        action="append",
        default=[],
        metavar="LABEL=PATH",
        help="Required local rule mirror; may be repeated.",
    )
    parser.add_argument(
        "--json-out",
        default="audit-artifacts/external-rule-gap-audit.json",
        help="JSON output path, relative to root by default.",
    )
    parser.add_argument(
        "--markdown-out",
        default="audit-artifacts/external-rule-gap-audit.md",
        help="Markdown output path, relative to root by default.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 2 only when an explicitly required source is missing.",
    )
    return parser


def _path(value: str, root: Path) -> Path:
    candidate = Path(value)
    return candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(args.root).resolve()
    try:
        sources = [parse_source_spec(value, root) for value in args.source]
        required_sources = [parse_source_spec(value, root) for value in args.required_source]
    except ValueError as exc:
        _parser().error(str(exc))
    report = build_report(
        root=root,
        sources=sources,
        required_sources=required_sources,
        engine_coverage_path=_path(args.engine_coverage, root) if args.engine_coverage else None,
    )
    json_out = _path(args.json_out, root)
    markdown_out = _path(args.markdown_out, root)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_out.write_text(render_markdown(report), encoding="utf-8")
    print("External rule gap audit JSON: {}".format(json_out))
    print("External rule gap audit Markdown: {}".format(markdown_out))
    print(
        "Techniques referenced: {}; high-priority gaps: {}".format(
            report["summary"]["techniques_referenced"],
            report["summary"]["high_priority_gaps"],
        )
    )
    if args.strict and report["summary"]["missing_required_sources"]:
        print(
            "Strict external rule audit failed: an explicitly required source is missing.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
