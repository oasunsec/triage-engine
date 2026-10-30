"""Produce an evidence-backed ATT&CK coverage inventory for Triage Engine.

This tool is intentionally an inventory, not a coverage claim.  It records
where a technique is mapped, which Windows event IDs are visible in the same
detector function, and which validation artefacts explicitly name the
technique.  A technique is only marked validated when a test or completed
benchmark report provides direct evidence.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "1.0"
ATTACK_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
PUBLIC_CORPUS_TOKENS = (
    "evtx-attack-samples",
    "evtx-to-mitre-attack",
    "security-datasets",
    "hayabusa",
    "atomicredteam",
    "atomic-red-team",
    "deepblue",
    "lichtsinnig",
    "otrf",
)


def normalize_technique(value: str) -> str:
    """Return a canonical upper-case ATT&CK ID or an empty string."""

    match = ATTACK_ID_RE.fullmatch(str(value or "").strip())
    return match.group(1).upper() if match else ""


def technique_ids(value: Any) -> set[str]:
    """Extract ATT&CK technique IDs from strings or nested JSON-like values."""

    found: set[str] = set()
    if isinstance(value, str):
        found.update(match.group(1).upper() for match in ATTACK_ID_RE.finditer(value))
    elif isinstance(value, dict):
        for key, item in value.items():
            found.update(technique_ids(key))
            found.update(technique_ids(item))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            found.update(technique_ids(item))
    return found


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")



def _event_ids_from_node(node: ast.AST, module_assignments: dict[str, ast.AST] | None = None) -> set[int]:
    """Find numeric event IDs in comparisons involving an event-id expression.

    Numeric literals are read directly. A named constant (for example
    ``_BITLOCKER_START_EVENT_IDS``) is resolved against the module-level
    assignments when supplied, so refactors toward named constant sets keep
    their telemetry evidence in the coverage audit.
    """

    event_ids: set[int] = set()
    module_assignments = module_assignments or {}

    def is_event_id_expression(candidate: ast.AST) -> bool:
        if isinstance(candidate, ast.Name):
            return candidate.id.lower().replace("_", "") in {"eventid", "eventids"}
        if isinstance(candidate, ast.Attribute):
            return candidate.attr.lower().replace("_", "") in {"eventid", "eventids"}
        return False

    def integers_from(node_or_value: ast.AST) -> set[int]:
        found: set[int] = set()
        for child in ast.walk(node_or_value):
            if isinstance(child, ast.Constant) and isinstance(child.value, int) and 1 <= child.value <= 65535:
                found.add(child.value)
        return found

    def resolve(expression: ast.AST) -> set[int]:
        values = integers_from(expression)
        if values:
            return values
        # Dereference a bare name that aliases a module-level constant.
        if isinstance(expression, ast.Name) and expression.id in module_assignments:
            return integers_from(module_assignments[expression.id])
        return set()

    for comparison in ast.walk(node):
        if not isinstance(comparison, ast.Compare):
            continue
        expressions = [comparison.left, *comparison.comparators]
        if any(is_event_id_expression(expression) for expression in expressions):
            for expression in expressions:
                event_ids.update(resolve(expression))
    return event_ids

def _functions(tree: ast.AST) -> Iterable[ast.AST]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def scan_detectors(detectors_dir: Path, root: Path) -> dict[str, dict[str, set[Any]]]:
    """Map techniques to detector files and function-local event-ID evidence."""

    techniques: dict[str, dict[str, set[Any]]] = defaultdict(lambda: defaultdict(set))
    if not detectors_dir.is_dir():
        return techniques
    for path in sorted(detectors_dir.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        text = _read_text(path)
        rel_path = _relative(path, root)
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            # A syntax error is reported in the artefact instead of preventing
            # an audit of other detectors.
            continue
        file_techniques = technique_ids(text)
        for technique in file_techniques:
            techniques[technique]["detector_files"].add(rel_path)
        module_assignments = {
            target.id: node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for function in _functions(tree):
            segment = ast.get_source_segment(text, function) or ""
            ids = technique_ids(segment)
            if not ids:
                continue
            event_ids = _event_ids_from_node(function, module_assignments)
            for technique in ids:
                techniques[technique]["detector_files"].add(rel_path)
                techniques[technique]["event_ids"].update(event_ids)
                techniques[technique]["detector_functions"].add(
                    f"{rel_path}:{getattr(function, 'name', '<anonymous>')}"
                )
    return techniques


def _is_skip_decorator(decorator: ast.AST) -> bool:
    text = ast.unparse(decorator).lower()
    return ".skip" in text or ".skipif" in text or ".skipunless" in text


def scan_tests(tests_dir: Path, root: Path) -> tuple[dict[str, dict[str, set[str]]], list[dict[str, str]]]:
    """Find tests that explicitly name ATT&CK IDs and skipped EVTX sample tests."""

    evidence: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    skipped: list[dict[str, str]] = []
    if not tests_dir.is_dir():
        return evidence, skipped
    for path in sorted(tests_dir.rglob("test_*.py")):
        text = _read_text(path)
        rel_path = _relative(path, root)
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            continue
        for function in _functions(tree):
            name = getattr(function, "name", "<anonymous>")
            segment = ast.get_source_segment(text, function) or ""
            ids = technique_ids(segment)
            test_ref = f"{rel_path}:{name}"
            lowered = f"{name}\n{segment}".lower()
            is_public_sample = any(token in lowered for token in (".evtx", "sample", "public", "corpus", "repo_cache"))
            is_benign = any(token in lowered for token in ("benign", "quiet", "false_positive", "false positive", "fp_"))
            if any(_is_skip_decorator(item) for item in getattr(function, "decorator_list", [])) and is_public_sample:
                skipped.append({"test": test_ref, "reason": "conditional_or_explicit_skip"})
            for technique in ids:
                if is_public_sample:
                    evidence[technique]["public_test_files"].add(test_ref)
                else:
                    evidence[technique]["synthetic_test_files"].add(test_ref)
                if is_benign:
                    evidence[technique]["benign_test_files"].add(test_ref)
    return evidence, sorted(skipped, key=lambda item: item["test"])


def _resolve_sample_path(value: str, manifest_path: Path, root: Path) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate.resolve()
    root_candidate = (root / candidate).resolve()
    manifest_candidate = (manifest_path.parent / candidate).resolve()
    return root_candidate if root_candidate.exists() or not manifest_candidate.exists() else manifest_candidate


def _is_public_evtx_sample(sample: dict[str, Any], path: Path, external_roots: list[Path]) -> bool:
    declared_source = str(sample.get("source", "") or "").lower()
    raw_path = str(sample.get("path", "") or "").lower()
    if declared_source in {"public", "external", "community"}:
        return True
    if any(token in raw_path for token in PUBLIC_CORPUS_TOKENS):
        return True
    try:
        return any(path.is_relative_to(root) for root in external_roots)
    except ValueError:
        return False


def _is_synthetic_sample(sample: dict[str, Any]) -> bool:
    tags = {str(item).lower() for item in sample.get("tags", []) if isinstance(item, str)}
    return bool(sample.get("synthetic")) or "synthetic" in tags or str(sample.get("source", "")).lower() == "synthetic"


def scan_benchmarks(
    manifest_paths: Iterable[Path], root: Path, external_roots: list[Path]
) -> tuple[dict[str, dict[str, set[str]]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Inventory benchmark samples and missing required files without executing them."""

    evidence: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    sample_rows: list[dict[str, Any]] = []
    missing_required: list[dict[str, Any]] = []
    invalid_manifests: list[str] = []
    for manifest_path in sorted(set(path.resolve() for path in manifest_paths)):
        try:
            payload = json.loads(_read_text(manifest_path))
        except (OSError, json.JSONDecodeError) as exc:
            invalid_manifests.append(f"{_relative(manifest_path, root)}: {exc}")
            continue
        samples = payload.get("samples") if isinstance(payload, dict) else None
        if not isinstance(samples, list):
            invalid_manifests.append(f"{_relative(manifest_path, root)}: samples must be a list")
            continue
        for index, sample in enumerate(samples, start=1):
            if not isinstance(sample, dict):
                invalid_manifests.append(f"{_relative(manifest_path, root)}: sample {index} is not an object")
                continue
            input_path = str(sample.get("path", "") or "").strip()
            sample_id = str(sample.get("id", "") or f"sample-{index}")
            resolved = _resolve_sample_path(input_path, manifest_path, root) if input_path else None
            expected = str(sample.get("expected", "informational") or "informational").lower()
            required = bool(sample.get("required", expected in {"malicious", "benign"}))
            exists = bool(resolved and resolved.is_file())
            public_evtx = bool(resolved and resolved.suffix.lower() == ".evtx" and _is_public_evtx_sample(sample, resolved, external_roots))
            synthetic = _is_synthetic_sample(sample)
            techniques = sorted(technique_ids(sample))
            row = {
                "manifest": _relative(manifest_path, root),
                "id": sample_id,
                "path": _relative(resolved, root) if resolved else "",
                "exists": exists,
                "required": required,
                "expected": expected,
                "public_evtx": public_evtx,
                "synthetic": synthetic,
                "techniques": techniques,
            }
            sample_rows.append(row)
            if required and not exists:
                missing_required.append(row)
            for technique in techniques:
                evidence[technique]["benchmark_samples"].add(f"{row['manifest']}:{sample_id}")
                if synthetic:
                    evidence[technique]["synthetic_benchmark_samples"].add(f"{row['manifest']}:{sample_id}")
                if expected == "benign":
                    evidence[technique]["benign_benchmark_samples"].add(f"{row['manifest']}:{sample_id}")
                if public_evtx and exists:
                    evidence[technique]["available_public_evtx_samples"].add(f"{row['manifest']}:{sample_id}")
    return evidence, sorted(sample_rows, key=lambda row: (row["manifest"], row["id"])), sorted(
        missing_required, key=lambda row: (row["manifest"], row["id"])
    ), sorted(invalid_manifests)


def scan_validation_reports(paths: Iterable[Path], root: Path) -> dict[str, set[str]]:
    """Read completed competitive_eval reports and retain only passed public EVTX samples."""

    validated: dict[str, set[str]] = defaultdict(set)
    for path in sorted(set(item.resolve() for item in paths if item.is_file())):
        try:
            payload = json.loads(_read_text(path))
        except (OSError, json.JSONDecodeError):
            continue
        samples = payload.get("samples") if isinstance(payload, dict) else None
        if not isinstance(samples, list):
            continue
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            expectation = sample.get("expectation") if isinstance(sample.get("expectation"), dict) else {}
            path_value = str(sample.get("path", "") or "")
            # A passing benign control is useful noise evidence, but it does not
            # demonstrate that the corresponding attack technique was detected.
            if str(sample.get("expected", "")).lower() != "malicious":
                continue
            if not expectation.get("passed") or not path_value.lower().endswith(".evtx"):
                continue
            if not any(token in path_value.lower() for token in PUBLIC_CORPUS_TOKENS):
                continue
            for technique in technique_ids(sample):
                validated[technique].add(f"{_relative(path, root)}:{sample.get('id', 'sample')}")
    return validated


def scan_external_evtx(roots: Iterable[Path], root: Path) -> dict[str, Any]:
    """Inventory optional corpus files; file presence alone never implies validation."""

    files: list[str] = []
    techniques: dict[str, set[str]] = defaultdict(set)
    missing_roots: list[str] = []
    for external_root in sorted(set(item.resolve() for item in roots)):
        if not external_root.is_dir():
            missing_roots.append(_relative(external_root, root))
            continue
        for path in sorted(external_root.rglob("*.evtx")):
            rel_path = _relative(path, root)
            files.append(rel_path)
            for technique in technique_ids(rel_path):
                techniques[technique].add(rel_path)
    return {
        "roots": [_relative(item, root) for item in sorted(set(path.resolve() for path in roots))],
        "missing_roots": sorted(missing_roots),
        "evtx_file_count": len(files),
        "techniques_named_in_paths": {key: sorted(value) for key, value in sorted(techniques.items())},
    }


def _annotations(path: Path | None) -> dict[str, dict[str, Any]]:
    """Load optional deliberate telemetry-state overrides, validating their shape."""

    if path is None or not path.is_file():
        return {}
    payload = json.loads(_read_text(path))
    entries = payload.get("techniques", payload) if isinstance(payload, dict) else {}
    if not isinstance(entries, dict):
        raise ValueError("coverage annotation document must contain an object keyed by ATT&CK ID")
    result: dict[str, dict[str, Any]] = {}
    for raw_id, value in entries.items():
        technique = normalize_technique(raw_id)
        if not technique or not isinstance(value, dict):
            continue
        result[technique] = {
            key: bool(value.get(key))
            for key in ("telemetry_gap", "not_event_log_observable")
            if key in value
        }
        note = str(value.get("note", "") or "").strip()
        if note:
            result[technique]["note"] = note
    return result


def build_report(
    *,
    root: Path = ROOT,
    detectors_dir: Path | None = None,
    tests_dir: Path | None = None,
    manifest_paths: Iterable[Path] = (),
    external_evtx_roots: Iterable[Path] = (),
    validation_report_paths: Iterable[Path] = (),
    annotations_path: Path | None = None,
) -> dict[str, Any]:
    """Create a deterministic report suitable for a release artefact or CI gate."""

    root = root.resolve()
    detector_evidence = scan_detectors(detectors_dir or root / "detectors", root)
    test_evidence, skipped_tests = scan_tests(tests_dir or root / "tests", root)
    external_roots = [path.resolve() for path in external_evtx_roots]
    benchmark_evidence, benchmark_samples, missing_required, invalid_manifests = scan_benchmarks(
        manifest_paths, root, external_roots
    )
    validation_evidence = scan_validation_reports(validation_report_paths, root)
    corpus = scan_external_evtx(external_roots, root)
    annotations = _annotations(annotations_path)

    # Corpus-only techniques are gaps worth reporting.  Excluding them would make
    # the audit answer only "what do we already claim?" instead of comparing the
    # engine with the public validation material supplied by the caller.
    corpus_techniques = set(corpus.get("techniques_named_in_paths", {}))
    technique_ids_seen = (
        set(detector_evidence)
        | set(test_evidence)
        | set(benchmark_evidence)
        | set(validation_evidence)
        | set(annotations)
        | corpus_techniques
    )
    rows: list[dict[str, Any]] = []
    for technique in sorted(technique_ids_seen):
        detector = detector_evidence.get(technique, {})
        tests = test_evidence.get(technique, {})
        benchmark = benchmark_evidence.get(technique, {})
        annotation = annotations.get(technique, {})
        mapped = bool(detector.get("detector_files"))
        telemetry_supported = mapped and bool(detector.get("event_ids"))
        states = {
            "mapped": mapped,
            "telemetry_supported": telemetry_supported,
            "validated_synthetic": bool(tests.get("synthetic_test_files") or benchmark.get("synthetic_benchmark_samples")),
            "validated_public_EVTX": bool(validation_evidence.get(technique)),
            "benign_regression": bool(tests.get("benign_test_files") or benchmark.get("benign_benchmark_samples")),
            "telemetry_gap": bool(annotation.get("telemetry_gap", False)),
            "not_event_log_observable": bool(annotation.get("not_event_log_observable", False)),
        }
        limitations: list[str] = []
        if mapped and not telemetry_supported and not states["telemetry_gap"] and not states["not_event_log_observable"]:
            limitations.append("No function-local Windows event-ID evidence was found; review telemetry manually.")
        if mapped and not states["validated_synthetic"] and not states["validated_public_EVTX"]:
            limitations.append("Mapped implementation has no explicit technique-level validation evidence.")
        if states["telemetry_gap"]:
            limitations.append(
                str(annotation.get("note", "") or "Deliberate telemetry gap declared in the coverage annotation document.")
            )
        if states["not_event_log_observable"]:
            limitations.append(
                str(annotation.get("note", "") or "Technique is declared not observable from this event-log-only intake.")
            )
        rows.append(
            {
                "technique": technique,
                "states": states,
                "evidence": {
                    "detector_files": sorted(detector.get("detector_files", set())),
                    "detector_functions": sorted(detector.get("detector_functions", set())),
                    "event_ids": sorted(detector.get("event_ids", set())),
                    "synthetic_tests": sorted(tests.get("synthetic_test_files", set())),
                    "public_test_references": sorted(tests.get("public_test_files", set())),
                    "benign_tests": sorted(tests.get("benign_test_files", set())),
                    "benchmark_samples": sorted(benchmark.get("benchmark_samples", set())),
                    "available_public_EVTX_samples": sorted(benchmark.get("available_public_evtx_samples", set())),
                    "external_corpus_samples": sorted(
                        corpus.get("techniques_named_in_paths", {}).get(technique, [])
                    ),
                    "validated_public_EVTX_reports": sorted(validation_evidence.get(technique, set())),
                },
                "limitations": limitations,
            }
        )
    state_counts = {key: sum(1 for row in rows if row["states"][key]) for key in (
        "mapped", "telemetry_supported", "validated_synthetic", "validated_public_EVTX", "benign_regression", "telemetry_gap", "not_event_log_observable"
    )}
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": {
            "root": str(root),
            "detectors_dir": _relative(detectors_dir or root / "detectors", root),
            "tests_dir": _relative(tests_dir or root / "tests", root),
            "benchmark_manifests": [_relative(path, root) for path in sorted(set(path.resolve() for path in manifest_paths))],
            "validation_reports": [_relative(path, root) for path in sorted(set(path.resolve() for path in validation_report_paths))],
            "annotations": _relative(annotations_path, root) if annotations_path else None,
        },
        "summary": {"technique_count": len(rows), **state_counts},
        "techniques": rows,
        "benchmark": {
            "sample_count": len(benchmark_samples),
            "samples": benchmark_samples,
            "missing_required_paths": missing_required,
            "invalid_manifests": invalid_manifests,
        },
        "skipped_public_sample_tests": skipped_tests,
        "external_EVTX_corpus": corpus,
        "limitations": [
            "This is an evidence inventory, not a claim of complete ATT&CK coverage.",
            "Technique-level validation requires an explicit ATT&CK ID in a test, manifest, or completed benchmark report.",
            "Public EVTX availability is not validation; only a passed completed benchmark report sets validated_public_EVTX.",
            "Telemetry-supported means an event-ID comparison was found in the same detector function, not that every variant is observable.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render a stable, review-friendly Markdown version of a JSON report."""

    summary = report["summary"]
    lines = [
        "# Detection coverage audit",
        "",
        "This is an evidence inventory, not a statement of complete ATT&CK coverage.",
        "",
        f"- Techniques observed: {summary['technique_count']}",
        f"- Mapped: {summary['mapped']}",
        f"- Telemetry-supported: {summary['telemetry_supported']}",
        f"- Synthetic validation: {summary['validated_synthetic']}",
        f"- Validated public EVTX: {summary['validated_public_EVTX']}",
        f"- Benign regression: {summary['benign_regression']}",
        f"- Missing required benchmark files: {len(report['benchmark']['missing_required_paths'])}",
        f"- Skipped public-sample tests: {len(report['skipped_public_sample_tests'])}",
        "",
        "## Technique evidence",
        "",
        "| Technique | States | Event IDs | Validation evidence |",
        "| --- | --- | --- | --- |",
    ]
    for row in report["techniques"]:
        states = ", ".join(key for key, value in row["states"].items() if value) or "none"
        event_ids = ", ".join(str(item) for item in row["evidence"]["event_ids"]) or "—"
        validation = row["evidence"]["validated_public_EVTX_reports"] or row["evidence"]["synthetic_tests"]
        lines.append(f"| {row['technique']} | {states} | {event_ids} | {', '.join(validation) or '—'} |")
    lines.extend(["", "## Required benchmark paths"])
    if report["benchmark"]["missing_required_paths"]:
        lines.append("")
        for item in report["benchmark"]["missing_required_paths"]:
            lines.append(f"- `{item['manifest']}` / `{item['id']}`: `{item['path']}`")
    else:
        lines.extend(["", "All required benchmark files were present."])
    lines.extend(["", "## Guardrails", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create an evidence-backed ATT&CK coverage audit.")
    parser.add_argument("--root", default=str(ROOT), help="Repository root to scan.")
    parser.add_argument("--detectors-dir", help="Detector directory (default: <root>/detectors).")
    parser.add_argument("--tests-dir", help="Tests directory (default: <root>/tests).")
    parser.add_argument("--benchmark", action="append", default=[], help="Benchmark manifest JSON; may be repeated.")
    parser.add_argument("--external-evtx-root", action="append", default=[], help="Optional public EVTX corpus root; may be repeated.")
    parser.add_argument("--validation-report", action="append", default=[], help="Completed competitive_eval JSON report; may be repeated.")
    parser.add_argument("--annotations", help="Optional coverage state annotation JSON.")
    parser.add_argument("--json-out", default="detection-coverage.json", help="Output JSON path, relative to root by default.")
    parser.add_argument("--markdown-out", default="detection-coverage.md", help="Output Markdown path, relative to root by default.")
    parser.add_argument("--strict", action="store_true", help="Exit 2 when a required benchmark file is missing or a manifest is invalid.")
    return parser


def _input_path(value: str, root: Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(args.root).resolve()
    manifests = [_input_path(value, root) for value in args.benchmark]
    if not manifests:
        manifests = sorted((root / "config" / "benchmark").glob("*.json"))
    report = build_report(
        root=root,
        detectors_dir=_input_path(args.detectors_dir, root) if args.detectors_dir else None,
        tests_dir=_input_path(args.tests_dir, root) if args.tests_dir else None,
        manifest_paths=manifests,
        external_evtx_roots=[_input_path(value, root) for value in args.external_evtx_root],
        validation_report_paths=[_input_path(value, root) for value in args.validation_report],
        annotations_path=_input_path(args.annotations, root) if args.annotations else None,
    )
    json_out = _input_path(args.json_out, root)
    markdown_out = _input_path(args.markdown_out, root)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_out.write_text(render_markdown(report), encoding="utf-8")
    print(f"Coverage JSON: {json_out}")
    print(f"Coverage Markdown: {markdown_out}")
    print(f"Techniques: {report['summary']['technique_count']}; mapped: {report['summary']['mapped']}")
    if args.strict and (report["benchmark"]["missing_required_paths"] or report["benchmark"]["invalid_manifests"]):
        print("Strict coverage audit failed: required benchmark files are missing or a manifest is invalid.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
