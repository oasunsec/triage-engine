"""Competitive evaluation runner for triage engine and optional Hayabusa benchmarking."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "competitive_eval.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _slug(value: str) -> str:
    token = re.sub(r"[^a-zA-Z0-9]+", "-", (value or "").strip().lower()).strip("-")
    token = re.sub(r"-{2,}", "-", token)
    return token or "sample"


def _resolve_path(value: str, *, base: Path) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate.resolve()
    return (base / candidate).resolve()


def _resolve_manifest_value(value: str, *, manifest_dir: Path) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate.resolve()

    root_candidate = (ROOT / candidate).resolve()
    manifest_candidate = (manifest_dir / candidate).resolve()
    if root_candidate.exists():
        return root_candidate
    if manifest_candidate.exists():
        return manifest_candidate
    return root_candidate


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"JSON document at {path} must be an object.")
    return payload


def _run_command(command: List[str], *, cwd: Path) -> Dict[str, Any]:
    started = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )
    runtime = round(time.perf_counter() - started, 3)
    return {
        "command": command,
        "cwd": str(cwd),
        "returncode": int(result.returncode),
        "runtime_seconds": runtime,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _summarize_tool_output(path: Path) -> Dict[str, Any]:
    summary = {
        "output_path": str(path),
        "output_present": path.is_file(),
        "output_size_bytes": path.stat().st_size if path.is_file() else 0,
        "output_rows": 0,
    }
    if not path.is_file():
        return summary

    suffix = path.suffix.lower()
    try:
        if suffix == ".csv":
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                line_count = sum(1 for _ in handle)
            summary["output_rows"] = max(0, line_count - 1)
        elif suffix == ".jsonl":
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                summary["output_rows"] = sum(1 for _ in handle)
        elif suffix == ".json":
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                summary["output_rows"] = len(data)
            elif isinstance(data, dict):
                for key in ("detections", "alerts", "results", "items"):
                    values = data.get(key)
                    if isinstance(values, list):
                        summary["output_rows"] = len(values)
                        break
    except Exception as exc:  # pragma: no cover - best effort parsing
        summary["parse_error"] = str(exc)
    return summary


def _extract_triage_metrics(case_path: Path) -> Dict[str, Any]:
    findings_path = case_path / "findings.json"
    summary: Dict[str, Any] = {
        "case_path": str(case_path),
        "findings_path": str(findings_path),
        "findings_present": findings_path.is_file(),
        "signal_count": 0,
        "finding_count": 0,
        "incident_count": 0,
        "raw_alert_count": 0,
        "suppressed_alert_count": 0,
        "response_priority": "",
        "parsed_event_count": 0,
    }
    if not findings_path.is_file():
        summary["load_error"] = "findings.json_missing"
        return summary

    try:
        payload = _load_json(findings_path)
    except Exception as exc:
        summary["load_error"] = str(exc)
        return summary

    case_meta = payload.get("case", {}) if isinstance(payload.get("case"), dict) else {}
    top_summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    quality = (
        top_summary.get("collection_quality_summary", {})
        if isinstance(top_summary.get("collection_quality_summary"), dict)
        else {}
    )

    summary.update(
        {
            "signal_count": int(top_summary.get("signal_count", 0) or 0),
            "finding_count": int(top_summary.get("finding_count", 0) or 0),
            "incident_count": int(top_summary.get("incident_count", 0) or 0),
            "raw_alert_count": int(top_summary.get("raw_alert_count", 0) or 0),
            "suppressed_alert_count": int(top_summary.get("suppressed_alert_count", 0) or 0),
            "response_priority": str(top_summary.get("response_priority", "") or ""),
            "parsed_event_count": int(quality.get("parsed_event_count", 0) or 0),
            "first_seen": str(case_meta.get("first_seen", "") or ""),
            "last_seen": str(case_meta.get("last_seen", "") or ""),
        }
    )
    return summary


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _evaluate_expectation(sample: Dict[str, Any], metrics: Dict[str, Any]) -> Dict[str, Any]:
    expected = str(sample.get("expected", "informational") or "informational").strip().lower()
    result: Dict[str, Any] = {
        "expected": expected,
        "passed": True,
        "incident_condition_passed": True,
        "finding_condition_passed": True,
    }

    incidents = int(metrics.get("incident_count", 0) or 0)
    findings = int(metrics.get("finding_count", 0) or 0)

    if expected == "malicious":
        min_incidents = _as_int(sample.get("expected_min_incidents"), 1)
        min_findings = _as_int(sample.get("expected_min_findings"), 1)
        incident_ok = incidents >= min_incidents
        finding_ok = findings >= min_findings
        result.update(
            {
                "criteria": {
                    "min_incidents": min_incidents,
                    "min_findings": min_findings,
                },
                "incident_condition_passed": incident_ok,
                "finding_condition_passed": finding_ok,
                "passed": incident_ok and finding_ok,
            }
        )
        return result

    if expected == "benign":
        max_incidents = _as_int(sample.get("expected_max_incidents"), 0)
        max_findings = _as_int(sample.get("expected_max_findings"), 0)
        incident_ok = incidents <= max_incidents
        finding_ok = findings <= max_findings
        result.update(
            {
                "criteria": {
                    "max_incidents": max_incidents,
                    "max_findings": max_findings,
                },
                "incident_condition_passed": incident_ok,
                "finding_condition_passed": finding_ok,
                "passed": incident_ok and finding_ok,
            }
        )
        return result

    result["criteria"] = {"mode": "informational_only"}
    return result


def _merged_triage_options(manifest_triage: Dict[str, Any], sample_triage: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "enable_sigma": bool(sample_triage.get("enable_sigma", manifest_triage.get("enable_sigma", False))),
        "no_fp_filter": bool(sample_triage.get("no_fp_filter", manifest_triage.get("no_fp_filter", False))),
        "sigma_rules": list(manifest_triage.get("sigma_rules", []) or []) + list(sample_triage.get("sigma_rules", []) or []),
        "tuning_paths": list(manifest_triage.get("tuning_paths", []) or []) + list(sample_triage.get("tuning_paths", []) or []),
        "extra_args": list(manifest_triage.get("extra_args", []) or []) + list(sample_triage.get("extra_args", []) or []),
    }


def _run_hayabusa(
    sample_path: Path,
    sample_slug: str,
    *,
    manifest_dir: Path,
    hayabusa_cfg: Dict[str, Any],
    output_dir: Path,
) -> Dict[str, Any]:
    executable_value = str(hayabusa_cfg.get("executable", "") or "").strip()
    if not executable_value:
        return {"skipped": True, "reason": "executable_missing"}

    executable = _resolve_manifest_value(executable_value, manifest_dir=manifest_dir)
    if not executable.is_file():
        return {
            "skipped": True,
            "reason": "executable_not_found",
            "expected_executable_path": str(executable),
        }

    output_ext = str(hayabusa_cfg.get("output_ext", ".csv") or ".csv")
    if not output_ext.startswith("."):
        output_ext = "." + output_ext
    output_path = output_dir / f"{sample_slug}{output_ext}"

    argument_template = hayabusa_cfg.get("arguments")
    if not isinstance(argument_template, list) or not argument_template:
        argument_template = ["csv-timeline", "-f", "{input}", "-o", "{output}"]

    args = [
        str(arg)
        .replace("{input}", str(sample_path))
        .replace("{output}", str(output_path))
        for arg in argument_template
    ]
    command = [str(executable), *args]

    cwd_value = str(hayabusa_cfg.get("cwd", "") or "").strip()
    cwd = _resolve_manifest_value(cwd_value, manifest_dir=manifest_dir) if cwd_value else executable.parent
    run = _run_command(command, cwd=cwd)
    run.update(_summarize_tool_output(output_path))
    return run


def _build_scorecard(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    expected_samples = [item for item in samples if item["expectation"]["expected"] in {"malicious", "benign"}]
    malicious_samples = [item for item in expected_samples if item["expectation"]["expected"] == "malicious"]
    benign_samples = [item for item in expected_samples if item["expectation"]["expected"] == "benign"]

    triage_runtimes = [item["triage"]["runtime_seconds"] for item in samples if item["triage"]["returncode"] == 0]
    hayabusa_runtimes = [
        item["hayabusa"]["runtime_seconds"]
        for item in samples
        if isinstance(item.get("hayabusa"), dict) and item["hayabusa"].get("returncode") == 0
    ]

    malicious_incident_passes = sum(1 for item in malicious_samples if item["expectation"]["incident_condition_passed"])
    malicious_finding_passes = sum(1 for item in malicious_samples if item["expectation"]["finding_condition_passed"])
    benign_incident_violations = sum(1 for item in benign_samples if not item["expectation"]["incident_condition_passed"])
    benign_finding_violations = sum(1 for item in benign_samples if not item["expectation"]["finding_condition_passed"])
    expected_failures = sum(1 for item in expected_samples if not item["expectation"]["passed"])

    triage_avg = round(mean(triage_runtimes), 3) if triage_runtimes else None
    hayabusa_avg = round(mean(hayabusa_runtimes), 3) if hayabusa_runtimes else None
    runtime_ratio = None
    if triage_avg and hayabusa_avg:
        runtime_ratio = round(triage_avg / hayabusa_avg, 3)

    return {
        "sample_count": len(samples),
        "expected_sample_count": len(expected_samples),
        "expected_sample_failures": expected_failures,
        "expectation_pass_rate": round((len(expected_samples) - expected_failures) / len(expected_samples), 4)
        if expected_samples
        else 1.0,
        "malicious_sample_count": len(malicious_samples),
        "malicious_incident_coverage": round(malicious_incident_passes / len(malicious_samples), 4)
        if malicious_samples
        else 0.0,
        "malicious_finding_coverage": round(malicious_finding_passes / len(malicious_samples), 4)
        if malicious_samples
        else 0.0,
        "benign_sample_count": len(benign_samples),
        "benign_incident_rate": round(benign_incident_violations / len(benign_samples), 4) if benign_samples else 0.0,
        "benign_finding_rate": round(benign_finding_violations / len(benign_samples), 4) if benign_samples else 0.0,
        "triage_avg_runtime_seconds": triage_avg,
        "hayabusa_avg_runtime_seconds": hayabusa_avg,
        "runtime_ratio_triage_over_hayabusa": runtime_ratio,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run competitive benchmark cases for triage engine.")
    parser.add_argument("--manifest", required=True, help="Benchmark manifest JSON file.")
    parser.add_argument("--report", default=str(DEFAULT_REPORT), help="Path for output report JSON.")
    parser.add_argument("--run-name", help="Optional run name override.")
    parser.add_argument("--cases-dir", help="Optional cases directory override.")
    parser.add_argument("--skip-hayabusa", action="store_true", help="Skip Hayabusa execution even when configured.")
    parser.add_argument(
        "--fail-on-expectation",
        action="store_true",
        help="Return exit code 2 when expected malicious/benign outcomes fail.",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    manifest_path = _resolve_path(args.manifest, base=ROOT)
    manifest = _load_json(manifest_path)
    manifest_dir = manifest_path.parent

    samples = manifest.get("samples")
    if not isinstance(samples, list) or not samples:
        raise SystemExit("Manifest must include a non-empty 'samples' list.")

    triage_cfg = manifest.get("triage", {}) if isinstance(manifest.get("triage"), dict) else {}
    hayabusa_cfg = manifest.get("hayabusa", {}) if isinstance(manifest.get("hayabusa"), dict) else {}

    cases_dir_value = args.cases_dir or triage_cfg.get("cases_dir") or str(ROOT / "cases")
    cases_dir = _resolve_manifest_value(str(cases_dir_value), manifest_dir=manifest_dir)
    cases_dir.mkdir(parents=True, exist_ok=True)

    run_name = args.run_name or str(manifest.get("name", "") or f"competitive-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    run_slug = _slug(run_name)
    run_output_dir = ROOT / "data" / "competitive_eval" / run_slug
    run_output_dir.mkdir(parents=True, exist_ok=True)

    sample_results: List[Dict[str, Any]] = []
    print(f"Competitive evaluation run: {run_name}")
    print(f"Samples: {len(samples)}")
    for index, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict):
            raise SystemExit(f"Sample #{index} is not an object.")
        input_value = str(sample.get("path", "") or "").strip()
        if not input_value:
            raise SystemExit(f"Sample #{index} is missing 'path'.")

        sample_path = _resolve_manifest_value(input_value, manifest_dir=manifest_dir)
        sample_id = str(sample.get("id", "") or sample_path.stem)
        sample_slug = _slug(sample_id)
        case_name = f"{run_slug}-{index:02d}-{sample_slug}"
        case_path = cases_dir / case_name

        print(f"[{index}/{len(samples)}] triage: {sample_id}")

        sample_triage_cfg = sample.get("triage", {}) if isinstance(sample.get("triage"), dict) else {}
        merged_triage = _merged_triage_options(triage_cfg, sample_triage_cfg)

        triage_command = [
            sys.executable,
            "-m",
            "triage_engine.cli",
            "investigate",
            "--evtx",
            str(sample_path),
            "--case",
            case_name,
            "--cases-dir",
            str(cases_dir),
            "--overwrite",
        ]
        if merged_triage["enable_sigma"]:
            triage_command.append("--enable-sigma")
        if merged_triage["no_fp_filter"]:
            triage_command.append("--no-fp-filter")
        for tuning_path in merged_triage["tuning_paths"]:
            triage_command.extend(["--tuning", str(_resolve_manifest_value(str(tuning_path), manifest_dir=manifest_dir))])
        for sigma_rule in merged_triage["sigma_rules"]:
            triage_command.extend(["--sigma-rules", str(_resolve_manifest_value(str(sigma_rule), manifest_dir=manifest_dir))])
        for extra in merged_triage["extra_args"]:
            triage_command.append(str(extra))

        triage_run = _run_command(triage_command, cwd=ROOT)
        triage_metrics = _extract_triage_metrics(case_path)
        expectation = _evaluate_expectation(sample, triage_metrics)

        hayabusa_result: Dict[str, Any] | None = None
        if not args.skip_hayabusa and hayabusa_cfg:
            print(f"[{index}/{len(samples)}] hayabusa: {sample_id}")
            hayabusa_result = _run_hayabusa(
                sample_path,
                sample_slug,
                manifest_dir=manifest_dir,
                hayabusa_cfg=hayabusa_cfg,
                output_dir=run_output_dir,
            )

        sample_results.append(
            {
                "id": sample_id,
                "path": str(sample_path),
                "expected": expectation["expected"],
                "notes": str(sample.get("notes", "") or ""),
                "tags": list(sample.get("tags", []) or []),
                "case_name": case_name,
                "triage": {
                    **triage_run,
                    "metrics": triage_metrics,
                },
                "expectation": expectation,
                "hayabusa": hayabusa_result,
            }
        )

    scorecard = _build_scorecard(sample_results)
    report = {
        "generated_at": _utc_now(),
        "run_name": run_name,
        "manifest_path": str(manifest_path),
        "cases_dir": str(cases_dir),
        "hayabusa_enabled": bool(hayabusa_cfg) and not args.skip_hayabusa,
        "samples": sample_results,
        "scorecard": scorecard,
    }

    report_path = _resolve_path(args.report, base=ROOT)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Competitive evaluation complete")
    print(f"Report: {report_path}")
    print(
        "Coverage: "
        f"malicious incidents {scorecard['malicious_incident_coverage']:.2%}, "
        f"malicious findings {scorecard['malicious_finding_coverage']:.2%}"
    )
    print(
        "Noise: "
        f"benign incidents {scorecard['benign_incident_rate']:.2%}, "
        f"benign findings {scorecard['benign_finding_rate']:.2%}"
    )

    triage_failures = [item for item in sample_results if item["triage"]["returncode"] != 0]
    if triage_failures:
        print(f"Detected {len(triage_failures)} sample run failure(s).")
        return 1

    if args.fail_on_expectation and scorecard["expected_sample_failures"] > 0:
        print(f"Detected {scorecard['expected_sample_failures']} expectation failure(s).")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
