"""Competitive evaluation runner for Corrobora and optional Hayabusa benchmarking."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import threading
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


def _cap_output(value: Any, limit: int = 200_000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = str(value)
    return text if len(text) <= limit else text[:limit] + " ... [truncated]"


def _run_command(command: List[str], *, cwd: Path, timeout: float | None = None) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runtime = round(time.perf_counter() - started, 3)
        return {
            "command": command,
            "cwd": str(cwd),
            "returncode": -9,
            "runtime_seconds": runtime,
            "timed_out": True,
            "stdout": _cap_output(exc.stdout),
            "stderr": _cap_output(exc.stderr),
        }
    except OSError as exc:
        runtime = round(time.perf_counter() - started, 3)
        return {
            "command": command,
            "cwd": str(cwd),
            "returncode": -2,
            "runtime_seconds": runtime,
            "spawn_error": str(exc),
            "stdout": "",
            "stderr": "",
        }
    runtime = round(time.perf_counter() - started, 3)
    return {
        "command": command,
        "cwd": str(cwd),
        "returncode": int(result.returncode),
        "runtime_seconds": runtime,
        "timed_out": False,
        "stdout": _cap_output(result.stdout),
        "stderr": _cap_output(result.stderr),
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
    timeout: float | None = None,
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
    run = _run_command(command, cwd=cwd, timeout=timeout)
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
        "completed_sample_count": sum(
            1 for item in samples if item["triage"].get("returncode") == 0
        ),
        "failed_sample_count": sum(
            1 for item in samples if item["triage"].get("returncode") not in (0, -9)
        ),
        "timed_out_sample_count": sum(
            1 for item in samples if item["triage"].get("timed_out")
        ),
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
    parser = argparse.ArgumentParser(description="Run competitive benchmark cases for Corrobora.")
    parser.add_argument("--manifest", required=True, help="Benchmark manifest JSON file.")
    parser.add_argument("--report", default=str(DEFAULT_REPORT), help="Path for output report JSON.")
    parser.add_argument("--run-name", help="Optional run name override.")
    parser.add_argument("--cases-dir", help="Optional cases directory override.")
    parser.add_argument(
        "--job-dir",
        help="Directory for the run journal and resume state. Defaults to the runner output directory.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Maximum number of samples to process concurrently. Defaults to 1 for deterministic CI runs.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0,
        help="Per-triage command timeout in seconds (0 disables).",
    )
    parser.add_argument(
        "--hayabusa-timeout",
        type=float,
        default=0,
        help="Per-Hayabusa command timeout in seconds (0 disables).",
    )
    parser.add_argument(
        "--id",
        "--sample-id",
        dest="sample_ids",
        action="append",
        default=[],
        help="Run only the sample with this id; may be repeated.",
    )
    parser.add_argument(
        "--tag",
        dest="tags",
        action="append",
        default=[],
        help="Run only samples carrying this tag; may be repeated.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Merge completed healthy sample results from an existing report and run only incomplete/failed samples.",
    )
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Equivalent to --resume plus forcing a fresh rerun of previously failed/timed-out samples.",
    )
    parser.add_argument("--skip-hayabusa", action="store_true", help="Skip Hayabusa execution even when configured.")
    parser.add_argument(
        "--fail-on-expectation",
        action="store_true",
        help="Return exit code 2 when expected malicious/benign outcomes fail.",
    )
    return parser


def _load_existing_samples(report_path: Path) -> Dict[str, Dict[str, Any]]:
    if not report_path.is_file():
        return {}
    payload = _load_json(report_path)
    rows = payload.get("samples")
    if not isinstance(rows, list):
        raise SystemExit(f"Existing report has no samples list: {report_path}")
    return {str(row.get("id", "") or ""): row for row in rows if isinstance(row, dict) and row.get("id")}


def _sample_is_complete(row: Dict[str, Any]) -> bool:
    triage = row.get("triage")
    if not isinstance(triage, dict):
        return False
    if triage.get("returncode") != 0:
        return False
    metrics = triage.get("metrics")
    if not isinstance(metrics, dict) or not bool(metrics.get("findings_present")):
        return False
    expectation = row.get("expectation")
    expected = str(row.get("expected", "") or "").lower()
    if expected in {"malicious", "benign"}:
        if not isinstance(expectation, dict) or not bool(expectation.get("passed")):
            return False
    return True


def _sample_needs_retry(row: Dict[str, Any]) -> bool:
    triage = row.get("triage")
    if not isinstance(triage, dict):
        return True
    if triage.get("returncode") != 0 or bool(triage.get("timed_out")):
        return True
    expectation = row.get("expectation")
    expected = str(row.get("expected", "") or "").lower()
    if expected in {"malicious", "benign"}:
        if not isinstance(expectation, dict) or not bool(expectation.get("passed")):
            return True
    return False


def _write_report(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload_text = json.dumps(payload, indent=2)
    path.write_text(payload_text + chr(10), encoding="utf-8")


def _print_run_summary(scorecard: Dict[str, Any]) -> None:
    print(
        "Expectations: "
        f"{scorecard['expected_sample_failures']} failed of "
        f"{scorecard['expected_sample_count']} expected, "
        f"pass rate {scorecard['expectation_pass_rate']:.2%}"
    )
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
    print(
        "Batches: "
        f"{scorecard['completed_sample_count']}/{scorecard['sample_count']} completed, "
        f"{scorecard['failed_sample_count']} failed, "
        f"{scorecard['timed_out_sample_count']} timed out"
    )


def _run_sample(
    index: int,
    total: int,
    sample: Dict[str, Any],
    *,
    manifest_dir: Path,
    cases_dir: Path,
    run_slug: str,
    triage_cfg: Dict[str, Any],
    hayabusa_cfg: Dict[str, Any],
    output_dir: Path,
    skip_hayabusa: bool,
    timeout: float,
    hayabusa_timeout: float,
    progress: Dict[str, Any],
    progress_lock: threading.Lock,
) -> Dict[str, Any]:
    input_value = str(sample.get("path", "") or "").strip()
    sample_path = _resolve_manifest_value(input_value, manifest_dir=manifest_dir)
    sample_id = str(sample.get("id", "") or sample_path.stem)
    sample_slug = _slug(sample_id)
    case_name = f"{run_slug}-{index:02d}-{sample_slug}"
    case_path = cases_dir / case_name

    with progress_lock:
        progress["started"] += 1
        print(f"[{index}/{total}] triage: {sample_id}")

    sample_triage_cfg = sample.get("triage", {}) if isinstance(sample.get("triage"), dict) else {}
    merged_triage = _merged_triage_options(triage_cfg, sample_triage_cfg)

    triage_command = [
        sys.executable,
        "-m",
        "corrobora.cli",
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

    triage_timeout = timeout if timeout > 0 else None
    triage_run = _run_command(triage_command, cwd=ROOT, timeout=triage_timeout)
    triage_metrics = _extract_triage_metrics(case_path)
    expectation = _evaluate_expectation(sample, triage_metrics)

    hayabusa_result: Dict[str, Any] | None = None
    if not skip_hayabusa and hayabusa_cfg:
        with progress_lock:
            print(f"[{index}/{total}] hayabusa: {sample_id}")
        hayabusa_timeout_value = hayabusa_timeout if hayabusa_timeout > 0 else None
        hayabusa_result = _run_hayabusa(
            sample_path,
            sample_slug,
            manifest_dir=manifest_dir,
            hayabusa_cfg=hayabusa_cfg,
            output_dir=output_dir,
            timeout=hayabusa_timeout_value,
        )

    return {
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


def main(argv: List[str] | None = None) -> int:
    from concurrent.futures import ThreadPoolExecutor, as_completed

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

    report_path = _resolve_path(args.report, base=ROOT)
    job_dir = _resolve_path(str(args.job_dir or run_output_dir), base=ROOT) if args.job_dir else run_output_dir
    job_dir.mkdir(parents=True, exist_ok=True)
    job_path = job_dir / "runner_job.json"
    selected_samples: List[Dict[str, Any]] = []
    skipped_samples: List[Dict[str, Any]] = []
    existing = _load_existing_samples(report_path) if args.resume or args.retry_failed else {}
    filter_ids = set(args.sample_ids)
    filter_tags = {item.lower() for item in args.tags}

    for index, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict):
            raise SystemExit(f"Sample #{index} is not an object.")
        sample_id = str(sample.get("id", "") or "")
        sample_tags = {str(item).lower() for item in sample.get("tags", []) if isinstance(item, str)}
        if filter_ids and sample_id not in filter_ids:
            continue
        if filter_tags and not filter_tags.issubset(sample_tags):
            continue
        sample_path = _resolve_manifest_value(str(sample.get("path", "") or "").strip(), manifest_dir=manifest_dir)
        if not sample_path.is_file():
            raise SystemExit(f"Sample input not found: {sample_id or sample_path} ({sample_path})")
        entry = existing.get(sample_id)
        if entry is not None:
            if args.retry_failed and _sample_needs_retry(entry):
                selected_samples.append(sample)
                continue
            if _sample_is_complete(entry):
                skipped_samples.append(entry)
                continue
        selected_samples.append(sample)

    if args.resume or args.retry_failed:
        print(f"Resume: {len(skipped_samples)} healthy sample(s) reused, {len(selected_samples)} to run")

    jobs = max(1, int(args.jobs))
    timeout = max(0.0, float(args.timeout))
    hayabusa_timeout = max(0.0, float(args.hayabusa_timeout))
    progress = {"started": 0, "completed": 0}
    progress_lock = threading.Lock()

    job_payload = {
        "generated_at": _utc_now(),
        "run_name": run_name,
        "run_slug": run_slug,
        "report_path": str(report_path),
        "manifest_path": str(manifest_path),
        "cases_dir": str(cases_dir),
        "jobs": jobs,
        "timeout_seconds": timeout,
        "hayabusa_timeout_seconds": hayabusa_timeout,
        "total_samples": len(samples),
        "selected_samples": len(selected_samples),
        "completed_samples": 0,
        "failed_samples": 0,
        "status": "running",
    }
    _write_report(job_path, job_payload)

    print(f"Competitive evaluation run: {run_name}")
    print(f"Samples: {len(samples)} selected: {len(selected_samples)} workers: {jobs}")

    new_results: List[Dict[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            futures = {
                executor.submit(
                    _run_sample,
                    index,
                    len(selected_samples),
                    sample,
                    manifest_dir=manifest_dir,
                    cases_dir=cases_dir,
                    run_slug=run_slug,
                    triage_cfg=triage_cfg,
                    hayabusa_cfg=hayabusa_cfg,
                    output_dir=run_output_dir,
                    skip_hayabusa=args.skip_hayabusa,
                    timeout=timeout,
                    hayabusa_timeout=hayabusa_timeout,
                    progress=progress,
                    progress_lock=progress_lock,
                ): (index, sample)
                for index, sample in enumerate(selected_samples, start=1)
            }
            for future in as_completed(futures):
                index, sample = futures[future]
                try:
                    new_results.append(future.result())
                except Exception as exc:
                    sample_id = str(sample.get("id", "") or "sample")
                    print(f"[failure] sample {sample_id}: {exc}")
                    expected = str(sample.get("expected", "informational") or "informational").lower()
                    case_name = f"{run_slug}-{index:02d}-{_slug(sample_id)}"
                    empty_metrics = _extract_triage_metrics(cases_dir / case_name)
                    new_results.append(
                        {
                            "id": sample_id,
                            "path": str(sample.get("path", "") or ""),
                            "expected": expected,
                            "notes": str(sample.get("notes", "") or ""),
                            "tags": list(sample.get("tags", []) or []),
                            "case_name": case_name,
                            "triage": {
                                "command": [],
                                "cwd": str(ROOT),
                                "returncode": -1,
                                "runtime_seconds": 0.0,
                                "stdout": "",
                                "stderr": str(exc),
                                "metrics": empty_metrics,
                            },
                            "expectation": _evaluate_expectation(sample, empty_metrics),
                            "hayabusa": None,
                        }
                    )
                with progress_lock:
                    progress["completed"] += 1
                    job_payload["completed_samples"] = progress["completed"]
                    _write_report(job_path, job_payload)
    finally:
        if job_path.is_file():
            try:
                job_state = _load_json(job_path)
                job_state["status"] = "interrupted"
                job_state["completed_at"] = _utc_now()
                _write_report(job_path, job_state)
            except Exception:
                pass

    sample_results = skipped_samples + new_results
    sample_results.sort(key=lambda item: str(item.get("id", "") or ""))
    scorecard = _build_scorecard(sample_results)
    has_failures = scorecard["completed_sample_count"] < scorecard["sample_count"]
    report = {
        "generated_at": _utc_now(),
        "run_name": run_name,
        "manifest_path": str(manifest_path),
        "cases_dir": str(cases_dir),
        "complete": not has_failures,
        "hayabusa_enabled": bool(hayabusa_cfg) and not args.skip_hayabusa,
        "runner": {
            "selected_sample_count": len(selected_samples),
            "reused_sample_count": len(skipped_samples),
            "jobs": jobs,
            "timeout_seconds": timeout,
            "hayabusa_timeout_seconds": hayabusa_timeout,
        },
        "samples": sample_results,
        "scorecard": scorecard,
    }

    _write_report(report_path, report)
    job_payload["status"] = "complete"
    job_payload["completed_at"] = _utc_now()
    job_payload["failed_samples"] = scorecard["failed_sample_count"]
    job_payload["timed_out_samples"] = scorecard["timed_out_sample_count"]
    job_payload["incomplete_samples"] = scorecard["sample_count"] - scorecard["completed_sample_count"]
    if has_failures:
        job_payload["status"] = "failed"
    _write_report(job_path, job_payload)

    print("Competitive evaluation complete")
    print(f"Report: {report_path}")
    _print_run_summary(scorecard)

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
