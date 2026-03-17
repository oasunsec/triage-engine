"""Release gate evaluator for triage engine readiness and competitive scorecards."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_READINESS = ROOT / "production_readiness.json"
DEFAULT_EVALUATION = ROOT / "competitive_eval.json"
DEFAULT_REPORT = ROOT / "release_gate.json"
DEFAULT_CONFIG = ROOT / "config" / "release_gate.json"

BASE_POLICY: Dict[str, Any] = {
    "required_readiness_statuses": ["production_candidate"],
    "required_checks": {
        "validation_passed": True,
        "local_tuning_configured": True,
        "sigma_rules_min": 1,
    },
    "thresholds": {
        "min_malicious_incident_coverage": 0.9,
        "min_malicious_finding_coverage": 0.95,
        "max_benign_incident_rate": 0.05,
        "max_benign_finding_rate": 0.10,
        "max_expected_sample_failures": 0,
        "max_avg_triage_runtime_seconds": None,
        "max_runtime_ratio_triage_over_hayabusa": None,
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _resolve_path(value: str, *, base: Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path.resolve()
    return (base / path).resolve()


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"JSON document at {path} must be an object.")
    return payload


def _merge_policy(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def _add_check(
    checks: List[Dict[str, Any]],
    *,
    name: str,
    passed: bool,
    observed: Any,
    expected: Any,
    operator: str,
    detail: str,
) -> None:
    checks.append(
        {
            "name": name,
            "passed": bool(passed),
            "observed": observed,
            "expected": expected,
            "operator": operator,
            "detail": detail,
        }
    )


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _policy_actions(failed_checks: List[Dict[str, Any]]) -> List[str]:
    actions: List[str] = []
    for check in failed_checks:
        name = check["name"]
        if name == "readiness_status":
            actions.append("Run scripts/production_readiness.py and resolve failing readiness checks before promotion.")
        elif name == "validation_passed":
            actions.append("Fix validation regressions in unit/regression suites and rerun readiness.")
        elif name == "local_tuning_configured":
            actions.append("Build or update config/tuning/local.json from validated clean cases.")
        elif name == "sigma_rules_min":
            actions.append("Add a reviewed Sigma starter set or lower sigma_rules_min explicitly with justification.")
        elif name == "malicious_incident_coverage":
            actions.append("Improve correlation and incident promotion for missed malicious samples.")
        elif name == "malicious_finding_coverage":
            actions.append("Improve signal-to-finding promotion for malicious samples that stayed signal-only.")
        elif name == "benign_incident_rate":
            actions.append("Narrow noisy detections and suppressions causing benign incident promotion.")
        elif name == "benign_finding_rate":
            actions.append("Narrow false-positive finding generation in clean/benign samples.")
        elif name == "expected_sample_failures":
            actions.append("Address failing expectation samples in the benchmark manifest before release.")
        elif name == "avg_triage_runtime_seconds":
            actions.append("Profile heavy detectors and parser settings to reduce average runtime.")
        elif name == "runtime_ratio_triage_over_hayabusa":
            actions.append("Optimize runtime or update runtime ratio threshold with documented environment context.")
    return actions


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate release gate based on readiness and benchmark outputs.")
    parser.add_argument("--readiness", default=str(DEFAULT_READINESS), help="Path to production_readiness.json")
    parser.add_argument("--evaluation", default=str(DEFAULT_EVALUATION), help="Path to competitive_eval.json")
    parser.add_argument("--config", help="Path to release gate policy JSON")
    parser.add_argument("--report", default=str(DEFAULT_REPORT), help="Path to output release gate report JSON")
    parser.add_argument("--strict", action="store_true", help="Return exit code 1 when gate status is fail.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    readiness_path = _resolve_path(args.readiness, base=ROOT)
    evaluation_path = _resolve_path(args.evaluation, base=ROOT)
    report_path = _resolve_path(args.report, base=ROOT)

    if not readiness_path.is_file():
        raise SystemExit(f"Readiness report not found: {readiness_path}")
    if not evaluation_path.is_file():
        raise SystemExit(f"Evaluation report not found: {evaluation_path}")

    readiness = _load_json(readiness_path)
    evaluation = _load_json(evaluation_path)

    policy_path = None
    policy_override: Dict[str, Any] = {}
    if args.config:
        policy_path = _resolve_path(args.config, base=ROOT)
    elif DEFAULT_CONFIG.is_file():
        policy_path = DEFAULT_CONFIG
    if policy_path:
        if not policy_path.is_file():
            raise SystemExit(f"Release gate config not found: {policy_path}")
        policy_override = _load_json(policy_path)

    policy = _merge_policy(BASE_POLICY, policy_override)
    checks: List[Dict[str, Any]] = []

    readiness_status = str(readiness.get("status", "") or "")
    valid_statuses = list(policy.get("required_readiness_statuses", []) or [])
    _add_check(
        checks,
        name="readiness_status",
        passed=readiness_status in valid_statuses,
        observed=readiness_status,
        expected=valid_statuses,
        operator="in",
        detail="Readiness status must be one of the allowed promotion states.",
    )

    required_checks = policy.get("required_checks", {}) if isinstance(policy.get("required_checks"), dict) else {}
    readiness_checks = readiness.get("checks", {}) if isinstance(readiness.get("checks"), dict) else {}
    validation = readiness_checks.get("validation", {}) if isinstance(readiness_checks.get("validation"), dict) else {}
    local_tuning = readiness_checks.get("local_tuning", {}) if isinstance(readiness_checks.get("local_tuning"), dict) else {}
    sigma_pack = readiness_checks.get("sigma_pack", {}) if isinstance(readiness_checks.get("sigma_pack"), dict) else {}

    if required_checks.get("validation_passed", True):
        observed = bool(validation.get("passed"))
        _add_check(
            checks,
            name="validation_passed",
            passed=observed,
            observed=observed,
            expected=True,
            operator="==",
            detail="Validation suite must pass before release.",
        )

    if required_checks.get("local_tuning_configured", True):
        observed = bool(local_tuning.get("configured"))
        _add_check(
            checks,
            name="local_tuning_configured",
            passed=observed,
            observed=observed,
            expected=True,
            operator="==",
            detail="Local tuning profile must be present and configured.",
        )

    sigma_min = int(required_checks.get("sigma_rules_min", 0) or 0)
    if sigma_min > 0:
        observed = int(sigma_pack.get("rule_count", 0) or 0)
        _add_check(
            checks,
            name="sigma_rules_min",
            passed=observed >= sigma_min,
            observed=observed,
            expected=sigma_min,
            operator=">=",
            detail="Sigma rule count must meet minimum configured policy.",
        )

    scorecard = evaluation.get("scorecard", {}) if isinstance(evaluation.get("scorecard"), dict) else {}
    thresholds = policy.get("thresholds", {}) if isinstance(policy.get("thresholds"), dict) else {}

    min_mal_inc = _to_float(thresholds.get("min_malicious_incident_coverage"))
    if min_mal_inc is not None:
        observed = _to_float(scorecard.get("malicious_incident_coverage"))
        passed = observed is not None and observed >= min_mal_inc
        _add_check(
            checks,
            name="malicious_incident_coverage",
            passed=passed,
            observed=observed,
            expected=min_mal_inc,
            operator=">=",
            detail="Malicious samples should promote into incidents at or above target coverage.",
        )

    min_mal_find = _to_float(thresholds.get("min_malicious_finding_coverage"))
    if min_mal_find is not None:
        observed = _to_float(scorecard.get("malicious_finding_coverage"))
        passed = observed is not None and observed >= min_mal_find
        _add_check(
            checks,
            name="malicious_finding_coverage",
            passed=passed,
            observed=observed,
            expected=min_mal_find,
            operator=">=",
            detail="Malicious samples should promote into findings at or above target coverage.",
        )

    max_ben_inc = _to_float(thresholds.get("max_benign_incident_rate"))
    if max_ben_inc is not None:
        observed = _to_float(scorecard.get("benign_incident_rate"))
        passed = observed is not None and observed <= max_ben_inc
        _add_check(
            checks,
            name="benign_incident_rate",
            passed=passed,
            observed=observed,
            expected=max_ben_inc,
            operator="<=",
            detail="Benign incident rate must remain at or below target.",
        )

    max_ben_find = _to_float(thresholds.get("max_benign_finding_rate"))
    if max_ben_find is not None:
        observed = _to_float(scorecard.get("benign_finding_rate"))
        passed = observed is not None and observed <= max_ben_find
        _add_check(
            checks,
            name="benign_finding_rate",
            passed=passed,
            observed=observed,
            expected=max_ben_find,
            operator="<=",
            detail="Benign finding rate must remain at or below target.",
        )

    max_expected_failures = thresholds.get("max_expected_sample_failures")
    if max_expected_failures is not None:
        expected_limit = int(max_expected_failures)
        observed = int(scorecard.get("expected_sample_failures", 0) or 0)
        _add_check(
            checks,
            name="expected_sample_failures",
            passed=observed <= expected_limit,
            observed=observed,
            expected=expected_limit,
            operator="<=",
            detail="Expected sample failures must remain below configured limit.",
        )

    max_avg_runtime = _to_float(thresholds.get("max_avg_triage_runtime_seconds"))
    if max_avg_runtime is not None:
        observed = _to_float(scorecard.get("triage_avg_runtime_seconds"))
        passed = observed is not None and observed <= max_avg_runtime
        _add_check(
            checks,
            name="avg_triage_runtime_seconds",
            passed=passed,
            observed=observed,
            expected=max_avg_runtime,
            operator="<=",
            detail="Average triage runtime per sample must stay below threshold.",
        )

    max_ratio = _to_float(thresholds.get("max_runtime_ratio_triage_over_hayabusa"))
    if max_ratio is not None:
        observed = _to_float(scorecard.get("runtime_ratio_triage_over_hayabusa"))
        passed = observed is not None and observed <= max_ratio
        _add_check(
            checks,
            name="runtime_ratio_triage_over_hayabusa",
            passed=passed,
            observed=observed,
            expected=max_ratio,
            operator="<=",
            detail="Triage runtime ratio against Hayabusa must stay below threshold when comparison is enabled.",
        )

    failed = [check for check in checks if not check["passed"]]
    gate_passed = len(failed) == 0

    report = {
        "generated_at": _utc_now(),
        "status": "pass" if gate_passed else "fail",
        "policy_path": str(policy_path) if policy_path else "",
        "inputs": {
            "readiness": str(readiness_path),
            "evaluation": str(evaluation_path),
        },
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "failed_checks": len(failed),
            "failed_check_names": [check["name"] for check in failed],
        },
        "recommended_actions": _policy_actions(failed),
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Release gate evaluation complete")
    print(f"Status: {report['status']}")
    print(f"Report: {report_path}")
    if failed:
        print("Failed checks:")
        for check in failed:
            print(f"- {check['name']}: observed={check['observed']} expected={check['operator']} {check['expected']}")

    if args.strict and not gate_passed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
