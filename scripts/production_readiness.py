"""Production-readiness check for Corrobora."""

from __future__ import annotations

import json
import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
TEST_MODULES = [
    "tests.test_regressions",
    "tests.test_benign_regressions",
    "tests.test_case_metrics",
    "tests.test_cli_usability",
    "tests.test_live_mode",
    "tests.test_parser_parallel",
    "tests.test_tuning_bootstrap",
    "tests.test_sigma_support",
    "tests.test_sigma_cli_e2e",
    "tests.test_api",
    "tests.test_backend_hardening",
    "tests.test_product_workflow",
    "tests.test_collector_ingest",
    "tests.test_workspace_delivery",
    "tests.test_parser_availability",
    "tests.test_packaging_assets",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _run_validation() -> Dict[str, Any]:
    # Pytest also collects function-style API/packaging tests; unittest silently
    # omits those functions when given the same module names.
    command = [
        sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
        *(module.replace(".", "/") + ".py" for module in TEST_MODULES),
    ]
    result = subprocess.run(
        command,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    return {
        "command": command,
        "returncode": int(result.returncode),
        "passed": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _tuning_status() -> Dict[str, Any]:
    path = ROOT / "config" / "tuning" / "local.json"
    status = {
        "path": str(path),
        "present": path.is_file(),
        "configured": False,
        "allowlist_entries": 0,
        "rule_suppressions": 0,
        "promotion_overrides": 0,
    }
    if not path.is_file():
        return status
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        status["load_error"] = str(exc)
        return status

    allowlists = payload.get("allowlists", {}) if isinstance(payload.get("allowlists"), dict) else {}
    allowlist_entries = sum(len(values) for values in allowlists.values() if isinstance(values, list))
    rule_suppressions = len(payload.get("rule_suppressions", []) or [])
    promotion = payload.get("promotion_overrides", {}) if isinstance(payload.get("promotion_overrides"), dict) else {}
    promotion_overrides = sum(len(values) for values in promotion.values() if isinstance(values, list))

    status.update(
        {
            "configured": bool(allowlist_entries or rule_suppressions or promotion_overrides),
            "allowlist_entries": allowlist_entries,
            "rule_suppressions": rule_suppressions,
            "promotion_overrides": promotion_overrides,
        }
    )
    return status


def _sigma_pack_status() -> Dict[str, Any]:
    sigma_dir = ROOT / "rules" / "sigma"
    files = []
    if sigma_dir.is_dir():
        files = sorted(name.name for name in sigma_dir.iterdir() if name.suffix.lower() in {".yml", ".yaml"})
    return {
        "path": str(sigma_dir),
        "present": sigma_dir.is_dir(),
        "rule_files": files,
        "rule_count": len(files),
    }


def _status_label(validation: Dict[str, Any], tuning: Dict[str, Any], sigma: Dict[str, Any]) -> str:
    if not validation.get("passed"):
        return "not_ready"
    if not sigma.get("present") or sigma.get("rule_count", 0) <= 0:
        return "pilot_ready_missing_sigma_pack"
    if not tuning.get("configured"):
        return "pilot_ready_needs_local_tuning"
    return "production_candidate"


def _recommendations(validation: Dict[str, Any], tuning: Dict[str, Any], sigma: Dict[str, Any]) -> List[str]:
    recommendations: List[str] = []
    if not validation.get("passed"):
        recommendations.append("Fix failing validation modules before changing tuning or onboarding more Sigma content.")
    if not tuning.get("configured"):
        recommendations.append(
            "Review 3-5 clean EVTX cases, run 'corrobora tuning-init --case <case> --force', and add only exact allowlists or suppressions you can verify."
        )
    if sigma.get("rule_count", 0) <= 0:
        recommendations.append("Add a reviewed Sigma starter pack before enabling Sigma in broader pilot runs.")
    else:
        recommendations.append("Keep Sigma imported as signal-only until your clean-case tuning profile is stable.")
    recommendations.append("Run this readiness check after every tuning wave and before promoting new rules into broader use.")
    return recommendations


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / "audit-artifacts" / "production_readiness.json")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero unless validation, reviewed Sigma content, and local tuning qualify as a production candidate.")
    args = parser.parse_args(argv)
    report_path = args.report.resolve()

    validation = _run_validation()
    tuning = _tuning_status()
    sigma = _sigma_pack_status()
    status = _status_label(validation, tuning, sigma)

    report = {
        "generated_at": _utc_now(),
        "status": status,
        "checks": {
            "validation": validation,
            "local_tuning": tuning,
            "sigma_pack": sigma,
        },
        "recommendations": _recommendations(validation, tuning, sigma),
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Production readiness check")
    print(f"Status: {status}")
    print(f"Report: {report_path}")
    print(f"Validation passed: {validation['passed']}")
    print(f"Local tuning configured: {tuning['configured']}")
    print(f"Sigma rules available: {sigma['rule_count']}")
    if not validation["passed"]:
        # The report is the record; the tail shows which test failed without opening it.
        output = (validation["stdout"] + validation["stderr"]).strip().splitlines()
        print("Validation output (last 40 lines):")
        print("
".join(output[-40:]))
    return 0 if validation["passed"] and (not args.strict or status == "production_candidate") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
