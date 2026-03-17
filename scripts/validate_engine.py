"""Maintainer validation workflow for precision-first hardening."""

from __future__ import annotations

import subprocess
import sys


TEST_MODULES = [
    "tests.test_regressions",
    "tests.test_benign_regressions",
    "tests.test_case_metrics",
    "tests.test_parser_parallel",
    "tests.test_tuning_bootstrap",
    "tests.test_sigma_support",
    "tests.test_sigma_cli_e2e",
]


def main() -> int:
    command = [sys.executable, "-m", "unittest", *TEST_MODULES]
    print("Running validation workflow:")
    print(" ".join(command))
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
