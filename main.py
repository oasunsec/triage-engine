#!/usr/bin/env python3
"""Compatibility entrypoint.

- Supports modern subcommands via triage_engine.cli
- Preserves legacy single-run style:
    python main.py --evtx logs/
"""

from __future__ import annotations

import sys

from triage_engine.cli import main as cli_main


SUBCOMMANDS = {"investigate", "summarize", "export", "tuning-init"}


def _translate_legacy_args(argv: list[str]) -> list[str]:
    if not argv:
        return argv

    first = argv[0]
    if first in SUBCOMMANDS:
        return argv
    if first in {"-h", "--help", "--version"}:
        return argv

    # Legacy behavior treated as investigate command options.
    if first.startswith("-"):
        return ["investigate", *argv]

    return argv


if __name__ == "__main__":
    raise SystemExit(cli_main(_translate_legacy_args(sys.argv[1:])))
