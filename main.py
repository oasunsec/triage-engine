#!/usr/bin/env python3
"""Compatibility entrypoint.

- Supports modern subcommands via corrobora.cli
- Preserves legacy single-run style:
    python main.py --evtx logs/
"""

from __future__ import annotations

import multiprocessing
import sys

from corrobora.cli import main as cli_main


SUBCOMMANDS = {"investigate", "summarize", "export", "tuning-init"}


GLOBAL_ONLY_FLAGS = {"--list-cases", "--show-tuning"}
GLOBAL_BOOL_FLAGS = {"--no-color"}


def _translate_legacy_args(argv: list[str]) -> list[str]:
    if not argv:
        return argv

    # Anything already naming a subcommand, or a global-only action, is modern usage.
    if any(token in SUBCOMMANDS for token in argv):
        return argv
    if any(token in GLOBAL_ONLY_FLAGS or token in {"-h", "--help", "--version"} for token in argv):
        return argv

    # Legacy behavior treated as investigate command options; global flags
    # must stay ahead of the subcommand for argparse to accept them.
    if argv[0].startswith("-"):
        leading = [token for token in argv if token in GLOBAL_BOOL_FLAGS]
        rest = [token for token in argv if token not in GLOBAL_BOOL_FLAGS]
        return [*leading, "investigate", *rest]

    return argv


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(cli_main(_translate_legacy_args(sys.argv[1:])))
