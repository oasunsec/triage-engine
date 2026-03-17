# Sigma Rules

Drop Windows EVTX-focused Sigma `.yml` or `.yaml` rules in this folder and run:

```powershell
python -m triage_engine.cli investigate --evtx <path> --enable-sigma
```

You can also point to specific files or directories with repeated `--sigma-rules` arguments.

Current support is intentionally narrow:

- equality and list membership
- `contains`, `startswith`, `endswith`, `regex`
- simple boolean `condition` expressions

Sigma hits are imported as signals by default and still flow through suppression, deduplication, correlation, and incident promotion.
