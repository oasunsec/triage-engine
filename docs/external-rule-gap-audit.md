# External rule gap audit

scripts/external_rule_gap_audit.py compares metadata from local external
Windows detection-rule mirrors with the engine coverage audit. It supports
research against Sigma, Hayabusa, Elastic, and similarly structured sources
without treating an upstream rule as an engine detection claim.

The script is dependency-free. It conservatively scans YAML, TOML, and common
text-rule files for ATT&CK IDs, EventID or EventCode evidence, title/name, and
Windows logsource/channel hints. It does not evaluate rule logic or copy,
embed, download, redistribute, or otherwise import upstream rule content.

Run from the repository root after creating local ignored mirrors under
repo_cache:

    python scripts/external_rule_gap_audit.py --engine-coverage .\audit-artifacts\detection-coverage-final.json --source sigma=.\repo_cache\sigma --source hayabusa=.\repo_cache\hayabusa-rules --source elastic=.\repo_cache\elastic-detection-rules --json-out .\audit-artifacts\external-rule-gap-audit.json --markdown-out .\audit-artifacts\external-rule-gap-audit.md

Use --required-source label=path when a mirror is part of a release check:

    python scripts/external_rule_gap_audit.py --required-source sigma=.\repo_cache\sigma --strict

Strict mode exits with code 2 only when a path passed through
--required-source is missing. An ordinary --source is optional: its missing
state is reported but does not fail the audit. A missing or malformed engine
coverage JSON is also reported rather than silently inventing coverage states.

The comparison classifications are deliberately narrow:

- unmapped_engine_gap: a local external Windows rule references the technique,
  but the engine coverage JSON has no detector mapping.
- mapped_without_public_EVTX_validation: the engine mapping exists but no
  passed public-EVTX validation is recorded.
- mapped_with_public_EVTX_validation: the mapping and passed public-EVTX
  validation are already recorded; the external rule remains reference
  evidence only.
- declared_event_log_limit: the engine coverage audit records a telemetry or
  event-log observability limitation.

Each upstream project remains responsible for its license, source provenance,
maintenance, and rule semantics. Before turning an audit gap into a Triage
Engine detector, reproduce it with a suitable EVTX sample, verify required
telemetry, add benign controls, and record a passed benchmark result in the
engine coverage audit.
