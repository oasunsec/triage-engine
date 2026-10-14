# Changelog

## Unreleased

- Added Linux and macOS start instructions to the README.
- Fixed the quality-gates CI job.
- Shortened the README, the production readiness guide and the quality gates guide.
- Removed local usernames, a hostname and local paths from the tests. Sample folders now default to `sample_cache/` or `TRIAGE_SAMPLE_ROOT`.

## 3.0.0 - 2026-03-17

First public release.

- Dashboard with a review queue, case overview, finding and incident detail, and an HTML case report.
- Screenshots of a quiet baseline case and a multi-stage attack case.
- `TRIAGE_DEMO_REDACTION=1` masks lab-specific names in reports and exports. `TRIAGE_DEMO_REDACTION_VALUES` adds your own.
- The UI shows whether it is running under Python or Docker.
- PowerShell `-EncodedCommand` arguments are decoded in the evidence view.
- `start-triage.ps1` sets up and starts the app on Windows.
- Example environment file, plus configuration and release-check guides in `docs/`.
- Local file paths are hidden in the UI and in exported reports.
