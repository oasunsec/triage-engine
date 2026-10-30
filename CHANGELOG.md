# Changelog

## Unreleased

- Added Linux and macOS start instructions to the README.
- Fixed the quality-gates CI job.
- Shortened the README, the production readiness guide and the quality gates guide.
- Removed local usernames, a hostname and local paths from the tests. Sample folders now default to `sample_cache/` or `TRIAGE_SAMPLE_ROOT`.

### Forensic artifacts and evidence links

- `pack-artifacts` packages offline copies with hashes. Supported: Prefetch `.pf` files (including compressed Windows 10/11 files), PECmd exports, registry hives (Run keys, services, Amcache), raw scheduled task files, `$MFT`, the USN journal, persistence snapshots and Chromium download history. Folders of task or Prefetch files are accepted.
- Event-log records are linked to matching artifacts, such as a process to its Prefetch run or a service install to the SYSTEM hive. Each link lists the fields that matched, what it shows, what it does not show, and any contradictions.
- A link only adds a finding when the event already raised a suspicious alert, and never raises its severity.
- Analysts can accept or reject links, and add their own, in the new Evidence tab. Decisions are kept with who made them and when.
- Reports and exports include the observations and links.
- The parsers were checked against one real Windows 11 machine. Fixes from that check: false alarms on PowerShell module manifests and Defender platform updates, routine service installs no longer become findings through a link, hash-only Amcache entries are labelled, and file sizes held in early `$MFT` extension records are kept.

### Hardening and per-host verdicts

- A case reference of `.` could address the whole cases folder; it no longer can.
- `X-Forwarded-For` is trusted only from `TRIAGE_TRUSTED_PROXIES`. Optional `TRIAGE_BOOTSTRAP_TOKEN` protects first-admin setup.
- HTML reports are served in a sandbox.
- Each host in a case gets its own verdict. Cases mixing hosts or spanning a long time show a warning.

### Workspace

- New overview, review queue, intake and job pages, with light and dark themes, keyboard navigation and a searchable evidence timeline. Assets are local, so the dashboard works offline.
- The container runs as a non-root user.

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
