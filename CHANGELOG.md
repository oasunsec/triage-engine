# Changelog

## Unreleased

- Added Linux and macOS start instructions to the README.
- Fixed the quality-gates CI job.
- Shortened the README, the production readiness guide and the quality gates guide.
- Removed local usernames, a hostname and local paths from the tests. Sample folders now default to `sample_cache/` or `TRIAGE_SAMPLE_ROOT`.

### Collection and ingest

- `scripts/collect-windows-evidence.ps1` collects a Windows machine from an elevated prompt and only reads it. It gathers event logs (including Defender, Sysmon and Task Scheduler), Prefetch, registry hives with their transaction logs, scheduled tasks, and the raw `$MFT` and USN journal. It writes `collection_manifest.json` with a SHA-256 for every file, records which steps failed, and builds a verified artifact bundle.
- With `-ServerUrl` and `-IngestToken`, the collection goes straight to a triage server (`send-collection.ps1` resends one later). Admins issue collector tokens in User access. A token is shown once, stored as a hash, can be revoked, and every use is audited. The server refuses unsafe archive entries, re-checks every hash, opens the case and records where the evidence came from. See `docs/collector-ingest.md`.
- Registry hives are read with their `.LOG1`/`.LOG2` transaction logs applied. Only consecutive entries with valid checksums are replayed, so recent changes still in the logs are no longer missed.

### Correlation and review

- Service and scheduled-task events are linked to the configured program's `$MFT` record, Amcache entry and any later Prefetch run.
- A new executable inventory brings together what Prefetch, Amcache, `$MFT`, services and tasks say about each program. It lists review reasons such as a run from a temporary folder, a persistence target that no longer exists, or a system name outside the system folder. It never changes a verdict on its own.
- An attack-chain incident now needs a promoted finding or real progression (two or more rules across two or more tactics). Routine activity on a real Windows 11 laptop no longer adds up to a P1.
- The case overview, entity graph and report were redesigned. The graph shows readable labels, first and last seen times and the rules involved, and can replay activity in time order. Reports work offline with no external scripts.
- Analyst decisions are exported with the case as `review_state.json` and `analyst_review.md`.

### Removed

- AI summaries and the AI reviewer, so case content is never sent to an outside service.
- MSP client profiles, webhooks and licensing editions. The tool is now aimed at responders working a case.

### Fixes

- Deleting a case could report success while Windows still held a file open, leaving half a case behind. Deletes are now checked; if anything is left, the server returns an error naming the files and keeps the review decisions.
- The jobs page button now says it removes history records. Cases are not affected.
- Signed-in reads have their own rate budget (`TRIAGE_API_READ_LIMIT_PER_MINUTE`), so reviewing cases quickly is no longer throttled into half-loaded screens.
- Validation errors now show their real message instead of `[object Object]`.
- The timeline and observations load in pages, so large cases open quickly.

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
