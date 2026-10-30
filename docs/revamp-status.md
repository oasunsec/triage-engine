# Production revamp — verified implementation

Date: 2026-09-05

## Outcome

Rebuilt the analyst workspace and strengthened verified runtime failure boundaries. Preserved existing detector/product edits and live data. The work is ready for review and controlled pilot use. Production rollout remains conditional on environment-specific checks below.

## Delivered

- Extracted dashboard CSS/JavaScript into locally served assets with an explicit server allowlist.
- New responsive overview, review queue, intake/jobs styling, light/dark palette, mobile navigation, associated field labels, keyboard search, modal focus handling, and live notices.
- Searchable evidence timeline with host/type filters, expandable command/summary context, and review links; mixed-host/long-window evidence notices.
- Case status/search filters, reusable review search, functioning overview shortcuts, bounded workload snapshot labels.
- Prevented repeated background preference writes; serialized preference patches; guarded stale case/queue/text responses; preserved data on refresh failures; cleared evidence caches on logout.
- Escaped untrusted inline JavaScript arguments and HTML attributes.
- Added no-store API/browser caching, no-referrer, no-sniff, anti-framing, and basic CSP restrictions.
- Non-root container, loopback port, process/capability restrictions, healthcheck, Linux host UID/GID overrides, writable upload staging, and private-file distribution exclusions.
- Missing EVTX dependency becomes an explicit parser failure; wholly unreadable inputs stop without generating a verdict, including duplicate basenames in separate directories. Partial successful batches retain warning behavior.
- Readiness gate now covers API/workflow/assets/parser boundaries and has strict pilot rejection.

## Evidence

- Full pytest run: **594 passed, 188 skipped, 78 subtests passed** in 344.46 seconds. Log: `.tmp/revamp-acceptance.log`. Skips primarily depend on unavailable external corpus/platform cases; one expected duplicate-ZIP warning comes from tamper-verifier coverage.
- Final checks after the last parser and upload changes: **10 passed, 10 subtests passed**. Log: `.tmp/revamp-contract-final.log`. Includes wholly unreadable input, duplicate basenames, partially readable batch retention, asset delivery, headers, and strict readiness behavior.
- Browser acceptance: **28 passed**, no uncaught exceptions, using real API calls against an isolated local database and a copy of the supplied audit case. Results: `output/workspace-check/results.json`; screenshots in the same directory and selected copies in `screenshots/workspace-*.png`.
- Browser coverage includes login, overview, status/text filters, queue navigation/reset, timeline expansion/search/host filtering, late response races, adversarial inline escaping, outage recovery, preferences focus/Escape, light/dark appearance, mobile navigation/overflow, and logout cache clearing.
- Independent read-only review identified and verified fixes for queue shortcuts, search reset, Docker UID upload permissions, and duplicate filename failure accounting. Final verdict: accepted within scope, no residual actionable blockers found.

## Environment and remaining release gates

The bundled Python runtime used existing local Python packages through a temporary sitecustomize path for testing; network package installation was blocked. Production still needs its documented dependency installation.

Local tuning is **not configured**; four Sigma rules are present. Strict readiness therefore remains pilot-only until reviewed tuning is supplied. No clean-host Docker runtime, Windows live/UAC/elevation run, installer signing, TLS/proxy deployment, backup restore on a target host, or production rollout was performed. Current artifacts and startup docs describe these boundaries. Inline event handlers remain; CSP is intentionally not represented as a strict script-source policy.

## Research and design decisions

Elastic's investigation workflow (https://www.elastic.co/docs/solutions/security/investigate) informed the evidence-to-review sequence. Carbon's table guidance (https://carbondesignsystem.com/components/data-table/usage/) informed filtering, actions, progressive disclosure and table layout. The UI is an original implementation. Deployment notes reference official platform practices and preserve existing data mounts.
