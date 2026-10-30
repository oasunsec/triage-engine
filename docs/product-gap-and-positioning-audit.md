# Triage Engine Product Gap and Positioning Audit

Date: 2026-08-26  
Scope: repository implementation, packaged Windows build, supplied `EVTX Sample` corpus, current dashboard flow, and comparable tools.

## Executive verdict

Triage Engine is technically viable as a **pilot-ready offline Windows triage and escalation tool for MSPs**. It is not yet ready to position as a consumer security product, a general event-log viewer, an EDR, or a production-grade remote collection platform.

The strongest product is not “another EVTX reader.” It is:

> **A one-button Windows check that turns suspicious activity into an explainable, verifiable handoff for IT.**

The buyer is the MSP/helpdesk. The end user is someone who reports that a computer is acting strangely and needs to collect evidence without understanding Event IDs, Sigma, or PowerShell.

## Implementation update

The highest-priority usability recommendations from this audit are now implemented:

- A guided Quick Check flow is available from a fresh install without an analyst account.
- Quick Check uses a loopback-only, short-lived capability token and exposes only fixed readiness, live-scan, result, and bundle operations.
- Full live collection can request UAC elevation; declining it leaves normal upload use available.
- Quick Check presents plain-language disposition colors and next steps.
- Entity graphs now include a visible legend and role metadata for observed entry point, suspected attacker, pivot point, and supporting entity.
- Case bundle export now uses a CSRF-aware POST/download flow in the dashboard.

The remaining P0/P1 gaps below still apply: signed binaries, multi-host/time segmentation, centralized edition enforcement, signed collector imports, hardened remote collection, and release validation on clean machines.

## Evidence from the current build

- The supplied seven-file corpus parsed **71 events** in approximately **4.1 seconds**.
- It produced **16 signals, 13 findings, and 10 incidents**.
- The deterministic result was **Escalate / high confidence**.
- The full test suite currently passes: **359 passed, 237 skipped, 68 subtests passed**.
- Production readiness reports **`pilot_ready_needs_local_tuning`**: validation passes and four Sigma rules are present, but there is no environment-specific clean-case tuning profile.
- The Windows installer compiles successfully with Inno Setup 6.7.3. The installer is about **39.7 MB**; the portable one-directory payload is about **101.6 MB**.

The supplied corpus is a useful detection fixture, not proof of real-world accuracy. It contains unrelated scenarios from five hosts spanning roughly 18 months. The current run aggregates those into one P1 case, which is appropriate for a lab validation but dangerous as a default user experience. Real bundles need host/time segmentation and an explicit “mixed or stale evidence” warning.

## What already exists

### Analysis foundation — substantially implemented

- EVTX parsing, normalized events, native behavioral detectors, correlation, timelines, graphs, HTML/JSON reports, raw event export.
- Credential-access, lateral-movement, persistence, defense-evasion, PowerShell, and LOLBin-oriented detections.
- Optional Sigma evaluation, currently with a small four-rule starter pack.
- Deterministic case disposition with confidence, reasons, telemetry gaps, and next collection steps.
- Bounded investigation executor, detector isolation/timeouts, upload size limits, disk checks, and job admission controls.

### MSP workflow — largely implemented

- Versioned client profiles, case metadata, acquisition methods, collection manifests, retention dates, and SQLite persistence.
- Case review queue, analyst notes/history, role-based authentication, CSRF protection, and audit records.
- ZIP export with an SHA-256 manifest and review-state payload.
- Optional webhook and OpenAI-compatible summary adapters.

### Windows distribution — implemented, but not release-hardened

- PyInstaller bundled runtime; end users do not need Python or pip.
- Portable one-directory distribution and Inno Setup installer.
- Localhost-only launcher and browser dashboard.
- Local and remote PowerShell collection scripts with collection manifests.

## Main gaps

### P0 — required for the intended non-technical workflow

1. **No dedicated Quick Check mode.** The dashboard presents sign-in, Review Queue, client profiles, case naming, Sigma, and analyst concepts. That is an operator console, not a user-facing first-response flow.
2. **No automatic UAC elevation.** The app can report live-channel readiness, but the user must know to run the server elevated. The launcher does not relaunch the executable with `RunAs` when full collection is requested.
3. **Scope can be misleading.** Mixed hosts, unrelated dates, and sample bundles are combined into one disposition. Add per-host dispositions, collection-window sanity checks, and a prominent “evidence scope” summary.
4. **Bundle export UI/API mismatch.** The dashboard opens `/api/cases/{case}/bundle` as a GET, while the server defines bundle creation as POST with CSRF protection. The visible Export button can therefore fail even though the API test passes.
5. **Unsigned binary trust.** SmartScreen/endpoint protection warnings are likely for a field USB workflow. Sign the installer and executable, publish hashes, and provide a clear offline verification story.

### P1 — required before a paid Pro edition

1. **Centralized entitlement enforcement is missing.** `capabilities()` reports Community/Pro flags, but routes do not consistently enforce those capabilities. Put one capability check at every Pro boundary.
2. **Collector import is not cryptographically trusted.** Exported case bundles have hash manifests, but collector manifests are only hashed and there is no signed import/rejection workflow.
3. **Remote collection is prototype-level.** The script base64-encodes entire EVTX files in memory and lacks visible host allowlisting, transfer limits, audit integration, and credential-store support.
4. **Webhook contract differs from the roadmap.** This gap is addressed: the implementation now emits `case.completed`, `case.escalated`, and `bundle.exported`, exposes a versioned idempotent envelope, and supports legacy aliases without duplicate delivery. Verify retry performance and consumer compatibility during a pilot; no remaining implementation work is required here.
5. **Release validation is incomplete.** There is no clean-machine installer, upgrade, uninstall-preserves-evidence, USB, signed-binary, or UAC smoke suite. Competitive evaluation cannot run from the current checkout because the referenced `repo_cache` and Hayabusa executable are absent.
6. **Real clean-corpus tuning is absent.** The code passes its current tests, but the readiness gate correctly remains pilot-only until several clean customer corpora are reviewed.

### P2 — defer until pilots prove demand

- Electron/Tauri shell to hide the browser tab. This improves presentation but does not improve detection or evidence quality.
- AI summaries, webhooks, branding, remote collection, and broad client management.
- Large Sigma expansion before local tuning and scope segmentation are stable.

## Competitive position

| Existing option | What it does well | Why it does not replace this product |
|---|---|---|
| Windows Event Viewer | Built in and free | Manual, noisy, and difficult to turn into a handoff |
| [FullEventLogView](https://www.nirsoft.net/utils/full_event_log_view.html) | Portable GUI viewer, EVTX loading, exports, no installation | A raw viewer; it does not provide MSP case workflow or explainable disposition |
| [Hayabusa](https://yamato-security.github.io/hayabusa/) | Fast Rust parsing, Sigma correlation, timelines, HTML/CSV/JSON | Analyst-oriented command line and detection output |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Fast standalone Sigma search/hunt and forensic extraction | Powerful CLI; not designed for a non-technical customer handoff |
| [Velociraptor](https://docs.velociraptor.app/docs/overview/) | Broad artifact collection, agents, live monitoring, remote workflows | Much broader and more operationally complex than a local one-shot triage kit |
| Cyber Triage / commercial DFIR suites | Automated collection, investigation, and reporting | Higher cost and broader forensic scope |
| Splunk, SIEM, EDR, RMM | Centralized monitoring and ongoing response | Require infrastructure, agents, licensing, or ongoing operations |

The defensible gap is **affordable local workflow**, not EVTX parsing. Free tools already parse logs quickly; Triage Engine should own the decision trail from “something feels wrong” to “here is the evidence package your IT provider can act on.”

## Recommended repositioning

### Product name/description

Replace “Windows Endpoint Investigation Platform” with:

> **Offline Windows incident triage for MSPs.**

Supporting line:

> **Run a guided check, understand what was found, and send IT a verifiable evidence package—without a SIEM or cloud account.**

### Primary persona

- MSP helpdesk technician or field technician
- Small-business owner with an IT provider
- Break/fix technician handling a suspicious endpoint without EDR telemetry

### Trigger-based use case

The customer reports a suspicious popup, unusual account activity, Defender alert, unauthorized software, or suspected remote access. The technician sends a portable package or runs the installed app. The app collects what it can, asks for elevation only when needed, explains limitations, and exports a package.

### User-facing result language

Avoid “you are hacked” and avoid a standalone risk score. Use:

- **Action required** — strong evidence supports escalation
- **Review recommended** — suspicious evidence exists, but context or telemetry is incomplete
- **No promoted incident** — nothing crossed the configured promotion threshold

Every result should show the evidence, confidence factors, missing telemetry, time range, hosts, and next action. This aligns the product with the FTC/CISA expectation that small organizations detect, investigate, and respond while coordinating with their service provider.

## Recommended implementation sequence

### Phase 1: make the portable check usable

1. Add a Quick Check/kiosk route with a random local launch token instead of exposing the analyst console.
2. Add automatic UAC relaunch for full live collection; continue with a limited scan if the user declines.
3. Fix bundle export to use a CSRF-aware fetch/download flow.
4. Add evidence scope cards: host count, time span, channels present/missing, collection warnings, and mixed-bundle warning.
5. Make the first screen a three-step flow: **Start Check → Result → Send to IT**.

### Phase 2: make evidence trustworthy

1. Sign the installer and portable release; publish SHA-256 values.
2. Sign collector manifests and verify imports before extraction.
3. Add per-host analysis and case-level aggregation rules that cannot confuse unrelated hosts or stale archives.
4. Add clean-corpus tuning and a repeatable benchmark report.
5. Add clean-machine installer, upgrade, uninstall, USB, UAC, and low-disk tests.

### Phase 3: monetize only proven workflow value

1. Add centralized Community/Pro capability enforcement.
2. Align webhook names and schema with the public contract; add retries and idempotency. **Implemented**; validate with a real consumer during pilot testing.
3. Add client branding and retention workflow.
4. Add remote collection only after allowlisting, streaming, credential-store, audit, and rate-limit controls are complete.
5. Add Electron/Tauri only if MSP pilot users reject the browser presentation.

## Validation plan

Run a pilot with three to five MSPs and approximately 20 real support incidents. Compare the existing manual process with the Quick Check flow. Track:

- time from intake to disposition;
- percentage completed without developer help;
- false escalation rate;
- report usefulness to the receiving security team;
- UAC decline/partial-telemetry rate;
- willingness to pay per technician or per MSP.

Suggested go/no-go targets are: a usable result in under ten minutes excluding analysis, at least 50% less technician triage time, no more than 5% benign incident promotion, zero expected-sample failures, and a clean install that needs no Python or cloud account.

## Audit limits

This review used the current repository, the packaged build, the supplied EVTX sample directory, and one live dashboard capture. It did not establish detection accuracy on a representative customer corpus, validate the remote collector on a clean Windows host, or prove MSP willingness to pay. Those are the highest-value unknowns to test next.
