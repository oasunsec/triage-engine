# Forensic execution and download expansion

Audience: incident-response teams and consultants. Authorized scope: extend the
verified artifact and case foundation beyond EVTX using explicitly supplied
offline evidence. Do not collect this workstation's browser or endpoint data.

Status: implemented and verified, 2026-10-03. Native Chromium History download
records and PECmd JSONL Prefetch exports now feed the case model, timeline, CLI,
and report. Native
Prefetch files were then retained as provenance only; since 2026-10-17 they are
parsed natively by `prefetch_binary.py` (see
[forensic artifacts](forensic-artifacts.md) and ADR 0001 decision 11). Amcache, Firefox, filesystem journals, memory, and disk images remain
future adapters.

Confirmed source contracts: Chromium records modern downloads and redirect
chains, using microseconds since 1601 UTC. PECmd writes one exported record per
JSON line with LastRun and PreviousRun0–6. Download, recorded run, and collection
timestamps have different meanings. Neither adapter automatically creates a
finding, incident, or execution chain.

Implementation ownership: browser adapter and tests; Prefetch adapter and tests;
offline packager and tests; parent owns shared envelope, case integration,
reporting, CLI, documentation, and integration tests. Preserve previous forensic
foundation changes and case history.

Implemented outcome: `pack-artifacts` packages explicitly selected offline files
into a hashed schema 1.1 bundle. Original SQLite/JSONL/optional `.pf` bytes are
retained before parsing. Artifact activity times remain distinct from collection
and Windows event time bounds. New inputs remain unscored observations. Existing
persistence heuristics still describe configuration and cannot create execution
incidents. Bare persistence records without their acquisition manifest produce
partial scope rather than a completeness claim.

PECmd export compatibility is explicit: current source uses global `--dt`, even
inside JSON export; default timestamps omit offsets. The guide requires
`--dt "yyyy-MM-ddTHH:mm:ss.fffffffzzz"` and omitting `--mp`. The parser rejects
naive timestamps, preserves seven-digit raw precision, and normalizes UTC on
Python 3.10 and newer. No PECmd executable or live collection was run.

Verification: the final affected forensic gate passed **168 tests and 92
subtests**, with one expected duplicate-ZIP warning, exit 0, in 69.47 seconds.
Evidence is `runtime/test-output/artifact-expansion-gate.xml`. The independent
review passed **73 tests and 6 subtests on native Python 3.10**. Parent parser and
packager checks also passed 56 tests on 3.10; PECmd checks passed 9 each on 3.10
and 3.13. Review discovered and verified repairs for an unused corrupt SQLite
page, Python 3.10 fractional timestamps, clean-checkout temporary paths, and real
Windows junctions. `quick_check`, the extraction queries, and schema validation
share the SQLite progress/deadline budget. Independent review accepted the final
code and corrected source documentation.

The actual CLI processed synthetic browser/Prefetch inputs into three
observations, zero findings, and zero incidents. Report and explicit-source ZIPs
verified 12 and 17 members. A resumed run preserved the case identity and earlier
run snapshot. Browser inspection verified separate collection/recorded times,
redirect URL search, expandable source hash/native ID, unscored timeline rows,
and source-specific overview guidance. Synthetic case and ZIPs remain under
`runtime/test-output/artifact-expansion/cli-smoke/`.

The Linux/Windows gate now includes Python 3.10 and 3.13; its YAML and Python 3.10
source syntax were validated locally. Remote CI and the entire server suite were
not rerun for this slice. An attempted cached-dependency invocation failed before
test startup with a PermissionError loading cached anyio; the completed gate
used the working standard Python environment. No cache permissions were changed.
The prior foundation broad regression remains separately documented.

Limits: tests are synthetic and official-source shaped; field accuracy, real
PECmd export acceptance, large-corpus performance, and Windows-version coverage
remain unestablished. Hashes demonstrate consistency rather than authenticity;
the engine does not attest export-to-binary derivation. The existing report's
entity graph loads Cytoscape from a CDN, so fully network-independent report
delivery still needs a vendored dependency and packaging acceptance.

Next grounded slice: Amcache and filesystem metadata/USN inputs with conservative
time semantics, followed by analyst pivots and independently corroborated
cross-source relationships. Keep memory/disk parsing and remote acquisition as
separate adapter and acquisition phases from the audit roadmap.

Organization: new source is `browser_artifacts.py`, `prefetch_artifacts.py`,
`artifact_packager.py`, and `path_safety.py` under `triage_engine/`; four new
test modules belong under `tests/`; this state record belongs under `docs/`.
Generated inputs, XML, CLI cases, and review evidence are contained under ignored
`runtime/`. Automatic approval review rejected recursive fixture cleanup with
“blocked by policy”; disposable fixtures remain in their designated runtime
directories. Preserve existing unrelated root files and persistent state.

Final organization check: Git status contains only intentional source, tests,
configuration, and documentation. `git diff --check` passed. No recent files were
created directly in Downloads or at the project root, and no expansion output
larger than 20 MiB was found. The task-owned synthetic report server was stopped
after browser inspection. Generated test fixtures remain ignored under runtime.

Evidence: Chromium's [download database implementation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/history/core/browser/download_database.cc)
and PECmd's [JSONL export implementation](https://github.com/EricZimmerman/PECmd/blob/master/PECmd/Program.cs).
