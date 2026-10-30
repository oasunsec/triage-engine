# ADR 0001: Cross-source evidence relationships

Date: 2026-10-16, updated 2026-10-17. Status: accepted; third slice (NTFS) implemented.
Inputs: the DFIR expansion blueprint (16 October 2026), the
[architecture audit](../audits/2026-10-02-architecture-audit.md), the
[forensic foundation](../forensic-foundation.md) and the
[execution/download expansion](../forensic-expansion.md).

## Phase 0 assessment: blueprint against the current tree

Baseline: commit `6a790a6` on `revamp-hardening-host-verdicts`, plus the
uncommitted forensic foundation and expansion work from 2–3 October. Python
3.13.14 locally; CI covers 3.10 and 3.13.

| Blueprint item | Current state | Gap |
|---|---|---|
| Evidence registry, SHA-256, provenance | Done: `evidence.py` retains exact bytes, re-verifies, writes versioned evidence/analysis manifests and run snapshots | None for this slice |
| Typed forensic observation | Done as dicts with deterministic `obs_<sha256>` IDs, source locator, time semantics, interpretation (`forensic_artifacts.py`, `prefetch_artifacts.py`, `browser_artifacts.py`) | No formal dataclass; field set is stable and tested |
| Non-EVTX parser or importer | Done: persistence records (Run keys, scheduled tasks, services), Chromium downloads, PECmd Prefetch JSONL | Raw task XML (decision 10), offline registry hives with Amcache (decision 11), native Prefetch binaries (decision 12) and NTFS $MFT/USN (decision 13) added |
| EVTX + artifact in one case | Done: `--evtx … --artifacts …` | — |
| EvidenceRelationship model | **Missing.** Docs state adapters never link to events | Implemented by this ADR |
| Cross-source finding | **Missing** | Implemented by this ADR |
| Source coverage per family | Partial: telemetry gaps and completeness flags | Per-family coverage added for linking |
| Analyst UI | HTML report has an artifact tab; the dashboard has no forensic view | Report Evidence Links table; dashboard Evidence tab (decision 9) |
| `config/release_gate.json` drift | `release_gate.example.json` / `release_gate.ci.json` are tracked; not changed in this slice | Not re-verified here |

## Decision

1. **Keep the flat module layout.** The forensic adapters already live as
   `triage_engine/*_artifacts.py`. Moving them into `triage_engine/forensics/`
   now would rename tested modules for no behaviour gain. Add
   `triage_engine/forensic_correlation.py` alongside them. Revisit the package
   split when a fourth adapter family arrives.
2. **Relationships are a separate, versioned record** (`schema_version` 1.0),
   written to `evidence_relationships.json` and mirrored (first 500) in
   `findings.json["evidence_relationships"]`. Each relationship has:
   deterministic `rel_<sha256>` ID from rule name, rule version and both
   observation IDs; source (event) and target (artifact) references with file,
   hash and record locator; `matched_fields`; `time_relation` with each side's
   time meaning; `link_class`; `inferred_claims` (each with its own class);
   `ambiguity`; `establishes`; `does_not_establish`.
3. **Link classes:** `observed_field_match` (the same value is recorded in both
   sources), `supported_inference` (several independent constraints agree),
   `weak_temporal_association` (ambiguous, e.g. a reused name in the window),
   `analyst_hypothesis` (analyst-entered links; decision 8).
4. **First two rules:**
   - `configured_action_matches_process_image` v1: the full executable path from
     a configured scheduled task, service or Run-key command equals a Sysmon 1 /
     4688 image on the same host. Environment-relative, `\SystemRoot` and bare
     names are counted as unresolved, never guessed. A matching launcher parent
     (taskeng/taskhostw/svchost, services.exe, explorer/userinit) adds a
     supported inference. Time ordering is marked not meaningful, because a
     snapshot only records configuration at collection time.
   - `prefetch_run_matches_process_creation` v1: same host, same file name, and
     the Prefetch recorded run falls 5 s before to 60 s after the process event.
     One candidate gives `supported_inference`; several give
     `weak_temporal_association`. A matching `FilesLoaded` path suffix is
     recorded as an extra matched field.
5. **Scoring is conservative.** A link between benign records is kept but never
   scored. A cross-source finding is raised only when the linked event already
   has a detector alert, or the linked configuration already has a
   persistence-heuristic alert. It also needs at least one non-weak link.
   Its severity never exceeds the contributing alert. Confidence is `high` only
   when two independent artifact families (Prefetch and configuration) link.
   Cross-source findings are kept out of deduplication, attack chains and
   incident building, so links alone cannot create incidents.
6. **Feature flag:** linking runs only when both event records and an artifact
   bundle are supplied. `TRIAGE_FORENSIC_CORRELATION=0` disables it.
   EVTX-only `findings.json` gains no new keys. Every case now writes an
   `evidence_relationships.json` (empty when not evaluated) so a rerun never
   leaves a stale file. Older cases without it remain exportable.
7. **Matching is indexed:** events are indexed by (host, full path) and
   (host, file name); Prefetch lookups use bisect over sorted times. Candidates
   per artifact are capped at 20 and relationships at 50,000.

### Second slice (2026-10-17)

8. **Third rule, `configuration_event_matches_record` v1** (relationship schema
   1.1, which adds `contradictions` to every link). Security 4698/4702/4699 task
   events match a snapshot task by full task path. System 7045 and Security 4697
   service installs match by service name. Sysmon 13 Run-key writes match by
   key path after the hive root. A matching configured command is an extra
   observed field. A differing command, or a task deleted before collection but
   present in the snapshot, is recorded as a contradiction and suppresses the
   inference. Task XML in 4698 is read with a bounded regular expression, not
   an XML parser.
9. **Analyst decisions and hypotheses** live in the review store (migration
   `003_evidence_link_reviews`), keyed by case and the deterministic link ID, so
   they survive reruns. Decisions about links a rerun no longer produces are
   returned as `orphaned_reviews` rather than dropped. Engine output files are
   never edited. Routes are in `triage_engine/forensic_api.py`, mounted from
   `server.py`: viewers read, analysts/admins decide, the existing CSRF
   middleware covers PATCH/POST, actors come from the session (never the
   request body), and every change is audited and kept in review history.
   Hypotheses must name two different observation IDs that exist in the case.
   The dashboard gains an Evidence tab (`static/forensics.js`) shown for cases
   with artifacts: coverage, links with decisions and history, hypotheses, and
   the observation explorer.
10. **Raw Task Scheduler XML** (`triage_engine/task_xml_artifacts.py`, bundle
    member kind `scheduled_task_xml`, CLI `pack-artifacts --task-xml`). Files
    are decoded as UTF-16 or UTF-8 and capped at 1 MiB. Any DOCTYPE or ENTITY
    declaration is rejected before parsing, and actions/triggers are bounded.
    One observation per Exec action feeds the existing rules. The registration
    date and author are kept as unverified, author-written values; a date
    without an offset is not converted. Individually selected task files mark
    the bundle partial, because other tasks may exist.


### Registry hive slice (2026-10-17)

11. **Native offline registry hive parser** (`triage_engine/registry_hive_artifacts.py`,
    bundle member kind `registry_hive` with a declared `hive_type` of `ntuser`,
    `software`, `system` or `amcache`; CLI `pack-artifacts --registry-hive
    --hive-type`). The parser is written from the public regf layout (base block,
    hbin, nk/vk/lf/lh/li/ri/db cells); no third-party parser code is copied or
    linked. It reads bytes only, never loads a hive through Windows APIs, and
    never writes the input. Bounds: 256 MiB per hive (`TRIAGE_MAX_HIVE_BYTES`),
    1 GiB of hives per bundle (a budget separate from the 64 MiB for other
    members), 200,000 subkeys and 65,536 values per key, 1 MiB per value, path
    depth 64, and a cell-visit budget. Each cell offset must fall inside an
    allocated cell within one hive bin. Repeated, self-referencing and ancestor
    references, and ri/db cycles, are rejected. Damage to the base block, bins
    or a key on a lookup path fails the hive. Damage inside one service or
    Amcache entry skips it with a warning. A dirty hive is parsed with a warning;
    **transaction logs are not replayed in v1**, so changes held only in
    `.LOG1/.LOG2` are missing.
    Run/RunOnce values (including `Wow6432Node`) from SOFTWARE and NTUSER.DAT
    become `registry_run` observations. SYSTEM services come from the control set
    named by `Select\Current` and become `service` observations. Both reuse
    `details.name/location/command`, so decisions 4 and 8 apply unchanged, and
    `_configuration_alert` flags suspicious commands. Amcache
    `InventoryApplicationFile` entries become a separate `amcache_file` kind with
    path, SHA-1 from `FileId` and raw `LinkDate`. They are not linked to process
    events, because inventory presence is not proof of execution.
    Observation IDs hash the source SHA-256 with the key path and value name.
    `timestamp` is the key's last write, with the new time meaning
    `registry_key_last_write`. It is a key-level time shared by all its values,
    not a value creation, install or execution time. It enters the activity
    timeline under that label. `HKCU` is a placeholder; an NTUSER.DAT hive does
    not identify its owner. Individually selected hives mark the bundle partial.

### Prefetch binary slice (2026-10-17)

12. **Native Prefetch binaries** (`triage_engine/prefetch_binary.py`, existing
    member kind `prefetch_source`). SCCA versions 17, 23, 26 and 30/31 are
    parsed, including the Windows 10+ `MAM` container. Its LZXPRESS Huffman
    decoder is a clean-room implementation of [MS-XCA] section 2.2.4; no
    third-party code is copied. Decompressed size must match both the container
    and the SCCA header and is capped at 16 MiB; the filename table is capped at
    4 MiB and 16,384 names, volumes at 64. Observations have the PECmd
    adapter's shape (`prefetch_run`, `prefetch_recorded_run`, `details.name`,
    `export_record.FilesLoaded`) with collector `triage-prefetch-binary`, so
    `prefetch_run_matches_process_creation` is unchanged. A damaged or
    unsupported `.pf` stays retained and becomes a warning that marks the
    bundle partial, so a `.pf`-only bundle is now analysable. When a PECmd
    export and the native parse describe the same name and Prefetch hash, both
    are kept and both interpretations say that two tools reading one file are
    not independent corroboration. `cross_source_alerts` counts Prefetch as one
    family whatever the parser, so the pair cannot raise confidence to high.

### File-system chronology slice (2026-10-17)

13. **NTFS $MFT and $UsnJrnl:$J** (`triage_engine/ntfs_artifacts.py`, bundle
    member kinds `ntfs_mft` and `ntfs_usn_journal`, CLI `pack-artifacts
    --ntfs-mft/--ntfs-usn-journal/--ntfs-volume`). One volume per bundle.
    Both files are hashed and parsed as streams and re-hashed during parsing, so
    a change after verification fails the run. Above the shared 64 MiB budget,
    the operator must pass `--allow-large-ntfs` to both packaging and
    investigation (up to 8 GiB per member). The bundle manifest cannot lift the
    limit by itself, and the option raises no other kind's limit.
    - $MFT: FILE signature, header bounds and fixups are checked per record, and
      damaged records are skipped and counted. The index is columnar arrays, not
      per-record objects, capped at 4 million records. Paths come from each
      name's parent reference and sequence, with memoized resolution, a
      255-level bound and cycle detection. Orphans keep their reason and are
      never linked.
    - $J: V2/V3 records; V4 is counted. Sparse regions are skipped and
      malformed regions resynchronised on 8-byte boundaries. Only FILE_CREATE
      records are indexed; all records feed reason counts and the time range.
    - Observations are materialized only for linked records and for up to
      5,000 $SI/$FN contradictions. `ntfs_file` comes in two observations per
      name, `mft_standard_information` and `mft_file_name`, never merged.
      `usn_change` uses `usn_journal_record`.
14. **Fourth rule, `process_image_matches_file_record` v1** (relationship schema
    1.2, which adds `assumptions` and `related_observation_ids` to NTFS links).
    Process images are grouped by volume-relative path, and one pass over the
    $MFT name table, pre-filtered by name length, finds the matching records.
    The `same_file_path` link is an observed field match. Without a supplied
    volume, the drive-letter mapping is recorded as an assumption. Journal
    FILE_CREATE records are found by file reference or by parent reference plus
    name, in one pass over the create index. Events are then found by bisect
    within 1 h before to 5 s after the create (`file_created_before_process`).
    A unique candidate with the same file reference is a supported inference;
    anything else is weak. $SI/$FN disagreement, a record created after the
    process, a deleted record, and $SI creation earlier than the journal's
    creation are contradictions, never proof. A file record at the path is
    context only: `ntfs_file` links never qualify a cross-source finding. A
    journal-creation link counts as the independent `file_system` family.

## Dependencies and licensing

No new runtime dependency. External tools stay outside the MIT tree. Licences below were not re-checked
against upstream in this slice; verify each before adoption:

| Tool | Use | Licence | Decision |
|---|---|---|---|
| PECmd | Analyst-run exporter; JSONL imported | MIT | Import its output only; not bundled or launched |
| Velociraptor, Dissect, Hayabusa | Future import adapters | AGPL-3.0 (Hayabusa rules carry separate licences) | Structured-output import only; no code copied or linked without a licence decision |
| Volatility 3 | Future memory adapter | Volatility Software Licence | Subprocess adapter only after review |
| Timesketch | Future export target | Apache-2.0 | Export format only |

## Threat model

Inputs are hostile. The correlation stage reads already-verified observations
and parsed events only. It opens no paths derived from evidence, executes
nothing and makes no network calls. Command strings are parsed as text. Report
rendering escapes every relationship field (`esc`) and embeds data via the
existing safe JSON-in-script path. Output size is capped as above. The
evidence-link API reads only fixed case file names, validates link and
observation IDs against strict patterns, and resolves cases through the
existing contained `resolve_case_path`. Task XML is never handed a DTD.

## Acceptance criteria (all automated)

- Exact-path, launcher-parent, wrong-host, shared-name, environment-path,
  naive-timestamp and non-process-event cases (`tests/test_forensic_correlation.py`).
- Prefetch in-window, outside-window, wrong-host and reused-name ambiguity cases.
- Native Prefetch (`tests/test_prefetch_binary.py`): synthetic v17/v23/v26/v30/v31
  files, a multi-chunk compressed v30 file from a test-side encoder, truncated,
  bad-signature, bad-declared-size, decompression-bomb and oversized string-table
  cases, PECmd-plus-binary independence, and a mixed case linking a process event
  to a binary-parsed run.
- Deterministic relationship and finding IDs across input order and reruns.
- Benign links raise no finding; weak links alone raise no finding; severity
  is not raised above the contributing alert.
- 20,000 events × 20,000 Prefetch runs link in under 20 s (indexed, not pairwise).
- A mixed case links back to retained source hashes, appears in timeline,
  report and the analysis-run snapshot, and its ZIP export verifies.
- An EVTX-only case has no correlation sections in `findings.json`.
- A public Sysmon sample (EVTX-ATTACK-SAMPLES, skipped when `repo_cache` is
  absent) links its taskeng-spawned `cmd.exe` to a synthetic task and Prefetch run.
- Configuration events: name and command match, command contradiction,
  delete-before-collection contradiction (and none when collected before the
  delete, checked on the public 4698/4699 sample), other folder/host, Sysmon-only
  event 13.
- API (`tests/test_forensic_api.py`): viewer read, viewer/anonymous mutation
  refused, missing CSRF refused, attribution from session, engine file unchanged,
  invalid/unknown IDs and decisions refused, hypothesis validation, decisions
  surviving a rerun.
- Task XML (`tests/test_task_xml_artifacts.py`): UTF-16/UTF-8, multiple and
  non-Exec actions, missing URI, entity expansion, external entity, truncated,
  wrong root, bad encoding, empty, oversized, too many actions, packaging and
  CLI, and a public-sample link to a raw task file.
- Registry hives (`tests/test_registry_hive_artifacts.py`, synthetic hives from an
  in-test regf writer): SOFTWARE/NTUSER Run, RunOnce and Wow6432Node values;
  SYSTEM services from `Select\Current` only; Amcache presence without links;
  ri/li/lh lists, big-data values, hidden data after NUL; dirty and bad-checksum
  warnings; bad signature, truncation, out-of-hive and in-header offsets, free
  cells, wrong cell types, bad version/log file, oversized subkey counts,
  self/ancestor/ri cycles, size limits by parameter and environment, declared-type
  mismatch, a skipped damaged service, a damaged sibling on a lookup path;
  packaging, missing `hive_type`, CLI pairing; and a mixed case where a Sysmon 13
  write and a Sysmon 1 launch both link to a hive-derived Run value.
- NTFS (`tests/test_ntfs_artifacts.py`, synthetic bytes built in the test):
  valid 1 KiB and 4 KiB records, hard links and extension records, bad fixups,
  malformed headers and attributes, truncation, record limits, digest change
  after verification, cyclic, reused, non-directory and missing parents, the
  depth bound, random record bodies, timestomp contradictions and their cap,
  sparse/garbage/V2/V3/V4 USN regions, process-to-MFT and process-to-journal
  links (with and without volume mapping, outside the window, ambiguous), the
  size-limit option, packaging, CLI and a full investigation with retained
  sources. A 5,000 × 5,000 indexed match runs in under 20 s.
- The dashboard Evidence tab was exercised in a browser against the demo case:
  it rendered coverage and links, saved a decision with CSRF, and showed
  attributed history.

## Plan after this slice

1. Registry transaction-log replay, more autostart locations (Winlogon,
   IFEO, AppInit, scheduled-task cache in SOFTWARE) and deleted-cell recovery.
2. Extend real-evidence validation beyond one Windows 11 machine
   ([real-evidence-validation.md](../real-evidence-validation.md)): Windows 10,
   Server, other locales and older Prefetch versions.
3. Hash-based file links when file hashes are available, and multi-volume
   NTFS bundles with per-volume pairing.
4. Analyst decisions in the HTML report and ZIP export (today they are in the
   dashboard and review store only).

## Limits

Tests use synthetic artifacts. On 2026-10-23 the native Prefetch, registry,
task XML and NTFS parsers were also run on one Windows 11 workstation's own
artifacts and checked against the live system
([real-evidence-validation.md](../real-evidence-validation.md)); that is one
machine and one build, and only version 31 Prefetch files were available, so
older Prefetch layouts (including the late Windows 10 layout chosen by file
metrics offset `0x128`) are still checked only against synthetic files. The
public-sample checks pair real events with synthetic artifacts. Nothing here
measures field detection accuracy. The 5 s / 60 s Prefetch window is a
reasoned heuristic that has not been validated against a corpus, and neither
is the 1 h / 5 s USN create window. The $ATTRIBUTE_LIST itself is not parsed:
extension-record names and data sizes attach through their base reference.
Hosts are compared by short name. That can merge
different machines with the same short name in a multi-domain case.
