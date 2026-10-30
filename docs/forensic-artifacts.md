# Windows forensic artifact intake

The forensic inputs include current registry autoruns, scheduled task actions,
service configuration, Chromium download History SQLite snapshots, PECmd
Prefetch JSONL exports, and native Prefetch (`.pf`) files. They work without EVTX through the CLI and can supplement
an EVTX or live investigation. The shared service supports the same input
contract; dashboard upload controls still accept their existing event sources.

## Offline browser and Prefetch evidence

Use your established authorized acquisition process to obtain offline copies.
The packager only reads paths you supply; it does not discover profiles, acquire
this workstation's evidence, or launch PECmd. A Chromium History input must be a
standalone SQLite snapshot using rollback journal format, without WAL/journal
sidecars. A raw copy of a live WAL database can omit records. Produce a consistent
standalone copy through your acquisition tooling before packaging; intake rejects
WAL input rather than modifying or checkpointing the supplied evidence.

PECmd's JSON option writes **JSONL**, one record per line. Supply the actual tool
version and configure a timezone-bearing export. The current source uses the
global `--dt` format even for JSON; its default omits the offset. Use
`--dt "yyyy-MM-ddTHH:mm:ss.fffffffzzz"` and omit `--mp`, which overrides that
format. Default/CSV timestamps without a timezone are rejected. Original `.pf`
files are retained and parsed natively (see below), with or without an export.
This contract follows Chromium's
[download database implementation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/history/core/browser/download_database.cc)
and PECmd's [export code](https://github.com/EricZimmerman/PECmd/blob/master/PECmd/Program.cs)
and [command documentation](https://github.com/EricZimmerman/PECmd/blob/master/README.md).

```powershell
# On your analysis workstation, with your established PECmd installation and offline evidence:
# This is a usage example; triage-engine does not install or run the external tool.
PECmd.exe -d C:\Evidence\Prefetch --json C:\Evidence\Exports --jsonf prefetch.jsonl --dt "yyyy-MM-ddTHH:mm:ss.fffffffzzz"

# Replace these paths, host, collection time, and version with the source evidence metadata.
# The output parent must exist; the bundle itself must be new.
python -m triage_engine.cli pack-artifacts --chromium-history C:\Evidence\Offline\History --pecmd-jsonl C:\Evidence\Exports\prefetch.jsonl --pecmd-version ACTUAL_VERSION --prefetch-source C:\Evidence\Prefetch\EXAMPLE.EXE-12345678.pf --host CLIENT-HOST --observed-at 2026-10-02T12:00:00Z --output-dir .\runtime\output\execution-download-bundle

python -m triage_engine.cli investigate --artifacts .\runtime\output\execution-download-bundle --case execution-download
```

Repeat input flags for multiple files. `--persistence-records` can combine the
existing collector's record JSON with these inputs. Because bare records omit
the acquisition manifest, that bundle is always marked partial with a warning
that collector scope and failures are unknown. Analyze the original persistence
bundle separately to preserve its collection metadata. The packager describes
successful copying of supplied files, not complete endpoint coverage or
authenticated tool output; preserve acquisition records with your engagement.

Generic bundles use `schema_version: "1.1"` and
`kind: "windows_forensic_artifacts"`. Each file declares `path`, `kind`,
`size_bytes`, and `sha256`; PECmd members also require
`exporter: {"name": "PECmd", "version": "actual-version"}`. Supported member kinds
are `chromium_history`, `pecmd_jsonl`, `prefetch_source`, `persistence_records`,
`scheduled_task_xml`, `registry_hive` (which also declares `hive_type`), `ntfs_mft`
and `ntfs_usn_journal`. NTFS members may carry `volume` (a drive letter such as `"C:"`).
Every member kind is parsed, so a bundle containing only `prefetch_source`
members is analysable.

Chromium observations retain the native download ID, paths, byte counts, state,
opened flag, start/end times, and ordered redirect URLs. Browser timestamps use
microseconds since 1601 UTC. The timeline uses download **start**, with completion
time and status available in the artifact details. A recorded download, even one
marked complete/opened, does not prove file existence or execution.

Prefetch observations expand LastRun and PreviousRun0–6 when present. PECmd records retain
the export line, source filename, run field, original timestamp precision, run
count, and raw exported fields. The Prefetch Hash field is not a content digest.
A recorded run supports an execution trace, but does not establish the user,
full executable path, or malicious intent. ParsingError records remain visible
and make processing partial. Exporter identity is declared, not attested, and
retaining a `.pf` alongside JSONL does not prove that the export was derived from
that binary. Corroborate it through your acquisition workflow.

Native `.pf` files are parsed by `triage_engine/prefetch_binary.py` (collector
`triage-prefetch-binary`): SCCA versions 17 (XP), 23 (Vista/7), 26 (8.1) and
30/31 (10/11), uncompressed or in the Windows 10+ `MAM` container. The
decompressor is written from Microsoft's
[MS-XCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/) LZ77+Huffman specification.
Each file yields the executable name, Prefetch hash, run count, each non-zero
last-run FILETIME (one in versions 17/23, up to eight later), volume device
path, serial and creation time, directories, and the loaded-file list, in the
same observation shape as PECmd records. Volume creation time stays in the
details; it is not a run time. Limits: 16 MiB per file and decompressed, a
4 MiB filename table and 16,384 names, 64 volumes, and 64 KiB for each joined
list in `export_record` (the executable's own path is kept first when the list
is cut, with a warning). An unsupported, damaged or inconsistent file is
retained, reported as a warning, and makes the analysis partial.

If both a PECmd export and the `.pf` it was made from are supplied, both sets of
observations are kept. Where name and Prefetch hash agree, each observation says
that two tools reading one file are not independent corroboration, and
cross-source findings count Prefetch as a single evidence family.

These observations appear in the artifact view and timeline as **unscored**
observations. They do not automatically create findings, incidents, or chains.
Collection time remains separate, and event-telemetry time bounds do not absorb
artifact timestamps. Strict unsupported/corrupt/schema/time inputs fail analysis
while already verified sources remain retained. Limits include 50,000 total
observations, 64 redirect URLs per download, bounded text fields, and a SQLite
query deadline. SQLite resource limits add protection on Python 3.11+; Python
3.10 uses schema, field, row, and progress-handler bounds.

## Persistence collection and investigation

On an authorized Windows endpoint, run the fixed collector with an explicit
output directory. It queries local configuration and writes two JSON files;
it does not launch configured commands, load other users' hives, or contact a
remote service. Elevated rights can improve task/service coverage. Query
failures are recorded as warnings rather than silently becoming empty evidence.

```powershell
# From the project directory, on the endpoint being investigated:
.\scripts\collect-windows-artifacts.ps1 -OutputDirectory .\runtime\output\endpoint-snapshot

# Analyze the snapshot alone; this does not automatically select live collection.
python -m triage_engine.cli investigate --artifacts .\runtime\output\endpoint-snapshot --case endpoint-persistence

# Supplement an offline event investigation.
python -m triage_engine.cli investigate --evtx C:\Evidence\Events --artifacts C:\Evidence\Persistence --case endpoint-combined

# Export the current display/report artifacts and provenance manifests.
python -m triage_engine.cli export --case endpoint-combined --zip --output .\runtime\output\endpoint-report.zip

# Explicitly include unredacted retained sources and normalized record stream.
python -m triage_engine.cli export --case endpoint-combined --zip --include-sources --output .\runtime\output\endpoint-evidence.zip
```

Use a new collector directory for each capture. The collector refuses to
overwrite its output files. Transfer both files together when collecting on
another endpoint. The collector covers machine autoruns plus the current
user's Run/RunOnce keys; other users' hives are not covered. That scope warning
makes its manifest partial even when all queries succeed. The snapshot is
collected sequentially, not as an atomic image of the endpoint.

## Evidence semantics

The reader validates the manifest schema, timezone, file paths, sizes, and
SHA-256 digests before accepting records. It parses the same bytes it hashes,
then verifies retained copies against those digests. It rejects traversal,
links/junctions in member paths, unknown record kinds/fields, and inconsistent
completeness declarations. Limits are 1 MiB for the manifest, 64 MiB of
artifact bytes, 64 members, and 50,000 observations. General retained inputs are
limited to 1,024 files and 4 GiB per capture batch; configure
`TRIAGE_MAX_EVIDENCE_BYTES` explicitly for larger evidence sets.

Collection times describe when configuration was observed. They do not
establish when a key/task/service was created or whether its command executed.
Host and collector names are declared source metadata, not authenticated
identities. Hashes establish byte consistency, not authenticity or a complete
chain of custody.

Benign configurations remain observations. Narrow command heuristics flag
encoded PowerShell, PowerShell remote-content launchers, and remote
mshta/regsvr32 commands as medium-severity configuration findings. These are
leads requiring validation; there are no synthetic Windows EventIDs. Snapshot
findings do not feed execution chains, incidents, or campaign correlation.
ATT&CK identifiers describe potential behavior to investigate.

The HTML report provides a searchable Persistence Snapshot or Forensic Artifacts
tab, with up to 500 matching display records and source references. `forensic_observations.json`
contains the full display projection; original records remain in `evidence/`.
Existing display sanitization may clip or summarize commands. Original sources
and `raw_events.jsonl` are unredacted and are included in a ZIP only with
`--include-sources`. Default exports are display/report packages and may still
contain identifying metadata; they are not an anonymization guarantee.

## Case layout and reruns

```text
case/
  case_identity.json             stable case UUID
  evidence_manifest.json         current run's retained source catalog
  evidence/<sha256>.*            exact .evtx/.json/.sqlite/.jsonl/.pf/.xml/.mft/.usnjrnl input bytes
  forensic_observations.json     current display projection (empty without a snapshot)
  evidence_relationships.json    derived event-to-artifact links and coverage (empty unless both are supplied)
  raw_events.jsonl               one record per normalized event, all model fields
  analysis_manifest.json         latest completed analysis manifest
  runs/<run-uuid>/
    analysis_manifest.json       retained manifest for this completed run
    outputs/                    retained output copies for that run
```

Each analysis manifest records configuration, software/rule/tuning/IOC hashes,
source references, output hashes, collection warnings, and partial failures.
Completed run directories are never reused by the application. They remain
ordinary filesystem files; no write protection or external attestation is
claimed. Sources are retained before parsing. Existing case projections can
be refreshed with `--resume` while completed output snapshots remain available.
Back up the entire case directory to preserve that history; current ZIP
exports do not package all historical runs.

Exports require the current run to be completed and its outputs to match the
analysis manifest. The exporter verifies the exact byte buffers it packages,
checks the run identity again before publishing, and atomically replaces the
destination ZIP. A failed/running rerun or changed output is rejected. ZIP
destinations cannot overwrite case evidence, historical runs, or existing case
files. Raw-source exclusion also applies to case variants on Windows and cannot
be bypassed through historical output paths.

The normalized event stream preserves every normalized model field and each
record; it is not the original EVTX format. Raw XML is retained only where the
existing parser retains it, and date filters, reader limits, and parse failures
still affect the normalized result. Original EVTX bytes are the reference for
re-extraction. Live API collection has no retained native EVTX source and is
explicitly qualified in the analysis manifest.

`complete` means no recorded processing or collection failure for the supplied
input, not full endpoint visibility. Event telemetry gaps remain visible. A
partial collector, capped/unreadable records, skipped Sigma rules, unavailable
components, or failed output publication produce a partial/failed result as
appropriate. Restarted server jobs are marked interrupted, retain their input,
and require an operator rerun; automatic execution recovery is not implemented.

## Evidence links between events and artifacts

When a case has both event records and an artifact bundle, process-creation
events (Sysmon 1, Security 4688) are linked to artifact observations. A
configured task, service or Run-key command can match the full image path, or a
Prefetch recorded run can match the file name within 5 s before to 60 s after
the event. Each link records the matching fields, its class (observed field
match, supported inference or weak temporal association) and what it does not
establish. Links are written to `evidence_relationships.json`, shown in the
report's Evidence Links table and attached to timeline artifact rows.

A link alone is never scored. A cross-source finding is raised only when the
linked event or configuration already has an alert. Its severity is capped at
that alert's severity, and it stays out of incident building. Task, service and Run-key change events (4698/4702/4699,
7045/4697, Sysmon 13) are also linked to snapshot records by name. A differing
command, or a deletion before collection, is shown as a contradiction. Set
`TRIAGE_FORENSIC_CORRELATION=0` to disable linking.

In the dashboard, cases with artifacts have an **Evidence** tab. It shows source
coverage, each link with its matching fields, contradictions and limits, and the
artifact observation explorer. Analysts can confirm, reject or flag a link, or
record their own hypothesis link between two observations; viewers can read
only. Decisions are stored in the review store with the analyst's name and
history, and they survive reruns because link IDs are deterministic.

### Raw scheduled-task definitions

`pack-artifacts --task-xml <file>` (repeatable) accepts files copied from
`C:\Windows\System32\Tasks`, or a copied Tasks folder: every regular file
beneath it is added, links and junctions are skipped. `--prefetch-source`
likewise accepts a Prefetch folder and takes its `.pf` files. A bundle holds
up to 1,024 members. Each Exec action becomes an observation with the
task path, principal, run level, hidden flag, triggers and command. The
registration date and author are written by whoever registered the task, so
they are shown as unverified, and a date without an offset is not converted.
Selecting individual task files marks the bundle partial, because other tasks
may exist on the host. Files with DOCTYPE or ENTITY declarations are rejected. Design and limits:
[ADR 0001](design/adr-0001-cross-source-evidence-relationships.md).

### Offline registry hives

`pack-artifacts --registry-hive <file> --hive-type <type>` (both repeatable,
paired in order) accepts offline copies of `NTUSER.DAT` (`ntuser`), `SOFTWARE`
(`software`), `SYSTEM` (`system`) and `Amcache.hve` (`amcache`). The type is
declared by you; the parser checks that the hive has the expected structure
but does not guess the type. The parser reads the regf bytes directly. It never
loads a hive through Windows APIs and never writes to the input.

```powershell
python -m triage_engine.cli pack-artifacts --registry-hive C:\Evidence\config\SOFTWARE --hive-type software --registry-hive C:\Evidence\config\SYSTEM --hive-type system --registry-hive C:\Evidence\Users\alice\NTUSER.DAT --hive-type ntuser --host CLIENT-HOST --observed-at 2026-10-02T12:00:00Z --output-dir .\runtime\output\hive-bundle
```

| Hive | Observations | Kind |
|---|---|---|
| SOFTWARE | `Microsoft\Windows\CurrentVersion\Run` and `RunOnce`, plus the `Wow6432Node` copies, shown under `HKLM\SOFTWARE` | `registry_run` |
| NTUSER.DAT | The same keys under `Software\`, shown under `HKCU\Software` | `registry_run` |
| SYSTEM | Every `Services` subkey of the control set named by `Select\Current`: ImagePath, Start, Type, ObjectName, DisplayName and `Parameters\ServiceDll` | `service` |
| Amcache.hve | `Root\InventoryApplicationFile` entries: LowerCaseLongPath, FileId as SHA-1, LinkDate, publisher and version | `amcache_file` |

Each observation carries `native_locator` (hive type, key path, value name) and
an ID derived from the source hash and that locator. Run and service
observations use the same `name`/`location`/`command` fields as snapshot
records, so the existing rules link them to process and Sysmon 13 events, and
the existing command heuristics flag suspicious values.

Time meaning: `timestamp` is the key's **last-write time**
(`registry_key_last_write`). It is shared by every value in that key. It is not
when a value was created, when a service was installed, or when anything ran.
Amcache `LinkDate` is kept raw. It is the PE link time set at build time, can be
forged, and is not an install or run time. An Amcache entry shows that the file
was inventoried, which is **not proof of execution**. Amcache entries are not
linked to process events. Published research reports that the Amcache SHA-1
covers only the first 30 MiB of larger files; this was not re-verified here. An NTUSER.DAT hive does not name its owner; `HKCU` is a placeholder.

Limits and caveats:

- **No transaction-log replay.** A dirty hive (sequence numbers differ) is parsed
  with a warning, and changes held only in `.LOG1`/`.LOG2` are missing. Logs
  found beside a selected hive are reported, not packaged.
- Hives are capped at 256 MiB each (`TRIAGE_MAX_HIVE_BYTES`) and 1 GiB per
  bundle, separate from the 64 MiB budget for other members.
- Every cell offset is checked against its hive bin. Subkey and value lists are
  bounded, and repeated, self-referencing or ancestor cell references are
  rejected as cycles. A damaged base block, bin, or key on a lookup path fails
  the hive. A damaged single service or Amcache entry is skipped with a warning.
- Deleted keys and values, slack space and the older Amcache `Root\File` layout
  are not read. A string value is cut at its first NUL, as Windows reads it;
  `data_after_nul` records hidden data after that point.
- Selecting individual hives marks the bundle partial, because other hives
  (including other users' NTUSER.DAT) may exist.

### NTFS $MFT and USN journal

`pack-artifacts --ntfs-mft <copy of $MFT>` and `--ntfs-usn-journal <copy of
$UsnJrnl:$J>` add one volume's file-system metadata (one of each per bundle).
Obtain the copies with your own acquisition tooling; the packager only reads the
paths you supply. `--ntfs-volume C:` records which drive the copies came from.
Without it, each link records an assumption that the $MFT describes the drive
letter in the event's image path. Both files are streamed, never loaded whole.
They count toward the shared 64 MiB bundle budget unless the operator passes
`--allow-large-ntfs` to both `pack-artifacts` and `investigate`. That option
allows up to 8 GiB per NTFS member and does not raise any other limit.

```powershell
python -m triage_engine.cli pack-artifacts --ntfs-mft C:\Evidence\C\$MFT --ntfs-usn-journal C:\Evidence\C\$J --ntfs-volume C: --allow-large-ntfs --host CLIENT-HOST --observed-at 2026-10-02T12:00:00Z --output-dir .\runtime\output\ntfs-bundle

python -m triage_engine.cli investigate --evtx C:\Evidence\Events --artifacts .\runtime\output\ntfs-bundle --allow-large-ntfs --case ntfs-chronology
```

The parser checks each record's FILE signature, header bounds and fixup array.
Damaged records are skipped and counted, and the bundle is marked partial.
Records of 1,024 and 4,096 bytes are supported, and up to 4 million records are
indexed. The index is columnar and holds the parent reference, sequence number,
times and names that correlation needs, not the records. Paths are rebuilt from
each name's parent reference and sequence number, up to 255 levels. A missing
or reused parent, a parent that is not a directory, a cycle or excess depth marks
the record as an orphan with that reason, and orphans are never linked. Every
non-DOS name is indexed, so hard links resolve. Names in extension records
belong to their base record.

Timestamps keep their meaning and are never merged. Each linked file produces
two `ntfs_file` observations from the current $MFT state:
`mft_standard_information` ($SI, which user-mode tools can change, so it may be
timestomped) and `mft_file_name` ($FN for that name, harder but not impossible
to alter). Each file's details compare the two: $SI creation earlier than $FN
creation, and every $SI time a whole second while $FN times are not. Only the
whole-second pattern is listed case-wide, up to 5,000 records, even without
events. On a real Windows 11 volume about 4% of files (129,322) had an earlier
$SI creation from installers, servicing and archive extraction, and none had the
whole-second pattern, so the earlier creation is counted in a warning but not
listed. Neither pattern is proof.

USN journal records (V2 and V3; V4 range records are counted) become
`usn_change` observations with `usn_journal_record` time and decoded reason
flags. Sparse and zero-filled regions are skipped. Malformed regions are
resynchronised on 8-byte boundaries and counted. Only FILE_CREATE records are
indexed; every record contributes to reason counts and the journal's time range.
Journal paths are resolved against the current $MFT, so a later rename changes
the shown path. The journal rolls over, so a missing record proves nothing.

The `process_image_matches_file_record` rule links Sysmon 1 / 4688 images to
the $MFT record at the same full path, as an observed field match. It also
links a journal FILE_CREATE for that file from one hour before to 5 s after the
process event as a supported inference. That needs one candidate with the same
file reference number; otherwise the link is a weak association. A file record
created after the process, a deleted record, or an $SI creation time earlier
than the journal's are shown as contradictions. A file record at the path is
context only and never raises a cross-source finding; a journal-creation link
to an alerted process can. Coverage lists record, orphan, fixup and journal
counts under `ntfs_mft` and `usn_journal`.

`scripts/benchmark_ntfs_parse.py` measures throughput and memory on a synthetic
1-million-record $MFT and writes the note to `runtime/test-output/`. On the
development machine (Python 3.13, Windows 11), 1 million $MFT records parsed at
about 37,000 records/s with a 131 MiB peak Python heap. 1 million USN records
parsed at about 49,000 records/s with 20 MiB. Real volumes with longer names or
more hard links use more memory per record.

## Executable inventory

Links need process-creation events, which many hosts never record. The
inventory works from the artifacts alone: `executable_inventory.json` joins
Prefetch runs, Amcache entries, services, Run keys and task commands, and $MFT
records per volume-relative executable path. Prefetch supplies the full path it
loaded the program from; `%SystemRoot%`-style commands are expanded with the
default Windows layout, and each expansion is listed as an assumption.

Each executable lists the observations it was built from and the reasons it may
deserve a look, each with what it does not establish: a core Windows program's
name outside the Windows directories; a recorded run or a persistence entry
whose file is no longer on disk; a run from a temporary or user-writable folder;
persistence from a user-writable folder; a file created in the 7 days before
collection that ran, outside Program Files and Windows. A missing Amcache
publisher only adds weight to another reason. An absent file with a present copy
whose path differs only in a version, build or hash folder is marked as
superseded instead of absent. The reasons are leads: they are not alerts and do
not change the verdict. The Evidence tab lists the ranked executables, and
`/api/cases/{case}/executable-inventory` serves them.

On one Windows 11 workstation (3,031 executables) the first version flagged 501;
every "ran but gone" executable was an updated program, and 480 flags were
developer tools without a publisher. Those findings set the rules above.

The HTML report embeds every alert-derived timeline row and at most 1,000
artifact rows, linked ones first; `timeline.json` keeps every row.

## What comes next

The current execution/download adapters establish the source and observation
contract. Next add hash-based file links, then explicit analyst
pivots and independently corroborated cross-source relationships. Each adapter
needs documented time semantics, malformed-input fixtures, and representative
benign/attack validation before broader correlation. Registry transaction-log
replay, memory, disk images, external collector import, and engagement
access control remain later phases in the
[architecture audit](audits/2026-10-02-architecture-audit.md).

No live collector run, installer/container acceptance, or field investigation
is implied by synthetic intake tests and PowerShell syntax validation.
