# Real-evidence validation (2026-10-23)

The native parsers were first built and tested against synthetic files. This
pass ran them on one Windows 11 workstation's own artifacts (an Insider
build, a single NTFS system volume, 4 KiB clusters) and compared their output
with what the live system reports. It is one machine, not a corpus: it shows
the parsers read real files correctly, not that they cover every Windows build.

Artifacts were copied read-only by an administrator: Prefetch files, the SYSTEM,
SOFTWARE, NTUSER.DAT and Amcache.hve hives (through a temporary shadow copy),
the raw `System32\Tasks` folder, the Application, System, Security and
PowerShell/Operational logs, the volume's `$MFT`, and the allocated part of
`$UsnJrnl:$J`. Nothing from the workstation is committed; the regression tests
added from this pass use synthetic records with the same shape.

## Results by parser

| Parser | Input | Ground truth | Result |
| --- | --- | --- | --- |
| Native Prefetch | 60 `.pf`, all version 31 (compressed) | File name (executable + hash); file write time; `vol C:` serial | 60/60 parsed. Executable name and hash match every file name. Run-time count equals min(run count, 8) for every file. Last run is 0–10 s before the file's write time (Windows writes the trace about 10 s after launch). Volume serial matches. |
| Registry: NTUSER, SOFTWARE | Dirty hives (logs not replayed) | Live `HKCU`/`HKLM` Run and RunOnce keys | Every live value found, none extra (5 HKCU, 2 HKLM). Dirty-hive warning raised. |
| Registry: SYSTEM | 36 MB hive | Live `Services` subkey count, `Select\Current` | 866 of 866 services, current control set chosen correctly. |
| Registry: Amcache | 11 MB hive, 14,548 entries | Raw value listing | 12,039 entries (all written since 2026-07) hold only `FileId` and `ProgramId`, no name or path. The parser now reports these honestly (see fixes). |
| Task XML | 293 raw files | `Get-ScheduledTask` | Every task visible to a standard user has a file; all 98 executable actions match the parsed command (the API strips quotes the XML keeps). |
| `$MFT` | 3.3 GB, 3,229,696 records | `os.stat` on 1,500 files untouched for a day, sampled across the volume | 1,500/1,500 resolved to the right path; created and modified times match to 100 ns; sizes 1,500/1,500 after one fix (see below). 237 s, about 14 MB/s. |
| USN journal | 36 MB allocated of 66.8 GB logical; 348,960 records | Files created at known times during the test | 9 s. Create records match creation times exactly (0 s or 1 µs). Files rewritten by temp-file-and-rename differ by 16–52 s, which is NTFS file-name tunnelling, not a parser error. The journal covered only 71 minutes on this busy machine. |

## End to end

All 359 files went into one bundle (`--prefetch-source` and `--task-xml`
given as folders) and were investigated with the four event logs: 15 minutes,
26,126 observations, 7 configuration links. Before the fixes below, the event
logs alone gave this ordinary workstation P1 "Escalate" with 7 critical
findings; afterwards the result is P3 "Investigate" with two findings (a real
account lockout and a local group enumeration). The case folder is 4.3 GB
because the original `$MFT` is retained as verified evidence.

The workstation does not log process creation (no Sysmon, no 4688), so the
process-to-Prefetch and process-to-file link rules had nothing to match here.
Those rules remain tested on public EVTX samples paired with synthetic
artifacts only.

## Defects found and fixed

1. **PowerShell download cradle (false positive, critical).** PowerShell logs
   its own module manifests as event 4104 script blocks. The
   `Microsoft.PowerShell.Utility` manifest lists `'Invoke-WebRequest'` as a
   quoted export name and has a `HelpInfoURI`, which was enough for the
   cradle rule. Blocks that are only a literal module-manifest hashtable are
   now exempt; any command, pipeline, variable or subexpression keeps the rule
   active (`tests/test_workstation_benign.py`).
2. **Defender platform update (false positive, critical).** Defender
   reinstalls its services from
   `ProgramData\Microsoft\Windows Defender\Platform\<version>\`, a
   `ProgramData` path the service rules treat as user-controlled. The exact
   service name, binary and versioned folder must now all match; a lookalike
   name, path traversal or extra arguments still alert. This checks the path,
   not the binary's signature.
3. **Cross-source findings from routine service installs.** Seven links
   between 7045 events and the SYSTEM hive (Defender's driver, a VPN client)
   became "Suspicious configuration change" findings, two of them critical,
   although the underlying "Service Installed" alerts were deliberately not
   findings. A link now corroborates only alerts that lack corroboration; it
   cannot promote one rejected on its own terms (routine service install, weak
   evidence, explicit `signal_only`). The links remain as relationships.
4. **Amcache hash-only entries.** These now carry `key_name_hint` (at most the
   first 16 characters of the lowercase file name, from the key name) and a
   warning; `name` and `path` stay empty rather than guessed.
5. **`$MFT` data size from an earlier extension record.** When a file's
   unnamed `$DATA` lives in an extension record numbered below its base
   record, the size was dropped. It is now deferred until the base record is
   read, as file names already were.
6. **Bundle limits.** A bundle now accepts 1,024 members instead of 64 (this
   machine's Tasks folder alone held 293 files), and `--task-xml` and
   `--prefetch-source` accept folders, because 359 paths exceed the Windows
   command-line length limit. Byte budgets are unchanged.

## Not covered

- Only one machine and one Windows build. No Windows 10, Server, or other
  locale; no FAT/ReFS volumes; no 4Kn-sector disk.
- Hives were dirty and transaction logs are still not replayed.
- The PowerShell `remote_ip` field holds a host name when the URL has one;
  that convention is shared with the incident builder and was left unchanged.
- Detection accuracy is not measured: a clean machine producing few findings
  shows fewer false positives, not that attacks would be found.
