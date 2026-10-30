# EVTX corpus coverage scan

- Samples total: **278**  - Completed: **276**  - Failed: **2**  - Skipped (unprovenanced): **0**
- Techniques with path hints: **44**  - Techniques detected: **74**  - Techniques missed: **17**

## Top 25 worklist rows

| Technique | Status | Path hints | Signal samples | Finding samples |
| --- | --- | ---: | ---: | ---: |
| T1068 | missed | 66 | 0 | 0 |
| T1078 | missed | 58 | 0 | 0 |
| T1046 | missed | 12 | 0 | 0 |
| T1021.004 | missed | 5 | 0 | 0 |
| T1574.002 | missed | 2 | 0 | 0 |
| T1558 | missed | 1 | 0 | 0 |
| T1059 | covered | 58 | 8 | 8 |
| T1021 | covered | 47 | 0 | 0 |
| T1003 | covered | 42 | 0 | 0 |
| T1562 | covered | 37 | 0 | 0 |
| T1218 | covered | 14 | 0 | 0 |
| T1218.005 | covered | 14 | 5 | 5 |
| T1003.001 | covered | 13 | 18 | 17 |
| T1021.001 | covered | 13 | 3 | 2 |
| T1059.003 | covered | 13 | 17 | 17 |
| T1018 | covered | 12 | 4 | 4 |
| T1059.001 | covered | 9 | 2 | 2 |
| T1047 | covered | 7 | 6 | 6 |
| T1505.001 | covered | 7 | 3 | 3 |
| T1021.002 | covered | 6 | 12 | 12 |
| T1127 | covered | 4 | 1 | 1 |
| T1197 | covered | 4 | 5 | 5 |
| T1021.003 | covered | 3 | 1 | 1 |
| T1021.006 | covered | 3 | 1 | 1 |
| T1505 | covered | 3 | 0 | 0 |

## Failed samples

- Credential Access/CA_PetiPotam_etw_rpc_efsr_5_6.evtx -- engine_error -- TimeoutError: Investigation exceeded timeout (180s) during stage 'parse'.
- Execution/Sysmon_Exec_CompiledHTML.evtx -- engine_error -- OSError: [Errno 22] Invalid argument: '<repo>\\tmp\\full-corpus-cases\\Execution-Sysmon_Exec_CompiledHTML.evtx-c139f692\\findings.json'

