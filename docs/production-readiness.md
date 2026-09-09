# Production Readiness

Use this checklist before a pilot or routine use.

## Detection path

1. Built-in detectors are the main detection path.
2. Sigma rules are optional.
3. Keep Sigma matches as `signal_only` until they have been checked against clean data.

## Run the readiness check

```powershell
python .\scripts\production_readiness.py
```

The script writes `production_readiness.json` in the project root. It reports one of these states:

- `not_ready`
- `pilot_ready_missing_sigma_pack`
- `pilot_ready_needs_local_tuning`
- `production_candidate`

`production_candidate` requires:

- The malicious and benign validation suites pass
- Sigma unit and CLI smoke tests pass
- `config/tuning/local.json` contains a local tuning profile

## Tune false positives

1. Choose 3–5 clean EVTX cases from the environment.
2. Run `triage investigate` with the current tuning.
3. Review `summary.txt`, `incident_brief.md`, and `findings.json`.
4. For large cases, use `raw_events.jsonl` for the full event stream. The raw tab in `report.html` is a preview.
5. Watch `run_status.json` during large folder runs. `parse_profile` shows the file set and executor. `parse_progress` shows file-by-file progress.
6. Check the campaign summary, rule metrics, and tuning recommendations.
7. Add only exact or narrow suppressions that can be verified.
8. Run the readiness check again.
9. Confirm the malicious suite still passes and clean cases did not gain unexpected findings or incidents.

## Safe tuning

Prefer:

- Exact process paths
- Exact service names
- Exact scheduled task names
- Exact known admin accounts
- Narrow path or wildcard matches for versioned vendor files

Avoid:

- Broad host allowlists
- Domain-wide user suppressions
- Global suppression of high-confidence rules
- Promoting Sigma matches directly to findings without correlation

## Sigma rollout

Before using Sigma more broadly:

1. Enable only reviewed rule folders.
2. Run the Sigma checks:

```powershell
python -m unittest tests.test_sigma_support tests.test_sigma_cli_e2e
```

3. Review Sigma hits in `findings.json`.
4. Confirm Sigma hits show `rule_source = "sigma"` and `promotion_policy = "signal_only"`.
5. Promote Sigma matches only after local tuning is stable.

## Rollout order

1. Test clean and mixed internal EVTX cases.
2. Tune false positives in `config/tuning/local.json`.
3. Run the readiness check.
4. Enable a small reviewed Sigma pack.
5. Run shadow mode against a larger batch.
6. Freeze the tuning baseline before routine use.

## Final checks

After readiness passes, run the benchmark and release checks:

```powershell
python .\scripts\competitive_eval.py --manifest .\config\benchmark\corpus.json --report .\competitive_eval.json --fail-on-expectation
python .\scripts\release_gate.py --config .\config\release_gate.json --strict --report .\release_gate.json
```

Use these results to track detection coverage, benign noise, and runtime changes before release.
