# Production Readiness Guide

This guide is the shortest path from a validated investigation engine to a controlled production rollout.

## Current Standard

Use the engine in this order:

1. Native detectors remain the primary detection path.
2. Sigma is optional and additive.
3. Sigma matches stay `signal_only` until local tuning is proven on clean data.

## Production Gate

Run the readiness check:

```powershell
python .\scripts\production_readiness.py
```

The script writes `production_readiness.json` in the project root and reports one of these states:

1. `not_ready`
2. `pilot_ready_missing_sigma_pack`
3. `pilot_ready_needs_local_tuning`
4. `production_candidate`

`production_candidate` means:

1. Core malicious and benign validation suites passed.
2. Sigma unit and CLI smoke tests passed.
3. A non-empty local tuning profile exists in `config/tuning/local.json`.

## False-Positive Narrowing Loop

Use this loop every time you change tuning:

1. Pick 3-5 clean EVTX cases from your environment.
2. Run `triage investigate` with your current tuning.
3. Review `summary.txt`, `incident_brief.md`, and `findings.json`.
4. If the case is large, use `raw_events.jsonl` for the full raw-event stream and treat the raw tab in `report.html` as a responsive preview.
5. Watch `run_status.json` during large EVTX folder runs. `parse_profile` shows the file set and executor choice, and `parse_progress` confirms file-by-file forward progress.
5. Focus on:
   - `Campaign Summary`
   - `Top Rule Metrics`
   - `Tuning Recommendations`
6. Add only exact allowlists or tightly-scoped wildcard/path-based suppressions you can verify.
7. Re-run:

```powershell
python .\scripts\production_readiness.py
```

7. Confirm the malicious suite is still green and clean cases did not gain findings or incidents.

## Safe Tuning Rules

Prefer:

1. Exact process paths
2. Exact service names
3. Exact scheduled task names
4. Exact known admin accounts
5. Narrow wildcard matches for versioned vendor services or installer paths when an exact string is not stable

Avoid:

1. Broad host allowlists
2. Broad domain-wide user suppressions
3. Global suppression of high-confidence rules
4. Promoting Sigma content directly into findings without correlation

## Sigma Rollout

Before broader Sigma use:

1. Keep Sigma enabled only with reviewed rule folders.
2. Confirm CLI smoke testing still passes:

```powershell
python -m unittest tests.test_sigma_support tests.test_sigma_cli_e2e
```

3. Review Sigma hits in `findings.json` and confirm they appear as `rule_source = "sigma"` and `promotion_policy = "signal_only"`.
4. For larger investigations, confirm `report.html` renders from the raw-event preview and `raw_events.jsonl` is present for full-fidelity review.
5. Promote only after the local tuning profile is stable.

## Recommended Rollout Sequence

1. Pilot on clean and mixed internal EVTX cases.
2. Tune false positives with `config/tuning/local.json`.
3. Re-run readiness check.
4. Enable a small reviewed Sigma pack.
5. Run shadow mode against a larger internal batch.
6. Freeze a production tuning baseline.
7. Only then broaden routine usage.

## Competitive Gate Layer

After readiness is green, run benchmark and release gate checks:

```powershell
python .\scripts\competitive_eval.py --manifest .\config\benchmark\corpus.json --report .\competitive_eval.json --fail-on-expectation
python .\scripts\release_gate.py --config .\config\release_gate.json --strict --report .\release_gate.json
```

Use this layer to track malicious coverage, benign noise rates, and runtime trends before promotion.
