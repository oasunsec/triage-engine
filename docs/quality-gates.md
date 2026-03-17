# Quality Gates

This document defines the quality gates and service-level targets used to keep the public release healthy.

## Gate Inputs

1. `production_readiness.json`
2. `competitive_eval.json`
3. `config/release_gate.json`
4. `config/release_gate.ci.json`

Gate execution:

```powershell
python .\scripts\release_gate.py --config .\config\release_gate.json
```

For GitHub Actions, use the CI policy:

```powershell
python .\scripts\release_gate.py --config .\config\release_gate.ci.json --strict
```

## CI Enforcement

Merge-blocking automation is implemented in:

1. `.github/workflows/quality-gates.yml`

The workflow enforces:

1. `python -m unittest tests.test_api`
2. `python -m unittest tests.test_performance`
3. `python scripts/competitive_eval.py --manifest config/benchmark/corpus.json --report competitive_eval.json --skip-hayabusa --fail-on-expectation`
4. `python scripts/production_readiness.py`
5. `python scripts/release_gate.py --config config/release_gate.ci.json --strict --report release_gate.json`

The CI policy keeps the public workflow strict on validation and benchmark quality without requiring a private `config/tuning/local.json` file to exist on clean GitHub runners.

## Default Quality SLOs

1. Malicious incident coverage: >= 0.90
2. Malicious finding coverage: >= 0.95
3. Benign incident rate: <= 0.05
4. Benign finding rate: <= 0.10
5. Expected sample failures: 0

## Performance SLOs

1. Average triage runtime per sample should stay under a defined threshold (environment-specific).
2. Runtime trends should not regress wave-over-wave without documented reason.

If Hayabusa comparison is enabled, include runtime ratio threshold in the release-gate config.

## Promotion Rules

Promotion is blocked when any required check fails:

1. Readiness status not accepted.
2. Validation suite failing.
3. Local tuning not configured.
4. Sigma pack below required minimum.
5. Competitive thresholds below target.

## Escalation

When a gate fails:

1. Stop detector promotion.
2. Review failed check(s) in `release_gate.json`.
3. Patch detector/tuning/tests.
4. Re-run benchmark and gate until pass.

## Governance Notes

1. Keep gate thresholds in version control.
2. Raise thresholds gradually after two stable pass cycles.
3. Avoid relaxing thresholds to hide regressions.
