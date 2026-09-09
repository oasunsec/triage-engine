# Quality Gates

These checks run before a public release.

## Inputs

- `production_readiness.json`
- `competitive_eval.json`
- `config/release_gate.json`
- `config/release_gate.ci.json`

## Run locally

```powershell
python .\scripts\release_gate.py --config .\config\release_gate.json
```

For GitHub Actions, use the CI policy:

```powershell
python .\scripts\release_gate.py --config .\config\release_gate.ci.json --strict
```

## CI checks

The workflow in `.github/workflows/quality-gates.yml` runs:

1. `python -m unittest tests.test_api`
2. `python -m unittest tests.test_performance`
3. `python scripts/competitive_eval.py --manifest config/benchmark/corpus.json --report competitive_eval.json --skip-hayabusa --fail-on-expectation`
4. `python scripts/production_readiness.py`
5. `python scripts/release_gate.py --config config/release_gate.ci.json --strict --report release_gate.json`

The CI policy does not require a private `config/tuning/local.json` file on a clean GitHub runner.

## Targets

- Malicious incident coverage: at least 0.90
- Malicious finding coverage: at least 0.95
- Benign incident rate: no more than 0.05
- Benign finding rate: no more than 0.10
- Expected sample failures: 0

Performance should stay within the project threshold for the environment. Runtime should not regress between benchmark waves without a documented reason.

If Hayabusa comparison is enabled, apply the runtime-ratio threshold in the release-gate configuration.

## Promotion rules

Do not promote a release when any required check fails:

- Readiness status is not accepted
- The validation suite fails
- Local tuning is not configured
- The Sigma pack is below its minimum
- Competitive thresholds are below target

## If a check fails

1. Stop detector promotion.
2. Review the failed check in `release_gate.json`.
3. Fix the detector, tuning, or test.
4. Run the benchmark and gate again.

## Keep thresholds honest

- Keep thresholds in version control.
- Raise thresholds gradually after two stable pass cycles.
- Do not relax thresholds to hide a regression.
