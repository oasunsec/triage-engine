# Detection coverage audit

`scripts/coverage_audit.py` produces a deterministic JSON and Markdown
inventory of ATT&CK techniques represented in the detectors. It is a coverage
measurement tool, not an assertion that every ATT&CK technique or attack
variant is detected.

Run it from the repository root:

```powershell
python scripts/coverage_audit.py `
  --external-evtx-root .\repo_cache\sbousseaden_EVTX-ATTACK-SAMPLES `
  --external-evtx-root .\repo_cache\mdecrevoisier_EVTX-to-MITRE-Attack `
  --validation-report .\audit-artifacts\public-corpus-retuned.json `
  --validation-report .\audit-artifacts\public-corpus-expansion.json `
  --validation-report .\audit-artifacts\full-public-corpus-scan-final-tight.json `
  --annotations .\config\coverage\windows-evtx-limitations.json `
  --json-out audit-artifacts\detection-coverage.json `
  --markdown-out audit-artifacts\detection-coverage.md `
  --strict
```

The default scan includes every `config/benchmark/*.json` manifest. `--strict`
returns exit code 2 if a required malicious or benign benchmark input is absent,
or if a selected manifest is invalid. This makes it safe to add as a release
gate without executing an investigation.

The report records these evidence states per technique:

- `mapped`: an ATT&CK ID was found in a detector.
- `telemetry_supported`: the same detector function compares a Windows event
  ID. It is a narrow code-evidence signal, not proof that every implementation
  variant is observable.
- `validated_synthetic`: a synthetic test or benchmark explicitly names the
  technique.
- `validated_public_EVTX`: a completed, passed `competitive_eval.py` report
  explicitly names the technique for a recognized public EVTX corpus sample.
- `benign_regression`: an explicitly named benign/quiet test or benchmark
  exists.
- `telemetry_gap` and `not_event_log_observable`: explicit states supplied by
  an optional annotation JSON, so known blind spots remain visible rather than
  silently looking unsupported.

Availability of a public `.evtx` file is intentionally reported separately
from validation. Passing a file through the engine and retaining a completed
benchmark report is required before it becomes `validated_public_EVTX`.
Only passed samples whose expected disposition is `malicious` establish this
state; benign controls measure noise but do not prove attack detection.

Public corpora are kept under the ignored `repo_cache` directory and are never
bundled into the product. `config/benchmark/corpus.json` is the stable gate,
while `config/benchmark/corpus_expansion.json` contains the second-corpus gap
probes. Informational samples deliberately exercise supporting evidence and
known telemetry/parser gaps without requiring an incident promotion.

## Optional coverage annotations

Use an annotation document only for a documented judgment that cannot be
derived safely from source code:

```json
{
  "techniques": {
    "T0000": { "telemetry_gap": true },
    "T0001": { "not_event_log_observable": true }
  }
}
```

Pass its path with `--annotations`. Annotation files should be reviewed with
the relevant telemetry and threat-model evidence; they never create a mapped
or validated state.
