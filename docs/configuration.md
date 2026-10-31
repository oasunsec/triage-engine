# Configuration Reference

This document lists the main environment variables used by the Triage Engine runtime.

Relative paths are resolved from the repository root.

At startup the server loads a local `.env` file when present, or the existing
`.env.txt` file as a fallback. Process environment variables always take
precedence. These files are ignored by Git; never copy their secret values into
`.env.example` or case artifacts.

## Server Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIAGE_HOST` | `127.0.0.1` | API bind address when running `python server.py`. |
| `TRIAGE_PORT` | `8000` | API bind port when running `python server.py`. |
| `TRIAGE_DATA_DIR` | `./data` | Root directory for SQLite state (`auth.db`, `reviews.db`, `jobs.db`) and backups. |
| `TRIAGE_CASES_DIR` | `./cases` | Root directory for generated case artifacts. |
| `TRIAGE_UPLOAD_DIR` | `./uploads` (packaged Windows: data directory's `uploads/`) | Temporary upload staging. Compose sets `/app/data/uploads` so it shares the writable data mount. |
| `TRIAGE_MAX_UPLOAD_MB` | `500` | Maximum upload size per EVTX file (MiB). |
| `TRIAGE_MAX_AGGREGATE_UPLOAD_MB` | `TRIAGE_MAX_UPLOAD_MB` | Maximum total size for one upload request (MiB). |
| `TRIAGE_MAX_CONCURRENT_JOBS` | `2` | Maximum investigations executing concurrently. |
| `TRIAGE_MAX_QUEUED_JOBS` | `8` | Additional investigations admitted to the bounded queue. |
| `TRIAGE_ALLOWED_PATH_ROOTS` | unset | Absolute evidence roots for local-path investigations; required when `TRIAGE_HOST` is not localhost. |
| `TRIAGE_CORS_ORIGINS` | `localhost` | Comma-separated CORS origins. `localhost` expands to `http://localhost:<TRIAGE_PORT>` and `http://127.0.0.1:<TRIAGE_PORT>`. |
| `TRIAGE_SECURE_COOKIES` | `false` | Force `Secure` session cookie flag (`true/false`). |
| `TRIAGE_BOOTSTRAP_TOKEN` | unset | When set, creating the first admin requires this value. Set it before exposing a fresh install beyond loopback; startup warns if a network-bound server has no admin and no token. |
| `TRIAGE_TRUSTED_PROXIES` | unset | Comma-separated reverse-proxy IPs whose `X-Forwarded-For` is honored for audit logs, sessions and rate limits. Without it the header is ignored, so clients cannot spoof their address. |
| `TRIAGE_CSRF_SECRET` | random per process | Optional fixed CSRF HMAC secret for multi-instance consistency. |
| `TRIAGE_QUEUE_SYNC_INTERVAL_SECONDS` | `30` | Minimum seconds between automatic queue-index sync checks. |
| `TRIAGE_RUNTIME_MODE` | `local` | Runtime label shown in the dashboard (`local` or `docker`). |
| `TRIAGE_EDITION` | `community` | Capability profile marker (`community` or `pro`); analysis remains local-first. |
| `TRIAGE_LICENSE_PATH` | unset | Optional local signed license JSON path. |
| `TRIAGE_LICENSE_SECRET` | unset | Offline verifier secret; keep outside case exports and source control. |

## Session Controls

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIAGE_SESSION_TTL_HOURS` | `12` | Session lifetime in hours (bounded to `1..72`). |
| `TRIAGE_SESSION_IDLE_HOURS` | `2` | Session idle timeout in hours (bounded to `1..72`). |

## Investigation Pipeline

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIAGE_INVESTIGATION_TIMEOUT_SECONDS` | `1800` | Max wall-clock runtime per investigation before fail/timeout. |
| `TRIAGE_DETECTOR_TIMEOUT_SECONDS` | `30` | Max runtime per detector before timeout isolation. |
| `TRIAGE_DETECTOR_EXECUTOR` | `process` | Detector execution mode: killable `process` (default) or `thread` for test/embedding callables. |
| `TRIAGE_PARSE_EXECUTOR` | `serial` | EVTX directory parsing mode: `serial`, `thread`, or `process`. |
| `TRIAGE_PARSE_WORKERS` | `4` | Worker count used for threaded/process EVTX parsing modes. |
| `TRIAGE_RAW_XML_MODE` | `auto` | Raw XML preservation mode: `auto`, `all`, or `none`. |

## Demo And Screenshot Safety

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIAGE_DEMO_REDACTION` | `0` | Enable public-demo masking for sensitive labels in dashboard/API views and case artifacts. |
| `TRIAGE_DEMO_REDACTION_VALUES` | unset | Comma-separated extra values to redact as `DemoValue` during screenshot/demo capture. |

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIAGE_LOG_LEVEL` | `INFO` | Structured logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, ...). |
| `TRIAGE_LOG_FILE_ENABLED` | `0` | Enable rotating file sink in addition to stderr (`1` to enable). |
| `TRIAGE_LOG_FILE_PATH` | `<TRIAGE_DATA_DIR>/triage-engine.log` | Log file destination when file logging is enabled. |
| `TRIAGE_LOG_FILE_MAX_BYTES` | `10485760` | Max size of each rotated log file (bytes). |
| `TRIAGE_LOG_FILE_BACKUP_COUNT` | `5` | Number of rotated log files to retain. |

## Integrations

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIAGE_WEBHOOK_CONFIG` | `./config/webhooks.json` | Optional webhook endpoint config path; relative paths resolve from the project root. |

Canonical webhook events are `case.completed`, `case.escalated`, and `bundle.exported`. Every payload includes `schema_version`, a stable `event_id`, `client_id`, `case_id`, `triage_disposition`, `confidence`, `confidence_score`, `summary`, and `artifact_ref`; legacy `investigation_completed` / `incident_p1` / `incident_p2` subscriptions remain supported as aliases. Retries are bounded (`max_attempts` up to 5, total backoff up to 15 seconds), and the entire dispatch for one event is capped at 45 seconds including per-attempt network timeouts. Endpoint URLs must be absolute `http` or `https` URLs without embedded credentials. Headers such as `X-Triage-Event`, `X-Triage-Event-ID`, and `X-Triage-Schema-Version` are generated by the engine and cannot be overridden in endpoint configuration; custom header names and values must be valid HTTP tokens so configuration cannot smuggle replacement lines.

## Regression Harness

These variables are used by dataset regression tests and are not required for normal runtime use.

| Variable | Default in tests | Description |
|----------|------------------|-------------|
| `TRIAGE_SAMPLE_ROOT` | `./sample_cache` | Base directory for the three sample directories below when they are not set. |
| `TRIAGE_MALICIOUS_EVTX_DIR` | `<TRIAGE_SAMPLE_ROOT>/logs` | Malicious sample directory for regression runs. Example: `C:\\path\\to\\malicious-logs`. |
| `TRIAGE_CLEAN_EVTX_DIR` | `<TRIAGE_SAMPLE_ROOT>/triage-logs` | Benign or clean sample directory for regression runs. Example: `C:\\path\\to\\clean-logs`. |
| `TRIAGE_ATTACK_SAMPLE_DIR` | `<TRIAGE_SAMPLE_ROOT>/EVTX Sample` | ATT&CK sample directory for regression runs. Example: `C:\\path\\to\\attack-samples`. |
| `TRIAGE_LOCAL_SAM_ADMIN_SAMPLE` | `<TRIAGE_ATTACK_SAMPLE_DIR>/Persistence/...` | Optional override for a specific local-SAM regression sample path. |

Tests that need a missing sample are skipped.
