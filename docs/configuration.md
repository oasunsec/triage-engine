# Configuration Reference

This document lists the main environment variables used by the Corrobora runtime.

Relative paths are resolved from the repository root.

At startup the server loads a local `.env` file when present, or the existing
`.env.txt` file as a fallback. Process environment variables always take
precedence. These files are ignored by Git; never copy their secret values into
`.env.example` or case artifacts.

## Server Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `CORROBORA_HOST` | `127.0.0.1` | API bind address when running `python server.py`. |
| `CORROBORA_PORT` | `8000` | API bind port when running `python server.py`. |
| `CORROBORA_DATA_DIR` | `./data` | Root directory for SQLite state (`auth.db`, `reviews.db`, `jobs.db`) and backups. |
| `CORROBORA_CASES_DIR` | `./cases` | Root directory for generated case artifacts. |
| `CORROBORA_UPLOAD_DIR` | `./uploads` (packaged Windows: data directory's `uploads/`) | Temporary upload staging. Compose sets `/app/data/uploads` so it shares the writable data mount. |
| `CORROBORA_MAX_UPLOAD_MB` | `500` | Maximum upload size per EVTX file (MiB). |
| `CORROBORA_MAX_AGGREGATE_UPLOAD_MB` | `CORROBORA_MAX_UPLOAD_MB` | Maximum total size for one upload request (MiB). |
| `CORROBORA_MAX_INGEST_MB` | `12288` | Maximum size of one collector archive sent to `POST /api/ingest/collection` (MiB). See [collector-ingest.md](collector-ingest.md). |
| `CORROBORA_API_READ_LIMIT_PER_MINUTE` | `600` | API reads allowed per signed-in user per minute (writes: 120; anonymous: 60). |
| `CORROBORA_MAX_CONCURRENT_JOBS` | `2` | Maximum investigations executing concurrently. |
| `CORROBORA_MAX_QUEUED_JOBS` | `8` | Additional investigations admitted to the bounded queue. |
| `CORROBORA_ALLOWED_PATH_ROOTS` | unset | Absolute evidence roots for local-path investigations; required when `CORROBORA_HOST` is not localhost. |
| `CORROBORA_CORS_ORIGINS` | `localhost` | Comma-separated CORS origins. `localhost` expands to `http://localhost:<CORROBORA_PORT>` and `http://127.0.0.1:<CORROBORA_PORT>`. |
| `CORROBORA_SECURE_COOKIES` | `false` | Force `Secure` session cookie flag (`true/false`). |
| `CORROBORA_BOOTSTRAP_TOKEN` | unset | When set, creating the first admin requires this value. Set it before exposing a fresh install beyond loopback; startup warns if a network-bound server has no admin and no token. |
| `CORROBORA_TRUSTED_PROXIES` | unset | Comma-separated reverse-proxy IPs whose `X-Forwarded-For` is honored for audit logs, sessions and rate limits. Without it the header is ignored, so clients cannot spoof their address. |
| `CORROBORA_CSRF_SECRET` | random per process | Optional fixed CSRF HMAC secret for multi-instance consistency. |
| `CORROBORA_QUEUE_SYNC_INTERVAL_SECONDS` | `30` | Minimum seconds between automatic queue-index sync checks. |
| `CORROBORA_RUNTIME_MODE` | `local` | Runtime label shown in the dashboard (`local` or `docker`). |
| `CORROBORA_CASE_RETENTION_DAYS` | `90` | Days a new case is kept before an explicit purge is allowed (1-3650). |

## Session Controls

| Variable | Default | Description |
|----------|---------|-------------|
| `CORROBORA_SESSION_TTL_HOURS` | `12` | Session lifetime in hours (bounded to `1..72`). |
| `CORROBORA_SESSION_IDLE_HOURS` | `2` | Session idle timeout in hours (bounded to `1..72`). |

## Investigation Pipeline

| Variable | Default | Description |
|----------|---------|-------------|
| `CORROBORA_INVESTIGATION_TIMEOUT_SECONDS` | `1800` | Max wall-clock runtime per investigation before fail/timeout. |
| `CORROBORA_DETECTOR_TIMEOUT_SECONDS` | `30` | Max runtime per detector before timeout isolation. |
| `CORROBORA_DETECTOR_EXECUTOR` | `process` | Detector execution mode: killable `process` (default) or `thread` for test/embedding callables. |
| `CORROBORA_PARSE_EXECUTOR` | `serial` | EVTX directory parsing mode: `serial`, `thread`, or `process`. |
| `CORROBORA_PARSE_WORKERS` | `4` | Worker count used for threaded/process EVTX parsing modes. |
| `CORROBORA_RAW_XML_MODE` | `auto` | Raw XML preservation mode: `auto`, `all`, or `none`. |

## Demo And Screenshot Safety

| Variable | Default | Description |
|----------|---------|-------------|
| `CORROBORA_DEMO_REDACTION` | `0` | Enable public-demo masking for sensitive labels in dashboard/API views and case artifacts. |
| `CORROBORA_DEMO_REDACTION_VALUES` | unset | Comma-separated extra values to redact as `DemoValue` during screenshot/demo capture. |

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `CORROBORA_LOG_LEVEL` | `INFO` | Structured logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, ...). |
| `CORROBORA_LOG_FILE_ENABLED` | `0` | Enable rotating file sink in addition to stderr (`1` to enable). |
| `CORROBORA_LOG_FILE_PATH` | `<CORROBORA_DATA_DIR>/corrobora.log` | Log file destination when file logging is enabled. |
| `CORROBORA_LOG_FILE_MAX_BYTES` | `10485760` | Max size of each rotated log file (bytes). |
| `CORROBORA_LOG_FILE_BACKUP_COUNT` | `5` | Number of rotated log files to retain. |

## Regression Harness

These variables are used by dataset regression tests and are not required for normal runtime use.

| Variable | Default in tests | Description |
|----------|------------------|-------------|
| `CORROBORA_SAMPLE_ROOT` | `./sample_cache` | Base directory for the three sample directories below when they are not set. |
| `CORROBORA_MALICIOUS_EVTX_DIR` | `<CORROBORA_SAMPLE_ROOT>/logs` | Malicious sample directory for regression runs. Example: `C:\\path\\to\\malicious-logs`. |
| `CORROBORA_CLEAN_EVTX_DIR` | `<CORROBORA_SAMPLE_ROOT>/triage-logs` | Benign or clean sample directory for regression runs. Example: `C:\\path\\to\\clean-logs`. |
| `CORROBORA_ATTACK_SAMPLE_DIR` | `<CORROBORA_SAMPLE_ROOT>/EVTX Sample` | ATT&CK sample directory for regression runs. Example: `C:\\path\\to\\attack-samples`. |
| `CORROBORA_LOCAL_SAM_ADMIN_SAMPLE` | `<CORROBORA_ATTACK_SAMPLE_DIR>/Persistence/...` | Optional override for a specific local-SAM regression sample path. |

Tests that need a missing sample are skipped.
