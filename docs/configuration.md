# Configuration Reference

This document lists the main environment variables used by the Triage Engine runtime.

Relative paths are resolved from the repository root.

## Server Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIAGE_HOST` | `127.0.0.1` | API bind address when running `python server.py`. |
| `TRIAGE_PORT` | `8000` | API bind port when running `python server.py`. |
| `TRIAGE_DATA_DIR` | `./data` | Root directory for SQLite state (`auth.db`, `reviews.db`, `jobs.db`) and backups. |
| `TRIAGE_CASES_DIR` | `./cases` | Root directory for generated case artifacts. |
| `TRIAGE_MAX_UPLOAD_MB` | `500` | Maximum upload size per EVTX file (MiB). |
| `TRIAGE_CORS_ORIGINS` | `localhost` | Comma-separated CORS origins. `localhost` expands to `http://localhost:<TRIAGE_PORT>` and `http://127.0.0.1:<TRIAGE_PORT>`. |
| `TRIAGE_SECURE_COOKIES` | `false` | Force `Secure` session cookie flag (`true/false`). |
| `TRIAGE_CSRF_SECRET` | random per process | Optional fixed CSRF HMAC secret for multi-instance consistency. |
| `TRIAGE_QUEUE_SYNC_INTERVAL_SECONDS` | `30` | Minimum seconds between automatic queue-index sync checks. |
| `TRIAGE_RUNTIME_MODE` | `local` | Runtime label shown in the dashboard (`local` or `docker`). |

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
| `TRIAGE_WEBHOOK_CONFIG` | `./config/webhooks.json` | Optional override path for webhook endpoint config file. |

## Regression Harness

These variables are used by dataset regression tests and are not required for normal runtime use.

| Variable | Default in tests | Description |
|----------|------------------|-------------|
| `TRIAGE_MALICIOUS_EVTX_DIR` | unset | Malicious sample directory for regression runs. Example: `C:\\path\\to\\malicious-logs`. |
| `TRIAGE_CLEAN_EVTX_DIR` | unset | Benign or clean sample directory for regression runs. Example: `C:\\path\\to\\clean-logs`. |
| `TRIAGE_ATTACK_SAMPLE_DIR` | unset | ATT&CK sample directory for regression runs. Example: `C:\\path\\to\\attack-samples`. |
| `TRIAGE_LOCAL_SAM_ADMIN_SAMPLE` | unset | Optional override for a specific local-SAM regression sample path. |
