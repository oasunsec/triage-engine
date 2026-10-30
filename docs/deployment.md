# Deployment and release verification

The supported deployment unit is one application process with persistent local
SQLite databases and case directories. The dashboard is an investigation tool;
a low-signal result is not proof that a host is safe. Validate detection and
collection coverage against your own clean and malicious evidence.

## Run the revised workspace

Install Python 3.10+ and the repository dependencies:

```bash
python -m venv .venv
# Activate .venv using your shell's activation command.
python -m pip install -e ".[server,sigma,test]"
python server.py
```

Open `http://127.0.0.1:8000`. The dashboard ships its HTML, CSS, and JavaScript in
`static/`; there is no Node build step and no external font or script dependency.
The `/assets/` route serves only the four named frontend files. Deploy all four
together with `dashboard.html`. The Windows packaging spec includes this folder.

## Container permissions and persistence

The image uses UID/GID `10001:10001`. Compose keeps the existing `./data` and
`./cases` bind mounts to preserve upgrade compatibility. Image ownership cannot
override host bind-mount permissions.

For a Linux host, run as the non-root account responsible for the application:

```bash
mkdir -p data cases
export TRIAGE_CONTAINER_UID="$(id -u)"
export TRIAGE_CONTAINER_GID="$(id -g)"
test -w data && test -w cases
docker compose up --build -d
docker compose ps
```

Keep those UID/GID values in the deployment's environment on subsequent starts.
Compose stages uploads in `/app/data/uploads`, inside that same writable mount.
If an earlier container wrote files as root, have the host administrator grant
the service account access to those existing files. Do not replace or empty the
directories to resolve a permission error. Docker Desktop manages bind access
through its VM; verify that the shared folders are writable there too.

Compose drops Linux capabilities, prevents privilege escalation, limits process
count, and checks `/api/health`. Its port mapping is loopback-only. Validate
bootstrap, an investigation, a case bundle export, a restart, and continued
access to the same case before accepting a host installation.

Local `.env` files, private tuning, generated evidence, and development outputs
are excluded from the image. Supply deployment environment variables explicitly;
mount a reviewed local tuning file at `/app/config/tuning/local.json:ro` when used.
The Windows distribution also excludes the developer's local tuning profile.

## Remote access

Use a maintained TLS reverse proxy and explicitly configure the trusted host,
allowed origins, and secure-cookie settings documented in `configuration.md`.
Keep the application listener behind that proxy. Set `TRIAGE_SECURE_COOKIES=1`
for HTTPS deployments and restrict local-path investigation roots. Do not use
multiple Uvicorn workers: job execution, admission controls, and Quick Check
capability tokens include process-local state. Separate installations need an
explicitly designed shared scheduler and identity/storage model.

Responses forbid framing, MIME sniffing, and referrer disclosure. Authenticated
API data and dashboard responses use `Cache-Control: no-store`; static assets
revalidate. The CSP restricts framing, objects, and base URLs. Legacy inline
event handlers remain, so this is not a strict script-source CSP deployment.

## Upgrade and rollback

1. Stop intake and let running investigations finish.
2. Back up the SQLite state using `scripts/backup_restore.py`; separately back
   up the complete case directory. Preserve the previous application version.
   Backups use SQLite's backup API to include committed WAL data and include
   `product.db` when present. Each database is consistent individually; the
   set is not a single cross-database transaction. Stop writes when a matching
   snapshot across all databases is required.
3. Deploy the code and all frontend assets together, retaining the same data
   directories and permissions.
4. Confirm login, review history, timeline filtering, export, and restart
   persistence against a known case.
5. If validation fails, stop the new process and restore the matching previous
   application plus backup. Do not restore SQLite files while a process is
   using them.
   The CLI requires `--service-stopped` after all application processes and
   database clients are stopped. Restore validates and stages all files first,
   then replaces them individually; an OS failure during replacement can still
   require recovery from the preserved backup. Legacy three-database backups
   do not restore a newer installation's `product.db`.

At single-process startup, queued/running jobs from the previous process are
marked failed/interrupted. Their upload directories remain available for an
operator rerun. Completed case output is preserved; automatic requeue is not
supported. Use `TRIAGE_ENV_FILE` to select an explicit environment file instead
of the project `.env`/`.env.txt` defaults, including an absent file for isolated
verification.

## Acceptance checks

```bash
python -m pip install pytest
python -m pytest tests -q
python scripts/production_readiness.py --strict --report output/readiness.json
```

The readiness gate now includes the API, workflow, parser availability, asset
delivery, and packaging checks. Strict mode fails when local tuning or reviewed
Sigma content is missing even if code validation passes. This is a candidate
gate; it does not certify host security, signing, or environment accuracy.

For browser checks, install Playwright and its Chromium browser in a development
environment, start an isolated server with temporary `TRIAGE_DATA_DIR` and
`TRIAGE_CASES_DIR`, and place a known fixture case in that case directory. Set
`TRIAGE_E2E_URL`, `TRIAGE_E2E_USERNAME`, and `TRIAGE_E2E_PASSWORD`, then run
`node scripts/check_workspace.cjs`. Only set `TRIAGE_E2E_ALLOW_BOOTSTRAP=1` for a
disposable first-run database. Never point this script at a production account.
It saves screenshots and a machine-readable check report under
`output/workspace-check/`.

Before broader rollout, also validate a signed Windows build on a clean machine,
live collection/UAC on supported Windows versions, Docker on the target host,
backup restoration, TLS/proxy behavior, and local clean-case tuning. No installer
signature, remote deployment, or production tuning profile is created by the
workspace revamp.

## Design references

The interface organizes evidence and review around the investigation sequence
described in [Elastic's investigation documentation](https://www.elastic.co/docs/solutions/security/investigate).
Search, filtering, table actions, and progressive disclosure follow the concepts
in [Carbon's data-table guidance](https://carbondesignsystem.com/components/data-table/usage/).
The resulting layout is an original implementation for this engine.
