# Collector ingest

Getting evidence off a machine is usually the slowest part of triage: someone collects by
hand, copies files around and starts the analysis by hand. The collector can send its output
straight to a triage server instead. The server checks the upload and opens the case itself.

## Flow

1. **Issue a token.** An admin opens *User access → Collector Tokens* in the dashboard (or calls
   `POST /api/ingest-tokens` with `{"name": "..."}`). The token (`tri_…`) is shown once.
   Only its SHA-256 hash is stored.
2. **Collect and send.** On the machine under investigation, run this from an elevated PowerShell:

   ```powershell
   .\scripts\collect-windows-evidence.ps1 -OutputDirectory D:\triage\host-01 `
       -ServerUrl https://triage.example.internal -IngestToken tri_... [-CaseName host-01-ir]
   ```

   The collector works as before. It reads only, writes `collection_manifest.json` with a SHA-256
   for every file and builds the artifact bundle. It then zips the folder to `<OutputDirectory>.zip`
   and streams the zip to `POST /api/ingest/collection` with the token as a Bearer credential.
   The local folder and zip are kept as the responder's copy.
3. **Server checks.** The server refuses the archive if any of these fail:
   - The token is valid and has not been revoked.
   - The upload is within `TRIAGE_MAX_INGEST_MB`, and it expands to no more than four times that.
   - Every entry is a plain file or folder under the collector's own layout (`logs/`, `prefetch/`,
     `hives/`, `tasks/`, `ntfs/`, `bundle/`, `collection_manifest.json`). Absolute paths, `..`,
     drive letters and links are refused.
   - Every file listed in the manifest is present and matches its SHA-256.
   - The artifact bundle passes its own manifest checks when the investigation loads it.
4. **Case opens.** The server queues an investigation of the event logs plus the artifact bundle.
   The case records the collection manifest: source host, time, file hashes, and which collection
   steps failed.

## What it does not do

- It never reaches out to an endpoint. Collection is started by a person on that machine. The
  server only receives.
- Tokens allow uploads and nothing else. They cannot read cases, start other investigations
  or sign in to the dashboard.
- A failed collection step (for example no raw NTFS access) does not block the upload. It is
  recorded on the case so a reviewer can see what was not collected.

## Audit

Each token creation, revocation and upload is written to the admin audit log as
`create_ingest_token`, `revoke_ingest_token` and `ingest_collection`. Upload entries record the
token, host, byte count, number of files verified and number of failed steps. The token list shows
each token's use count and when it was last used.

## Transport

Put the server behind TLS (see [deployment.md](deployment.md)) before collectors send evidence
over a network. Bearer tokens and evidence must not cross an untrusted network in plain HTTP.
