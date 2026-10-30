# Windows packaging

Triage Engine ships as a local-first Windows application with two distribution forms:

- **Portable**: a PyInstaller one-directory payload that can be copied to a field laptop or removable media.
- **Installer**: an Inno Setup installer built from the same portable payload.

Both forms bundle the Python runtime and launch the existing local web dashboard on `127.0.0.1`. No Python installation is needed on an end-user machine. Durable state is kept outside the application directory so upgrades and uninstall do not remove cases or authentication data.

## Build

Build on Windows with Python 3.10+ and the project server extras installed. The build script does not install dependencies:

```powershell
python -m pip install -e ".[server,sigma,live]"
python -m pip install pyinstaller
.\scripts\build-windows.ps1 -Clean
```

The portable payload is written to `dist-windows/portable/TriageEngine`. To also create the installer, install Inno Setup and run:

```powershell
.\scripts\build-windows.ps1 -Clean -BuildInstaller
```

The build script uses `ISCC.exe` from `PATH` or the standard per-user/machine Inno Setup 6 installation paths. For a reproducible build, use a pinned Python environment and build from a clean checkout; PyInstaller receives the same spec and staged source directories in every build.

## Running

Run `launch-triage.ps1` from the payload directory. It sets `TRIAGE_HOST=127.0.0.1`, chooses an available durable data location, starts the bundled `TriageEngine.exe`, and opens the browser. `-NoBrowser` is useful for scripted smoke tests and `-Wait` keeps the launcher attached.

Installed mode uses `%ProgramData%\TriageEngine\data` and `%ProgramData%\TriageEngine\cases`. Portable mode defaults to `%LOCALAPPDATA%\TriageEngine\data` and `%LOCALAPPDATA%\TriageEngine\cases`; override either location with `TRIAGE_DATA_DIR` or `TRIAGE_CASES_DIR`.

### Quick Check

The dashboard's **Start Check** action is intended for a non-technical user. It
uses a short-lived loopback token rather than requiring an analyst account, runs
the fixed recent-activity profile, and presents a plain-language disposition.
Reading protected Security/Sysmon channels may trigger a Windows UAC prompt. If
permission is declined, no live scan is started and the user can instead supply
saved `.evtx` files to IT. The analyst console and generic case APIs remain
authenticated.

The launcher deliberately forces localhost even if a broader host was used during development. Do not expose the dashboard through a firewall rule or reverse proxy without applying the deployment hardening guidance. `launch-triage.ps1 -Elevated` is available for an explicitly administrator-run session; the Quick Check button requests elevation only when needed.

## Collection options

For a removable collection workflow, run `scripts/collect-windows-evtx.ps1` on
the endpoint and import the resulting directory through the Local Path mode.
For an explicitly authorized Windows PowerShell remoting workflow, use
`scripts/collect-remote-windows-evtx.ps1`; it prompts for credentials each run,
does not persist them, and emits the same versioned manifest. Review firewall,
WinRM, least-privilege, and host-allowlist policy before using remote mode.

## Optional AI summaries

The `/api/cases/{case_name}/ai-summary` endpoint is disabled unless the caller
sets explicit consent and supplies an HTTP(S) OpenAI-compatible endpoint. It
sends only deterministic case summaries, findings, and incidents; raw event
streams and review notes are excluded. AI output is marked assisted content and
cannot change findings, confidence, or disposition. Leaving the endpoint
unused preserves fully offline operation.

## Upgrade and uninstall

Inno Setup overwrites only files under `Program Files\Triage Engine`. The data and cases directories are created under `%ProgramData%` and are not listed in `[UninstallDelete]`. Therefore an upgrade preserves cases, jobs, reviews, users, and reports, and uninstall removes the executable payload while leaving evidence to survive uninstall for deliberate administrative cleanup.

## Verification without build tools

The repository test `tests/test_packaging_assets.py` validates the spec, launcher, installer safety properties, and build-script contracts without invoking PyInstaller or Inno Setup. CI can run these checks on non-Windows hosts. A Windows release job should additionally run the build script, launch with `-NoBrowser`, poll `http://127.0.0.1:8000/health`, and verify that a case created before upgrade remains available afterward.
