# PyInstaller one-directory build for the local Windows distribution.
# Build with: pyinstaller --noconfirm packaging/triage-engine.spec

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


ROOT = Path(SPECPATH).parent

datas = []
for relative in ("static", "rules", "config", "scripts"):
    source = ROOT / relative
    if source.exists():
        # Include source assets but never generated evidence, benchmark case
        # outputs, caches, or local databases from a developer checkout.
        for file_path in source.rglob("*"):
            if not file_path.is_file():
                continue
            rel_path = file_path.relative_to(ROOT).as_posix()
            if rel_path == "config/tuning/local.json":
                continue
            if "/cases/" in f"/{rel_path}" or rel_path.endswith(".db") or rel_path.endswith(".sqlite"):
                continue
            datas.append((str(file_path), str(Path(rel_path).parent)))

# These packages are loaded by the API and optional Sigma/live paths at runtime.
hiddenimports = []
for package in ("triage_engine", "models", "parser", "detectors", "correlation", "reporting"):
    hiddenimports.extend(collect_submodules(package))
for package in ("fastapi", "starlette", "uvicorn", "multipart"):
    hiddenimports.extend(collect_submodules(package))
for package in ("yaml", "win32evtlog", "win32evtlogutil"):
    try:
        hiddenimports.extend(collect_submodules(package))
    except Exception:
        # Optional dependencies are supplied by the build environment when present.
        pass

datas.extend(collect_data_files("triage_engine"))

a = Analysis(
    [str(ROOT / "server.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=sorted(set(hiddenimports)),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    name="TriageEngine",
    exclude_binaries=True,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="TriageEngine",
)
