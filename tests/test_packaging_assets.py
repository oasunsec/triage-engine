from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_windows_build_assets_exist_and_share_payload_contract():
    build = (ROOT / "scripts" / "build-windows.ps1").read_text(encoding="utf-8")
    spec = (ROOT / "packaging" / "corrobora.spec").read_text(encoding="utf-8")
    launcher = (ROOT / "scripts" / "launch-corrobora.ps1").read_text(encoding="utf-8")

    assert "packaging\\corrobora.spec" in build
    assert "--distpath $distPath" in build
    assert "Corrobora.exe" in launcher
    assert '"127.0.0.1"' in launcher
    assert '"static", "rules", "config"' in spec
    assert "ConvertTo-TriageProcessArgument" in launcher
    assert "CommonApplicationData" in launcher
    assert "expected payload" in build
    assert "Refusing -Clean" in build


def test_installer_preserves_durable_state():
    installer = (ROOT / "packaging" / "corrobora.iss").read_text(encoding="utf-8")

    assert "{commonappdata}\\Corrobora\\data" in installer
    assert "{commonappdata}\\Corrobora\\cases" in installer
    assert "[UninstallDelete]" in installer
    assert "Name: \"{commonappdata}" not in installer.split("[UninstallDelete]", 1)[1]


def test_documentation_describes_offline_runtime_and_upgrade_safety():
    docs = (ROOT / "docs" / "windows-packaging.md").read_text(encoding="utf-8")

    for phrase in ("PyInstaller", "Inno Setup", "127.0.0.1", "No Python installation is needed", "survive uninstall"):
        assert phrase in docs
