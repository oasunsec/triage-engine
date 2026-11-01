"""Live-scan artifact collection against a synthetic Windows folder; no host data or elevation needed."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tests.test_prefetch_binary import build_scca
from tests.test_registry_hive_artifacts import HiveWriter, system_spec
from tests.test_task_xml_artifacts import task_xml
from triage_engine.forensic_artifacts import read_forensic_bundle
from triage_engine.live_artifacts import collect_live_artifacts

OBSERVED = "2026-11-01T02:00:00+00:00"


def _windows(root: Path) -> tuple[Path, Path]:
    system_root, profile = root / "Windows", root / "Users" / "analyst"
    (system_root / "Prefetch").mkdir(parents=True)
    (system_root / "Prefetch" / "UPD.EXE-11223344.pf").write_bytes(build_scca())
    (system_root / "System32" / "Tasks" / "Vendor").mkdir(parents=True)
    (system_root / "System32" / "Tasks" / "Vendor" / "Updater").write_text(task_xml(), encoding="utf-16")
    (system_root / "System32" / "config").mkdir(parents=True)
    writer = HiveWriter()
    hive = writer.build(writer.tree(system_spec()))
    (system_root / "System32" / "config" / "SYSTEM").write_bytes(hive)
    (system_root / "System32" / "config" / "SYSTEM.LOG1").write_bytes(b"HvLE" + b"\x00" * 508)
    profile.mkdir(parents=True)
    return system_root, profile


def test_collects_prefetch_tasks_and_hives_into_a_verified_bundle(tmp_path):
    system_root, profile = _windows(tmp_path)
    copied = []

    def copy_locked(source: Path, destination: Path) -> None:
        copied.append(source.name)
        shutil.copyfile(source, destination)

    bundle, steps = collect_live_artifacts(tmp_path / "staging", host="LAB-01", observed_at=OBSERVED,
                                           system_root=system_root, user_profile=profile, copy_locked=copy_locked)
    status = {step["step"]: step["status"] for step in steps}
    assert status["prefetch"] == "ok" and status["tasks"] == "ok" and status["hive:SYSTEM"] == "ok"
    assert status["hive:SOFTWARE"] == "failed" and status["package"] == "ok"
    assert copied[:2] == ["SYSTEM", "SYSTEM.LOG1"]
    kinds = {member["kind"] for member in json.loads((bundle / "manifest.json").read_text())["files"]}
    assert {"prefetch_source", "scheduled_task_xml", "registry_hive"} <= kinds
    forensic = read_forensic_bundle(str(bundle))
    assert {item["kind"] for item in forensic.observations} >= {"prefetch_run", "scheduled_task"}


def test_nothing_readable_returns_no_bundle_and_records_why(tmp_path):
    empty = tmp_path / "Windows"
    empty.mkdir()

    def refuse(source: Path, destination: Path) -> None:
        raise PermissionError("access denied")

    bundle, steps = collect_live_artifacts(tmp_path / "staging", host="LAB-01", observed_at=OBSERVED,
                                           system_root=empty, user_profile=tmp_path, copy_locked=refuse)
    assert bundle is None
    assert all(step["status"] == "failed" for step in steps)
    assert any("access denied" in step["error"] for step in steps)
