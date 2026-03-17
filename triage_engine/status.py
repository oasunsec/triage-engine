"""Run status and structured error output."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class RunStatus:
    def __init__(self, case_name: str, case_path: str, input_source: str):
        now = _utc_now()
        self.case_name = case_name
        self.case_path = case_path
        self.input_source = input_source
        self.run_status_path = os.path.join(case_path, "run_status.json")
        self.error_path = os.path.join(case_path, "errors.json")
        self._state = {
            "case_name": case_name,
            "case_path": os.path.abspath(case_path),
            "input_source": input_source,
            "status": "running",
            "current_stage": "init",
            "message": "Run initialized",
            "started_at": now,
            "updated_at": now,
            "completed_at": None,
            "stage_history": {
                "init": {
                    "started_at": now,
                    "completed_at": None,
                }
            },
            "artifacts_created": [],
            "diagnostics": [],
            "metadata": {},
        }
        self._write()

    def stage(self, stage_name: str, message: str = "") -> None:
        now = _utc_now()
        current_stage = str(self._state.get("current_stage", "") or "")
        stage_history = self._state.setdefault("stage_history", {})
        if current_stage and current_stage != stage_name:
            current_entry = stage_history.setdefault(
                current_stage,
                {"started_at": now, "completed_at": None},
            )
            if not current_entry.get("completed_at"):
                current_entry["completed_at"] = now

        next_entry = stage_history.setdefault(
            stage_name,
            {"started_at": now, "completed_at": None},
        )
        if not next_entry.get("started_at"):
            next_entry["started_at"] = now
        next_entry["completed_at"] = None
        self._state["current_stage"] = stage_name
        self._state["message"] = message or stage_name
        self._state["updated_at"] = now
        self._write()

    def add_artifact(self, artifact_path: str) -> None:
        abs_path = os.path.abspath(artifact_path)
        rel = os.path.relpath(abs_path, self.case_path)
        entry = {"name": os.path.basename(abs_path), "path": rel, "created_at": _utc_now()}
        if entry not in self._state["artifacts_created"]:
            self._state["artifacts_created"].append(entry)
            self._state["updated_at"] = _utc_now()
            self._write()

    def add_diagnostic(self, message: str) -> None:
        entry = {"message": message, "created_at": _utc_now()}
        if entry not in self._state["diagnostics"]:
            self._state["diagnostics"].append(entry)
            self._state["updated_at"] = _utc_now()
            self._write()

    def set_metadata(self, key: str, value) -> None:
        self._state.setdefault("metadata", {})[key] = value
        self._state["updated_at"] = _utc_now()
        self._write()

    def complete(self, message: str = "Investigation completed") -> None:
        now = _utc_now()
        current_stage = str(self._state.get("current_stage", "") or "")
        if current_stage:
            stage_history = self._state.setdefault("stage_history", {})
            entry = stage_history.setdefault(
                current_stage,
                {"started_at": now, "completed_at": None},
            )
            if not entry.get("started_at"):
                entry["started_at"] = now
            if not entry.get("completed_at"):
                entry["completed_at"] = now
        self._state["status"] = "completed"
        self._state["message"] = message
        self._state["completed_at"] = now
        self._state["updated_at"] = now
        self._write()

    def fail(self, stage_name: str, error_message: str, traceback_text: Optional[str] = None) -> None:
        now = _utc_now()
        stage_history = self._state.setdefault("stage_history", {})
        current_stage = str(self._state.get("current_stage", "") or "")
        if current_stage and current_stage != stage_name:
            current_entry = stage_history.setdefault(
                current_stage,
                {"started_at": now, "completed_at": None},
            )
            if not current_entry.get("started_at"):
                current_entry["started_at"] = now
            if not current_entry.get("completed_at"):
                current_entry["completed_at"] = now
        failed_entry = stage_history.setdefault(
            stage_name,
            {"started_at": now, "completed_at": None},
        )
        if not failed_entry.get("started_at"):
            failed_entry["started_at"] = now
        if not failed_entry.get("completed_at"):
            failed_entry["completed_at"] = now
        self._state["status"] = "failed"
        self._state["current_stage"] = stage_name
        self._state["message"] = error_message
        self._state["completed_at"] = now
        self._state["updated_at"] = now
        self._write()

        error_data = {
            "case_name": self.case_name,
            "case_path": os.path.abspath(self.case_path),
            "failed_stage": stage_name,
            "error": error_message,
            "traceback": traceback_text or "",
            "created_artifacts": self._state.get("artifacts_created", []),
            "timestamp": _utc_now(),
        }
        with open(self.error_path, "w", encoding="utf-8") as handle:
            json.dump(error_data, handle, indent=2)

    def _write(self) -> None:
        os.makedirs(self.case_path, exist_ok=True)
        with open(self.run_status_path, "w", encoding="utf-8") as handle:
            json.dump(self._state, handle, indent=2)
