"""Structured JSON logging configuration for triage-engine."""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional


_DEFAULT_LEVEL = "INFO"
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_BACKUP_COUNT = 5
_RESERVED_FIELDS = set(logging.makeLogRecord({}).__dict__.keys()) | {"message", "asctime"}


def _to_bool(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = str(os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class JsonLogFormatter(logging.Formatter):
    """Serialize log records into a compact JSON payload."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc)
            .replace(microsecond=int(record.msecs) * 1000)
            .isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = getattr(record, "request_id", "")
        user = getattr(record, "user", "")
        duration_ms = getattr(record, "duration_ms", None)
        if request_id:
            payload["request_id"] = str(request_id)
        if user:
            payload["user"] = str(user)
        if duration_ms is not None:
            payload["duration_ms"] = int(duration_ms)

        for key, value in record.__dict__.items():
            if key in _RESERVED_FIELDS or key in payload or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except TypeError:
                payload[key] = str(value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, sort_keys=True)


def configure_logging(data_root: Optional[str] = None) -> None:
    """Configure triage loggers with JSON output.

    Default sink: stderr.
    Optional rotating file sink:
      TRIAGE_LOG_FILE_ENABLED=1
      TRIAGE_LOG_FILE_PATH=<path> (optional)
      TRIAGE_LOG_FILE_MAX_BYTES=<int> (optional)
      TRIAGE_LOG_FILE_BACKUP_COUNT=<int> (optional)
    """

    logger = logging.getLogger("triage")
    if getattr(logger, "_triage_configured", False):
        return

    level_name = str(os.environ.get("TRIAGE_LOG_LEVEL", _DEFAULT_LEVEL) or _DEFAULT_LEVEL).upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)
    logger.propagate = False

    formatter = JsonLogFormatter()

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    if _to_bool(os.environ.get("TRIAGE_LOG_FILE_ENABLED", "0")):
        root_dir = os.path.abspath(data_root or os.path.join(os.getcwd(), "data"))
        os.makedirs(root_dir, exist_ok=True)
        file_path = str(os.environ.get("TRIAGE_LOG_FILE_PATH", "") or "").strip()
        if not file_path:
            file_path = os.path.join(root_dir, "triage-engine.log")
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        file_handler = RotatingFileHandler(
            file_path,
            maxBytes=max(1024, _int_env("TRIAGE_LOG_FILE_MAX_BYTES", _DEFAULT_MAX_BYTES)),
            backupCount=max(1, _int_env("TRIAGE_LOG_FILE_BACKUP_COUNT", _DEFAULT_BACKUP_COUNT)),
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger._triage_configured = True  # type: ignore[attr-defined]
