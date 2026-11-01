"""Settings and tokens from before the rename to Corrobora keep working."""

from __future__ import annotations

import os
from unittest.mock import patch

from corrobora import adopt_legacy_environment
from corrobora.env_loader import load_project_env


def test_triage_settings_fill_unset_corrobora_settings():
    with patch.dict(os.environ, {"TRIAGE_PORT": "9001", "TRIAGE_HOST": "0.0.0.0", "CORROBORA_HOST": "127.0.0.1"}, clear=False):
        os.environ.pop("CORROBORA_PORT", None)
        adopt_legacy_environment()
        assert os.environ["CORROBORA_PORT"] == "9001"
        assert os.environ["CORROBORA_HOST"] == "127.0.0.1"


def test_legacy_env_file_is_honored(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("TRIAGE_MAX_UPLOAD_MB=42\n", encoding="utf-8")
    with patch.dict(os.environ, {}, clear=False):
        for key in ("TRIAGE_MAX_UPLOAD_MB", "CORROBORA_MAX_UPLOAD_MB"):
            os.environ.pop(key, None)
        load_project_env(str(tmp_path), explicit=str(env_file))
        assert os.environ["CORROBORA_MAX_UPLOAD_MB"] == "42"
