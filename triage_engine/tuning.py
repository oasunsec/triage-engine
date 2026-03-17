"""JSON-backed tuning configuration for suppression and promotion overrides."""

from __future__ import annotations

import copy
import json
import os
from typing import Iterable, List, Tuple


DEFAULT_TUNING = {
    "allowlists": {
        "hosts": [],
        "users": [],
        "processes": [],
        "services": [],
        "tasks": [],
        "ips": [],
    },
    "rule_suppressions": [],
    "promotion_overrides": {
        "standalone": [
            "AdminSDHolder Rights Obfuscation",
            "Group Policy Object Modified",
            "Hosts File Modified",
            "OpenSSH Server Listening",
            "Remote SAMR Password Reset",
            "Repeated RDP Authentication Accepted",
            "System Security Access Granted",
        ],
        "correlate": [],
        "signal_only": [],
    },
}

ALLOWLIST_KEYS = tuple(DEFAULT_TUNING["allowlists"].keys())
PROMOTION_KEYS = tuple(DEFAULT_TUNING["promotion_overrides"].keys())


def _merge_unique(base_values: List[str], overlay_values: List[str]) -> List[str]:
    merged = list(base_values or [])
    for value in overlay_values or []:
        if value not in merged:
            merged.append(copy.deepcopy(value))
    return merged


def _merge_unique_objects(base_values: List[dict], overlay_values: List[dict]) -> List[dict]:
    merged = list(base_values or [])
    for value in overlay_values or []:
        if value not in merged:
            merged.append(copy.deepcopy(value))
    return merged


def _merge_tuning(base: dict, overlay: dict) -> dict:
    allowlists = overlay.get("allowlists", {})
    if isinstance(allowlists, dict):
        for key in ALLOWLIST_KEYS:
            if key in allowlists:
                base["allowlists"][key] = _merge_unique(base["allowlists"].get(key, []), allowlists.get(key, []))

    suppressions = overlay.get("rule_suppressions")
    if suppressions is not None:
        base["rule_suppressions"] = _merge_unique_objects(base.get("rule_suppressions", []), suppressions)

    promotion = overlay.get("promotion_overrides", {})
    if isinstance(promotion, dict):
        for key in PROMOTION_KEYS:
            if key in promotion:
                base["promotion_overrides"][key] = _merge_unique(
                    base["promotion_overrides"].get(key, []),
                    promotion.get(key, []),
                )
    return base


def _normalize_string_list(value) -> Tuple[List[str], List[str]]:
    if value is None:
        return [], []
    if not isinstance(value, list):
        return [], [f"Expected list but received {type(value).__name__}"]
    cleaned = []
    errors = []
    for item in value:
        text = str(item or "").strip()
        if not text:
            errors.append("Encountered empty tuning value")
            continue
        cleaned.append(text)
    return cleaned, errors


def _validate_rule_suppressions(value) -> Tuple[List[dict], List[str]]:
    if value is None:
        return [], []
    if not isinstance(value, list):
        return [], [f"rule_suppressions must be a list, not {type(value).__name__}"]
    normalized: List[dict] = []
    errors: List[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"rule_suppressions[{idx}] must be an object")
            continue
        rule = str(item.get("rule", "") or "").strip()
        if not rule:
            errors.append(f"rule_suppressions[{idx}] missing required key 'rule'")
            continue
        normalized.append(
            {
                "rule": rule,
                "host": str(item.get("host", "") or "").strip(),
                "user": str(item.get("user", "") or "").strip(),
                "process": str(item.get("process", "") or "").strip(),
                "service": str(item.get("service", "") or "").strip(),
                "task": str(item.get("task", "") or "").strip(),
                "ip": str(item.get("ip", "") or "").strip(),
                "command_line": str(item.get("command_line", "") or "").strip(),
                "parent_process": str(item.get("parent_process", "") or "").strip(),
                "description": str(item.get("description", "") or "").strip(),
                "reason": str(item.get("reason", "") or "").strip() or f"tuning_rule:{rule}",
            }
        )
    return normalized, errors


def _validate_tuning_payload(payload: dict) -> Tuple[dict, List[str]]:
    normalized: dict = {}
    errors: List[str] = []
    if "allowlists" in payload:
        allowlists_payload = payload.get("allowlists")
        if not isinstance(allowlists_payload, dict):
            errors.append(f"allowlists must be an object, not {type(allowlists_payload).__name__}")
        else:
            normalized["allowlists"] = {}
            for key in ALLOWLIST_KEYS:
                if key not in allowlists_payload:
                    continue
                values, field_errors = _normalize_string_list(allowlists_payload.get(key, []))
                normalized["allowlists"][key] = values
                errors.extend([f"allowlists.{key}: {msg}" for msg in field_errors])

    if "promotion_overrides" in payload:
        promotion_payload = payload.get("promotion_overrides")
        if not isinstance(promotion_payload, dict):
            errors.append(f"promotion_overrides must be an object, not {type(promotion_payload).__name__}")
        else:
            normalized["promotion_overrides"] = {}
            for key in PROMOTION_KEYS:
                if key not in promotion_payload:
                    continue
                values, field_errors = _normalize_string_list(promotion_payload.get(key, []))
                normalized["promotion_overrides"][key] = values
                errors.extend([f"promotion_overrides.{key}: {msg}" for msg in field_errors])

    if "rule_suppressions" in payload:
        suppressions, suppression_errors = _validate_rule_suppressions(payload.get("rule_suppressions", []))
        normalized["rule_suppressions"] = suppressions
        errors.extend(suppression_errors)
    return normalized, errors


def load_tuning(root_dir: str, extra_paths: Iterable[str] | None = None) -> Tuple[dict, List[str], List[str]]:
    config = copy.deepcopy(DEFAULT_TUNING)
    diagnostics: List[str] = []
    loaded_paths: List[str] = []
    candidate_paths = [
        os.path.join(root_dir, "config", "tuning", "default.json"),
        os.path.join(root_dir, "config", "tuning", "local.json"),
    ]
    candidate_paths.extend(list(extra_paths or []))

    for path in candidate_paths:
        is_optional_local = path.endswith(os.path.join("config", "tuning", "local.json"))
        if not path:
            continue
        if not os.path.isfile(path):
            if is_optional_local:
                continue
            diagnostics.append(f"Tuning file not found: {path}")
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as exc:
            diagnostics.append(f"Failed to load tuning file {path}: {exc}")
            continue
        if not isinstance(payload, dict):
            diagnostics.append(f"Tuning file {path} must contain a JSON object")
            continue
        normalized, errors = _validate_tuning_payload(payload)
        _merge_tuning(config, normalized)
        loaded_paths.append(os.path.abspath(path))
        diagnostics.extend([f"{path}: {message}" for message in errors])

    return config, diagnostics, loaded_paths
