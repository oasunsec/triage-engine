"""Load Sigma-like YAML rules from files or directories."""

from __future__ import annotations

import os
from typing import Iterable, List, Tuple

import yaml

from corrobora.sigma_mapper import split_modifier, supported_field
from corrobora.sigma_runner import _parse_condition, _tokenize, _validate_selection


def _iter_rule_files(paths: Iterable[str]) -> Iterable[str]:
    for path in paths:
        if not path:
            continue
        if os.path.isfile(path):
            yield os.path.abspath(path)
            continue
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for name in sorted(files):
                    if name.lower().endswith((".yml", ".yaml")):
                        yield os.path.abspath(os.path.join(root, name))


def load_rules(paths: Iterable[str]) -> Tuple[List[dict], List[str]]:
    rules: List[dict] = []
    diagnostics: List[str] = []
    for path in _iter_rule_files(paths):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                docs = [doc for doc in yaml.safe_load_all(handle) if doc]
        except Exception as exc:
            diagnostics.append(f"Failed to load Sigma rule {path}: {exc}")
            continue
        for idx, doc in enumerate(docs):
            if not isinstance(doc, dict):
                diagnostics.append(f"Skipped {path} document {idx + 1}: expected mapping")
                continue
            detection = doc.get("detection")
            if not isinstance(detection, dict) or not detection.get("condition"):
                diagnostics.append(f"Skipped {path} document {idx + 1}: missing detection.condition")
                continue
            condition = str(detection.get("condition", "") or "").strip()
            unsupported_fields = []
            for name, selection in detection.items():
                if name == "condition" or not isinstance(selection, dict):
                    continue
                for field in selection:
                    if not supported_field(field):
                        unsupported_fields.append(str(field))
            if unsupported_fields:
                diagnostics.append(
                    f"Skipped {path} document {idx + 1}: unsupported field or modifier(s) {', '.join(sorted(set(unsupported_fields)))}"
                )
                continue
            selectors = {
                str(name).lower(): value
                for name, value in detection.items()
                if name != "condition" and isinstance(value, dict)
            }
            try:
                tokens = _tokenize(condition)
                _parse_condition(tokens, selectors)
                for selection in selectors.values():
                    _validate_selection(selection)
            except (TypeError, ValueError) as exc:
                diagnostics.append(f"Skipped {path} document {idx + 1}: {exc}")
                continue
            doc["_rule_path"] = path
            rules.append(doc)
    return rules, diagnostics

