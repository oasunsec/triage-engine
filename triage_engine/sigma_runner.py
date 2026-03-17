"""Evaluate a small Sigma subset against normalized EVTX events."""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from models.event_model import Alert, NormalizedEvent
from triage_engine.sigma_mapper import event_values, split_modifier


TACTIC_MAP = {
    "credential_access": "Credential Access",
    "defense_evasion": "Defense Evasion",
    "discovery": "Discovery",
    "execution": "Execution",
    "lateral_movement": "Lateral Movement",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "collection": "Collection",
    "impact": "Impact",
}
LEVEL_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}


def _match_scalar(candidate: str, expected, modifier: str) -> bool:
    text = str(candidate or "")
    if modifier == "contains":
        return str(expected).lower() in text.lower()
    if modifier == "startswith":
        return text.lower().startswith(str(expected).lower())
    if modifier == "endswith":
        return text.lower().endswith(str(expected).lower())
    if modifier in {"re", "regex"}:
        try:
            return bool(re.search(str(expected), text, re.IGNORECASE))
        except re.error:
            return False
    return text.lower() == str(expected).lower()


def _selection_matches(event: NormalizedEvent, selection: dict) -> bool:
    for field, expected in selection.items():
        base, modifier = split_modifier(field)
        candidates = event_values(event, base)
        if isinstance(expected, list):
            matched = any(_match_scalar(candidate, item, modifier) for candidate in candidates for item in expected)
        else:
            matched = any(_match_scalar(candidate, expected, modifier) for candidate in candidates)
        if not matched:
            return False
    return True


def _tokenize(condition: str) -> List[str]:
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_]+", condition, flags=re.IGNORECASE)
    return [token.lower() for token in tokens]


def _parse_condition(tokens: List[str], values: dict[str, bool]) -> bool:
    position = 0

    def parse_or() -> bool:
        nonlocal position
        result = parse_and()
        while position < len(tokens) and tokens[position] == "or":
            position += 1
            result = result or parse_and()
        return result

    def parse_and() -> bool:
        nonlocal position
        result = parse_not()
        while position < len(tokens) and tokens[position] == "and":
            position += 1
            result = result and parse_not()
        return result

    def parse_not() -> bool:
        nonlocal position
        if position < len(tokens) and tokens[position] == "not":
            position += 1
            return not parse_not()
        return parse_primary()

    def parse_primary() -> bool:
        nonlocal position
        token = tokens[position]
        position += 1
        if token == "(":
            result = parse_or()
            if position < len(tokens) and tokens[position] == ")":
                position += 1
            return result
        return bool(values.get(token, False))

    return parse_or()


def _rule_metadata(rule: dict) -> tuple[str, str, str, str]:
    title = str(rule.get("title", "Sigma Rule")).strip() or "Sigma Rule"
    level = LEVEL_MAP.get(str(rule.get("level", "medium")).strip().lower(), "medium")
    tags = [str(tag).strip().lower() for tag in rule.get("tags", []) if str(tag).strip()]
    tactic = "Execution"
    technique = "TBD"
    for tag in tags:
        if tag.startswith("attack.t") and technique == "TBD":
            technique = tag.split(".", 1)[-1].upper()
        elif tag.startswith("attack.") and technique == "TBD":
            tactic_key = tag.split(".", 1)[-1]
            tactic = TACTIC_MAP.get(tactic_key, tactic)
    return title, level, tactic, technique


def evaluate_rules(events: Iterable[NormalizedEvent], rules: Iterable[dict]) -> Tuple[List[Alert], List[str]]:
    alerts: List[Alert] = []
    diagnostics: List[str] = []
    for rule in rules:
        detection = rule.get("detection", {}) or {}
        selectors = {
            str(name).lower(): value
            for name, value in detection.items()
            if name != "condition" and isinstance(value, dict)
        }
        condition = str(detection.get("condition", "") or "")
        title, severity, tactic, technique = _rule_metadata(rule)
        for event in events:
            selector_results = {name: _selection_matches(event, selector) for name, selector in selectors.items()}
            try:
                matched = _parse_condition(_tokenize(condition), selector_results)
            except Exception as exc:
                diagnostics.append(f"Skipped Sigma evaluation for {title}: {exc}")
                break
            if not matched:
                continue
            alerts.append(
                Alert(
                    rule_name=title,
                    severity=severity,
                    mitre_tactic=tactic,
                    mitre_technique=technique,
                    description=str(rule.get("description", title) or title),
                    explanation=f"Sigma rule '{title}' matched normalized EVTX data.",
                    event=event,
                    confidence="medium",
                    confidence_factors=["sigma_rule_match"],
                    promotion_policy="signal_only",
                    investigate_next="Validate the Sigma match against adjacent raw events and native detector output.",
                    evidence={
                        "sigma_rule_id": str(rule.get("id", "") or ""),
                        "sigma_rule_path": str(rule.get("_rule_path", "") or ""),
                        "sigma_tags": [str(tag) for tag in rule.get("tags", [])],
                        "sigma_condition": condition,
                        "evidence_strength": "medium",
                    },
                    rule_source="sigma",
                )
            )
    return alerts, diagnostics
