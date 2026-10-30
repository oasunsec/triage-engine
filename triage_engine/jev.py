"""Opt-in TypeSafe Jev review of a bounded case summary.

Jev returns typed judgments, not narrative text. This module never changes the
engine's deterministic findings, disposition, priority, or review records.
"""

from __future__ import annotations

import json
import math
import urllib.error
import urllib.request
from typing import Any, Dict


JEV_API_URL = "https://api.typesafe.ai/v1/systemone"
DEFAULT_JEV_MODEL = "jev-latest"
QUESTION_VERSION = "1.0"
MAX_RESPONSE_BYTES = 64 * 1024

REVIEW_FOCUS = {
    "validate_detection": "Validate whether promoted detections have supporting evidence.",
    "expand_scope": "Look for related activity across affected assets and identities.",
    "collect_telemetry": "Collect missing or incomplete telemetry before reaching a conclusion.",
    "routine_review": "Continue ordinary analyst review without a specialized first pivot.",
}


class JevIntegrationError(RuntimeError):
    """A remote Jev call or its response could not be used safely."""


def _short_text(value: Any, limit: int = 180) -> str:
    return " ".join(str(value or "").split())[:limit]


def _bounded_items(value: Any, limit: int) -> list[dict]:
    if not isinstance(value, list):
        return []
    selected = []
    for item in value:
        if not isinstance(item, dict):
            continue
        selected.append({
            "title": _short_text(item.get("title")),
            "summary": _short_text(item.get("summary") or item.get("description")),
            "severity": _short_text(item.get("severity"), 32),
            "mitre_technique": _short_text(item.get("mitre_technique"), 48),
        })
        if len(selected) >= limit:
            break
    return selected


def _count(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("Case summary is malformed")
    try:
        number = int(value or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Case summary is malformed") from exc
    if number < 0:
        raise ValueError("Case summary is malformed")
    return number


def build_jev_state(case_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Allowlist the case fields sent to TypeSafe; never include raw events."""
    if not isinstance(case_payload, dict):
        raise ValueError("Case summary is malformed")
    case = case_payload.get("case") or {}
    summary = case_payload.get("summary") or {}
    if not isinstance(case, dict) or not isinstance(summary, dict):
        raise ValueError("Case summary is malformed")
    disposition = case.get("triage_disposition") or {}
    quality = case.get("collection_quality_summary") or {}
    if not isinstance(disposition, dict):
        disposition = {}
    if not isinstance(quality, dict):
        quality = {}
    gaps = quality.get("telemetry_missing") or disposition.get("telemetry_gaps") or []
    if not isinstance(gaps, list):
        gaps = []
    return {
        "response_priority": _short_text(case.get("response_priority"), 8),
        "deterministic_disposition": _short_text(disposition.get("disposition"), 48),
        "finding_count": _count(summary.get("finding_count")),
        "incident_count": _count(summary.get("incident_count")),
        "missing_telemetry": [_short_text(value, 80) for value in gaps[:8]],
        "incidents": _bounded_items(case_payload.get("incidents"), 6),
        "findings": _bounded_items(case_payload.get("findings"), 8),
    }


def _probability(value: Any) -> float:
    if isinstance(value, bool):
        raise JevIntegrationError("Jev returned an invalid probability")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise JevIntegrationError("Jev returned an invalid probability") from exc
    if not math.isfinite(number) or not 0 <= number <= 1:
        raise JevIntegrationError("Jev returned an invalid probability")
    return number


def review_case(case_payload: Dict[str, Any], *, api_key: str, model: str = DEFAULT_JEV_MODEL) -> Dict[str, Any]:
    """Ask Jev for an advisory review focus and prompt-review probability."""
    if not api_key:
        raise JevIntegrationError("TYPESAFE_API_KEY is not configured")
    if not model or len(model) > 128 or any(ord(char) < 32 for char in model):
        raise JevIntegrationError("TRIAGE_JEV_MODEL is invalid")
    body = {
        "model": model,
        "state": build_jev_state(case_payload),
        "questions": {
            "review_focus": {
                "type": "choice",
                "instructions": "Based only on this case summary, which single analyst task is the most useful first review focus? This is not a verdict about compromise.",
                "criteria": REVIEW_FOCUS,
            },
            "prompt_review": {
                "type": "noul",
                "instructions": "Does this case summary warrant prompt analyst review today?",
                "criteria": {
                    "true": "Review today because the described activity may need timely investigation.",
                    "false": "Normal review timing is adequate based on the supplied summary.",
                },
            },
        },
    }
    request = urllib.request.Request(
        JEV_API_URL,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw_bytes = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw_bytes) > MAX_RESPONSE_BYTES:
            raise JevIntegrationError("Jev returned an oversized response")
        raw = json.loads(raw_bytes.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise JevIntegrationError("Jev rejected the configured API key") from exc
        if exc.code == 429:
            raise JevIntegrationError("Jev rate limit reached; try again later") from exc
        raise JevIntegrationError("Jev request failed") from exc
    except (urllib.error.URLError, TimeoutError, UnicodeError, ValueError) as exc:
        raise JevIntegrationError("Jev request failed") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("answers"), dict):
        raise JevIntegrationError("Jev returned an unexpected response")
    focus = raw["answers"].get("review_focus")
    prompt = raw["answers"].get("prompt_review")
    if not isinstance(focus, dict) or not isinstance(prompt, dict):
        raise JevIntegrationError("Jev returned an unexpected response")
    if focus.get("type") != "choice" or prompt.get("type") != "noul":
        raise JevIntegrationError("Jev returned an unexpected response")
    choice = focus.get("choice")
    probabilities = focus.get("probabilities")
    if choice not in REVIEW_FOCUS or not isinstance(probabilities, dict):
        raise JevIntegrationError("Jev returned an unexpected response")
    if set(probabilities) != set(REVIEW_FOCUS):
        raise JevIntegrationError("Jev returned an unexpected response")
    normalized_probabilities = {key: _probability(probabilities[key]) for key in REVIEW_FOCUS}
    confidence = _probability(focus.get("confidence"))
    prompt_probability = _probability(prompt.get("noul"))
    return {
        "provider": "typesafe_jev",
        "model": _short_text(raw.get("model") or model, 128),
        "question_version": QUESTION_VERSION,
        "advisory_only": True,
        "review_focus": {
            "choice": choice,
            "label": REVIEW_FOCUS[choice],
            "confidence": confidence,
            "probabilities": normalized_probabilities,
        },
        "prompt_review_probability": prompt_probability,
    }
