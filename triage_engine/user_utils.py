"""Shared user-identity normalization helpers for analyst-facing outputs."""

from __future__ import annotations

from typing import Any, Dict, Iterable


EMPTY_VALUES = {"", "-", "(null)", "none", "unknown"}
SPECIAL_ACCOUNTS = {
    "system",
    "local service",
    "network service",
    "trustedinstaller",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "nt service\\trustedinstaller",
    "anonymous logon",
}


def clean_text(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text.lower() in EMPTY_VALUES else text


def normalize_user_identity(value: Any, host_hint: Any = "") -> Dict[str, str]:
    raw = clean_text(value)
    host = clean_text(host_hint)
    if not raw:
        return {
            "raw": "",
            "canonical": "",
            "display": "",
            "scope": "",
            "short_name": "",
        }

    lowered = raw.lower()
    if lowered in SPECIAL_ACCOUNTS:
        return {
            "raw": raw,
            "canonical": raw,
            "display": raw,
            "scope": "",
            "short_name": raw.split("\\")[-1],
        }

    if "@" in raw:
        return {
            "raw": raw,
            "canonical": raw,
            "display": raw,
            "scope": raw.split("@", 1)[-1],
            "short_name": raw,
        }

    if "\\" in raw:
        scope, short_name = raw.split("\\", 1)
        scope = clean_text(scope)
    else:
        scope, short_name = "", raw

    lower_short = short_name.lower()
    host_is_safe_scope = bool(host and scope and scope.lower() == host.lower())
    should_host_qualify = bool(
        host
        and not scope
        and short_name
        and "\\" not in short_name
        and "@" not in short_name
        and not lower_short.endswith("$")
        and lower_short not in SPECIAL_ACCOUNTS
    )

    if host_is_safe_scope:
        canonical = f"{host}\\{short_name}"
        display = short_name
        scope_value = host
    elif should_host_qualify:
        canonical = f"{host}\\{short_name}"
        display = short_name
        scope_value = host
    else:
        canonical = raw
        display = short_name if scope and host_is_safe_scope else raw
        scope_value = scope

    return {
        "raw": raw,
        "canonical": canonical,
        "display": display or canonical or raw,
        "scope": scope_value,
        "short_name": short_name or raw,
    }


def add_user_identity_fields(payload: Dict[str, Any], field_name: str, value: Any, host_hint: Any = "") -> None:
    identity = normalize_user_identity(value, host_hint)
    payload[f"{field_name}_raw"] = identity["raw"]
    payload[f"{field_name}_canonical"] = identity["canonical"]
    payload[f"{field_name}_display"] = identity["display"]


def safe_user_displays(canonical_values: Iterable[str], host_map: Dict[str, str] | None = None) -> Dict[str, str]:
    host_map = host_map or {}
    display_map: Dict[str, str] = {}
    collisions: Dict[str, int] = {}

    for canonical in canonical_values:
        identity = normalize_user_identity(canonical, host_map.get(canonical, ""))
        display = identity["display"] or canonical
        collisions[display] = collisions.get(display, 0) + 1
        display_map[canonical] = display

    for canonical, display in list(display_map.items()):
        if collisions.get(display, 0) > 1:
            display_map[canonical] = canonical

    return display_map
