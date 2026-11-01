"""Executable inventory: artifact observations joined per executable path.

Event-to-artifact links need process-creation telemetry, which many hosts do
not record. The inventory answers artifact-first questions instead: which
executables ran, persist, or were inventoried; where they live; whether they
are still on disk; and when they first appear. Each executable carries the
observations it was built from and explicit reasons it may deserve a look.

Reasons are leads for review. They never raise alerts, never change the case
verdict, and each states what it does not establish.
"""

from __future__ import annotations

import ntpath
import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Iterable

SCHEMA_VERSION = "1.0"
MAX_EXECUTABLES = 20_000
RECENT_WINDOW = timedelta(days=7)

_EXECUTABLE = re.compile(r"\.(?:exe|com|scr|dll|sys|bat|cmd|ps1|vbs|js|hta)$", re.I)
_VOLUME_PREFIX = re.compile(r"^\\volume\{[^}]*\}", re.I)
_DRIVE_PREFIX = re.compile(r"^[a-z]:", re.I)
_IMAGE = re.compile(r"(.+?\.(?:exe|com|scr|bat|cmd|sys|dll))(?=\s|,|$)", re.I)
# Expansions assume a default Windows layout; every use is recorded as an assumption.
_DEFAULT_EXPANSIONS = (
    ("%systemroot%", "\\windows"), ("%windir%", "\\windows"), ("\\systemroot", "\\windows"),
    ("%programfiles(x86)%", "\\program files (x86)"), ("%programfiles%", "\\program files"),
    ("%commonprogramfiles(x86)%", "\\program files (x86)\\common files"),
    ("%commonprogramfiles%", "\\program files\\common files"), ("%programdata%", "\\programdata"),
    ("%systemdrive%", ""),
)
SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\", "\\windows\\servicing\\")
TEMP_MARKERS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\temp\\", "\\tmp\\")
USER_WRITABLE = ("\\users\\", "\\programdata\\", "\\windows\\temp\\", "\\$recycle.bin\\", "\\perflogs\\")
# ProgramData folders whose ACLs admit only the system and its installers.
PROTECTED_PROGRAMDATA = ("\\programdata\\microsoft\\windows defender\\",)
# Names of core Windows processes and the only directories they ship in.
SYSTEM_NAMES = {
    name: SYSTEM_DIRS for name in (
        "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
        "spoolsv.exe", "taskhostw.exe", "rundll32.exe", "dllhost.exe", "conhost.exe", "lsaiso.exe",
        "sihost.exe", "ctfmon.exe", "searchindexer.exe", "wmiprvse.exe", "taskmgr.exe", "regsvr32.exe")
}
SYSTEM_NAMES["explorer.exe"] = ("\\windows\\", *SYSTEM_DIRS)
MECHANISM = {"scheduled_task": "scheduled task", "service": "service", "registry_run": "registry autorun"}

REASONS = {
    "system_name_outside_system_directory": (
        5, "Carries the name of a core Windows program but lives outside the directories Windows installs it in.",
        "That the file is malicious; some vendors reuse these names."),
    "executed_but_absent": (
        4, "Prefetch records a run from this path, but the supplied $MFT has no file there now.",
        "Why the file is gone; updaters and installers routinely delete what they ran."),
    "persistence_target_absent": (
        3, "A persistence entry launches this path, but the supplied $MFT has no file there.",
        "That the entry ever ran; stale entries from uninstalled software are common."),
    "ran_from_temporary_directory": (
        3, "Ran from a temporary directory.",
        "Malicious intent; installers and updaters often run from temporary folders."),
    "persists_from_user_writable_location": (
        2, "A persistence entry launches it from a location an ordinary user can write to.",
        "That it ran, or that it is unwanted; many per-user applications install this way."),
    "ran_from_user_writable_location": (
        2, "Ran from a location an ordinary user can write to.",
        "That it is unwanted; many per-user applications live in user profiles."),
    "new_and_executed": (
        2, "First appears on disk within 7 days of collection and has run.",
        "That it arrived by unusual means; the date only bounds when the file record was created."),
    "no_publisher_recorded": (
        1, "Amcache records no publisher for this user-writable executable.",
        "That it is unsigned; Amcache publisher fields are often empty."),
    "superseded_by_other_version": (
        0, "No longer on disk, but the same program is present in a folder that differs only by version or build.",
        "That the newer copy is genuine; it explains the absence, nothing more."),
}


def volume_path(raw: str) -> tuple[str, list[str]]:
    """Return (casefolded volume-relative path, assumptions) or ("", []) when unresolvable."""
    text = str(raw or "").strip().strip('"').replace("/", "\\")
    if text.startswith("\\??\\"):
        text = text[4:]
    text = re.sub(r"\\+", r"\\", text).casefold()
    assumptions = []
    for token, value in _DEFAULT_EXPANSIONS:
        if text.startswith(token):
            text = value + text[len(token):]
            assumptions.append(f"{token} expanded with the default Windows layout")
            break
    if text.startswith("system32\\"):
        text = "\\windows\\" + text
        assumptions.append("service path relative to the Windows directory")
    text = _VOLUME_PREFIX.sub("", text)
    text = _DRIVE_PREFIX.sub("", text)
    if "%" in text or not text.startswith("\\") or not _EXECUTABLE.search(text):
        return "", []
    return text, assumptions


def _command_image(command: str) -> str:
    text = re.sub(r'^"{2,}', '"', str(command or "").strip())
    if not text:
        return ""
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 0 else ""
    match = _IMAGE.match(text)
    return match.group(1) if match else text.split()[0]


def command_target(command: str) -> tuple[str, list[str]]:
    """The executable a configured command launches, as a volume-relative path."""
    return volume_path(_command_image(command))


def location_class(path: str) -> str:
    if path.startswith(SYSTEM_DIRS) or path.startswith("\\windows\\") or path.startswith(PROTECTED_PROGRAMDATA):
        return "windows"
    if path.startswith(("\\program files\\", "\\program files (x86)\\")):
        return "program_files"
    if path.startswith(USER_WRITABLE) or any(marker in path for marker in TEMP_MARKERS):
        return "user_writable"
    return "other"


def _time(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _prefetch_path(details: dict) -> str:
    record = details.get("export_record") or {}
    files = record.get("FilesLoaded") or ""
    files = files if isinstance(files, list) else str(files).split(", ")
    suffix = "\\" + str(details.get("name", "")).casefold()
    for item in files:
        if str(item).casefold().endswith(suffix):
            return str(item)
    return ""


def build_executable_inventory(observations: Iterable[dict], *, ntfs=None, observed_at: str = "") -> dict:
    """Join observations per executable and attach review reasons. Never raises alerts."""
    entries: dict[str, dict] = {}
    unresolved: Counter = Counter()

    def entry_for(path: str, raw: str, priority: int) -> dict | None:
        """Entry for ``path``; ``raw`` is a source spelling, lower ``priority`` reads better."""
        if path not in entries:
            if len(entries) >= MAX_EXECUTABLES:
                unresolved["inventory_limit"] += 1
                return None
            entries[path] = {"path": path, "display_path": "", "name": ntpath.basename(path),
                             "location": location_class(path), "runs": [], "run_count": 0,
                             "persistence": [], "amcache": [], "assumptions": [], "observation_ids": [],
                             "prefetch_volumes": set(), "_display_candidates": []}
        entries[path]["_display_candidates"].append((priority, raw))
        return entries[path]

    for observation in observations:
        kind, details = observation.get("kind"), observation.get("details") or {}
        if kind == "prefetch_run":
            raw = _prefetch_path(details)
            path, assumptions = volume_path(raw)
            if not path:
                unresolved["prefetch_without_path"] += 1
                continue
            entry = entry_for(path, raw, 2)  # Prefetch spells paths in capitals
            if entry is None:
                continue
            entry["runs"].append(observation.get("timestamp"))
            entry["run_count"] = max(entry["run_count"], int(details.get("run_count") or 0))
            serial = (details.get("export_record") or {}).get("Volume0Serial")
            if serial:
                entry["prefetch_volumes"].add(str(serial).upper())
        elif kind in MECHANISM:
            path, assumptions = command_target(details.get("command", ""))
            if not path:
                # COM-handler tasks and driver services legitimately have no command line.
                empty = not str(details.get("command") or "").strip()
                unresolved[f"{kind}_{'without_command' if empty else 'unresolved_command'}"] += 1
                continue
            entry = entry_for(path, _command_image(details.get("command", "")), 0)
            if entry is None:
                continue
            entry["persistence"].append({"mechanism": MECHANISM[kind], "name": details.get("name", ""),
                                         "location": details.get("location", ""), "observation_id": observation["id"]})
        elif kind == "amcache_file":
            path, assumptions = volume_path(details.get("path", ""))
            if not path:
                continue  # Hash-only entries carry no path.
            entry = entry_for(path, details.get("path", ""), 1)
            if entry is None:
                continue
            entry["amcache"].append({"sha1": details.get("sha1", ""), "publisher": details.get("publisher", ""),
                                     "product_name": details.get("product_name", ""),
                                     "key_last_write": observation.get("timestamp")})
        else:
            continue
        for assumption in assumptions:
            if assumption not in entry["assumptions"]:
                entry["assumptions"].append(assumption)
        entry["observation_ids"].append(observation["id"])

    file_system = _file_system_facts(entries, ntfs)
    collected = _time(observed_at) or (_time(ntfs.observed_at) if ntfs is not None else None)
    absent_names = {ntpath.basename(path) for path, facts in file_system.items() if not facts.get("present")}
    present_by_name = _present_by_name(ntfs, absent_names)
    executables = []
    for path, entry in entries.items():
        facts = file_system.get(path)
        entry["file_system"] = facts
        entry["runs"] = sorted({run for run in entry["runs"] if run})
        entry["prefetch_volumes"] = sorted(entry["prefetch_volumes"])
        entry["reasons"] = _reasons(entry, facts, collected, present_by_name)
        entry["display_path"] = _display_path(entry, facts, ntfs.volume.upper() if ntfs is not None and ntfs.volume else "")
        entry["score"] = sum(REASONS[item["code"]][0] for item in entry["reasons"])
        executables.append(entry)
    executables.sort(key=lambda item: (-item["score"], item["path"]))
    by_reason = Counter(item["code"] for entry in executables for item in entry["reasons"])
    return {
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "executables": len(executables),
            "with_reasons": sum(1 for entry in executables if entry["score"] > 0),
            "by_reason": dict(sorted(by_reason.items())),
            "by_location": dict(sorted(Counter(entry["location"] for entry in executables).items())),
            "unresolved": dict(sorted(unresolved.items())),
            "file_system_checked": ntfs is not None and ntfs.mft is not None,
            "verdict_effect": "none",
            "notes": [
                "Reasons are review leads, not detections; they do not change the case verdict.",
                "Paths are volume-relative. Prefetch and $MFT are compared only when Prefetch names one volume, "
                "which is assumed to be the supplied $MFT volume.",
                "An absent file means no in-use $MFT record at that path at collection time.",
            ],
        },
        "reasons": {code: {"weight": weight, "meaning": meaning, "does_not_establish": limit}
                    for code, (weight, meaning, limit) in REASONS.items()},
        "executables": executables,
    }


def _file_system_facts(entries: dict[str, dict], ntfs) -> dict[str, dict]:
    if ntfs is None or ntfs.mft is None or not entries:
        return {}
    mft = ntfs.mft
    matches = mft.lookup_paths(entries)
    creates = ntfs.usn_creates_for(entry for found in matches.values() for entry in found[:4])
    facts = {}
    for path in entries:
        found = matches.get(path, [])
        in_use = [entry for entry in found if mft.flags[mft.name_record[entry]] & 2]
        if not in_use:
            facts[path] = {"present": False, "deleted_records": len(found)}
            continue
        entry = in_use[0]
        si_obs, fn_obs = ntfs.file_observations(entry)
        journal = sorted(ntfs.usn.ts[create] for create, _ in creates.get(entry, []))
        true_path, _ = mft.entry_path(entry, {})
        facts[path] = {
            "present": True,
            "path": true_path,
            "size": fn_obs["details"].get("data_size"),
            "file_name_created": fn_obs["details"]["times"]["created"]["value"],
            "standard_information_created": si_obs["details"]["times"]["created"]["value"],
            "journal_creates": len(journal),
            "observation_ids": [si_obs["id"], fn_obs["id"]],
        }
    return facts


def _display_path(entry: dict, facts: dict | None, volume: str) -> str:
    """Readable path: the $MFT's own spelling when present, else the best-cased source."""
    if facts and facts.get("path"):
        return volume + facts["path"]
    for _, raw in sorted(entry.pop("_display_candidates", ())):
        text = re.sub(r"\\+", r"\\", raw.strip().strip('"'))
        text = _DRIVE_PREFIX.sub("", _VOLUME_PREFIX.sub("", text))
        if text.casefold() == entry["path"]:
            return volume + text
    return volume + entry["path"]


def _present_by_name(ntfs, names: set[str]) -> dict[str, list[str]]:
    """In-use, resolved $MFT paths for files with these names: one pass over the name table."""
    if not names or ntfs is None or ntfs.mft is None:
        return {}
    mft, found, cache = ntfs.mft, {}, {}
    lengths = {len(name.encode("utf-16-le")) // 2 for name in names}
    for entry in range(len(mft.name_len)):
        if mft.name_len[entry] not in lengths:
            continue
        owner = mft.name_record[entry]
        if owner >= mft.records or not mft.flags[owner] & 2:
            continue
        name = mft.name(entry).casefold()
        if name in names:
            path, status = mft.entry_path(entry, cache)
            if status == "resolved":
                found.setdefault(name, []).append(path.casefold())
    return found


_HEX_FOLDER = re.compile(r"[0-9a-f]{8,}")


def _version_variants(first: str, second: str) -> bool:
    """Folder names that differ only by a version, build number or content hash."""
    if _HEX_FOLDER.fullmatch(first) and _HEX_FOLDER.fullmatch(second):
        return True
    prefix = lambda name: re.split(r"\d", name, maxsplit=1)[0]
    return bool(re.search(r"\d", first) and re.search(r"\d", second)) and prefix(first) == prefix(second)


def _other_version(path: str, present_by_name: dict[str, list[str]]) -> str:
    """A present path with the same name that differs from ``path`` only in one version-like folder."""
    parts = path.split("\\")
    for other in present_by_name.get(parts[-1], ()):
        other_parts = other.split("\\")
        if len(other_parts) != len(parts):
            continue
        differing = [(a, b) for a, b in zip(parts, other_parts) if a != b]
        if len(differing) == 1 and _version_variants(*differing[0]):
            return other
    return ""


def _reasons(entry: dict, facts: dict | None, collected: datetime | None,
             present_by_name: dict[str, list[str]] | None = None) -> list[dict]:
    path, codes = entry["path"], []
    executed = bool(entry["runs"])
    allowed = SYSTEM_NAMES.get(entry["name"])
    if allowed and not path.startswith(allowed):
        codes.append("system_name_outside_system_directory")
    # Absence is only claimed when the Prefetch volume is unambiguous.
    comparable = facts is not None and len(entry["prefetch_volumes"]) <= 1
    newer = _other_version(path, present_by_name or {}) if facts is not None and not facts["present"] else ""
    if newer:
        entry["other_version"] = newer
        codes.append("superseded_by_other_version")
    elif executed and comparable and not facts["present"]:
        codes.append("executed_but_absent")
    if entry["persistence"] and facts is not None and not facts["present"] and not newer:
        codes.append("persistence_target_absent")
    if executed and any(marker in path for marker in TEMP_MARKERS):
        codes.append("ran_from_temporary_directory")
    elif executed and entry["location"] == "user_writable":
        codes.append("ran_from_user_writable_location")
    if entry["persistence"] and entry["location"] == "user_writable":
        codes.append("persists_from_user_writable_location")
    # Program Files and Windows need administrator rights; a recent file there is usually an update.
    if executed and collected and facts and facts.get("present") and entry["location"] in {"user_writable", "other"}:
        created = _time(facts.get("file_name_created"))
        if created and timedelta(0) <= collected - created <= RECENT_WINDOW:
            codes.append("new_and_executed")
    # A missing publisher only adds weight; on its own it flagged 480 developer tools on one workstation.
    if any(REASONS[code][0] for code in codes) and entry["location"] == "user_writable" and entry["amcache"] \
            and not any(item["publisher"] for item in entry["amcache"]):
        codes.append("no_publisher_recorded")
    return [{"code": code, "meaning": REASONS[code][1], "does_not_establish": REASONS[code][2]} for code in codes]
