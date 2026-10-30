"""Explainable links between Windows event records and forensic artifact observations.

Relationships describe which recorded field values match across sources and
which claims those matches support. They never establish causation from time
alone. Each relationship separates observed field matches from inferences and
lists what remains unestablished. Matching is indexed by host and executable,
not a pairwise comparison of every event against every artifact.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import ntpath
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from models.event_model import Alert, NormalizedEvent

SCHEMA_VERSION = "1.2"  # 1.1 adds configuration-change links and contradictions; 1.2 NTFS links and assumptions
RULES = {
    "configured_action_matches_process_image": "1",
    "prefetch_run_matches_process_creation": "1",
    "configuration_event_matches_record": "1",
    "process_image_matches_file_record": "1",
}
# Events that record a configuration change, keyed to the snapshot record kind.
CONFIG_EVENTS = {
    4698: ("scheduled_task", "created"), 4702: ("scheduled_task", "updated"), 4699: ("scheduled_task", "deleted"),
    7045: ("service", "installed"), 4697: ("service", "installed"),
    13: ("registry_run", "value_set"),
}
_TASK_EXEC = re.compile(r"<Exec>\s*<Command>(.*?)</Command>(?:\s*<Arguments>(.*?)</Arguments>)?", re.S)
_RUN_KEY = re.compile(r"\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\run(?:once)?\\", re.I)
LINK_CLASSES = ("observed_field_match", "supported_inference", "weak_temporal_association", "analyst_hypothesis")
# Prefetch is written after a process starts; the recorded run is normally
# shortly after the process-creation event on the same host clock. The window
# is a reviewed heuristic, recorded on every relationship it produces.
PREFETCH_WINDOW_BEFORE = timedelta(seconds=5)
PREFETCH_WINDOW_AFTER = timedelta(seconds=60)
# A journal FILE_CREATE for the image path from one hour before to 5 s after
# the process event is "near" it; a reviewed heuristic recorded on each link.
USN_CREATE_WINDOW_BEFORE = timedelta(hours=1)
USN_CREATE_WINDOW_AFTER = timedelta(seconds=5)
CLOCK_SKEW = timedelta(seconds=2)
FILE_SYSTEM_KINDS = {"ntfs_file", "usn_change"}
MAX_CANDIDATES = 20
MAX_RELATIONSHIPS = 50_000
LAUNCHERS = {
    "scheduled_task": {"taskeng.exe", "taskhostw.exe", "taskhost.exe", "svchost.exe"},
    "service": {"services.exe"},
    "registry_run": {"explorer.exe", "userinit.exe"},
}
MECHANISM = {"scheduled_task": "scheduled task", "service": "service", "registry_run": "registry autorun"}
_IMAGE = re.compile(r"(.+?\.(?:exe|com|scr|bat|cmd))(?=\s|$)", re.I)
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _host_key(host: str) -> str:
    # NetBIOS and FQDN forms of one name compare equal; raw values are retained.
    return str(host or "").strip().casefold().split(".")[0]


def _path_key(path: str) -> str:
    text = str(path or "").strip().strip('"').replace("/", "\\")
    if text.startswith("\\??\\"):
        text = text[4:]
    return re.sub(r"\\+", r"\\", text).casefold()


def command_image(command: str) -> tuple[str, str]:
    """Return (normalized full image path, unresolved reason) for a configured command."""
    text = str(command or "").strip()
    if not text:
        return "", "empty_command"
    if text.startswith('"'):
        end = text.find('"', 1)
        image = text[1:end] if end > 0 else ""
    else:
        match = _IMAGE.match(text)
        image = match.group(1) if match else text.split()[0]
    if "%" in image or image.casefold().startswith("\\systemroot\\"):
        return "", "environment_relative_path"
    key = _path_key(image)
    if not re.match(r"^[a-z]:\\", key):
        return "", "not_a_full_path"
    return key, ""


def is_process_creation(event: NormalizedEvent) -> bool:
    channel = f"{event.channel} {event.provider}".casefold()
    if event.event_id == 4688:
        return "sysmon" not in channel
    return event.event_id == 1 and "sysmon" in channel


def _relationship_id(rule: str, source_id: str, target_id: str) -> str:
    identity = json.dumps([rule, RULES[rule], source_id, target_id], separators=(",", ":"))
    return "rel_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _event_ref(event: NormalizedEvent) -> dict:
    return {"observation_id": event.observation_id, "source_kind": "windows_event",
            "source_file": event.source_file, "source_sha256": event.source_sha256,
            "record_id": event.record_id, "event_id": event.event_id, "channel": event.channel,
            "host": event.computer, "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "time_semantics": "event_recorded_time", "process": event.process_name,
            "parent_process": event.parent_process}


def _artifact_ref(observation: dict) -> dict:
    return {"observation_id": observation["id"], "source_kind": "forensic_artifact",
            "artifact_kind": observation["kind"], "source_file": observation.get("source_file", ""),
            "source_record": observation.get("source_record"), "source_sha256": observation.get("source_sha256", ""),
            "host": observation.get("host", ""), "timestamp": observation.get("timestamp") or observation.get("observed_at"),
            "time_semantics": observation.get("time_semantics", "")}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else None


def correlate_evidence(events: Iterable[NormalizedEvent], observations: list[dict], *, ntfs=None) -> tuple[list[dict], dict]:
    """Return (relationships, coverage) for process events and artifact observations.

    ``ntfs`` is an optional ``ntfs_artifacts.NtfsEvidence``. File-system
    observations that a link targets are materialized from its index and
    appended to ``observations``, so every link target is a recorded observation.
    """
    by_path: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    by_name: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    process_count = without_locator = 0
    events_list = list(events)
    for event in events_list:
        if not is_process_creation(event):
            continue
        process_count += 1
        image = _path_key(event.process_name)
        if not event.observation_id or event.timestamp is None or event.timestamp.tzinfo is None or not image:
            without_locator += 1
            continue
        host = _host_key(event.computer)
        by_path[(host, image)].append(event)
        by_name[(host, ntpath.basename(image))].append(event)
    for bucket in by_name.values():
        bucket.sort(key=lambda item: (item.timestamp, item.observation_id))
    for bucket in by_path.values():
        bucket.sort(key=lambda item: (item.timestamp, item.observation_id))

    config_index, config_count = _index_configuration_events(events_list)
    relationships: list[dict] = []
    unresolved = Counter()
    kinds = Counter(observation["kind"] for observation in observations)
    for observation in observations:
        if len(relationships) >= MAX_RELATIONSHIPS:
            break
        if observation["kind"] in LAUNCHERS:
            relationships.extend(_configured_action_links(observation, by_path, unresolved))
            relationships.extend(_configuration_event_links(observation, config_index))
        elif observation["kind"] == "prefetch_run":
            relationships.extend(_prefetch_links(observation, by_name))
    if ntfs is not None and ntfs.mft is not None and len(relationships) < MAX_RELATIONSHIPS:
        known = {observation["id"] for observation in observations}
        relationships.extend(_ntfs_links(by_path, ntfs))
        observations.extend(item for key, item in ntfs.materialized.items() if key not in known)
    relationships = relationships[:MAX_RELATIONSHIPS]
    relationships.sort(key=lambda item: item["relationship_id"])

    def family(count: int, supplied: bool) -> str:
        return "not_supplied" if not supplied else ("observed" if count else "supplied_no_records")

    persistence_count = sum(kinds[kind] for kind in LAUNCHERS)
    coverage = {
        "schema_version": SCHEMA_VERSION,
        "families": {
            "windows_process_creation": {"status": "observed" if process_count else "no_records",
                                         "count": process_count, "unlinkable_without_locator": without_locator},
            "windows_configuration_change": {"status": "observed" if config_count else "no_records", "count": config_count},
            "prefetch": {"status": family(kinds["prefetch_run"], bool(kinds["prefetch_run"] or kinds["prefetch_record"])),
                         "run_observations": kinds["prefetch_run"], "records_without_run_time": kinds["prefetch_record"]},
            "persistence_configuration": {"status": family(persistence_count, bool(persistence_count)),
                                          "count": persistence_count,
                                          "unresolved_command_paths": dict(unresolved)},
            "browser_download": {"status": "observed_not_correlated" if kinds["browser_download"] else "not_supplied",
                                 "count": kinds["browser_download"]},
            **(ntfs.coverage() if ntfs is not None else
               {"ntfs_mft": {"status": "not_supplied"}, "usn_journal": {"status": "not_supplied"}}),
        },
        "limitations": [
            "Missing or unsupplied evidence is not proof that activity did not occur.",
            "Commands using environment variables or relative paths are not resolved and are not linked.",
            "Prefetch links match executable name, host, and a time window; Prefetch does not record the full path or user in this export.",
            "Configuration observed at collection time does not establish that it existed when the event was recorded.",
            "Run-key writes are matched by key path after the hive root; HKCU and HKU\\<SID> forms are not mapped to a specific user.",
            "$MFT timestamps can be altered (timestomping); $STANDARD_INFORMATION and $FILE_NAME times are kept separate, never merged.",
            "The USN journal rolls over; a missing journal record is not proof that no change occurred.",
        ],
    }
    return relationships, coverage


def _configured_action_links(observation, by_path, unresolved) -> list[dict]:
    details = observation.get("details", {})
    image, reason = command_image(details.get("command", ""))
    if reason:
        unresolved[reason] += 1
        return []
    kind = observation["kind"]
    events = by_path.get((_host_key(observation.get("host", "")), image), [])
    links = []
    for event in events[:MAX_CANDIDATES]:
        parent = ntpath.basename(_path_key(event.parent_process))
        inferred = []
        if parent in LAUNCHERS[kind]:
            inferred.append({
                "class": "supported_inference",
                "claim": f"The recorded process launch is consistent with the {MECHANISM[kind]} mechanism.",
                "basis": [f"parent_process:{parent}"],
            })
        links.append({
            "schema_version": SCHEMA_VERSION,
            "relationship_id": _relationship_id("configured_action_matches_process_image", event.observation_id, observation["id"]),
            "type": "target_path",
            "rule": {"name": "configured_action_matches_process_image", "version": RULES["configured_action_matches_process_image"]},
            "link_class": "observed_field_match",
            "source": _event_ref(event), "target": _artifact_ref(observation),
            "matched_fields": [
                {"event_field": "process_name", "artifact_field": "details.command (executable)", "value": image},
                {"event_field": "computer", "artifact_field": "host", "event_value": event.computer,
                 "artifact_value": observation.get("host", "")},
            ],
            "time_relation": {"event_time": event.timestamp.isoformat(), "artifact_time": observation.get("observed_at"),
                              "artifact_time_semantics": observation.get("time_semantics", ""),
                              "ordering_meaningful": False},
            "inferred_claims": inferred,
            "contradictions": [],
            "ambiguity": {"candidate_events": len(events), "truncated": len(events) > MAX_CANDIDATES},
            "establishes": [f"A configured {MECHANISM[kind]} action and a recorded process creation name the same executable path on the same host."],
            "does_not_establish": [
                f"That this {MECHANISM[kind]} launched this process.",
                "That the configuration existed when the process was created.",
                "That the executable at that path was the same file at both times.",
            ],
        })
    return links


def _prefetch_links(observation, by_name) -> list[dict]:
    artifact_time = _parse_time(observation.get("timestamp"))
    name = str(observation.get("details", {}).get("name", "")).strip().casefold()
    if artifact_time is None or not name:
        return []
    bucket = by_name.get((_host_key(observation.get("host", "")), name), [])
    times = [event.timestamp for event in bucket]
    start = bisect.bisect_left(times, artifact_time - PREFETCH_WINDOW_AFTER)
    end = bisect.bisect_right(times, artifact_time + PREFETCH_WINDOW_BEFORE)
    candidates = bucket[start:end]
    files_loaded = str((observation.get("details", {}).get("export_record") or {}).get("FilesLoaded", "")).casefold()
    links = []
    for event in candidates[:MAX_CANDIDATES]:
        image = _path_key(event.process_name)
        delta = (artifact_time - event.timestamp).total_seconds()
        matched = [
            {"event_field": "process_name (file name)", "artifact_field": "details.name", "value": name},
            {"event_field": "computer", "artifact_field": "host", "event_value": event.computer,
             "artifact_value": observation.get("host", "")},
        ]
        suffix = image[2:] if re.match(r"^[a-z]:\\", image) else ""
        if suffix and suffix in files_loaded:
            matched.append({"event_field": "process_name (path without drive)", "artifact_field": "export_record.FilesLoaded",
                            "value": suffix})
        unique = len(candidates) == 1
        links.append({
            "schema_version": SCHEMA_VERSION,
            "relationship_id": _relationship_id("prefetch_run_matches_process_creation", event.observation_id, observation["id"]),
            "type": "within_time_window",
            "rule": {"name": "prefetch_run_matches_process_creation", "version": RULES["prefetch_run_matches_process_creation"]},
            "link_class": "supported_inference" if unique else "weak_temporal_association",
            "source": _event_ref(event), "target": _artifact_ref(observation),
            "matched_fields": matched,
            "time_relation": {"event_time": event.timestamp.isoformat(), "artifact_time": artifact_time.isoformat(),
                              "artifact_time_semantics": observation.get("time_semantics", ""),
                              "artifact_minus_event_seconds": delta,
                              "window_seconds": {"before_event": PREFETCH_WINDOW_BEFORE.total_seconds(),
                                                 "after_event": PREFETCH_WINDOW_AFTER.total_seconds()},
                              "ordering_meaningful": True},
            "inferred_claims": [{
                "class": "supported_inference" if unique else "weak_temporal_association",
                "claim": "The Prefetch recorded run corresponds to this process creation."
                         if unique else "The Prefetch recorded run may correspond to one of several process creations.",
                "basis": ["same_host", "same_executable_name", "recorded_run_within_window"],
            }],
            "contradictions": [],
            "ambiguity": {"candidate_events": len(candidates), "truncated": len(candidates) > MAX_CANDIDATES},
            "establishes": ["Prefetch and the event log both record execution of an executable with this name on this host near this time."],
            "does_not_establish": [
                "That both records describe the same binary or full path." if len(matched) < 3 else
                "That the loaded-file path in Prefetch belongs to the same binary content.",
                "Which user ran the executable.",
                "Malicious intent.",
            ],
        })
    return links


def cross_source_alerts(relationships: list[dict], events: Iterable[NormalizedEvent], alerts: list[Alert]) -> list[Alert]:
    """Raise a finding only when a linked process or configuration is already suspicious.

    A link between benign records is retained as a relationship, never scored.
    """
    by_event: dict[str, list[dict]] = defaultdict(list)
    for relationship in relationships:
        by_event[relationship["source"]["observation_id"]].append(relationship)
    if not by_event:
        return []
    events_by_id = {event.observation_id: event for event in events if event.observation_id in by_event}
    event_alerts: dict[str, list[Alert]] = defaultdict(list)
    artifact_alerts: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.rule_source == "forensic_correlation":
            continue
        if alert.event is not None and alert.event.observation_id in by_event:
            event_alerts[alert.event.observation_id].append(alert)
        elif alert.event is None and (alert.evidence or {}).get("observation_id"):
            artifact_alerts[alert.evidence["observation_id"]].append(alert)
    from triage_engine.adapters import _finding_candidate

    intrinsic = {"weak_evidence", "service_not_suspicious"}

    def suspicious(alert: Alert) -> bool:
        # A link shows the same configuration or execution was recorded twice, not that it
        # is malicious. It may corroborate an alert that only lacks corroboration, but it
        # must not promote one rejected on its own terms: a routine "Service Installed"
        # signal (such as a Defender driver), weak evidence, or a detector's explicit
        # signal_only policy.
        if (alert.promotion_policy or "").lower() == "signal_only":
            return False
        return not intrinsic & set(_finding_candidate(alert, 1)[1])

    results = []
    for observation_id in sorted(by_event):
        links = by_event[observation_id]
        event = events_by_id.get(observation_id)
        contributing = [alert for alert in event_alerts.get(observation_id, []) if suspicious(alert)]
        for link in links:
            contributing.extend(alert for alert in artifact_alerts.get(link["target"]["observation_id"], [])
                                if suspicious(alert))
        if event is None or not contributing:
            continue
        strong = [link for link in links if link["link_class"] in {"observed_field_match", "supported_inference"}]
        if not strong:
            continue
        # A file record existing at the image path is context, not corroboration.
        strong = [link for link in strong if link["target"]["artifact_kind"] != "ntfs_file"]
        if not strong:
            continue
        families = sorted({link["target"]["artifact_kind"] for link in strong})
        # One family per evidence type, not per parser: PECmd and the native parser reading the
        # same .pf both yield prefetch_run and count once.
        independent = len({"prefetch" if kind.startswith("prefetch") else
                           "file_system" if kind in FILE_SYSTEM_KINDS else "configuration" for kind in families})
        severity = max((alert.severity.lower() for alert in contributing), key=lambda item: SEVERITY_ORDER.get(item, 0))
        lead = sorted(contributing, key=lambda item: (-SEVERITY_ORDER.get(item.severity.lower(), 0), item.rule_name))[0]
        if is_process_creation(event):
            subject = ntpath.basename(event.process_name) or event.process_name
            rule_name, recorded = "Cross-Source: Suspicious process linked to forensic artifacts", "process creation"
        else:
            subject = event.task_name or event.service_name or (event.event_data or {}).get("TargetObject", "")
            rule_name, recorded = "Cross-Source: Suspicious configuration change linked to snapshot", "configuration change"
        results.append(Alert(
            rule_name=rule_name,
            severity=severity if severity in SEVERITY_ORDER else "medium",
            mitre_tactic=lead.mitre_tactic, mitre_technique=lead.mitre_technique,
            description=f"{subject}: event-log {recorded} linked to {', '.join(families)} evidence.",
            explanation=(f"Recorded {recorded} and independent artifact records share the field values listed in the "
                         "relationships. The links support, but do not prove, that both describe the same activity. "
                         "Review any listed contradictions."),
            event=event, rule_source="forensic_correlation", promotion_policy="standalone",
            confidence="high" if independent >= 2 else "medium",
            confidence_factors=["cross_source_link", *(f"link:{link['link_class']}" for link in strong[:5])],
            investigate_next=("Confirm the binary hash at the linked path, review the configuration's creation history, "
                              "and identify the account and logon session for the process."),
            evidence={
                "time_semantics": "cross_source_correlation",
                "relationship_ids": [link["relationship_id"] for link in links],
                "supporting_observation_ids": sorted({observation_id, *(link["target"]["observation_id"] for link in links)}),
                "linked_artifact_kinds": families,
                "contributing_alerts": sorted({alert.rule_name for alert in contributing}),
                "link_classes": dict(Counter(link["link_class"] for link in links)),
                "established": sorted({claim for link in strong for claim in link["establishes"]}),
                "not_established": sorted({claim for link in links for claim in link["does_not_establish"]}),
                "contradictions": [{**item, "relationship_id": link["relationship_id"]}
                                   for link in links for item in link.get("contradictions", [])],
                "alternate_explanations": ["Legitimate software configured to start this executable.",
                                           "A different binary with the same name or a later replacement at the same path."],
                "missing_evidence": ["Binary hash or file-system metadata for the linked path.",
                                     "Configuration creation event (for example 4698 or 7045) when not present."],
                "evidence_strength": "high" if independent >= 2 else "medium",
                "event_recorded_process_creation": True,
            },
        ))
    return results


def _norm_text(value: str) -> str:
    text = str(value or "").strip().replace("&quot;", '"').replace("&amp;", "&")
    return re.sub(r"\s+", " ", text).casefold()


def _config_key(kind: str, name: str, location: str = "") -> str:
    if kind == "scheduled_task":
        folder = str(location or "\\").strip().rstrip("\\")
        return _path_key(name if str(name).startswith("\\") else f"{folder}\\{name}")
    if kind == "registry_run":
        full = "\\" + _path_key(location) + "\\" + _path_key(name)
        match = _RUN_KEY.search(full)
        return full[match.start():] if match else ""
    return str(name or "").strip().casefold()


def _event_configuration(event: NormalizedEvent):
    """Return (record kind, change, identity key, configured command) for a configuration event."""
    spec = CONFIG_EVENTS.get(event.event_id)
    if not spec:
        return None
    kind, change = spec
    channel = f"{event.channel} {event.provider}".casefold()
    data = event.event_data or {}
    if event.event_id == 13:
        if "sysmon" not in channel:
            return None
        target = _path_key(data.get("TargetObject", ""))
        match = _RUN_KEY.search(target)
        return (kind, change, target[match.start():], data.get("Details", "")) if match else None
    if "sysmon" in channel:
        return None
    if kind == "scheduled_task":
        content = str(data.get("TaskContent", "") or data.get("TaskContentNew", ""))[:65536]
        found = _TASK_EXEC.search(content)
        command = " ".join(part.strip() for part in found.groups() if part) if found else ""
        return kind, change, _path_key(data.get("TaskName", "")), command
    return kind, change, str(event.service_name or "").strip().casefold(), \
        data.get("ImagePath", "") or data.get("ServiceFileName", "")


def _index_configuration_events(events: list[NormalizedEvent]):
    index: dict[tuple[str, str, str], list] = defaultdict(list)
    count = 0
    for event in events:
        parsed = _event_configuration(event)
        if parsed is None:
            continue
        count += 1
        kind, change, key, command = parsed
        if key and event.observation_id and event.timestamp is not None and event.timestamp.tzinfo is not None:
            index[(_host_key(event.computer), kind, key)].append((event, change, command))
    for bucket in index.values():
        bucket.sort(key=lambda item: (item[0].timestamp, item[0].observation_id))
    return index, count


def _configuration_event_links(observation, index) -> list[dict]:
    details = observation.get("details", {})
    kind = observation["kind"]
    key = _config_key(kind, details.get("name", ""), details.get("location", ""))
    if not key:
        return []
    bucket = index.get((_host_key(observation.get("host", "")), kind, key), [])
    collected = _parse_time(observation.get("observed_at"))
    field = {"registry_run": "TargetObject", "scheduled_task": "TaskName", "service": "ServiceName"}[kind]
    links = []
    for event, change, command in bucket[:MAX_CANDIDATES]:
        matched = [{"event_field": field, "artifact_field": "details.name/location", "value": key},
                   {"event_field": "computer", "artifact_field": "host", "event_value": event.computer,
                    "artifact_value": observation.get("host", "")}]
        contradictions = []
        record_command = details.get("command", "")
        if command and record_command:
            if _norm_text(command) == _norm_text(record_command):
                matched.append({"event_field": "configured command", "artifact_field": "details.command", "value": record_command})
            else:
                contradictions.append({"field": "command", "event_value": command, "artifact_value": record_command,
                                       "meaning": "The configured command differs; it may have changed between the event and collection."})
        before_collection = None if collected is None else event.timestamp <= collected
        if change == "deleted" and before_collection:
            contradictions.append({"field": "existence", "event_value": "deleted", "artifact_value": "present at collection",
                                   "meaning": "Deleted before collection yet present in the snapshot; it may have been recreated."})
        inferred = []
        if not contradictions and change != "deleted":
            inferred.append({"class": "supported_inference",
                             "claim": f"The configuration seen at collection is the one {change} by this event.",
                             "basis": ["same_host", "same_configuration_name", *(["same_command"] if len(matched) > 2 else [])]})
        links.append({
            "schema_version": SCHEMA_VERSION,
            "relationship_id": _relationship_id("configuration_event_matches_record", event.observation_id, observation["id"]),
            "type": "same_configuration_object",
            "rule": {"name": "configuration_event_matches_record", "version": RULES["configuration_event_matches_record"]},
            "link_class": "observed_field_match",
            "source": {**_event_ref(event), "configuration_change": change},
            "target": _artifact_ref(observation),
            "matched_fields": matched,
            "time_relation": {"event_time": event.timestamp.isoformat(), "artifact_time": observation.get("observed_at"),
                              "artifact_time_semantics": observation.get("time_semantics", ""),
                              "event_before_collection": before_collection, "ordering_meaningful": True},
            "inferred_claims": inferred,
            "contradictions": contradictions,
            "ambiguity": {"candidate_events": len(bucket), "truncated": len(bucket) > MAX_CANDIDATES},
            "establishes": [f"The event log records a {MECHANISM[kind]} change ({change}) with the same name as a configuration observed at collection."],
            "does_not_establish": ["That the configured command executed.",
                                   "That no other change occurred between the event and collection."],
        })
    return links


def _ntfs_times(observation: dict) -> dict:
    return {field: value["value"] for field, value in observation["details"]["times"].items()}


def _ntfs_links(by_path, ntfs) -> list[dict]:
    """Link process images to the $MFT record at the same path and to nearby journal FILE_CREATE records.

    Paths are matched through one indexed pass over the $MFT name table, never
    by comparing every event with every record.
    """
    host = _host_key(ntfs.host)
    volume = ntfs.volume.casefold()
    wanted: dict[str, list[tuple[str, list[NormalizedEvent]]]] = defaultdict(list)
    for (event_host, image), bucket in by_path.items():
        if event_host != host or not re.match(r"^[a-z]:\\", image) or (volume and image[:2] != volume):
            continue
        wanted[image[2:]].append((image[:2], bucket))
    if not wanted:
        return []
    matches = ntfs.mft.lookup_paths(wanted)
    creates = ntfs.usn_creates_for(entry for entries in matches.values() for entry in entries[:MAX_CANDIDATES])
    links = []
    for volume_path in sorted(matches):
        entries = matches[volume_path]
        for drive, bucket in wanted[volume_path]:
            assumptions = [] if volume else [
                f"No volume mapping was supplied; the $MFT is assumed to describe drive {drive.upper()} named in the event."]
            for entry in entries[:MAX_CANDIDATES]:
                si_obs, fn_obs = ntfs.file_observations(entry)
                links.extend(_file_record_links(bucket, si_obs, fn_obs, len(entries), assumptions))
                links.extend(_usn_create_links(bucket, ntfs, si_obs, creates.get(entry, []), assumptions))
    return links


def _file_record_links(bucket, si_obs, fn_obs, candidate_records, assumptions) -> list[dict]:
    details = fn_obs["details"]
    si_times, fn_times = _ntfs_times(si_obs), _ntfs_times(fn_obs)
    created = [_parse_time(value) for value in (si_times["created"], fn_times["created"]) if value]
    links = []
    for event in bucket[:MAX_CANDIDATES]:
        contradictions = [dict(item) for item in details["contradictions"]]
        if created and all(value > event.timestamp + CLOCK_SKEW for value in created):
            contradictions.append({"field": "created", "event_value": event.timestamp.isoformat(),
                                   "artifact_value": {"mft_standard_information": si_times["created"],
                                                      "mft_file_name": fn_times["created"]},
                                   "meaning": "The current file record was created after the process event; the path "
                                              "may now hold a different file."})
        if not details["in_use"]:
            contradictions.append({"field": "in_use", "event_value": "image path executed", "artifact_value": "record not in use",
                                   "meaning": "The $MFT record is marked deleted; it may describe an earlier or later file."})
        links.append({
            "schema_version": SCHEMA_VERSION,
            "relationship_id": _relationship_id("process_image_matches_file_record", event.observation_id, fn_obs["id"]),
            "type": "same_file_path",
            "rule": {"name": "process_image_matches_file_record", "version": RULES["process_image_matches_file_record"]},
            "link_class": "observed_field_match",
            "source": _event_ref(event), "target": _artifact_ref(fn_obs),
            "related_observation_ids": [si_obs["id"]],
            "matched_fields": [
                {"event_field": "process_name (path without drive)", "artifact_field": "$FILE_NAME parent chain",
                 "value": details["path"]},
                {"event_field": "computer", "artifact_field": "host", "event_value": event.computer,
                 "artifact_value": fn_obs.get("host", "")},
            ],
            "time_relation": {"event_time": event.timestamp.isoformat(), "artifact_time": fn_times["created"],
                              "artifact_time_semantics": "mft_file_name",
                              "artifact_times": {"mft_standard_information": si_times, "mft_file_name": fn_times},
                              "ordering_meaningful": False},
            "inferred_claims": [],
            "assumptions": list(assumptions),
            "contradictions": contradictions,
            "ambiguity": {"candidate_events": len(bucket), "truncated": len(bucket) > MAX_CANDIDATES,
                          "candidate_file_records": candidate_records},
            "establishes": ["The $MFT at collection has a file record at the path of the recorded process image."],
            "does_not_establish": [
                "That the file in this record is the binary that ran.",
                "That the $MFT timestamps are unaltered.",
                "That the file has not been replaced or modified since the process event.",
            ],
        })
    return links


def _usn_create_links(bucket, ntfs, si_obs, creates, assumptions) -> list[dict]:
    if not creates:
        return []
    times = [event.timestamp for event in bucket]
    si_created = _parse_time(_ntfs_times(si_obs)["created"])
    by_event: dict[str, list] = defaultdict(list)
    events_by_id = {}
    for create, same_reference in creates:
        observation = None
        created = None
        # Events whose time lies from AFTER before the journal record to BEFORE after it.
        stamp = ntfs.usn_time(create)
        if stamp is None:
            continue
        start = bisect.bisect_left(times, stamp - USN_CREATE_WINDOW_AFTER)
        end = bisect.bisect_right(times, stamp + USN_CREATE_WINDOW_BEFORE)
        for event in bucket[start:end][:MAX_CANDIDATES]:
            if observation is None:
                observation = ntfs.usn_observation(create)
                created = stamp
            by_event[event.observation_id].append((observation, created, same_reference))
            events_by_id[event.observation_id] = event
    links = []
    for event_id in sorted(by_event):
        candidates = by_event[event_id]
        event = events_by_id[event_id]
        unique = len(candidates) == 1
        for observation, created, same_reference in candidates[:MAX_CANDIDATES]:
            supported = unique and same_reference
            link_class = "supported_inference" if supported else "weak_temporal_association"
            contradictions = []
            if same_reference and si_created is not None and si_created + CLOCK_SKEW < created:
                contradictions.append({"field": "created", "event_value": None,
                                       "artifact_value": {"usn_journal_record": created.isoformat(),
                                                          "mft_standard_information": si_created.isoformat()},
                                       "meaning": "$STANDARD_INFORMATION creation is earlier than the journal-recorded "
                                                  "creation of the same file reference; $SI may have been altered."})
            links.append({
                "schema_version": SCHEMA_VERSION,
                "relationship_id": _relationship_id("process_image_matches_file_record", event.observation_id, observation["id"]),
                "type": "file_created_before_process",
                "rule": {"name": "process_image_matches_file_record", "version": RULES["process_image_matches_file_record"]},
                "link_class": link_class,
                "source": _event_ref(event), "target": _artifact_ref(observation),
                "related_observation_ids": [si_obs["id"], si_obs["details"]["companion_observation_id"]],
                "matched_fields": [
                    {"event_field": "process_name (path without drive)", "artifact_field": "USN parent reference + name",
                     "value": observation["details"]["path"]},
                    *([{"event_field": "$MFT file reference", "artifact_field": "FileReferenceNumber",
                        "value": si_obs["details"]["file_reference"]}] if same_reference else []),
                    {"event_field": "computer", "artifact_field": "host", "event_value": event.computer,
                     "artifact_value": observation.get("host", "")},
                ],
                "time_relation": {"event_time": event.timestamp.isoformat(), "artifact_time": created.isoformat(),
                                  "artifact_time_semantics": "usn_journal_record",
                                  "artifact_minus_event_seconds": (created - event.timestamp).total_seconds(),
                                  "window_seconds": {"before_event": USN_CREATE_WINDOW_BEFORE.total_seconds(),
                                                     "after_event": USN_CREATE_WINDOW_AFTER.total_seconds()},
                                  "ordering_meaningful": True},
                "inferred_claims": [{
                    "class": link_class,
                    "claim": ("The file at the process image path was created shortly before the process started."
                              if supported else "A file with this path may have been created near the process start."),
                    "basis": ["same_host", "same_path", "journal_create_within_window",
                              "same_file_reference" if same_reference else "file_reference_differs"],
                }],
                "assumptions": list(assumptions),
                "contradictions": contradictions,
                "ambiguity": {"candidate_journal_records": len(candidates), "truncated": len(candidates) > MAX_CANDIDATES},
                "establishes": ["The USN journal recorded creation of a file at the process image path near the process time."],
                "does_not_establish": [
                    "That the created file is the binary that ran.",
                    "Who or what created the file.",
                    "That no other creation occurred; the journal rolls over and may be incomplete.",
                    "That the directory path was the same at change time; it is resolved against the current $MFT.",
                ],
            })
    return links
