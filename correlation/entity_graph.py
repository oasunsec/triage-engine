"""Entity graph builder for analyst pivoting and Cytoscape exports."""

from __future__ import annotations

from typing import Dict, List

from models.event_model import Finding, Incident, Signal
from triage_engine.id_utils import stable_id
from triage_engine.user_utils import normalize_user_identity

NOISY_USERS = {
    "",
    "-",
    "unknown",
    "system",
    "nt authority\\system",
    "local service",
    "nt authority\\local service",
    "network service",
    "nt authority\\network service",
}


def build_entity_graph(signals: List[Signal], findings: List[Finding], incidents: List[Incident]) -> Dict:
    nodes: Dict[str, dict] = {}
    edges: Dict[str, dict] = {}

    def upsert_node(
        entity_type: str,
        value: str,
        ref_id: str,
        display_value: str | None = None,
        raw_value: str | None = None,
    ) -> str:
        clean = (value or "").strip()
        if not _is_graphable(clean, entity_type):
            return ""

        if entity_type == "command":
            node_id = f"command:{stable_id('cmd', {'command': clean}, length=12)}"
            label = _truncate(display_value or clean, 80)
        else:
            node_id = f"{entity_type}:{clean.lower()}"
            label = display_value or clean

        node = nodes.setdefault(
            node_id,
            {
                "data": {
                    "id": node_id,
                    "label": label,
                    "type": entity_type,
                    "value": clean,
                    "ref_ids": [],
                    "raw_values": [],
                }
            },
        )
        if ref_id and ref_id not in node["data"]["ref_ids"]:
            node["data"]["ref_ids"].append(ref_id)
        raw = (raw_value or clean).strip()
        if raw and raw not in node["data"]["raw_values"]:
            node["data"]["raw_values"].append(raw)
        return node_id

    def upsert_edge(source: str, target: str, edge_type: str, ref_id: str) -> None:
        if not source or not target or source == target:
            return
        edge_id = f"{edge_type}:{source}->{target}"
        edge = edges.setdefault(
            edge_id,
            {
                "data": {
                    "id": edge_id,
                    "source": source,
                    "target": target,
                    "type": edge_type,
                    "ref_ids": [],
                }
            },
        )
        if ref_id and ref_id not in edge["data"]["ref_ids"]:
            edge["data"]["ref_ids"].append(ref_id)

    def link_item(item) -> None:
        ref_id = item.id
        host_node = upsert_node("host", getattr(item, "host", ""), ref_id)
        service_node = upsert_node("service", getattr(item, "service", ""), ref_id)
        process_node = upsert_node("process", getattr(item, "process", ""), ref_id)
        command_node = upsert_node("command", getattr(item, "command_line", ""), ref_id)
        evidence = getattr(item, "evidence", {}) or {}

        registry_values = []
        for value in [
            evidence.get("registry_key", ""),
            evidence.get("target_object", ""),
            *[entry for entry in evidence.get("registry_paths", []) or [] if entry],
            *[entry for entry in evidence.get("alias_paths", []) or [] if entry],
            *[entry for entry in evidence.get("sam_paths", []) or [] if entry],
        ]:
            clean = (value or "").strip()
            if clean and clean not in registry_values:
                registry_values.append(clean)

        users = []
        for user in [
            getattr(item, "user", ""),
            getattr(item, "subject_user", ""),
            getattr(item, "target_user", ""),
            getattr(item, "account_name", ""),
        ]:
            identity = normalize_user_identity(user, getattr(item, "host", ""))
            canonical = identity["canonical"] or identity["raw"]
            if canonical and canonical not in [entry["canonical"] for entry in users]:
                users.append(
                    {
                        "canonical": canonical,
                        "display": identity["display"] or canonical,
                        "raw": identity["raw"] or canonical,
                    }
                )

        ips = []
        for ip in [getattr(item, "source_ip", ""), getattr(item, "destination_ip", "")]:
            if ip and ip not in ips:
                ips.append(ip)

        user_nodes = [
            upsert_node(
                "user",
                user["canonical"],
                ref_id,
                display_value=user["display"],
                raw_value=user["raw"],
            )
            for user in users
        ]
        user_nodes = [node for node in user_nodes if node]
        ip_nodes = [upsert_node("ip", ip, ref_id) for ip in ips]
        ip_nodes = [node for node in ip_nodes if node]
        registry_nodes = [upsert_node("registry", value, ref_id, display_value=_truncate(value, 80)) for value in registry_values]
        registry_nodes = [node for node in registry_nodes if node]

        for ip_node in ip_nodes:
            for user_node in user_nodes:
                upsert_edge(ip_node, user_node, "IP_TO_USER", ref_id)

        for user_node in user_nodes:
            upsert_edge(user_node, host_node, "USER_TO_HOST", ref_id)
            upsert_edge(user_node, process_node, "USER_TO_PROCESS", ref_id)
            for registry_node in registry_nodes:
                upsert_edge(user_node, registry_node, "USER_TO_REGISTRY", ref_id)

        upsert_edge(host_node, service_node, "HOST_TO_SERVICE", ref_id)
        upsert_edge(host_node, process_node, "HOST_TO_PROCESS", ref_id)
        for registry_node in registry_nodes:
            upsert_edge(host_node, registry_node, "HOST_TO_REGISTRY", ref_id)
            upsert_edge(process_node, registry_node, "PROCESS_TO_REGISTRY", ref_id)
        upsert_edge(service_node, process_node, "SERVICE_TO_PROCESS", ref_id)
        upsert_edge(process_node, command_node, "PROCESS_TO_COMMAND", ref_id)

    for collection in (signals, findings, incidents):
        for item in collection:
            link_item(item)

    return {
        "nodes": sorted(nodes.values(), key=lambda n: n["data"]["id"]),
        "edges": sorted(edges.values(), key=lambda e: e["data"]["id"]),
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "signal_refs": len(signals),
            "finding_refs": len(findings),
            "incident_refs": len(incidents),
        },
    }


def _is_graphable(value: str, entity_type: str) -> bool:
    clean = (value or "").strip()
    if not clean:
        return False
    if clean.lower() in {"-", "unknown"}:
        return False
    if entity_type == "user":
        user = clean.lower()
        if user in NOISY_USERS or user.endswith("$") or user.startswith(("font driver host\\umfd-", "window manager\\dwm-")):
            return False
    return True


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else f"{value[: limit - 3]}..."
