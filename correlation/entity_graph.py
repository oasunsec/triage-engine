"""Entity graph builder for analyst pivoting and Cytoscape exports."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Set

from models.event_model import Finding, Incident, Signal
from corrobora.id_utils import stable_id
from corrobora.user_utils import normalize_user_identity

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
    source_ip_nodes: Set[str] = set()
    suspected_attacker_nodes: Set[str] = set()

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
        for ip in [getattr(item, "source_ip", "")]:
            source_node = upsert_node("ip", ip, ref_id)
            if source_node:
                source_ip_nodes.add(source_node)
            if source_node and _is_external_source(ip):
                suspected_attacker_nodes.add(source_node)
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
        # A command hangs off its process; a service install has no process, so the
        # service (else the host) anchors it instead of leaving it unconnected.
        if process_node:
            upsert_edge(process_node, command_node, "PROCESS_TO_COMMAND", ref_id)
        elif service_node:
            upsert_edge(service_node, command_node, "SERVICE_TO_COMMAND", ref_id)
        else:
            upsert_edge(host_node, command_node, "HOST_TO_COMMAND", ref_id)

    item_info: Dict[str, dict] = {}
    for collection in (signals, findings, incidents):
        for item in collection:
            link_item(item)
            item_info[item.id] = {
                "title": getattr(item, "title", "") or getattr(item, "source_rule", "") or item.id,
                "first": _iso(getattr(item, "first_seen", None) or getattr(item, "timestamp", None)),
                "last": _iso(getattr(item, "last_seen", None) or getattr(item, "timestamp", None)),
            }
    for element in (*nodes.values(), *edges.values()):
        _add_time_and_rules(element["data"], item_info)
    for edge in edges.values():
        data = edge["data"]
        rules = data["rules"]
        data["relation"] = EDGE_RELATIONS.get(data["type"], data["type"].replace("_", " ").lower())
        data["label"] = (rules[0] if rules else data["relation"]) + (f" ×{data['count']}" if data["count"] > 1 else "")
    for node in nodes.values():
        node["data"]["type_label"] = NODE_TYPES.get(node["data"]["type"], node["data"]["type"].title())

    _assign_node_roles(nodes, edges, source_ip_nodes, suspected_attacker_nodes)

    return {
        "nodes": sorted(nodes.values(), key=lambda n: n["data"]["id"]),
        "edges": sorted(edges.values(), key=lambda e: e["data"]["id"]),
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "signal_refs": len(signals),
            "finding_refs": len(findings),
            "incident_refs": len(incidents),
            "role_counts": _role_counts(nodes),
        },
        "role_legend": [
            {"role": "entry_point", "label": "Observed entry point", "color": "#f97316"},
            {"role": "suspected_attacker", "label": "Suspected attacker", "color": "#dc2626"},
            {"role": "pivot_point", "label": "Pivot point", "color": "#7c3aed"},
            {"role": "supporting", "label": "Supporting entity", "color": "#64748b"},
        ],
    }


EDGE_RELATIONS = {
    "IP_TO_USER": "source address used account", "USER_TO_HOST": "account active on host",
    "USER_TO_PROCESS": "account ran process", "USER_TO_REGISTRY": "account changed registry",
    "HOST_TO_SERVICE": "service on host", "HOST_TO_PROCESS": "process on host",
    "HOST_TO_REGISTRY": "registry change on host", "PROCESS_TO_REGISTRY": "process changed registry",
    "SERVICE_TO_PROCESS": "service started process", "PROCESS_TO_COMMAND": "process command line",
    "SERVICE_TO_COMMAND": "service command line", "HOST_TO_COMMAND": "command on host",
}
NODE_TYPES = {"ip": "IP address", "user": "Account", "host": "Host", "service": "Service",
              "process": "Process", "command": "Command line", "registry": "Registry key"}


def _iso(value) -> str:
    if value is None or value == "":
        return ""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _add_time_and_rules(data: dict, item_info: Dict[str, dict]) -> None:
    """Attach first/last seen, how many alerts mention the element, and their rule titles."""
    infos = [item_info[ref] for ref in data.get("ref_ids", []) if ref in item_info]
    firsts = sorted(info["first"] for info in infos if info["first"])
    lasts = sorted(info["last"] for info in infos if info["last"])
    data["first_seen"] = firsts[0] if firsts else ""
    data["last_seen"] = lasts[-1] if lasts else data["first_seen"]
    data["count"] = len(infos)
    titles: Dict[str, int] = {}
    for info in infos:
        titles[info["title"]] = titles.get(info["title"], 0) + 1
    data["rules"] = [title for title, _ in sorted(titles.items(), key=lambda item: (-item[1], item[0]))][:5]


ROLE_STYLES = {
    "entry_point": {"label": "Observed entry point", "color": "#f97316"},
    "suspected_attacker": {"label": "Suspected attacker", "color": "#dc2626"},
    "pivot_point": {"label": "Pivot point", "color": "#7c3aed"},
    "supporting": {"label": "Supporting entity", "color": "#64748b"},
}


def _assign_node_roles(
    nodes: Dict[str, dict],
    edges: Dict[str, dict],
    source_ip_nodes: Set[str],
    suspected_attacker_nodes: Set[str],
) -> None:
    """Add explainable visual roles without changing the graph's entity model."""
    degree: Dict[str, int] = {node_id: 0 for node_id in nodes}
    for edge in edges.values():
        data = edge["data"]
        degree[data["source"]] = degree.get(data["source"], 0) + 1
        degree[data["target"]] = degree.get(data["target"], 0) + 1

    # Source IPs are the clearest available entry-point signal. Keep the
    # observed role separate from attacker suspicion: loopback is still an
    # observed entry point, but is never promoted to suspected attacker.
    for node_id in source_ip_nodes:
        if node_id in nodes:
            _set_role(nodes[node_id], "entry_point")
    for node_id in suspected_attacker_nodes:
        if node_id in nodes:
            _set_role(nodes[node_id], "suspected_attacker")

    # Choose the most connected host/user/process as the investigation pivot.
    # Tie-break by id keeps output stable across runs and Python versions.
    candidates = [
        (degree.get(node_id, 0), len(node["data"].get("ref_ids", [])), node_id, node)
        for node_id, node in nodes.items()
        if node_id not in source_ip_nodes and node["data"].get("type") in {"host", "user", "process", "service"}
    ]
    if candidates:
        _, _, _, pivot = max(candidates, key=lambda item: (item[0], item[1], item[2]))
        if degree.get(pivot["data"]["id"], 0) > 0:
            _set_role(pivot, "pivot_point")

    for node in nodes.values():
        node["data"].setdefault("role", "supporting")
        node["data"].setdefault("role_label", ROLE_STYLES["supporting"]["label"])
        node["data"].setdefault("role_color", ROLE_STYLES["supporting"]["color"])


def _set_role(node: dict, role: str) -> None:
    style = ROLE_STYLES[role]
    node["data"].update({"role": role, "role_label": style["label"], "role_color": style["color"]})


def _role_counts(nodes: Dict[str, dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for node in nodes.values():
        role = node["data"].get("role", "supporting")
        counts[role] = counts.get(role, 0) + 1
    return counts


def _is_external_source(value: str) -> bool:
    """Return true only for a routable IP source with attacker-like context.

    URL hostnames are also stored in the legacy ``source_ip`` field by some
    detectors. A hostname alone is not evidence that an attacker controls it,
    so keep those nodes as observed entry points rather than labeling them
    "Suspected attacker".
    """
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified)


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
