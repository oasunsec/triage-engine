from types import SimpleNamespace

from correlation.entity_graph import build_entity_graph


def _item(item_id, **kwargs):
    values = {
        "id": item_id,
        "host": "WORKSTATION-1",
        "service": "LanmanServer",
        "process": r"C:\Windows\System32\svchost.exe",
        "command_line": "svchost.exe -k netsvcs",
        "user": "alice",
        "subject_user": "",
        "target_user": "",
        "account_name": "",
        "source_ip": "203.0.113.10",
        "destination_ip": "",
        "evidence": {},
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


def test_graph_assigns_entry_pivot_and_supporting_roles_deterministically():
    graph = build_entity_graph(
        [_item("sig-1")],
        [_item("find-1", source_ip="203.0.113.10")],
        [_item("inc-1", source_ip="203.0.113.10")],
    )
    by_role = {node["data"]["role"]: node["data"] for node in graph["nodes"]}
    assert by_role["suspected_attacker"]["value"] == "203.0.113.10"
    assert by_role["suspected_attacker"]["role_label"] == "Suspected attacker"
    assert any(node["data"]["role"] == "suspected_attacker" for node in graph["nodes"])
    assert by_role["pivot_point"]["type"] in {"host", "user", "process", "service"}
    assert by_role["supporting"]["role_color"] == "#64748b"
    assert graph["summary"]["role_counts"]["suspected_attacker"] == 1
    assert {entry["role"] for entry in graph["role_legend"]} == {
        "entry_point", "suspected_attacker", "pivot_point", "supporting"
    }


def test_loopback_source_is_observed_entry_point_not_suspected_attacker():
    graph = build_entity_graph([_item("sig-1", source_ip="::1")], [], [])
    ip_node = next(node["data"] for node in graph["nodes"] if node["data"]["type"] == "ip")
    assert ip_node["role"] == "entry_point"
    assert ip_node["role_label"] == "Observed entry point"


def test_hostname_source_is_not_labeled_as_suspected_attacker():
    graph = build_entity_graph([_item("sig-1", source_ip="aka.ms")], [], [])
    ip_node = next(node["data"] for node in graph["nodes"] if node["data"]["type"] == "ip")
    assert ip_node["role"] == "entry_point"
    assert ip_node["role_label"] == "Observed entry point"


def test_service_install_commands_are_connected_and_edges_carry_time_and_rules():
    # Public sample LM_Remote_Service02_7045: cmd.exe and calc.exe floated unconnected.
    from datetime import datetime, timezone
    first = datetime(2019, 3, 3, 9, 20, 28, tzinfo=timezone.utc)
    later = datetime(2019, 3, 3, 9, 24, 24, tzinfo=timezone.utc)
    items = [_item("fnd-1", process="", user="", source_ip="", service="spoolfool", command_line="cmd.exe /c calc.exe",
                   title="Service Installed", first_seen=first, last_seen=first),
             _item("fnd-2", process="", user="", source_ip="", service="spoolfool", command_line="cmd.exe /c calc.exe",
                   title="Suspicious Service Execution", first_seen=later, last_seen=later)]
    graph = build_entity_graph([], items, [])
    connected = {edge["data"][end] for edge in graph["edges"] for end in ("source", "target")}
    assert {node["data"]["id"] for node in graph["nodes"]} <= connected
    edge = next(edge["data"] for edge in graph["edges"] if edge["data"]["type"] == "SERVICE_TO_COMMAND")
    assert edge["count"] == 2 and edge["first_seen"] == first.isoformat() and edge["last_seen"] == later.isoformat()
    assert edge["rules"] == ["Service Installed", "Suspicious Service Execution"]
    assert edge["label"] == "Service Installed ×2" and edge["relation"] == "service command line"
    service = next(node["data"] for node in graph["nodes"] if node["data"]["type"] == "service")
    assert service["type_label"] == "Service" and service["first_seen"] == first.isoformat()
