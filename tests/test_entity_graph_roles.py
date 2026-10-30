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
