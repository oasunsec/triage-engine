"""Offline registry hives: synthetic hives built in-test only, never read from this host."""

import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from models.event_model import NormalizedEvent
from triage_engine import cli, service
from triage_engine.artifact_packager import pack_artifacts
from triage_engine.forensic_artifacts import read_forensic_bundle
from triage_engine.forensic_correlation import correlate_evidence
from triage_engine.registry_hive_artifacts import Hive, HiveError, parse_registry_hive

CONTEXT = {"source_name": "registry_hive-1.hive", "source_sha256": "e" * 64, "host": "WS-LAB-01",
           "observed_at": "2026-10-02T12:00:00Z", "collector": {"name": "test", "version": "1"}}
LAST_WRITE = datetime(2026, 9, 30, 8, 15, tzinfo=timezone.utc)
RUN = "Microsoft\\Windows\\CurrentVersion\\Run"
REG_SZ, REG_EXPAND_SZ, REG_DWORD = 1, 2, 4


def filetime(moment=LAST_WRITE):
    return int((moment - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000


def sz(text, kind=REG_SZ):
    return kind, (text + "\x00").encode("utf-16-le")


def dword(number):
    return REG_DWORD, struct.pack("<I", number)


class HiveWriter:
    """Minimal regf writer for tests: one hive bin, allocated cells only."""

    def __init__(self, minor=5):
        self.minor = minor
        self.cells = bytearray()
        self.offsets = {}

    def alloc(self, data):
        offset = 32 + len(self.cells)
        size = (len(data) + 4 + 7) // 8 * 8
        self.cells += struct.pack("<i", -size) + data + b"\x00" * (size - 4 - len(data))
        return offset

    def value(self, name, kind, data):
        if len(data) <= 4:
            size, pointer = len(data) | 0x80000000, struct.unpack("<I", data.ljust(4, b"\x00"))[0]
        elif len(data) > 16344 and self.minor >= 4:
            segments = [self.alloc(data[start:start + 16344]) for start in range(0, len(data), 16344)]
            index = self.alloc(b"".join(struct.pack("<I", segment) for segment in segments))
            size, pointer = len(data), self.alloc(b"db" + struct.pack("<HI", len(segments), index))
        else:
            size, pointer = len(data), self.alloc(data)
        raw = name.encode("latin-1")
        return self.alloc(b"vk" + struct.pack("<HIIIHH", len(raw), size, pointer, kind, 1, 0) + raw)

    def key(self, name, values=(), subkeys=(), *, last_write=None, list_kind="lf", root=False):
        value_cells = [self.value(*value) for value in values]
        value_list = self.alloc(b"".join(struct.pack("<I", cell) for cell in value_cells)) if value_cells else 0xFFFFFFFF
        subkey_list = 0xFFFFFFFF
        if subkeys:
            if list_kind == "ri":
                inner = self.alloc(b"li" + struct.pack("<H", len(subkeys)) + b"".join(struct.pack("<I", k) for k in subkeys))
                subkey_list = self.alloc(b"ri" + struct.pack("<HI", 1, inner))
            elif list_kind == "li":
                subkey_list = self.alloc(b"li" + struct.pack("<H", len(subkeys)) + b"".join(struct.pack("<I", k) for k in subkeys))
            else:
                subkey_list = self.alloc(list_kind.encode() + struct.pack("<H", len(subkeys))
                                         + b"".join(struct.pack("<II", k, 0) for k in subkeys))
        raw = name.encode("latin-1")
        header = struct.pack("<2sHQIIIIIIIIIIIIIIIHH", b"nk", 0x2C if root else 0x20,
                             filetime(last_write or LAST_WRITE), 0, 0, len(subkeys), 0, subkey_list, 0xFFFFFFFF,
                             len(value_cells), value_list, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, len(raw), 0)
        return self.alloc(header + raw)

    def tree(self, spec, path=""):
        """spec: (name, values, children[, options]); records each key's offset by path."""
        name, values, children, *options = spec
        child_path = lambda child: f"{path}\\{child[0]}" if path else child[0]
        offsets = [self.tree(child, child_path(child)) for child in children]
        offset = self.key(name, values, offsets, root=not path, **(options[0] if options else {}))
        self.offsets[path] = offset
        return offset

    def build(self, root, *, sequences=(7, 7), name="\\??\\C:\\Windows\\System32\\config\\TEST"):
        bin_size = (32 + len(self.cells) + 4095) // 4096 * 4096
        free = bin_size - 32 - len(self.cells)
        cells = bytes(self.cells) + (struct.pack("<i", free) + b"\x00" * (free - 4) if free else b"")
        hbin = b"hbin" + struct.pack("<IIQQI", 0, bin_size, 0, filetime(), 0) + cells
        base = bytearray(4096)
        struct.pack_into("<4sIIQIIIIIII", base, 0, b"regf", sequences[0], sequences[1], filetime(), 1, self.minor,
                         0, 1, root, bin_size, 1)
        base[48:48 + min(64, len(name) * 2)] = name.encode("utf-16-le")[:64]
        checksum(base)
        return bytes(base) + hbin


def checksum(base):
    value = 0
    for (word,) in struct.iter_unpack("<I", bytes(base[:508])):
        value ^= word
    struct.pack_into("<I", base, 508, 0xFFFFFFFE if value == 0xFFFFFFFF else (value or 1))


def software_spec(run_values=None):
    run_values = run_values if run_values is not None else [
        ("Updater", *sz("C:\\Users\\Public\\upd.exe /quiet")),
        ("Sync", *sz("powershell.exe -enc QQBCAEMA")),
    ]
    later = {"last_write": datetime(2026, 9, 30, 9, 0, tzinfo=timezone.utc)}
    version = lambda keys: ("Microsoft", [], [("Windows", [], [("CurrentVersion", [], keys)])])
    return ("CMI-CreateHive{TEST}", [], [
        version([("Run", run_values, []), ("RunOnce", [("Once", *sz("C:\\Temp\\once.exe"))], [], later)]),
        ("Wow6432Node", [], [version([("Run", [("Legacy", *sz("C:\\Program Files (x86)\\Old\\old.exe"))], [])])]),
    ])


def hive_bytes(spec, **build):
    writer = HiveWriter(minor=build.pop("minor", 5))
    return writer.build(writer.tree(spec), **build), writer


def parse(content, hive_type="software", **kwargs):
    return parse_registry_hive(content, hive_type=hive_type, **CONTEXT, **kwargs)


# ---- extraction ----

def test_software_run_values_include_runonce_and_wow64_with_key_last_write():
    content, _ = hive_bytes(software_spec())
    before = hashlib.sha256(content).hexdigest()
    observations, warnings = parse(content)
    assert warnings == [] and hashlib.sha256(content).hexdigest() == before
    by_name = {item["details"]["name"]: item for item in observations}
    assert set(by_name) == {"Updater", "Sync", "Once", "Legacy"}
    updater = by_name["Updater"]
    assert updater["kind"] == "registry_run" and updater["time_semantics"] == "registry_key_last_write"
    assert updater["timestamp"] == "2026-09-30T08:15:00+00:00" and updater["observed_at"] == "2026-10-02T12:00:00+00:00"
    assert updater["details"]["location"] == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert updater["details"]["command"] == "C:\\Users\\Public\\upd.exe /quiet"
    assert updater["native_locator"] == {"hive_type": "software", "key_path": RUN, "value_name": "Updater"}
    assert "not this value's creation time" in updater["interpretation"]
    assert by_name["Once"]["details"]["run_once"] and by_name["Once"]["timestamp"] == "2026-09-30T09:00:00+00:00"
    assert by_name["Legacy"]["details"]["location"] == "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    identity = json.dumps(["e" * 64, "registry_hive", RUN, "Updater"], separators=(",", ":"))
    assert updater["id"] == "obs_" + hashlib.sha256(identity.encode()).hexdigest()
    assert [item["id"] for item in parse(content)[0]] == [item["id"] for item in observations]


def test_ntuser_run_values_map_to_hkcu_without_inventing_an_owner():
    spec = ("ROOT", [], [("Software", [], [software_spec()[2][0]])])
    observations, _ = parse(hive_bytes(spec)[0], "ntuser")
    assert {item["details"]["location"] for item in observations} >= {"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}
    assert all(item["details"]["hive_owner"] == "unidentified" and "user" not in item["details"] for item in observations)
    assert observations[0]["native_locator"]["key_path"].startswith("Software\\Microsoft\\")


def test_value_data_hidden_after_nul_and_big_data_cells_are_reported():
    long_command = "C:\\Tools\\long.exe " + "A" * 12000
    content, _ = hive_bytes(software_spec([("Hidden", REG_SZ, "C:\\ok.exe\x00 -payload\x00".encode("utf-16-le")),
                                           ("Long", *sz(long_command)), ("Binary", 3, b"\x01\x02\x03\x04\x05")]))
    by_name = {item["details"]["name"]: item["details"] for item in parse(content)[0]}
    assert by_name["Hidden"]["command"] == "C:\\ok.exe" and by_name["Hidden"]["data_after_nul"] is True
    assert by_name["Long"]["command"] == long_command  # stored through a db big-data cell
    assert by_name["Binary"]["command"] == "" and by_name["Binary"]["value_type"] == "REG_BINARY"


def system_spec(services_002=None):
    def services(entries):
        return ("Services", [], entries)
    services_002 = services_002 if services_002 is not None else [
        ("EvilSvc", [("ImagePath", *sz("C:\\ProgramData\\evil.exe", REG_EXPAND_SZ)), ("Start", *dword(2)),
                     ("Type", *dword(0x10)), ("ObjectName", *sz("LocalSystem")), ("DisplayName", *sz("Evil"))], []),
        ("NetHost", [("ImagePath", *sz("%SystemRoot%\\System32\\svchost.exe -k netsvcs", REG_EXPAND_SZ)),
                     ("Start", *dword(4)), ("Type", *dword(0x20))],
         [("Parameters", [("ServiceDll", *sz("C:\\Windows\\System32\\nethost.dll", REG_EXPAND_SZ))], [])]),
    ]
    return ("ROOT", [], [
        ("ControlSet001", [], [services([("OldSvc", [("ImagePath", *sz("C:\\old.exe"))], [])])]),
        ("ControlSet002", [], [services(services_002)]),
        ("Select", [("Current", *dword(2)), ("Default", *dword(2)), ("LastKnownGood", *dword(1))], []),
    ])


def test_system_services_use_the_control_set_selected_by_current():
    observations, warnings = parse(hive_bytes(system_spec())[0], "system")
    assert warnings == []
    names = {item["details"]["name"]: item for item in observations}
    assert set(names) == {"EvilSvc", "NetHost"}  # ControlSet001 is not current
    evil = names["EvilSvc"]
    assert evil["kind"] == "service" and evil["time_semantics"] == "registry_key_last_write"
    details = evil["details"]
    assert details["command"] == "C:\\ProgramData\\evil.exe" and details["user"] == "LocalSystem"
    assert details["start"] == 2 and details["start_type"] == "automatic" and details["service_type"] == 0x10
    assert details["enabled"] is True and details["control_set"] == "ControlSet002"
    assert details["location"] == "HKLM\\SYSTEM\\ControlSet002\\Services"
    assert details["select"] == {"Current": 2, "Default": 2, "LastKnownGood": 1, "Failed": None}
    assert evil["native_locator"] == {"hive_type": "system", "key_path": "ControlSet002\\Services\\EvilSvc", "value_name": None}
    nethost = names["NetHost"]["details"]
    assert nethost["enabled"] is False and nethost["service_dll"] == "C:\\Windows\\System32\\nethost.dll"


def test_amcache_entries_are_a_separate_kind_that_never_claims_execution():
    sha1 = "a" * 40
    spec = ("ROOT", [], [("Root", [], [("InventoryApplicationFile", [], [
        ("tool.exe|1234", [("LowerCaseLongPath", *sz("c:\\users\\public\\tool.exe")), ("FileId", *sz("0000" + sha1)),
                           ("LinkDate", *sz("09/29/2026 10:00:00")), ("Publisher", *sz("Example"))], []),
        ("nohash.exe|99", [("LowerCaseLongPath", *sz("c:\\temp\\nohash.exe")), ("FileId", *sz("bogus"))], []),
    ])])])
    observations, warnings = parse(hive_bytes(spec)[0], "amcache")
    assert warnings == [] and {item["kind"] for item in observations} == {"amcache_file"}
    tool = next(item for item in observations if item["details"]["name"] == "tool.exe")
    assert tool["details"]["sha1"] == sha1 and tool["details"]["path"] == "c:\\users\\public\\tool.exe"
    assert tool["details"]["link_date_raw"] == "09/29/2026 10:00:00"
    assert "not proof of execution" in tool["interpretation"] and "command" not in tool["details"]
    assert next(item for item in observations if item["details"]["name"] == "nohash.exe")["details"]["sha1"] == ""
    event = NormalizedEvent(1, LAST_WRITE, computer="WS-LAB-01", channel="Microsoft-Windows-Sysmon/Operational",
                            provider="Microsoft-Windows-Sysmon", process_name_value="C:\\Users\\Public\\tool.exe",
                            record_id="1", observation_id="obs_evt_1")
    assert correlate_evidence([event], observations)[0] == []  # presence is not linked as execution


def test_hash_only_amcache_entry_keeps_name_unknown_and_reports_a_key_name_hint():
    # Shape seen in a real Windows 11 Amcache: FileId/ProgramId only, name truncated in the key.
    spec = ("ROOT", [], [("Root", [], [("InventoryApplicationFile", [], [
        ("32bitmapibroker.|7c94cd198d03999", [("ProgramId", *sz("0000391f")), ("FileId", *sz("0000" + "b" * 40))], []),
        ("$rsj6qi6.exe|ca5e13eec8a27ab", [("FileId", *sz("0000" + "c" * 40))], []),
    ])])])
    observations, warnings = parse(hive_bytes(spec)[0], "amcache")
    by_hint = {item["details"]["key_name_hint"]: item["details"] for item in observations}
    broker, short = by_hint["32bitmapibroker."], by_hint["$rsj6qi6.exe"]
    assert broker["name"] == broker["path"] == "" and broker["sha1"] == "b" * 40
    assert broker["key_name_hint_may_be_truncated"] is True and short["key_name_hint_may_be_truncated"] is False
    assert len(warnings) == 1 and "2 Amcache entries record no file name or path" in warnings[0]


def test_older_amcache_layout_is_reported_not_guessed():
    observations, warnings = parse(hive_bytes(("ROOT", [], [("Root", [], [("File", [], [])])]))[0], "amcache")
    assert observations == [] and "older Root\\File layout" in warnings[0]


def test_ri_index_lists_are_followed():
    spec = ("ROOT", [], [("Microsoft", [], [("Windows", [], [("CurrentVersion", [], [("Run", [("A", *sz("C:\\a.exe"))], [])],
                                                              {"list_kind": "ri"})], {"list_kind": "li"})], {"list_kind": "lh"})])
    assert [item["details"]["name"] for item in parse(hive_bytes(spec)[0])[0]] == ["A"]


# ---- dirty, corrupt, truncated, cyclic and oversized hives ----

def test_dirty_hive_is_parsed_with_an_explicit_no_replay_warning():
    observations, warnings = parse(hive_bytes(software_spec(), sequences=(8, 7))[0])
    assert observations and any("dirty" in warning and "no transaction logs were supplied" in warning for warning in warnings)


def test_bad_checksum_is_a_warning():
    content = bytearray(hive_bytes(software_spec())[0])
    content[508] ^= 0xFF
    assert any("checksum" in warning for warning in parse(bytes(content))[1])


def patched(content, position, fmt, value):
    data = bytearray(content)
    struct.pack_into(fmt, data, position, value)
    return bytes(data)


def cell_position(writer, path, field=0):
    return 4096 + writer.offsets[path] + 4 + field


@pytest.mark.parametrize("mutate, message", [
    (lambda c, w: b"rogf" + c[4:], "regf signature"),
    (lambda c, w: c[:4096 + 100], "truncated"),
    (lambda c, w: c[:-1], "truncated"),
    (lambda c, w: patched(c, 36, "<I", 0x7FFFFFF8), "outside the hive"),
    (lambda c, w: patched(c, 36, "<I", 0x18), "not inside a hive bin"),
    (lambda c, w: patched(c, 4096, "<4s", b"hbim"), "hbin signature"),
    (lambda c, w: patched(c, 20, "<I", 2), "format version"),
    (lambda c, w: patched(c, 28, "<I", 1), "primary hive"),
    (lambda c, w: patched(c, 4096 + w.offsets[""], "<i", 64), "unallocated"),
    (lambda c, w: patched(c, cell_position(w, ""), "<2s", b"xx"), "not a key"),
    (lambda c, w: patched(c, cell_position(w, "Microsoft", 20), "<I", 300_000), "more than 200000 subkeys"),
], ids=["signature", "truncated-bins", "truncated-end", "offset-outside", "offset-in-header", "bad-hbin",
        "version", "log-file", "free-cell", "not-nk", "subkey-count"])
def test_corrupt_or_truncated_hives_fail_closed(mutate, message):
    content, writer = hive_bytes(software_spec())
    with pytest.raises(HiveError, match=message):
        parse(mutate(content, writer))


def subkey_list(content, writer, path):
    return struct.unpack_from("<I", content, cell_position(writer, path, 28))[0]


def test_self_referencing_subkey_is_rejected_as_a_cycle():
    content, writer = hive_bytes(software_spec())
    windows = writer.offsets["Microsoft\\Windows"]
    # Point the first entry of Windows' lf list at Windows itself.
    content = patched(content, 4096 + subkey_list(content, writer, "Microsoft\\Windows") + 4 + 4, "<I", windows)
    with pytest.raises(HiveError, match="self-referencing"):
        parse(content)


def test_subkey_pointing_back_to_an_ancestor_is_rejected_as_a_cycle():
    writer = HiveWriter()
    content = writer.build(writer.tree(("ROOT", [], [("Microsoft", [], [("Windows", [], [])])])))
    # Give Windows the root's subkey list, so Microsoft -> Windows -> Microsoft.
    content = patched(content, cell_position(writer, "Microsoft\\Windows", 20), "<I", 1)
    content = patched(content, cell_position(writer, "Microsoft\\Windows", 28), "<I", subkey_list(content, writer, ""))
    with pytest.raises(HiveError, match="Key cycle"):
        Hive(content).open("Microsoft\\Windows\\Microsoft")


def test_ri_list_cycle_is_rejected():
    spec = ("ROOT", [], [("Microsoft", [], [("Windows", [], [])], {"list_kind": "ri"})])
    writer = HiveWriter()
    content = writer.build(writer.tree(spec))
    ri = subkey_list(content, writer, "Microsoft")
    content = patched(content, 4096 + ri + 4 + 4, "<I", ri)  # ri entry points at the ri list itself
    with pytest.raises(HiveError, match="Subkey list cycle"):
        parse(content)


def test_oversized_hive_is_rejected_by_parameter_and_environment(monkeypatch):
    content, _ = hive_bytes(software_spec())
    with pytest.raises(HiveError, match="byte limit"):
        parse(content, max_bytes=len(content) - 1)
    monkeypatch.setenv("TRIAGE_MAX_HIVE_BYTES", str(len(content) - 1))
    with pytest.raises(HiveError, match="byte limit"):
        parse(content)


def test_declared_type_must_match_hive_structure():
    content, _ = hive_bytes(software_spec())
    with pytest.raises(HiveError, match="no Select key"):
        parse(content, "system")
    with pytest.raises(HiveError, match="no Software key"):
        parse(content, "ntuser")
    with pytest.raises(ValueError, match="Unsupported hive type"):
        parse(content, "sam")
    spec = system_spec()
    spec[2][2] = ("Select", [("Current", *dword(9))], [])
    with pytest.raises(HiveError, match="ControlSet009"):
        parse(hive_bytes(spec)[0], "system")


def test_damaged_single_service_is_skipped_with_a_warning():
    content, writer = hive_bytes(system_spec())
    evil = writer.offsets["ControlSet002\\Services\\EvilSvc"]
    content = patched(content, 4096 + evil + 4 + 40, "<I", 0x7FFFFFF8)  # value list outside the hive
    observations, warnings = parse(content, "system")
    assert [item["details"]["name"] for item in observations] == ["NetHost"]
    assert any("EvilSvc" in warning and "outside the hive" in warning for warning in warnings)


def test_damaged_sibling_on_a_lookup_path_is_not_reported_as_absence():
    content, writer = hive_bytes(software_spec())
    # Damage Wow6432Node; looking up Wow6432Node\... cannot tell whether the key exists.
    content = patched(content, cell_position(writer, "Wow6432Node"), "<2s", b"xx")
    with pytest.raises(HiveError, match="Cannot tell whether"):
        parse(content)


# ---- packaging, bundle intake, CLI and a mixed case ----

def write_hive(folder, name, content):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_bytes(content)
    return path


def test_packaged_hives_are_retained_typed_and_flag_suspicious_run_values(tmp_path):
    software = write_hive(tmp_path / "config", "SOFTWARE", hive_bytes(software_spec())[0])
    system = write_hive(tmp_path / "config", "SYSTEM", hive_bytes(system_spec())[0])
    (tmp_path / "config" / "SYSTEM.LOG1").write_bytes(b"log")
    bundle = pack_artifacts(tmp_path / "bundle", host="WS-LAB-01", observed_at="2026-10-02T12:00:00Z",
                            registry_hives=[(software, "software"), (system, "system")])
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert [(item["kind"], item.get("hive_type"), item["path"]) for item in manifest["files"]] == [
        ("registry_hive", "software", "registry_hive-1.hive"), ("registry_hive", "system", "registry_hive-2.hive"),
        ("registry_hive_log", None, "registry_hive_log-1.log1")]
    assert manifest["files"][2]["hive_member"] == "registry_hive-2.hive"
    assert manifest["completeness"] == "partial"
    # SYSTEM's log travels with it; SOFTWARE has none, which is stated.
    assert any("SOFTWARE" in warning and "No transaction logs" in warning for warning in manifest["warnings"])
    assert not any("SYSTEM" in warning and "transaction logs" in warning.lower() for warning in manifest["warnings"])
    assert (bundle / "registry_hive-1.hive").read_bytes() == software.read_bytes()
    result = read_forensic_bundle(str(bundle), temp_dir=tmp_path)
    kinds = sorted(observation["kind"] for observation in result.observations)
    assert kinds == ["registry_run"] * 4 + ["service"] * 2
    assert [alert.rule_name for alert in result.alerts] == ["Persistence Snapshot: Encoded PowerShell launch configured"]
    assert result.alerts[0].registry_key == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"


def test_bundle_rejects_hive_without_declared_type(tmp_path):
    software = write_hive(tmp_path / "config", "SOFTWARE", hive_bytes(software_spec())[0])
    bundle = pack_artifacts(tmp_path / "bundle", host="WS-LAB-01", observed_at="2026-10-02T12:00:00Z",
                            registry_hives=[(software, "software")])
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["files"][0]["hive_type"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="hive_type"):
        read_forensic_bundle(str(bundle), temp_dir=tmp_path)


def test_packager_rejects_unknown_type_and_non_hive(tmp_path):
    text = write_hive(tmp_path / "config", "notes.txt", b"not a hive")
    with pytest.raises(ValueError, match="regf"):
        pack_artifacts(tmp_path / "a", host="H", observed_at="2026-10-02T12:00:00Z", registry_hives=[(text, "system")])
    with pytest.raises(ValueError, match="Hive type"):
        pack_artifacts(tmp_path / "b", host="H", observed_at="2026-10-02T12:00:00Z", registry_hives=[(text, "sam")])


def test_cli_pack_pairs_registry_hives_with_types(tmp_path):
    hive = write_hive(tmp_path / "config", "NTUSER.DAT", hive_bytes(("ROOT", [], [("Software", [], [])]))[0])
    base = ["pack-artifacts", "--host", "WS-LAB-01", "--observed-at", "2026-10-02T12:00:00Z"]
    args = cli.build_parser().parse_args(base + ["--registry-hive", str(hive), "--hive-type", "ntuser",
                                                 "--output-dir", str(tmp_path / "out")])
    assert cli.cmd_pack_artifacts(args) == 0
    assert (tmp_path / "out" / "registry_hive-1.hive").read_bytes() == hive.read_bytes()
    args = cli.build_parser().parse_args(base + ["--registry-hive", str(hive), "--output-dir", str(tmp_path / "out2")])
    assert cli.cmd_pack_artifacts(args) == 1 and not (tmp_path / "out2").exists()


def test_mixed_case_links_sysmon_events_to_hive_derived_run_value(tmp_path):
    spec = ("ROOT", [], [("Software", [], [software_spec([("Updater", *sz("C:\\Users\\Public\\upd.exe /quiet"))])[2][0]])])
    ntuser = write_hive(tmp_path / "profile", "NTUSER.DAT", hive_bytes(spec)[0])
    bundle = pack_artifacts(tmp_path / "bundle", host="WS-LAB-01", observed_at="2026-10-02T12:00:00Z",
                            registry_hives=[(ntuser, "ntuser")])
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic evtx")
    sysmon = {"channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
              "computer": "WS-LAB-01"}

    def read(path, *args, source_files, **kwargs):
        write = NormalizedEvent(13, datetime(2026, 9, 30, 8, 14, 58, tzinfo=timezone.utc), record_id="11", event_data={
            "TargetObject": "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\Users\\Public\\upd.exe /quiet"}, **sysmon)
        launch = NormalizedEvent(1, datetime(2026, 10, 1, 13, 20, tzinfo=timezone.utc), record_id="12",
                                 process_name_value="C:\\Users\\Public\\upd.exe",
                                 parent_process_value="C:\\Windows\\explorer.exe", **sysmon)
        for event in (write, launch):
            event.source_file = source_files[0]
        return [write, launch]

    with patch.object(service, "read_evtx_path", side_effect=read), \
            patch.object(service, "_run_detectors", side_effect=lambda events, **kwargs: ([], {})):
        result = service.run_investigation(service.InvestigationRequest(
            str(evtx), artifact_bundle=str(bundle), case_name="hive-mixed", cases_dir=str(tmp_path / "cases")))
    case = Path(result.case_path)
    links = json.loads((case / "evidence_relationships.json").read_text(encoding="utf-8"))["relationships"]
    assert sorted(link["rule"]["name"] for link in links) == ["configuration_event_matches_record",
                                                              "configured_action_matches_process_image"]
    retained = {source["sha256"] for source in json.loads((case / "evidence_manifest.json").read_text(encoding="utf-8"))["sources"]}
    for link in links:
        assert link["target"]["artifact_kind"] == "registry_run"
        assert link["target"]["time_semantics"] == "registry_key_last_write"
        assert link["target"]["source_file"].endswith(".hive") and link["target"]["source_sha256"] in retained
    config = next(link for link in links if link["rule"]["name"] == "configuration_event_matches_record")
    assert config["contradictions"] == [] and any(f["event_field"] == "configured command" for f in config["matched_fields"])
    launch = next(link for link in links if link["rule"]["name"] == "configured_action_matches_process_image")
    assert launch["inferred_claims"][0]["basis"] == ["parent_process:explorer.exe"]
    timeline = json.loads((case / "timeline.json").read_text(encoding="utf-8"))["timeline"]
    row = next(row for row in timeline if row["type"] == "artifact")
    assert row["time_semantics"] == "registry_key_last_write" and row["timestamp"] == "2026-09-30T08:15:00+00:00"
