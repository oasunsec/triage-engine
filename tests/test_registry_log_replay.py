"""Registry transaction-log replay: verified HvLE entries recover changes a dirty hive lacks."""

import json
import struct

from corrobora.artifact_packager import pack_artifacts
from corrobora.forensic_artifacts import read_forensic_bundle
from corrobora.registry_log_replay import log_entries, marvin32, replay
from tests.test_registry_hive_artifacts import hive_bytes, parse, software_spec, sz, write_hive


def _checksum(data: bytearray) -> None:
    value = 0
    for (word,) in struct.iter_unpack("<I", bytes(data[:508])):
        value ^= word
    struct.pack_into("<I", data, 508, value)


def _dirty(hive: bytes, primary: int, secondary: int) -> bytes:
    data = bytearray(hive)
    struct.pack_into("<II", data, 4, primary, secondary)
    _checksum(data)
    return bytes(data)


def _log(entries) -> bytes:
    """A log file: a 512-byte base block, then one HvLE entry per (sequence, bins_size, pages)."""
    out = bytearray(b"regf" + b"\x00" * 508)
    for sequence, bins_size, pages in entries:
        refs = b"".join(struct.pack("<II", offset, len(page)) for offset, page in pages)
        body = refs + b"".join(page for _, page in pages)
        size = -(-(40 + len(body)) // 512) * 512
        entry = bytearray(size)
        struct.pack_into("<4sIIIII", entry, 0, b"HvLE", size, 0, sequence, bins_size, len(pages))
        entry[40:40 + len(body)] = body
        struct.pack_into("<Q", entry, 24, marvin32(bytes(entry[40:])))
        struct.pack_into("<Q", entry, 32, marvin32(bytes(entry[:32])))
        out += entry
    return bytes(out)


def _changed_pages(old: bytes, new: bytes):
    pages = []
    for offset in range(0, len(new) - 4096, 4096):
        page = new[4096 + offset:4096 + offset + 4096]
        if page != old[4096 + offset:4096 + offset + 4096]:
            pages.append((offset, page))
    return pages


def _run_names(observations):
    return {item["details"]["name"]: item["details"]["command"] for item in observations if item["kind"] == "registry_run"}


def _hives():
    old, _ = hive_bytes(software_spec([("Updater", *sz("C:\\Program Files\\Vendor\\upd.exe"))]))
    new, _ = hive_bytes(software_spec([("Updater", *sz("C:\\Users\\Public\\Vendor\\evil.exe"))]))
    assert len(old) == len(new)
    bins_size = struct.unpack_from("<I", new, 0x28)[0]
    return old, new, bins_size


def test_dirty_hive_recovers_the_logged_change():
    old, new, bins_size = _hives()
    dirty = _dirty(old, 6, 5)
    log = _log([(5, bins_size, _changed_pages(old, new))])
    observations, warnings = parse(dirty, logs=[log])
    assert _run_names(observations)["Updater"] == "C:\\Users\\Public\\Vendor\\evil.exe"
    assert any("Replayed 1 verified transaction-log entries (sequence 5-5)" in warning for warning in warnings)
    assert struct.unpack_from("<II", dirty, 4) == (6, 5)  # input bytes untouched
    # Without logs the stale value is all there is, and the gap is stated.
    observations, warnings = parse(dirty)
    assert _run_names(observations)["Updater"] == "C:\\Program Files\\Vendor\\upd.exe"
    assert any("no transaction logs were supplied" in warning for warning in warnings)


def test_bad_hash_stale_entries_and_gaps_are_not_applied():
    old, new, bins_size = _hives()
    pages = _changed_pages(old, new)
    dirty = _dirty(old, 6, 5)
    torn = bytearray(_log([(5, bins_size, pages)]))
    torn[600] ^= 0xFF
    assert log_entries(bytes(torn)) == {}
    for logs in ([bytes(torn)], [_log([(4, bins_size, pages)])], [_log([(6, bins_size, pages)])]):
        replayed, report = replay(dirty, logs)
        assert replayed == dirty and report["entries_applied"] == 0
        observations, warnings = parse(dirty, logs=logs)
        assert _run_names(observations)["Updater"] == "C:\\Program Files\\Vendor\\upd.exe"
        assert any("no verified entry continuing" in warning for warning in warnings)


def test_clean_hive_ignores_older_entries_left_in_its_logs():
    # Real Windows 11 default profile: hive at 97/97, logs still holding entries 95 and 96.
    old, new, bins_size = _hives()
    clean = _dirty(old, 97, 97)
    replayed, report = replay(clean, [_log([(95, bins_size, _changed_pages(old, new))]), _log([(96, bins_size, [])])])
    assert replayed == clean and report == {**report, "dirty": False, "entries_found": 2, "entries_applied": 0}


def test_packager_carries_logs_and_the_bundle_replays_them(tmp_path):
    old, new, bins_size = _hives()
    hive = write_hive(tmp_path / "config", "SOFTWARE", _dirty(old, 6, 5))
    (tmp_path / "config" / "SOFTWARE.LOG1").write_bytes(_log([(5, bins_size, _changed_pages(old, new))]))
    bundle = pack_artifacts(tmp_path / "bundle", host="WS-LAB-01", observed_at="2026-10-02T12:00:00Z",
                            registry_hives=[(hive, "software")])
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    log_member = next(item for item in manifest["files"] if item["kind"] == "registry_hive_log")
    assert log_member["log_slot"] == "LOG1" and log_member["hive_member"] == "registry_hive-1.hive"
    assert not any("transaction logs" in warning.lower() for warning in manifest["warnings"])
    result = read_forensic_bundle(str(bundle))
    assert _run_names(result.observations)["Updater"] == "C:\\Users\\Public\\Vendor\\evil.exe"
