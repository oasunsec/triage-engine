"""NTFS $MFT and $UsnJrnl:$J adapter: synthetic bytes built in-test, never host collection."""

import json
import random
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from models.event_model import Alert, NormalizedEvent
from triage_engine import forensic_artifacts, ntfs_artifacts, service
from triage_engine import artifact_packager
from triage_engine.artifact_packager import pack_artifacts
from triage_engine.cli import main as cli_main
from triage_engine.forensic_artifacts import read_forensic_bundle
from triage_engine.forensic_correlation import correlate_evidence, cross_source_alerts
from triage_engine.ntfs_artifacts import (NtfsEvidence, filetime_iso, parse_mft, parse_usn_journal,
                                          read_ntfs_members, reason_names)

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
T0 = datetime(2026, 10, 1, 13, 20, tzinfo=timezone.utc)
HOST = "WS-LAB-01"


def ft(moment: datetime, fraction: int = 1234) -> int:
    """FILETIME with a sub-second remainder, so default times are not whole seconds."""
    return (moment - EPOCH) // timedelta(microseconds=1) * 10 + fraction


def ref(number: int, seq: int) -> int:
    return number | (seq << 48)


def _attribute(kind: int, value: bytes) -> bytes:
    length = (24 + len(value) + 7) // 8 * 8
    header = struct.pack("<IIBBHHHIH", kind, length, 0, 0, 0, 0, 0, len(value), 24) + b"\x00\x00"
    return (header + value).ljust(length, b"\x00")


def si_value(times) -> bytes:
    return struct.pack("<qqqqI", *times, 0x20).ljust(72, b"\x00")


def fn_value(parent: int, name: str, times, namespace: int = 1) -> bytes:
    encoded = name.encode("utf-16-le")
    return struct.pack("<Qqqqq", parent, *times) + struct.pack("<qqII", 0, 0, 0x20, 0) + \
        bytes([len(name), namespace]) + encoded


def data_nonresident(size: int) -> bytes:
    header = struct.pack("<IIBBHHH", 0x80, 72, 1, 0, 0, 0, 1)
    body = struct.pack("<QQHH4xQQQ", 0, 0, 64, 0, size, size, size)
    return (header + body).ljust(72, b"\x00")


def mft_record(*, seq=1, in_use=True, directory=False, base=0, si=None, names=(), data_size=None,
               record_size=1024, usn=0x0001, break_fixup=False) -> bytes:
    record = bytearray(record_size)
    usa_count = record_size // 512 + 1
    attributes = b""
    if si is not None:
        attributes += _attribute(0x10, si_value(si))
    for parent, name, times, *namespace in names:
        attributes += _attribute(0x30, fn_value(parent, name, times, *(namespace or [1])))
    if data_size is not None:
        attributes += data_nonresident(data_size)
    attributes += b"\xff\xff\xff\xff\x00\x00\x00\x00"
    first = (0x30 + 2 * usa_count + 7) // 8 * 8
    used = first + len(attributes)
    assert used <= record_size
    flags = (1 if in_use else 0) | (2 if directory else 0)
    struct.pack_into("<4sHHQHHHHIIQHHI", record, 0, b"FILE", 0x30, usa_count, 0, seq, 1, first, flags,
                     used, record_size, base, 0, 0, 0)
    record[first:used] = attributes
    struct.pack_into("<H", record, 0x30, usn)
    for index in range(1, usa_count):
        end = index * 512
        record[0x30 + 2 * index:0x32 + 2 * index] = record[end - 2:end]
        record[end - 2:end] = struct.pack("<H", usn ^ 0xFFFF if break_fixup and index == 2 else usn)
    return bytes(record)


def times(moment: datetime, fraction: int = 1234):
    value = ft(moment, fraction)
    return (value, value, value, value)


def build_mft(records: dict[int, bytes], record_size: int = 1024) -> bytes:
    count = max(records) + 1
    return b"".join(records.get(number, b"\x00" * record_size) for number in range(count))


ROOT = ref(5, 5)
FILE_TIME = T0 - timedelta(minutes=10)


def standard_records(**overrides) -> dict[int, bytes]:
    old = T0 - timedelta(days=200)
    records = {
        0: mft_record(si=times(old), names=[(ROOT, "$MFT", times(old))]),
        5: mft_record(seq=5, directory=True, si=times(old), names=[(ROOT, ".", times(old))]),
        30: mft_record(seq=2, directory=True, si=times(old), names=[(ROOT, "Users", times(old))]),
        31: mft_record(seq=3, directory=True, si=times(old), names=[(ref(30, 2), "Public", times(old))]),
        32: mft_record(seq=7, si=times(FILE_TIME), data_size=4096,
                       names=[(ref(31, 3), "UPD~1.EXE", times(FILE_TIME), 2), (ref(31, 3), "upd.exe", times(FILE_TIME))]),
    }
    records.update(overrides)
    return records


def write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def usn_record(file_ref, parent_ref, usn, stamp, reason, name, *, version=2) -> bytes:
    encoded = name.encode("utf-16-le")
    if version == 2:
        head = struct.pack("<QQqqIIIIHH", file_ref, parent_ref, usn, stamp, reason, 0, 0, 0x20, len(encoded), 60)
    else:
        head = struct.pack("<QQQQqqIIIIHH", file_ref, 0, parent_ref, 0, usn, stamp, reason, 0, 0, 0x20, len(encoded), 76)
    body = head + encoded
    length = (8 + len(body) + 7) // 8 * 8
    return (struct.pack("<IHH", length, version, 0) + body).ljust(length, b"\x00")


def process_event(image="C:\\Users\\Public\\upd.exe", *, at=T0, record="7", host=HOST):
    return NormalizedEvent(1, at, computer=host, channel="Microsoft-Windows-Sysmon/Operational",
                           provider="Microsoft-Windows-Sysmon", process_name_value=image,
                           parent_process_value="C:\\Windows\\explorer.exe", record_id=record,
                           source_file="evidence/a.evtx", source_sha256="a" * 64, observation_id=f"obs_evt_{record}")


def evidence(tmp_path, records=None, usn=b"", volume=""):
    mft_path = write(tmp_path, "mft.bin", build_mft(records or standard_records()))
    usn_path = write(tmp_path, "usn.bin", usn) if usn else None
    from triage_engine.evidence import sha256_file
    ntfs, observations, warnings = read_ntfs_members(
        host=HOST, observed_at="2026-10-02T12:00:00+00:00", collector={"name": "test", "version": "1"}, volume=volume,
        mft=(mft_path, "ntfs_mft-1.mft", sha256_file(mft_path)),
        usn=(usn_path, "ntfs_usn_journal-1.usnjrnl", sha256_file(usn_path)) if usn_path else None)
    return ntfs, observations, warnings


# -- $MFT parsing ------------------------------------------------------------------------------------


def test_valid_records_resolve_paths_and_keep_both_time_families(tmp_path):
    ntfs, observations, warnings = evidence(tmp_path)
    mft = ntfs.mft
    assert mft.record_size == 1024 and mft.stats["valid_records"] == 5 and mft.stats["empty_records"] == 28
    assert observations == [] and warnings == []
    found = mft.lookup_paths(["\\users\\public\\upd.exe"])
    (entry,) = found["\\users\\public\\upd.exe"]
    assert mft.name(entry) == "upd.exe"  # The DOS 8.3 name is not indexed.
    si, fn = ntfs.file_observations(entry)
    assert si["kind"] == fn["kind"] == "ntfs_file"
    assert (si["time_semantics"], fn["time_semantics"]) == ("mft_standard_information", "mft_file_name")
    assert si["id"] != fn["id"] and si["details"]["companion_observation_id"] == fn["id"]
    assert "timestomping" in si["interpretation"]
    assert fn["details"]["path"] == "\\Users\\Public\\upd.exe" and fn["details"]["path_resolution"] == "resolved"
    assert fn["details"]["data_size"] == 4096 and fn["details"]["sequence"] == 7
    assert fn["details"]["times"]["created"]["filetime"] == ft(FILE_TIME)
    assert fn["timestamp"] == filetime_iso(ft(FILE_TIME)) and fn["native_locator"]["byte_offset"] == 32 * 1024
    assert ntfs.file_observations(entry)[0] is si  # Deterministic and materialized once.


def test_hard_links_and_extension_record_names_are_indexed(tmp_path):
    records = standard_records()
    records[33] = mft_record(seq=1, si=times(FILE_TIME), names=[(ref(30, 2), "a.exe", times(FILE_TIME))])
    # Extension record 40 carries a second (hard-link) name for base record 33.
    records[40] = mft_record(seq=1, base=ref(33, 1), names=[(ref(31, 3), "b.exe", times(FILE_TIME))])
    ntfs, _, _ = evidence(tmp_path, records)
    found = ntfs.mft.lookup_paths(["\\users\\a.exe", "\\users\\public\\b.exe"])
    assert set(found) == {"\\users\\a.exe", "\\users\\public\\b.exe"}
    assert {ntfs.mft.name_record[entry] for entries in found.values() for entry in entries} == {33}
    assert ntfs.mft.stats["extension_records"] == 1


def test_data_size_from_extension_record_before_its_base_is_kept(tmp_path):
    # Real Windows 11 layout: base record 1630685 kept its names, and its unnamed $DATA
    # lived in extension record 1568933, which comes earlier in the $MFT.
    records = standard_records()
    records[34] = mft_record(seq=1, base=ref(60, 1), data_size=26088)
    records[60] = mft_record(seq=1, si=times(FILE_TIME), names=[(ref(31, 3), "late.dll", times(FILE_TIME))])
    ntfs, _, _ = evidence(tmp_path, records)
    (entry,) = ntfs.mft.lookup_paths(["\\users\\public\\late.dll"])["\\users\\public\\late.dll"]
    assert ntfs.file_observations(entry)[1]["details"]["data_size"] == 26088


def test_4096_byte_records_are_supported(tmp_path):
    records = {number: mft_record(record_size=4096, seq=5 if number == 5 else 1, directory=number == 5,
                                  si=times(FILE_TIME), names=[(ROOT, "." if number == 5 else f"f{number}", times(FILE_TIME))])
               for number in (0, 5, 6)}
    index = parse_mft(write(tmp_path, "mft.bin", build_mft(records, 4096)))
    assert index.record_size == 4096 and index.stats["valid_records"] == 3
    assert index.lookup_paths(["\\f6"])


def test_bad_fixup_record_is_skipped_and_warned(tmp_path):
    records = standard_records()
    records[32] = mft_record(seq=7, si=times(FILE_TIME), names=[(ref(31, 3), "upd.exe", times(FILE_TIME))], break_fixup=True)
    ntfs, _, warnings = evidence(tmp_path, records)
    assert ntfs.mft.stats["bad_fixup"] == 1
    assert ntfs.mft.lookup_paths(["\\users\\public\\upd.exe"]) == {}
    assert any("fixup" in warning for warning in warnings)


@pytest.mark.parametrize("mutate", [
    lambda r: r[:4] + b"\x00\x02" + r[6:],                   # usa offset beyond record
    lambda r: r[:6] + b"\x09\x00" + r[8:],                   # wrong usa count
    lambda r: r[:24] + struct.pack("<I", 4096) + r[28:],    # used size larger than record
    lambda r: r[:20] + b"\xf0\x03" + r[22:],                 # first attribute beyond used size
    lambda r: b"BAAD" + r[4:],                               # chkdsk-marked bad record
])
def test_malformed_headers_are_rejected_per_record(tmp_path, mutate):
    records = standard_records()
    records[32] = mutate(records[32])
    index = parse_mft(write(tmp_path, "mft.bin", build_mft(records)))
    assert index.stats["valid_records"] == 4
    assert index.lookup_paths(["\\users\\public\\upd.exe"]) == {}


def test_attribute_overrun_stops_record_parsing_without_crash(tmp_path):
    records = standard_records()
    record = bytearray(records[32])
    struct.pack_into("<I", record, 0x38 + 4, 0x3F0)  # first attribute claims to run past used size
    records[32] = bytes(record)
    index = parse_mft(write(tmp_path, "mft.bin", build_mft(records)))
    assert index.stats["attribute_overrun"] == 1


def test_truncated_inputs(tmp_path):
    data = build_mft(standard_records())
    index = parse_mft(write(tmp_path, "cut.bin", data[:32 * 1024 + 700]))
    assert index.stats["trailing_partial_record_bytes"] == 700
    assert index.lookup_paths(["\\users\\public\\upd.exe"]) == {}
    with pytest.raises(ValueError, match="shorter than one record"):
        parse_mft(write(tmp_path, "tiny.bin", b"FILE"))
    with pytest.raises(ValueError, match="FILE signature"):
        parse_mft(write(tmp_path, "notmft.bin", b"\x00" * 2048))
    limited = parse_mft(write(tmp_path, "mft.bin", data), max_records=6)
    assert limited.truncated and limited.records == 6


def test_digest_mismatch_after_verification_is_rejected(tmp_path):
    path = write(tmp_path, "mft.bin", build_mft(standard_records()))
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        parse_mft(path, expected_sha256="0" * 64)


def test_cyclic_and_broken_parent_chains_are_marked_orphans(tmp_path):
    records = standard_records()
    old = times(T0 - timedelta(days=9))
    records[50] = mft_record(seq=1, directory=True, si=old, names=[(ref(51, 1), "A", old)])
    records[51] = mft_record(seq=1, directory=True, si=old, names=[(ref(50, 1), "B", old)])
    records[52] = mft_record(seq=1, si=old, names=[(ref(50, 1), "loop.exe", old)])
    records[53] = mft_record(seq=1, si=old, names=[(ref(31, 9), "stale.exe", old)])   # parent reused
    records[54] = mft_record(seq=1, si=old, names=[(ref(32, 7), "child.exe", old)])   # parent is a file
    records[55] = mft_record(seq=1, si=old, names=[(ref(999, 1), "lost.exe", old)])   # parent missing
    ntfs, _, _ = evidence(tmp_path, records)
    mft = ntfs.mft
    status = {number: ntfs_artifacts.PATH_STATUS[mft.status[number]] for number in (50, 51, 52, 53, 54, 55)}
    assert status[50] == status[51] == status[52] == "orphan_cycle"
    assert status[53] == "orphan_parent_sequence_mismatch"
    assert status[54] == "orphan_parent_not_directory"
    assert status[55] == "orphan_parent_missing"
    assert mft.stats["orphan_cycle"] == 3
    entry = mft.first_name[52]
    path, resolution = mft.entry_path(entry, {})
    assert path.startswith("<orphan_cycle>") and resolution == "orphan_cycle"
    assert mft.lookup_paths(["\\a\\loop.exe", "\\b\\a\\loop.exe"]) == {}


def test_parent_chain_depth_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(ntfs_artifacts, "MAX_PATH_DEPTH", 4)
    records = standard_records()
    old = times(T0 - timedelta(days=9))
    parent = ROOT
    for number in range(60, 68):
        records[number] = mft_record(seq=1, directory=True, si=old, names=[(parent, f"d{number}", old)])
        parent = ref(number, 1)
    index = parse_mft(write(tmp_path, "mft.bin", build_mft(records)))
    assert ntfs_artifacts.PATH_STATUS[index.status[67]] == "orphan_depth_exceeded"
    assert ntfs_artifacts.PATH_STATUS[index.status[61]] == "resolved"


def test_random_record_bodies_never_raise(tmp_path):
    generator = random.Random(1337)
    records = standard_records()
    for number in range(100, 400):
        body = bytearray(generator.randbytes(1024))
        body[:4] = b"FILE"
        if number % 2:  # Plausible header so the attribute walker sees hostile attributes.
            struct.pack_into("<HHQHHHHII", body, 4, 0x30, 3, 0, 1, 1, 0x38, 1, 1024, 1024)
            struct.pack_into("<Q", body, 32, 0)
            for index in (1, 2):
                body[index * 512 - 2:index * 512] = body[0x30:0x32]
        records[number] = bytes(body)
    index = parse_mft(write(tmp_path, "mft.bin", build_mft(records)))
    assert index.records == 400
    NtfsEvidence(host=HOST, observed_at="2026-10-02T12:00:00+00:00", collector={}, mft=index,
                 mft_source=("m", "0" * 64)).contradiction_observations()


# -- $SI / $FN contradictions ------------------------------------------------------------------------


def test_timestomp_is_reported_as_contradiction_not_proof(tmp_path):
    stomped_si = times(T0 - timedelta(days=900), fraction=0)  # Earlier and whole-second.
    records = standard_records()
    records[32] = mft_record(seq=7, si=stomped_si, names=[(ref(31, 3), "upd.exe", times(FILE_TIME))])
    ntfs, observations, _ = evidence(tmp_path, records)
    assert [item["time_semantics"] for item in observations] == ["mft_standard_information", "mft_file_name"]
    fields = {item["field"] for item in observations[0]["details"]["contradictions"]}
    assert fields == {"created", "precision"}
    assert all("not proof" in item["meaning"] or "legitimately" in item["meaning"]
               for item in observations[0]["details"]["contradictions"])
    # Each family keeps its own time; nothing is merged.
    assert observations[0]["timestamp"] != observations[1]["timestamp"]


def test_contradiction_observations_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(ntfs_artifacts, "MAX_CONTRADICTION_OBSERVATIONS", 2)
    records = standard_records()
    for number in range(70, 75):
        records[number] = mft_record(si=times(T0 - timedelta(days=900)),
                                     names=[(ROOT, f"s{number}.exe", times(FILE_TIME))])
    _, observations, warnings = evidence(tmp_path, records)
    assert len(observations) == 4
    assert any("5 $MFT records" in warning for warning in warnings)


# -- USN journal ------------------------------------------------------------------------------------


def usn_stream(*records, lead=0, gap=0) -> bytes:
    data = b"\x00" * lead
    for index, record in enumerate(records):
        data += record
        if index == 0:
            data += b"\x00" * gap
    return data


def test_usn_sparse_regions_versions_and_reasons(tmp_path):
    stamp = ft(FILE_TIME)
    data = usn_stream(
        usn_record(ref(32, 7), ref(31, 3), 4096, stamp, 0x100, "upd.exe"),
        usn_record(ref(32, 7), ref(31, 3), 4200, stamp + 10, 0x80000002, "upd.exe", version=3),
        struct.pack("<IHH", 72, 4, 0).ljust(72, b"\x01"),       # V4 range record
        b"\xee" * 24,                                         # garbage region
        usn_record(ref(33, 1), ref(31, 3), 4300, stamp + 20, 0x200 | 0x80000000, "gone.txt"),
        lead=5 * 1024 * 1024 + 8, gap=4096)
    index = parse_usn_journal(write(tmp_path, "usn.bin", data))
    assert index.stats["records"] == 3 and index.stats["v2_records"] == 2 and index.stats["v3_records"] == 1
    assert index.stats["v4_range_records"] == 1 and index.stats["invalid_regions"] == 1
    assert index.stats["sparse_bytes_skipped"] >= 5 * 1024 * 1024 + 4096
    assert len(index.ts) == 1 and index.name(0) == "upd.exe"
    assert index.reasons["FILE_CREATE"] == 1 and index.reasons["CLOSE"] == 2 and index.reasons["FILE_DELETE"] == 1
    assert index.offset[0] == 5 * 1024 * 1024 + 8
    assert reason_names(0x80000300) == ["FILE_CREATE", "FILE_DELETE", "CLOSE"]
    assert reason_names(0x08) == ["UNKNOWN_0x00000008"]


def test_usn_truncated_and_invalid_names(tmp_path):
    good = usn_record(ref(32, 7), ref(31, 3), 1, ft(FILE_TIME), 0x100, "a.exe")
    bad_name = bytearray(usn_record(ref(32, 7), ref(31, 3), 2, ft(FILE_TIME), 0x100, "b.exe"))
    struct.pack_into("<H", bad_name, 58, 300)  # name offset past record end
    index = parse_usn_journal(write(tmp_path, "usn.bin", good + bytes(bad_name) + good[:40]))
    assert index.stats["records"] == 1 and index.stats["invalid_records"] == 1
    assert index.stats["truncated_final_record"] == 1 or index.stats["trailing_bytes"]
    empty = parse_usn_journal(write(tmp_path, "empty.bin", b"\x00" * 10000))
    assert empty.stats["records"] == 0 and empty.stats["sparse_bytes_skipped"] == 10000


def test_usn_record_limit_marks_truncation(tmp_path):
    record = usn_record(ref(32, 7), ref(31, 3), 1, ft(FILE_TIME), 0x2, "a.exe")
    index = parse_usn_journal(write(tmp_path, "usn.bin", record * 10), max_records=4)
    assert index.truncated and index.stats["records"] == 4


# -- correlation ------------------------------------------------------------------------------------


def journal(*entries) -> bytes:
    return b"\x00" * 4096 + b"".join(entries)


def test_mixed_case_links_process_to_mft_record_and_journal_create(tmp_path):
    usn = journal(usn_record(ref(32, 7), ref(31, 3), 4096, ft(FILE_TIME), 0x100, "upd.exe"))
    ntfs, observations, _ = evidence(tmp_path, usn=usn)
    relationships, coverage = correlate_evidence([process_event()], observations, ntfs=ntfs)
    by_type = {link["type"]: link for link in relationships}
    assert set(by_type) == {"same_file_path", "file_created_before_process"}
    file_link, usn_link = by_type["same_file_path"], by_type["file_created_before_process"]
    assert file_link["rule"]["name"] == "process_image_matches_file_record"
    assert file_link["link_class"] == "observed_field_match" and file_link["inferred_claims"] == []
    assert file_link["target"]["artifact_kind"] == "ntfs_file" and file_link["target"]["time_semantics"] == "mft_file_name"
    assert "drive C:" in file_link["assumptions"][0]
    assert set(file_link["time_relation"]["artifact_times"]) == {"mft_standard_information", "mft_file_name"}
    assert file_link["contradictions"] == []
    assert usn_link["link_class"] == "supported_inference"
    assert usn_link["target"]["artifact_kind"] == "usn_change"
    assert usn_link["target"]["time_semantics"] == "usn_journal_record"
    assert "same_file_reference" in usn_link["inferred_claims"][0]["basis"]
    assert usn_link["time_relation"]["artifact_minus_event_seconds"] == pytest.approx(-600, abs=1)
    assert any("rolls over" in item for item in usn_link["does_not_establish"])
    targets = {link["target"]["observation_id"] for link in relationships}
    assert targets <= {observation["id"] for observation in observations}
    assert {o["kind"] for o in observations} == {"ntfs_file", "usn_change"}
    assert coverage["families"]["ntfs_mft"]["status"] == "observed"
    assert coverage["families"]["usn_journal"]["file_create_indexed"] == 1
    assert any("timestomping" in item for item in coverage["limitations"])
    again, _ = correlate_evidence([process_event()], list(observations), ntfs=ntfs)
    assert [link["relationship_id"] for link in again] == [link["relationship_id"] for link in relationships]


def test_volume_mapping_replaces_assumption_and_filters_other_drives(tmp_path):
    ntfs, observations, _ = evidence(tmp_path, volume="C:")
    relationships, _ = correlate_evidence([process_event(), process_event("D:\\Users\\Public\\upd.exe", record="8")],
                                          observations, ntfs=ntfs)
    assert len(relationships) == 1 and relationships[0]["assumptions"] == []
    assert relationships[0]["source"]["observation_id"] == "obs_evt_7"


@pytest.mark.parametrize("event", [
    process_event(host="OTHER-HOST"),
    process_event("C:\\Users\\Public\\other.exe"),
    process_event("upd.exe"),
])
def test_unrelated_events_are_not_linked(tmp_path, event):
    ntfs, observations, _ = evidence(tmp_path)
    assert correlate_evidence([event], observations, ntfs=ntfs)[0] == []


def test_journal_create_outside_window_or_ambiguous_is_not_supported(tmp_path):
    far = journal(usn_record(ref(32, 7), ref(31, 3), 1, ft(T0 - timedelta(hours=3)), 0x100, "upd.exe"))
    ntfs, observations, _ = evidence(tmp_path, usn=far)
    relationships, _ = correlate_evidence([process_event()], observations, ntfs=ntfs)
    assert [link["type"] for link in relationships] == ["same_file_path"]

    twice = journal(usn_record(ref(32, 7), ref(31, 3), 1, ft(FILE_TIME), 0x100, "upd.exe"),
                    usn_record(ref(32, 6), ref(31, 3), 2, ft(FILE_TIME - timedelta(minutes=5)), 0x100, "upd.exe"))
    ntfs, observations, _ = evidence(tmp_path, usn=twice)
    relationships, _ = correlate_evidence([process_event()], observations, ntfs=ntfs)
    usn_links = [link for link in relationships if link["type"] == "file_created_before_process"]
    assert len(usn_links) == 2 and {link["link_class"] for link in usn_links} == {"weak_temporal_association"}
    assert {"same_file_reference", "file_reference_differs"} == {
        link["inferred_claims"][0]["basis"][-1] for link in usn_links}


def test_timestomped_image_reports_contradictions_on_links(tmp_path):
    records = standard_records()
    records[32] = mft_record(seq=7, si=times(T0 - timedelta(days=900), fraction=0),
                             names=[(ref(31, 3), "upd.exe", times(FILE_TIME))])
    usn = journal(usn_record(ref(32, 7), ref(31, 3), 1, ft(FILE_TIME), 0x100, "upd.exe"))
    ntfs, observations, _ = evidence(tmp_path, records, usn=usn)
    relationships, _ = correlate_evidence([process_event()], observations, ntfs=ntfs)
    by_type = {link["type"]: link for link in relationships}
    assert {item["field"] for item in by_type["same_file_path"]["contradictions"]} == {"created", "precision"}
    assert by_type["file_created_before_process"]["contradictions"][0]["field"] == "created"
    assert "$SI may have been altered" in by_type["file_created_before_process"]["contradictions"][0]["meaning"]


def test_record_created_after_process_and_deleted_record_are_contradictions(tmp_path):
    later = times(T0 + timedelta(hours=1))
    records = standard_records()
    records[32] = mft_record(seq=7, in_use=False, si=later, names=[(ref(31, 3), "upd.exe", later)])
    ntfs, observations, _ = evidence(tmp_path, records)
    (link,) = correlate_evidence([process_event()], observations, ntfs=ntfs)[0]
    assert {item["field"] for item in link["contradictions"]} == {"created", "in_use"}


def test_file_record_alone_never_raises_finding_but_journal_create_can(tmp_path):
    event = process_event()
    alert = Alert("Suspicious Child", "high", "Execution", "T1204", "d", "e", event)
    ntfs, observations, _ = evidence(tmp_path)
    relationships, _ = correlate_evidence([event], observations, ntfs=ntfs)
    assert cross_source_alerts(relationships, [event], [alert]) == []
    usn = journal(usn_record(ref(32, 7), ref(31, 3), 1, ft(FILE_TIME), 0x100, "upd.exe"))
    ntfs, observations, _ = evidence(tmp_path, usn=usn)
    relationships, _ = correlate_evidence([event], observations, ntfs=ntfs)
    (finding,) = cross_source_alerts(relationships, [event], [alert])
    assert finding.evidence["linked_artifact_kinds"] == ["usn_change"]
    assert finding.severity == "high" and finding.confidence == "medium"


def test_indexed_matching_scales_without_pairwise_comparison(tmp_path):
    import time
    records = standard_records()
    old = times(T0 - timedelta(days=9))
    for number in range(100, 5100):
        records[number] = mft_record(si=old, names=[(ref(31, 3), f"tool{number}.exe", old)])
    events = [process_event(f"C:\\Users\\Public\\tool{100 + index % 5000}.exe", at=T0 + timedelta(seconds=index),
                            record=str(index)) for index in range(5000)]
    ntfs, observations, _ = evidence(tmp_path, records)
    started = time.perf_counter()
    relationships, _ = correlate_evidence(events, observations, ntfs=ntfs)
    assert len(relationships) == 5000
    assert time.perf_counter() - started < 20


# -- bundle, packager, CLI and investigation ---------------------------------------------------------


def make_bundle(tmp_path, *, usn=True, volume="", **options):
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    mft = write(source, "$MFT", build_mft(standard_records()))
    usn_path = write(source, "$J", journal(usn_record(ref(32, 7), ref(31, 3), 1, ft(FILE_TIME), 0x100, "upd.exe")))
    return pack_artifacts(tmp_path / "bundle", host=HOST, observed_at="2026-10-02T12:00:00Z",
                          ntfs_mft=[mft], ntfs_usn_journal=[usn_path] if usn else [], ntfs_volume=volume, **options)


def test_packager_writes_ntfs_members_and_reader_parses_them(tmp_path):
    bundle = make_bundle(tmp_path, volume="c:")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    kinds = {item["kind"]: item for item in manifest["files"]}
    assert set(kinds) == {"ntfs_mft", "ntfs_usn_journal"} and kinds["ntfs_mft"]["volume"] == "C:"
    assert kinds["ntfs_mft"]["path"] == "ntfs_mft-1.mft" and kinds["ntfs_mft"]["original_name"] == "$MFT"
    retained = []
    forensic = read_forensic_bundle(str(bundle), retain_verified_sources=lambda files, hashes: retained.extend(files))
    assert {kind for _, kind in retained} == {"artifact_manifest", "ntfs_mft", "ntfs_usn_journal"}
    assert forensic.ntfs.volume == "C:" and forensic.ntfs.mft.stats["valid_records"] == 5
    assert forensic.observations == []


def test_packager_rejects_two_volumes_and_bad_volume(tmp_path):
    mft = write(tmp_path, "m", build_mft(standard_records()))
    with pytest.raises(ValueError, match="at most one"):
        pack_artifacts(tmp_path / "b1", host=HOST, observed_at="2026-10-02T12:00:00Z", ntfs_mft=[mft, mft])
    with pytest.raises(ValueError, match="drive letter"):
        pack_artifacts(tmp_path / "b2", host=HOST, observed_at="2026-10-02T12:00:00Z", ntfs_mft=[mft], ntfs_volume="C:\\")


def test_large_ntfs_members_need_explicit_option(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact_packager, "_LIMIT", 4096)
    with pytest.raises(ValueError, match="allow-large-NTFS"):
        make_bundle(tmp_path)
    bundle = make_bundle(tmp_path, allow_large_ntfs=True)
    monkeypatch.setattr(forensic_artifacts, "ARTIFACT_BYTE_BUDGET", 4096)
    with pytest.raises(ValueError, match="allow-large-NTFS"):
        read_forensic_bundle(str(bundle))
    assert read_forensic_bundle(str(bundle), allow_large_ntfs=True).ntfs is not None
    # The option never lifts the budget for other member kinds.
    (tmp_path / "records.json").write_text(json.dumps({"schema_version": "1.0", "records": [
        {"kind": "service", "name": "x" * 5000, "location": "l", "command": ""}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="64 MiB"):
        pack_artifacts(tmp_path / "other", host=HOST, observed_at="2026-10-02T12:00:00Z",
                       persistence_records=[tmp_path / "records.json"], allow_large_ntfs=True)


def test_reader_rejects_tampered_or_mismatched_ntfs_members(tmp_path):
    bundle = make_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["volume"] = "C:"
    manifest["files"][1]["volume"] = "D:"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="different volumes"):
        read_forensic_bundle(str(bundle))
    manifest["files"][1]["volume"] = "C:\\x"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="drive letter"):
        read_forensic_bundle(str(bundle))
    manifest["files"][1].pop("volume")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (bundle / "ntfs_mft-1.mft").write_bytes(b"F" * manifest["files"][0]["size_bytes"])
    with pytest.raises(ValueError, match="SHA-256"):
        read_forensic_bundle(str(bundle))


def test_cli_pack_artifacts_accepts_ntfs_flags(tmp_path, capsys):
    mft = write(tmp_path, "mft.bin", build_mft(standard_records()))
    code = cli_main(["pack-artifacts", "--output-dir", str(tmp_path / "bundle"), "--host", HOST,
                     "--observed-at", "2026-10-02T12:00:00Z", "--ntfs-mft", str(mft), "--ntfs-volume", "C:"])
    assert code == 0 and "Artifact bundle" in capsys.readouterr().out
    manifest = json.loads((tmp_path / "bundle" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["files"][0]["kind"] == "ntfs_mft" and manifest["files"][0]["volume"] == "C:"


def test_investigation_links_event_to_mft_and_journal_with_retained_sources(tmp_path):
    bundle = make_bundle(tmp_path)
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic evtx")
    captured = {}

    def parse(path, *args, source_files, **kwargs):
        event = process_event()
        event.source_file, event.observation_id, event.source_sha256 = source_files[0], "", ""
        captured["event"] = event
        return [event]

    def detect(events, **kwargs):
        return [Alert("Suspicious Child", "high", "Execution", "T1204", "d", "e", captured["event"])], {}

    with patch.object(service, "read_evtx_path", side_effect=parse), patch.object(service, "_run_detectors", side_effect=detect):
        result = service.run_investigation(service.InvestigationRequest(
            str(evtx), artifact_bundle=str(bundle), case_name="ntfs", cases_dir=str(tmp_path / "cases")))
    case = Path(result.case_path)
    links = json.loads((case / "evidence_relationships.json").read_text(encoding="utf-8"))["relationships"]
    assert {link["type"] for link in links} == {"same_file_path", "file_created_before_process"}
    manifest = json.loads((case / "evidence_manifest.json").read_text(encoding="utf-8"))
    retained = {source["sha256"]: source for source in manifest["sources"]}
    assert {"ntfs_mft", "ntfs_usn_journal"} <= {source["kind"] for source in retained.values()}
    for link in links:
        target = link["target"]
        assert target["source_sha256"] in retained and target["source_file"] == retained[target["source_sha256"]]["path"]
    observations = json.loads((case / "forensic_observations.json").read_text(encoding="utf-8"))["observations"]
    assert {o["kind"] for o in observations} == {"ntfs_file", "usn_change"}
    assert all(o["source_file"].startswith("evidence/") for o in observations)
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    coverage = findings["case"]["forensic_correlation"]["coverage"]["families"]
    assert coverage["ntfs_mft"]["volume_mapping"] == "assumed_from_event_path"
    assert findings["case"]["forensic_correlation"]["cross_source_finding_count"] == 1
