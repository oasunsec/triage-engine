"""Native Prefetch parser: synthetic SCCA files built in-test, never host collection.

Compressed cases use a minimal test-side LZ77+Huffman encoder. It gives every
symbol a 9-bit code (512 x 2^6 entries fill the 2^15 decoding table exactly) and
places bit words and extended-length bytes in the order the [MS-XCA] 2.2.4
decoder reads them.
"""

import hashlib
import json
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from models.event_model import Alert, NormalizedEvent
from triage_engine import service
from triage_engine.artifact_packager import pack_artifacts
from triage_engine.forensic_artifacts import read_forensic_bundle
from triage_engine.forensic_correlation import correlate_evidence, cross_source_alerts
from triage_engine.prefetch_artifacts import parse_pecmd_jsonl
from triage_engine.prefetch_binary import (
    MAX_DECOMPRESSED, MAX_FILENAMES, MAX_JOINED, MAX_STRING_TABLE, lzxpress_huffman_decompress,
    parse_prefetch_binary,
)

T0 = datetime(2026, 10, 1, 13, 20, tzinfo=timezone.utc)
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
SHA = "d" * 64
CONTEXT = {"source_name": "prefetch_source-1.pf", "source_sha256": SHA, "host": "WS-LAB-01",
           "observed_at": "2026-10-02T12:00:00Z"}
UPD_PATH = "\\VOLUME{01d0a1b2c3d4e5f6-1a2b3c4d}\\USERS\\PUBLIC\\UPD.EXE"


def filetime(moment: datetime) -> int:
    return (moment - EPOCH) // timedelta(microseconds=1) * 10


# ---- synthetic SCCA builder ----

def build_scca(version=30, *, exe="UPD.EXE", pf_hash=0x11223344, runs=(T0 + timedelta(seconds=9),), run_count=3,
               filenames=("\\VOLUME{01d0a1b2c3d4e5f6-1a2b3c4d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL", UPD_PATH),
               volumes=(("\\VOLUME{01d0a1b2c3d4e5f6-1a2b3c4d}", 0x1A2B3C4D, T0 - timedelta(days=400),
                         ("\\VOLUME{01d0a1b2c3d4e5f6-1a2b3c4d}\\USERS", "\\VOLUME{01d0a1b2c3d4e5f6-1a2b3c4d}\\USERS\\PUBLIC")),),
               late_win10=False, strings_size=None, raw_strings=None) -> bytes:
    info_size = {17: 68, 23: 156, 26: 220, 30: 212 if late_win10 else 220, 31: 220}[version]
    floor = 84 + info_size
    strings = raw_strings if raw_strings is not None else b"".join(n.encode("utf-16-le") + b"\0\0" for n in filenames)
    entry_size = {17: 40, 23: 104, 26: 104, 30: 96, 31: 96}[version]
    area = bytearray(entry_size * len(volumes))
    for index, (device, serial, created, directories) in enumerate(volumes):
        base = index * entry_size
        path_offset = len(area)
        area += device.encode("utf-16-le") + b"\0\0"
        directory_offset = len(area)
        for directory in directories:
            area += struct.pack("<H", len(directory)) + directory.encode("utf-16-le") + b"\0\0"
        struct.pack_into("<IIQI", area, base, path_offset, len(device), filetime(created), serial)
        struct.pack_into("<II", area, base + 28, directory_offset, len(directories))
    strings_offset = floor
    volumes_offset = strings_offset + len(strings)
    total = volumes_offset + len(area)
    header = bytearray(84)
    struct.pack_into("<I4sII", header, 0, version, b"SCCA", 0x11, total)
    name = exe.encode("utf-16-le")[:58]
    header[16:16 + len(name)] = name
    struct.pack_into("<I", header, 76, pf_hash)
    info = bytearray(info_size)
    struct.pack_into("<9I", info, 0, floor, len(filenames), floor, 0, strings_offset,
                     len(strings) if strings_size is None else strings_size, volumes_offset if volumes else 0,
                     len(volumes), len(area))
    times = [filetime(moment) if moment else 0 for moment in runs]
    if version == 17:
        struct.pack_into("<Q", info, 36, times[0] if times else 0)
        struct.pack_into("<I", info, 60, run_count)
    elif version == 23:
        struct.pack_into("<Q", info, 44, times[0] if times else 0)
        struct.pack_into("<I", info, 68, run_count)
    else:
        struct.pack_into("<8Q", info, 44, *(times + [0] * 8)[:8])
        struct.pack_into("<I", info, 116 if late_win10 else 124, run_count)
    return bytes(header + info + strings + area)


# ---- test-side [MS-XCA] LZ77+Huffman encoder ----

def huffman_compress(data: bytes) -> bytes:
    out = bytearray()
    position = 0
    while position < len(data):
        out += b"\x99" * 256  # Every symbol: 9-bit code length.
        slots, bits = [], []
        state = {"extra": 16}

        def reserve():
            slots.append(len(out))
            out.extend(b"\0\0")

        def put(value, count):
            bits.extend((value >> shift) & 1 for shift in range(count - 1, -1, -1))
            state["extra"] -= count
            if state["extra"] < 0:
                reserve()
                state["extra"] += 16

        reserve()
        reserve()
        block_end = position + 65536
        recent: dict[bytes, int] = {}
        while position < block_end and position < len(data):
            key = data[position:position + 3]
            candidate = recent.get(key)
            recent[key] = position
            length = 0
            if candidate is not None and len(key) == 3 and position - candidate < 65536:
                limit = min(len(data) - position, 65535 + 3)
                while length < limit and data[candidate + length] == data[position + length]:
                    length += 1
            if length < 3:
                put(data[position], 9)
                position += 1
                continue
            offset = position - candidate
            high = offset.bit_length() - 1
            stored = length - 3
            put(256 + (high << 4) + min(stored, 15), 9)
            if stored >= 15:
                if stored - 15 < 255:
                    out.append(stored - 15)
                else:
                    out.append(255)
                    out.extend(struct.pack("<H", stored))
            put(offset - (1 << high), high)
            position += length
        bits.extend([0] * (16 * len(slots) - len(bits)))
        for index, at in enumerate(slots):
            value = int("".join(map(str, bits[16 * index:16 * index + 16])), 2)
            out[at:at + 2] = struct.pack("<H", value)
    return bytes(out)


def mam(data: bytes, declared: int | None = None) -> bytes:
    return b"MAM\x04" + struct.pack("<I", len(data) if declared is None else declared) + huffman_compress(data)


# ---- format coverage ----

@pytest.mark.parametrize("version, late", [(17, False), (23, False), (26, False), (30, False), (30, True), (31, False)])
def test_uncompressed_versions_produce_pecmd_shaped_runs(version, late):
    observations, warnings = parse_prefetch_binary(build_scca(version, late_win10=late), **CONTEXT)
    assert warnings == []
    [run] = observations
    assert run["kind"] == "prefetch_run" and run["time_semantics"] == "prefetch_recorded_run"
    assert run["timestamp"] == (T0 + timedelta(seconds=9)).isoformat()
    assert run["timestamp_raw"].startswith("FILETIME:0x")
    assert run["collector"] == {"name": "triage-prefetch-binary", "version": "1.0.0"}
    details = run["details"]
    assert details["name"] == "UPD.EXE" and details["run_count"] == 3 and details["prefetch_hash"] == "11223344"
    record = details["export_record"]
    assert record["FilesLoaded"].endswith(UPD_PATH) and record["RunCount"] == "3"
    assert record["Version"] == str(version) and record["ParsingError"] is False
    assert record["Volume0Serial"] == "1A2B3C4D"
    assert record["Volume0Name"] == "\\VOLUME{01d0a1b2c3d4e5f6-1a2b3c4d}"
    assert record["Volume0Created"] == (T0 - timedelta(days=400)).isoformat()
    assert "\\USERS\\PUBLIC" in record["Directories"]
    assert details["native"]["compressed"] is False and details["native"]["filename_count"] == 2


def test_binary_observations_match_pecmd_observation_shape():
    export = json.dumps({"SourceFilename": "UPD.EXE-11223344.pf", "ExecutableName": "UPD.EXE", "RunCount": "3",
                         "Version": "30", "Hash": "11223344", "LastRun": "2026-10-01T13:20:09.0000000+00:00",
                         "ParsingError": False}).encode() + b"\n"
    [pecmd], _ = parse_pecmd_jsonl(export, **{**CONTEXT, "source_sha256": "e" * 64},
                                   collector={"name": "PECmd", "version": "test"})
    [native], _ = parse_prefetch_binary(build_scca(30), **CONTEXT, original_name="UPD.EXE-11223344.pf")
    assert set(native) == set(pecmd)
    assert set(pecmd["details"]) <= set(native["details"])
    assert (native["timestamp"], native["kind"], native["details"]["name"]) == \
        (pecmd["timestamp"], pecmd["kind"], pecmd["details"]["name"])
    assert native["details"]["location"] == "UPD.EXE-11223344.pf"


def test_eight_run_times_skip_zero_slots_and_record_without_runs():
    runs = [T0, None, T0 - timedelta(hours=1), None, None, None, None, T0 - timedelta(days=2)]
    observations, _ = parse_prefetch_binary(build_scca(30, runs=runs), **CONTEXT)
    assert [o["native_locator"]["runField"] for o in observations] == ["LastRun", "PreviousRun1", "PreviousRun6"]
    assert len({o["id"] for o in observations}) == 3
    [record], warnings = parse_prefetch_binary(build_scca(26, runs=(), run_count=0), **CONTEXT)
    assert record["kind"] == "prefetch_record" and record["timestamp"] is None and warnings == []
    [record], warnings = parse_prefetch_binary(build_scca(23, runs=(), run_count=2), **CONTEXT)
    assert record["kind"] == "prefetch_record" and "no run timestamp" in warnings[0]
    assert record["details"]["export_record"]["ParsingError"] is True


def test_compressed_v30_matches_uncompressed_parse():
    names = tuple(f"\\VOLUME{{01d0a1b2c3d4e5f6-1a2b3c4d}}\\WINDOWS\\SYSTEM32\\LIB{i:05}.DLL" for i in range(1200))
    plain = build_scca(30, filenames=names + (UPD_PATH,))
    assert len(plain) > 2 * 65536  # Spans several 64 KiB Huffman chunks.
    packed = mam(plain)
    assert len(packed) < len(plain)
    [compressed], warnings = parse_prefetch_binary(packed, **CONTEXT)
    [uncompressed], _ = parse_prefetch_binary(plain, **CONTEXT)
    # The long list is truncated in export_record but keeps the executable's own path.
    assert warnings == ["Prefetch filename list truncated to 65536 characters in export_record"]
    assert compressed["details"]["export_record"]["FilesLoaded"].startswith(UPD_PATH)
    assert compressed["details"]["native"]["compressed"] is True
    assert compressed["details"]["native"]["filename_count"] == 1201
    assert compressed["details"]["export_record"] == uncompressed["details"]["export_record"]
    assert compressed["timestamp"] == uncompressed["timestamp"]


@pytest.mark.parametrize("data", [
    b"",
    bytes(range(256)) * 3,
    b"A" * 70000,                                 # Overlapping matches and 16-bit extended lengths.
    b"abc" * 40 + b"x" * 300 + b"abc" * 40,       # Byte-extended lengths.
    hashlib.sha256(b"seed").digest() * 5000,
], ids=["empty", "literals", "long-run", "byte-length", "multi-chunk"])
def test_decoder_round_trips_test_encoder(data):
    if not data:
        with pytest.raises(ValueError, match="out of bounds"):
            lzxpress_huffman_decompress(huffman_compress(data), 0)
        return
    assert lzxpress_huffman_decompress(huffman_compress(data), len(data)) == data


# ---- hostile input ----

def test_truncated_inputs_are_rejected():
    plain = build_scca(30)
    for cut in (10, 83, 200, len(plain) - 1):
        with pytest.raises(ValueError):
            parse_prefetch_binary(plain[:cut], **CONTEXT)
    packed = mam(plain)
    with pytest.raises(ValueError, match="Truncated"):
        parse_prefetch_binary(packed[:200], **CONTEXT)
    with pytest.raises(ValueError, match="MAM header"):
        parse_prefetch_binary(b"MAM\x04\x10", **CONTEXT)


@pytest.mark.parametrize("mutate, message", [
    (lambda b: b[:4] + b"SCCB" + b[8:], "signature"),
    (lambda b: struct.pack("<I", 29) + b[4:], "Unsupported Prefetch format version"),
    (lambda b: b"MAM\x05" + b[4:], "Unsupported Prefetch compression"),
    (lambda b: b[:16] + b"\0" * 60 + b[76:], "no executable name"),
])
def test_bad_signature_version_and_name_are_rejected(mutate, message):
    with pytest.raises(ValueError, match=message):
        parse_prefetch_binary(mutate(build_scca(30)), **CONTEXT)


def test_bad_declared_sizes_are_rejected():
    plain = bytearray(build_scca(30))
    struct.pack_into("<I", plain, 12, len(plain) + 8)
    with pytest.raises(ValueError, match="file size does not match"):
        parse_prefetch_binary(bytes(plain), **CONTEXT)
    good = build_scca(30)
    # Container declares fewer bytes than the SCCA header: decoded content is inconsistent.
    with pytest.raises(ValueError):
        parse_prefetch_binary(mam(good, declared=len(good) - 16), **CONTEXT)
    # Container declares more bytes than the stream encodes.
    with pytest.raises(ValueError):
        parse_prefetch_binary(mam(good, declared=len(good) + 70000), **CONTEXT)


def test_decompression_bomb_is_bounded():
    with pytest.raises(ValueError, match="out of bounds"):
        parse_prefetch_binary(b"MAM\x04" + struct.pack("<I", MAX_DECOMPRESSED + 1) + b"\0" * 300, **CONTEXT)
    with pytest.raises(ValueError, match="out of bounds"):
        parse_prefetch_binary(b"MAM\x04" + struct.pack("<I", 0xFFFFFFFF) + b"\0" * 300, **CONTEXT)
    # A tiny stream of long matches expanding past the declared size stops at the bound.
    stream = huffman_compress(b"\0" * 300000)
    assert len(stream) < 2000
    with pytest.raises(ValueError, match="exceeds declared size"):
        lzxpress_huffman_decompress(stream, 1000)
    # Expanding to the declared cap still yields only a bounded, non-SCCA buffer.
    with pytest.raises(ValueError, match="signature"):
        parse_prefetch_binary(b"MAM\x04" + struct.pack("<I", 300000) + stream, **CONTEXT)


def test_oversized_and_out_of_bounds_string_tables():
    with pytest.raises(ValueError, match="string table exceeds limit"):
        parse_prefetch_binary(build_scca(30, strings_size=MAX_STRING_TABLE + 2), **CONTEXT)
    with pytest.raises(ValueError, match="filename strings outside file"):
        parse_prefetch_binary(build_scca(30, strings_size=10**6), **CONTEXT)
    names = tuple(f"\\V\\F{i}" for i in range(MAX_FILENAMES + 10))
    [run], warnings = parse_prefetch_binary(build_scca(30, filenames=names), **CONTEXT)
    assert any("truncated at" in w for w in warnings) and any("export_record" in w for w in warnings)
    assert run["details"]["native"]["filename_count"] == MAX_FILENAMES
    assert len(run["details"]["export_record"]["FilesLoaded"]) <= MAX_JOINED
    assert run["details"]["export_record"]["ParsingError"] is True
    with pytest.raises(ValueError, match="Oversized Prefetch filename"):
        parse_prefetch_binary(build_scca(30, raw_strings=("B" * 33000).encode("utf-16-le") + b"\0\0"), **CONTEXT)


def test_volume_count_and_offsets_are_bounded():
    plain = bytearray(build_scca(30))
    struct.pack_into("<I", plain, 84 + 28, 10_000)
    with pytest.raises(ValueError, match="volume count"):
        parse_prefetch_binary(bytes(plain), **CONTEXT)
    plain = bytearray(build_scca(17))
    struct.pack_into("<I", plain, 84 + 24, 40)  # Volume area overlapping the header.
    with pytest.raises(ValueError, match="volume information outside file"):
        parse_prefetch_binary(bytes(plain), **CONTEXT)


# ---- intake and correlation ----

def write_pf(folder: Path, name: str, data: bytes) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_bytes(data)
    return path


def pecmd_export(folder: Path) -> Path:
    path = folder / "prefetch.jsonl"
    path.write_text(json.dumps({"SourceFilename": "C:\\Windows\\Prefetch\\UPD.EXE-11223344.pf", "ExecutableName": "UPD.EXE",
                                "RunCount": "3", "Version": "30", "Hash": "11223344",
                                "LastRun": "2026-10-01T13:20:09.0000000+00:00", "ParsingError": False}) + "\n",
                    encoding="utf-8")
    return path


def test_prefetch_only_bundle_is_parsed_and_damaged_file_marks_partial(tmp_path):
    good = write_pf(tmp_path / "src", "UPD.EXE-11223344.pf", mam(build_scca(30)))
    bad = write_pf(tmp_path / "src", "BAD.EXE-00000000.pf", b"MAM\x04" + b"\xff" * 12)
    bundle = pack_artifacts(tmp_path / "bundle", host="WS-LAB-01", observed_at="2026-10-02T12:00:00Z",
                            prefetch_source=[good, bad])
    result = read_forensic_bundle(str(bundle), temp_dir=tmp_path / "temp")
    [run] = result.observations
    assert run["details"]["location"] == "UPD.EXE-11223344.pf"
    assert run["source_file"] == "prefetch_source-1.pf"
    assert result.manifest["completeness"] == "partial"
    assert any("prefetch_source-2.pf not parsed" in w for w in result.manifest["warnings"])
    assert {kind for _, kind in result.files} == {"artifact_manifest", "prefetch_source"}


def test_pecmd_and_binary_of_same_file_are_kept_but_not_independent(tmp_path):
    sources = tmp_path / "src"
    native = write_pf(sources, "UPD.EXE-11223344.pf", build_scca(30))
    bundle = pack_artifacts(tmp_path / "bundle", host="WS-LAB-01", observed_at="2026-10-02T12:00:00Z",
                            prefetch_source=[native], pecmd_jsonl=[pecmd_export(sources)], pecmd_version="test")
    observations = read_forensic_bundle(str(bundle), temp_dir=tmp_path / "temp").observations
    assert {o["collector"]["name"] for o in observations} == {"PECmd", "triage-prefetch-binary"}
    assert len({o["id"] for o in observations}) == 2
    assert all("not independent corroboration" in o["interpretation"] for o in observations)
    assert all(o["details"]["shared_source_parsers"] == ["PECmd", "triage-prefetch-binary"] for o in observations)

    event = NormalizedEvent(1, T0, computer="WS-LAB-01", channel="Microsoft-Windows-Sysmon/Operational",
                            provider="Microsoft-Windows-Sysmon", process_name_value="C:\\Users\\Public\\upd.exe",
                            parent_process_value="C:\\Windows\\explorer.exe", record_id="7",
                            source_file="evidence/a.evtx", source_sha256="a" * 64, observation_id="obs_evt_7")
    relationships, coverage = correlate_evidence([event], observations)
    assert len(relationships) == 2 and coverage["families"]["prefetch"]["run_observations"] == 2
    native_link = next(r for r in relationships if r["target"]["source_sha256"] == hashlib.sha256(build_scca(30)).hexdigest())
    assert native_link["link_class"] == "supported_inference"
    assert any(m["artifact_field"] == "export_record.FilesLoaded" for m in native_link["matched_fields"])
    [finding] = cross_source_alerts(relationships, [event],
                                    [Alert("Suspicious Child", "high", "Execution", "T1204", "d", "e", event)])
    assert finding.confidence == "medium" and finding.evidence["evidence_strength"] == "medium"
    assert finding.evidence["linked_artifact_kinds"] == ["prefetch_run"]


def test_mixed_case_links_process_event_to_binary_parsed_run(tmp_path):
    native = write_pf(tmp_path / "src", "UPD.EXE-11223344.pf", mam(build_scca(30)))
    bundle = pack_artifacts(tmp_path / "bundle", host="WS-LAB-01", observed_at="2026-10-02T12:00:00Z",
                            prefetch_source=[native])
    evtx = tmp_path / "events.evtx"
    evtx.write_bytes(b"synthetic evtx")

    def parse(path, *args, source_files, **kwargs):
        event = NormalizedEvent(1, T0, computer="WS-LAB-01", channel="Microsoft-Windows-Sysmon/Operational",
                                provider="Microsoft-Windows-Sysmon", process_name_value="C:\\Users\\Public\\upd.exe",
                                parent_process_value="C:\\Windows\\explorer.exe", record_id="7")
        event.source_file = source_files[0]
        return [event]

    with patch.object(service, "read_evtx_path", side_effect=parse), \
         patch.object(service, "_run_detectors", return_value=([], {})):
        result = service.run_investigation(service.InvestigationRequest(
            str(evtx), artifact_bundle=str(bundle), case_name="native-pf", cases_dir=str(tmp_path / "cases")))
    case = Path(result.case_path)
    [link] = json.loads((case / "evidence_relationships.json").read_text(encoding="utf-8"))["relationships"]
    assert link["rule"]["name"] == "prefetch_run_matches_process_creation"
    assert link["link_class"] == "supported_inference"
    assert link["target"]["source_sha256"] == hashlib.sha256(native.read_bytes()).hexdigest()
    retained = json.loads((case / "evidence_manifest.json").read_text(encoding="utf-8"))
    assert any(source["sha256"] == link["target"]["source_sha256"] for source in retained["sources"])
    assert result.incident_count == 0
