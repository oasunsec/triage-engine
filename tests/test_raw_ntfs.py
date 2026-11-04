"""Raw-volume $MFT/$J extraction against synthetic NTFS images (no disk access)."""

import io
import struct

import pytest

from corrobora.raw_ntfs import RawNtfsError, data_runs, extract, newest_bytes_skip
from corrobora.ntfs_artifacts import parse_mft, parse_usn_journal

SECTOR, CLUSTER, RECORD = 512, 4096, 1024
MFT_LCN, MFT_CLUSTERS = 4, 4          # 16 records
J_LCN = 20


def boot_sector() -> bytes:
    boot = bytearray(SECTOR)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 0x0B, SECTOR, CLUSTER // SECTOR)
    struct.pack_into("<Q", boot, 0x30, MFT_LCN)
    struct.pack_into("<b", boot, 0x40, -10)  # 2**10 = 1024-byte records
    struct.pack_into("<Q", boot, 0x48, 0x01DB0A05801DB9B9)
    return bytes(boot)


def run_list(runs) -> bytes:
    out, previous = b"", 0
    for lcn, count in runs:
        length = count.to_bytes(2, "little")
        if lcn is None:
            out += bytes([0x02]) + length
        else:
            delta = (lcn - previous).to_bytes(2, "little", signed=True)
            out += bytes([0x22]) + length + delta
            previous = lcn
    return out + b"\x00"


def nonresident(kind, runs, real_size, *, name="", vcn=0) -> bytes:
    encoded_name = name.encode("utf-16-le")
    name_offset = 0x40
    runs_offset = (name_offset + len(encoded_name) + 7) // 8 * 8
    body = run_list(runs)
    length = (runs_offset + len(body) + 7) // 8 * 8
    clusters = sum(count for _, count in runs)
    attr = bytearray(length)
    struct.pack_into("<IIBBHHH", attr, 0, kind, length, 1, len(name), name_offset, 0, 0)
    struct.pack_into("<QQHH", attr, 0x10, vcn, vcn + clusters - 1, runs_offset, 0)
    struct.pack_into("<QQQ", attr, 0x28, clusters * CLUSTER, real_size, real_size)
    attr[name_offset:name_offset + len(encoded_name)] = encoded_name
    attr[runs_offset:runs_offset + len(body)] = body
    return bytes(attr)


def resident(kind, value) -> bytes:
    length = (0x18 + len(value) + 7) // 8 * 8
    attr = bytearray(length)
    struct.pack_into("<IIBBHHHIH", attr, 0, kind, length, 0, 0, 0x18, 0, 0, len(value), 0x18)
    attr[0x18:0x18 + len(value)] = value
    return bytes(attr)


def file_name(parent: int, name: str) -> bytes:
    encoded = name.encode("utf-16-le")
    value = bytearray(66 + len(encoded))
    struct.pack_into("<Q", value, 0, parent | (1 << 48))
    value[64], value[65] = len(name), 1
    value[66:] = encoded
    return resident(0x30, bytes(value))


def attribute_list_entry(kind, record, name="", vcn=0) -> bytes:
    encoded = name.encode("utf-16-le")
    length = (0x1A + len(encoded) + 7) // 8 * 8
    entry = bytearray(length)
    struct.pack_into("<IHBBQQH", entry, 0, kind, length, len(name), 0x1A, vcn, record | (1 << 48), 0)
    entry[0x1A:0x1A + len(encoded)] = encoded
    return bytes(entry)


def mft_record(attrs, *, base=0, directory=False) -> bytes:
    record = bytearray(RECORD)
    first = 0x38
    body = b"".join(attrs) + b"\xff\xff\xff\xff\x00\x00\x00\x00"
    used = first + len(body)
    struct.pack_into("<4sHHQHHHHIIQ", record, 0, b"FILE", 0x30, 3, 0, 1, 1, first, 1 | (2 if directory else 0),
                     used, RECORD, base | (1 << 48) if base else 0)
    record[first:used] = body
    struct.pack_into("<H", record, 0x30, 0x0101)
    for index in (1, 2):
        end = index * SECTOR
        record[0x30 + 2 * index:0x32 + 2 * index] = record[end - 2:end]
        record[end - 2:end] = b"\x01\x01"
    return bytes(record)


def usn_record(usn: int, name: str) -> bytes:
    encoded = name.encode("utf-16-le")
    length = (60 + len(encoded) + 7) // 8 * 8
    record = bytearray(length)
    struct.pack_into("<IHHQQqqIIIIHH", record, 0, length, 2, 0, 40 | (1 << 48), 5 | (5 << 48), usn,
                     133000000000000000, 0x100, 0, 0, 0x20, len(encoded), 60)
    record[60:60 + len(encoded)] = encoded
    return bytes(record)


def volume_image(*, attribute_list: bool) -> tuple[bytes, bytes]:
    journal = usn_record(8192, "dropper.exe") + usn_record(8192 + 72, "note.txt")
    j_size = 2 * CLUSTER + len(journal)              # two sparse clusters, then data
    j_runs = [(None, 2), (J_LCN, 1)]
    records = {0: mft_record([file_name(5, "$MFT"), nonresident(0x80, [(MFT_LCN, MFT_CLUSTERS)], MFT_CLUSTERS * CLUSTER)]),
               5: mft_record([file_name(5, ".")], directory=True),
               11: mft_record([file_name(5, "$Extend")], directory=True)}
    if attribute_list:
        listing = attribute_list_entry(0x30, 12) + attribute_list_entry(0x80, 13, "$J")
        records[12] = mft_record([resident(0x20, listing), file_name(11, "$UsnJrnl")])
        records[13] = mft_record([nonresident(0x80, j_runs, j_size, name="$J")], base=12)
    else:
        records[12] = mft_record([file_name(11, "$UsnJrnl"), nonresident(0x80, j_runs, j_size, name="$J")])
    image = bytearray(CLUSTER * (J_LCN + 1))
    image[:SECTOR] = boot_sector()
    for number, record in records.items():
        start = MFT_LCN * CLUSTER + number * RECORD
        image[start:start + RECORD] = record
    image[J_LCN * CLUSTER:J_LCN * CLUSTER + len(journal)] = journal
    return bytes(image), journal


@pytest.mark.parametrize("attribute_list", [False, True], ids=["base-record", "attribute-list"])
def test_extract_copies_mft_and_allocated_journal(tmp_path, attribute_list):
    image, journal = volume_image(attribute_list=attribute_list)
    manifest = extract(io.BytesIO(image), tmp_path / "out")
    mft = (tmp_path / "out" / "MFT.bin").read_bytes()
    assert mft == image[MFT_LCN * CLUSTER:(MFT_LCN + MFT_CLUSTERS) * CLUSTER]
    assert (tmp_path / "out" / "UsnJrnl_J.bin").read_bytes() == journal  # sparse head not written
    assert [item["kind"] for item in manifest["files"]] == ["ntfs_mft", "ntfs_usn_journal"]
    assert manifest["volume_serial"] == "01DB0A05801DB9B9"
    # The engine's own parsers read the copies.
    assert parse_mft(tmp_path / "out" / "MFT.bin").records == 16
    usn = parse_usn_journal(tmp_path / "out" / "UsnJrnl_J.bin")
    assert usn.stats["records"] == 2


def test_journal_cap_keeps_the_newest_allocated_bytes():
    runs = [(None, 10), (100, 2), (200, 3)]
    assert newest_bytes_skip(runs, CLUSTER, 10 ** 9) == 0
    assert newest_bytes_skip(runs, CLUSTER, 3 * CLUSTER) == 12 * CLUSTER
    assert newest_bytes_skip(runs, CLUSTER, 4 * CLUSTER) == 11 * CLUSTER


def test_sparse_runs_and_rejections(tmp_path):
    attr = nonresident(0x80, [(None, 3), (50, 2), (40, 1)], 6 * CLUSTER)
    assert data_runs(attr) == [(None, 3), (50, 2), (40, 1)]
    with pytest.raises(RawNtfsError, match="Not an NTFS volume"):
        extract(io.BytesIO(b"\x00" * 8192), tmp_path / "bad")
