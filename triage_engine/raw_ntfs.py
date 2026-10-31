"""Read-only copies of an NTFS volume's $MFT and the allocated part of $UsnJrnl:$J.

Windows locks both files, so they are read through the raw volume
(``\\\\.\\C:``, administrator only). The volume is only ever read. Functions
take any seekable binary handle, so tests run against synthetic images.

Command line (elevated):  python -m triage_engine.raw_ntfs C: OUTPUT_DIR [--usn-cap-mib N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import BinaryIO, Callable

REF_MASK = (1 << 48) - 1
EXTEND_RECORD = 11
COPY_BLOCK = 4 * 1024 * 1024


class RawNtfsError(ValueError):
    """The volume or a record could not be read as NTFS."""


def boot_geometry(boot: bytes) -> dict:
    if boot[3:11] != b"NTFS    ":
        raise RawNtfsError("Not an NTFS volume")
    bytes_per_sector, sectors_per_cluster = struct.unpack_from("<HB", boot, 0x0B)
    cluster = bytes_per_sector * sectors_per_cluster
    raw = struct.unpack_from("<b", boot, 0x40)[0]
    record_size = 2 ** -raw if raw < 0 else raw * cluster
    if not cluster or record_size < 512:
        raise RawNtfsError("Implausible NTFS geometry")
    return {"sector": bytes_per_sector, "cluster": cluster, "record_size": record_size,
            "mft_lcn": struct.unpack_from("<Q", boot, 0x30)[0], "serial": f"{struct.unpack_from('<Q', boot, 0x48)[0]:016X}"}


def apply_fixup(record: bytearray, sector: int) -> bool:
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    check = record[usa_offset:usa_offset + 2]
    for index in range(1, usa_count):
        end = index * sector
        if end > len(record) or record[end - 2:end] != check:
            return False
        record[end - 2:end] = record[usa_offset + 2 * index:usa_offset + 2 * index + 2]
    return True


def attributes(record: bytes):
    offset = struct.unpack_from("<H", record, 0x14)[0]
    while offset + 8 <= len(record):
        kind, length = struct.unpack_from("<II", record, offset)
        if kind == 0xFFFFFFFF or length < 16 or offset + length > len(record):
            return
        yield kind, record[offset:offset + length]
        offset += length


def attribute_name(attribute: bytes) -> str:
    count, offset = attribute[9], struct.unpack_from("<H", attribute, 0x0A)[0]
    return attribute[offset:offset + 2 * count].decode("utf-16-le", "replace")


def data_runs(attribute: bytes) -> list[tuple[int | None, int]]:
    """(LCN or None for a sparse run, cluster count) for a non-resident attribute."""
    position, lcn, runs = struct.unpack_from("<H", attribute, 0x20)[0], 0, []
    while position < len(attribute) and attribute[position]:
        header = attribute[position]
        length_size, offset_size = header & 0x0F, header >> 4
        if not length_size or position + 1 + length_size + offset_size > len(attribute):
            raise RawNtfsError("Malformed data run")
        length = int.from_bytes(attribute[position + 1:position + 1 + length_size], "little")
        if offset_size:
            lcn += int.from_bytes(attribute[position + 1 + length_size:position + 1 + length_size + offset_size],
                                  "little", signed=True)
            runs.append((lcn, length))
        else:
            runs.append((None, length))
        position += 1 + length_size + offset_size
    return runs


def _read_at(volume: BinaryIO, offset: int, size: int, cluster: int) -> bytes:
    # Raw volume reads must start and end on sector boundaries; whole clusters always do.
    start = offset // cluster * cluster
    end = -(-(offset + size) // cluster) * cluster
    volume.seek(start)
    data = volume.read(end - start)
    return data[offset - start:offset - start + size]


def copy_stream(volume: BinaryIO, runs, cluster: int, real_size: int, output: BinaryIO, skip: int = 0) -> tuple[int, str]:
    """Copy allocated runs (sparse runs are never written), starting ``skip`` bytes into the stream."""
    digest, logical, written = hashlib.sha256(), 0, 0
    for lcn, count in runs:
        run_bytes = count * cluster
        take = min(run_bytes, max(real_size - logical, 0))
        if lcn is not None and take > 0 and logical + run_bytes > skip:
            start = max(skip - logical, 0) // cluster * cluster
            position, remaining = lcn * cluster + start, take - start
            while remaining > 0:
                block = _read_at(volume, position, min(remaining, COPY_BLOCK), cluster)
                if not block:
                    raise RawNtfsError("Short read from volume")
                output.write(block)
                digest.update(block)
                written += len(block)
                position += len(block)
                remaining -= len(block)
        logical += run_bytes
    return written, digest.hexdigest()


def record_reader(volume: BinaryIO, geometry: dict, mft_runs) -> Callable[[int], bytearray]:
    """Read MFT record ``number`` live through the $MFT run list."""
    cluster, size = geometry["cluster"], geometry["record_size"]

    def read(number: int) -> bytearray:
        offset, base = number * size, 0
        for lcn, count in mft_runs:
            length = count * cluster
            if lcn is not None and base <= offset < base + length:
                record = bytearray(_read_at(volume, lcn * cluster + offset - base, size, cluster))
                if record[:4] != b"FILE" or not apply_fixup(record, geometry["sector"]):
                    raise RawNtfsError(f"MFT record {number} unreadable")
                return record
            base += length
        raise RawNtfsError(f"MFT record {number} is outside the $MFT")
    return read


def mft_data_attribute(volume: BinaryIO, geometry: dict) -> bytes:
    cluster, size = geometry["cluster"], geometry["record_size"]
    record = bytearray(_read_at(volume, geometry["mft_lcn"] * cluster, size, cluster))
    if record[:4] != b"FILE" or not apply_fixup(record, geometry["sector"]):
        raise RawNtfsError("$MFT record 0 unreadable")
    found = [attribute for kind, attribute in attributes(record) if kind == 0x80 and attribute[8] == 1 and attribute[9] == 0]
    if not found:
        raise RawNtfsError("$MFT data is described by an attribute list; not supported")
    return found[0]


def find_usn_record(mft_copy: BinaryIO, geometry: dict) -> int | None:
    """Record number of $Extend\\$UsnJrnl in a copied $MFT, or None when the journal is disabled."""
    size, number = geometry["record_size"], -1
    mft_copy.seek(0)
    while True:
        number += 1
        record = bytearray(mft_copy.read(size))
        if len(record) < size:
            return None
        if record[:4] != b"FILE" or not struct.unpack_from("<H", record, 0x16)[0] & 1 \
                or not apply_fixup(record, geometry["sector"]):
            continue
        for kind, attribute in attributes(record):
            if kind == 0x30 and attribute[8] == 0:
                value = attribute[struct.unpack_from("<H", attribute, 0x14)[0]:]
                if len(value) < 66:
                    continue
                parent = struct.unpack_from("<Q", value, 0)[0] & REF_MASK
                name = value[66:66 + 2 * value[64]].decode("utf-16-le", "replace")
                if parent == EXTEND_RECORD and name == "$UsnJrnl":
                    return number


def journal_stream(volume: BinaryIO, geometry: dict, read_record, number: int) -> tuple[int, list]:
    """($J logical size, ordered run list), following an $ATTRIBUTE_LIST when present."""
    record = read_record(number)
    found = list(attributes(record))
    pieces = [a for kind, a in found if kind == 0x80 and a[8] == 1 and attribute_name(a) == "$J"]
    lists = [a for kind, a in found if kind == 0x20]
    if lists:
        pieces = []  # The list names every extent, including those in the base record.
        listed = lists[0]
        if listed[8] == 0:
            value_size, value_offset = struct.unpack_from("<IH", listed, 0x10)
            content = listed[value_offset:value_offset + value_size]
        else:
            content = bytearray()
            for lcn, count in data_runs(listed):
                if lcn is not None:
                    content += _read_at(volume, lcn * geometry["cluster"], count * geometry["cluster"], geometry["cluster"])
            content = bytes(content[:struct.unpack_from("<Q", listed, 0x30)[0]])
        numbers, position = set(), 0
        while position + 0x1A <= len(content):
            kind, length = struct.unpack_from("<IH", content, position)
            if not length:
                break
            name_length, name_offset = content[position + 6], content[position + 7]
            name = content[position + name_offset:position + name_offset + 2 * name_length].decode("utf-16-le", "replace")
            if kind == 0x80 and name == "$J":
                numbers.add(struct.unpack_from("<Q", content, position + 0x10)[0] & REF_MASK)
            position += length
        for extent in sorted(numbers):
            pieces += [a for kind, a in attributes(read_record(extent))
                       if kind == 0x80 and a[8] == 1 and attribute_name(a) == "$J"]
    if not pieces:
        raise RawNtfsError("$UsnJrnl has no $J stream")
    by_vcn = {struct.unpack_from("<Q", piece, 0x10)[0]: piece for piece in pieces}
    if 0 not in by_vcn:
        raise RawNtfsError("$J first extent missing")
    ordered = [by_vcn[vcn] for vcn in sorted(by_vcn)]
    return struct.unpack_from("<Q", ordered[0], 0x30)[0], [run for piece in ordered for run in data_runs(piece)]


def newest_bytes_skip(runs, cluster: int, cap: int) -> int:
    """Logical offset to start at so that at most ``cap`` allocated bytes (the newest) are copied."""
    spans, logical = [], 0
    for lcn, count in runs:
        spans.append((logical, count * cluster, lcn is not None))
        logical += count * cluster
    need = cap
    for start, length, allocated in reversed(spans):
        if allocated:
            if length >= need:
                return start + length - need
            need -= length
    return 0


def extract(volume: BinaryIO, output_dir: Path, *, usn_cap: int = 1024 ** 3) -> dict:
    """Copy $MFT and the newest allocated $J bytes into ``output_dir``; returns a manifest dict."""
    output_dir.mkdir(parents=True, exist_ok=True)
    volume.seek(0)
    geometry = boot_geometry(volume.read(512))
    mft_attribute = mft_data_attribute(volume, geometry)
    mft_runs = data_runs(mft_attribute)
    mft_size = struct.unpack_from("<Q", mft_attribute, 0x30)[0]
    manifest = {"volume_serial": geometry["serial"], "cluster_size": geometry["cluster"],
                "record_size": geometry["record_size"], "files": []}
    with open(output_dir / "MFT.bin", "xb") as out:
        size, digest = copy_stream(volume, mft_runs, geometry["cluster"], mft_size, out)
    manifest["files"].append({"name": "MFT.bin", "kind": "ntfs_mft", "size_bytes": size, "sha256": digest})
    with open(output_dir / "MFT.bin", "rb") as copied:
        number = find_usn_record(copied, geometry)
    if number is None:
        manifest["warnings"] = ["No $UsnJrnl was found; the change journal may be disabled."]
        return manifest
    j_size, j_runs = journal_stream(volume, geometry, record_reader(volume, geometry, mft_runs), number)
    skip = newest_bytes_skip(j_runs, geometry["cluster"], usn_cap)
    with open(output_dir / "UsnJrnl_J.bin", "xb") as out:
        size, digest = copy_stream(volume, j_runs, geometry["cluster"], j_size, out, skip)
    manifest["files"].append({"name": "UsnJrnl_J.bin", "kind": "ntfs_usn_journal", "size_bytes": size,
                              "sha256": digest, "logical_size": j_size, "skipped_logical_bytes": skip,
                              "note": "Allocated bytes only; the sparse head of the journal holds no records."})
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Copy $MFT and $UsnJrnl:$J from a raw NTFS volume (read only, elevated).")
    parser.add_argument("volume", help="Drive letter such as C:")
    parser.add_argument("output", type=Path, help="New output folder")
    parser.add_argument("--usn-cap-mib", type=int, default=1024, help="Newest journal bytes to keep (default 1024)")
    args = parser.parse_args(argv)
    letter = args.volume.rstrip("\\").rstrip(":")
    if len(letter) != 1 or not letter.isalpha():
        parser.error("volume must be a drive letter such as C:")
    try:
        with open(rf"\\.\{letter}:", "rb", buffering=0) as volume:
            manifest = extract(volume, args.output, usn_cap=args.usn_cap_mib * 1024 * 1024)
    except PermissionError:
        print("Raw volume access needs an elevated (administrator) prompt.", file=sys.stderr)
        return 2
    except (OSError, RawNtfsError) as exc:
        print(f"NTFS extraction failed: {exc}", file=sys.stderr)
        return 1
    manifest["volume"] = f"{letter.upper()}:"
    (args.output / "ntfs_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
