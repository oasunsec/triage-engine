"""Replay registry transaction logs (.LOG1/.LOG2, Windows 8.1+ "HvLE" format) onto a dirty hive.

A hive copied from a running system is usually dirty: its newest changes are
still only in the transaction logs. Each log entry carries two Marvin32 hashes;
entries are applied only when both verify, in consecutive sequence order,
starting at the hive's own secondary sequence number. Anything else (a gap, a
bad hash, an older entry left over in a log) stops replay instead of guessing.
The original hive bytes are never modified; replay returns a new buffer.
"""

from __future__ import annotations

import struct

BASE_BLOCK = 4096
PAGE = 4096
ENTRY_HEADER = 40
MAX_DIRTY_PAGES = 1 << 20
MARVIN_SEED = 0x82EF4D887A4E55C5
_MASK = 0xFFFFFFFF


def _rotl(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK


def marvin32(data: bytes, seed: int = MARVIN_SEED) -> int:
    """Marvin32 as the registry uses it: the 64-bit (low | high << 32) state.

    The output form was confirmed against real Windows 11 log entries.
    """
    lo, hi = seed & _MASK, seed >> 32

    def mix(lo: int, hi: int) -> tuple[int, int]:
        hi ^= lo
        lo = (_rotl(lo, 20) + hi) & _MASK
        hi = _rotl(hi, 9) ^ lo
        lo = (_rotl(lo, 27) + hi) & _MASK
        hi = _rotl(hi, 19)
        return lo, hi

    full = len(data) // 4 * 4
    for (word,) in struct.iter_unpack("<I", data[:full]):
        lo, hi = mix((lo + word) & _MASK, hi)
    tail = data[full:]
    final = 0x80 << (8 * len(tail))
    for index, byte in enumerate(tail):
        final |= byte << (8 * index)
    lo, hi = mix((lo + (final & _MASK)) & _MASK, hi)
    lo, hi = mix(lo, hi)
    return lo | (hi << 32)


def log_entries(log: bytes) -> dict[int, dict]:
    """Verified entries of one log file, keyed by sequence number."""
    entries: dict[int, dict] = {}
    offset = 512
    while offset + ENTRY_HEADER <= len(log) and log[offset:offset + 4] == b"HvLE":
        size, _flags, sequence, bins_size, page_count = struct.unpack_from("<IIIII", log, offset + 4)
        hash1, hash2 = struct.unpack_from("<QQ", log, offset + 24)
        if size < ENTRY_HEADER or size % 512 or offset + size > len(log) or page_count > MAX_DIRTY_PAGES:
            break
        entry = log[offset:offset + size]
        if marvin32(entry[:32]) != hash2 or marvin32(entry[ENTRY_HEADER:]) != hash1:
            break  # Torn or stale tail: nothing after it can be trusted.
        references = ENTRY_HEADER + 8 * page_count
        if references > size:
            break
        pages, data_offset = [], references
        for index in range(page_count):
            page_offset, page_size = struct.unpack_from("<II", entry, ENTRY_HEADER + 8 * index)
            if page_size % PAGE or page_offset % PAGE or page_offset + page_size > bins_size \
                    or data_offset + page_size > size:
                pages = None
                break
            pages.append((page_offset, entry[data_offset:data_offset + page_size]))
            data_offset += page_size
        if pages is None:
            break
        entries[sequence] = {"sequence": sequence, "bins_size": bins_size, "pages": pages}
        offset += size
    return entries


def replay(hive: bytes, logs: list[bytes]) -> tuple[bytes, dict]:
    """Return (hive bytes with verified log entries applied, report)."""
    if len(hive) < BASE_BLOCK or hive[:4] != b"regf":
        raise ValueError("Not a registry hive")
    primary, secondary = struct.unpack_from("<II", hive, 4)
    report = {"dirty": primary != secondary, "primary_sequence": primary, "secondary_sequence": secondary,
              "entries_found": 0, "entries_applied": 0, "first_applied": None, "last_applied": None}
    entries: dict[int, dict] = {}
    for log in logs:
        found = log_entries(log)
        report["entries_found"] += len(found)
        entries.update(found)
    # A flush writes log entry N while the hive is at N, then advances it to N+1, so entries
    # continue from the secondary number. Windows also flushes hives lazily, so a hive whose
    # two numbers agree can still have newer entries waiting; older entries are never applied.
    if secondary not in entries:
        return hive, report
    data = bytearray(hive)
    sequence = secondary
    while sequence in entries:
        entry = entries[sequence]
        end = BASE_BLOCK + entry["bins_size"]
        if len(data) < end:
            data.extend(b"\x00" * (end - len(data)))
        for page_offset, page in entry["pages"]:
            start = BASE_BLOCK + page_offset
            data[start:start + len(page)] = page
        struct.pack_into("<I", data, 0x28, entry["bins_size"])
        report["first_applied"] = report["first_applied"] if report["first_applied"] is not None else sequence
        report["last_applied"] = sequence
        report["entries_applied"] += 1
        sequence += 1
    if report["entries_applied"]:
        struct.pack_into("<II", data, 4, sequence, sequence)
        checksum = 0
        for (word,) in struct.iter_unpack("<I", bytes(data[:508])):
            checksum ^= word
        struct.pack_into("<I", data, 508, checksum)
    return bytes(data), report
