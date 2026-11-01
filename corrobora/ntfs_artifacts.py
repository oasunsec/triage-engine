"""Bounded, streaming NTFS $MFT and $UsnJrnl:$J parsing for file-system chronology.

The parser reads each file once, sequentially, and keeps a compact columnar
index (Python arrays, not per-record objects) of what path resolution and
correlation need. Observations are materialized only for records that a
correlation rule links, plus a bounded set of records whose $STANDARD_INFORMATION
and $FILE_NAME timestamps disagree.

Meaning of the timestamps, which are never merged:

- ``mft_standard_information``: the $SI times. User-mode APIs can set them, so
  they can be altered (timestomping).
- ``mft_file_name``: the $FILE_NAME times for one name of the file. The kernel
  maintains them, but they can still be altered (for example by moving a file
  after changing $SI), so they corroborate rather than prove.
- ``usn_journal_record``: when the journal recorded a change. The journal is a
  bounded circular log; records roll over, so absence is not proof.

Inputs are hostile: every offset and length is bounds-checked, fixups are
verified, parent chains are walked with a depth bound and cycle detection, and
record counts are capped.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from array import array
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

MAX_MFT_RECORDS = 4_000_000
MAX_USN_RECORDS = 20_000_000
MAX_USN_CREATES = 4_000_000
MAX_PATH_DEPTH = 255
MAX_NAMES_PER_RECORD = 8
MAX_ATTRIBUTES = 128
MAX_USN_RECORD = 4096
MAX_CONTRADICTION_OBSERVATIONS = 5_000
CHUNK = 4 * 1024 * 1024
ROOT_RECORD = 5
SECTOR = 512
REF_MASK = (1 << 48) - 1
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MAX_FILETIME = int((datetime(9999, 12, 31, tzinfo=timezone.utc) - _EPOCH).total_seconds()) * 10_000_000
# Same-second tolerance before an attribute time counts as later than an event.
CLOCK_TOLERANCE = timedelta(seconds=2)

REASONS = {
    0x00000001: "DATA_OVERWRITE", 0x00000002: "DATA_EXTEND", 0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE", 0x00000020: "NAMED_DATA_EXTEND", 0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE", 0x00000200: "FILE_DELETE", 0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE", 0x00001000: "RENAME_OLD_NAME", 0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE", 0x00008000: "BASIC_INFO_CHANGE", 0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE", 0x00040000: "ENCRYPTION_CHANGE", 0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE", 0x00200000: "STREAM_CHANGE", 0x00400000: "TRANSACTED_CHANGE",
    0x00800000: "INTEGRITY_CHANGE", 0x01000000: "DESIRED_STORAGE_CLASS_CHANGE", 0x80000000: "CLOSE",
}
FILE_CREATE = 0x100

# Per-record flag bits in the compact index.
_VALID, _IN_USE, _DIRECTORY, _HAS_SI, _EXTENSION = 1, 2, 4, 8, 16
# Path resolution status per record.
PATH_STATUS = {1: "resolved", 2: "orphan_parent_missing", 3: "orphan_parent_sequence_mismatch",
               4: "orphan_parent_not_directory", 5: "orphan_cycle", 6: "orphan_depth_exceeded", 7: "no_name"}
_OK = 1

_HEADER = struct.Struct("<4sHHQHHHHIIQ")  # signature .. base record reference (offset 0..40)
_ATTR = struct.Struct("<IIBBHHH")
_RESIDENT = struct.Struct("<IH")
_TIMES = struct.Struct("<qqqq")
_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")
_USN_HEAD = struct.Struct("<IHH")
_USN_V2 = struct.Struct("<QQqqIIIIHH")
_USN_V3 = struct.Struct("<QQQQqqIIIIHH")
_NONZERO = re.compile(rb"[^\x00]")
TIME_FIELDS = ("created", "modified", "mft_modified", "accessed")


def filetime_iso(value: int) -> str | None:
    """Return an ISO-8601 UTC string for a FILETIME, or None when zero or out of range."""
    if value <= 0 or value > _MAX_FILETIME:
        return None
    return (_EPOCH + timedelta(microseconds=value // 10)).isoformat()


def reason_names(mask: int) -> list[str]:
    names = [name for bit, name in REASONS.items() if mask & bit]
    unknown = mask & ~sum(REASONS)
    return names + ([f"UNKNOWN_0x{unknown:08x}"] if unknown else [])


def _split_ref(value: int) -> tuple[int, int]:
    return value & REF_MASK, value >> 48


def _observation_id(*parts) -> str:
    return "obs_" + hashlib.sha256(json.dumps(list(parts), separators=(",", ":")).encode("utf-8")).hexdigest()


class MftIndex:
    """Compact columnar index of an $MFT: one slot per record number, one entry per non-DOS name."""

    def __init__(self) -> None:
        self.record_size = 0
        self.flags = bytearray()
        self.seq = array("H")
        self.si = array("q")          # created, modified, mft_modified, accessed per record
        self.size = array("q")        # unnamed $DATA size, -1 when absent
        self.first_name = array("i")  # preferred name entry, -1 when none
        self.status = bytearray()
        self.depth = array("H")       # components below the root, for resolved records
        self.name_record = array("I")
        self.name_parent = array("Q")
        self.name_off = array("I")
        self.name_len = array("H")    # UTF-16 code units
        self.name_space = bytearray()
        self.fn = array("q")          # four times per name entry
        self.name_data = bytearray()
        self.stats = Counter()
        self.truncated = False
        # $DATA sizes from extension records that precede their base record.
        self.pending_size: dict[int, int] = {}

    @property
    def records(self) -> int:
        return len(self.flags)

    def _add_slot(self) -> int:
        self.flags.append(0)
        self.seq.append(0)
        self.si.extend((0, 0, 0, 0))
        self.size.append(-1)
        self.first_name.append(-1)
        self.status.append(0)
        self.depth.append(0)
        return len(self.flags) - 1

    def name(self, entry: int) -> str:
        offset = self.name_off[entry]
        return bytes(self.name_data[offset:offset + 2 * self.name_len[entry]]).decode("utf-16-le", "replace")

    # -- parsing --------------------------------------------------------------------------------

    def parse_record(self, raw: memoryview, number: int) -> None:
        slot = self._add_slot()
        signature = bytes(raw[:4])
        if signature == b"\x00\x00\x00\x00":
            self.stats["empty_records"] += 1
            return
        if signature == b"BAAD":
            self.stats["baad_records"] += 1
            return
        if signature != b"FILE":
            self.stats["invalid_signature"] += 1
            return
        size = len(raw)
        (_, usa_off, usa_count, _lsn, seq, _links, attr_off, flags, used, allocated, base) = _HEADER.unpack_from(raw, 0)
        if (usa_count != size // SECTOR + 1 or usa_off < 0x28 or usa_off % 2
                or usa_off + 2 * usa_count > size or allocated != size or not 0 < used <= size):
            self.stats["invalid_header"] += 1
            return
        record = bytearray(raw)
        check = record[usa_off:usa_off + 2]
        for index in range(1, usa_count):
            end = index * SECTOR
            if record[end - 2:end] != check:
                self.stats["bad_fixup"] += 1
                return
            record[end - 2:end] = record[usa_off + 2 * index:usa_off + 2 * index + 2]
        if not usa_off + 2 * usa_count <= attr_off < used:
            self.stats["invalid_header"] += 1
            return
        self.flags[slot] = _VALID | (_IN_USE if flags & 1 else 0) | (_DIRECTORY if flags & 2 else 0)
        self.seq[slot] = seq
        base_number, _base_seq = _split_ref(base)
        owner = slot
        if base_number:
            # Extension record: its $FILE_NAME and $DATA belong to the base record.
            self.flags[slot] |= _EXTENSION
            self.stats["extension_records"] += 1
            owner = base_number
        names = 0
        position = attr_off
        for _ in range(MAX_ATTRIBUTES):
            if position + 4 > used:
                self.stats["attribute_overrun"] += 1
                break
            kind = _U32.unpack_from(record, position)[0]
            if kind == 0xFFFFFFFF:
                break
            if position + 16 > used:
                self.stats["attribute_overrun"] += 1
                break
            kind, length, non_resident, name_length, _name_off, _aflags, _aid = _ATTR.unpack_from(record, position)
            if length < 16 or length % 8 or position + length > used:
                self.stats["attribute_overrun"] += 1
                break
            if not non_resident and length >= 24:
                value_length, value_off = _RESIDENT.unpack_from(record, position + 16)
                start = position + value_off
                if value_off < 24 or start + value_length > position + length:
                    self.stats["attribute_overrun"] += 1
                    break
                if kind == 0x10 and not base_number and value_length >= 36:
                    self.si[4 * slot:4 * slot + 4] = array("q", _TIMES.unpack_from(record, start))
                    self.flags[slot] |= _HAS_SI
                elif kind == 0x30 and value_length >= 66 and names < MAX_NAMES_PER_RECORD:
                    count, space = record[start + 64], record[start + 65]
                    if 66 + 2 * count > value_length or count == 0:
                        self.stats["invalid_file_name"] += 1
                    elif space != 2:  # DOS 8.3 names duplicate a Win32 name.
                        names += 1
                        self._add_name(owner, _U64.unpack_from(record, start)[0], _TIMES.unpack_from(record, start + 8),
                                       space, record[start + 66:start + 66 + 2 * count])
                elif kind == 0x80 and name_length == 0:
                    self._set_size(owner, value_length)
            elif non_resident and kind == 0x80 and name_length == 0 and length >= 64:
                lowest_vcn = _U64.unpack_from(record, position + 16)[0]
                if lowest_vcn == 0:
                    self._set_size(owner, _U64.unpack_from(record, position + 48)[0] & 0x7FFFFFFFFFFFFFFF)
            position += length
        self.stats["valid_records"] += 1
        if flags & 1:
            self.stats["in_use_records"] += 1

    def _set_size(self, owner: int, value: int) -> None:
        if owner < len(self.size):
            if self.size[owner] < 0:
                self.size[owner] = value
        elif owner not in self.pending_size and len(self.pending_size) < MAX_MFT_RECORDS:
            self.pending_size[owner] = value

    def _add_name(self, owner: int, parent: int, times, space: int, encoded) -> None:
        if len(self.name_data) + len(encoded) > 0xFFFFFFFF:
            self.stats["names_dropped"] += 1
            return
        entry = len(self.name_record)
        self.name_record.append(owner)
        self.name_parent.append(parent)
        self.name_off.append(len(self.name_data))
        self.name_len.append(len(encoded) // 2)
        self.name_space.append(space)
        self.fn.extend(times)
        self.name_data += encoded
        if owner < len(self.first_name) and self.first_name[owner] < 0:
            self.first_name[owner] = entry

    def finish(self) -> None:
        # Extension records can precede their base record; attach names afterwards.
        for owner, value in self.pending_size.items():
            if owner < self.records and self.flags[owner] & _VALID and self.size[owner] < 0:
                self.size[owner] = value
        self.pending_size.clear()
        for entry in range(len(self.name_record)):
            owner = self.name_record[entry]
            if owner < self.records and self.first_name[owner] < 0:
                self.first_name[owner] = entry
        self._resolve_all()

    # -- path resolution --------------------------------------------------------------------------

    def _parent_problem(self, entry: int) -> tuple[int, int]:
        """Return (parent record, problem status or 0) for a name entry."""
        parent, parent_seq = _split_ref(self.name_parent[entry])
        if parent >= self.records or not self.flags[parent] & _VALID:
            return parent, 2
        if not self.flags[parent] & _DIRECTORY:
            return parent, 4
        if parent_seq and self.seq[parent] != parent_seq:
            return parent, 3
        return parent, 0

    def _resolve_all(self) -> None:
        root_ok = self.records > ROOT_RECORD and self.flags[ROOT_RECORD] & _VALID and self.flags[ROOT_RECORD] & _DIRECTORY
        if root_ok:
            self.status[ROOT_RECORD] = _OK
        for start in range(self.records):
            if self.status[start] or not self.flags[start] & _VALID or self.flags[start] & _EXTENSION:
                continue  # Extension records carry their base record's names.
            chain: list[int] = []
            on_chain: set[int] = set()
            current = start
            base_depth = 0
            while True:
                if self.status[current]:
                    result = self.status[current]
                    base_depth = self.depth[current]
                    break
                if current == ROOT_RECORD:
                    result = _OK if root_ok else 2
                    break
                if current in on_chain:
                    result = 5
                    break
                if len(chain) >= MAX_PATH_DEPTH:
                    result = 6
                    break
                chain.append(current)
                on_chain.add(current)
                entry = self.first_name[current]
                if entry < 0:
                    result = 7
                    break
                parent, problem = self._parent_problem(entry)
                if problem:
                    result = problem
                    break
                current = parent
            for position, node in enumerate(chain):
                # Memoized ancestors still count toward the depth bound.
                node_depth = base_depth + len(chain) - position
                if result == _OK and node_depth > MAX_PATH_DEPTH:
                    self.status[node] = 6
                else:
                    self.status[node] = result
                    self.depth[node] = min(node_depth, 0xFFFF)
        counts = Counter(self.status[number] for number in range(self.records)
                         if self.flags[number] & _VALID and not self.flags[number] & _EXTENSION)
        for code, count in counts.items():
            if code != _OK and code in PATH_STATUS:
                self.stats[PATH_STATUS[code]] += count

    def directory_path(self, number: int, cache: dict[int, str | None]) -> str | None:
        """Volume-relative path of a resolved directory record ("" for the root), or None when orphaned."""
        if number in cache:
            return cache[number]
        if number >= self.records or self.status[number] != _OK:
            cache[number] = None
            return None
        parts: list[str] = []
        prefix = ""
        current = number
        for _ in range(MAX_PATH_DEPTH + 1):
            if current == ROOT_RECORD:
                break
            if cache.get(current) is not None:
                prefix = cache[current]
                break
            entry = self.first_name[current]
            parts.append(self.name(entry))
            current, _ = self._parent_problem(entry)
        else:
            cache[number] = None
            return None
        path = prefix + "".join("\\" + part for part in reversed(parts))
        cache[number] = path
        return path

    def entry_path(self, entry: int, cache: dict[int, str | None]) -> tuple[str, str]:
        """Return (volume-relative path, resolution status) for one name of a record."""
        parent, problem = self._parent_problem(entry)
        name = self.name(entry)
        if problem:
            return f"<{PATH_STATUS[problem]}>\\{name}", PATH_STATUS[problem]
        directory = self.directory_path(parent, cache)
        if directory is None:
            status = PATH_STATUS.get(self.status[parent], "orphan_parent_missing")
            return f"<{status}>\\{name}", status
        return f"{directory}\\{name}", "resolved"

    def lookup_paths(self, keys: Iterable[str]) -> dict[str, list[int]]:
        """Map casefolded volume-relative paths (``\\dir\\file``) to matching name entries.

        One pass over the name table, pre-filtered by name length, then a
        bounded parent walk only for entries whose file name matches.
        """
        wanted: dict[str, set[str]] = {}
        for key in keys:
            directory, _, base = key.rpartition("\\")
            if base:
                wanted.setdefault(base, set()).add(key)
        lengths = {len(base.encode("utf-16-le")) // 2 for base in wanted}
        found: dict[str, list[int]] = {}
        cache: dict[int, str | None] = {}
        name_len, name_off, data = self.name_len, self.name_off, self.name_data
        for entry in range(len(name_len)):
            if name_len[entry] not in lengths:
                continue
            owner = self.name_record[entry]
            if owner >= self.records or not self.flags[owner] & _VALID:
                continue
            offset = name_off[entry]
            name = bytes(data[offset:offset + 2 * name_len[entry]]).decode("utf-16-le", "replace").casefold()
            if name not in wanted:
                continue
            path, status = self.entry_path(entry, cache)
            key = path.casefold()
            if status == "resolved" and key in wanted[name]:
                found.setdefault(key, []).append(entry)
        return found

    def contradictions(self, number: int, entry: int) -> list[dict]:
        """Disagreements between $SI and one $FILE_NAME; reported, never treated as proof."""
        if not self.flags[number] & _HAS_SI:
            return []
        si = self.si[4 * number:4 * number + 4]
        fn = self.fn[4 * entry:4 * entry + 4]
        items = []
        if si[0] > 0 and fn[0] > 0 and si[0] < fn[0]:
            items.append({"field": "created", "standard_information": filetime_iso(si[0]), "file_name": filetime_iso(fn[0]),
                          "meaning": "$STANDARD_INFORMATION creation is earlier than $FILE_NAME creation. This pattern is "
                                     "consistent with timestamp manipulation, but archive extraction, copy tools and "
                                     "some installers produce it legitimately."})
        whole = [value for value in si if value > 0 and value % 10_000_000 == 0]
        fractional_fn = any(value > 0 and value % 10_000_000 for value in fn)
        if len(whole) == sum(1 for value in si if value > 0) and whole and fractional_fn:
            items.append({"field": "precision", "standard_information": [filetime_iso(value) for value in si],
                          "file_name": [filetime_iso(value) for value in fn],
                          "meaning": "Every $STANDARD_INFORMATION time has zero sub-second precision while $FILE_NAME "
                                     "times do not. Some timestomping tools leave this pattern; it is not proof."})
        return items


class UsnIndex:
    """Counters for every USN record and a compact index of FILE_CREATE records only."""

    def __init__(self) -> None:
        self.ts = array("q")
        self.file_ref = array("Q")
        self.parent_ref = array("Q")
        self.usn = array("q")
        self.reason = array("I")
        self.offset = array("Q")
        self.version = bytearray()
        self.source_info = array("I")
        self.attributes = array("I")
        self.name_off = array("I")
        self.name_len = array("H")
        self.name_data = bytearray()
        self.reasons = Counter()
        self.stats = Counter()
        self.first_time = self.last_time = 0
        self.first_usn = self.last_usn = None
        self.truncated = False

    def name(self, entry: int) -> str:
        offset = self.name_off[entry]
        return bytes(self.name_data[offset:offset + 2 * self.name_len[entry]]).decode("utf-16-le", "replace")

    def parse_record(self, buffer, position: int, length: int, file_offset: int) -> None:
        _, major, _minor = _USN_HEAD.unpack_from(buffer, position)
        if major == 2 and length >= 64:
            (file_ref, parent_ref, usn, stamp, reason, source, _sec, attributes,
             name_length, name_offset) = _USN_V2.unpack_from(buffer, position + 8)
        elif major == 3 and length >= 80:
            (file_lo, file_hi, parent_lo, parent_hi, usn, stamp, reason, source, _sec, attributes,
             name_length, name_offset) = _USN_V3.unpack_from(buffer, position + 8)
            if file_hi or parent_hi:
                # 128-bit identifiers that are not NTFS references (for example ReFS).
                self.stats["v3_non_ntfs_reference"] += 1
            file_ref, parent_ref = file_lo, parent_lo
        elif major == 4:
            self.stats["v4_range_records"] += 1
            return
        else:
            self.stats["invalid_records"] += 1
            return
        if name_length % 2 or name_offset < (60 if major == 2 else 76) or name_offset + name_length > length:
            self.stats["invalid_records"] += 1
            return
        self.stats["records"] += 1
        self.stats[f"v{major}_records"] += 1
        for bit in REASONS:
            if reason & bit:
                self.reasons[REASONS[bit]] += 1
        if 0 < stamp <= _MAX_FILETIME:
            self.first_time = stamp if not self.first_time else min(self.first_time, stamp)
            self.last_time = max(self.last_time, stamp)
        else:
            self.stats["invalid_timestamp"] += 1
        self.first_usn = usn if self.first_usn is None else min(self.first_usn, usn)
        self.last_usn = usn if self.last_usn is None else max(self.last_usn, usn)
        if not reason & FILE_CREATE:
            return
        if len(self.ts) >= MAX_USN_CREATES:
            self.stats["file_create_not_indexed"] += 1
            self.truncated = True
            return
        self.ts.append(stamp)
        self.file_ref.append(file_ref)
        self.parent_ref.append(parent_ref)
        self.usn.append(usn)
        self.reason.append(reason)
        self.offset.append(file_offset)
        self.version.append(major)
        self.source_info.append(source)
        self.attributes.append(attributes)
        self.name_off.append(len(self.name_data))
        self.name_len.append(name_length // 2)
        self.name_data += buffer[position + name_offset:position + name_offset + name_length]


def parse_mft(path: str | Path, *, expected_sha256: str | None = None, max_records: int = MAX_MFT_RECORDS) -> MftIndex:
    """Stream an $MFT file into a compact index; the SHA-256 of the bytes read must match."""
    index = MftIndex()
    digest = hashlib.sha256()
    pending = b""
    number = 0
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
            if index.truncated:
                continue  # Keep hashing so the digest still covers every byte.
            data = pending + chunk if pending else chunk
            if not index.record_size:
                if len(data) < 32:
                    pending = data
                    continue
                if data[:4] != b"FILE":
                    raise ValueError("Not an NTFS $MFT: record 0 lacks a FILE signature")
                index.record_size = _U32.unpack_from(data, 28)[0]
                if index.record_size not in (1024, 4096):
                    raise ValueError("Unsupported $MFT record size")
            size = index.record_size
            usable = len(data) - len(data) % size
            view = memoryview(data)
            for start in range(0, usable, size):
                if number >= max_records:
                    index.truncated = True
                    break
                index.parse_record(view[start:start + size], number)
                number += 1
            view.release()
            pending = data[usable:]
    if not index.record_size:
        raise ValueError("Not an NTFS $MFT: file is shorter than one record header")
    if pending and not index.truncated:
        index.stats["trailing_partial_record_bytes"] = len(pending)
    _verify_digest(digest, expected_sha256)
    index.finish()
    return index


def _verify_digest(digest, expected: str | None) -> None:
    if expected is not None and digest.hexdigest() != expected.lower():
        raise ValueError("NTFS artifact changed after verification (SHA-256 mismatch)")


def parse_usn_journal(path: str | Path, *, expected_sha256: str | None = None, max_records: int = MAX_USN_RECORDS) -> UsnIndex:
    """Stream $UsnJrnl:$J records, skipping sparse zero regions, into a bounded index."""
    index = UsnIndex()
    digest = hashlib.sha256()
    buffer = b""
    base = 0  # file offset of buffer[0], always 8-byte aligned
    in_garbage = False
    stop = False
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            digest.update(chunk)
            eof = not chunk
            buffer = buffer + chunk if buffer else chunk
            position = 0
            while not stop and position + 8 <= len(buffer):
                length = _U32.unpack_from(buffer, position)[0]
                if length == 0:
                    # Sparse or zero-padded region: jump to the next aligned non-zero byte.
                    found = _NONZERO.search(buffer, position)
                    skip_to = (len(buffer) - len(buffer) % 8 if found is None
                               else max(found.start() & ~7, position + 8))
                    index.stats["sparse_bytes_skipped"] += skip_to - position
                    position = skip_to
                    in_garbage = False
                    continue
                if length < 56 or length % 8 or length > MAX_USN_RECORD:  # 56: smallest (V4) header
                    if not in_garbage:
                        index.stats["invalid_regions"] += 1
                    in_garbage = True
                    index.stats["invalid_bytes_skipped"] += 8
                    position += 8
                    continue
                if position + length > len(buffer):
                    if eof:
                        index.stats["truncated_final_record"] += 1
                        position = len(buffer)
                    break
                if index.stats["records"] >= max_records:
                    index.truncated = True
                    stop = True
                    break
                before = index.stats["invalid_records"]
                index.parse_record(buffer, position, length, base + position)
                if index.stats["invalid_records"] != before:
                    if not in_garbage:
                        index.stats["invalid_regions"] += 1
                    in_garbage = True
                    index.stats["invalid_bytes_skipped"] += 8
                    position += 8
                    continue
                in_garbage = False
                position += length
            if eof:
                index.stats["trailing_bytes"] += len(buffer) - position
                break
            consumed = position - position % 8
            buffer = buffer[consumed:]
            base += consumed
            if stop:
                for chunk in iter(lambda: handle.read(CHUNK), b""):
                    digest.update(chunk)
                break
    _verify_digest(digest, expected_sha256)
    return index


class NtfsEvidence:
    """One NTFS volume: an optional $MFT index and an optional USN journal index."""

    def __init__(self, *, host: str, observed_at: str, collector: dict, volume: str = "",
                 mft: MftIndex | None = None, mft_source: tuple[str, str] | None = None,
                 usn: UsnIndex | None = None, usn_source: tuple[str, str] | None = None) -> None:
        self.host, self.observed_at, self.collector, self.volume = host, observed_at, collector, volume
        self.mft, self.usn = mft, usn
        # (source name, sha256); the name is rebound to the retained case path.
        self.mft_source, self.usn_source = mft_source, usn_source
        self.materialized: dict[str, dict] = {}

    def bind_retained_paths(self, paths_by_sha256: dict[str, str]) -> None:
        if self.mft_source:
            self.mft_source = (paths_by_sha256.get(self.mft_source[1], self.mft_source[0]), self.mft_source[1])
        if self.usn_source:
            self.usn_source = (paths_by_sha256.get(self.usn_source[1], self.usn_source[0]), self.usn_source[1])
        for observation in self.materialized.values():
            observation["source_file"] = paths_by_sha256.get(observation["source_sha256"], observation["source_file"])

    # -- observations -----------------------------------------------------------------------------

    def _base(self, source: tuple[str, str], identity: list, kind: str) -> dict:
        name, digest = source
        return {"id": _observation_id(digest, *identity, self.host), "kind": kind, "host": self.host,
                "observed_at": self.observed_at, "source_id": "evi_" + digest, "source_file": name,
                "source_sha256": digest, "collector": self.collector}

    def file_observations(self, entry: int) -> tuple[dict, dict]:
        """Return the $SI and $FILE_NAME observations for one name entry (kept separate)."""
        mft = self.mft
        number = mft.name_record[entry]
        path, status = mft.entry_path(entry, {})
        si_values = mft.si[4 * number:4 * number + 4] if mft.flags[number] & _HAS_SI else array("q", (0, 0, 0, 0))
        fn_values = mft.fn[4 * entry:4 * entry + 4]
        contradictions = mft.contradictions(number, entry)
        parent, parent_seq = _split_ref(mft.name_parent[entry])
        common = {
            "record_number": number, "sequence": mft.seq[number], "file_reference": number | (mft.seq[number] << 48),
            "in_use": bool(mft.flags[number] & _IN_USE), "directory": bool(mft.flags[number] & _DIRECTORY),
            "name": mft.name(entry), "name_namespace": mft.name_space[entry],
            "parent_record_number": parent, "parent_sequence": parent_seq,
            "path": path, "path_resolution": status, "volume": self.volume,
            "data_size": mft.size[number] if mft.size[number] >= 0 else None,
            "contradictions": contradictions,
        }
        observations = []
        for semantics, values, label in (("mft_standard_information", si_values, "si"),
                                         ("mft_file_name", fn_values, f"fn:{entry}")):
            observation = self._base(self.mft_source, ["ntfs_file", number, mft.seq[number], label], "ntfs_file")
            times = {field: {"value": filetime_iso(value), "filetime": value} for field, value in zip(TIME_FIELDS, values)}
            observation.update({
                "timestamp": times["created"]["value"], "timestamp_field": "created",
                "time_semantics": semantics,
                "interpretation": (
                    "Current $MFT state at collection. $STANDARD_INFORMATION times can be set from user mode and may "
                    "have been altered (timestomping)." if label == "si" else
                    "Current $MFT state at collection. $FILE_NAME times describe this name and are harder, but not "
                    "impossible, to alter; they corroborate rather than prove."),
                "source_record": number,
                "native_locator": {"mft_record": number, "byte_offset": number * mft.record_size,
                                   "attribute": "$STANDARD_INFORMATION" if label == "si" else "$FILE_NAME"},
                "details": {**common, "attribute": "$STANDARD_INFORMATION" if label == "si" else "$FILE_NAME",
                            "times": times},
            })
            observations.append(observation)
        si_obs, fn_obs = observations
        si_obs["details"]["companion_observation_id"] = fn_obs["id"]
        fn_obs["details"]["companion_observation_id"] = si_obs["id"]
        for observation in observations:
            self.materialized.setdefault(observation["id"], observation)
        return self.materialized[si_obs["id"]], self.materialized[fn_obs["id"]]

    def usn_observation(self, entry: int) -> dict:
        usn = self.usn
        file_number, file_seq = _split_ref(usn.file_ref[entry])
        parent_number, parent_seq = _split_ref(usn.parent_ref[entry])
        path, status = self.usn_path(entry)
        observation = self._base(self.usn_source, ["usn_change", usn.offset[entry]], "usn_change")
        observation.update({
            "timestamp": filetime_iso(usn.ts[entry]), "time_semantics": "usn_journal_record",
            "interpretation": ("The USN journal recorded this change at this time. The journal rolls over, so a missing "
                               "record is not proof that no change occurred. The path is resolved against the current "
                               "$MFT and may differ from the path at change time."),
            "source_record": usn.offset[entry],
            "native_locator": {"usn": usn.usn[entry], "byte_offset": usn.offset[entry], "major_version": usn.version[entry]},
            "details": {"usn": usn.usn[entry], "reasons": reason_names(usn.reason[entry]), "reason_mask": usn.reason[entry],
                        "file_record_number": file_number, "file_sequence": file_seq,
                        "parent_record_number": parent_number, "parent_sequence": parent_seq,
                        "name": usn.name(entry), "path": path, "path_resolution": status,
                        "source_info": usn.source_info[entry], "file_attributes": usn.attributes[entry],
                        "filetime": usn.ts[entry], "volume": self.volume},
        })
        return self.materialized.setdefault(observation["id"], observation)

    def usn_time(self, entry: int) -> datetime | None:
        value = filetime_iso(self.usn.ts[entry])
        return datetime.fromisoformat(value) if value else None

    def usn_path(self, entry: int) -> tuple[str, str]:
        name = self.usn.name(entry)
        if self.mft is None:
            return f"<no_mft>\\{name}", "unresolved_without_mft"
        parent, parent_seq = _split_ref(self.usn.parent_ref[entry])
        mft = self.mft
        if parent >= mft.records or not mft.flags[parent] & _VALID:
            return f"<orphan_parent_missing>\\{name}", "orphan_parent_missing"
        if parent_seq and mft.seq[parent] != parent_seq:
            # The directory record was reused after this change.
            return f"<orphan_parent_sequence_mismatch>\\{name}", "orphan_parent_sequence_mismatch"
        directory = mft.directory_path(parent, {})
        if directory is None:
            return f"<{PATH_STATUS.get(mft.status[parent], 'orphan_parent_missing')}>\\{name}", "orphan_parent_unresolved"
        return f"{directory}\\{name}", "resolved_against_current_mft"

    def usn_creates_for(self, entries: Iterable[int]) -> dict[int, list[tuple[int, bool]]]:
        """Map MFT name entries to FILE_CREATE journal entries: (usn entry, same file reference).

        A create matches by file record number or by parent directory reference
        plus name. One pass over the create index.
        """
        if self.usn is None or self.mft is None:
            return {}
        mft, usn = self.mft, self.usn
        by_record: dict[int, list[int]] = {}
        by_parent_name: dict[tuple[int, str], list[int]] = {}
        for entry in entries:
            number = mft.name_record[entry]
            by_record.setdefault(number, []).append(entry)
            by_parent_name.setdefault((mft.name_parent[entry], mft.name(entry).casefold()), []).append(entry)
        parents = {key[0] for key in by_parent_name}
        result: dict[int, list[tuple[int, bool]]] = {}
        for create in range(len(usn.ts)):
            number = usn.file_ref[create] & REF_MASK
            targets: dict[int, bool] = {}
            for entry in by_record.get(number, ()):
                # A different sequence number means another file in a reused record.
                if usn.file_ref[create] == number | (mft.seq[number] << 48):
                    targets[entry] = True
            if usn.parent_ref[create] in parents:
                for entry in by_parent_name.get((usn.parent_ref[create], usn.name(create).casefold()), ()):
                    targets.setdefault(entry, False)
            for entry, same in targets.items():
                result.setdefault(entry, []).append((create, same))
        return result

    # -- coverage ---------------------------------------------------------------------------------

    def coverage(self) -> dict:
        families = {}
        if self.mft is None:
            families["ntfs_mft"] = {"status": "not_supplied"}
        else:
            stats = dict(self.mft.stats)
            families["ntfs_mft"] = {
                "status": "observed" if stats.get("valid_records") else "supplied_no_records",
                "records_read": self.mft.records, "record_size": self.mft.record_size,
                "truncated_at_record_limit": self.mft.truncated, "volume": self.volume or None,
                "volume_mapping": "supplied" if self.volume else "assumed_from_event_path", **stats,
            }
        if self.usn is None:
            families["usn_journal"] = {"status": "not_supplied"}
        else:
            stats = dict(self.usn.stats)
            families["usn_journal"] = {
                "status": "observed" if stats.get("records") else "supplied_no_records",
                "earliest_record_time": filetime_iso(self.usn.first_time),
                "latest_record_time": filetime_iso(self.usn.last_time),
                "first_usn": self.usn.first_usn, "last_usn": self.usn.last_usn,
                "file_create_indexed": len(self.usn.ts), "truncated_at_record_limit": self.usn.truncated,
                "reason_counts": dict(sorted(self.usn.reasons.items())), **stats,
            }
        return families

    def warnings(self) -> list[str]:
        items = []
        if self.mft is not None:
            stats = self.mft.stats
            if self.mft.truncated:
                items.append(f"$MFT parsing stopped at the {MAX_MFT_RECORDS}-record limit; later records were not indexed.")
            damaged = stats["bad_fixup"] + stats["invalid_header"] + stats["invalid_signature"] + stats["baad_records"]
            if damaged:
                items.append(f"{damaged} $MFT record(s) failed signature, header or fixup validation and were skipped.")
            if stats["attribute_overrun"]:
                items.append(f"{stats['attribute_overrun']} $MFT record(s) had malformed attributes; parsing of those records stopped early.")
        if self.usn is not None:
            stats = self.usn.stats
            if self.usn.truncated:
                items.append("USN journal indexing reached its record limit; later records were not indexed.")
            if stats["invalid_regions"]:
                items.append(f"{stats['invalid_regions']} malformed USN journal region(s) were skipped.")
        return items

    def contradiction_observations(self, limit: int | None = None) -> tuple[list[dict], int, int]:
        """Materialize in-use records whose $SI times all lack sub-second precision, bounded.

        Returns (observations, total listed-pattern records, records whose only
        disagreement is an earlier $SI creation). On a real Windows 11 volume about
        4% of files show that earlier creation (installers, servicing, archive
        extraction), so it stays in each file's details and is counted, not listed.
        """
        limit = MAX_CONTRADICTION_OBSERVATIONS if limit is None else limit
        if self.mft is None:
            return [], 0, 0
        mft = self.mft
        observations: list[dict] = []
        total = created_only = 0
        for number in range(mft.records):
            entry = mft.first_name[number]
            if entry < 0 or not mft.flags[number] & _IN_USE or not mft.flags[number] & _HAS_SI:
                continue
            si_created = mft.si[4 * number]
            fn_created = mft.fn[4 * entry]
            # Cheap pre-check for the two reported patterns before building dicts.
            if not (0 < si_created < fn_created) and not (si_created > 0 and si_created % 10_000_000 == 0):
                continue
            fields = {item["field"] for item in mft.contradictions(number, entry)}
            if "precision" not in fields:
                created_only += "created" in fields
                continue
            total += 1
            if len(observations) < 2 * limit:
                observations.extend(self.file_observations(entry))
        return observations, total, created_only


def read_ntfs_members(*, host: str, observed_at: str, collector: dict, volume: str = "",
                      mft: tuple[Path, str, str] | None = None, usn: tuple[Path, str, str] | None = None,
                      ) -> tuple[NtfsEvidence, list[dict], list[str]]:
    """Parse verified bundle members (path, source name, sha256); return evidence, observations, warnings."""
    mft_index = parse_mft(mft[0], expected_sha256=mft[2]) if mft else None
    usn_index = parse_usn_journal(usn[0], expected_sha256=usn[2]) if usn else None
    evidence = NtfsEvidence(host=host, observed_at=observed_at, collector=collector, volume=volume,
                            mft=mft_index, mft_source=(mft[1], mft[2]) if mft else None,
                            usn=usn_index, usn_source=(usn[1], usn[2]) if usn else None)
    observations, total, created_only = evidence.contradiction_observations()
    warnings = evidence.warnings()
    if total > MAX_CONTRADICTION_OBSERVATIONS:
        warnings.append(f"{total} $MFT records have whole-second $SI times unlike their $FILE_NAME times; only the first "
                        f"{MAX_CONTRADICTION_OBSERVATIONS} are listed as observations.")
    if created_only:
        warnings.append(f"{created_only} $MFT records have an $SI creation time earlier than their $FILE_NAME creation, "
                        "which installers and Windows servicing produce routinely. They are not listed; each file's "
                        "details keep the comparison.")
    if usn_index is not None and mft_index is None:
        warnings.append("USN journal supplied without its $MFT; journal paths cannot be resolved or linked.")
    return evidence, observations, warnings
