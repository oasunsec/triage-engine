"""Native, read-only parser for offline Windows registry hive files (regf).

The parser reads the hive bytes it is given and nothing else: it never loads a
hive through Windows APIs, never writes to the input, and never replays
transaction logs (.LOG1/.LOG2). A dirty hive is reported as a warning because
recent changes recorded only in its logs are missing from this view.

Every cell reference is bounds-checked against the hive bin that contains it,
subkey and value lists are capped, and visited cell offsets are tracked so a
crafted hive cannot loop. Structural damage on the path to a requested key
fails the parse; damage inside one enumerated service, value or Amcache entry
skips that item with a warning.

Key timestamps are the key's last-write time. That is a key-level time, shared
by every value in the key; it is not the creation time of a value and not an
execution time.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import ntpath
import os
import re
import struct
from datetime import datetime, timedelta, timezone

HIVE_TYPES = {"ntuser", "software", "system", "amcache"}
DEFAULT_MAX_HIVE_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 64
MAX_SUBKEYS = 200_000
MAX_VALUES = 65_536
MAX_VALUE_DATA = 1024 * 1024
MAX_TEXT = 32_768
MAX_CELL_VISITS = 5_000_000
MAX_WARNINGS = 200
_BASE = 4096
_HBIN_HEADER = 32
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_KEY_COMP_NAME = 0x0020
_VALUE_COMP_NAME = 0x0001
REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BE, REG_LINK, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 5, 6, 7, 11
_TYPE_NAMES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
               6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 11: "REG_QWORD"}
_START_NAMES = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
_RUN_KEYS = ("Microsoft\\Windows\\CurrentVersion\\Run", "Microsoft\\Windows\\CurrentVersion\\RunOnce",
             "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
_INTERPRETATIONS = {
    "registry_run": ("Run/RunOnce value present in the offline hive; execution unconfirmed. The timestamp is the "
                     "key's last-write time, shared by every value in the key, not this value's creation time."),
    "service": ("Service configuration present in the offline SYSTEM hive for the current control set; execution "
                "unconfirmed. The timestamp is the service key's last-write time, not its install time."),
    "amcache_file": ("Amcache InventoryApplicationFile entry: the file was inventoried on this system at some point. "
                     "Presence is not proof of execution. The timestamp is the entry key's last-write time; LinkDate is "
                     "the PE header link time set by the compiler, unverified and not an install or run time."),
}


class HiveError(ValueError):
    """Structural damage or a limit breach in a hive."""


def max_hive_bytes() -> int:
    value = os.environ.get("TRIAGE_MAX_HIVE_BYTES", "")
    if not value:
        return DEFAULT_MAX_HIVE_BYTES
    try:
        limit = int(value)
    except ValueError as exc:
        raise ValueError("TRIAGE_MAX_HIVE_BYTES must be an integer") from exc
    if limit < _BASE:
        raise ValueError("TRIAGE_MAX_HIVE_BYTES is too small for a hive")
    return limit


def _filetime(value: int) -> str | None:
    if value <= 0 or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return (_FILETIME_EPOCH + timedelta(microseconds=value // 10)).isoformat()
    except OverflowError:
        return None


class Hive:
    """Bounds-checked view over regf bytes. Offsets are relative to the first hive bin."""

    def __init__(self, data: bytes, *, max_bytes: int | None = None):
        limit = max_hive_bytes() if max_bytes is None else max_bytes
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise HiveError("Hive content must be bytes")
        self.data = memoryview(bytes(data)).toreadonly()
        if len(self.data) > limit:
            raise HiveError(f"Hive exceeds the {limit} byte limit")
        if len(self.data) < _BASE + _HBIN_HEADER:
            raise HiveError("Hive is truncated: shorter than a base block and one hive bin")
        if bytes(self.data[0:4]) != b"regf":
            raise HiveError("Not a registry hive (missing regf signature)")
        primary, secondary, last_written, major, minor, file_type, file_format, root, bins_size = \
            struct.unpack_from("<IIQIIIIII", self.data, 4)
        if major != 1 or not 2 <= minor <= 6:
            raise HiveError(f"Unsupported hive format version {major}.{minor}")
        if file_type != 0 or file_format != 1:
            raise HiveError("Not a primary hive file (transaction log or unsupported format)")
        self.minor = minor
        self.dirty = primary != secondary
        self.last_written = _filetime(last_written)
        self.embedded_name = bytes(self.data[48:112]).decode("utf-16-le", "replace").split("\x00", 1)[0]
        checksum = 0
        for (word,) in struct.iter_unpack("<I", self.data[0:508]):
            checksum ^= word
        checksum = 0xFFFFFFFE if checksum == 0xFFFFFFFF else (1 if checksum == 0 else checksum)
        self.checksum_valid = checksum == struct.unpack_from("<I", self.data, 508)[0]
        if bins_size < 4096 or bins_size % 4096:
            raise HiveError("Hive bins data size is invalid")
        if _BASE + bins_size > len(self.data):
            raise HiveError("Hive is truncated: bins data extends past the end of the file")
        self.bins_size = bins_size
        self._bin_starts: list[int] = []
        self._bin_ends: list[int] = []
        offset = 0
        while offset < bins_size:
            absolute = _BASE + offset
            if bytes(self.data[absolute:absolute + 4]) != b"hbin":
                raise HiveError(f"Missing hbin signature at bin offset {offset:#x}")
            declared, size = struct.unpack_from("<II", self.data, absolute + 4)
            if declared != offset or size < 4096 or size % 4096 or offset + size > bins_size:
                raise HiveError(f"Invalid hbin header at bin offset {offset:#x}")
            self._bin_starts.append(offset)
            self._bin_ends.append(offset + size)
            offset += size
        self.root = root
        self.visits = 0

    def cell(self, offset: int) -> memoryview:
        """Return an allocated cell's data (without its size field)."""
        self.visits += 1
        if self.visits > MAX_CELL_VISITS:
            raise HiveError("Hive cell visit budget exceeded")
        if offset == 0xFFFFFFFF or offset % 8 or offset >= self.bins_size:
            raise HiveError(f"Cell offset {offset:#x} is outside the hive")
        index = bisect.bisect_right(self._bin_starts, offset) - 1
        if index < 0 or offset < self._bin_starts[index] + _HBIN_HEADER:
            raise HiveError(f"Cell offset {offset:#x} is not inside a hive bin")
        end = self._bin_ends[index]
        if offset + 4 > end:
            raise HiveError(f"Cell at {offset:#x} is truncated")
        (raw,) = struct.unpack_from("<i", self.data, _BASE + offset)
        if raw >= 0:
            raise HiveError(f"Cell at {offset:#x} is unallocated")
        size = -raw
        if size < 8 or offset + size > end:
            raise HiveError(f"Cell at {offset:#x} has an invalid size")
        return self.data[_BASE + offset + 4:_BASE + offset + size]

    def key(self, offset: int) -> dict:
        cell = self.cell(offset)
        if len(cell) < 76 or bytes(cell[0:2]) != b"nk":
            raise HiveError(f"Cell at {offset:#x} is not a key (nk) record")
        flags, = struct.unpack_from("<H", cell, 2)
        last_write, = struct.unpack_from("<Q", cell, 4)
        subkey_count, = struct.unpack_from("<I", cell, 20)
        subkey_list, = struct.unpack_from("<I", cell, 28)
        value_count, value_list = struct.unpack_from("<II", cell, 36)
        name_length, = struct.unpack_from("<H", cell, 72)
        if 76 + name_length > len(cell):
            raise HiveError(f"Key name at {offset:#x} extends past its cell")
        raw_name = bytes(cell[76:76 + name_length])
        name = raw_name.decode("latin-1") if flags & _KEY_COMP_NAME else raw_name.decode("utf-16-le", "replace")
        if subkey_count > MAX_SUBKEYS:
            raise HiveError(f"Key {name!r} declares more than {MAX_SUBKEYS} subkeys")
        if value_count > MAX_VALUES:
            raise HiveError(f"Key {name!r} declares more than {MAX_VALUES} values")
        return {"offset": offset, "name": name, "last_write": _filetime(last_write),
                "subkey_count": subkey_count, "subkey_list": subkey_list,
                "value_count": value_count, "value_list": value_list}

    def subkeys(self, key: dict) -> list[int]:
        """Return nk offsets of a key's stable subkeys, following li/lf/lh/ri lists."""
        if key["subkey_count"] == 0:
            return []
        found: list[int] = []
        seen_lists: set[int] = set()

        def walk(list_offset: int, depth: int) -> None:
            if list_offset in seen_lists:
                raise HiveError(f"Subkey list cycle at {list_offset:#x}")
            if depth > 2:
                raise HiveError("Subkey index (ri) nesting is too deep")
            seen_lists.add(list_offset)
            cell = self.cell(list_offset)
            if len(cell) < 4:
                raise HiveError(f"Subkey list at {list_offset:#x} is truncated")
            signature, count = bytes(cell[0:2]), struct.unpack_from("<H", cell, 2)[0]
            stride = {b"li": 4, b"ri": 4, b"lf": 8, b"lh": 8}.get(signature)
            if stride is None:
                raise HiveError(f"Unknown subkey list signature at {list_offset:#x}")
            if 4 + count * stride > len(cell):
                raise HiveError(f"Subkey list at {list_offset:#x} extends past its cell")
            for index in range(count):
                (child,) = struct.unpack_from("<I", cell, 4 + index * stride)
                if signature == b"ri":
                    walk(child, depth + 1)
                else:
                    found.append(child)
                if len(found) > MAX_SUBKEYS:
                    raise HiveError(f"Key {key['name']!r} has more than {MAX_SUBKEYS} subkeys")

        walk(key["subkey_list"], 0)
        if len(found) != key["subkey_count"]:
            raise HiveError(f"Key {key['name']!r} subkey count does not match its list")
        if len(set(found)) != len(found) or key["offset"] in found:
            raise HiveError(f"Key {key['name']!r} has a repeated or self-referencing subkey")
        return found

    def child(self, key: dict, name: str) -> dict | None:
        wanted = name.casefold()
        damaged = None
        for offset in self.subkeys(key):
            try:
                candidate = self.key(offset)
            except HiveError as exc:
                damaged = exc
                continue
            if candidate["name"].casefold() == wanted:
                return candidate
        if damaged is not None:
            # The damaged subkey may be the one sought, so absence cannot be reported.
            raise HiveError(f"Cannot tell whether {key['name']!r} has subkey {name!r}: {damaged}")
        return None

    def open(self, path: str) -> dict | None:
        """Walk a backslash path from the root key; None when a component is absent."""
        current = self.key(self.root)
        on_path = {current["offset"]}
        parts = [part for part in path.split("\\") if part]
        if len(parts) > MAX_DEPTH:
            raise HiveError("Key path exceeds the maximum depth")
        for part in parts:
            current = self.child(current, part)
            if current is None:
                return None
            if current["offset"] in on_path:
                raise HiveError(f"Key cycle at {current['offset']:#x}")
            on_path.add(current["offset"])
        return current

    def values(self, key: dict) -> list[dict]:
        if key["value_count"] == 0:
            return []
        cell = self.cell(key["value_list"])
        if key["value_count"] * 4 > len(cell):
            raise HiveError(f"Value list of key {key['name']!r} extends past its cell")
        offsets = [struct.unpack_from("<I", cell, index * 4)[0] for index in range(key["value_count"])]
        if len(set(offsets)) != len(offsets):
            raise HiveError(f"Key {key['name']!r} repeats a value cell")
        return [self.value(offset) for offset in offsets]

    def value(self, offset: int) -> dict:
        cell = self.cell(offset)
        if len(cell) < 20 or bytes(cell[0:2]) != b"vk":
            raise HiveError(f"Cell at {offset:#x} is not a value (vk) record")
        name_length, size, data_offset, data_type, flags = struct.unpack_from("<HIIIH", cell, 2)
        if 20 + name_length > len(cell):
            raise HiveError(f"Value name at {offset:#x} extends past its cell")
        raw_name = bytes(cell[20:20 + name_length])
        name = raw_name.decode("latin-1") if flags & _VALUE_COMP_NAME else raw_name.decode("utf-16-le", "replace")
        if size & 0x80000000:
            length = size & 0x7FFFFFFF
            if length > 4:
                raise HiveError(f"Resident value data at {offset:#x} is longer than 4 bytes")
            data = struct.pack("<I", data_offset)[:length]
        else:
            if size > MAX_VALUE_DATA:
                raise HiveError(f"Value {name!r} data exceeds {MAX_VALUE_DATA} bytes")
            data = self._data(data_offset, size) if size else b""
        return {"name": name, "type": data_type, "data": data}

    def _data(self, offset: int, size: int) -> bytes:
        cell = self.cell(offset)
        if self.minor >= 4 and size > 16344 and len(cell) >= 8 and bytes(cell[0:2]) == b"db":
            count, segments = struct.unpack_from("<HI", cell, 2)
            index = self.cell(segments)
            if count * 4 > len(index):
                raise HiveError(f"Big-data segment list at {segments:#x} extends past its cell")
            parts, seen, remaining = [], set(), size
            for position in range(count):
                (segment,) = struct.unpack_from("<I", index, position * 4)
                if segment in seen:
                    raise HiveError(f"Big-data segment cycle at {segment:#x}")
                seen.add(segment)
                chunk = self.cell(segment)[:min(16344, remaining)]
                parts.append(bytes(chunk))
                remaining -= len(chunk)
                if remaining <= 0:
                    break
            if remaining > 0:
                raise HiveError(f"Big-data value at {offset:#x} is shorter than its declared size")
            return b"".join(parts)
        if size > len(cell):
            raise HiveError(f"Value data at {offset:#x} extends past its cell")
        return bytes(cell[:size])


def _string(value: dict) -> tuple[str, bool]:
    """Decode REG_SZ/REG_EXPAND_SZ like Windows (stop at NUL); report hidden data after it."""
    raw = value["data"]
    if len(raw) % 2:
        raw = raw[:-1]
    text = raw.decode("utf-16-le", "replace")
    head, _, tail = text.partition("\x00")
    return head[:MAX_TEXT], bool(tail.strip("\x00"))


def _scalar(value: dict | None):
    if value is None:
        return None
    if value["type"] in (REG_SZ, REG_EXPAND_SZ):
        return _string(value)[0]
    if value["type"] == REG_DWORD and len(value["data"]) == 4:
        return struct.unpack("<I", value["data"])[0]
    if value["type"] == REG_DWORD_BE and len(value["data"]) == 4:
        return struct.unpack(">I", value["data"])[0]
    if value["type"] == REG_QWORD and len(value["data"]) == 8:
        return struct.unpack("<Q", value["data"])[0]
    return None


def _by_name(values: list[dict]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for value in values:
        result.setdefault(value["name"].casefold(), value)
    return result


class _Builder:
    def __init__(self, hive: Hive, *, hive_type, source_name, source_sha256, host, observed_at, collector, original_name):
        self.hive, self.hive_type = hive, hive_type
        self.source_name, self.digest = source_name, source_sha256.lower()
        self.host, self.collector, self.original_name = host, collector, original_name
        self.observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
        self.observations: list[dict] = []
        self.warnings: list[str] = []

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(f"{self.source_name}: {message}")
        elif len(self.warnings) == MAX_WARNINGS:
            self.warnings.append(f"{self.source_name}: further hive warnings suppressed")

    def add(self, kind: str, key_path: str, value_name: str | None, key: dict, details: dict) -> None:
        locator = {"hive_type": self.hive_type, "key_path": key_path, "value_name": value_name}
        identity = json.dumps([self.digest, "registry_hive", key_path, value_name], separators=(",", ":"))
        self.observations.append({
            "id": "obs_" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "kind": kind, "host": self.host, "observed_at": self.observed,
            "timestamp": key["last_write"], "time_semantics": "registry_key_last_write",
            "interpretation": _INTERPRETATIONS[kind],
            "source_id": "evi_" + self.digest, "source_file": self.source_name,
            "source_record": len(self.observations), "source_sha256": self.digest,
            "collector": self.collector, "native_locator": locator,
            "details": {**details, "hive_type": self.hive_type, "key_path": key_path,
                        "key_last_write": key["last_write"], "source_format": "registry_hive",
                        "original_name": self.original_name},
        })


def _run_values(builder: _Builder, prefix: str, display_root: str) -> None:
    hive = builder.hive
    for relative in _RUN_KEYS:
        key_path = f"{prefix}{relative}"
        key = hive.open(key_path)
        if key is None:
            continue
        location = f"{display_root}\\{relative}"
        try:
            values = hive.values(key)
        except HiveError as exc:
            builder.warn(f"Skipped values of {key_path}: {exc}")
            continue
        for value in values:
            command, hidden = _string(value) if value["type"] in (REG_SZ, REG_EXPAND_SZ) else ("", False)
            builder.add("registry_run", key_path, value["name"], key, {
                "name": value["name"] or "(Default)", "location": location, "command": command,
                "value_type": _TYPE_NAMES.get(value["type"], str(value["type"])),
                "data_after_nul": hidden, "run_once": relative.endswith("RunOnce"),
                # NTUSER.DAT does not name its owning account; HKCU is a placeholder, not an identity.
                **({"hive_owner": "unidentified"} if builder.hive_type == "ntuser" else {}),
            })


def _services(builder: _Builder) -> None:
    hive = builder.hive
    select = hive.open("Select")
    if select is None:
        raise HiveError("Declared SYSTEM hive has no Select key")
    select_values = _by_name(hive.values(select))
    current = _scalar(select_values.get("current"))
    if not isinstance(current, int) or not 1 <= current <= 999:
        raise HiveError("SYSTEM hive Select\\Current is missing or invalid")
    control_set = f"ControlSet{current:03d}"
    services_path = f"{control_set}\\Services"
    services = hive.open(services_path)
    if services is None:
        raise HiveError(f"SYSTEM hive has no {services_path} key for Select\\Current")
    selection = {name: _scalar(select_values.get(name.casefold())) for name in ("Current", "Default", "LastKnownGood", "Failed")}
    for offset in hive.subkeys(services):
        try:
            key = hive.key(offset)
        except HiveError as exc:
            builder.warn(f"Skipped unreadable service key: {exc}")
            continue
        name = key["name"]
        key_path = f"{services_path}\\{name}"
        try:
            values = _by_name(hive.values(key))
            image = values.get("imagepath")
            command, hidden = _string(image) if image and image["type"] in (REG_SZ, REG_EXPAND_SZ) else ("", False)
            start, service_type = _scalar(values.get("start")), _scalar(values.get("type"))
            object_name = _scalar(values.get("objectname"))
            details = {
                "name": name, "location": f"HKLM\\SYSTEM\\{services_path}", "command": command,
                "display_name": str(_scalar(values.get("displayname")) or "")[:1024],
                "user": object_name if isinstance(object_name, str) else "",
                "start": start if isinstance(start, int) else None,
                "start_type": _START_NAMES.get(start, "unknown") if isinstance(start, int) else "absent",
                "service_type": service_type if isinstance(service_type, int) else None,
                "data_after_nul": hidden, "control_set": control_set, "select": selection,
            }
            if isinstance(start, int):
                details["enabled"] = start != 4
            parameters = hive.child(key, "Parameters")
            if parameters is not None:
                dll = _scalar(_by_name(hive.values(parameters)).get("servicedll"))
                if isinstance(dll, str) and dll:
                    details["service_dll"] = dll
        except HiveError as exc:
            builder.warn(f"Skipped service {name!r}: {exc}")
            continue
        builder.add("service", key_path, None, key, details)


def _amcache(builder: _Builder) -> None:
    hive = builder.hive
    inventory = hive.open("Root\\InventoryApplicationFile")
    if inventory is None:
        if hive.open("Root\\File") is not None:
            builder.warn("Amcache uses the older Root\\File layout, which this parser does not read in v1")
        else:
            builder.warn("Amcache hive has no Root\\InventoryApplicationFile key")
        return
    hash_only = 0
    for offset in hive.subkeys(inventory):
        try:
            key = hive.key(offset)
            values = _by_name(hive.values(key))
        except HiveError as exc:
            builder.warn(f"Skipped Amcache entry at {offset:#x}: {exc}")
            continue
        key_path = f"Root\\InventoryApplicationFile\\{key['name']}"
        path = str(_scalar(values.get("lowercaselongpath")) or "")
        # Key names are "<first 16 chars of lowercase file name>|<hash>". Recent
        # Windows 11 builds write entries holding only FileId/ProgramId; the
        # prefix is then the only name evidence, and it is a hint, not a name.
        hint = re.fullmatch(r"(.+)\|[0-9a-f]{1,16}", key["name"])
        hint = hint.group(1)[:16] if hint else ""
        if not path and not _scalar(values.get("name")):
            hash_only += 1
        file_id = str(_scalar(values.get("fileid")) or "").strip().lower()
        sha1 = file_id[4:] if len(file_id) == 44 and file_id.startswith("0000") else file_id
        if not re.fullmatch(r"[0-9a-f]{40}", sha1):
            sha1 = ""
        builder.add("amcache_file", key_path, None, key, {
            "name": ntpath.basename(path) or str(_scalar(values.get("name")) or ""),
            "location": path, "path": path, "sha1": sha1, "file_id_raw": file_id[:128],
            # The SHA-1 covers at most the first 31,457,280 bytes of the file.
            "sha1_scope": "first_31457280_bytes" if sha1 else "absent",
            "link_date_raw": str(_scalar(values.get("linkdate")) or "")[:64],
            "publisher": str(_scalar(values.get("publisher")) or "")[:1024],
            "version": str(_scalar(values.get("version")) or "")[:256],
            "product_name": str(_scalar(values.get("productname")) or "")[:1024],
            "program_id": str(_scalar(values.get("programid")) or "")[:256],
            "key_name_hint": hint,
            "key_name_hint_may_be_truncated": len(hint) == 16,
        })
    if hash_only:
        builder.warn(f"{hash_only} Amcache entries record no file name or path (FileId/ProgramId only); "
                     "key_name_hint holds at most the first 16 characters of the lowercase file name")


def parse_registry_hive(content: bytes, *, hive_type: str, source_name: str, source_sha256: str, host: str,
                        observed_at: str, collector: dict, original_name: str = "",
                        max_bytes: int | None = None) -> tuple[list[dict], list[str]]:
    """Return (observations, warnings) for one offline hive of a declared type."""
    if hive_type not in HIVE_TYPES:
        raise ValueError(f"Unsupported hive type {hive_type!r}")
    hive = Hive(content, max_bytes=max_bytes)
    builder = _Builder(hive, hive_type=hive_type, source_name=source_name, source_sha256=source_sha256, host=host,
                       observed_at=observed_at, collector=collector, original_name=original_name)
    if hive.dirty:
        builder.warn("Hive is dirty (primary and secondary sequence numbers differ). Transaction logs are not "
                     "replayed in this version, so changes held only in .LOG1/.LOG2 are missing.")
    if not hive.checksum_valid:
        builder.warn("Hive base block checksum does not match")
    root = hive.key(hive.root)
    if hive_type == "software":
        _run_values(builder, "", "HKLM\\SOFTWARE")
    elif hive_type == "ntuser":
        if hive.child(root, "Software") is None:
            raise HiveError("Declared NTUSER hive has no Software key")
        _run_values(builder, "Software\\", "HKCU\\Software")
    elif hive_type == "system":
        _services(builder)
    else:
        if hive.child(root, "Root") is None:
            raise HiveError("Declared Amcache hive has no Root key")
        _amcache(builder)
    return builder.observations, builder.warnings
