"""Bounded native parser for Windows Prefetch (SCCA) files.

Supports format versions 17 (XP/2003), 23 (Vista/7), 26 (8.1) and 30/31
(10/11), uncompressed or wrapped in the Windows 10+ ``MAM`` container. The
container uses LZXPRESS Huffman compression; the decoder below is a clean-room
implementation of Microsoft's published [MS-XCA] "LZ77+Huffman" algorithm and
copies no third-party code.

Observations match ``prefetch_artifacts.parse_pecmd_jsonl`` in shape so the
cross-source Prefetch rule reads both. A Prefetch file records an execution
trace for an executable name; it does not establish the user, the full path of
the executed image, or intent.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import zlib
from datetime import datetime, timedelta, timezone


PARSER_NAME = "triage-prefetch-binary"
PARSER_VERSION = "1.0.0"
COLLECTOR = {"name": PARSER_NAME, "version": PARSER_VERSION}

MAX_INPUT = 16 * 1024 * 1024
MAX_DECOMPRESSED = 16 * 1024 * 1024
MAX_STRING_TABLE = 4 * 1024 * 1024
MAX_FILENAMES = 16384
MAX_NAME_CHARS = 32767
MAX_JOINED = 64 * 1024  # Same per-string bound as the PECmd JSONL adapter.
MAX_VOLUMES = 64
MAX_DIRECTORIES = 16384
SUPPORTED_VERSIONS = (17, 23, 26, 30, 31)
RUN_FIELDS = ("LastRun", *(f"PreviousRun{i}" for i in range(7)))
HEADER_SIZE = 84
# Volume information entry sizes by format version.
VOLUME_ENTRY = {17: 40, 23: 104, 26: 104, 30: 96, 31: 96}
INTERPRETATION = ("Prefetch records an execution trace; malicious intent, user and full executable path "
                  "are unconfirmed.")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


# --- [MS-XCA] LZ77+Huffman decompression -------------------------------------

_CHUNK = 65536          # [MS-XCA] 2.2.4: each Huffman table covers 64 KiB of output.
_TABLE_BYTES = 256      # 512 symbols x 4-bit code lengths.
_TABLE_BITS = 15        # Maximum code length; decoding table has 2^15 entries.


def _decoding_table(lengths: bytes) -> tuple[list[int], list[int]]:
    """Build the canonical decoding table ([MS-XCA] 2.2.4, "Building the decoding table")."""
    bit_lengths = [0] * 512
    for index, byte in enumerate(lengths):
        bit_lengths[2 * index] = byte & 0x0F
        bit_lengths[2 * index + 1] = byte >> 4
    table: list[int] = []
    for length in range(1, _TABLE_BITS + 1):
        span = 1 << (_TABLE_BITS - length)
        for symbol in range(512):
            if bit_lengths[symbol] == length:
                if len(table) + span > 1 << _TABLE_BITS:
                    raise ValueError("Invalid Prefetch compression table")
                table.extend([symbol] * span)
    if len(table) != 1 << _TABLE_BITS:
        raise ValueError("Invalid Prefetch compression table")
    return table, bit_lengths


def lzxpress_huffman_decompress(data: bytes, output_size: int) -> bytes:
    """Decompress an [MS-XCA] 2.2 LZ77+Huffman stream to exactly ``output_size`` bytes.

    Follows the decompression pseudo-code of [MS-XCA] section 2.2.4. Output is
    bounded by ``output_size``, which the caller bounds by ``MAX_DECOMPRESSED``.
    """
    if not 0 < output_size <= MAX_DECOMPRESSED:
        raise ValueError("Prefetch decompressed size out of bounds")
    size = len(data)
    out = bytearray()
    position = 0

    def word(at: int) -> int:
        # Bit words past the end read as zero: the reader prefetches 32 bits.
        if at + 2 <= size:
            return data[at] | (data[at + 1] << 8)
        if at >= size:
            return 0
        return data[at]

    while len(out) < output_size:
        if position + _TABLE_BYTES + 4 > size:
            raise ValueError("Truncated Prefetch compressed stream")
        table, bit_lengths = _decoding_table(data[position:position + _TABLE_BYTES])
        position += _TABLE_BYTES
        bits = (word(position) << 16) | word(position + 2)
        position += 4
        extra = 16
        block_end = len(out) + _CHUNK
        while len(out) < block_end and len(out) < output_size:
            symbol = table[bits >> (32 - _TABLE_BITS)]
            length = bit_lengths[symbol]
            bits = (bits << length) & 0xFFFFFFFF
            extra -= length
            if extra < 0:
                bits |= word(position) << -extra
                extra += 16
                position += 2
                if position > size + 4:
                    raise ValueError("Truncated Prefetch compressed stream")
            if symbol < 256:
                out.append(symbol)
                continue
            symbol -= 256
            match_length = symbol & 0x0F
            offset_bits = symbol >> 4
            if match_length == 15:
                if position >= size:
                    raise ValueError("Truncated Prefetch compressed stream")
                match_length = data[position]
                position += 1
                if match_length == 255:
                    if position + 2 > size:
                        raise ValueError("Truncated Prefetch compressed stream")
                    match_length = data[position] | (data[position + 1] << 8)
                    position += 2
                    if match_length == 0:
                        # Later [MS-XCA] revisions: a zero 16-bit length is followed by a 32-bit length.
                        if position + 4 > size:
                            raise ValueError("Truncated Prefetch compressed stream")
                        match_length = struct.unpack_from("<I", data, position)[0]
                        position += 4
                    if match_length < 15:
                        raise ValueError("Invalid Prefetch match length")
                    match_length -= 15
                match_length += 15
            match_length += 3
            offset = ((bits >> (32 - offset_bits)) if offset_bits else 0) + (1 << offset_bits)
            bits = (bits << offset_bits) & 0xFFFFFFFF
            extra -= offset_bits
            if extra < 0:
                bits |= word(position) << -extra
                extra += 16
                position += 2
            if offset > len(out):
                raise ValueError("Prefetch match offset precedes output")
            if len(out) + match_length > output_size:
                raise ValueError("Prefetch decompressed data exceeds declared size")
            start = len(out) - offset
            if offset >= match_length:
                out += out[start:start + match_length]
            else:
                # Overlapping copy repeats the last ``offset`` bytes.
                pattern = bytes(out[start:])
                out += (pattern * (match_length // offset + 1))[:match_length]
        if position > size + 4:
            raise ValueError("Truncated Prefetch compressed stream")
    return bytes(out)


def decompress_mam(content: bytes) -> tuple[bytes, list[str]]:
    """Unwrap a Windows 10+ ``MAM`` container (signature, size, optional CRC32)."""
    warnings: list[str] = []
    if len(content) < 8:
        raise ValueError("Truncated Prefetch MAM header")
    flags = content[3]
    if content[:3] != b"MAM" or flags & 0x0F != 0x04:
        raise ValueError("Unsupported Prefetch compression")
    declared = struct.unpack_from("<I", content, 4)[0]
    if not 0 < declared <= MAX_DECOMPRESSED:
        raise ValueError("Prefetch decompressed size out of bounds")
    start = 8
    if flags & 0x80:
        # The checksum covers the container with its CRC field zeroed.
        if len(content) < 12:
            raise ValueError("Truncated Prefetch MAM header")
        stored = struct.unpack_from("<I", content, 8)[0]
        computed = zlib.crc32(content[12:], zlib.crc32(b"\x00\x00\x00\x00", zlib.crc32(content[:8])))
        if stored != computed:
            warnings.append("Prefetch MAM checksum does not match; decoded content may be damaged")
        start = 12
    return lzxpress_huffman_decompress(content[start:], declared), warnings


# --- SCCA structure -----------------------------------------------------------

def _u32(buffer: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(buffer):
        raise ValueError("Truncated Prefetch structure")
    return struct.unpack_from("<I", buffer, offset)[0]


def _u64(buffer: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(buffer):
        raise ValueError("Truncated Prefetch structure")
    return struct.unpack_from("<Q", buffer, offset)[0]


def _section(buffer: bytes, offset: int, length: int, floor: int, label: str) -> bytes:
    if offset < floor or length < 0 or offset + length > len(buffer):
        raise ValueError(f"Prefetch {label} outside file")
    return buffer[offset:offset + length]


def _utf16(raw: bytes) -> str:
    return raw.decode("utf-16-le", errors="replace").replace("\x00", "")


def _filetime(value: int) -> str | None:
    if value == 0:
        return None
    try:
        moment = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    return moment.isoformat()


def _filename_list(raw: bytes, warnings: list[str]) -> list[str]:
    if len(raw) % 2:
        raw = raw[:-1]
    names: list[str] = []
    text = raw.decode("utf-16-le", errors="replace")
    for name in text.split("\x00"):
        if not name:
            continue
        if len(name) > MAX_NAME_CHARS:
            raise ValueError("Oversized Prefetch filename string")
        if len(names) >= MAX_FILENAMES:
            warnings.append(f"Prefetch filename list truncated at {MAX_FILENAMES} entries")
            break
        names.append(name)
    return names


def _join_bounded(values: list[str], label: str, warnings: list[str], keep: str = "") -> str:
    if keep and sum(len(value) + 2 for value in values) > MAX_JOINED:
        # Keep the executable's own path when the list must be truncated; the
        # cross-source rule matches it.
        suffix = "\\" + keep.casefold()
        values = sorted(values, key=lambda value: not value.casefold().endswith(suffix))
    joined, total = [], 0
    for value in values:
        cost = len(value) + (2 if joined else 0)
        if total + cost > MAX_JOINED:
            warnings.append(f"Prefetch {label} truncated to {MAX_JOINED} characters in export_record")
            break
        joined.append(value)
        total += cost
    return ", ".join(joined)


def _volumes(buffer: bytes, version: int, offset: int, count: int, size: int, floor: int) -> list[dict]:
    if count == 0:
        return []
    if count > MAX_VOLUMES:
        raise ValueError("Prefetch volume count exceeds limit")
    entry_size = VOLUME_ENTRY[version]
    area = _section(buffer, offset, size, floor, "volume information")
    if count * entry_size > len(area):
        raise ValueError("Prefetch volume information truncated")
    volumes, directory_total = [], 0
    for index in range(count):
        base = index * entry_size
        path_offset, path_chars = _u32(area, base), _u32(area, base + 4)
        if path_chars > MAX_NAME_CHARS:
            raise ValueError("Oversized Prefetch volume path")
        device = _utf16(_section(area, path_offset, path_chars * 2, 0, "volume path"))
        directories: list[str] = []
        directory_offset, directory_count = _u32(area, base + 28), _u32(area, base + 32)
        if directory_total + directory_count > MAX_DIRECTORIES:
            raise ValueError("Prefetch directory count exceeds limit")
        directory_total += directory_count
        cursor = directory_offset
        for _ in range(directory_count):
            chars = struct.unpack_from("<H", _section(area, cursor, 2, 0, "directory strings"))[0]
            directories.append(_utf16(_section(area, cursor + 2, chars * 2, 0, "directory strings")))
            cursor += 2 + chars * 2 + 2  # Length prefix, characters, terminating NUL.
        volumes.append({
            "device_path": device,
            "serial": f"{_u32(area, base + 16):08X}",
            "created": _filetime(_u64(area, base + 8)),
            "created_raw": f"FILETIME:0x{_u64(area, base + 8):016X}",
            "directories": directories,
        })
    return volumes


def parse_scca(buffer: bytes) -> tuple[dict, list[str]]:
    """Parse a decompressed SCCA buffer into bounded fields and warnings."""
    warnings: list[str] = []
    if len(buffer) < HEADER_SIZE:
        raise ValueError("Truncated Prefetch header")
    version = _u32(buffer, 0)
    if buffer[4:8] != b"SCCA":
        raise ValueError("Invalid Prefetch signature")
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported Prefetch format version {version}")
    declared = _u32(buffer, 12)
    if declared != len(buffer):
        raise ValueError("Prefetch header file size does not match content")
    executable = buffer[16:76].decode("utf-16-le", errors="replace").split("\x00")[0].strip()
    if not executable:
        raise ValueError("Prefetch header has no executable name")
    prefetch_hash = _u32(buffer, 76)
    info = HEADER_SIZE
    metrics_offset = _u32(buffer, info)
    strings_offset, strings_size = _u32(buffer, info + 16), _u32(buffer, info + 20)
    volumes_offset, volume_count, volumes_size = _u32(buffer, info + 24), _u32(buffer, info + 28), _u32(buffer, info + 32)
    if version == 17:
        info_size, run_times, run_count_at = 68, [info + 36], info + 60
    elif version == 23:
        info_size, run_times, run_count_at = 156, [info + 44], info + 68
    else:
        run_times = [info + 44 + 8 * index for index in range(8)]
        # Windows 10 later builds shrank file information; their metrics start at 0x128.
        if version in (30, 31) and metrics_offset == 0x128:
            info_size, run_count_at = 212, info + 116
        else:
            info_size, run_count_at = 220, info + 124
    floor = info + info_size
    if len(buffer) < floor:
        raise ValueError("Truncated Prefetch file information")
    if strings_size > MAX_STRING_TABLE:
        raise ValueError("Prefetch filename string table exceeds limit")
    filenames = _filename_list(_section(buffer, strings_offset, strings_size, floor, "filename strings"), warnings)
    volumes = _volumes(buffer, version, volumes_offset, volume_count, volumes_size, floor)
    runs = []
    for field, at in zip(RUN_FIELDS, run_times):
        raw = _u64(buffer, at)
        if raw == 0:
            continue
        stamp = _filetime(raw)
        if stamp is None:
            warnings.append(f"Prefetch {field} FILETIME out of range")
            continue
        runs.append({"field": field, "timestamp": stamp, "raw": f"FILETIME:0x{raw:016X}", "offset": at})
    return {
        "version": version, "executable": executable, "hash": f"{prefetch_hash:08X}",
        "file_size": declared, "run_count": _u32(buffer, run_count_at), "runs": runs,
        "volumes": volumes, "filenames": filenames,
    }, warnings


def parse_prefetch_binary(
    content: bytes, *, source_name: str, source_sha256: str, host: str,
    observed_at: str, original_name: str = "",
) -> tuple[list[dict], list[str]]:
    """Parse one Prefetch file into execution-time observations and bounded warnings."""
    if not isinstance(content, bytes) or len(content) > MAX_INPUT:
        raise ValueError("Prefetch file exceeds 16 MiB")
    for value, label, limit in ((source_name, "source name", 512), (host, "host", 256)):
        if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
            raise ValueError(f"Invalid {label}")
    if not isinstance(original_name, str) or len(original_name) > 512 or "\x00" in original_name:
        raise ValueError("Invalid original name")
    if not isinstance(source_sha256, str) or not _SHA256.fullmatch(source_sha256):
        raise ValueError("Invalid source SHA-256")
    try:
        observed_dt = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid observed_at") from exc
    if observed_dt.tzinfo is None or observed_dt.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")
    observed_iso = observed_dt.astimezone(timezone.utc).isoformat()

    compressed = content[:3] == b"MAM"
    if compressed:
        buffer, warnings = decompress_mam(content)
    else:
        buffer, warnings = content, []
    parsed, scca_warnings = parse_scca(buffer)
    warnings.extend(scca_warnings)
    location = original_name.strip() or source_name
    if parsed["run_count"] > 0 and not parsed["runs"]:
        warnings.append(f"Prefetch {location} reports runs but has no run timestamp")

    record = {
        "SourceFilename": location, "ExecutableName": parsed["executable"], "Hash": parsed["hash"],
        "Size": str(parsed["file_size"]), "Version": str(parsed["version"]),
        "RunCount": str(parsed["run_count"]),
        **{run["field"]: run["timestamp"] for run in parsed["runs"]},
        "Directories": _join_bounded([d for v in parsed["volumes"] for d in v["directories"]], "directory list", warnings),
        "FilesLoaded": _join_bounded(parsed["filenames"], "filename list", warnings, keep=parsed["executable"]),
        "ParsingError": bool(warnings),
    }
    for index, volume in enumerate(parsed["volumes"][:2]):
        record[f"Volume{index}Name"] = volume["device_path"]
        record[f"Volume{index}Serial"] = volume["serial"]
        record[f"Volume{index}Created"] = volume["created"] or ""
    native = {
        "format_version": parsed["version"], "compressed": compressed,
        "filename_count": len(parsed["filenames"]),
        "volumes": [{key: value for key, value in volume.items() if key != "directories"}
                    | {"directory_count": len(volume["directories"])} for volume in parsed["volumes"]],
    }
    runs = parsed["runs"] or [None]
    observations = []
    for run in runs:
        field = run["field"] if run else None
        identity = json.dumps([source_sha256.lower(), "scca", field, host], separators=(",", ":"))
        observations.append({
            "id": "obs_" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "kind": "prefetch_run" if run else "prefetch_record",
            "host": host, "timestamp": run["timestamp"] if run else None,
            "timestamp_raw": run["raw"] if run else None, "observed_at": observed_iso,
            "time_semantics": "prefetch_recorded_run" if run else "artifact_metadata",
            "interpretation": INTERPRETATION,
            "source_id": "evi_" + source_sha256.lower(), "source_file": source_name,
            "source_record": 1, "source_sha256": source_sha256.lower(),
            "collector": dict(COLLECTOR),
            "native_locator": {"SourceFilename": location, "runField": field,
                               "decompressedOffset": run["offset"] if run else None},
            "details": {
                "name": parsed["executable"], "location": location, "run_count": parsed["run_count"],
                "prefetch_hash": parsed["hash"], "version": str(parsed["version"]),
                "export_record": record, "native": native,
            },
        })
    return observations, warnings
