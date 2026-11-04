"""Measure $MFT and USN journal parsing throughput and peak memory on synthetic input.

Usage: python scripts/benchmark_ntfs_parse.py [--records 1000000] [--usn-records 1000000]

Synthetic files are written under runtime/temp/ntfs-benchmark/ and removed
afterwards; the note goes to runtime/test-output/ntfs-performance.{md,json}.
Timing and peak memory use separate passes, because tracemalloc slows parsing.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import platform
import shutil
import struct
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corrobora.ntfs_artifacts import parse_mft, parse_usn_journal  # noqa: E402

FILETIME = 133_700_000_001_234_567
DIRECTORIES = 1000


def _attribute(kind: int, value: bytes) -> bytes:
    length = (24 + len(value) + 7) // 8 * 8
    return (struct.pack("<IIBBHHHIH", kind, length, 0, 0, 0, 0, 0, len(value), 24) + b"\x00\x00" + value).ljust(length, b"\x00")


def _record(seq: int, directory: bool, parent: int, name: str) -> bytearray:
    record = bytearray(1024)
    times = (FILETIME,) * 4
    si = struct.pack("<qqqqI", *times, 0x20).ljust(72, b"\x00")
    fn = struct.pack("<Qqqqq", parent, *times) + struct.pack("<qqII", 0, 0, 0x20, 0) + bytes([len(name), 1]) + name.encode("utf-16-le")
    attributes = _attribute(0x10, si) + _attribute(0x30, fn) + b"\xff\xff\xff\xff\x00\x00\x00\x00"
    struct.pack_into("<4sHHQHHHHIIQ", record, 0, b"FILE", 0x30, 3, 0, seq, 1, 0x38, 1 | (2 if directory else 0),
                     0x38 + len(attributes), 1024, 0)
    record[0x38:0x38 + len(attributes)] = attributes
    struct.pack_into("<HHH", record, 0x30, 1, 0, 0)
    record[510:512] = record[1022:1024] = b"\x01\x00"
    return record


def write_mft(path: Path, count: int) -> None:
    # Record 5 is the root; records 16..16+DIRECTORIES are directories; the rest are files.
    file_template = _record(1, False, 0, "f0000000.exe")
    name_offset = file_template.find("f0000000.exe".encode("utf-16-le"))
    parent_offset = 0x38 + 96 + 24  # first $FILE_NAME value byte
    with path.open("wb") as handle:
        block = bytearray()
        for number in range(count):
            if number == 5:
                record = _record(5, True, 5 | (5 << 48), ".")
            elif 16 <= number < 16 + DIRECTORIES:
                record = _record(1, True, 5 | (5 << 48), f"d{number:07d}")
            else:
                record = bytearray(file_template)
                struct.pack_into("<Q", record, parent_offset, (16 + number % DIRECTORIES) | (1 << 48))
                record[name_offset:name_offset + 24] = f"f{number:07d}.exe".encode("utf-16-le")
            block += record
            if len(block) >= 8 * 1024 * 1024:
                handle.write(block)
                block.clear()
        handle.write(block)


def write_usn(path: Path, count: int) -> None:
    with path.open("wb") as handle:
        handle.write(b"\x00" * (1024 * 1024))  # leading sparse region
        block = bytearray()
        for number in range(count):
            name = f"f{number % 1_000_000:07d}.exe".encode("utf-16-le")
            reason = 0x100 if number % 10 == 0 else 0x80000002
            body = struct.pack("<QQqqIIIIHH", (100 + number) | (1 << 48), 16 | (1 << 48), number * 88,
                               FILETIME + number, reason, 0, 0, 0x20, len(name), 60) + name
            length = (8 + len(body) + 7) // 8 * 8
            block += (struct.pack("<IHH", length, 2, 0) + body).ljust(length, b"\x00")
            if len(block) >= 8 * 1024 * 1024:
                handle.write(block)
                block.clear()
        handle.write(block)


def peak_working_set_mib() -> float | None:
    if sys.platform != "win32":
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    psapi = ctypes.WinDLL("psapi")
    kernel = ctypes.WinDLL("kernel32")
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
    if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        return None
    return counters.PeakWorkingSetSize / 1024**2


def measure(label: str, parse, path: Path, count: int) -> dict:
    started = time.perf_counter()
    index = parse(path)
    elapsed = time.perf_counter() - started
    del index
    tracemalloc.start()
    index = parse(path)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"input": label, "records": count, "bytes": path.stat().st_size, "seconds": round(elapsed, 2),
            "records_per_second": round(count / elapsed), "peak_python_heap_mib": round(peak / 1024**2, 1),
            "stats": {key: value for key, value in dict(index.stats).items()}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--records", type=int, default=1_000_000)
    parser.add_argument("--usn-records", type=int, default=1_000_000)
    args = parser.parse_args()
    work = ROOT / "runtime" / "temp" / "ntfs-benchmark"
    output = ROOT / "runtime" / "test-output"
    work.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    try:
        mft_path, usn_path = work / "synthetic.mft", work / "synthetic.usnjrnl"
        write_mft(mft_path, args.records)
        write_usn(usn_path, args.usn_records)
        results = [measure("$MFT", parse_mft, mft_path, args.records),
                   measure("$UsnJrnl:$J", parse_usn_journal, usn_path, args.usn_records)]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    payload = {"measured_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
               "platform": platform.platform(), "processor": platform.processor(),
               "peak_process_working_set_mib": round(peak_working_set_mib() or 0, 1), "results": results}
    (output / "ntfs-performance.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = ["# NTFS parser performance (synthetic input)", "",
             f"Measured {payload['measured_at']} on Python {payload['python']}, {payload['platform']}.",
             f"Generated by `scripts/benchmark_ntfs_parse.py`; synthetic files were deleted after the run.", "",
             "| Input | Records | Size (MiB) | Seconds | Records/s | Peak Python heap (MiB) |", "|---|---|---|---|---|---|"]
    for item in results:
        lines.append(f"| {item['input']} | {item['records']:,} | {item['bytes'] / 1024**2:,.0f} | {item['seconds']} | "
                     f"{item['records_per_second']:,} | {item['peak_python_heap_mib']} |")
    lines += ["", f"Peak process working set across the whole run (generation and both passes): "
                  f"{payload['peak_process_working_set_mib']} MiB.", "",
              "The $MFT layout is 1,000 directories under the root with files spread across them, one $SI and one "
              "$FILE_NAME per record. Every tenth USN record is a FILE_CREATE, so 10% of journal records are indexed. "
              "Timing excludes tracemalloc; heap peak comes from a second, traced pass. Real volumes with attribute "
              "lists, longer names or several hard links per file will use more memory per record.", ""]
    (output / "ntfs-performance.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
