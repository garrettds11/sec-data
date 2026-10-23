#!/usr/bin/env python3
"""Measure generator plus JSONL serialization without disk-I/O variance."""
import argparse
import ctypes
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import create_vuln_table as vuln
import create_compliance_table as compliance
from common.export import json_default


def peak_memory_bytes():
    if os.name != "nt":
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    size_t = ctypes.c_size_t
    dword = ctypes.c_ulong
    class Counters(ctypes.Structure):
        _fields_ = [("cb", dword), ("PageFaultCount", dword),
                    ("PeakWorkingSetSize", size_t), ("WorkingSetSize", size_t),
                    ("QuotaPeakPagedPoolUsage", size_t), ("QuotaPagedPoolUsage", size_t),
                    ("QuotaPeakNonPagedPoolUsage", size_t), ("QuotaNonPagedPoolUsage", size_t),
                    ("PagefileUsage", size_t), ("PeakPagefileUsage", size_t)]
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = (ctypes.c_void_p, ctypes.c_void_p, dword)
    if not ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(),
                                                     ctypes.byref(counters), counters.cb):
        raise OSError("GetProcessMemoryInfo failed")
    return counters.PeakWorkingSetSize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=("vuln", "compliance"), required=True)
    parser.add_argument("--records", type=int, required=True)
    parser.add_argument("--host-count", type=int, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--as-of", default="2026-10-15T12:00:00Z")
    args = parser.parse_args()
    if args.records < 1:
        parser.error("--records must be positive")
    source = (vuln.iter_items(args.seed, args.as_of, args.host_count) if args.dataset == "vuln"
              else compliance.iter_items(args.seed, args.as_of, host_count=args.host_count))
    start = time.perf_counter()
    count = bytes_written = 0
    for item in source:
        bytes_written += len((json.dumps(item, default=json_default, sort_keys=True,
                                         separators=(",", ":")) + "\n").encode("utf-8"))
        count += 1
        if count == args.records:
            break
    if count != args.records:
        parser.error(f"Only {count} applicable records generated")
    print(json.dumps({"dataset": args.dataset, "records": count, "host_count": args.host_count,
                      "seconds": round(time.perf_counter() - start, 3),
                      "peak_process_bytes": peak_memory_bytes(), "jsonl_bytes": bytes_written,
                      "method": "generation and JSONL serialization; bytes counted, not written to disk",
                      "python": sys.version.split()[0], "platform": sys.platform}, sort_keys=True))


if __name__ == "__main__":
    main()
