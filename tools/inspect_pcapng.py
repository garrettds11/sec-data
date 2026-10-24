#!/usr/bin/env python3
"""Inspect Ethernet/IPv4/TCP packets in a local PCAPNG, without third-party packages."""
import argparse
import hashlib
import ipaddress
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path


def packets(path):
    data = Path(path).read_bytes()
    offset, endian, interfaces = 0, None, []
    while offset + 12 <= len(data):
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8:offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                raise ValueError("Invalid PCAPNG byte-order magic")
            interfaces = []
        if endian is None:
            raise ValueError("PCAPNG must begin with a section header")
        block_type, length = struct.unpack_from(endian + "II", data, offset)
        if length < 12 or offset + length > len(data):
            raise ValueError("Invalid PCAPNG block length")
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise ValueError("PCAPNG block length trailer mismatch")
        body = data[offset + 8:offset + length - 4]
        if block_type == 1:
            linktype = struct.unpack_from(endian + "H", body)[0]
            resolution = 1e-6
            options = body[8:]
            pos = 0
            while pos + 4 <= len(options):
                code, size = struct.unpack_from(endian + "HH", options, pos)
                pos += 4
                value = options[pos:pos + size]
                pos += (size + 3) & ~3
                if code == 9 and value:
                    v = value[0]
                    resolution = (2 if v & 0x80 else 10) ** -(v & 0x7f)
                if code == 0:
                    break
            interfaces.append((linktype, resolution))
        elif block_type == 6:
            interface, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
            if interface >= len(interfaces):
                raise ValueError("Packet references missing interface")
            linktype, resolution = interfaces[interface]
            frame = body[20:20 + captured]
            if len(frame) != captured:
                raise ValueError("Truncated enhanced packet block")
            yield (high * 2**32 + low) * resolution, frame, linktype, original
        offset += length
    if offset != len(data):
        raise ValueError("Trailing PCAPNG bytes")


def tcp_packet(frame, linktype):
    if linktype != 1 or len(frame) < 34:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    ip_start = 14
    if ethertype == 0x8100 and len(frame) >= 38:
        ethertype = struct.unpack_from("!H", frame, 16)[0]
        ip_start = 18
    if ethertype != 0x0800 or frame[ip_start] >> 4 != 4:
        return None
    ihl = (frame[ip_start] & 15) * 4
    if ihl < 20 or len(frame) < ip_start + ihl + 20 or frame[ip_start + 9] != 6:
        return None
    tcp_start = ip_start + ihl
    total_length = struct.unpack_from("!H", frame, ip_start + 2)[0]
    tcp_header_length = (frame[tcp_start + 12] >> 4) * 4
    src = str(ipaddress.IPv4Address(frame[ip_start + 12:ip_start + 16]))
    dst = str(ipaddress.IPv4Address(frame[ip_start + 16:ip_start + 20]))
    sport, dport = struct.unpack_from("!HH", frame, tcp_start)
    flags = frame[tcp_start + 13]
    return dict(src=src, dst=dst, src_port=sport, dst_port=dport,
                syn=bool(flags & 2), ack=bool(flags & 16), rst=bool(flags & 4),
                fin=bool(flags & 1), frame_bytes=len(frame),
                payload_bytes=max(0, total_length - ihl - tcp_header_length))


def analyze(path, scanner, target):
    probes = defaultdict(list)
    replies = defaultdict(list)
    total = Counter()
    for when, frame, linktype, original in packets(path):
        total["packets"] += 1
        row = tcp_packet(frame, linktype)
        if not row:
            total["non_ipv4_tcp"] += 1
            continue
        total["tcp_payload_bytes"] += row["payload_bytes"]
        if row["src"] == scanner and row["dst"] == target:
            total["scanner_to_target"] += 1
            total[f"scanner_frame_bytes_{row['frame_bytes']}"] += 1
            if row["syn"] and not row["ack"]:
                probes[row["dst_port"]].append((when, row))
        elif row["src"] == target and row["dst"] == scanner:
            total["target_to_scanner"] += 1
            total[f"target_frame_bytes_{row['frame_bytes']}"] += 1
            if row["syn"] and row["ack"] or row["rst"]:
                replies[row["src_port"]].append((when, row))
    outcomes = Counter()
    outcomes_by_port = {}
    packet_counts = Counter()
    sizes = Counter()
    probe_times = []
    response_ms = []
    for port, attempts in probes.items():
        response = replies.get(port, [])
        outcome = "syn_ack" if any(r["syn"] and r["ack"] for _, r in response) else \
                  "rst" if any(r["rst"] for _, r in response) else "no_response"
        outcomes[outcome] += 1
        outcomes_by_port[port] = outcome
        packet_counts[len(attempts)] += 1
        for t, row in attempts:
            probe_times.append(t)
            sizes[row["frame_bytes"]] += 1
        if attempts and response:
            response_ms.append(round((response[0][0] - attempts[0][0]) * 1000, 3))
    probe_times.sort()
    gaps = [round((b - a) * 1000, 3) for a, b in zip(probe_times, probe_times[1:])]
    return {
        "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        "capture_bytes": Path(path).stat().st_size,
        "scanner": scanner, "target": target, "packet_counts": dict(total),
        "distinct_destination_ports": len(probes), "response_outcomes": dict(outcomes),
        "destination_ports": sorted(probes),
        "probe_port_order": list(probes),
        "open_ports": sorted(port for port, outcome in outcomes_by_port.items() if outcome == "syn_ack"),
        "syn_probes_per_port": dict(packet_counts), "syn_frame_bytes": dict(sizes),
        "first_probe_epoch": probe_times[0] if probe_times else None,
        "last_probe_epoch": probe_times[-1] if probe_times else None,
        "probe_gap_ms_min": min(gaps) if gaps else None,
        "probe_gap_ms_median": sorted(gaps)[len(gaps)//2] if gaps else None,
        "probe_gap_ms_max": max(gaps) if gaps else None,
        "response_ms_min": min(response_ms) if response_ms else None,
        "response_ms_median": sorted(response_ms)[len(response_ms)//2] if response_ms else None,
        "response_ms_max": max(response_ms) if response_ms else None,
    }


def verify_profile(summary, profile):
    measured = profile["measurements"]
    def check(ok, message):
        if not ok:
            raise ValueError(message)
    check(summary["sha256"] == profile["capture"]["sha256"], "Capture checksum differs")
    check(summary["capture_bytes"] == profile["capture"]["size_bytes"], "Capture size differs")
    check(summary["destination_ports"] == measured["destination_ports"], "Destination ports differ")
    check(summary["open_ports"] == measured["open_ports"], "Open ports differ")
    check(summary["response_outcomes"] == {k: v for k, v in measured["response_outcomes"].items() if v},
          "Outcomes differ")
    counts = summary["packet_counts"]
    check(counts["packets"] == measured["packet_counts"]["total"], "Packet total differs")
    check(counts["scanner_to_target"] == measured["packet_counts"]["scanner_to_target"],
          "Outbound packet total differs")
    check(counts["target_to_scanner"] == measured["packet_counts"]["target_to_scanner"],
          "Inbound packet total differs")
    check(counts["tcp_payload_bytes"] == 0, "Unexpected application payload")
    check(summary["syn_probes_per_port"] == {1: 100}, "Unexpected SYN retry count")
    check(summary["syn_frame_bytes"] == {measured["frame_bytes"]["syn"]: 100},
          "SYN frame sizes differ")
    check(counts[f"target_frame_bytes_{measured['frame_bytes']['closed_response']}"] == 97,
          "Closed response frame sizes differ")
    check(counts[f"target_frame_bytes_{measured['frame_bytes']['open_response']}"] == 3,
          "Open response frame sizes differ")
    span = (summary["last_probe_epoch"] - summary["first_probe_epoch"]) * 1000
    check(abs(span - measured["probe_span_ms"]) < 0.01, "Probe span differs")
    check(abs(summary["probe_gap_ms_max"] - measured["probe_gap_ms"]["max"]) < 0.01,
          "Probe gap differs")
    check(abs(summary["response_ms_median"] - measured["response_delay_ms"]["median"]) < 0.01,
          "Response delay differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--verify-profile", type=Path, help="Fail if measured capture differs from profile")
    args = parser.parse_args()
    summary = analyze(args.capture, args.scanner, args.target)
    if args.verify_profile:
        verify_profile(summary, json.loads(args.verify_profile.read_text(encoding="utf-8")))
        summary["profile_verification"] = "passed"
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
