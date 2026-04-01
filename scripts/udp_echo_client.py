#!/usr/bin/env python3
"""Send a small batch of UDP request/reply probes and print JSON metrics.

Modes:
- basic: JSON payload, plain RTT measurement (current Mode 1 behavior)
- int:   binary INT-like payload; P4 switches fill two hop slots in-band
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import statistics
import struct
import time
from typing import Any

INT_MAGIC = 0x4954
INT_VERSION = 1
INT_MAIN_STRUCT = struct.Struct("!HBBIHH")
INT_HOP_STRUCT = struct.Struct("!HHII")
INT_MAIN_SIZE = INT_MAIN_STRUCT.size
INT_HOP_SIZE = INT_HOP_STRUCT.size
INT_TOTAL_SIZE = INT_MAIN_SIZE + (2 * INT_HOP_SIZE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UDP echo client for the SDX demo")
    parser.add_argument("--dst", required=True)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--tos", type=int, default=0)
    parser.add_argument("--mode", choices=["basic", "int"], default="basic")
    return parser.parse_args()


def build_int_payload(sequence: int) -> bytes:
    probe_id = random.getrandbits(32)
    main = INT_MAIN_STRUCT.pack(INT_MAGIC, INT_VERSION, 0, probe_id, sequence, 0)
    empty_hop = INT_HOP_STRUCT.pack(0, 0, 0, 0)
    return main + empty_hop + empty_hop


def parse_int_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) < INT_TOTAL_SIZE:
        return {"hop_count": 0, "queue_depth_avg": None, "residence_ms": None}

    magic, version, hop_count, probe_id, sequence, reserved = INT_MAIN_STRUCT.unpack_from(payload, 0)
    _ = (probe_id, sequence, reserved)
    if magic != INT_MAGIC or version != INT_VERSION:
        return {"hop_count": 0, "queue_depth_avg": None, "residence_ms": None}

    queue_depths: list[float] = []
    residence_ms_total = 0.0
    for hop_index in range(min(hop_count, 2)):
        offset = INT_MAIN_SIZE + (hop_index * INT_HOP_SIZE)
        egress_port, reserved_hop, queue_depth, residence_us = INT_HOP_STRUCT.unpack_from(payload, offset)
        _ = (egress_port, reserved_hop)
        queue_depths.append(float(queue_depth))
        residence_ms_total += float(residence_us) / 1000.0

    return {
        "hop_count": int(hop_count),
        "queue_depth_avg": (statistics.mean(queue_depths) if queue_depths else None),
        "residence_ms": (residence_ms_total if queue_depths else None),
    }


def main() -> None:
    args = parse_args()
    destination = (args.dst, args.port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, args.tos)

    rtts_ms: list[float] = []
    int_queue_depths: list[float] = []
    int_residence_ms: list[float] = []
    int_reports = 0

    for sequence in range(args.count):
        if args.mode == "basic":
            payload = json.dumps(
                {
                    "sequence": sequence,
                    "reply_tos": args.tos,
                    "sent_ns": time.time_ns(),
                }
            ).encode("utf-8")
        else:
            payload = build_int_payload(sequence)

        start_ns = time.perf_counter_ns()
        try:
            sock.sendto(payload, destination)
            data, _ = sock.recvfrom(65535)
            end_ns = time.perf_counter_ns()
            rtts_ms.append((end_ns - start_ns) / 1_000_000.0)

            if args.mode == "int":
                parsed = parse_int_payload(data)
                if parsed["queue_depth_avg"] is not None:
                    int_queue_depths.append(float(parsed["queue_depth_avg"]))
                if parsed["residence_ms"] is not None:
                    int_residence_ms.append(float(parsed["residence_ms"]))
                if parsed["hop_count"]:
                    int_reports += 1
        except socket.timeout:
            pass

        if sequence + 1 < args.count:
            time.sleep(args.interval)

    sent = args.count
    received = len(rtts_ms)
    loss_pct = 100.0 * (sent - received) / max(sent, 1)

    summary = {
        "sent": sent,
        "received": received,
        "loss_pct": loss_pct,
        "rtts_ms": rtts_ms,
        "avg_ms": (statistics.mean(rtts_ms) if rtts_ms else None),
        "min_ms": (min(rtts_ms) if rtts_ms else None),
        "max_ms": (max(rtts_ms) if rtts_ms else None),
        "aux_queue_avg": (statistics.mean(int_queue_depths) if int_queue_depths else None),
        "aux_residence_ms": (statistics.mean(int_residence_ms) if int_residence_ms else None),
        "aux_report_count": int_reports,
    }
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
