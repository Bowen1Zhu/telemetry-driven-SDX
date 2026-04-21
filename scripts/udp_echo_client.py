#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import socket
import statistics
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UDP echo client for the SDX run")
    parser.add_argument("--dst", required=True)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--tos", type=int, default=0)
    return parser.parse_args()


def main() -> None:
    # Send a short UDP probe batch and print one JSON summary.
    args = parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, args.tos)

    rtts_ms: list[float] = []
    for seq in range(args.count):
        payload = json.dumps({"sequence": seq, "reply_tos": args.tos, "sent_ns": time.time_ns()}).encode("utf-8")
        start_ns = time.perf_counter_ns()
        try:
            sock.sendto(payload, (args.dst, args.port))
            sock.recvfrom(65535)
            rtts_ms.append((time.perf_counter_ns() - start_ns) / 1_000_000.0)
        except socket.timeout:
            pass
        if seq + 1 < args.count:
            time.sleep(args.interval)

    sent = args.count
    received = len(rtts_ms)
    print(
        json.dumps(
            {
                "sent": sent,
                "received": received,
                "loss_pct": 100.0 * (sent - received) / max(sent, 1),
                "rtts_ms": rtts_ms,
                "avg_ms": statistics.mean(rtts_ms) if rtts_ms else None,
                "min_ms": min(rtts_ms) if rtts_ms else None,
                "max_ms": max(rtts_ms) if rtts_ms else None,
            }
        )
    )


if __name__ == "__main__":
    main()
