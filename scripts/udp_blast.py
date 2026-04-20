#!/usr/bin/env python3
from __future__ import annotations

import argparse
import signal
import socket
import time

RUNNING = True

def _stop(_signum, _frame):
    global RUNNING
    RUNNING = False

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate one-way UDP load")
    parser.add_argument("--dst", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--tos", type=int, default=0)
    parser.add_argument("--rate-mbps", type=float, required=True)
    parser.add_argument("--size", type=int, default=1200)
    parser.add_argument("--bind", default="")
    parser.add_argument("--duration", type=float, default=0.0, help="0 means run until terminated")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.bind:
        sock.bind((args.bind, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, args.tos)

    payload = b'Q' * max(64, args.size)
    frame_bits = float((len(payload) + 28) * 8)
    rate_bps = max(1.0, float(args.rate_mbps) * 1_000_000.0)
    spacing_s = frame_bits / rate_bps

    start = time.monotonic()
    next_send = start
    try:
        while RUNNING:
            now = time.monotonic()
            if args.duration > 0.0 and (now - start) >= args.duration:
                break
            if now < next_send:
                time.sleep(min(0.001, next_send - now))
                continue
            sock.sendto(payload, (args.dst, args.port))
            next_send += spacing_s
            if next_send < now - 0.25:
                next_send = now
    finally:
        sock.close()

if __name__ == "__main__":
    main()
