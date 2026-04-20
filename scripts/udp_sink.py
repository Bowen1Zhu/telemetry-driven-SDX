#!/usr/bin/env python3
from __future__ import annotations

import argparse
import signal
import socket

RUNNING = True

def _stop(_signum, _frame):
    global RUNNING
    RUNNING = False

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UDP sink")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--bufsize", type=int, default=65535)
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.settimeout(1.0)

    try:
        while RUNNING:
            try:
                sock.recvfrom(args.bufsize)
            except socket.timeout:
                continue
    finally:
        sock.close()

if __name__ == "__main__":
    main()
