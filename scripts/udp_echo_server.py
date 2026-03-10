#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import socket


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UDP echo server for the SDX run")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    return parser.parse_args()


def main() -> None:
    # UDP echo server.
    args = parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            reply_tos = int(json.loads(data.decode("utf-8")).get("reply_tos", 0))
        except Exception:
            reply_tos = 0
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, reply_tos)
        sock.sendto(data, addr)


if __name__ == "__main__":
    main()
