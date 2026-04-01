#!/usr/bin/env python3
"""Tiny UDP echo server used by the SDX demo probes.

It listens on two ports:
- the normal JSON echo port used by Mode 1 / Mode 2 probes
- a second port used by INT-like binary probes for Mode 3

For JSON payloads, the server honors a `reply_tos` field.
For binary INT-like payloads, the server simply reuses the TOS value received on
that packet so the reply follows the same steering rule.
"""

from __future__ import annotations

import argparse
import json
import select
import socket
from typing import Iterable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UDP echo server for the SDX demo")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--int-port", type=int, default=5001)
    return parser.parse_args()


def create_socket(bind_ip: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if hasattr(socket, "IP_RECVTOS"):
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    sock.bind((bind_ip, port))
    return sock


def extract_received_tos(ancdata: Iterable[tuple[int, int, bytes]]) -> int:
    for level, cmsg_type, cmsg_data in ancdata:
        if level != socket.IPPROTO_IP:
            continue
        if cmsg_type in {getattr(socket, "IP_TOS", -1), getattr(socket, "IP_RECVTOS", -1)}:
            if cmsg_data:
                return int(cmsg_data[0])
    return 0


def main() -> None:
    args = parse_args()
    sockets = [create_socket(args.bind, args.port)]
    if args.int_port != args.port:
        sockets.append(create_socket(args.bind, args.int_port))

    while True:
        readable, _, _ = select.select(sockets, [], [])
        for sock in readable:
            data, ancdata, _flags, address = sock.recvmsg(65535, 1024)
            received_tos = extract_received_tos(ancdata)
            reply_tos = received_tos

            try:
                message = json.loads(data.decode("utf-8"))
                reply_tos = int(message.get("reply_tos", received_tos))
            except Exception:
                pass

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, reply_tos)
            sock.sendto(data, address)


if __name__ == "__main__":
    main()
