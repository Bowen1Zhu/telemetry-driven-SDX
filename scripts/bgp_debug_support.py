
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


def ensure_dir(path: str | os.PathLike[str]) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_text(path: str | os.PathLike[str], text: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def run_host_cmd(host: Any, command: str) -> str:
    return host.cmd(command)


def parse_ping(output: str) -> dict[str, Any]:
    """
    Parse Linux ping output into a small structured dict.
    """
    result: dict[str, Any] = {"success": False, "loss_pct": None, "avg_ms": None}
    m = re.search(r'(\d+)% packet loss', output)
    if m:
        result["loss_pct"] = float(m.group(1))
        result["success"] = float(m.group(1)) < 100.0
    m = re.search(r'rtt [^=]+= [^/]+/([^/]+)/', output)
    if m:
        try:
            result["avg_ms"] = float(m.group(1))
        except ValueError:
            pass
    return result


def ping_test(host: Any, dst_ip: str, count: int = 1, timeout_s: int = 1) -> dict[str, Any]:
    cmd = f"ping -c {count} -W {timeout_s} {dst_ip}"
    output = run_host_cmd(host, cmd)
    result = parse_ping(output)
    result["command"] = cmd
    result["output"] = output
    return result


def route_get(host: Any, dst_ip: str) -> dict[str, Any]:
    cmd = f"ip route get {dst_ip}"
    output = run_host_cmd(host, cmd)
    return {"command": cmd, "output": output, "success": ("via" in output or "dev" in output)}


def show_ip_route(host: Any, prefix: str) -> dict[str, Any]:
    cmd = f"vtysh -c 'show ip route {prefix}'"
    output = run_host_cmd(host, cmd)
    return {"command": cmd, "output": output}


def show_bgp_prefix(host: Any, prefix: str) -> dict[str, Any]:
    cmd = f"vtysh -c 'show bgp ipv4 unicast {prefix}'"
    output = run_host_cmd(host, cmd)
    return {"command": cmd, "output": output}


def show_neighbors(host: Any) -> dict[str, Any]:
    cmd = "ip neigh show"
    output = run_host_cmd(host, cmd)
    return {"command": cmd, "output": output}


def classify_breakpoint(
    client_ping: dict[str, Any],
    source_ping: dict[str, Any],
    dest_ping: dict[str, Any],
    transit_ping: dict[str, Any] | None,
    udp_ok: bool,
) -> str:
    """
    Heuristic diagnosis only. The goal is to quickly narrow where the packet likely dies.
    """
    if client_ping.get("success") and udp_ok:
        return "no_obvious_problem"
    if not source_ping.get("success"):
        return "source_edge_cannot_reach_destination"
    if transit_ping is not None and not transit_ping.get("success"):
        return "transit_path_cannot_reach_destination"
    if source_ping.get("success") and dest_ping.get("success") and not client_ping.get("success"):
        return "ixp_or_reverse_path_problem"
    if client_ping.get("success") and not udp_ok:
        return "udp_or_tos_specific_problem"
    return "undetermined"
