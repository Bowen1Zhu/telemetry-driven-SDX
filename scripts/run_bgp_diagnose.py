
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import pathlib
import sys
import time
from typing import Any

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, "../"))
sys.path.append(REPOSITORY_DIRECTORY)

from controller.sdx_controller import RunConfig, SdxController, TrafficSessionConfig
from networks import load_topology_class
from scripts.bgp_support import BgpReachabilityTracker, wait_for_bgp_readiness
from scripts.bgp_debug_support import (
    classify_breakpoint,
    ensure_dir,
    ping_test,
    route_get,
    show_bgp_prefix,
    show_ip_route,
    show_neighbors,
    write_text,
)
from scripts.run_sdx import configure_logging, ensure_parent_dirs, run_udp_probe_async

LOGGER = logging.getLogger("sdx_bgp_diagnose")


def _group_by_name(config: RunConfig) -> dict[str, Any]:
    return {group.name: group for group in config.traffic_groups}


def _observer_router_for_group(tracker: BgpReachabilityTracker, group: Any) -> str | None:
    observer = tracker.observers.get((group.switch, group.tenant_id))
    if observer is None:
        return None
    return observer.router


async def _set_initial_legal_paths(
    controller: SdxController,
    tracker: BgpReachabilityTracker,
    sessions: list[TrafficSessionConfig],
) -> dict[str, str | None]:
    chosen: dict[str, str | None] = {}
    for session in sessions:
        allowed = tracker.allowed_paths_for_session(session.name)
        if not allowed:
            chosen[session.name] = None
            continue
        path = allowed[0]
        await controller.set_session_path(session.name, path)
        chosen[session.name] = path
    return chosen


async def _start_udp_servers(network: Mininet, config: RunConfig, server_script_path: str) -> dict[str, Any]:
    processes: dict[str, Any] = {}
    server_hosts = sorted({session.server_host for session in config.traffic_sessions})
    for host_name in server_hosts:
        host = network.get(host_name)
        proc = host.popen(
            [
                "python3",
                server_script_path,
                "--port",
                str(config.probe_service.udp_port),
                "--int-port",
                str(config.probe_service.int_udp_port),
            ],
            stdout=None,
            stderr=None,
            text=True,
        )
        processes[host_name] = proc
    await asyncio.sleep(1.0)
    return processes


def _stop_udp_servers(processes: dict[str, Any]) -> None:
    for proc in processes.values():
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


async def async_main(args: argparse.Namespace, network: Mininet, config: RunConfig) -> None:
    build_dir = os.path.join(REPOSITORY_DIRECTORY, "build/p4")
    controller = SdxController(
        config_path=args.config,
        p4info_path=os.path.join(build_dir, "sdx_ixp.p4info.txtpb"),
        p4blob_path=os.path.join(build_dir, "sdx_ixp.json"),
    )
    tracker = BgpReachabilityTracker(network=network, config=config, logger=LOGGER)

    results_dir = ensure_dir(args.results_dir)
    raw_dir = ensure_dir(results_dir / "raw")
    csv_path = results_dir / "latest_run.csv"
    summary_path = results_dir / "latest_summary.json"

    client_script_path = os.path.join(REPOSITORY_DIRECTORY, "scripts/udp_echo_client.py")
    server_script_path = os.path.join(REPOSITORY_DIRECTORY, "scripts/udp_echo_server.py")

    rows: list[dict[str, Any]] = []
    server_processes: dict[str, Any] = {}
    group_by_name = _group_by_name(config)

    try:
        await controller.start()
        await controller.wait_until_ready(timeout_s=45.0)

        LOGGER.info("Waiting %.1fs for initial FRR/BGP warm-up", args.warmup_s)
        await asyncio.sleep(args.warmup_s)
        await wait_for_bgp_readiness(
            tracker=tracker,
            timeout_s=args.bgp_wait_timeout_s,
            poll_s=args.bgp_poll_s,
            logger=LOGGER,
            require_expected=False,
        )
        tracker.refresh()
        tracker.install_session_dataplane_routes()
        await asyncio.sleep(3.0)

        initial_path_by_session = await _set_initial_legal_paths(controller, tracker, config.traffic_sessions)
        await asyncio.sleep(2.0)

        # Start servers and do a brief ignored ping warm-up
        server_processes = await _start_udp_servers(network, config, server_script_path)

        for session in config.traffic_sessions:
            fwd_group = group_by_name[session.forward_group]
            client = network.get(session.client_host)
            server = network.get(session.server_host)
            client.cmd(f"ping -c 1 -W 1 {session.server_ip} >/dev/null 2>&1 || true")
            server.cmd(f"ping -c 1 -W 1 {fwd_group.src_ip} >/dev/null 2>&1 || true")

        for session in config.traffic_sessions:
            allowed = tracker.allowed_paths_for_session(session.name)
            fwd_group = group_by_name[session.forward_group]
            rev_group = group_by_name[session.reverse_group]

            source_router_name = _observer_router_for_group(tracker, fwd_group)
            dest_router_name = _observer_router_for_group(tracker, rev_group)

            client = network.get(session.client_host)
            server = network.get(session.server_host)
            source_router = network.get(source_router_name) if source_router_name else None
            dest_router = network.get(dest_router_name) if dest_router_name else None

            client_ip = fwd_group.src_ip
            server_ip = session.server_ip

            # Common diagnostics first
            client_ping = ping_test(client, server_ip)
            server_ping = ping_test(server, client_ip)
            source_ping = ping_test(source_router, server_ip) if source_router is not None else {"success": False, "output": ""}
            dest_ping = ping_test(dest_router, client_ip) if dest_router is not None else {"success": False, "output": ""}

            # Save routing snapshots for edge routers
            if source_router is not None:
                write_text(raw_dir / f"{session.name}__{source_router_name}__ip_route_get.txt", route_get(source_router, server_ip)["output"])
                write_text(raw_dir / f"{session.name}__{source_router_name}__show_ip_route.txt", show_ip_route(source_router, f"{server_ip}/32")["output"])
                write_text(raw_dir / f"{session.name}__{source_router_name}__show_bgp.txt", show_bgp_prefix(source_router, f"{server_ip}/32")["output"])
                write_text(raw_dir / f"{session.name}__{source_router_name}__ip_neigh.txt", show_neighbors(source_router)["output"])
            if dest_router is not None:
                write_text(raw_dir / f"{session.name}__{dest_router_name}__ip_route_get.txt", route_get(dest_router, client_ip)["output"])
                write_text(raw_dir / f"{session.name}__{dest_router_name}__show_ip_route.txt", show_ip_route(dest_router, f"{client_ip}/32")["output"])
                write_text(raw_dir / f"{session.name}__{dest_router_name}__show_bgp.txt", show_bgp_prefix(dest_router, f"{client_ip}/32")["output"])
                write_text(raw_dir / f"{session.name}__{dest_router_name}__ip_neigh.txt", show_neighbors(dest_router)["output"])

            # Try actual traffic/probe over each legal path separately
            for path_name in allowed:
                await controller.set_session_path(session.name, path_name)
                await asyncio.sleep(1.0)

                transit_router_name = tracker.transit_router_for_path(path_name)
                transit_router = network.get(transit_router_name) if transit_router_name else None
                transit_ping = ping_test(transit_router, server_ip) if transit_router is not None else None

                if transit_router is not None:
                    write_text(raw_dir / f"{session.name}__{transit_router_name}__to_server__ip_route_get.txt", route_get(transit_router, server_ip)["output"])
                    write_text(raw_dir / f"{session.name}__{transit_router_name}__to_server__show_ip_route.txt", show_ip_route(transit_router, f"{server_ip}/32")["output"])
                    write_text(raw_dir / f"{session.name}__{transit_router_name}__to_server__show_bgp.txt", show_bgp_prefix(transit_router, f"{server_ip}/32")["output"])
                    write_text(raw_dir / f"{session.name}__{transit_router_name}__ip_neigh.txt", show_neighbors(transit_router)["output"])

                udp_traffic = await run_udp_probe_async(
                    host=client,
                    client_script_path=client_script_path,
                    dst_ip=server_ip,
                    udp_port=config.probe_service.udp_port,
                    tos=session.traffic_tos,
                    count=1,
                    timeout_s=config.closed_loop.probe_timeout_s,
                    mode="basic",
                )

                probe_tos = config.probe_tos_for_session_path(session.name, path_name)
                udp_probe = await run_udp_probe_async(
                    host=client,
                    client_script_path=client_script_path,
                    dst_ip=server_ip,
                    udp_port=config.probe_service.udp_port,
                    tos=probe_tos,
                    count=1,
                    timeout_s=config.closed_loop.probe_timeout_s,
                    mode="basic",
                )

                row = {
                    "session": session.name,
                    "client_host": session.client_host,
                    "server_host": session.server_host,
                    "server_ip": server_ip,
                    "bgp_allowed_paths": ",".join(allowed),
                    "tested_path": path_name,
                    "initial_path": initial_path_by_session.get(session.name),
                    "client_ping_success": client_ping.get("success"),
                    "client_ping_loss_pct": client_ping.get("loss_pct"),
                    "server_ping_success": server_ping.get("success"),
                    "server_ping_loss_pct": server_ping.get("loss_pct"),
                    "source_router": source_router_name,
                    "source_router_ping_success": source_ping.get("success"),
                    "dest_router": dest_router_name,
                    "dest_router_ping_success": dest_ping.get("success"),
                    "transit_router": transit_router_name,
                    "transit_router_ping_success": None if transit_ping is None else transit_ping.get("success"),
                    "udp_traffic_avg_ms": udp_traffic.get("avg_ms"),
                    "udp_traffic_loss_pct": udp_traffic.get("loss_pct"),
                    "udp_probe_avg_ms": udp_probe.get("avg_ms"),
                    "udp_probe_loss_pct": udp_probe.get("loss_pct"),
                    "suspected_breakpoint": classify_breakpoint(
                        client_ping=client_ping,
                        source_ping=source_ping,
                        dest_ping=dest_ping,
                        transit_ping=transit_ping,
                        udp_ok=(udp_traffic.get("loss_pct", 100.0) < 100.0),
                    ),
                }
                rows.append(row)

                # Save raw outputs for this path-specific test
                write_text(raw_dir / f"{session.name}__{path_name}__client_ping.txt", client_ping["output"])
                write_text(raw_dir / f"{session.name}__{path_name}__server_ping.txt", server_ping["output"])
                if source_router is not None:
                    write_text(raw_dir / f"{session.name}__{path_name}__source_ping.txt", source_ping["output"])
                if dest_router is not None:
                    write_text(raw_dir / f"{session.name}__{path_name}__dest_ping.txt", dest_ping["output"])
                if transit_ping is not None:
                    write_text(raw_dir / f"{session.name}__{path_name}__transit_ping.txt", transit_ping["output"])
                write_text(raw_dir / f"{session.name}__{path_name}__udp_traffic.json", json.dumps(udp_traffic, indent=2))
                write_text(raw_dir / f"{session.name}__{path_name}__udp_probe.json", json.dumps(udp_probe, indent=2))

        ensure_parent_dirs(str(csv_path))
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["session"])
            writer.writeheader()
            writer.writerows(rows)

        success_rows = [r for r in rows if (r.get("udp_traffic_loss_pct") is not None and float(r["udp_traffic_loss_pct"]) < 100.0)]
        summary = {
            "topology_name": config.topology_name,
            "session_count": len(config.traffic_sessions),
            "tested_session_path_pairs": len(rows),
            "successful_udp_pairs": len(success_rows),
            "failed_udp_pairs": len(rows) - len(success_rows),
            "csv_path": str(csv_path),
            "raw_dir": str(raw_dir),
        }
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        LOGGER.info("Wrote BGP diagnosis outputs to %s", results_dir)

    finally:
        _stop_udp_servers(server_processes)
        await controller.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diagnose BGP-aware dataplane failures hop by hop")
    parser.add_argument("--config", default=os.path.join(REPOSITORY_DIRECTORY, "config/run_config_bgp_generalized.json"))
    parser.add_argument("--results-dir", default=os.path.join(REPOSITORY_DIRECTORY, "results/bgp_diagnose"))
    parser.add_argument("--warmup-s", type=float, default=12.0)
    parser.add_argument("--bgp-wait-timeout-s", type=float, default=45.0)
    parser.add_argument("--bgp-poll-s", type=float, default=2.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging()
    setLogLevel("info")
    config = RunConfig.load(args.config)
    topology_class = load_topology_class(config.topology_name)
    network = Mininet(topo=topology_class(), link=TCLink, controller=None, autoSetMacs=False)
    network.start()
    try:
        asyncio.run(async_main(args, network, config))
    finally:
        network.stop()


if __name__ == "__main__":
    main()
