#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import statistics
import subprocess
import sys
from typing import Any

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, "../"))
sys.path.append(REPOSITORY_DIRECTORY)

from controller.sdx_controller import RunConfig, SdxController  # noqa: E402
from networks import load_topology_class  # noqa: E402
from scripts.run_sdx import configure_logging, ensure_parent_dirs, run_udp_probe_async  # noqa: E402

LOGGER = logging.getLogger("sdx_3ixp_validate")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate 3-IXP / 3-path SDX steering")
    parser.add_argument("--config", default=os.path.join(REPOSITORY_DIRECTORY, "config/run_config_3ixp.json"), help="Path to the 3-IXP json config file")
    parser.add_argument("--results-dir", default=os.path.join(REPOSITORY_DIRECTORY, "results/threeixp_validation"), help="Directory for csv/json results")
    parser.add_argument("--warmup-s", type=float, default=6.0)
    parser.add_argument("--fast-max-ms", type=float, default=120.0)
    parser.add_argument("--medium-min-ms", type=float, default=120.0)
    parser.add_argument("--medium-max-ms", type=float, default=350.0)
    parser.add_argument("--slow-min-ms", type=float, default=350.0)
    return parser.parse_args()


class ThreeIxpValidationRunner:
    def __init__(self, network: Mininet, controller: SdxController, config: RunConfig, results_dir: str, fast_max_ms: float, medium_min_ms: float, medium_max_ms: float, slow_min_ms: float):
        self.network = network
        self.controller = controller
        self.config = config
        self.results_dir = results_dir
        self.fast_max_ms = fast_max_ms
        self.medium_min_ms = medium_min_ms
        self.medium_max_ms = medium_max_ms
        self.slow_min_ms = slow_min_ms
        os.makedirs(self.results_dir, exist_ok=True)
        self.client_script_path = os.path.join(REPOSITORY_DIRECTORY, "scripts/udp_echo_client.py")
        self.server_script_path = os.path.join(REPOSITORY_DIRECTORY, "scripts/udp_echo_server.py")
        self._server_processes: dict[str, Any] = {}
        self.rows: list[dict[str, Any]] = []
        self.csv_path = os.path.join(self.results_dir, "latest_run.csv")
        self.summary_path = os.path.join(self.results_dir, "latest_summary.json")

    def start_servers(self) -> None:
        server_hosts = sorted({session.server_host for session in self.config.traffic_sessions})
        for host_name in server_hosts:
            if host_name in self._server_processes:
                continue
            host = self.network.get(host_name)
            process = host.popen([
                "python3", self.server_script_path,
                "--port", str(self.config.probe_service.udp_port),
                "--int-port", str(self.config.probe_service.int_udp_port),
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self._server_processes[host_name] = process

    def stop_servers(self) -> None:
        for process in self._server_processes.values():
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2.0)
        self._server_processes.clear()

    def warm_up(self) -> None:
        for session in self.config.traffic_sessions:
            self.network.get(session.client_host).cmd(f"ping -c 1 -W 1 {session.server_ip} >/dev/null 2>&1 || true")

    async def apply_assignments(self, assignments: dict[str, str]) -> None:
        await asyncio.gather(*(self.controller.set_group_path(group_name, path_name) for group_name, path_name in assignments.items()))

    async def measure_session(self, session) -> dict[str, Any]:
        host = self.network.get(session.client_host)
        return await run_udp_probe_async(
            host=host,
            client_script_path=self.client_script_path,
            dst_ip=session.server_ip,
            udp_port=self.config.probe_service.udp_port,
            tos=session.traffic_tos,
            count=self.config.closed_loop.probe_count,
            timeout_s=self.config.closed_loop.probe_timeout_s,
            mode="basic",
        )

    def _pass_for_expected_path(self, expected_path: str, avg_ms: float | None) -> bool:
        if avg_ms is None:
            return False
        if expected_path == "fast":
            return avg_ms <= self.fast_max_ms
        if expected_path == "medium":
            return self.medium_min_ms <= avg_ms <= self.medium_max_ms
        return avg_ms >= self.slow_min_ms

    async def run_validation(self) -> None:
        for scenario in self.config.validation_scenarios:
            LOGGER.info("Applying validation scenario %s", scenario.name)
            await self.apply_assignments(scenario.assignments)
            await asyncio.sleep(1.0)
            results = await asyncio.gather(*(self.measure_session(session) for session in self.config.traffic_sessions))
            for session, result in zip(self.config.traffic_sessions, results):
                expected_path = scenario.assignments.get(session.forward_group, self.controller.group_current_path.get(session.forward_group, "unknown"))
                avg_ms = result.get("avg_ms")
                passed = self._pass_for_expected_path(expected_path, avg_ms)
                self.rows.append({
                    "scenario": scenario.name,
                    "description": scenario.description,
                    "session": session.name,
                    "client_host": session.client_host,
                    "server_host": session.server_host,
                    "server_ip": session.server_ip,
                    "traffic_tos": session.traffic_tos,
                    "forward_group": session.forward_group,
                    "reverse_group": session.reverse_group,
                    "expected_path": expected_path,
                    "avg_ms": avg_ms,
                    "loss_pct": result.get("loss_pct"),
                    "pass": passed,
                })

        self.write_csv(); self.write_summary()

    def write_csv(self) -> None:
        ensure_parent_dirs(self.csv_path)
        with open(self.csv_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["scenario","description","session","client_host","server_host","server_ip","traffic_tos","forward_group","reverse_group","expected_path","avg_ms","loss_pct","pass"])
            writer.writeheader(); writer.writerows(self.rows)

    def write_summary(self) -> None:
        scenarios: dict[str, dict[str, Any]] = {}
        for scenario in self.config.validation_scenarios:
            rows = [r for r in self.rows if r["scenario"] == scenario.name]
            pass_count = sum(1 for r in rows if r["pass"])
            scenarios[scenario.name] = {
                "description": scenario.description,
                "total_sessions": len(rows),
                "pass_count": pass_count,
                "fail_count": len(rows) - pass_count,
                "avg_rtt_ms": statistics.mean(float(r["avg_ms"]) for r in rows if r["avg_ms"] is not None) if rows else None,
            }
        summary = {
            "topology_name": self.config.topology_name,
            "scenario_count": len(self.config.validation_scenarios),
            "sessions_per_scenario": len(self.config.traffic_sessions),
            "fast_max_ms": self.fast_max_ms,
            "medium_min_ms": self.medium_min_ms,
            "medium_max_ms": self.medium_max_ms,
            "slow_min_ms": self.slow_min_ms,
            "csv_path": self.csv_path,
            "scenarios": scenarios,
        }
        ensure_parent_dirs(self.summary_path)
        with open(self.summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)


async def async_main(args: argparse.Namespace, network: Mininet, config: RunConfig) -> None:
    build_dir = os.path.join(REPOSITORY_DIRECTORY, "build/p4")
    controller = SdxController(config_path=args.config, p4info_path=os.path.join(build_dir, "sdx_ixp.p4info.txtpb"), p4blob_path=os.path.join(build_dir, "sdx_ixp.json"))
    runner = ThreeIxpValidationRunner(network, controller, config, args.results_dir, args.fast_max_ms, args.medium_min_ms, args.medium_max_ms, args.slow_min_ms)
    try:
        await controller.start(); await controller.wait_until_ready(timeout_s=45.0)
        await asyncio.sleep(args.warmup_s)
        runner.warm_up(); runner.start_servers(); await asyncio.sleep(1.0)
        await runner.run_validation()
    finally:
        runner.stop_servers(); await controller.stop()


def main() -> None:
    args = parse_args(); configure_logging(); setLogLevel("info")
    config = RunConfig.load(args.config)
    topology_class = load_topology_class(config.topology_name)
    network = Mininet(topo=topology_class(), link=TCLink, autoSetMacs=False)
    network.start()
    try:
        asyncio.run(async_main(args, network, config))
    finally:
        network.stop(); LOGGER.info("Stopped Mininet network")


if __name__ == "__main__":
    main()
