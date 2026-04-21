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
import time
from typing import Any

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
REPO_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "../"))

sys.path.append(REPO_DIR)

from controller.sdx_controller import SdxController
from networks.sdx_run.mininet.networks import Topology

LOG = logging.getLogger("sdx_run")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SDX code")
    parser.add_argument(
        "--config",
        default=os.path.join(REPO_DIR, "config/run_config.json"),
        help="Path to the json config file",
    )
    parser.add_argument(
        "--mode",
        choices=["closed-loop", "fixed"],
        default="closed-loop",
        help="Run the closed-loop controller or a fixed-path baseline",
    )
    parser.add_argument(
        "--fixed-path",
        choices=["slow", "fast"],
        default="slow",
        help="Path to use when --mode=fixed",
    )
    parser.add_argument(
        "--warmup-s",
        type=float,
        default=15.0,
        help="Seconds to wait for FRR/BGP and basic MAC learning before probing",
    )
    parser.add_argument(
        "--results-dir",
        default=os.path.join(REPO_DIR, "results"),
        help="Directory for csv and json output",
    )
    return parser.parse_args()


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def empty_probe_result(count: int) -> dict[str, Any]:
    return {
        "sent": count,
        "received": 0,
        "loss_pct": 100.0,
        "rtts_ms": [],
        "avg_ms": None,
        "min_ms": None,
        "max_ms": None,
    }


def run_on_host(host, argv: list[str], timeout_s: float | None = None) -> tuple[int, str, str]:
    process = host.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return -1, stdout, stderr
    return process.returncode, stdout, stderr


async def run_probe(host, client_script: str, dst_ip: str, udp_port: int, tos: int, count: int, timeout_s: float) -> dict[str, Any]:
    def _run() -> dict[str, Any]:
        argv = [
            "python3",
            client_script,
            "--dst",
            dst_ip,
            "--port",
            str(udp_port),
            "--count",
            str(count),
            "--timeout",
            str(timeout_s),
            "--tos",
            str(tos),
        ]
        rc, stdout, stderr = run_on_host(host, argv, timeout_s=max(timeout_s * count + 2.0, 5.0))
        if rc != 0:
            LOG.warning("Probe command failed on %s: rc=%s stderr=%s", host.name, rc, stderr.strip())

        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if not lines:
            return empty_probe_result(count)

        try:
            return json.loads(lines[-1])
        except json.JSONDecodeError:
            LOG.warning("Unable to decode probe output from %s: %s", host.name, stdout)
            return empty_probe_result(count)

    return await asyncio.to_thread(_run)


class Runner:
    def __init__(self, network: Mininet, controller: SdxController, config: RunConfig, results_dir: str) -> None:
        self.network = network
        self.controller = controller
        self.config = config
        self.results_dir = results_dir
        os.makedirs(self.results_dir, exist_ok=True)

        self.client_script = os.path.join(REPO_DIR, "scripts/udp_echo_client.py")
        self.server_script = os.path.join(REPO_DIR, "scripts/udp_echo_server.py")
        self.client = network.get(config.probe.client_host)
        self.server = network.get(config.probe.server_host)

        self.server_process = None
        self.events = sorted(config.run.get("events", []), key=lambda item: float(item["time_s"]))
        self.event_index = 0

        self.probe_tos = config.probe_tos_by_path
        self.ema = {path_name: None for path_name in self.probe_tos}
        self.active_path = controller.group_current_path.get("traffic_forward", "slow")
        self.last_switch_time = time.monotonic()
        self.path_changes: list[dict[str, Any]] = []
        self.rows: list[dict[str, Any]] = []

        self.csv_path = os.path.join(results_dir, "latest_run.csv")
        self.summary_path = os.path.join(results_dir, "latest_summary.json")

    def start_server(self) -> None:
        if self.server_process is not None:
            return
        self.server_process = self.server.popen(
            ["python3", self.server_script, "--port", str(self.config.probe.udp_port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        LOG.info("Started UDP echo server on %s", self.server.name)

    def stop_server(self) -> None:
        if self.server_process is None:
            return
        self.server_process.terminate()
        try:
            self.server_process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self.server_process.kill()
            self.server_process.wait(timeout=2.0)
        self.server_process = None

    def warm_up(self) -> None:
        self.client.cmd("ping -c 1 -W 1 8.1.2.101 >/dev/null 2>&1 || true")
        self.server.cmd("ping -c 1 -W 1 8.1.1.101 >/dev/null 2>&1 || true")

    def _set_delay(self, node_name: str, ifname: str, delay_ms: int) -> None:
        node = self.network.get(node_name)
        if delay_ms <= 0:
            node.cmd(f"tc qdisc del dev {ifname} root >/dev/null 2>&1 || true")
        else:
            node.cmd(f"tc qdisc replace dev {ifname} root netem delay {delay_ms}ms")

    def set_path_delay(self, path_name: str, delay_ms: int) -> None:
        for item in self.config.path_links.get(path_name, ()):  # empty tuple if missing
            self._set_delay(item["node"], item["interface"], delay_ms)
        LOG.info("Applied extra delay of %sms to path %s", delay_ms, path_name)

    def apply_events(self, elapsed_s: float) -> list[str]:
        messages: list[str] = []
        while self.event_index < len(self.events) and float(self.events[self.event_index]["time_s"]) <= elapsed_s:
            event = self.events[self.event_index]
            self.event_index += 1
            if event.get("type") == "set_path_extra_delay":
                self.set_path_delay(str(event["path"]), int(event["delay_ms"]))
                messages.append(f"set_path_extra_delay(path={event['path']}, delay_ms={event['delay_ms']})")
            else:
                messages.append(f"unknown_event({event})")
        return messages

    async def probe_path(self, path_name: str) -> dict[str, Any]:
        return await run_probe(
            self.client,
            self.client_script,
            self.config.probe.server_ip,
            self.config.probe.udp_port,
            self.probe_tos[path_name],
            self.config.closed_loop.probe_count,
            self.config.closed_loop.probe_timeout_s,
        )

    async def measure_traffic(self) -> dict[str, Any]:
        return await run_probe(
            self.client,
            self.client_script,
            self.config.probe.server_ip,
            self.config.probe.udp_port,
            self.config.probe.traffic_tos,
            self.config.closed_loop.probe_count,
            self.config.closed_loop.probe_timeout_s,
        )

    @staticmethod
    def effective_ms(result: dict[str, Any]) -> float:
        avg_ms = result.get("avg_ms")
        if avg_ms is None:
            return 10_000.0
        return float(avg_ms) + (5.0 * float(result.get("loss_pct", 0.0)))

    def update_emas(self, probe_results: dict[str, dict[str, Any]]) -> None:
        alpha = self.config.closed_loop.ema_alpha
        for path_name, result in probe_results.items():
            sample = self.effective_ms(result)
            current = self.ema[path_name]
            self.ema[path_name] = sample if current is None else (alpha * sample + (1.0 - alpha) * current)

    def score(self, path_name: str) -> float:
        score = self.ema[path_name]
        if score is None:
            return float("inf")
        if path_name != self.active_path:
            score += self.config.closed_loop.switch_penalty_ms
        return score

    async def maybe_switch(self, elapsed_s: float) -> str | None:
        if any(value is None for value in self.ema.values()):
            return None

        best_path = min(self.ema, key=self.score)
        if best_path == self.active_path:
            return None

        improvement_ms = self.score(self.active_path) - self.score(best_path)
        if improvement_ms < self.config.closed_loop.min_improvement_ms:
            return None
        if (time.monotonic() - self.last_switch_time) < self.config.closed_loop.hold_down_s:
            return None

        await self.controller.set_traffic_path(best_path)
        self.active_path = best_path
        self.last_switch_time = time.monotonic()
        self.path_changes.append(
            {
                "time_s": round(elapsed_s, 3),
                "new_path": best_path,
                "improvement_ms": round(improvement_ms, 3),
            }
        )
        LOG.info("Closed-loop switch -> %s (improvement %.2f ms)", best_path, improvement_ms)
        return best_path

    def write_csv(self) -> None:
        fieldnames = [
            "elapsed_s",
            "event",
            "active_path",
            "switched_to",
            "traffic_avg_ms",
            "traffic_loss_pct",
            "slow_probe_avg_ms",
            "slow_probe_loss_pct",
            "fast_probe_avg_ms",
            "fast_probe_loss_pct",
        ]
        os.makedirs(os.path.dirname(self.csv_path), exist_ok=True)
        with open(self.csv_path, "w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.rows)

    def write_summary(self) -> None:
        traffic_values = [float(row["traffic_avg_ms"]) for row in self.rows if row.get("traffic_avg_ms") is not None]
        traffic_fast = [
            float(row["traffic_avg_ms"])
            for row in self.rows
            if row.get("traffic_avg_ms") is not None and row.get("active_path") == "fast"
        ]
        traffic_slow = [
            float(row["traffic_avg_ms"])
            for row in self.rows
            if row.get("traffic_avg_ms") is not None and row.get("active_path") == "slow"
        ]
        summary = {
            "final_active_path": self.active_path,
            "path_changes": self.path_changes,
            "overall_mean_traffic_ms": statistics.mean(traffic_values) if traffic_values else None,
            "mean_traffic_ms_fast": statistics.mean(traffic_fast) if traffic_fast else None,
            "mean_traffic_ms_slow": statistics.mean(traffic_slow) if traffic_slow else None,
            "csv_path": self.csv_path,
        }
        os.makedirs(os.path.dirname(self.summary_path), exist_ok=True)
        with open(self.summary_path, "w", encoding="utf-8") as summary_file:
            json.dump(summary, summary_file, indent=2)

    async def run_fixed(self, fixed_path: str) -> None:
        await self.controller.set_traffic_path(fixed_path)
        self.active_path = fixed_path
        result = await self.measure_traffic()
        self.rows.append(
            {
                "elapsed_s": 0.0,
                "event": f"fixed_path={fixed_path}",
                "active_path": fixed_path,
                "switched_to": None,
                "traffic_avg_ms": result.get("avg_ms"),
                "traffic_loss_pct": result.get("loss_pct"),
                "slow_probe_avg_ms": None,
                "slow_probe_loss_pct": None,
                "fast_probe_avg_ms": None,
                "fast_probe_loss_pct": None,
            }
        )
        self.write_csv()
        self.write_summary()
        LOG.info(
            "Fixed run finished: fixed_path=%s traffic_avg_ms=%s loss_pct=%s",
            fixed_path,
            result.get("avg_ms"),
            result.get("loss_pct"),
        )

    async def run_closed_loop(self) -> None:
        duration_s = float(self.config.run.get("duration_s", 55.0))
        interval_s = self.config.closed_loop.probe_interval_s

        await self.controller.set_traffic_path("slow")
        self.active_path = "slow"
        self.last_switch_time = time.monotonic() - self.config.closed_loop.hold_down_s

        start_time = time.monotonic()
        next_tick = start_time

        while True:
            elapsed_s = time.monotonic() - start_time
            if elapsed_s > duration_s:
                break

            messages = self.apply_events(elapsed_s)
            probe_results = {path_name: await self.probe_path(path_name) for path_name in sorted(self.probe_tos)}
            self.update_emas(probe_results)
            switched_to = await self.maybe_switch(elapsed_s)
            traffic_result = await self.measure_traffic()

            row = {
                "elapsed_s": round(elapsed_s, 3),
                "event": "; ".join(messages) if messages else None,
                "active_path": self.active_path,
                "switched_to": switched_to,
                "traffic_avg_ms": traffic_result.get("avg_ms"),
                "traffic_loss_pct": traffic_result.get("loss_pct"),
                "slow_probe_avg_ms": probe_results["slow"].get("avg_ms"),
                "slow_probe_loss_pct": probe_results["slow"].get("loss_pct"),
                "fast_probe_avg_ms": probe_results["fast"].get("avg_ms"),
                "fast_probe_loss_pct": probe_results["fast"].get("loss_pct"),
            }
            self.rows.append(row)
            self.write_csv()

            LOG.info(
                "t=%.1fs active=%s traffic=%.2fms slow=%.2fms fast=%.2fms%s",
                elapsed_s,
                self.active_path,
                -1.0 if row["traffic_avg_ms"] is None else float(row["traffic_avg_ms"]),
                -1.0 if row["slow_probe_avg_ms"] is None else float(row["slow_probe_avg_ms"]),
                -1.0 if row["fast_probe_avg_ms"] is None else float(row["fast_probe_avg_ms"]),
                " switched" if switched_to else "",
            )

            next_tick += interval_s
            await asyncio.sleep(max(0.0, next_tick - time.monotonic()))

        self.write_summary()
        LOG.info("Closed-loop run finished; results written to %s and %s", self.csv_path, self.summary_path)


async def async_main(args: argparse.Namespace, network: Mininet) -> None:
    controller = SdxController(
        config_path=args.config,
        p4info_path=os.path.join(REPO_DIR, "build/p4/sdx_ixp.p4info.txtpb"),
        p4blob_path=os.path.join(REPO_DIR, "build/p4/sdx_ixp.json"),
    )
    runner = Runner(network, controller, controller.config, args.results_dir)

    try:
        await controller.start()
        await controller.wait_until_ready(timeout_s=30.0)

        LOG.info("Waiting %.1fs for FRR/BGP warm-up", args.warmup_s)
        await asyncio.sleep(args.warmup_s)
        runner.warm_up()
        runner.start_server()
        await asyncio.sleep(1.0)

        if args.mode == "fixed":
            await runner.run_fixed(args.fixed_path)
        else:
            await runner.run_closed_loop()
    finally:
        runner.stop_server()
        await controller.stop()


def main() -> None:
    args = parse_args()
    configure_logging()
    setLogLevel("info")

    network = Mininet(topo=Topology(), link=TCLink, autoSetMacs=False)
    LOG.info("Starting Mininet network")
    network.start()
    try:
        asyncio.run(async_main(args, network))
    finally:
        LOG.info("Stopping Mininet network")
        network.stop()


if __name__ == "__main__":
    main()
