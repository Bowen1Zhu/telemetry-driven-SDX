#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import pathlib
import statistics
import subprocess
import sys
import time
from typing import Any

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, "../"))

sys.path.append(REPOSITORY_DIRECTORY)

from controller.sdx_controller import SdxController, RunConfig
from networks.sdx_run.mininet.networks import Topology

LOGGER = logging.getLogger("sdx_run")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SDX code")
    parser.add_argument(
        "--config",
        default=os.path.join(REPOSITORY_DIRECTORY, "config/run_config.json"),
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
        "--telemetry-mode",
        choices=["mode1", "mode2", "mode3"],
        default=None,
        help="Override telemetry mode from the config file",
    )
    parser.add_argument(
        "--warmup-s",
        type=float,
        default=15.0,
        help="Seconds to wait for FRR/BGP and basic MAC learning before probing",
    )
    parser.add_argument(
        "--results-dir",
        default=os.path.join(REPOSITORY_DIRECTORY, "results"),
        help="Directory for csv and json",
    )
    return parser.parse_args()


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def ensure_parent_dirs(path: str | pathlib.Path) -> None:
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)


def run_host_program_sync(host, argv: list[str], timeout_s: float | None = None) -> tuple[int, str, str]:
    process = host.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return -1, stdout, stderr
    return process.returncode, stdout, stderr


async def run_udp_probe_async(
    host,
    client_script_path: str,
    dst_ip: str,
    udp_port: int,
    tos: int,
    count: int,
    timeout_s: float,
    mode: str = "basic",
) -> dict[str, Any]:
    def _run() -> dict[str, Any]:
        argv = [
            "python3",
            client_script_path,
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
            "--mode",
            mode,
        ]
        returncode, stdout, stderr = run_host_program_sync(
            host,
            argv,
            timeout_s=max(timeout_s * count + 3.0, 6.0),
        )
        if returncode != 0:
            LOGGER.warning("Probe command failed on %s: rc=%s stderr=%s", host.name, returncode, stderr.strip())
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if not lines:
            return {
                "sent": count,
                "received": 0,
                "loss_pct": 100.0,
                "rtts_ms": [],
                "avg_ms": None,
                "min_ms": None,
                "max_ms": None,
                "aux_queue_avg": None,
                "aux_residence_ms": None,
                "aux_report_count": 0,
            }
        try:
            result = json.loads(lines[-1])
        except json.JSONDecodeError:
            LOGGER.warning("Unable to decode probe output from %s: %s", host.name, stdout)
            return {
                "sent": count,
                "received": 0,
                "loss_pct": 100.0,
                "rtts_ms": [],
                "avg_ms": None,
                "min_ms": None,
                "max_ms": None,
                "aux_queue_avg": None,
                "aux_residence_ms": None,
                "aux_report_count": 0,
            }
        result.setdefault("aux_queue_avg", None)
        result.setdefault("aux_residence_ms", None)
        result.setdefault("aux_report_count", 0)
        return result

    return await asyncio.to_thread(_run)


class ExperimentRunner:
    def __init__(
        self,
        network: Mininet,
        controller: SdxController,
        config: RunConfig,
        results_dir: str,
        telemetry_mode: str,
    ) -> None:
        self.network = network
        self.controller = controller
        self.config = config
        self.results_dir = results_dir
        self.telemetry_mode = telemetry_mode
        os.makedirs(self.results_dir, exist_ok=True)

        self.client_script_path = os.path.join(REPOSITORY_DIRECTORY, "scripts/udp_echo_client.py")
        self.server_script_path = os.path.join(REPOSITORY_DIRECTORY, "scripts/udp_echo_server.py")

        self.client_host = self.network.get(self.config.probe_service.client_host)
        self.server_host = self.network.get(self.config.probe_service.server_host)

        self._server_process = None
        self._event_index = 0
        self._events = sorted(self.config.experiment.get("events", []), key=lambda item: float(item["time_s"]))

        self.probe_tos_by_path = self.config.probe_tos_by_path
        self.ema_by_path: dict[str, float | None] = {path_name: None for path_name in self.probe_tos_by_path}
        self.active_path = self.controller.group_current_path.get("traffic_forward", "slow")
        self.last_switch_time = time.monotonic()
        self.path_changes: list[dict[str, Any]] = []
        self.rows: list[dict[str, Any]] = []

        self.csv_path = os.path.join(self.results_dir, "latest_run.csv")
        self.summary_path = os.path.join(self.results_dir, "latest_summary.json")

    def start_servers(self) -> None:
        if self._server_process is not None:
            return
        self._server_process = self.server_host.popen(
            [
                "python3",
                self.server_script_path,
                "--port",
                str(self.config.probe_service.udp_port),
                "--int-port",
                str(self.config.probe_service.int_udp_port),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        LOGGER.info("Started UDP echo server on %s (ports %s/%s)", self.server_host.name, self.config.probe_service.udp_port, self.config.probe_service.int_udp_port)

    def stop_servers(self) -> None:
        if self._server_process is None:
            return
        self._server_process.terminate()
        try:
            self._server_process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self._server_process.kill()
            self._server_process.wait(timeout=2.0)
        self._server_process = None

    def warm_up(self) -> None:
        self.client_host.cmd("ping -c 1 -W 1 8.1.2.101 >/dev/null 2>&1 || true")
        self.server_host.cmd("ping -c 1 -W 1 8.1.1.101 >/dev/null 2>&1 || true")

    def _set_interface_delay(self, node_name: str, interface_name: str, delay_ms: int) -> None:
        node = self.network.get(node_name)
        if delay_ms <= 0:
            node.cmd(f"tc qdisc del dev {interface_name} root >/dev/null 2>&1 || true")
        else:
            node.cmd(f"tc qdisc replace dev {interface_name} root netem delay {delay_ms}ms")

    def set_path_extra_delay(self, path_name: str, delay_ms: int) -> None:
        for link_endpoint in self.config.path_links.get(path_name, ()):  # empty tuple if missing
            self._set_interface_delay(
                node_name=link_endpoint["node"],
                interface_name=link_endpoint["interface"],
                delay_ms=delay_ms,
            )

    def apply_due_events(self, elapsed_s: float) -> list[str]:
        event_messages: list[str] = []
        while self._event_index < len(self._events):
            event = self._events[self._event_index]
            if float(event["time_s"]) > elapsed_s:
                break
            self._event_index += 1

            if event["type"] == "set_path_extra_delay":
                path_name = str(event["path"])
                delay_ms = int(event["delay_ms"])
                self.set_path_extra_delay(path_name, delay_ms)
                event_messages.append(f"set_path_extra_delay(path={path_name}, delay_ms={delay_ms})")
            else:
                event_messages.append(f"unknown_event({event})")
        return event_messages

    async def probe_path(self, path_name: str) -> dict[str, Any]:
        if self.telemetry_mode == "mode3":
            result = await run_udp_probe_async(
                host=self.client_host,
                client_script_path=self.client_script_path,
                dst_ip=self.config.probe_service.server_ip,
                udp_port=self.config.probe_service.int_udp_port,
                tos=self.probe_tos_by_path[path_name],
                count=self.config.closed_loop.probe_count,
                timeout_s=self.config.closed_loop.probe_timeout_s,
                mode="int",
            )
            return result

        probe_start = time.monotonic()
        result = await run_udp_probe_async(
            host=self.client_host,
            client_script_path=self.client_script_path,
            dst_ip=self.config.probe_service.server_ip,
            udp_port=self.config.probe_service.udp_port,
            tos=self.probe_tos_by_path[path_name],
            count=self.config.closed_loop.probe_count,
            timeout_s=self.config.closed_loop.probe_timeout_s,
            mode="basic",
        )

        if self.telemetry_mode == "mode2":
            await asyncio.sleep(self.config.telemetry.sampling.drain_wait_s)
            sampling = self.controller.get_sampling_summary(path_name, probe_start)
            result["aux_queue_avg"] = sampling["avg_queue_depth"]
            result["aux_residence_ms"] = sampling["avg_residence_ms"]
            result["aux_report_count"] = sampling["report_count"]
            result["aux_switches"] = sampling["switches"]
        return result

    async def measure_traffic(self) -> dict[str, Any]:
        return await run_udp_probe_async(
            host=self.client_host,
            client_script_path=self.client_script_path,
            dst_ip=self.config.probe_service.server_ip,
            udp_port=self.config.probe_service.udp_port,
            tos=self.config.probe_service.traffic_tos,
            count=self.config.closed_loop.probe_count,
            timeout_s=self.config.closed_loop.probe_timeout_s,
            mode="basic",
        )

    def _telemetry_weights(self) -> tuple[float, float]:
        if self.telemetry_mode == "mode2":
            return (
                self.config.telemetry.sampling.queue_weight,
                self.config.telemetry.sampling.residence_weight,
            )
        if self.telemetry_mode == "mode3":
            return (
                self.config.telemetry.int_mode.queue_weight,
                self.config.telemetry.int_mode.residence_weight,
            )
        return (0.0, 0.0)

    def _score_result_ms(self, result: dict[str, Any]) -> float:
        avg_ms = result.get("avg_ms")
        if avg_ms is None:
            return 10_000.0

        score = float(avg_ms) + (5.0 * float(result.get("loss_pct", 0.0)))
        queue_weight, residence_weight = self._telemetry_weights()
        aux_queue = result.get("aux_queue_avg")
        aux_residence = result.get("aux_residence_ms")
        if aux_queue is not None:
            score += queue_weight * float(aux_queue)
        if aux_residence is not None:
            score += residence_weight * float(aux_residence)
        return score

    def update_emas(self, probe_results: dict[str, dict[str, Any]]) -> None:
        alpha = self.config.closed_loop.ema_alpha
        for path_name, result in probe_results.items():
            sample = self._score_result_ms(result)
            current = self.ema_by_path[path_name]
            self.ema_by_path[path_name] = sample if current is None else (alpha * sample + (1.0 - alpha) * current)

    def _score(self, candidate_path: str) -> float:
        base = self.ema_by_path[candidate_path]
        if base is None:
            return float("inf")
        if candidate_path != self.active_path:
            base += self.config.closed_loop.switch_penalty_ms
        return base

    async def maybe_switch(self, elapsed_s: float) -> str | None:
        if any(value is None for value in self.ema_by_path.values()):
            return None

        best_path = min(self.ema_by_path, key=self._score)
        if best_path == self.active_path:
            return None

        current_score = self._score(self.active_path)
        best_score = self._score(best_path)
        improvement_ms = current_score - best_score
        hold_down_elapsed = time.monotonic() - self.last_switch_time

        if improvement_ms < self.config.closed_loop.min_improvement_ms:
            return None
        if hold_down_elapsed < self.config.closed_loop.hold_down_s:
            return None

        await self.controller.set_traffic_path(best_path)
        self.active_path = best_path
        self.last_switch_time = time.monotonic()
        event = {
            "time_s": round(elapsed_s, 3),
            "new_path": best_path,
            "improvement_ms": round(improvement_ms, 3),
        }
        self.path_changes.append(event)
        LOGGER.info("Closed-loop switch -> %s (improvement %.2f ms)", best_path, improvement_ms)
        return best_path

    def write_csv(self) -> None:
        ensure_parent_dirs(self.csv_path)
        fieldnames = [
            "elapsed_s",
            "event",
            "telemetry_mode",
            "active_path",
            "switched_to",
            "traffic_avg_ms",
            "traffic_loss_pct",
            "slow_probe_avg_ms",
            "slow_probe_loss_pct",
            "slow_probe_score_ms",
            "slow_aux_queue_avg",
            "slow_aux_residence_ms",
            "slow_aux_report_count",
            "fast_probe_avg_ms",
            "fast_probe_loss_pct",
            "fast_probe_score_ms",
            "fast_aux_queue_avg",
            "fast_aux_residence_ms",
            "fast_aux_report_count",
        ]
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
            "telemetry_mode": self.telemetry_mode,
            "final_active_path": self.active_path,
            "path_changes": self.path_changes,
            "overall_mean_traffic_ms": (statistics.mean(traffic_values) if traffic_values else None),
            "mean_traffic_ms_fast": (statistics.mean(traffic_fast) if traffic_fast else None),
            "mean_traffic_ms_slow": (statistics.mean(traffic_slow) if traffic_slow else None),
            "csv_path": self.csv_path,
        }
        ensure_parent_dirs(self.summary_path)
        with open(self.summary_path, "w", encoding="utf-8") as summary_file:
            json.dump(summary, summary_file, indent=2)

    def _build_closed_loop_row(
        self,
        elapsed_s: float,
        event_messages: list[str],
        switched_to: str | None,
        traffic_result: dict[str, Any],
        probe_results: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "elapsed_s": round(elapsed_s, 3),
            "event": "; ".join(event_messages) if event_messages else None,
            "telemetry_mode": self.telemetry_mode,
            "active_path": self.active_path,
            "switched_to": switched_to,
            "traffic_avg_ms": traffic_result.get("avg_ms"),
            "traffic_loss_pct": traffic_result.get("loss_pct"),
            "slow_probe_avg_ms": probe_results["slow"].get("avg_ms"),
            "slow_probe_loss_pct": probe_results["slow"].get("loss_pct"),
            "slow_probe_score_ms": self._score_result_ms(probe_results["slow"]),
            "slow_aux_queue_avg": probe_results["slow"].get("aux_queue_avg"),
            "slow_aux_residence_ms": probe_results["slow"].get("aux_residence_ms"),
            "slow_aux_report_count": probe_results["slow"].get("aux_report_count"),
            "fast_probe_avg_ms": probe_results["fast"].get("avg_ms"),
            "fast_probe_loss_pct": probe_results["fast"].get("loss_pct"),
            "fast_probe_score_ms": self._score_result_ms(probe_results["fast"]),
            "fast_aux_queue_avg": probe_results["fast"].get("aux_queue_avg"),
            "fast_aux_residence_ms": probe_results["fast"].get("aux_residence_ms"),
            "fast_aux_report_count": probe_results["fast"].get("aux_report_count"),
        }

    async def run_static(self, fixed_path: str) -> None:
        await self.controller.set_traffic_path(fixed_path)
        self.active_path = fixed_path
        result = await self.measure_traffic()
        row = {
            "elapsed_s": 0.0,
            "event": f"fixed_path={fixed_path}",
            "telemetry_mode": self.telemetry_mode,
            "active_path": fixed_path,
            "switched_to": None,
            "traffic_avg_ms": result.get("avg_ms"),
            "traffic_loss_pct": result.get("loss_pct"),
            "slow_probe_avg_ms": None,
            "slow_probe_loss_pct": None,
            "slow_probe_score_ms": None,
            "slow_aux_queue_avg": None,
            "slow_aux_residence_ms": None,
            "slow_aux_report_count": None,
            "fast_probe_avg_ms": None,
            "fast_probe_loss_pct": None,
            "fast_probe_score_ms": None,
            "fast_aux_queue_avg": None,
            "fast_aux_residence_ms": None,
            "fast_aux_report_count": None,
        }
        self.rows.append(row)
        self.write_csv()
        self.write_summary()
        LOGGER.info(
            "Fixed run finished: pinned=%s traffic_avg_ms=%s loss_pct=%s",
            fixed_path,
            result.get("avg_ms"),
            result.get("loss_pct"),
        )

    async def run_closed_loop(self) -> None:
        duration_s = float(self.config.experiment.get("duration_s", 55.0))
        interval_s = self.config.closed_loop.probe_interval_s

        await self.controller.set_traffic_path("slow")
        self.active_path = "slow"
        self.last_switch_time = time.monotonic() - self.config.closed_loop.hold_down_s

        start_time = time.monotonic()
        next_tick = start_time

        while True:
            now = time.monotonic()
            elapsed_s = now - start_time
            if elapsed_s > duration_s:
                break

            event_messages = self.apply_due_events(elapsed_s)
            probe_results = {
                path_name: await self.probe_path(path_name)
                for path_name in sorted(self.probe_tos_by_path)
            }
            self.update_emas(probe_results)
            switched_to = await self.maybe_switch(elapsed_s)
            traffic_result = await self.measure_traffic()

            row = self._build_closed_loop_row(
                elapsed_s=elapsed_s,
                event_messages=event_messages,
                switched_to=switched_to,
                traffic_result=traffic_result,
                probe_results=probe_results,
            )
            self.rows.append(row)
            self.write_csv()

            LOGGER.info(
                "t=%.1fs mode=%s active=%s prod=%.2fms slow=%.2fms fast=%.2fms%s",
                elapsed_s,
                self.telemetry_mode,
                self.active_path,
                -1.0 if row["traffic_avg_ms"] is None else float(row["traffic_avg_ms"]),
                -1.0 if row["slow_probe_avg_ms"] is None else float(row["slow_probe_avg_ms"]),
                -1.0 if row["fast_probe_avg_ms"] is None else float(row["fast_probe_avg_ms"]),
                " switched" if switched_to else "",
            )

            next_tick += interval_s
            sleep_s = max(0.0, next_tick - time.monotonic())
            await asyncio.sleep(sleep_s)

        self.write_summary()
        LOGGER.info("Closed-loop run finished; results written to %s and %s", self.csv_path, self.summary_path)


async def async_main(args: argparse.Namespace, network: Mininet) -> None:
    config = RunConfig.load(args.config)
    telemetry_mode = args.telemetry_mode or config.telemetry.mode
    build_dir = os.path.join(REPOSITORY_DIRECTORY, "build/p4")
    controller = SdxController(
        config_path=args.config,
        p4info_path=os.path.join(build_dir, "sdx_ixp.p4info.txtpb"),
        p4blob_path=os.path.join(build_dir, "sdx_ixp.json"),
    )

    runner = ExperimentRunner(
        network=network,
        controller=controller,
        config=config,
        results_dir=args.results_dir,
        telemetry_mode=telemetry_mode,
    )

    try:
        await controller.start()
        await controller.wait_until_ready(timeout_s=30.0)

        LOGGER.info("Waiting %.1fs for FRR/BGP warm-up", args.warmup_s)
        await asyncio.sleep(args.warmup_s)
        runner.warm_up()
        runner.start_servers()
        await asyncio.sleep(1.0)

        if args.mode == "fixed":
            await runner.run_static(args.fixed_path)
        else:
            await runner.run_closed_loop()
    finally:
        runner.stop_servers()
        await controller.stop()


def main() -> None:
    args = parse_args()
    configure_logging()
    setLogLevel("info")

    topology = Topology()
    network = Mininet(topo=topology, link=TCLink, autoSetMacs=False)

    LOGGER.info("Starting Mininet network")
    network.start()
    try:
        asyncio.run(async_main(args, network))
    finally:
        LOGGER.info("Stopping Mininet network")
        network.stop()


if __name__ == "__main__":
    main()
