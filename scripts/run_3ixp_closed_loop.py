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
from dataclasses import dataclass, field
from typing import Any

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, "../"))
sys.path.append(REPOSITORY_DIRECTORY)

from controller.sdx_controller import RunConfig, SdxController, TrafficSessionConfig  # noqa: E402
from networks import load_topology_class  # noqa: E402
from scripts.run_sdx import configure_logging, ensure_parent_dirs, run_udp_probe_async  # noqa: E402

LOGGER = logging.getLogger("sdx_3ixp_closed_loop")


@dataclass
class SessionState:
    session: TrafficSessionConfig
    allowed_paths: tuple[str, ...]
    active_path: str
    ema_by_path: dict[str, float | None] = field(default_factory=dict)
    last_switch_time: float = 0.0
    path_changes: list[dict[str, Any]] = field(default_factory=list)


class ThreeIxpClosedLoopRunner:
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
        self._server_processes: dict[str, Any] = {}
        self._event_index = 0
        self._events = sorted(self.config.experiment.get("events", []), key=lambda item: float(item["time_s"]))

        self.session_allowed_paths: dict[str, tuple[str, ...]] = {}
        for session in self.config.traffic_sessions:
            forward_group = next(group for group in self.config.traffic_groups if group.name == session.forward_group)
            self.session_allowed_paths[session.name] = tuple(forward_group.allowed_paths)

        # stable path order from ixp1 config
        self.path_names = tuple(self.config.switches["ixp1s1"].paths.keys())

        self.session_states: dict[str, SessionState] = {}
        for session in self.config.traffic_sessions:
            allowed = self.session_allowed_paths[session.name]
            initial = next(group for group in self.config.traffic_groups if group.name == session.forward_group).initial_path
            if initial not in allowed:
                initial = allowed[0]
            self.session_states[session.name] = SessionState(
                session=session,
                allowed_paths=allowed,
                active_path=self.controller.group_current_path.get(session.forward_group, initial),
                ema_by_path={path_name: None for path_name in allowed},
            )

        self.session_probe_tos: dict[str, dict[str, int]] = {
            session.name: {
                path_name: self.config.probe_tos_for_session_path(session.name, path_name)
                for path_name in self.session_allowed_paths[session.name]
            }
            for session in self.config.traffic_sessions
        }

        self.rows: list[dict[str, Any]] = []
        self.csv_path = os.path.join(self.results_dir, "latest_run.csv")
        self.summary_path = os.path.join(self.results_dir, "latest_summary.json")

    def start_servers(self) -> None:
        server_hosts = sorted({session.server_host for session in self.config.traffic_sessions})
        for host_name in server_hosts:
            if host_name in self._server_processes:
                continue
            host = self.network.get(host_name)
            process = host.popen(
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
            self._server_processes[host_name] = process
            LOGGER.info("Started UDP echo server on %s", host_name)

    def stop_servers(self) -> None:
        for process in self._server_processes.values():
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        self._server_processes.clear()

    def warm_up(self) -> None:
        for session in self.config.traffic_sessions:
            client = self.network.get(session.client_host)
            client.cmd(f"ping -c 1 -W 1 {session.server_ip} >/dev/null 2>&1 || true")

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

    def _telemetry_weights(self) -> tuple[float, float]:
        if self.telemetry_mode == "mode2":
            return (self.config.telemetry.sampling.queue_weight, self.config.telemetry.sampling.residence_weight)
        if self.telemetry_mode == "mode3":
            return (self.config.telemetry.int_mode.queue_weight, self.config.telemetry.int_mode.residence_weight)
        return (0.0, 0.0)

    def _hop_count(self, result: dict[str, Any]) -> int:
        value = result.get("hop_count")
        if value is None:
            return 0
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

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

    async def _run_probe_for_session_path(self, session: TrafficSessionConfig, path_name: str) -> tuple[float, dict[str, Any]]:
        host = self.network.get(session.client_host)
        udp_port = self.config.probe_service.int_udp_port if self.telemetry_mode == "mode3" else self.config.probe_service.udp_port
        mode = "int" if self.telemetry_mode == "mode3" else "basic"
        start_time = time.monotonic()
        result = await run_udp_probe_async(
            host=host,
            client_script_path=self.client_script_path,
            dst_ip=session.server_ip,
            udp_port=udp_port,
            tos=self.session_probe_tos[session.name][path_name],
            count=self.config.closed_loop.probe_count,
            timeout_s=self.config.closed_loop.probe_timeout_s,
            mode=mode,
        )
        return start_time, result

    async def collect_probe_results(self) -> dict[str, dict[str, dict[str, Any]]]:
        tasks: dict[tuple[str, str], asyncio.Task[tuple[float, dict[str, Any]]]] = {}
        for session in self.config.traffic_sessions:
            for path_name in self.session_allowed_paths[session.name]:
                tasks[(session.name, path_name)] = asyncio.create_task(self._run_probe_for_session_path(session, path_name))

        raw_results = await asyncio.gather(*tasks.values())
        combined: dict[str, dict[str, dict[str, Any]]] = {session.name: {} for session in self.config.traffic_sessions}
        timing: dict[tuple[str, str], float] = {}
        for (session_name, path_name), (start_time, result) in zip(tasks.keys(), raw_results):
            combined[session_name][path_name] = result
            timing[(session_name, path_name)] = start_time

        if self.telemetry_mode == "mode2":
            await asyncio.sleep(self.config.telemetry.sampling.drain_wait_s)
            for session in self.config.traffic_sessions:
                for path_name in self.session_allowed_paths[session.name]:
                    sampling = self.controller.get_sampling_summary_for_session_path(session.name, path_name, timing[(session.name, path_name)])
                    combined[session.name][path_name]["aux_queue_avg"] = sampling["avg_queue_depth"]
                    combined[session.name][path_name]["aux_residence_ms"] = sampling["avg_residence_ms"]
                    combined[session.name][path_name]["aux_report_count"] = sampling["report_count"]
                    combined[session.name][path_name]["aux_switches"] = sampling["switches"]
        return combined

    async def collect_traffic_results(self) -> dict[str, dict[str, Any]]:
        tasks: dict[str, asyncio.Task[dict[str, Any]]] = {}
        for session in self.config.traffic_sessions:
            host = self.network.get(session.client_host)
            tasks[session.name] = asyncio.create_task(
                run_udp_probe_async(
                    host=host,
                    client_script_path=self.client_script_path,
                    dst_ip=session.server_ip,
                    udp_port=self.config.probe_service.udp_port,
                    tos=session.traffic_tos,
                    count=self.config.closed_loop.probe_count,
                    timeout_s=self.config.closed_loop.probe_timeout_s,
                    mode="basic",
                )
            )
        values = await asyncio.gather(*tasks.values())
        return {session_name: result for session_name, result in zip(tasks.keys(), values)}

    def update_emas(self, probe_results: dict[str, dict[str, dict[str, Any]]]) -> None:
        alpha = self.config.closed_loop.ema_alpha
        for session_name, path_results in probe_results.items():
            state = self.session_states[session_name]
            for path_name, result in path_results.items():
                sample = self._score_result_ms(result)
                current = state.ema_by_path[path_name]
                state.ema_by_path[path_name] = sample if current is None else (alpha * sample + (1.0 - alpha) * current)

    def _score(self, state: SessionState, candidate_path: str) -> float:
        base = state.ema_by_path[candidate_path]
        if base is None:
            return float("inf")
        if candidate_path != state.active_path:
            base += self.config.closed_loop.switch_penalty_ms
        return base

    async def maybe_switch_session(self, state: SessionState, elapsed_s: float) -> str | None:
        if any(value is None for value in state.ema_by_path.values()):
            return None
        best_path = min(state.allowed_paths, key=lambda path_name: self._score(state, path_name))
        if best_path == state.active_path:
            return None

        current_score = self._score(state, state.active_path)
        best_score = self._score(state, best_path)
        improvement_ms = current_score - best_score
        hold_down_elapsed = time.monotonic() - state.last_switch_time

        if improvement_ms < self.config.closed_loop.min_improvement_ms:
            return None
        if hold_down_elapsed < self.config.closed_loop.hold_down_s:
            return None

        await self.controller.set_session_path(state.session.name, best_path)
        state.active_path = best_path
        state.last_switch_time = time.monotonic()
        event = {"time_s": round(elapsed_s, 3), "new_path": best_path, "improvement_ms": round(improvement_ms, 3)}
        state.path_changes.append(event)
        LOGGER.info("%s: closed-loop switch -> %s (improvement %.2f ms)", state.session.name, best_path, improvement_ms)
        return best_path

    def write_csv(self) -> None:
        ensure_parent_dirs(self.csv_path)
        fieldnames = [
            "elapsed_s", "event", "telemetry_mode", "session", "client_host", "server_host", "server_ip", "active_path", "switched_to", "traffic_avg_ms", "traffic_loss_pct",
        ]
        for path_name in self.path_names:
            fieldnames.extend([
                f"{path_name}_probe_avg_ms",
                f"{path_name}_probe_loss_pct",
                f"{path_name}_probe_score_ms",
                f"{path_name}_aux_queue_avg",
                f"{path_name}_aux_residence_ms",
                f"{path_name}_aux_report_count",
                f"{path_name}_aux_hop_count",
            ])
        with open(self.csv_path, "w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.rows)

    def write_summary(self) -> None:
        summary = {
            "topology_name": self.config.topology_name,
            "telemetry_mode": self.telemetry_mode,
            "path_names": list(self.path_names),
            "session_count": len(self.config.traffic_sessions),
            "csv_path": self.csv_path,
            "final_active_path_by_session": {},
            "path_changes_by_session": {},
            "mean_traffic_ms_by_session": {},
        }
        all_values: list[float] = []
        for session in self.config.traffic_sessions:
            session_rows = [row for row in self.rows if row["session"] == session.name and row.get("traffic_avg_ms") is not None]
            values = [float(row["traffic_avg_ms"]) for row in session_rows]
            if values:
                all_values.extend(values)
            summary["final_active_path_by_session"][session.name] = self.session_states[session.name].active_path
            summary["path_changes_by_session"][session.name] = self.session_states[session.name].path_changes
            summary["mean_traffic_ms_by_session"][session.name] = statistics.mean(values) if values else None
        summary["overall_mean_traffic_ms"] = statistics.mean(all_values) if all_values else None
        ensure_parent_dirs(self.summary_path)
        with open(self.summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)

    def _build_row(self, elapsed_s: float, event_messages: list[str], state: SessionState, switched_to: str | None, traffic_result: dict[str, Any], probe_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
        row = {
            "elapsed_s": round(elapsed_s, 3),
            "event": "; ".join(event_messages) if event_messages else None,
            "telemetry_mode": self.telemetry_mode,
            "session": state.session.name,
            "client_host": state.session.client_host,
            "server_host": state.session.server_host,
            "server_ip": state.session.server_ip,
            "active_path": state.active_path,
            "switched_to": switched_to,
            "traffic_avg_ms": traffic_result.get("avg_ms"),
            "traffic_loss_pct": traffic_result.get("loss_pct"),
        }
        for path_name in self.path_names:
            result = probe_results.get(path_name, {})
            row[f"{path_name}_probe_avg_ms"] = result.get("avg_ms")
            row[f"{path_name}_probe_loss_pct"] = result.get("loss_pct")
            row[f"{path_name}_probe_score_ms"] = self._score_result_ms(result) if result else None
            row[f"{path_name}_aux_queue_avg"] = result.get("aux_queue_avg")
            row[f"{path_name}_aux_residence_ms"] = result.get("aux_residence_ms")
            row[f"{path_name}_aux_report_count"] = result.get("aux_report_count")
            row[f"{path_name}_aux_hop_count"] = self._hop_count(result) if result else 0
        return row

    async def run_closed_loop(self) -> None:
        duration_s = float(self.config.experiment.get("duration_s", 55.0))
        interval_s = self.config.closed_loop.probe_interval_s

        # Start from each session's initial path.
        await asyncio.gather(*(self.controller.set_session_path(state.session.name, state.active_path) for state in self.session_states.values()))
        baseline = time.monotonic() - self.config.closed_loop.hold_down_s
        for state in self.session_states.values():
            state.last_switch_time = baseline

        start_time = time.monotonic()
        next_tick = start_time
        while True:
            now = time.monotonic()
            elapsed_s = now - start_time
            if elapsed_s > duration_s:
                break
            event_messages = self.apply_due_events(elapsed_s)
            probe_results = await self.collect_probe_results()
            self.update_emas(probe_results)
            switched_to: dict[str, str | None] = {}
            for session in self.config.traffic_sessions:
                state = self.session_states[session.name]
                switched_to[session.name] = await self.maybe_switch_session(state, elapsed_s)
            traffic_results = await self.collect_traffic_results()
            for session in self.config.traffic_sessions:
                state = self.session_states[session.name]
                row = self._build_row(elapsed_s, event_messages, state, switched_to[session.name], traffic_results[session.name], probe_results[session.name])
                self.rows.append(row)
            self.write_csv()
            active_summary = ", ".join(f"{s.name}:{self.session_states[s.name].active_path}" for s in self.config.traffic_sessions)
            LOGGER.info("t=%.1fs mode=%s active_paths=[%s]", elapsed_s, self.telemetry_mode, active_summary)
            next_tick += interval_s
            await asyncio.sleep(max(0.0, next_tick - time.monotonic()))
        self.write_summary()
        LOGGER.info("3-IXP closed-loop finished; results written to %s and %s", self.csv_path, self.summary_path)


async def async_main(args: argparse.Namespace, network: Mininet, config: RunConfig) -> None:
    telemetry_mode = args.telemetry_mode or config.telemetry.mode
    build_dir = os.path.join(REPOSITORY_DIRECTORY, "build/p4")
    controller = SdxController(
        config_path=args.config,
        p4info_path=os.path.join(build_dir, "sdx_ixp.p4info.txtpb"),
        p4blob_path=os.path.join(build_dir, "sdx_ixp.json"),
    )
    runner = ThreeIxpClosedLoopRunner(network, controller, config, args.results_dir, telemetry_mode)
    try:
        await controller.start()
        await controller.wait_until_ready(timeout_s=45.0)
        LOGGER.info("Waiting %.1fs for static routing warm-up", args.warmup_s)
        await asyncio.sleep(args.warmup_s)
        runner.warm_up()
        runner.start_servers()
        await asyncio.sleep(1.0)
        await runner.run_closed_loop()
    finally:
        runner.stop_servers()
        await controller.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run 3-IXP, 3-path generalized closed-loop SDX")
    parser.add_argument("--config", default=os.path.join(REPOSITORY_DIRECTORY, "config/run_config_3ixp.json"), help="Path to the 3-IXP json config file")
    parser.add_argument("--results-dir", default=os.path.join(REPOSITORY_DIRECTORY, "results/threeixp_closed_loop"), help="Directory for csv/json results")
    parser.add_argument("--telemetry-mode", choices=["mode1", "mode2", "mode3"], default=None, help="Override telemetry mode from config")
    parser.add_argument("--warmup-s", type=float, default=6.0, help="Seconds to wait for routing/ARP warm-up")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging()
    setLogLevel("info")
    config = RunConfig.load(args.config)
    topology_class = load_topology_class(config.topology_name)
    network = Mininet(topo=topology_class(), link=TCLink, autoSetMacs=False)
    LOGGER.info("Starting Mininet network for topology %s", config.topology_name)
    network.start()
    try:
        asyncio.run(async_main(args, network, config))
    finally:
        network.stop()
        LOGGER.info("Stopped Mininet network")


if __name__ == "__main__":
    main()
