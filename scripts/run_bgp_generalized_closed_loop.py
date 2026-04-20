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
from dataclasses import dataclass, field
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
from scripts.queue_support import QueueScenarioManager
from scripts.run_sdx import configure_logging, ensure_parent_dirs, run_udp_probe_async

LOGGER = logging.getLogger("sdx_bgp_closed_loop")


@dataclass
class SessionState:
    session: TrafficSessionConfig
    active_path: str = "slow"
    ema_by_path: dict[str, float | None] = field(default_factory=lambda: {"slow": None, "fast": None})
    last_switch_time: float = 0.0
    path_changes: list[dict[str, Any]] = field(default_factory=list)


class BgpAwareClosedLoopRunner:
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

        self.session_states: dict[str, SessionState] = {
            session.name: SessionState(
                session=session,
                active_path=self.controller.group_current_path.get(session.forward_group, "slow"),
            )
            for session in self.config.traffic_sessions
        }
        self.session_probe_tos: dict[str, dict[str, int]] = {
            session.name: {
                path_name: self.config.probe_tos_for_session_path(session.name, path_name)
                for path_name in ("slow", "fast")
            }
            for session in self.config.traffic_sessions
        }
        self.group_by_name = {group.name: group for group in self.config.traffic_groups}

        self.rows: list[dict[str, Any]] = []
        self.csv_path = os.path.join(self.results_dir, "latest_run.csv")
        self.summary_path = os.path.join(self.results_dir, "latest_summary.json")
        self.queue_manager = QueueScenarioManager(
            network=self.network,
            repository_directory=REPOSITORY_DIRECTORY,
            experiment=self.config.experiment,
            logger=LOGGER,
        )
        self.bgp_tracker = BgpReachabilityTracker(network=self.network, config=self.config, logger=LOGGER)

    async def prepare_initial_paths(self) -> None:
        """Install the initial legal path for every session before warm-up traffic.

        This ensures that warm-up probes and traffic use the same forwarding state as
        the later closed-loop run, especially for sessions that are BGP-constrained to
        a single legal path.
        """
        baseline = time.monotonic()
        for session in self.config.traffic_sessions:
            allowed_paths = self.bgp_tracker.allowed_paths_for_session(session.name)
            if not allowed_paths:
                continue
            initial_path = allowed_paths[0]
            await self.controller.set_session_path(session.name, initial_path)
            state = self.session_states[session.name]
            state.active_path = initial_path
            state.last_switch_time = baseline
            state.ema_by_path = {"slow": None, "fast": None}

    async def prime_udp_paths(self) -> None:
        """Send one best-effort round of UDP traffic/probes to populate ARP/MAC state.

        The BGP-aware topology is more fragile than the earlier generalized topology.
        A short ignored warm-up round helps populate ARP, MAC learning, and the newly
        installed static /32 routes before we start recording measurements.
        """
        try:
            await self.collect_probe_results()
            await self.collect_traffic_results()
        except Exception as exc:
            LOGGER.warning("Initial UDP warm-up encountered %s: %r", type(exc).__name__, exc)

    def start_servers(self) -> None:
        self.queue_manager.start_sinks()
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
        self.queue_manager.stop_all_loads()
        self.queue_manager.stop_sinks()
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
            server = self.network.get(session.server_host)
            client_ip = self.group_by_name[session.forward_group].src_ip
            client.cmd(f"ping -c 2 -W 1 {session.server_ip} >/dev/null 2>&1 || true")
            server.cmd(f"ping -c 2 -W 1 {client_ip} >/dev/null 2>&1 || true")

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
            elif event["type"] == "start_path_congestion":
                path_name = str(event["path"])
                self.queue_manager.start_load(path_name)
                event_messages.append(f"start_path_congestion(path={path_name})")
            elif event["type"] == "stop_path_congestion":
                path_name = str(event["path"])
                self.queue_manager.stop_load(path_name)
                event_messages.append(f"stop_path_congestion(path={path_name})")
            else:
                event_messages.append(f"unknown_event({event})")
        return event_messages

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
        return (self.config.telemetry.base.queue_weight, 0.0)

    def _hop_count(self, result: dict[str, Any]) -> int:
        value = result.get("hop_count")
        if value is None:
            return 0
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _score_result_ms(self, result: dict[str, Any]) -> float | None:
        if result.get("bgp_reachable") is False:
            return None
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
        combined: dict[str, dict[str, dict[str, Any]]] = {
            session.name: {
                "slow": {"bgp_reachable": False, "aux_queue_avg": None, "aux_residence_ms": None, "aux_report_count": 0},
                "fast": {"bgp_reachable": False, "aux_queue_avg": None, "aux_residence_ms": None, "aux_report_count": 0},
            }
            for session in self.config.traffic_sessions
        }
        timing: dict[tuple[str, str], float] = {}

        for session in self.config.traffic_sessions:
            allowed_paths = set(self.bgp_tracker.allowed_paths_for_session(session.name))
            for path_name in ("slow", "fast"):
                combined[session.name][path_name]["bgp_reachable"] = path_name in allowed_paths
                if path_name in allowed_paths:
                    tasks[(session.name, path_name)] = asyncio.create_task(
                        self._run_probe_for_session_path(session, path_name)
                    )

        if tasks:
            raw_results = await asyncio.gather(*tasks.values())
            for (session_name, path_name), (start_time, result) in zip(tasks.keys(), raw_results):
                result["bgp_reachable"] = True
                combined[session_name][path_name].update(result)
                timing[(session_name, path_name)] = start_time

        if self.telemetry_mode == "mode2":
            await asyncio.sleep(self.config.telemetry.sampling.drain_wait_s)
            for session in self.config.traffic_sessions:
                allowed_paths = set(self.bgp_tracker.allowed_paths_for_session(session.name))
                for path_name in ("slow", "fast"):
                    if path_name not in allowed_paths:
                        continue
                    sampling = self.controller.get_sampling_summary_for_session_path(
                        session.name,
                        path_name,
                        timing[(session.name, path_name)],
                    )
                    combined[session.name][path_name]["aux_residence_ms"] = sampling["avg_residence_ms"]
                    combined[session.name][path_name]["aux_report_count"] = sampling["report_count"]
                    combined[session.name][path_name]["aux_switches"] = sampling["switches"]
        if self.queue_manager.enabled:
            queue_by_path = {path_name: self.queue_manager.queue_delay_ms(path_name) for path_name in ("slow", "fast")}
            for session in self.config.traffic_sessions:
                allowed_paths = set(self.bgp_tracker.allowed_paths_for_session(session.name))
                for path_name in ("slow", "fast"):
                    if path_name in allowed_paths:
                        combined[session.name][path_name]["aux_queue_avg"] = queue_by_path[path_name]
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
                if sample is None:
                    state.ema_by_path[path_name] = None
                    continue
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
        allowed_paths = self.bgp_tracker.allowed_paths_for_session(state.session.name)
        if not allowed_paths:
            return None
        if len(allowed_paths) == 1:
            only_path = allowed_paths[0]
            if state.active_path == only_path:
                return None
            await self.controller.set_session_path(state.session.name, only_path)
            state.active_path = only_path
            state.last_switch_time = time.monotonic()
            event = {
                "time_s": round(elapsed_s, 3),
                "new_path": only_path,
                "improvement_ms": None,
                "reason": "bgp_forced",
            }
            state.path_changes.append(event)
            LOGGER.info("%s: BGP forced path -> %s", state.session.name, only_path)
            return only_path

        if any(state.ema_by_path[path_name] is None for path_name in allowed_paths):
            return None

        best_path = min(allowed_paths, key=lambda path_name: self._score(state, path_name))
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
        event = {
            "time_s": round(elapsed_s, 3),
            "new_path": best_path,
            "improvement_ms": round(improvement_ms, 3),
            "reason": "score",
        }
        state.path_changes.append(event)
        LOGGER.info("%s: closed-loop switch -> %s (improvement %.2f ms)", state.session.name, best_path, improvement_ms)
        return best_path

    def write_csv(self) -> None:
        ensure_parent_dirs(self.csv_path)
        fieldnames = [
            "elapsed_s", "event", "telemetry_mode", "session", "client_host", "server_host", "server_ip",
            "bgp_allowed_paths", "slow_bgp_reachable", "fast_bgp_reachable",
            "active_path", "switched_to", "traffic_avg_ms", "traffic_loss_pct",
            "slow_probe_avg_ms", "slow_probe_loss_pct", "slow_probe_score_ms", "slow_aux_queue_avg", "slow_aux_residence_ms", "slow_aux_report_count", "slow_aux_hop_count",
            "fast_probe_avg_ms", "fast_probe_loss_pct", "fast_probe_score_ms", "fast_aux_queue_avg", "fast_aux_residence_ms", "fast_aux_report_count", "fast_aux_hop_count",
        ]
        with open(self.csv_path, "w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.rows)

    def write_summary(self) -> None:
        summary = {
            "topology_name": self.config.topology_name,
            "telemetry_mode": self.telemetry_mode,
            "session_count": len(self.config.traffic_sessions),
            "csv_path": self.csv_path,
            "final_active_path_by_session": {},
            "path_changes_by_session": {},
            "mean_traffic_ms_by_session": {},
            "bgp_allowed_paths_by_session": {},
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
            summary["bgp_allowed_paths_by_session"][session.name] = list(self.bgp_tracker.allowed_paths_for_session(session.name))
        summary["overall_mean_traffic_ms"] = statistics.mean(all_values) if all_values else None
        ensure_parent_dirs(self.summary_path)
        with open(self.summary_path, "w", encoding="utf-8") as summary_file:
            json.dump(summary, summary_file, indent=2)

    def _build_row(self, elapsed_s: float, event_messages: list[str], state: SessionState, switched_to: str | None, traffic_result: dict[str, Any], probe_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
        allowed_paths = self.bgp_tracker.allowed_paths_for_session(state.session.name)
        return {
            "elapsed_s": round(elapsed_s, 3),
            "event": "; ".join(event_messages) if event_messages else None,
            "telemetry_mode": self.telemetry_mode,
            "session": state.session.name,
            "client_host": state.session.client_host,
            "server_host": state.session.server_host,
            "server_ip": state.session.server_ip,
            "bgp_allowed_paths": ",".join(allowed_paths),
            "slow_bgp_reachable": "slow" in allowed_paths,
            "fast_bgp_reachable": "fast" in allowed_paths,
            "active_path": state.active_path,
            "switched_to": switched_to,
            "traffic_avg_ms": traffic_result.get("avg_ms"),
            "traffic_loss_pct": traffic_result.get("loss_pct"),
            "slow_probe_avg_ms": probe_results["slow"].get("avg_ms"),
            "slow_probe_loss_pct": probe_results["slow"].get("loss_pct"),
            "slow_probe_score_ms": self._score_result_ms(probe_results["slow"]),
            "slow_aux_queue_avg": probe_results["slow"].get("aux_queue_avg"),
            "slow_aux_residence_ms": probe_results["slow"].get("aux_residence_ms"),
            "slow_aux_report_count": probe_results["slow"].get("aux_report_count"),
            "slow_aux_hop_count": self._hop_count(probe_results["slow"]),
            "fast_probe_avg_ms": probe_results["fast"].get("avg_ms"),
            "fast_probe_loss_pct": probe_results["fast"].get("loss_pct"),
            "fast_probe_score_ms": self._score_result_ms(probe_results["fast"]),
            "fast_aux_queue_avg": probe_results["fast"].get("aux_queue_avg"),
            "fast_aux_residence_ms": probe_results["fast"].get("aux_residence_ms"),
            "fast_aux_report_count": probe_results["fast"].get("aux_report_count"),
            "fast_aux_hop_count": self._hop_count(probe_results["fast"]),
        }

    async def run_closed_loop(self) -> None:
        duration_s = float(self.config.experiment.get("duration_s", 55.0))
        interval_s = self.config.closed_loop.probe_interval_s

        self.bgp_tracker.refresh()
        baseline = time.monotonic() - self.config.closed_loop.hold_down_s
        for session in self.config.traffic_sessions:
            allowed = self.bgp_tracker.allowed_paths_for_session(session.name)
            initial_path = "slow" if "slow" in allowed else (allowed[0] if allowed else "slow")
            try:
                await self.controller.set_session_path(session.name, initial_path)
            except Exception as exc:
                LOGGER.warning("%s: failed to set initial path %s (%s): %r", session.name, initial_path, type(exc).__name__, exc)
            state = self.session_states[session.name]
            state.active_path = initial_path
            state.last_switch_time = baseline
            state.ema_by_path = {"slow": None, "fast": None}

        start_time = time.monotonic()
        next_tick = start_time
        while True:
            now = time.monotonic()
            elapsed_s = now - start_time
            if elapsed_s > duration_s:
                break
            if self.bgp_tracker.refresh_each_interval:
                self.bgp_tracker.refresh()
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
            active_summary = ", ".join(f"{session.name}:{self.session_states[session.name].active_path}/{','.join(self.bgp_tracker.allowed_paths_for_session(session.name))}" for session in self.config.traffic_sessions)
            LOGGER.info("t=%.1fs mode=%s active_paths=[%s]", elapsed_s, self.telemetry_mode, active_summary)
            next_tick += interval_s
            await asyncio.sleep(max(0.0, next_tick - time.monotonic()))

        self.write_summary()
        LOGGER.info("BGP-aware generalized closed-loop finished; results written to %s and %s", self.csv_path, self.summary_path)


async def async_main(args: argparse.Namespace, network: Mininet, config: RunConfig) -> None:
    telemetry_mode = args.telemetry_mode or config.telemetry.mode
    build_dir = os.path.join(REPOSITORY_DIRECTORY, "build/p4")
    controller = SdxController(
        config_path=args.config,
        p4info_path=os.path.join(build_dir, "sdx_ixp.p4info.txtpb"),
        p4blob_path=os.path.join(build_dir, "sdx_ixp.json"),
    )
    runner = BgpAwareClosedLoopRunner(network=network, controller=controller, config=config, results_dir=args.results_dir, telemetry_mode=telemetry_mode)
    try:
        await controller.start()
        await controller.wait_until_ready(timeout_s=45.0)
        runner.queue_manager.configure_profiles()
        LOGGER.info("Waiting %.1fs for initial FRR/BGP warm-up", args.warmup_s)
        await asyncio.sleep(args.warmup_s)
        await wait_for_bgp_readiness(
            tracker=runner.bgp_tracker,
            timeout_s=args.bgp_wait_timeout_s,
            poll_s=args.bgp_poll_s,
            logger=LOGGER,
            require_expected=False,
        )
        runner.bgp_tracker.refresh()
        runner.bgp_tracker.install_session_dataplane_routes()
        await asyncio.sleep(3.0)
        await runner.prepare_initial_paths()
        runner.warm_up()
        runner.start_servers()
        await asyncio.sleep(2.0)
        runner.warm_up()
        await runner.prime_udp_paths()
        runner.bgp_tracker.refresh()
        await runner.run_closed_loop()
    finally:
        runner.stop_servers()
        await controller.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run BGP-aware generalized multi-session closed-loop SDX")
    parser.add_argument("--config", default=os.path.join(REPOSITORY_DIRECTORY, "config/run_config_bgp_generalized.json"), help="Path to the BGP-aware generalized json config file")
    parser.add_argument("--results-dir", default=os.path.join(REPOSITORY_DIRECTORY, "results/bgp_generalized_closed_loop"), help="Directory where CSV/JSON outputs are written")
    parser.add_argument("--telemetry-mode", choices=["mode1", "mode2", "mode3"], default=None, help="Override telemetry mode from config")
    parser.add_argument("--warmup-s", type=float, default=12.0, help="Initial seconds to wait before polling for BGP convergence")
    parser.add_argument("--bgp-wait-timeout-s", type=float, default=45.0, help="Additional seconds to keep polling for BGP reachability")
    parser.add_argument("--bgp-poll-s", type=float, default=2.0, help="Polling interval while waiting for BGP reachability")
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
