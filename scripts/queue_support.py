from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any

BACKLOG_RE = re.compile(r"backlog\s+([0-9.]+)([KMG]?b)\s+(\d+)p")


def _size_token_to_bytes(value_text: str, unit_text: str) -> float:
    value = float(value_text)
    unit = unit_text.lower()
    if unit == "b":
        return value
    if unit == "kb":
        return value * 1024.0
    if unit == "mb":
        return value * 1024.0 * 1024.0
    if unit == "gb":
        return value * 1024.0 * 1024.0 * 1024.0
    return value


class QueueScenarioManager:
    def __init__(self, network, repository_directory: str, experiment: dict[str, Any], logger: logging.Logger) -> None:
        self.network = network
        self.repository_directory = repository_directory
        self.logger = logger
        self.queueing = dict(experiment.get("queueing", {}))
        self.path_cfgs: dict[str, dict[str, Any]] = dict(self.queueing.get("paths", {}))
        self.sink_script_path = os.path.join(repository_directory, "scripts/udp_sink.py")
        self.blast_script_path = os.path.join(repository_directory, "scripts/udp_blast.py")
        self._sink_processes: dict[tuple[str, int], Any] = {}
        self._load_processes: dict[str, Any] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.path_cfgs)

    def configure_profiles(self) -> None:
        for path_name in self.path_cfgs:
            self._apply_profile(path_name)

    def _apply_profile(self, path_name: str) -> None:
        cfg = self.path_cfgs.get(path_name, {})
        rate_mbps = float(cfg.get("rate_mbps", 0.0))
        burst_kb = float(cfg.get("burst_kb", 64.0))
        latency_ms = float(cfg.get("latency_ms", 50.0))
        if rate_mbps <= 0.0:
            return
        for item in cfg.get("bottleneck_links", []):
            node = self.network.get(str(item["node"]))
            iface = str(item["interface"])
            node.cmd(
                f"tc qdisc replace dev {iface} root tbf rate {rate_mbps}mbit burst {burst_kb}kb latency {latency_ms}ms"
            )

    def clear_profiles(self) -> None:
        for cfg in self.path_cfgs.values():
            for item in cfg.get("bottleneck_links", []):
                node = self.network.get(str(item["node"]))
                iface = str(item["interface"])
                node.cmd(f"tc qdisc del dev {iface} root >/dev/null 2>&1 || true")

    def start_sinks(self) -> None:
        for cfg in self.path_cfgs.values():
            load = dict(cfg.get("load", {}))
            if not load:
                continue
            server_host = str(load["server_host"])
            udp_port = int(load["udp_port"])
            key = (server_host, udp_port)
            if key in self._sink_processes:
                continue
            host = self.network.get(server_host)
            process = host.popen(
                ["python3", self.sink_script_path, "--port", str(udp_port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            self._sink_processes[key] = process
            self.logger.info("Started queue sink on %s:%d", server_host, udp_port)

    def stop_sinks(self) -> None:
        for process in self._sink_processes.values():
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        self._sink_processes.clear()

    def start_load(self, path_name: str) -> None:
        if path_name in self._load_processes:
            return
        cfg = self.path_cfgs.get(path_name, {})
        load = dict(cfg.get("load", {}))
        if not load:
            return
        host = self.network.get(str(load["client_host"]))
        argv = [
            "python3",
            self.blast_script_path,
            "--dst",
            str(load["server_ip"]),
            "--port",
            str(int(load["udp_port"])),
            "--tos",
            str(int(load["tos"])),
            "--rate-mbps",
            str(float(load["rate_mbps"])),
            "--size",
            str(int(load.get("packet_size", 1200))),
        ]
        process = host.popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        self._load_processes[path_name] = process
        self.logger.info("Started queue load on path %s", path_name)

    def stop_load(self, path_name: str) -> None:
        process = self._load_processes.pop(path_name, None)
        if process is None:
            return
        process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)
        self.logger.info("Stopped queue load on path %s", path_name)

    def stop_all_loads(self) -> None:
        for path_name in list(self._load_processes):
            self.stop_load(path_name)

    def queue_delay_ms(self, path_name: str) -> float | None:
        cfg = self.path_cfgs.get(path_name, {})
        rate_mbps = float(cfg.get("rate_mbps", 0.0))
        if rate_mbps <= 0.0:
            return None
        delays: list[float] = []
        for item in cfg.get("bottleneck_links", []):
            node = self.network.get(str(item["node"]))
            iface = str(item["interface"])
            output = node.cmd(f"tc -s qdisc show dev {iface}")
            match = BACKLOG_RE.search(output)
            if not match:
                continue
            backlog_bytes = _size_token_to_bytes(match.group(1), match.group(2))
            delay_ms = (backlog_bytes * 8.0 * 1000.0) / (rate_mbps * 1_000_000.0)
            delays.append(delay_ms)
        if not delays:
            return 0.0
        return sum(delays) / len(delays)
