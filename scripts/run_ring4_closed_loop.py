
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
REPO_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '../'))
sys.path.append(REPO_DIR)

from controller.sdx_controller import RunConfig, SdxController
from networks.sdx_ring4.mininet.networks import Topology

LOG = logging.getLogger('sdx_ring4')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run 4-IXP ring SDX experiment')
    parser.add_argument('--config', default=os.path.join(REPO_DIR, 'config/run_config_ring4.json'))
    parser.add_argument('--mode', choices=['closed-loop', 'fixed'], default='closed-loop')
    parser.add_argument('--fixed-path', default='via_ixp2')
    parser.add_argument('--warmup-s', type=float, default=5.0)
    parser.add_argument('--results-dir', default=os.path.join(REPO_DIR, 'results/ring4'))
    return parser.parse_args()


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')


def empty_probe_result(count: int) -> dict[str, Any]:
    return {'sent': count, 'received': 0, 'loss_pct': 100.0, 'rtts_ms': [], 'avg_ms': None, 'min_ms': None, 'max_ms': None}


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
            'python3', client_script,
            '--dst', dst_ip,
            '--port', str(udp_port),
            '--count', str(count),
            '--timeout', str(timeout_s),
            '--tos', str(tos),
        ]
        rc, stdout, stderr = run_on_host(host, argv, timeout_s=max(timeout_s * count + 2.0, 5.0))
        if rc != 0:
            LOG.warning('Probe command failed on %s: rc=%s stderr=%s', host.name, rc, stderr.strip())
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if not lines:
            return empty_probe_result(count)
        try:
            return json.loads(lines[-1])
        except json.JSONDecodeError:
            LOG.warning('Unable to decode probe output from %s: %s', host.name, stdout)
            return empty_probe_result(count)
    return await asyncio.to_thread(_run)


class RingRunner:
    def __init__(self, network: Mininet, controller: SdxController, config: RunConfig, results_dir: str) -> None:
        self.network = network
        self.controller = controller
        self.config = config
        self.results_dir = results_dir
        os.makedirs(self.results_dir, exist_ok=True)
        self.client_script = os.path.join(REPO_DIR, 'scripts/udp_echo_client.py')
        self.server_script = os.path.join(REPO_DIR, 'scripts/udp_echo_server.py')
        self.client = network.get(config.probe.client_host)
        self.server = network.get(config.probe.server_host)
        self.server_process = None
        self.events = sorted(config.run.get('events', []), key=lambda item: float(item['time_s']))
        self.event_index = 0
        self.path_names = tuple(config.probe_tos_by_path.keys())
        self.probe_tos = config.probe_tos_by_path
        self.path_base_delay_ms = {str(k): int(v) for k, v in dict(config.run.get('base_path_delay_ms', {})).items()}
        self.path_extra_delay_ms = {path_name: 0 for path_name in self.path_names}
        self.ema = {path_name: None for path_name in self.path_names}
        self.active_path = controller.group_current_path.get('traffic_forward', self.path_names[0])
        self.last_switch_time = time.monotonic()
        self.path_changes: list[dict[str, Any]] = []
        self.rows: list[dict[str, Any]] = []
        self.csv_path = os.path.join(results_dir, 'latest_run.csv')
        self.summary_path = os.path.join(results_dir, 'latest_summary.json')

    def start_server(self) -> None:
        if self.server_process is not None:
            return
        self.server_process = self.server.popen(['python3', self.server_script, '--port', str(self.config.probe.udp_port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        LOG.info('Started UDP echo server on %s', self.server.name)

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
        self.client.cmd(f'ping -c 1 -W 1 {self.config.probe.server_ip} >/dev/null 2>&1 || true')
        reverse_group = next(group for group in self.config.groups if group.name == 'traffic_reverse')
        self.server.cmd(f'ping -c 1 -W 1 {reverse_group.dst_ip} >/dev/null 2>&1 || true')

    def _set_delay(self, node_name: str, ifname: str, delay_ms: int) -> None:
        node = self.network.get(node_name)
        if delay_ms <= 0:
            node.cmd(f'tc qdisc del dev {ifname} root >/dev/null 2>&1 || true')
        else:
            node.cmd(f'tc qdisc replace dev {ifname} root netem delay {delay_ms}ms')

    def _apply_path_delay(self, path_name: str) -> None:
        base_delay_ms = int(self.path_base_delay_ms.get(path_name, 0))
        extra_delay_ms = int(self.path_extra_delay_ms.get(path_name, 0))
        total_delay_ms = base_delay_ms + extra_delay_ms
        for endpoint in self.config.path_links.get(path_name, ()):
            self._set_delay(endpoint['node'], endpoint['interface'], total_delay_ms)

    def initialize_path_delays(self) -> None:
        for path_name in self.path_names:
            self._apply_path_delay(path_name)

    def set_path_delay(self, path_name: str, delay_ms: int) -> None:
        self.path_extra_delay_ms[path_name] = int(delay_ms)
        self._apply_path_delay(path_name)

    def apply_due_events(self, elapsed_s: float) -> list[str]:
        messages: list[str] = []
        while self.event_index < len(self.events) and float(self.events[self.event_index]['time_s']) <= elapsed_s:
            event = self.events[self.event_index]
            self.event_index += 1
            if event.get('type') == 'set_path_extra_delay':
                self.set_path_delay(str(event['path']), int(event['delay_ms']))
                messages.append(f"set_path_extra_delay(path={event['path']}, delay_ms={event['delay_ms']})")
            else:
                messages.append(f'unknown_event({event})')
        return messages

    async def probe_path(self, path_name: str) -> dict[str, Any]:
        return await run_probe(self.client, self.client_script, self.config.probe.server_ip, self.config.probe.udp_port, self.probe_tos[path_name], self.config.closed_loop.probe_count, self.config.closed_loop.probe_timeout_s)

    async def measure_traffic(self) -> dict[str, Any]:
        return await run_probe(self.client, self.client_script, self.config.probe.server_ip, self.config.probe.udp_port, self.config.probe.traffic_tos, self.config.closed_loop.probe_count, self.config.closed_loop.probe_timeout_s)

    def update_emas(self, probe_results: dict[str, dict[str, Any]]) -> None:
        alpha = self.config.closed_loop.ema_alpha
        for path_name, result in probe_results.items():
            sample = result.get('avg_ms')
            if sample is None:
                continue
            current = self.ema[path_name]
            self.ema[path_name] = float(sample) if current is None else alpha * float(sample) + (1.0 - alpha) * float(current)

    def score(self, candidate_path: str) -> float:
        base = self.ema[candidate_path]
        if base is None:
            return float('inf')
        if candidate_path != self.active_path:
            base += self.config.closed_loop.switch_penalty_ms
        return base

    async def maybe_switch(self, elapsed_s: float) -> str | None:
        if any(self.ema[p] is None for p in self.path_names):
            return None
        best_path = min(self.path_names, key=self.score)
        if best_path == self.active_path:
            return None
        current_score = self.score(self.active_path)
        best_score = self.score(best_path)
        improvement_ms = current_score - best_score
        hold_down_elapsed = time.monotonic() - self.last_switch_time
        if improvement_ms < self.config.closed_loop.min_improvement_ms:
            return None
        if hold_down_elapsed < self.config.closed_loop.hold_down_s:
            return None
        await self.controller.set_traffic_path(best_path)
        self.active_path = best_path
        self.last_switch_time = time.monotonic()
        self.path_changes.append({'time_s': round(elapsed_s, 3), 'new_path': best_path, 'improvement_ms': round(improvement_ms, 3)})
        return best_path

    def write_csv(self) -> None:
        fieldnames = ['elapsed_s', 'event', 'active_path', 'switched_to', 'traffic_avg_ms', 'traffic_loss_pct']
        for p in self.path_names:
            fieldnames.extend([f'{p}_probe_avg_ms', f'{p}_probe_loss_pct'])
        with open(self.csv_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader(); writer.writerows(self.rows)

    def write_summary(self) -> None:
        traffic_values = [float(row['traffic_avg_ms']) for row in self.rows if row['traffic_avg_ms'] is not None]
        summary = {
            'topology': 'sdx_ring4',
            'paths': list(self.path_names),
            'final_active_path': self.active_path,
            'path_changes': self.path_changes,
            'overall_mean_traffic_ms': (statistics.mean(traffic_values) if traffic_values else None),
            'csv_path': self.csv_path,
        }
        with open(self.summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

    async def run_fixed(self, path_name: str) -> None:
        if path_name not in self.path_names:
            raise ValueError(f'Unknown fixed path {path_name}; valid={self.path_names}')
        await self.controller.set_traffic_path(path_name)
        self.active_path = path_name
        self.last_switch_time = time.monotonic()
        self.path_changes = []
        await self.run_closed_loop(fixed=True)

    async def run_closed_loop(self, fixed: bool = False) -> None:
        duration_s = float(self.config.run.get('duration_s', 55.0))
        interval_s = self.config.closed_loop.probe_interval_s
        start_time = time.monotonic()
        next_tick = start_time
        while True:
            now = time.monotonic(); elapsed_s = now - start_time
            if elapsed_s > duration_s:
                break
            messages = self.apply_due_events(elapsed_s)
            probe_results = {p: await self.probe_path(p) for p in self.path_names}
            self.update_emas(probe_results)
            switched_to = None if fixed else await self.maybe_switch(elapsed_s)
            traffic_result = await self.measure_traffic()
            row = {'elapsed_s': round(elapsed_s,3), 'event': '; '.join(messages) if messages else None, 'active_path': self.active_path, 'switched_to': switched_to, 'traffic_avg_ms': traffic_result.get('avg_ms'), 'traffic_loss_pct': traffic_result.get('loss_pct')}
            for p in self.path_names:
                row[f'{p}_probe_avg_ms'] = probe_results[p].get('avg_ms')
                row[f'{p}_probe_loss_pct'] = probe_results[p].get('loss_pct')
            self.rows.append(row)
            self.write_csv()
            LOG.info('t=%.1fs active=%s traffic=%.2fms %s%s', elapsed_s, self.active_path, -1.0 if row['traffic_avg_ms'] is None else float(row['traffic_avg_ms']), ' '.join(f'{p}=%.2fms' % (-1.0 if row[f'{p}_probe_avg_ms'] is None else float(row[f'{p}_probe_avg_ms'])) for p in self.path_names), ' switched' if switched_to else '')
            next_tick += interval_s
            await asyncio.sleep(max(0.0, next_tick - time.monotonic()))
        self.write_summary()
        LOG.info('Ring-4 run finished; results written to %s and %s', self.csv_path, self.summary_path)


async def async_main(args: argparse.Namespace, network: Mininet) -> None:
    controller = SdxController(config_path=args.config, p4info_path=os.path.join(REPO_DIR, 'build/p4/sdx_ixp.p4info.txtpb'), p4blob_path=os.path.join(REPO_DIR, 'build/p4/sdx_ixp.json'))
    runner = RingRunner(network, controller, controller.config, args.results_dir)
    try:
        await controller.start()
        await controller.wait_until_ready(timeout_s=30.0)
        runner.initialize_path_delays()
        LOG.info('Waiting %.1fs for static-route warm-up', args.warmup_s)
        await asyncio.sleep(args.warmup_s)
        runner.warm_up(); runner.start_server(); await asyncio.sleep(1.0)
        if args.mode == 'fixed':
            await runner.run_fixed(args.fixed_path)
        else:
            await runner.run_closed_loop()
    finally:
        runner.stop_server(); await controller.stop()


def main() -> None:
    args = parse_args(); configure_logging(); setLogLevel('info')
    network = Mininet(topo=Topology(), link=TCLink, autoSetMacs=False)
    LOG.info('Starting 4-IXP ring Mininet network')
    network.start()
    try:
        asyncio.run(async_main(args, network))
    finally:
        LOG.info('Stopping 4-IXP ring Mininet network'); network.stop()


if __name__ == '__main__':
    main()
