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
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, '../'))
sys.path.append(REPOSITORY_DIRECTORY)

from controller.sdx_controller import RunConfig, SdxController
from networks import load_topology_class
from scripts.bgp_support import BgpReachabilityTracker, wait_for_bgp_readiness
from scripts.queue_support import QueueScenarioManager
from scripts.run_sdx import configure_logging, ensure_parent_dirs, run_udp_probe_async

LOGGER = logging.getLogger('sdx_bgp_superloop_segmented_local')

@dataclass
class StageControllerSpec:
    stage_key: str
    switch: str
    traffic_paths: dict[str, str]
    probe_paths: dict[str, str]
    probe_client: str
    probe_targets: dict[str, str]
    probe_server_hosts: dict[str, str]
    probe_tos: dict[str, int]
    segment_id: str

@dataclass
class StageState:
    spec: StageControllerSpec
    active_choice: str = 'fast'
    ema_by_choice: dict[str, float | None] = field(default_factory=lambda: {'slow': None, 'fast': None})
    last_switch_time: float = 0.0
    path_changes: list[dict[str, Any]] = field(default_factory=list)

@dataclass
class SegmentedSessionSpec:
    name: str
    dynamic_groups: dict[str, str]
    static_groups: dict[str, str]

class SegmentedLocalRunner:
    def __init__(self, network: Mininet, controller: SdxController, config: RunConfig, results_dir: str, telemetry_mode: str) -> None:
        self.network = network
        self.controller = controller
        self.config = config
        self.results_dir = results_dir
        self.telemetry_mode = telemetry_mode
        os.makedirs(self.results_dir, exist_ok=True)

        self.client_script_path = os.path.join(REPOSITORY_DIRECTORY, 'scripts/udp_echo_client.py')
        self.server_script_path = os.path.join(REPOSITORY_DIRECTORY, 'scripts/udp_echo_server.py')
        self._server_processes: dict[str, Any] = {}
        self._event_index = 0
        self._events = sorted(self.config.experiment.get('events', []), key=lambda item: float(item['time_s']))

        self.stage_specs = {item['stage_key']: StageControllerSpec(stage_key=str(item['stage_key']), switch=str(item['switch']), traffic_paths={str(k): str(v) for k, v in item['traffic_paths'].items()}, probe_paths={str(k): str(v) for k, v in item['probe_paths'].items()}, probe_client=str(item['probe_client']), probe_targets={str(k): str(v) for k, v in item['probe_targets'].items()}, probe_server_hosts={str(k): str(v) for k, v in item['probe_server_hosts'].items()}, probe_tos={str(k): int(v) for k, v in item['probe_tos'].items()}, segment_id=str(item['segment_id'])) for item in self.config.experiment.get('segment_local_controllers', [])}
        self.stage_states = {key: StageState(spec=spec) for key, spec in self.stage_specs.items()}
        self.segmented_sessions = {item['name']: SegmentedSessionSpec(name=str(item['name']), dynamic_groups={str(k): str(v) for k, v in item['dynamic_groups'].items()}, static_groups={str(k): str(v) for k, v in item['static_groups'].items()}) for item in self.config.experiment.get('segmented_sessions', [])}
        self.group_by_name = {group.name: group for group in self.config.traffic_groups}
        self.rows: list[dict[str, Any]] = []
        self.csv_path = os.path.join(self.results_dir, 'latest_run.csv')
        self.summary_path = os.path.join(self.results_dir, 'latest_summary.json')
        self.queue_manager = QueueScenarioManager(network=self.network, repository_directory=REPOSITORY_DIRECTORY, experiment=self.config.experiment, logger=LOGGER)
        self.bgp_tracker = BgpReachabilityTracker(network=self.network, config=self.config, logger=LOGGER)

    def _telemetry_weights(self) -> tuple[float, float]:
        if self.telemetry_mode == 'mode2':
            return self.config.telemetry.sampling.queue_weight, self.config.telemetry.sampling.residence_weight
        if self.telemetry_mode == 'mode3':
            return self.config.telemetry.int_mode.queue_weight, self.config.telemetry.int_mode.residence_weight
        return self.config.telemetry.base.queue_weight, 0.0

    def _score_result_ms(self, stage: StageControllerSpec, choice: str, result: dict[str, Any]) -> float | None:
        avg_ms = result.get('avg_ms')
        if avg_ms is None:
            return 10000.0
        score = float(avg_ms) + (5.0 * float(result.get('loss_pct', 0.0)))
        queue_weight, residence_weight = self._telemetry_weights()
        if result.get('aux_queue_avg') is not None:
            score += queue_weight * float(result['aux_queue_avg'])
        if result.get('aux_residence_ms') is not None:
            score += residence_weight * float(result['aux_residence_ms'])
        if self.queue_manager.enabled:
            score += queue_weight * float(self.queue_manager.queue_delay_ms(f"{stage.segment_id}_{choice}"))
        return score

    def start_servers(self) -> None:
        self.queue_manager.start_sinks()
        server_hosts = sorted({session.server_host for session in self.config.traffic_sessions})
        for spec in self.stage_specs.values():
            server_hosts.extend(spec.probe_server_hosts.values())
        for host_name in sorted(set(server_hosts)):
            if host_name in self._server_processes:
                continue
            host = self.network.get(host_name)
            process = host.popen(['python3', self.server_script_path, '--port', str(self.config.probe_service.udp_port), '--int-port', str(self.config.probe_service.int_udp_port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self._server_processes[host_name] = process
            LOGGER.info('Started UDP echo server on %s', host_name)

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
        for spec in self.stage_specs.values():
            client = self.network.get(spec.probe_client)
            for target in spec.probe_targets.values():
                client.cmd(f"ping -c 2 -W 1 {target} >/dev/null 2>&1 || true")

    def _set_interface_delay(self, node_name: str, interface_name: str, delay_ms: int) -> None:
        node = self.network.get(node_name)
        if delay_ms <= 0:
            node.cmd(f"tc qdisc del dev {interface_name} root >/dev/null 2>&1 || true")
        else:
            node.cmd(f"tc qdisc replace dev {interface_name} root netem delay {delay_ms}ms")

    def set_path_extra_delay(self, path_name: str, delay_ms: int) -> None:
        for item in self.config.path_links.get(path_name, ()):
            self._set_interface_delay(item['node'], item['interface'], delay_ms)

    def apply_due_events(self, elapsed_s: float) -> list[str]:
        messages=[]
        while self._event_index < len(self._events):
            event=self._events[self._event_index]
            if float(event['time_s']) > elapsed_s:
                break
            self._event_index += 1
            if event['type']=='set_path_extra_delay':
                self.set_path_extra_delay(str(event['path']), int(event['delay_ms']))
                messages.append(f"set_path_extra_delay(path={event['path']}, delay_ms={event['delay_ms']})")
            elif event['type']=='start_path_congestion':
                self.queue_manager.start_load(str(event['path']))
                messages.append(f"start_path_congestion(path={event['path']})")
            elif event['type']=='stop_path_congestion':
                self.queue_manager.stop_load(str(event['path']))
                messages.append(f"stop_path_congestion(path={event['path']})")
        return messages

    async def _run_stage_probe(self, spec: StageControllerSpec, choice: str) -> tuple[float, dict[str, Any]]:
        host = self.network.get(spec.probe_client)
        udp_port = self.config.probe_service.int_udp_port if self.telemetry_mode == 'mode3' else self.config.probe_service.udp_port
        mode = 'int' if self.telemetry_mode == 'mode3' else 'basic'
        start = time.monotonic()
        result = await run_udp_probe_async(host=host, client_script_path=self.client_script_path, dst_ip=spec.probe_targets[choice], udp_port=udp_port, tos=spec.probe_tos[choice], count=self.config.closed_loop.probe_count, timeout_s=self.config.closed_loop.probe_timeout_s, mode=mode)
        return start, result

    async def collect_stage_probe_results(self) -> dict[str, dict[str, dict[str, Any]]]:
        tasks={}
        timing={}
        combined={k:{'slow':{},'fast':{}} for k in self.stage_specs}
        for stage_key, spec in self.stage_specs.items():
            for choice in ('slow','fast'):
                tasks[(stage_key, choice)] = asyncio.create_task(self._run_stage_probe(spec, choice))
        raw = await asyncio.gather(*tasks.values())
        for (stage_key, choice), (start, result) in zip(tasks.keys(), raw):
            combined[stage_key][choice].update(result)
            timing[(stage_key, choice)] = start
        if self.telemetry_mode == 'mode2':
            await asyncio.sleep(self.config.telemetry.sampling.drain_wait_s)
            for stage_key, spec in self.stage_specs.items():
                for choice in ('slow','fast'):
                    summary = self.controller.get_sampling_summary(spec.probe_paths[choice], timing[(stage_key, choice)])
                    combined[stage_key][choice]['aux_queue_avg'] = summary['avg_queue_depth']
                    combined[stage_key][choice]['aux_residence_ms'] = summary['avg_residence_ms']
                    combined[stage_key][choice]['aux_report_count'] = summary['report_count']
        return combined

    def update_stage_emas(self, results: dict[str, dict[str, dict[str, Any]]]) -> None:
        alpha=self.config.closed_loop.ema_alpha
        for stage_key, choices in results.items():
            state=self.stage_states[stage_key]
            for choice, result in choices.items():
                sample=self._score_result_ms(state.spec, choice, result)
                current=state.ema_by_choice[choice]
                state.ema_by_choice[choice] = sample if current is None else (alpha*sample + (1.0-alpha)*current)

    def _score(self, state: StageState, choice: str) -> float:
        base = state.ema_by_choice[choice]
        if base is None:
            return float('inf')
        if choice != state.active_choice:
            base += self.config.closed_loop.switch_penalty_ms
        return base

    async def maybe_switch_stage(self, stage_key: str, elapsed_s: float) -> str | None:
        state = self.stage_states[stage_key]
        if state.ema_by_choice['slow'] is None or state.ema_by_choice['fast'] is None:
            return None
        best = min(('slow','fast'), key=lambda c: self._score(state,c))
        if best == state.active_choice:
            return None
        improvement = self._score(state, state.active_choice) - self._score(state, best)
        if improvement < self.config.closed_loop.min_improvement_ms:
            return None
        if (time.monotonic() - state.last_switch_time) < self.config.closed_loop.hold_down_s:
            return None
        state.active_choice = best
        state.last_switch_time = time.monotonic()
        state.path_changes.append({'time_s': round(elapsed_s,3), 'new_choice': best, 'improvement_ms': round(improvement,3)})
        LOGGER.info('%s switched locally -> %s', stage_key, best)
        return best

    async def apply_session_group_paths(self) -> None:
        for session_name, session_spec in self.segmented_sessions.items():
            allowed = set(self.bgp_tracker.allowed_paths_for_session(session_name))
            if not allowed:
                continue
            for stage_key, group_name in session_spec.dynamic_groups.items():
                spec=self.stage_specs[stage_key]
                if 'fast' not in allowed:
                    choice='slow'
                elif 'slow' not in allowed:
                    choice='fast'
                else:
                    choice=self.stage_states[stage_key].active_choice
                await self.controller.set_group_path(group_name, spec.traffic_paths[choice])

    async def collect_traffic_results(self) -> dict[str, dict[str, Any]]:
        tasks={}
        for session in self.config.traffic_sessions:
            host=self.network.get(session.client_host)
            tasks[session.name]=asyncio.create_task(run_udp_probe_async(host=host, client_script_path=self.client_script_path, dst_ip=session.server_ip, udp_port=self.config.probe_service.udp_port, tos=session.traffic_tos, count=self.config.closed_loop.probe_count, timeout_s=self.config.closed_loop.probe_timeout_s, mode='basic'))
        values=await asyncio.gather(*tasks.values())
        return {name:res for name,res in zip(tasks.keys(), values)}

    def _choice_for_session_stage(self, session_name: str, stage_key: str) -> str | None:
        allowed = set(self.bgp_tracker.allowed_paths_for_session(session_name))
        if not allowed:
            return None
        if 'fast' not in allowed:
            return 'slow'
        if 'slow' not in allowed:
            return 'fast'
        return self.stage_states[stage_key].active_choice

    def _row(self, elapsed_s: float, events: list[str], session_name: str, traffic: dict[str, Any]) -> dict[str, Any]:
        vals = {k:self._choice_for_session_stage(session_name,k) for k in self.stage_states}
        return {
            'elapsed_s': round(elapsed_s,3), 'event': '; '.join(events) if events else None, 'telemetry_mode': self.telemetry_mode, 'session': session_name, 'bgp_allowed_paths': ','.join(self.bgp_tracker.allowed_paths_for_session(session_name)),
            'ixp1_fwd': vals.get('ixp1_fwd'), 'ixp2_fwd': vals.get('ixp2_fwd'), 'ixp3_fwd': vals.get('ixp3_fwd'), 'ixp4_rev': vals.get('ixp4_rev'), 'ixp3_rev': vals.get('ixp3_rev'), 'ixp2_rev': vals.get('ixp2_rev'),
            'forward_effective_path': '-'.join(v or 'none' for v in (vals.get('ixp1_fwd'), vals.get('ixp2_fwd'), vals.get('ixp3_fwd'))),
            'reverse_effective_path': '-'.join(v or 'none' for v in (vals.get('ixp4_rev'), vals.get('ixp3_rev'), vals.get('ixp2_rev'))),
            'traffic_avg_ms': traffic.get('avg_ms'), 'traffic_loss_pct': traffic.get('loss_pct'),
            'ixp1_fwd_slow_score': self._score(self.stage_states['ixp1_fwd'],'slow') if self.stage_states['ixp1_fwd'].ema_by_choice['slow'] is not None else None,
            'ixp1_fwd_fast_score': self._score(self.stage_states['ixp1_fwd'],'fast') if self.stage_states['ixp1_fwd'].ema_by_choice['fast'] is not None else None,
            'ixp2_fwd_slow_score': self._score(self.stage_states['ixp2_fwd'],'slow') if self.stage_states['ixp2_fwd'].ema_by_choice['slow'] is not None else None,
            'ixp2_fwd_fast_score': self._score(self.stage_states['ixp2_fwd'],'fast') if self.stage_states['ixp2_fwd'].ema_by_choice['fast'] is not None else None,
            'ixp3_fwd_slow_score': self._score(self.stage_states['ixp3_fwd'],'slow') if self.stage_states['ixp3_fwd'].ema_by_choice['slow'] is not None else None,
            'ixp3_fwd_fast_score': self._score(self.stage_states['ixp3_fwd'],'fast') if self.stage_states['ixp3_fwd'].ema_by_choice['fast'] is not None else None,
            'ixp4_rev_slow_score': self._score(self.stage_states['ixp4_rev'],'slow') if self.stage_states['ixp4_rev'].ema_by_choice['slow'] is not None else None,
            'ixp4_rev_fast_score': self._score(self.stage_states['ixp4_rev'],'fast') if self.stage_states['ixp4_rev'].ema_by_choice['fast'] is not None else None,
            'ixp3_rev_slow_score': self._score(self.stage_states['ixp3_rev'],'slow') if self.stage_states['ixp3_rev'].ema_by_choice['slow'] is not None else None,
            'ixp3_rev_fast_score': self._score(self.stage_states['ixp3_rev'],'fast') if self.stage_states['ixp3_rev'].ema_by_choice['fast'] is not None else None,
            'ixp2_rev_slow_score': self._score(self.stage_states['ixp2_rev'],'slow') if self.stage_states['ixp2_rev'].ema_by_choice['slow'] is not None else None,
            'ixp2_rev_fast_score': self._score(self.stage_states['ixp2_rev'],'fast') if self.stage_states['ixp2_rev'].ema_by_choice['fast'] is not None else None,
        }

    def write_csv(self) -> None:
        ensure_parent_dirs(self.csv_path)
        fieldnames=list(self.rows[0].keys()) if self.rows else []
        with open(self.csv_path,'w',encoding='utf-8',newline='') as f:
            w=csv.DictWriter(f, fieldnames=fieldnames); w.writeheader(); w.writerows(self.rows)

    def write_summary(self) -> None:
        summary={'topology_name':self.config.topology_name,'telemetry_mode':self.telemetry_mode,'csv_path':self.csv_path,'stage_final_choice':{k:s.active_choice for k,s in self.stage_states.items()},'stage_path_changes':{k:s.path_changes for k,s in self.stage_states.items()},'bgp_allowed_paths_by_session':{sess.name:list(self.bgp_tracker.allowed_paths_for_session(sess.name)) for sess in self.config.traffic_sessions},'mean_traffic_ms_by_session':{}}
        all_vals=[]
        for session in self.config.traffic_sessions:
            vals=[float(r['traffic_avg_ms']) for r in self.rows if r['session']==session.name and r.get('traffic_avg_ms') is not None]
            if vals: all_vals.extend(vals)
            summary['mean_traffic_ms_by_session'][session.name]=statistics.mean(vals) if vals else None
        summary['overall_mean_traffic_ms']=statistics.mean(all_vals) if all_vals else None
        ensure_parent_dirs(self.summary_path)
        with open(self.summary_path,'w',encoding='utf-8') as f: json.dump(summary,f,indent=2)

    async def run(self) -> None:
        duration_s=float(self.config.experiment.get('duration_s',55.0))
        interval_s=self.config.closed_loop.probe_interval_s
        self.bgp_tracker.refresh()
        baseline=time.monotonic()-self.config.closed_loop.hold_down_s
        for state in self.stage_states.values():
            state.active_choice='fast'; state.last_switch_time=baseline; state.ema_by_choice={'slow':None,'fast':None}
        await self.apply_session_group_paths()
        start=time.monotonic(); next_tick=start
        while True:
            now=time.monotonic(); elapsed=now-start
            if elapsed>duration_s: break
            if self.bgp_tracker.refresh_each_interval: self.bgp_tracker.refresh()
            events=self.apply_due_events(elapsed)
            probes=await self.collect_stage_probe_results()
            self.update_stage_emas(probes)
            for stage_key in self.stage_states: await self.maybe_switch_stage(stage_key, elapsed)
            await self.apply_session_group_paths()
            traffic=await self.collect_traffic_results()
            for session in self.config.traffic_sessions: self.rows.append(self._row(elapsed, events, session.name, traffic[session.name]))
            self.write_csv()
            LOGGER.info('t=%.1fs local stage choices=%s', elapsed, ', '.join(f"{k}:{s.active_choice}" for k,s in self.stage_states.items()))
            next_tick += interval_s
            await asyncio.sleep(max(0.0, next_tick - time.monotonic()))
        self.write_summary()

async def async_main(args: argparse.Namespace, network: Mininet, config: RunConfig) -> None:
    telemetry_mode=args.telemetry_mode or config.telemetry.mode
    build_dir=os.path.join(REPOSITORY_DIRECTORY,'build/p4')
    controller=SdxController(config_path=args.config,p4info_path=os.path.join(build_dir,'sdx_ixp.p4info.txtpb'),p4blob_path=os.path.join(build_dir,'sdx_ixp.json'))
    runner=SegmentedLocalRunner(network, controller, config, args.results_dir, telemetry_mode)
    try:
        await controller.start()
        await controller.wait_until_ready(timeout_s=45.0)
        runner.queue_manager.configure_profiles()
        LOGGER.info('Waiting %.1fs for initial FRR/BGP warm-up', args.warmup_s)
        await asyncio.sleep(args.warmup_s)
        await wait_for_bgp_readiness(tracker=runner.bgp_tracker, timeout_s=args.bgp_wait_timeout_s, poll_s=args.bgp_poll_s, logger=LOGGER, require_expected=False)
        runner.bgp_tracker.refresh()
        runner.bgp_tracker.install_session_dataplane_routes()
        await asyncio.sleep(3.0)
        await runner.apply_session_group_paths()
        runner.warm_up()
        runner.start_servers()
        await asyncio.sleep(2.0)
        runner.warm_up()
        await runner.run()
    finally:
        runner.stop_servers()
        await controller.stop()

def parse_args() -> argparse.Namespace:
    parser=argparse.ArgumentParser(description='Run BGP superloop with true per-segment local IXP steering')
    parser.add_argument('--config', default=os.path.join(REPOSITORY_DIRECTORY,'config/run_config_bgp_superloop_segmented.json'))
    parser.add_argument('--results-dir', default=os.path.join(REPOSITORY_DIRECTORY,'results/bgp_superloop_segmented_local'))
    parser.add_argument('--telemetry-mode', choices=['mode1','mode2','mode3'], default=None)
    parser.add_argument('--warmup-s', type=float, default=12.0)
    parser.add_argument('--bgp-wait-timeout-s', type=float, default=45.0)
    parser.add_argument('--bgp-poll-s', type=float, default=2.0)
    return parser.parse_args()

def main() -> None:
    args=parse_args()
    configure_logging(); setLogLevel('info')
    config=RunConfig.load(args.config)
    topology_class=load_topology_class(config.topology_name)
    network=Mininet(topo=topology_class(), link=TCLink, autoSetMacs=False)
    LOGGER.info('Starting Mininet network for topology %s', config.topology_name)
    network.start()
    try:
        asyncio.run(async_main(args, network, config))
    finally:
        network.stop()

if __name__ == '__main__':
    main()
