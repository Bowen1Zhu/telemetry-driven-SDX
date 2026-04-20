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

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, '../'))
sys.path.append(REPOSITORY_DIRECTORY)

from controller.sdx_controller import RunConfig, SdxController
from networks import load_topology_class
from scripts.bgp_support import BgpReachabilityTracker, wait_for_bgp_readiness
from scripts.run_sdx import configure_logging, ensure_parent_dirs

LOGGER = logging.getLogger('sdx_bgp_validate')

async def async_main(args: argparse.Namespace, network: Mininet, config: RunConfig) -> None:
    build_dir = os.path.join(REPOSITORY_DIRECTORY, 'build/p4')
    controller = SdxController(
        config_path=args.config,
        p4info_path=os.path.join(build_dir, 'sdx_ixp.p4info.txtpb'),
        p4blob_path=os.path.join(build_dir, 'sdx_ixp.json'),
    )
    tracker = BgpReachabilityTracker(network=network, config=config, logger=LOGGER)
    rows: list[dict[str, object]] = []
    results_dir = args.results_dir
    os.makedirs(results_dir, exist_ok=True)
    csv_path = os.path.join(results_dir, 'latest_run.csv')
    summary_path = os.path.join(results_dir, 'latest_summary.json')
    try:
        await controller.start()
        await controller.wait_until_ready(timeout_s=45.0)
        LOGGER.info('Waiting %.1fs for initial FRR/BGP warm-up', args.warmup_s)
        await asyncio.sleep(args.warmup_s)
        await wait_for_bgp_readiness(
            tracker=tracker,
            timeout_s=args.bgp_wait_timeout_s,
            poll_s=args.bgp_poll_s,
            logger=LOGGER,
            require_expected=True,
        )
        tracker.refresh()
        pass_count = 0
        for session in config.traffic_sessions:
            observed = list(tracker.allowed_paths_for_session(session.name))
            expected = tracker.expected_paths_for_session(session.name)
            passed = (expected is None) or (tuple(observed) == tuple(expected))
            if passed:
                pass_count += 1
            rows.append({
                'session': session.name,
                'client_host': session.client_host,
                'server_host': session.server_host,
                'server_ip': session.server_ip,
                'observed_allowed_paths': ','.join(observed),
                'expected_allowed_paths': '' if expected is None else ','.join(expected),
                'pass': passed,
            })
        ensure_parent_dirs(csv_path)
        with open(csv_path, 'w', encoding='utf-8', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=list(rows[0].keys()) if rows else ['session'])
            writer.writeheader()
            writer.writerows(rows)
        summary = {
            'topology_name': config.topology_name,
            'session_count': len(config.traffic_sessions),
            'pass_count': pass_count,
            'fail_count': len(config.traffic_sessions) - pass_count,
            'csv_path': csv_path,
        }
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        LOGGER.info('BGP reachability validation finished; results written to %s and %s', csv_path, summary_path)
    finally:
        await controller.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Validate BGP-derived allowed path sets for the BGP-aware topology')
    parser.add_argument('--config', default=os.path.join(REPOSITORY_DIRECTORY, 'config/run_config_bgp_generalized.json'))
    parser.add_argument('--results-dir', default=os.path.join(REPOSITORY_DIRECTORY, 'results/bgp_reachability_validation'))
    parser.add_argument('--warmup-s', type=float, default=12.0)
    parser.add_argument('--bgp-wait-timeout-s', type=float, default=45.0)
    parser.add_argument('--bgp-poll-s', type=float, default=2.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging()
    setLogLevel('info')
    config = RunConfig.load(args.config)
    topology_class = load_topology_class(config.topology_name)
    network = Mininet(topo=topology_class(), link=TCLink, autoSetMacs=False)
    LOGGER.info("Starting Mininet network for topology %s", config.topology_name)
    network.start()
    try:
        asyncio.run(async_main(args, network, config))
    finally:
        network.stop()

if __name__ == '__main__':
    main()
