from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import re
import statistics
import subprocess
import time
from dataclasses import dataclass
from typing import Any

import finsy

from common.p4.functions import HelperFunctions

logger = finsy.LoggerAdapter(logging.getLogger("finsy"))

MAC_DIGEST_NAME = "mac_learn_digest_t"
SAMPLING_DIGEST_NAME = "telemetry_sample_digest_t"
DMAC_TABLE = "dmac"
FORWARD_ACTION = "forward"
TENANT_TABLE = "tenant_port_map"
CLASSIFIER_TABLE = "steering_classifier"
ACTIVE_EGRESS_TABLE = "active_egress"
SAMPLING_TABLE = "telemetry_sample_control"
MODE2_COUNT_REGISTER = "mode2_sample_count_reg"
MODE2_QUEUE_REGISTER = "mode2_queue_sum_reg"
MODE2_RESIDENCE_REGISTER = "mode2_residence_sum_reg"


@dataclass(frozen=True)
class PathConfig:
    name: str
    egress_port: int
    egress_mac: str


@dataclass(frozen=True)
class SwitchConfig:
    name: str
    grpc_address: str
    device_id: int
    thrift_port: int
    ports: tuple[int, ...]
    paths: dict[str, PathConfig]


@dataclass(frozen=True)
class TenantConfig:
    switch: str
    tenant_id: int
    ingress_port: int
    name: str


@dataclass(frozen=True)
class GroupConfig:
    name: str
    switch: str
    group_id: int
    policy_id: int
    tenant_id: int
    src_ip: str
    dst_ip: str
    ip_proto: int
    tos: int
    allowed_paths: tuple[str, ...]
    initial_path: str
    kind: str
    path_name: str | None = None


@dataclass(frozen=True)
class ProbeServiceConfig:
    client_host: str
    server_host: str
    server_ip: str
    udp_port: int
    int_udp_port: int
    traffic_tos: int


@dataclass(frozen=True)
class ClosedLoopConfig:
    probe_interval_s: float
    probe_count: int
    probe_timeout_s: float
    ema_alpha: float
    switch_penalty_ms: float
    min_improvement_ms: float
    hold_down_s: float


@dataclass(frozen=True)
class SamplingTelemetryConfig:
    sample_every_n: int
    queue_weight: float
    residence_weight: float
    drain_wait_s: float


@dataclass(frozen=True)
class IntTelemetryConfig:
    queue_weight: float
    residence_weight: float


@dataclass(frozen=True)
class TelemetryConfig:
    mode: str
    sampling: SamplingTelemetryConfig
    int_mode: IntTelemetryConfig


@dataclass(frozen=True)
class RunConfig:
    switches: dict[str, SwitchConfig]
    tenants: tuple[TenantConfig, ...]
    groups: tuple[GroupConfig, ...]
    probe_service: ProbeServiceConfig
    closed_loop: ClosedLoopConfig
    telemetry: TelemetryConfig
    path_links: dict[str, tuple[dict[str, str], ...]]
    experiment: dict[str, Any]

    @classmethod
    def load(cls, config_path: str | pathlib.Path) -> "RunConfig":
        with open(config_path, "r", encoding="utf-8") as file:
            raw = json.load(file)

        switches: dict[str, SwitchConfig] = {}
        for switch_name, switch_raw in raw["switches"].items():
            paths = {
                path_name: PathConfig(
                    name=path_name,
                    egress_port=int(path_raw["egress_port"]),
                    egress_mac=str(path_raw["egress_mac"]),
                )
                for path_name, path_raw in switch_raw["paths"].items()
            }
            device_id = int(switch_raw["device_id"])
            switches[switch_name] = SwitchConfig(
                name=switch_name,
                grpc_address=str(switch_raw["grpc_address"]),
                device_id=device_id,
                thrift_port=int(switch_raw.get("thrift_port", 9090 + device_id)),
                ports=tuple(int(port) for port in switch_raw["ports"]),
                paths=paths,
            )

        tenants = tuple(
            TenantConfig(
                switch=str(entry["switch"]),
                tenant_id=int(entry["tenant_id"]),
                ingress_port=int(entry["ingress_port"]),
                name=str(entry.get("name", f"tenant-{entry['tenant_id']}")),
            )
            for entry in raw["tenants"]
        )

        groups = tuple(
            GroupConfig(
                name=str(entry["name"]),
                switch=str(entry["switch"]),
                group_id=int(entry["group_id"]),
                policy_id=int(entry["policy_id"]),
                tenant_id=int(entry["tenant_id"]),
                src_ip=str(entry["src_ip"]),
                dst_ip=str(entry["dst_ip"]),
                ip_proto=int(entry["ip_proto"]),
                tos=int(entry["tos"]),
                allowed_paths=tuple(str(path_name) for path_name in entry["allowed_paths"]),
                initial_path=str(entry["initial_path"]),
                kind=str(entry["kind"]),
                path_name=(None if entry.get("path_name") is None else str(entry["path_name"])),
            )
            for entry in raw["groups"]
        )

        telemetry_raw = dict(raw.get("telemetry", {}))
        sampling_raw = dict(telemetry_raw.get("sampling", {}))
        int_raw = dict(telemetry_raw.get("int", {}))
        int_udp_port = int(raw.get("probe_service", {}).get("int_udp_port", int_raw.get("udp_port", 5001)))

        probe_service = ProbeServiceConfig(
            client_host=str(raw["probe_service"]["client_host"]),
            server_host=str(raw["probe_service"]["server_host"]),
            server_ip=str(raw["probe_service"]["server_ip"]),
            udp_port=int(raw["probe_service"]["udp_port"]),
            int_udp_port=int_udp_port,
            traffic_tos=int(raw["probe_service"]["traffic_tos"]),
        )

        closed_loop = ClosedLoopConfig(
            probe_interval_s=float(raw["closed_loop"]["probe_interval_s"]),
            probe_count=int(raw["closed_loop"]["probe_count"]),
            probe_timeout_s=float(raw["closed_loop"]["probe_timeout_s"]),
            ema_alpha=float(raw["closed_loop"]["ema_alpha"]),
            switch_penalty_ms=float(raw["closed_loop"]["switch_penalty_ms"]),
            min_improvement_ms=float(raw["closed_loop"]["min_improvement_ms"]),
            hold_down_s=float(raw["closed_loop"]["hold_down_s"]),
        )

        telemetry = TelemetryConfig(
            mode=str(telemetry_raw.get("mode", "mode1")),
            sampling=SamplingTelemetryConfig(
                sample_every_n=int(sampling_raw.get("sample_every_n", 1)),
                queue_weight=float(sampling_raw.get("queue_weight", 0.0)),
                residence_weight=float(sampling_raw.get("residence_weight", 0.0)),
                drain_wait_s=float(sampling_raw.get("drain_wait_s", 0.2)),
            ),
            int_mode=IntTelemetryConfig(
                queue_weight=float(int_raw.get("queue_weight", 0.0)),
                residence_weight=float(int_raw.get("residence_weight", 0.0)),
            ),
        )

        path_links = {
            str(path_name): tuple(dict(item) for item in items)
            for path_name, items in raw.get("path_links", {}).items()
        }
        experiment = dict(raw.get("experiment", {}))

        demo_config = cls(
            switches=switches,
            tenants=tenants,
            groups=groups,
            probe_service=probe_service,
            closed_loop=closed_loop,
            telemetry=telemetry,
            path_links=path_links,
            experiment=experiment,
        )
        demo_config.validate()
        return demo_config

    def validate(self) -> None:
        known_switches = set(self.switches)
        known_tenants = {(tenant.switch, tenant.tenant_id) for tenant in self.tenants}

        if not self.groups:
            raise ValueError("At least one steering group must be configured")
        if self.telemetry.mode not in {"mode1", "mode2", "mode3"}:
            raise ValueError(f"Unsupported telemetry mode: {self.telemetry.mode}")

        for tenant in self.tenants:
            if tenant.switch not in known_switches:
                raise ValueError(f"Tenant {tenant.name} refers to unknown switch {tenant.switch}")

        for group in self.groups:
            if group.switch not in known_switches:
                raise ValueError(f"Group {group.name} refers to unknown switch {group.switch}")
            if (group.switch, group.tenant_id) not in known_tenants:
                raise ValueError(
                    f"Group {group.name} refers to tenant_id={group.tenant_id} not configured on switch {group.switch}"
                )
            if not group.allowed_paths:
                raise ValueError(f"Group {group.name} has an empty allowed_paths list")
            for path_name in group.allowed_paths:
                if path_name not in self.switches[group.switch].paths:
                    raise ValueError(
                        f"Group {group.name} allows unknown path {path_name} on switch {group.switch}"
                    )
            if group.initial_path not in group.allowed_paths:
                raise ValueError(
                    f"Group {group.name} initial_path={group.initial_path} is not inside allowed_paths"
                )
            if group.kind == "probe" and not group.path_name:
                raise ValueError(f"Probe group {group.name} must include path_name")

    @property
    def group_by_name(self) -> dict[str, GroupConfig]:
        return {group.name: group for group in self.groups}

    @property
    def groups_by_switch(self) -> dict[str, list[GroupConfig]]:
        grouped: dict[str, list[GroupConfig]] = {switch_name: [] for switch_name in self.switches}
        for group in self.groups:
            grouped[group.switch].append(group)
        return grouped

    @property
    def tenants_by_switch(self) -> dict[str, list[TenantConfig]]:
        grouped: dict[str, list[TenantConfig]] = {switch_name: [] for switch_name in self.switches}
        for tenant in self.tenants:
            grouped[tenant.switch].append(tenant)
        return grouped

    @property
    def traffic_groups(self) -> tuple[GroupConfig, ...]:
        return tuple(group for group in self.groups if group.kind == "traffic")

    @property
    def probe_tos_by_path(self) -> dict[str, int]:
        mapping: dict[str, int] = {}
        for group in self.groups:
            if group.kind != "probe" or not group.path_name:
                continue
            existing = mapping.get(group.path_name)
            if existing is not None and existing != group.tos:
                raise ValueError(
                    f"Probe path {group.path_name} uses inconsistent TOS values ({existing} vs {group.tos})"
                )
            mapping[group.path_name] = group.tos
        return mapping


@dataclass
class MacEntry:
    port: int
    last_seen: float


@dataclass(frozen=True)
class SamplingReport:
    time_s: float
    switch_name: str
    group_name: str
    path_name: str
    egress_port: int
    queue_depth: int
    residence_us: int
    diffserv: int


@dataclass
class Mode2RegisterSnapshot:
    sample_count: int
    queue_sum: int
    residence_sum: int


class SdxController:
    """P4Runtime controller for the SDX prototype.

    Mode 1 uses active RTT probes only.
    Mode 2 adds sampled digest reports from the switches.
    Mode 3 uses INT-like probe packets decoded at the sender.
    """

    def __init__(
        self,
        config_path: str | pathlib.Path,
        p4info_path: str | pathlib.Path,
        p4blob_path: str | pathlib.Path,
        mac_idle_timeout_s: float = 10.0,
    ) -> None:
        self.config = RunConfig.load(config_path)
        self.p4info_path = pathlib.Path(p4info_path)
        self.p4blob_path = pathlib.Path(p4blob_path)
        self.mac_idle_timeout_s = mac_idle_timeout_s

        self._ready_events: dict[str, asyncio.Event] = {
            switch_name: asyncio.Event() for switch_name in self.config.switches
        }
        self._switches: dict[str, finsy.Switch] = {}
        self._mac_dbs: dict[str, dict[str, MacEntry]] = {}
        self._sampling_reports: list[SamplingReport] = []
        self._mode2_register_snapshots: dict[tuple[str, int], Mode2RegisterSnapshot] = {}
        self.group_current_path: dict[str, str] = {
            group.name: group.initial_path for group in self.config.groups
        }
        self._group_by_switch_and_id: dict[tuple[str, int], GroupConfig] = {
            (group.switch, group.group_id): group for group in self.config.groups
        }

        for switch_name, switch_cfg in self.config.switches.items():
            self._switches[switch_name] = finsy.Switch(
                switch_name,
                switch_cfg.grpc_address,
                finsy.SwitchOptions(
                    p4info=self.p4info_path,
                    p4blob=self.p4blob_path,
                    device_id=switch_cfg.device_id,
                    ready_handler=self._controller_ready_handler,
                ),
            )

        self._controller = finsy.Controller(list(self._switches.values()))
        self._controller_task: asyncio.Task[None] | None = None

    @property
    def switches(self) -> dict[str, finsy.Switch]:
        return self._switches

    async def start(self) -> None:
        if self._controller_task is not None:
            return
        self._controller_task = asyncio.create_task(self._controller.run())

    async def stop(self) -> None:
        if self._controller_task is None:
            return
        self._controller_task.cancel()
        try:
            await self._controller_task
        except asyncio.CancelledError:
            pass
        self._controller_task = None

    async def wait_until_ready(self, timeout_s: float = 30.0) -> None:
        await asyncio.wait_for(
            asyncio.gather(*(event.wait() for event in self._ready_events.values())),
            timeout=timeout_s,
        )

    async def set_group_path(self, group_name: str, path_name: str) -> None:
        group = self.config.group_by_name[group_name]
        if path_name not in group.allowed_paths:
            raise ValueError(
                f"Path {path_name} is not allowed for group {group_name}; allowed={group.allowed_paths}"
            )
        entry = self._build_active_egress_entry(group, path_name)
        switch = self._switches[group.switch]
        await switch.modify([entry])
        self.group_current_path[group_name] = path_name
        logger.info("%s: group %s -> path %s", group.switch, group_name, path_name)

    async def set_traffic_path(self, path_name: str) -> None:
        await asyncio.gather(
            *(self.set_group_path(group.name, path_name) for group in self.config.traffic_groups)
        )

    def _mode2_probe_groups_for_path(self, path_name: str) -> tuple[GroupConfig, ...]:
        return tuple(
            group
            for group in self.config.groups
            if group.kind == "probe" and group.path_name == path_name
        )

    def _read_mode2_register_snapshot(self, switch_name: str, group_ids: tuple[int, ...]) -> dict[int, Mode2RegisterSnapshot]:
        if not group_ids:
            return {}

        switch_cfg = self.config.switches[switch_name]
        commands: list[str] = []
        for group_id in group_ids:
            commands.append(f"register_read {MODE2_COUNT_REGISTER} {group_id}")
            commands.append(f"register_read {MODE2_QUEUE_REGISTER} {group_id}")
            commands.append(f"register_read {MODE2_RESIDENCE_REGISTER} {group_id}")
        cli_input = "\n".join(commands) + "\n"

        try:
            result = subprocess.run(
                ["simple_switch_CLI", "--thrift-port", str(switch_cfg.thrift_port)],
                input=cli_input,
                text=True,
                capture_output=True,
                check=True,
                timeout=5.0,
            )
        except Exception as exc:  # pragma: no cover - depends on local BMv2 install
            logger.warning("%s: failed to read Mode 2 registers (%s): %r", switch_name, type(exc).__name__, exc)
            return {}

        stdout = result.stdout
        snapshots: dict[int, Mode2RegisterSnapshot] = {}
        for group_id in group_ids:
            count = self._extract_register_value(stdout, MODE2_COUNT_REGISTER, group_id)
            queue_sum = self._extract_register_value(stdout, MODE2_QUEUE_REGISTER, group_id)
            residence_sum = self._extract_register_value(stdout, MODE2_RESIDENCE_REGISTER, group_id)
            if count is None or queue_sum is None or residence_sum is None:
                continue
            snapshots[group_id] = Mode2RegisterSnapshot(
                sample_count=count,
                queue_sum=queue_sum,
                residence_sum=residence_sum,
            )
        return snapshots

    @staticmethod
    def _extract_register_value(cli_stdout: str, register_name: str, index: int) -> int | None:
        pattern = re.compile(rf"{re.escape(register_name)}\[{index}\]\s*=\s*(\d+)")
        match = pattern.search(cli_stdout)
        if match:
            return int(match.group(1))
        return None

    def get_sampling_summary(self, path_name: str, since_s: float) -> dict[str, Any]:
        probe_groups = self._mode2_probe_groups_for_path(path_name)
        probe_group_names = {group.name for group in probe_groups}
        relevant = [
            report
            for report in self._sampling_reports
            if report.time_s >= since_s
            and report.path_name == path_name
            and report.group_name in probe_group_names
        ]

        avg_queue_depth: float | None = None
        avg_residence_ms: float | None = None
        register_report_count = 0

        if self.config.telemetry.mode == "mode2":
            groups_by_switch: dict[str, list[GroupConfig]] = {}
            for group in probe_groups:
                groups_by_switch.setdefault(group.switch, []).append(group)

            total_delta_count = 0
            total_delta_queue = 0
            total_delta_residence = 0
            for switch_name, groups in groups_by_switch.items():
                group_ids = tuple(group.group_id for group in groups)
                current = self._read_mode2_register_snapshot(switch_name, group_ids)
                for group in groups:
                    snapshot = current.get(group.group_id)
                    if snapshot is None:
                        continue
                    key = (switch_name, group.group_id)
                    previous = self._mode2_register_snapshots.get(key)
                    if previous is None:
                        delta_count = snapshot.sample_count
                        delta_queue = snapshot.queue_sum
                        delta_residence = snapshot.residence_sum
                    else:
                        delta_count = max(0, snapshot.sample_count - previous.sample_count)
                        delta_queue = max(0, snapshot.queue_sum - previous.queue_sum)
                        delta_residence = max(0, snapshot.residence_sum - previous.residence_sum)
                    self._mode2_register_snapshots[key] = snapshot
                    total_delta_count += delta_count
                    total_delta_queue += delta_queue
                    total_delta_residence += delta_residence

            if total_delta_count > 0:
                register_report_count = total_delta_count
                avg_queue_depth = total_delta_queue / total_delta_count
                avg_residence_ms = (total_delta_residence / total_delta_count) / 1000.0

        digest_report_count = len(relevant)
        report_count = register_report_count if register_report_count > 0 else digest_report_count
        if digest_report_count > 0 and register_report_count > 0:
            report_count = min(digest_report_count, register_report_count)

        return {
            "report_count": report_count,
            "avg_queue_depth": avg_queue_depth,
            "avg_residence_ms": avg_residence_ms,
            "switches": sorted({report.switch_name for report in relevant}),
        }

    async def _controller_ready_handler(self, sw: finsy.Switch) -> None:
        if not sw.is_primary:
            return

        switch_cfg = self.config.switches[sw.name]
        await sw.delete_all()
        await self._provision_multicast_groups(sw, switch_cfg.ports)
        await self._provision_tenant_entries(sw)
        await self._provision_classifier_entries(sw)
        await self._provision_active_egress_entries(sw)
        await self._provision_sampling_entries(sw)
        await self._reset_mode2_registers(sw)
        await self._enable_digests(sw)

        mac_db: dict[str, MacEntry] = {}
        self._mac_dbs[sw.name] = mac_db
        sw.create_task(self._digest_listener_task(sw, mac_db))
        sw.create_task(self._sampling_digest_listener_task(sw))
        sw.create_task(self._mac_aging_task(sw, mac_db))

        self._ready_events[sw.name].set()
        logger.info("%s: SDX controller ready", sw.name)

    async def _provision_multicast_groups(self, sw: finsy.Switch, ports: tuple[int, ...]) -> None:
        groups = []
        for ingress in ports:
            replicas = [port for port in ports if port != ingress]
            groups.append(finsy.P4MulticastGroupEntry(ingress, replicas=replicas))
        await sw.insert(groups)

    async def _provision_tenant_entries(self, sw: finsy.Switch) -> None:
        entries = [self._build_tenant_entry(tenant) for tenant in self.config.tenants_by_switch[sw.name]]
        if entries:
            await sw.insert(entries)

    async def _provision_classifier_entries(self, sw: finsy.Switch) -> None:
        entries = [self._build_classifier_entry(group) for group in self.config.groups_by_switch[sw.name]]
        if entries:
            await sw.insert(entries)

    async def _provision_active_egress_entries(self, sw: finsy.Switch) -> None:
        entries = [self._build_active_egress_entry(group, group.initial_path) for group in self.config.groups_by_switch[sw.name]]
        if entries:
            await sw.insert(entries)

    async def _provision_sampling_entries(self, sw: finsy.Switch) -> None:
        sample_every_n = max(0, int(self.config.telemetry.sampling.sample_every_n))
        if sample_every_n <= 0:
            return
        entries = [self._build_sampling_entry(group, sample_every_n) for group in self.config.groups_by_switch[sw.name]]
        if entries:
            await sw.insert(entries)

    async def _reset_mode2_registers(self, sw: finsy.Switch) -> None:
        if self.config.telemetry.mode != "mode2" or self.config.telemetry.sampling.sample_every_n <= 0:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._reset_mode2_registers_sync, sw.name)

    def _reset_mode2_registers_sync(self, switch_name: str) -> None:
        switch_cfg = self.config.switches[switch_name]
        commands = "\n".join(
            [
                f"register_reset {MODE2_COUNT_REGISTER}",
                f"register_reset {MODE2_QUEUE_REGISTER}",
                f"register_reset {MODE2_RESIDENCE_REGISTER}",
            ]
        ) + "\n"
        try:
            subprocess.run(
                ["simple_switch_CLI", "--thrift-port", str(switch_cfg.thrift_port)],
                input=commands,
                text=True,
                capture_output=True,
                check=True,
                timeout=5.0,
            )
        except Exception as exc:  # pragma: no cover - depends on local BMv2 install
            logger.warning("%s: failed to reset Mode 2 registers (%s): %r", switch_name, type(exc).__name__, exc)
        else:
            logger.info("%s: reset Mode 2 egress telemetry registers", switch_name)

    async def _enable_digests(self, sw: finsy.Switch) -> None:
        entries = [finsy.P4DigestEntry(MAC_DIGEST_NAME, max_list_size=1)]
        if self.config.telemetry.sampling.sample_every_n > 0:
            entries.append(finsy.P4DigestEntry(SAMPLING_DIGEST_NAME, max_list_size=1))
        await sw.insert(entries)

    def _build_tenant_entry(self, tenant: TenantConfig) -> finsy.P4TableEntry:
        return finsy.P4TableEntry(
            TENANT_TABLE,
            match=finsy.Match(ingress_port=tenant.ingress_port),
            action=finsy.Action("set_tenant", tenant_id=tenant.tenant_id),
        )

    def _build_classifier_entry(self, group: GroupConfig) -> finsy.P4TableEntry:
        return finsy.P4TableEntry(
            CLASSIFIER_TABLE,
            match=finsy.Match(
                tenant_id=group.tenant_id,
                srcAddr=HelperFunctions.convert_ip_address_string_to_integer(group.src_ip),
                dstAddr=HelperFunctions.convert_ip_address_string_to_integer(group.dst_ip),
                protocol=group.ip_proto,
                diffserv=group.tos,
            ),
            action=finsy.Action("classify", group_id=group.group_id, policy_id=group.policy_id),
        )

    def _build_active_egress_entry(self, group: GroupConfig, path_name: str) -> finsy.P4TableEntry:
        path_cfg = self.config.switches[group.switch].paths[path_name]
        return finsy.P4TableEntry(
            ACTIVE_EGRESS_TABLE,
            match=finsy.Match(group_id=group.group_id),
            action=finsy.Action(
                "set_active_egress",
                egress_mac=path_cfg.egress_mac,
                port=path_cfg.egress_port,
            ),
        )

    def _build_sampling_entry(self, group: GroupConfig, sample_every_n: int) -> finsy.P4TableEntry:
        return finsy.P4TableEntry(
            SAMPLING_TABLE,
            match=finsy.Match(group_id=group.group_id),
            action=finsy.Action("set_sampling", sample_every_n=sample_every_n),
        )

    def _build_forward_entry(self, mac_address: str, port: int) -> finsy.P4TableEntry:
        return finsy.P4TableEntry(
            DMAC_TABLE,
            match=finsy.Match(dstAddr=mac_address),
            action=finsy.Action(FORWARD_ACTION, port=port),
        )

    async def _mac_aging_task(self, sw: finsy.Switch, mac_db: dict[str, MacEntry]) -> None:
        while True:
            await asyncio.sleep(1.0)
            now = time.monotonic()
            expired = [
                mac_address
                for mac_address, entry in mac_db.items()
                if (now - entry.last_seen) >= self.mac_idle_timeout_s
            ]
            if not expired:
                continue

            delete_entries = []
            for mac_address in expired:
                entry = mac_db.pop(mac_address, None)
                if entry is None:
                    continue
                delete_entries.append(self._build_forward_entry(mac_address, entry.port))

            if delete_entries:
                await sw.delete(delete_entries)
                logger.info("%s: aged out %d MAC entries", sw.name, len(delete_entries))

    async def _digest_listener_task(self, sw: finsy.Switch, mac_db: dict[str, MacEntry]) -> None:
        async for digest_message in sw.read_digests(MAC_DIGEST_NAME):
            try:
                records = self._extract_digest_records(digest_message)
            except Exception as exc:  # pragma: no cover - depends on runtime representation
                logger.warning(
                    "%s: failed to read digest records (%s): %r",
                    sw.name,
                    type(exc).__name__,
                    exc,
                )
                await sw.write([digest_message.ack()])
                continue

            for record in records:
                try:
                    src_mac = self._normalize_mac_from_digest(record["srcAddr"])
                    ingress_port = int(record["ingress_port"])
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "%s: failed to parse digest record (%s): %r",
                        sw.name,
                        type(exc).__name__,
                        exc,
                    )
                    continue

                if not self._is_unicast_src_mac(src_mac):
                    continue

                now = time.monotonic()
                old_entry = mac_db.get(src_mac)
                if old_entry is None:
                    mac_db[src_mac] = MacEntry(port=ingress_port, last_seen=now)
                    await sw.insert([self._build_forward_entry(src_mac, ingress_port)])
                    logger.info("%s: learned %s on port %d", sw.name, src_mac, ingress_port)
                    continue

                old_entry.last_seen = now
                if old_entry.port != ingress_port:
                    old_entry.port = ingress_port
                    await sw.modify([self._build_forward_entry(src_mac, ingress_port)])
                    logger.info("%s: moved %s to port %d", sw.name, src_mac, ingress_port)

            await sw.write([digest_message.ack()])

    async def _sampling_digest_listener_task(self, sw: finsy.Switch) -> None:
        if self.config.telemetry.sampling.sample_every_n <= 0:
            return
        async for digest_message in sw.read_digests(SAMPLING_DIGEST_NAME):
            try:
                records = self._extract_digest_records(digest_message)
            except Exception as exc:  # pragma: no cover - runtime dependent
                logger.warning(
                    "%s: failed to read sampling digest records (%s): %r",
                    sw.name,
                    type(exc).__name__,
                    exc,
                )
                await sw.write([digest_message.ack()])
                continue

            now = time.monotonic()
            for record in records:
                try:
                    group_id = int(record["group_id"])
                    egress_port = int(record.get("egress_port", 0))
                    diffserv = int(record.get("diffserv", 0))
                    queue_depth = int(record.get("queue_depth", 0))
                    residence_us = int(record.get("residence_us", 0))
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "%s: failed to parse sampling digest record (%s): %r",
                        sw.name,
                        type(exc).__name__,
                        exc,
                    )
                    continue

                group = self._group_by_switch_and_id.get((sw.name, group_id))
                if group is None:
                    continue

                path_name = group.path_name or self._path_name_from_egress_port(sw.name, egress_port)
                if path_name is None:
                    continue

                self._sampling_reports.append(
                    SamplingReport(
                        time_s=now,
                        switch_name=sw.name,
                        group_name=group.name,
                        path_name=path_name,
                        egress_port=egress_port,
                        queue_depth=queue_depth,
                        residence_us=residence_us,
                        diffserv=diffserv,
                    )
                )

            self._prune_sampling_reports(now)
            await sw.write([digest_message.ack()])

    def _prune_sampling_reports(self, now_s: float | None = None, window_s: float = 60.0) -> None:
        cutoff = (time.monotonic() if now_s is None else now_s) - window_s
        self._sampling_reports = [report for report in self._sampling_reports if report.time_s >= cutoff]

    def _path_name_from_egress_port(self, switch_name: str, egress_port: int) -> str | None:
        for path_name, path_cfg in self.config.switches[switch_name].paths.items():
            if path_cfg.egress_port == egress_port:
                return path_name
        return None

    @staticmethod
    def _extract_digest_records(digest_message: Any) -> list[dict[str, Any]]:
        if hasattr(digest_message, "data"):
            records = digest_message.data
            if isinstance(records, dict):
                return [records]
            return list(records)
        if isinstance(digest_message, (list, tuple)):
            return list(digest_message)
        return [digest_message]

    @staticmethod
    def _normalize_mac_from_digest(value: Any) -> str:
        if isinstance(value, int):
            return HelperFunctions.convert_mac_address_integer_to_string(value & 0xFFFFFFFFFFFF)

        value_str = str(value).strip().lower()
        if ":" in value_str:
            return value_str

        try:
            if value_str.startswith("0x"):
                mac_int = int(value_str, 16)
            elif value_str.isdigit():
                mac_int = int(value_str)
            else:
                mac_int = int(value_str, 16)
            return HelperFunctions.convert_mac_address_integer_to_string(mac_int & 0xFFFFFFFFFFFF)
        except ValueError:
            return value_str

    @staticmethod
    def _is_unicast_src_mac(mac_str: str) -> bool:
        mac = mac_str.lower()
        if mac == "ff:ff:ff:ff:ff:ff":
            return False
        first_octet = int(mac.split(":")[0], 16)
        return (first_octet & 0x01) == 0
