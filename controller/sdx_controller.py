from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import time
from dataclasses import dataclass
from typing import Any

import finsy

from common.p4.functions import HelperFunctions

LOG = finsy.LoggerAdapter(logging.getLogger("finsy"))

DIGEST_NAME = "mac_learn_digest_t"
DMAC_TABLE = "dmac"
FORWARD_ACTION = "forward"
TENANT_TABLE = "tenant_port_map"
CLASSIFIER_TABLE = "steering_classifier"
ACTIVE_EGRESS_TABLE = "active_egress"


@dataclass(frozen=True)
class PathConfig:
    egress_port: int
    egress_mac: str


@dataclass(frozen=True)
class SwitchConfig:
    grpc_address: str
    device_id: int
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
class ProbeConfig:
    client_host: str
    server_host: str
    server_ip: str
    udp_port: int
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
class RunConfig:
    switches: dict[str, SwitchConfig]
    tenants: tuple[TenantConfig, ...]
    groups: tuple[GroupConfig, ...]
    probe: ProbeConfig
    closed_loop: ClosedLoopConfig
    path_links: dict[str, tuple[dict[str, str], ...]]
    run: dict[str, Any]

    @classmethod
    def load(cls, config_path: str | pathlib.Path) -> "RunConfig":
        with open(config_path, "r", encoding="utf-8") as file:
            raw = json.load(file)

        switches = {
            switch_name: SwitchConfig(
                grpc_address=str(switch_raw["grpc_address"]),
                device_id=int(switch_raw["device_id"]),
                ports=tuple(int(port) for port in switch_raw["ports"]),
                paths={
                    path_name: PathConfig(
                        egress_port=int(path_raw["egress_port"]),
                        egress_mac=str(path_raw["egress_mac"]),
                    )
                    for path_name, path_raw in switch_raw["paths"].items()
                },
            )
            for switch_name, switch_raw in raw["switches"].items()
        }

        tenants = tuple(
            TenantConfig(
                switch=str(item["switch"]),
                tenant_id=int(item["tenant_id"]),
                ingress_port=int(item["ingress_port"]),
                name=str(item.get("name", f"tenant-{item['tenant_id']}")),
            )
            for item in raw["tenants"]
        )

        groups = tuple(
            GroupConfig(
                name=str(item["name"]),
                switch=str(item["switch"]),
                group_id=int(item["group_id"]),
                policy_id=int(item["policy_id"]),
                tenant_id=int(item["tenant_id"]),
                src_ip=str(item["src_ip"]),
                dst_ip=str(item["dst_ip"]),
                ip_proto=int(item["ip_proto"]),
                tos=int(item["tos"]),
                allowed_paths=tuple(str(path_name) for path_name in item["allowed_paths"]),
                initial_path=str(item["initial_path"]),
                kind=str(item["kind"]),
                path_name=(None if item.get("path_name") is None else str(item["path_name"])),
            )
            for item in raw["groups"]
        )

        probe = ProbeConfig(
            client_host=str(raw["probe_service"]["client_host"]),
            server_host=str(raw["probe_service"]["server_host"]),
            server_ip=str(raw["probe_service"]["server_ip"]),
            udp_port=int(raw["probe_service"]["udp_port"]),
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

        run_config = cls(
            switches=switches,
            tenants=tenants,
            groups=groups,
            probe=probe,
            closed_loop=closed_loop,
            path_links={
                str(path_name): tuple(dict(item) for item in items)
                for path_name, items in raw.get("path_links", {}).items()
            },
            run=dict(raw.get("experiment", {})),
        )
        run_config.validate()
        return run_config

    def validate(self) -> None:
        known_switches = set(self.switches)
        known_tenants = {(tenant.switch, tenant.tenant_id) for tenant in self.tenants}

        if not self.groups:
            raise ValueError("At least one steering group must be configured")

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
    def groups_by_name(self) -> dict[str, GroupConfig]:
        return {group.name: group for group in self.groups}

    @property
    def traffic_groups(self) -> tuple[GroupConfig, ...]:
        return tuple(group for group in self.groups if group.kind == "traffic")

    @property
    def probe_tos_by_path(self) -> dict[str, int]:
        probe_tos: dict[str, int] = {}
        for group in self.groups:
            if group.kind != "probe" or group.path_name is None:
                continue
            old_tos = probe_tos.get(group.path_name)
            if old_tos is not None and old_tos != group.tos:
                raise ValueError(
                    f"Probe path {group.path_name} uses inconsistent TOS values ({old_tos} vs {group.tos})"
                )
            probe_tos[group.path_name] = group.tos
        return probe_tos

    def groups_on(self, switch_name: str) -> tuple[GroupConfig, ...]:
        return tuple(group for group in self.groups if group.switch == switch_name)

    def tenants_on(self, switch_name: str) -> tuple[TenantConfig, ...]:
        return tuple(tenant for tenant in self.tenants if tenant.switch == switch_name)


@dataclass
class MacEntry:
    port: int
    last_seen: float


class SdxController:
    def __init__(
        self,
        config_path: str | pathlib.Path,
        p4info_path: str | pathlib.Path,
        p4blob_path: str | pathlib.Path,
        mac_idle_timeout_s: float = 10.0,
    ) -> None:
        self.config = RunConfig.load(config_path)
        self.mac_idle_timeout_s = mac_idle_timeout_s
        self.group_current_path = {group.name: group.initial_path for group in self.config.groups}

        self._ready = {switch_name: asyncio.Event() for switch_name in self.config.switches}
        self._mac_tables: dict[str, dict[str, MacEntry]] = {}
        self._switches = {
            switch_name: finsy.Switch(
                switch_name,
                switch_cfg.grpc_address,
                finsy.SwitchOptions(
                    p4info=pathlib.Path(p4info_path),
                    p4blob=pathlib.Path(p4blob_path),
                    device_id=switch_cfg.device_id,
                    ready_handler=self._on_ready,
                ),
            )
            for switch_name, switch_cfg in self.config.switches.items()
        }
        self._controller = finsy.Controller(list(self._switches.values()))
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._controller.run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def wait_until_ready(self, timeout_s: float = 30.0) -> None:
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in self._ready.values())), timeout=timeout_s)

    async def set_group_path(self, group_name: str, path_name: str) -> None:
        group = self.config.groups_by_name[group_name]
        if path_name not in group.allowed_paths:
            raise ValueError(
                f"Path {path_name} is not allowed for group {group_name}; allowed={group.allowed_paths}"
            )
        await self._switches[group.switch].modify([self._active_egress_entry(group, path_name)])
        self.group_current_path[group_name] = path_name
        LOG.info("%s: group %s -> path %s", group.switch, group_name, path_name)

    async def set_traffic_path(self, path_name: str) -> None:
        await asyncio.gather(*(self.set_group_path(group.name, path_name) for group in self.config.traffic_groups))

    async def _on_ready(self, switch: finsy.Switch) -> None:
        if not switch.is_primary:
            return

        cfg = self.config.switches[switch.name]
        await switch.delete_all()
        await switch.insert(self._multicast_entries(cfg.ports))
        await self._insert_if_any(switch, [self._tenant_entry(tenant) for tenant in self.config.tenants_on(switch.name)])
        await self._insert_if_any(switch, [self._classifier_entry(group) for group in self.config.groups_on(switch.name)])
        await self._insert_if_any(
            switch,
            [self._active_egress_entry(group, group.initial_path) for group in self.config.groups_on(switch.name)],
        )
        await switch.insert([finsy.P4DigestEntry(DIGEST_NAME, max_list_size=1)])

        mac_table: dict[str, MacEntry] = {}
        self._mac_tables[switch.name] = mac_table
        switch.create_task(self._digest_task(switch, mac_table))
        switch.create_task(self._mac_aging_task(switch, mac_table))

        self._ready[switch.name].set()
        LOG.info("%s: SDX controller ready", switch.name)

    @staticmethod
    async def _insert_if_any(switch: finsy.Switch, entries: list[Any]) -> None:
        if entries:
            await switch.insert(entries)

    @staticmethod
    def _multicast_entries(ports: tuple[int, ...]) -> list[finsy.P4MulticastGroupEntry]:
        return [
            finsy.P4MulticastGroupEntry(ingress_port, replicas=[port for port in ports if port != ingress_port])
            for ingress_port in ports
        ]

    @staticmethod
    def _tenant_entry(tenant: TenantConfig) -> finsy.P4TableEntry:
        return finsy.P4TableEntry(
            TENANT_TABLE,
            match=finsy.Match(ingress_port=tenant.ingress_port),
            action=finsy.Action("set_tenant", tenant_id=tenant.tenant_id),
        )

    @staticmethod
    def _classifier_entry(group: GroupConfig) -> finsy.P4TableEntry:
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

    def _active_egress_entry(self, group: GroupConfig, path_name: str) -> finsy.P4TableEntry:
        path = self.config.switches[group.switch].paths[path_name]
        return finsy.P4TableEntry(
            ACTIVE_EGRESS_TABLE,
            match=finsy.Match(group_id=group.group_id),
            action=finsy.Action("set_active_egress", egress_mac=path.egress_mac, port=path.egress_port),
        )

    @staticmethod
    def _forward_entry(mac_address: str, port: int) -> finsy.P4TableEntry:
        return finsy.P4TableEntry(
            DMAC_TABLE,
            match=finsy.Match(dstAddr=mac_address),
            action=finsy.Action(FORWARD_ACTION, port=port),
        )

    async def _mac_aging_task(self, switch: finsy.Switch, mac_table: dict[str, MacEntry]) -> None:
        while True:
            await asyncio.sleep(1.0)
            now = time.monotonic()
            expired = [
                mac_address
                for mac_address, entry in mac_table.items()
                if (now - entry.last_seen) >= self.mac_idle_timeout_s
            ]
            if not expired:
                continue

            delete_entries = []
            for mac_address in expired:
                entry = mac_table.pop(mac_address, None)
                if entry is not None:
                    delete_entries.append(self._forward_entry(mac_address, entry.port))

            if delete_entries:
                await switch.delete(delete_entries)
                LOG.info("%s: aged out %d MAC entries", switch.name, len(delete_entries))

    async def _digest_task(self, switch: finsy.Switch, mac_table: dict[str, MacEntry]) -> None:
        async for digest in switch.read_digests(DIGEST_NAME):
            try:
                records = self._digest_records(digest)
            except Exception as exc:  # pragma: no cover - runtime-dependent representation
                LOG.warning("%s: failed to read digest records (%s): %r", switch.name, type(exc).__name__, exc)
                await switch.write([digest.ack()])
                continue

            for record in records:
                try:
                    src_mac = self._mac_string(record["srcAddr"])
                    ingress_port = int(record["ingress_port"])
                except Exception as exc:  # pragma: no cover - defensive parsing
                    LOG.warning("%s: failed to parse digest record (%s): %r", switch.name, type(exc).__name__, exc)
                    continue

                if not self._is_unicast(src_mac):
                    continue

                now = time.monotonic()
                old = mac_table.get(src_mac)
                if old is None:
                    mac_table[src_mac] = MacEntry(port=ingress_port, last_seen=now)
                    await switch.insert([self._forward_entry(src_mac, ingress_port)])
                    LOG.info("%s: learned %s on port %d", switch.name, src_mac, ingress_port)
                    continue

                old.last_seen = now
                if old.port != ingress_port:
                    old.port = ingress_port
                    await switch.modify([self._forward_entry(src_mac, ingress_port)])
                    LOG.info("%s: moved %s to port %d", switch.name, src_mac, ingress_port)

            await switch.write([digest.ack()])

    @staticmethod
    def _digest_records(digest: Any) -> list[dict[str, Any]]:
        if hasattr(digest, "data"):
            data = digest.data
            return [data] if isinstance(data, dict) else list(data)
        if isinstance(digest, (list, tuple)):
            return list(digest)
        return [digest]

    @staticmethod
    def _mac_string(value: Any) -> str:
        if isinstance(value, int):
            return HelperFunctions.convert_mac_address_integer_to_string(value & 0xFFFFFFFFFFFF)

        text = str(value).strip().lower()
        if ":" in text:
            return text

        try:
            mac_int = int(text, 0) if text.startswith("0x") or text.isdigit() else int(text, 16)
            return HelperFunctions.convert_mac_address_integer_to_string(mac_int & 0xFFFFFFFFFFFF)
        except ValueError:
            return text

    @staticmethod
    def _is_unicast(mac_address: str) -> bool:
        if mac_address.lower() == "ff:ff:ff:ff:ff:ff":
            return False
        return (int(mac_address.split(":")[0], 16) & 0x01) == 0
