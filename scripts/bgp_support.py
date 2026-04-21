from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from controller.sdx_controller import RunConfig


@dataclass(frozen=True)
class BgpObserverConfig:
    switch: str
    tenant_id: int
    router: str
    next_hop_to_path: dict[str, str]


class BgpReachabilityTracker:
    """Track BGP-derived allowed paths and install minimal bootstrap routes.

    The BGP tracker is the source of truth for which path names are legal for each
    session. In this emulated environment, however, the Linux forwarding plane on the
    edge/transit routers is not always ready to carry host /32 traffic purely from the
    BGP control plane. To make packets actually traverse the topology, we install a
    small set of static /32 bootstrap routes on:
      * the source edge router,
      * the destination edge router,
      * and the relevant slow/fast transit routers.

    These routes do NOT decide which path is legal. They simply make the data plane
    operational so that the SDX can steer within the BGP-allowed set.
    """

    def __init__(self, network: Any, config: RunConfig, logger: logging.Logger) -> None:
        self.network = network
        self.config = config
        self.logger = logger

        raw = dict(config.bgp_reachability or {})
        self.enabled = bool(raw.get("enabled", False))
        self.refresh_each_interval = bool(raw.get("refresh_each_interval", False))

        self.expected_by_session: dict[str, tuple[str, ...]] = {
            str(name): tuple(str(p) for p in paths)
            for name, paths in dict(raw.get("expected_allowed_paths_by_session", {})).items()
        }

        self.observers: dict[tuple[str, int], BgpObserverConfig] = {}
        for item in raw.get("observers", []):
            observer = BgpObserverConfig(
                switch=str(item["switch"]),
                tenant_id=int(item["tenant_id"]),
                router=str(item["router"]),
                next_hop_to_path={str(k): str(v) for k, v in dict(item["next_hop_to_path"]).items()},
            )
            self.observers[(observer.switch, observer.tenant_id)] = observer

        # Optional explicit peering/transit metadata. Fall back to topology-specific defaults.
        self.edge_router_peering_ip: dict[str, str] = {
            str(router): str(ip)
            for router, ip in dict(raw.get("edge_router_peering_ip", {})).items()
        }
        self.path_transit_router: dict[str, str] = {
            str(path): str(router)
            for path, router in dict(raw.get("path_transit_router", {})).items()
        }
        self.path_transit_routers: dict[str, tuple[str, ...]] = {
            str(path): tuple(str(router) for router in routers)
            for path, routers in dict(raw.get("path_transit_routers", {})).items()
        }

        self.group_by_name = {group.name: group for group in self.config.traffic_groups}
        self.session_by_name = {session.name: session for session in self.config.traffic_sessions}
        self.group_allowed_paths: dict[str, tuple[str, ...]] = {}
        self.session_allowed_paths: dict[str, tuple[str, ...]] = {}
        self.refresh_static_fallback()

    def refresh_static_fallback(self) -> None:
        self.group_allowed_paths = {group.name: tuple(group.allowed_paths) for group in self.config.traffic_groups}
        self.session_allowed_paths = {}
        for session in self.config.traffic_sessions:
            forward = set(self.group_allowed_paths.get(session.forward_group, ()))
            reverse = set(self.group_allowed_paths.get(session.reverse_group, ()))
            self.session_allowed_paths[session.name] = tuple(
                path for path in ("slow", "fast") if path in forward and path in reverse
            )

    def refresh(self) -> None:
        if not self.enabled:
            self.refresh_static_fallback()
            return

        cache: dict[tuple[str, str], tuple[str, ...]] = {}
        updated_group_paths: dict[str, tuple[str, ...]] = {}
        for group in self.config.traffic_groups:
            observer = self.observers.get((group.switch, group.tenant_id))
            if observer is None:
                updated_group_paths[group.name] = tuple(group.allowed_paths)
                continue
            prefix = f"{group.dst_ip}/32"
            observed_paths = self._reachable_paths(observer, prefix, cache)
            allowed = tuple(path for path in group.allowed_paths if path in observed_paths)
            updated_group_paths[group.name] = allowed

        self.group_allowed_paths = updated_group_paths
        updated_session_paths: dict[str, tuple[str, ...]] = {}
        for session in self.config.traffic_sessions:
            forward = set(self.group_allowed_paths.get(session.forward_group, ()))
            reverse = set(self.group_allowed_paths.get(session.reverse_group, ()))
            updated_session_paths[session.name] = tuple(
                path for path in ("slow", "fast") if path in forward and path in reverse
            )
        self.session_allowed_paths = updated_session_paths

    def allowed_paths_for_session(self, session_name: str) -> tuple[str, ...]:
        return tuple(self.session_allowed_paths.get(session_name, ()))

    def allowed_paths_for_group(self, group_name: str) -> tuple[str, ...]:
        return tuple(self.group_allowed_paths.get(group_name, ()))

    def expected_paths_for_session(self, session_name: str) -> tuple[str, ...] | None:
        value = self.expected_by_session.get(session_name)
        return None if value is None else tuple(value)

    def _group_config(self, group_name: str):
        return self.group_by_name[group_name]

    def _observer_for_group(self, group_name: str) -> BgpObserverConfig | None:
        group = self._group_config(group_name)
        return self.observers.get((group.switch, group.tenant_id))

    def next_hop_for_group_path(self, group_name: str, path_name: str) -> str | None:
        observer = self._observer_for_group(group_name)
        if observer is None:
            return None
        for next_hop, observed_path in observer.next_hop_to_path.items():
            if observed_path == path_name:
                return next_hop
        return None

    def _default_edge_router_peering_ip(self, router_name: str) -> str | None:
        defaults = {
            "as1r1": "8.2.1.1",
            "as5r1": "8.2.1.4",
            "as2r1": "8.2.2.1",
            "as6r1": "8.2.2.4",
        }
        return defaults.get(router_name)

    def edge_peering_ip(self, router_name: str) -> str | None:
        return self.edge_router_peering_ip.get(router_name) or self._default_edge_router_peering_ip(router_name)

    def transit_router_for_path(self, path_name: str) -> str | None:
        value = self.path_transit_router.get(path_name)
        if value is not None:
            return value
        if path_name == "slow":
            return "as3r1"
        if path_name == "fast":
            return "as4r1"
        return None

    def transit_routers_for_path(self, path_name: str) -> tuple[str, ...]:
        value = self.path_transit_routers.get(path_name)
        if value:
            return value
        single = self.transit_router_for_path(path_name)
        return () if single is None else (single,)

    def install_session_dataplane_routes(self) -> None:
        """Install bootstrap /32 routes end-to-end for every session.

        For each session:
          * source edge router gets a route to the server /32 via one legal path;
          * destination edge router gets a reverse route to the client /32 via one legal path;
          * every legal transit router gets the forward and reverse /32 via the relevant
            edge-router peering IP.
        """
        if not self.enabled:
            return

        for session in self.config.traffic_sessions:
            allowed_paths = self.allowed_paths_for_session(session.name)
            if not allowed_paths:
                continue

            preferred_path = "slow" if "slow" in allowed_paths else allowed_paths[0]

            forward_group = self._group_config(session.forward_group)
            reverse_group = self._group_config(session.reverse_group)

            source_observer = self._observer_for_group(session.forward_group)
            dest_observer = self._observer_for_group(session.reverse_group)

            client_ip = forward_group.src_ip
            server_ip = session.server_ip

            # Edge bootstrap: one legal next hop is enough, because the SDX can still
            # rewrite the actual egress path on the IXP switch.
            if source_observer is not None:
                source_next_hop = self.next_hop_for_group_path(session.forward_group, preferred_path)
                if source_next_hop is not None:
                    self._install_host_route(source_observer.router, f"{server_ip}/32", source_next_hop)
            if dest_observer is not None:
                reverse_next_hop = self.next_hop_for_group_path(session.reverse_group, preferred_path)
                if reverse_next_hop is not None:
                    self._install_host_route(dest_observer.router, f"{client_ip}/32", reverse_next_hop)

            # Transit bootstrap: every legal path gets an explicit /32 on the matching
            # transit router so whichever path the SDX selects can actually forward.
            if source_observer is None or dest_observer is None:
                continue

            source_edge_peer = self.edge_peering_ip(source_observer.router)
            dest_edge_peer = self.edge_peering_ip(dest_observer.router)
            if source_edge_peer is None or dest_edge_peer is None:
                self.logger.warning(
                    "Missing edge peering IP metadata for %s or %s",
                    source_observer.router,
                    dest_observer.router,
                )
                continue

            for path_name in allowed_paths:
                transit_routers = self.transit_routers_for_path(path_name)
                for transit_router in transit_routers:
                    self._install_host_route(transit_router, f"{server_ip}/32", dest_edge_peer)
                    self._install_host_route(transit_router, f"{client_ip}/32", source_edge_peer)

    def _install_host_route(self, router_name: str, prefix: str, next_hop: str) -> None:
        """Install a bootstrap host route both in FRR and in the Linux FIB.

        In this emulated setup, programming only the Linux kernel route table was not
        reliable enough because Zebra may later overwrite the kernel state. Installing
        the route through vtysh makes Zebra own the static route, and the direct
        kernel route replace acts as a best-effort immediate backup.
        """
        node = self.network.get(router_name)
        cmds = [
            f"vtysh -c 'configure terminal' -c 'ip route {prefix} {next_hop}'",
            f"ip route replace {prefix} via {next_hop}",
        ]
        outputs = []
        for cmd in cmds:
            out = node.cmd(cmd).strip()
            if out:
                outputs.append(f"{cmd} -> {out}")
        if outputs:
            self.logger.info("%s: bootstrap route %s via %s (%s)", router_name, prefix, next_hop, ' | '.join(outputs))
        else:
            self.logger.info("%s: installed bootstrap route %s via %s", router_name, prefix, next_hop)

    def all_sessions_have_reachability(self) -> bool:
        return all(bool(self.allowed_paths_for_session(session.name)) for session in self.config.traffic_sessions)

    def all_sessions_match_expected(self) -> bool:
        for session in self.config.traffic_sessions:
            expected = self.expected_paths_for_session(session.name)
            if expected is None:
                continue
            if tuple(self.allowed_paths_for_session(session.name)) != tuple(expected):
                return False
        return True

    def _reachable_paths(
        self,
        observer: BgpObserverConfig,
        prefix: str,
        cache: dict[tuple[str, str], tuple[str, ...]],
    ) -> tuple[str, ...]:
        key = (observer.router, prefix)
        if key in cache:
            return cache[key]
        node = self.network.get(observer.router)
        json_output = node.cmd(f"vtysh -c 'show bgp ipv4 unicast {prefix} json'")
        found = self._extract_paths_from_json(observer, prefix, json_output)
        if not found:
            text_output = node.cmd(f"vtysh -c 'show bgp ipv4 unicast {prefix}'")
            found = self._extract_paths_from_text(observer, text_output)
        value = tuple(found)
        cache[key] = value
        return value

    def _extract_paths_from_json(self, observer: BgpObserverConfig, prefix: str, output: str) -> list[str]:
        json_text = self._extract_json_blob(output)
        if json_text is None:
            return []
        try:
            payload = json.loads(json_text)
        except Exception as exc:
            self.logger.warning(
                "%s: failed to decode BGP JSON for %s (%s): %r",
                observer.router,
                prefix,
                type(exc).__name__,
                exc,
            )
            return []
        entries = self._extract_path_entries(payload, prefix)
        found: list[str] = []
        seen: set[str] = set()
        for entry in entries:
            if not self._path_is_usable(entry):
                continue
            for nh in self._extract_next_hops(entry):
                path_name = observer.next_hop_to_path.get(nh)
                if path_name and path_name not in seen:
                    seen.add(path_name)
                    found.append(path_name)
        return found

    @staticmethod
    def _extract_paths_from_text(observer: BgpObserverConfig, output: str) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for next_hop, path_name in observer.next_hop_to_path.items():
            if re.search(rf"(?<![\d.]){re.escape(next_hop)}(?![\d.])", output):
                if path_name not in seen:
                    seen.add(path_name)
                    found.append(path_name)
        return found

    @staticmethod
    def _extract_json_blob(text: str) -> str | None:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end < start:
            return None
        return text[start : end + 1]

    @staticmethod
    def _extract_path_entries(payload: Any, prefix: str) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            if isinstance(payload.get("paths"), list):
                return [item for item in payload["paths"] if isinstance(item, dict)]
            routes = payload.get("routes")
            if isinstance(routes, dict):
                value = routes.get(prefix)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
                if isinstance(value, dict) and isinstance(value.get("paths"), list):
                    return [item for item in value["paths"] if isinstance(item, dict)]
            value = payload.get(prefix)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                if isinstance(value.get("paths"), list):
                    return [item for item in value["paths"] if isinstance(item, dict)]
                return [value]
        return []

    @staticmethod
    def _path_is_usable(path_entry: dict[str, Any]) -> bool:
        if path_entry.get("valid") is False:
            return False
        if path_entry.get("stale") is True:
            return False
        if path_entry.get("bestpath", {}).get("overall") is False and path_entry.get("bestpath") is not None:
            # If FRR exposes explicit best-path information, prefer installed/overall best paths.
            # If this key is missing, keep the older permissive behavior.
            return False
        return True

    @staticmethod
    def _extract_next_hops(path_entry: dict[str, Any]) -> list[str]:
        hops: list[str] = []
        nexthops = path_entry.get("nexthops")
        if isinstance(nexthops, list):
            for item in nexthops:
                if isinstance(item, str):
                    hops.append(item)
                elif isinstance(item, dict):
                    for key in ("ip", "ipAddress", "hostname"):
                        value = item.get(key)
                        if isinstance(value, str):
                            hops.append(value)
                            break
        for key in ("nexthop", "peerId"):
            value = path_entry.get(key)
            if isinstance(value, str):
                hops.append(value)
        return hops


async def wait_for_bgp_readiness(
    tracker: BgpReachabilityTracker,
    timeout_s: float,
    poll_s: float,
    logger: logging.Logger,
    require_expected: bool = False,
) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        tracker.refresh()
        if require_expected:
            if tracker.all_sessions_match_expected():
                return True
        else:
            if tracker.all_sessions_have_reachability():
                return True
        if time.monotonic() >= deadline:
            break
        await asyncio.sleep(poll_s)
    if require_expected:
        logger.warning("Timed out waiting for BGP routes to match expected session path sets")
    else:
        logger.warning("Timed out waiting for non-empty BGP reachability for all sessions")
    return False
