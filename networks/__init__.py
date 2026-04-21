from __future__ import annotations

from importlib import import_module
from typing import Type

from mininet.topo import Topo

_TOPOLOGY_MODULES: dict[str, str] = {
    "sdx_run": "networks.sdx_run.mininet.networks",
    "sdx_general": "networks.sdx_general.mininet.networks",
    "sdx_bgp": "networks.sdx_bgp.mininet.networks",
    "sdx_bgp_loop": "networks.sdx_bgp_loop.mininet.networks",
    "sdx_bgp_superloop": "networks.sdx_bgp_superloop.mininet.networks",
}


def load_topology_class(topology_name: str) -> Type[Topo]:
    module_name = _TOPOLOGY_MODULES.get(topology_name)
    if module_name is None:
        raise ValueError(f"Unknown topology_name={topology_name!r}; known={sorted(_TOPOLOGY_MODULES)}")
    module = import_module(module_name)
    topology_class = getattr(module, "Topology", None)
    if topology_class is None:
        raise ValueError(f"Topology module {module_name} does not export Topology")
    return topology_class
