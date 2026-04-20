from __future__ import annotations

import os
import sys

from mininet.node import OVSSwitch
from mininet.topo import Topo

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, "../../../"))
FRR_CONFIGURATION_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, "../frr/"))

sys.path.append(REPOSITORY_DIRECTORY)

from common.p4.functions import HelperFunctions
from common.mininet.nodes import Client, P4Switch, FRRRouter


class Topology(Topo):
    """Generalized multi-tenant SDX topology.

    Left side / IXP1:
      - AS100 and AS500 are IXP members/tenants.
      - AS300 is the slower inter-domain path.
      - AS400 is the faster inter-domain path.

    Right side / IXP2:
      - AS200 and AS600 are IXP members/tenants.
      - AS300 and AS400 continue the two alternate paths.

    The model keeps the same two candidate inter-domain paths but now supports
    multiple source/destination prefixes crossing the IXP fabric at once.
    """

    def build(self, *args, **params):
        macs: dict[str, dict[str, str]] = {
            "as1r1": {"as1r1-eth0": "f0:00:0d:01:01:00", "as1r1-eth1": "f0:00:0d:01:01:01"},
            "as2r1": {"as2r1-eth0": "f0:00:0d:01:02:00", "as2r1-eth1": "f0:00:0d:01:02:01"},
            "as3r1": {"as3r1-eth0": "f0:00:0d:01:03:00", "as3r1-eth1": "f0:00:0d:01:03:01"},
            "as4r1": {"as4r1-eth0": "f0:00:0d:01:04:00", "as4r1-eth1": "f0:00:0d:01:04:01"},
            "as5r1": {"as5r1-eth0": "f0:00:0d:01:05:00", "as5r1-eth1": "f0:00:0d:01:05:01"},
            "as6r1": {"as6r1-eth0": "f0:00:0d:01:06:00", "as6r1-eth1": "f0:00:0d:01:06:01"},
            "as1h1": {"as1h1-eth0": "f0:00:0d:00:01:00"},
            "as1h2": {"as1h2-eth0": "f0:00:0d:00:01:01"},
            "as2h1": {"as2h1-eth0": "f0:00:0d:00:02:00"},
            "as2h2": {"as2h2-eth0": "f0:00:0d:00:02:01"},
            "as5h1": {"as5h1-eth0": "f0:00:0d:00:05:00"},
            "as5h2": {"as5h2-eth0": "f0:00:0d:00:05:01"},
            "as6h1": {"as6h1-eth0": "f0:00:0d:00:06:00"},
            "as6h2": {"as6h2-eth0": "f0:00:0d:00:06:01"},
        }

        as1s1 = self.addSwitch("as1s1", cls=OVSSwitch)
        as2s1 = self.addSwitch("as2s1", cls=OVSSwitch)
        as5s1 = self.addSwitch("as5s1", cls=OVSSwitch)
        as6s1 = self.addSwitch("as6s1", cls=OVSSwitch)

        def add_router(name: str, router_id: str) -> str:
            return self.addNode(
                name,
                cls=FRRRouter,
                zebraConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, f"{name}-zebra.conf"),
                bgpConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, f"{name}-bgp.conf"),
                configCmds=(
                    HelperFunctions.generate_set_interface_mac_commands(macs[name])
                    + [HelperFunctions.generate_add_loopback_interface_ip_command(f"{router_id}/32")]
                ),
            )

        as1r1 = add_router("as1r1", "100.100.1.1")
        as2r1 = add_router("as2r1", "100.100.2.1")
        as3r1 = add_router("as3r1", "100.100.3.1")
        as4r1 = add_router("as4r1", "100.100.4.1")
        as5r1 = add_router("as5r1", "100.100.5.1")
        as6r1 = add_router("as6r1", "100.100.6.1")

        def add_host(name: str, gateway: str) -> str:
            return self.addHost(
                name,
                cls=Client,
                configCmds=(
                    HelperFunctions.generate_set_interface_mac_commands(macs[name])
                    + [HelperFunctions.generate_set_default_route_command(gateway)]
                ),
            )

        as1h1 = add_host("as1h1", "8.1.1.1")
        as1h2 = add_host("as1h2", "8.1.1.1")
        as2h1 = add_host("as2h1", "8.1.2.1")
        as2h2 = add_host("as2h2", "8.1.2.1")
        as5h1 = add_host("as5h1", "8.1.5.1")
        as5h2 = add_host("as5h2", "8.1.5.1")
        as6h1 = add_host("as6h1", "8.1.6.1")
        as6h2 = add_host("as6h2", "8.1.6.1")

        ixp1s1 = self.addSwitch(
            "ixp1s1",
            cls=P4Switch,
            identifier=1,
            thrift_port=9091,
            grpc_address="0.0.0.0",
            grpc_port=50001,
        )
        ixp2s1 = self.addSwitch(
            "ixp2s1",
            cls=P4Switch,
            identifier=2,
            thrift_port=9092,
            grpc_address="0.0.0.0",
            grpc_port=50002,
        )

        # AS100 LAN
        self.addLink(as1r1, as1s1, intfName1="as1r1-eth0", params1={"ip": "8.1.1.1/24"}, intfName2="as1s1-eth0")
        self.addLink(as1h1, as1s1, intfName1="as1h1-eth0", params1={"ip": "8.1.1.101/24"}, intfName2="as1s1-eth1")
        self.addLink(as1h2, as1s1, intfName1="as1h2-eth0", params1={"ip": "8.1.1.102/24"}, intfName2="as1s1-eth2")

        # AS200 LAN
        self.addLink(as2r1, as2s1, intfName1="as2r1-eth0", params1={"ip": "8.1.2.1/24"}, intfName2="as2s1-eth0")
        self.addLink(as2h1, as2s1, intfName1="as2h1-eth0", params1={"ip": "8.1.2.101/24"}, intfName2="as2s1-eth1")
        self.addLink(as2h2, as2s1, intfName1="as2h2-eth0", params1={"ip": "8.1.2.102/24"}, intfName2="as2s1-eth2")

        # AS500 LAN
        self.addLink(as5r1, as5s1, intfName1="as5r1-eth0", params1={"ip": "8.1.5.1/24"}, intfName2="as5s1-eth0")
        self.addLink(as5h1, as5s1, intfName1="as5h1-eth0", params1={"ip": "8.1.5.101/24"}, intfName2="as5s1-eth1")
        self.addLink(as5h2, as5s1, intfName1="as5h2-eth0", params1={"ip": "8.1.5.102/24"}, intfName2="as5s1-eth2")

        # AS600 LAN
        self.addLink(as6r1, as6s1, intfName1="as6r1-eth0", params1={"ip": "8.1.6.1/24"}, intfName2="as6s1-eth0")
        self.addLink(as6h1, as6s1, intfName1="as6h1-eth0", params1={"ip": "8.1.6.101/24"}, intfName2="as6s1-eth1")
        self.addLink(as6h2, as6s1, intfName1="as6h2-eth0", params1={"ip": "8.1.6.102/24"}, intfName2="as6s1-eth2")

        # IXP1 peering LAN. Order matters: ports 1..4 = AS100, AS500, slow(AS300), fast(AS400).
        self.addLink(as1r1, ixp1s1, intfName1="as1r1-eth1", params1={"ip": "8.2.1.1/24"}, intfName2="ixp1s1-eth0")
        self.addLink(as5r1, ixp1s1, intfName1="as5r1-eth1", params1={"ip": "8.2.1.4/24"}, intfName2="ixp1s1-eth1")
        self.addLink(as3r1, ixp1s1, intfName1="as3r1-eth0", params1={"ip": "8.2.1.2/24"}, intfName2="ixp1s1-eth2", delay="240ms")
        self.addLink(as4r1, ixp1s1, intfName1="as4r1-eth0", params1={"ip": "8.2.1.3/24"}, intfName2="ixp1s1-eth3")

        # IXP2 peering LAN. Order matters: ports 1..4 = AS200, AS600, slow(AS300), fast(AS400).
        self.addLink(as2r1, ixp2s1, intfName1="as2r1-eth1", params1={"ip": "8.2.2.1/24"}, intfName2="ixp2s1-eth0")
        self.addLink(as6r1, ixp2s1, intfName1="as6r1-eth1", params1={"ip": "8.2.2.4/24"}, intfName2="ixp2s1-eth1")
        self.addLink(as3r1, ixp2s1, intfName1="as3r1-eth1", params1={"ip": "8.2.2.2/24"}, intfName2="ixp2s1-eth2", delay="240ms")
        self.addLink(as4r1, ixp2s1, intfName1="as4r1-eth1", params1={"ip": "8.2.2.3/24"}, intfName2="ixp2s1-eth3")


# pylint: disable=W0108
topos = {
    "topology": (lambda: Topology())
}
