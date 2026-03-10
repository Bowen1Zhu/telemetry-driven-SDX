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
    # Two-path IXP topology based on cs6204 Assignment 1 Task 2.

    def build(self, *args, **params):
        hosts_mac_addresses: dict[str, dict[str, str]] = {
            "as1r1": {
                "as1r1-eth0": "f0:00:0d:01:01:00",
                "as1r1-eth1": "f0:00:0d:01:01:01",
            },
            "as2r1": {
                "as2r1-eth0": "f0:00:0d:01:02:00",
                "as2r1-eth1": "f0:00:0d:01:02:01",
            },
            "as3r1": {
                "as3r1-eth0": "f0:00:0d:01:03:00",
                "as3r1-eth1": "f0:00:0d:01:03:01",
            },
            "as4r1": {
                "as4r1-eth0": "f0:00:0d:01:04:00",
                "as4r1-eth1": "f0:00:0d:01:04:01",
            },
            "as1h1": {
                "as1h1-eth0": "f0:00:0d:00:01:00",
            },
            "as1h2": {
                "as1h2-eth0": "f0:00:0d:00:01:01",
            },
            "as2h1": {
                "as2h1-eth0": "f0:00:0d:00:02:00",
            },
            "as2h2": {
                "as2h2-eth0": "f0:00:0d:00:02:01",
            },
        }

        as1s1 = self.addSwitch("as1s1", cls=OVSSwitch)
        as2s1 = self.addSwitch("as2s1", cls=OVSSwitch)

        as1r1 = self.addNode(
            "as1r1",
            cls=FRRRouter,
            zebraConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, "as1r1-zebra.conf"),
            bgpConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, "as1r1-bgp.conf"),
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(hosts_mac_addresses["as1r1"])
                + [HelperFunctions.generate_add_loopback_interface_ip_command("100.100.1.1/32")]
            ),
        )
        as2r1 = self.addNode(
            "as2r1",
            cls=FRRRouter,
            zebraConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, "as2r1-zebra.conf"),
            bgpConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, "as2r1-bgp.conf"),
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(hosts_mac_addresses["as2r1"])
                + [HelperFunctions.generate_add_loopback_interface_ip_command("100.100.2.1/32")]
            ),
        )
        as3r1 = self.addNode(
            "as3r1",
            cls=FRRRouter,
            zebraConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, "as3r1-zebra.conf"),
            bgpConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, "as3r1-bgp.conf"),
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(hosts_mac_addresses["as3r1"])
                + [HelperFunctions.generate_add_loopback_interface_ip_command("100.100.3.1/32")]
            ),
        )
        as4r1 = self.addNode(
            "as4r1",
            cls=FRRRouter,
            zebraConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, "as4r1-zebra.conf"),
            bgpConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, "as4r1-bgp.conf"),
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(hosts_mac_addresses["as4r1"])
                + [HelperFunctions.generate_add_loopback_interface_ip_command("100.100.4.1/32")]
            ),
        )

        as1h1 = self.addHost(
            "as1h1",
            cls=Client,
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(hosts_mac_addresses["as1h1"])
                + [HelperFunctions.generate_set_default_route_command("8.1.1.1")]
            ),
        )
        as1h2 = self.addHost(
            "as1h2",
            cls=Client,
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(hosts_mac_addresses["as1h2"])
                + [HelperFunctions.generate_set_default_route_command("8.1.1.1")]
            ),
        )
        as2h1 = self.addHost(
            "as2h1",
            cls=Client,
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(hosts_mac_addresses["as2h1"])
                + [HelperFunctions.generate_set_default_route_command("8.1.2.1")]
            ),
        )
        as2h2 = self.addHost(
            "as2h2",
            cls=Client,
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(hosts_mac_addresses["as2h2"])
                + [HelperFunctions.generate_set_default_route_command("8.1.2.1")]
            ),
        )

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

        # Hosts and router in AS100.
        self.addLink(as1r1, as1s1, intfName1="as1r1-eth0", params1={"ip": "8.1.1.1/24"}, intfName2="as1s1-eth0")
        self.addLink(as1h1, as1s1, intfName1="as1h1-eth0", params1={"ip": "8.1.1.101/24"}, intfName2="as1s1-eth1")
        self.addLink(as1h2, as1s1, intfName1="as1h2-eth0", params1={"ip": "8.1.1.102/24"}, intfName2="as1s1-eth2")

        # Hosts and router in AS200.
        self.addLink(as2r1, as2s1, intfName1="as2r1-eth0", params1={"ip": "8.1.2.1/24"}, intfName2="as2s1-eth0")
        self.addLink(as2h1, as2s1, intfName1="as2h1-eth0", params1={"ip": "8.1.2.101/24"}, intfName2="as2s1-eth1")
        self.addLink(as2h2, as2s1, intfName1="as2h2-eth0", params1={"ip": "8.1.2.102/24"}, intfName2="as2s1-eth2")

        # Connect AS100 to IXP1.
        self.addLink(as1r1, ixp1s1, intfName1="as1r1-eth1", params1={"ip": "8.2.1.1/24"}, intfName2="ixp1s1-eth0")

        # Path 1 / slow path via AS300.
        self.addLink(
            as3r1,
            ixp1s1,
            intfName1="as3r1-eth0",
            params1={"ip": "8.2.1.2/24"},
            intfName2="ixp1s1-eth1",
            delay="240ms",
        )

        # Path 2 / fast path via AS400.
        self.addLink(as4r1, ixp1s1, intfName1="as4r1-eth0", params1={"ip": "8.2.1.3/24"}, intfName2="ixp1s1-eth2")

        # Connect AS200 to IXP2.
        self.addLink(as2r1, ixp2s1, intfName1="as2r1-eth1", params1={"ip": "8.2.2.1/24"}, intfName2="ixp2s1-eth0")
        self.addLink(
            as3r1,
            ixp2s1,
            intfName1="as3r1-eth1",
            params1={"ip": "8.2.2.2/24"},
            intfName2="ixp2s1-eth1",
            delay="240ms",
        )
        self.addLink(as4r1, ixp2s1, intfName1="as4r1-eth1", params1={"ip": "8.2.2.3/24"}, intfName2="ixp2s1-eth2")


# pylint: disable=W0108
topos = {
    "topology": (lambda: Topology())
}
