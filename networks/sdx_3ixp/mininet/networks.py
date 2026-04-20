from __future__ import annotations

import os
import sys

from mininet.node import OVSSwitch, Node
from mininet.topo import Topo

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, "../../../"))

sys.path.append(REPOSITORY_DIRECTORY)

from common.p4.functions import HelperFunctions
from common.mininet.nodes import Client, P4Switch


class LinuxRouter(Node):
    def __init__(self, name: str, *args, configCmds=None, **kwargs):
        self.configuration_commands = [
            "sysctl -w net.ipv4.ip_forward=1",
            "sysctl -w net.ipv6.conf.all.forwarding=0",
        ]
        if isinstance(configCmds, list):
            self.configuration_commands.extend(configCmds)
        kwargs["ip"] = None
        super().__init__(name, *args, **kwargs)

    def config(self, mac=None, ip=None, defaultRoute=None, lo="up", **params):
        super().config(mac=mac, ip=ip, defaultRoute=defaultRoute, lo=lo, **params)
        for intf in self.intfList():
            self.cmd(f"ethtool -K {intf} rx off tx off sg off")
        for command in self.configuration_commands:
            self.cmd(command)


class Topology(Topo):
    """Three-IXP, three-path SDX topology.

    Left tenants:
      - AS100 and AS500 connect to IXP1.

    Right tenants:
      - AS200 and AS600 connect to IXP3.

    Transit core:
      - Three end-to-end paths traverse all three IXPs:
          * slow   : slow12r1 -> IXP2 -> slow23r1
          * medium : med12r1  -> IXP2 -> med23r1
          * fast   : fast12r1 -> IXP2 -> fast23r1

    IXP1 and IXP3 perform SDX steering. IXP2 is still a programmable switch but is
    used mainly as a middle exchange fabric carrying traffic between the first and
    second path segments.
    """

    def build(self, *args, **params):
        macs: dict[str, dict[str, str]] = {
            # Edge routers
            "as1r1": {"as1r1-eth0": "f0:00:0d:01:01:00", "as1r1-eth1": "f0:00:0d:01:01:01"},
            "as2r1": {"as2r1-eth0": "f0:00:0d:01:02:00", "as2r1-eth1": "f0:00:0d:01:02:01"},
            "as5r1": {"as5r1-eth0": "f0:00:0d:01:05:00", "as5r1-eth1": "f0:00:0d:01:05:01"},
            "as6r1": {"as6r1-eth0": "f0:00:0d:01:06:00", "as6r1-eth1": "f0:00:0d:01:06:01"},
            # Path segment routers: between IXP1-IXP2 and IXP2-IXP3
            "slow12r1": {"slow12r1-eth0": "f0:00:0d:01:31:00", "slow12r1-eth1": "f0:00:0d:01:31:01"},
            "med12r1": {"med12r1-eth0": "f0:00:0d:01:41:00", "med12r1-eth1": "f0:00:0d:01:41:01"},
            "fast12r1": {"fast12r1-eth0": "f0:00:0d:01:71:00", "fast12r1-eth1": "f0:00:0d:01:71:01"},
            "slow23r1": {"slow23r1-eth0": "f0:00:0d:01:32:00", "slow23r1-eth1": "f0:00:0d:01:32:01"},
            "med23r1": {"med23r1-eth0": "f0:00:0d:01:42:00", "med23r1-eth1": "f0:00:0d:01:42:01"},
            "fast23r1": {"fast23r1-eth0": "f0:00:0d:01:72:00", "fast23r1-eth1": "f0:00:0d:01:72:01"},
            # End hosts
            "as1h1": {"as1h1-eth0": "f0:00:0d:00:01:00"},
            "as1h2": {"as1h2-eth0": "f0:00:0d:00:01:01"},
            "as2h1": {"as2h1-eth0": "f0:00:0d:00:02:00"},
            "as2h2": {"as2h2-eth0": "f0:00:0d:00:02:01"},
            "as5h1": {"as5h1-eth0": "f0:00:0d:00:05:00"},
            "as5h2": {"as5h2-eth0": "f0:00:0d:00:05:01"},
            "as6h1": {"as6h1-eth0": "f0:00:0d:00:06:00"},
            "as6h2": {"as6h2-eth0": "f0:00:0d:00:06:01"},
        }

        def add_router(name: str, config_cmds: list[str]) -> str:
            return self.addNode(name, cls=LinuxRouter, configCmds=config_cmds)

        def add_host(name: str, gateway: str) -> str:
            return self.addHost(
                name,
                cls=Client,
                configCmds=(
                    HelperFunctions.generate_set_interface_mac_commands(macs[name])
                    + [HelperFunctions.generate_set_default_route_command(gateway)]
                ),
            )

        # Edge OVS LAN switches
        as1s1 = self.addSwitch("as1s1", cls=OVSSwitch)
        as2s1 = self.addSwitch("as2s1", cls=OVSSwitch)
        as5s1 = self.addSwitch("as5s1", cls=OVSSwitch)
        as6s1 = self.addSwitch("as6s1", cls=OVSSwitch)

        # P4 IXP switches
        ixp1s1 = self.addSwitch("ixp1s1", cls=P4Switch, identifier=1, thrift_port=9091, grpc_address="0.0.0.0", grpc_port=50001)
        ixp2s1 = self.addSwitch("ixp2s1", cls=P4Switch, identifier=2, thrift_port=9092, grpc_address="0.0.0.0", grpc_port=50002)
        ixp3s1 = self.addSwitch("ixp3s1", cls=P4Switch, identifier=3, thrift_port=9093, grpc_address="0.0.0.0", grpc_port=50003)

        # Hosts
        as1h1 = add_host("as1h1", "8.1.1.1")
        as1h2 = add_host("as1h2", "8.1.1.1")
        as2h1 = add_host("as2h1", "8.1.2.1")
        as2h2 = add_host("as2h2", "8.1.2.1")
        as5h1 = add_host("as5h1", "8.1.5.1")
        as5h2 = add_host("as5h2", "8.1.5.1")
        as6h1 = add_host("as6h1", "8.1.6.1")
        as6h2 = add_host("as6h2", "8.1.6.1")

        # Router config commands
        as1_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["as1r1"]) + [
            "ip route replace 8.1.2.0/24 via 8.2.1.11",
            "ip route replace 8.1.6.0/24 via 8.2.1.11",
        ]
        as5_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["as5r1"]) + [
            "ip route replace 8.1.2.0/24 via 8.2.1.11",
            "ip route replace 8.1.6.0/24 via 8.2.1.11",
        ]
        as2_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["as2r1"]) + [
            "ip route replace 8.1.1.0/24 via 8.2.3.21",
            "ip route replace 8.1.5.0/24 via 8.2.3.21",
        ]
        as6_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["as6r1"]) + [
            "ip route replace 8.1.1.0/24 via 8.2.3.21",
            "ip route replace 8.1.5.0/24 via 8.2.3.21",
        ]

        slow12_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["slow12r1"]) + [
            "ip route replace 8.1.2.0/24 via 8.2.2.21",
            "ip route replace 8.1.6.0/24 via 8.2.2.21",
            "ip route replace 8.1.1.0/24 via 8.2.1.1",
            "ip route replace 8.1.5.0/24 via 8.2.1.2",
        ]
        med12_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["med12r1"]) + [
            "ip route replace 8.1.2.0/24 via 8.2.2.22",
            "ip route replace 8.1.6.0/24 via 8.2.2.22",
            "ip route replace 8.1.1.0/24 via 8.2.1.1",
            "ip route replace 8.1.5.0/24 via 8.2.1.2",
        ]
        fast12_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["fast12r1"]) + [
            "ip route replace 8.1.2.0/24 via 8.2.2.23",
            "ip route replace 8.1.6.0/24 via 8.2.2.23",
            "ip route replace 8.1.1.0/24 via 8.2.1.1",
            "ip route replace 8.1.5.0/24 via 8.2.1.2",
        ]
        slow23_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["slow23r1"]) + [
            "ip route replace 8.1.1.0/24 via 8.2.2.11",
            "ip route replace 8.1.5.0/24 via 8.2.2.11",
            "ip route replace 8.1.2.0/24 via 8.2.3.1",
            "ip route replace 8.1.6.0/24 via 8.2.3.2",
        ]
        med23_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["med23r1"]) + [
            "ip route replace 8.1.1.0/24 via 8.2.2.12",
            "ip route replace 8.1.5.0/24 via 8.2.2.12",
            "ip route replace 8.1.2.0/24 via 8.2.3.1",
            "ip route replace 8.1.6.0/24 via 8.2.3.2",
        ]
        fast23_cmds = HelperFunctions.generate_set_interface_mac_commands(macs["fast23r1"]) + [
            "ip route replace 8.1.1.0/24 via 8.2.2.13",
            "ip route replace 8.1.5.0/24 via 8.2.2.13",
            "ip route replace 8.1.2.0/24 via 8.2.3.1",
            "ip route replace 8.1.6.0/24 via 8.2.3.2",
        ]

        # Routers
        as1r1 = add_router("as1r1", as1_cmds)
        as2r1 = add_router("as2r1", as2_cmds)
        as5r1 = add_router("as5r1", as5_cmds)
        as6r1 = add_router("as6r1", as6_cmds)
        slow12r1 = add_router("slow12r1", slow12_cmds)
        med12r1 = add_router("med12r1", med12_cmds)
        fast12r1 = add_router("fast12r1", fast12_cmds)
        slow23r1 = add_router("slow23r1", slow23_cmds)
        med23r1 = add_router("med23r1", med23_cmds)
        fast23r1 = add_router("fast23r1", fast23_cmds)

        # Edge LANs
        self.addLink(as1r1, as1s1, intfName1="as1r1-eth0", params1={"ip": "8.1.1.1/24"}, intfName2="as1s1-eth0")
        self.addLink(as1h1, as1s1, intfName1="as1h1-eth0", params1={"ip": "8.1.1.101/24"}, intfName2="as1s1-eth1")
        self.addLink(as1h2, as1s1, intfName1="as1h2-eth0", params1={"ip": "8.1.1.102/24"}, intfName2="as1s1-eth2")

        self.addLink(as5r1, as5s1, intfName1="as5r1-eth0", params1={"ip": "8.1.5.1/24"}, intfName2="as5s1-eth0")
        self.addLink(as5h1, as5s1, intfName1="as5h1-eth0", params1={"ip": "8.1.5.101/24"}, intfName2="as5s1-eth1")
        self.addLink(as5h2, as5s1, intfName1="as5h2-eth0", params1={"ip": "8.1.5.102/24"}, intfName2="as5s1-eth2")

        self.addLink(as2r1, as2s1, intfName1="as2r1-eth0", params1={"ip": "8.1.2.1/24"}, intfName2="as2s1-eth0")
        self.addLink(as2h1, as2s1, intfName1="as2h1-eth0", params1={"ip": "8.1.2.101/24"}, intfName2="as2s1-eth1")
        self.addLink(as2h2, as2s1, intfName1="as2h2-eth0", params1={"ip": "8.1.2.102/24"}, intfName2="as2s1-eth2")

        self.addLink(as6r1, as6s1, intfName1="as6r1-eth0", params1={"ip": "8.1.6.1/24"}, intfName2="as6s1-eth0")
        self.addLink(as6h1, as6s1, intfName1="as6h1-eth0", params1={"ip": "8.1.6.101/24"}, intfName2="as6s1-eth1")
        self.addLink(as6h2, as6s1, intfName1="as6h2-eth0", params1={"ip": "8.1.6.102/24"}, intfName2="as6s1-eth2")

        # IXP1 LAN: ports 1..5 = AS100, AS500, slow, medium, fast
        self.addLink(as1r1, ixp1s1, intfName1="as1r1-eth1", params1={"ip": "8.2.1.1/24"}, intfName2="ixp1s1-eth0")
        self.addLink(as5r1, ixp1s1, intfName1="as5r1-eth1", params1={"ip": "8.2.1.2/24"}, intfName2="ixp1s1-eth1")
        self.addLink(slow12r1, ixp1s1, intfName1="slow12r1-eth0", params1={"ip": "8.2.1.11/24"}, intfName2="ixp1s1-eth2", delay="80ms")
        self.addLink(med12r1, ixp1s1, intfName1="med12r1-eth0", params1={"ip": "8.2.1.12/24"}, intfName2="ixp1s1-eth3", delay="20ms")
        self.addLink(fast12r1, ixp1s1, intfName1="fast12r1-eth0", params1={"ip": "8.2.1.13/24"}, intfName2="ixp1s1-eth4", delay="5ms")

        # IXP2 LAN: 6 path-segment router ports, used mainly as middle exchange fabric
        self.addLink(slow12r1, ixp2s1, intfName1="slow12r1-eth1", params1={"ip": "8.2.2.11/24"}, intfName2="ixp2s1-eth0", delay="80ms")
        self.addLink(med12r1, ixp2s1, intfName1="med12r1-eth1", params1={"ip": "8.2.2.12/24"}, intfName2="ixp2s1-eth1", delay="20ms")
        self.addLink(fast12r1, ixp2s1, intfName1="fast12r1-eth1", params1={"ip": "8.2.2.13/24"}, intfName2="ixp2s1-eth2", delay="5ms")
        self.addLink(slow23r1, ixp2s1, intfName1="slow23r1-eth0", params1={"ip": "8.2.2.21/24"}, intfName2="ixp2s1-eth3", delay="80ms")
        self.addLink(med23r1, ixp2s1, intfName1="med23r1-eth0", params1={"ip": "8.2.2.22/24"}, intfName2="ixp2s1-eth4", delay="20ms")
        self.addLink(fast23r1, ixp2s1, intfName1="fast23r1-eth0", params1={"ip": "8.2.2.23/24"}, intfName2="ixp2s1-eth5", delay="5ms")

        # IXP3 LAN: ports 1..5 = AS200, AS600, slow, medium, fast
        self.addLink(as2r1, ixp3s1, intfName1="as2r1-eth1", params1={"ip": "8.2.3.1/24"}, intfName2="ixp3s1-eth0")
        self.addLink(as6r1, ixp3s1, intfName1="as6r1-eth1", params1={"ip": "8.2.3.2/24"}, intfName2="ixp3s1-eth1")
        self.addLink(slow23r1, ixp3s1, intfName1="slow23r1-eth1", params1={"ip": "8.2.3.21/24"}, intfName2="ixp3s1-eth2", delay="80ms")
        self.addLink(med23r1, ixp3s1, intfName1="med23r1-eth1", params1={"ip": "8.2.3.22/24"}, intfName2="ixp3s1-eth3", delay="20ms")
        self.addLink(fast23r1, ixp3s1, intfName1="fast23r1-eth1", params1={"ip": "8.2.3.23/24"}, intfName2="ixp3s1-eth4", delay="5ms")


# pylint: disable=W0108
topos = {
    "topology": (lambda: Topology())
}
