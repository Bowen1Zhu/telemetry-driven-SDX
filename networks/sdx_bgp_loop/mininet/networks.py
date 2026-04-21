from __future__ import annotations

import os
import sys

from mininet.node import OVSSwitch
from mininet.topo import Topo

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, '../../../'))
FRR_CONFIGURATION_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, '../frr/'))

sys.path.append(REPOSITORY_DIRECTORY)

from common.p4.functions import HelperFunctions
from common.mininet.nodes import Client, P4Switch, FRRRouter


class Topology(Topo):
    """Larger BGP-aware topology with 3 IXPs and a loop-capable middle transit fabric.

    Physical picture:
      AS100 / AS500 -- IXP1 -- {slow12, fast12} -- IXP2(shared fabric) -- {slow23, fast23} -- IXP3 -- AS200 / AS600

    The shared middle IXP makes the control plane larger and more complicated than the
    original 2-IXP / 2-transit design, while the SDX still exposes two legal end-to-end
    path classes for steering:
      * slow = slow12 -> slow23
      * fast = fast12 -> fast23
    """

    def build(self, *args, **params):
        macs: dict[str, dict[str, str]] = {
            'as1r1': {'as1r1-eth0': 'f0:00:0d:11:01:00', 'as1r1-eth1': 'f0:00:0d:11:01:01'},
            'as2r1': {'as2r1-eth0': 'f0:00:0d:11:02:00', 'as2r1-eth1': 'f0:00:0d:11:02:01'},
            'as5r1': {'as5r1-eth0': 'f0:00:0d:11:05:00', 'as5r1-eth1': 'f0:00:0d:11:05:01'},
            'as6r1': {'as6r1-eth0': 'f0:00:0d:11:06:00', 'as6r1-eth1': 'f0:00:0d:11:06:01'},
            'slow12r1': {'slow12r1-eth0': 'f0:00:0d:11:31:00', 'slow12r1-eth1': 'f0:00:0d:11:31:01'},
            'fast12r1': {'fast12r1-eth0': 'f0:00:0d:11:41:00', 'fast12r1-eth1': 'f0:00:0d:11:41:01'},
            'slow23r1': {'slow23r1-eth0': 'f0:00:0d:11:32:00', 'slow23r1-eth1': 'f0:00:0d:11:32:01'},
            'fast23r1': {'fast23r1-eth0': 'f0:00:0d:11:42:00', 'fast23r1-eth1': 'f0:00:0d:11:42:01'},
            'as1h1': {'as1h1-eth0': 'f0:00:0d:10:01:00'},
            'as1h2': {'as1h2-eth0': 'f0:00:0d:10:01:01'},
            'as2h1': {'as2h1-eth0': 'f0:00:0d:10:02:00'},
            'as2h2': {'as2h2-eth0': 'f0:00:0d:10:02:01'},
            'as5h1': {'as5h1-eth0': 'f0:00:0d:10:05:00'},
            'as5h2': {'as5h2-eth0': 'f0:00:0d:10:05:01'},
            'as6h1': {'as6h1-eth0': 'f0:00:0d:10:06:00'},
            'as6h2': {'as6h2-eth0': 'f0:00:0d:10:06:01'},
        }

        as1s1 = self.addSwitch('as1s1', cls=OVSSwitch)
        as2s1 = self.addSwitch('as2s1', cls=OVSSwitch)
        as5s1 = self.addSwitch('as5s1', cls=OVSSwitch)
        as6s1 = self.addSwitch('as6s1', cls=OVSSwitch)

        def add_router(name: str, router_id: str) -> str:
            return self.addNode(
                name,
                cls=FRRRouter,
                zebraConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, f'{name}-zebra.conf'),
                bgpConfigFile=os.path.join(FRR_CONFIGURATION_DIRECTORY, f'{name}-bgp.conf'),
                configCmds=(
                    HelperFunctions.generate_set_interface_mac_commands(macs[name])
                    + [HelperFunctions.generate_add_loopback_interface_ip_command(f'{router_id}/32')]
                ),
            )

        def add_host(name: str, gateway: str) -> str:
            return self.addHost(
                name,
                cls=Client,
                configCmds=(
                    HelperFunctions.generate_set_interface_mac_commands(macs[name])
                    + [HelperFunctions.generate_set_default_route_command(gateway)]
                ),
            )

        # Edge routers / hosts
        as1r1 = add_router('as1r1', '100.100.1.1')
        as2r1 = add_router('as2r1', '100.100.2.1')
        as5r1 = add_router('as5r1', '100.100.5.1')
        as6r1 = add_router('as6r1', '100.100.6.1')
        slow12r1 = add_router('slow12r1', '100.100.31.1')
        fast12r1 = add_router('fast12r1', '100.100.41.1')
        slow23r1 = add_router('slow23r1', '100.100.32.1')
        fast23r1 = add_router('fast23r1', '100.100.42.1')

        as1h1 = add_host('as1h1', '8.1.1.1')
        as1h2 = add_host('as1h2', '8.1.1.1')
        as2h1 = add_host('as2h1', '8.1.2.1')
        as2h2 = add_host('as2h2', '8.1.2.1')
        as5h1 = add_host('as5h1', '8.1.5.1')
        as5h2 = add_host('as5h2', '8.1.5.1')
        as6h1 = add_host('as6h1', '8.1.6.1')
        as6h2 = add_host('as6h2', '8.1.6.1')

        # Outer steering IXPs are P4; middle IXP is a shared fabric that creates the loop-capable transit core.
        ixp1s1 = self.addSwitch('ixp1s1', cls=P4Switch, identifier=1, thrift_port=9091, grpc_address='0.0.0.0', grpc_port=50001)
        ixp2s1 = self.addSwitch('ixp2s1', cls=OVSSwitch)
        ixp3s1 = self.addSwitch('ixp3s1', cls=P4Switch, identifier=3, thrift_port=9093, grpc_address='0.0.0.0', grpc_port=50003)

        # Edge LANs
        self.addLink(as1r1, as1s1, intfName1='as1r1-eth0', params1={'ip': '8.1.1.1/24'}, intfName2='as1s1-eth0')
        self.addLink(as1h1, as1s1, intfName1='as1h1-eth0', params1={'ip': '8.1.1.101/24'}, intfName2='as1s1-eth1')
        self.addLink(as1h2, as1s1, intfName1='as1h2-eth0', params1={'ip': '8.1.1.102/24'}, intfName2='as1s1-eth2')

        self.addLink(as5r1, as5s1, intfName1='as5r1-eth0', params1={'ip': '8.1.5.1/24'}, intfName2='as5s1-eth0')
        self.addLink(as5h1, as5s1, intfName1='as5h1-eth0', params1={'ip': '8.1.5.101/24'}, intfName2='as5s1-eth1')
        self.addLink(as5h2, as5s1, intfName1='as5h2-eth0', params1={'ip': '8.1.5.102/24'}, intfName2='as5s1-eth2')

        self.addLink(as2r1, as2s1, intfName1='as2r1-eth0', params1={'ip': '8.1.2.1/24'}, intfName2='as2s1-eth0')
        self.addLink(as2h1, as2s1, intfName1='as2h1-eth0', params1={'ip': '8.1.2.101/24'}, intfName2='as2s1-eth1')
        self.addLink(as2h2, as2s1, intfName1='as2h2-eth0', params1={'ip': '8.1.2.102/24'}, intfName2='as2s1-eth2')

        self.addLink(as6r1, as6s1, intfName1='as6r1-eth0', params1={'ip': '8.1.6.1/24'}, intfName2='as6s1-eth0')
        self.addLink(as6h1, as6s1, intfName1='as6h1-eth0', params1={'ip': '8.1.6.101/24'}, intfName2='as6s1-eth1')
        self.addLink(as6h2, as6s1, intfName1='as6h2-eth0', params1={'ip': '8.1.6.102/24'}, intfName2='as6s1-eth2')

        # IXP1: ports 1..4 = AS100, AS500, slow12, fast12
        self.addLink(as1r1, ixp1s1, intfName1='as1r1-eth1', params1={'ip': '8.2.1.1/24'}, intfName2='ixp1s1-eth0')
        self.addLink(as5r1, ixp1s1, intfName1='as5r1-eth1', params1={'ip': '8.2.1.4/24'}, intfName2='ixp1s1-eth1')
        self.addLink(slow12r1, ixp1s1, intfName1='slow12r1-eth0', params1={'ip': '8.2.1.2/24'}, intfName2='ixp1s1-eth2', delay='120ms')
        self.addLink(fast12r1, ixp1s1, intfName1='fast12r1-eth0', params1={'ip': '8.2.1.3/24'}, intfName2='ixp1s1-eth3', delay='10ms')

        # IXP2: shared middle transit fabric. This is the loop-capable middle exchange.
        self.addLink(slow12r1, ixp2s1, intfName1='slow12r1-eth1', params1={'ip': '8.2.2.11/24'}, intfName2='ixp2s1-eth0')
        self.addLink(fast12r1, ixp2s1, intfName1='fast12r1-eth1', params1={'ip': '8.2.2.12/24'}, intfName2='ixp2s1-eth1')
        self.addLink(slow23r1, ixp2s1, intfName1='slow23r1-eth0', params1={'ip': '8.2.2.21/24'}, intfName2='ixp2s1-eth2')
        self.addLink(fast23r1, ixp2s1, intfName1='fast23r1-eth0', params1={'ip': '8.2.2.22/24'}, intfName2='ixp2s1-eth3')

        # IXP3: ports 1..4 = AS200, AS600, slow23, fast23
        self.addLink(as2r1, ixp3s1, intfName1='as2r1-eth1', params1={'ip': '8.2.3.1/24'}, intfName2='ixp3s1-eth0')
        self.addLink(as6r1, ixp3s1, intfName1='as6r1-eth1', params1={'ip': '8.2.3.4/24'}, intfName2='ixp3s1-eth1')
        self.addLink(slow23r1, ixp3s1, intfName1='slow23r1-eth1', params1={'ip': '8.2.3.2/24'}, intfName2='ixp3s1-eth2', delay='120ms')
        self.addLink(fast23r1, ixp3s1, intfName1='fast23r1-eth1', params1={'ip': '8.2.3.3/24'}, intfName2='ixp3s1-eth3', delay='10ms')


topos = {'topology': (lambda: Topology())}
