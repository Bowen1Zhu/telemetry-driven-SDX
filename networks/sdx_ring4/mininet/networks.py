
from __future__ import annotations

import os
import sys

from mininet.node import Node, OVSSwitch
from mininet.topo import Topo

SCRIPT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_DIRECTORY = os.path.abspath(os.path.join(SCRIPT_DIRECTORY, '../../../'))

sys.path.append(REPOSITORY_DIRECTORY)

from common.p4.functions import HelperFunctions
from common.mininet.nodes import Client, P4Switch


class StaticRouter(Node):
    def __init__(self, *args, configCmds=None, inNamespace=True, **kwargs):
        self.configuration_commands = []
        if isinstance(configCmds, list):
            self.configuration_commands.extend(configCmds)
        kwargs['ip'] = None
        super().__init__(*args, inNamespace=inNamespace, **kwargs)

    def config(self, mac=None, ip=None, defaultRoute=None, lo='up', **params):
        super().config(mac=mac, ip=ip, defaultRoute=defaultRoute, lo=lo, **params)
        for intf in self.intfList():
            self.cmd(f'ethtool -K {intf} rx off tx off sg off')
        for command in self.configuration_commands:
            self.cmd(command)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('iptables -F')


class Topology(Topo):
    """4-IXP ring topology.

    Opposite-edge traffic from IXP1/AS100 to IXP3/AS300 can traverse either:
      * via IXP2 (clockwise / initially faster)
      * via IXP4 (counter-clockwise / initially slower)
    """

    def build(self, *args, **params):
        macs = {
            'as1r1': {'as1r1-eth0': 'f0:00:0d:10:01:00', 'as1r1-eth1': 'f0:00:0d:10:01:01'},
            'as3r1': {'as3r1-eth0': 'f0:00:0d:10:03:00', 'as3r1-eth1': 'f0:00:0d:10:03:01'},
            'seg12r1': {'seg12r1-eth0': 'f0:00:0d:12:00:01', 'seg12r1-eth1': 'f0:00:0d:12:00:02'},
            'seg23r1': {'seg23r1-eth0': 'f0:00:0d:23:00:01', 'seg23r1-eth1': 'f0:00:0d:23:00:02'},
            'seg34r1': {'seg34r1-eth0': 'f0:00:0d:34:00:01', 'seg34r1-eth1': 'f0:00:0d:34:00:02'},
            'seg41r1': {'seg41r1-eth0': 'f0:00:0d:41:00:01', 'seg41r1-eth1': 'f0:00:0d:41:00:02'},
            'as1h1': {'as1h1-eth0': 'f0:00:0d:00:01:00'},
            'as1h2': {'as1h2-eth0': 'f0:00:0d:00:01:01'},
            'as3h1': {'as3h1-eth0': 'f0:00:0d:00:03:00'},
            'as3h2': {'as3h2-eth0': 'f0:00:0d:00:03:01'},
        }

        # Access LAN switches.
        as1s1 = self.addSwitch('as1s1', cls=OVSSwitch)
        as3s1 = self.addSwitch('as3s1', cls=OVSSwitch)

        # Routers.
        as1r1 = self.addNode(
            'as1r1', cls=StaticRouter,
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(macs['as1r1'])
                + [
                    HelperFunctions.generate_add_loopback_interface_ip_command('100.100.1.1/32'),
                    'ip route add 8.1.3.0/24 via 8.2.1.2',
                ]
            ),
        )
        as3r1 = self.addNode(
            'as3r1', cls=StaticRouter,
            configCmds=(
                HelperFunctions.generate_set_interface_mac_commands(macs['as3r1'])
                + [
                    HelperFunctions.generate_add_loopback_interface_ip_command('100.100.3.1/32'),
                    'ip route add 8.1.1.0/24 via 8.2.3.2',
                ]
            ),
        )

        def add_seg_router(name: str, loopback: str, commands: list[str]):
            return self.addNode(
                name,
                cls=StaticRouter,
                configCmds=(
                    HelperFunctions.generate_set_interface_mac_commands(macs[name])
                    + [HelperFunctions.generate_add_loopback_interface_ip_command(loopback)]
                    + commands
                ),
            )

        seg12r1 = add_seg_router('seg12r1', '100.100.12.1/32', [
            'ip route add 8.1.1.0/24 via 8.2.1.1',
            'ip route add 8.1.3.0/24 via 8.2.2.2',
        ])
        seg23r1 = add_seg_router('seg23r1', '100.100.23.1/32', [
            'ip route add 8.1.1.0/24 via 8.2.2.1',
            'ip route add 8.1.3.0/24 via 8.2.3.1',
        ])
        seg34r1 = add_seg_router('seg34r1', '100.100.34.1/32', [
            'ip route add 8.1.1.0/24 via 8.2.4.2',
            'ip route add 8.1.3.0/24 via 8.2.3.1',
        ])
        seg41r1 = add_seg_router('seg41r1', '100.100.41.1/32', [
            'ip route add 8.1.1.0/24 via 8.2.1.1',
            'ip route add 8.1.3.0/24 via 8.2.4.1',
        ])

        # Hosts.
        as1h1 = self.addHost('as1h1', cls=Client, configCmds=(
            HelperFunctions.generate_set_interface_mac_commands(macs['as1h1'])
            + [HelperFunctions.generate_set_default_route_command('8.1.1.1')]
        ))
        as1h2 = self.addHost('as1h2', cls=Client, configCmds=(
            HelperFunctions.generate_set_interface_mac_commands(macs['as1h2'])
            + [HelperFunctions.generate_set_default_route_command('8.1.1.1')]
        ))
        as3h1 = self.addHost('as3h1', cls=Client, configCmds=(
            HelperFunctions.generate_set_interface_mac_commands(macs['as3h1'])
            + [HelperFunctions.generate_set_default_route_command('8.1.3.1')]
        ))
        as3h2 = self.addHost('as3h2', cls=Client, configCmds=(
            HelperFunctions.generate_set_interface_mac_commands(macs['as3h2'])
            + [HelperFunctions.generate_set_default_route_command('8.1.3.1')]
        ))

        # IXP P4 switches.
        ixp1s1 = self.addSwitch('ixp1s1', cls=P4Switch, identifier=1, thrift_port=9091, grpc_address='0.0.0.0', grpc_port=50001)
        ixp2s1 = self.addSwitch('ixp2s1', cls=P4Switch, identifier=2, thrift_port=9092, grpc_address='0.0.0.0', grpc_port=50002)
        ixp3s1 = self.addSwitch('ixp3s1', cls=P4Switch, identifier=3, thrift_port=9093, grpc_address='0.0.0.0', grpc_port=50003)
        ixp4s1 = self.addSwitch('ixp4s1', cls=P4Switch, identifier=4, thrift_port=9094, grpc_address='0.0.0.0', grpc_port=50004)

        # Access LANs.
        self.addLink(as1r1, as1s1, intfName1='as1r1-eth0', params1={'ip': '8.1.1.1/24'}, intfName2='as1s1-eth0')
        self.addLink(as1h1, as1s1, intfName1='as1h1-eth0', params1={'ip': '8.1.1.101/24'}, intfName2='as1s1-eth1')
        self.addLink(as1h2, as1s1, intfName1='as1h2-eth0', params1={'ip': '8.1.1.102/24'}, intfName2='as1s1-eth2')

        self.addLink(as3r1, as3s1, intfName1='as3r1-eth0', params1={'ip': '8.1.3.1/24'}, intfName2='as3s1-eth0')
        self.addLink(as3h1, as3s1, intfName1='as3h1-eth0', params1={'ip': '8.1.3.101/24'}, intfName2='as3s1-eth1')
        self.addLink(as3h2, as3s1, intfName1='as3h2-eth0', params1={'ip': '8.1.3.102/24'}, intfName2='as3s1-eth2')

        # Ring edge IXP1 subnet.
        self.addLink(as1r1, ixp1s1, intfName1='as1r1-eth1', params1={'ip': '8.2.1.1/24'}, intfName2='ixp1s1-eth0')
        self.addLink(seg12r1, ixp1s1, intfName1='seg12r1-eth0', params1={'ip': '8.2.1.2/24'}, intfName2='ixp1s1-eth1', delay='10ms')
        self.addLink(seg41r1, ixp1s1, intfName1='seg41r1-eth1', params1={'ip': '8.2.1.4/24'}, intfName2='ixp1s1-eth2', delay='40ms')

        # IXP2 subnet.
        self.addLink(seg12r1, ixp2s1, intfName1='seg12r1-eth1', params1={'ip': '8.2.2.1/24'}, intfName2='ixp2s1-eth0', delay='10ms')
        self.addLink(seg23r1, ixp2s1, intfName1='seg23r1-eth0', params1={'ip': '8.2.2.2/24'}, intfName2='ixp2s1-eth1', delay='10ms')

        # IXP3 subnet.
        self.addLink(as3r1, ixp3s1, intfName1='as3r1-eth1', params1={'ip': '8.2.3.1/24'}, intfName2='ixp3s1-eth0')
        self.addLink(seg23r1, ixp3s1, intfName1='seg23r1-eth1', params1={'ip': '8.2.3.2/24'}, intfName2='ixp3s1-eth1', delay='10ms')
        self.addLink(seg34r1, ixp3s1, intfName1='seg34r1-eth0', params1={'ip': '8.2.3.4/24'}, intfName2='ixp3s1-eth2', delay='40ms')

        # IXP4 subnet.
        self.addLink(seg34r1, ixp4s1, intfName1='seg34r1-eth1', params1={'ip': '8.2.4.1/24'}, intfName2='ixp4s1-eth0', delay='40ms')
        self.addLink(seg41r1, ixp4s1, intfName1='seg41r1-eth0', params1={'ip': '8.2.4.2/24'}, intfName2='ixp4s1-eth1', delay='40ms')


topos = {'topology': (lambda: Topology())}
