"""
This module defines the client, switch, router, and server classes used by the
Mininet network emulator within the virtual P4 environments.
"""

__author__ = "Fang Jie LIM"
__credits__ = ["Fang Jie LIM", "NECUS Technologies"]
__email__ = "fangjie.lim@necus.tech"

import os

from mininet.node import Host, Switch, Node

SCRIPT_DIRECTORY = os.path.abspath(
    os.path.dirname(__file__)
)
REPOSITORY_DIRECTORY = SCRIPT_DIRECTORY
DEFAULT_WORKING_DIRECTORY = os.path.abspath(
    os.path.join(
        REPOSITORY_DIRECTORY,
        "../../temp"
    )
)

class Client(Host):
    def __init__(
        self,
        *args,
        inNamespace=True,
        configCmds=None,
        **kwargs
    ):
        self.configuration_commands = [
            "sysctl -w net.ipv4.ip_forward=0",
            "sysctl -w net.ipv6.conf.all.forwarding=0",
        ]
        if isinstance(configCmds, list):
            self.configuration_commands.extend(configCmds)
        kwargs["ip"] = None

        super().__init__(
            *args,
            inNamespace,
            **kwargs
        )

    def config(
        self,
        mac=None,
        ip=None,
        defaultRoute=None,
        lo="up",
        **_params
    ):
        super().config(
            mac,
            ip,
            defaultRoute,
            lo,
            **_params
        )

        for intf in self.intfList():
            self.cmd(f"ethtool -K {intf} rx off tx off sg off")

        for command in self.configuration_commands:
            self.cmd(command)

class P4Switch(Switch):
    def __init__(
        self,
        name,
        identifier,
        thrift_port,
        grpc_address,
        grpc_port,
        cpu_port=510,
        working_directory=DEFAULT_WORKING_DIRECTORY,
        **kwargs
    ):
        self.switch_name = name
        self.switch_identifier = identifier
        self.thrift_port = thrift_port
        self.grpc_address = grpc_address
        self.grpc_port = grpc_port
        self.process_identifier = None
        self.process_identifier_file_path = None
        self.cpu_port = cpu_port
        self.working_directory = os.path.join(
            *[
                working_directory,
                "p4_switch",
                str(self.switch_name)
            ]
        )
        self.configuration_commands = [
            "sysctl -w net.ipv4.ip_forward=0",
            "sysctl -w net.ipv6.conf.all.forwarding=0",
        ]

        os.makedirs(self.working_directory, exist_ok=True)

        super().__init__(name, **kwargs)

    def start(
        self,
        controllers
    ):
        self.process_identifier_file_path = os.path.join(
            self.working_directory,
            self.switch_name + ".pid"
        )
        process_nanolog_ipc_path = (
            "ipc:///tmp/bmv2-" +
            self.switch_name +
            "-log.ipc"
        )
        process_log_bmv2_file_path = os.path.join(
            self.working_directory,
            self.switch_name + "-bmv2"
        )
        process_log_stdout_file_path = os.path.join(
            self.working_directory,
            self.switch_name + "-stdout.txt"
        )

        for intf in self.intfList():
            self.cmd(f"ethtool -K {intf} rx off tx off sg off")

        for command in self.configuration_commands:
            self.cmd(command)

        command = []
        command.append("simple_switch_grpc")
        for port, interface in list(self.intfs.items()):
            if not interface.IP():
                command.append("-i " + str(port) + "@" + interface.name)
        command.append("--no-p4")
        command.append("--device-id " + str(self.switch_identifier))
        command.append("--thrift-port " + str(self.thrift_port))
        command.append("--nanolog " + process_nanolog_ipc_path)
        command.append("--log-file " + process_log_bmv2_file_path)
        command.append("--pcap " + self.working_directory)
        command.append("--")
        command.append("--grpc-server-addr " + str(self.grpc_address) + ":" + str(self.grpc_port))
        command.append("--cpu-port " + str(self.cpu_port))
        command.append("> " + process_log_stdout_file_path + " 2>&1")
        command.append("& echo $! > " + self.process_identifier_file_path)

        self.cmd(' '.join(command))

        with open(self.process_identifier_file_path, 'r', encoding="utf-8") as file:
            self.process_identifier = file.read()

    def stop(
            self,
            deleteIntfs=True
        ):
        command = []
        command.append("kill")
        command.append("-9")
        command.append(self.process_identifier)
        self.cmd(' '.join(command))

        os.remove(self.process_identifier_file_path)

        if deleteIntfs:
            self.deleteIntfs()

class FRRRouter(Node):
    def __init__(
        self,
        name,
        *args,
        inNamespace=True,
        zebraConfigFile=None,
        bgpConfigFile=None,
        configCmds=None,
        working_directory=DEFAULT_WORKING_DIRECTORY,
        **kwargs
    ):
        self.router_name = name
        self.working_directory = os.path.join(
            *[
                working_directory,
                "frr_router",
                str(self.router_name)
            ]
        )
        self.zebra_configuration_file = zebraConfigFile
        self.bgp_configuration_file = bgpConfigFile
        self.configuration_commands = []
        if isinstance(configCmds, list):
            self.configuration_commands.extend(configCmds)
        self.process_identifier_zebra = None
        self.process_identifier_zebra_file_path_1 = "/var/run/frr/zebra.pid"
        self.process_identifier_zebra_file_path_2 = os.path.join(
            self.working_directory,
            self.router_name + "-zebra.pid"
        )
        self.process_log_zebra_file_path = os.path.join(
            self.working_directory,
            self.router_name + "-zebra.log"
        )
        self.process_identifier_bgpd = None
        self.process_identifier_bgpd_file_path_1 = "/var/run/frr/bgpd.pid"
        self.process_identifier_bgpd_file_path_2 = os.path.join(
            self.working_directory,
            self.router_name + "-bgpd.pid"
        )
        self.process_log_bgpd_file_path = os.path.join(
            self.working_directory,
            self.router_name + "-bgpd.log"
        )
        if "privateDirs" not in kwargs:
            kwargs["privateDirs"] = [
                "/etc/frr",
                "/var/run/frr",
            ]
        kwargs["ip"] = None

        os.makedirs(self.working_directory, exist_ok=True)

        super().__init__(
            name,
            *args,
            inNamespace,
            **kwargs
        )

    def config(
        self,
        mac=None,
        ip=None,
        defaultRoute=None,
        lo="up",
        **_params
    ):
        super().config(
            mac,
            ip,
            defaultRoute,
            lo,
            **_params
        )

        for intf in self.intfList():
            self.cmd(f"ethtool -K {intf} rx off tx off sg off")

        for command in self.configuration_commands:
            self.cmd(command)

        if self.zebra_configuration_file is not None:
            command = []
            command.append("cp")
            command.append(self.zebra_configuration_file)
            command.append("/etc/frr/zebra.conf")
            self.cmd(' '.join(command))

        if self.bgp_configuration_file is not None:
            command = []
            command.append("cp")
            command.append(self.bgp_configuration_file)
            command.append("/etc/frr/bgpd.conf")
            self.cmd(' '.join(command))

        command = []
        command.append("sysctl")
        command.append("net.ipv4.ip_forward=1")
        self.cmd(' '.join(command))

        command = []
        command.append("iptables")
        command.append("-F")
        self.cmd(' '.join(command))

        command = []
        command.append("echo")
        command.append("\"hostname " + self.router_name + "\"")
        command.append("> /etc/frr/vtysh.conf")
        self.cmd(' '.join(command))

        command = []
        command.append("/usr/lib/frr/zebra")
        command.append("-d")
        command.append("--log file:" + self.process_log_zebra_file_path)
        command.append("--log-level debugging")
        self.cmd(' '.join(command))

        command = []
        command.append("cat")
        command.append(self.process_identifier_zebra_file_path_1)
        self.process_identifier_zebra = self.cmd(' '.join(command))

        with open(
            self.process_identifier_zebra_file_path_2,
            "w",
            encoding="utf-8",
            newline="",
        ) as pid_file:
            pid_file.write(self.process_identifier_zebra)

        command = []
        command.append("chmod +r")
        command.append(self.process_log_zebra_file_path)
        self.cmd(' '.join(command))

        command = []
        command.append("/usr/lib/frr/bgpd")
        command.append("-d")
        command.append("--log file:" + self.process_log_bgpd_file_path)
        command.append("--log-level debugging")
        self.cmd(' '.join(command))

        command = []
        command.append("cat")
        command.append(self.process_identifier_bgpd_file_path_1)
        self.process_identifier_bgpd = self.cmd(' '.join(command))

        with open(
            self.process_identifier_bgpd_file_path_2,
            "w",
            encoding="utf-8",
            newline="",
        ) as pid_file:
            pid_file.write(self.process_identifier_bgpd)

        command = []
        command.append("chmod +r")
        command.append(self.process_log_bgpd_file_path)
        self.cmd(' '.join(command))

    def terminate(self):
        command = []
        command.append("kill")
        command.append("-9")
        command.append(self.process_identifier_zebra)
        self.cmd(' '.join(command))

        os.remove(self.process_identifier_zebra_file_path_2)

        command = []
        command.append("kill")
        command.append("-9")
        command.append(self.process_identifier_bgpd)
        self.cmd(' '.join(command))

        os.remove(self.process_identifier_bgpd_file_path_2)

        super().terminate()

class BIRDRouter(Node):
    def __init__(
        self,
        name,
        *args,
        inNamespace=True,
        configFile=None,
        configCmds=None,
        controlSocket=None,
        toEnableIpv4Forwarding=True,
        working_directory=DEFAULT_WORKING_DIRECTORY,
        **kwargs
    ):
        self.router_name = name
        self.working_directory = os.path.abspath(
            os.path.join(
                *[
                    working_directory,
                    "bird_router",
                    str(self.router_name)
                ]
            )
        )
        self.configuration_file = configFile
        self.configuration_commands = []
        if isinstance(configCmds, list):
            self.configuration_commands.extend(configCmds)
        self.control_socket_file_path = os.path.join(
            "/run/mininet/bird/",
            self.router_name + ".sock"
        )
        if isinstance(controlSocket, str):
            self.control_socket_file_path = controlSocket
        self.to_enable_ipv4_forwarding = toEnableIpv4Forwarding
        self.process_identifier = None
        self.process_identifier_file_path_1 = "/var/run/bird/bird.pid"
        self.process_identifier_file_path_2 =  os.path.join(
            self.working_directory,
            self.router_name + "-bird.pid"
        )
        self.process_log_file_path = os.path.join(
            self.working_directory,
            self.router_name + "-bird.log"
        )
        if "privateDirs" not in kwargs:
            kwargs["privateDirs"] = [
                "/etc/bird",
                "/var/run/bird",
            ]
        kwargs["ip"] = None

        os.makedirs(self.working_directory, exist_ok=True)

        super().__init__(
            name,
            *args,
            inNamespace,
            **kwargs
        )

    def config(
        self,
        mac=None,
        ip=None,
        defaultRoute=None,
        lo="up",
        **_params
    ):
        super().config(
            mac,
            ip,
            defaultRoute,
            lo,
            **_params
        )

        for intf in self.intfList():
            self.cmd(f"ethtool -K {intf} rx off tx off sg off")

        for command in self.configuration_commands:
            self.cmd(command)

        control_socket_directory = os.path.dirname(
            self.control_socket_file_path
        )
        print(control_socket_directory)
        if not os.path.isdir(control_socket_directory):
            os.makedirs(control_socket_directory, exist_ok=True)
            os.chmod(control_socket_directory, 0o777)

        if self.configuration_file is not None:
            command = []
            command.append("cp")
            command.append(self.configuration_file)
            command.append("/etc/bird/bird.conf")
            self.cmd(' '.join(command))

        if self.to_enable_ipv4_forwarding:
            command = []
            command.append("sysctl")
            command.append("net.ipv4.ip_forward=1")
            self.cmd(' '.join(command))

        command = []
        command.append("iptables")
        command.append("-F")
        self.cmd(' '.join(command))

        command = []
        command.append("/usr/sbin/bird")
        command.append("-s")
        command.append(self.control_socket_file_path)
        command.append("-P")
        command.append(self.process_identifier_file_path_1)
        command.append("-D")
        command.append(self.process_log_file_path)
        self.cmd(' '.join(command))

        command = []
        command.append("cat")
        command.append(self.process_identifier_file_path_1)
        self.process_identifier = self.cmd(' '.join(command))

        with open(
            self.process_identifier_file_path_2,
            "w",
            encoding="utf-8",
            newline="",
        ) as pid_file:
            pid_file.write(self.process_identifier)

    def terminate(self):
        command = []
        command.append("kill")
        command.append("-9")
        command.append(self.process_identifier)
        self.cmd(' '.join(command))

        os.remove(self.process_identifier_file_path_2)

        super().terminate()

class IPerf3Server(Node):
    def __init__(
        self,
        name,
        *args,
        inNamespace=True,
        configCmds=None,
        working_directory=DEFAULT_WORKING_DIRECTORY,
        **kwargs
    ):
        self.server_name = name
        self.working_directory = os.path.join(
            *[
                working_directory,
                "iperf3_server",
                str(self.server_name)
            ]
        )
        self.configuration_commands = [
            "sysctl -w net.ipv4.ip_forward=0",
            "sysctl -w net.ipv6.conf.all.forwarding=0",
        ]
        if isinstance(configCmds, list):
            self.configuration_commands.extend(configCmds)
        self.process_identifier = None
        self.process_identifier_file_path =  os.path.join(
            self.working_directory,
            self.server_name + "-iperf3.pid"
        )
        self.process_log_file_path = os.path.join(
            self.working_directory,
            self.server_name + "-iperf3.log"
        )

        kwargs["ip"] = None

        os.makedirs(self.working_directory, exist_ok=True)

        super().__init__(
            name,
            *args,
            inNamespace,
            **kwargs
        )

    def config(
        self,
        mac=None,
        ip=None,
        defaultRoute=None,
        lo="up",
        **_params
    ):
        super().config(
            mac,
            ip,
            defaultRoute,
            lo,
            **_params
        )

        for intf in self.intfList():
            self.cmd(f"ethtool -K {intf} rx off tx off sg off")

        for command in self.configuration_commands:
            self.cmd(command)

        command = []
        command.append("iptables")
        command.append("-F")
        self.cmd(' '.join(command))

        command = []
        command.append("iperf3")
        command.append("-s")
        command.append("--logfile")
        command.append(self.process_log_file_path)
        command.append("& echo $! >")
        command.append(self.process_identifier_file_path)
        self.cmd(' '.join(command))

        with open(self.process_identifier_file_path, 'r', encoding="utf-8") as file:
            self.process_identifier = file.read()

    def terminate(self):
        command = []
        command.append("kill")
        command.append("-9")
        command.append(self.process_identifier)
        self.cmd(' '.join(command))

        os.remove(self.process_identifier_file_path)

        super().terminate()
