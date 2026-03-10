"""
This module defines the functions used by the various P4 environments.
"""

__author__ = "Fang Jie LIM"
__credits__ = ["Fang Jie LIM", "NECUS Technologies"]
__email__ = "fangjie.lim@necus.tech"

import ipaddress

from scapy.all import ICMP, IP, PacketList

class HelperFunctions:
    @classmethod
    def convert_mac_address_integer_to_string(
        cls,
        mac_address: int
    ) -> str:
        return ':'.join(
            [
                f"{upper_nibble}{lower_nibble}"
                for upper_nibble, lower_nibble in
                zip(*[iter(f"{mac_address:012x}")] * 2)
            ]
        )

    @classmethod
    def convert_mac_address_string_to_integer(
        cls,
        mac_address: str
    ) -> int:
        return int(mac_address.replace(":", ""), 16)

    @classmethod
    def convert_ip_address_integer_to_string(
        cls,
        ip_address: int
    ) -> str:
        return str(ipaddress.ip_address(ip_address))

    @classmethod
    def convert_ip_address_string_to_integer(
        cls,
        ip_address: str
    ) -> int:
        return int(ipaddress.ip_address(ip_address))

    @classmethod
    def generate_set_interface_mac_command(
        cls,
        interface_name: str,
        mac_address: str,
    ) -> str:
        return f"ip link set dev {interface_name} address {mac_address}"

    @classmethod
    def generate_set_interface_mac_commands(
        cls,
        interfaces_names_mac_addresses: dict[str:str]
    ) -> list:
        commands = []

        for interface_name in interfaces_names_mac_addresses:
            commands.append(
                cls.generate_set_interface_mac_command(
                    interface_name,
                    interfaces_names_mac_addresses[interface_name]
                )
            )

        return commands

    @classmethod
    def generate_add_loopback_interface_ip_command(
        cls,
        ip_address: str,
    ) -> str:
        return f"ip addr add {ip_address} dev lo"

    @classmethod
    def generate_set_static_arp_command(
        cls,
        ip_address: str,
        mac_address: str
    ) -> str:
        return f"arp -s {ip_address} {mac_address}"

    @classmethod
    def generate_set_static_route_command(
        cls,
        destination_address: str,
        next_hop_address: str,
    ) -> str:
        return f"ip route add {destination_address} via {next_hop_address}"

    @classmethod
    def generate_set_default_route_command(
        cls,
        next_hop_address: str,
    ) -> str:
        return f"ip route add default via {next_hop_address}"

    @classmethod
    def is_scapy_ipv4_chksum_valid(
        cls,
        packet
    ):
        if IP not in packet:
            return False

        packet_original = packet[IP].copy()
        packet_copy = packet[IP].copy()

        packet_copy.chksum = None
        packet_copy = packet.__class__(bytes(packet_copy))

        return packet_original.chksum == packet_copy.chksum

    @classmethod
    def is_scapy_icmp_chksum_valid(
        cls,
        packet
    ):
        if ICMP not in packet:
            return False

        packet_original = packet[ICMP].copy()
        packet_copy = packet[ICMP].copy()

        packet_copy.chksum = None
        packet_copy = packet.__class__(bytes(packet_copy))

        return packet_original.chksum == packet_copy.chksum

    @classmethod
    def filter_frames(
        cls,
        packets: PacketList,
        ip_packet_source: str=None,
        ip_packet_destination: str=None,
        icmp_packet_type: int=None,
        icmp_packet_code: int=None,
        icmp_packet_sequence_number: int=None,
        validate_ip_packet_checksum: bool=False,
        validate_icmp_packet_checksum: bool=False,
    ) -> list:
        packets_filtered = packets

        if isinstance(ip_packet_source, str):
            packets_filtered = [
                pkt for pkt in packets_filtered if (
                    IP in pkt and
                    pkt[IP].src == ip_packet_source
                )
            ]

        if isinstance(ip_packet_destination, str):
            packets_filtered = [
                pkt for pkt in packets_filtered if (
                    IP in pkt and
                    pkt[IP].dst == ip_packet_destination
                )
            ]

        if isinstance(icmp_packet_type, int):
            packets_filtered = [
                pkt for pkt in packets_filtered if (
                    ICMP in pkt and
                    pkt[ICMP].type == icmp_packet_type
                )
            ]

        if isinstance(icmp_packet_code, int):
            packets_filtered = [
                pkt for pkt in packets_filtered if (
                    ICMP in pkt and
                    pkt[ICMP].code == icmp_packet_code
                )
            ]

        if isinstance(icmp_packet_sequence_number, int):
            packets_filtered = [
                pkt for pkt in packets_filtered if (
                    ICMP in pkt and
                    pkt[ICMP].seq == icmp_packet_sequence_number
                )
            ]

        if validate_ip_packet_checksum:
            packets_filtered = [
                pkt for pkt in packets_filtered if (
                    IP in pkt and
                    cls.is_scapy_ipv4_chksum_valid(pkt[IP])
                )
            ]

        if validate_icmp_packet_checksum:
            packets_filtered = [
                pkt for pkt in packets_filtered if (
                    ICMP in pkt and
                    cls.is_scapy_icmp_chksum_valid(pkt[ICMP])
                )
            ]

        return packets_filtered
