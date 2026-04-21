#include <core.p4>
#include <v1model.p4>

typedef bit<48> mac_addr_t;

header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16>    etherType;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<16> tenant_id;
    bit<16> policy_id;
    bit<16> group_id;

    /* Include L4 ports for future. */
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct mac_learn_digest_t {
    mac_addr_t srcAddr;
    bit<9>     ingress_port;
}

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6:  parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply { }
}

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action flood() {
        /* Controller creates one multicast group per ingress port. */
        standard_metadata.mcast_grp = (bit<16>) standard_metadata.ingress_port;
    }

    action set_tenant(bit<16> tenant_id) {
        meta.tenant_id = tenant_id;
    }

    action classify(bit<16> group_id, bit<16> policy_id) {
        meta.group_id = group_id;
        meta.policy_id = policy_id;
    }

    action set_active_egress(mac_addr_t egress_mac, bit<9> port) {
        hdr.ethernet.dstAddr = egress_mac;
        standard_metadata.egress_spec = port;

        /* Ensure this packet is treated as unicast steering, not multicast flood. */
        standard_metadata.mcast_grp = 0;
    }

    table tenant_port_map {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_tenant;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }

    table steering_classifier {
        key = {
            meta.tenant_id:     exact;
            hdr.ipv4.srcAddr:   exact;
            hdr.ipv4.dstAddr:   exact;
            hdr.ipv4.protocol:  exact;
            hdr.ipv4.diffserv:  exact;
        }
        actions = {
            classify;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    table active_egress {
        key = {
            meta.group_id: exact;
        }
        actions = {
            set_active_egress;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
            flood;
        }
        size = 4096;
        default_action = flood();
    }

    apply {
        if (!hdr.ethernet.isValid()) {
            drop();
        } else {
            /* MAC learning stays on for all traffic. */
            mac_learn_digest_t learn;
            learn.srcAddr = hdr.ethernet.srcAddr;
            learn.ingress_port = standard_metadata.ingress_port;
            digest<mac_learn_digest_t>(1, learn);

            meta.tenant_id = 0;
            meta.policy_id = 0;
            meta.group_id = 0;
            meta.l4_src_port = 0;
            meta.l4_dst_port = 0;

            tenant_port_map.apply();

            if (hdr.tcp.isValid()) {
                meta.l4_src_port = hdr.tcp.srcPort;
                meta.l4_dst_port = hdr.tcp.dstPort;
            } else if (hdr.udp.isValid()) {
                meta.l4_src_port = hdr.udp.srcPort;
                meta.l4_dst_port = hdr.udp.dstPort;
            }

            /* Steering only applies to classified IPv4 packets. */
            if (hdr.ipv4.isValid()) {
                if (steering_classifier.apply().hit) {
                    if (!active_egress.apply().hit) {
                        dmac.apply();
                    }
                } else {
                    dmac.apply();
                }
            } else {
                dmac.apply();
            }
        }
    }
}

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    apply { }
}

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply { }
}

control MyDeparser(
    packet_out packet,
    in headers hdr
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
