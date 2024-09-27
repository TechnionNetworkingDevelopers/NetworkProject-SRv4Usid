/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<8> usid_t;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
}
struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    // Action to drop the packet
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Action to process the next SRv4 segment ID
    action srv4_next_c_sid() {
        bit<8> subnet_id;
        bit<8> current_sid;
        bit<16> curry;
        // Extract subnet ID and current SID from the destination address
        subnet_id = hdr.ipv4.dstAddr[31:24];
        current_sid = hdr.ipv4.dstAddr[23:16];
        curry = hdr.ipv4.dstAddr[15:0];
        // Update the destination address with the next segment ID
        hdr.ipv4.dstAddr[31:24] = subnet_id;
        hdr.ipv4.dstAddr[23:8] = curry;
        hdr.ipv4.dstAddr[7:0] = 0;
    }

    // Table to match on the destination address for SRv4 processing
    table srv4_my_sid {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            srv4_next_c_sid;
            NoAction;
        }
    }

    // Action to push a new SRv4 segment ID
    action srv4_push_c_sid(usid_t s1) {
        // Hardcoded assumption that size of each usid is 8 bits
        bit<8> subnet_id = hdr.ipv4.dstAddr[31:24];
        // Hardcoded assumption that size of each subnet is 8 bits
        if ((hdr.ipv4.dstAddr & 0x0000FFFF) == 0) {
            bit<8> destination_suffix = hdr.ipv4.dstAddr[23:16];
            hdr.ipv4.dstAddr[15:8] = destination_suffix;
        }
        else if ((hdr.ipv4.dstAddr & 0x000000FF) == 0) {
            bit<16> destination_suffix;
            destination_suffix = hdr.ipv4.dstAddr[23:8];
            hdr.ipv4.dstAddr[15:0] = destination_suffix[15:0];
        }
        // Update the destination address with the new segment ID
        hdr.ipv4.dstAddr[31:24] = subnet_id;
        hdr.ipv4.dstAddr[23:16] = s1;
    }

    // Table to match on the destination address for SRv4 ingress processing
    table srv4_ingress {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            srv4_push_c_sid;
            NoAction;
        }
    }

    // Action to forward the packet based on the destination MAC address and port
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Table to match on the destination address for IPv4 forwarding
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // Action to send an ARP reply
    action send_arp_reply(bit<48> target_hw_addr, bit<32> target_proto_addr) {
        hdr.arp.opcode = 2; // ARP reply
        hdr.arp.target_hw_addr = hdr.arp.sender_hw_addr;
        hdr.arp.target_proto_addr = hdr.arp.sender_proto_addr;
        hdr.arp.sender_hw_addr = target_hw_addr;
        hdr.arp.sender_proto_addr = target_proto_addr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = target_hw_addr;
    }

    // Table to match on ARP requests and send ARP replies
    table arp_table {
        key = {
            hdr.arp.opcode: exact;
            hdr.arp.target_proto_addr: exact;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        // Apply ARP table if ARP header is valid
        if (hdr.arp.isValid()) {
            arp_table.apply();
        }
        // Apply IPv4 processing if IPv4 header is valid and TTL is greater than 0
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            // Apply SRv4 my SID table
            if (srv4_my_sid.apply().hit) {
                // No additional action needed if hit
            } else {
                // Apply SRv4 ingress table if no hit in my SID table
                srv4_ingress.apply();
            }
            // Apply IPv4 LPM table for forwarding
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
