/*
Copyright 2013-present Barefoot Networks, Inc. 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// to test direct meters
// #define USE_DIRECT_METER

#define ETHERTYPE_IPV4 0x0800
#define IPPROTOCOL_TCP 0x06

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type intrinsic_metadata_t {
    fields {
        mcast_grp : 4;
        egress_rid : 4;
        mcast_hash : 16;
        lf_field_list: 32;
    }
}

header_type meta_t {
    fields {
        current_port : 16;
        previous_port: 16;
        scan_occurrences: 32;
    }
}

metadata meta_t meta;

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;

metadata intrinsic_metadata_t intrinsic_metadata;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select (latest.protocol){
        IPPROTOCOL_TCP : parse_tcp;
        default: ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    return ingress;
}

action _drop() {
    drop();
}

action _nop() {
}

register port_register {
    width: 16;
    static: m_table;
    instance_count: 1200;
}

register scan_register {
    width: 32;
    static: m_table;
    instance_count: 1200;
}
    
action m_action(register1) {
    register_read(meta.previous_port, port_register, register1);
    modify_field(meta.current_port, tcp.dstPort);
    register_read(meta.scan_occurrences, scan_register, register1);
}

action steer_port(steerport) {
    modify_field(standard_metadata.egress_spec, steerport);
}

action set_good_register_state (register_idx) {
    modify_field (meta.scan_occurrences, 0);
    register_write (port_register, register_idx, meta.current_port);
    register_write (scan_register, register_idx, meta.scan_occurrences);
}

action set_bad_register_state (register_idx) {
    modify_field (meta.scan_occurrences, meta.scan_occurrences + 1);
    register_write (port_register, register_idx, meta.current_port);
    register_write (scan_register, register_idx, meta.scan_occurrences);
}

table m_table {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
    }
    actions {
        m_action; _nop;
    }
    size : 16384;
}

table m_filter {
    reads {
        meta.scan_occurrences : exact;
    }
    actions {
        steer_port;_drop;
    }
    size: 16;
}
table m_go {
    reads {
        ipv4.protocol : exact;
    }
    actions {
        steer_port; _nop;
    }
    size : 16;
}

table bad_register {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
    }
    actions {
        set_bad_register_state; _nop;
    }
    size : 1100;
}

table good_register {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
    }
    actions {
        set_good_register_state; _nop;
    }
    size : 1100;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

control ingress {
    apply(m_table);
    if (meta.previous_port == meta.current_port - 1){
        apply (bad_register);
        apply (m_filter);
    }
    else{
        apply(good_register);
        apply (m_go);
    }
    
}

control egress {
    apply(send_frame);   
}