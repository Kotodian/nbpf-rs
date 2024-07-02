#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use libc::c_void;
#[cfg(not(windows))]
use libc::{c_char, c_int};

#[cfg(windows)]
mod windows_types {
    pub type u_char = u8;
    pub type u_short = u16;
    pub type uint = u32;
    pub type u_long = u32;
    pub type u_int8_t = u8;
    pub type u_int16_t = u16;
    pub type u_int32_t = u32;
    pub type int32_t = i32;
    pub type u_int64_t = u64;
    pub type int64_t = i64;
}

#[cfg(windows)]
use windows_types::*;

#[cfg(not(windows))]
mod unix_types {
    pub type u_int8_t = libc::c_uchar;
    pub type u_int16_t = libc::c_ushort;
    pub type u_int32_t = libc::c_uint;
    pub type int32_t = libc::c_int;
    pub type u_int64_t = libc::c_ulong;
    pub type int64_t = libc::c_long;
}

#[cfg(not(windows))]
use unix_types::*;

#[cfg(windows)]
use winapi::shared::ws2def::WSAData;
#[cfg(windows)]
use winapi::um::winsock2::{WSACleanup, WSAStartup, MAKEWORD};

#[repr(C)]
#[derive(Copy, Clone)]
pub union nbpf_in6_addr {
    pub addr8: [u_int8_t; 16],
    pub addr16: [u_int16_t; 8],
    pub addr32: [u_int32_t; 4],
}

#[repr(C, packed)]
pub union nbpf_ip_addr {
    pub v6: nbpf_in6_addr,
    pub v4: u_int32_t,
}

// Header qualifiers
pub const NBPF_Q_OUTER: u8 = 1;
pub const NBPF_Q_INNER: u8 = 2;

// Protocol qualifiers
pub const NBPF_Q_LINK: u8 = 1;
pub const NBPF_Q_IP: u8 = 2;
pub const NBPF_Q_SCTP: u8 = 3;
pub const NBPF_Q_TCP: u8 = 4;
pub const NBPF_Q_UDP: u8 = 5;
pub const NBPF_Q_IPV6: u8 = 6;
pub const NBPF_Q_GTP: u8 = 7;
pub const NBPF_Q_ICMP: u8 = 8;

// Direction qualifiers
pub const NBPF_Q_SRC: u8 = 1;
pub const NBPF_Q_DST: u8 = 2;
pub const NBPF_Q_OR: u8 = 3;
pub const NBPF_Q_AND: u8 = 4;

// Address qualifiers
pub const NBPF_Q_HOST: u8 = 1;
pub const NBPF_Q_NET: u8 = 2;
pub const NBPF_Q_PORT: u8 = 3;
pub const NBPF_Q_PROTO: u8 = 5;
pub const NBPF_Q_PORTRANGE: u8 = 7;
pub const NBPF_Q_VLAN: u8 = 8;
pub const NBPF_Q_MPLS: u8 = 9;
pub const NBPF_Q_L7PROTO: u8 = 10;
pub const NBPF_Q_PROTO_REL: u8 = 11;
pub const NBPF_Q_CUSTOM: u8 = 12;
pub const NBPF_Q_LOCAL: u8 = 13;
pub const NBPF_Q_REMOTE: u8 = 14;
pub const NBPF_Q_DEVICE: u8 = 15;
pub const NBPF_Q_INTERFACE: u8 = 16;

// Common qualifiers
pub const NBPF_Q_DEFAULT: u8 = 0;
pub const NBPF_Q_UNDEF: u8 = 255;

// Rel Op
pub const NBPF_R_EQ: u8 = 0; // ==
pub const NBPF_R_NE: u8 = 1; // !=
pub const NBPF_R_LT: u8 = 2; // <
pub const NBPF_R_LE: u8 = 4; // <=
pub const NBPF_R_GT: u8 = 3; // >
pub const NBPF_R_GE: u8 = 5; // >=

// Node types
pub const N_EMPTY: u8 = 0;
pub const N_PRIMITIVE: u8 = 1;
pub const N_AND: u8 = 2;
pub const N_OR: u8 = 3;

#[repr(C, packed)]
pub struct nbpf_qualifiers_t {
    pub header: u_int8_t,
    pub protocol: u_int8_t,
    pub direction: u_int8_t,
    pub address: u_int8_t,
}

#[repr(C, packed)]
pub struct nbpf_arth_t {
    pub protocol: c_int,
    pub offset: u_int16_t,
    pub mask: u_int8_t,
}

#[repr(C, packed)]
pub struct nbpf_node_t {
    pub type_: c_int,
    pub level: c_int,
    pub qualifiers: nbpf_qualifiers_t,
    pub not_rule: u_int8_t,
    pub device_id: u_int16_t,
    pub interface_id: u_int16_t,
    pub vlan_id_defined: u_int8_t,
    pub mpls_label_defined: u_int8_t,
    pub __padding: u_int8_t,
    pub vlan_id: u_int16_t,
    pub mpls_label: u_int16_t,
    pub mac: [u_int8_t; 6],
    pub ip6: [u_int8_t; 16],
    pub mask6: [u_int8_t; 16],
    pub ip: u_int32_t,
    pub mask: u_int32_t,
    pub port_from: u_int16_t,
    pub port_to: u_int16_t,
    pub protocol: u_int16_t,
    pub l7protocol: u_int16_t,
    pub byte_match: nbpf_byte_match_t,
    pub custom_key: *mut c_char,
    pub custom_value: *mut c_char,
    pub l: *mut nbpf_node_t,
    pub r: *mut nbpf_node_t,
}

#[repr(C, packed)]
pub struct nbpf_byte_match_t {
    pub protocol: u_int16_t,
    pub offset: u_int16_t,
    pub mask: u_int8_t,
    pub relop: u_int8_t,
    pub value: u_int8_t,
}

pub type nbpf_custom_node_callback = Option<
    unsafe extern "C" fn(key: *const c_char, value: *const c_char, user: *mut c_void) -> c_int,
>;
pub type nbpf_ip_locality_callback = Option<
    unsafe extern "C" fn(ip: *mut nbpf_ip_addr, ip_version: u_int8_t, user: *mut c_void) -> c_int,
>;

#[repr(C, packed)]
pub struct nbpf_tree_t {
    pub root: *mut nbpf_node_t,
    pub compatibility_level: c_int,
    pub default_pass: c_int,
    pub custom_callback: nbpf_custom_node_callback,
    pub locality_callback: nbpf_ip_locality_callback,
}

pub type l7protocol_by_name_func = Option<unsafe extern "C" fn(name: *const c_char) -> c_int>;

#[repr(C, packed)]
pub struct nbpf_pkt_info_tuple_t {
    pub eth_type: u_int16_t,
    pub ip_version: u_int8_t,
    pub l3_proto: u_int8_t,
    pub ip_tos: u_int8_t,
    pub ip_src: nbpf_ip_addr,
    pub ip_dst: nbpf_ip_addr,
    pub l4_src_port: u_int16_t,
    pub l4_dst_port: u_int16_t,
}

#[repr(C, packed)]
pub struct nbpf_pkt_info_t {
    pub device_id: u_int16_t,
    pub interface_id: u_int16_t,
    pub dmac: [u_int8_t; 6],
    pub smac: [u_int8_t; 6],
    pub vlan_id: u_int16_t,
    pub vlan_id_qinq: u_int16_t,
    pub master_l7_proto: u_int16_t,
    pub l7_proto: u_int16_t,
    pub tuple: nbpf_pkt_info_tuple_t,
    pub tunneled_tuple: nbpf_pkt_info_tuple_t,
}

#[repr(C, packed)]
pub struct nbpf_rule_core_fields_byte_match_t {
    pub protocol: u_int16_t,
    pub offset: u_int16_t,
    pub mask: u_int8_t,
    pub relop: u_int8_t,
    pub value: u_int8_t,
    pub next: *mut nbpf_rule_core_fields_byte_match_t,
}

#[repr(C, packed)]
pub struct nbpf_rule_core_fields_t {
    pub not_rule: u_int8_t,
    pub smac: [u_int8_t; 6],
    pub dmac: [u_int8_t; 6],
    pub proto: u_int8_t, // tcp, udp, sctp
    pub ip_version: u_int8_t,
    pub gtp: u_int8_t,
    pub vlan: u_int8_t,
    pub mpls: u_int8_t,
    pub vlan_id: u_int16_t,
    pub l7_proto: u_int16_t,
    pub mpls_label: u_int16_t,
    pub shost: nbpf_ip_addr,
    pub dhost: nbpf_ip_addr,
    pub shost_mask: nbpf_ip_addr,
    pub dhost_mask: nbpf_ip_addr,
    pub sport_low: u_int16_t,
    pub sport_high: u_int16_t,
    pub dport_low: u_int16_t,
    pub dport_high: u_int16_t,
    pub byte_match: *mut nbpf_rule_core_fields_byte_match_t,
}

#[repr(C, packed)]
pub struct nbpf_rule_list_item_t {
    pub fields: nbpf_rule_core_fields_t,
    pub bidirectional: c_int,
    pub next: *mut nbpf_rule_list_item_t,
}

#[repr(C, packed)]
pub struct nbpf_rule_block_list_item_t {
    pub rule_list_head: *mut nbpf_rule_list_item_t,
    pub next: *mut nbpf_rule_block_list_item_t,
}

extern "C" {
    pub fn nbpf_parse(
        bpf_filter: *const c_char,
        l7proto_by_name_callback: l7protocol_by_name_func,
    ) -> *mut nbpf_tree_t;
    pub fn nbpf_match(tree: *const nbpf_tree_t, h: *const nbpf_pkt_info_t) -> c_int;
    pub fn nbpf_free(t: *mut nbpf_tree_t);

    pub fn nbpf_generate_rules(tree: *const nbpf_tree_t) -> *mut nbpf_rule_list_item_t;
    pub fn nbpf_rule_list_free(list: *mut nbpf_rule_list_item_t);

    pub fn nbpf_generate_optimized_rules(
        tree: *const nbpf_tree_t,
    ) -> *mut nbpf_rule_block_list_item_t;
    pub fn nbpf_rule_block_list_free(blocks: *mut nbpf_rule_block_list_item_t);
}

#[cfg(test)]
mod test {
    use libc::c_char;
    use std::ffi::CString;

    use crate::{nbpf_ip_addr, nbpf_tree_t};

    use super::{nbpf_free, nbpf_match, nbpf_parse, nbpf_pkt_info_t, nbpf_pkt_info_tuple_t};

    #[test]
    pub fn test_nbpf_base() {
        unsafe {
            let filter = "not host 192.168.0.1";
            let filter = CString::new(filter).unwrap();
            let tree = nbpf_parse(filter.as_ptr() as *const c_char, None);
            let l4_src_port: u16 = 34;
            let l4_dst_port: u16 = 345;

            let pkt_info = nbpf_pkt_info_t {
                device_id: 0,
                interface_id: 0,
                dmac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                smac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                vlan_id: 0,
                vlan_id_qinq: 0,
                master_l7_proto: 0,
                l7_proto: 7,
                tuple: nbpf_pkt_info_tuple_t {
                    eth_type: 0x0800,
                    ip_version: 4,
                    l3_proto: 17,
                    ip_tos: 0,
                    ip_src: nbpf_ip_addr { v4: 0x0100000A },
                    ip_dst: nbpf_ip_addr { v4: 0x0100A8C1 },
                    l4_src_port: l4_src_port.to_be(),
                    l4_dst_port: l4_dst_port.to_be(),
                },
                tunneled_tuple: nbpf_pkt_info_tuple_t {
                    eth_type: 0,
                    ip_version: 0,
                    l3_proto: 0,
                    ip_tos: 0,
                    ip_src: nbpf_ip_addr { v4: 0 },
                    ip_dst: nbpf_ip_addr { v4: 0 },
                    l4_src_port: 0,
                    l4_dst_port: 0,
                },
            };

            let matched = nbpf_match(
                tree as *const nbpf_tree_t,
                &pkt_info as *const nbpf_pkt_info_t,
            );

            assert_eq!(matched, 1);
            nbpf_free(tree);
        }
    }

    #[test]
    pub fn test_nbpf_complex() {
        unsafe {
            let filter = "(host 192.168.0.1 and port 3000) or (src host 10.0.0.1 and proto 17)";
            let filter = CString::new(filter).unwrap();
            let tree = nbpf_parse(filter.as_ptr() as *const c_char, None);
            let l4_src_port: u16 = 3000;
            let l4_dst_port: u16 = 345;

            let pkt_info = nbpf_pkt_info_t {
                device_id: 0,
                interface_id: 0,
                dmac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                smac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                vlan_id: 0,
                vlan_id_qinq: 0,
                master_l7_proto: 0,
                l7_proto: 7,
                tuple: nbpf_pkt_info_tuple_t {
                    eth_type: 0x0800,
                    ip_version: 4,
                    l3_proto: 17,
                    ip_tos: 0,
                    ip_src: nbpf_ip_addr { v4: 0x0100000A },
                    ip_dst: nbpf_ip_addr { v4: 0x0100A8C0 },
                    l4_src_port: l4_src_port.to_be(),
                    l4_dst_port: l4_dst_port.to_be(),
                },
                tunneled_tuple: nbpf_pkt_info_tuple_t {
                    eth_type: 0,
                    ip_version: 0,
                    l3_proto: 0,
                    ip_tos: 0,
                    ip_src: nbpf_ip_addr { v4: 0 },
                    ip_dst: nbpf_ip_addr { v4: 0 },
                    l4_src_port: 0,
                    l4_dst_port: 0,
                },
            };

            let matched = nbpf_match(
                tree as *const nbpf_tree_t,
                &pkt_info as *const nbpf_pkt_info_t,
            );

            assert_eq!(matched, 1);
            nbpf_free(tree);
        }
    }
}
