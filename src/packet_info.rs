use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::util::MacAddr;

use crate::{nbpf_pkt_info_t, nbpf_pkt_info_tuple_t};

pub enum IPversion {
    IPv4,
    IPv6,
}

impl Default for IPversion {
    fn default() -> Self {
        Self::IPv4
    }
}

impl From<IPversion> for u8 {
    fn from(value: IPversion) -> Self {
        match value {
            IPversion::IPv4 => 4,
            IPversion::IPv6 => 6,
        }
    }
}

#[derive(Default)]
pub struct PacketInfoBuilder {
    /// L2
    device_id: Option<u16>,
    interface_id: Option<u16>,
    dmac: Option<MacAddr>,
    smac: Option<MacAddr>,
    vlan_id: Option<u16>,
    vlan_id_qinq: Option<u16>,
    l3_eth_type: Option<u16>,
    /// L3
    l3_ip_version: Option<IPversion>,
    l3_proto: Option<u8>,
    l3_ip_tos: Option<u8>,
    l3_ip_src: Option<IpAddr>,
    l3_ip_dst: Option<IpAddr>,
    /// l4
    l4_src_port: Option<u16>,
    l4_dst_port: Option<u16>,

    /// tunnel
    tunnel_eth_type: Option<u16>,
    tunnel_ip_version: Option<IPversion>,
    tunnel_l3_proto: Option<u8>,
    tunnel_ip_tos: Option<u8>,
    tunnel_ip_src: Option<IpAddr>,
    tunnel_ip_dst: Option<IpAddr>,
    tunnel_l4_src_port: Option<u16>,
    tunnel_l4_dst_port: Option<u16>,

    /// l7
    master_l7_proto: Option<u16>,
    l7_proto: Option<u16>,
}

impl PacketInfoBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_device_id(&mut self, device_id: u16) {
        self.device_id = Some(device_id);
    }

    /// l2
    pub fn with_l2(&mut self, interface_id: u16, smac: MacAddr, dmac: MacAddr, eth_type: u16) {
        self.interface_id = Some(interface_id);
        self.smac = Some(smac);
        self.dmac = Some(dmac);
        self.l3_eth_type = Some(eth_type);
    }

    /// vlan
    pub fn with_l2_vlan(&mut self, vlan_id: u16, vlan_id_qinq: u16) {
        self.vlan_id = Some(vlan_id);
        self.vlan_id_qinq = Some(vlan_id_qinq);
    }

    pub fn with_tunnel_l2(&mut self, eth_type: u16) {
        self.tunnel_eth_type = Some(eth_type);
    }

    /// l3
    pub fn with_l3(&mut self, ip_version: IPversion, proto: u8, tos: u8, src: IpAddr, dst: IpAddr) {
        self.l3_ip_version = Some(ip_version);
        self.l3_proto = Some(proto);
        self.l3_ip_tos = Some(tos);
        self.l3_ip_src = Some(src);
        self.l3_ip_dst = Some(dst);
    }

    pub fn with_tunnel_l3(
        &mut self,
        ip_version: IPversion,
        proto: u8,
        tos: u8,
        src: IpAddr,
        dst: IpAddr,
    ) {
        self.tunnel_ip_version = Some(ip_version);
        self.tunnel_l3_proto = Some(proto);
        self.tunnel_ip_tos = Some(tos);
        self.tunnel_ip_src = Some(src);
        self.tunnel_ip_dst = Some(dst);
    }

    /// l4
    pub fn with_l4(&mut self, src_port: u16, dst_port: u16) {
        self.l4_src_port = Some(src_port);
        self.l4_dst_port = Some(dst_port);
    }

    pub fn with_tunnel_l4(&mut self, src_port: u16, dst_port: u16) {
        self.tunnel_l4_src_port = Some(src_port);
        self.tunnel_l4_dst_port = Some(dst_port);
    }

    /// l7
    pub fn with_l7_master_proto(&mut self, master_l7_proto: u16) {
        self.master_l7_proto = Some(master_l7_proto);
    }

    pub fn with_l7_proto(&mut self, l7_proto: u16) {
        self.l7_proto = Some(l7_proto);
    }

    pub fn build(self) -> PacketInfo {
        let nbpf_pkt_info = Box::new(nbpf_pkt_info_t {
            device_id: self.device_id.unwrap_or_default(),
            interface_id: self.interface_id.unwrap_or_default(),
            dmac: self.dmac.unwrap_or_default().into(),
            smac: self.smac.unwrap_or_default().into(),
            vlan_id: self.vlan_id.unwrap_or(0),
            vlan_id_qinq: self.vlan_id_qinq.unwrap_or(0),
            tuple: nbpf_pkt_info_tuple_t {
                eth_type: self.l3_eth_type.unwrap_or(0),
                ip_version: self.l3_ip_version.unwrap_or_default().into(),
                l3_proto: self.l3_proto.unwrap_or_default(),
                ip_tos: self.l3_ip_tos.unwrap_or_default(),
                ip_src: self
                    .l3_ip_src
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
                    .into(),
                ip_dst: self
                    .l3_ip_dst
                    .unwrap_or(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)))
                    .into(),
                l4_src_port: self.l4_src_port.unwrap_or_default(),
                l4_dst_port: self.l4_dst_port.unwrap_or_default(),
            },
            tunneled_tuple: nbpf_pkt_info_tuple_t {
                eth_type: self.tunnel_eth_type.unwrap_or_default(),
                ip_version: self.tunnel_ip_version.unwrap_or_default().into(),
                l3_proto: self.tunnel_l3_proto.unwrap_or_default(),
                ip_tos: self.tunnel_ip_tos.unwrap_or_default(),
                ip_src: self
                    .tunnel_ip_src
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
                    .into(),
                ip_dst: self
                    .tunnel_ip_dst
                    .unwrap_or(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)))
                    .into(),
                l4_src_port: self.tunnel_l4_src_port.unwrap_or_default(),
                l4_dst_port: self.tunnel_l4_dst_port.unwrap_or_default(),
            },
            master_l7_proto: self.master_l7_proto.unwrap_or_default(),
            l7_proto: self.l7_proto.unwrap_or_default(),
        });

        PacketInfo {
            ptr: Box::into_raw(nbpf_pkt_info),
        }
    }
}

pub struct PacketInfo {
    ptr: *mut nbpf_pkt_info_t,
}

impl PacketInfo {
    pub(crate) fn get_ptr(&self) -> *mut nbpf_pkt_info_t {
        self.ptr
    }
}

impl Drop for PacketInfo {
    fn drop(&mut self) {
        drop(unsafe { Box::from_raw(self.ptr) })
    }
}
