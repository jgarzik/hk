//! IPv4 Protocol Implementation
//!
//! This module handles IPv4 packet parsing, building, routing,
//! and checksum computation.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::fmt;

use crate::net::KernelError;
use crate::net::NetNamespace;
use crate::net::arp;
use crate::net::ethernet::{self, ETH_ALEN, EtherType};
use crate::net::inet::route::{self, IpInput};
use crate::net::skb::SkBuff;
use crate::net::tcp;
use crate::net::udp;

/// IP protocol numbers
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// IP header minimum length
pub const IP_HLEN_MIN: usize = 20;

/// IP header maximum length (with options)
pub const IP_HLEN_MAX: usize = 60;

/// Default TTL
pub const IP_DEFAULT_TTL: u8 = 64;

/// IPv4 address
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4Addr(pub u32);

impl Ipv4Addr {
    /// Create from octets
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32))
    }

    /// Create from big-endian bytes
    pub fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    /// Create from network byte order u32
    pub fn from_be(value: u32) -> Self {
        Self(u32::from_be(value))
    }

    /// Convert to network byte order bytes
    pub fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Convert to network byte order u32
    pub fn to_be(self) -> u32 {
        self.0.to_be()
    }

    /// Get as host byte order u32
    pub fn to_u32(self) -> u32 {
        self.0
    }

    /// Get octets
    pub fn octets(self) -> [u8; 4] {
        [
            (self.0 >> 24) as u8,
            (self.0 >> 16) as u8,
            (self.0 >> 8) as u8,
            self.0 as u8,
        ]
    }

    /// Check if this is a loopback address (127.0.0.0/8)
    pub fn is_loopback(self) -> bool {
        (self.0 >> 24) == 127
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(self) -> bool {
        self.0 == 0xFFFFFFFF
    }

    /// Check if this is a multicast address (224.0.0.0/4)
    pub fn is_multicast(self) -> bool {
        (self.0 >> 28) == 0x0E
    }

    /// Check if this is the any address (0.0.0.0)
    pub fn is_unspecified(self) -> bool {
        self.0 == 0
    }

    /// Apply netmask
    pub fn mask(self, netmask: Self) -> Self {
        Self(self.0 & netmask.0)
    }

    /// Broadcast address for a network
    pub fn broadcast(self, netmask: Self) -> Self {
        Self(self.0 | !netmask.0)
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.octets();
        write!(f, "{}.{}.{}.{}", o[0], o[1], o[2], o[3])
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::ops::BitAnd for Ipv4Addr {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// IPv4 header (without options)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv4Hdr {
    /// Version (4 bits) + IHL (4 bits)
    pub version_ihl: u8,
    /// Type of Service
    pub tos: u8,
    /// Total length (big-endian)
    pub tot_len: [u8; 2],
    /// Identification (big-endian)
    pub id: [u8; 2],
    /// Flags (3 bits) + Fragment offset (13 bits) (big-endian)
    pub frag_off: [u8; 2],
    /// Time to Live
    pub ttl: u8,
    /// Protocol
    pub protocol: u8,
    /// Header checksum (big-endian)
    pub check: [u8; 2],
    /// Source address (big-endian)
    pub saddr: [u8; 4],
    /// Destination address (big-endian)
    pub daddr: [u8; 4],
}

impl Ipv4Hdr {
    /// Get IP version (should be 4)
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Get header length in bytes
    pub fn ihl(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    /// Get total packet length
    pub fn tot_len(&self) -> u16 {
        u16::from_be_bytes(self.tot_len)
    }

    /// Get fragment flags
    pub fn flags(&self) -> u8 {
        (self.frag_off[0] >> 5) & 0x07
    }

    /// Get fragment offset
    pub fn frag_offset(&self) -> u16 {
        u16::from_be_bytes([self.frag_off[0] & 0x1F, self.frag_off[1]]) * 8
    }

    /// Check if packet is fragmented
    pub fn is_fragment(&self) -> bool {
        // More Fragments flag set or fragment offset > 0
        (self.frag_off[0] & 0x20 != 0) || self.frag_offset() > 0
    }

    /// Get source address
    pub fn saddr(&self) -> Ipv4Addr {
        Ipv4Addr::from_be_bytes(self.saddr)
    }

    /// Get destination address
    pub fn daddr(&self) -> Ipv4Addr {
        Ipv4Addr::from_be_bytes(self.daddr)
    }

    /// Get checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }
}

/// Global IP ID counter for fragmentation
static IP_ID: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(1);

/// Get next IP ID
fn next_ip_id() -> u16 {
    IP_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Compute IP checksum
///
/// The checksum is the 16-bit one's complement of the one's complement
/// sum of all 16-bit words in the header.
pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Add odd byte if present
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take one's complement
    !(sum as u16)
}

/// Verify IP header checksum
pub fn ip_check_checksum(hdr: &[u8]) -> bool {
    ip_checksum(hdr) == 0
}

/// Compute TCP/UDP pseudo-header checksum
///
/// Used for TCP and UDP checksum computation.
pub fn pseudo_header_checksum(saddr: Ipv4Addr, daddr: Ipv4Addr, protocol: u8, len: u16) -> u32 {
    let mut sum: u32 = 0;

    // Source address
    let s = saddr.to_be_bytes();
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;

    // Destination address
    let d = daddr.to_be_bytes();
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;

    // Protocol
    sum += protocol as u32;

    // Length
    sum += len as u32;

    sum
}

/// Receive an IP packet (EtherType 0x0800 handler; thread context)
///
/// `skb.data()` starts at the IP header (eth_type_trans pulled the MAC
/// header). The packet's namespace is its device's.
pub fn ip_rcv(mut skb: SkBuff) {
    if skb.len() < IP_HLEN_MIN {
        return;
    }

    // Parse IP header
    let hdr = unsafe { &*(skb.data().as_ptr() as *const Ipv4Hdr) };

    // Validate version
    if hdr.version() != 4 {
        return;
    }

    // Validate header length
    let ihl = hdr.ihl();
    if ihl < IP_HLEN_MIN || ihl > skb.len() {
        return;
    }

    // Verify checksum
    if !ip_check_checksum(&skb.data()[..ihl]) {
        return;
    }

    // Validate total length
    let tot_len = hdr.tot_len() as usize;
    if tot_len < ihl || tot_len > skb.len() {
        return;
    }

    // Trim any padding
    if tot_len < skb.len() {
        skb.trim(skb.len() - tot_len);
    }

    // We don't support fragmentation yet
    if hdr.is_fragment() {
        return;
    }

    // Input route (Linux ip_route_input_slow): local delivery only, no
    // forwarding; martians and frames for other hosts are dropped
    let Some(dev) = skb.dev.clone() else {
        return;
    };
    let Some(net) = dev.net() else {
        return;
    };
    match route::input(&net, hdr.saddr(), hdr.daddr(), &dev) {
        IpInput::Local => skb.ip_bcast = false,
        IpInput::Broadcast => skb.ip_bcast = true,
        IpInput::Drop(_) => return,
    }

    // Store protocol info in skb
    skb.ip_protocol = hdr.protocol;
    skb.ip_ttl = hdr.ttl;
    skb.ip_tos = hdr.tos;
    skb.saddr = Some(hdr.saddr());
    skb.daddr = Some(hdr.daddr());

    // Set transport header offset
    skb.set_transport_header(ihl);

    // Skip IP header and dispatch to transport layer
    if skb.pull(ihl).is_none() {
        return;
    }

    match hdr.protocol {
        IPPROTO_TCP => tcp::tcp_rcv(skb),
        IPPROTO_UDP => udp::udp_rcv(skb),
        IPPROTO_ICMP => crate::net::icmp::icmp_rcv(skb),
        _ => {
            // Unknown protocol, drop
        }
    }
}

/// Queue a packet for transmission in namespace `net` with default
/// TOS/TTL: routes `skb.daddr` from `skb.saddr` (0 = the route's
/// source), then `ip_send_rt`
pub fn ip_queue_xmit(
    net: &NetNamespace,
    skb: Box<SkBuff>,
    protocol: u8,
) -> Result<(), KernelError> {
    let daddr = skb.daddr.ok_or(KernelError::InvalidArgument)?;
    let src = skb.saddr.unwrap_or_default();
    let rt = route::output(net, daddr, src, 0)?;
    ip_send_rt(net, &rt, skb, protocol, IpParams::default())
}

/// Per-packet IP header parameters (Linux ipcm_cookie subset)
#[derive(Clone, Copy, Debug)]
pub struct IpParams {
    pub tos: u8,
    pub ttl: u8,
}

impl Default for IpParams {
    fn default() -> Self {
        Self {
            tos: 0,
            ttl: IP_DEFAULT_TTL,
        }
    }
}

/// Build the IP header for `skb` (source `skb.saddr`, else the route's)
/// and send it along `rt` (`lo` for local destinations; ARP for the next
/// hop otherwise). EMSGSIZE above the device MTU (DF; no fragmentation
/// yet). Never delivers synchronously: `lo` queues to the receive
/// backlog. Callers may hold a socket lock (lock order: socket -> FIB
/// -> ARP -> device TX).
pub fn ip_send_rt(
    net: &NetNamespace,
    rt: &route::Rtable,
    mut skb: Box<SkBuff>,
    protocol: u8,
    p: IpParams,
) -> Result<(), KernelError> {
    let src = skb.saddr.unwrap_or_default();
    let saddr = if src.is_unspecified() { rt.saddr } else { src };
    let daddr = rt.daddr;
    let dev = rt.dev.clone();
    let next_hop = rt.nexthop();
    let tot_len = IP_HLEN_MIN + skb.len();
    if tot_len > dev.mtu() as usize || tot_len > u16::MAX as usize {
        return Err(KernelError::MessageTooLong);
    }
    let ip_hdr = skb.push(IP_HLEN_MIN).ok_or(KernelError::NoBufferSpace)?;
    ip_hdr[0] = 0x45;
    ip_hdr[1] = p.tos;
    ip_hdr[2..4].copy_from_slice(&(tot_len as u16).to_be_bytes());
    ip_hdr[4..6].copy_from_slice(&next_ip_id().to_be_bytes());
    // Don't Fragment
    ip_hdr[6] = 0x40;
    ip_hdr[7] = 0;
    ip_hdr[8] = p.ttl;
    ip_hdr[9] = protocol;
    ip_hdr[10] = 0;
    ip_hdr[11] = 0;
    ip_hdr[12..16].copy_from_slice(&saddr.to_be_bytes());
    ip_hdr[16..20].copy_from_slice(&daddr.to_be_bytes());
    let checksum = ip_checksum(&ip_hdr[..IP_HLEN_MIN]);
    ip_hdr[10..12].copy_from_slice(&checksum.to_be_bytes());
    skb.dev = Some(Arc::clone(&dev));

    // Loopback has no link-layer resolution (Linux: NUD_NOARP neighbour)
    if dev.is_loopback() {
        return ip_finish_output(skb, dev.mac());
    }
    if rt.rtype == crate::net::inet::fib::RouteType::Broadcast {
        return ip_finish_output(skb, ethernet::ETH_BROADCAST);
    }
    arp::arp_resolve(net, &dev, next_hop, skb)
}

/// Build IP header and transmit (called by ARP when resolution completes)
pub fn ip_finish_output(mut skb: Box<SkBuff>, dest_mac: [u8; ETH_ALEN]) -> Result<(), KernelError> {
    let dev = skb.dev.as_ref().ok_or(KernelError::NoDevice)?;
    let source_mac = dev.mac();

    // Build Ethernet header
    ethernet::eth_header(&mut skb, &dest_mac, &source_mac, EtherType::Ipv4)
        .ok_or(KernelError::NoBufferSpace)?;

    // Transmit
    crate::net::dev::dev_queue_xmit(skb)
}
