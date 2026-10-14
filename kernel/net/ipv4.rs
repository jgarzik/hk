//! IPv4 Protocol Implementation
//!
//! This module handles IPv4 packet parsing, building, routing,
//! and checksum computation.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::net::KernelError;
use crate::net::NetNamespace;
use crate::net::arp;
use crate::net::ethernet::{self, ETH_ALEN, EtherType};
use crate::net::inet::frag::Defrag;
use crate::net::inet::route::{self, IpInput};
use crate::net::skb::{NET_SKB_PAD, SkBuff};
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

/// Identification buckets (Linux ip_idents / ip_tstamps)
const IDENTS: usize = 2048;
static IP_IDENTS: [AtomicU32; IDENTS] = [const { AtomicU32::new(0) }; IDENTS];
static IP_TSTAMPS: [AtomicU32; IDENTS] = [const { AtomicU32::new(0) }; IDENTS];

/// Reserve `segs` ids from bucket `hash`, jumping by a random amount
/// that grows with the time since the bucket was last used, so ids do
/// not leak traffic counts (Linux ip_idents_reserve)
fn idents_reserve(hash: u32, segs: u32) -> u32 {
    let b = hash as usize & (IDENTS - 1);
    let now = crate::time::current_ticks() as u32;
    let old = IP_TSTAMPS[b].load(Ordering::Relaxed);
    let mut delta = 0;
    if old != now
        && IP_TSTAMPS[b]
            .compare_exchange(old, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        delta = crate::random::get_random_u32() % now.wrapping_sub(old).max(1);
    }
    IP_IDENTS[b]
        .fetch_add(segs + delta, Ordering::Relaxed)
        .wrapping_add(delta)
}

/// IP id for a datagram without a connected socket's counter (Linux
/// __ip_select_ident: per-destination bucket chosen by a keyed hash)
pub fn select_ident(net: &NetNamespace, saddr: Ipv4Addr, daddr: Ipv4Addr, proto: u8) -> u16 {
    let h = crate::net::inet::port::siphash(
        net.ip_id_key,
        &[((daddr.0 as u64) << 32) | saddr.0 as u64, proto as u64],
    );
    idents_reserve(h as u32, 1) as u16
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
    let Some(ihl) = ip_check(&mut skb) else {
        return;
    };
    let Some(dev) = skb.dev.clone() else {
        return;
    };
    let Some(net) = dev.net() else {
        return;
    };
    let (saddr, daddr) = {
        let h = skb.data();
        (
            Ipv4Addr::from_be_bytes([h[12], h[13], h[14], h[15]]),
            Ipv4Addr::from_be_bytes([h[16], h[17], h[18], h[19]]),
        )
    };
    // Input route (Linux ip_route_input_slow): local delivery only, no
    // forwarding; martians and frames for other hosts are dropped
    skb.ip_bcast = match route::input(&net, saddr, daddr, &dev) {
        IpInput::Local => false,
        IpInput::Broadcast => true,
        IpInput::Drop(_) => return,
    };
    if !ip_options_ok(&skb.data()[IP_HLEN_MIN..ihl]) {
        return;
    }
    let fo = u16::from_be_bytes([skb.data()[6], skb.data()[7]]);
    if fo & 0x3fff == 0 {
        return ip_local_deliver(skb);
    }
    // Linux ip_local_deliver -> ip_defrag
    if let Defrag::Whole(pkt) = net.frags.add(&net, skb.data())
        && let Some(whole) = rebuild(&skb, &pkt)
    {
        ip_local_deliver(whole);
    }
}

/// Header validation (Linux ip_rcv_core): version, header length,
/// checksum, total length; trims link-layer padding. Returns the
/// header length.
fn ip_check(skb: &mut SkBuff) -> Option<usize> {
    let h = skb.data();
    if h.len() < IP_HLEN_MIN || h[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((h[0] & 0x0f) as usize) * 4;
    if ihl < IP_HLEN_MIN || ihl > h.len() || !ip_check_checksum(&h[..ihl]) {
        return None;
    }
    let tot = u16::from_be_bytes([h[2], h[3]]) as usize;
    if tot < ihl || tot > h.len() {
        return None;
    }
    let pad = h.len() - tot;
    skb.trim(pad)?;
    Some(ihl)
}

/// IP option types
const IPOPT_END: u8 = 0;
const IPOPT_NOOP: u8 = 1;
const IPOPT_LSRR: u8 = 131;
const IPOPT_SSRR: u8 = 137;

/// Options are skipped, but must be well formed, and source-routed
/// packets are dropped (Linux ip_options_compile + accept_source_route
/// = 0)
pub fn ip_options_ok(opt: &[u8]) -> bool {
    let mut i = 0;
    while i < opt.len() {
        match opt[i] {
            IPOPT_END => return true,
            IPOPT_NOOP => i += 1,
            t => {
                let Some(&l) = opt.get(i + 1) else {
                    return false;
                };
                let l = l as usize;
                if l < 2 || i + l > opt.len() || t == IPOPT_LSRR || t == IPOPT_SSRR {
                    return false;
                }
                i += l;
            }
        }
    }
    true
}

/// A reassembled datagram as a received skb (device and link-layer
/// classification of its last fragment)
fn rebuild(last: &SkBuff, pkt: &[u8]) -> Option<SkBuff> {
    let mut s = SkBuff::alloc(NET_SKB_PAD, pkt.len())?;
    s.put_slice(pkt)?;
    s.dev = last.dev.clone();
    s.pkt_type = last.pkt_type;
    s.ip_bcast = last.ip_bcast;
    Some(*s)
}

/// Deliver a whole datagram for us to its protocol (Linux
/// ip_local_deliver_finish)
fn ip_local_deliver(mut skb: SkBuff) {
    let mut h = [0u8; IP_HLEN_MIN];
    h.copy_from_slice(&skb.data()[..IP_HLEN_MIN]);
    let ihl = ((h[0] & 0x0f) as usize) * 4;
    let proto = h[9];
    skb.ip_protocol = proto;
    skb.ip_tos = h[1];
    skb.ip_ttl = h[8];
    skb.saddr = Some(Ipv4Addr::from_be_bytes([h[12], h[13], h[14], h[15]]));
    skb.daddr = Some(Ipv4Addr::from_be_bytes([h[16], h[17], h[18], h[19]]));
    skb.mark_network_header();
    if skb.pull(ihl).is_none() {
        return;
    }
    match proto {
        IPPROTO_TCP => tcp::tcp_rcv(skb),
        IPPROTO_UDP => udp::udp_rcv(skb),
        IPPROTO_ICMP => crate::net::icmp::icmp_rcv(skb),
        _ => {
            if let Some(net) = skb.net() {
                crate::net::icmp::prot_unreach(&net, &skb);
            }
        }
    }
}

/// Transmit a packet from `skb.saddr` (0 = the route's source) to
/// `skb.daddr` in namespace `net` (Linux ip_queue_xmit without the
/// socket's cached route)
pub fn ip_queue_xmit(
    net: &NetNamespace,
    skb: Box<SkBuff>,
    protocol: u8,
    p: IpParams,
) -> Result<(), KernelError> {
    let daddr = skb.daddr.ok_or(KernelError::InvalidArgument)?;
    let src = skb.saddr.unwrap_or_default();
    let rt = route::output(net, daddr, src, 0)?;
    ip_send_rt(net, &rt, skb, protocol, p)
}

/// Path MTU discovery modes (IP_MTU_DISCOVER values)
pub mod pmtu {
    pub const DONT: u8 = 0;
    pub const WANT: u8 = 1;
    pub const DO: u8 = 2;
    pub const PROBE: u8 = 3;
    pub const INTERFACE: u8 = 4;
    pub const OMIT: u8 = 5;
}

/// Per-packet IP header parameters (Linux ipcm_cookie + inet_sock bits)
#[derive(Clone, Copy, Debug)]
pub struct IpParams {
    pub tos: u8,
    pub ttl: u8,
    /// IP_MTU_DISCOVER mode (`pmtu::*`)
    pub pmtudisc: u8,
    /// Identification from a connected socket's counter (Linux
    /// inet_id); None = DF packets get 0, others a hashed id
    pub id: Option<u16>,
}

impl Default for IpParams {
    fn default() -> Self {
        Self {
            tos: 0,
            ttl: IP_DEFAULT_TTL,
            pmtudisc: pmtu::WANT,
            id: None,
        }
    }
}

impl IpParams {
    /// MTU the packet is sized against (Linux ip_sk_use_pmtu: PROBE,
    /// INTERFACE and OMIT ignore the learned path MTU)
    fn mtu(&self, rt: &route::Rtable) -> usize {
        if self.pmtudisc < pmtu::PROBE {
            rt.mtu as usize
        } else {
            rt.dev.mtu() as usize
        }
    }

    /// Larger datagrams may be fragmented (Linux ip_sk_ignore_df)
    fn may_frag(&self) -> bool {
        self.pmtudisc < pmtu::DO || self.pmtudisc == pmtu::OMIT
    }

    /// DF on a packet that fits (Linux __ip_make_skb)
    fn df(&self) -> bool {
        matches!(self.pmtudisc, pmtu::WANT | pmtu::DO | pmtu::PROBE)
    }
}

/// Build the IP header for `skb` (source `skb.saddr`, else the route's)
/// and send it along `rt`, fragmenting a datagram larger than the MTU
/// when the socket's PMTU mode allows (else EMSGSIZE). Never delivers
/// synchronously: `lo` queues to the receive backlog. Callers may hold a
/// socket lock (lock order: socket -> FIB -> neighbour -> device TX).
pub fn ip_send_rt(
    net: &NetNamespace,
    rt: &route::Rtable,
    mut skb: Box<SkBuff>,
    protocol: u8,
    p: IpParams,
) -> Result<(), KernelError> {
    let src = skb.saddr.unwrap_or_default();
    let saddr = if src.is_unspecified() { rt.saddr } else { src };
    let tot_len = IP_HLEN_MIN + skb.len();
    let mtu = p.mtu(rt);
    let frag = tot_len > mtu;
    if tot_len > u16::MAX as usize || (frag && !p.may_frag()) {
        return Err(KernelError::MessageTooLong);
    }
    let df = !frag && p.df();
    let id = match p.id {
        Some(id) => id,
        None if df => 0,
        None => select_ident(net, saddr, rt.daddr, protocol),
    };
    let h = skb.push(IP_HLEN_MIN).ok_or(KernelError::NoBufferSpace)?;
    h[0] = 0x45;
    h[1] = p.tos;
    h[2..4].copy_from_slice(&(tot_len as u16).to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h[6] = if df { 0x40 } else { 0 };
    h[7] = 0;
    h[8] = p.ttl;
    h[9] = protocol;
    h[10] = 0;
    h[11] = 0;
    h[12..16].copy_from_slice(&saddr.to_be_bytes());
    h[16..20].copy_from_slice(&rt.daddr.to_be_bytes());
    let c = ip_checksum(&h[..IP_HLEN_MIN]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    ip_output(net, rt, skb, saddr, mtu)
}

/// Send a packet with a complete IP header along `rt`, fragmenting it
/// to `mtu` if needed (Linux ip_finish_output -> ip_fragment)
pub fn ip_output(
    net: &NetNamespace,
    rt: &route::Rtable,
    mut skb: Box<SkBuff>,
    saddr: Ipv4Addr,
    mtu: usize,
) -> Result<(), KernelError> {
    skb.dev = Some(Arc::clone(&rt.dev));
    skb.saddr = Some(saddr);
    skb.daddr = Some(rt.daddr);
    if skb.len() <= mtu {
        return neigh_output(net, &rt.dev, rt, rt.nexthop(), skb);
    }
    for f in fragment(&skb, mtu)? {
        neigh_output(net, &rt.dev, rt, rt.nexthop(), f)?;
    }
    Ok(())
}

/// Split an IP packet (no options are ever generated, so every fragment
/// repeats the header) into fragments of at most `mtu` bytes (Linux
/// ip_do_fragment slow path)
pub fn fragment(skb: &SkBuff, mtu: usize) -> Result<Vec<Box<SkBuff>>, KernelError> {
    let pkt = skb.data();
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let room = (mtu.saturating_sub(ihl)) & !7;
    if room == 0 {
        return Err(KernelError::MessageTooLong);
    }
    let payload = &pkt[ihl..];
    let mut out = Vec::new();
    let mut off = 0;
    while off < payload.len() {
        let len = room.min(payload.len() - off);
        let more = off + len < payload.len();
        let mut f = SkBuff::alloc_tx(ihl + len).ok_or(KernelError::NoBufferSpace)?;
        f.put_slice(&pkt[..ihl]).ok_or(KernelError::NoBufferSpace)?;
        f.put_slice(&payload[off..off + len])
            .ok_or(KernelError::NoBufferSpace)?;
        let h = f.data_mut();
        h[2..4].copy_from_slice(&((ihl + len) as u16).to_be_bytes());
        let fo = (off / 8) as u16 | if more { 0x2000 } else { 0 };
        h[6..8].copy_from_slice(&fo.to_be_bytes());
        h[10] = 0;
        h[11] = 0;
        let c = ip_checksum(&h[..ihl]);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        f.dev = skb.dev.clone();
        f.saddr = skb.saddr;
        f.daddr = skb.daddr;
        out.push(f);
        off += len;
    }
    Ok(out)
}

/// Link-layer destination of a routed packet (Linux ip_finish_output2:
/// NOARP devices and broadcast/multicast map directly, unicast next hops
/// go through the ARP table)
fn neigh_output(
    net: &NetNamespace,
    dev: &Arc<crate::net::NetDevice>,
    rt: &route::Rtable,
    next_hop: Ipv4Addr,
    skb: Box<SkBuff>,
) -> Result<(), KernelError> {
    use crate::net::device::flags::IFF_NOARP;
    use crate::net::inet::fib::RouteType;
    if dev.is_loopback() || dev.get_flags() & IFF_NOARP != 0 {
        return ip_finish_output(skb, dev.mac());
    }
    match rt.rtype {
        RouteType::Broadcast => ip_finish_output(skb, ethernet::ETH_BROADCAST),
        RouteType::Multicast => ip_finish_output(skb, mc_map(rt.daddr)),
        _ => arp::output(net, dev, next_hop, skb),
    }
}

/// Ethernet address of an IPv4 multicast group (Linux ip_eth_mc_map)
fn mc_map(a: Ipv4Addr) -> [u8; ETH_ALEN] {
    let o = a.octets();
    [0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]]
}

/// A queued packet's next hop never answered (Linux ipv4_link_failure
/// via arp_error_report): tell its sender
pub fn ip_link_failure(skb: Box<SkBuff>) {
    crate::net::icmp::link_failure(&skb);
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
