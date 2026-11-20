//! IPv4 Protocol Implementation
//!
//! This module handles IPv4 packet parsing, building, routing,
//! and checksum computation.

use crate::mm::page_alloc::Gfp;
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
use crate::net::mib::*;
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
    // ids are a free-running 32-bit space (Linux ip_idents_reserve's
    // atomic_add_return wraps)
    IP_IDENTS[b]
        .fetch_add(segs.wrapping_add(delta), Ordering::Relaxed)
        .wrapping_add(delta)
}

/// IP id for a datagram without a connected socket's counter (Linux
/// __ip_select_ident: per-destination bucket chosen by a keyed hash)
pub fn select_ident(net: &NetNamespace, saddr: Ipv4Addr, daddr: Ipv4Addr, proto: u8) -> u16 {
    let h = crate::net::inet::port::siphash(
        net.ip_id_key,
        &[
            (u64::from(daddr.0) << 32) | u64::from(saddr.0),
            u64::from(proto),
        ],
    );
    idents_reserve(h as u32, 1) as u16
}

/// Compute IP checksum
///
/// The checksum is the 16-bit one's complement of the one's complement
/// sum of all 16-bit words in the header.
pub fn ip_checksum(data: &[u8]) -> u16 {
    // 64 bits: no slice is long enough to carry out of it (a u32 would
    // overflow past 128KiB of 0xffff words)
    let mut sum: u64 = 0;

    // Sum all 16-bit words
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u64::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }

    // Add odd byte if present
    if i < data.len() {
        sum += u64::from(data[i]) << 8;
    }

    // Fold to 16 bits
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
    sum += u32::from(u16::from_be_bytes([s[0], s[1]]));
    sum += u32::from(u16::from_be_bytes([s[2], s[3]]));

    // Destination address
    let d = daddr.to_be_bytes();
    sum += u32::from(u16::from_be_bytes([d[0], d[1]]));
    sum += u32::from(u16::from_be_bytes([d[2], d[3]]));

    // Protocol
    sum += u32::from(protocol);

    // Length
    sum += u32::from(len);

    sum
}

/// Receive an IP packet (EtherType 0x0800 handler; thread context)
///
/// `skb.data()` starts at the IP header (eth_type_trans pulled the MAC
/// header). The packet's namespace is its device's.
pub fn ip_rcv(mut skb: Box<SkBuff>) {
    let Some(dev) = skb.dev.clone() else {
        return;
    };
    let Some(net) = dev.net() else {
        return;
    };
    let Some(ihl) = ip_rcv_core(&net, &mut skb) else {
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
        IpInput::HostUnreach => {
            // Linux ip_error on a host that does not forward
            net.mib.ip.inc(IPSTATS_MIB_INADDRERRORS);
            return;
        }
        IpInput::Drop(_) => return,
    };
    if skb.ip_bcast {
        // Linux ip_rcv_finish_core: RTN_BROADCAST input
        net.mib.ip.upd_po(
            IPSTATS_MIB_INBCASTPKTS,
            IPSTATS_MIB_INBCASTOCTETS,
            skb.len(),
        );
    }
    if ihl > IP_HLEN_MIN && !ip_rcv_options(&net, &dev, &mut skb, ihl) {
        return;
    }
    let fo = u16::from_be_bytes([skb.data()[6], skb.data()[7]]);
    if fo & 0x3fff == 0 {
        return ip_local_deliver(skb);
    }
    // Linux ip_local_deliver -> ip_defrag
    if let Defrag::Whole(whole) = net.frags.add(&net, skb) {
        net.mib.ip.inc(IPSTATS_MIB_REASMOKS);
        ip_local_deliver(whole);
    }
}

/// Header validation (Linux ip_rcv_core): version, header length,
/// checksum, total length, counted as Linux does; trims link-layer
/// padding. Returns the header length.
fn ip_rcv_core(net: &NetNamespace, skb: &mut SkBuff) -> Option<usize> {
    let ip = &net.mib.ip;
    ip.upd_po(IPSTATS_MIB_INPKTS, IPSTATS_MIB_INOCTETS, skb.len());
    let h = skb.data();
    if h.len() < IP_HLEN_MIN || h[0] >> 4 != 4 || h[0] & 0x0f < 5 {
        ip.inc(IPSTATS_MIB_INHDRERRORS);
        return None;
    }
    // Linux: InNoECTPkts + the ECN field
    ip.inc(IPSTATS_MIB_NOECTPKTS + usize::from(h[1] & 3));
    let ihl = ((h[0] & 0x0f) as usize) * 4;
    if ihl > h.len() {
        ip.inc(IPSTATS_MIB_INHDRERRORS);
        return None;
    }
    if !ip_check_checksum(&h[..ihl]) {
        ip.inc(IPSTATS_MIB_CSUMERRORS);
        ip.inc(IPSTATS_MIB_INHDRERRORS);
        return None;
    }
    let tot = u16::from_be_bytes([h[2], h[3]]) as usize;
    if tot > h.len() {
        ip.inc(IPSTATS_MIB_INTRUNCATEDPKTS);
        return None;
    }
    if tot < ihl {
        ip.inc(IPSTATS_MIB_INHDRERRORS);
        return None;
    }
    let pad = h.len() - tot;
    if skb.trim(pad).is_none() {
        ip.inc(IPSTATS_MIB_INDISCARDS);
        return None;
    }
    Some(ihl)
}

/// A received header's options (Linux ip_rcv_options): compiled, our
/// record route and timestamp slots filled (the checksum redone); a
/// malformed set is answered with a parameter problem and dropped
/// (InHdrErrors). A source-routed packet is dropped unless both "all"
/// and its device accept source routes (IN_DEV_SOURCE_ROUTE) and its
/// route is spent: hk does not forward, so one with hops left is
/// dropped (Linux ip_options_rcv_srr routes it on). Whether to go on.
fn ip_rcv_options(
    net: &NetNamespace,
    dev: &crate::net::NetDevice,
    skb: &mut SkBuff,
    ihl: usize,
) -> bool {
    use crate::net::inet::devconf::ci;
    use crate::net::inet::options;
    let h = skb.data();
    let saddr = Ipv4Addr::from_be_bytes([h[12], h[13], h[14], h[15]]);
    let daddr = Ipv4Addr::from_be_bytes([h[16], h[17], h[18], h[19]]);
    // Linux fib_compute_spec_dst: the address the packet was for, or
    // ours facing the sender
    let spec = || {
        if net.fib.addr_type(daddr) == crate::net::inet::fib::RouteType::Local {
            daddr
        } else {
            crate::net::inet::ifaddr::inet_select_addr(
                net,
                dev,
                saddr,
                crate::net::inet::ifaddr::RT_SCOPE_UNIVERSE,
            )
            .unwrap_or_default()
        }
    };
    let at = |a| net.fib.addr_type(a);
    let rcv = options::Rcv { spec_dst: &spec };
    let m = match options::compile(&mut skb.data_mut()[..ihl], &rcv, &at) {
        Ok(m) => m,
        Err(pp) => {
            net.mib.ip.inc(IPSTATS_MIB_INHDRERRORS);
            skb.mark_network_header();
            if let Some(o) = crate::net::icmp::Offender::of(skb) {
                let info = (u32::from(pp) << 24).to_be_bytes();
                let ty = crate::net::icmp::icmp_type::PARAMETERPROB;
                crate::net::icmp::icmp_send(net, &o, ty, 0, info);
            }
            return false;
        }
    };
    if m.is_changed {
        let h = skb.data_mut();
        h[10] = 0;
        h[11] = 0;
        let c = ip_checksum(&h[..ihl]);
        h[10..12].copy_from_slice(&c.to_be_bytes());
    }
    skb.ip_opt = m;
    if m.srr != 0 {
        let all = net.devconf_all.get(ci::ACCEPT_SOURCE_ROUTE) != 0;
        let mine = dev.in_dev().cnf.get(ci::ACCEPT_SOURCE_ROUTE) != 0;
        let s = usize::from(m.srr);
        let h = skb.data();
        // Linux ip_options_rcv_srr: unicast to us only; a spent route
        // (pointer past its length) is delivered here
        let spent = usize::from(h[s + 2]) > usize::from(h[s + 1]);
        if !(all && mine) || skb.pkt_type != crate::net::ethernet::PktType::Host || !spent {
            return false;
        }
    }
    true
}

/// Deliver a whole datagram for us to its protocol (Linux
/// ip_local_deliver_finish)
fn ip_local_deliver(mut skb: Box<SkBuff>) {
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
    let Some(net) = skb.net() else {
        return;
    };
    let raw = crate::net::raw::raw_deliver(&net, &skb);
    // Linux ip_protocol_deliver_rcu: InDelivers for a protocol handler
    // or raw socket that took it, else InUnknownProtos
    let known = matches!(proto, IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMP);
    if known || raw {
        net.mib.ip.inc(IPSTATS_MIB_INDELIVERS);
    }
    match proto {
        IPPROTO_TCP => tcp::tcp_rcv(skb),
        IPPROTO_UDP => udp::udp_rcv(*skb),
        IPPROTO_ICMP => crate::net::icmp::icmp_rcv(*skb),
        _ if !raw => {
            net.mib.ip.inc(IPSTATS_MIB_INUNKNOWNPROTOS);
            crate::net::icmp::prot_unreach(&net, &skb);
        }
        _ => {}
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
    /// ICMP type counted for the packet in place of its header's
    /// (Linux fl4_icmp_type of a SOCK_RAW sender, which
    /// __ip_make_skb counts)
    pub icmp_type: Option<u8>,
    /// Confirm the next hop's neighbour as it goes out (Linux
    /// skb_set_dst_pending_confirm: MSG_CONFIRM, TCP's forward progress)
    pub confirm: bool,
    /// Route from a source address that is not local (Linux
    /// FLOWI_FLAG_ANYSRC of inet_sk_flowi_flags)
    pub anysrc: bool,
    /// Options for the header (Linux ipc.opt / inet_opt) and the
    /// final destination a source route ends with
    pub opt: Option<TxOpt>,
}

/// Options an outgoing header carries (Linux ip_options_build's opt
/// and daddr)
#[derive(Clone, Copy, Debug)]
pub struct TxOpt {
    pub opt: crate::net::inet::options::IpOptions,
    pub daddr: Ipv4Addr,
}

impl TxOpt {
    /// `opt` if it has any bytes, for a datagram to `daddr`
    pub fn of(opt: Option<crate::net::inet::options::IpOptions>, daddr: Ipv4Addr) -> Option<Self> {
        opt.filter(|o| o.m.optlen != 0)
            .map(|opt| Self { opt, daddr })
    }

    /// Where the route goes: a source route's first hop, else `daddr`
    /// (Linux udp_sendmsg's faddr)
    pub fn first_hop(t: &Option<Self>, daddr: Ipv4Addr) -> Ipv4Addr {
        match t {
            Some(t) if t.opt.m.srr != 0 => t.opt.faddr,
            _ => daddr,
        }
    }
}

impl Default for IpParams {
    fn default() -> Self {
        Self {
            tos: 0,
            ttl: IP_DEFAULT_TTL,
            pmtudisc: pmtu::WANT,
            id: None,
            icmp_type: None,
            confirm: false,
            anysrc: false,
            opt: None,
        }
    }
}

impl IpParams {
    /// MTU the packet is sized against (Linux ip_sk_use_pmtu: PROBE,
    /// INTERFACE and OMIT ignore the learned path MTU)
    pub fn mtu(&self, rt: &route::Rtable) -> usize {
        if self.pmtudisc < pmtu::PROBE {
            rt.mtu as usize
        } else {
            rt.dev.mtu() as usize
        }
    }

    /// Larger datagrams may be fragmented (Linux ip_sk_ignore_df)
    pub fn may_frag(&self) -> bool {
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
/// socket lock (TCP always does: it transmits owning `TcpSock.lock` or
/// under its slock; lock order: socket -> FIB -> neighbour -> device
/// TX -> backlog), so
/// nothing here may take a socket lock or flush the backlog.
pub fn ip_send_rt(
    net: &NetNamespace,
    rt: &route::Rtable,
    mut skb: Box<SkBuff>,
    protocol: u8,
    p: IpParams,
) -> Result<(), KernelError> {
    let src = skb.saddr.unwrap_or_default();
    let saddr = if src.is_unspecified() { rt.saddr } else { src };
    let optlen = p.opt.map_or(0, |o| usize::from(o.opt.m.optlen));
    let hlen = IP_HLEN_MIN + optlen;
    let tot_len = hlen + skb.len();
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
    let h = skb.push(hlen).ok_or(KernelError::NoBufferSpace)?;
    h[0] = 0x40 | (hlen / 4) as u8;
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
    if let Some(o) = &p.opt {
        crate::net::inet::options::build(h, &o.opt, o.daddr, saddr);
    }
    let c = ip_checksum(&h[..hlen]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    if protocol == IPPROTO_ICMP
        && let Some(ty) = p.icmp_type.or(skb.data().get(hlen).copied())
    {
        // Linux __ip_make_skb
        net.mib.icmp_out_count(ty);
    }
    if p.confirm {
        skb.dst_pending_confirm = true;
    }
    // Linux __ip_local_out
    net.mib.ip.inc(IPSTATS_MIB_OUTREQUESTS);
    ip_output(net, rt, skb, saddr, mtu)
}

/// Send a packet with a complete IP header along `rt`, fragmenting it
/// to `mtu` if needed (Linux ip_finish_output -> ip_fragment); `net`
/// is the sender's namespace, where the IP MIB counts it
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
        return ip_finish_output2(net, rt, skb);
    }
    // Linux ip_do_fragment (slow path)
    let ip = &net.mib.ip;
    let frags = fragment(&skb, mtu).inspect_err(|_| ip.inc(IPSTATS_MIB_FRAGFAILS))?;
    for f in frags {
        ip_finish_output2(net, rt, f).inspect_err(|_| ip.inc(IPSTATS_MIB_FRAGFAILS))?;
        ip.inc(IPSTATS_MIB_FRAGCREATES);
    }
    ip.inc(IPSTATS_MIB_FRAGOKS);
    Ok(())
}

/// One packet or fragment to its next hop (Linux ip_finish_output2:
/// OutTransmits and OutOctets after fragmenting)
fn ip_finish_output2(
    net: &NetNamespace,
    rt: &route::Rtable,
    skb: Box<SkBuff>,
) -> Result<(), KernelError> {
    use crate::net::inet::fib::RouteType;
    let ip = &net.mib.ip;
    match rt.rtype {
        RouteType::Multicast => ip.upd_po(
            IPSTATS_MIB_OUTMCASTPKTS,
            IPSTATS_MIB_OUTMCASTOCTETS,
            skb.len(),
        ),
        RouteType::Broadcast => ip.upd_po(
            IPSTATS_MIB_OUTBCASTPKTS,
            IPSTATS_MIB_OUTBCASTOCTETS,
            skb.len(),
        ),
        _ => {}
    }
    ip.upd_po(IPSTATS_MIB_OUTPKTS, IPSTATS_MIB_OUTOCTETS, skb.len());
    neigh_output(&rt.dev, rt, rt.nexthop(), skb)
}

/// Split an IP packet into fragments of at most `mtu` bytes, the first
/// with the whole header, the rest with only its copied options (Linux
/// ip_do_fragment slow path); ENOMEM if one cannot be allocated (Linux
/// ip_frag_next)
pub fn fragment(skb: &SkBuff, mtu: usize) -> Result<Vec<Box<SkBuff>>, KernelError> {
    let pkt = skb.data();
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let room = (mtu.saturating_sub(ihl)) & !7;
    if room == 0 {
        return Err(KernelError::MessageTooLong);
    }
    let payload = &pkt[ihl..];
    // Later fragments repeat only the copied options (Linux
    // ip_options_fragment after the first)
    let mut later = [0u8; 60];
    later[..ihl].copy_from_slice(&pkt[..ihl]);
    let mut m = crate::net::inet::options::OptMeta {
        optlen: (ihl - IP_HLEN_MIN) as u8,
        ..Default::default()
    };
    crate::net::inet::options::fragment(&mut later[..ihl], &mut m);
    let mut out = Vec::new();
    let mut off = 0;
    while off < payload.len() {
        let len = room.min(payload.len() - off);
        let more = off + len < payload.len();
        let mut f = SkBuff::alloc_tx(ihl + len, Gfp::ATOMIC).ok_or(KernelError::OutOfMemory)?;
        let hdr = if off == 0 { &pkt[..ihl] } else { &later[..ihl] };
        f.put_slice(hdr).ok_or(KernelError::OutOfMemory)?;
        f.put_slice(&payload[off..off + len])
            .ok_or(KernelError::OutOfMemory)?;
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
        // Linux __ip_append_data marks the first skb only
        f.dst_pending_confirm = off == 0 && skb.dst_pending_confirm;
        out.push(f);
        off += len;
    }
    Ok(out)
}

/// Link-layer destination of a routed packet (Linux ip_finish_output2:
/// NOARP devices and broadcast/multicast map directly, unicast next hops
/// go through the ARP table)
fn neigh_output(
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
        _ => arp::output(dev, next_hop, skb),
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

#[cfg(test)]
mod tests {
    use super::ip_checksum;

    #[test]
    fn checksum_long_input() {
        // 256KiB of 0xffff words: a 32-bit sum would carry out
        let b = alloc::vec![0xffu8; 256 << 10];
        assert_eq!(ip_checksum(&b), 0);
        assert_eq!(ip_checksum(&[0x45, 0x00, 0x00, 0x1c]), !0x451c);
        assert_eq!(ip_checksum(&[0x01]), !0x0100);
    }
}
