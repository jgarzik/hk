//! ICMP (Linux net/ipv4/icmp.c)
//!
//! Receive: echo requests are answered (icmp_echo_ignore_all,
//! icmp_echo_ignore_broadcasts), echo replies go to ping sockets, and
//! error messages (destination unreachable, time exceeded, parameter
//! problem) are matched to the socket that sent the offending packet
//! (`IcmpErr` -> raw, UDP, ping; TCP's hook waits for the TCP rewrite).
//! Frag-needed lowers the destination's path MTU.
//!
//! Send: `icmp_send` builds errors about a received or locally queued
//! packet with Linux's guards (never about ICMP errors, broadcasts,
//! link-level multicast or non-first fragments) and rate limits: a
//! global token bucket (icmp_msgs_per_sec / icmp_msgs_burst) and a
//! per-destination one (icmp_ratelimit) for the types in
//! icmp_ratemask; loopback is exempt.
//!
//! ## Locking
//!
//! `IcmpRate.st` (`spin::Mutex`, per namespace, thread only) is a leaf
//! taken around the token-bucket arithmetic only.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

use crate::net::NetNamespace;
use crate::net::af_inet::RxInfo;
use crate::net::ethernet::PktType;
use crate::net::inet::fib::RouteType;
use crate::net::inet::route;
use crate::net::ipv4::{self, IP_HLEN_MIN, IPPROTO_ICMP, IpParams, Ipv4Addr, ip_checksum, pmtu};
use crate::net::skb::SkBuff;
use crate::waitqueue::WaitQueue;

/// ICMP header length
pub const ICMP_HLEN: usize = 8;

/// ICMP types
pub mod icmp_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACH: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETERPROB: u8 = 12;
    pub const TIMESTAMP: u8 = 13;
    pub const ADDRESS: u8 = 17;
    pub const ADDRESSREPLY: u8 = 18;
    /// Highest known type (NR_ICMP_TYPES)
    pub const MAX: u8 = 18;
}

/// Codes
pub mod code {
    pub const HOST_UNREACH: u8 = 1;
    pub const PROT_UNREACH: u8 = 2;
    pub const PORT_UNREACH: u8 = 3;
    pub const FRAG_NEEDED: u8 = 4;
    /// Highest unreachable code (NR_ICMP_UNREACH)
    pub const MAX_UNREACH: u8 = 15;
    /// Time exceeded: fragment reassembly
    pub const EXC_FRAGTIME: u8 = 1;
}

/// ICMP header structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IcmpHdr {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: [u8; 2],
    pub id: [u8; 2],
    pub sequence: [u8; 2],
}

impl IcmpHdr {
    pub fn id(&self) -> u16 {
        u16::from_be_bytes(self.id)
    }

    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes(self.sequence)
    }
}

/// Counters for the kernel self-test (global)
pub static ICMP_IN_ECHO_REPS: AtomicU64 = AtomicU64::new(0);
/// Woken on every received echo reply
pub static ICMP_ECHO_REPLY_WQ: WaitQueue = WaitQueue::new();

/// Linux icmp_pointers[].error; unknown types count as errors
pub fn is_error(ty: u8) -> bool {
    use icmp_type::*;
    ty > MAX
        || matches!(
            ty,
            DEST_UNREACH | SOURCE_QUENCH | REDIRECT | TIME_EXCEEDED | PARAMETERPROB
        )
}

/// Linux icmp_err_convert: (errno, fatal) of an unreachable code
pub fn unreach_err(code: u8) -> (crate::error::KernelError, bool) {
    use crate::error::KernelError as E;
    match code {
        0 => (E::NetworkUnreachable, false),
        1 => (E::HostUnreachable, false),
        2 => (E::NoProtocolOption, true),
        3 => (E::ConnectionRefused, true),
        4 => (E::MessageTooLong, false),
        5 => (E::OperationNotSupported, false),
        6 | 9 => (E::NetworkUnreachable, true),
        7 => (E::HostDown, true),
        8 => (E::NoNetwork, true),
        11 => (E::NetworkUnreachable, false),
        12 => (E::HostUnreachable, false),
        _ => (E::HostUnreachable, true),
    }
}

// ============================================================================
// Rate limiting (pure token buckets + per-namespace state)
// ============================================================================

/// Global credit (Linux icmp_global_allow / icmp_global_consume), ms
#[derive(Clone, Copy, Debug, Default)]
pub struct Global {
    pub credit: i64,
    pub stamp: u64,
}

impl Global {
    /// May an error go out now?
    pub fn allow(&mut self, now: u64, per_sec: i64, burst: i64) -> bool {
        if self.credit > 0 {
            return true;
        }
        let delta = now.saturating_sub(self.stamp).min(1000);
        if delta < 20 {
            return false;
        }
        let incr = per_sec.max(0) * delta as i64 / 1000;
        if incr == 0 {
            return false;
        }
        self.stamp = now;
        self.credit = (self.credit + incr).min(burst);
        true
    }

    /// An error was sent: spend 0..2 credits (random, like Linux)
    pub fn consume(&mut self, credits: i64) {
        self.credit -= credits;
    }
}

/// Per-destination limiter (Linux inet_peer_xrlim_allow), ms
#[derive(Clone, Copy, Debug)]
pub struct XrLim {
    pub tokens: u64,
    pub last: u64,
}

/// Burst allowance in multiples of the rate (XRLIM_BURST_FACTOR)
const BURST: u64 = 6;

impl XrLim {
    /// A new peer starts with a full burst (Linux: rate_last 60 s back)
    pub fn new(now: u64) -> Self {
        Self {
            tokens: 0,
            last: now.saturating_sub(60_000),
        }
    }

    pub fn allow(&mut self, now: u64, timeout: u64) -> bool {
        let delta = now.saturating_sub(self.last);
        if delta != 0 {
            self.last = now;
            self.tokens = (self.tokens + delta).min(BURST * timeout);
        }
        if self.tokens >= timeout {
            self.tokens -= timeout;
            return true;
        }
        false
    }
}

/// Peers remembered for rate limiting (least recently used evicted)
const MAX_PEERS: usize = 256;

struct RateState {
    global: Global,
    peers: BTreeMap<Ipv4Addr, XrLim>,
}

/// A namespace's ICMP rate-limit state
pub struct IcmpRate {
    st: Mutex<RateState>,
}

impl Default for IcmpRate {
    fn default() -> Self {
        Self {
            st: Mutex::new(RateState {
                global: Global::default(),
                peers: BTreeMap::new(),
            }),
        }
    }
}

impl IcmpRate {
    fn global_allow(&self, net: &NetNamespace, now: u64) -> bool {
        let s = &net.sysctl;
        let per_sec = s.icmp_msgs_per_sec.load(Ordering::Relaxed) as i64;
        let burst = s.icmp_msgs_burst.load(Ordering::Relaxed) as i64;
        self.st.lock().global.allow(now, per_sec, burst)
    }

    fn peer_allow(&self, dst: Ipv4Addr, now: u64, timeout: u64) -> bool {
        let mut st = self.st.lock();
        if st.peers.len() >= MAX_PEERS && !st.peers.contains_key(&dst) {
            let old = st.peers.iter().min_by_key(|(_, p)| p.last).map(|(k, _)| *k);
            if let Some(k) = old {
                st.peers.remove(&k);
            }
        }
        st.peers
            .entry(dst)
            .or_insert_with(|| XrLim::new(now))
            .allow(now, timeout)
    }

    fn consume(&self) {
        let c = (crate::random::get_random_u32() % 3) as i64;
        self.st.lock().global.consume(c);
    }
}

/// Is `ty`/`code` subject to rate limiting (Linux icmpv4_mask_allow
/// inverted: types in icmp_ratemask, never frag needed)
fn limited(net: &NetNamespace, ty: u8, code: u8) -> bool {
    if ty > icmp_type::MAX {
        return false;
    }
    if ty == icmp_type::DEST_UNREACH && code == code::FRAG_NEEDED {
        return false;
    }
    (1i32 << ty) & net.sysctl.icmp_ratemask.load(Ordering::Relaxed) != 0
}

// ============================================================================
// Receive
// ============================================================================

/// Receive an ICMP packet (from ip_local_deliver; thread context; the
/// receiving device's namespace)
pub fn icmp_rcv(skb: SkBuff) {
    let Some(net) = skb.net() else {
        return;
    };
    let d = skb.data();
    if d.len() < ICMP_HLEN || ip_checksum(d) != 0 {
        return;
    }
    let ty = d[0];
    if skb.ip_bcast {
        // Linux icmp_rcv: errors to broadcasts are bogus; echo per sysctl
        use icmp_type::*;
        let echo = ty == ECHO || ty == TIMESTAMP;
        if (echo && net.sysctl.icmp_echo_ignore_bcast())
            || !(echo || ty == ADDRESS || ty == ADDRESSREPLY)
        {
            return;
        }
    }
    match ty {
        icmp_type::ECHO => icmp_echo(&net, &skb),
        icmp_type::ECHO_REPLY => {
            ICMP_IN_ECHO_REPS.fetch_add(1, Ordering::Relaxed);
            ICMP_ECHO_REPLY_WQ.wake_all();
        }
        icmp_type::DEST_UNREACH
        | icmp_type::TIME_EXCEEDED
        | icmp_type::PARAMETERPROB
        | icmp_type::SOURCE_QUENCH => icmp_unreach(&net, &skb),
        _ => {}
    }
}

/// Answer an echo request (Linux icmp_echo + icmp_reply)
fn icmp_echo(net: &NetNamespace, skb: &SkBuff) {
    if net.sysctl.icmp_echo_ignore_all() {
        return;
    }
    let (Some(src), Some(dst)) = (skb.saddr, skb.daddr) else {
        return;
    };
    let bad = |a: Ipv4Addr| a.is_broadcast() || a.is_multicast() || (a.0 >> 24) == 0;
    if bad(src) {
        return;
    }
    let req = skb.data();
    let Some(mut out) = SkBuff::alloc_tx(req.len()) else {
        return;
    };
    if out.put_slice(req).is_none() {
        return;
    }
    let h = out.data_mut();
    h[0] = icmp_type::ECHO_REPLY;
    h[2] = 0;
    h[3] = 0;
    let c = ip_checksum(h);
    h[2..4].copy_from_slice(&c.to_be_bytes());
    // A broadcast request is answered from our address on that link
    out.saddr = Some(if skb.ip_bcast { Ipv4Addr(0) } else { dst });
    out.daddr = Some(src);
    let p = IpParams {
        tos: skb.ip_tos,
        ..Default::default()
    };
    let _ = ipv4::ip_queue_xmit(net, out, IPPROTO_ICMP, p);
}

/// An ICMP error as seen by the transport error handlers (Linux
/// icmp_unreach + the skb they get): `inner` is the quoted offending
/// packet, IP header first, with at least its header + 8 bytes
pub struct IcmpErr<'a> {
    pub ty: u8,
    pub code: u8,
    /// Frag needed: next-hop MTU; parameter problem: pointer
    pub info: u32,
    pub inner: &'a [u8],
    /// Sender of the ICMP message (the offender)
    pub from: Ipv4Addr,
    /// Receive metadata of the ICMP message
    pub rx: RxInfo,
}

impl IcmpErr<'_> {
    pub fn ihl(&self) -> usize {
        ((self.inner[0] & 0x0f) as usize) * 4
    }

    pub fn inner_saddr(&self) -> Ipv4Addr {
        let i = self.inner;
        Ipv4Addr::from_be_bytes([i[12], i[13], i[14], i[15]])
    }

    pub fn inner_daddr(&self) -> Ipv4Addr {
        let i = self.inner;
        Ipv4Addr::from_be_bytes([i[16], i[17], i[18], i[19]])
    }

    pub fn proto(&self) -> u8 {
        self.inner[9]
    }

    /// The offending packet's transport header and data
    pub fn l4(&self) -> &[u8] {
        &self.inner[self.ihl()..]
    }

    /// errno and hard/soft classification shared by the datagram
    /// protocols (Linux udp_err / ping_err switch; frag needed is hard
    /// unless the socket does IP_PMTUDISC_DONT, which ignores it: None)
    pub fn errno(&self, pmtudisc: u8) -> Option<(crate::error::KernelError, bool)> {
        use crate::error::KernelError as E;
        match self.ty {
            icmp_type::SOURCE_QUENCH => None,
            icmp_type::PARAMETERPROB => Some((E::ProtocolError, true)),
            icmp_type::DEST_UNREACH if self.code == code::FRAG_NEEDED => {
                (pmtudisc != pmtu::DONT).then_some((E::MessageTooLong, true))
            }
            icmp_type::DEST_UNREACH if self.code <= code::MAX_UNREACH => {
                Some(unreach_err(self.code))
            }
            _ => Some((E::HostUnreachable, false)),
        }
    }
}

/// An error message arrived (Linux icmp_unreach + icmp_socket_deliver)
fn icmp_unreach(net: &NetNamespace, skb: &SkBuff) {
    let d = skb.data();
    let inner = &d[ICMP_HLEN..];
    if inner.len() < IP_HLEN_MIN || inner[0] >> 4 != 4 {
        return;
    }
    let ihl = ((inner[0] & 0x0f) as usize) * 4;
    if ihl < IP_HLEN_MIN || inner.len() < ihl + 8 {
        return;
    }
    let (ty, code) = (d[0], d[1]);
    if ty == icmp_type::DEST_UNREACH && code > code::MAX_UNREACH {
        return;
    }
    let mut info = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
    if ty == icmp_type::DEST_UNREACH && code == code::FRAG_NEEDED {
        info = u16::from_be_bytes([d[6], d[7]]) as u32;
    } else if ty == icmp_type::PARAMETERPROB {
        info = (d[4] as u32) << 24;
    }
    let e = IcmpErr {
        ty,
        code,
        info,
        inner,
        from: skb.saddr.unwrap_or_default(),
        rx: RxInfo {
            ifindex: skb.dev.as_ref().map_or(0, |d| d.ifindex()),
            spec_dst: skb.daddr.unwrap_or_default(),
            daddr: skb.daddr.unwrap_or_default(),
            ttl: skb.ip_ttl,
            tos: skb.ip_tos,
        },
    };
    if ty == icmp_type::DEST_UNREACH && code == code::FRAG_NEEDED {
        update_pmtu(net, &e);
    }
    deliver_err(net, &e);
}

/// Frag needed for a packet we sent: remember the smaller path MTU
fn update_pmtu(net: &NetNamespace, e: &IcmpErr) {
    if net.fib.addr_type(e.inner_saddr()) != RouteType::Local {
        return;
    }
    if let Ok(rt) = route::output(net, e.inner_daddr(), Ipv4Addr(0), 0) {
        net.pmtu.update(e.inner_daddr(), e.info, rt.mtu);
    }
}

/// Hand an error to the raw sockets and the inner protocol
fn deliver_err(net: &NetNamespace, e: &IcmpErr) {
    // TCP soft/hard errors (EHOSTUNREACH on SYN_SENT, PMTU) come with
    // the TCP rewrite
    if e.proto() == ipv4::IPPROTO_UDP {
        crate::net::udp::udp_err(net, e);
    }
}

// ============================================================================
// Send errors
// ============================================================================

/// The packet an error is about (Linux skb_in of icmp_send)
pub struct Offender<'a> {
    /// IP header onwards
    pub pkt: &'a [u8],
    /// Arrived on loopback (exempt from the global limit)
    pub in_lo: bool,
    /// Link-level unicast to us (PACKET_HOST)
    pub host: bool,
    /// Addressed to a broadcast address (RTCF_BROADCAST)
    pub bcast: bool,
}

impl<'a> Offender<'a> {
    /// A received packet whose IP header was marked
    pub fn of(skb: &'a SkBuff) -> Option<Self> {
        Some(Self {
            pkt: skb.network_packet()?,
            in_lo: skb.dev.as_ref().is_some_and(|d| d.is_loopback()),
            host: skb.pkt_type == PktType::Host,
            bcast: skb.ip_bcast,
        })
    }
}

/// May an error be sent about `o` at all (Linux __icmp_send guards)?
fn may_send(net: &NetNamespace, o: &Offender, ty: u8) -> bool {
    let p = o.pkt;
    if p.len() < IP_HLEN_MIN || !o.host || o.bcast {
        return false;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let daddr = Ipv4Addr::from_be_bytes([p[16], p[17], p[18], p[19]]);
    if daddr.is_multicast() || net.fib.addr_type(daddr) == RouteType::Broadcast {
        return false;
    }
    // Only about fragment 0
    if u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 {
        return false;
    }
    // Never an error about an ICMP error
    if is_error(ty) && p[9] == IPPROTO_ICMP {
        match p.get(ihl) {
            Some(&inner) if !is_error(inner) => {}
            _ => return false,
        }
    }
    true
}

/// Send ICMP `ty`/`code` with 4 bytes of `rest` about `o` (Linux
/// __icmp_send)
pub fn icmp_send(net: &NetNamespace, o: &Offender, ty: u8, code: u8, rest: [u8; 4]) {
    if !may_send(net, o, ty) {
        return;
    }
    let now = crate::net::neigh::now_ms();
    // Rate limits apply to the ratemask types, not to loopback input
    let apply = limited(net, ty, code) && !o.in_lo;
    if apply && !net.icmp.global_allow(net, now) {
        return;
    }
    let p = o.pkt;
    let src = Ipv4Addr::from_be_bytes([p[12], p[13], p[14], p[15]]);
    let dst = Ipv4Addr::from_be_bytes([p[16], p[17], p[18], p[19]]);
    // Reply from the address the packet was for, if it is ours
    let saddr = if net.fib.addr_type(dst) == RouteType::Local {
        dst
    } else {
        Ipv4Addr(0)
    };
    let Ok(rt) = route::output(net, src, saddr, 0) else {
        return;
    };
    if matches!(rt.rtype, RouteType::Broadcast | RouteType::Multicast) {
        return;
    }
    if apply {
        let timeout = net.sysctl.icmp_ratelimit.load(Ordering::Relaxed).max(0) as u64;
        if timeout != 0 && !rt.dev.is_loopback() && !net.icmp.peer_allow(src, now, timeout) {
            return;
        }
        net.icmp.consume();
    }
    let room = (rt.mtu as usize).min(576) - IP_HLEN_MIN - ICMP_HLEN;
    if room <= IP_HLEN_MIN {
        return;
    }
    let quote = &p[..p.len().min(room)];
    let tos = if is_error(ty) {
        (p[1] & 0x1e) | 0xc0
    } else {
        p[1]
    };
    xmit(net, &rt, ty, code, rest, quote, tos);
}

/// Build and send an ICMP message along `rt`
fn xmit(
    net: &NetNamespace,
    rt: &route::Rtable,
    ty: u8,
    code: u8,
    rest: [u8; 4],
    data: &[u8],
    tos: u8,
) {
    let Some(mut skb) = SkBuff::alloc_tx(ICMP_HLEN + data.len()) else {
        return;
    };
    if skb.put_slice(&[ty, code, 0, 0]).is_none()
        || skb.put_slice(&rest).is_none()
        || skb.put_slice(data).is_none()
    {
        return;
    }
    let c = ip_checksum(skb.data());
    skb.data_mut()[2..4].copy_from_slice(&c.to_be_bytes());
    skb.saddr = Some(rt.saddr);
    skb.daddr = Some(rt.daddr);
    let p = IpParams {
        tos,
        pmtudisc: pmtu::DONT,
        ..Default::default()
    };
    let _ = ipv4::ip_send_rt(net, rt, skb, IPPROTO_ICMP, p);
}

/// UDP datagram for no socket (Linux __udp4_lib_rcv)
pub fn port_unreach(net: &NetNamespace, skb: &SkBuff) {
    if let Some(o) = Offender::of(skb) {
        icmp_send(net, &o, icmp_type::DEST_UNREACH, code::PORT_UNREACH, [0; 4]);
    }
}

/// Unknown transport protocol (Linux ip_local_deliver_finish)
pub fn prot_unreach(net: &NetNamespace, skb: &SkBuff) {
    if let Some(o) = Offender::of(skb) {
        icmp_send(net, &o, icmp_type::DEST_UNREACH, code::PROT_UNREACH, [0; 4]);
    }
}

/// A queued packet's next hop never answered (Linux ipv4_link_failure):
/// host unreachable to its (local) sender
pub fn link_failure(skb: &SkBuff) {
    let Some(net) = skb.net() else {
        return;
    };
    let o = Offender {
        pkt: skb.data(),
        in_lo: false,
        host: true,
        bcast: false,
    };
    icmp_send(
        &net,
        &o,
        icmp_type::DEST_UNREACH,
        code::HOST_UNREACH,
        [0; 4],
    );
}

/// A reassembly queue timed out with its first fragment in (`first`:
/// its IP header + leading payload; Linux ip_expire)
pub fn frag_expired(net: &NetNamespace, first: &[u8]) {
    let o = Offender {
        pkt: first,
        in_lo: false,
        host: true,
        bcast: false,
    };
    icmp_send(
        net,
        &o,
        icmp_type::TIME_EXCEEDED,
        code::EXC_FRAGTIME,
        [0; 4],
    );
}

/// Send an echo request from `net` (kernel self-test)
pub fn icmp_send_echo(
    net: &NetNamespace,
    dest: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Result<(), crate::error::KernelError> {
    use crate::error::KernelError;
    let mut skb = SkBuff::alloc_tx(ICMP_HLEN + payload.len()).ok_or(KernelError::NoBufferSpace)?;
    skb.put_slice(&[icmp_type::ECHO, 0, 0, 0])
        .ok_or(KernelError::NoBufferSpace)?;
    skb.put_slice(&id.to_be_bytes())
        .ok_or(KernelError::NoBufferSpace)?;
    skb.put_slice(&seq.to_be_bytes())
        .ok_or(KernelError::NoBufferSpace)?;
    skb.put_slice(payload).ok_or(KernelError::NoBufferSpace)?;
    let c = ip_checksum(skb.data());
    skb.data_mut()[2..4].copy_from_slice(&c.to_be_bytes());
    skb.daddr = Some(dest);
    ipv4::ip_queue_xmit(net, skb, IPPROTO_ICMP, IpParams::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_bucket() {
        let mut g = Global::default();
        // First call after a long idle refills to the burst
        assert!(g.allow(10_000, 1000, 50));
        assert_eq!(g.credit, 50);
        g.consume(50);
        // Too soon to refill (< 20 ms)
        assert!(!g.allow(10_010, 1000, 50));
        // 20 ms at 1000/s = 20 credits
        assert!(g.allow(10_020, 1000, 50));
        assert_eq!(g.credit, 20);
        // Disabled rate
        let mut g = Global::default();
        assert!(!g.allow(10_000, 0, 50));
    }

    #[test]
    fn peer_bucket_burst_then_rate() {
        let mut p = XrLim::new(100_000);
        let sent = (0..20).filter(|_| p.allow(100_000, 1000)).count();
        assert_eq!(sent, 6);
        assert!(!p.allow(100_500, 1000));
        assert!(p.allow(101_000, 1000));
        assert!(!p.allow(101_001, 1000));
    }

    #[test]
    fn error_types() {
        assert!(is_error(icmp_type::DEST_UNREACH));
        assert!(is_error(icmp_type::TIME_EXCEEDED));
        assert!(is_error(200));
        assert!(!is_error(icmp_type::ECHO));
        assert!(!is_error(icmp_type::ECHO_REPLY));
        assert_eq!(
            unreach_err(3),
            (crate::error::KernelError::ConnectionRefused, true)
        );
        assert_eq!(
            unreach_err(1),
            (crate::error::KernelError::HostUnreachable, false)
        );
    }
}
