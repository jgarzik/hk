//! ICMP (Linux net/ipv4/icmp.c)
//!
//! Receive: echo requests are answered (icmp_echo_ignore_all,
//! icmp_echo_ignore_broadcasts), so are timestamp requests (only
//! icmp_echo_ignore_broadcasts applies), echo replies go to ping sockets, and
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
//! The global credit is two atomics, updated lock-free (Linux
//! icmp_global_allow: a stamp compare-exchange, then the credit).
//! `IcmpRate.peers` (`crate::sync::spin::Mutex`, per namespace, thread
//! only; Linux inet_peer_base.lock) is a leaf over the peer tree: a new
//! peer's node is allocated GFP_ATOMIC under it, as Linux inet_getpeer
//! does, and peers collected by the walk's GC are freed after it.

use crate::mm::page_alloc::Gfp;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::util::rbtree::{RbTree, RbTreeNode, RbTreeNodeReservation};

use crate::sync::spin::Mutex;

use crate::net::NetNamespace;
use crate::net::af_inet::RxInfo;
use crate::net::ethernet::PktType;
use crate::net::inet::fib::RouteType;
use crate::net::inet::route;
use crate::net::ipv4::{self, IP_HLEN_MIN, IPPROTO_ICMP, IpParams, Ipv4Addr, ip_checksum, pmtu};
use crate::net::mib::*;
use crate::net::skb::SkBuff;
use crate::sync::waitqueue::WaitQueue;

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
    pub const TIMESTAMPREPLY: u8 = 14;
    pub const ADDRESS: u8 = 17;
    pub const ADDRESSREPLY: u8 = 18;
    /// Highest known type (NR_ICMP_TYPES)
    pub const MAX: u8 = 18;
    /// RFC 8335 PROBE request and reply
    pub const EXT_ECHO: u8 = 42;
    pub const EXT_ECHOREPLY: u8 = 43;
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
pub fn unreach_err(code: u8) -> (crate::util::error::KernelError, bool) {
    use crate::util::error::KernelError as E;
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

/// Global credit (Linux net->ipv4.icmp_global_credit and _stamp), ms
#[derive(Debug, Default)]
pub struct Global {
    credit: AtomicI64,
    stamp: AtomicU64,
}

impl Global {
    /// May an error go out now? (Linux icmp_global_allow: many CPUs may
    /// find credit at once and overspend it, an accepted race; one
    /// refill per stamp, won by compare-exchange)
    pub fn allow(&self, now: u64, per_sec: i64, burst: i64) -> bool {
        if self.credit.load(Ordering::Relaxed) > 0 {
            return true;
        }
        let old = self.stamp.load(Ordering::Relaxed);
        let delta = now.saturating_sub(old).min(1000);
        if delta < 20 {
            return false;
        }
        let incr = per_sec.max(0) * delta as i64 / 1000;
        if incr == 0 {
            return false;
        }
        if self
            .stamp
            .compare_exchange(old, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let _ = self
                .credit
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                    Some((c + incr).min(burst))
                });
        }
        true
    }

    /// An error was sent: spend `credits` (Linux icmp_global_consume:
    /// may go negative)
    pub fn consume(&self, credits: i64) {
        self.credit.fetch_sub(credits, Ordering::Relaxed);
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

/// A peer (Linux struct inet_peer: its rate limiter and dtime, the
/// last use, in ms)
struct Peer {
    lim: XrLim,
    dtime: u64,
}

/// GC candidates per lookup (Linux PEER_MAX_GC)
const PEER_MAX_GC: usize = 32;
/// Peer time to live under high load and normally (Linux
/// inet_peer_minttl, inet_peer_maxttl), ms
const PEER_MINTTL: u64 = 120_000;
const PEER_MAXTTL: u64 = 600_000;

/// Peers past which entries are dropped aggressively (Linux
/// inet_initpeers: 1% of memory in entries, 4096 to 65536 + 128)
fn peer_threshold() -> usize {
    static T: spin::Once<usize> = spin::Once::new();
    *T.call_once(|| {
        let entry = core::mem::size_of::<RbTreeNode<Ipv4Addr, Peer>>().next_multiple_of(64);
        (crate::FRAME_ALLOCATOR.buffer_pages() * 4096 / (100 * entry)).clamp(4096, 65536 + 128)
    })
}

/// A namespace's ICMP rate-limit state (Linux net->ipv4.icmp_global_*
/// and net->ipv4.peers)
pub struct IcmpRate {
    global: Global,
    peers: Mutex<RbTree<Ipv4Addr, Peer>>,
}

impl Default for IcmpRate {
    fn default() -> Self {
        Self {
            global: Global::default(),
            peers: Mutex::new(RbTree::new()),
        }
    }
}

impl IcmpRate {
    fn global_allow(&self, net: &NetNamespace, now: u64) -> bool {
        let s = &net.sysctl;
        let per_sec = i64::from(s.icmp_msgs_per_sec.load(Ordering::Relaxed));
        let burst = i64::from(s.icmp_msgs_burst.load(Ordering::Relaxed));
        self.global.allow(now, per_sec, burst)
    }

    /// Linux icmpv4_xrlim_allow: the peer for `dst` (inet_getpeer_v4,
    /// made GFP_ATOMIC under the lock if new), then its limiter
    /// (inet_peer_xrlim_allow; no peer, no limit). Peers the lookup
    /// passed that outlived their time to live go (inet_peer_gc).
    fn peer_allow(&self, dst: Ipv4Addr, now: u64, timeout: u64) -> bool {
        let threshold = peer_threshold();
        let mut gc = [Ipv4Addr(0); PEER_MAX_GC];
        let mut ngc = 0;
        let mut dead: [Option<RbTreeNode<Ipv4Addr, Peer>>; PEER_MAX_GC] =
            [const { None }; PEER_MAX_GC];
        let mut t = self.peers.lock();
        let total = t.len();
        let ttl = if total >= threshold {
            0
        } else {
            PEER_MAXTTL - (PEER_MAXTTL - PEER_MINTTL) * total as u64 / threshold as u64
        };
        let mut visit = |k: &Ipv4Addr, p: &Peer| {
            if ngc < PEER_MAX_GC && *k != dst && now.saturating_sub(p.dtime) >= ttl {
                gc[ngc] = *k;
                ngc += 1;
            }
        };
        let ok = match t.get_mut_visiting(&dst, &mut visit) {
            Some(p) => {
                p.dtime = now;
                p.lim.allow(now, timeout)
            }
            None => match RbTreeNodeReservation::new_gfp(Gfp::ATOMIC) {
                Ok(r) => {
                    let mut p = Peer {
                        lim: XrLim::new(now),
                        dtime: now,
                    };
                    let ok = p.lim.allow(now, timeout);
                    let _ = t.insert(r.into_node(dst, p));
                    ok
                }
                Err(_) => true,
            },
        };
        for (k, d) in gc[..ngc].iter().zip(dead.iter_mut()) {
            *d = t.remove_node(k);
        }
        drop(t);
        drop(dead);
        ok
    }

    fn consume(&self) {
        let c = i64::from(crate::random::get_random_u32() % 3);
        self.global.consume(c);
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
/// receiving device's namespace), counted as Linux icmp_rcv does
pub fn icmp_rcv(skb: SkBuff) {
    let Some(net) = skb.net() else {
        return;
    };
    let icmp = &net.mib.icmp;
    icmp.inc(ICMP_MIB_INMSGS);
    let d = skb.data();
    if ip_checksum(d) != 0 {
        icmp.inc(ICMP_MIB_CSUMERRORS);
        icmp.inc(ICMP_MIB_INERRORS);
        return;
    }
    if d.len() < ICMP_HLEN {
        icmp.inc(ICMP_MIB_INERRORS);
        return;
    }
    let ty = d[0];
    net.mib.icmpmsg_in(ty);
    if ty == icmp_type::EXT_ECHO {
        // PROBE (RFC 8335): answered only with icmp_echo_enable_probe,
        // which hk does not have (Linux's default is off)
        return;
    }
    if skb.ip_bcast {
        // Linux icmp_rcv: errors to broadcasts are bogus; echo per sysctl
        use icmp_type::*;
        let echo = ty == ECHO || ty == TIMESTAMP;
        if (echo && net.sysctl.icmp_echo_ignore_bcast())
            || !(echo || ty == ADDRESS || ty == ADDRESSREPLY)
        {
            icmp.inc(ICMP_MIB_INERRORS);
            return;
        }
    }
    // Linux: echo replies go to ping first (no PROBE replies here: hk
    // never sends PROBEs); past that, an unknown type is an error
    if ty > icmp_type::MAX && ty != icmp_type::EXT_ECHOREPLY {
        icmp.inc(ICMP_MIB_INERRORS);
        return;
    }
    match ty {
        icmp_type::ECHO => icmp_echo(&net, &skb),
        icmp_type::TIMESTAMP => icmp_timestamp(&net, &skb),
        icmp_type::ECHO_REPLY => {
            ICMP_IN_ECHO_REPS.fetch_add(1, Ordering::Relaxed);
            ICMP_ECHO_REPLY_WQ.wake_all();
            crate::net::ping::ping_rcv(&net, &skb);
        }
        icmp_type::DEST_UNREACH
        | icmp_type::TIME_EXCEEDED
        | icmp_type::PARAMETERPROB
        | icmp_type::SOURCE_QUENCH => icmp_unreach(&net, &skb),
        _ => {}
    }
}

/// Answer an echo request (Linux icmp_echo)
fn icmp_echo(net: &NetNamespace, skb: &SkBuff) {
    if net.sysctl.icmp_echo_ignore_all() {
        return;
    }
    icmp_reply(net, skb, icmp_type::ECHO_REPLY, None, skb.data(), &[]);
}

/// Answer a timestamp request (Linux icmp_timestamp): the request's
/// header and originate time, then receive and transmit times, both
/// now; anything past the originate time is not echoed
fn icmp_timestamp(net: &NetNamespace, skb: &SkBuff) {
    let req = skb.data();
    // Linux: too short past the header
    if req.len() < ICMP_HLEN + 4 {
        net.mib.icmp.inc(ICMP_MIB_INERRORS);
        return;
    }
    let now = inet_current_timestamp().to_be_bytes();
    let mut times = [0u8; 8];
    times[..4].copy_from_slice(&now);
    times[4..].copy_from_slice(&now);
    let head = &req[..ICMP_HLEN + 4];
    icmp_reply(net, skb, icmp_type::TIMESTAMPREPLY, Some(0), head, &times);
}

/// Milliseconds since midnight UTC (Linux inet_current_timestamp,
/// net/ipv4/af_inet.c; host order here, sent big-endian)
pub fn inet_current_timestamp() -> u32 {
    ms_of_day(crate::time::realtime_ns())
}

/// Milliseconds into the UTC day of a CLOCK_REALTIME `ns`
fn ms_of_day(ns: u64) -> u32 {
    ((ns / 1_000_000) % 86_400_000) as u32
}

/// Send `head` (a received request's ICMP header and leading data)
/// then `tail` back to its sender as type `ty`, its code `code` or, if
/// None, the request's (Linux icmp_echo keeps it, icmp_timestamp sets
/// 0; icmp_reply + icmp_push_reply)
fn icmp_reply(
    net: &NetNamespace,
    skb: &SkBuff,
    ty: u8,
    code: Option<u8>,
    head: &[u8],
    tail: &[u8],
) {
    let (Some(src), Some(dst)) = (skb.saddr, skb.daddr) else {
        return;
    };
    let bad = |a: Ipv4Addr| a.is_broadcast() || a.is_multicast() || (a.0 >> 24) == 0;
    if bad(src) {
        return;
    }
    let Some(mut out) = SkBuff::alloc_tx(head.len() + tail.len(), Gfp::ATOMIC) else {
        // Linux icmp_push_reply: ip_append_data failed
        net.mib.icmp.inc(ICMP_MIB_OUTERRORS);
        net.mib.out_discard();
        return;
    };
    if out.put_slice(head).is_none() || out.put_slice(tail).is_none() {
        net.mib.icmp.inc(ICMP_MIB_OUTERRORS);
        net.mib.out_discard();
        return;
    }
    let h = out.data_mut();
    h[0] = ty;
    if let Some(c) = code {
        h[1] = c;
    }
    h[2] = 0;
    h[3] = 0;
    let c = ip_checksum(h);
    h[2..4].copy_from_slice(&c.to_be_bytes());
    // A broadcast request is answered from our address on that link
    out.saddr = Some(if skb.ip_bcast { Ipv4Addr(0) } else { dst });
    out.daddr = Some(src);
    // Linux icmp_reply leaves fl4_icmp_type 0, so every reply counts
    // as an echo reply (Icmp OutEchoReps, IcmpMsg OutType0)
    let p = IpParams {
        tos: skb.ip_tos,
        icmp_type: Some(icmp_type::ECHO_REPLY),
        ..Default::default()
    };
    // Linux icmp_reply: no reply without a route
    let Ok(rt) = route::output(net, src, out.saddr.unwrap_or_default(), 0) else {
        return;
    };
    if ipv4::ip_send_rt(net, &rt, out, IPPROTO_ICMP, p).is_err() {
        net.mib.out_discard();
    }
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
    pub fn errno(&self, pmtudisc: u8) -> Option<(crate::util::error::KernelError, bool)> {
        use crate::util::error::KernelError as E;
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
    let ihl = inner.first().map_or(0, |b| usize::from(b & 0x0f) * 4);
    // Linux icmp_unreach / icmp_socket_deliver: a quote too short or
    // mangled is an input error
    if inner.len() < IP_HLEN_MIN || inner[0] >> 4 != 4 || ihl < IP_HLEN_MIN || inner.len() < ihl + 8
    {
        net.mib.icmp.inc(ICMP_MIB_INERRORS);
        return;
    }
    let (ty, code) = (d[0], d[1]);
    if ty == icmp_type::DEST_UNREACH && code > code::MAX_UNREACH {
        return;
    }
    let mut info = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
    if ty == icmp_type::DEST_UNREACH && code == code::FRAG_NEEDED {
        info = u32::from(u16::from_be_bytes([d[6], d[7]]));
    } else if ty == icmp_type::PARAMETERPROB {
        info = u32::from(d[4]) << 24;
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
fn update_pmtu(net: &NetNamespace, e: &IcmpErr<'_>) {
    if net.fib.addr_type(e.inner_saddr()) != RouteType::Local {
        return;
    }
    if let Ok(rt) = route::output(net, e.inner_daddr(), Ipv4Addr(0), 0) {
        route::update_pmtu(&rt, e.info);
    }
}

/// Hand an error to the raw sockets and the inner protocol
fn deliver_err(net: &NetNamespace, e: &IcmpErr<'_>) {
    crate::net::raw::raw_err(net, e);
    match e.proto() {
        ipv4::IPPROTO_TCP => crate::net::tcp::tcp_err(net, e),
        ipv4::IPPROTO_UDP => crate::net::udp::udp_err(net, e),
        IPPROTO_ICMP => crate::net::ping::ping_err(net, e),
        _ => {}
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
fn may_send(net: &NetNamespace, o: &Offender<'_>, ty: u8) -> bool {
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
pub fn icmp_send(net: &NetNamespace, o: &Offender<'_>, ty: u8, code: u8, rest: [u8; 4]) {
    if !may_send(net, o, ty) {
        return;
    }
    let now = crate::net::neigh::now_ms();
    // Rate limits apply to the ratemask types, not to loopback input
    let apply = limited(net, ty, code) && !o.in_lo;
    if apply && !net.icmp.global_allow(net, now) {
        net.mib.icmp.inc(ICMP_MIB_RATELIMITGLOBAL);
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
            net.mib.icmp.inc(ICMP_MIB_RATELIMITHOST);
            return;
        }
        net.icmp.consume();
    }
    // A route MTU below the headers leaves no room (no wrap to a huge
    // quote; Linux __icmp_send's room is an int that goes negative)
    let room = (rt.mtu as usize)
        .min(576)
        .saturating_sub(IP_HLEN_MIN + ICMP_HLEN);
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
    let Some(mut skb) = SkBuff::alloc_tx(ICMP_HLEN + data.len(), Gfp::ATOMIC) else {
        // Linux icmp_push_reply: ip_append_data failed
        net.mib.icmp.inc(ICMP_MIB_OUTERRORS);
        net.mib.out_discard();
        return;
    };
    if skb.put_slice(&[ty, code, 0, 0]).is_none()
        || skb.put_slice(&rest).is_none()
        || skb.put_slice(data).is_none()
    {
        net.mib.icmp.inc(ICMP_MIB_OUTERRORS);
        net.mib.out_discard();
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
    if ipv4::ip_send_rt(net, rt, skb, IPPROTO_ICMP, p).is_err() {
        // Linux ip_push_pending_frames -> ip_send_skb
        net.mib.out_discard();
    }
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
) -> Result<(), crate::util::error::KernelError> {
    use crate::util::error::KernelError;
    let mut skb = SkBuff::alloc_tx(ICMP_HLEN + payload.len(), Gfp::KERNEL)
        .ok_or(KernelError::NoBufferSpace)?;
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
        let g = Global::default();
        let credit = |g: &Global| g.credit.load(Ordering::Relaxed);
        // First call after a long idle refills to the burst
        assert!(g.allow(10_000, 1000, 50));
        assert_eq!(credit(&g), 50);
        g.consume(50);
        // Too soon to refill (< 20 ms)
        assert!(!g.allow(10_010, 1000, 50));
        // 20 ms at 1000/s = 20 credits
        assert!(g.allow(10_020, 1000, 50));
        assert_eq!(credit(&g), 20);
        // Disabled rate
        let g = Global::default();
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
    fn timestamp_ms_of_day() {
        assert_eq!(ms_of_day(0), 0);
        // 1 day + 1 h + 2.345678 s past the epoch
        let ns = (86_400 + 3_600 + 2) * 1_000_000_000 + 345_678_901;
        assert_eq!(ms_of_day(ns), 3_602_345);
        // Last millisecond of a day, then the next midnight
        assert_eq!(ms_of_day(86_400_000_000_000 - 1), 86_399_999);
        assert_eq!(ms_of_day(86_400_000_000_000), 0);
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
            (crate::util::error::KernelError::ConnectionRefused, true)
        );
        assert_eq!(
            unreach_err(1),
            (crate::util::error::KernelError::HostUnreachable, false)
        );
    }
}
