//! The UDP socket table (Linux udp_table: hash by local port, hash2 by
//! local address and port; net/ipv4/udp.c)
//!
//! Every namespace shares one table, sized from memory at boot. A
//! bound socket is on its port's `hash` slot (Linux sk_node) and on
//! its (address, port) `hash2` slot (Linux udp_portaddr_node), each
//! slot counting its sockets. Receive looks up hash2: (daddr, port),
//! then (INADDR_ANY, port), then the port slot for a socket whose
//! address changed before its rehash (Linux __udp4_lib_lookup). Bind
//! checks conflicts on the port slot, or on the two hash2 slots when
//! the port slot is long (Linux udp_lib_get_port); connect and
//! disconnect move a socket whose address changed between hash2 slots
//! (Linux udp_lib_rehash).
//!
//! ## Locking
//!
//! A `hash` slot's lock (Linux hslot->lock) -> a `hash2` slot's lock
//! (Linux hslot2->lock; one at a time, under its socket's port slot)
//! and `REUSEPORT_LOCK` (under the port slot, never with a hash2 slot)
//! -> `Inet.addr`. Lookups walk slots under `rcu::read_lock` once each,
//! as Linux walks its hlists: a socket moved meanwhile may lead a walk
//! into another chain, which the port slot fallback covers. Slot counts
//! change under their slot's lock; receive reads them unlocked (Linux
//! `hslot->count > 10`).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::UdpSock;
use crate::mm::page_alloc::Gfp;
use crate::net::NetNamespace;
use crate::net::inet::port::{self, BindInfo, Flow, Parity};
use crate::net::ipv4::Ipv4Addr;
use crate::net::mib::*;
use crate::net::skb::SkBuff;
use crate::net::sock::sf;
use crate::net::sock_reuseport;
use crate::sync::rcu::RcuReadGuard;
use crate::util::error::KernelError;
use crate::util::hlist_nulls::{NullsGuard, NullsHead};

crate::nulls_adapter!(pub(super) UdpHash, UdpSock, link);
crate::nulls_adapter!(pub(super) UdpHash2, UdpSock, link2);
crate::rcu_puts!(UdpSock, rcu);

/// A slot (Linux struct udp_hslot): its chain, lock, and count
pub(super) struct Slot<A: crate::util::hlist_nulls::NullsAdapter> {
    pub(super) head: NullsHead<A>,
    /// Sockets on it (Linux count): changed under its lock, read
    /// unlocked by lookups choosing a table
    count: AtomicU32,
}

impl<A: crate::util::hlist_nulls::NullsAdapter> Slot<A> {
    fn count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }

    /// Count `d` more sockets, the slot locked
    fn count_add(&self, _g: &NullsGuard<'_, A>, d: i32) {
        let n = self.count.load(Ordering::Relaxed).wrapping_add_signed(d);
        self.count.store(n, Ordering::Relaxed);
    }
}

/// Linux udp_table
struct Table {
    hash: Box<[Slot<UdpHash>]>,
    hash2: Box<[Slot<UdpHash2>]>,
    mask: usize,
}

static UDP_TABLE: spin::Once<Table> = spin::Once::new();

/// `n` empty slots, the lock class the caller's
#[track_caller]
fn slots<A: crate::util::hlist_nulls::NullsAdapter>(n: usize) -> Box<[Slot<A>]> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).expect("udp: hash table");
    for i in 0..n {
        v.push(Slot {
            head: NullsHead::new(i),
            count: AtomicU32::new(0),
        });
    }
    v.into_boxed_slice()
}

/// Size the table from memory (Linux udp_table_init:
/// alloc_large_system_hash with one slot per 2 MiB, a power of two
/// between UDP_HTABLE_SIZE_MIN and 64 Ki slots; hash2 as many)
pub fn init() {
    let n = (crate::FRAME_ALLOCATOR.buffer_pages() >> 9)
        .next_power_of_two()
        .clamp(256, 1 << 16);
    UDP_TABLE.call_once(|| Table {
        hash: slots(n),
        hash2: slots(n),
        mask: n - 1,
    });
}

fn table() -> &'static Table {
    UDP_TABLE.get().expect("udp table not initialized")
}

/// The port slots, for /proc/net/udp
pub(super) fn hash_slots() -> &'static [Slot<UdpHash>] {
    &table().hash
}

/// Linux udp_hashslot (udp_hashfn: the port plus the namespace's
/// random mix, masked)
fn hslot(net: &NetNamespace, port: u16) -> &'static Slot<UdpHash> {
    let t = table();
    &t.hash[usize::from(port).wrapping_add(net.hash_mix as usize) & t.mask]
}

/// Linux udp_hashslot2: the namespace is mixed into `hash` already
fn hslot2(hash: u32) -> &'static Slot<UdpHash2> {
    let t = table();
    &t.hash2[hash as usize & t.mask]
}

/// Linux ipv4_portaddr_hash
pub(super) fn portaddr_hash(net: &NetNamespace, addr: Ipv4Addr, port: u16) -> u32 {
    crate::util::jhash::jhash_1word(addr.0, net.hash_mix) ^ u32::from(port)
}

/// Address `s` is bound to (for the bind rules), read under a slot lock
/// (order: slot -> Inet.addr)
fn bound_addr(s: &UdpSock) -> Ipv4Addr {
    s.inet.get().rcv_saddr
}

/// `o` (another socket of `net` on `port`) conflicts with `info`
fn conflicts(o: &UdpSock, net: u64, port: u16, info: &BindInfo) -> bool {
    o.sk.net.id == net
        && o.inet.get().sport == port
        && port::conflict(info, &o.bind_info(bound_addr(o)), false)
}

/// Another socket on `port` conflicts with `info` (Linux
/// udp_lib_lport_inuse), the port slot locked
fn inuse(g: &NullsGuard<'_, UdpHash>, net: u64, port: u16, info: &BindInfo) -> bool {
    g.find(|o| conflicts(o, net, port, info)).is_some()
}

/// As `inuse`, over a hash2 slot (Linux udp_lib_lport_inuse2: the port
/// slot stays locked, so no socket on `port` comes or goes)
fn inuse2(s2: &Slot<UdpHash2>, net: u64, port: u16, info: &BindInfo) -> bool {
    let g = s2.head.lock();
    g.find(|o| conflicts(o, net, port, info)).is_some()
}

/// The port is taken (Linux udp_lib_get_port's check for a given port):
/// a long port slot defers to the two hash2 slots of the address and of
/// INADDR_ANY, unless the address's is longer still
fn port_taken(
    s: &UdpSock,
    g: &NullsGuard<'_, UdpHash>,
    hs: &Slot<UdpHash>,
    p: u16,
    info: &BindInfo,
) -> bool {
    let net = &*s.sk.net;
    // Linux inet_use_hash2_on_bind
    if !info.addr.is_unspecified() && hs.count() > 10 {
        let t = table();
        let slot2 = portaddr_hash(net, info.addr, p) as usize & t.mask;
        let null2 = portaddr_hash(net, Ipv4Addr::default(), p) as usize & t.mask;
        let s2 = &t.hash2[slot2];
        if hs.count() >= s2.count() {
            return inuse2(s2, net.id, p, info)
                || (null2 != slot2 && inuse2(&t.hash2[null2], net.id, p, info));
        }
    }
    inuse(g, net.id, p, info)
}

/// Hash `s` on `port` (0 = an ephemeral port) and set the port, all
/// under the port slot's lock, joining or starting a SO_REUSEPORT group
/// (Linux udp_lib_get_port, udp_reuseport_add_sock): EADDRINUSE on a
/// conflict, when the range is exhausted, or when the group cannot
/// grow
pub(super) fn get_port(
    s: &Arc<UdpSock>,
    info: &BindInfo,
    port: u16,
    flow: Flow,
) -> Result<u16, KernelError> {
    let net = &*s.sk.net;
    let take = |p: u16| -> Option<Result<u16, KernelError>> {
        let hs = hslot(net, p);
        let mut g = hs.head.lock();
        if port_taken(s, &g, hs, p, info) {
            return None;
        }
        if s.sk.flag(sf::REUSEPORT) && reuseport_add(&g, s, p, info).is_err() {
            return Some(Err(KernelError::AddressInUse));
        }
        s.inet.addr.lock().sport = p;
        let h2 = portaddr_hash(net, info.addr, p);
        s.portaddr_hash.store(h2, Ordering::Relaxed);
        g.add_head_rcu(s.clone());
        hs.count_add(&g, 1);
        let s2 = hslot2(h2);
        let mut g2 = s2.head.lock();
        g2.add_head_rcu(s.clone());
        s2.count_add(&g2, 1);
        Some(Ok(p))
    };
    if port != 0 {
        return take(port).unwrap_or(Err(KernelError::AddressInUse));
    }
    let mut r = None;
    let range = net.port_range.get();
    port::ephemeral(range, flow, Parity::Any, |p| {
        r = take(p);
        r.is_some()
    });
    r.unwrap_or(Err(KernelError::AddressInUse))
}

/// Join the group of a socket on `port` with the same owner, device
/// and address, or start one (Linux udp_reuseport_add_sock)
fn reuseport_add(
    g: &NullsGuard<'_, UdpHash>,
    s: &Arc<UdpSock>,
    port: u16,
    info: &BindInfo,
) -> Result<(), KernelError> {
    let net = s.sk.net.id;
    let peer = g.find(|o| {
        o.sk.net.id == net
            && o.inet.get().sport == port
            && o.sk.flag(sf::REUSEPORT)
            && o.sk.cred.euid == info.uid
            && o.sk.bound_dev_if() == info.dev
            && bound_addr(o) == info.addr
    });
    let mut o = sock_reuseport::lock();
    match peer {
        Some(p) => s.reuse.add(s, &p.reuse, &mut o),
        None => s.reuse.alloc(s, &mut o),
    }
}

/// Linux udp_lib_unhash: off both slots and out of its group, the port
/// cleared; the tables' references go after a grace period. False if it
/// was not hashed.
pub(super) fn unhash(s: &UdpSock) -> bool {
    let net = &*s.sk.net;
    let hs = hslot(net, s.inet.get().sport);
    let mut g = hs.head.lock();
    if !s.reuse.is_none() {
        s.reuse.detach(s, &mut sock_reuseport::lock());
    }
    let Some(u) = g.del_rcu(s) else {
        return false;
    };
    hs.count_add(&g, -1);
    s.inet.addr.lock().sport = 0;
    let s2 = hslot2(s.portaddr_hash.load(Ordering::Relaxed));
    let mut g2 = s2.head.lock();
    let u2 = g2.del_rcu(s);
    if u2.is_some() {
        s2.count_add(&g2, -1);
    }
    drop(g2);
    drop(g);
    u.defer();
    if let Some(u2) = u2 {
        u2.defer();
    }
    true
}

/// Linux udp_lib_rehash via udp_v4_rehash: the bound address changed
/// (connect, disconnect), so move to its new hash2 slot, leaving any
/// reuseport group; the socket lock held
pub(super) fn rehash(s: &UdpSock) {
    if !s.link.is_hashed() {
        return;
    }
    let net = &*s.sk.net;
    let a = s.inet.get();
    let new = portaddr_hash(net, a.rcv_saddr, a.sport);
    let old = s.portaddr_hash.load(Ordering::Relaxed);
    let (s2, n2) = (hslot2(old), hslot2(new));
    if !core::ptr::eq(s2, n2) || !s.reuse.is_none() {
        let hs = hslot(net, a.sport);
        let _g = hs.head.lock();
        if !s.reuse.is_none() {
            s.reuse.detach(s, &mut sock_reuseport::lock());
        }
        if !core::ptr::eq(s2, n2) {
            let mut g2 = s2.head.lock();
            let u = g2.del_rcu(s);
            if u.is_some() {
                s2.count_add(&g2, -1);
            }
            drop(g2);
            if let Some(u) = u {
                let mut g2 = n2.head.lock();
                u.rehash(&mut g2);
                n2.count_add(&g2, 1);
            }
        }
    }
    s.portaddr_hash.store(new, Ordering::Relaxed);
}

/// A received datagram's addressing
#[derive(Clone, Copy)]
pub(super) struct Key {
    pub(super) saddr: Ipv4Addr,
    pub(super) sport: u16,
    pub(super) daddr: Ipv4Addr,
    pub(super) dport: u16,
    pub(super) dif: u32,
}

/// Linux compute_score for a lookup of local address `daddr`: -1 = no
/// match
fn score(s: &UdpSock, net: &NetNamespace, k: &Key, daddr: Ipv4Addr) -> i32 {
    let a = s.inet.get();
    if s.sk.net.id != net.id || a.sport != k.dport || a.rcv_saddr != daddr {
        return -1;
    }
    let mut sc = 2;
    if !a.daddr.is_unspecified() {
        if a.daddr != k.saddr {
            return -1;
        }
        sc += 4;
    }
    if a.dport != 0 {
        if a.dport != k.sport {
            return -1;
        }
        sc += 4;
    }
    let dev = s.sk.bound_dev_if();
    if dev != 0 {
        if dev != k.dif {
            return -1;
        }
        sc += 4;
    }
    sc
}

/// Linux udp_ehashfn: a keyed hash of the flow, for a reuseport pick
fn flow_hash(net: &NetNamespace, k: &Key) -> u32 {
    port::secure_hash(
        0x7564_7065_6861,
        &[
            net.id,
            (u64::from(k.saddr.0) << 32) | u64::from(k.daddr.0),
            (u64::from(k.sport) << 16) | u64::from(k.dport),
        ],
    ) as u32
}

/// Best socket on a hash2 slot for local address `daddr` (Linux
/// udp4_lib_lookup2): a better unconnected socket in a SO_REUSEPORT
/// group hands over to the member the flow hash picks, returned at once
/// unless the group has connected members, which rescore the pick
fn lookup2<'a>(
    net: &NetNamespace,
    k: &Key,
    daddr: Ipv4Addr,
    s2: &'a Slot<UdpHash2>,
    g: &'a RcuReadGuard,
) -> Option<&'a UdpSock> {
    let mut result: Option<&UdpSock> = None;
    let mut badness = 0;
    for e in s2.head.iter_rcu(g) {
        let s = e.get();
        let sc = score(s, net, k, daddr);
        if sc <= badness {
            continue;
        }
        badness = sc;
        if s.connected.load(Ordering::Acquire) || !s.sk.flag(sf::REUSEPORT) {
            result = Some(s);
            continue;
        }
        let est = |m: &UdpSock| m.connected.load(Ordering::Acquire);
        let Some((r, conns)) = s.reuse.select(flow_hash(net, k), g, est) else {
            result = Some(s);
            continue;
        };
        if !conns {
            return Some(r);
        }
        result = Some(r);
        badness = badness.max(score(r, net, k, daddr));
    }
    result
}

/// Best socket on the port slot (Linux udp4_lib_lookup1: the fallback
/// for a socket whose address changed before its rehash; groups
/// ignored)
fn lookup1<'a>(net: &NetNamespace, k: &Key, g: &'a RcuReadGuard) -> Option<&'a UdpSock> {
    let mut result = None;
    let mut badness = 0;
    for e in hslot(net, k.dport).head.iter_rcu(g) {
        let sc = score(e.get(), net, k, k.daddr);
        if sc > badness {
            result = Some(e.get());
            badness = sc;
        }
    }
    result
}

/// Socket for a unicast datagram or an ICMP error (Linux
/// __udp4_lib_lookup): connected or bound to `daddr`, else bound to
/// INADDR_ANY, else the port slot fallback
pub(super) fn lookup(net: &NetNamespace, k: &Key) -> Option<Arc<UdpSock>> {
    let g = crate::sync::rcu::read_lock();
    let s2 = hslot2(portaddr_hash(net, k.daddr, k.dport));
    let r = lookup2(net, k, k.daddr, s2, &g)
        .or_else(|| {
            let any = Ipv4Addr::default();
            lookup2(net, k, any, hslot2(portaddr_hash(net, any, k.dport)), &g)
        })
        .or_else(|| lookup1(net, k, &g));
    r.and_then(|s| s.me.upgrade())
}

/// Linux __udp_is_mcast_sock: broadcast and multicast receivers
fn mcast_match(s: &UdpSock, net: &NetNamespace, k: &Key) -> bool {
    let a = s.inet.get();
    let dev = s.sk.bound_dev_if();
    s.sk.net.id == net.id
        && a.sport == k.dport
        && (a.daddr.is_unspecified() || a.daddr == k.saddr)
        && (a.dport == 0 || a.dport == k.sport)
        && (a.rcv_saddr.is_unspecified() || a.rcv_saddr == k.daddr)
        && (dev == 0 || dev == k.dif)
}

/// `s`, if it matches, becomes `first` or gets a clone of `skb`
fn mcast_one<'a>(
    net: &NetNamespace,
    k: &Key,
    skb: &SkBuff,
    first: &mut Option<&'a UdpSock>,
    s: &'a UdpSock,
) {
    if !mcast_match(s, net, k) {
        return;
    }
    if first.is_none() {
        *first = Some(s);
        return;
    }
    match skb.clone_gfp(Gfp::ATOMIC) {
        Some(c) => super::queue_rcv(net, s, c),
        None => {
            s.sk.drops.fetch_add(1, Ordering::Relaxed);
            net.mib.udp.inc(UDP_MIB_RCVBUFERRORS);
            net.mib.udp.inc(UDP_MIB_INERRORS);
        }
    }
}

/// A broadcast or multicast datagram to every matching socket (Linux
/// __udp4_lib_mcast_deliver): the port slot, or when it is long the
/// hash2 slots of (daddr, port) and (INADDR_ANY, port). Each but the
/// first gets a clone made GFP_ATOMIC (a failed clone counts a drop on
/// that socket), the first the skb itself. Each slot is walked once,
/// never again from the start (that would deliver twice).
pub(super) fn mcast_deliver(net: &NetNamespace, skb: SkBuff, k: &Key) {
    let g = crate::sync::rcu::read_lock();
    let mut first: Option<&UdpSock> = None;
    let hs = hslot(net, k.dport);
    if hs.count() > 10 {
        let t = table();
        let any = portaddr_hash(net, Ipv4Addr::default(), k.dport) as usize & t.mask;
        let h2 = portaddr_hash(net, k.daddr, k.dport) as usize & t.mask;
        for e in t.hash2[h2].head.iter_rcu(&g) {
            mcast_one(net, k, &skb, &mut first, e.get());
        }
        if h2 != any {
            for e in t.hash2[any].head.iter_rcu(&g) {
                mcast_one(net, k, &skb, &mut first, e.get());
            }
        }
    } else {
        for e in hs.head.iter_rcu(&g) {
            mcast_one(net, k, &skb, &mut first, e.get());
        }
    }
    match first {
        Some(s) => super::queue_rcv(net, s, skb),
        None => net.mib.udp.inc(UDP_MIB_IGNOREDMULTI),
    }
}
