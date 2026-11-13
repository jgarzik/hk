//! IPv4 input/output routing (Linux net/ipv4/route.c, without a route
//! cache: every call consults the FIB)
//!
//! `output()` picks the device, next hop and source address for a locally
//! generated packet (Linux ip_route_output_key_hash_rcu); `input()`
//! classifies a received one (Linux ip_route_input_slow, no forwarding).
//! Learned path MTUs are exceptions on the route's nexthop (Linux
//! fib_nh_exception): chains per nexthop read under RCU, written under
//! the leaf spin lock `FNHE_LOCK`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

use crate::mm::page_alloc::Gfp;
use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::fib::{FibEntry, FlowKey, RouteType};
use crate::net::inet::ifaddr::{RT_SCOPE_LINK, inet_select_addr, ip_dev_find};
use crate::net::ipv4::Ipv4Addr;
use crate::sync::rcu::RcuPuts;
use crate::util::error::KernelError;
use crate::util::rcuhlist::{HNode, RcuHList};

/// An output route (Linux struct rtable)
#[derive(Clone)]
pub struct Rtable {
    /// Output device (`lo` for local destinations)
    pub dev: Arc<NetDevice>,
    /// Local, broadcast, multicast or unicast
    pub rtype: RouteType,
    /// Source address to use (may be unspecified if no address exists)
    pub saddr: Ipv4Addr,
    /// Destination
    pub daddr: Ipv4Addr,
    /// Gateway, if not on-link
    pub gateway: Option<Ipv4Addr>,
    /// Table the route came from (RT_TABLE_*; 0 if synthesized)
    pub table: u32,
    /// Path MTU: the device's, or less if learned (ICMP frag needed)
    pub mtu: u32,
    /// The route it came from (Linux the fib_info its nexthop is in),
    /// for a unicast route out of the FIB
    pub fi: Option<Arc<FibEntry>>,
}

impl Rtable {
    /// Next hop to resolve on the link
    pub fn nexthop(&self) -> Ipv4Addr {
        self.gateway.unwrap_or(self.daddr)
    }
}

fn zeronet(a: Ipv4Addr) -> bool {
    (a.0 >> 24) == 0
}

/// Route a locally generated packet to `daddr` from `saddr` (0 = pick
/// one) through `oif` (0 = any); the MTU reflects a learned path MTU
pub fn output(
    net: &NetNamespace,
    daddr: Ipv4Addr,
    saddr: Ipv4Addr,
    oif: u32,
) -> Result<Rtable, KernelError> {
    let mut rt = output_fib(net, daddr, saddr, oif)?;
    // Linux __mkroute_output: find_exception on the nexthop
    if rt.rtype == RouteType::Unicast
        && let Some(m) = rt.fi.as_ref().and_then(|fi| fi.exceptions.find(rt.daddr))
    {
        rt.mtu = rt.mtu.min(m);
    }
    Ok(rt)
}

fn output_fib(
    net: &NetNamespace,
    mut daddr: Ipv4Addr,
    mut saddr: Ipv4Addr,
    oif: u32,
) -> Result<Rtable, KernelError> {
    let lo = || net.loopback().ok_or(KernelError::NetworkUnreachable);
    if !saddr.is_unspecified() {
        let dev = src_dev(net, saddr)?;
        // Multicast / limited broadcast without oif leave through the
        // source address's device
        if oif == 0 && (daddr.is_multicast() || daddr.is_broadcast()) {
            return make(dev, daddr, saddr, None, 0);
        }
    }
    let mut odev = None;
    if oif != 0 {
        let dev = net.dev_get_by_index(oif).ok_or(KernelError::NoDevice)?;
        if !dev.is_up() {
            return Err(KernelError::NetworkUnreachable);
        }
        if daddr.is_broadcast() || daddr.is_multicast() {
            if saddr.is_unspecified() {
                saddr = inet_select_addr(net, &dev, Ipv4Addr(0), RT_SCOPE_LINK).unwrap_or_default();
            }
            return make(dev, daddr, saddr, None, 0);
        }
        odev = Some(dev);
    }
    if daddr.is_unspecified() {
        daddr = saddr;
        if daddr.is_unspecified() {
            daddr = Ipv4Addr::new(127, 0, 0, 1);
            saddr = daddr;
        }
        return make(lo()?, daddr, saddr, None, 0);
    }
    let key = FlowKey {
        daddr,
        oif,
        ..Default::default()
    };
    let res = match net.fib.lookup(&key) {
        Ok(r) => r,
        Err(e) => {
            // Linux: with an explicit oif, assume the destination is on link
            let Some(dev) = odev else {
                return Err(e);
            };
            if saddr.is_unspecified() {
                saddr = inet_select_addr(net, &dev, Ipv4Addr(0), RT_SCOPE_LINK).unwrap_or_default();
            }
            return make(dev, daddr, saddr, None, 0);
        }
    };
    if res.rtype == RouteType::Local {
        if saddr.is_unspecified() {
            saddr = res.prefsrc.unwrap_or(daddr);
        }
        let mut rt = make(lo()?, daddr, saddr, None, res.table)?;
        rt.rtype = RouteType::Local;
        return Ok(rt);
    }
    let dev = res.dev.clone().ok_or(KernelError::NetworkUnreachable)?;
    if saddr.is_unspecified() {
        saddr = match res.prefsrc {
            Some(p) => p,
            None => inet_select_addr(net, &dev, res.gateway.unwrap_or_default(), res.scope)
                .unwrap_or_default(),
        };
    }
    let gw = if res.rtype == RouteType::Broadcast {
        None
    } else {
        res.gateway
    };
    let mut rt = make(dev, daddr, saddr, gw, res.table)?;
    if res.rtype == RouteType::Broadcast {
        rt.rtype = RouteType::Broadcast;
    }
    rt.fi = Some(res);
    Ok(rt)
}

/// Validate a caller-chosen source address (Linux
/// ip_route_output_key_hash_rcu, no FLOWI_FLAG_ANYSRC: there is no
/// IP_TRANSPARENT; raw IP_HDRINCL senders do not route with their
/// header's source). Multicast and limited broadcast are EINVAL; any
/// other address that is not local in this namespace (inet_addr_type !=
/// RTN_LOCAL, so a deleted address too) is ENETUNREACH, which stops
/// source spoofing through IP_PKTINFO or a stale bound address. Returns
/// a device owning it (lo for addresses only covered by a local route).
fn src_dev(net: &NetNamespace, saddr: Ipv4Addr) -> Result<Arc<NetDevice>, KernelError> {
    if saddr.is_multicast() || saddr.is_broadcast() {
        return Err(KernelError::InvalidArgument);
    }
    if net.fib.addr_type(saddr) != RouteType::Local {
        return Err(KernelError::NetworkUnreachable);
    }
    ip_dev_find(net, saddr)
        .or_else(|| net.loopback())
        .ok_or(KernelError::NetworkUnreachable)
}

/// Linux __mkroute_output checks and type
fn make(
    dev: Arc<NetDevice>,
    daddr: Ipv4Addr,
    saddr: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    table: u32,
) -> Result<Rtable, KernelError> {
    if saddr.is_loopback() && !dev.is_loopback() {
        return Err(KernelError::InvalidArgument);
    }
    let rtype = if daddr.is_broadcast() {
        RouteType::Broadcast
    } else if daddr.is_multicast() {
        RouteType::Multicast
    } else if zeronet(daddr) {
        return Err(KernelError::InvalidArgument);
    } else {
        RouteType::Unicast
    };
    let gateway = if rtype == RouteType::Unicast {
        gateway
    } else {
        None
    };
    let mtu = dev.mtu();
    Ok(Rtable {
        dev,
        rtype,
        saddr,
        daddr,
        gateway,
        table,
        mtu,
        fi: None,
    })
}

/// ip_rt_min_pmtu / ip_rt_mtu_expires
pub const MIN_PMTU: u32 = 552;
const PMTU_EXPIRES: u64 = 600_000;

/// Exception chains per nexthop, and the depth past which the oldest
/// is reused (Linux FNHE_HASH_SHIFT, FNHE_RECLAIM_DEPTH)
const FNHE_HASH_SHIFT: u32 = 11;
const FNHE_HASH_SIZE: usize = 1 << FNHE_HASH_SHIFT;
const FNHE_RECLAIM_DEPTH: usize = 5;

/// The data of `FNHE_LOCK`: every nexthop's exception chains belong to
/// it (Linux fnhe_lock)
pub struct FnheLock(());

// SAFETY: the one value is FNHE_LOCK's, made by its initializer only
unsafe impl crate::sync::UniqueOwner for FnheLock {}

/// Serializes the writers of every nexthop's exceptions (Linux
/// fnhe_lock: a spin lock, leaf, thread context: ICMP input in softnet,
/// expiry found by route output)
static FNHE_LOCK: crate::sync::spin::Mutex<FnheLock> = crate::sync::spin::Mutex::new(FnheLock(()));

/// A learned exception for one destination through a nexthop (Linux
/// struct fib_nh_exception, its PMTU part). Peer-driven (ICMP frag
/// needed), so bounded per chain; it expires after 10 minutes.
pub struct FibNhException {
    daddr: Ipv4Addr,
    /// Path MTU (Linux fnhe_pmtu, READ_ONCE by readers)
    pmtu: AtomicU32,
    /// Expiry, ms (fnhe_expires)
    expires: AtomicU64,
    /// Last update, ms, to pick the oldest (fnhe_stamp)
    stamp: AtomicU64,
    /// On its chain (fnhe_next)
    link: HNode,
    rcu: RcuPuts,
}

crate::hadapter!(pub FnheLink, FibNhException, link);
crate::rcu_puts!(FibNhException, rcu);

type FnheChain = RcuHList<FnheLink, FnheLock>;

/// A nexthop's exceptions (Linux nhc_exceptions): the chains, allocated
/// at the first exception (GFP_ATOMIC under FNHE_LOCK, as Linux), read
/// under RCU; freed with the route, a grace period after it left its
/// table (so a replaced route's exceptions go with it)
#[derive(Default)]
pub struct NhExceptions(spin::Once<Box<[FnheChain]>>);

/// Linux fnhe_hashfun: the destination, keyed by a boot secret
fn fnhe_hashfun(daddr: Ipv4Addr) -> usize {
    static KEY: spin::Once<u32> = spin::Once::new();
    let k = *KEY.call_once(crate::random::get_random_u32);
    ((daddr.0 ^ k).wrapping_mul(0x61C8_8647) >> (32 - FNHE_HASH_SHIFT)) as usize
}

impl NhExceptions {
    /// The chain for `daddr`, if any exception exists on the nexthop
    fn chain(&self, daddr: Ipv4Addr) -> Option<&FnheChain> {
        self.0.get().map(|h| &h[fnhe_hashfun(daddr)])
    }

    /// The chains, made now if missing (Linux kzalloc GFP_ATOMIC under
    /// fnhe_lock); None without memory
    fn chains(&self, _o: &FnheLock) -> Option<&[FnheChain]> {
        if let Some(h) = self.0.get() {
            return Some(h);
        }
        let h = crate::util::kalloc::with_gfp(Gfp::ATOMIC, || {
            let mut v = alloc::vec::Vec::new();
            v.try_reserve_exact(FNHE_HASH_SIZE).ok()?;
            v.extend((0..FNHE_HASH_SIZE).map(|_| FnheChain::new()));
            Some(v.into_boxed_slice())
        })?;
        // Writers hold FNHE_LOCK: no other call_once races this one
        Some(self.0.call_once(|| h))
    }

    /// The valid path MTU learned towards `daddr`, if any (Linux
    /// find_exception: an expired one is deleted)
    pub fn find(&self, daddr: Ipv4Addr) -> Option<u32> {
        let chain = self.chain(daddr)?;
        let now = crate::net::neigh::now_ms();
        let expired = {
            let g = crate::sync::rcu::read_lock();
            let e = chain.iter(&g).find(|e| e.daddr == daddr)?;
            if e.expires.load(Relaxed) >= now {
                return Some(e.pmtu.load(Relaxed));
            }
            true
        };
        if expired {
            self.del(daddr);
        }
        None
    }

    /// Delete the exception for `daddr` (Linux ip_del_fnhe)
    fn del(&self, daddr: Ipv4Addr) {
        let Some(chain) = self.chain(daddr) else {
            return;
        };
        let mut o = FNHE_LOCK.lock();
        if let Some(gone) = chain.remove_first(|e| e.daddr == daddr, &mut o) {
            gone.defer();
        }
    }

    /// Record path MTU `pmtu` towards `daddr` until `expires` (Linux
    /// update_or_create_fnhe): an existing exception is updated in
    /// place; a new one is allocated GFP_ATOMIC under the lock, the
    /// oldest of a chain past its (randomized) depth removed first. No
    /// memory: nothing is learned.
    fn update(&self, daddr: Ipv4Addr, pmtu: u32, expires: u64) {
        let now = crate::net::neigh::now_ms();
        let mut o = FNHE_LOCK.lock();
        let Some(chains) = self.chains(&o) else {
            return;
        };
        let chain = &chains[fnhe_hashfun(daddr)];
        let mut depth = 0;
        if let Some(e) = chain
            .iter_locked(&o)
            .inspect(|_| depth += 1)
            .find(|e| e.daddr == daddr)
        {
            e.pmtu.store(pmtu, Relaxed);
            e.expires.store(expires.max(1), Relaxed);
            e.stamp.store(now, Relaxed);
            return;
        }
        // Randomized to avoid side channels (Linux)
        let max_depth =
            FNHE_RECLAIM_DEPTH + crate::random::get_random_u32() as usize % FNHE_RECLAIM_DEPTH;
        while depth > max_depth {
            fnhe_remove_oldest(chain, &mut o);
            depth -= 1;
        }
        let e = FibNhException {
            daddr,
            pmtu: AtomicU32::new(pmtu),
            expires: AtomicU64::new(expires.max(1)),
            stamp: AtomicU64::new(now),
            link: HNode::new(),
            rcu: RcuPuts::new(),
        };
        if let Ok(e) = crate::util::kalloc::try_arc_gfp(e, Gfp::ATOMIC) {
            chain.add_head(e, &mut o);
        }
    }
}

/// Remove a chain's least recently updated exception (Linux
/// fnhe_remove_oldest)
fn fnhe_remove_oldest(chain: &FnheChain, o: &mut FnheLock) {
    let oldest = chain
        .iter_locked(o)
        .min_by_key(|e| e.stamp.load(Relaxed))
        .map(|e| core::ptr::from_ref(e.item()));
    if let Some(p) = oldest
        && let Some(gone) = chain.remove_first(|e| core::ptr::eq(e, p), o)
    {
        gone.defer();
    }
}

/// ICMP frag needed said `mtu` on the path of `rt`: lower its path MTU,
/// never below ip_rt_min_pmtu, as an exception on its nexthop (Linux
/// __ip_rt_update_pmtu -> update_or_create_fnhe)
pub fn update_pmtu(rt: &Rtable, mtu: u32) {
    let cur = rt.mtu;
    if mtu >= cur {
        return;
    }
    let mtu = if mtu < MIN_PMTU {
        cur.min(MIN_PMTU)
    } else {
        mtu
    };
    if let Some(fi) = &rt.fi {
        let expires = crate::net::neigh::now_ms() + PMTU_EXPIRES;
        fi.exceptions.update(rt.daddr, mtu, expires);
    }
}

/// Input routing decision for a received IPv4 packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpInput {
    /// Unicast to one of our addresses
    Local,
    /// Limited (255.255.255.255) or a local-table broadcast address
    Broadcast,
    /// Dropped (reason, for debugging)
    Drop(&'static str),
}

/// Classify a packet received on `dev` (Linux ip_route_input_slow,
/// route_localnet=0, no forwarding, no multicast routing yet)
pub fn input(net: &NetNamespace, saddr: Ipv4Addr, daddr: Ipv4Addr, dev: &NetDevice) -> IpInput {
    classify(saddr, daddr, dev.is_loopback(), |a| net.fib.addr_type(a))
}

/// Pure classification: `loopback` = received on `lo` (already routed on
/// output); `addr_type` = Linux inet_addr_type (local table)
pub fn classify(
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
    loopback: bool,
    addr_type: impl Fn(Ipv4Addr) -> RouteType,
) -> IpInput {
    if daddr.is_multicast() {
        return IpInput::Drop("multicast destination");
    }
    if saddr.is_multicast() || saddr.is_broadcast() {
        return IpInput::Drop("martian source");
    }
    if loopback {
        // lo only carries our own traffic, already routed on output: a
        // broadcast keeps that route's type (Linux keeps the output
        // dst, RTCF_BROADCAST, on a looped skb)
        return if daddr.is_unspecified() {
            IpInput::Drop("zero destination")
        } else if daddr.is_broadcast() || addr_type(daddr) == RouteType::Broadcast {
            IpInput::Broadcast
        } else {
            IpInput::Local
        };
    }
    // On a real device, 127/8 is martian in either direction
    if saddr.is_loopback() || daddr.is_loopback() {
        return IpInput::Drop("loopback address on non-loopback device");
    }
    // Limited broadcast may come from 0.0.0.0 (DHCP)
    if daddr.is_broadcast() {
        return if saddr.is_unspecified() || addr_type(saddr) != RouteType::Local {
            IpInput::Broadcast
        } else {
            IpInput::Drop("martian source")
        };
    }
    if zeronet(saddr) {
        return IpInput::Drop("martian source (0.0.0.0/8)");
    }
    if zeronet(daddr) {
        return IpInput::Drop("martian destination (0.0.0.0/8)");
    }
    // Source validation: our own or a broadcast address is spoofed
    if matches!(addr_type(saddr), RouteType::Local | RouteType::Broadcast) {
        return IpInput::Drop("martian source");
    }
    match addr_type(daddr) {
        RouteType::Local => IpInput::Local,
        RouteType::Broadcast => IpInput::Broadcast,
        _ => IpInput::Drop("not for us (no forwarding)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// eth0 10.0.2.15/24 (local table: local .15, broadcast .255) + lo
    fn types(a: Ipv4Addr) -> RouteType {
        if a == ip(10, 0, 2, 15) || a.is_loopback() {
            RouteType::Local
        } else if a == ip(10, 0, 2, 255) || (a.0 >> 24) == 0 || a.is_broadcast() {
            RouteType::Broadcast
        } else {
            RouteType::Unicast
        }
    }

    fn eth(saddr: Ipv4Addr, daddr: Ipv4Addr) -> IpInput {
        classify(saddr, daddr, false, types)
    }

    #[test]
    fn unicast_to_us_is_local() {
        assert_eq!(eth(ip(10, 0, 2, 3), ip(10, 0, 2, 15)), IpInput::Local);
        assert_eq!(eth(ip(8, 8, 8, 8), ip(10, 0, 2, 15)), IpInput::Local);
    }

    #[test]
    fn other_hosts_are_not_forwarded() {
        assert!(matches!(
            eth(ip(10, 0, 2, 3), ip(10, 0, 2, 16)),
            IpInput::Drop(_)
        ));
    }

    #[test]
    fn broadcasts() {
        assert_eq!(
            eth(ip(10, 0, 2, 2), ip(255, 255, 255, 255)),
            IpInput::Broadcast
        );
        // DHCP: limited broadcast from 0.0.0.0
        assert_eq!(
            eth(ip(0, 0, 0, 0), ip(255, 255, 255, 255)),
            IpInput::Broadcast
        );
        assert_eq!(eth(ip(10, 0, 2, 2), ip(10, 0, 2, 255)), IpInput::Broadcast);
        // Zero source only for limited broadcast
        assert!(matches!(
            eth(ip(0, 0, 0, 0), ip(10, 0, 2, 255)),
            IpInput::Drop(_)
        ));
    }

    #[test]
    fn martians_dropped() {
        let d = |s, t| matches!(eth(s, t), IpInput::Drop(_));
        assert!(d(ip(127, 0, 0, 1), ip(10, 0, 2, 15)));
        assert!(d(ip(10, 0, 2, 3), ip(127, 0, 0, 1)));
        assert!(d(ip(224, 0, 0, 1), ip(10, 0, 2, 15)));
        assert!(d(ip(255, 255, 255, 255), ip(10, 0, 2, 15)));
        assert!(d(ip(0, 0, 0, 0), ip(10, 0, 2, 15)));
        assert!(d(ip(10, 0, 2, 3), ip(0, 0, 0, 0)));
        assert!(d(ip(10, 0, 2, 3), ip(224, 0, 0, 1)));
        assert!(d(ip(10, 0, 2, 255), ip(10, 0, 2, 15)));
        // Spoofed own address
        assert!(d(ip(10, 0, 2, 15), ip(10, 0, 2, 15)));
    }

    #[test]
    fn loopback_device() {
        let lo = |s, t| classify(s, t, true, types);
        assert_eq!(lo(ip(127, 0, 0, 1), ip(127, 0, 0, 1)), IpInput::Local);
        assert_eq!(lo(ip(127, 0, 0, 1), ip(10, 0, 2, 255)), IpInput::Broadcast);
        assert_eq!(lo(ip(10, 0, 2, 15), ip(10, 0, 2, 15)), IpInput::Local);
        assert!(matches!(
            lo(ip(127, 0, 0, 1), ip(224, 0, 0, 1)),
            IpInput::Drop(_)
        ));
    }

    /// An exception is found until deleted, updated in place, and a
    /// chain never grows past twice the reclaim depth
    #[test]
    fn exceptions() {
        let nh = NhExceptions::default();
        let d = ip(192, 0, 2, 1);
        assert_eq!(nh.find(d), None);
        let later = crate::net::neigh::now_ms() + 60_000;
        nh.update(d, 1400, later);
        assert_eq!(nh.find(d), Some(1400));
        nh.update(d, 1300, later);
        assert_eq!(nh.find(d), Some(1300));
        // Deleted (as an expired one is)
        nh.del(d);
        assert_eq!(nh.find(d), None);
        // Destinations on one chain (same hash) reuse the oldest
        let h = fnhe_hashfun(d);
        let same: alloc::vec::Vec<Ipv4Addr> = (0..u32::MAX)
            .map(|i| Ipv4Addr(d.0.wrapping_add(i)))
            .filter(|a| fnhe_hashfun(*a) == h)
            .take(3 * FNHE_RECLAIM_DEPTH)
            .collect();
        for a in &same {
            nh.update(*a, 1000, later);
        }
        let g = crate::sync::rcu::read_lock();
        let depth = nh.chain(d).unwrap().iter(&g).count();
        assert!(depth <= 2 * FNHE_RECLAIM_DEPTH, "depth {depth}");
        drop(g);
        assert_eq!(nh.find(*same.last().unwrap()), Some(1000));
    }
}
