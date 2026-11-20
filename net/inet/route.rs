//! IPv4 input/output routing (Linux net/ipv4/route.c, without a route
//! cache: every call consults the FIB)
//!
//! `output()` picks the device, next hop and source address for a locally
//! generated packet (Linux ip_route_output_key_hash_rcu); `input()`
//! classifies a received one (Linux ip_route_input_slow, no forwarding).
//! Learned path MTUs are exceptions on the route's nexthop (Linux
//! fib_nh_exception): chains per nexthop read under RCU, written under
//! the leaf spin lock `FNHE_LOCK`. A write to net.ipv4.route.flush
//! starts a new exception generation (Linux fnhe_genid): an exception
//! of an older one counts as reset when next found. With no route
//! cache, there is no cached route to expire (Linux rt_genid).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

use crate::mm::page_alloc::Gfp;
use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::fib::{FibEntry, FlowKey, RouteType};
use crate::net::inet::ifaddr::{RT_SCOPE_LINK, inet_select_addr, ip_dev_find};
use crate::net::ipv4::Ipv4Addr;
use crate::sync::rcu::RcuHead;
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
    // Linux __mkroute_output: find_exception on the nexthop, then
    // rt_bind_exception
    let genid = fnhe_genid(net);
    if rt.rtype == RouteType::Unicast
        && let Some(m) = rt
            .fi
            .as_ref()
            .and_then(|fi| fi.exceptions.find(rt.daddr, genid))
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
    /// Generation it was learned in (Linux fnhe_genid), under FNHE_LOCK
    genid: AtomicU32,
    /// Path MTU, 0 = none (Linux fnhe_pmtu, READ_ONCE by readers)
    pmtu: AtomicU32,
    /// Expiry, ms; 0 = never (fnhe_expires)
    expires: AtomicU64,
    /// Last update, ms, to pick the oldest (fnhe_stamp)
    stamp: AtomicU64,
    /// On its chain (fnhe_next)
    link: HNode,
    rcu: RcuHead,
}

crate::hadapter!(pub FnheLink, FibNhException, link);
crate::rcu_head!(FibNhException, rcu);

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

    /// The valid path MTU learned towards `daddr` in generation
    /// `genid`, if any: an expired exception is deleted (Linux
    /// find_exception), one of an older generation reset
    /// (rt_bind_exception)
    pub fn find(&self, daddr: Ipv4Addr, genid: u32) -> Option<u32> {
        let chain = self.chain(daddr)?;
        let now = crate::net::neigh::now_ms();
        {
            let g = crate::sync::rcu::read_lock();
            let e = chain.iter(&g).find(|e| e.daddr == daddr)?;
            let exp = e.expires.load(Relaxed);
            if exp == 0 || exp >= now {
                if e.genid.load(Relaxed) == genid {
                    return Some(e.pmtu.load(Relaxed)).filter(|&m| m != 0);
                }
                drop(g);
                self.reset_stale(daddr, genid);
                return None;
            }
        }
        self.del(daddr);
        None
    }

    /// Reset the exception for `daddr` if it is of a generation other
    /// than `genid` (Linux rt_bind_exception under fnhe_lock: no path
    /// MTU, no expiry, the current generation)
    fn reset_stale(&self, daddr: Ipv4Addr, genid: u32) {
        let Some(chain) = self.chain(daddr) else {
            return;
        };
        let o = FNHE_LOCK.lock();
        if let Some(e) = chain.iter_locked(&o).find(|e| e.daddr == daddr)
            && e.genid.load(Relaxed) != genid
        {
            e.genid.store(genid, Relaxed);
            e.pmtu.store(0, Relaxed);
            e.expires.store(0, Relaxed);
        }
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

    /// Record path MTU `pmtu` towards `daddr` until `expires`, in
    /// generation `genid` (Linux update_or_create_fnhe): an existing
    /// exception is updated in place; a new one is allocated GFP_ATOMIC
    /// under the lock, the oldest of a chain past its (randomized)
    /// depth removed first. No memory: nothing is learned.
    fn update(&self, daddr: Ipv4Addr, pmtu: u32, expires: u64, genid: u32) {
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
            e.genid.store(genid, Relaxed);
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
            genid: AtomicU32::new(genid),
            pmtu: AtomicU32::new(pmtu),
            expires: AtomicU64::new(expires.max(1)),
            stamp: AtomicU64::new(now),
            link: HNode::new(),
            rcu: RcuHead::new(),
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
pub fn update_pmtu(net: &NetNamespace, rt: &Rtable, mtu: u32) {
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
        fi.exceptions
            .update(rt.daddr, mtu, expires, fnhe_genid(net));
    }
}

/// The current exception generation (Linux fnhe_genid)
fn fnhe_genid(net: &NetNamespace) -> u32 {
    net.fnhe_genid.load(Relaxed)
}

/// Start a new exception generation (Linux fnhe_genid_bump)
pub fn fnhe_genid_bump(net: &NetNamespace) {
    net.fnhe_genid.fetch_add(1, Relaxed);
}

/// net.ipv4.route.flush: any write flushes the route cache (Linux
/// ipv4_sysctl_rtcache_flush: rt_cache_flush, which has nothing to do
/// without one, then fnhe_genid_bump); write-only
fn rtcache_flush(_: &str) -> Result<(), KernelError> {
    fnhe_genid_bump(&crate::net::current_net_ns());
    Ok(())
}

/// The /proc/sys/net/ipv4/route files (Linux ipv4_route_table subset)
pub static ROUTE_CTLS: &[crate::sysctl::Ctl] = &[crate::sysctl::Ctl {
    path: "net/ipv4/route/flush",
    mode: 0o200,
    show: alloc::vec::Vec::new,
    store: |_| Ok(()),
    text: Some(crate::sysctl::Text {
        show: String::new,
        store: rtcache_flush,
    }),
}];

/// Input routing decision for a received IPv4 packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpInput {
    /// Unicast to one of our addresses
    Local,
    /// Limited (255.255.255.255) or a local-table broadcast address
    Broadcast,
    /// Not ours, and we do not forward (Linux no_route with
    /// forwarding off: an RTN_UNREACHABLE dst, -EHOSTUNREACH, whose
    /// ip_error counts InAddrErrors)
    HostUnreach,
    /// Dropped (reason, for debugging)
    Drop(&'static str),
}

/// Classify a packet received on `dev` (Linux ip_route_input_slow,
/// route_localnet=0, no forwarding, no multicast routing yet)
pub fn input(net: &NetNamespace, saddr: Ipv4Addr, daddr: Ipv4Addr, dev: &NetDevice) -> IpInput {
    classify_in(net, saddr, daddr, dev.is_loopback())
}

/// `classify` against `net`'s tables and addresses
pub fn classify_in(
    net: &NetNamespace,
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
    loopback: bool,
) -> IpInput {
    classify(
        saddr,
        daddr,
        loopback,
        |a| net.fib.addr_type(a),
        |a| crate::net::inet::ifaddr::ip_dev_find(net, a).is_some(),
    )
}

/// Pure classification: `loopback` = received on `lo` (already routed on
/// output); `addr_type` = Linux inet_addr_type (local table); `ours` =
/// an address assigned to one of the namespace's devices (Linux
/// inet_lookup_ifaddr_rcu)
pub fn classify(
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
    loopback: bool,
    addr_type: impl Fn(Ipv4Addr) -> RouteType,
    ours: impl Fn(Ipv4Addr) -> bool,
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
    // Limited broadcast may come from 0.0.0.0 (DHCP); another source is
    // validated (Linux brd_input's fib_validate_source)
    if daddr.is_broadcast() {
        return if saddr.is_unspecified() || !ours(saddr) {
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
    // Source validation (Linux fib_validate_source with rp_filter off,
    // its default, and no custom local routes or rules): one of our own
    // addresses is spoofed
    if ours(saddr) {
        return IpInput::Drop("martian source");
    }
    match addr_type(daddr) {
        RouteType::Local => IpInput::Local,
        RouteType::Broadcast => IpInput::Broadcast,
        _ => IpInput::HostUnreach,
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

    /// Assigned addresses: eth0's and lo's
    fn ours(a: Ipv4Addr) -> bool {
        a == ip(10, 0, 2, 15) || a == ip(127, 0, 0, 1)
    }

    fn eth(saddr: Ipv4Addr, daddr: Ipv4Addr) -> IpInput {
        classify(saddr, daddr, false, types, ours)
    }

    #[test]
    fn unicast_to_us_is_local() {
        assert_eq!(eth(ip(10, 0, 2, 3), ip(10, 0, 2, 15)), IpInput::Local);
        assert_eq!(eth(ip(8, 8, 8, 8), ip(10, 0, 2, 15)), IpInput::Local);
    }

    #[test]
    fn other_hosts_are_not_forwarded() {
        assert_eq!(eth(ip(10, 0, 2, 3), ip(10, 0, 2, 16)), IpInput::HostUnreach);
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
        // Spoofed own address
        assert!(d(ip(10, 0, 2, 15), ip(10, 0, 2, 15)));
        assert!(d(ip(10, 0, 2, 15), ip(255, 255, 255, 255)));
    }

    /// With rp_filter off only assigned addresses are spoofed sources
    /// (Linux fib_validate_source's inet_lookup_ifaddr_rcu): a subnet
    /// broadcast source, or another address a local route covers, is not
    #[test]
    fn source_validated_by_address() {
        assert_eq!(eth(ip(10, 0, 2, 255), ip(10, 0, 2, 15)), IpInput::Local);
        let lo24 = |a: Ipv4Addr| {
            if (a.0 >> 8) == u32::from_be_bytes([0, 10, 9, 9]) {
                RouteType::Local
            } else {
                types(a)
            }
        };
        let r = classify(ip(10, 9, 9, 2), ip(10, 9, 9, 1), false, lo24, |a| {
            a == ip(10, 9, 9, 1)
        });
        assert_eq!(r, IpInput::Local);
    }

    #[test]
    fn loopback_device() {
        let lo = |s, t| classify(s, t, true, types, ours);
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
        assert_eq!(nh.find(d, 0), None);
        let later = crate::net::neigh::now_ms() + 60_000;
        nh.update(d, 1400, later, 0);
        assert_eq!(nh.find(d, 0), Some(1400));
        nh.update(d, 1300, later, 0);
        assert_eq!(nh.find(d, 0), Some(1300));
        // Deleted (as an expired one is)
        nh.del(d);
        assert_eq!(nh.find(d, 0), None);
        // Destinations on one chain (same hash) reuse the oldest
        let h = fnhe_hashfun(d);
        let same: alloc::vec::Vec<Ipv4Addr> = (0..u32::MAX)
            .map(|i| Ipv4Addr(d.0.wrapping_add(i)))
            .filter(|a| fnhe_hashfun(*a) == h)
            .take(3 * FNHE_RECLAIM_DEPTH)
            .collect();
        for a in &same {
            nh.update(*a, 1000, later, 0);
        }
        let g = crate::sync::rcu::read_lock();
        let depth = nh.chain(d).unwrap().iter(&g).count();
        assert!(depth <= 2 * FNHE_RECLAIM_DEPTH, "depth {depth}");
        drop(g);
        assert_eq!(nh.find(*same.last().unwrap(), 0), Some(1000));
    }

    /// After a flush (a new generation) an exception counts as reset:
    /// no path MTU, also for the old generation, until learned again
    #[test]
    fn exception_generations() {
        let nh = NhExceptions::default();
        let d = ip(198, 51, 100, 9);
        let later = crate::net::neigh::now_ms() + 60_000;
        nh.update(d, 1280, later, 4);
        assert_eq!(nh.find(d, 4), Some(1280));
        assert_eq!(nh.find(d, 5), None);
        assert_eq!(nh.find(d, 5), None);
        assert_eq!(nh.find(d, 4), None);
        let g = crate::sync::rcu::read_lock();
        assert_eq!(nh.chain(d).unwrap().iter(&g).count(), 1);
        drop(g);
        nh.update(d, 1300, later, 5);
        assert_eq!(nh.find(d, 5), Some(1300));
    }
}
