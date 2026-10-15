//! IPv4 input/output routing (Linux net/ipv4/route.c, without a route
//! cache: every call consults the FIB)
//!
//! `output()` picks the device, next hop and source address for a locally
//! generated packet (Linux ip_route_output_key_hash_rcu); `input()`
//! classifies a received one (Linux ip_route_input_slow, no forwarding).

use alloc::sync::Arc;

use crate::error::KernelError;
use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::fib::{FlowKey, RouteType};
use crate::net::inet::ifaddr::{RT_SCOPE_LINK, inet_select_addr, ip_dev_find};
use crate::net::ipv4::Ipv4Addr;

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
    if rt.rtype == RouteType::Unicast
        && let Some(m) = net.pmtu.get(rt.daddr)
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
    })
}

/// ip_rt_min_pmtu / ip_rt_mtu_expires
pub const MIN_PMTU: u32 = 552;
const PMTU_EXPIRES: u64 = 600_000;
/// Destinations remembered
const PMTU_MAX: usize = 256;

/// Learned path MTUs by destination (Linux fib_nh_exception PMTU part).
/// Peer-driven (ICMP frag needed), so bounded: at most `PMTU_MAX`
/// entries, the soonest-expiring evicted first; entries expire after
/// 10 minutes. `spin::Mutex` leaf, thread context only.
#[derive(Default)]
pub struct PmtuCache {
    m: spin::Mutex<alloc::collections::BTreeMap<Ipv4Addr, (u32, u64)>>,
}

impl PmtuCache {
    /// Learned MTU towards `daddr`, if still valid
    pub fn get(&self, daddr: Ipv4Addr) -> Option<u32> {
        let now = crate::net::neigh::now_ms();
        let mut m = self.m.lock();
        match m.get(&daddr) {
            Some(&(mtu, exp)) if exp > now => Some(mtu),
            Some(_) => {
                m.remove(&daddr);
                None
            }
            None => None,
        }
    }

    /// ICMP frag needed said `mtu` towards `daddr` (current route MTU
    /// `cur`): lower it, never below ip_rt_min_pmtu (Linux
    /// __ip_rt_update_pmtu)
    pub fn update(&self, daddr: Ipv4Addr, mtu: u32, cur: u32) {
        if mtu >= cur {
            return;
        }
        let mtu = if mtu < MIN_PMTU {
            cur.min(MIN_PMTU)
        } else {
            mtu
        };
        let now = crate::net::neigh::now_ms();
        let mut m = self.m.lock();
        if m.len() >= PMTU_MAX && !m.contains_key(&daddr) {
            let victim = m.iter().min_by_key(|(_, v)| v.1).map(|(k, _)| *k);
            if let Some(k) = victim {
                m.remove(&k);
            }
        }
        m.insert(daddr, (mtu, now + PMTU_EXPIRES));
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
        // lo only carries our own traffic
        return if daddr.is_unspecified() {
            IpInput::Drop("zero destination")
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
        let lo = |s, t| classify(s, t, true, |_| RouteType::Local);
        assert_eq!(lo(ip(127, 0, 0, 1), ip(127, 0, 0, 1)), IpInput::Local);
        assert_eq!(lo(ip(10, 0, 2, 15), ip(10, 0, 2, 15)), IpInput::Local);
        assert!(matches!(
            lo(ip(127, 0, 0, 1), ip(224, 0, 0, 1)),
            IpInput::Drop(_)
        ));
    }
}
