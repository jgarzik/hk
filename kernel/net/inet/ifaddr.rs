//! IPv4 interface addresses (Linux net/ipv4/devinet.c)
//!
//! Each device keeps its protocol addresses in an [`IfAddrs`] (one list
//! per address family; IPv6 adds `inet6` later). An IPv4 address is an
//! [`InIfaddr`]: local address, prefix, optional broadcast, label, scope
//! and flags. Within a subnet the first address is primary and later ones
//! are `IFA_F_SECONDARY`, like Linux.
//!
//! Adding an address installs its FIB routes (`fib_add_ifaddr`): a local
//! /32 in table local always, and while the device is up the subnet
//! broadcast (local) and the prefix route (main, scope link). Deleting it
//! removes them again (`fib_del_ifaddr`); deleting a primary also deletes
//! its secondaries (Linux default, promote_secondaries=0).
//!
//! ## Locking
//!
//! All changes run under RTNL (callers pass the `RtnlGuard`); the per-device
//! list is a leaf `RwLock` read through snapshots, so the receive path never
//! needs RTNL. Order: RTNL -> device address list -> FIB tables -> netlink
//! socket queues (notifications).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::error::KernelError;
use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::fib::{self, RouteType};
use crate::net::ipv4::Ipv4Addr;
use crate::net::netlink::NlInfo;
use crate::net::netlink::rtnetlink;
use crate::net::rtnl::RtnlGuard;

/// Address flags (Linux IFA_F_*)
pub const IFA_F_SECONDARY: u32 = 0x01;
pub const IFA_F_NOPREFIXROUTE: u32 = 0x200;
pub const IFA_F_PERMANENT: u32 = 0x80;
/// Flags that only make sense for IPv6 (cleared on IPv4 addresses)
const IPV6ONLY_FLAGS: u32 = 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x100 | 0x800;

/// Route/address scopes (Linux RT_SCOPE_*)
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_HOST: u8 = 254;
pub const RT_SCOPE_NOWHERE: u8 = 255;

/// Infinite address lifetime
pub const INFINITY_LIFE_TIME: u32 = 0xFFFF_FFFF;

/// Linux IFNAMSIZ (label length limit incl. NUL)
pub const IFNAMSIZ: usize = 16;

/// One IPv4 address on a device (Linux struct in_ifaddr)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InIfaddr {
    /// Local address
    pub local: Ipv4Addr,
    /// Peer/prefix address (equal to `local` except point-to-point)
    pub address: Ipv4Addr,
    /// Prefix length
    pub prefixlen: u8,
    /// Broadcast address (unspecified = none)
    pub broadcast: Ipv4Addr,
    /// Label (device name, or "eth0:1" style alias)
    pub label: String,
    /// Scope (RT_SCOPE_*)
    pub scope: u8,
    /// IFA_F_* flags
    pub flags: u32,
    /// Metric of the prefix route
    pub rt_priority: u32,
    /// Originating protocol (IFA_PROTO)
    pub proto: u8,
}

impl InIfaddr {
    /// A permanent address `local/prefixlen` labelled `label`
    pub fn new(local: Ipv4Addr, prefixlen: u8, label: &str) -> Self {
        Self {
            local,
            address: local,
            prefixlen,
            broadcast: Ipv4Addr(0),
            label: String::from(label),
            scope: RT_SCOPE_UNIVERSE,
            flags: IFA_F_PERMANENT,
            rt_priority: 0,
            proto: 0,
        }
    }

    /// Netmask for the prefix
    pub fn mask(&self) -> Ipv4Addr {
        inet_make_mask(self.prefixlen)
    }

    /// Network prefix (address & mask)
    pub fn prefix(&self) -> Ipv4Addr {
        self.address.mask(self.mask())
    }

    /// Linux inet_ifa_match: `addr` lies in this address's subnet
    pub fn matches(&self, addr: Ipv4Addr) -> bool {
        (addr.0 ^ self.address.0) & self.mask().0 == 0
    }

    /// Secondary address
    pub fn is_secondary(&self) -> bool {
        self.flags & IFA_F_SECONDARY != 0
    }
}

/// Netmask with `prefixlen` leading ones
pub fn inet_make_mask(prefixlen: u8) -> Ipv4Addr {
    match prefixlen {
        0 => Ipv4Addr(0),
        n if n >= 32 => Ipv4Addr(u32::MAX),
        n => Ipv4Addr(u32::MAX << (32 - n as u32)),
    }
}

/// Prefix length of a contiguous netmask, or None (Linux bad_mask)
pub fn inet_mask_len(mask: Ipv4Addr) -> Option<u8> {
    let ones = mask.0.leading_ones();
    if mask.0.checked_shl(ones).unwrap_or(0) != 0 {
        return None;
    }
    Some(ones as u8)
}

/// Per-device protocol addresses, one list per family
#[derive(Default)]
pub struct IfAddrs {
    /// IPv4 addresses: primaries (by scope) then secondaries
    pub inet: Vec<InIfaddr>,
}

// ============================================================================
// Queries (no RTNL needed)
// ============================================================================

/// Linux inet_select_addr: a source address on `dev` with scope <= `scope`
/// (preferring one in `dst`'s subnet), else any non-link-scope primary of
/// another device in the namespace
pub fn inet_select_addr(
    net: &NetNamespace,
    dev: &NetDevice,
    dst: Ipv4Addr,
    scope: u8,
) -> Option<Ipv4Addr> {
    let mut first = None;
    for ifa in dev.inet_addrs() {
        if ifa.is_secondary() || ifa.scope > scope {
            continue;
        }
        if dst.is_unspecified() || ifa.matches(dst) {
            return Some(ifa.local);
        }
        if first.is_none() {
            first = Some(ifa.local);
        }
    }
    if first.is_some() {
        return first;
    }
    // Any device (lo first, so 127.0.0.1 is never preferred here: its
    // scope is host)
    for d in net.devices() {
        for ifa in d.inet_addrs() {
            if !ifa.is_secondary() && ifa.scope != RT_SCOPE_LINK && ifa.scope <= scope {
                return Some(ifa.local);
            }
        }
    }
    None
}

/// Device owning local address `addr` (Linux __ip_dev_find)
pub fn ip_dev_find(net: &NetNamespace, addr: Ipv4Addr) -> Option<Arc<NetDevice>> {
    net.devices()
        .into_iter()
        .find(|d| d.inet_addrs().iter().any(|a| a.local == addr))
}

// ============================================================================
// Changes (RTNL held)
// ============================================================================

/// Insert `ifa` on `dev` (Linux __inet_insert_ifa): EEXIST for the same
/// local address in the same subnet; secondaries are detected here. The
/// RTM_NEWADDR notification precedes the FIB update like Linux.
pub fn inet_insert_ifa(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &Arc<NetDevice>,
    mut ifa: InIfaddr,
    nl: NlInfo,
) -> Result<(), KernelError> {
    ifa.flags &= !(IFA_F_SECONDARY | IPV6ONLY_FLAGS);
    let inserted = dev.addrs_mut(|a| {
        let mut last_primary = 0;
        for (i, ifa1) in a.inet.iter().enumerate() {
            if !ifa1.is_secondary() && ifa.scope <= ifa1.scope {
                last_primary = i + 1;
            }
            if ifa1.prefixlen == ifa.prefixlen && ifa.matches(ifa1.address) {
                if ifa1.local == ifa.local {
                    return Err(KernelError::AlreadyExists);
                }
                if ifa1.scope != ifa.scope {
                    return Err(KernelError::InvalidArgument);
                }
                ifa.flags |= IFA_F_SECONDARY;
            }
        }
        if ifa.is_secondary() {
            a.inet.push(ifa.clone());
        } else {
            a.inet.insert(last_primary, ifa.clone());
        }
        Ok(ifa)
    })?;
    rtnetlink::notify_addr(net, dev, &inserted, rtnetlink::RTM_NEWADDR, nl);
    fib::fib_add_ifaddr(rtnl, net, dev, &inserted);
    Ok(())
}

/// Delete the address equal to `ifa` from `dev` (Linux __inet_del_ifa
/// with promote_secondaries=0: a primary takes its secondaries along)
pub fn inet_del_ifa(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &Arc<NetDevice>,
    ifa: &InIfaddr,
    nl: NlInfo,
) {
    let removed: Vec<InIfaddr> = dev.addrs_mut(|a| {
        let Some(pos) = a.inet.iter().position(|x| x == ifa) else {
            return Vec::new();
        };
        let victim = a.inet.remove(pos);
        let mut out = Vec::new();
        if !victim.is_secondary() {
            // Secondaries of the same subnet go first (announced first)
            a.inet.retain(|x| {
                let dead = x.is_secondary()
                    && x.prefixlen == victim.prefixlen
                    && victim.matches(x.address);
                if dead {
                    out.push(x.clone());
                }
                !dead
            });
        }
        out.push(victim);
        out
    });
    for x in &removed {
        rtnetlink::notify_addr(net, dev, x, rtnetlink::RTM_DELADDR, nl);
        fib::fib_del_ifaddr(rtnl, net, dev, x);
    }
}

/// Update an existing address in place (NLM_F_REPLACE): metric, proto,
/// non-structural flags. Re-announced with RTM_NEWADDR.
pub fn inet_replace_ifa(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &Arc<NetDevice>,
    new: &InIfaddr,
    nl: NlInfo,
) {
    let updated = dev.addrs_mut(|a| {
        let x = a.inet.iter_mut().find(|x| {
            x.local == new.local && x.prefixlen == new.prefixlen && x.matches(new.address)
        })?;
        let secondary = x.flags & IFA_F_SECONDARY;
        x.flags = (new.flags & !(IFA_F_SECONDARY | IPV6ONLY_FLAGS)) | secondary;
        x.rt_priority = new.rt_priority;
        x.proto = new.proto;
        Some(x.clone())
    });
    if let Some(x) = updated {
        rtnetlink::notify_addr(net, dev, &x, rtnetlink::RTM_NEWADDR, nl);
        fib::fib_add_ifaddr(rtnl, net, dev, &x);
    }
}

/// Device came up (Linux inetdev_event/fib_netdev_event NETDEV_UP): `lo`
/// gets 127.0.0.1/8 if it has no address; every address's routes are
/// (re)installed
pub fn inetdev_up(rtnl: &RtnlGuard, net: &NetNamespace, dev: &Arc<NetDevice>) {
    if dev.is_loopback() && dev.inet_addrs().is_empty() {
        let mut ifa = InIfaddr::new(Ipv4Addr::new(127, 0, 0, 1), 8, dev.name());
        ifa.scope = RT_SCOPE_HOST;
        let _ = inet_insert_ifa(rtnl, net, dev, ifa, NlInfo::default());
    }
    for ifa in dev.inet_addrs() {
        fib::fib_add_ifaddr(rtnl, net, dev, &ifa);
    }
}

/// Device went down (Linux fib_netdev_event NETDEV_DOWN): routes through
/// it go, except host-scope (local) ones
pub fn inetdev_down(rtnl: &RtnlGuard, net: &NetNamespace, dev: &Arc<NetDevice>) {
    fib::fib_disable_dev(rtnl, net, dev, false);
    net.arp_flush_dev(dev.ifindex());
}

/// Type of `addr` in the namespace (Linux inet_addr_type)
pub fn inet_addr_type(net: &NetNamespace, addr: Ipv4Addr) -> RouteType {
    net.fib.addr_type(addr)
}
