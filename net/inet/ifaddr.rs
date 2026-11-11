//! IPv4 interface addresses (Linux net/ipv4/devinet.c)
//!
//! Each device keeps its IPv4 addresses on its [`InDevice`]'s
//! `ifa_list` (Linux in_device; IPv6 gets an `inet6_dev` sibling). An
//! address is an [`InIfaddr`]: local address, prefix, optional
//! broadcast, label, scope and flags. Within a subnet the first address
//! is primary and later ones are `IFA_F_SECONDARY`, like Linux: the
//! list holds the primaries (by scope, in insertion order) and then the
//! secondaries. Every address is also on the namespace-keyed hash
//! `INET_ADDR_LST` by local address (Linux inet_addr_lst), for
//! `ip_dev_find`.
//!
//! Adding an address installs its FIB routes (`fib_add_ifaddr`): a local
//! /32 in table local always, and while the device is up the subnet
//! broadcast (local) and the prefix route (main, scope link). Deleting it
//! removes them again (`fib_del_ifaddr`); deleting a primary also deletes
//! its secondaries (Linux default, promote_secondaries=0).
//!
//! ## Locking
//!
//! Writers hold RTNL (callers pass the `RtnlGuard`) and the lists' own
//! leaf writer locks; readers (source selection on transmit, possibly
//! under a socket lock, `ip_dev_find`, dumps) walk the lists under
//! `rcu::read_lock`, with no lock and no copy (Linux
//! in_dev_for_each_ifa_rcu). An address deleted is freed a grace period
//! later (`RcuUnlinked::defer_with`, Linux inet_free_ifa's call_rcu).
//! Its address fields never change once it is listed; `flags`,
//! `rt_priority` and `proto` change in place under RTNL (NLM_F_REPLACE)
//! and are read without it (Linux READ_ONCE). Order: RTNL -> address
//! lists -> FIB -> netlink socket queues (notifications).

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering::Relaxed};

use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::fib::{self, RouteType};
use crate::net::ipv4::Ipv4Addr;
use crate::net::netlink::NlInfo;
use crate::net::netlink::rtnetlink;
use crate::net::rtnl::RtnlGuard;
use crate::sync::rcu::{RcuHead, RcuReadGuard};
use crate::util::error::KernelError;
use crate::util::list::Link;
use crate::util::rculist::{RcuIter, RcuList, RcuUnlinked};

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

/// An address label (Linux ifa_label[IFNAMSIZ]): at most 15 bytes,
/// NUL-padded, held inline
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IfaLabel([u8; IFNAMSIZ]);

impl IfaLabel {
    /// `s`, cut at 15 bytes (on a character boundary)
    pub fn new(s: &str) -> Self {
        let mut n = s.len().min(IFNAMSIZ - 1);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        let mut b = [0; IFNAMSIZ];
        b[..n].copy_from_slice(&s.as_bytes()[..n]);
        Self(b)
    }

    pub fn as_str(&self) -> &str {
        let n = self.0.iter().position(|&c| c == 0).unwrap_or(IFNAMSIZ);
        // Built from a str cut on a character boundary
        core::str::from_utf8(&self.0[..n]).unwrap_or("")
    }
}

impl core::fmt::Debug for IfaLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One IPv4 address on a device (Linux struct in_ifaddr). Built
/// unlinked, then given to `inet_insert_ifa`, which shares it.
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
    pub label: IfaLabel,
    /// Scope (RT_SCOPE_*)
    pub scope: u8,
    /// IFA_F_* flags (Linux ifa_flags, READ_ONCE by readers)
    flags: AtomicU32,
    /// Metric of the prefix route
    rt_priority: AtomicU32,
    /// Originating protocol (IFA_PROTO)
    proto: AtomicU8,
    /// The device it is on (Linux ifa_dev), set when inserted
    dev: Weak<NetDevice>,
    /// Its device's namespace (`NetNamespace::id`), the hash key's half
    net_id: u64,
    /// On its device's `ifa_list`
    ifa_link: Link,
    /// On its `INET_ADDR_LST` chain (Linux ifa->hash)
    hash: Link,
    /// Freed through it a grace period after it leaves both lists
    rcu: RcuHead,
}

crate::adapter!(pub IfaList, InIfaddr, ifa_link);
crate::adapter!(IfaHash, InIfaddr, hash);
crate::rcu_head!(InIfaddr, rcu);

impl InIfaddr {
    /// A permanent address `local/prefixlen` labelled `label`
    pub fn new(local: Ipv4Addr, prefixlen: u8, label: &str) -> Self {
        Self {
            local,
            address: local,
            prefixlen,
            broadcast: Ipv4Addr(0),
            label: IfaLabel::new(label),
            scope: RT_SCOPE_UNIVERSE,
            flags: AtomicU32::new(IFA_F_PERMANENT),
            rt_priority: AtomicU32::new(0),
            proto: AtomicU8::new(0),
            dev: Weak::new(),
            net_id: 0,
            ifa_link: Link::new(),
            hash: Link::new(),
            rcu: RcuHead::new(),
        }
    }

    /// An unlinked copy, to build a changed address from
    pub fn dup(&self) -> Self {
        let mut n = Self::new(self.local, self.prefixlen, self.label.as_str());
        n.address = self.address;
        n.broadcast = self.broadcast;
        n.scope = self.scope;
        n.set_flags(self.flags());
        n.set_rt_priority(self.rt_priority());
        n.set_proto(self.proto());
        n
    }

    /// IFA_F_* flags
    pub fn flags(&self) -> u32 {
        self.flags.load(Relaxed)
    }

    pub fn set_flags(&self, v: u32) {
        self.flags.store(v, Relaxed);
    }

    /// Metric of the prefix route
    pub fn rt_priority(&self) -> u32 {
        self.rt_priority.load(Relaxed)
    }

    pub fn set_rt_priority(&self, v: u32) {
        self.rt_priority.store(v, Relaxed);
    }

    /// Originating protocol (IFA_PROTO)
    pub fn proto(&self) -> u8 {
        self.proto.load(Relaxed)
    }

    pub fn set_proto(&self, v: u8) {
        self.proto.store(v, Relaxed);
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
        self.flags() & IFA_F_SECONDARY != 0
    }

    /// Same subnet as `o` (Linux: equal ifa_mask, inet_ifa_match)
    pub fn same_subnet(&self, o: &InIfaddr) -> bool {
        self.prefixlen == o.prefixlen && self.matches(o.address)
    }
}

/// Netmask with `prefixlen` leading ones
pub fn inet_make_mask(prefixlen: u8) -> Ipv4Addr {
    match prefixlen {
        0 => Ipv4Addr(0),
        n if n >= 32 => Ipv4Addr(u32::MAX),
        n => Ipv4Addr(u32::MAX << (32 - u32::from(n))),
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

/// A device's IPv4 state (Linux struct in_device)
#[derive(Default)]
pub struct InDevice {
    /// Addresses: primaries (by scope) then secondaries (Linux
    /// ifa_list); read under RCU, changed under RTNL
    pub ifa_list: RcuList<IfaList>,
}

impl InDevice {
    /// The addresses, while `g` is held (Linux in_dev_for_each_ifa_rcu)
    pub fn addrs<'a>(&'a self, g: &'a RcuReadGuard) -> RcuIter<'a, IfaList> {
        self.ifa_list.iter(g)
    }

    /// Any address
    pub fn has_addrs(&self) -> bool {
        !self.ifa_list.is_empty()
    }
}

/// Buckets of `INET_ADDR_LST` (Linux IN4_ADDR_HSIZE)
const IN4_ADDR_HSIZE_SHIFT: u32 = 8;
const IN4_ADDR_HSIZE: usize = 1 << IN4_ADDR_HSIZE_SHIFT;

/// Every namespace's addresses by (namespace, local address) (Linux
/// inet_addr_lst): read under RCU, changed under RTNL
static INET_ADDR_LST: [RcuList<IfaHash>; IN4_ADDR_HSIZE] =
    [const { RcuList::new() }; IN4_ADDR_HSIZE];

/// Linux inet_addr_hash: the address mixed with the namespace, hash_32
fn inet_addr_hash(net_id: u64, addr: Ipv4Addr) -> usize {
    let val = addr.0 ^ (net_id as u32); // the low half mixes enough
    (val.wrapping_mul(0x61C8_8647) >> (32 - IN4_ADDR_HSIZE_SHIFT)) as usize
}

fn hash_chain(ifa: &InIfaddr) -> &'static RcuList<IfaHash> {
    &INET_ADDR_LST[inet_addr_hash(ifa.net_id, ifa.local)]
}

// ============================================================================
// Queries (no RTNL needed)
// ============================================================================

/// Linux inet_select_addr: a source address on `dev` with scope <= `scope`
/// (preferring one in `dst`'s subnet), else any non-link-scope primary of
/// another device in the namespace; walked under RCU, no copy
pub fn inet_select_addr(
    net: &NetNamespace,
    dev: &NetDevice,
    dst: Ipv4Addr,
    scope: u8,
) -> Option<Ipv4Addr> {
    let g = crate::sync::rcu::read_lock();
    let mut first = None;
    for ifa in dev.in_dev().addrs(&g) {
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
    // scope is host); Linux in_dev_select_addr
    net.devices_rcu(&g).find_map(|d| {
        d.in_dev()
            .addrs(&g)
            .find(|ifa| !ifa.is_secondary() && ifa.scope != RT_SCOPE_LINK && ifa.scope <= scope)
            .map(|ifa| ifa.local)
    })
}

/// Device owning local address `addr` (Linux __ip_dev_find, by the
/// address hash under RCU)
pub fn ip_dev_find(net: &NetNamespace, addr: Ipv4Addr) -> Option<Arc<NetDevice>> {
    let g = crate::sync::rcu::read_lock();
    INET_ADDR_LST[inet_addr_hash(net.id, addr)]
        .iter(&g)
        .find(|ifa| ifa.local == addr && ifa.net_id == net.id)
        .and_then(|ifa| ifa.dev.upgrade())
}

// ============================================================================
// Changes (RTNL held)
// ============================================================================

/// Insert `ifa` on `dev` (Linux __inet_insert_ifa): EEXIST for the same
/// local address in the same subnet; secondaries are detected here. A
/// primary goes after the last primary of its scope or a wider one,
/// a secondary last. The RTM_NEWADDR notification precedes the FIB
/// update like Linux.
pub fn inet_insert_ifa(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &Arc<NetDevice>,
    mut ifa: InIfaddr,
    nl: NlInfo,
) -> Result<(), KernelError> {
    ifa.set_flags(ifa.flags() & !(IFA_F_SECONDARY | IPV6ONLY_FLAGS));
    let mut last_primary: *const InIfaddr = core::ptr::null();
    {
        let g = crate::sync::rcu::read_lock();
        for ifa1 in dev.in_dev().addrs(&g) {
            if !ifa1.is_secondary() && ifa.scope <= ifa1.scope {
                last_primary = ifa1;
            }
            if ifa1.same_subnet(&ifa) {
                if ifa1.local == ifa.local {
                    return Err(KernelError::AlreadyExists);
                }
                if ifa1.scope != ifa.scope {
                    return Err(KernelError::InvalidArgument);
                }
                ifa.set_flags(ifa.flags() | IFA_F_SECONDARY);
            }
        }
    }
    ifa.dev = Arc::downgrade(dev);
    ifa.net_id = net.id;
    let ifa = crate::util::kalloc::try_arc(ifa)?;
    let list = &dev.in_dev().ifa_list;
    if ifa.is_secondary() {
        list.push_back(Arc::clone(&ifa));
    } else {
        // RTNL keeps the list as walked: the position is still there
        list.insert_after(Arc::clone(&ifa), |x| core::ptr::eq(x, last_primary));
    }
    hash_chain(&ifa).push_back(Arc::clone(&ifa));
    rtnetlink::notify_addr(net, dev, &ifa, rtnetlink::RTM_NEWADDR, nl);
    fib::fib_add_ifaddr(rtnl, net, dev, &ifa);
    Ok(())
}

/// An address unlinked from its device's list and the hash (Linux
/// __inet_del_ifa's step 2)
struct Unlinked {
    list: RcuUnlinked<IfaList>,
    hash: Option<RcuUnlinked<IfaHash>>,
}

impl Unlinked {
    fn ifa(&self) -> &InIfaddr {
        self.list.item()
    }
}

impl Unlinked {
    /// Free it after a grace period, without waiting
    fn free(self) {
        match self.hash {
            Some(h) => self.list.defer_with(h),
            None => self.list.defer(),
        }
    }
}

/// Unlink the first address of `dev` that `pick` accepts (RTNL held)
fn ifa_unlink(dev: &NetDevice, pick: impl FnMut(&InIfaddr) -> bool) -> Option<Unlinked> {
    let list = dev.in_dev().ifa_list.remove_first(pick)?;
    let ifa = list.item();
    let hash = hash_chain(ifa).remove_first(|x| core::ptr::eq(x, ifa));
    Some(Unlinked { list, hash })
}

/// Unlink an address of `dev`, announce it and remove its routes, then
/// free it after a grace period (Linux __inet_del_ifa's steps 2 and 3,
/// then inet_free_ifa)
fn inet_unlink_ifa(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &NetDevice,
    pick: impl FnMut(&InIfaddr) -> bool,
    nl: NlInfo,
) -> bool {
    let Some(gone) = ifa_unlink(dev, pick) else {
        return false;
    };
    rtnetlink::notify_addr(net, dev, gone.ifa(), rtnetlink::RTM_DELADDR, nl);
    fib::fib_del_ifaddr(rtnl, net, dev, gone.ifa());
    gone.free();
    true
}

/// Delete `ifa` from `dev` (Linux __inet_del_ifa with
/// promote_secondaries=0: a primary takes the secondaries of its subnet
/// along, each announced before it)
pub fn inet_del_ifa(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &Arc<NetDevice>,
    ifa: &InIfaddr,
    nl: NlInfo,
) {
    let listed = {
        let g = crate::sync::rcu::read_lock();
        dev.in_dev().addrs(&g).any(|x| core::ptr::eq(x, ifa))
    };
    if !listed {
        return;
    }
    if !ifa.is_secondary() {
        let sec = |x: &InIfaddr| x.is_secondary() && x.same_subnet(ifa);
        while inet_unlink_ifa(rtnl, net, dev, sec, nl) {}
    }
    inet_unlink_ifa(rtnl, net, dev, |x| core::ptr::eq(x, ifa), nl);
}

/// The address on `dev` with `local` in the subnet of `local/prefixlen`
/// at `address` (Linux find_matching_ifa)
pub fn find_matching_ifa(dev: &NetDevice, new: &InIfaddr) -> Option<Arc<InIfaddr>> {
    dev.in_dev()
        .ifa_list
        .find(|x| x.local == new.local && x.same_subnet(new))
}

/// Update an existing address in place (NLM_F_REPLACE; Linux
/// inet_rtm_newaddr on ifa_existing): metric, proto, non-structural
/// flags. It keeps its place on the list; re-announced with
/// RTM_NEWADDR.
pub fn inet_replace_ifa(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &Arc<NetDevice>,
    new: &InIfaddr,
    nl: NlInfo,
) {
    let Some(x) = find_matching_ifa(dev, new) else {
        return;
    };
    let secondary = x.flags() & IFA_F_SECONDARY;
    x.set_flags((new.flags() & !(IFA_F_SECONDARY | IPV6ONLY_FLAGS)) | secondary);
    x.set_rt_priority(new.rt_priority());
    x.set_proto(new.proto());
    rtnetlink::notify_addr(net, dev, &x, rtnetlink::RTM_NEWADDR, nl);
    fib::fib_add_ifaddr(rtnl, net, dev, &x);
}

/// Device came up (Linux inetdev_event/fib_netdev_event NETDEV_UP): `lo`
/// gets 127.0.0.1/8 if it has no address; every address's routes are
/// (re)installed
pub fn inetdev_up(rtnl: &RtnlGuard, net: &NetNamespace, dev: &Arc<NetDevice>) {
    if dev.is_loopback() && !dev.in_dev().has_addrs() {
        let mut ifa = InIfaddr::new(Ipv4Addr::new(127, 0, 0, 1), 8, dev.name());
        ifa.scope = RT_SCOPE_HOST;
        let _ = inet_insert_ifa(rtnl, net, dev, ifa, NlInfo::default());
    }
    // Each route insert takes RTNL-side locks: a reference per address
    for ifa in dev.in_dev().ifa_list.snapshot() {
        fib::fib_add_ifaddr(rtnl, net, dev, &ifa);
    }
}

/// Device went down (Linux fib_netdev_event NETDEV_DOWN): routes through
/// it go, except host-scope (local) ones
pub fn inetdev_down(rtnl: &RtnlGuard, net: &NetNamespace, dev: &Arc<NetDevice>) {
    fib::fib_disable_dev(rtnl, net, dev, false);
    crate::net::arp::arp_tbl().flush_dev(dev);
}

/// Device unregistered (Linux inetdev_event NETDEV_UNREGISTER ->
/// inetdev_destroy, then fib_netdev_event -> fib_disable_ip(force)):
/// every address is deleted and announced, then every route through it
pub fn inetdev_destroy(rtnl: &RtnlGuard, net: &NetNamespace, dev: &Arc<NetDevice>) {
    while let Some(ifa) = dev.in_dev().ifa_list.find(|_| true) {
        inet_del_ifa(rtnl, net, dev, &ifa, NlInfo::default());
    }
    fib::fib_disable_dev(rtnl, net, dev, true);
}

/// A device of a namespace that is gone loses its addresses (Linux
/// NETDEV_UNREGISTER -> inetdev_destroy from cleanup_net): they leave
/// its list and the address hash. Its FIB went with the namespace and
/// no socket is left to hear an announcement.
pub fn inetdev_exit(_rtnl: &RtnlGuard, dev: &NetDevice) {
    while let Some(gone) = ifa_unlink(dev, |_| true) {
        gone.free();
    }
}

/// Type of `addr` in the namespace (Linux inet_addr_type)
pub fn inet_addr_type(net: &NetNamespace, addr: Ipv4Addr) -> RouteType {
    net.fib.addr_type(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(IfaLabel::new("eth0:1").as_str(), "eth0:1");
        assert_eq!(
            IfaLabel::new("a-very-long-label-name").as_str(),
            "a-very-long-lab"
        );
        // Cut on a character boundary
        assert_eq!(
            IfaLabel::new("abcdefghijklmn\u{e9}").as_str(),
            "abcdefghijklmn"
        );
    }

    #[test]
    fn hash_spreads_and_keys_namespace() {
        let a = Ipv4Addr::new(10, 0, 2, 15);
        assert!(inet_addr_hash(1, a) < IN4_ADDR_HSIZE);
        assert_ne!(inet_addr_hash(1, a), inet_addr_hash(2, a));
    }
}
