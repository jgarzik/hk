//! IPv4 forwarding information base (Linux net/ipv4/fib_frontend.c,
//! fib_semantics.c, fib_trie.c semantics)
//!
//! Per network namespace: routing tables by id (local = 255, main = 254;
//! others are created on demand). Lookups consult local then main (the
//! Linux default rules without a rule engine), longest prefix first, and
//! within a prefix the first entry whose TOS, scope and output device fit.
//! Route types follow Linux: unicast, local, broadcast, and the error
//! types unreachable (EHOSTUNREACH), prohibit (EACCES), blackhole (EINVAL).
//!
//! Address-derived routes (`fib_add_ifaddr`) have protocol `kernel`.
//! Devices going down lose their routes except host-scope (local) ones;
//! a device losing its last address loses all.
//!
//! ## Locking
//!
//! `Fib.tables`: `crate::sync::spin::RwLock`, thread context only. Writers hold RTNL
//! (every mutating function takes the `RtnlGuard`); readers (input/output
//! routing, dumps) take the read lock briefly and get `Arc<FibEntry>`
//! clones, so no guard escapes (RCU-ready, plan 3a). Order: RTNL ->
//! device address lists -> `Fib.tables` (leaf; never held while calling
//! out, notifications are sent after it is dropped).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::spin::RwLock;

use crate::error::KernelError;
use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::ifaddr::{
    InIfaddr, RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE, inet_make_mask,
};
use crate::net::ipv4::Ipv4Addr;
use crate::net::netlink::NlInfo;
use crate::net::netlink::rtnetlink;
use crate::net::rtnl::RtnlGuard;

/// Routing table ids (Linux RT_TABLE_*)
pub const RT_TABLE_UNSPEC: u32 = 0;
pub const RT_TABLE_MAIN: u32 = 254;
pub const RT_TABLE_LOCAL: u32 = 255;

/// Route origin (Linux RTPROT_*)
pub const RTPROT_KERNEL: u8 = 2;
pub const RTPROT_BOOT: u8 = 3;

/// Nexthop flags (Linux RTNH_F_*)
pub const RTNH_F_DEAD: u32 = 1;
pub const RTNH_F_ONLINK: u32 = 4;
pub const RTNH_F_LINKDOWN: u32 = 16;

/// netlink request flags used by table updates
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

/// Route types (Linux RTN_*)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RouteType {
    Unspec = 0,
    Unicast = 1,
    Local = 2,
    Broadcast = 3,
    Anycast = 4,
    Multicast = 5,
    Blackhole = 6,
    Unreachable = 7,
    Prohibit = 8,
    Throw = 9,
}

/// Largest valid RTN_* value (RTN_XRESOLVE)
pub const RTN_MAX: u8 = 11;

impl RouteType {
    /// Decode RTN_*; NAT/XRESOLVE are accepted by Linux only to be
    /// rejected later, so they map to None here (EINVAL)
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Unspec,
            1 => Self::Unicast,
            2 => Self::Local,
            3 => Self::Broadcast,
            4 => Self::Anycast,
            5 => Self::Multicast,
            6 => Self::Blackhole,
            7 => Self::Unreachable,
            8 => Self::Prohibit,
            9 => Self::Throw,
            _ => return None,
        })
    }

    /// Smallest scope a route of this type may have (Linux fib_props)
    fn min_scope(self) -> u8 {
        match self {
            Self::Local => RT_SCOPE_HOST,
            Self::Broadcast | Self::Anycast => RT_SCOPE_LINK,
            _ => RT_SCOPE_UNIVERSE,
        }
    }

    /// Lookup error of the error types (Linux fib_props[].error)
    fn error(self) -> Option<KernelError> {
        match self {
            Self::Blackhole => Some(KernelError::InvalidArgument),
            Self::Unreachable => Some(KernelError::HostUnreachable),
            Self::Prohibit => Some(KernelError::PermissionDenied),
            Self::Throw => Some(KernelError::WouldBlock),
            _ => None,
        }
    }
}

/// One route (Linux fib_alias + fib_info + single fib_nh)
#[derive(Clone)]
pub struct FibEntry {
    pub table: u32,
    pub dst: Ipv4Addr,
    pub dst_len: u8,
    pub tos: u8,
    pub rtype: RouteType,
    pub scope: u8,
    pub protocol: u8,
    pub priority: u32,
    pub prefsrc: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    /// Output device (None for the error types)
    pub dev: Option<Arc<NetDevice>>,
    /// RTNH_F_* flags (ONLINK)
    pub flags: u32,
}

impl FibEntry {
    /// Output interface index (0 = none)
    pub fn oif(&self) -> u32 {
        self.dev.as_ref().map_or(0, |d| d.ifindex())
    }

    fn matches(&self, addr: Ipv4Addr) -> bool {
        addr.mask(inet_make_mask(self.dst_len)) == self.dst
    }

    /// Same route identity as Linux's exact-duplicate check (alias with
    /// the same fib_info)
    fn same_route(&self, o: &FibEntry) -> bool {
        self.table == o.table
            && self.dst == o.dst
            && self.dst_len == o.dst_len
            && self.tos == o.tos
            && self.rtype == o.rtype
            && self.scope == o.scope
            && self.protocol == o.protocol
            && self.priority == o.priority
            && self.prefsrc == o.prefsrc
            && self.gateway == o.gateway
            && self.oif() == o.oif()
    }

    fn same_key(&self, o: &FibEntry) -> bool {
        self.dst == o.dst && self.dst_len == o.dst_len && self.tos == o.tos
    }
}

/// Route lookup request (subset of Linux flowi4)
#[derive(Clone, Copy, Default)]
pub struct FlowKey {
    pub daddr: Ipv4Addr,
    /// Output interface constraint (0 = any)
    pub oif: u32,
    /// Smallest acceptable route scope
    pub scope: u8,
    pub tos: u8,
}

/// Per-namespace IPv4 FIB
pub struct Fib {
    /// table id -> entries sorted by prefix length (longest first)
    tables: RwLock<BTreeMap<u32, Vec<Arc<FibEntry>>>>,
}

impl Default for Fib {
    fn default() -> Self {
        Self::new()
    }
}

impl Fib {
    pub fn new() -> Self {
        let mut t = BTreeMap::new();
        t.insert(RT_TABLE_LOCAL, Vec::new());
        t.insert(RT_TABLE_MAIN, Vec::new());
        Self {
            tables: RwLock::new(t),
        }
    }

    /// Look up in one table: Ok(None) = no match
    fn lookup_table(
        &self,
        table: u32,
        key: &FlowKey,
    ) -> Result<Option<Arc<FibEntry>>, KernelError> {
        let tables = self.tables.read();
        let Some(entries) = tables.get(&table) else {
            return Ok(None);
        };
        for e in entries.iter() {
            if !e.matches(key.daddr) {
                continue;
            }
            if e.tos != 0 && e.tos != key.tos {
                continue;
            }
            if e.scope < key.scope {
                continue;
            }
            if let Some(err) = e.rtype.error() {
                if e.rtype == RouteType::Throw {
                    return Ok(None);
                }
                return Err(err);
            }
            if key.oif != 0 && e.oif() != key.oif {
                continue;
            }
            return Ok(Some(Arc::clone(e)));
        }
        Ok(None)
    }

    /// Full lookup: local, then main (Linux default rules); ENETUNREACH
    /// when nothing matches
    pub fn lookup(&self, key: &FlowKey) -> Result<Arc<FibEntry>, KernelError> {
        for table in [RT_TABLE_LOCAL, RT_TABLE_MAIN] {
            if let Some(e) = self.lookup_table(table, key)? {
                return Ok(e);
            }
        }
        Err(KernelError::NetworkUnreachable)
    }

    /// Linux inet_addr_type: classify `addr` by the local table
    pub fn addr_type(&self, addr: Ipv4Addr) -> RouteType {
        if (addr.0 >> 24) == 0 || addr.is_broadcast() {
            return RouteType::Broadcast;
        }
        if addr.is_multicast() {
            return RouteType::Multicast;
        }
        let key = FlowKey {
            daddr: addr,
            ..Default::default()
        };
        match self.lookup_table(RT_TABLE_LOCAL, &key) {
            Ok(Some(e)) => e.rtype,
            _ => RouteType::Unicast,
        }
    }

    /// Snapshot of every route (all tables)
    pub fn dump(&self) -> Vec<Arc<FibEntry>> {
        self.tables
            .read()
            .iter()
            .rev()
            .flat_map(|(_, v)| v.iter().cloned())
            .collect()
    }

    /// Snapshot of one table
    pub fn table(&self, id: u32) -> Vec<Arc<FibEntry>> {
        self.tables.read().get(&id).cloned().unwrap_or_default()
    }

    /// Insert with Linux fib_table_insert duplicate rules
    fn insert(&self, e: FibEntry, nlflags: u16) -> Result<Arc<FibEntry>, KernelError> {
        let mut tables = self.tables.write();
        let entries = tables.entry(e.table).or_default();
        let same_key: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, x)| x.same_key(&e) && x.priority == e.priority)
            .map(|(i, _)| i)
            .collect();
        let new = Arc::new(e);
        if let Some(&first) = same_key.first() {
            if nlflags & NLM_F_EXCL != 0 {
                return Err(KernelError::AlreadyExists);
            }
            if nlflags & NLM_F_REPLACE != 0 {
                entries[first] = Arc::clone(&new);
                return Ok(new);
            }
            if same_key.iter().any(|&i| entries[i].same_route(&new)) {
                return Err(KernelError::AlreadyExists);
            }
            if nlflags & NLM_F_CREATE == 0 {
                return Err(KernelError::NotFound);
            }
            let at = if nlflags & NLM_F_APPEND != 0 {
                *same_key.last().unwrap() + 1
            } else {
                first
            };
            entries.insert(at, Arc::clone(&new));
            return Ok(new);
        }
        if nlflags & NLM_F_CREATE == 0 {
            return Err(KernelError::NotFound);
        }
        // Longest prefix first; within a prefix, by priority
        let at = entries
            .iter()
            .position(|x| {
                x.dst_len < new.dst_len
                    || (x.dst_len == new.dst_len && x.dst == new.dst && x.priority > new.priority)
            })
            .unwrap_or(entries.len());
        entries.insert(at, Arc::clone(&new));
        Ok(new)
    }

    /// Remove and return the entries `pred` selects
    fn remove_where(&self, mut pred: impl FnMut(&FibEntry) -> bool) -> Vec<Arc<FibEntry>> {
        let mut out = Vec::new();
        for entries in self.tables.write().values_mut() {
            entries.retain(|e| {
                let dead = pred(e);
                if dead {
                    out.push(Arc::clone(e));
                }
                !dead
            });
        }
        out
    }
}

/// A route change request (Linux struct fib_config)
#[derive(Clone, Default)]
pub struct FibConfig {
    pub table: u32,
    pub dst: Ipv4Addr,
    pub dst_len: u8,
    pub tos: u8,
    /// RTN_* (0 = unspecified, matches any on delete)
    pub rtype: u8,
    pub scope: u8,
    /// 0 = unspecified (matches any on delete)
    pub protocol: u8,
    pub priority: u32,
    pub prefsrc: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub oif: u32,
    pub flags: u32,
    pub nlflags: u16,
    pub nl: NlInfo,
}

impl FibConfig {
    fn table_id(&self) -> u32 {
        if self.table == RT_TABLE_UNSPEC {
            RT_TABLE_MAIN
        } else {
            self.table
        }
    }
}

/// Resolve and validate a new route (Linux fib_create_info / fib_check_nh)
fn fib_create_info(net: &NetNamespace, cfg: &FibConfig) -> Result<FibEntry, KernelError> {
    if cfg.rtype > RTN_MAX {
        return Err(KernelError::InvalidArgument);
    }
    let rtype = RouteType::from_u8(cfg.rtype).ok_or(KernelError::InvalidArgument)?;
    if rtype.min_scope() > cfg.scope {
        return Err(KernelError::InvalidArgument);
    }
    if cfg.flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let mut e = FibEntry {
        table: cfg.table_id(),
        dst: cfg.dst,
        dst_len: cfg.dst_len,
        tos: cfg.tos,
        rtype,
        scope: cfg.scope,
        protocol: cfg.protocol,
        priority: cfg.priority,
        prefsrc: cfg.prefsrc,
        gateway: cfg.gateway,
        dev: None,
        flags: cfg.flags,
    };
    if rtype.error().is_some() {
        if cfg.gateway.is_some() || cfg.oif != 0 {
            return Err(KernelError::InvalidArgument);
        }
        return Ok(e);
    }
    if !matches!(
        rtype,
        RouteType::Unicast
            | RouteType::Local
            | RouteType::Broadcast
            | RouteType::Anycast
            | RouteType::Multicast
    ) {
        return Err(KernelError::InvalidArgument);
    }
    if cfg.scope > RT_SCOPE_HOST {
        return Err(KernelError::InvalidArgument);
    }
    if cfg.scope == RT_SCOPE_HOST {
        // A local address is being added: no gateway, device must exist
        if cfg.gateway.is_some() {
            return Err(KernelError::InvalidArgument);
        }
        e.dev = Some(net.dev_get_by_index(cfg.oif).ok_or(KernelError::NoDevice)?);
    } else if let Some(gw) = cfg.gateway {
        e.dev = Some(fib_check_nh_gw(net, cfg, gw)?);
    } else {
        if cfg.flags & RTNH_F_ONLINK != 0 {
            return Err(KernelError::InvalidArgument);
        }
        let dev = net.dev_get_by_index(cfg.oif).ok_or(KernelError::NoDevice)?;
        if !dev.is_up() {
            return Err(KernelError::NetworkDown);
        }
        e.dev = Some(dev);
    }
    if let Some(p) = cfg.prefsrc {
        let own = rtype == RouteType::Local && !cfg.dst.is_unspecified() && p == cfg.dst;
        if !own && net.fib.addr_type(p) != RouteType::Local {
            return Err(KernelError::InvalidArgument);
        }
    }
    Ok(e)
}

/// Gateway nexthop check (Linux fib_check_nh_v4_gw): the gateway must be
/// reachable by a link/host-scope route (ENETUNREACH otherwise), through
/// an up device (ENETDOWN)
fn fib_check_nh_gw(
    net: &NetNamespace,
    cfg: &FibConfig,
    gw: Ipv4Addr,
) -> Result<Arc<NetDevice>, KernelError> {
    if cfg.flags & RTNH_F_ONLINK != 0 {
        if cfg.scope >= RT_SCOPE_LINK {
            return Err(KernelError::InvalidArgument);
        }
        let dev = net.dev_get_by_index(cfg.oif).ok_or(KernelError::NoDevice)?;
        if !dev.is_up() {
            return Err(KernelError::NetworkDown);
        }
        if net.fib.addr_type(gw) != RouteType::Unicast {
            return Err(KernelError::InvalidArgument);
        }
        return Ok(dev);
    }
    let key = FlowKey {
        daddr: gw,
        oif: cfg.oif,
        scope: cfg.scope.saturating_add(1).max(RT_SCOPE_LINK),
        tos: 0,
    };
    let res = net.fib.lookup(&key)?;
    if res.rtype != RouteType::Unicast && res.rtype != RouteType::Local {
        return Err(KernelError::InvalidArgument);
    }
    let dev = res.dev.clone().ok_or(KernelError::InvalidArgument)?;
    if !dev.is_up() {
        return Err(KernelError::NetworkDown);
    }
    Ok(dev)
}

/// Add a route (Linux fib_table_insert); notifies RTNLGRP_IPV4_ROUTE
pub fn fib_table_insert(
    _rtnl: &RtnlGuard,
    net: &NetNamespace,
    cfg: &FibConfig,
) -> Result<(), KernelError> {
    if cfg.dst_len > 32 {
        return Err(KernelError::InvalidArgument);
    }
    if cfg.dst.0 & !inet_make_mask(cfg.dst_len).0 != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let e = fib_create_info(net, cfg)?;
    let e = net.fib.insert(e, cfg.nlflags)?;
    rtnetlink::notify_route(net, &e, rtnetlink::RTM_NEWROUTE, cfg.nl);
    Ok(())
}

/// Delete the first route matching `cfg` (Linux fib_table_delete):
/// unspecified type/protocol/prefsrc/priority/gateway/oif and scope
/// RT_SCOPE_NOWHERE match anything; ESRCH if none
pub fn fib_table_delete(
    _rtnl: &RtnlGuard,
    net: &NetNamespace,
    cfg: &FibConfig,
) -> Result<(), KernelError> {
    if cfg.dst_len > 32 {
        return Err(KernelError::InvalidArgument);
    }
    let table = cfg.table_id();
    let mut done = false;
    let removed = net.fib.remove_where(|e| {
        let hit = !done
            && e.table == table
            && e.dst == cfg.dst
            && e.dst_len == cfg.dst_len
            && e.tos == cfg.tos
            && (cfg.rtype == 0 || e.rtype as u8 == cfg.rtype)
            && (cfg.scope == RT_SCOPE_NOWHERE || e.scope == cfg.scope)
            && (cfg.prefsrc.is_none() || e.prefsrc == cfg.prefsrc)
            && (cfg.protocol == 0 || e.protocol == cfg.protocol)
            && (cfg.priority == 0 || e.priority == cfg.priority)
            && (cfg.oif == 0 || e.oif() == cfg.oif)
            && (cfg.gateway.is_none() || e.gateway == cfg.gateway);
        if hit {
            done = true;
        }
        hit
    });
    let Some(e) = removed.first() else {
        return Err(KernelError::NoProcess);
    };
    rtnetlink::notify_route(net, e, rtnetlink::RTM_DELROUTE, cfg.nl);
    Ok(())
}

/// The routes an address implies (Linux fib_add_ifaddr's fib_magic calls)
fn ifa_routes(dev: &NetDevice, ifa: &InIfaddr, prim_local: Ipv4Addr) -> Vec<FibConfig> {
    let magic = |rtype: RouteType, dst: Ipv4Addr, dst_len: u8, priority: u32| FibConfig {
        table: if rtype == RouteType::Unicast {
            RT_TABLE_MAIN
        } else {
            RT_TABLE_LOCAL
        },
        dst,
        dst_len,
        rtype: rtype as u8,
        scope: if rtype == RouteType::Local {
            RT_SCOPE_HOST
        } else {
            RT_SCOPE_LINK
        },
        protocol: RTPROT_KERNEL,
        priority,
        prefsrc: Some(prim_local),
        oif: dev.ifindex(),
        nlflags: NLM_F_CREATE | NLM_F_APPEND,
        ..Default::default()
    };
    let mut out = alloc::vec![magic(RouteType::Local, ifa.local, 32, 0)];
    if !dev.is_up() {
        return out;
    }
    if !ifa.broadcast.is_unspecified() && !ifa.broadcast.is_broadcast() {
        out.push(magic(RouteType::Broadcast, ifa.broadcast, 32, 0));
    }
    let mask = ifa.mask();
    let prefix = ifa.prefix();
    if (prefix.0 >> 24) != 0 && !ifa.is_secondary() && (prefix != ifa.local || ifa.prefixlen < 32) {
        if ifa.flags & crate::net::inet::ifaddr::IFA_F_NOPREFIXROUTE == 0 {
            let t = if dev.is_loopback() {
                RouteType::Local
            } else {
                RouteType::Unicast
            };
            out.push(magic(t, prefix, ifa.prefixlen, ifa.rt_priority));
        }
        if ifa.prefixlen < 31 {
            out.push(magic(
                RouteType::Broadcast,
                Ipv4Addr(prefix.0 | !mask.0),
                32,
                0,
            ));
        }
    }
    out
}

/// Primary address of `ifa`'s subnet on `dev` (itself if primary)
fn primary_local(dev: &NetDevice, ifa: &InIfaddr) -> Ipv4Addr {
    if !ifa.is_secondary() {
        return ifa.local;
    }
    dev.inet_addrs()
        .into_iter()
        .find(|p| !p.is_secondary() && p.prefixlen == ifa.prefixlen && p.matches(ifa.address))
        .map_or(ifa.local, |p| p.local)
}

/// Install the routes for `ifa` (Linux fib_add_ifaddr); existing ones are
/// kept
pub fn fib_add_ifaddr(rtnl: &RtnlGuard, net: &NetNamespace, dev: &NetDevice, ifa: &InIfaddr) {
    for cfg in ifa_routes(dev, ifa, primary_local(dev, ifa)) {
        let _ = fib_table_insert(rtnl, net, &cfg);
    }
}

/// Remove the routes of a deleted address (Linux fib_del_ifaddr +
/// fib_sync_down_addr): routes still implied by a remaining address stay;
/// routes using the address as preferred source go once nobody owns it;
/// a device without addresses loses all its routes
pub fn fib_del_ifaddr(rtnl: &RtnlGuard, net: &NetNamespace, dev: &NetDevice, ifa: &InIfaddr) {
    let mut still: Vec<FibConfig> = Vec::new();
    for d in net.devices() {
        for other in d.inet_addrs() {
            still.extend(ifa_routes(&d, &other, primary_local(&d, &other)));
        }
    }
    let same = |a: &FibConfig, b: &FibConfig| {
        a.table == b.table
            && a.dst == b.dst
            && a.dst_len == b.dst_len
            && a.rtype == b.rtype
            && a.prefsrc == b.prefsrc
            && a.oif == b.oif
    };
    let prim = if ifa.is_secondary() {
        primary_local(dev, ifa)
    } else {
        ifa.local
    };
    // Routes are computed as if the device were up, so a down device's
    // leftovers are found too (deleting a missing one is harmless)
    for mut cfg in ifa_routes_all(dev, ifa, prim) {
        if still.iter().any(|s| same(s, &cfg)) {
            continue;
        }
        cfg.nlflags = 0;
        let _ = fib_table_delete(rtnl, net, &cfg);
    }
    if crate::net::inet::ifaddr::ip_dev_find(net, ifa.local).is_none() {
        let local = ifa.local;
        for e in net.fib.remove_where(|e| e.prefsrc == Some(local)) {
            rtnetlink::notify_route(net, &e, rtnetlink::RTM_DELROUTE, NlInfo::default());
        }
    }
    if dev.inet_addrs().is_empty() {
        fib_disable_dev(rtnl, net, dev, true);
    }
}

/// `ifa_routes` for an up device (deletion must find all of them)
fn ifa_routes_all(dev: &NetDevice, ifa: &InIfaddr, prim: Ipv4Addr) -> Vec<FibConfig> {
    let mut v = ifa_routes(dev, ifa, prim);
    if !dev.is_up() {
        // Same computation with the up-only part included
        let mask = ifa.mask();
        let prefix = ifa.prefix();
        let mk = |rtype: RouteType, dst: Ipv4Addr, dst_len: u8| FibConfig {
            table: if rtype == RouteType::Unicast {
                RT_TABLE_MAIN
            } else {
                RT_TABLE_LOCAL
            },
            dst,
            dst_len,
            rtype: rtype as u8,
            scope: RT_SCOPE_NOWHERE,
            protocol: RTPROT_KERNEL,
            prefsrc: Some(prim),
            oif: dev.ifindex(),
            ..Default::default()
        };
        if !ifa.broadcast.is_unspecified() {
            v.push(mk(RouteType::Broadcast, ifa.broadcast, 32));
        }
        let t = if dev.is_loopback() {
            RouteType::Local
        } else {
            RouteType::Unicast
        };
        v.push(mk(t, prefix, ifa.prefixlen));
        v.push(mk(RouteType::Broadcast, Ipv4Addr(prefix.0 | !mask.0), 32));
    }
    for c in v.iter_mut() {
        c.scope = RT_SCOPE_NOWHERE;
    }
    v
}

/// Drop routes through `dev` (Linux fib_disable_ip): all of them when
/// `force`, else all but host-scope ones (local addresses stay reachable
/// on a down device). Like Linux, no RTM_DELROUTE is sent for these.
pub fn fib_disable_dev(_rtnl: &RtnlGuard, net: &NetNamespace, dev: &NetDevice, force: bool) {
    let idx = dev.ifindex();
    net.fib
        .remove_where(|e| e.oif() == idx && (force || e.scope != RT_SCOPE_HOST));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn entry(table: u32, dst: Ipv4Addr, len: u8, rtype: RouteType, prio: u32) -> FibEntry {
        FibEntry {
            table,
            dst,
            dst_len: len,
            tos: 0,
            rtype,
            scope: if rtype == RouteType::Local {
                RT_SCOPE_HOST
            } else {
                RT_SCOPE_UNIVERSE
            },
            protocol: RTPROT_BOOT,
            priority: prio,
            prefsrc: None,
            gateway: None,
            dev: None,
            flags: 0,
        }
    }

    fn key(d: Ipv4Addr) -> FlowKey {
        FlowKey {
            daddr: d,
            ..Default::default()
        }
    }

    #[test]
    fn longest_prefix_and_local_first() {
        let f = Fib::new();
        let c = NLM_F_CREATE;
        f.insert(
            entry(RT_TABLE_MAIN, ip(0, 0, 0, 0), 0, RouteType::Unicast, 0),
            c,
        )
        .unwrap();
        f.insert(
            entry(RT_TABLE_MAIN, ip(10, 0, 2, 0), 24, RouteType::Unicast, 0),
            c,
        )
        .unwrap();
        f.insert(
            entry(RT_TABLE_LOCAL, ip(10, 0, 2, 15), 32, RouteType::Local, 0),
            c,
        )
        .unwrap();
        assert_eq!(f.lookup(&key(ip(10, 0, 2, 3))).unwrap().dst_len, 24);
        assert_eq!(f.lookup(&key(ip(8, 8, 8, 8))).unwrap().dst_len, 0);
        assert_eq!(
            f.lookup(&key(ip(10, 0, 2, 15))).unwrap().rtype,
            RouteType::Local
        );
        assert_eq!(f.addr_type(ip(10, 0, 2, 15)), RouteType::Local);
        assert_eq!(f.addr_type(ip(10, 0, 2, 16)), RouteType::Unicast);
    }

    #[test]
    fn no_route_and_error_types() {
        let f = Fib::new();
        assert!(matches!(
            f.lookup(&key(ip(1, 2, 3, 4))),
            Err(KernelError::NetworkUnreachable)
        ));
        f.insert(
            entry(RT_TABLE_MAIN, ip(1, 2, 3, 0), 24, RouteType::Unreachable, 0),
            NLM_F_CREATE,
        )
        .unwrap();
        assert!(matches!(
            f.lookup(&key(ip(1, 2, 3, 4))),
            Err(KernelError::HostUnreachable)
        ));
        f.insert(
            entry(RT_TABLE_MAIN, ip(5, 0, 0, 0), 8, RouteType::Prohibit, 0),
            NLM_F_CREATE,
        )
        .unwrap();
        assert!(matches!(
            f.lookup(&key(ip(5, 1, 1, 1))),
            Err(KernelError::PermissionDenied)
        ));
    }

    #[test]
    fn duplicate_rules() {
        let f = Fib::new();
        let e = entry(RT_TABLE_MAIN, ip(10, 1, 0, 0), 16, RouteType::Unicast, 5);
        assert!(matches!(f.insert(e.clone(), 0), Err(KernelError::NotFound)));
        f.insert(e.clone(), NLM_F_CREATE | NLM_F_EXCL).unwrap();
        assert!(matches!(
            f.insert(e.clone(), NLM_F_CREATE | NLM_F_EXCL),
            Err(KernelError::AlreadyExists)
        ));
        assert!(matches!(
            f.insert(e.clone(), NLM_F_CREATE),
            Err(KernelError::AlreadyExists)
        ));
        // Same prefix, other metric: a separate route
        let mut e2 = e.clone();
        e2.priority = 10;
        f.insert(e2, NLM_F_CREATE | NLM_F_EXCL).unwrap();
        assert_eq!(f.table(RT_TABLE_MAIN).len(), 2);
        // Lower metric wins
        assert_eq!(f.lookup(&key(ip(10, 1, 2, 3))).unwrap().priority, 5);
        // Replace keeps the count
        let mut e3 = e.clone();
        e3.protocol = RTPROT_KERNEL;
        f.insert(e3, NLM_F_CREATE | NLM_F_REPLACE).unwrap();
        assert_eq!(f.table(RT_TABLE_MAIN).len(), 2);
    }

    #[test]
    fn scope_filter() {
        let f = Fib::new();
        f.insert(
            entry(RT_TABLE_MAIN, ip(0, 0, 0, 0), 0, RouteType::Unicast, 0),
            NLM_F_CREATE,
        )
        .unwrap();
        let k = FlowKey {
            daddr: ip(10, 0, 2, 2),
            scope: RT_SCOPE_LINK,
            ..Default::default()
        };
        // A gateway reachable only via a universe-scope route is not
        // directly reachable
        assert!(f.lookup(&k).is_err());
    }

    #[test]
    fn masks() {
        use crate::net::inet::ifaddr::inet_mask_len;
        assert_eq!(inet_make_mask(24), ip(255, 255, 255, 0));
        assert_eq!(inet_make_mask(0), ip(0, 0, 0, 0));
        assert_eq!(inet_make_mask(32), ip(255, 255, 255, 255));
        assert_eq!(inet_mask_len(ip(255, 255, 255, 0)), Some(24));
        assert_eq!(inet_mask_len(ip(0, 0, 0, 0)), Some(0));
        assert_eq!(inet_mask_len(ip(255, 0, 255, 0)), None);
    }
}
