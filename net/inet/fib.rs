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
//! a device losing its last address loses all; routes preferring a
//! source address nobody owns any more go too. Like Linux, those routes
//! are first marked dead (fib_sync_down_dev, fib_sync_down_addr), then
//! unlinked in one walk per table (fib_flush, fib_table_flush).
//!
//! ## Locking
//!
//! Linux fib_table_insert/delete under RTNL, lookups under RCU: the
//! tables and each table's entries are RCU lists. Writers hold RTNL
//! (every mutating function takes the `RtnlGuard`) and the lists' leaf
//! writer locks; readers (input/output routing in softnet and socket
//! calls, possibly under a socket lock; dumps filling an `NlBuf`;
//! /proc/net/route into a `SeqBuf`) walk under `rcu::read_lock` with no
//! lock and no copy, and a lookup takes a reference to the entry it
//! returns. An entry removed or replaced is freed after a grace period
//! (`RcuUnlinked::defer`, Linux alias_free_mem_rcu); notifications are
//! sent outside the RCU guard. An entry's dead mark (`fib_flags`,
//! `pfsrc_removed`) is set under RTNL and read by lookups without a
//! lock (Linux fi->fib_flags, read locklessly by fib_table_lookup).
//! Order: RTNL -> device address lists -> FIB lists' writer locks
//! (leaves).

use crate::util::kalloc::try_arc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};

use crate::sync::rcu::{RcuHead, RcuReadGuard};
use crate::util::list::Link;
use crate::util::rculist::{RcuIter, RcuList, RcuRef, RcuUnlinked};

use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::ifaddr::{
    IFA_F_NOPREFIXROUTE, InIfaddr, RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_NOWHERE,
    RT_SCOPE_UNIVERSE, inet_make_mask,
};
use crate::net::inet::route::NhExceptions;
use crate::net::ipv4::Ipv4Addr;
use crate::net::netlink::NlInfo;
use crate::net::netlink::rtnetlink;
use crate::net::rtnl::RtnlGuard;
use crate::util::error::KernelError;

/// Routing table ids (Linux RT_TABLE_*)
pub const RT_TABLE_UNSPEC: u32 = 0;
pub const RT_TABLE_DEFAULT: u32 = 253;
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

/// One route (Linux fib_alias + fib_info + single fib_nh): fixed once
/// it is in a table
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
    /// RTNH_F_DEAD once its device or preferred source is gone, until
    /// `fib_flush` unlinks it (Linux fi->fib_flags): set under RTNL,
    /// read by lookups without a lock
    fib_flags: AtomicU32,
    /// Dead because its preferred source went: announced when flushed
    /// (Linux fi->pfsrc_removed); under RTNL
    pfsrc_removed: AtomicBool,
    /// Learned exceptions of its nexthop (Linux nhc_exceptions): PMTU
    pub exceptions: NhExceptions,
    /// On its table's entries (Linux fa_list)
    link: Link,
    /// Freed through it a grace period after it leaves its table
    rcu: RcuHead,
}

crate::adapter!(pub FibLink, FibEntry, link);
crate::rcu_head!(FibEntry, rcu);

impl FibEntry {
    /// Output interface index (0 = none)
    pub fn oif(&self) -> u32 {
        self.dev.as_ref().map_or(0, |d| d.ifindex())
    }

    fn matches(&self, addr: Ipv4Addr) -> bool {
        addr.mask(inet_make_mask(self.dst_len)) == self.dst
    }

    /// Marked dead, waiting for `fib_flush` (RTNH_F_DEAD)
    pub fn dead(&self) -> bool {
        self.fib_flags.load(Relaxed) & RTNH_F_DEAD != 0
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

/// One routing table (Linux struct fib_table)
pub struct FibTable {
    pub id: u32,
    /// Routes, longest prefix first; within a prefix by priority, then
    /// in insertion order (Linux a trie leaf's fa_list); read under
    /// RCU, changed under RTNL
    entries: RcuList<FibLink>,
    /// On `Fib.tables`
    link: Link,
}

crate::adapter!(pub TableLink, FibTable, link);

impl FibTable {
    fn new(id: u32) -> Result<Arc<Self>, KernelError> {
        try_arc(Self {
            id,
            entries: RcuList::new(),
            link: Link::new(),
        })
    }

    /// The routes, while `g` is held
    pub fn entries<'a>(&'a self, g: &'a RcuReadGuard) -> RcuIter<'a, FibLink> {
        self.entries.iter(g)
    }

    /// Look up `key` (Ok(None) = no match): the first route, longest
    /// prefix first, whose TOS, scope and device fit
    fn lookup<'a>(
        &'a self,
        g: &'a RcuReadGuard,
        key: &FlowKey,
    ) -> Result<Option<RcuRef<'a, FibEntry>>, KernelError> {
        for e in self.entries.iter_ref(g) {
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
            if e.dead() {
                continue;
            }
            if key.oif != 0 && e.oif() != key.oif {
                continue;
            }
            return Ok(Some(e));
        }
        Ok(None)
    }

    /// Insert with Linux fib_table_insert's duplicate rules (RTNL held)
    fn insert(&self, new: &Arc<FibEntry>, nlflags: u16) -> Result<(), KernelError> {
        /// Where the route goes
        enum At {
            Replace(*const FibEntry),
            Before(*const FibEntry),
            After(*const FibEntry),
            Sorted,
        }
        let at = {
            let g = crate::sync::rcu::read_lock();
            // The entries with the same key and priority (Linux
            // fib_find_alias), and whether one is the same route
            let (mut first, mut last, mut dup) = (None, None, false);
            for x in self.entries.iter(&g) {
                if x.same_key(new) && x.priority == new.priority {
                    first = first.or(Some(core::ptr::from_ref(x)));
                    last = Some(core::ptr::from_ref(x));
                    dup |= x.same_route(new);
                }
            }
            match (first, last) {
                (Some(_), _) if nlflags & NLM_F_EXCL != 0 => {
                    return Err(KernelError::AlreadyExists);
                }
                (Some(f), _) if nlflags & NLM_F_REPLACE != 0 => At::Replace(f),
                (Some(_), _) if dup => return Err(KernelError::AlreadyExists),
                _ if nlflags & NLM_F_CREATE == 0 => return Err(KernelError::NotFound),
                (Some(_), Some(l)) if nlflags & NLM_F_APPEND != 0 => At::After(l),
                (Some(f), _) => At::Before(f),
                (None, _) => At::Sorted,
            }
        };
        // RTNL keeps the entries as walked: the positions are still there
        let new = Arc::clone(new);
        match at {
            At::Replace(f) => {
                if let Ok(old) = self.entries.replace(new, |x| core::ptr::eq(x, f)) {
                    old.defer();
                }
            }
            At::Before(f) => self.entries.insert_before(new, |x| core::ptr::eq(x, f)),
            At::After(l) => self.entries.insert_after(new, |x| core::ptr::eq(x, l)),
            At::Sorted => {
                let (len, dst, prio) = (new.dst_len, new.dst, new.priority);
                self.entries.insert_before(new, |x| {
                    x.dst_len < len || (x.dst_len == len && x.dst == dst && x.priority > prio)
                });
            }
        }
        Ok(())
    }
}

/// Per-namespace IPv4 FIB (Linux netns_ipv4's fib_table_hash)
pub struct Fib {
    /// Tables by descending id: local, main, then those created on
    /// demand; never removed while the namespace lives
    tables: RcuList<TableLink>,
}

impl Fib {
    pub fn new() -> Result<Self, KernelError> {
        let tables = RcuList::new();
        tables.push_back(FibTable::new(RT_TABLE_LOCAL)?);
        tables.push_back(FibTable::new(RT_TABLE_MAIN)?);
        Ok(Self { tables })
    }

    /// Table `id`, while `g` is held (Linux fib_get_table)
    pub fn get_table<'a>(&'a self, g: &'a RcuReadGuard, id: u32) -> Option<&'a FibTable> {
        self.tables.iter(g).find(|t| t.id == id)
    }

    /// The tables (by descending id), while `g` is held
    pub fn tables<'a>(&'a self, g: &'a RcuReadGuard) -> RcuIter<'a, TableLink> {
        self.tables.iter(g)
    }

    /// Every route, table by table, while `g` is held
    pub fn entries<'a>(&'a self, g: &'a RcuReadGuard) -> impl Iterator<Item = &'a FibEntry> + 'a {
        self.tables(g).flat_map(move |t| t.entries(g))
    }

    /// Table `id`, created if missing (Linux fib_new_table; RTNL held)
    fn new_table(&self, id: u32) -> Result<Arc<FibTable>, KernelError> {
        if let Some(t) = self.tables.find(|t| t.id == id) {
            return Ok(t);
        }
        let t = FibTable::new(id)?;
        self.tables.insert_before(Arc::clone(&t), |x| x.id < id);
        Ok(t)
    }

    /// Look up in one table: Ok(None) = no match
    fn lookup_table<'a>(
        &'a self,
        g: &'a RcuReadGuard,
        table: u32,
        key: &FlowKey,
    ) -> Result<Option<RcuRef<'a, FibEntry>>, KernelError> {
        match self.get_table(g, table) {
            Some(t) => t.lookup(g, key),
            None => Ok(None),
        }
    }

    /// Full lookup: local, then main (Linux default rules); ENETUNREACH
    /// when nothing matches. The route is referenced, nothing copied.
    pub fn lookup(&self, key: &FlowKey) -> Result<Arc<FibEntry>, KernelError> {
        let g = crate::sync::rcu::read_lock();
        for table in [RT_TABLE_LOCAL, RT_TABLE_MAIN] {
            if let Some(e) = self.lookup_table(&g, table, key)? {
                return Ok(e.get());
            }
        }
        Err(KernelError::NetworkUnreachable)
    }

    /// Linux inet_addr_type: classify `addr` by the local table
    pub fn addr_type(&self, addr: Ipv4Addr) -> RouteType {
        self.dev_addr_type(None, addr)
    }

    /// Linux __inet_dev_addr_type on the local table: the type of
    /// `addr` as if only `dev` existed (any device for None)
    pub fn dev_addr_type(&self, dev: Option<&NetDevice>, addr: Ipv4Addr) -> RouteType {
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
        let g = crate::sync::rcu::read_lock();
        match self.lookup_table(&g, RT_TABLE_LOCAL, &key) {
            Ok(Some(e)) if dev.is_none_or(|d| e.oif() == d.ifindex()) => e.rtype,
            _ => RouteType::Unicast,
        }
    }

    /// Insert `e` into its table (created if missing), RTNL held
    fn insert(&self, e: FibEntry, nlflags: u16) -> Result<Arc<FibEntry>, KernelError> {
        let t = self.new_table(e.table)?;
        let new = try_arc(e)?;
        t.insert(&new, nlflags)?;
        Ok(new)
    }

    /// Mark dead the live routes `pred` picks, of table `table` or of
    /// all (the marking of Linux fib_sync_down_dev / fib_sync_down_addr;
    /// `pfsrc`: for a preferred source gone, announced when flushed).
    /// RTNL held; returns how many.
    fn mark_dead(
        &self,
        table: Option<u32>,
        pfsrc: bool,
        mut pred: impl FnMut(&FibEntry) -> bool,
    ) -> usize {
        let g = crate::sync::rcu::read_lock();
        let mut n = 0;
        for t in self.tables(&g) {
            if table.is_some_and(|id| id != t.id) {
                continue;
            }
            for e in t.entries(&g).filter(|e| !e.dead() && pred(e)) {
                if pfsrc {
                    e.pfsrc_removed.store(true, Relaxed);
                }
                e.fib_flags.fetch_or(RTNH_F_DEAD, Relaxed);
                n += 1;
            }
        }
        n
    }

    /// Unlink every dead route, one walk per table (Linux fib_flush's
    /// fib_table_flush calls, flush_all false); RTNL held. Those gone
    /// with their preferred source go to `pfsrc` while it has room (to
    /// be announced), the others are freed after a grace period.
    /// Returns how many went.
    fn flush(&self, pfsrc: &mut Vec<RcuUnlinked<FibLink>>) -> usize {
        let g = crate::sync::rcu::read_lock();
        let mut n = 0;
        for t in self.tables(&g) {
            n += t.entries.remove_all(FibEntry::dead, |u| {
                // Within the reserved capacity: no allocation under the
                // list's lock
                if u.item().pfsrc_removed.load(Relaxed) && pfsrc.len() < pfsrc.capacity() {
                    pfsrc.push(u);
                } else {
                    u.defer();
                }
            });
        }
        n
    }

    /// Unlink the first route of table `id` that `pred` picks
    fn remove_first(
        &self,
        id: u32,
        pred: impl FnMut(&FibEntry) -> bool,
    ) -> Option<RcuUnlinked<FibLink>> {
        self.tables.find(|t| t.id == id)?.entries.remove_first(pred)
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
        fib_flags: AtomicU32::new(0),
        pfsrc_removed: AtomicBool::new(false),
        exceptions: NhExceptions::default(),
        link: Link::new(),
        rcu: RcuHead::new(),
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
    let removed = net.fib.remove_first(cfg.table_id(), |e| {
        e.dst == cfg.dst
            && e.dst_len == cfg.dst_len
            && e.tos == cfg.tos
            && (cfg.rtype == 0 || e.rtype as u8 == cfg.rtype)
            && (cfg.scope == RT_SCOPE_NOWHERE || e.scope == cfg.scope)
            && (cfg.prefsrc.is_none() || e.prefsrc == cfg.prefsrc)
            && (cfg.protocol == 0 || e.protocol == cfg.protocol)
            && (cfg.priority == 0 || e.priority == cfg.priority)
            && (cfg.oif == 0 || e.oif() == cfg.oif)
            && (cfg.gateway.is_none() || e.gateway == cfg.gateway)
    });
    let Some(e) = removed else {
        return Err(KernelError::NoProcess);
    };
    rtnetlink::notify_route(net, e.item(), rtnetlink::RTM_DELROUTE, cfg.nl);
    e.defer();
    Ok(())
}

/// Add or delete a route an address implies (Linux fib_magic): unicast
/// goes to the main table, the other types to local; preferred source
/// `prim` (the local address of the subnet's primary). Failures are
/// ignored, as Linux does.
#[allow(clippy::too_many_arguments)]
fn fib_magic(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    add: bool,
    rtype: RouteType,
    dst: Ipv4Addr,
    dst_len: u8,
    dev: &NetDevice,
    prim: Ipv4Addr,
    priority: u32,
) {
    let cfg = FibConfig {
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
        prefsrc: Some(prim),
        oif: dev.ifindex(),
        nlflags: if add { NLM_F_CREATE | NLM_F_APPEND } else { 0 },
        ..Default::default()
    };
    let _ = if add {
        fib_table_insert(rtnl, net, &cfg)
    } else {
        fib_table_delete(rtnl, net, &cfg)
    };
}

/// Linux ipv4_is_zeronet
fn zeronet(a: Ipv4Addr) -> bool {
    (a.0 >> 24) == 0
}

/// The first address of `dev` in subnet `prefix/prefixlen`, while `g`
/// is held (Linux inet_ifa_byprefix: primaries come first)
fn ifa_byprefix<'a>(
    dev: &'a NetDevice,
    g: &'a RcuReadGuard,
    prefix: Ipv4Addr,
    prefixlen: u8,
) -> Option<&'a InIfaddr> {
    dev.in_dev()
        .addrs(g)
        .find(|i| i.prefixlen == prefixlen && i.matches(prefix))
}

/// Install the routes for `ifa` (Linux fib_add_ifaddr); existing ones are
/// kept
pub fn fib_add_ifaddr(rtnl: &RtnlGuard, net: &NetNamespace, dev: &NetDevice, ifa: &InIfaddr) {
    let mask = ifa.mask();
    let addr = ifa.local;
    let prefix = ifa.prefix();
    let prim = if ifa.is_secondary() {
        let g = crate::sync::rcu::read_lock();
        match ifa_byprefix(dev, &g, prefix, ifa.prefixlen) {
            Some(p) => p.local,
            None => return,
        }
    } else {
        ifa.local
    };
    let magic =
        |rtype, dst, len, prio| fib_magic(rtnl, net, true, rtype, dst, len, dev, prim, prio);
    magic(RouteType::Local, addr, 32, 0);
    if !dev.is_up() {
        return;
    }
    // A broadcast address explicitly assigned
    if !ifa.broadcast.is_unspecified() && !ifa.broadcast.is_broadcast() {
        magic(RouteType::Broadcast, ifa.broadcast, 32, 0);
    }
    if !zeronet(prefix) && !ifa.is_secondary() && (prefix != addr || ifa.prefixlen < 32) {
        if ifa.flags() & IFA_F_NOPREFIXROUTE == 0 {
            let t = if dev.is_loopback() {
                RouteType::Local
            } else {
                RouteType::Unicast
            };
            magic(t, prefix, ifa.prefixlen, ifa.rt_priority());
        }
        // The network broadcast address, where it makes sense
        if ifa.prefixlen < 31 {
            magic(RouteType::Broadcast, Ipv4Addr(prefix.0 | !mask.0), 32, 0);
        }
    }
}

/// An address's metric changes (Linux fib_modify_prefix_metric, from
/// inet_rtm_newaddr's NLM_F_REPLACE): its prefix route is added at
/// `new_metric`, then the one at its old metric deleted
pub fn fib_modify_prefix_metric(
    rtnl: &RtnlGuard,
    net: &NetNamespace,
    dev: &NetDevice,
    ifa: &InIfaddr,
    new_metric: u32,
) {
    let prefix = ifa.prefix();
    if !dev.is_up()
        || ifa.is_secondary()
        || ifa.flags() & IFA_F_NOPREFIXROUTE != 0
        || zeronet(prefix)
        || (prefix == ifa.local && ifa.prefixlen == 32)
    {
        return;
    }
    let t = if dev.is_loopback() {
        RouteType::Local
    } else {
        RouteType::Unicast
    };
    let (len, prim) = (ifa.prefixlen, ifa.local);
    fib_magic(rtnl, net, true, t, prefix, len, dev, prim, new_metric);
    fib_magic(
        rtnl,
        net,
        false,
        t,
        prefix,
        len,
        dev,
        prim,
        ifa.rt_priority(),
    );
}

/// Which of a deleted address's routes another address of the device
/// still implies (Linux fib_del_ifaddr's `ok` bits)
const LOCAL_OK: u32 = 1;
const BRD_OK: u32 = 2;
const BRD0_OK: u32 = 4;
const BRD1_OK: u32 = 8;

/// What fib_del_ifaddr's scan of the remaining addresses found: the
/// preferred source of the address's routes (its subnet's primary),
/// the routes still implied, and whether the address itself is gone
struct DelScan {
    prim: Ipv4Addr,
    ok: u32,
    gone: bool,
}

/// Linux fib_del_ifaddr's scan of `dev`'s addresses (promote_secondaries
/// off: no iprim); None if a secondary `ifa` has no primary
fn del_ifaddr_scan(dev: &NetDevice, ifa: &InIfaddr) -> Option<DelScan> {
    let g = crate::sync::rcu::read_lock();
    let mask = ifa.mask();
    let brd = Ipv4Addr(ifa.address.0 | !mask.0);
    let any = Ipv4Addr(ifa.address.0 & mask.0);
    let prim: &InIfaddr = if ifa.is_secondary() {
        ifa_byprefix(dev, &g, any, ifa.prefixlen)?
    } else {
        ifa
    };
    let (mut ok, mut gone, mut same_prefsrc) = (0, true, false);
    let mut prim1: Option<&InIfaddr> = None;
    for ifa1 in dev.in_dev().addrs(&g) {
        if core::ptr::eq(ifa1, ifa) {
            // Promotion, keep the IP
            gone = false;
            continue;
        }
        // Ignore an address using another primary IP (prefsrc)
        if ifa1.is_secondary() {
            if ifa1.prefixlen == prim.prefixlen && prim.matches(ifa1.address) {
                // Another address of our subnet
                prim1 = Some(prim);
            } else {
                // Among the secondaries: same_prefsrc is known now
                if !same_prefsrc {
                    continue;
                }
                if prim1.is_none_or(|p| ifa1.prefixlen != p.prefixlen || !p.matches(ifa1.address)) {
                    prim1 = ifa_byprefix(dev, &g, ifa1.address, ifa1.prefixlen);
                }
                match prim1 {
                    Some(p) if p.local == prim.local => {}
                    _ => continue,
                }
            }
        } else {
            if prim.local != ifa1.local {
                continue;
            }
            prim1 = Some(ifa1);
            if !core::ptr::eq(prim, ifa1) {
                same_prefsrc = true;
            }
        }
        if ifa.local == ifa1.local {
            ok |= LOCAL_OK;
        }
        if ifa.broadcast == ifa1.broadcast {
            ok |= BRD_OK;
        }
        if brd == ifa1.broadcast {
            ok |= BRD1_OK;
        }
        if any == ifa1.broadcast {
            ok |= BRD0_OK;
        }
        // A primary has network specific broadcasts
        if prim1.is_some_and(|p| core::ptr::eq(p, ifa1)) && ifa1.prefixlen < 31 {
            let m1 = ifa1.mask();
            let brd1 = Ipv4Addr(ifa1.address.0 | !m1.0);
            let any1 = Ipv4Addr(ifa1.address.0 & m1.0);
            if !zeronet(any1) {
                if ifa.broadcast == brd1 || ifa.broadcast == any1 {
                    ok |= BRD_OK;
                }
                if brd == brd1 || brd == any1 {
                    ok |= BRD1_OK;
                }
                if any == brd1 || any == any1 {
                    ok |= BRD0_OK;
                }
            }
        }
    }
    Some(DelScan {
        prim: prim.local,
        ok,
        gone,
    })
}

/// Remove the routes of `ifa`, already off `dev`'s list (Linux
/// fib_del_ifaddr): those another address of the device still implies
/// stay; once the address is gone from the device, routes preferring
/// it as source are flushed (fib_sync_down_addr) and announced
pub fn fib_del_ifaddr(rtnl: &RtnlGuard, net: &NetNamespace, dev: &NetDevice, ifa: &InIfaddr) {
    let Some(scan) = del_ifaddr_scan(dev, ifa) else {
        return;
    };
    let mask = ifa.mask();
    let brd = Ipv4Addr(ifa.address.0 | !mask.0);
    let any = Ipv4Addr(ifa.address.0 & mask.0);
    let del = |rtype, dst, len| fib_magic(rtnl, net, false, rtype, dst, len, dev, scan.prim, 0);
    let mut subnet = false;
    if !ifa.is_secondary() && !zeronet(any) && (any != ifa.local || ifa.prefixlen < 32) {
        if ifa.flags() & IFA_F_NOPREFIXROUTE == 0 {
            let t = if dev.is_loopback() {
                RouteType::Local
            } else {
                RouteType::Unicast
            };
            del(t, any, ifa.prefixlen);
        }
        subnet = true;
    }
    if scan.ok & BRD_OK == 0 {
        del(RouteType::Broadcast, ifa.broadcast, 32);
    }
    if subnet && ifa.prefixlen < 31 {
        if scan.ok & BRD1_OK == 0 {
            del(RouteType::Broadcast, brd, 32);
        }
        if scan.ok & BRD0_OK == 0 {
            del(RouteType::Broadcast, any, 32);
        }
    }
    if scan.ok & LOCAL_OK == 0 {
        del(RouteType::Local, ifa.local, 32);
        // The local address finally disappeared: flush stray routes
        // Local on any device keeps its routes (Linux
        // inet_addr_type_dev_table: __inet_dev_addr_type with no device)
        if scan.gone && net.fib.dev_addr_type(None, ifa.local) != RouteType::Local {
            let n = fib_sync_down_addr(rtnl, net, ifa.local);
            if n > 0 {
                fib_flush(rtnl, net, n);
            }
        }
    }
}

/// Mark dead the main-table routes preferring `local` as source (Linux
/// fib_sync_down_addr, no l3mdev); returns how many
fn fib_sync_down_addr(_rtnl: &RtnlGuard, net: &NetNamespace, local: Ipv4Addr) -> usize {
    if local.is_unspecified() {
        return 0;
    }
    net.fib
        .mark_dead(Some(RT_TABLE_MAIN), true, |e| e.prefsrc == Some(local))
}

/// Mark dead the routes through `dev` (Linux fib_sync_down_dev for
/// NETDEV_DOWN / NETDEV_UNREGISTER): all of them when `force`, else all
/// but host-scope ones (local addresses stay reachable on a down
/// device); returns how many
fn fib_sync_down_dev(_rtnl: &RtnlGuard, net: &NetNamespace, dev: &NetDevice, force: bool) -> usize {
    let idx = dev.ifindex();
    net.fib.mark_dead(None, false, |e| {
        e.oif() == idx && (force || e.scope != RT_SCOPE_HOST)
    })
}

/// Unlink every dead route (Linux fib_flush). The `announce` routes
/// fib_sync_down_addr marked get RTM_DELROUTE (Linux fib_table_flush's
/// pfsrc_removed rtmsg_fib; one the list has no memory for is dropped,
/// as rtmsg_fib drops one); the others go silently. hk has no route
/// cache to flush after (Linux rt_cache_flush).
fn fib_flush(_rtnl: &RtnlGuard, net: &NetNamespace, announce: usize) {
    let mut pfsrc = Vec::new();
    let _ = pfsrc.try_reserve_exact(announce);
    net.fib.flush(&mut pfsrc);
    for u in pfsrc {
        rtnetlink::notify_route(net, u.item(), rtnetlink::RTM_DELROUTE, NlInfo::default());
        u.defer();
    }
}

/// Drop the routes through `dev` (Linux fib_disable_ip): all of them
/// when `force`, else all but host-scope ones; like Linux, no
/// RTM_DELROUTE is sent for these. Its ARP entries go too (arp_ifdown).
pub fn fib_disable_ip(rtnl: &RtnlGuard, net: &NetNamespace, dev: &NetDevice, force: bool) {
    if fib_sync_down_dev(rtnl, net, dev, force) > 0 {
        fib_flush(rtnl, net, 0);
    }
    crate::net::arp::arp_tbl().flush_dev(dev);
}

/// An address left `dev` (Linux fib_inetaddr_event NETDEV_DOWN): its
/// routes go, then every route through `dev` once it has no address
pub fn fib_inetaddr_down(rtnl: &RtnlGuard, net: &NetNamespace, dev: &NetDevice, ifa: &InIfaddr) {
    fib_del_ifaddr(rtnl, net, dev, ifa);
    if !dev.in_dev().has_addrs() {
        fib_disable_ip(rtnl, net, dev, true);
    }
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
            fib_flags: AtomicU32::new(0),
            pfsrc_removed: AtomicBool::new(false),
            exceptions: NhExceptions::default(),
            link: Link::new(),
            rcu: RcuHead::new(),
        }
    }

    impl FibEntry {
        /// An unlinked copy
        fn dup(&self) -> Self {
            let mut e = entry(
                self.table,
                self.dst,
                self.dst_len,
                self.rtype,
                self.priority,
            );
            e.scope = self.scope;
            e.protocol = self.protocol;
            e
        }
    }

    fn table_len(f: &Fib, id: u32) -> usize {
        let g = crate::sync::rcu::read_lock();
        f.get_table(&g, id).map_or(0, |t| t.entries(&g).count())
    }

    fn key(d: Ipv4Addr) -> FlowKey {
        FlowKey {
            daddr: d,
            ..Default::default()
        }
    }

    #[test]
    fn longest_prefix_and_local_first() {
        let f = Fib::new().unwrap();
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
        let f = Fib::new().unwrap();
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
        let f = Fib::new().unwrap();
        let e = entry(RT_TABLE_MAIN, ip(10, 1, 0, 0), 16, RouteType::Unicast, 5);
        assert!(matches!(f.insert(e.dup(), 0), Err(KernelError::NotFound)));
        f.insert(e.dup(), NLM_F_CREATE | NLM_F_EXCL).unwrap();
        assert!(matches!(
            f.insert(e.dup(), NLM_F_CREATE | NLM_F_EXCL),
            Err(KernelError::AlreadyExists)
        ));
        assert!(matches!(
            f.insert(e.dup(), NLM_F_CREATE),
            Err(KernelError::AlreadyExists)
        ));
        // Same prefix, other metric: a separate route
        let mut e2 = e.dup();
        e2.priority = 10;
        f.insert(e2, NLM_F_CREATE | NLM_F_EXCL).unwrap();
        assert_eq!(table_len(&f, RT_TABLE_MAIN), 2);
        // Lower metric wins
        assert_eq!(f.lookup(&key(ip(10, 1, 2, 3))).unwrap().priority, 5);
        // Same key, other route: before the first (append: after the
        // last) of its key and priority
        let mut e4 = e.dup();
        e4.scope = RT_SCOPE_LINK;
        f.insert(e4, NLM_F_CREATE).unwrap();
        let mut e5 = e.dup();
        e5.protocol = RTPROT_KERNEL;
        f.insert(e5, NLM_F_CREATE | NLM_F_APPEND).unwrap();
        let order = |f: &Fib| {
            let g = crate::sync::rcu::read_lock();
            let t = f.get_table(&g, RT_TABLE_MAIN).unwrap();
            t.entries(&g)
                .map(|x| (x.priority, x.scope, x.protocol))
                .collect::<Vec<_>>()
        };
        let (u, l) = (RT_SCOPE_UNIVERSE, RT_SCOPE_LINK);
        assert_eq!(
            order(&f),
            [
                (5, l, RTPROT_BOOT),
                (5, u, RTPROT_BOOT),
                (5, u, RTPROT_KERNEL),
                (10, u, RTPROT_BOOT)
            ]
        );
        // Replace takes the first's place and keeps the count
        let mut e3 = e.dup();
        e3.protocol = 9;
        f.insert(e3, NLM_F_CREATE | NLM_F_REPLACE).unwrap();
        assert_eq!(table_len(&f, RT_TABLE_MAIN), 4);
        assert_eq!(order(&f)[0], (5, u, 9));
    }

    #[test]
    fn scope_filter() {
        let f = Fib::new().unwrap();
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

    /// Many routes marked dead go in one flush, every table walked once
    /// (Linux fib_sync_down_addr + fib_flush): only main-table routes
    /// with the preferred source are marked, a dead route is no longer
    /// found, the rest stay in order, and the marked ones are handed
    /// back for announcing while there is room
    #[test]
    fn flush_dead() {
        const N: u32 = 600;
        let f = Fib::new().unwrap();
        let src = ip(192, 0, 2, 10);
        let mut add = |table, dst: Ipv4Addr, prefsrc| {
            let rtype = if table == RT_TABLE_LOCAL {
                RouteType::Local
            } else {
                RouteType::Unicast
            };
            let mut e = entry(table, dst, 32, rtype, 0);
            e.prefsrc = prefsrc;
            f.insert(e, NLM_F_CREATE).unwrap();
        };
        for i in 0..N {
            let d = Ipv4Addr(u32::from_be_bytes([198, 51, 0, 0]) + i);
            // Every other main route prefers `src`
            add(RT_TABLE_MAIN, d, (i % 2 == 0).then_some(src));
        }
        add(RT_TABLE_LOCAL, src, Some(src));
        let n = f.mark_dead(Some(RT_TABLE_MAIN), true, |e| e.prefsrc == Some(src));
        assert_eq!(n, N as usize / 2);
        // Marked again: nothing new
        assert_eq!(
            f.mark_dead(Some(RT_TABLE_MAIN), true, |e| e.prefsrc == Some(src)),
            0
        );
        assert!(matches!(
            f.lookup(&key(ip(198, 51, 0, 0))),
            Err(KernelError::NetworkUnreachable)
        ));
        assert_eq!(
            f.lookup(&key(ip(198, 51, 0, 1))).unwrap().dst,
            ip(198, 51, 0, 1)
        );
        // Room for some: the rest are freed unannounced
        let mut pfsrc = Vec::with_capacity(10);
        assert_eq!(f.flush(&mut pfsrc), N as usize / 2);
        assert_eq!(pfsrc.len(), 10);
        assert!(pfsrc.iter().all(|u| u.item().prefsrc == Some(src)));
        pfsrc.into_iter().for_each(RcuUnlinked::defer);
        assert_eq!(table_len(&f, RT_TABLE_MAIN), N as usize / 2);
        assert_eq!(table_len(&f, RT_TABLE_LOCAL), 1);
        let g = crate::sync::rcu::read_lock();
        let left: Vec<u32> = f
            .get_table(&g, RT_TABLE_MAIN)
            .unwrap()
            .entries(&g)
            .map(|e| e.dst.0 - u32::from_be_bytes([198, 51, 0, 0]))
            .collect();
        drop(g);
        assert!(left.iter().all(|i| i % 2 == 1));
        assert!(left.is_sorted());
        // Nothing dead: a flush removes nothing
        assert_eq!(f.flush(&mut Vec::new()), 0);
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
