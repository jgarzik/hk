//! Routing rules (Linux net/core/fib_rules.c)
//!
//! A namespace keeps, per address family, an ordered list of rules
//! (`FibRules`, Linux struct fib_rules_ops' rules_list): each selects
//! flows (interfaces, fwmark, uid range, IP protocol, ports and the
//! family's own selectors) and acts on them (look up a table, jump
//! forward, do nothing, or fail). Lookups walk the list in priority
//! order (`rules_lookup`, Linux fib_rules_lookup); RTM_NEWRULE /
//! RTM_DELRULE / RTM_GETRULE change and dump it (fib_newrule,
//! fib_delrule, fib_nl_dumprule) and RTNLGRP_*_RULE hears the changes.
//! The family supplies its part through `RulesOps` (IPv4:
//! `inet::fib_rules`); this layer never reads an address.
//!
//! A goto's target is the first rule of the target priority, found when
//! the goto is taken: the same rule Linux's ctarget points at, kept
//! there by fib_newrule/fib_delrule's fixups.
//!
//! ## Locking
//!
//! The list is an `RcuList` (its `ends` leaf lock): changed under RTNL
//! (Linux 6.8's rtnl doits; current Linux takes RTNL for the first
//! custom rule and ops->lock after), walked under `rcu::read_lock` by
//! lookups (any context), dumps and the RTNL holders themselves. A rule
//! removed is freed after a grace period (`RcuUnlinked::defer`, Linux
//! fib_rule_put's kfree_rcu). `iifindex` / `oifindex` are atomics
//! written under RTNL as devices come and go (attach_rules,
//! detach_rules), read by lookups without a lock (Linux
//! READ_ONCE/WRITE_ONCE).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering::Relaxed};

use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::inet::fib::NLM_F_EXCL;
use crate::net::inet::ifaddr::IFNAMSIZ;
use crate::net::netlink::attr::{Attrs, NlBuf, attr_size, msg_size, nlmsg_new};
use crate::net::netlink::{
    ExtAck, NETLINK_ROUTE, NlInfo, kernel_skb, notify as nl_notify, set_err,
};
use crate::net::rtnl::RtnlGuard;
use crate::sync::rcu::{RcuHead, RcuReadGuard};
use crate::util::error::KernelError;
use crate::util::list::Link;
use crate::util::rculist::RcuList;

pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;

/// Rule actions (Linux FR_ACT_*)
pub const FR_ACT_TO_TBL: u8 = 1;
pub const FR_ACT_GOTO: u8 = 2;
pub const FR_ACT_NOP: u8 = 3;
pub const FR_ACT_BLACKHOLE: u8 = 6;
pub const FR_ACT_UNREACHABLE: u8 = 7;
pub const FR_ACT_PROHIBIT: u8 = 8;

/// Rule flags (Linux FIB_RULE_*)
pub const FIB_RULE_PERMANENT: u32 = 0x1;
pub const FIB_RULE_INVERT: u32 = 0x2;
pub const FIB_RULE_UNRESOLVED: u32 = 0x4;
pub const FIB_RULE_IIF_DETACHED: u32 = 0x8;
pub const FIB_RULE_OIF_DETACHED: u32 = 0x10;

// FRA_*
pub const FRA_DST: u16 = 1;
pub const FRA_SRC: u16 = 2;
pub const FRA_IIFNAME: u16 = 3;
pub const FRA_GOTO: u16 = 4;
pub const FRA_PRIORITY: u16 = 6;
pub const FRA_FWMARK: u16 = 10;
pub const FRA_FLOW: u16 = 11;
pub const FRA_TUN_ID: u16 = 12;
pub const FRA_SUPPRESS_IFGROUP: u16 = 13;
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
pub const FRA_TABLE: u16 = 15;
pub const FRA_FWMASK: u16 = 16;
pub const FRA_OIFNAME: u16 = 17;
pub const FRA_L3MDEV: u16 = 19;
pub const FRA_UID_RANGE: u16 = 20;
pub const FRA_PROTOCOL: u16 = 21;
pub const FRA_IP_PROTO: u16 = 22;
pub const FRA_SPORT_RANGE: u16 = 23;
pub const FRA_DPORT_RANGE: u16 = 24;
pub const FRA_DSCP: u16 = 25;
pub const FRA_FLOWLABEL: u16 = 26;
pub const FRA_FLOWLABEL_MASK: u16 = 27;
pub const FRA_SPORT_MASK: u16 = 28;
pub const FRA_DPORT_MASK: u16 = 29;
pub const FRA_DSCP_MASK: u16 = 30;
const FRA_MAX: u16 = 30;

/// struct fib_rule_hdr
pub const FIB_RULE_HDR_LEN: usize = 12;
/// Linux RT_TABLE_COMPAT: a table id above 255 in the header
const RT_TABLE_COMPAT: u8 = 252;
/// fib_kuid_range_unset
const UID_UNSET: (u32, u32) = (0, u32::MAX);

/// struct fib_rule_hdr fields
#[derive(Clone, Copy, Default)]
pub struct RuleHdr {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub res1: u8,
    pub res2: u8,
    pub action: u8,
    pub flags: u32,
}

impl RuleHdr {
    fn parse(p: &[u8]) -> Option<Self> {
        let h = p.get(..FIB_RULE_HDR_LEN)?;
        Some(Self {
            family: h[0],
            dst_len: h[1],
            src_len: h[2],
            tos: h[3],
            table: h[4],
            res1: h[5],
            res2: h[6],
            action: h[7],
            flags: u32::from_ne_bytes([h[8], h[9], h[10], h[11]]),
        })
    }

    fn bytes(&self) -> [u8; FIB_RULE_HDR_LEN] {
        let mut h = [0u8; FIB_RULE_HDR_LEN];
        h[..8].copy_from_slice(&[
            self.family,
            self.dst_len,
            self.src_len,
            self.tos,
            self.table,
            self.res1,
            self.res2,
            self.action,
        ]);
        h[8..].copy_from_slice(&self.flags.to_ne_bytes());
        h
    }
}

/// An inclusive port range (Linux struct fib_rule_port_range); 0..0 is
/// none
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// Linux fib_rule_port_range_set
    fn set(&self) -> bool {
        self.start != 0 && self.end != 0
    }

    /// Linux fib_rule_port_range_valid
    fn valid(&self) -> bool {
        self.start != 0 && self.end != 0 && self.end < 0xffff && self.start <= self.end
    }

    fn is_range(&self) -> bool {
        self.start != self.end
    }

    /// Linux fib_rule_port_match
    pub fn matches(&self, mask: u16, port: u16) -> bool {
        if (self.start ^ port) & mask != 0 {
            return false;
        }
        !(mask == 0 && self.set() && !(self.start..=self.end).contains(&port))
    }

    fn of(b: &[u8]) -> Self {
        Self {
            start: u16::from_ne_bytes([b[0], b[1]]),
            end: u16::from_ne_bytes([b[2], b[3]]),
        }
    }

    fn bytes(&self) -> [u8; 4] {
        let s = self.start.to_ne_bytes();
        let e = self.end.to_ne_bytes();
        [s[0], s[1], e[0], e[1]]
    }
}

/// What a lookup knows of a flow for the common selectors (Linux
/// struct flowi_common)
#[derive(Clone, Copy, Default)]
pub struct RuleFlow {
    pub iif: u32,
    pub oif: u32,
    pub mark: u32,
    pub uid: u32,
}

/// One rule (Linux struct fib_rule), its family's part in `af`
pub struct FibRule<A> {
    pub pref: u32,
    pub table: u32,
    pub action: u8,
    pub flags: u32,
    /// Originator (RTPROT_*)
    pub proto: u8,
    pub iifname: [u8; IFNAMSIZ],
    pub oifname: [u8; IFNAMSIZ],
    /// The named devices' indexes, -1 while absent (0: no name)
    iifindex: AtomicI32,
    oifindex: AtomicI32,
    pub mark: u32,
    pub mark_mask: u32,
    pub tun_id: u64,
    pub l3mdev: u8,
    /// FR_ACT_GOTO's target priority
    pub target: u32,
    pub uid_range: (u32, u32),
    pub ip_proto: u8,
    pub sport: PortRange,
    pub dport: PortRange,
    pub sport_mask: u16,
    pub dport_mask: u16,
    /// Suppress results with a prefix this long or shorter (-1: off)
    pub suppress_prefixlen: i32,
    /// Suppress results through a device of this group (-1: off)
    pub suppress_ifgroup: i32,
    pub af: A,
    link: Link,
    rcu: RcuHead,
}

impl<A: Default> FibRule<A> {
    /// A blank rule (Linux kzalloc in fib_nl2rule)
    fn blank() -> Self {
        Self {
            pref: 0,
            table: 0,
            action: 0,
            flags: 0,
            proto: 0,
            iifname: [0; IFNAMSIZ],
            oifname: [0; IFNAMSIZ],
            iifindex: AtomicI32::new(0),
            oifindex: AtomicI32::new(0),
            mark: 0,
            mark_mask: 0,
            tun_id: 0,
            l3mdev: 0,
            target: 0,
            uid_range: UID_UNSET,
            ip_proto: 0,
            sport: PortRange::default(),
            dport: PortRange::default(),
            sport_mask: 0,
            dport_mask: 0,
            suppress_prefixlen: -1,
            suppress_ifgroup: -1,
            af: A::default(),
            link: Link::new(),
            rcu: RcuHead::new(),
        }
    }

    /// A default rule (Linux fib_default_rule_add)
    pub fn default_rule(pref: u32, table: u32) -> Self {
        let mut r = Self::blank();
        r.action = FR_ACT_TO_TBL;
        r.pref = pref;
        r.table = table;
        r.proto = crate::net::inet::fib::RTPROT_KERNEL;
        r
    }
}

impl<A> FibRule<A> {
    pub fn iifindex(&self) -> i32 {
        self.iifindex.load(Relaxed)
    }

    pub fn oifindex(&self) -> i32 {
        self.oifindex.load(Relaxed)
    }

    /// Linux uid_range_set
    fn uid_set(&self) -> bool {
        self.uid_range.0 != u32::MAX && self.uid_range.1 != u32::MAX
    }

    /// The common selectors (Linux fib_rule_match without the family's
    /// ops->match); hk devices are never l3 masters
    fn match_common(&self, fl: &RuleFlow) -> bool {
        let iif = self.iifindex();
        if iif != 0 && iif as u32 != fl.iif {
            return false;
        }
        let oif = self.oifindex();
        if oif != 0 && oif as u32 != fl.oif {
            return false;
        }
        if (self.mark ^ fl.mark) & self.mark_mask != 0 {
            return false;
        }
        // No tunnel metadata (flowi_tun_key.tun_id 0), no l3mdev
        // devices
        if self.tun_id != 0 || self.l3mdev != 0 {
            return false;
        }
        fl.uid >= self.uid_range.0 && fl.uid <= self.uid_range.1
    }
}

crate::adapter!(pub RuleLink4, FibRule<crate::net::inet::fib_rules::Fib4Rule>, link);
crate::rcu_head!(FibRule<crate::net::inet::fib_rules::Fib4Rule>, rcu);

/// Linux ops->configure: the family's selectors from the request, a
/// table chosen for a table-less lookup rule
pub type ConfigureFn<A> = fn(
    r: &mut FibRule<A>,
    net: &NetNamespace,
    rtnl: &RtnlGuard,
    h: &RuleHdr,
    tb: &Attrs<'_>,
    ext: &ExtAck,
) -> Result<(), KernelError>;

/// A family's part of the rules (Linux struct fib_rules_ops' callbacks)
pub struct RulesOps<A: 'static> {
    pub family: u8,
    /// Bytes of an address (Linux addr_size)
    pub addr_size: usize,
    /// Notification group (Linux nlgroup)
    pub nlgroup: u32,
    pub configure: ConfigureFn<A>,
    /// Linux ops->compare: `r` has the family selectors the request
    /// `nl` (its header `h`) names
    pub compare: fn(r: &FibRule<A>, h: &RuleHdr, nl: &FibRule<A>, tb: &Attrs<'_>) -> bool,
    /// Linux ops->fill: header fields and attributes
    pub fill: fn(r: &FibRule<A>, h: &mut RuleHdr, nb: &mut NlBuf<'_>) -> Result<(), KernelError>,
    /// Linux ops->nlmsg_payload
    pub payload: usize,
}

/// The rules of one family in one namespace (Linux struct
/// fib_rules_ops' rules_list)
pub struct FibRules {
    pub ops: &'static RulesOps<crate::net::inet::fib_rules::Fib4Rule>,
    list: RcuList<RuleLink4>,
}

type Rule = FibRule<crate::net::inet::fib_rules::Fib4Rule>;

impl FibRules {
    /// The list with `defaults` in order (Linux fib_rules_register,
    /// then fib_default_rules_init)
    pub fn new(
        ops: &'static RulesOps<crate::net::inet::fib_rules::Fib4Rule>,
        defaults: &[(u32, u32)],
    ) -> Result<Self, KernelError> {
        let list = RcuList::new();
        for &(pref, table) in defaults {
            list.push_back(crate::util::kalloc::try_arc(Rule::default_rule(
                pref, table,
            ))?);
        }
        Ok(Self { ops, list })
    }

    /// The rules, while `g` is held
    pub fn iter<'a>(&'a self, g: &'a RcuReadGuard) -> impl Iterator<Item = &'a Rule> + 'a {
        self.list.iter(g)
    }

    /// Whether a goto to `target` finds a rule (Linux ctarget set)
    fn resolved(&self, g: &RcuReadGuard, target: u32) -> bool {
        self.iter(g).any(|r| r.pref == target)
    }

    /// Walk the rules for a flow (Linux fib_rules_lookup): each rule
    /// whose selectors (`fl` and the family's `af_match`) fit, after
    /// INVERT, acts: a goto jumps to the first rule of its target
    /// priority (passed over when there is none), NOP passes,
    /// `action` gives a result, None to go on (Linux -EAGAIN), or an
    /// error that ends the walk; `suppress` may refuse a result. ESRCH
    /// when no rule decides.
    pub fn lookup<R>(
        &self,
        fl: &RuleFlow,
        af_match: impl Fn(&Rule) -> bool,
        mut action: impl FnMut(&Rule) -> Result<Option<R>, KernelError>,
        suppress: impl Fn(&Rule, &R) -> bool,
    ) -> Result<R, KernelError> {
        let g = crate::sync::rcu::read_lock();
        // The rule to resume at after a goto
        let mut from: Option<*const Rule> = None;
        'restart: loop {
            let mut it = self.iter(&g);
            if let Some(f) = from {
                // Forward only: the target follows the goto
                for r in it.by_ref() {
                    if core::ptr::eq(r, f) {
                        break;
                    }
                }
            }
            let mut cur = from.map(|f| {
                // SAFETY: `f` is a rule of the list found under `g`,
                // which keeps it alive
                unsafe { &*f }
            });
            loop {
                let r = match cur.take() {
                    Some(r) => r,
                    None => match it.next() {
                        Some(r) => r,
                        None => return Err(KernelError::NoProcess),
                    },
                };
                let m = r.match_common(fl) && af_match(r);
                if m == (r.flags & FIB_RULE_INVERT != 0) {
                    continue;
                }
                match r.action {
                    FR_ACT_GOTO => {
                        if let Some(t) = self.iter(&g).find(|x| x.pref == r.target) {
                            from = Some(core::ptr::from_ref(t));
                            continue 'restart;
                        }
                    }
                    FR_ACT_NOP => {}
                    _ => match action(r)? {
                        Some(res) if !suppress(r, &res) => return Ok(res),
                        _ => {}
                    },
                }
            }
        }
    }

    /// Linux attach_rules (NETDEV_REGISTER, NETDEV_CHANGENAME): rules
    /// naming `dev` while detached take its index; RTNL held
    pub fn attach(&self, dev: &NetDevice) {
        let g = crate::sync::rcu::read_lock();
        let idx = dev.ifindex() as i32;
        for r in self.iter(&g) {
            if r.iifindex() == -1 && name_is(&r.iifname, dev.name()) {
                r.iifindex.store(idx, Relaxed);
            }
            if r.oifindex() == -1 && name_is(&r.oifname, dev.name()) {
                r.oifindex.store(idx, Relaxed);
            }
        }
    }

    /// Linux detach_rules (NETDEV_UNREGISTER, NETDEV_CHANGENAME):
    /// rules on `dev`'s index lose it; RTNL held
    pub fn detach(&self, dev: &NetDevice) {
        let g = crate::sync::rcu::read_lock();
        let idx = dev.ifindex() as i32;
        for r in self.iter(&g) {
            if r.iifindex() == idx {
                r.iifindex.store(-1, Relaxed);
            }
            if r.oifindex() == idx {
                r.oifindex.store(-1, Relaxed);
            }
        }
    }

    /// Linux fib_default_rule_pref: one below the second rule's, if
    /// that is not 0
    fn default_pref(&self, g: &RcuReadGuard) -> u32 {
        self.iter(g).nth(1).map_or(0, |r| r.pref.saturating_sub(1))
    }
}

/// `name` (NUL-padded) is `s`
fn name_is(name: &[u8; IFNAMSIZ], s: &str) -> bool {
    let n = name.iter().position(|&c| c == 0).unwrap_or(IFNAMSIZ);
    name[0] != 0 && &name[..n] == s.as_bytes()
}

// ============================================================================
// Netlink
// ============================================================================

/// The request's attributes, read as Linux's fib_rule_policy validates
/// them, before anything else
struct RuleAttrs<'a> {
    tb: Attrs<'a>,
    src: Option<&'a [u8]>,
    dst: Option<&'a [u8]>,
    iifname: Option<&'a str>,
    oifname: Option<&'a str>,
    pref: Option<u32>,
    mark: Option<u32>,
    mask: Option<u32>,
    tun_id: Option<u64>,
    table: Option<u32>,
    suppress_prefixlen: Option<u32>,
    suppress_ifgroup: Option<u32>,
    target: Option<u32>,
    l3mdev: Option<u8>,
    uid: Option<(u32, u32)>,
    proto: Option<u8>,
    ip_proto: Option<u8>,
    sport: Option<PortRange>,
    dport: Option<PortRange>,
    sport_mask: Option<u16>,
    dport_mask: Option<u16>,
}

fn u16_attr(tb: &Attrs<'_>, t: u16) -> Result<Option<u16>, KernelError> {
    Ok(tb.min(t, 2)?.map(|b| u16::from_ne_bytes([b[0], b[1]])))
}

fn rule_attrs<'a>(p: &'a [u8], ext: &'a ExtAck) -> Result<RuleAttrs<'a>, KernelError> {
    let tb = Attrs::parse(&p[FIB_RULE_HDR_LEN..], FRA_MAX)?.ext(ext);
    let u64_attr = |t| -> Result<Option<u64>, KernelError> {
        Ok(tb
            .min(t, 8)?
            .map(|b| u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
    };
    Ok(RuleAttrs {
        src: tb.get(FRA_SRC),
        dst: tb.get(FRA_DST),
        iifname: tb.str(FRA_IIFNAME, IFNAMSIZ)?,
        oifname: tb.str(FRA_OIFNAME, IFNAMSIZ)?,
        pref: tb.u32(FRA_PRIORITY)?,
        mark: tb.u32(FRA_FWMARK)?,
        mask: tb.u32(FRA_FWMASK)?,
        tun_id: u64_attr(FRA_TUN_ID)?,
        table: tb.u32(FRA_TABLE)?,
        suppress_prefixlen: tb.u32(FRA_SUPPRESS_PREFIXLEN)?,
        suppress_ifgroup: tb.u32(FRA_SUPPRESS_IFGROUP)?,
        target: tb.u32(FRA_GOTO)?,
        l3mdev: tb.u8(FRA_L3MDEV)?,
        uid: tb.min(FRA_UID_RANGE, 8)?.map(|b| {
            (
                u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
                u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            )
        }),
        proto: tb.u8(FRA_PROTOCOL)?,
        ip_proto: tb.u8(FRA_IP_PROTO)?,
        sport: tb.min(FRA_SPORT_RANGE, 4)?.map(PortRange::of),
        dport: tb.min(FRA_DPORT_RANGE, 4)?.map(PortRange::of),
        sport_mask: u16_attr(&tb, FRA_SPORT_MASK)?,
        dport_mask: u16_attr(&tb, FRA_DPORT_MASK)?,
        tb,
    })
}

/// NUL-padded copy of `s` (Linux nla_strscpy into IFNAMSIZ)
fn ifname(s: &str) -> [u8; IFNAMSIZ] {
    let mut b = [0u8; IFNAMSIZ];
    let n = s.len().min(IFNAMSIZ - 1);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

/// Linux fib_nl2rule_port_mask
fn port_mask(
    tb: &Attrs<'_>,
    t: u16,
    range: &PortRange,
    m: u16,
    ext: &ExtAck,
) -> Result<u16, KernelError> {
    let at = tb.get(t).unwrap_or_default();
    let e = |s| {
        ext.attr_msg(at, s);
        Err(KernelError::InvalidArgument)
    };
    if !range.valid() {
        return e("Cannot specify port mask without port value");
    }
    if range.is_range() {
        return e("Cannot specify port mask for port range");
    }
    if range.start & !m != 0 {
        return e("Invalid port mask");
    }
    Ok(m)
}

/// The rule a request describes (Linux fib_nl2rule); `user_pref`: it
/// named a priority
fn nl2rule(
    ops: &RulesOps<crate::net::inet::fib_rules::Fib4Rule>,
    h: &RuleHdr,
    a: &RuleAttrs<'_>,
    ext: &ExtAck,
) -> Result<(Rule, bool), KernelError> {
    use KernelError::InvalidArgument as E;
    let bits = ops.addr_size * 8;
    let bad = |len: u8, at: Option<&[u8]>| {
        len != 0 && (at.is_none_or(|b| b.len() != ops.addr_size) || usize::from(len) > bits)
    };
    if bad(h.src_len, a.src) {
        ext.msg("Invalid source address");
        return Err(E);
    }
    if bad(h.dst_len, a.dst) {
        ext.msg("Invalid dst address");
        return Err(E);
    }
    let mut r = Rule::blank();
    r.pref = a.pref.unwrap_or(0);
    r.proto = a.proto.unwrap_or(0);
    if let Some(n) = a.iifname {
        r.iifindex.store(-1, Relaxed);
        r.iifname = ifname(n);
    }
    if let Some(n) = a.oifname {
        r.oifindex.store(-1, Relaxed);
        r.oifname = ifname(n);
    }
    if let Some(m) = a.mark {
        r.mark = m;
        // All bits compared unless a mask is given
        if m != 0 {
            r.mark_mask = u32::MAX;
        }
    }
    if let Some(m) = a.mask {
        r.mark_mask = m;
    }
    r.tun_id = a.tun_id.unwrap_or(0);
    if let Some(l) = a.l3mdev {
        r.l3mdev = l;
        if l != 1 {
            ext.msg("Invalid l3mdev attribute");
            return Err(E);
        }
    }
    r.action = h.action;
    r.flags = h.flags;
    r.table = a.table.unwrap_or(u32::from(h.table));
    r.suppress_prefixlen = a.suppress_prefixlen.map_or(-1, |v| v as i32);
    r.suppress_ifgroup = a.suppress_ifgroup.map_or(-1, |v| v as i32);
    match a.target {
        Some(_) if r.action != FR_ACT_GOTO => {
            ext.msg("Unexpected goto");
            return Err(E);
        }
        Some(t) => r.target = t,
        None if r.action == FR_ACT_GOTO => {
            ext.msg("Missing goto target for action goto");
            return Err(E);
        }
        None => {}
    }
    if r.l3mdev != 0 && r.table != 0 {
        ext.msg("l3mdev and table are mutually exclusive");
        return Err(E);
    }
    if let Some(u) = a.uid {
        r.uid_range = u;
        if !r.uid_set() || u.0 > u.1 {
            ext.msg("Invalid uid range");
            return Err(E);
        }
    }
    r.ip_proto = a.ip_proto.unwrap_or(0);
    if let Some(s) = a.sport {
        if !s.valid() {
            ext.msg("Invalid sport range");
            return Err(E);
        }
        r.sport = s;
        if !s.is_range() {
            r.sport_mask = u16::MAX;
        }
    }
    if let Some(m) = a.sport_mask {
        r.sport_mask = port_mask(&a.tb, FRA_SPORT_MASK, &r.sport, m, ext)?;
    }
    if let Some(d) = a.dport {
        if !d.valid() {
            ext.msg("Invalid dport range");
            return Err(E);
        }
        r.dport = d;
        if !d.is_range() {
            r.dport_mask = u16::MAX;
        }
    }
    if let Some(m) = a.dport_mask {
        r.dport_mask = port_mask(&a.tb, FRA_DPORT_MASK, &r.dport, m, ext)?;
    }
    Ok((r, a.pref.is_some()))
}

/// Linux fib_nl2rule_locked: the default priority, no backward goto,
/// the named devices resolved
fn nl2rule_locked(
    rules: &FibRules,
    net: &NetNamespace,
    r: &mut Rule,
    user_pref: bool,
    ext: &ExtAck,
) -> Result<(), KernelError> {
    let g = crate::sync::rcu::read_lock();
    if !user_pref {
        r.pref = rules.default_pref(&g);
    }
    if r.action == FR_ACT_GOTO && r.target <= r.pref {
        ext.msg("Backward goto not supported");
        return Err(KernelError::InvalidArgument);
    }
    for d in net.devices_rcu(&g) {
        if r.iifname[0] != 0 && name_is(&r.iifname, d.name()) {
            r.iifindex.store(d.ifindex() as i32, Relaxed);
        }
        if r.oifname[0] != 0 && name_is(&r.oifname, d.name()) {
            r.oifindex.store(d.ifindex() as i32, Relaxed);
        }
    }
    Ok(())
}

/// The common fields `a` and `b` share exactly (Linux rule_exists)
fn same_rule(a: &Rule, b: &Rule) -> bool {
    a.action == b.action
        && a.table == b.table
        && a.pref == b.pref
        && a.iifname == b.iifname
        && a.oifname == b.oifname
        && a.mark == b.mark
        && a.suppress_ifgroup == b.suppress_ifgroup
        && a.suppress_prefixlen == b.suppress_prefixlen
        && a.mark_mask == b.mark_mask
        && a.tun_id == b.tun_id
        && a.l3mdev == b.l3mdev
        && a.uid_range == b.uid_range
        && a.ip_proto == b.ip_proto
        && a.proto == b.proto
        && a.sport == b.sport
        && a.sport_mask == b.sport_mask
        && a.dport == b.dport
        && a.dport_mask == b.dport_mask
}

/// `r` has every common field the request `nl` sets (Linux rule_find)
fn rule_matches(r: &Rule, nl: &Rule, user_pref: bool) -> bool {
    (nl.action == 0 || r.action == nl.action)
        && (nl.table == 0 || r.table == nl.table)
        && (!user_pref || r.pref == nl.pref)
        && (nl.iifname[0] == 0 || r.iifname == nl.iifname)
        && (nl.oifname[0] == 0 || r.oifname == nl.oifname)
        && (nl.mark == 0 || r.mark == nl.mark)
        && (nl.suppress_ifgroup == -1 || r.suppress_ifgroup == nl.suppress_ifgroup)
        && (nl.suppress_prefixlen == -1 || r.suppress_prefixlen == nl.suppress_prefixlen)
        && (nl.mark_mask == 0 || r.mark_mask == nl.mark_mask)
        && (nl.tun_id == 0 || r.tun_id == nl.tun_id)
        && (nl.l3mdev == 0 || r.l3mdev == nl.l3mdev)
        && (!nl.uid_set() || r.uid_range == nl.uid_range)
        && (nl.ip_proto == 0 || r.ip_proto == nl.ip_proto)
        && (nl.proto == 0 || r.proto == nl.proto)
        && (!nl.sport.set() || r.sport == nl.sport)
        && (nl.sport_mask == 0 || r.sport_mask == nl.sport_mask)
        && (!nl.dport.set() || r.dport == nl.dport)
        && (nl.dport_mask == 0 || r.dport_mask == nl.dport_mask)
}

/// The rules of `family` in `net` (Linux lookup_rules_ops): IPv4 only
fn rules_of(net: &NetNamespace, family: u8) -> Option<&FibRules> {
    (family == net.fib.rules.ops.family).then_some(&net.fib.rules)
}

/// The header and attributes of a NEW/DELRULE request, with Linux's
/// messages (fib_newrule / fib_delrule's first steps)
fn rule_req<'a>(
    net: &'a NetNamespace,
    p: &'a [u8],
    ext: &'a ExtAck,
) -> Result<(&'a FibRules, RuleHdr, RuleAttrs<'a>), KernelError> {
    let Some(h) = RuleHdr::parse(p) else {
        ext.msg("Invalid msg length");
        return Err(KernelError::InvalidArgument);
    };
    let Some(rules) = rules_of(net, h.family) else {
        ext.msg("Rule family not supported");
        return Err(KernelError::AddressFamilyNotSupported);
    };
    let a = rule_attrs(p, ext).inspect_err(|_| ext.msg("Error parsing msg"))?;
    Ok((rules, h, a))
}

/// RTM_NEWRULE (Linux fib_newrule; RTNL held)
pub fn newrule(
    r: &RtnlGuard,
    net: &NetNamespace,
    nlflags: u16,
    p: &[u8],
    nl: NlInfo,
    ext: &ExtAck,
) -> Result<(), KernelError> {
    let (rules, h, a) = rule_req(net, p, ext)?;
    let (mut rule, user_pref) = nl2rule(rules.ops, &h, &a, ext)?;
    nl2rule_locked(rules, net, &mut rule, user_pref, ext)?;
    if nlflags & NLM_F_EXCL != 0 {
        let g = crate::sync::rcu::read_lock();
        let dup = rules
            .iter(&g)
            .any(|x| same_rule(x, &rule) && (rules.ops.compare)(x, &h, &rule, &a.tb));
        if dup {
            return Err(KernelError::AlreadyExists);
        }
    }
    (rules.ops.configure)(&mut rule, net, r, &h, &a.tb, ext)?;
    let rule = crate::util::kalloc::try_arc(rule)?;
    let pref = rule.pref;
    rules
        .list
        .insert_after(Arc::clone(&rule), |x| x.pref <= pref);
    notify_rule(net, rules, &rule, RTM_NEWRULE, nl);
    Ok(())
}

/// RTM_DELRULE (Linux fib_delrule; RTNL held): the first rule having
/// what the request names; ENOENT if none, EPERM for a permanent one
pub fn delrule(
    _r: &RtnlGuard,
    net: &NetNamespace,
    p: &[u8],
    nl: NlInfo,
    ext: &ExtAck,
) -> Result<(), KernelError> {
    let (rules, h, a) = rule_req(net, p, ext)?;
    let (mut nlrule, user_pref) = nl2rule(rules.ops, &h, &a, ext)?;
    nl2rule_locked(rules, net, &mut nlrule, user_pref, ext)?;
    let found = {
        let g = crate::sync::rcu::read_lock();
        rules
            .iter(&g)
            .find(|x| {
                rule_matches(x, &nlrule, user_pref) && (rules.ops.compare)(x, &h, &nlrule, &a.tb)
            })
            .map(|x| (core::ptr::from_ref(x), x.flags & FIB_RULE_PERMANENT != 0))
    };
    let Some((target, permanent)) = found else {
        return Err(KernelError::NotFound);
    };
    if permanent {
        return Err(KernelError::NotPermitted);
    }
    // RTNL keeps the list as walked: the rule is still there
    let Some(gone) = rules.list.remove_first(|x| core::ptr::eq(x, target)) else {
        return Err(KernelError::NotFound);
    };
    notify_rule(net, rules, gone.item(), RTM_DELRULE, nl);
    gone.defer();
    Ok(())
}

/// Largest rule message (Linux fib_rule_nlmsg_size, which leaves out
/// FRA_GOTO and FRA_L3MDEV and relies on skb slack; an hk buffer has
/// none, so every attribute fill_rule writes is counted)
fn rule_nlmsg_size(ops: &RulesOps<crate::net::inet::fib_rules::Fib4Rule>) -> usize {
    msg_size(
        FIB_RULE_HDR_LEN
            + 2 * attr_size(IFNAMSIZ)
            + 7 * attr_size(4)
            + attr_size(8)
            + attr_size(8)
            + 3 * attr_size(1)
            + 2 * attr_size(4)
            + 2 * attr_size(2)
            + ops.payload,
    )
}

/// Announce a rule change to its family's group (Linux
/// notify_rule_change: echoed with NLM_F_ECHO; without memory the
/// group's listeners get ENOMEM)
fn notify_rule(net: &NetNamespace, rules: &FibRules, r: &Rule, ty: u16, nl: NlInfo) {
    let size = rule_nlmsg_size(rules.ops);
    let built = (|| {
        let mut v = nlmsg_new(size)?;
        let g = crate::sync::rcu::read_lock();
        fill_rule(
            &mut NlBuf::new(&mut v, size),
            rules,
            &g,
            r,
            ty,
            0,
            nl.seq,
            nl.portid,
        )?;
        Ok::<_, KernelError>(v)
    })();
    let group = rules.ops.nlgroup;
    match built {
        Ok(v) => nl_notify(
            net,
            NETLINK_ROUTE,
            kernel_skb(v, group),
            nl.portid,
            nl.report,
            crate::mm::page_alloc::Gfp::KERNEL,
        ),
        Err(_) => set_err(net, NETLINK_ROUTE, group, KernelError::OutOfMemory),
    }
}

/// A rule as a message in `nb` (Linux fib_nl_fill_rule); `g` lets it
/// see whether a goto resolves. EMSGSIZE, nothing left behind, if it
/// does not fit.
#[allow(clippy::too_many_arguments)]
pub fn fill_rule(
    nb: &mut NlBuf<'_>,
    rules: &FibRules,
    g: &RcuReadGuard,
    r: &Rule,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
) -> Result<(), KernelError> {
    let mut h = RuleHdr {
        family: rules.ops.family,
        table: u8::try_from(r.table).unwrap_or(RT_TABLE_COMPAT),
        action: r.action,
        flags: r.flags,
        ..Default::default()
    };
    if r.action == FR_ACT_GOTO && !rules.resolved(g, r.target) {
        h.flags |= FIB_RULE_UNRESOLVED;
    }
    if r.iifname[0] != 0 && r.iifindex() == -1 {
        h.flags |= FIB_RULE_IIF_DETACHED;
    }
    if r.oifname[0] != 0 && r.oifindex() == -1 {
        h.flags |= FIB_RULE_OIF_DETACHED;
    }
    // The header is completed by the attributes' fill: written last
    let m = nb.msg_put(ty, flags, seq, pid, &h.bytes())?;
    let start = nb.len() - FIB_RULE_HDR_LEN;
    match rule_attrs_fill(nb, rules, r, &mut h) {
        Ok(()) => {
            nb.patch(start, &h.bytes());
            nb.msg_end(m);
            Ok(())
        }
        Err(e) => {
            nb.msg_cancel(m);
            Err(e)
        }
    }
}

/// A rule's attributes, in fib_nl_fill_rule's order
fn rule_attrs_fill(
    nb: &mut NlBuf<'_>,
    rules: &FibRules,
    r: &Rule,
    h: &mut RuleHdr,
) -> Result<(), KernelError> {
    let str_put = |nb: &mut NlBuf<'_>, t, n: &[u8; IFNAMSIZ]| {
        let len = n.iter().position(|&c| c == 0).unwrap_or(IFNAMSIZ - 1);
        nb.put(t, &n[..=len])
    };
    nb.put_u32(FRA_TABLE, r.table)?;
    nb.put(FRA_SUPPRESS_PREFIXLEN, &r.suppress_prefixlen.to_ne_bytes())?;
    nb.put(FRA_PROTOCOL, &[r.proto])?;
    if r.iifname[0] != 0 {
        str_put(nb, FRA_IIFNAME, &r.iifname)?;
    }
    if r.oifname[0] != 0 {
        str_put(nb, FRA_OIFNAME, &r.oifname)?;
    }
    if r.pref != 0 {
        nb.put_u32(FRA_PRIORITY, r.pref)?;
    }
    if r.mark != 0 {
        nb.put_u32(FRA_FWMARK, r.mark)?;
    }
    if r.mark_mask != 0 || r.mark != 0 {
        nb.put_u32(FRA_FWMASK, r.mark_mask)?;
    }
    if r.target != 0 {
        nb.put_u32(FRA_GOTO, r.target)?;
    }
    if r.tun_id != 0 {
        nb.put(FRA_TUN_ID, &r.tun_id.to_ne_bytes())?;
    }
    if r.l3mdev != 0 {
        nb.put(FRA_L3MDEV, &[r.l3mdev])?;
    }
    if r.uid_set() {
        let mut u = [0u8; 8];
        u[..4].copy_from_slice(&r.uid_range.0.to_ne_bytes());
        u[4..].copy_from_slice(&r.uid_range.1.to_ne_bytes());
        nb.put(FRA_UID_RANGE, &u)?;
    }
    if r.sport.set() {
        nb.put(FRA_SPORT_RANGE, &r.sport.bytes())?;
    }
    if r.sport_mask != 0 {
        nb.put(FRA_SPORT_MASK, &r.sport_mask.to_ne_bytes())?;
    }
    if r.dport.set() {
        nb.put(FRA_DPORT_RANGE, &r.dport.bytes())?;
    }
    if r.dport_mask != 0 {
        nb.put(FRA_DPORT_MASK, &r.dport_mask.to_ne_bytes())?;
    }
    if r.ip_proto != 0 {
        nb.put(FRA_IP_PROTO, &[r.ip_proto])?;
    }
    if r.suppress_ifgroup != -1 {
        nb.put(FRA_SUPPRESS_IFGROUP, &r.suppress_ifgroup.to_ne_bytes())?;
    }
    (rules.ops.fill)(r, h, nb)
}

/// A rule dump request (Linux fib_nl_dumprule, fib_valid_dumprule_req
/// when strict): the family's rules, or the error and its message.
/// AF_UNSPEC lists every family's: IPv4's.
pub fn dump_req(
    net: &NetNamespace,
    p: &[u8],
    strict: bool,
) -> Result<(), (KernelError, Option<&'static str>)> {
    use KernelError::InvalidArgument as E;
    if strict {
        let Some(h) = RuleHdr::parse(p) else {
            return Err((E, Some("Invalid header for fib rule dump request")));
        };
        if h.dst_len != 0
            || h.src_len != 0
            || h.tos != 0
            || h.table != 0
            || h.res1 != 0
            || h.res2 != 0
            || h.action != 0
            || h.flags != 0
        {
            return Err((
                E,
                Some("Invalid values in header for fib rule dump request"),
            ));
        }
        if p.len() > FIB_RULE_HDR_LEN {
            return Err((
                E,
                Some("Invalid data after header in fib rule dump request"),
            ));
        }
    }
    match p.first() {
        Some(0) | None => Ok(()),
        Some(&f) if rules_of(net, f).is_some() => Ok(()),
        Some(_) => Err((KernelError::AddressFamilyNotSupported, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::inet::fib_rules::FIB4_RULES_OPS;

    fn rule(pref: u32, action: u8, target: u32) -> Rule {
        let mut r = Rule::default_rule(pref, pref);
        r.action = action;
        r.target = target;
        r
    }

    fn rules(v: &[Rule]) -> FibRules {
        let r = FibRules::new(&FIB4_RULES_OPS, &[]).unwrap();
        for x in v {
            let mut y = rule(x.pref, x.action, x.target);
            y.flags = x.flags;
            r.list.push_back(crate::util::kalloc::arc_nofail(y));
        }
        r
    }

    /// The table of the first lookup rule reached (its pref here)
    fn walk(r: &FibRules, skip: &[u32]) -> Result<u32, KernelError> {
        r.lookup(
            &RuleFlow::default(),
            |_| true,
            |x| Ok((!skip.contains(&x.table)).then_some(x.table)),
            |_, _| false,
        )
    }

    /// A goto jumps forward to the first rule of its target priority;
    /// without one it is passed over; NOP passes; exhaustion is ESRCH
    #[test]
    fn goto_and_nop() {
        let r = rules(&[
            rule(10, FR_ACT_GOTO, 30),
            rule(20, FR_ACT_TO_TBL, 0),
            rule(30, FR_ACT_TO_TBL, 0),
        ]);
        assert_eq!(walk(&r, &[]), Ok(30));
        let r = rules(&[
            rule(10, FR_ACT_GOTO, 25),
            rule(20, FR_ACT_NOP, 0),
            rule(30, FR_ACT_TO_TBL, 0),
        ]);
        assert_eq!(walk(&r, &[]), Ok(30));
        assert_eq!(walk(&r, &[30]), Err(KernelError::NoProcess));
    }

    /// INVERT turns a match into a miss
    #[test]
    fn invert() {
        let mut a = rule(10, FR_ACT_TO_TBL, 0);
        a.flags = FIB_RULE_INVERT;
        let r = rules(&[a, rule(20, FR_ACT_TO_TBL, 0)]);
        assert_eq!(walk(&r, &[]), Ok(20));
    }

    /// A rule with every attribute set fits the size its notification
    /// is allocated with (Linux fib_rule_nlmsg_size)
    #[test]
    fn full_rule_fits() {
        let mut r = rule(10, FR_ACT_GOTO, 30);
        r.table = 100;
        r.iifname = [b'i'; IFNAMSIZ];
        r.iifname[IFNAMSIZ - 1] = 0;
        r.oifname = [b'o'; IFNAMSIZ];
        r.oifname[IFNAMSIZ - 1] = 0;
        (r.mark, r.mark_mask, r.tun_id, r.l3mdev) = (1, 1, 1, 1);
        (r.uid_range, r.ip_proto) = ((1, 2), 6);
        r.sport = PortRange { start: 1, end: 2 };
        r.dport = PortRange { start: 1, end: 2 };
        (r.sport_mask, r.dport_mask, r.suppress_ifgroup) = (1, 1, 1);
        let a = &mut r.af;
        (a.dst_len, a.src_len, a.dscp_full, a.dscp, a.tclassid) = (8, 8, true, 4, 1);
        let rs = rules(&[]);
        let size = rule_nlmsg_size(rs.ops);
        let mut v = nlmsg_new(size).unwrap();
        let g = crate::sync::rcu::read_lock();
        let mut nb = NlBuf::new(&mut v, size);
        assert!(fill_rule(&mut nb, &rs, &g, &r, RTM_NEWRULE, 0, 0, 0).is_ok());
    }

    /// Port ranges and masks (Linux fib_rule_port_match)
    #[test]
    fn ports() {
        let p = PortRange { start: 80, end: 90 };
        assert!(p.matches(0, 85));
        assert!(!p.matches(0, 91));
        let one = PortRange { start: 80, end: 80 };
        assert!(one.matches(0xffff, 80));
        assert!(!one.matches(0xffff, 81));
        assert!(PortRange::default().matches(0, 1234));
        assert!(
            !PortRange {
                start: 1,
                end: 0xffff
            }
            .valid()
        );
    }
}
