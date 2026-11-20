//! IPv4 routing rules (Linux net/ipv4/fib_rules.c)
//!
//! The family's part of the rule engine (`net::fib_rules`): source and
//! destination prefixes, TOS / DSCP, the IP protocol and ports, and the
//! action of a rule: a table lookup (`fib4_rule_action`) whose result a
//! rule may suppress by prefix length or device group. Every namespace
//! starts with Linux's three rules (fib_default_rules_init): priority 0
//! looks up table local, 32766 main, 32767 default.

use crate::net::NetNamespace;
use crate::net::device::NetDevice;
use crate::net::fib_rules::{
    FR_ACT_BLACKHOLE, FR_ACT_PROHIBIT, FR_ACT_TO_TBL, FR_ACT_UNREACHABLE, FRA_DSCP, FRA_DSCP_MASK,
    FRA_DST, FRA_FLOW, FRA_FLOWLABEL, FRA_FLOWLABEL_MASK, FRA_SRC, FibRule, FibRules, RuleFlow,
    RuleHdr, RulesOps,
};
use crate::net::inet::fib::{FlowKey, RT_TABLE_DEFAULT, RT_TABLE_LOCAL, RT_TABLE_MAIN};
use crate::net::inet::ifaddr::inet_make_mask;
use crate::net::ipv4::Ipv4Addr;
use crate::net::netlink::ExtAck;
use crate::net::netlink::attr::{Attrs, NlBuf, attr_size};
use crate::net::rtnl::RtnlGuard;
use crate::util::error::KernelError;

/// Multicast group (Linux RTNLGRP_IPV4_RULE)
pub const RTNLGRP_IPV4_RULE: u32 = 8;
/// Linux INET_DSCP_MASK, IPTOS_TOS_MASK, INET_DSCP_LEGACY_TOS_MASK
const INET_DSCP_MASK: u8 = 0xfc;
const IPTOS_TOS_MASK: u8 = 0x1e;
const DSCP_LEGACY_TOS_MASK: u8 = 0x1c;
/// Highest table id fib_empty_table hands out (Linux
/// FIB_MAX_AUTO_TABLE_ID)
const FIB_MAX_AUTO_TABLE_ID: u32 = 4096;

/// The IPv4 part of a rule (Linux struct fib4_rule)
#[derive(Default)]
pub struct Fib4Rule {
    pub src: Ipv4Addr,
    pub src_len: u8,
    pub dst: Ipv4Addr,
    pub dst_len: u8,
    /// DS field bits selected (Linux dscp, as a dsfield)
    pub dscp: u8,
    pub dscp_mask: u8,
    /// Selected by FRA_DSCP (whole field) rather than the header's TOS
    pub dscp_full: bool,
    /// FRA_FLOW (Linux tclassid; no route classifier uses it)
    pub tclassid: u32,
}

pub type Rule = FibRule<Fib4Rule>;

/// The IPv4 rules' operations (Linux fib4_rules_ops_template)
pub static FIB4_RULES_OPS: RulesOps<Fib4Rule> = RulesOps {
    family: 2,
    addr_size: 4,
    nlgroup: RTNLGRP_IPV4_RULE,
    configure: fib4_rule_configure,
    compare: fib4_rule_compare,
    fill: fib4_rule_fill,
    payload: 3 * attr_size(4) + 2 * attr_size(1),
};

/// A namespace's rules, Linux's defaults (fib4_rules_init)
pub fn fib4_rules_init() -> Result<FibRules, KernelError> {
    FibRules::new(
        &FIB4_RULES_OPS,
        &[
            (0, RT_TABLE_LOCAL),
            (0x7FFE, RT_TABLE_MAIN),
            (0x7FFF, RT_TABLE_DEFAULT),
        ],
    )
}

/// The common selectors' view of `key`
pub fn rule_flow(key: &FlowKey) -> RuleFlow {
    RuleFlow {
        iif: key.iif,
        oif: key.oif,
        mark: key.mark,
        uid: key.uid,
    }
}

/// Linux fib4_rule_match: prefixes, DSCP, protocol, ports
pub fn fib4_rule_match(r: &Rule, key: &FlowKey) -> bool {
    let a = &r.af;
    let (srcmask, dstmask) = (inet_make_mask(a.src_len), inet_make_mask(a.dst_len));
    if (key.saddr.0 ^ a.src.0) & srcmask.0 != 0 || (key.daddr.0 ^ a.dst.0) & dstmask.0 != 0 {
        return false;
    }
    let fl_dscp = key.tos & INET_DSCP_MASK;
    if a.dscp_full {
        if (a.dscp ^ fl_dscp) & a.dscp_mask != 0 {
            return false;
        }
    } else if a.dscp != 0 && a.dscp != fl_dscp & DSCP_LEGACY_TOS_MASK {
        return false;
    }
    if r.ip_proto != 0 && r.ip_proto != key.proto {
        return false;
    }
    r.sport.matches(r.sport_mask, key.sport) && r.dport.matches(r.dport_mask, key.dport)
}

/// Linux fib4_rule_suppress: a result of too short a prefix, or through
/// a device of the suppressed group, is passed over
pub fn fib4_rule_suppress(r: &Rule, prefixlen: u8, dev: Option<&NetDevice>) -> bool {
    if i32::from(prefixlen) <= r.suppress_prefixlen {
        return true;
    }
    r.suppress_ifgroup != -1 && dev.is_some_and(|d| d.group() as i32 == r.suppress_ifgroup)
}

/// Linux fib4_rule_action's verdict before the table lookup: Ok(table)
/// to look up, or the action's error
pub fn fib4_rule_action(r: &Rule) -> Result<u32, KernelError> {
    match r.action {
        FR_ACT_TO_TBL => Ok(r.table),
        FR_ACT_UNREACHABLE => Err(KernelError::NetworkUnreachable),
        FR_ACT_PROHIBIT => Err(KernelError::PermissionDenied),
        FR_ACT_BLACKHOLE => Err(KernelError::InvalidArgument),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// Linux fib4_nl2rule_dscp, fib4_nl2rule_dscp_mask
fn nl2rule_dscp(a: &mut Fib4Rule, tb: &Attrs<'_>, ext: &ExtAck) -> Result<(), KernelError> {
    use KernelError::InvalidArgument as E;
    if let Some(d) = tb.u8(FRA_DSCP)? {
        if d > INET_DSCP_MASK >> 2 {
            ext.attr_msg(
                tb.get(FRA_DSCP).unwrap_or_default(),
                "Attribute failed policy validation",
            );
            return Err(KernelError::Range);
        }
        if a.dscp != 0 {
            ext.msg("Cannot specify both TOS and DSCP");
            return Err(E);
        }
        a.dscp = d << 2;
        a.dscp_mask = INET_DSCP_MASK;
        a.dscp_full = true;
    }
    if let Some(m) = tb.u8(FRA_DSCP_MASK)? {
        let at = tb.get(FRA_DSCP_MASK).unwrap_or_default();
        if !a.dscp_full {
            ext.attr_msg(at, "Cannot specify DSCP mask without DSCP value");
            return Err(E);
        }
        let mask = (m << 2) & INET_DSCP_MASK;
        if a.dscp & !mask != 0 {
            ext.attr_msg(at, "Invalid DSCP mask");
            return Err(E);
        }
        a.dscp_mask = mask;
    }
    Ok(())
}

/// Linux fib4_rule_configure: the IPv4 selectors, and the first unused
/// table for a table-less lookup rule (fib_empty_table)
fn fib4_rule_configure(
    r: &mut Rule,
    net: &NetNamespace,
    rtnl: &RtnlGuard,
    h: &RuleHdr,
    tb: &Attrs<'_>,
    ext: &ExtAck,
) -> Result<(), KernelError> {
    use KernelError::InvalidArgument as E;
    if tb.has(FRA_FLOWLABEL) || tb.has(FRA_FLOWLABEL_MASK) {
        ext.msg("Flow label cannot be specified for IPv4 FIB rules");
        return Err(E);
    }
    if h.tos & !INET_DSCP_MASK != 0 {
        ext.msg("Invalid dsfield (tos): ECN bits must be 0");
        return Err(E);
    }
    if h.tos & !IPTOS_TOS_MASK != 0 {
        ext.msg("Invalid tos");
        return Err(E);
    }
    r.af.dscp = h.tos & INET_DSCP_MASK;
    nl2rule_dscp(&mut r.af, tb, ext)?;
    if r.table == 0 && r.l3mdev == 0 && r.action == FR_ACT_TO_TBL {
        r.table = (1..=FIB_MAX_AUTO_TABLE_ID)
            .find(|&id| !net.fib.has_table(id))
            .ok_or(KernelError::NoBufferSpace)?;
        net.fib.new_table_rtnl(rtnl, r.table)?;
    }
    let addr = |t| tb.in_addr(t).map(Option::unwrap_or_default);
    if h.src_len != 0 {
        r.af.src = addr(FRA_SRC)?;
    }
    if h.dst_len != 0 {
        r.af.dst = addr(FRA_DST)?;
    }
    r.af.tclassid = tb.u32(FRA_FLOW)?.unwrap_or(0);
    r.af.src_len = h.src_len;
    r.af.dst_len = h.dst_len;
    Ok(())
}

/// Linux fib4_rule_compare: the IPv4 selectors the request names
fn fib4_rule_compare(r: &Rule, h: &RuleHdr, _nl: &Rule, tb: &Attrs<'_>) -> bool {
    let a = &r.af;
    if h.src_len != 0 && a.src_len != h.src_len {
        return false;
    }
    if h.dst_len != 0 && a.dst_len != h.dst_len {
        return false;
    }
    if h.tos != 0 && (a.dscp_full || a.dscp != h.tos) {
        return false;
    }
    if let Ok(Some(d)) = tb.u8(FRA_DSCP)
        && (!a.dscp_full || a.dscp != d << 2)
    {
        return false;
    }
    if let Ok(Some(m)) = tb.u8(FRA_DSCP_MASK)
        && (!a.dscp_full || a.dscp_mask != (m << 2) & INET_DSCP_MASK)
    {
        return false;
    }
    if let Ok(Some(f)) = tb.u32(FRA_FLOW)
        && a.tclassid != f
    {
        return false;
    }
    if h.src_len != 0 && tb.in_addr(FRA_SRC).ok().flatten() != Some(a.src) {
        return false;
    }
    !(h.dst_len != 0 && tb.in_addr(FRA_DST).ok().flatten() != Some(a.dst))
}

/// Linux fib4_rule_fill
fn fib4_rule_fill(r: &Rule, h: &mut RuleHdr, nb: &mut NlBuf<'_>) -> Result<(), KernelError> {
    let a = &r.af;
    h.dst_len = a.dst_len;
    h.src_len = a.src_len;
    if a.dscp_full {
        h.tos = 0;
        nb.put(FRA_DSCP, &[a.dscp >> 2])?;
        nb.put(FRA_DSCP_MASK, &[a.dscp_mask >> 2])?;
    } else {
        h.tos = a.dscp;
    }
    if a.dst_len != 0 {
        nb.put(FRA_DST, &a.dst.to_be_bytes())?;
    }
    if a.src_len != 0 {
        nb.put(FRA_SRC, &a.src.to_be_bytes())?;
    }
    if a.tclassid != 0 {
        nb.put_u32(FRA_FLOW, a.tclassid)?;
    }
    Ok(())
}
