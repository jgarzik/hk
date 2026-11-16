//! IPv4 routing rules (Linux net/ipv4/fib_rules.c, net/core/fib_rules.c)
//!
//! Every namespace has exactly the three rules Linux installs
//! (fib_default_rules_init): priority 0 looks up table local, 32766
//! main, 32767 default. Rules cannot be added or deleted, so one
//! immutable list serves all namespaces and needs no lock.

use crate::net::inet::fib::{RT_TABLE_DEFAULT, RT_TABLE_LOCAL, RT_TABLE_MAIN, RTPROT_KERNEL};

/// Rule actions (Linux FR_ACT_*)
pub const FR_ACT_TO_TBL: u8 = 1;

/// One rule (Linux struct fib4_rule): no selectors, no fwmark, no
/// interface, no ifgroup suppression
pub struct FibRule {
    /// Priority (Linux pref)
    pub pref: u32,
    pub table: u32,
    pub action: u8,
    /// Originator (RTPROT_*)
    pub proto: u8,
    /// Suppress routes with a prefix this long or shorter; -1 = off
    pub suppress_prefixlen: i32,
}

const fn default_rule(pref: u32, table: u32) -> FibRule {
    // Linux fib_default_rule_add
    FibRule {
        pref,
        table,
        action: FR_ACT_TO_TBL,
        proto: RTPROT_KERNEL,
        suppress_prefixlen: -1,
    }
}

/// The rules in priority order (Linux ops->rules_list)
pub static RULES: [FibRule; 3] = [
    default_rule(0, RT_TABLE_LOCAL),
    default_rule(0x7FFE, RT_TABLE_MAIN),
    default_rule(0x7FFF, RT_TABLE_DEFAULT),
];
