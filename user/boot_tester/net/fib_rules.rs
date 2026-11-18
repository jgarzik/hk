//! IPv4 routing rules over NETLINK_ROUTE (hk and Linux)
//!
//! - NL_RULE_DUMP (in a new network namespace, so only the defaults
//!   exist): an AF_INET RTM_GETRULE dump returns exactly the three rules
//!   Linux installs (fib_default_rules_init), byte for byte as
//!   fib_nl_fill_rule builds them: priority 0 table local, 32766 main,
//!   32767 default, action FR_ACT_TO_TBL, protocol kernel, no prefix
//!   suppression; an AF_UNSPEC dump holds the same AF_INET rules (other
//!   families' rules are ignored); a strict dump with a non-zero table
//!   in the header is EINVAL

use hk_syscall::{CLONE_NEWNET, sys_exit, sys_fork, sys_setsockopt, sys_unshare};

use crate::harness::{T, fail_num, pass};
use crate::helpers::{host_mode, println, skip};
use crate::net::nl::*;
use crate::net::tcp_xfer::wait_child;

const EINVAL: i64 = -22;
const AF_UNSPEC: u8 = 0;
const RT_TABLE_DEFAULT: u8 = 253;
const FR_ACT_TO_TBL: u8 = 1;
const FRA_PRIORITY: u16 = 6;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_PROTOCOL: u16 = 21;

pub fn run_tests() {
    println(b"=== FIB rule Tests ===");
    test_rule_dump();
}

/// The checks run in a child in a new network namespace (exit 2: no
/// unshare)
fn test_rule_dump() {
    let pid = sys_fork();
    if pid < 0 {
        println(b"NL_RULE_DUMP:FAIL fork");
        return;
    }
    if pid == 0 {
        if sys_unshare(CLONE_NEWNET) != 0 {
            sys_exit(2);
        }
        sys_exit(if rule_dump() { 0 } else { 1 });
    }
    let st = wait_child(pid);
    let code = (st >> 8) & 0xff;
    if st & 0x7f == 0 && code == 0 {
        pass(b"NL_RULE_DUMP");
    } else if code == 2 && host_mode() {
        skip(b"NL_RULE_DUMP", b"unshare(CLONE_NEWNET) not permitted");
    } else if code != 1 {
        fail_num(b"NL_RULE_DUMP:FAIL status=", st as i64);
    }
}

/// The RTM_NEWRULE Linux sends for a default rule: fib_rule_hdr,
/// FRA_TABLE, FRA_SUPPRESS_PREFIXLEN (-1), FRA_PROTOCOL, and
/// FRA_PRIORITY unless 0
fn expected(pref: u32, table: u8) -> Req {
    let frh = [AF_INET, 0, 0, 0, table, 0, 0, FR_ACT_TO_TBL, 0, 0, 0, 0];
    let mut r = Req::new(RTM_NEWRULE, 0, &frh);
    r.u32(FRA_TABLE, u32::from(table))
        .u32(FRA_SUPPRESS_PREFIXLEN, u32::MAX)
        .attr(FRA_PROTOCOL, &[RTPROT_KERNEL]);
    if pref != 0 {
        r.u32(FRA_PRIORITY, pref);
    }
    r
}

const DEFAULTS: [(u32, u8); 3] = [
    (0, RT_TABLE_LOCAL),
    (32766, RT_TABLE_MAIN),
    (32767, RT_TABLE_DEFAULT),
];

/// Dump `family`'s rules; every AF_INET one must be the next default.
/// Returns (dump result, AF_INET rules matched, first mismatch index+1)
fn dump(nl: &mut Nl, family: u8) -> (i32, usize, usize) {
    let mut r = Req::new(RTM_GETRULE, 0, &[family, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let (mut seen, mut bad) = (0usize, 0usize);
    let n = nl.dump(&mut r, &mut |m| {
        if m.body.first() != Some(&AF_INET) {
            return;
        }
        let ok = match DEFAULTS.get(seen) {
            Some(&(pref, table)) => {
                m.ty == RTM_NEWRULE
                    && m.flags == NLM_F_MULTI
                    && m.body == expected(pref, table).body()
            }
            None => false,
        };
        seen += 1;
        if !ok && bad == 0 {
            bad = seen;
        }
    });
    (n, seen, bad)
}

fn rule_dump() -> bool {
    let mut t = T::new(b"NL_RULE_DUMP");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"open", false, 0);
        return false;
    };
    let (n, seen, bad) = dump(&mut nl, AF_INET);
    t.eq(b"inet dump", n as i64, 3);
    t.eq(b"inet rules", seen as i64, 3);
    t.eq(b"inet rule differs", bad as i64, 0);
    let (n, seen, bad) = dump(&mut nl, AF_UNSPEC);
    t.ok(b"unspec dump", n >= 3, n as i64);
    t.eq(b"unspec inet rules", seen as i64, 3);
    t.eq(b"unspec rule differs", bad as i64, 0);
    // Strict checking: only the family may be set
    let one: i32 = 1;
    let p1 = &one as *const i32 as *const u8;
    sys_setsockopt(nl.fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, p1, 4);
    let hdr = [AF_INET, 0, 0, 0, RT_TABLE_MAIN, 0, 0, 0, 0, 0, 0, 0];
    let mut r = Req::new(RTM_GETRULE, 0, &hdr);
    let n = nl.dump(&mut r, &mut |_| {});
    t.eq(b"strict table", n as i64, EINVAL);
    let (n, seen, _) = dump(&mut nl, AF_INET);
    t.eq(b"strict dump", n as i64, 3);
    t.eq(b"strict rules", seen as i64, 3);
    // The parent reports success
    !t.failed()
}
