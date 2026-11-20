//! IPv4 routing rules over NETLINK_ROUTE (hk and Linux)
//!
//! - NL_RULE_ENGINE (new namespace): RTM_NEWRULE/DELRULE with Linux's
//!   validation (EEXIST, backward or missing goto), lookups through the
//!   rules (source prefix to a user table, table default, unreachable /
//!   prohibit / blackhole actions, goto resolved and unresolved, local
//!   first), FIB_RULE_UNRESOLVED / IIF_DETACHED in dumps, a table-less
//!   rule given table 1, delete by attributes, RTNLGRP_IPV4_RULE events
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
    run_engine_tests();
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

const RTM_DELRULE: u16 = 33;
const RTNLGRP_IPV4_RULE: i32 = 8;
const FRA_DST: u16 = 1;
const FRA_SRC: u16 = 2;
const FRA_IIFNAME: u16 = 3;
const FRA_GOTO: u16 = 4;
const FRA_OIFNAME: u16 = 17;
const RTA_SRC: u16 = 2;
const RTA_TABLE: u16 = 15;
const FR_ACT_GOTO: u8 = 2;
const FR_ACT_BLACKHOLE: u8 = 6;
const FR_ACT_UNREACHABLE: u8 = 7;
const FR_ACT_PROHIBIT: u8 = 8;
const FIB_RULE_UNRESOLVED: u32 = 4;
const FIB_RULE_IIF_DETACHED: u32 = 8;
const EEXIST: i64 = -17;
const ENOENT: i64 = -2;
const EACCES: i64 = -13;
const ENETUNREACH: i64 = -101;

/// NL_RULE_ENGINE, in a new network namespace
fn run_engine_tests() {
    crate::net::rtnl_ack::in_netns(b"NL_RULE_ENGINE", rule_engine);
}

/// struct fib_rule_hdr
fn frh(src_len: u8, dst_len: u8, table: u8, action: u8) -> [u8; 12] {
    [
        AF_INET, dst_len, src_len, 0, table, 0, 0, action, 0, 0, 0, 0,
    ]
}

/// RTM_NEWRULE / RTM_DELRULE: (header, priority, extra attributes)
fn rule_req(ty: u16, flags: u16, h: [u8; 12], pref: u32, f: &dyn Fn(&mut Req)) -> Req {
    let mut r = Req::new(ty, flags, &h);
    r.u32(FRA_PRIORITY, pref);
    f(&mut r);
    r
}

/// The dumped rule of priority `pref`: (flags, table, action, attribute
/// `attr`'s first 4 bytes as u32, or its length if shorter)
fn find_rule(nl: &mut Nl, pref: u32, attr: u16) -> Option<(u32, u32, u8, u32)> {
    let mut out = None;
    let mut r = Req::new(RTM_GETRULE, 0, &frh(0, 0, 0, 0));
    nl.dump(&mut r, &mut |m| {
        if m.body.first() != Some(&AF_INET) || m.attr_u32(12, FRA_PRIORITY).unwrap_or(0) != pref {
            return;
        }
        let a = m.attr(12, attr).map_or(0, |a| {
            if a.len() >= 4 {
                u32::from_ne_bytes([a[0], a[1], a[2], a[3]])
            } else {
                a.len() as u32
            }
        });
        let t = m.attr_u32(12, FRA_TABLE).unwrap_or(0);
        out = Some((m.u32_at(8), t, m.body[7], a));
    });
    out
}

/// "ip route get `dst` [from `src`]": the table of the answer, or the
/// error
fn route_get(nl: &mut Nl, dst: [u8; 4], src: Option<[u8; 4]>) -> i64 {
    let mut r = Req::new(RTM_GETROUTE, 0, &rtmsg(32, 0, 0, 0, 0));
    r.attr(RTA_DST, &dst);
    if let Some(s) = src {
        r.attr(RTA_SRC, &s);
    }
    let seq = nl.send(&mut r);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    let mut out = -10000;
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if m.seq != seq {
                return;
            }
            if m.ty == NLMSG_ERROR {
                out = i64::from(m.error());
            } else if m.ty == RTM_NEWROUTE {
                out = i64::from(m.attr_u32(12, RTA_TABLE).unwrap_or(0));
            }
        });
    }
    out
}

/// A route `dst/plen` through lo in `table`
fn lo_route(nl: &mut Nl, dst: [u8; 4], plen: u8, table: u32) -> i64 {
    let mut r = Req::new(
        RTM_NEWROUTE,
        NLM_F_CREATE | NLM_F_EXCL,
        &rtmsg(plen, 0, RTPROT_BOOT, RT_SCOPE_LINK, RTN_UNICAST),
    );
    r.attr(RTA_DST, &dst).u32(RTA_OIF, 1).u32(RTA_TABLE, table);
    i64::from(nl.ack(&mut r))
}

/// The next RTNLGRP_IPV4_RULE message's type and priority on `sub`
fn rule_event(sub: &Nl) -> (u16, u32) {
    if !wait_readable(sub.fd, 1000) {
        return (0, 0);
    }
    let buf = rxbuf();
    let n = sub.recv(buf, 0);
    let mut out = (0, 0);
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if out.0 == 0 {
                out = (m.ty, m.attr_u32(12, FRA_PRIORITY).unwrap_or(0));
            }
        });
    }
    out
}

fn rule_engine(name: &'static [u8]) -> bool {
    let mut t = T::new(name);
    let (Some(mut nl), Some(sub)) = (Nl::open(), Nl::open()) else {
        t.ok(b"open", false, 0);
        return false;
    };
    let g = RTNLGRP_IPV4_RULE;
    let p = &g as *const i32 as *const u8;
    let r = sys_setsockopt(sub.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, p, 4);
    t.eq(b"subscribe", r, 0);
    t.eq(b"lo up", i64::from(set_link_up(&mut nl, 1, true)), 0);
    let ip = [10, 20, 0, 1];
    t.eq(
        b"addr",
        i64::from(addr(&mut nl, true, 1, ip, 32, NLM_F_CREATE)),
        0,
    );
    t.eq(b"route 100", lo_route(&mut nl, [10, 30, 0, 0], 24, 100), 0);
    t.eq(
        b"route default",
        lo_route(&mut nl, [10, 50, 0, 0], 24, 253),
        0,
    );
    // Table default is walked (rule 32767)
    t.eq(
        b"get default",
        route_get(&mut nl, [10, 50, 0, 9], None),
        253,
    );
    t.eq(
        b"get no rule",
        route_get(&mut nl, [10, 30, 0, 5], Some(ip)),
        ENETUNREACH,
    );
    // from 10.20.0.0/16 lookup 100
    let ce = NLM_F_CREATE | NLM_F_EXCL;
    let src = |r: &mut Req| {
        r.attr(FRA_SRC, &[10, 20, 0, 0]).u32(FRA_TABLE, 100);
    };
    let mut r = rule_req(RTM_NEWRULE, ce, frh(16, 0, 0, FR_ACT_TO_TBL), 1000, &src);
    t.eq(b"add", i64::from(nl.ack(&mut r)), 0);
    t.ok(b"add event", rule_event(&sub) == (RTM_NEWRULE, 1000), 0);
    let mut r = rule_req(RTM_NEWRULE, ce, frh(16, 0, 0, FR_ACT_TO_TBL), 1000, &src);
    t.eq(b"excl", i64::from(nl.ack(&mut r)), EEXIST);
    let want = Some((0, 100, FR_ACT_TO_TBL, u32::from_ne_bytes([10, 20, 0, 0])));
    t.ok(b"dump", find_rule(&mut nl, 1000, FRA_SRC) == want, 0);
    t.eq(
        b"get from",
        route_get(&mut nl, [10, 30, 0, 5], Some(ip)),
        100,
    );
    t.eq(
        b"get not from",
        route_get(&mut nl, [10, 30, 0, 5], None),
        ENETUNREACH,
    );
    // Actions that end the lookup
    for (pref, act, d, want) in [
        (900, FR_ACT_UNREACHABLE, 40, ENETUNREACH),
        (901, FR_ACT_PROHIBIT, 41, EACCES),
        (902, FR_ACT_BLACKHOLE, 42, EINVAL),
    ] {
        let to = |r: &mut Req| {
            r.attr(FRA_DST, &[10, d, 0, 0]);
        };
        let mut r = rule_req(RTM_NEWRULE, ce, frh(0, 16, 0, act), pref, &to);
        t.eq(b"add act", i64::from(nl.ack(&mut r)), 0);
        rule_event(&sub);
        t.eq(b"act", route_get(&mut nl, [10, d, 0, 1], None), want);
    }
    // goto: forward only, a target required, unresolved without one
    let gt = |target: u32| {
        move |r: &mut Req| {
            r.u32(FRA_GOTO, target);
        }
    };
    let mut r = rule_req(RTM_NEWRULE, ce, frh(0, 0, 0, FR_ACT_GOTO), 500, &gt(400));
    t.eq(b"backward goto", i64::from(nl.ack(&mut r)), EINVAL);
    let mut r = rule_req(RTM_NEWRULE, ce, frh(0, 0, 0, FR_ACT_GOTO), 500, &|_| {});
    t.eq(b"no target", i64::from(nl.ack(&mut r)), EINVAL);
    let mut r = rule_req(RTM_NEWRULE, ce, frh(0, 0, 0, FR_ACT_GOTO), 500, &gt(600));
    t.eq(b"goto", i64::from(nl.ack(&mut r)), 0);
    rule_event(&sub);
    let f = find_rule(&mut nl, 500, FRA_GOTO).map_or(0, |x| x.0);
    t.eq(
        b"unresolved",
        i64::from(f & FIB_RULE_UNRESOLVED),
        i64::from(FIB_RULE_UNRESOLVED),
    );
    // A rule at the target resolves it: goto 600 -> unreachable
    let mut r = rule_req(
        RTM_NEWRULE,
        ce,
        frh(0, 0, 0, FR_ACT_UNREACHABLE),
        600,
        &|_| {},
    );
    t.eq(b"target", i64::from(nl.ack(&mut r)), 0);
    rule_event(&sub);
    let f = find_rule(&mut nl, 500, FRA_GOTO).map_or(-1, |x| i64::from(x.0));
    t.eq(b"resolved", f & i64::from(FIB_RULE_UNRESOLVED), 0);
    t.eq(
        b"goto jumps",
        route_get(&mut nl, [10, 30, 0, 5], Some(ip)),
        ENETUNREACH,
    );
    // Local routes still win (rule 0)
    t.eq(b"local first", route_get(&mut nl, ip, None), 255);
    let mut r = rule_req(RTM_DELRULE, 0, frh(0, 0, 0, 0), 600, &|_| {});
    t.eq(b"del target", i64::from(nl.ack(&mut r)), 0);
    t.ok(b"del event", rule_event(&sub) == (RTM_DELRULE, 600), 0);
    t.eq(
        b"goto falls through",
        route_get(&mut nl, [10, 30, 0, 5], Some(ip)),
        100,
    );
    let mut r = rule_req(RTM_DELRULE, 0, frh(0, 0, 0, 0), 600, &|_| {});
    t.eq(b"del again", i64::from(nl.ack(&mut r)), ENOENT);
    // Interfaces by name; one that does not exist is detached
    let iif = |r: &mut Req| {
        r.attr(FRA_IIFNAME, b"nosuchdev0\0").u32(FRA_TABLE, 101);
    };
    let mut r = rule_req(RTM_NEWRULE, ce, frh(0, 0, 0, FR_ACT_TO_TBL), 1100, &iif);
    t.eq(b"iif", i64::from(nl.ack(&mut r)), 0);
    let f = find_rule(&mut nl, 1100, FRA_IIFNAME).map_or(0, |x| x.0);
    let d = FIB_RULE_IIF_DETACHED;
    t.eq(b"detached", i64::from(f & d), i64::from(d));
    let oif = |r: &mut Req| {
        r.attr(FRA_OIFNAME, b"lo\0").u32(FRA_TABLE, 102);
    };
    let mut r = rule_req(RTM_NEWRULE, ce, frh(0, 0, 0, FR_ACT_TO_TBL), 1101, &oif);
    t.eq(b"oif", i64::from(nl.ack(&mut r)), 0);
    let f = find_rule(&mut nl, 1101, FRA_OIFNAME).map_or(-1, |x| i64::from(x.0));
    t.eq(b"attached", f, 0);
    // A table-less lookup rule gets the first unused table
    let mut r = rule_req(RTM_NEWRULE, ce, frh(0, 0, 0, FR_ACT_TO_TBL), 1200, &|_| {});
    t.eq(b"auto table", i64::from(nl.ack(&mut r)), 0);
    let tb = find_rule(&mut nl, 1200, FRA_TABLE).map_or(0, |x| x.1);
    t.eq(b"auto id", i64::from(tb), 1);
    // Delete by attributes, without a priority
    let mut r = Req::new(RTM_DELRULE, 0, &frh(16, 0, 0, FR_ACT_TO_TBL));
    r.attr(FRA_SRC, &[10, 20, 0, 0]).u32(FRA_TABLE, 100);
    t.eq(b"del by match", i64::from(nl.ack(&mut r)), 0);
    t.ok(b"gone", find_rule(&mut nl, 1000, FRA_SRC).is_none(), 0);
    !t.failed()
}
