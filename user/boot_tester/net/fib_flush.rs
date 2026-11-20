//! FIB flushes (hk and Linux): many routes through a device all go when
//! it goes down, host-scope local routes stay (Linux fib_disable_ip ->
//! fib_sync_down_dev + fib_flush); many routes preferring an address as
//! source all go, announced, when the address is deleted (Linux
//! fib_del_ifaddr -> fib_sync_down_addr + fib_flush).
//!
//! Runs after the netlink tests, with the Ethernet link down and
//! without addresses, and leaves it so.

use hk_syscall::sys_setsockopt;

use crate::harness::{fail_why, pass};
use crate::net::nl::*;

const TEST_IP: [u8; 4] = [192, 0, 2, 10];
const TEST_GW: [u8; 4] = [192, 0, 2, 1];
/// Routes added per kind
const ROUTES: u8 = 64;
const RTNLGRP_IPV4_ROUTE: i32 = 7;

pub fn run_tests() {
    crate::helpers::println(b"=== FIB Flush Tests ===");
    test_linkdown();
    test_prefsrc();
}

/// A main-table /32 route to `dst`: via `gw` (0 = on link) through
/// `oif`, preferring source `src` (0 = none); returns the ACK code
fn route32(nl: &mut Nl, dst: [u8; 4], gw: [u8; 4], oif: u32, src: [u8; 4]) -> i32 {
    let scope = if gw == [0; 4] {
        RT_SCOPE_LINK
    } else {
        RT_SCOPE_UNIVERSE
    };
    let mut r = Req::new(
        RTM_NEWROUTE,
        NLM_F_CREATE | NLM_F_EXCL,
        &rtmsg(32, RT_TABLE_MAIN, RTPROT_BOOT, scope, RTN_UNICAST),
    );
    r.attr(RTA_DST, &dst).u32(RTA_OIF, oif);
    if gw != [0; 4] {
        r.attr(RTA_GATEWAY, &gw);
    }
    if src != [0; 4] {
        r.attr(RTA_PREFSRC, &src);
    }
    nl.ack(&mut r)
}

/// Routes in `table` that `f` picks (by message), or a negative errno
fn count(nl: &mut Nl, table: u8, f: &mut dyn FnMut(&Msg) -> bool) -> i32 {
    let mut n = 0;
    let mut r = Req::new(RTM_GETROUTE, 0, &rtmsg(0, 0, 0, 0, 0));
    let e = nl.dump(&mut r, &mut |m| {
        if m.ty == RTM_NEWROUTE && m.body[0] == AF_INET && m.body[4] == table && f(m) {
            n += 1;
        }
    });
    if e < 0 { e } else { n }
}

/// FIB_LINKDOWN_FLUSH: link down drops every main-table route through
/// the link (on-link and via a gateway), keeps the local /32
fn test_linkdown() {
    const N: &[u8] = b"FIB_LINKDOWN_FLUSH";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let Some(eth) = first_ether(&mut nl) else {
        return fail_why(N, b"no ethernet link", 0);
    };
    let i = eth.index;
    set_link_up(&mut nl, i, true);
    let result = (|| -> Result<(), (&'static [u8], i64)> {
        let e = addr(&mut nl, true, i, TEST_IP, 24, NLM_F_CREATE | NLM_F_EXCL);
        if e != 0 {
            return Err((b"newaddr", e as i64));
        }
        for k in 0..ROUTES {
            let e = route32(&mut nl, [198, 51, 100, k], [0; 4], i, [0; 4]);
            if e != 0 {
                return Err((b"on-link route", e as i64));
            }
            let e = route32(&mut nl, [203, 0, 113, k], TEST_GW, i, [0; 4]);
            if e != 0 {
                return Err((b"gateway route", e as i64));
            }
        }
        let on = |m: &Msg| m.attr_u32(12, RTA_OIF) == Some(i);
        // The prefix route and ours
        let want = 1 + 2 * i32::from(ROUTES);
        let n = count(&mut nl, RT_TABLE_MAIN, &mut |m| on(m));
        if n != want {
            return Err((b"routes before down", n as i64));
        }
        set_link_up(&mut nl, i, false);
        let n = count(&mut nl, RT_TABLE_MAIN, &mut |m| on(m));
        if n != 0 {
            return Err((b"main routes left after down", n as i64));
        }
        let n = count(&mut nl, RT_TABLE_LOCAL, &mut |m| {
            on(m) && m.body[7] == RTN_LOCAL && m.attr_ip(12, RTA_DST) == Some(TEST_IP)
        });
        if n != 1 {
            return Err((b"local route after down", n as i64));
        }
        Ok(())
    })();
    set_link_up(&mut nl, i, false);
    addr(&mut nl, false, i, TEST_IP, 24, 0);
    match result {
        Ok(()) => pass(N),
        Err((what, v)) => fail_why(N, what, v),
    }
}

/// RTM_DELROUTE notifications on `mon` for main-table routes preferring
/// TEST_IP through lo, until none arrives for 500 ms
fn delroutes(mon: &Nl) -> i32 {
    let mut n = 0;
    while wait_readable(mon.fd, 500) {
        let buf = rxbuf();
        let len = mon.recv(buf, 0);
        if len <= 0 {
            break;
        }
        each_msg(&buf[..len as usize], &mut |m| {
            if m.ty == RTM_DELROUTE
                && m.body[4] == RT_TABLE_MAIN
                && m.attr_u32(12, RTA_OIF) == Some(1)
                && m.attr_ip(12, RTA_PREFSRC) == Some(TEST_IP)
            {
                n += 1;
            }
        });
    }
    n
}

/// FIB_PREFSRC_FLUSH: deleting an address drops every main-table route
/// preferring it as source, on any device (here lo), each announced
/// with RTM_DELROUTE
fn test_prefsrc() {
    const N: &[u8] = b"FIB_PREFSRC_FLUSH";
    let (Some(mut nl), Some(mon)) = (Nl::open(), Nl::open()) else {
        return fail_why(N, b"open", 0);
    };
    let Some(eth) = first_ether(&mut nl) else {
        return fail_why(N, b"no ethernet link", 0);
    };
    let i = eth.index;
    set_link_up(&mut nl, i, true);
    let result = (|| -> Result<(), (&'static [u8], i64)> {
        let e = addr(&mut nl, true, i, TEST_IP, 24, NLM_F_CREATE | NLM_F_EXCL);
        if e != 0 {
            return Err((b"newaddr", e as i64));
        }
        for k in 0..ROUTES {
            let e = route32(&mut nl, [198, 51, 100, k], [0; 4], 1, TEST_IP);
            if e != 0 {
                return Err((b"route via lo", e as i64));
            }
        }
        let ours = |m: &Msg| {
            m.attr_u32(12, RTA_OIF) == Some(1) && m.attr_ip(12, RTA_PREFSRC) == Some(TEST_IP)
        };
        let n = count(&mut nl, RT_TABLE_MAIN, &mut |m| ours(m));
        if n != i32::from(ROUTES) {
            return Err((b"routes before deladdr", n as i64));
        }
        let g = RTNLGRP_IPV4_ROUTE;
        let r = sys_setsockopt(
            mon.fd,
            SOL_NETLINK,
            NETLINK_ADD_MEMBERSHIP,
            &g as *const i32 as *const u8,
            4,
        );
        if r != 0 {
            return Err((b"subscribe", r));
        }
        let e = addr(&mut nl, false, i, TEST_IP, 24, 0);
        if e != 0 {
            return Err((b"deladdr", e as i64));
        }
        let n = count(&mut nl, RT_TABLE_MAIN, &mut |m| ours(m));
        if n != 0 {
            return Err((b"routes left after deladdr", n as i64));
        }
        let n = delroutes(&mon);
        if n != i32::from(ROUTES) {
            return Err((b"RTM_DELROUTE announced", n as i64));
        }
        Ok(())
    })();
    for k in 0..ROUTES {
        let mut r = Req::new(RTM_DELROUTE, 0, &rtmsg(32, RT_TABLE_MAIN, 0, 255, 0));
        r.attr(RTA_DST, &[198, 51, 100, k]);
        nl.ack(&mut r);
    }
    addr(&mut nl, false, i, TEST_IP, 24, 0);
    set_link_up(&mut nl, i, false);
    match result {
        Ok(()) => pass(N),
        Err((what, v)) => fail_why(N, what, v),
    }
}
