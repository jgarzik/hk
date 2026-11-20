//! Neighbour notifications and proxy entries over NETLINK_ROUTE (hk and
//! Linux):
//!
//! - NEIGH_NOTIFY (eth0): a RTNLGRP_NEIGH subscriber hears RTM_NEWNEIGH
//!   for an administrative add (PERMANENT, its address, NDA_PROTOCOL)
//!   and for a replaced address; a delete sends RTM_NEWNEIGH (FAILED)
//!   then RTM_DELNEIGH (Linux __neigh_update, neigh_cleanup_and_release);
//!   RTM_GETNEIGH reports NDA_PROTOCOL
//! - NEIGH_USE (eth0): RTM_NEWNEIGH with NTF_USE for an address nobody
//!   answers creates the entry and starts resolution (INCOMPLETE, Linux
//!   neigh_add's neigh_event_send); the subscriber hears it fail
//!   (RTM_NEWNEIGH FAILED from neigh_timer_handler)
//! - NEIGH_PROXY (new network namespace): RTM_NEWNEIGH with NTF_PROXY
//!   adds proxy entries with or without a device (pneigh_create); a
//!   NTF_PROXY dump lists them (NTF_PROXY, NUD_NONE, NDA_PROTOCOL), a
//!   plain dump does not; RTM_GETNEIGH finds one by its device or a
//!   device-less one by any device; RTM_DELNEIGH needs the exact device
//!   (ENOENT otherwise, pneigh_delete); /proc/net/arp lists them
//!   (ATF_PUBL | ATF_PERM, device or "*"); the device going down drops
//!   its entries but not the device-less one (arp_ifdown ->
//!   pneigh_ifdown)

use hk_syscall::sys_setsockopt;

use crate::harness::T;
use crate::helpers::skip;
use crate::net::nl::*;
use crate::net::rtnl_ack::in_netns;

const RTM_DELNEIGH: u16 = 29;
const RTNLGRP_NEIGH: i32 = 3;
const NLM_F_REPLACE: u16 = 0x100;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_PROTOCOL: u16 = 12;
const NTF_USE: u8 = 0x01;
const NTF_PROXY: u8 = 0x08;
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_FAILED: u16 = 0x20;
const NUD_PERMANENT: u16 = 0x80;
const RTPROT_STATIC: u8 = 4;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;

pub fn run_tests() {
    crate::helpers::println(b"=== Neighbour netlink Tests ===");
    in_netns(b"NEIGH_PROXY", proxy);
    let idx = match net_setup_eth0() {
        Ok(i) => i,
        Err(e) => {
            skip(b"NEIGH_NOTIFY", e.as_bytes());
            return;
        }
    };
    test_notify(idx);
    test_use(idx);
}

/// struct ndmsg
fn ndmsg(ifindex: u32, state: u16, flags: u8) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0] = AF_INET;
    h[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    h[8..10].copy_from_slice(&state.to_ne_bytes());
    h[10] = flags;
    h
}

/// One neighbour message's facts
#[derive(Clone, Copy, Default, PartialEq)]
struct Nd {
    ty: u16,
    ifindex: u32,
    state: u16,
    flags: u8,
    ll: Option<[u8; 6]>,
    proto: Option<u8>,
}

fn nd_of(m: &Msg) -> Nd {
    Nd {
        ty: m.ty,
        ifindex: m.u32_at(4),
        state: u16::from_ne_bytes([m.body[8], m.body[9]]),
        flags: m.body[10],
        ll: m.attr(12, NDA_LLADDR).filter(|a| a.len() == 6).map(|a| {
            let mut x = [0u8; 6];
            x.copy_from_slice(a);
            x
        }),
        proto: m.attr(12, NDA_PROTOCOL).and_then(|a| a.first().copied()),
    }
}

fn is_neigh(m: &Msg, ip: [u8; 4]) -> bool {
    matches!(m.ty, RTM_NEWNEIGH | RTM_DELNEIGH)
        && m.body.len() >= 12
        && m.body[0] == AF_INET
        && m.attr_ip(12, NDA_DST) == Some(ip)
}

/// The next notification about `ip` on `nl` within `ms`
fn next_about(nl: &Nl, ip: [u8; 4], ms: i32) -> Option<Nd> {
    let mut left = ms;
    while left > 0 {
        if !wait_readable(nl.fd, 100) {
            left -= 100;
            continue;
        }
        let buf = rxbuf();
        let n = nl.recv(buf, 0);
        if n <= 0 {
            return None;
        }
        let mut got = None;
        each_msg(&buf[..n as usize], &mut |m| {
            if got.is_none() && is_neigh(m, ip) {
                got = Some(nd_of(m));
            }
        });
        if got.is_some() {
            return got;
        }
    }
    None
}

fn subscriber() -> Option<Nl> {
    let nl = Nl::open()?;
    let g = RTNLGRP_NEIGH;
    let r = sys_setsockopt(
        nl.fd,
        SOL_NETLINK,
        NETLINK_ADD_MEMBERSHIP,
        &g as *const i32 as *const u8,
        4,
    );
    (r == 0).then_some(nl)
}

/// RTM_NEWNEIGH of `ip` on `ifindex`
fn add(
    nl: &mut Nl,
    ifindex: u32,
    flags: u16,
    nd: (u16, u8),
    ip: [u8; 4],
    ll: Option<[u8; 6]>,
    proto: u8,
) -> i64 {
    let mut r = Req::new(RTM_NEWNEIGH, flags, &ndmsg(ifindex, nd.0, nd.1));
    r.attr(NDA_DST, &ip);
    if let Some(l) = ll {
        r.attr(NDA_LLADDR, &l);
    }
    if proto != 0 {
        r.attr(NDA_PROTOCOL, &[proto]);
    }
    i64::from(nl.ack(&mut r))
}

/// RTM_NEWNEIGH of `ip` with no device and a 1-byte NDA_LLADDR
fn short_ll(nl: &mut Nl, ntf: u8, ip: [u8; 4]) -> i64 {
    let mut r = Req::new(RTM_NEWNEIGH, NLM_F_CREATE, &ndmsg(0, NUD_PERMANENT, ntf));
    r.attr(NDA_DST, &ip).attr(NDA_LLADDR, &[1]);
    i64::from(nl.ack(&mut r))
}

fn del(nl: &mut Nl, ifindex: u32, ntf: u8, ip: [u8; 4]) -> i64 {
    let mut r = Req::new(RTM_DELNEIGH, 0, &ndmsg(ifindex, 0, ntf));
    r.attr(NDA_DST, &ip);
    i64::from(nl.ack(&mut r))
}

/// RTM_GETNEIGH of `ip`: the reply, or the error
fn get(nl: &mut Nl, ifindex: u32, ntf: u8, ip: [u8; 4]) -> Result<Nd, i64> {
    let mut r = Req::new(RTM_GETNEIGH, 0, &ndmsg(ifindex, 0, ntf));
    r.attr(NDA_DST, &ip);
    let seq = nl.send(&mut r);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    let mut out = Err(-10000);
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if m.seq != seq {
                return;
            }
            if m.ty == NLMSG_ERROR {
                out = Err(i64::from(m.error()));
            } else if m.ty == RTM_NEWNEIGH {
                out = Ok(nd_of(m));
            }
        });
    }
    out
}

fn test_notify(idx: u32) {
    let mut t = T::new(b"NEIGH_NOTIFY");
    let (Some(mut nl), Some(sub)) = (Nl::open(), subscriber()) else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    let ip = [10, 0, 2, 200];
    let (mac, mac2) = ([0x02, 0, 0, 0, 0, 0xc8], [0x02, 0, 0, 0, 0, 0xc9]);
    let ce = NLM_F_CREATE | NLM_F_EXCL;
    let perm = (NUD_PERMANENT, 0);
    t.eq(
        b"add",
        add(&mut nl, idx, ce, perm, ip, Some(mac), RTPROT_STATIC),
        0,
    );
    let n = next_about(&sub, ip, 1000).unwrap_or_default();
    t.eq(b"add ty", i64::from(n.ty), i64::from(RTM_NEWNEIGH));
    t.eq(b"add state", i64::from(n.state), i64::from(NUD_PERMANENT));
    t.eq(b"add index", i64::from(n.ifindex), i64::from(idx));
    t.ok(b"add ll", n.ll == Some(mac), 0);
    t.eq(
        b"add proto",
        i64::from(n.proto.unwrap_or(0)),
        i64::from(RTPROT_STATIC),
    );
    let g = get(&mut nl, idx, 0, ip);
    t.ok(
        b"get proto",
        g.is_ok_and(|n| n.proto == Some(RTPROT_STATIC)),
        0,
    );
    // A new address: announced
    let rep = NLM_F_CREATE | NLM_F_REPLACE;
    t.eq(
        b"replace",
        add(&mut nl, idx, rep, perm, ip, Some(mac2), 0),
        0,
    );
    let n = next_about(&sub, ip, 1000).unwrap_or_default();
    t.eq(b"replace ty", i64::from(n.ty), i64::from(RTM_NEWNEIGH));
    t.ok(b"replace ll", n.ll == Some(mac2), 0);
    // Delete: failed, then gone
    t.eq(b"del", del(&mut nl, idx, 0, ip), 0);
    let n = next_about(&sub, ip, 1000).unwrap_or_default();
    t.eq(b"del new ty", i64::from(n.ty), i64::from(RTM_NEWNEIGH));
    t.eq(b"del new state", i64::from(n.state), i64::from(NUD_FAILED));
    let n = next_about(&sub, ip, 1000).unwrap_or_default();
    t.eq(b"del ty", i64::from(n.ty), i64::from(RTM_DELNEIGH));
    t.ok(b"no more", next_about(&sub, ip, 300).is_none(), 0);
    t.done();
}

fn test_use(idx: u32) {
    let mut t = T::new(b"NEIGH_USE");
    let (Some(mut nl), Some(sub)) = (Nl::open(), subscriber()) else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    // On the slirp subnet, never answered
    let ip = [10, 0, 2, 78];
    let ce = NLM_F_CREATE | NLM_F_EXCL;
    t.eq(b"use", add(&mut nl, idx, ce, (0, NTF_USE), ip, None, 0), 0);
    let g = get(&mut nl, idx, 0, ip);
    t.ok(
        b"incomplete",
        g.is_ok_and(|n| n.state == NUD_INCOMPLETE),
        g.map_or_else(|e| e, |n| i64::from(n.state)),
    );
    // Three probes a second apart, then FAILED is announced
    let n = next_about(&sub, ip, 6000).unwrap_or_default();
    t.eq(b"fail ty", i64::from(n.ty), i64::from(RTM_NEWNEIGH));
    t.eq(b"fail state", i64::from(n.state), i64::from(NUD_FAILED));
    del(&mut nl, idx, 0, ip);
    t.done();
}

/// The proxy entries of a NTF_PROXY dump: (address last byte, ifindex,
/// protocol) for 10.3.3.x, and whether a plain dump lists any
fn proxy_dump(nl: &mut Nl, ntf: u8) -> ([(u8, u32, u8); 4], usize, bool) {
    let mut out = [(0u8, 0u32, 0u8); 4];
    let (mut n, mut bad) = (0, false);
    let mut r = Req::new(RTM_GETNEIGH, 0, &ndmsg(0, 0, ntf));
    nl.dump(&mut r, &mut |m| {
        let Some(d) = m.attr_ip(12, NDA_DST) else {
            return;
        };
        if d[..3] != [10, 3, 3] {
            return;
        }
        let x = nd_of(m);
        bad |= x.flags != NTF_PROXY || x.state != 0;
        if n < out.len() {
            out[n] = (d[3], x.ifindex, x.proto.unwrap_or(0));
        }
        n += 1;
    });
    (out, n, bad)
}

/// A /proc/net/arp line starting with `ip` holds `flags` and ends with
/// `dev`
fn proc_line(text: &[u8], ip: &[u8], flags: &[u8], dev: &[u8]) -> bool {
    text.split(|&c| c == b'\n').any(|l| {
        l.starts_with(ip) && l.windows(flags.len()).any(|w| w == flags) && l.ends_with(dev)
    })
}

fn has(v: &[(u8, u32, u8)], n: usize, e: (u8, u32, u8)) -> bool {
    v[..n.min(v.len())].contains(&e)
}

fn proxy(name: &'static [u8]) -> bool {
    let mut t = T::new(name);
    let Some(mut nl) = Nl::open() else {
        t.ok(b"open", false, 0);
        return false;
    };
    let px = (NUD_PERMANENT, NTF_PROXY);
    let (a, b) = ([10, 3, 3, 3], [10, 3, 3, 4]);
    t.eq(b"lo up", i64::from(set_link_up(&mut nl, 1, true)), 0);
    // A short NDA_LLADDR: a proxy entry never reads it; without a
    // device there is nothing to check it against (Device not
    // specified)
    t.eq(
        b"short ll proxy",
        short_ll(&mut nl, NTF_PROXY, [10, 3, 3, 8]),
        0,
    );
    t.eq(
        b"short ll nodev",
        short_ll(&mut nl, 0, [10, 3, 3, 8]),
        EINVAL,
    );
    t.eq(b"del short", del(&mut nl, 0, NTF_PROXY, [10, 3, 3, 8]), 0);
    t.eq(b"add lo", add(&mut nl, 1, 0, px, a, None, RTPROT_STATIC), 0);
    t.eq(b"add any", add(&mut nl, 0, 0, px, b, None, 0), 0);
    // Again: an update, not EEXIST
    t.eq(b"add again", add(&mut nl, 0, NLM_F_EXCL, px, b, None, 0), 0);
    let (v, n, bad) = proxy_dump(&mut nl, NTF_PROXY);
    t.eq(b"dump count", n as i64, 2);
    t.ok(b"dump flags", !bad, 0);
    t.ok(b"dump lo", has(&v, n, (3, 1, RTPROT_STATIC)), 0);
    t.ok(b"dump any", has(&v, n, (4, 0, 0)), 0);
    let (_, n, _) = proxy_dump(&mut nl, 0);
    t.eq(b"plain dump", n as i64, 0);
    let mut buf = [0u8; 1024];
    let len = crate::proc::sysctl::read_file(b"/proc/net/arp\0", &mut buf);
    let text = &buf[..len.max(0) as usize];
    t.ok(
        b"proc lo",
        proc_line(text, b"10.3.3.3 ", b"0xc ", b" lo"),
        len,
    );
    t.ok(
        b"proc any",
        proc_line(text, b"10.3.3.4 ", b"0xc ", b" *"),
        len,
    );
    let g = get(&mut nl, 1, NTF_PROXY, a);
    t.ok(
        b"get lo",
        g.is_ok_and(|x| x.flags == NTF_PROXY && x.ifindex == 1),
        0,
    );
    let g = get(&mut nl, 1, NTF_PROXY, b);
    t.ok(b"get any by lo", g.is_ok_and(|x| x.ifindex == 0), 0);
    t.eq(
        b"get none",
        get(&mut nl, 1, NTF_PROXY, [10, 3, 3, 9]).err().unwrap_or(0),
        ENOENT,
    );
    t.eq(b"del any by lo", del(&mut nl, 1, NTF_PROXY, b), ENOENT);
    t.eq(b"del lo", del(&mut nl, 1, NTF_PROXY, a), 0);
    t.eq(b"del lo again", del(&mut nl, 1, NTF_PROXY, a), ENOENT);
    // lo going down drops its entries only
    t.eq(b"re-add lo", add(&mut nl, 1, 0, px, a, None, 0), 0);
    t.eq(b"lo down", i64::from(set_link_up(&mut nl, 1, false)), 0);
    let (v, n, _) = proxy_dump(&mut nl, NTF_PROXY);
    t.eq(b"after down", n as i64, 1);
    t.ok(b"any kept", has(&v, n, (4, 0, 0)), 0);
    t.eq(b"del any", del(&mut nl, 0, NTF_PROXY, b), 0);
    !t.failed()
}
