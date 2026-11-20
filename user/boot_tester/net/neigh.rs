//! Neighbour (ARP) table over eth0 and QEMU slirp (hk and Linux):
//! resolution of the gateway (/proc/net/arp, RTM_GETNEIGH), failure of
//! an unused address after three probes, administrative entries
//! (RTM_NEWNEIGH / RTM_DELNEIGH errors and PERMANENT state),
//! confirmation by forward progress (MSG_CONFIRM, MSG_PROBE), proxy
//! ARP (proxy_arp, proxy_arp_pvlan, forwarding), and a table of
//! hundreds: a multipart dump and /proc/net/arp past a page.

use crate::harness::T;
use crate::helpers::skip;
use crate::net::nl::{
    AF_INET, Msg, NLM_F_CREATE, NLM_F_EXCL, Nl, RTM_GETNEIGH, RTM_NEWNEIGH, Req, each_msg, msleep,
    net_setup_eth0, route, rxbuf,
};
use crate::net::sk::*;
use crate::proc::sysctl::read_file;

const RTM_DELNEIGH: u16 = 29;
const NLM_F_REPLACE: u16 = 0x100;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_CACHEINFO: u16 = 3;
const NUD_STALE: u16 = 0x04;
const MSG_PROBE: i32 = 0x10;
const MSG_CONFIRM: i32 = 0x800;
const SOCK_RAW: i32 = 3;
const IPPROTO_RAW_TEST: i32 = 253;
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_FAILED: u16 = 0x20;
const NUD_PERMANENT: u16 = 0x80;
/// REACHABLE | STALE | DELAY | PROBE
const NUD_RESOLVED: u16 = 0x02 | 0x04 | 0x08 | 0x10;
const ENOENT: i64 = -2;
const ENODEV: i64 = -19;
const EEXIST: i64 = -17;

pub const GW: [u8; 4] = [10, 0, 2, 2];
/// On the slirp subnet, never answered (slirp only answers its own
/// addresses)
pub const UNUSED: [u8; 4] = [10, 0, 2, 77];

pub fn run_tests() {
    crate::helpers::println(b"=== Neighbour Tests ===");
    let idx = match net_setup_eth0() {
        Ok(i) => i,
        Err(e) => {
            skip(b"NEIGH", e.as_bytes());
            return;
        }
    };
    test_gateway(idx);
    test_failed(idx);
    test_admin(idx);
    test_confirm(idx);
    test_proxy(idx);
    test_many(idx);
}

/// struct ndmsg
fn ndmsg(family: u8, ifindex: u32, state: u16) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0] = family;
    h[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    h[8..10].copy_from_slice(&state.to_ne_bytes());
    h
}

/// (state, lladdr) of `ip` on `ifindex` from an RTM_GETNEIGH dump
pub fn neigh_state(nl: &mut Nl, ifindex: u32, ip: [u8; 4]) -> Option<(u16, Option<[u8; 6]>)> {
    let mut out = None;
    let mut r = Req::new(RTM_GETNEIGH, 0, &ndmsg(AF_INET, 0, 0));
    nl.dump(&mut r, &mut |m: &Msg| {
        if m.ty != RTM_NEWNEIGH || m.body.len() < 12 || m.body[0] != AF_INET {
            return;
        }
        let idx = m.u32_at(4);
        if idx == ifindex && m.attr_ip(12, NDA_DST) == Some(ip) {
            let st = u16::from_ne_bytes([m.body[8], m.body[9]]);
            let ll = m.attr(12, NDA_LLADDR).filter(|a| a.len() == 6).map(|a| {
                let mut x = [0u8; 6];
                x.copy_from_slice(a);
                x
            });
            out = Some((st, ll));
        }
    });
    out
}

/// The /proc/net/arp line for `ip` (text after the address column)
fn arp_line<'a>(buf: &'a [u8], ip: &[u8]) -> Option<&'a [u8]> {
    buf.split(|&c| c == b'\n')
        .find(|l| l.len() > ip.len() && l.starts_with(ip) && l[ip.len()] == b' ')
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

/// Poke `ip` with a UDP datagram (starts resolution)
fn poke(ip: [u8; 4]) {
    let fd = udp();
    send_to(fd, b"x", ip, 9, 0);
    close(fd);
}

/// The gateway resolves: /proc/net/arp lists it complete (ATF_COM) and
/// RTM_GETNEIGH reports a resolved state with a 6-byte address
fn test_gateway(idx: u32) {
    let mut t = T::new(b"NEIGH_GATEWAY");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    poke(GW);
    let mut st = None;
    for _ in 0..40 {
        st = neigh_state(&mut nl, idx, GW);
        if st.is_some_and(|(s, _)| s & NUD_RESOLVED != 0) {
            break;
        }
        msleep(50);
    }
    let (s, ll) = st.unwrap_or((0, None));
    t.ok(b"resolved", s & NUD_RESOLVED != 0, s as i64);
    t.ok(b"lladdr", ll.is_some(), 0);
    let mut buf = [0u8; 2048];
    let n = read_file(b"/proc/net/arp\0", &mut buf);
    t.ok(b"read", n > 0, n);
    let text = &buf[..n.max(0) as usize];
    t.ok(
        b"header",
        text.starts_with(b"IP address       HW type     Flags"),
        0,
    );
    let line = arp_line(text, b"10.0.2.2");
    t.ok(b"line", line.is_some(), 0);
    if let Some(l) = line {
        t.ok(b"flags", contains(l, b"0x1         0x2 "), 0);
    }
    t.done();
}

/// An address nobody answers: INCOMPLETE, then FAILED after three
/// probes one second apart
fn test_failed(idx: u32) {
    let mut t = T::new(b"NEIGH_UNANSWERED");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    let start = now_ms();
    poke(UNUSED);
    let s0 = neigh_state(&mut nl, idx, UNUSED).map_or(0, |s| s.0);
    t.ok(b"incomplete", s0 == NUD_INCOMPLETE, s0 as i64);
    let mut s = s0;
    while now_ms() - start < 8000 {
        s = neigh_state(&mut nl, idx, UNUSED).map_or(0, |s| s.0);
        if s == NUD_FAILED {
            break;
        }
        msleep(100);
    }
    let el = (now_ms() - start) as i64;
    t.ok(b"failed", s == NUD_FAILED, s as i64);
    t.ok(b"after ~3 s", (2500..6000).contains(&el), el);
    t.done();
}

/// RTM_NEWNEIGH / RTM_DELNEIGH semantics
fn test_admin(idx: u32) {
    let mut t = T::new(b"NEIGH_ADMIN");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    let ip = [10, 0, 2, 99];
    let mac = [0x02, 0, 0, 0, 0, 0x99];
    let add = |nl: &mut Nl, ifindex: u32, flags: u16, dst: bool, ll: bool| -> i64 {
        let mut r = Req::new(RTM_NEWNEIGH, flags, &ndmsg(AF_INET, ifindex, NUD_PERMANENT));
        if dst {
            r.attr(NDA_DST, &ip);
        }
        if ll {
            r.attr(NDA_LLADDR, &mac);
        }
        nl.ack(&mut r) as i64
    };
    let ce = NLM_F_CREATE | NLM_F_EXCL;
    t.eq(b"no dst", add(&mut nl, idx, ce, false, true), EINVAL);
    t.eq(b"no dev", add(&mut nl, 0, ce, true, true), EINVAL);
    t.eq(b"bad dev", add(&mut nl, 999, ce, true, true), ENODEV);
    t.eq(b"no create", add(&mut nl, idx, 0, true, true), ENOENT);
    t.eq(b"add", add(&mut nl, idx, ce, true, true), 0);
    t.eq(b"excl", add(&mut nl, idx, ce, true, true), EEXIST);
    t.eq(
        b"replace",
        add(&mut nl, idx, NLM_F_CREATE | NLM_F_REPLACE, true, true),
        0,
    );
    let st = neigh_state(&mut nl, idx, ip);
    t.ok(
        b"permanent",
        st == Some((NUD_PERMANENT, Some(mac))),
        st.map_or(-1, |s| s.0 as i64),
    );
    // A single-entry RTM_GETNEIGH
    let mut r = Req::new(RTM_GETNEIGH, 0, &ndmsg(AF_INET, idx, 0));
    r.attr(NDA_DST, &ip);
    let seq = nl.send(&mut r);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    let mut got = 0u16;
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if m.ty == RTM_NEWNEIGH && m.seq == seq {
                got = u16::from_ne_bytes([m.body[8], m.body[9]]);
            }
        });
    }
    t.eq(b"get", got as i64, NUD_PERMANENT as i64);
    let mut abuf = [0u8; 2048];
    let n = read_file(b"/proc/net/arp\0", &mut abuf);
    let line = arp_line(&abuf[..n.max(0) as usize], b"10.0.2.99");
    t.ok(
        b"proc perm",
        line.is_some_and(|l| contains(l, b"0x6 ") && contains(l, b"02:00:00:00:00:99")),
        0,
    );
    let del = |nl: &mut Nl| -> i64 {
        let mut r = Req::new(RTM_DELNEIGH, 0, &ndmsg(AF_INET, idx, 0));
        r.attr(NDA_DST, &ip);
        nl.ack(&mut r) as i64
    };
    t.eq(b"del", del(&mut nl), 0);
    t.eq(b"del again", del(&mut nl), ENOENT);
    t.ok(b"gone", neigh_state(&mut nl, idx, ip).is_none(), 0);
    t.done();
}

/// The age of `ip`'s confirmation on `ifindex` in clock ticks
/// (nda_cacheinfo.ndm_confirmed)
fn neigh_confirmed(nl: &mut Nl, ifindex: u32, ip: [u8; 4]) -> Option<u32> {
    let mut out = None;
    let mut r = Req::new(RTM_GETNEIGH, 0, &ndmsg(AF_INET, 0, 0));
    nl.dump(&mut r, &mut |m: &Msg| {
        if m.ty != RTM_NEWNEIGH || m.body.len() < 12 || m.body[0] != AF_INET {
            return;
        }
        if m.u32_at(4) == ifindex && m.attr_ip(12, NDA_DST) == Some(ip) {
            out = m.attr_u32(12, NDA_CACHEINFO);
        }
    });
    out
}

/// A STALE entry for `ip` with a made-up address
fn add_stale(nl: &mut Nl, ifindex: u32, ip: [u8; 4]) -> i64 {
    let mut r = Req::new(
        RTM_NEWNEIGH,
        NLM_F_CREATE | NLM_F_EXCL,
        &ndmsg(AF_INET, ifindex, NUD_STALE),
    );
    r.attr(NDA_DST, &ip);
    r.attr(NDA_LLADDR, &[0x02, 0, 0, 0, 0, ip[3]]);
    nl.ack(&mut r) as i64
}

fn del_neigh(nl: &mut Nl, ifindex: u32, ip: [u8; 4]) {
    let mut r = Req::new(RTM_DELNEIGH, 0, &ndmsg(AF_INET, ifindex, 0));
    r.attr(NDA_DST, &ip);
    nl.ack(&mut r);
}

/// Forward progress confirms an entry (Linux dst_confirm_neigh,
/// sock_confirm_neigh): a fresh administrative STALE entry was never
/// confirmed (age of two reachable times); MSG_CONFIRM | MSG_PROBE on
/// UDP or raw confirms it without sending, MSG_CONFIRM with data
/// confirms it as the datagram leaves, a plain send or probe does not
fn test_confirm(idx: u32) {
    let mut t = T::new(b"NEIGH_CONFIRM");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    let ips = [[10, 0, 2, 96], [10, 0, 2, 97], [10, 0, 2, 98]];
    for ip in ips {
        t.eq(b"add", add_stale(&mut nl, idx, ip), 0);
    }
    let age = |nl: &mut Nl, ip| neigh_confirmed(nl, idx, ip).map_or(-1, i64::from);
    let old = |a: i64| a >= 1000;
    let fresh = |a: i64| (0..100).contains(&a);
    let fd = udp();
    // A plain datagram and a probe confirm nothing
    t.eq(b"plain", send_to(fd, b"x", ips[0], 9, 0), 1);
    t.eq(b"probe", send_to(fd, b"probe", ips[0], 9, MSG_PROBE), 5);
    let a = age(&mut nl, ips[0]);
    t.ok(b"unconfirmed", old(a), a);
    // MSG_CONFIRM with data: as it leaves
    t.eq(
        b"confirm data",
        send_to(fd, b"x", ips[0], 9, MSG_CONFIRM),
        1,
    );
    let a = age(&mut nl, ips[0]);
    t.ok(b"data confirmed", fresh(a), a);
    // MSG_CONFIRM | MSG_PROBE, no data: confirmed, nothing sent
    let a = age(&mut nl, ips[1]);
    t.ok(b"udp before", old(a), a);
    t.eq(
        b"udp probe",
        send_to(fd, b"", ips[1], 9, MSG_CONFIRM | MSG_PROBE),
        0,
    );
    let a = age(&mut nl, ips[1]);
    t.ok(b"udp confirmed", fresh(a), a);
    close(fd);
    let raw = hk_syscall::sys_socket(2, SOCK_RAW, IPPROTO_RAW_TEST) as i32;
    t.ok(b"raw", raw >= 0, raw as i64);
    let a = age(&mut nl, ips[2]);
    t.ok(b"raw before", old(a), a);
    t.eq(
        b"raw probe",
        send_to(raw, b"", ips[2], 0, MSG_CONFIRM | MSG_PROBE),
        0,
    );
    let a = age(&mut nl, ips[2]);
    t.ok(b"raw confirmed", fresh(a), a);
    close(raw);
    for ip in ips {
        del_neigh(&mut nl, idx, ip);
    }
    t.done();
}

const ETH_P_ARP: u16 = 0x0806;
const IPPROTO_RAW: i32 = 255;

/// Have slirp ask for `ip` (it reflects an echo from that made-up
/// source to the gateway, so it must resolve it) and wait for a reply
/// of ours claiming it, seen leaving eth0
fn proxied(eth: u32, ip: [u8; 4]) -> bool {
    use crate::net::packet::{bound, find};
    let ps = bound(SOCK_RAW, ETH_P_ARP, eth as i32);
    let raw = hk_syscall::sys_socket(2, SOCK_RAW, IPPROTO_RAW) as i32;
    let mut pkt = [0u8; 28];
    pkt[..20].copy_from_slice(&[
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 0, 0, 0, 0, GW[0], GW[1], GW[2], GW[3],
    ]);
    pkt[12..16].copy_from_slice(&ip);
    pkt[20..28].copy_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]);
    let c = crate::net::raw::csum(&pkt[20..28]);
    pkt[22..24].copy_from_slice(&c.to_be_bytes());
    let hc = crate::net::raw::csum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&hc.to_be_bytes());
    let sent = send_to(raw, &pkt, GW, 0, 0) == 28;
    let mut buf = [0u8; 128];
    let got = find(ps, &mut buf, 3000, &|f, _| {
        f.len() >= 42
            && f[12..14] == [8, 6]
            && f[20..22] == [0, 2]
            && f[28..32] == ip
            && f[38..42] == GW
    });
    close(raw);
    close(ps);
    sent && got.is_some()
}

fn conf_put(dev: &[u8], name: &[u8], v: &[u8]) -> i64 {
    let mut p = [0u8; 96];
    let mut n = 0;
    for part in [b"/proc/sys/net/ipv4/conf/" as &[u8], dev, b"/", name, b"\0"] {
        p[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    crate::proc::sysctl::write_file(&p[..n], v)
}

/// Proxy ARP (Linux arp_process's IN_DEV_FORWARD branch): with
/// forwarding on, a request for an address routed out another device
/// is answered with proxy_arp, one routed back out eth0 with
/// proxy_arp_pvlan, each after a random part of proxy_delay (the
/// request is a broadcast); without forwarding none is
fn test_proxy(idx: u32) {
    let mut t = T::new(b"NEIGH_PROXY");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    let lo = crate::net::packet::ifindex(b"lo") as u32;
    let (a, b, c) = ([10, 0, 2, 200], [10, 0, 2, 201], [10, 0, 2, 202]);
    let ce = NLM_F_CREATE | NLM_F_EXCL;
    t.eq(b"forwarding", conf_put(b"all", b"forwarding", b"1"), 1);
    t.eq(b"proxy_arp", conf_put(b"eth0", b"proxy_arp", b"1"), 1);
    t.eq(
        b"route",
        route(&mut nl, true, a, 32, [0; 4], lo, ce) as i64,
        0,
    );
    t.ok(b"proxy_arp answered", proxied(idx, a), 0);
    route(&mut nl, false, a, 32, [0; 4], lo, 0);
    t.eq(b"proxy_arp off", conf_put(b"eth0", b"proxy_arp", b"0"), 1);
    t.eq(b"pvlan", conf_put(b"eth0", b"proxy_arp_pvlan", b"1"), 1);
    t.ok(b"pvlan answered", proxied(idx, b), 0);
    t.eq(b"pvlan off", conf_put(b"eth0", b"proxy_arp_pvlan", b"0"), 1);
    t.eq(b"forwarding off", conf_put(b"all", b"forwarding", b"0"), 1);
    t.eq(b"proxy_arp again", conf_put(b"eth0", b"proxy_arp", b"1"), 1);
    t.eq(
        b"route c",
        route(&mut nl, true, c, 32, [0; 4], lo, ce) as i64,
        0,
    );
    t.ok(b"not forwarding", !proxied(idx, c), 0);
    route(&mut nl, false, c, 32, [0; 4], lo, 0);
    t.eq(b"restore", conf_put(b"eth0", b"proxy_arp", b"0"), 1);
    t.done();
}

/// Entries of `test_many`: more than the first hash's buckets (the
/// table grows) and than one dump part or /proc page holds
const MANY: u32 = 300;

/// The `i`th address of `test_many`: 10.123.x.y, off every subnet used
fn many_ip(i: u32) -> [u8; 4] {
    [10, 123, (i / 250) as u8, (i % 250 + 1) as u8]
}

const ARP_LEN: usize = 65536;
static mut ARP: [u8; ARP_LEN] = [0; ARP_LEN];

/// /proc/net/arp's length and how many PERMANENT 10.123. lines it has
fn proc_many() -> (i64, u32) {
    // SAFETY: single-threaded test program; no other user of the buffer
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(ARP) };
    let n = read_file(b"/proc/net/arp\0", buf);
    if n <= 0 {
        return (n, 0);
    }
    let lines = buf[..n as usize]
        .split(|&c| c == b'\n')
        .filter(|l| l.starts_with(b"10.123.") && contains(l, b"0x6 "))
        .count();
    (n, lines as u32)
}

/// How many PERMANENT 10.123. entries on `ifindex` a dump reports, and
/// the dump's result (message count or -errno)
fn dump_many(nl: &mut Nl, ifindex: u32) -> (u32, i32) {
    let mut seen = 0;
    let mut r = Req::new(RTM_GETNEIGH, 0, &ndmsg(AF_INET, 0, 0));
    let rc = nl.dump(&mut r, &mut |m: &Msg| {
        if m.ty != RTM_NEWNEIGH || m.body.len() < 12 || m.u32_at(4) != ifindex {
            return;
        }
        let st = u16::from_ne_bytes([m.body[8], m.body[9]]);
        if st == NUD_PERMANENT && m.attr_ip(12, NDA_DST).is_some_and(|a| a[..2] == [10, 123]) {
            seen += 1;
        }
    });
    (seen, rc)
}

/// Hundreds of PERMANENT entries: all in a multipart dump and in
/// /proc/net/arp (more than a page), then all deleted
fn test_many(idx: u32) {
    let mut t = T::new(b"NEIGH_MANY");
    let Some(mut nl) = Nl::open() else {
        t.ok(b"netlink", false, 0);
        return t.done();
    };
    let mut bad = 0;
    for i in 0..MANY {
        let mac = [0x02, 0, 0, 0x7b, (i >> 8) as u8, i as u8];
        let mut r = Req::new(
            RTM_NEWNEIGH,
            NLM_F_CREATE | NLM_F_EXCL,
            &ndmsg(AF_INET, idx, NUD_PERMANENT),
        );
        r.attr(NDA_DST, &many_ip(i));
        r.attr(NDA_LLADDR, &mac);
        if nl.ack(&mut r) != 0 {
            bad += 1;
        }
    }
    t.eq(b"added", bad, 0);
    let (seen, rc) = dump_many(&mut nl, idx);
    t.eq(b"dumped", seen as i64, MANY as i64);
    t.ok(b"dump done", rc >= MANY as i32, rc as i64);
    let (len, lines) = proc_many();
    t.ok(b"proc > page", len > 4096, len);
    t.eq(b"proc lines", lines as i64, MANY as i64);
    let mut bad = 0;
    for i in 0..MANY {
        let mut r = Req::new(RTM_DELNEIGH, 0, &ndmsg(AF_INET, idx, 0));
        r.attr(NDA_DST, &many_ip(i));
        if nl.ack(&mut r) != 0 {
            bad += 1;
        }
    }
    t.eq(b"deleted", bad, 0);
    t.eq(b"gone", dump_many(&mut nl, idx).0 as i64, 0);
    t.eq(b"proc gone", proc_many().1 as i64, 0);
    t.done();
}
