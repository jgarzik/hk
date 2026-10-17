//! Neighbour (ARP) table over eth0 and QEMU slirp (hk and Linux):
//! resolution of the gateway (/proc/net/arp, RTM_GETNEIGH), failure of
//! an unused address after three probes, administrative entries
//! (RTM_NEWNEIGH / RTM_DELNEIGH errors and PERMANENT state).

use super::helpers::skip;
use super::nl::{
    AF_INET, Msg, NLM_F_CREATE, NLM_F_EXCL, Nl, RTM_GETNEIGH, RTM_NEWNEIGH, Req, each_msg, msleep,
    net_setup_eth0, rxbuf,
};
use super::sk::*;
use super::sysctl::read_file;

const RTM_DELNEIGH: u16 = 29;
const NLM_F_REPLACE: u16 = 0x100;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
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
    super::helpers::println(b"=== Neighbour Tests ===");
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
