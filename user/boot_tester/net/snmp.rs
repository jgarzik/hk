//! SNMP / Linux MIB counters: /proc/net/snmp and /proc/net/netstat
//! (hk and Linux)
//!
//! - SNMP_FORMAT: every header line is followed by a value line with
//!   the same tag and as many fields; Ip, Icmp, Tcp and Udp rows with
//!   the common fields, Tcp's RFC 2012 constants
//! - NETSTAT_FORMAT: TcpExt and IpExt row pairs, the common fields
//! - SNMP_NETNS (in a new network namespace, so no other traffic):
//!   fresh counters start at zero; a loopback TCP connect and close
//!   moves ActiveOpens, PassiveOpens, CurrEstab (back to 0), InSegs,
//!   OutSegs, the IP counters and TcpExt TW; an SO_LINGER 0 close
//!   counts EstabResets, OutRsts and TCPAbortOnData; a refused connect
//!   AttemptFails; a datagram to a closed UDP port Udp NoPorts and the
//!   ICMP port unreachable both ways; a received datagram InDatagrams.
//!   Deltas are checked with >=, as Linux counts some events twice.
//! - PROC_PID_NET: /proc/net is the link self/net; a child in a new
//!   namespace, read by its parent through /proc/<pid>/net and
//!   /proc/<pid>/task/<tid>/net, shows its own devices and counters

use hk_syscall::{
    CLONE_NEWNET, sys_exit, sys_fork, sys_pipe2, sys_read, sys_readlink, sys_setsockopt,
    sys_unshare, sys_write,
};

use crate::harness::{T, fail_num, pass};
use crate::helpers::{host_mode, loopback_up, msleep, println, read_file, skip};
use crate::net::sk::*;
use crate::net::tcp_xfer::{accept, listener, set_timeo, wait_child};

const SNMP: &[u8] = b"/proc/net/snmp\0";
const NETSTAT: &[u8] = b"/proc/net/netstat\0";
const ECONNREFUSED: i64 = -111;

pub fn run_tests() {
    println(b"=== SNMP Tests ===");
    test_snmp_format();
    test_netstat_format();
    test_snmp_netns();
    test_proc_pid_net();
}

/// A /proc MIB file's text
struct Mib {
    buf: [u8; 8192],
    len: usize,
}

impl Mib {
    fn read(path: &[u8]) -> Option<Mib> {
        let mut m = Mib {
            buf: [0; 8192],
            len: 0,
        };
        let n = read_file(path, &mut m.buf);
        if n <= 0 || n as usize == m.buf.len() {
            return None;
        }
        m.len = n as usize;
        Some(m)
    }

    fn lines(&self) -> impl Iterator<Item = &[u8]> {
        self.buf[..self.len]
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
    }

    /// Header/value line pairs: (tag, names, values)
    fn pairs(&self) -> impl Iterator<Item = (&[u8], &[u8], &[u8])> {
        let mut it = self.lines();
        core::iter::from_fn(move || {
            let h = it.next()?;
            let v = it.next().unwrap_or(b"");
            let tag = &h[..h.iter().position(|&b| b == b':').unwrap_or(0)];
            Some((tag, h, v))
        })
    }

    /// Field `name` of row `tag` (any of its line pairs; IcmpMsg has
    /// several, and lists only nonzero entries)
    fn get(&self, tag: &[u8], name: &[u8]) -> Option<i64> {
        for (t, h, v) in self.pairs() {
            if t != tag {
                continue;
            }
            if let Some(i) = words(h).position(|w| w == name) {
                return words(v).nth(i).and_then(num);
            }
        }
        None
    }

    /// `get`, with a missing field as 0
    fn val(&self, tag: &[u8], name: &[u8]) -> i64 {
        self.get(tag, name).unwrap_or(0)
    }
}

/// The fields after a line's `Tag:`
fn words(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    let s = line.iter().position(|&b| b == b':').map_or(0, |p| p + 1);
    line[s..].split(|&b| b == b' ').filter(|w| !w.is_empty())
}

/// A decimal value, possibly negative (MaxConn)
fn num(w: &[u8]) -> Option<i64> {
    let (neg, d) = match w.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, w),
    };
    if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let v = d.iter().fold(0i64, |a, &c| {
        a.wrapping_mul(10).wrapping_add(i64::from(c - b'0'))
    });
    Some(if neg { -v } else { v })
}

/// Every line pairs with the next: same tag, as many values as names,
/// all decimal. Returns the failing pair's index.
fn pairs_ok(m: &Mib) -> Result<i64, i64> {
    let mut n = 0;
    for (tag, h, v) in m.pairs() {
        let vtag = &v[..v.iter().position(|&b| b == b':').unwrap_or(0)];
        let names = words(h).count();
        if tag.is_empty() || vtag != tag || names == 0 || words(v).count() != names {
            return Err(n as i64);
        }
        if words(v).any(|w| num(w).is_none()) {
            return Err(n as i64);
        }
        n += 1;
    }
    Ok(n as i64)
}

/// Every name of `names` is a field of row `tag`
fn has_all(t: &mut T, m: &Mib, tag: &[u8], names: &[&[u8]]) {
    for (i, n) in names.iter().enumerate() {
        t.ok(n, m.get(tag, n).is_some(), i as i64);
    }
}

fn test_snmp_format() {
    let mut t = T::new(b"SNMP_FORMAT");
    let Some(m) = Mib::read(SNMP) else {
        println(b"SNMP_FORMAT:FAIL read /proc/net/snmp");
        return;
    };
    t.ok(
        b"first line",
        m.buf.starts_with(b"Ip: Forwarding DefaultTTL InReceives "),
        0,
    );
    let pairs = pairs_ok(&m);
    t.ok(b"pairs", pairs.is_ok(), pairs.unwrap_or_else(|e| e));
    has_all(
        &mut t,
        &m,
        b"Ip",
        &[
            b"Forwarding",
            b"DefaultTTL",
            b"InReceives",
            b"InHdrErrors",
            b"InAddrErrors",
            b"InDelivers",
            b"OutRequests",
            b"OutNoRoutes",
            b"ReasmOKs",
            b"FragOKs",
        ],
    );
    has_all(
        &mut t,
        &m,
        b"Icmp",
        &[
            b"InMsgs",
            b"InErrors",
            b"InDestUnreachs",
            b"OutMsgs",
            b"OutDestUnreachs",
            b"OutEchoReps",
        ],
    );
    has_all(
        &mut t,
        &m,
        b"Tcp",
        &[
            b"ActiveOpens",
            b"PassiveOpens",
            b"AttemptFails",
            b"EstabResets",
            b"CurrEstab",
            b"InSegs",
            b"OutSegs",
            b"RetransSegs",
            b"InErrs",
            b"OutRsts",
            b"InCsumErrors",
        ],
    );
    has_all(
        &mut t,
        &m,
        b"Udp",
        &[
            b"InDatagrams",
            b"NoPorts",
            b"InErrors",
            b"OutDatagrams",
            b"RcvbufErrors",
            b"SndbufErrors",
        ],
    );
    // RFC 2012: Van Jacobson, 200 ms, 120 s, no limit (signed)
    t.eq(b"RtoAlgorithm", m.val(b"Tcp", b"RtoAlgorithm"), 1);
    t.eq(b"RtoMin", m.val(b"Tcp", b"RtoMin"), 200);
    t.eq(b"RtoMax", m.val(b"Tcp", b"RtoMax"), 120_000);
    t.eq(b"MaxConn", m.val(b"Tcp", b"MaxConn"), -1);
    t.done();
}

fn test_netstat_format() {
    let mut t = T::new(b"NETSTAT_FORMAT");
    let Some(m) = Mib::read(NETSTAT) else {
        println(b"NETSTAT_FORMAT:FAIL read /proc/net/netstat");
        return;
    };
    t.ok(
        b"first line",
        m.buf.starts_with(b"TcpExt: SyncookiesSent "),
        0,
    );
    let pairs = pairs_ok(&m);
    t.ok(b"pairs", pairs.is_ok(), pairs.unwrap_or_else(|e| e));
    has_all(
        &mut t,
        &m,
        b"TcpExt",
        &[
            b"EmbryonicRsts",
            b"TW",
            b"DelayedACKs",
            b"ListenOverflows",
            b"ListenDrops",
            b"TCPTimeouts",
            b"TCPAbortOnData",
            b"TCPAbortOnClose",
            b"TCPAbortOnTimeout",
            b"TCPBacklogDrop",
            b"TCPOrigDataSent",
        ],
    );
    has_all(
        &mut t,
        &m,
        b"IpExt",
        &[b"InOctets", b"OutOctets", b"InBcastPkts", b"InNoECTPkts"],
    );
    t.done();
}

/// /proc/net/snmp and /proc/net/netstat now
fn snap() -> Option<(Mib, Mib)> {
    Some((Mib::read(SNMP)?, Mib::read(NETSTAT)?))
}

/// Re-read until `done` holds on (snmp, netstat), for at most ~2 s
/// (loopback traffic is processed asynchronously)
fn settle(done: impl Fn(&Mib, &Mib) -> bool) -> Option<(Mib, Mib)> {
    for _ in 0..200 {
        let s = snap()?;
        if done(&s.0, &s.1) {
            return Some(s);
        }
        msleep(10);
    }
    snap()
}

/// `name` of `tag` grew by at least `min` from `a` to `b`
fn grew(t: &mut T, a: &Mib, b: &Mib, tag: &[u8], name: &[u8], min: i64) {
    let d = b.val(tag, name) - a.val(tag, name);
    t.ok(name, d >= min, d);
}

/// The counting tests, in a new network namespace (exit 2: no
/// unshare)
fn test_snmp_netns() {
    let pid = sys_fork();
    if pid < 0 {
        println(b"SNMP_NETNS:FAIL fork");
        return;
    }
    if pid == 0 {
        if sys_unshare(CLONE_NEWNET) != 0 {
            sys_exit(2);
        }
        loopback_up();
        netns_fresh();
        netns_tcp();
        netns_tcp_reset();
        netns_tcp_refused();
        netns_udp();
        sys_exit(0);
    }
    let st = wait_child(pid);
    let code = (st >> 8) & 0xff;
    if st & 0x7f == 0 && code == 0 {
        pass(b"SNMP_NETNS");
    } else if code == 2 && host_mode() {
        skip(b"SNMP_NETNS", b"unshare(CLONE_NEWNET) not permitted");
    } else {
        fail_num(b"SNMP_NETNS:FAIL status=", st as i64);
    }
}

/// A namespace's MIBs start at zero (Linux allocates them per
/// namespace)
fn netns_fresh() {
    let mut t = T::new(b"SNMP_NETNS_FRESH");
    let Some((s, n)) = snap() else {
        println(b"SNMP_NETNS_FRESH:FAIL read");
        return;
    };
    for f in [
        b"ActiveOpens" as &[u8],
        b"PassiveOpens",
        b"CurrEstab",
        b"OutRsts",
    ] {
        t.eq(f, s.val(b"Tcp", f), 0);
    }
    for f in [b"InDatagrams" as &[u8], b"NoPorts", b"OutDatagrams"] {
        t.eq(f, s.val(b"Udp", f), 0);
    }
    t.eq(b"TW", n.val(b"TcpExt", b"TW"), 0);
    t.eq(b"RtoMin", s.val(b"Tcp", b"RtoMin"), 200);
    t.done();
}

/// Connect and close over loopback
fn netns_tcp() {
    let mut t = T::new(b"SNMP_TCP_LOOPBACK");
    let Some((a, an)) = snap() else {
        println(b"SNMP_TCP_LOOPBACK:FAIL read");
        return;
    };
    let (l, p) = listener(4);
    let c = tcp();
    set_timeo(c, 10_000);
    t.eq(b"connect", connect(c, LO, p), 0);
    set_timeo(l, 10_000);
    let s = accept(l);
    t.ok(b"accept", s >= 0, s as i64);
    set_timeo(s, 10_000);
    // Both ends established (the passive one once its ACK is in)
    let Some((b, _)) = settle(|m, _| m.val(b"Tcp", b"CurrEstab") >= 2) else {
        println(b"SNMP_TCP_LOOPBACK:FAIL read");
        return;
    };
    t.ok(
        b"CurrEstab open",
        b.val(b"Tcp", b"CurrEstab") >= 2,
        b.val(b"Tcp", b"CurrEstab"),
    );
    grew(&mut t, &a, &b, b"Tcp", b"ActiveOpens", 1);
    grew(&mut t, &a, &b, b"Tcp", b"PassiveOpens", 1);
    grew(&mut t, &a, &b, b"Tcp", b"InSegs", 3);
    grew(&mut t, &a, &b, b"Tcp", b"OutSegs", 3);
    grew(&mut t, &a, &b, b"Ip", b"InReceives", 3);
    grew(&mut t, &a, &b, b"Ip", b"InDelivers", 3);
    grew(&mut t, &a, &b, b"Ip", b"OutRequests", 3);
    // The active closer ends in TIME_WAIT once the peer's FIN is in
    close(c);
    let mut buf = [0u8; 4];
    t.eq(b"eof", recv(s, &mut buf, 0), 0);
    close(s);
    close(l);
    let Some((e, en)) = settle(|m, n| {
        m.val(b"Tcp", b"CurrEstab") == 0 && n.val(b"TcpExt", b"TW") > an.val(b"TcpExt", b"TW")
    }) else {
        println(b"SNMP_TCP_LOOPBACK:FAIL read");
        return;
    };
    t.eq(b"CurrEstab closed", e.val(b"Tcp", b"CurrEstab"), 0);
    grew(&mut t, &an, &en, b"TcpExt", b"TW", 1);
    grew(&mut t, &a, &e, b"Tcp", b"OutSegs", 6);
    t.done();
}

/// An SO_LINGER {1, 0} close resets an established connection
fn netns_tcp_reset() {
    let mut t = T::new(b"SNMP_TCP_RESET");
    let Some((a, an)) = snap() else {
        println(b"SNMP_TCP_RESET:FAIL read");
        return;
    };
    let (l, p) = listener(4);
    let c = tcp();
    set_timeo(c, 10_000);
    t.eq(b"connect", connect(c, LO, p), 0);
    set_timeo(l, 10_000);
    let s = accept(l);
    let lg = [1i32, 0];
    t.eq(
        b"linger",
        sys_setsockopt(s, SOL_SOCKET, SO_LINGER, lg.as_ptr() as *const u8, 8),
        0,
    );
    close(s);
    let mut buf = [0u8; 4];
    t.ok(b"reset", recv(c, &mut buf, 0) < 0, 0);
    close(c);
    close(l);
    let Some((b, bn)) = settle(|m, _| m.val(b"Tcp", b"CurrEstab") == 0) else {
        println(b"SNMP_TCP_RESET:FAIL read");
        return;
    };
    t.eq(b"CurrEstab", b.val(b"Tcp", b"CurrEstab"), 0);
    grew(&mut t, &a, &b, b"Tcp", b"EstabResets", 1);
    grew(&mut t, &a, &b, b"Tcp", b"OutRsts", 1);
    grew(&mut t, &an, &bn, b"TcpExt", b"TCPAbortOnData", 1);
    t.done();
}

/// A connect to a port nobody listens on is refused by a RST
fn netns_tcp_refused() {
    let mut t = T::new(b"SNMP_TCP_REFUSED");
    let Some((a, _)) = snap() else {
        println(b"SNMP_TCP_REFUSED:FAIL read");
        return;
    };
    let x = tcp();
    bind(x, LO, 0);
    let p = port(x);
    close(x);
    let c = tcp();
    set_timeo(c, 10_000);
    t.eq(b"connect", connect(c, LO, p), ECONNREFUSED);
    close(c);
    let Some((b, _)) = snap() else {
        println(b"SNMP_TCP_REFUSED:FAIL read");
        return;
    };
    grew(&mut t, &a, &b, b"Tcp", b"ActiveOpens", 1);
    grew(&mut t, &a, &b, b"Tcp", b"AttemptFails", 1);
    grew(&mut t, &a, &b, b"Tcp", b"OutRsts", 1);
    t.done();
}

/// A datagram to a closed port, and one received
fn netns_udp() {
    let mut t = T::new(b"SNMP_UDP_NOPORTS");
    let Some((a, _)) = snap() else {
        println(b"SNMP_UDP_NOPORTS:FAIL read");
        return;
    };
    let u = udp();
    bind(u, LO, 0);
    let x = udp();
    bind(x, LO, 0);
    let closed = port(x);
    close(x);
    t.eq(b"send", send_to(u, b"snmp", LO, closed, 0), 4);
    // The port unreachable comes back over lo
    let Some((b, _)) = settle(|m, _| {
        m.val(b"Udp", b"NoPorts") > a.val(b"Udp", b"NoPorts")
            && m.val(b"Icmp", b"InDestUnreachs") > a.val(b"Icmp", b"InDestUnreachs")
    }) else {
        println(b"SNMP_UDP_NOPORTS:FAIL read");
        return;
    };
    grew(&mut t, &a, &b, b"Udp", b"OutDatagrams", 1);
    grew(&mut t, &a, &b, b"Udp", b"NoPorts", 1);
    grew(&mut t, &a, &b, b"Icmp", b"OutMsgs", 1);
    grew(&mut t, &a, &b, b"Icmp", b"OutDestUnreachs", 1);
    grew(&mut t, &a, &b, b"Icmp", b"InMsgs", 1);
    grew(&mut t, &a, &b, b"Icmp", b"InDestUnreachs", 1);
    grew(&mut t, &a, &b, b"IcmpMsg", b"OutType3", 1);
    grew(&mut t, &a, &b, b"IcmpMsg", b"InType3", 1);
    t.done();

    let mut t = T::new(b"SNMP_UDP_RECV");
    let r = udp();
    bind(r, LO, 0);
    set_timeo(r, 10_000);
    t.eq(b"send", send_to(u, b"snmp", LO, port(r), 0), 4);
    let mut buf = [0u8; 8];
    t.eq(b"recv", recv(r, &mut buf, 0), 4);
    let Some((c, _)) = snap() else {
        println(b"SNMP_UDP_RECV:FAIL read");
        return;
    };
    grew(&mut t, &b, &c, b"Udp", b"InDatagrams", 1);
    grew(&mut t, &b, &c, b"Udp", b"OutDatagrams", 1);
    close(r);
    close(u);
    t.done();
}

/// `v` in decimal, in `buf`
fn dec(buf: &mut [u8; 20], mut v: u64) -> &[u8] {
    let mut k = buf.len();
    loop {
        k -= 1;
        buf[k] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[k..]
}

/// `parts` joined and NUL-terminated in `buf`
fn join<'a>(buf: &'a mut [u8; 96], parts: &[&[u8]]) -> &'a [u8] {
    let mut n = 0;
    for &c in parts.iter().flat_map(|p| p.iter()) {
        buf[n] = c;
        n += 1;
    }
    buf[n] = 0;
    &buf[..=n]
}

/// The number of lines of a /proc/net/dev text (2 header lines, then
/// one per device)
fn dev_lines(path: &[u8]) -> i64 {
    let mut b = [0u8; 4096];
    let n = read_file(path, &mut b);
    if n <= 0 {
        return n;
    }
    b[..n as usize]
        .split(|&c| c == b'\n')
        .filter(|l| !l.is_empty())
        .count() as i64
}

/// /proc/net is the link self/net, and /proc/<pid>/net and
/// /proc/<pid>/task/<tid>/net show that task's namespace: a child in a
/// new namespace, seen from its parent, has its own devices (lo only)
/// and its own counters (exactly the datagrams it sent)
fn test_proc_pid_net() {
    let mut t = T::new(b"PROC_PID_NET");
    let mut l = [0u8; 32];
    let n = sys_readlink(b"/proc/net\0".as_ptr(), l.as_mut_ptr(), l.len() as u64);
    t.ok(b"readlink", n == 8 && &l[..8] == b"self/net", n);
    let mut ready = [0i32; 2];
    let mut done = [0i32; 2];
    if sys_pipe2(ready.as_mut_ptr(), 0) != 0 || sys_pipe2(done.as_mut_ptr(), 0) != 0 {
        println(b"PROC_PID_NET:FAIL pipe");
        return;
    }
    const SENT: i64 = 7;
    let pid = sys_fork();
    if pid == 0 {
        let ok = sys_unshare(CLONE_NEWNET) == 0;
        if ok {
            loopback_up();
            let u = udp();
            bind(u, LO, 0);
            for _ in 0..SENT {
                send_to(u, b"x", LO, port(u), 0);
            }
        }
        let b = [u8::from(ok)];
        sys_write(ready[1] as u64, b.as_ptr(), 1);
        let mut c = [0u8; 1];
        sys_read(done[0] as u64, c.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let mut b = [0u8; 1];
    sys_read(ready[0] as u64, b.as_mut_ptr(), 1);
    if b[0] == 0 {
        sys_write(done[1] as u64, b.as_ptr(), 1);
        wait_child(pid);
        for fd in ready.into_iter().chain(done) {
            close(fd);
        }
        if host_mode() {
            skip(b"PROC_PID_NET", b"unshare(CLONE_NEWNET) not permitted");
        } else {
            println(b"PROC_PID_NET:FAIL unshare");
        }
        return;
    }
    let mut d = [0u8; 20];
    let pid_s = dec(&mut d, pid as u64);
    let mut p = [0u8; 96];
    let child = Mib::read(join(&mut p, &[b"/proc/", pid_s, b"/net/snmp"]));
    // The child is single-threaded: its tid is its pid
    let thread = Mib::read(join(
        &mut p,
        &[b"/proc/", pid_s, b"/task/", pid_s, b"/net/snmp"],
    ));
    let mine = Mib::read(b"/proc/self/net/snmp\0");
    match (child, thread, mine) {
        (Some(c), Some(th), Some(m)) => {
            t.eq(b"child OutDatagrams", c.val(b"Udp", b"OutDatagrams"), SENT);
            t.eq(
                b"thread OutDatagrams",
                th.val(b"Udp", b"OutDatagrams"),
                SENT,
            );
            t.ok(
                b"own OutDatagrams",
                m.val(b"Udp", b"OutDatagrams") != SENT,
                m.val(b"Udp", b"OutDatagrams"),
            );
        }
        _ => {
            t.ok(b"read snmp", false, 0);
        }
    }
    t.eq(
        b"child dev lines",
        dev_lines(join(&mut p, &[b"/proc/", pid_s, b"/net/dev"])),
        3,
    );
    t.ok(
        b"own dev lines",
        dev_lines(b"/proc/self/net/dev\0") > 3,
        dev_lines(b"/proc/self/net/dev\0"),
    );
    sys_write(done[1] as u64, b.as_ptr(), 1);
    wait_child(pid);
    for fd in ready.into_iter().chain(done) {
        close(fd);
    }
    t.done();
}
