//! TCP buffers and window (hk and Linux 6.8).
//!
//! - TCP_WINDOW_CLAMP: 0 on a new socket, at least SOCK_MIN_RCVBUF / 2,
//!   0 refused on a connection (tcp_set_window_clamp); a clamp set
//!   before connect holds on the connection.
//! - TCP_RCV_SSTHRESH: a connection's tcpi_rcv_ssthresh lies within its
//!   window clamp.
//! - TCP_RCVBUF_AUTOTUNE: a new socket's SO_RCVBUF is tcp_rmem[1]; a
//!   reader taking 4 MB over lo has it grown (tcp_rcv_space_adjust,
//!   tcp_moderate_rcvbuf 1) within tcp_rmem[2] and reports
//!   tcpi_rcv_space; one with SO_RCVBUF set keeps it.
//! - TCP_SNDBUF_EXPAND: a new socket's SO_SNDBUF is tcp_wmem[1]; once
//!   connected it is expanded for the initial window
//!   (tcp_sndbuf_expand), within tcp_wmem[2]; one with SO_SNDBUF set
//!   keeps it.
//! - TCP_MAX_ORPHANS: net.ipv4.tcp_max_orphans is positive and only in
//!   the initial namespace (ipv4_table); at 0 an orphan stuck in
//!   FIN_WAIT_1 against a shut window is aborted at its next probe
//!   (tcp_out_of_resources, TCPAbortOnMemory).
//! - TCP_CHALLENGE_ACK_LIMIT: net.ipv4.tcp_challenge_ack_limit is
//!   INT_MAX (no global budget, Linux 6.0 on) and per namespace.
//! - TCP_MAX_TW_BUCKETS: net.ipv4.tcp_max_tw_buckets is positive and
//!   per namespace; at 0 a connection closing first skips TIME_WAIT
//!   (inet_twsk_alloc refuses, TCPTimeWaitOverflow).
//! - TCP_FIN_WAIT2_TW: an orphan's FIN_WAIT_2 (tcp_fin_timeout within
//!   TIME_WAIT's length) is a timewait entry (sockstat tw, a 05 line
//!   with the timewait timer in /proc/net/tcp); data from the peer is
//!   answered with a reset.
//! - TCP_PEEK_OFF: SO_PEEK_OFF on TCP (Linux 6.10 on: before it,
//!   EOPNOTSUPP): MSG_PEEK reads from the offset and moves it on, a
//!   read moves it back.

use hk_syscall::{sys_exit, sys_fork, sys_getsockopt};

use crate::harness::T;
use crate::net::sk::*;
use crate::net::snmp::Mib;
use crate::net::tcp_xfer::{accept, listener, recv_pat, send_pat, set_timeo, wait_child};
use crate::proc::sysctl::{read_file, write_file};

const TCP_WINDOW_CLAMP: i32 = 10;
const TCP_INFO: i32 = 11;
const EINVAL: i64 = -22;
const MB: usize = 1024 * 1024;

pub fn run_tests() {
    test_window_clamp();
    test_rcv_ssthresh();
    test_autotune();
    test_sndbuf();
    test_max_orphans();
    test_challenge_limit();
    test_max_tw();
    test_fin_wait2_tw();
    test_peek_off();
}

/// A connected pair over lo: (client, server, listener)
fn pair() -> (i32, i32, i32) {
    let (l, p) = listener(4);
    let c = tcp();
    connect(c, LO, p);
    (c, accept(l), l)
}

/// The u32 at `off` of `fd`'s TCP_INFO
fn info_u32(fd: i32, off: usize) -> u32 {
    let mut b = [0u8; 256];
    let mut len = b.len() as u32;
    sys_getsockopt(fd, IPPROTO_TCP, TCP_INFO, b.as_mut_ptr(), &mut len);
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn test_window_clamp() {
    let mut t = T::new(b"TCP_WINDOW_CLAMP");
    let fd = tcp();
    let get = |fd| getint(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP).1 as i64;
    t.eq(b"default", get(fd), 0);
    t.eq(
        b"set small",
        setint(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, 100),
        0,
    );
    t.eq(b"min", get(fd), 1152);
    t.eq(
        b"clear closed",
        setint(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, 0),
        0,
    );
    t.eq(b"cleared", get(fd), 0);
    setint(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, 20000);
    let (l, p) = listener(4);
    t.eq(b"connect", connect(fd, LO, p), 0);
    let s = accept(l);
    t.eq(b"kept", get(fd), 20000);
    t.eq(
        b"clear connected",
        setint(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, 0),
        EINVAL,
    );
    t.eq(b"set", setint(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, 5000), 0);
    t.eq(b"lowered", get(fd), 5000);
    t.ok(
        b"rcv_ssthresh",
        info_u32(fd, 64) <= 5000,
        info_u32(fd, 64) as i64,
    );
    close(s);
    close(fd);
    close(l);
    t.done();
}

fn test_rcv_ssthresh() {
    let mut t = T::new(b"TCP_RCV_SSTHRESH");
    let (c, s, l) = pair();
    let clamp = getint(s, IPPROTO_TCP, TCP_WINDOW_CLAMP).1 as i64;
    let ssth = info_u32(s, 64) as i64;
    t.ok(b"clamp", clamp > 0, clamp);
    t.ok(b"within clamp", ssth > 0 && ssth <= clamp, ssth);
    close(c);
    close(s);
    close(l);
    t.done();
}

/// The integers of a sysctl file (up to 3)
fn sysctl_ints(path: &[u8]) -> [i64; 3] {
    let mut b = [0u8; 64];
    let n = read_file(path, &mut b).max(0) as usize;
    let mut v = [0i64; 3];
    let fields = b[..n]
        .split(|c| !c.is_ascii_digit())
        .filter(|f| !f.is_empty());
    for (x, f) in v.iter_mut().zip(fields) {
        *x = f.iter().fold(0i64, |a, &c| a * 10 + i64::from(c - b'0'));
    }
    v
}

/// 4 MB from a forked client to a server socket whose SO_RCVBUF is
/// `rcvbuf` if nonzero: the server's SO_RCVBUF and tcpi_rcv_space after
fn bulk(t: &mut T, rcvbuf: i32) -> (i64, i64) {
    let (l, p) = listener(4);
    if rcvbuf != 0 {
        setint(l, SOL_SOCKET, SO_RCVBUF, rcvbuf);
    }
    let child = sys_fork();
    if child == 0 {
        let c = tcp();
        set_timeo(c, 60_000);
        if connect(c, LO, p) != 0 {
            sys_exit(1);
        }
        let ok = send_pat(c, 9, 4 * MB) == (4 * MB) as i64;
        close(c);
        sys_exit(if ok { 0 } else { 2 });
    }
    let s = accept(l);
    set_timeo(s, 60_000);
    let (n, bad, _) = recv_pat(s, 9, 4 * MB, 16384);
    t.eq(b"got", n as i64, (4 * MB) as i64);
    t.eq(b"data", bad, -1);
    t.eq(b"client", wait_child(child) as i64, 0);
    let r = (
        getint(s, SOL_SOCKET, SO_RCVBUF).1 as i64,
        info_u32(s, 96) as i64,
    );
    close(s);
    close(l);
    r
}

fn test_autotune() {
    let mut t = T::new(b"TCP_RCVBUF_AUTOTUNE");
    let moderate = sysctl_ints(b"/proc/sys/net/ipv4/tcp_moderate_rcvbuf\0");
    t.eq(b"moderate_rcvbuf", moderate[0], 1);
    let [_, def, max] = sysctl_ints(b"/proc/sys/net/ipv4/tcp_rmem\0");
    t.ok(b"tcp_rmem", def > 0 && max >= def, def);
    let fd = tcp();
    t.eq(b"initial", getint(fd, SOL_SOCKET, SO_RCVBUF).1 as i64, def);
    close(fd);
    let (grown, space) = bulk(&mut t, 0);
    t.ok(b"grown", grown > def && grown <= max, grown);
    t.ok(b"rcv_space", space > 0, space);
    // SO_RCVBUF 65536 (doubled) on the listener, inherited
    let (fixed, _) = bulk(&mut t, 65536);
    t.eq(b"fixed", fixed, 131072);
    t.done();
}

fn test_sndbuf() {
    let mut t = T::new(b"TCP_SNDBUF_EXPAND");
    let [min, def, max] = sysctl_ints(b"/proc/sys/net/ipv4/tcp_wmem\0");
    t.ok(b"tcp_wmem", min > 0 && def >= min && max >= def, def);
    let fd = tcp();
    t.eq(b"initial", getint(fd, SOL_SOCKET, SO_SNDBUF).1 as i64, def);
    close(fd);
    let (c, s, l) = pair();
    let grown = getint(c, SOL_SOCKET, SO_SNDBUF).1 as i64;
    t.ok(b"expanded", grown > def && grown <= max, grown);
    close(c);
    close(s);
    close(l);
    let (l, p) = listener(4);
    let c = tcp();
    setint(c, SOL_SOCKET, SO_SNDBUF, 20000);
    connect(c, LO, p);
    let s = accept(l);
    t.eq(b"fixed", getint(c, SOL_SOCKET, SO_SNDBUF).1 as i64, 40000);
    close(c);
    close(s);
    close(l);
    t.done();
}

const MAX_ORPHANS: &[u8] = b"/proc/sys/net/ipv4/tcp_max_orphans\0";

/// TcpExt TCPAbortOnMemory
fn abort_on_memory() -> i64 {
    Mib::read(b"/proc/net/netstat\0").map_or(-1, |m| m.val(b"TcpExt", b"TCPAbortOnMemory"))
}

fn test_max_orphans() {
    let mut t = T::new(b"TCP_MAX_ORPHANS");
    let mut old = [0u8; 32];
    let n = read_file(MAX_ORPHANS, &mut old);
    let max = sysctl_ints(MAX_ORPHANS)[0];
    t.ok(b"default", n > 0 && max > 0, max);
    let child = sys_fork();
    if child == 0 {
        if hk_syscall::sys_unshare(hk_syscall::CLONE_NEWNET) != 0 {
            sys_exit(1);
        }
        let mut b = [0u8; 32];
        sys_exit(if read_file(MAX_ORPHANS, &mut b) < 0 {
            0
        } else {
            2
        });
    }
    t.eq(b"netns", wait_child(child) as i64, 0);
    if n <= 0 {
        t.done();
        return;
    }
    // A receiver that never reads, behind a small buffer
    let (l, p) = listener(4);
    setint(l, SOL_SOCKET, SO_RCVBUF, 4096);
    let c = tcp();
    connect(c, LO, p);
    let s = accept(l);
    let buf = [7u8; 4096];
    for _ in 0..1000 {
        if send(c, &buf, MSG_DONTWAIT | MSG_NOSIGNAL) <= 0 {
            break;
        }
    }
    let before = abort_on_memory();
    // An orphan holding data, probing the shut window
    close(c);
    write_file(MAX_ORPHANS, b"0\n");
    let mut aborted = false;
    for _ in 0..300 {
        if abort_on_memory() > before {
            aborted = true;
            break;
        }
        crate::helpers::msleep(50);
    }
    write_file(MAX_ORPHANS, &old[..n as usize]);
    t.ok(b"aborted", aborted, abort_on_memory() - before);
    close(s);
    close(l);
    t.done();
}

const CHALLENGE: &[u8] = b"/proc/sys/net/ipv4/tcp_challenge_ack_limit\0";

fn test_challenge_limit() {
    let mut t = T::new(b"TCP_CHALLENGE_ACK_LIMIT");
    t.eq(b"default", sysctl_ints(CHALLENGE)[0], 2147483647);
    let child = sys_fork();
    if child == 0 {
        if hk_syscall::sys_unshare(hk_syscall::CLONE_NEWNET) != 0 {
            sys_exit(1);
        }
        if sysctl_ints(CHALLENGE)[0] != 2147483647 {
            sys_exit(2);
        }
        if write_file(CHALLENGE, b"100\n") < 0 {
            sys_exit(3);
        }
        sys_exit(if sysctl_ints(CHALLENGE)[0] == 100 {
            0
        } else {
            4
        });
    }
    t.eq(b"netns", wait_child(child) as i64, 0);
    t.eq(b"init unchanged", sysctl_ints(CHALLENGE)[0], 2147483647);
    t.done();
}

const MAX_TW: &[u8] = b"/proc/sys/net/ipv4/tcp_max_tw_buckets\0";

/// In a new namespace with tcp_max_tw_buckets 0: an active close's
/// TIME_WAIT is refused (exit status 0 if so)
fn tw_refused() -> u64 {
    crate::helpers::loopback_up();
    if write_file(MAX_TW, b"0\n") < 0 {
        return 1;
    }
    let ovf = || {
        Mib::read(b"/proc/net/netstat\0").map_or(-1, |m| m.val(b"TcpExt", b"TCPTimeWaitOverflow"))
    };
    let before = ovf();
    let (l, p) = listener(4);
    let c = tcp();
    if connect(c, LO, p) != 0 {
        return 2;
    }
    let s = accept(l);
    close(c);
    crate::helpers::msleep(50);
    close(s);
    for _ in 0..100 {
        if ovf() > before {
            close(l);
            return 0;
        }
        crate::helpers::msleep(20);
    }
    3
}

fn test_max_tw() {
    let mut t = T::new(b"TCP_MAX_TW_BUCKETS");
    let max = sysctl_ints(MAX_TW)[0];
    t.ok(b"default", max > 0, max);
    let child = sys_fork();
    if child == 0 {
        if hk_syscall::sys_unshare(hk_syscall::CLONE_NEWNET) != 0 {
            sys_exit(9);
        }
        sys_exit(tw_refused());
    }
    t.eq(b"refused", wait_child(child) as i64, 0);
    t.eq(b"init unchanged", sysctl_ints(MAX_TW)[0], max);
    t.done();
}

/// The sockstat "TCP: ... tw N" value
fn sockstat_tw() -> i64 {
    let mut b = [0u8; 1024];
    let n = read_file(b"/proc/net/sockstat\0", &mut b).max(0) as usize;
    let Some(line) = b[..n]
        .split(|&c| c == b'\n')
        .find(|l| l.starts_with(b"TCP:"))
    else {
        return -1;
    };
    let mut w = line.split(|&c| c == b' ');
    while let Some(x) = w.next() {
        if x == b"tw" {
            let v = w.next().unwrap_or(b"");
            return v.iter().fold(0i64, |a, &c| a * 10 + i64::from(c - b'0'));
        }
    }
    -1
}

/// In a new namespace: the orphan's FIN_WAIT_2 entry (exit status 0)
fn fw2_entry() -> u64 {
    crate::helpers::loopback_up();
    let (l, p) = listener(4);
    let c = tcp();
    if connect(c, LO, p) != 0 {
        return 1;
    }
    let s = accept(l);
    close(c);
    let mut seen = false;
    for _ in 0..100 {
        if sockstat_tw() == 1 {
            seen = true;
            break;
        }
        crate::helpers::msleep(10);
    }
    if !seen {
        return 2;
    }
    let mut b = [0u8; 4096];
    let n = read_file(b"/proc/net/tcp\0", &mut b).max(0) as usize;
    // "sl local rem st tx:rx tr:when": state 05, timer 03
    let fw2 = b[..n].split(|&c| c == b'\n').any(|l| {
        let f: [&[u8]; 6] = {
            let mut it = l.split(|&c| c == b' ').filter(|w| !w.is_empty());
            [(); 6].map(|_| it.next().unwrap_or(b""))
        };
        f[3] == b"05" && f[5].starts_with(b"03:")
    });
    if !fw2 {
        return 3;
    }
    // Data after the half-duplex close: reset (TCP_TW_RST). The FIN
    // already set SOCK_DONE, so recv keeps reading 0 (Linux
    // tcp_recvmsg_locked); the reset shows as TCP_CLOSE in TCP_INFO.
    send(s, b"late", MSG_NOSIGNAL);
    let mut closed = false;
    for _ in 0..100 {
        if info_u32(s, 0) & 0xff == 7 {
            closed = true;
            break;
        }
        crate::helpers::msleep(10);
    }
    if !closed {
        return 4;
    }
    close(s);
    close(l);
    0
}

fn test_fin_wait2_tw() {
    let mut t = T::new(b"TCP_FIN_WAIT2_TW");
    let child = sys_fork();
    if child == 0 {
        if hk_syscall::sys_unshare(hk_syscall::CLONE_NEWNET) != 0 {
            sys_exit(9);
        }
        sys_exit(fw2_entry());
    }
    t.eq(b"entry", wait_child(child) as i64, 0);
    t.done();
}

const SO_PEEK_OFF: i32 = 42;

fn test_peek_off() {
    let mut t = T::new(b"TCP_PEEK_OFF");
    let (c, s, l) = pair();
    if !crate::helpers::linux_at_least(6, 10) {
        t.eq(b"old", setint(s, SOL_SOCKET, SO_PEEK_OFF, 0), EOPNOTSUPP);
    } else {
        t.eq(b"default", getint(s, SOL_SOCKET, SO_PEEK_OFF).1 as i64, -1);
        t.eq(b"set", setint(s, SOL_SOCKET, SO_PEEK_OFF, 0), 0);
        send(c, b"abcdefgh", 0);
        let mut b = [0u8; 8];
        // Let all eight bytes arrive
        for _ in 0..100 {
            if recv(s, &mut b, MSG_PEEK | MSG_DONTWAIT) == 8 {
                break;
            }
            setint(s, SOL_SOCKET, SO_PEEK_OFF, 0);
            crate::helpers::msleep(10);
        }
        setint(s, SOL_SOCKET, SO_PEEK_OFF, 0);
        let get = |flags: i32, n: usize| {
            let mut x = [0u8; 8];
            let r = recv(s, &mut x[..n], flags | MSG_DONTWAIT);
            (r, x)
        };
        let (r, x) = get(MSG_PEEK, 3);
        t.ok(b"peek abc", r == 3 && &x[..3] == b"abc", r);
        let (r, x) = get(MSG_PEEK, 3);
        t.ok(b"peek def", r == 3 && &x[..3] == b"def", r);
        t.eq(b"offset", getint(s, SOL_SOCKET, SO_PEEK_OFF).1 as i64, 6);
        let (r, x) = get(0, 2);
        t.ok(b"read ab", r == 2 && &x[..2] == b"ab", r);
        t.eq(b"back", getint(s, SOL_SOCKET, SO_PEEK_OFF).1 as i64, 4);
        let (r, x) = get(MSG_PEEK, 2);
        t.ok(b"peek gh", r == 2 && &x[..2] == b"gh", r);
        setint(s, SOL_SOCKET, SO_PEEK_OFF, -1);
        let (r, x) = get(MSG_PEEK, 2);
        t.ok(b"off: peek cd", r == 2 && &x[..2] == b"cd", r);
    }
    close(c);
    close(s);
    close(l);
    t.done();
}
