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

use hk_syscall::{sys_exit, sys_fork, sys_getsockopt};

use crate::harness::T;
use crate::net::sk::*;
use crate::net::tcp_xfer::{accept, listener, recv_pat, send_pat, set_timeo, wait_child};
use crate::proc::sysctl::read_file;

const TCP_WINDOW_CLAMP: i32 = 10;
const TCP_INFO: i32 = 11;
const EINVAL: i64 = -22;
const MB: usize = 1024 * 1024;

pub fn run_tests() {
    test_window_clamp();
    test_rcv_ssthresh();
    test_autotune();
    test_sndbuf();
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
