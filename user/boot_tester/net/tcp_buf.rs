//! TCP buffers and window (hk and Linux 6.8).
//!
//! - TCP_WINDOW_CLAMP: 0 on a new socket, at least SOCK_MIN_RCVBUF / 2,
//!   0 refused on a connection (tcp_set_window_clamp); a clamp set
//!   before connect holds on the connection.
//! - TCP_RCV_SSTHRESH: a connection's tcpi_rcv_ssthresh lies within its
//!   window clamp.

use hk_syscall::sys_getsockopt;

use crate::harness::T;
use crate::net::sk::*;
use crate::net::tcp_xfer::{accept, listener};

const TCP_WINDOW_CLAMP: i32 = 10;
const TCP_INFO: i32 = 11;
const EINVAL: i64 = -22;

pub fn run_tests() {
    test_window_clamp();
    test_rcv_ssthresh();
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
