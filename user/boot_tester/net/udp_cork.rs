//! UDP corking and SOL_UDP options over lo (hk and Linux: udp_sendmsg
//! with up->pending, udp_push_pending_frames, udp_lib_setsockopt).
//!
//! - UDP_MSG_MORE: sends with MSG_MORE append to one datagram, sent by
//!   the first send without it; appends ignore their address.
//! - UDP_CORK: data corked while UDP_CORK is set goes out as one
//!   datagram when it is cleared; close drops a corked datagram.
//! - UDP_CORK_EMSGSIZE: an append past the largest datagram fails and
//!   drops everything corked.
//! - UDP_SEGMENT: a send with a segment size arrives as datagrams of
//!   that size (software GSO on hk, segmented at the receiver on
//!   Linux's lo); too many segments is EINVAL.
//! - UDP_SOL_OPTS: UDP_ENCAP, UDP_NO_CHECK6_*, UDP_GRO round trips.

use crate::harness::T;
use crate::net::sk::*;

const MSG_MORE: i32 = 0x8000;
const UDP_CORK: i32 = 1;
const UDP_ENCAP: i32 = 100;
const UDP_NO_CHECK6_TX: i32 = 101;
const UDP_NO_CHECK6_RX: i32 = 102;
const UDP_SEGMENT: i32 = 103;
const UDP_GRO: i32 = 104;

pub fn run_tests() {
    crate::helpers::println(b"=== UDP cork Tests ===");
    test_msg_more();
    test_cork();
    test_cork_emsgsize();
    test_segment();
    test_sol_opts();
}

/// One datagram into `buf`, waiting up to a second: its length or -1
fn recv_wait(fd: i32, buf: &mut [u8]) -> i64 {
    if poll1(fd, 1, 1000).0 != 1 {
        return -1;
    }
    recv(fd, buf, MSG_DONTWAIT)
}

/// Nothing queued after a short wait
fn quiet(fd: i32) -> bool {
    poll1(fd, 1, 50).0 == 0
}

fn test_msg_more() {
    let mut t = T::new(b"UDP_MSG_MORE");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    let (c, pc) = udp_lo();
    t.eq(b"more 1", send_to(a, b"ab", LO, pb, MSG_MORE), 2);
    t.ok(b"held", quiet(b), 0);
    t.eq(b"more 2", send_to(a, b"cd", LO, pb, MSG_MORE), 2);
    // An append's own address is ignored
    t.eq(b"last", send_to(a, b"ef", LO, pc, 0), 2);
    let mut buf = [0u8; 16];
    let n = recv_wait(b, &mut buf);
    t.ok(b"one datagram", n == 6 && &buf[..6] == b"abcdef", n);
    t.ok(b"no more", quiet(b), 0);
    t.ok(b"other quiet", quiet(c), 0);
    for fd in [a, b, c] {
        close(fd);
    }
    t.done();
}

fn test_cork() {
    let mut t = T::new(b"UDP_CORK");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    t.eq(b"cork", setint(a, SOL_UDP, UDP_CORK, 1), 0);
    t.eq(b"get", getint(a, SOL_UDP, UDP_CORK).1 as i64, 1);
    t.eq(b"send 1", send_to(a, b"12", LO, pb, 0), 2);
    t.eq(b"send 2", send_to(a, b"34", LO, pb, 0), 2);
    t.ok(b"held", quiet(b), 0);
    t.eq(b"uncork", setint(a, SOL_UDP, UDP_CORK, 0), 0);
    t.eq(b"get off", getint(a, SOL_UDP, UDP_CORK).1 as i64, 0);
    let mut buf = [0u8; 16];
    let n = recv_wait(b, &mut buf);
    t.ok(b"flushed", n == 4 && &buf[..4] == b"1234", n);
    t.ok(b"no more", quiet(b), 0);
    // Closing drops what is corked
    let x = udp();
    setint(x, SOL_UDP, UDP_CORK, 1);
    send_to(x, b"lost", LO, pb, 0);
    close(x);
    t.ok(b"close drops", quiet(b), 0);
    close(a);
    close(b);
    t.done();
}

fn test_cork_emsgsize() {
    let mut t = T::new(b"UDP_CORK_EMSGSIZE");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    let big = [7u8; 60000];
    t.eq(b"first", send_to(a, &big, LO, pb, MSG_MORE), 60000);
    t.eq(
        b"too long",
        send_to(a, &big[..6000], LO, pb, MSG_MORE),
        EMSGSIZE,
    );
    t.eq(b"after", send_to(a, b"z", LO, pb, 0), 1);
    let mut buf = [0u8; 16];
    let n = recv_wait(b, &mut buf);
    t.ok(b"only the new one", n == 1 && buf[0] == b'z', n);
    close(a);
    close(b);
    t.done();
}

fn test_segment() {
    let mut t = T::new(b"UDP_SEGMENT");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    t.eq(b"set", setint(a, SOL_UDP, UDP_SEGMENT, 100), 0);
    t.eq(b"get", getint(a, SOL_UDP, UDP_SEGMENT).1 as i64, 100);
    let mut data = [0u8; 250];
    for (i, x) in data.iter_mut().enumerate() {
        *x = i as u8;
    }
    t.eq(b"send", send_to(a, &data, LO, pb, 0), 250);
    let mut buf = [0u8; 300];
    for (k, want) in [100usize, 100, 50].into_iter().enumerate() {
        let n = recv_wait(b, &mut buf);
        let first = (k * 100) as u8;
        t.ok(b"segment", n == want as i64 && buf[0] == first, n);
    }
    t.ok(b"no more", quiet(b), 0);
    t.eq(b"too many", setint(a, SOL_UDP, UDP_SEGMENT, 1), 0);
    t.eq(b"129 segments", send_to(a, &[0u8; 129], LO, pb, 0), EINVAL);
    t.eq(b"negative", setint(a, SOL_UDP, UDP_SEGMENT, -1), EINVAL);
    t.eq(b"too big", setint(a, SOL_UDP, UDP_SEGMENT, 65536), EINVAL);
    close(a);
    close(b);
    t.done();
}

fn test_sol_opts() {
    let mut t = T::new(b"UDP_SOL_OPTS");
    let s = udp();
    t.eq(b"encap l2tp", setint(s, SOL_UDP, UDP_ENCAP, 3), 0);
    t.eq(b"encap get", getint(s, SOL_UDP, UDP_ENCAP).1 as i64, 3);
    t.eq(b"encap bad", setint(s, SOL_UDP, UDP_ENCAP, 99), ENOPROTOOPT);
    t.eq(b"encap off", setint(s, SOL_UDP, UDP_ENCAP, 0), 0);
    for opt in [UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX, UDP_GRO] {
        t.eq(b"default", getint(s, SOL_UDP, opt).1 as i64, 0);
        t.eq(b"set", setint(s, SOL_UDP, opt, 5), 0);
        t.eq(b"bool", getint(s, SOL_UDP, opt).1 as i64, 1);
    }
    t.eq(b"unknown", setint(s, SOL_UDP, 999, 1), ENOPROTOOPT);
    close(s);
    t.done();
}
