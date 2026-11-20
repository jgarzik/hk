//! TCP listener paths (hk and Linux), seen on the wire through the
//! played peer of `tcp_synrecv` (raw segments from an address routed out
//! lo, captured on lo).
//!
//! - TCP_TW_ISN: a SYN taking over a TIME_WAIT tuple opens with ISN =
//!   the old connection's snd_nxt + 65535 + 2 (Linux
//!   tcp_timewait_state_process TCP_TW_SYN, tcp_conn_request's
//!   tcp_tw_isn). The value is not checked on the reference kernel:
//!   Ubuntu's 6.8 keeps tcp_tw_isn per CPU without 1bbf0ced1d9d, so a
//!   stale value is used (BUGS.md)

use hk_syscall::{sys_accept, sys_listen};

use crate::harness::T;
use crate::helpers::host_mode;
use crate::net::sk::*;
use crate::net::tcp_synrecv::{ACK, FIN, Peer, RST, SYN, got};

pub fn run_tests() {
    crate::helpers::println(b"=== TCP Listener Tests ===");
    test_tw_isn();
}

/// A listener on 127.0.0.1 and its port
fn listener(backlog: i32) -> (i32, u16) {
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, backlog);
    (l, port(l))
}

/// The peer completes a handshake with `pl` from `y`: the server's ISN,
/// or None
fn handshake(t: &mut T, peer: &Peer, pl: u16, y: u32) -> Option<u32> {
    t.eq(b"peer syn", peer.send(pl, y, 0, SYN), 40);
    let (f, s, a) = got(peer.from(pl, 1000));
    if !t.ok(b"syn-ack", f == i64::from(SYN | ACK) && a == y + 1, f) {
        return None;
    }
    t.eq(b"peer ack", peer.send(pl, y + 1, s + 1, ACK), 40);
    Some(s)
}

/// Accept one connection within `ms`
fn accept_in(l: i32, ms: i32) -> i32 {
    if poll1(l, 1, ms).0 != 1 {
        return -1;
    }
    sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32
}

fn test_tw_isn() {
    const Y: u32 = 0x5000_0000;
    let mut t = T::new(b"TCP_TW_ISN");
    let Some(peer) = Peer::new(&mut t) else {
        return t.done();
    };
    let (l, pl) = listener(8);
    let Some(s) = handshake(&mut t, &peer, pl, Y) else {
        close(l);
        return t.done();
    };
    let a = accept_in(l, 1000);
    t.ok(b"accept", a >= 0, i64::from(a));
    // The server closes first: FIN, ACKed; the peer's FIN takes it to
    // TIME_WAIT
    close(a);
    let (f, seq, _) = got(peer.from(pl, 1000));
    t.ok(b"fin", f == i64::from(FIN | ACK) && seq == s + 1, f);
    t.eq(b"peer ack", peer.send(pl, Y + 1, s + 2, ACK), 40);
    t.eq(b"peer fin", peer.send(pl, Y + 1, s + 2, FIN | ACK), 40);
    let (f, _, ack) = got(peer.from(pl, 1000));
    t.ok(b"time_wait ack", f == i64::from(ACK) && ack == Y + 2, f);
    // A new SYN beyond the old sequence space takes the tuple over
    let y2 = Y + 100_000;
    t.eq(b"takeover syn", peer.send(pl, y2, 0, SYN), 40);
    let (f, seq, ack) = got(peer.from(pl, 1000));
    t.ok(b"syn-ack", f == i64::from(SYN | ACK) && ack == y2 + 1, f);
    let isn = (s + 2).wrapping_add(65535 + 2);
    if !host_mode() {
        t.ok(b"isn", seq == isn, i64::from(seq.wrapping_sub(isn) as i32));
    }
    // The request goes with a reset
    peer.send(pl, y2 + 1, 0, RST);
    close(l);
    t.done();
}
