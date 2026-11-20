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
//! - TCP_SYNCOOKIE: with the SYN queue full a SYN gets a cookie SYN-ACK
//!   (timestamp and window scale kept); its ACK makes an accepted
//!   connection with the cookie's MSS and the ACK's data; a forged
//!   cookie gets a RST; the Syncookies* and TCPReqQFullDoCookies
//!   counters (Linux tcp_conn_request want_cookie, cookie_v4_check)
//! - TCP_MAX_SYN_BACKLOG: without SYN cookies a listener keeps the last
//!   quarter of tcp_max_syn_backlog requests for proven peers: past it
//!   a SYN from a new peer is dropped (ListenDrops), however large the
//!   listen backlog (Linux tcp_conn_request)

use hk_syscall::{sys_accept, sys_listen, sys_setsockopt};

use crate::harness::T;
use crate::helpers::{host_mode, skip};
use crate::net::sk::*;
use crate::net::snmp::Mib;
use crate::net::tcp_synrecv::{ACK, FIN, Peer, RST, SYN, got};
use crate::proc::sysctl::{read_file, reads, write_file};

const NETSTAT: &[u8] = b"/proc/net/netstat\0";
const TCP_MAXSEG: i32 = 2;

pub fn run_tests() {
    crate::helpers::println(b"=== TCP Listener Tests ===");
    test_tw_isn();
    test_syncookie();
    test_max_syn_backlog();
}

/// SYN options: MSS 1460, SACK permitted, timestamps (`tsval`, 0),
/// window scale 7
fn syn_opts(tsval: u32) -> [u8; 20] {
    let mut o = [0u8; 20];
    o[..8].copy_from_slice(&[2, 4, 0x05, 0xb4, 4, 2, 8, 10]);
    o[8..12].copy_from_slice(&tsval.to_be_bytes());
    o[16..].copy_from_slice(&[1, 3, 3, 7]);
    o
}

/// A timestamps option (`v`, `e`)
fn ts_opt(v: u32, e: u32) -> [u8; 12] {
    let mut o = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
    o[4..8].copy_from_slice(&v.to_be_bytes());
    o[8..].copy_from_slice(&e.to_be_bytes());
    o
}

/// TcpExt counter `name` from /proc/net/netstat
fn tcpext(name: &[u8]) -> i64 {
    Mib::read(NETSTAT).map_or(-1, |m| m.val(b"TcpExt", name))
}

/// Abort `fd` with a RST (SO_LINGER 0): no orphan resends to the played
/// peer after its route is gone
fn abort(fd: i32) {
    let linger0 = [1i32, 0];
    sys_setsockopt(fd, SOL_SOCKET, SO_LINGER, linger0.as_ptr().cast(), 8);
    close(fd);
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

fn test_syncookie() {
    const Y: u32 = 0x6000_0000;
    const P1: u16 = 7791;
    const P2: u16 = 7792;
    const P3: u16 = 7793;
    if host_mode() {
        // Ubuntu's 6.8: a stale per-CPU tcp_tw_isn makes a SYN look
        // like a TIME_WAIT takeover, never a cookie (BUGS.md)
        return skip(b"TCP_SYNCOOKIE", b"reference tcp_tw_isn leak");
    }
    let mut t = T::new(b"TCP_SYNCOOKIE");
    let on = reads(b"/proc/sys/net/ipv4/tcp_syncookies\0", b"1\n");
    if !t.ok(b"tcp_syncookies 1", on, 0) {
        return t.done();
    }
    let Some(peer) = Peer::new(&mut t) else {
        return t.done();
    };
    let names: [&[u8]; 4] = [
        b"SyncookiesSent",
        b"SyncookiesRecv",
        b"SyncookiesFailed",
        b"TCPReqQFullDoCookies",
    ];
    let before = names.map(tcpext);
    let (l, pl) = listener(1);
    // One request fills the SYN queue of backlog 1
    t.eq(b"syn", peer.send_full(P1, pl, Y, 0, SYN, &[], &[]), 40);
    let (f, _, _) = got(peer.from_to(pl, P1, 1000));
    t.eq(b"syn-ack", f, i64::from(SYN | ACK));
    // The next SYN gets a cookie
    let r = peer.send_full(P2, pl, Y, 0, SYN, &syn_opts(100), &[]);
    t.eq(b"cookie syn", r, 60);
    let sa = peer.from_to(pl, P2, 1000).unwrap_or_default();
    t.ok(
        b"cookie syn-ack",
        sa.flags == SYN | ACK && sa.ack == Y + 1,
        i64::from(sa.flags),
    );
    let (tsval, tsecr) = sa.ts.unwrap_or((0, 0));
    t.ok(
        b"cookie ts",
        sa.ts.is_some() && tsecr == 100,
        i64::from(tsecr),
    );
    t.ok(b"cookie wscale", sa.ws.is_some(), 0);
    // Its ACK, with data, makes the connection
    let ack = ts_opt(101, tsval);
    let r = peer.send_full(P2, pl, Y + 1, sa.seq + 1, ACK, &ack, b"hello");
    t.eq(b"cookie ack", r, 57);
    let a = accept_in(l, 1000);
    t.ok(b"accept", a >= 0, i64::from(a));
    // The cookie's MSS (1460) less the timestamp option
    t.eq(b"mss", getint(a, IPPROTO_TCP, TCP_MAXSEG).1.into(), 1448);
    let mut b = [0u8; 8];
    t.eq(b"data", recv(a, &mut b, MSG_DONTWAIT), 5);
    t.ok(b"data bytes", &b[..5] == b"hello", 0);
    // A forged cookie: RST
    let r = peer.send_full(P3, pl, Y + 1, 0x1234_5678, ACK, &[], &[]);
    t.eq(b"forged ack", r, 40);
    let (f, seq, _) = got(peer.from_to(pl, P3, 1000));
    t.ok(b"reset", f == i64::from(RST) && seq == 0x1234_5678, f);
    let after = names.map(tcpext);
    for (i, n) in names.iter().enumerate() {
        t.ok(n, after[i] == before[i] + 1, after[i] - before[i]);
    }
    abort(a);
    peer.send_full(P1, pl, Y + 1, 0, RST, &[], &[]);
    close(l);
    t.done();
}

fn test_max_syn_backlog() {
    const Y: u32 = 0x7000_0000;
    const MAXSYN: &[u8] = b"/proc/sys/net/ipv4/tcp_max_syn_backlog\0";
    const COOKIES: &[u8] = b"/proc/sys/net/ipv4/tcp_syncookies\0";
    let mut t = T::new(b"TCP_MAX_SYN_BACKLOG");
    // A peer address no earlier test used (no tcp_metrics: unproven)
    let Some(peer) = Peer::at(&mut t, [192, 0, 2, 79]) else {
        return t.done();
    };
    let mut old = [0u8; 16];
    let n = read_file(MAXSYN, &mut old);
    if !t.ok(b"read", n > 0, n) {
        return t.done();
    }
    t.eq(b"set max", write_file(MAXSYN, b"4"), 1);
    t.eq(b"no cookies", write_file(COOKIES, b"0"), 1);
    let drops = tcpext(b"ListenDrops");
    let (l, pl) = listener(100);
    // Four requests fit: 4 - qlen < 4 / 4 only at qlen 4
    for i in 0..4u16 {
        peer.send_full(7801 + i, pl, Y, 0, SYN, &[], &[]);
        let (f, _, _) = got(peer.from_to(pl, 7801 + i, 1000));
        t.eq(b"syn-ack", f, i64::from(SYN | ACK));
    }
    peer.send_full(7805, pl, Y, 0, SYN, &[], &[]);
    t.eq(b"dropped", got(peer.from_to(pl, 7805, 500)).0, -1);
    t.eq(b"ListenDrops", tcpext(b"ListenDrops") - drops, 1);
    for i in 0..4u16 {
        peer.send_full(7801 + i, pl, Y + 1, 0, RST, &[], &[]);
    }
    close(l);
    write_file(COOKIES, b"1");
    write_file(MAXSYN, &old[..n as usize - 1]);
    t.ok(b"restored", reads(MAXSYN, &old[..n as usize]), 0);
    t.done();
}
