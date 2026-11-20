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
//! - TCP_DEFER_ACCEPT: a listener's request drops the bare ACK
//!   (TCPDeferAcceptDrop) and is accepted once data comes (Linux
//!   tcp_check_req); a connecting socket with it saves the handshake's
//!   last ACK for the delayed ACK timer (tcp_rcv_synsent_state_process)
//! - TCP_FASTOPEN_SERVER: with tcp_fastopen 3 and TCP_FASTOPEN on the
//!   listener a cookie request gets a cookie; a SYN with that cookie and
//!   data is accepted at once, its data readable and acknowledged by the
//!   SYN-ACK, the child sending before the handshake completes; a wrong
//!   cookie gets the SYN only acknowledged and the right cookie
//!   (TCPFastOpenCookieReqd, TCPFastOpenPassive, TCPFastOpenPassiveFail;
//!   Linux tcp_try_fastopen)
//! - TCP_FASTOPEN_KEYS: TCP_FASTOPEN_KEY takes a primary and backup key
//!   and returns them; net.ipv4.tcp_fastopen_key reads back as
//!   "%08x-%08x-%08x-%08x" words (tcp_fastopen_reset_cipher,
//!   proc_tcp_fastopen_key)

use hk_syscall::{
    AF_INET, SOCK_NONBLOCK, SOCK_STREAM, sys_accept, sys_getsockopt, sys_listen, sys_setsockopt,
    sys_socket,
};

use crate::harness::T;
use crate::helpers::{host_mode, skip};
use crate::net::sk::*;
use crate::net::snmp::Mib;
use crate::net::tcp_synrecv::{ACK, FIN, PEER_PORT, Peer, RST, SYN, VOID, got};
use crate::proc::sysctl::{read_file, reads, write_file};

const NETSTAT: &[u8] = b"/proc/net/netstat\0";
const TCP_MAXSEG: i32 = 2;
const TCP_DEFER_ACCEPT: i32 = 9;
const TCP_FASTOPEN: i32 = 23;

pub fn run_tests() {
    crate::helpers::println(b"=== TCP Listener Tests ===");
    test_tw_isn();
    test_syncookie();
    test_max_syn_backlog();
    test_defer_accept();
    test_fastopen_server();
    test_fastopen_keys();
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

fn test_defer_accept() {
    const Y: u32 = 0x7800_0000;
    const S: u32 = 0x7900_0000;
    let mut t = T::new(b"TCP_DEFER_ACCEPT");
    let Some(peer) = Peer::new(&mut t) else {
        return t.done();
    };
    let l = tcp();
    bind(l, LO, 0);
    let pl = port(l);
    t.eq(b"defer", setint(l, IPPROTO_TCP, TCP_DEFER_ACCEPT, 5), 0);
    sys_listen(l, 8);
    let drops = tcpext(b"TCPDeferAcceptDrop");
    t.eq(b"syn", peer.send(pl, Y, 0, SYN), 40);
    let (f, s, _) = got(peer.from(pl, 1000));
    t.eq(b"syn-ack", f, i64::from(SYN | ACK));
    // The bare ACK is dropped: nothing to accept
    t.eq(b"bare ack", peer.send(pl, Y + 1, s + 1, ACK), 40);
    t.eq(b"not ready", poll1(l, 1, 300).0, 0);
    t.eq(
        b"TCPDeferAcceptDrop",
        tcpext(b"TCPDeferAcceptDrop") - drops,
        1,
    );
    // Data completes it
    let r = peer.send_full(PEER_PORT, pl, Y + 1, s + 1, ACK, &[], b"hi");
    t.eq(b"data", r, 42);
    let a = accept_in(l, 1000);
    t.ok(b"accept", a >= 0, i64::from(a));
    let mut b = [0u8; 4];
    t.eq(b"recv", recv(a, &mut b, MSG_DONTWAIT), 2);
    abort(a);
    close(l);
    // A connecting socket with it delays the handshake's last ACK
    let c = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0) as i32;
    t.eq(
        b"client defer",
        setint(c, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1),
        0,
    );
    bind(c, LO, 0);
    t.eq(b"connect", connect(c, VOID, PEER_PORT), EINPROGRESS);
    let pc = port(c);
    let (f, iss, _) = got(peer.from(pc, 1000));
    t.eq(b"client syn", f, i64::from(SYN));
    let start = now_ms();
    t.eq(b"peer syn-ack", peer.send(pc, S, iss + 1, SYN | ACK), 40);
    let (f, _, ack) = got(peer.from(pc, 1000));
    let waited = now_ms() - start;
    t.ok(b"ack", f == i64::from(ACK) && ack == S + 1, f);
    t.ok(b"delayed", (150..1000).contains(&waited), waited as i64);
    abort(c);
    t.done();
}

fn test_fastopen_server() {
    const Y: u32 = 0x7a00_0000;
    const P1: u16 = 7821;
    const P2: u16 = 7822;
    const P3: u16 = 7823;
    const TFO: &[u8] = b"/proc/sys/net/ipv4/tcp_fastopen\0";
    let mut t = T::new(b"TCP_FASTOPEN_SERVER");
    let Some(peer) = Peer::new(&mut t) else {
        return t.done();
    };
    let mut old = [0u8; 16];
    let n = read_file(TFO, &mut old);
    if !t.ok(b"read", n > 0, n) {
        return t.done();
    }
    t.eq(b"enable", write_file(TFO, b"3"), 1);
    let names: [&[u8]; 3] = [
        b"TCPFastOpenCookieReqd",
        b"TCPFastOpenPassive",
        b"TCPFastOpenPassiveFail",
    ];
    let before = names.map(tcpext);
    let l = tcp();
    bind(l, LO, 0);
    let pl = port(l);
    t.eq(b"TCP_FASTOPEN", setint(l, IPPROTO_TCP, TCP_FASTOPEN, 5), 0);
    sys_listen(l, 8);
    // A cookie request
    peer.send_full(P1, pl, Y, 0, SYN, &[34, 2, 1, 1], &[]);
    let sa = peer.from_to(pl, P1, 1000).unwrap_or_default();
    t.ok(
        b"syn-ack",
        sa.flags == SYN | ACK && sa.ack == Y + 1,
        i64::from(sa.flags),
    );
    let (clen, cookie) = sa.foc.unwrap_or_default();
    t.eq(b"cookie", clen as i64, 8);
    peer.send_full(P1, pl, Y + 1, 0, RST, &[], &[]);
    // The cookie with data: accepted at once
    let mut opt = [0u8; 12];
    opt[..2].copy_from_slice(&[34, 10]);
    opt[2..10].copy_from_slice(&cookie[..8]);
    opt[10..].copy_from_slice(&[1, 1]);
    peer.send_full(P2, pl, Y, 0, SYN, &opt, b"hello");
    let sa = peer.from_to(pl, P2, 1000).unwrap_or_default();
    t.ok(
        b"data acked",
        sa.flags == SYN | ACK && sa.ack == Y + 6,
        i64::from(sa.ack.wrapping_sub(Y)),
    );
    let a = accept_in(l, 1000);
    t.ok(b"accept", a >= 0, i64::from(a));
    let mut b = [0u8; 8];
    t.eq(b"recv", recv(a, &mut b, MSG_DONTWAIT), 5);
    t.ok(b"bytes", &b[..5] == b"hello", 0);
    t.eq(b"send", send(a, b"ok", MSG_DONTWAIT), 2);
    let d = peer.from_to(pl, P2, 1000).unwrap_or_default();
    t.ok(
        b"sent early",
        d.len == 2 && d.seq == sa.seq + 1,
        d.len as i64,
    );
    peer.send_full(P2, pl, Y + 6, sa.seq + 3, ACK, &[], &[]);
    // A wrong cookie: the SYN alone is acknowledged, with the cookie
    let mut bad = opt;
    bad[2..10].fill(0);
    peer.send_full(P3, pl, Y, 0, SYN, &bad, b"hello");
    let sa = peer.from_to(pl, P3, 1000).unwrap_or_default();
    t.ok(
        b"syn only",
        sa.flags == SYN | ACK && sa.ack == Y + 1,
        i64::from(sa.ack.wrapping_sub(Y)),
    );
    t.ok(
        b"right cookie",
        sa.foc.is_some_and(|(n, c)| n == 8 && c == cookie),
        0,
    );
    peer.send_full(P3, pl, Y + 1, 0, RST, &[], &[]);
    let after = names.map(tcpext);
    for (i, n) in names.iter().enumerate() {
        t.ok(n, after[i] == before[i] + 1, after[i] - before[i]);
    }
    abort(a);
    close(l);
    write_file(TFO, &old[..n as usize - 1]);
    t.done();
}

fn test_fastopen_keys() {
    const KEY: &[u8] = b"/proc/sys/net/ipv4/tcp_fastopen_key\0";
    const TCP_FASTOPEN_KEY: i32 = 33;
    let mut t = T::new(b"TCP_FASTOPEN_KEYS");
    let s = tcp();
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    let r = sys_setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN_KEY, k.as_ptr(), 32);
    t.eq(b"set", r, 0);
    t.eq(
        b"bad len",
        sys_setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN_KEY, k.as_ptr(), 20),
        EINVAL,
    );
    let mut g = [0u8; 40];
    let mut len = g.len() as u32;
    let r = sys_getsockopt(s, IPPROTO_TCP, TCP_FASTOPEN_KEY, g.as_mut_ptr(), &mut len);
    t.ok(b"get", r == 0 && len == 32 && g[..32] == k, i64::from(len));
    close(s);
    let mut old = [0u8; 128];
    let n = read_file(KEY, &mut old);
    t.ok(b"read", n > 0, n);
    t.eq(b"write", write_file(KEY, b"1-2-3-4,a-b-c-d"), 15);
    let want = b"00000001-00000002-00000003-00000004,0000000a-0000000b-0000000c-0000000d\n";
    t.ok(b"format", reads(KEY, want), 0);
    t.ok(b"bad key", write_file(KEY, b"1-2-3") < 0, 0);
    if n > 0 {
        write_file(KEY, &old[..n as usize - 1]);
    }
    t.done();
}
