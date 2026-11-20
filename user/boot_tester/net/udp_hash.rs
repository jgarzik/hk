//! UDP socket table tests over lo (hk and Linux): many sockets on one
//! port by address (Linux udp_table.hash2, used once the port's slot
//! holds more than 10), rehash on connect/disconnect, connected
//! sockets beside wildcard ones, and a SO_REUSEPORT group with a
//! connected member.

use hk_syscall::SockAddrIn;

use crate::harness::T;
use crate::net::sk::*;

pub fn run_tests() {
    crate::helpers::println(b"=== UDP table Tests ===");
    test_addrs();
    test_rehash();
    test_connected();
    test_reuseport_connected();
}

/// A free port, by a bind and close
fn free_port() -> u16 {
    let s = udp();
    bind(s, ANY, 0);
    let p = port(s);
    close(s);
    p
}

/// A UDP socket with SO_REUSEADDR bound to `ip`:`p`, and the result
fn reuse_bind(ip: [u8; 4], p: u16) -> (i32, i64) {
    let s = udp();
    setint(s, SOL_SOCKET, SO_REUSEADDR, 1);
    (s, bind(s, ip, p))
}

/// One datagram's first byte, waiting up to a second; -1 if none
fn recv1(fd: i32) -> i64 {
    if poll1(fd, 1, 1000).0 != 1 {
        return -1;
    }
    let mut b = [0u8; 8];
    match recv(fd, &mut b, MSG_DONTWAIT) {
        n if n > 0 => i64::from(b[0]),
        n => n,
    }
}

/// Nothing queued after a short wait
fn quiet(fd: i32) -> bool {
    poll1(fd, 1, 50).0 == 0
}

/// Send byte `v` to `ip`:`p` from a fresh socket
fn send_byte(v: u8, ip: [u8; 4], p: u16) -> i64 {
    let c = udp();
    let r = send_to(c, &[v], ip, p, 0);
    close(c);
    r
}

/// 16 sockets bound to one port on 127.0.0.10..25 and one on INADDR_ANY:
/// each address reaches its own socket, another address the wildcard;
/// binds on the long slot check the address's and the wildcard's
/// hash2 slots (Linux udp_lib_lport_inuse2)
fn test_addrs() {
    let mut t = T::new(b"UDP_HASH2_ADDRS");
    let p = free_port();
    let mut s = [-1i32; 16];
    for (i, fd) in s.iter_mut().enumerate() {
        let (f, r) = reuse_bind([127, 0, 0, 10 + i as u8], p);
        t.eq(b"bind addr", r, 0);
        *fd = f;
    }
    let (any, r) = reuse_bind(ANY, p);
    t.eq(b"bind wildcard", r, 0);
    for (i, &fd) in s.iter().enumerate() {
        send_byte(i as u8, [127, 0, 0, 10 + i as u8], p);
        t.eq(b"own address", recv1(fd), i as i64);
    }
    send_byte(99, [127, 0, 0, 99], p);
    t.eq(b"wildcard gets other", recv1(any), 99);
    t.ok(b"addr sockets quiet", s.iter().all(|&fd| quiet(fd)), 0);
    let x = udp();
    t.eq(
        b"same addr no reuse",
        bind(x, [127, 0, 0, 10], p),
        EADDRINUSE,
    );
    t.eq(
        b"wildcard conflict",
        bind(x, [127, 0, 0, 200], p),
        EADDRINUSE,
    );
    close(x);
    let (y, r) = reuse_bind([127, 0, 0, 200], p);
    t.eq(b"reuse new addr", r, 0);
    send_byte(7, [127, 0, 0, 200], p);
    t.eq(b"exact beats wildcard", recv1(y), 7);
    t.ok(b"wildcard quiet", quiet(any), 0);
    for fd in s {
        close(fd);
    }
    close(any);
    close(y);
    t.done();
}

/// A socket bound to INADDR_ANY:port connects (its address becomes the
/// route's, Linux __ip4_datagram_connect's rehash), then disconnects
/// (back to INADDR_ANY, Linux __udp_disconnect's rehash): delivery
/// follows both
fn test_rehash() {
    let mut t = T::new(b"UDP_HASH2_REHASH");
    let p = free_port();
    let a = udp();
    t.eq(b"bind", bind(a, ANY, p), 0);
    let (c, pc) = udp_lo();
    t.eq(b"connect", connect(a, LO, pc), 0);
    t.ok(b"address set", name(a) == (LO, p), i64::from(name(a).1));
    send_to(c, &[1], LO, p, 0);
    t.eq(b"from peer", recv1(a), 1);
    send_byte(2, LO, p);
    t.ok(b"stranger filtered", quiet(a), 0);
    let unspec = SockAddrIn::new(0, 0, 0);
    t.eq(
        b"disconnect",
        hk_syscall::sys_connect(a, sa(&unspec), 16),
        0,
    );
    t.ok(b"address reset", name(a) == (ANY, p), i64::from(name(a).1));
    send_byte(3, [127, 0, 0, 7], p);
    t.eq(b"wildcard again", recv1(a), 3);
    close(a);
    close(c);
    t.done();
}

/// Two SO_REUSEADDR sockets on INADDR_ANY:port, one connected: its
/// peer's datagrams reach it, others the unconnected one
fn test_connected() {
    let mut t = T::new(b"UDP_HASH2_CONNECTED");
    let p = free_port();
    let (x, r) = reuse_bind(ANY, p);
    t.eq(b"bind x", r, 0);
    let (y, r) = reuse_bind(ANY, p);
    t.eq(b"bind y", r, 0);
    let (c, pc) = udp_lo();
    t.eq(b"connect x", connect(x, LO, pc), 0);
    send_to(c, &[1], LO, p, 0);
    t.eq(b"peer to connected", recv1(x), 1);
    t.ok(b"unconnected quiet", quiet(y), 0);
    send_byte(2, LO, p);
    t.eq(b"stranger to unconnected", recv1(y), 2);
    t.ok(b"connected quiet", quiet(x), 0);
    for fd in [x, y, c] {
        close(fd);
    }
    t.done();
}

/// A SO_REUSEPORT group on 127.0.0.1:port with one member connected:
/// the peer's datagrams all reach that member; the flow hash never
/// picks it for others (Linux reuseport_select_sock_by_hash skips
/// connected members, udp4_lib_lookup2 rescores the pick)
fn test_reuseport_connected() {
    let mut t = T::new(b"UDP_REUSEPORT_CONNECTED");
    let p = free_port();
    let mut g = [-1i32; 4];
    for fd in g.iter_mut() {
        let s = udp();
        setint(s, SOL_SOCKET, SO_REUSEPORT, 1);
        t.eq(b"join", bind(s, LO, p), 0);
        *fd = s;
    }
    let (c, pc) = udp_lo();
    t.eq(b"connect member", connect(g[0], LO, pc), 0);
    for i in 0..16u8 {
        send_to(c, &[i], LO, p, 0);
    }
    for i in 0..32u8 {
        send_byte(100 + i, LO, p);
    }
    let mut counts = [0i64; 4];
    let mut stray = 0;
    let mut buf = [0u8; 8];
    for _ in 0..200 {
        for (k, &s) in g.iter().enumerate() {
            while recv(s, &mut buf, MSG_DONTWAIT) > 0 {
                counts[k] += 1;
                if (k == 0) != (buf[0] < 100) {
                    stray += 1;
                }
            }
        }
        if counts.iter().sum::<i64>() >= 48 {
            break;
        }
        crate::helpers::msleep(10);
    }
    t.eq(b"all delivered", counts.iter().sum::<i64>(), 48);
    t.eq(b"peer to connected member", counts[0], 16);
    t.eq(b"none astray", stray, 0);
    for fd in g {
        close(fd);
    }
    close(c);
    t.done();
}
