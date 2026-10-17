//! UDP tests over lo (hk and Linux): datagram semantics, connected
//! sockets, PEEK/TRUNC/DONTWAIT, size limits, bind and ephemeral port
//! rules, receive buffer bounds, control messages, broadcast permission,
//! poll/epoll readiness. The eth0 DNS exchange is in netdev.rs.

use hk_syscall::{
    EPOLL_CTL_ADD, EPOLLIN, EpollEvent, IoVec, MsgHdr, SHUT_RD, SockAddrIn, sys_close,
    sys_epoll_create1, sys_epoll_ctl, sys_epoll_wait, sys_read, sys_sendmsg, sys_shutdown,
    sys_write,
};

use super::sk::*;

pub fn run_tests() {
    super::helpers::println(b"=== UDP Tests ===");
    test_basic();
    test_connected();
    test_disconnect();
    test_dest_errors();
    test_peek_trunc();
    test_dontwait();
    test_sizes();
    test_bind_rules();
    test_ephemeral();
    test_rcvbuf_drops();
    test_pktinfo();
    test_ttl_tos();
    test_timestamp();
    test_broadcast();
    test_poll_epoll();
    test_shut_rd();
    test_errqueue();
    test_src_spoof();
}

/// sendto/recvfrom with the source address
fn test_basic() {
    let mut t = T::new(b"UDP_BASIC");
    let (a, pa) = udp_lo();
    let (b, pb) = udp_lo();
    t.eq(b"sendto", send_to(a, b"ping", LO, pb, 0), 4);
    let mut buf = [0u8; 16];
    let (n, ip, p) = recv_from(b, &mut buf, 0);
    t.ok(
        b"recvfrom",
        n == 4 && &buf[..4] == b"ping" && ip == LO && p == pa,
        n,
    );
    close(a);
    close(b);
    t.done();
}

/// connect: send/write/recv/read without addresses, getsockname gets
/// the route's source, getpeername the peer, other sources are filtered
fn test_connected() {
    let mut t = T::new(b"UDP_CONNECTED");
    let (srv, ps) = udp_lo();
    let c = udp();
    t.eq(b"connect", connect(c, LO, ps), 0);
    let (ip, pc) = name(c);
    t.ok(b"autobound source", ip == LO && pc != 0, pc as i64);
    let mut s = sin(ANY, 0);
    let mut len = 16u32;
    let r = hk_syscall::sys_getpeername(c, &mut s as *mut SockAddrIn as *mut u8, &mut len);
    t.ok(b"getpeername", r == 0 && u16::from_be(s.sin_port) == ps, r);
    t.eq(b"send", send(c, b"one", 0), 3);
    t.eq(b"write", sys_write(c as u64, b"two".as_ptr(), 3), 3);
    let mut buf = [0u8; 8];
    t.eq(b"srv recv 1", recv(srv, &mut buf, 0), 3);
    t.eq(b"srv recv 2", recv(srv, &mut buf, 0), 3);
    // A third socket's datagram does not reach the connected socket
    let (x, _) = udp_lo();
    send_to(x, b"stray", LO, pc, 0);
    send_to(srv, b"reply", LO, pc, 0);
    let n = sys_read(c as u64, buf.as_mut_ptr(), buf.len() as u64);
    t.ok(b"read reply", n == 5 && &buf[..5] == b"reply", n);
    t.eq(b"no stray", recv(c, &mut buf, MSG_DONTWAIT), EAGAIN);
    for f in [srv, c, x] {
        close(f);
    }
    t.done();
}

/// connect(AF_UNSPEC) disconnects: no peer, sends need an address
fn test_disconnect() {
    let mut t = T::new(b"UDP_DISCONNECT");
    let (srv, ps) = udp_lo();
    let c = udp();
    connect(c, LO, ps);
    let unspec = SockAddrIn::new(0, 0, 0);
    t.eq(b"AF_UNSPEC", hk_syscall::sys_connect(c, sa(&unspec), 16), 0);
    let mut s = sin(ANY, 0);
    let mut len = 16u32;
    let r = hk_syscall::sys_getpeername(c, &mut s as *mut SockAddrIn as *mut u8, &mut len);
    t.eq(b"getpeername", r, ENOTCONN);
    t.eq(b"send", send(c, b"x", 0), EDESTADDRREQ);
    close(srv);
    close(c);
    t.done();
}

/// Destination errors: no address (EDESTADDRREQ), port 0 (EINVAL),
/// short address (EINVAL), wrong family (EAFNOSUPPORT)
fn test_dest_errors() {
    let mut t = T::new(b"UDP_DEST_ERRORS");
    let fd = udp();
    t.eq(b"no dest", send(fd, b"x", 0), EDESTADDRREQ);
    t.eq(b"port 0", send_to(fd, b"x", LO, 0, 0), EINVAL);
    let a = sin(LO, 9);
    t.eq(
        b"short",
        hk_syscall::sys_sendto(fd, b"x".as_ptr(), 1, 0, sa(&a), 8),
        EINVAL,
    );
    let mut a6 = sin(LO, 9);
    a6.sin_family = 10;
    t.eq(
        b"AF_INET6",
        hk_syscall::sys_sendto(fd, b"x".as_ptr(), 1, 0, sa(&a6), 16),
        EAFNOSUPPORT,
    );
    t.eq(b"MSG_OOB", send_to(fd, b"x", LO, 9, MSG_OOB), EOPNOTSUPP);
    close(fd);
    t.done();
}

/// MSG_PEEK leaves the datagram queued; a short buffer truncates
/// (MSG_TRUNC in msg_flags) and MSG_TRUNC returns the real length;
/// a zero-length datagram reads as 0
fn test_peek_trunc() {
    let mut t = T::new(b"UDP_PEEK_TRUNC");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    send_to(a, b"0123456789", LO, pb, 0);
    let mut small = [0u8; 4];
    let mut ctl = [0u8; 0];
    let (n, fl, _) = recv_msg(b, &mut small, &mut ctl, MSG_PEEK);
    t.ok(
        b"peek short",
        n == 4 && fl & MSG_TRUNC != 0 && &small == b"0123",
        n,
    );
    t.eq(
        b"peek trunc len",
        recv(b, &mut small, MSG_PEEK | MSG_TRUNC),
        10,
    );
    let (n, fl, _) = recv_msg(b, &mut small, &mut ctl, 0);
    t.ok(b"read short", n == 4 && fl & MSG_TRUNC != 0, n);
    t.eq(b"consumed", recv(b, &mut small, MSG_DONTWAIT), EAGAIN);
    send_to(a, b"", LO, pb, 0);
    let mut buf = [0u8; 8];
    t.eq(b"empty datagram", recv(b, &mut buf, MSG_DONTWAIT), 0);
    close(a);
    close(b);
    t.done();
}

/// MSG_DONTWAIT and O_NONBLOCK on an empty queue: EAGAIN
fn test_dontwait() {
    let mut t = T::new(b"UDP_DONTWAIT");
    let (fd, _) = udp_lo();
    let mut buf = [0u8; 8];
    t.eq(b"DONTWAIT", recv(fd, &mut buf, MSG_DONTWAIT), EAGAIN);
    close(fd);
    t.done();
}

static mut BIG: [u8; 65600] = [0x5a; 65600];

/// The largest datagram (65507) goes through lo; one byte more EMSGSIZE
fn test_sizes() {
    let mut t = T::new(b"UDP_SIZES");
    let big = unsafe { &mut *core::ptr::addr_of_mut!(BIG) };
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    t.eq(b"65508", send_to(a, &big[..65508], LO, pb, 0), EMSGSIZE);
    t.eq(b"65507", send_to(a, &big[..65507], LO, pb, 0), 65507);
    big[..65507].fill(0);
    let n = recv(b, &mut big[..65600], 0);
    t.ok(b"recv 65507", n == 65507 && big[65506] == 0x5a, n);
    big.fill(0x5a);
    close(a);
    close(b);
    t.done();
}

/// Bind rules: duplicate EADDRINUSE; SO_REUSEADDR or SO_REUSEPORT on
/// both shares; one-sided does not; distinct local addresses coexist;
/// non-local EADDRNOTAVAIL; bind twice EINVAL; port free after close
fn test_bind_rules() {
    let mut t = T::new(b"UDP_BIND_RULES");
    let (a, p) = udp_lo();
    let b = udp();
    t.eq(b"duplicate", bind(b, LO, p), EADDRINUSE);
    t.eq(b"wildcard overlap", bind(b, ANY, p), EADDRINUSE);
    t.eq(b"other address", bind(b, [127, 0, 0, 2], p), 0);
    t.eq(b"bind twice", bind(b, LO, 0), EINVAL);
    t.eq(b"non-local", bind(udp(), [192, 0, 2, 1], 0), EADDRNOTAVAIL);
    close(a);
    close(b);
    let c = udp();
    t.eq(b"free after close", bind(c, LO, p), 0);
    let d = udp();
    setint(d, SOL_SOCKET, SO_REUSEADDR, 1);
    t.eq(b"one-sided reuse", bind(d, LO, p), EADDRINUSE);
    close(c);
    let (e, f) = (udp(), udp());
    for s in [e, f] {
        setint(s, SOL_SOCKET, SO_REUSEADDR, 1);
    }
    t.eq(b"reuseaddr e", bind(e, LO, p), 0);
    t.eq(b"reuseaddr f", bind(f, LO, p), 0);
    let (g, h) = (udp(), udp());
    for s in [g, h] {
        setint(s, SOL_SOCKET, SO_REUSEPORT, 1);
    }
    t.eq(b"reuseport g", bind(g, LO, 0), 0);
    let q = port(g);
    t.eq(b"reuseport h", bind(h, LO, q), 0);
    for s in [d, e, f, g, h] {
        close(s);
    }
    t.done();
}

/// Ephemeral ports come from ip_local_port_range (default 32768-60999):
/// bind(0) and the autobind of an unbound sendto
fn test_ephemeral() {
    let mut t = T::new(b"UDP_EPHEMERAL");
    let mut seen = [0u16; 8];
    for s in seen.iter_mut() {
        let fd = udp();
        bind(fd, LO, 0);
        *s = port(fd);
        close(fd);
    }
    t.ok(
        b"range",
        seen.iter().all(|&p| (32768..=60999).contains(&p)),
        seen[0] as i64,
    );
    let (r, pr) = udp_lo();
    let fd = udp();
    send_to(fd, b"x", LO, pr, 0);
    let p = port(fd);
    t.ok(b"autobind", (32768..=60999).contains(&p), p as i64);
    close(fd);
    close(r);
    t.done();
}

/// A full receive buffer drops datagrams (SO_RCVBUF minimum), and
/// SO_RXQ_OVFL reports the drop count on later datagrams
fn test_rcvbuf_drops() {
    let mut t = T::new(b"UDP_RCVBUF_DROPS");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    setint(b, SOL_SOCKET, SO_RCVBUF, 0);
    setint(b, SOL_SOCKET, SO_RXQ_OVFL, 1);
    let payload = [7u8; 1000];
    for _ in 0..64 {
        send_to(a, &payload, LO, pb, 0);
    }
    let mut buf = [0u8; 2000];
    let mut got = 0;
    while recv(b, &mut buf, MSG_DONTWAIT) > 0 {
        got += 1;
    }
    t.ok(b"bounded", got > 0 && got < 64, got);
    send_to(a, &payload, LO, pb, 0);
    let mut ctl = [0u8; 64];
    let (n, _, cl) = recv_msg(b, &mut buf, &mut ctl, MSG_DONTWAIT);
    let drops = cmsg_find(&ctl, cl, SOL_SOCKET, SO_RXQ_OVFL)
        .map_or(0, |d| u32::from_ne_bytes([d[0], d[1], d[2], d[3]]));
    t.ok(b"rxq_ovfl", n == 1000 && drops > 0, drops as i64);
    close(a);
    close(b);
    t.done();
}

/// IP_PKTINFO: receiving interface (lo = 1) and addresses
fn test_pktinfo() {
    let mut t = T::new(b"UDP_PKTINFO");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    t.eq(b"setsockopt", setint(b, SOL_IP, IP_PKTINFO, 1), 0);
    send_to(a, b"hi", LO, pb, 0);
    let mut buf = [0u8; 8];
    let mut ctl = [0u8; 64];
    let (n, fl, cl) = recv_msg(b, &mut buf, &mut ctl, 0);
    let info = cmsg_find(&ctl, cl, SOL_IP, IP_PKTINFO);
    t.ok(
        b"cmsg",
        n == 2 && fl & MSG_CTRUNC == 0 && info.is_some(),
        cl as i64,
    );
    if let Some(d) = info {
        let idx = i32::from_ne_bytes([d[0], d[1], d[2], d[3]]);
        t.ok(b"ifindex", idx == 1, idx as i64);
        t.ok(b"addrs", d[4..8] == LO && d[8..12] == LO, d[4] as i64);
    }
    // No room for the control message: MSG_CTRUNC
    send_to(a, b"hi", LO, pb, 0);
    let (_, fl, cl) = recv_msg(b, &mut buf, &mut ctl[..8], 0);
    t.ok(b"ctrunc", fl & MSG_CTRUNC != 0 && cl == 0, fl as i64);
    close(a);
    close(b);
    t.done();
}

/// IP_TTL / IP_TOS set on the sender arrive in IP_RECVTTL / IP_RECVTOS
fn test_ttl_tos() {
    let mut t = T::new(b"UDP_TTL_TOS");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    t.eq(b"IP_TTL", setint(a, SOL_IP, IP_TTL, 33), 0);
    t.eq(b"IP_TOS", setint(a, SOL_IP, IP_TOS, 0x10), 0);
    t.eq(b"get IP_TTL", getint(a, SOL_IP, IP_TTL).1 as i64, 33);
    t.eq(b"bad TTL", setint(a, SOL_IP, IP_TTL, 256), EINVAL);
    setint(b, SOL_IP, IP_RECVTTL, 1);
    setint(b, SOL_IP, IP_RECVTOS, 1);
    send_to(a, b"x", LO, pb, 0);
    let mut buf = [0u8; 8];
    let mut ctl = [0u8; 128];
    let (_, _, cl) = recv_msg(b, &mut buf, &mut ctl, 0);
    let ttl = cmsg_find(&ctl, cl, SOL_IP, IP_TTL)
        .map_or(-1, |d| i32::from_ne_bytes([d[0], d[1], d[2], d[3]]));
    let tos = cmsg_find(&ctl, cl, SOL_IP, IP_TOS).map_or(-1, |d| d[0] as i32);
    t.eq(b"ttl", ttl as i64, 33);
    t.eq(b"tos", tos as i64, 0x10);
    close(a);
    close(b);
    t.done();
}

/// SO_TIMESTAMP: an SCM_TIMESTAMP timeval with a plausible time
fn test_timestamp() {
    let mut t = T::new(b"UDP_TIMESTAMP");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    setint(b, SOL_SOCKET, SO_TIMESTAMP, 1);
    send_to(a, b"x", LO, pb, 0);
    let mut buf = [0u8; 8];
    let mut ctl = [0u8; 64];
    let (_, _, cl) = recv_msg(b, &mut buf, &mut ctl, 0);
    let tv = cmsg_find(&ctl, cl, SOL_SOCKET, SO_TIMESTAMP);
    t.ok(b"cmsg", tv.is_some_and(|d| d.len() == 16), cl as i64);
    if let Some(d) = tv {
        let usec = i64::from_ne_bytes(d[8..16].try_into().unwrap());
        t.ok(b"usec range", (0..1_000_000).contains(&usec), usec);
    }
    close(a);
    close(b);
    t.done();
}

/// Sending to a broadcast address needs SO_BROADCAST (EACCES); with
/// it, a wildcard-bound socket on the port receives the datagram
fn test_broadcast() {
    let mut t = T::new(b"UDP_BROADCAST");
    let r = udp();
    bind(r, ANY, 0);
    let pr = port(r);
    let s = udp();
    let bc = [127, 255, 255, 255];
    t.eq(b"no SO_BROADCAST", send_to(s, b"b", bc, pr, 0), EACCES);
    t.eq(b"SO_BROADCAST", setint(s, SOL_SOCKET, SO_BROADCAST, 1), 0);
    t.eq(b"sendto", send_to(s, b"b", bc, pr, 0), 1);
    let (n, ev) = poll1(r, 1, 2000);
    t.ok(b"received", n == 1 && ev & 1 != 0, ev as i64);
    close(r);
    close(s);
    t.done();
}

/// poll/epoll: POLLOUT always, POLLIN once a datagram is queued;
/// epoll_wait sleeps until it arrives
fn test_poll_epoll() {
    let mut t = T::new(b"UDP_POLL_EPOLL");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    let (n, ev) = poll1(b, 1 | 4, 0);
    t.ok(b"idle", n == 1 && ev == 4, ev as i64);
    let ep = sys_epoll_create1(0) as i32;
    let e = EpollEvent::new(EPOLLIN, 1);
    sys_epoll_ctl(ep, EPOLL_CTL_ADD, b, &e);
    let mut out = [EpollEvent::empty(); 1];
    t.eq(
        b"epoll empty",
        sys_epoll_wait(ep, out.as_mut_ptr(), 1, 0),
        0,
    );
    send_to(a, b"x", LO, pb, 0);
    t.eq(
        b"epoll ready",
        sys_epoll_wait(ep, out.as_mut_ptr(), 1, 2000),
        1,
    );
    let (n, ev) = poll1(b, 1, 0);
    t.ok(b"pollin", n == 1 && ev & 1 != 0, ev as i64);
    sys_close(ep as u64);
    close(a);
    close(b);
    t.done();
}

/// shutdown(SHUT_RD) on a connected socket: POLLIN|POLLRDHUP, a
/// blocking recv returns 0, a non-blocking one EAGAIN
fn test_shut_rd() {
    let mut t = T::new(b"UDP_SHUT_RD");
    let (srv, ps) = udp_lo();
    let c = udp();
    connect(c, LO, ps);
    t.eq(b"shutdown", sys_shutdown(c, SHUT_RD), 0);
    let (_, ev) = poll1(c, 1 | 0x2000, 0);
    t.ok(b"poll", ev & 1 != 0 && ev & 0x2000 != 0, ev as i64);
    let mut buf = [0u8; 4];
    t.eq(b"recv", recv(c, &mut buf, 0), 0);
    t.eq(b"recv nonblock", recv(c, &mut buf, MSG_DONTWAIT), EAGAIN);
    let u = udp();
    t.eq(b"unconnected", sys_shutdown(u, SHUT_RD), ENOTCONN);
    for f in [srv, c, u] {
        close(f);
    }
    t.done();
}

/// MSG_ERRQUEUE with nothing queued is EAGAIN; sendmsg ignores
/// SCM_RIGHTS on an inet socket and rejects unknown SOL_SOCKET messages
fn test_errqueue() {
    let mut t = T::new(b"UDP_ERRQUEUE");
    let (fd, p) = udp_lo();
    let mut buf = [0u8; 8];
    t.eq(b"errqueue", recv(fd, &mut buf, MSG_ERRQUEUE), EAGAIN);
    // SCM_RIGHTS on an inet socket
    let mut ctl = [0u8; 24];
    ctl[..8].copy_from_slice(&20u64.to_ne_bytes());
    ctl[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
    ctl[12..16].copy_from_slice(&1i32.to_ne_bytes());
    ctl[16..20].copy_from_slice(&0i32.to_ne_bytes());
    let mut dst = sin(LO, p);
    let mut iov = IoVec {
        iov_base: b"x".as_ptr(),
        iov_len: 1,
    };
    let mut m = MsgHdr::with_addr(&mut dst, &mut iov, 1);
    m.msg_control = ctl.as_mut_ptr();
    m.msg_controllen = 24;
    t.eq(b"SCM_RIGHTS", sys_sendmsg(fd, &m, 0), 1);
    ctl[12..16].copy_from_slice(&99i32.to_ne_bytes());
    t.eq(b"unknown cmsg", sys_sendmsg(fd, &m, 0), EINVAL);
    close(fd);
    t.done();
}

/// sendmsg with IP_PKTINFO ipi_spec_dst
fn send_spec(fd: i32, src: [u8; 4], dst: [u8; 4], port: u16) -> i64 {
    let mut ctl = [0u8; 32];
    ctl[..8].copy_from_slice(&28u64.to_ne_bytes());
    ctl[8..12].copy_from_slice(&SOL_IP.to_ne_bytes());
    ctl[12..16].copy_from_slice(&IP_PKTINFO.to_ne_bytes());
    ctl[20..24].copy_from_slice(&src);
    let mut to = sin(dst, port);
    let mut iov = IoVec {
        iov_base: b"s".as_ptr(),
        iov_len: 1,
    };
    let mut m = MsgHdr::with_addr(&mut to, &mut iov, 1);
    m.msg_control = ctl.as_mut_ptr();
    m.msg_controllen = 32;
    sys_sendmsg(fd, &m, 0)
}

/// Source addresses must be local (Linux ip_route_output_key_hash_rcu):
/// IP_PKTINFO spec_dst and bound addresses that were deleted
fn test_src_spoof() {
    use super::nl::{Nl, addr};
    let mut t = T::new(b"UDP_SRC_SPOOF");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    let mut buf = [0u8; 8];
    t.eq(b"foreign", send_spec(a, [1, 2, 3, 4], LO, pb), ENETUNREACH);
    t.eq(b"lbcast", send_spec(a, [255; 4], LO, pb), EINVAL);
    t.eq(b"mcast", send_spec(a, [224, 0, 0, 1], LO, pb), EINVAL);
    t.eq(b"own", send_spec(a, LO, LO, pb), 1);
    t.eq(b"own recv", recv(b, &mut buf, MSG_DONTWAIT), 1);
    // Any address of a local route (127/8) is local
    t.eq(b"127.0.0.2", send_spec(a, [127, 0, 0, 2], LO, pb), 1);
    let (n, ip, _) = recv_from(b, &mut buf, MSG_DONTWAIT);
    t.ok(b"127.0.0.2 src", n == 1 && ip == [127, 0, 0, 2], n);
    // Bound to an address that is then deleted
    let mut nl = Nl::open();
    let x = [10, 9, 9, 9];
    if let Some(nl) = nl.as_mut() {
        t.eq(
            b"add addr",
            addr(nl, true, 1, x, 32, 0x400 | 0x200) as i64,
            0,
        );
        let c = udp();
        t.eq(b"bind", bind(c, x, 0), 0);
        t.eq(b"send bound", send_to(c, b"y", LO, pb, 0), 1);
        t.eq(b"del addr", addr(nl, false, 1, x, 32, 0) as i64, 0);
        t.eq(b"send deleted", send_to(c, b"y", LO, pb, 0), ENETUNREACH);
        close(c);
    }
    close(a);
    close(b);
    t.done();
}
