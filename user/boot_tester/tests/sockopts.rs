//! Socket option tests (hk and Linux): unknown options ENOPROTOOPT
//! (unknown levels: EOPNOTSUPP on get, like Linux),
//! length rules, SO_RCVBUF/SNDBUF doubling and limits, identity
//! options, boolean round trips, SO_LINGER, SO_RCVTIMEO encoding,
//! SO_BINDTODEVICE, IP-level options, TCP-level validation. Values are
//! compared with Linux semantics, not hk internals.

use hk_syscall::{
    sys_exit, sys_fork, sys_getsockopt, sys_listen, sys_setresuid, sys_setsockopt, sys_wait4,
};

use super::sk::*;

pub fn run_tests() {
    super::helpers::println(b"=== Socket Option Tests ===");
    test_unknown();
    test_lengths();
    test_bufs();
    test_identity();
    test_bools();
    test_linger();
    test_timeo();
    test_bindtodevice();
    test_ip_opts();
    test_tcp_opts();
}

const TCP_NODELAY: i32 = 1;
const TCP_KEEPIDLE: i32 = 4;
const TCP_KEEPCNT: i32 = 6;
const ENODEV: i64 = -19;

/// Unknown options and levels: ENOPROTOOPT for get and set
fn test_unknown() {
    let mut t = T::new(b"SOCKOPT_ENOPROTOOPT");
    let (u, c) = (udp(), tcp());
    t.eq(
        b"SOL_SOCKET set",
        setint(u, SOL_SOCKET, 999, 1),
        ENOPROTOOPT,
    );
    t.eq(b"SOL_SOCKET get", getint(u, SOL_SOCKET, 999).0, ENOPROTOOPT);
    t.eq(b"SOL_IP set", setint(u, SOL_IP, 999, 1), ENOPROTOOPT);
    t.eq(b"SOL_IP get", getint(u, SOL_IP, 999).0, ENOPROTOOPT);
    t.eq(
        b"TCP opt on udp",
        setint(u, IPPROTO_TCP, TCP_NODELAY, 1),
        ENOPROTOOPT,
    );
    t.eq(b"TCP 999", setint(c, IPPROTO_TCP, 999, 1), ENOPROTOOPT);
    t.eq(b"set level 12345", setint(c, 12345, 1, 1), ENOPROTOOPT);
    // Linux do_ip_getsockopt: unknown levels are EOPNOTSUPP on get
    t.eq(b"get level 12345", getint(c, 12345, 1).0, EOPNOTSUPP);
    t.eq(b"SOL_UDP 999", getint(u, SOL_UDP, 999).0, ENOPROTOOPT);
    t.eq(
        b"SO_SNDLOWAT set",
        setint(u, SOL_SOCKET, SO_SNDLOWAT, 1),
        ENOPROTOOPT,
    );
    t.eq(
        b"SO_SNDLOWAT get",
        getint(u, SOL_SOCKET, SO_SNDLOWAT).1 as i64,
        1,
    );
    close(u);
    close(c);
    t.done();
}

/// Short and negative lengths
fn test_lengths() {
    let mut t = T::new(b"SOCKOPT_LENGTHS");
    let fd = udp();
    let v = 1i32;
    let p = &v as *const i32 as *const u8;
    t.eq(
        b"set short",
        sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, p, 2),
        EINVAL,
    );
    t.eq(
        b"set negative",
        sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, p, u32::MAX),
        EINVAL,
    );
    let mut out = [0xffu8; 4];
    let mut len = 2u32;
    let r = sys_getsockopt(fd, SOL_SOCKET, SO_TYPE, out.as_mut_ptr(), &mut len);
    t.ok(
        b"get short",
        r == 0 && len == 2 && out[0] == 2 && out[2] == 0xff,
        len as i64,
    );
    let mut neg = u32::MAX;
    t.eq(
        b"get negative",
        sys_getsockopt(fd, SOL_SOCKET, SO_TYPE, out.as_mut_ptr(), &mut neg),
        EINVAL,
    );
    close(fd);
    t.done();
}

/// SO_RCVBUF/SO_SNDBUF are doubled, floored and capped at the sysctl
/// maximum (default 212992); *FORCE needs CAP_NET_ADMIN
fn test_bufs() {
    let mut t = T::new(b"SOCKOPT_BUFS");
    let fd = udp();
    setint(fd, SOL_SOCKET, SO_RCVBUF, 4096);
    t.eq(
        b"rcvbuf doubled",
        getint(fd, SOL_SOCKET, SO_RCVBUF).1 as i64,
        8192,
    );
    setint(fd, SOL_SOCKET, SO_SNDBUF, 20000);
    t.eq(
        b"sndbuf doubled",
        getint(fd, SOL_SOCKET, SO_SNDBUF).1 as i64,
        40000,
    );
    setint(fd, SOL_SOCKET, SO_RCVBUF, 0);
    let min = getint(fd, SOL_SOCKET, SO_RCVBUF).1;
    t.ok(b"rcvbuf floor", (2048..5000).contains(&min), min as i64);
    setint(fd, SOL_SOCKET, SO_SNDBUF, 0);
    let smin = getint(fd, SOL_SOCKET, SO_SNDBUF).1;
    t.ok(b"sndbuf floor", (2048..10000).contains(&smin), smin as i64);
    setint(fd, SOL_SOCKET, SO_RCVBUF, i32::MAX);
    t.eq(
        b"rcvbuf cap",
        getint(fd, SOL_SOCKET, SO_RCVBUF).1 as i64,
        425984,
    );
    setint(fd, SOL_SOCKET, SO_RCVBUF, -1);
    t.eq(
        b"rcvbuf negative",
        getint(fd, SOL_SOCKET, SO_RCVBUF).1 as i64,
        425984,
    );
    t.eq(
        b"force as root",
        setint(fd, SOL_SOCKET, SO_RCVBUFFORCE, 1 << 20),
        0,
    );
    t.eq(
        b"force value",
        getint(fd, SOL_SOCKET, SO_RCVBUF).1 as i64,
        2 << 20,
    );
    close(fd);
    let pid = sys_fork();
    if pid == 0 {
        sys_setresuid(65534, 65534, 65534);
        let fd = udp();
        sys_exit(
            if setint(fd, SOL_SOCKET, SO_RCVBUFFORCE, 1 << 20) == EPERM {
                0
            } else {
                1
            },
        );
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"force unprivileged", st as i64, 0);
    t.done();
}

/// SO_TYPE/DOMAIN/PROTOCOL/ACCEPTCONN/ERROR
fn test_identity() {
    let mut t = T::new(b"SOCKOPT_IDENTITY");
    let (u, c) = (udp(), tcp());
    t.eq(b"udp type", getint(u, SOL_SOCKET, SO_TYPE).1 as i64, 2);
    t.eq(b"udp domain", getint(u, SOL_SOCKET, SO_DOMAIN).1 as i64, 2);
    t.eq(
        b"udp protocol",
        getint(u, SOL_SOCKET, SO_PROTOCOL).1 as i64,
        17,
    );
    t.eq(
        b"tcp protocol",
        getint(c, SOL_SOCKET, SO_PROTOCOL).1 as i64,
        6,
    );
    t.eq(b"error", getint(u, SOL_SOCKET, SO_ERROR).1 as i64, 0);
    t.eq(
        b"acceptconn 0",
        getint(c, SOL_SOCKET, SO_ACCEPTCONN).1 as i64,
        0,
    );
    bind(c, LO, 0);
    sys_listen(c, 1);
    t.eq(
        b"acceptconn 1",
        getint(c, SOL_SOCKET, SO_ACCEPTCONN).1 as i64,
        1,
    );
    t.eq(
        b"set SO_TYPE",
        setint(u, SOL_SOCKET, SO_TYPE, 1),
        ENOPROTOOPT,
    );
    close(u);
    close(c);
    t.done();
}

/// Boolean options read back as 0/1
fn test_bools() {
    let mut t = T::new(b"SOCKOPT_BOOLS");
    let fd = udp();
    for opt in [
        SO_REUSEADDR,
        SO_REUSEPORT,
        SO_KEEPALIVE,
        SO_BROADCAST,
        SO_TIMESTAMP,
    ] {
        t.eq(b"set", setint(fd, SOL_SOCKET, opt, 5), 0);
        t.eq(b"get on", getint(fd, SOL_SOCKET, opt).1 as i64, 1);
        setint(fd, SOL_SOCKET, opt, 0);
        t.eq(b"get off", getint(fd, SOL_SOCKET, opt).1 as i64, 0);
    }
    close(fd);
    t.done();
}

/// SO_LINGER round trip; shorter than struct linger is EINVAL
fn test_linger() {
    let mut t = T::new(b"SOCKOPT_LINGER");
    let fd = tcp();
    let l = [1i32, 7];
    t.eq(
        b"set",
        sys_setsockopt(fd, SOL_SOCKET, SO_LINGER, l.as_ptr() as *const u8, 8),
        0,
    );
    let mut out = [0i32; 2];
    let mut len = 8u32;
    sys_getsockopt(
        fd,
        SOL_SOCKET,
        SO_LINGER,
        out.as_mut_ptr() as *mut u8,
        &mut len,
    );
    t.ok(b"get", out == [1, 7] && len == 8, out[1] as i64);
    t.eq(
        b"short",
        sys_setsockopt(fd, SOL_SOCKET, SO_LINGER, l.as_ptr() as *const u8, 4),
        EINVAL,
    );
    close(fd);
    t.done();
}

/// SO_RCVTIMEO as struct timeval: round trip, EDOM for bad usec,
/// EINVAL when short; 0 means no timeout
fn test_timeo() {
    let mut t = T::new(b"SOCKOPT_TIMEO");
    let fd = udp();
    let tv = [1i64, 500_000];
    let p = tv.as_ptr() as *const u8;
    t.eq(
        b"set",
        sys_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, p, 16),
        0,
    );
    let mut out = [0i64; 2];
    let mut len = 16u32;
    sys_getsockopt(
        fd,
        SOL_SOCKET,
        SO_RCVTIMEO,
        out.as_mut_ptr() as *mut u8,
        &mut len,
    );
    t.ok(b"get", out == [1, 500_000] && len == 16, out[1]);
    let bad = [0i64, 1_000_000];
    t.eq(
        b"EDOM",
        sys_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, bad.as_ptr() as *const u8, 16),
        EDOM,
    );
    t.eq(
        b"short",
        sys_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, p, 8),
        EINVAL,
    );
    let zero = [0i64, 0];
    sys_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, zero.as_ptr() as *const u8, 16);
    sys_getsockopt(
        fd,
        SOL_SOCKET,
        SO_RCVTIMEO,
        out.as_mut_ptr() as *mut u8,
        &mut len,
    );
    t.ok(b"zero", out == [0, 0], out[0]);
    close(fd);
    t.done();
}

/// SO_BINDTODEVICE by name: "lo" reads back, unknown is ENODEV
fn test_bindtodevice() {
    let mut t = T::new(b"SOCKOPT_BINDTODEVICE");
    let fd = udp();
    t.eq(
        b"lo",
        sys_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, b"lo\0".as_ptr(), 3),
        0,
    );
    let mut out = [0u8; 16];
    let mut len = 16u32;
    let r = sys_getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, out.as_mut_ptr(), &mut len);
    t.ok(
        b"get",
        r == 0 && &out[..3] == b"lo\0" && len == 3,
        len as i64,
    );
    let fd2 = udp();
    t.eq(
        b"unknown",
        sys_setsockopt(fd2, SOL_SOCKET, SO_BINDTODEVICE, b"nosuch0\0".as_ptr(), 8),
        ENODEV,
    );
    close(fd);
    close(fd2);
    t.done();
}

/// IP options: TTL default 64, byte-sized values, TOS/PKTINFO round trip
fn test_ip_opts() {
    let mut t = T::new(b"SOCKOPT_IP");
    let fd = udp();
    t.eq(b"ttl default", getint(fd, SOL_IP, IP_TTL).1 as i64, 64);
    let b7 = 7u8;
    t.eq(b"ttl byte", sys_setsockopt(fd, SOL_IP, IP_TTL, &b7, 1), 0);
    t.eq(b"ttl byte get", getint(fd, SOL_IP, IP_TTL).1 as i64, 7);
    t.eq(b"ttl -1", setint(fd, SOL_IP, IP_TTL, -1), 0);
    t.eq(b"ttl reset", getint(fd, SOL_IP, IP_TTL).1 as i64, 64);
    t.eq(b"ttl 0", setint(fd, SOL_IP, IP_TTL, 0), EINVAL);
    setint(fd, SOL_IP, IP_TOS, 0x28);
    t.eq(b"tos", getint(fd, SOL_IP, IP_TOS).1 as i64, 0x28);
    setint(fd, SOL_IP, IP_PKTINFO, 1);
    t.eq(b"pktinfo", getint(fd, SOL_IP, IP_PKTINFO).1 as i64, 1);
    setint(fd, SOL_IP, IP_RECVERR, 1);
    t.eq(b"recverr", getint(fd, SOL_IP, IP_RECVERR).1 as i64, 1);
    close(fd);
    t.done();
}

/// TCP-level options validate their ranges
fn test_tcp_opts() {
    let mut t = T::new(b"SOCKOPT_TCP");
    let fd = tcp();
    t.eq(b"nodelay", setint(fd, IPPROTO_TCP, TCP_NODELAY, 9), 0);
    t.eq(
        b"nodelay get",
        getint(fd, IPPROTO_TCP, TCP_NODELAY).1 as i64,
        1,
    );
    t.eq(
        b"keepidle 0",
        setint(fd, IPPROTO_TCP, TCP_KEEPIDLE, 0),
        EINVAL,
    );
    t.eq(b"keepidle", setint(fd, IPPROTO_TCP, TCP_KEEPIDLE, 30), 0);
    t.eq(
        b"keepidle get",
        getint(fd, IPPROTO_TCP, TCP_KEEPIDLE).1 as i64,
        30,
    );
    t.eq(
        b"keepcnt 128",
        setint(fd, IPPROTO_TCP, TCP_KEEPCNT, 128),
        EINVAL,
    );
    close(fd);
    t.done();
}
