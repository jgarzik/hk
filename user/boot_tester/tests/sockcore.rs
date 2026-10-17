//! Socket core tests (hk and Linux): sockfs identity (fstat S_IFSOCK,
//! /proc/self/fd readlink socket:[N]), socket() argument errors,
//! ENOTSOCK/EBADF/ESPIPE, EFAULT per socket syscall, getsockname/
//! getpeername rules, TCP port ownership (bind conflicts, privileged
//! ports, SO_REUSEPORT owner, unique four-tuples), nonblocking connect
//! with SO_ERROR.

use hk_syscall::{
    AF_INET, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_STREAM, SockAddrIn, Stat, sys_accept, sys_bind,
    sys_close, sys_connect, sys_exit, sys_fork, sys_fstat, sys_getpeername, sys_getsockname,
    sys_getsockopt, sys_listen, sys_lseek, sys_pipe, sys_readlink, sys_recvfrom, sys_recvmsg,
    sys_sendmsg, sys_sendto, sys_setresuid, sys_setsockopt, sys_socket, sys_socketpair, sys_wait4,
};

use super::sk::*;

pub fn run_tests() {
    super::helpers::println(b"=== Socket Core Tests ===");
    test_fstat();
    test_proc_fd();
    test_create_errors();
    test_not_socket();
    test_efault();
    test_names();
    test_tcp_bind_rules();
    test_privileged_port();
    test_reuseport_owner();
    test_unique_tuple();
    test_nonblock_refused();
    test_churn();
}

const S_IFMT: u32 = 0o170000;
const S_IFSOCK: u32 = 0o140000;

fn ino(fd: i32) -> (i64, u32, u64) {
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let r = sys_fstat(fd, &mut st);
    (r, st.st_mode, st.st_ino)
}

/// fstat on a socket: S_IFSOCK, distinct non-zero inode numbers
fn test_fstat() {
    let mut t = T::new(b"SOCKCORE_FSTAT");
    let (a, b) = (udp(), tcp());
    let (r, mode, ia) = ino(a);
    t.eq(b"fstat", r, 0);
    t.eq(b"S_IFSOCK", (mode & S_IFMT) as i64, S_IFSOCK as i64);
    let (_, mode_b, ib) = ino(b);
    t.eq(b"tcp S_IFSOCK", (mode_b & S_IFMT) as i64, S_IFSOCK as i64);
    t.ok(b"inode numbers", ia != 0 && ib != 0 && ia != ib, ia as i64);
    close(a);
    close(b);
    t.done();
}

/// /proc/self/fd/N of a socket reads socket:[<inode>]
fn test_proc_fd() {
    let mut t = T::new(b"SOCKCORE_PROC_FD");
    let fd = udp();
    let (_, _, i) = ino(fd);
    let mut path = *b"/proc/self/fd/\0\0\0\0\0\0";
    let mut n = 14;
    let mut digits = [0u8; 6];
    let mut k = 0;
    let mut v = fd as u32;
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        path[n] = digits[k];
        n += 1;
    }
    let mut buf = [0u8; 64];
    let r = sys_readlink(path.as_ptr(), buf.as_mut_ptr(), buf.len() as u64);
    let mut want = [0u8; 40];
    let w = fmt_socket(&mut want, i);
    t.ok(b"readlink", r == w as i64 && buf[..w] == want[..w], r);
    close(fd);
    t.done();
}

/// "socket:[ino]" into `b`, returns its length
fn fmt_socket(b: &mut [u8], ino: u64) -> usize {
    let pre = b"socket:[";
    b[..8].copy_from_slice(pre);
    let mut n = 8;
    let mut d = [0u8; 20];
    let mut k = 0;
    let mut v = ino;
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        b[n] = d[k];
        n += 1;
    }
    b[n] = b']';
    n + 1
}

/// socket() argument errors (Linux __sock_create / inet_create)
fn test_create_errors() {
    let mut t = T::new(b"SOCKCORE_CREATE_ERRORS");
    t.eq(
        b"bad flags",
        sys_socket(AF_INET, SOCK_DGRAM | 0x100000, 0),
        EINVAL,
    );
    t.eq(b"type >= SOCK_MAX", sys_socket(AF_INET, 11, 0), EINVAL);
    t.eq(
        b"family 9999",
        sys_socket(9999, SOCK_DGRAM, 0),
        EAFNOSUPPORT,
    );
    t.eq(
        b"stream/udp",
        sys_socket(AF_INET, SOCK_STREAM, 17),
        EPROTONOSUPPORT,
    );
    t.eq(
        b"dgram/tcp",
        sys_socket(AF_INET, SOCK_DGRAM, 6),
        EPROTONOSUPPORT,
    );
    t.eq(b"seqpacket", sys_socket(AF_INET, 5, 0), ESOCKTNOSUPPORT);
    let mut sv = [-1i32; 2];
    t.eq(
        b"socketpair inet",
        sys_socketpair(AF_INET, SOCK_STREAM, 0, &mut sv),
        EOPNOTSUPP,
    );
    t.eq(
        b"socketpair EFAULT",
        sys_socketpair(AF_INET, SOCK_DGRAM, 0, BAD as *mut [i32; 2]),
        EFAULT,
    );
    t.done();
}

/// Socket calls on non-sockets: ENOTSOCK / EBADF; lseek is ESPIPE
fn test_not_socket() {
    let mut t = T::new(b"SOCKCORE_ENOTSOCK");
    let mut p = [0i32; 2];
    sys_pipe(p.as_mut_ptr());
    let mut a = sin(ANY, 0);
    let mut len = 16u32;
    let ap = &mut a as *mut SockAddrIn as *mut u8;
    t.eq(
        b"getsockname pipe",
        sys_getsockname(p[0], ap, &mut len),
        ENOTSOCK,
    );
    t.eq(b"bind pipe", bind(p[0], LO, 0), ENOTSOCK);
    t.eq(
        b"getsockname badfd",
        sys_getsockname(999, ap, &mut len),
        EBADF,
    );
    let fd = udp();
    t.eq(b"lseek", sys_lseek(fd, 0, 0), ESPIPE);
    t.eq(b"listen udp", sys_listen(fd, 1), EOPNOTSUPP);
    t.eq(
        b"accept udp",
        sys_accept(fd, core::ptr::null_mut(), core::ptr::null_mut()),
        EOPNOTSUPP,
    );
    close(fd);
    close(p[0]);
    close(p[1]);
    t.done();
}

/// Bad user pointers: EFAULT from every socket call
fn test_efault() {
    let mut t = T::new(b"SOCKCORE_EFAULT");
    let (fd, port) = udp_lo();
    let b = BAD as *mut u8;
    let mut len = 16u32;
    t.eq(b"bind", sys_bind(fd, b, 16), EFAULT);
    t.eq(b"connect", sys_connect(fd, b, 16), EFAULT);
    t.eq(
        b"sendto buf",
        sys_sendto(fd, b, 8, 0, sa(&sin(LO, port)), 16),
        EFAULT,
    );
    t.eq(
        b"sendto addr",
        sys_sendto(fd, b"x".as_ptr(), 1, 0, b, 16),
        EFAULT,
    );
    t.eq(
        b"getsockname addr",
        sys_getsockname(fd, b, &mut len),
        EFAULT,
    );
    t.eq(
        b"getsockname len",
        sys_getsockname(fd, b, BAD as *mut u32),
        EFAULT,
    );
    // Unconnected: getname fails before the user length is read
    t.eq(
        b"getpeername len",
        sys_getpeername(fd, b, BAD as *mut u32),
        ENOTCONN,
    );
    let v = 1i32;
    t.eq(
        b"setsockopt",
        sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, b, 4),
        EFAULT,
    );
    let mut l4 = 4u32;
    t.eq(
        b"getsockopt val",
        sys_getsockopt(fd, SOL_SOCKET, SO_TYPE, b, &mut l4),
        EFAULT,
    );
    t.eq(
        b"getsockopt len",
        sys_getsockopt(
            fd,
            SOL_SOCKET,
            SO_TYPE,
            &v as *const i32 as *mut u8,
            BAD as *mut u32,
        ),
        EFAULT,
    );
    t.eq(b"sendmsg", sys_sendmsg(fd, BAD as *const _, 0), EFAULT);
    t.eq(b"recvmsg", sys_recvmsg(fd, BAD as *mut _, 0), EFAULT);
    // A fault copying the datagram out consumes it (Linux udp_recvmsg)
    send_to(fd, b"lost", LO, port, 0);
    // (an unmapped address inside user space: access_ok passes)
    let hole = 0x4000_0000_0000u64 as *mut u8;
    t.eq(
        b"recvfrom buf",
        sys_recvfrom(fd, hole, 8, 0, core::ptr::null_mut(), core::ptr::null_mut()),
        EFAULT,
    );
    let mut buf = [0u8; 8];
    t.eq(
        b"datagram consumed",
        recv(fd, &mut buf, MSG_DONTWAIT),
        EAGAIN,
    );
    close(fd);
    t.done();
}

/// getsockname/getpeername: unbound 0.0.0.0:0, ENOTCONN without a
/// peer, short addrlen truncates and reports the real length
fn test_names() {
    let mut t = T::new(b"SOCKCORE_NAMES");
    let fd = udp();
    let (a, p) = name(fd);
    t.ok(b"unbound name", a == ANY && p == 0, p as i64);
    let mut s = sin(ANY, 0);
    let mut len = 16u32;
    let sp = &mut s as *mut SockAddrIn as *mut u8;
    t.eq(b"no peer", sys_getpeername(fd, sp, &mut len), ENOTCONN);
    bind(fd, LO, 0);
    let mut short = [0xffu8; 16];
    let mut l = 4u32;
    let r = sys_getsockname(fd, short.as_mut_ptr(), &mut l);
    t.ok(
        b"short addrlen",
        r == 0 && l == 16 && short[4] == 0xff && short[0] == 2,
        l as i64,
    );
    close(fd);
    t.done();
}

/// TCP bind rules: duplicate EADDRINUSE; both SO_REUSEADDR share while
/// none listens; a listener blocks REUSEADDR; bind twice EINVAL;
/// non-local EADDRNOTAVAIL; the port is free again after close
fn test_tcp_bind_rules() {
    let mut t = T::new(b"SOCKCORE_TCP_BIND");
    let a = tcp();
    t.eq(b"bind", bind(a, LO, 0), 0);
    let p = port(a);
    let b = tcp();
    t.eq(b"duplicate", bind(b, LO, p), EADDRINUSE);
    t.eq(b"wildcard overlap", bind(b, ANY, p), EADDRINUSE);
    t.eq(b"bind twice", bind(a, LO, 0), EINVAL);
    t.eq(b"non-local", bind(b, [192, 0, 2, 1], 0), EADDRNOTAVAIL);
    close(a);
    close(b);
    let (c, d) = (tcp(), tcp());
    setint(c, SOL_SOCKET, SO_REUSEADDR, 1);
    setint(d, SOL_SOCKET, SO_REUSEADDR, 1);
    t.eq(b"reuse c", bind(c, LO, p), 0);
    t.eq(b"reuse d", bind(d, LO, p), 0);
    t.eq(b"listen c", sys_listen(c, 1), 0);
    t.eq(b"listen d", sys_listen(d, 1), EADDRINUSE);
    let e = tcp();
    setint(e, SOL_SOCKET, SO_REUSEADDR, 1);
    t.eq(b"reuse vs listener", bind(e, LO, p), EADDRINUSE);
    close(c);
    close(d);
    t.eq(b"free after close", bind(e, LO, p), 0);
    close(e);
    t.done();
}

/// Run `f` in a child with uid/euid 65534 (no capabilities); the
/// child's exit status (0 = pass)
fn as_nobody(f: fn() -> u64) -> i32 {
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(90);
        }
        sys_exit(f());
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

/// Ports below 1024 need CAP_NET_BIND_SERVICE (TCP and UDP)
fn test_privileged_port() {
    let mut t = T::new(b"SOCKCORE_PRIV_PORT");
    fn child() -> u64 {
        let (a, b) = (tcp(), udp());
        let r1 = bind(a, LO, 80);
        let r2 = bind(b, ANY, 81);
        let r3 = bind(a, LO, 0);
        if r1 != EACCES {
            return 1;
        }
        if r2 != EACCES {
            return 2;
        }
        if r3 != 0 {
            return 3;
        }
        0
    }
    t.eq(b"child", as_nobody(child) as i64, 0);
    t.done();
}

static mut SHARED_PORT: u16 = 0;

/// SO_REUSEPORT shares a port only between sockets of the same owner
fn test_reuseport_owner() {
    let mut t = T::new(b"SOCKCORE_REUSEPORT_UID");
    let (a, u) = (tcp(), udp());
    setint(a, SOL_SOCKET, SO_REUSEPORT, 1);
    setint(u, SOL_SOCKET, SO_REUSEPORT, 1);
    bind(a, LO, 0);
    let p = port(a);
    t.eq(b"udp bind", bind(u, LO, p), 0);
    let (b, v) = (tcp(), udp());
    setint(b, SOL_SOCKET, SO_REUSEPORT, 1);
    setint(v, SOL_SOCKET, SO_REUSEPORT, 1);
    t.eq(b"same uid tcp", bind(b, LO, p), 0);
    t.eq(b"same uid udp", bind(v, LO, p), 0);
    close(b);
    close(v);
    unsafe { SHARED_PORT = p };
    fn child() -> u64 {
        let p = unsafe { SHARED_PORT };
        let (x, y) = (tcp(), udp());
        setint(x, SOL_SOCKET, SO_REUSEPORT, 1);
        setint(y, SOL_SOCKET, SO_REUSEPORT, 1);
        if bind(x, LO, p) != EADDRINUSE {
            return 1;
        }
        if bind(y, LO, p) != EADDRINUSE {
            return 2;
        }
        0
    }
    t.eq(b"other uid", as_nobody(child) as i64, 0);
    close(a);
    close(u);
    t.done();
}

/// Two connections cannot share a four-tuple: the second connect from
/// the same (REUSEADDR) local port to the same peer is EADDRNOTAVAIL
fn test_unique_tuple() {
    let mut t = T::new(b"SOCKCORE_UNIQUE_TUPLE");
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, 4);
    let lp = port(l);
    let (a, b) = (tcp(), tcp());
    setint(a, SOL_SOCKET, SO_REUSEADDR, 1);
    setint(b, SOL_SOCKET, SO_REUSEADDR, 1);
    bind(a, LO, 0);
    let p = port(a);
    t.eq(b"bind b", bind(b, LO, p), 0);
    t.eq(b"connect a", connect(a, LO, lp), 0);
    t.eq(b"connect b", connect(b, LO, lp), EADDRNOTAVAIL);
    let c = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    t.ok(b"accept", c >= 0, c as i64);
    for f in [a, b, c, l] {
        close(f);
    }
    t.done();
}

/// Non-blocking connect to a closed port: EINPROGRESS, then poll
/// reports the failure and SO_ERROR reads (and clears) ECONNREFUSED
fn test_nonblock_refused() {
    let mut t = T::new(b"SOCKCORE_CONNECT_REFUSED");
    let probe = tcp();
    bind(probe, LO, 0);
    let dead = port(probe);
    close(probe);
    let fd = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0) as i32;
    let r = connect(fd, LO, dead);
    t.ok(b"connect", r == EINPROGRESS || r == ECONNREFUSED, r);
    if r == EINPROGRESS {
        let (pr, ev) = poll1(fd, 4 /* POLLOUT */, 5000);
        t.ok(b"poll", pr == 1 && ev & 4 != 0, ev as i64);
        t.eq(
            b"SO_ERROR",
            getint(fd, SOL_SOCKET, SO_ERROR).1 as i64,
            -ECONNREFUSED,
        );
        t.eq(
            b"SO_ERROR cleared",
            getint(fd, SOL_SOCKET, SO_ERROR).1 as i64,
            0,
        );
    }
    close(fd);
    let b = tcp();
    t.eq(b"blocking refused", connect(b, LO, dead), ECONNREFUSED);
    close(b);
    let _ = sys_close;
    t.done();
}

/// Ports and table entries are released on every close path: a fixed
/// local port is reusable after (a) a refused connect + close, (b)
/// listen + close; (c) many connect/accept/close pairs all succeed
fn test_churn() {
    let mut t = T::new(b"SOCKCORE_CHURN");
    let probe = tcp();
    bind(probe, LO, 0);
    let dead = port(probe);
    close(probe);
    let fixed = {
        let p = tcp();
        bind(p, LO, 0);
        let x = port(p);
        close(p);
        x
    };
    for i in 0..5000 {
        let fd = tcp();
        let b = bind(fd, LO, fixed);
        let c = connect(fd, LO, dead);
        close(fd);
        if !t.eq(b"refused bind", b, 0) || !t.eq(b"refused connect", c, ECONNREFUSED) {
            super::helpers::print_num(i);
            break;
        }
    }
    for _ in 0..2000 {
        let fd = tcp();
        let b = bind(fd, LO, fixed);
        let l = sys_listen(fd, 4);
        close(fd);
        if !t.eq(b"listen bind", b, 0) || !t.eq(b"listen", l, 0) {
            break;
        }
    }
    let l = tcp();
    bind(l, LO, fixed);
    sys_listen(l, 8);
    let mut buf = [0u8; 4];
    for _ in 0..1000 {
        let c = tcp();
        let r = connect(c, LO, fixed);
        let a = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
        if !t.eq(b"pair connect", r, 0) || !t.ok(b"pair accept", a >= 0, a as i64) {
            close(c);
            break;
        }
        close(a);
        let eof = recv(c, &mut buf, 0);
        close(c);
        if !t.eq(b"pair eof", eof, 0) {
            break;
        }
    }
    close(l);
    t.done();
}
