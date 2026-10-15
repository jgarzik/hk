//! AF_UNIX tests (hk and Linux): filesystem and abstract names,
//! autobind, name lengths, permissions, stream/datagram/seqpacket data
//! and EOF rules, socketpair, backlog, buffer accounting, SCM_RIGHTS
//! (MSG_CTRUNC, MSG_CMSG_CLOEXEC), SO_PEERCRED, SCM_CREDENTIALS checks,
//! EPIPE/SIGPIPE, poll states, /proc/net/unix.

use hk_syscall::{
    sys_accept, sys_bind, sys_chmod, sys_connect, sys_exit, sys_fcntl, sys_fork,
    sys_getpeername, sys_getpid, sys_getsockname, sys_ioctl, sys_listen, sys_mknod, sys_open,
    sys_pipe, sys_read, sys_recvfrom, sys_rt_sigaction, sys_sendmsg, sys_sendto, sys_setresgid,
    sys_setresuid, sys_shutdown, sys_socket, sys_socketpair, sys_stat, sys_umask,
    sys_unlink, sys_wait4, sys_write, IoVec, MsgHdr, Stat, AF_UNIX, FIONREAD, O_RDONLY, SHUT_RD,
    SHUT_WR, SIGPIPE, SIG_DFL, SIG_IGN, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_STREAM,
};

use super::sk::*;

const SOCK_SEQPACKET: i32 = 5;
const SO_PASSCRED: i32 = 16;
const SO_PEERCRED: i32 = 17;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
const SIOCOUTQ: u64 = 0x5411;
const F_GETFD: i32 = 1;
const S_IFMT: u32 = 0o170000;
const S_IFSOCK: u32 = 0o140000;
const POLLIN: i16 = 0x1;
const POLLOUT: i16 = 0x4;
const POLLHUP: i16 = 0x10;
const POLLRDHUP: i16 = 0x2000;

const ENOENT: i64 = -2;
const ENXIO: i64 = -6;
const EPROTOTYPE: i64 = -91;
const ECONNRESET: i64 = -104;
const ENOTCONN_: i64 = -107;
const USER: u32 = 2000;

pub fn run_tests() {
    super::helpers::println(b"=== AF_UNIX Tests ===");
    test_create();
    test_fs_bind();
    test_fs_connect_errors();
    test_perm();
    test_abstract();
    test_autobind();
    test_names();
    test_socketpair();
    test_stream_data();
    test_stream_coalesce();
    test_peek_waitall();
    test_shutdown();
    test_backlog();
    test_sndbuf();
    test_dgram();
    test_dgram_queue();
    test_seqpacket();
    test_epipe();
    test_reset();
    test_scm_rights();
    test_ctrunc();
    test_inflight();
    test_peercred();
    test_scm_creds();
    test_poll();
    test_proc();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A struct sockaddr_un and the length to pass
struct Sun {
    b: [u8; 110],
    len: u32,
}

/// Filesystem name: family + path + NUL
fn sun_path(p: &[u8]) -> Sun {
    let mut b = [0u8; 110];
    b[..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    b[2..2 + p.len()].copy_from_slice(p);
    Sun { b, len: (2 + p.len() + 1) as u32 }
}

/// Abstract name: family + NUL + name (no terminator)
fn sun_abs(p: &[u8]) -> Sun {
    let mut b = [0u8; 110];
    b[..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    b[3..3 + p.len()].copy_from_slice(p);
    Sun { b, len: (3 + p.len()) as u32 }
}

fn ux(t: i32) -> i32 {
    sys_socket(AF_UNIX, t, 0) as i32
}

fn ubind(fd: i32, a: &Sun) -> i64 {
    sys_bind(fd, a.b.as_ptr(), a.len)
}

fn uconnect(fd: i32, a: &Sun) -> i64 {
    sys_connect(fd, a.b.as_ptr(), a.len)
}

/// getsockname / getpeername: (return, length, bytes)
fn uname(fd: i32, peer: bool) -> (i64, u32, [u8; 128]) {
    let mut b = [0xffu8; 128];
    let mut len = 128u32;
    let r = if peer {
        sys_getpeername(fd, b.as_mut_ptr(), &mut len)
    } else {
        sys_getsockname(fd, b.as_mut_ptr(), &mut len)
    };
    (r, len, b)
}

fn pair(t: i32) -> (i32, i32) {
    let mut sv = [-1i32; 2];
    sys_socketpair(AF_UNIX, t, 0, &mut sv);
    (sv[0], sv[1])
}

/// NUL-terminated copy of a path
fn cpath(p: &[u8]) -> [u8; 128] {
    let mut b = [0u8; 128];
    b[..p.len()].copy_from_slice(p);
    b
}

fn unlink(p: &[u8]) {
    sys_unlink(cpath(p).as_ptr());
}

fn mode_of(p: &[u8]) -> (i64, u32) {
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let r = sys_stat(cpath(p).as_ptr(), &mut st);
    (r, st.st_mode)
}

/// A listening socket of type `t` bound to `a`
fn listener(t: i32, a: &Sun, backlog: i32) -> i32 {
    let l = ux(t);
    ubind(l, a);
    sys_listen(l, backlog);
    l
}

/// sendmsg with one control message (level, type, payload)
fn send_cmsg(fd: i32, data: &[u8], level: i32, ty: i32, payload: &[u8], flags: i32) -> i64 {
    let mut ctl = [0u8; 1100];
    let clen = 16 + payload.len();
    ctl[..8].copy_from_slice(&(clen as u64).to_ne_bytes());
    ctl[8..12].copy_from_slice(&level.to_ne_bytes());
    ctl[12..16].copy_from_slice(&ty.to_ne_bytes());
    ctl[16..clen].copy_from_slice(payload);
    let mut iov = IoVec { iov_base: data.as_ptr(), iov_len: data.len() };
    let mut m = MsgHdr::new(&mut iov, 1);
    m.msg_control = ctl.as_mut_ptr();
    m.msg_controllen = (clen + 7) & !7;
    sys_sendmsg(fd, &m, flags)
}

/// Send `data` with SCM_RIGHTS `fds`
fn send_fds(fd: i32, data: &[u8], fds: &[i32]) -> i64 {
    let mut p = [0u8; 1024];
    for (i, f) in fds.iter().enumerate() {
        p[i * 4..i * 4 + 4].copy_from_slice(&f.to_ne_bytes());
    }
    send_cmsg(fd, data, SOL_SOCKET, SCM_RIGHTS, &p[..fds.len() * 4], MSG_NOSIGNAL)
}

/// First fd of an SCM_RIGHTS message in `ctl[..len]` (-1 if none) and
/// the number of fds
fn got_fds(ctl: &[u8], len: usize) -> (i32, usize) {
    match cmsg_find(ctl, len, SOL_SOCKET, SCM_RIGHTS) {
        Some(d) if d.len() >= 4 => (i32::from_ne_bytes(d[..4].try_into().unwrap()), d.len() / 4),
        _ => (-1, 0),
    }
}

fn ioctl_int(fd: i32, req: u64) -> (i64, i32) {
    let mut v: i32 = -1;
    let r = sys_ioctl(fd, req, &mut v as *mut i32 as u64);
    (r, v)
}

fn wait_status(pid: i64) -> i32 {
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

#[repr(C)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

fn sigpipe(handler: u64) {
    let a = SigAction { handler, flags: 0, restorer: 0, mask: 0 };
    sys_rt_sigaction(SIGPIPE, &a as *const SigAction as u64, 0, 8);
}

/// ucred of SO_PEERCRED: (return, pid, uid, gid)
fn peercred(fd: i32) -> (i64, i32, u32, u32) {
    let mut b = [0u8; 12];
    let mut len = 12u32;
    let r = hk_syscall::sys_getsockopt(fd, SOL_SOCKET, SO_PEERCRED, b.as_mut_ptr(), &mut len);
    let w = |o: usize| u32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
    (r, w(0) as i32, w(4), w(8))
}

fn ucred(pid: i32, uid: u32, gid: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[..4].copy_from_slice(&pid.to_ne_bytes());
    b[4..8].copy_from_slice(&uid.to_ne_bytes());
    b[8..].copy_from_slice(&gid.to_ne_bytes());
    b
}

fn msleep(ms: u64) {
    let ts = hk_syscall::Timespec { tv_sec: 0, tv_nsec: (ms * 1_000_000) as i64 };
    hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// socket(): types, SOCK_RAW is SOCK_DGRAM, protocol and type errors
fn test_create() {
    let mut t = T::new(b"UNIX_CREATE");
    for ty in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET] {
        let fd = ux(ty);
        t.ok(b"socket", fd >= 0, fd as i64);
        t.eq(b"SO_TYPE", getint(fd, SOL_SOCKET, SO_TYPE).1 as i64, ty as i64);
        t.eq(b"SO_DOMAIN", getint(fd, SOL_SOCKET, SO_DOMAIN).1 as i64, AF_UNIX as i64);
        close(fd);
    }
    let raw = ux(3);
    t.eq(b"raw is dgram", getint(raw, SOL_SOCKET, SO_TYPE).1 as i64, SOCK_DGRAM as i64);
    close(raw);
    t.eq(b"protocol 1", { let f = sys_socket(AF_UNIX, SOCK_STREAM, 1); close(f as i32); f.min(0) }, 0);
    t.eq(b"protocol 2", sys_socket(AF_UNIX, SOCK_STREAM, 2), EPROTONOSUPPORT);
    t.eq(b"type RDM", sys_socket(AF_UNIX, 4, 0), ESOCKTNOSUPPORT);
    t.done();
}

/// Bind a path: S_IFSOCK inode with the umask applied, EADDRINUSE for an
/// existing name, EINVAL when already bound (no file left behind), the
/// name survives unlink, open is ENXIO
fn test_fs_bind() {
    let mut t = T::new(b"UNIX_FS_BIND");
    let p: &[u8] = b"/tmp/ux_bind";
    let p2: &[u8] = b"/tmp/ux_bind2";
    unlink(p);
    unlink(p2);
    let old = sys_umask(0o022);
    let a = sun_path(p);
    let s = ux(SOCK_STREAM);
    t.eq(b"bind", ubind(s, &a), 0);
    let (r, mode) = mode_of(p);
    t.eq(b"stat", r, 0);
    t.eq(b"S_IFSOCK", (mode & S_IFMT) as i64, S_IFSOCK as i64);
    t.eq(b"mode 0755", (mode & 0o777) as i64, 0o755);
    t.eq(b"open ENXIO", sys_open(cpath(p).as_ptr(), O_RDONLY, 0), ENXIO);
    let s2 = ux(SOCK_STREAM);
    t.eq(b"EADDRINUSE", ubind(s2, &a), EADDRINUSE);
    t.eq(b"rebind EINVAL", ubind(s, &sun_path(p2)), EINVAL);
    t.eq(b"no file left", mode_of(p2).0, ENOENT);
    t.eq(b"rebind same EADDRINUSE", ubind(s, &a), EADDRINUSE);
    let (r, len, b) = uname(s, false);
    t.eq(b"getsockname", r, 0);
    t.eq(b"name len", len as i64, (2 + p.len() + 1) as i64);
    t.ok(b"name bytes", &b[2..2 + p.len()] == p && b[2 + p.len()] == 0, b[2] as i64);
    sys_listen(s, 5);
    let c = ux(SOCK_STREAM);
    t.eq(b"connect", uconnect(c, &a), 0);
    let acc = sys_accept(s, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    t.ok(b"accept", acc >= 0, acc as i64);
    t.eq(b"peer of client", uname(c, true).1 as i64, a.len as i64);
    t.eq(b"client unnamed", uname(c, false).1 as i64, 2);
    t.eq(b"peer of accepted", uname(acc, true).1 as i64, 2);
    t.eq(b"accepted name", uname(acc, false).1 as i64, a.len as i64);
    // Unlinking the path keeps the binding but nobody can reach it
    unlink(p);
    t.eq(b"name after unlink", uname(s, false).1 as i64, a.len as i64);
    let c2 = ux(SOCK_STREAM);
    t.eq(b"connect after unlink", uconnect(c2, &a), ENOENT);
    // A long path: 107 characters
    let mut long = [b'a'; 107];
    long[..5].copy_from_slice(b"/tmp/");
    unlink(&long);
    let s3 = ux(SOCK_DGRAM);
    t.eq(b"bind long", ubind(s3, &sun_path(&long)), 0);
    t.eq(b"long len", uname(s3, false).1 as i64, 110);
    unlink(&long);
    // Bytes after the terminator do not count
    let mut a4 = sun_path(b"/tmp/ux_bind4");
    unlink(b"/tmp/ux_bind4");
    a4.b[20] = b'x';
    a4.len = 110;
    let s4 = ux(SOCK_DGRAM);
    t.eq(b"bind full len", ubind(s4, &a4), 0);
    t.eq(b"len to NUL", uname(s4, false).1 as i64, 2 + 13 + 1);
    unlink(b"/tmp/ux_bind4");
    sys_umask(old as u32);
    for f in [s, s2, c, acc, c2, s3, s4] {
        close(f);
    }
    t.done();
}

/// connect(): ECONNREFUSED for a non-socket, a mknod'ed socket and a
/// non-listening one; EPROTOTYPE across types; ENOENT
fn test_fs_connect_errors() {
    let mut t = T::new(b"UNIX_FS_CONNECT_ERRORS");
    let reg: &[u8] = b"/tmp/ux_reg";
    let nod: &[u8] = b"/tmp/ux_nod";
    let dg: &[u8] = b"/tmp/ux_dg";
    let idle: &[u8] = b"/tmp/ux_idle";
    for p in [reg, nod, dg, idle] {
        unlink(p);
    }
    let f = sys_open(cpath(reg).as_ptr(), 0o101, 0o644);
    close(f as i32);
    sys_mknod(cpath(nod).as_ptr(), S_IFSOCK | 0o666, 0);
    t.eq(b"mknod S_IFSOCK", (mode_of(nod).1 & S_IFMT) as i64, S_IFSOCK as i64);
    let d = ux(SOCK_DGRAM);
    ubind(d, &sun_path(dg));
    let i = ux(SOCK_STREAM);
    ubind(i, &sun_path(idle));
    let c = ux(SOCK_STREAM);
    t.eq(b"regular file", uconnect(c, &sun_path(reg)), ECONNREFUSED);
    t.eq(b"mknod socket", uconnect(c, &sun_path(nod)), ECONNREFUSED);
    t.eq(b"not listening", uconnect(c, &sun_path(idle)), ECONNREFUSED);
    t.eq(b"wrong type", uconnect(c, &sun_path(dg)), EPROTOTYPE);
    t.eq(b"missing", uconnect(c, &sun_path(b"/tmp/ux_none")), ENOENT);
    t.eq(b"short addr", sys_connect(c, sun_path(dg).b.as_ptr(), 2), EINVAL);
    t.eq(b"listen dgram", sys_listen(d, 1), EOPNOTSUPP);
    t.eq(b"listen unbound", sys_listen(c, 1), EINVAL);
    t.eq(b"accept unlistened", sys_accept(i, core::ptr::null_mut(), core::ptr::null_mut()), EINVAL);
    for p in [reg, nod, dg, idle] {
        unlink(p);
    }
    for f in [d, i, c] {
        close(f);
    }
    t.done();
}

/// Connecting needs write permission on the socket inode; binding needs
/// write permission on the directory
fn test_perm() {
    let mut t = T::new(b"UNIX_PERM");
    let p: &[u8] = b"/tmp/ux_perm";
    unlink(p);
    let old = sys_umask(0o077);
    let a = sun_path(p);
    let l = listener(SOCK_STREAM, &a, 5);
    t.eq(b"mode 0700", (mode_of(p).1 & 0o777) as i64, 0o700);
    sys_umask(old as u32);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(USER, USER, USER) != 0 || sys_setresuid(USER, USER, USER) != 0 {
            sys_exit(90);
        }
        let c = ux(SOCK_STREAM);
        if uconnect(c, &a) != EACCES {
            sys_exit(1);
        }
        let b = ux(SOCK_STREAM);
        if ubind(b, &sun_path(b"/proc/ux_perm")) == 0 {
            sys_exit(2);
        }
        sys_exit(0);
    }
    t.eq(b"non-root refused", wait_status(pid) as i64, 0);
    sys_chmod(cpath(p).as_ptr(), 0o777);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(USER, USER, USER) != 0 || sys_setresuid(USER, USER, USER) != 0 {
            sys_exit(90);
        }
        let c = ux(SOCK_STREAM);
        sys_exit(if uconnect(c, &a) == 0 { 0 } else { 1 });
    }
    t.eq(b"after chmod", wait_status(pid) as i64, 0);
    unlink(p);
    close(l);
    t.done();
}

/// Abstract names: per type, EADDRINUSE within a type, never in the
/// filesystem, reachable by connect
fn test_abstract() {
    let mut t = T::new(b"UNIX_ABSTRACT");
    let a = sun_abs(b"hk-ux-abs");
    let l = ux(SOCK_STREAM);
    t.eq(b"bind", ubind(l, &a), 0);
    let (_, len, b) = uname(l, false);
    t.eq(b"name len", len as i64, a.len as i64);
    t.ok(b"name bytes", b[2] == 0 && &b[3..12] == b"hk-ux-abs", b[3] as i64);
    let l2 = ux(SOCK_STREAM);
    t.eq(b"EADDRINUSE", ubind(l2, &a), EADDRINUSE);
    let d = ux(SOCK_DGRAM);
    t.eq(b"other type ok", ubind(d, &a), 0);
    sys_listen(l, 5);
    let c = ux(SOCK_STREAM);
    t.eq(b"connect", uconnect(c, &a), 0);
    let s = ux(SOCK_SEQPACKET);
    t.eq(b"seqpacket refused", uconnect(s, &a), ECONNREFUSED);
    // A shorter name is a different name
    let c2 = ux(SOCK_STREAM);
    t.eq(b"prefix refused", uconnect(c2, &sun_abs(b"hk-ux-ab")), ECONNREFUSED);
    close(l);
    let l3 = ux(SOCK_STREAM);
    t.eq(b"free after close", ubind(l3, &a), 0);
    for f in [l2, d, c, s, c2, l3] {
        close(f);
    }
    t.done();
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
}

/// Autobind: bind with just the family, or connect/send with
/// SO_PASSCRED: "\0" + 5 hex digits (length 8)
fn test_autobind() {
    let mut t = T::new(b"UNIX_AUTOBIND");
    let s = ux(SOCK_DGRAM);
    let fam = (AF_UNIX as u16).to_ne_bytes();
    t.eq(b"bind family only", sys_bind(s, fam.as_ptr(), 2), 0);
    let (_, len, b) = uname(s, false);
    t.eq(b"len 8", len as i64, 8);
    t.ok(b"format", b[2] == 0 && b[3..8].iter().all(|&c| is_hex(c)), b[3] as i64);
    t.eq(b"bound again", ubind(s, &sun_abs(b"hk-ux-auto")), EINVAL);
    t.eq(b"autobind again", sys_bind(s, fam.as_ptr(), 2), 0);
    let srv = ux(SOCK_DGRAM);
    let sa = sun_abs(b"hk-ux-auto-srv");
    ubind(srv, &sa);
    let c = ux(SOCK_DGRAM);
    setint(c, SOL_SOCKET, SO_PASSCRED, 1);
    t.eq(b"connect", uconnect(c, &sa), 0);
    t.eq(b"passcred autobind", uname(c, false).1 as i64, 8);
    let c2 = ux(SOCK_DGRAM);
    t.eq(b"plain connect", uconnect(c2, &sa), 0);
    t.eq(b"no autobind", uname(c2, false).1 as i64, 2);
    // The receiver sees the autobound sender's name
    send(c, b"hi", 0);
    let mut buf = [0u8; 8];
    let mut from = [0u8; 32];
    let mut flen = 32u32;
    let r = sys_recvfrom(srv, buf.as_mut_ptr(), 8, 0, from.as_mut_ptr(), &mut flen);
    t.eq(b"recv", r, 2);
    t.eq(b"sender name", flen as i64, 8);
    send(c2, b"hi", 0);
    flen = 32;
    sys_recvfrom(srv, buf.as_mut_ptr(), 8, 0, from.as_mut_ptr(), &mut flen);
    t.eq(b"unnamed sender", flen as i64, 0);
    for f in [s, srv, c, c2] {
        close(f);
    }
    t.done();
}

/// Name rules: unbound sockets are just the family (length 2),
/// ENOTCONN without a peer, bad lengths and families
fn test_names() {
    let mut t = T::new(b"UNIX_NAMES");
    let s = ux(SOCK_STREAM);
    let (r, len, b) = uname(s, false);
    t.eq(b"unbound", r, 0);
    t.eq(b"len 2", len as i64, 2);
    t.eq(b"family", u16::from_ne_bytes([b[0], b[1]]) as i64, AF_UNIX as i64);
    t.eq(b"no peer", uname(s, true).0, ENOTCONN_);
    let a = sun_abs(b"hk-ux-names");
    t.eq(b"addrlen 1", sys_bind(s, a.b.as_ptr(), 1), EINVAL);
    t.eq(b"addrlen 111", sys_bind(s, a.b.as_ptr(), 111), EINVAL);
    let mut bad = sun_abs(b"hk-ux-names");
    bad.b[0] = 2;
    t.eq(b"AF_INET family", ubind(s, &bad), EINVAL);
    let (x, y) = pair(SOCK_STREAM);
    t.eq(b"pair peer len", uname(x, true).1 as i64, 2);
    t.eq(b"pair name len", uname(y, false).1 as i64, 2);
    for f in [s, x, y] {
        close(f);
    }
    t.done();
}

/// socketpair of every type: both directions, flags on both ends
fn test_socketpair() {
    let mut t = T::new(b"UNIX_SOCKETPAIR");
    for ty in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET] {
        let mut sv = [-1i32; 2];
        let r = sys_socketpair(AF_UNIX, ty | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, &mut sv);
        t.eq(b"socketpair", r, 0);
        t.eq(b"a->b", send(sv[0], b"ping", 0), 4);
        let mut b = [0u8; 8];
        t.eq(b"b recv", recv(sv[1], &mut b, 0), 4);
        t.eq(b"b->a", send(sv[1], b"pong!", 0), 5);
        t.eq(b"a recv", recv(sv[0], &mut b, 0), 5);
        t.eq(b"nonblock", recv(sv[0], &mut b, 0), EAGAIN);
        t.eq(b"cloexec", sys_fcntl(sv[1], F_GETFD, 0), 1);
        close(sv[0]);
        close(sv[1]);
    }
    let mut sv = [-1i32; 2];
    t.eq(b"protocol 2", sys_socketpair(AF_UNIX, SOCK_STREAM, 2, &mut sv), EPROTONOSUPPORT);
    t.done();
}

/// 1 MiB through a stream from a child, verified byte by byte
fn test_stream_data() {
    let mut t = T::new(b"UNIX_STREAM_1MB");
    const TOTAL: usize = 1 << 20;
    let (a, b) = pair(SOCK_STREAM);
    let pid = sys_fork();
    if pid == 0 {
        close(a);
        let mut buf = [0u8; 8192];
        let mut off = 0;
        while off < TOTAL {
            for (i, c) in buf.iter_mut().enumerate() {
                *c = ((off + i) % 251) as u8;
            }
            let n = send(b, &buf, 0);
            if n <= 0 {
                sys_exit(1);
            }
            off += n as usize;
        }
        sys_exit(0);
    }
    close(b);
    let mut buf = [0u8; 10000];
    let mut got = 0;
    let mut bad = false;
    loop {
        let n = recv(a, &mut buf, 0);
        if n <= 0 {
            break;
        }
        for (i, &c) in buf[..n as usize].iter().enumerate() {
            if c != ((got + i) % 251) as u8 {
                bad = true;
            }
        }
        got += n as usize;
    }
    t.eq(b"total", got as i64, TOTAL as i64);
    t.ok(b"content", !bad, 0);
    t.eq(b"writer", wait_status(pid) as i64, 0);
    close(a);
    t.done();
}

/// Reads join messages, but end after one that carried files
fn test_stream_coalesce() {
    let mut t = T::new(b"UNIX_STREAM_COALESCE");
    let (a, b) = pair(SOCK_STREAM);
    send(a, b"x", 0);
    send(a, b"yy", 0);
    send(a, b"zzz", 0);
    let mut buf = [0u8; 64];
    t.eq(b"joined", recv(b, &mut buf, 0), 6);
    let mut p = [0i32; 2];
    sys_pipe(p.as_mut_ptr());
    send(a, b"aaa", 0);
    t.eq(b"send fds", send_fds(a, b"bbb", &[p[0]]), 3);
    send(a, b"ccc", 0);
    let mut ctl = [0u8; 64];
    let (r, fl, clen) = recv_msg(b, &mut buf, &mut ctl, 0);
    t.eq(b"up to the files", r, 6);
    t.ok(b"data", &buf[..6] == b"aaabbb", buf[0] as i64);
    let (fd, n) = got_fds(&ctl, clen);
    t.ok(b"fd", fd >= 0 && n == 1 && fl & MSG_CTRUNC == 0, fl as i64);
    let (r, _, clen) = recv_msg(b, &mut buf, &mut ctl, 0);
    t.eq(b"rest", r, 3);
    t.eq(b"no more fds", clen as i64, 0);
    for f in [a, b, p[0], p[1], fd] {
        close(f);
    }
    t.done();
}

/// MSG_PEEK leaves data, MSG_WAITALL collects across writes,
/// MSG_DONTWAIT, FIONREAD
fn test_peek_waitall() {
    let mut t = T::new(b"UNIX_PEEK_WAITALL");
    let (a, b) = pair(SOCK_STREAM);
    send(a, b"hello", 0);
    let mut buf = [0u8; 16];
    t.eq(b"FIONREAD", ioctl_int(b, FIONREAD as u64).1 as i64, 5);
    t.eq(b"peek", recv(b, &mut buf, MSG_PEEK), 5);
    t.eq(b"still there", recv(b, &mut buf, 0), 5);
    t.eq(b"DONTWAIT", recv(b, &mut buf, MSG_DONTWAIT), EAGAIN);
    let pid = sys_fork();
    if pid == 0 {
        for part in [b"abc", b"def", b"ghi"] {
            msleep(30);
            send(a, part, 0);
        }
        sys_exit(0);
    }
    t.eq(b"WAITALL", recv(b, &mut buf[..9], MSG_WAITALL), 9);
    t.ok(b"WAITALL data", &buf[..9] == b"abcdefghi", buf[0] as i64);
    wait_status(pid);
    close(a);
    close(b);
    t.done();
}

/// shutdown: SHUT_WR is EOF for the peer and EPIPE for us; the other
/// direction still works; bad how is EINVAL
fn test_shutdown() {
    let mut t = T::new(b"UNIX_SHUTDOWN");
    let (a, b) = pair(SOCK_STREAM);
    t.eq(b"SHUT_WR", sys_shutdown(a, SHUT_WR), 0);
    let mut buf = [0u8; 8];
    t.eq(b"peer EOF", recv(b, &mut buf, 0), 0);
    t.eq(b"EPIPE", send(a, b"x", MSG_NOSIGNAL), EPIPE);
    t.eq(b"reverse send", send(b, b"ok", 0), 2);
    t.eq(b"reverse recv", recv(a, &mut buf, 0), 2);
    t.eq(b"SHUT_RD", sys_shutdown(b, SHUT_RD), 0);
    t.eq(b"after SHUT_RD", recv(b, &mut buf, MSG_DONTWAIT), 0);
    t.eq(b"bad how", sys_shutdown(a, 7), EINVAL);
    let s = ux(SOCK_STREAM);
    t.eq(b"unconnected", sys_shutdown(s, SHUT_WR), 0);
    for f in [a, b, s] {
        close(f);
    }
    t.done();
}

/// Backlog: a full queue is EAGAIN for non-blocking connects; accept
/// makes room; EISCONN
fn test_backlog() {
    let mut t = T::new(b"UNIX_BACKLOG");
    let a = sun_abs(b"hk-ux-backlog");
    let l = listener(SOCK_STREAM, &a, 0);
    let c1 = ux(SOCK_STREAM | SOCK_NONBLOCK);
    t.eq(b"first", uconnect(c1, &a), 0);
    let c2 = ux(SOCK_STREAM | SOCK_NONBLOCK);
    t.eq(b"full EAGAIN", uconnect(c2, &a), EAGAIN);
    let s1 = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    t.ok(b"accept", s1 >= 0, s1 as i64);
    t.eq(b"EISCONN", uconnect(c1, &a), EISCONN);
    // A listener connecting (to itself) is EINVAL, never a self-deadlock
    t.eq(b"listener connect", uconnect(l, &a), EINVAL);
    t.eq(b"after accept", uconnect(c2, &a), 0);
    // Data written before accept is there after it
    t.eq(b"early write", send(c2, b"early", 0), 5);
    let s2 = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    let mut buf = [0u8; 8];
    t.eq(b"early read", recv(s2, &mut buf, 0), 5);
    let ln = ux(SOCK_STREAM | SOCK_NONBLOCK);
    ubind(ln, &sun_abs(b"hk-ux-backlog2"));
    sys_listen(ln, 4);
    t.eq(b"accept EAGAIN", sys_accept(ln, core::ptr::null_mut(), core::ptr::null_mut()), EAGAIN);
    for f in [l, c1, c2, s1, s2, ln] {
        close(f);
    }
    t.done();
}

/// SO_SNDBUF bounds what a writer has queued; SIOCOUTQ, FIONREAD;
/// draining makes the writer writable again
fn test_sndbuf() {
    let mut t = T::new(b"UNIX_SNDBUF");
    let (a, b) = pair(SOCK_STREAM | SOCK_NONBLOCK);
    setint(a, SOL_SOCKET, SO_SNDBUF, 4096);
    let chunk = [7u8; 1000];
    let mut total = 0i64;
    let mut last = 0;
    for _ in 0..1000 {
        last = send(a, &chunk, 0);
        if last < 0 {
            break;
        }
        total += last;
    }
    t.eq(b"EAGAIN", last, EAGAIN);
    t.ok(b"bounded", total > 0 && total <= 16384, total);
    t.ok(b"SIOCOUTQ", ioctl_int(a, SIOCOUTQ).1 as i64 >= total, ioctl_int(a, SIOCOUTQ).1 as i64);
    t.eq(b"FIONREAD", ioctl_int(b, FIONREAD as u64).1 as i64, total);
    t.eq(b"not writable", poll1(a, POLLOUT, 0).0, 0);
    let mut buf = [0u8; 2048];
    while recv(b, &mut buf, 0) > 0 {}
    t.eq(b"SIOCOUTQ drained", ioctl_int(a, SIOCOUTQ).1 as i64, 0);
    t.eq(b"writable", poll1(a, POLLOUT, 0).0, 1);
    let ln = ux(SOCK_STREAM);
    ubind(ln, &sun_abs(b"hk-ux-sndbuf"));
    sys_listen(ln, 1);
    t.eq(b"listener SIOCINQ", ioctl_int(ln, FIONREAD as u64).0, EINVAL);
    for f in [a, b, ln] {
        close(f);
    }
    t.done();
}

/// Datagrams: boundaries, MSG_TRUNC, sender addresses, destination
/// errors, EMSGSIZE, EPERM from a socket connected elsewhere
fn test_dgram() {
    let mut t = T::new(b"UNIX_DGRAM");
    let sa = sun_abs(b"hk-ux-dg");
    let srv = ux(SOCK_DGRAM);
    ubind(srv, &sa);
    let c = ux(SOCK_DGRAM);
    for m in [&b"1"[..], b"22", b"333"] {
        sys_sendto(c, m.as_ptr(), m.len(), 0, sa.b.as_ptr(), sa.len);
    }
    let mut buf = [0u8; 16];
    t.eq(b"FIONREAD first", ioctl_int(srv, FIONREAD as u64).1 as i64, 1);
    for want in 1..=3 {
        t.eq(b"boundary", recv(srv, &mut buf, 0), want);
    }
    sys_sendto(c, b"0123456789".as_ptr(), 10, 0, sa.b.as_ptr(), sa.len);
    let mut ctl = [0u8; 8];
    let (r, fl, _) = recv_msg(srv, &mut buf[..4], &mut ctl, 0);
    t.eq(b"truncated", r, 4);
    t.ok(b"MSG_TRUNC flag", fl & MSG_TRUNC != 0, fl as i64);
    sys_sendto(c, b"0123456789".as_ptr(), 10, 0, sa.b.as_ptr(), sa.len);
    t.eq(b"MSG_TRUNC real length", recv(srv, &mut buf[..4], MSG_TRUNC), 10);
    t.eq(b"rest discarded", recv(srv, &mut buf, MSG_DONTWAIT), EAGAIN);
    let x = sun_path(b"/tmp/ux_nowhere");
    t.eq(b"ENOENT", sys_sendto(c, b"x".as_ptr(), 1, 0, x.b.as_ptr(), x.len), ENOENT);
    let y = sun_abs(b"hk-ux-nobody");
    t.eq(b"ECONNREFUSED", sys_sendto(c, b"x".as_ptr(), 1, 0, y.b.as_ptr(), y.len), ECONNREFUSED);
    t.eq(b"ENOTCONN", send(c, b"x", 0), ENOTCONN_);
    let big = [0u8; 8192];
    setint(c, SOL_SOCKET, SO_SNDBUF, 1024);
    t.eq(b"EMSGSIZE", sys_sendto(c, big.as_ptr(), 8192, 0, sa.b.as_ptr(), sa.len), EMSGSIZE);
    // srv connected to another socket refuses c
    let other = ux(SOCK_DGRAM);
    let oa = sun_abs(b"hk-ux-dg-other");
    ubind(other, &oa);
    t.eq(b"connect", uconnect(srv, &oa), 0);
    let c2 = ux(SOCK_DGRAM);
    t.eq(b"EPERM", sys_sendto(c2, b"x".as_ptr(), 1, 0, sa.b.as_ptr(), sa.len), EPERM);
    t.eq(b"from peer ok", sys_sendto(other, b"y".as_ptr(), 1, 0, sa.b.as_ptr(), sa.len), 1);
    let unspec = [0u8; 2];
    t.eq(b"AF_UNSPEC", sys_connect(srv, unspec.as_ptr(), 2), 0);
    t.eq(b"after disconnect", sys_sendto(c2, b"x".as_ptr(), 1, 0, sa.b.as_ptr(), sa.len), 1);
    for f in [srv, c, other, c2] {
        close(f);
    }
    t.done();
}

/// A receiver not connected back takes max_dgram_qlen + 1 messages,
/// then EAGAIN (and no POLLOUT for a connected sender) until it reads
fn test_dgram_queue() {
    let mut t = T::new(b"UNIX_DGRAM_QUEUE");
    let f = sys_open(b"/proc/sys/net/unix/max_dgram_qlen\0".as_ptr(), O_RDONLY, 0) as i32;
    let mut v = [0u8; 8];
    let n = sys_read(f as u64, v.as_mut_ptr(), 8);
    close(f);
    t.ok(b"max_dgram_qlen 10", n == 3 && &v[..3] == b"10\n", n);
    let sa = sun_abs(b"hk-ux-q");
    let srv = ux(SOCK_DGRAM);
    ubind(srv, &sa);
    let c = ux(SOCK_DGRAM);
    uconnect(c, &sa);
    let mut sent = 0;
    for _ in 0..20 {
        if send(c, b"m", MSG_DONTWAIT) != 1 {
            break;
        }
        sent += 1;
    }
    t.eq(b"queued", sent, 11);
    t.eq(b"EAGAIN", send(c, b"m", MSG_DONTWAIT), EAGAIN);
    t.eq(b"no POLLOUT", poll1(c, POLLOUT, 0).0, 0);
    let mut buf = [0u8; 4];
    recv(srv, &mut buf, 0);
    let (n, ev) = poll1(c, POLLOUT, 1000);
    t.ok(b"POLLOUT after read", n == 1 && ev & POLLOUT != 0, ev as i64);
    t.eq(b"room again", send(c, b"m", MSG_DONTWAIT), 1);
    // A blocked sender is woken by the reader (child reads after 100 ms)
    let pid = sys_fork();
    if pid == 0 {
        msleep(100);
        recv(srv, &mut buf, 0);
        sys_exit(0);
    }
    t.eq(b"blocking send", send(c, b"m", 0), 1);
    wait_status(pid);
    // A sleeping poller is woken when the reader makes room
    t.eq(b"full again", send(c, b"m", MSG_DONTWAIT), EAGAIN);
    let pid = sys_fork();
    if pid == 0 {
        msleep(100);
        recv(srv, &mut buf, 0);
        sys_exit(0);
    }
    let t0 = now_ms();
    let (n, ev) = poll1(c, POLLOUT, 5000);
    t.ok(b"poll woken", n == 1 && ev & POLLOUT != 0 && now_ms() - t0 < 4000, ev as i64);
    wait_status(pid);
    for f in [srv, c] {
        close(f);
    }
    t.done();
}

/// SOCK_SEQPACKET: boundaries, truncation, EOF and EPIPE after close,
/// ENOTCONN unconnected
fn test_seqpacket() {
    let mut t = T::new(b"UNIX_SEQPACKET");
    let a = sun_abs(b"hk-ux-seq");
    let l = listener(SOCK_SEQPACKET, &a, 5);
    let c = ux(SOCK_SEQPACKET);
    t.eq(b"connect", uconnect(c, &a), 0);
    let s = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    for m in [&b"a"[..], b"bb", b"ccc"] {
        send(c, m, 0);
    }
    let mut buf = [0u8; 16];
    t.eq(b"FIONREAD sum", ioctl_int(s, FIONREAD as u64).1 as i64, 6);
    for want in 1..=3 {
        t.eq(b"boundary", recv(s, &mut buf, 0), want);
    }
    send(c, b"0123456789", 0);
    send(c, b"next", 0);
    let mut ctl = [0u8; 8];
    let (r, fl, _) = recv_msg(s, &mut buf[..4], &mut ctl, 0);
    t.ok(b"truncated", r == 4 && fl & MSG_TRUNC != 0, r);
    t.eq(b"next message", recv(s, &mut buf, 0), 4);
    close(c);
    t.eq(b"EOF", recv(s, &mut buf, 0), 0);
    t.eq(b"EOF nonblocking", recv(s, &mut buf, MSG_DONTWAIT), 0);
    t.eq(b"EPIPE", send(s, b"x", MSG_NOSIGNAL), EPIPE);
    let u = ux(SOCK_SEQPACKET);
    t.eq(b"send unconnected", send(u, b"x", 0), ENOTCONN_);
    t.eq(b"recv unconnected", recv(u, &mut buf, MSG_DONTWAIT), ENOTCONN_);
    for f in [l, s, u] {
        close(f);
    }
    t.done();
}

/// EPIPE: a stream raises SIGPIPE (not with MSG_NOSIGNAL); datagram and
/// seqpacket sockets never do
fn test_epipe() {
    let mut t = T::new(b"UNIX_EPIPE");
    let pid = sys_fork();
    if pid == 0 {
        let (a, b) = pair(SOCK_STREAM);
        close(b);
        if send(a, b"x", MSG_NOSIGNAL) != EPIPE {
            sys_exit(1);
        }
        send(a, b"x", 0);
        sys_exit(3);
    }
    let st = wait_status(pid);
    t.eq(b"killed by SIGPIPE", (st & 0x7f) as i64, SIGPIPE as i64);
    let pid = sys_fork();
    if pid == 0 {
        let (s1, s2) = pair(SOCK_SEQPACKET);
        close(s2);
        sys_exit(if send(s1, b"x", 0) == EPIPE { 0 } else { 1 });
    }
    t.eq(b"seqpacket no SIGPIPE", wait_status(pid) as i64, 0);
    let pid = sys_fork();
    if pid == 0 {
        sigpipe(SIG_IGN);
        let (a, b) = pair(SOCK_STREAM);
        close(b);
        let r = send(a, b"x", 0);
        sigpipe(SIG_DFL);
        sys_exit(if r == EPIPE { 0 } else { 1 });
    }
    t.eq(b"ignored", wait_status(pid) as i64, 0);
    // A datagram peer that went away: ECONNREFUSED once, then ENOTCONN
    let (a, b) = pair(SOCK_DGRAM);
    close(b);
    t.eq(b"dgram ECONNREFUSED", send(a, b"x", 0), ECONNREFUSED);
    t.eq(b"dgram ENOTCONN", send(a, b"x", 0), ENOTCONN_);
    close(a);
    t.done();
}

/// Closing with unread data resets the peer (ECONNRESET once, then EOF)
fn test_reset() {
    let mut t = T::new(b"UNIX_RESET");
    let (a, b) = pair(SOCK_STREAM);
    send(a, b"unread", 0);
    close(b);
    let mut buf = [0u8; 8];
    t.eq(b"ECONNRESET", recv(a, &mut buf, 0), ECONNRESET);
    t.eq(b"then EOF", recv(a, &mut buf, 0), 0);
    let (c, d) = pair(SOCK_STREAM);
    close(d);
    t.eq(b"clean close EOF", recv(c, &mut buf, 0), 0);
    let (e, f) = pair(SOCK_STREAM);
    send(e, b"xy", 0);
    close(e);
    t.eq(b"data before EOF", recv(f, &mut buf, 0), 2);
    t.eq(b"EOF", recv(f, &mut buf, 0), 0);
    for x in [a, c, f] {
        close(x);
    }
    t.done();
}

/// SCM_RIGHTS: a pipe read end passed over a datagram socket reads the
/// pipe; MSG_CMSG_CLOEXEC; bad descriptors
fn test_scm_rights() {
    let mut t = T::new(b"UNIX_SCM_RIGHTS");
    let (a, b) = pair(SOCK_DGRAM);
    let mut p = [0i32; 2];
    sys_pipe(p.as_mut_ptr());
    t.eq(b"send", send_fds(a, b"f", &[p[0]]), 1);
    close(p[0]);
    sys_write(p[1] as u64, b"hello".as_ptr(), 5);
    let mut buf = [0u8; 8];
    let mut ctl = [0u8; 64];
    let (r, fl, clen) = recv_msg(b, &mut buf, &mut ctl, 0);
    t.eq(b"recv", r, 1);
    let (fd, n) = got_fds(&ctl, clen);
    t.ok(b"one fd", fd >= 0 && n == 1 && fl & MSG_CTRUNC == 0, fl as i64);
    t.eq(b"no cloexec", sys_fcntl(fd, F_GETFD, 0), 0);
    let mut data = [0u8; 8];
    t.eq(b"read pipe", sys_read(fd as u64, data.as_mut_ptr(), 8), 5);
    t.ok(b"pipe data", &data[..5] == b"hello", data[0] as i64);
    send_fds(a, b"g", &[p[1]]);
    let (_, _, clen) = recv_msg(b, &mut buf, &mut ctl, MSG_CMSG_CLOEXEC);
    let (fd2, _) = got_fds(&ctl, clen);
    t.eq(b"cloexec", sys_fcntl(fd2, F_GETFD, 0), 1);
    t.eq(b"EBADF", send_fds(a, b"h", &[999]), EBADF);
    let many = [p[1]; 254];
    t.eq(b"over SCM_MAX_FD", send_fds(a, b"h", &many), EINVAL);
    t.eq(b"SCM_MAX_FD", send_fds(a, b"h", &many[..253]), 1);
    let mut big = [0u8; 1100];
    let (_, _, clen) = recv_msg(b, &mut buf, &mut big, 0);
    let d = cmsg_find(&big, clen, SOL_SOCKET, SCM_RIGHTS).unwrap_or(&[]);
    t.eq(b"253 fds", (d.len() / 4) as i64, 253);
    for c in d.chunks_exact(4) {
        close(i32::from_ne_bytes(c.try_into().unwrap()));
    }
    // MSG_PEEK duplicates the files; the real read gets them again
    send_fds(a, b"p", &[p[1]]);
    let (_, _, clen) = recv_msg(b, &mut buf, &mut ctl, MSG_PEEK);
    let (pk, _) = got_fds(&ctl, clen);
    let (_, _, clen) = recv_msg(b, &mut buf, &mut ctl, 0);
    let (rd, _) = got_fds(&ctl, clen);
    t.ok(b"peek fds", pk >= 0 && rd >= 0 && pk != rd, pk as i64);
    for f in [a, b, p[1], fd, fd2, pk, rd] {
        close(f);
    }
    t.done();
}

/// A control buffer for one fd gets one of three (MSG_CTRUNC); the
/// other two are closed, as are all fds of a recv without control
/// space (checked through the pipe: no reader left -> EPIPE)
fn test_ctrunc() {
    let mut t = T::new(b"UNIX_CTRUNC");
    let pid = sys_fork();
    if pid == 0 {
        sigpipe(SIG_IGN);
        let (a, b) = pair(SOCK_STREAM);
        let mut p = [0i32; 2];
        sys_pipe(p.as_mut_ptr());
        if send_fds(a, b"x", &[p[0], p[0], p[0]]) != 1 {
            sys_exit(1);
        }
        let mut buf = [0u8; 4];
        // CMSG_LEN(sizeof(int)): room for exactly one
        let mut ctl = [0u8; 20];
        let (r, fl, clen) = recv_msg(b, &mut buf, &mut ctl, 0);
        let (fd, n) = got_fds(&ctl, clen);
        if r != 1 || fl & MSG_CTRUNC == 0 || n != 1 || clen != 20 {
            sys_exit(2);
        }
        if send_fds(a, b"y", &[p[0]]) != 1 {
            sys_exit(3);
        }
        let mut none = [0u8; 0];
        let (r, fl, _) = recv_msg(b, &mut buf, &mut none, 0);
        if r != 1 || fl & MSG_CTRUNC == 0 {
            sys_exit(4);
        }
        close(p[0]);
        close(fd);
        let w = sys_write(p[1] as u64, b"z".as_ptr(), 1);
        sys_exit(if w == EPIPE { 0 } else { 5 });
    }
    t.eq(b"child", wait_status(pid) as i64, 0);
    t.done();
}

/// Files in flight per user are capped near RLIMIT_NOFILE: an
/// unprivileged sender gets ETOOMANYREFS once its count exceeds the
/// limit, and may send again after the receiver takes them
fn test_inflight() {
    let mut t = T::new(b"UNIX_INFLIGHT");
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(USER, USER, USER) != 0 || sys_setresuid(USER, USER, USER) != 0 {
            sys_exit(90);
        }
        let lim = hk_syscall::RLimit { rlim_cur: 16, rlim_max: 16 };
        hk_syscall::sys_setrlimit(hk_syscall::RLIMIT_NOFILE, &lim);
        let (a, b) = pair(SOCK_STREAM);
        let mut sent = 0;
        let mut last = 0;
        for _ in 0..40 {
            last = send_fds(a, b"x", &[a]);
            if last != 1 {
                break;
            }
            sent += 1;
        }
        if last != -109 {
            sys_exit(1);
        }
        if sent != 17 {
            sys_exit(2);
        }
        // Receiving (and closing) them all uncharges the user
        let mut buf = [0u8; 64];
        let mut ctl = [0u8; 0];
        while recv_msg(b, &mut buf, &mut ctl, MSG_DONTWAIT).0 > 0 {}
        sys_exit(if send_fds(a, b"x", &[a]) == 1 { 0 } else { 3 });
    }
    t.eq(b"child", wait_status(pid) as i64, 0);
    t.done();
}

/// SO_PEERCRED: socketpair (creator), connect (listener's at listen()),
/// accept (connector's), none without a connection
fn test_peercred() {
    let mut t = T::new(b"UNIX_PEERCRED");
    let me = sys_getpid() as i32;
    let (a, b) = pair(SOCK_STREAM);
    let (r, pid, uid, gid) = peercred(a);
    t.eq(b"getsockopt", r, 0);
    t.ok(b"pair", pid == me && uid == 0 && gid == 0, pid as i64);
    let s = ux(SOCK_STREAM);
    let (_, pid, uid, gid) = peercred(s);
    t.ok(b"unconnected", pid == 0 && uid == u32::MAX && gid == u32::MAX, uid as i64);
    let sa = sun_abs(b"hk-ux-cred");
    let l = listener(SOCK_STREAM, &sa, 5);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(USER, USER, USER) != 0 || sys_setresuid(USER, USER, USER) != 0 {
            sys_exit(90);
        }
        let c = ux(SOCK_STREAM);
        uconnect(c, &sa);
        let (_, pp, pu, _) = peercred(c);
        let mut b = [0u8; 1];
        recv(c, &mut b, 0);
        sys_exit(if pp == me && pu == 0 { 0 } else { 1 });
    }
    let acc = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    let (_, cp, cu, cg) = peercred(acc);
    t.ok(b"accepted", cp as i64 == pid && cu == USER && cg == USER, cp as i64);
    close(acc);
    t.eq(b"child", wait_status(pid) as i64, 0);
    for f in [a, b, s, l] {
        close(f);
    }
    t.done();
}

/// SCM_CREDENTIALS: delivered with SO_PASSCRED; a sender may only claim
/// its own ids (EPERM otherwise), ESRCH for a missing pid with
/// CAP_SYS_ADMIN, EINVAL for a bad length or uid -1
fn test_scm_creds() {
    let mut t = T::new(b"UNIX_SCM_CREDS");
    let me = sys_getpid() as i32;
    let (a, b) = pair(SOCK_DGRAM);
    setint(b, SOL_SOCKET, SO_PASSCRED, 1);
    send(a, b"x", 0);
    let mut buf = [0u8; 4];
    let mut ctl = [0u8; 64];
    let (_, _, clen) = recv_msg(b, &mut buf, &mut ctl, 0);
    let c = cmsg_find(&ctl, clen, SOL_SOCKET, SCM_CREDENTIALS);
    t.ok(b"creds", c.is_some_and(|d| d == ucred(me, 0, 0)), clen as i64);
    t.eq(b"own creds", send_cmsg(a, b"x", SOL_SOCKET, SCM_CREDENTIALS, &ucred(me, 0, 0), 0), 1);
    recv_msg(b, &mut buf, &mut ctl, 0);
    t.eq(b"bad length", send_cmsg(a, b"x", SOL_SOCKET, SCM_CREDENTIALS, &ucred(me, 0, 0)[..8], 0), EINVAL);
    t.eq(b"uid -1", send_cmsg(a, b"x", SOL_SOCKET, SCM_CREDENTIALS, &ucred(me, u32::MAX, 0), 0), EINVAL);
    t.eq(b"ESRCH", send_cmsg(a, b"x", SOL_SOCKET, SCM_CREDENTIALS, &ucred(0x3fff_fff0, 0, 0), 0), ESRCH);
    t.eq(b"unknown type", send_cmsg(a, b"x", SOL_SOCKET, 99, &[0; 4], 0), EINVAL);
    t.eq(b"other level ignored", send_cmsg(a, b"x", 0, 99, &[0; 4], 0), 1);
    recv_msg(b, &mut buf, &mut ctl, 0);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(USER, USER, USER) != 0 || sys_setresuid(USER, USER, USER) != 0 {
            sys_exit(90);
        }
        let me = sys_getpid() as i32;
        if send_cmsg(a, b"x", SOL_SOCKET, SCM_CREDENTIALS, &ucred(me, 0, USER), 0) != EPERM {
            sys_exit(1);
        }
        if send_cmsg(a, b"x", SOL_SOCKET, SCM_CREDENTIALS, &ucred(1, USER, USER), 0) != EPERM {
            sys_exit(2);
        }
        if send_cmsg(a, b"x", SOL_SOCKET, SCM_CREDENTIALS, &ucred(me, USER, USER), 0) != 1 {
            sys_exit(3);
        }
        sys_exit(0);
    }
    t.eq(b"non-root spoof", wait_status(pid) as i64, 0);
    let (_, _, clen) = recv_msg(b, &mut buf, &mut ctl, 0);
    let c = cmsg_find(&ctl, clen, SOL_SOCKET, SCM_CREDENTIALS);
    t.ok(b"child creds", c.is_some_and(|d| d[4..] == ucred(0, USER, USER)[4..]), clen as i64);
    // Without control space the credentials are truncated
    send(a, b"x", 0);
    let mut none = [0u8; 0];
    let (_, fl, _) = recv_msg(b, &mut buf, &mut none, 0);
    t.ok(b"CTRUNC", fl & MSG_CTRUNC != 0, fl as i64);
    close(a);
    close(b);
    t.done();
}

/// poll() states of stream sockets
fn test_poll() {
    let mut t = T::new(b"UNIX_POLL");
    let all = POLLIN | POLLOUT | POLLRDHUP;
    let (a, b) = pair(SOCK_STREAM);
    t.eq(b"idle", poll1(a, all, 0).1 as i64, POLLOUT as i64);
    send(b, b"x", 0);
    t.eq(b"readable", poll1(a, all, 0).1 as i64, (POLLIN | POLLOUT) as i64);
    sys_shutdown(b, SHUT_WR);
    t.eq(b"RDHUP", poll1(a, all, 0).1 as i64, (POLLIN | POLLOUT | POLLRDHUP) as i64);
    close(b);
    t.eq(b"HUP", poll1(a, all, 0).1 as i64, (POLLIN | POLLOUT | POLLRDHUP | POLLHUP) as i64);
    let s = ux(SOCK_STREAM);
    t.eq(b"unconnected", poll1(s, all, 0).1 as i64, (POLLOUT | POLLHUP) as i64);
    let sa = sun_abs(b"hk-ux-poll");
    let l = listener(SOCK_STREAM, &sa, 5);
    t.eq(b"listener idle", poll1(l, all, 0).0, 0);
    let c = ux(SOCK_STREAM);
    uconnect(c, &sa);
    t.eq(b"listener pending", poll1(l, all, 0).1 as i64, POLLIN as i64);
    for f in [a, s, l, c] {
        close(f);
    }
    t.done();
}

/// /proc/net/unix lists bound sockets: path, '@' for abstract names,
/// the listening flag
fn test_proc() {
    let mut t = T::new(b"UNIX_PROC");
    let p: &[u8] = b"/tmp/ux_proc";
    unlink(p);
    let l = listener(SOCK_STREAM, &sun_path(p), 5);
    let d = ux(SOCK_DGRAM);
    ubind(d, &sun_abs(b"hk-ux-proc"));
    let f = sys_open(b"/proc/net/unix\0".as_ptr(), O_RDONLY, 0) as i32;
    t.ok(b"open", f >= 0, f as i64);
    let mut buf = [0u8; 8192];
    let mut n = 0;
    loop {
        let r = sys_read(f as u64, buf[n..].as_mut_ptr(), (buf.len() - n) as u64);
        if r <= 0 || n + r as usize >= buf.len() {
            break;
        }
        n += r as usize;
    }
    close(f);
    let text = &buf[..n];
    t.ok(b"header", text.starts_with(b"Num       RefCount Protocol Flags    Type St Inode Path\n"), n as i64);
    let line = text.split(|&c| c == b'\n').find(|l| l.ends_with(b" /tmp/ux_proc"));
    t.ok(b"path line", line.is_some(), 0);
    // Flags __SO_ACCEPTCON, type 0001, state 01 (unconnected)
    t.ok(b"listener fields", line.is_some_and(|l| contains(l, b" 00010000 0001 01 ")), 0);
    t.ok(b"abstract", text.split(|&c| c == b'\n').any(|l| l.ends_with(b" @hk-ux-proc")), 0);
    unlink(p);
    close(l);
    close(d);
    t.done();
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}
