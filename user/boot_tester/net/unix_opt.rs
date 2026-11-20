//! AF_UNIX options (hk and Linux): SO_PEEK_OFF on stream, datagram and
//! seqpacket sockets (Linux selftests af_unix/so_peek_off.c);
//! SO_PASSPIDFD / SCM_PIDFD and SO_PEERPIDFD (af_unix/scm_pidfd.c);
//! SIOCUNIXFILE.

use hk_syscall::{
    AF_UNIX, O_PATH, Stat, sys_bind, sys_fstat, sys_ioctl, sys_socket, sys_stat, sys_unlink,
};
use hk_syscall::{
    O_RDONLY, SOCK_DGRAM, SOCK_STREAM, sys_exit, sys_fcntl, sys_fork, sys_getpid, sys_open,
    sys_pidfd_send_signal, sys_pipe, sys_read, sys_wait4, sys_write,
};

use crate::harness::T;
use crate::net::sk::*;
use crate::net::unix::pair;

const SOCK_SEQPACKET: i32 = 5;
const SO_PEEK_OFF: i32 = 42;
const SO_PASSPIDFD: i32 = 76;
const SO_PEERPIDFD: i32 = 77;
const SCM_PIDFD: i32 = 4;
const F_GETFD: i32 = 1;
const F_GETFL: i32 = 3;
const SIOCUNIXFILE: u64 = 0x89E0;

pub fn run_tests() {
    crate::helpers::println(b"=== AF_UNIX option Tests ===");
    for ty in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET] {
        test_peek_off(ty);
    }
    test_pidfd();
    test_pidfd_child();
    test_unixfile();
}

/// Receive into a `len`-byte buffer: exactly the bytes `want`
fn recveq(fd: i32, len: usize, flags: i32, want: &[u8]) -> bool {
    let mut buf = [0u8; 128];
    let r = recv(fd, &mut buf[..len], flags);
    r == want.len() as i64 && &buf[..want.len()] == want
}

fn peek_off(fd: i32) -> i64 {
    let (r, v) = getint(fd, SOL_SOCKET, SO_PEEK_OFF);
    if r < 0 { r } else { v as i64 }
}

/// so_peek_off.c single_chunk, two_chunks and two_chunks_overlap: each
/// peek starts at the offset and moves it; reads move it back
fn test_peek_off(ty: i32) {
    let mut t = T::new(match ty {
        SOCK_STREAM => b"UNIX_PEEK_OFF_STREAM",
        SOCK_DGRAM => b"UNIX_PEEK_OFF_DGRAM",
        _ => b"UNIX_PEEK_OFF_SEQPACKET",
    });
    let (a, b) = pair(ty);
    t.eq(b"default off", peek_off(b), -1);
    t.eq(b"set", setint(b, SOL_SOCKET, SO_PEEK_OFF, 0), 0);
    t.eq(b"get", peek_off(b), 0);
    // single_chunk
    send(a, b"aaaabbbb", 0);
    t.ok(b"single peek 1", recveq(b, 4, MSG_PEEK, b"aaaa"), 0);
    t.eq(b"single off 1", peek_off(b), 4);
    t.ok(b"single peek 2", recveq(b, 100, MSG_PEEK, b"bbbb"), 0);
    t.eq(b"single off 2", peek_off(b), 8);
    t.ok(b"single read", recveq(b, 8, 0, b"aaaabbbb"), 0);
    t.eq(b"single off 0", peek_off(b), 0);
    // two_chunks
    send(a, b"aaaa", 0);
    send(a, b"bbbb", 0);
    t.ok(b"two peek 1", recveq(b, 4, MSG_PEEK, b"aaaa"), 0);
    t.eq(b"two off 1", peek_off(b), 4);
    t.ok(b"two peek 2", recveq(b, 100, MSG_PEEK, b"bbbb"), 0);
    t.eq(b"two off 2", peek_off(b), 8);
    t.ok(b"two read 1", recveq(b, 4, 0, b"aaaa"), 0);
    t.ok(b"two read 2", recveq(b, 4, 0, b"bbbb"), 0);
    t.eq(b"two off 0", peek_off(b), 0);
    // two_chunks_overlap
    send(a, b"aaaa", 0);
    t.ok(b"overlap peek", recveq(b, 2, MSG_PEEK, b"aa"), 0);
    t.eq(b"overlap off", peek_off(b), 2);
    send(a, b"bbbb", 0);
    if ty == SOCK_STREAM {
        // A stream fills the buffer
        t.ok(b"overlap peek 2", recveq(b, 4, MSG_PEEK, b"aabb"), 0);
        t.eq(b"overlap off 2", peek_off(b), 6);
        t.ok(b"overlap peek 3", recveq(b, 100, MSG_PEEK, b"bb"), 0);
    } else {
        // Datagrams end at the message boundary
        t.ok(b"overlap peek 2", recveq(b, 100, MSG_PEEK, b"aa"), 0);
        t.eq(b"overlap off 2", peek_off(b), 4);
        t.ok(b"overlap peek 3", recveq(b, 100, MSG_PEEK, b"bbbb"), 0);
    }
    t.eq(b"overlap off 3", peek_off(b), 8);
    t.ok(b"overlap read 1", recveq(b, 4, 0, b"aaaa"), 0);
    t.ok(b"overlap read 2", recveq(b, 4, 0, b"bbbb"), 0);
    t.eq(b"overlap off 0", peek_off(b), 0);
    // An offset past the queue: nothing to peek
    send(a, b"cc", 0);
    setint(b, SOL_SOCKET, SO_PEEK_OFF, 2);
    let mut buf = [0u8; 8];
    t.eq(
        b"peek past end",
        recv(b, &mut buf, MSG_PEEK | MSG_DONTWAIT),
        EAGAIN,
    );
    t.ok(b"read after", recveq(b, 8, 0, b"cc"), 0);
    close(a);
    close(b);
    t.done();
}

/// The `Pid:` of a pidfd's /proc/self/fdinfo (-1000 if unreadable)
fn fdinfo_pid(fd: i32) -> i64 {
    let mut path = *b"/proc/self/fdinfo/\0\0\0\0\0";
    let mut d = [0u8; 5];
    let (mut v, mut k) = (fd as u32, 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..k {
        path[18 + i] = d[k - 1 - i];
    }
    let f = sys_open(path.as_ptr(), O_RDONLY, 0) as i32;
    if f < 0 {
        return -1000;
    }
    let mut buf = [0u8; 512];
    let n = sys_read(f as u64, buf.as_mut_ptr(), buf.len() as u64);
    close(f);
    if n <= 0 {
        return -1000;
    }
    let text = &buf[..n as usize];
    let Some(line) = text
        .split(|&c| c == b'\n')
        .find(|l| l.starts_with(b"Pid:\t"))
    else {
        return -1000;
    };
    let mut v: i64 = 0;
    let mut neg = false;
    for &c in &line[5..] {
        match c {
            b'-' => neg = true,
            b'0'..=b'9' => v = v * 10 + i64::from(c - b'0'),
            _ => break,
        }
    }
    if neg { -v } else { v }
}

/// The SCM_PIDFD of a received message (-1000 if none)
fn recv_pidfd(fd: i32) -> i64 {
    let mut buf = [0u8; 8];
    let mut ctl = [0u8; 64];
    let (r, _, clen) = recv_msg(fd, &mut buf, &mut ctl, 0);
    if r < 0 {
        return r;
    }
    match cmsg_find(&ctl, clen, SOL_SOCKET, SCM_PIDFD) {
        Some(d) if d.len() >= 4 => i32::from_ne_bytes(d[..4].try_into().unwrap()) as i64,
        _ => -1000,
    }
}

/// A pidfd names `pid`, is O_CLOEXEC and signals (signal 0)
fn pidfd_is(t: &mut T, fd: i64, pid: i64) {
    t.ok(b"pidfd", fd >= 0, fd);
    if fd < 0 {
        return;
    }
    let fd = fd as i32;
    t.eq(b"fdinfo Pid", fdinfo_pid(fd), pid);
    t.eq(b"FD_CLOEXEC", sys_fcntl(fd, F_GETFD, 0) & 1, 1);
    t.eq(
        b"pidfd_send_signal 0",
        sys_pidfd_send_signal(fd, 0, core::ptr::null(), 0),
        0,
    );
    close(fd);
}

/// SO_PASSPIDFD: a message comes with SCM_PIDFD of its sender;
/// SO_PEERPIDFD: a pidfd of the peer's creator; ENODATA without peer
fn test_pidfd() {
    let mut t = T::new(b"UNIX_PIDFD");
    let me = sys_getpid();
    let (a, b) = pair(SOCK_STREAM);
    t.eq(b"off", getint(b, SOL_SOCKET, SO_PASSPIDFD).1 as i64, 0);
    t.eq(b"set", setint(b, SOL_SOCKET, SO_PASSPIDFD, 1), 0);
    t.eq(b"on", getint(b, SOL_SOCKET, SO_PASSPIDFD).1 as i64, 1);
    send(a, b"x", 0);
    let fd = recv_pidfd(b);
    pidfd_is(&mut t, fd, me);
    // Without the option, none
    send(b, b"y", 0);
    t.eq(b"none unasked", recv_pidfd(a), -1000);
    let (r, fd) = getint(a, SOL_SOCKET, SO_PEERPIDFD);
    t.eq(b"SO_PEERPIDFD", r, 0);
    pidfd_is(&mut t, fd as i64, me);
    let u = udp();
    t.eq(b"udp", getint(u, SOL_SOCKET, SO_PEERPIDFD).0, -61);
    for f in [a, b, u] {
        close(f);
    }
    t.done();
}

/// Another process's datagram: SCM_PIDFD names it
fn test_pidfd_child() {
    let mut t = T::new(b"UNIX_PIDFD_CHILD");
    let (a, b) = pair(SOCK_DGRAM);
    setint(b, SOL_SOCKET, SO_PASSPIDFD, 1);
    let mut p = [0i32; 2];
    sys_pipe(p.as_mut_ptr());
    let pid = sys_fork();
    if pid == 0 {
        send(a, b"c", 0);
        let mut c = [0u8; 1];
        sys_read(p[0] as u64, c.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let fd = recv_pidfd(b);
    pidfd_is(&mut t, fd, pid);
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    for f in [a, b, p[0], p[1]] {
        close(f);
    }
    t.done();
}

/// A sockaddr_un for a filesystem name (length to pass)
fn sun(p: &[u8]) -> ([u8; 110], u32) {
    let mut b = [0u8; 110];
    b[..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    b[2..2 + p.len()].copy_from_slice(p);
    (b, (2 + p.len() + 1) as u32)
}

/// SIOCUNIXFILE: an O_PATH, O_CLOEXEC descriptor of the socket inode
/// a filesystem name bound; ENOENT unbound or abstract
fn test_unixfile() {
    let mut t = T::new(b"UNIX_SIOCUNIXFILE");
    let path = b"/tmp/ux_unixfile\0";
    sys_unlink(path.as_ptr());
    let s = sys_socket(AF_UNIX, SOCK_STREAM, 0) as i32;
    t.eq(b"unbound", sys_ioctl(s, SIOCUNIXFILE, 0), -2);
    let (a, len) = sun(&path[..path.len() - 1]);
    t.eq(b"bind", sys_bind(s, a.as_ptr(), len), 0);
    let fd = sys_ioctl(s, SIOCUNIXFILE, 0);
    t.ok(b"open", fd >= 0, fd);
    if fd >= 0 {
        let fd = fd as i32;
        let fl = sys_fcntl(fd, F_GETFL, 0);
        t.ok(b"O_PATH", fl >= 0 && fl as u32 & O_PATH != 0, fl);
        t.eq(b"FD_CLOEXEC", sys_fcntl(fd, F_GETFD, 0) & 1, 1);
        let mut st = Stat::default();
        let mut st2 = Stat::default();
        t.eq(b"fstat", sys_fstat(fd, &mut st), 0);
        sys_stat(path.as_ptr(), &mut st2);
        t.ok(
            b"socket inode",
            st.st_mode & 0o170000 == 0o140000 && st.st_ino == st2.st_ino,
            st.st_mode as i64,
        );
        close(fd);
    }
    // An abstract name has no inode
    let d = sys_socket(AF_UNIX, SOCK_DGRAM, 0) as i32;
    let mut b = [0u8; 110];
    b[..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    b[3..8].copy_from_slice(b"uxuf!");
    sys_bind(d, b.as_ptr(), 8);
    t.eq(b"abstract", sys_ioctl(d, SIOCUNIXFILE, 0), -2);
    close(d);
    close(s);
    sys_unlink(path.as_ptr());
    t.done();
}
