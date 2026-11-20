//! AF_UNIX out-of-band data (hk and Linux, CONFIG_AF_UNIX_OOB): MSG_OOB
//! sends and reads, the mark (SIOCATMARK, reads stopping at it),
//! SO_OOBINLINE, POLLPRI and SIGURG to the owner (Linux selftests
//! af_unix/msg_oob.c, the cases where v6.8 and current Linux agree).

use hk_syscall::{
    F_SETOWN, IoVec, MsgHdr, SOCK_DGRAM, SOCK_STREAM, sys_fcntl, sys_getpid, sys_ioctl,
    sys_recvmsg, sys_rt_sigaction, sys_rt_sigpending, sys_rt_sigprocmask,
};

use crate::harness::T;
use crate::net::sk::*;
use crate::net::unix::pair;

const SIOCATMARK: u64 = 0x8905;
const SO_OOBINLINE: i32 = 10;
const POLLPRI: i16 = 0x2;
const SIGURG: i32 = 23;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_IGN: u64 = 1;
const SIG_DFL: u64 = 0;

pub fn run_tests() {
    crate::helpers::println(b"=== AF_UNIX OOB Tests ===");
    test_oob_basic();
    test_oob_skip();
    test_oob_inline();
    test_oob_sigurg();
}

fn atmark(fd: i32) -> i64 {
    let mut v: i32 = -1;
    let r = sys_ioctl(fd, SIOCATMARK, &mut v as *mut i32 as u64);
    if r < 0 { r } else { v as i64 }
}

/// recvmsg into `buf`: (return, msg_flags)
fn recv_flags(fd: i32, buf: &mut [u8], flags: i32) -> (i64, i32) {
    let mut iov = IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: buf.len(),
    };
    let mut m = MsgHdr::new(&mut iov, 1);
    let r = sys_recvmsg(fd, &mut m, flags);
    (r, m.msg_flags)
}

fn has_pri(fd: i32) -> bool {
    let (r, ev) = poll1(fd, POLLPRI, 0);
    r == 1 && ev & POLLPRI != 0
}

/// The last byte of a MSG_OOB send is the out-of-band byte: reads stop
/// before it, SIOCATMARK says when it is next, MSG_OOB takes (or peeks
/// at) it, POLLPRI shows it pending
fn test_oob_basic() {
    let mut t = T::new(b"UNIX_OOB");
    let (a, b) = pair(SOCK_STREAM);
    let mut buf = [0u8; 16];
    t.eq(b"empty OOB send", send(a, b"", MSG_OOB), EOPNOTSUPP);
    t.eq(b"none pending", recv(b, &mut buf, MSG_OOB), EINVAL);
    t.ok(b"no POLLPRI", !has_pri(b), 0);
    t.eq(b"send", send(a, b"hello", MSG_OOB), 5);
    t.ok(b"POLLPRI", has_pri(b), 0);
    t.eq(b"FIONREAD", ioctl_fionread(b), 5);
    t.eq(b"not at mark", atmark(b), 0);
    t.eq(b"read to mark", recv(b, &mut buf, 0), 4);
    t.ok(b"data", &buf[..4] == b"hell", buf[0] as i64);
    t.eq(b"at mark", atmark(b), 1);
    let (r, fl) = recv_flags(b, &mut buf, MSG_OOB | MSG_PEEK);
    t.ok(
        b"peek OOB",
        r == 1 && buf[0] == b'o' && fl & MSG_OOB != 0,
        r,
    );
    t.ok(b"still POLLPRI", has_pri(b), 0);
    buf[0] = 0;
    let (r, fl) = recv_flags(b, &mut buf, MSG_OOB);
    t.ok(
        b"read OOB",
        r == 1 && buf[0] == b'o' && fl & MSG_OOB != 0,
        r,
    );
    t.ok(b"POLLPRI gone", !has_pri(b), 0);
    t.eq(b"OOB once", recv(b, &mut buf, MSG_OOB), EINVAL);
    t.eq(b"FIONREAD 0", ioctl_fionread(b), 0);
    t.eq(b"nothing left", recv(b, &mut buf, MSG_DONTWAIT), EAGAIN);
    // Datagram sockets have none
    let (c, d) = pair(SOCK_DGRAM);
    t.eq(b"dgram OOB", send(c, b"x", MSG_OOB), EOPNOTSUPP);
    for f in [a, b, c, d] {
        close(f);
    }
    t.done();
}

fn ioctl_fionread(fd: i32) -> i64 {
    let mut v: i32 = -1;
    let r = sys_ioctl(fd, hk_syscall::FIONREAD as u64, &mut v as *mut i32 as u64);
    if r < 0 { r } else { v as i64 }
}

/// Without SO_OOBINLINE a read past the mark drops the out-of-band
/// byte; a second OOB send makes the first an ordinary byte
fn test_oob_skip() {
    let mut t = T::new(b"UNIX_OOB_SKIP");
    let (a, b) = pair(SOCK_STREAM);
    let mut buf = [0u8; 16];
    send(a, b"ab", MSG_OOB);
    send(a, b"cd", 0);
    t.eq(b"to mark", recv(b, &mut buf, 0), 1);
    t.eq(b"past mark", recv(b, &mut buf, 0), 2);
    t.ok(b"OOB byte skipped", &buf[..2] == b"cd", buf[0] as i64);
    // (v6.8 left u->oob_skb set here; no test of the state after)
    // Replaced: "x" stays as data, "y" is the new mark
    send(a, b"x", MSG_OOB);
    send(a, b"y", MSG_OOB);
    let (r, _) = recv_flags(b, &mut buf, MSG_OOB);
    t.ok(b"newest OOB", r == 1 && buf[0] == b'y', r);
    t.eq(b"old one is data", recv(b, &mut buf, MSG_DONTWAIT), 1);
    t.ok(b"old data", buf[0] == b'x', buf[0] as i64);
    close(a);
    close(b);
    t.done();
}

/// SO_OOBINLINE: the byte is read in the stream, after the read that
/// stops at the mark; MSG_OOB is EINVAL
fn test_oob_inline() {
    let mut t = T::new(b"UNIX_OOB_INLINE");
    let (a, b) = pair(SOCK_STREAM);
    let mut buf = [0u8; 16];
    t.eq(b"set", setint(b, SOL_SOCKET, SO_OOBINLINE, 1), 0);
    send(a, b"ab", MSG_OOB);
    t.eq(b"MSG_OOB inline", recv(b, &mut buf, MSG_OOB), EINVAL);
    t.eq(b"to mark", recv(b, &mut buf, 0), 1);
    t.ok(b"first", buf[0] == b'a', buf[0] as i64);
    t.eq(b"at mark", atmark(b), 1);
    t.eq(b"inline byte", recv(b, &mut buf, 0), 1);
    t.ok(b"OOB data", buf[0] == b'b', buf[0] as i64);
    t.ok(b"no POLLPRI", !has_pri(b), 0);
    close(a);
    close(b);
    t.done();
}

#[repr(C)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

fn sigurg_action(handler: u64) {
    let a = SigAction {
        handler,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    sys_rt_sigaction(SIGURG as u32, &a as *const SigAction as u64, 0, 8);
}

fn urg_pending() -> bool {
    let mut set: u64 = 0;
    sys_rt_sigpending(&mut set as *mut u64 as u64, 8);
    set & (1 << (SIGURG - 1)) != 0
}

/// An OOB send raises SIGURG for the receiving socket's owner
/// (F_SETOWN), and none without an owner
fn test_oob_sigurg() {
    let mut t = T::new(b"UNIX_OOB_SIGURG");
    let mask: u64 = 1 << (SIGURG - 1);
    sys_rt_sigprocmask(SIG_BLOCK, &mask as *const u64 as u64, 0, 8);
    let (a, b) = pair(SOCK_STREAM);
    send(a, b"x", MSG_OOB);
    t.ok(b"no owner", !urg_pending(), 0);
    t.eq(b"F_SETOWN", sys_fcntl(b, F_SETOWN, sys_getpid() as u64), 0);
    send(a, b"y", MSG_OOB);
    t.ok(b"SIGURG", urg_pending(), 0);
    // Discard it: ignoring a pending signal drops it
    sigurg_action(SIG_IGN);
    sigurg_action(SIG_DFL);
    t.ok(b"discarded", !urg_pending(), 0);
    sys_rt_sigprocmask(SIG_UNBLOCK, &mask as *const u64 as u64, 0, 8);
    close(a);
    close(b);
    t.done();
}
