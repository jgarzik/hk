//! Blocking-mode tests (hk and Linux): O_NONBLOCK from fcntl and FIONBIO
//! seen at every call, SOCK_NONBLOCK, SO_RCVTIMEO timeouts, signals
//! (EINTR without SA_RESTART, restart with it, EINTR when a socket
//! timeout is set), FIONREAD/SIOCOUTQ, EPIPE with and without SIGPIPE,
//! TCP accept/poll/WAITALL/PEEK/RDHUP and non-blocking connect.

use core::sync::atomic::{AtomicU32, Ordering};

use hk_syscall::{
    sys_accept, sys_accept4, sys_exit, sys_fcntl, sys_fork, sys_getppid, sys_ioctl, sys_kill,
    sys_listen, sys_nanosleep, sys_rt_sigaction, sys_setsockopt, sys_shutdown, sys_socket,
    sys_wait4, Timespec, AF_INET, O_NONBLOCK, SA_RESTART, SA_RESTORER, SHUT_WR, SIGPIPE, SIGUSR1,
    SIG_DFL, SIG_IGN, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_STREAM,
};

use super::sk::*;

const F_GETFD: i32 = 1;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const FIONBIO: u64 = 0x5421;
const FIONREAD: u64 = 0x541B;
const SIOCOUTQ: u64 = 0x5411;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLRDHUP: i16 = 0x2000;

pub fn run_tests() {
    super::helpers::println(b"=== Non-blocking / Timeout Tests ===");
    test_fcntl_nonblock();
    test_fionbio();
    test_sock_nonblock();
    test_rcvtimeo();
    test_signals();
    test_fionread();
    test_epipe();
    test_tcp_accept();
    test_tcp_recv_flags();
    test_tcp_rdhup();
    test_tcp_nb_connect();
}

fn msleep(ms: u64) {
    let ts = Timespec { tv_sec: (ms / 1000) as i64, tv_nsec: ((ms % 1000) * 1_000_000) as i64 };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// fcntl(O_NONBLOCK) on and off takes effect on the next call
fn test_fcntl_nonblock() {
    let mut t = T::new(b"NONBLOCK_FCNTL");
    let (fd, _) = udp_lo();
    let fl = sys_fcntl(fd, F_GETFL, 0);
    t.eq(b"F_SETFL", sys_fcntl(fd, F_SETFL, (fl as u64) | O_NONBLOCK as u64), 0);
    let mut buf = [0u8; 4];
    t.eq(b"EAGAIN", recv(fd, &mut buf, 0), EAGAIN);
    sys_fcntl(fd, F_SETFL, fl as u64);
    set_timeo(fd, 100);
    t.eq(b"blocking again (timeout)", recv(fd, &mut buf, 0), EAGAIN);
    close(fd);
    t.done();
}

/// FIONBIO sets the file's O_NONBLOCK
fn test_fionbio() {
    let mut t = T::new(b"NONBLOCK_FIONBIO");
    let (fd, _) = udp_lo();
    let one = 1i32;
    t.eq(b"ioctl", sys_ioctl(fd, FIONBIO, &one as *const i32 as u64), 0);
    t.ok(b"F_GETFL", sys_fcntl(fd, F_GETFL, 0) & O_NONBLOCK as i64 != 0, 0);
    let mut buf = [0u8; 4];
    t.eq(b"EAGAIN", recv(fd, &mut buf, 0), EAGAIN);
    close(fd);
    t.done();
}

/// SOCK_NONBLOCK|SOCK_CLOEXEC at creation
fn test_sock_nonblock() {
    let mut t = T::new(b"NONBLOCK_SOCK_FLAGS");
    let fd = sys_socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) as i32;
    t.ok(b"O_NONBLOCK", sys_fcntl(fd, F_GETFL, 0) & O_NONBLOCK as i64 != 0, 0);
    t.eq(b"FD_CLOEXEC", sys_fcntl(fd, F_GETFD, 0), 1);
    close(fd);
    t.done();
}

fn set_timeo(fd: i32, ms: u64) {
    let tv = [(ms / 1000) as i64, ((ms % 1000) * 1000) as i64];
    sys_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv.as_ptr() as *const u8, 16);
}

/// SO_RCVTIMEO: a blocking recv gives up with EAGAIN after ~300 ms
fn test_rcvtimeo() {
    let mut t = T::new(b"NONBLOCK_RCVTIMEO");
    let (fd, _) = udp_lo();
    set_timeo(fd, 300);
    let t0 = now_ms();
    let mut buf = [0u8; 4];
    let r = recv(fd, &mut buf, 0);
    let dt = now_ms() - t0;
    t.eq(b"EAGAIN", r, EAGAIN);
    t.ok(b"elapsed", (290..1500).contains(&dt), dt as i64);
    close(fd);
    t.done();
}

#[repr(C)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn restorer() -> ! {
    core::arch::naked_asm!("mov rax, 15", "syscall", "ud2")
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn restorer() -> ! {
    core::arch::naked_asm!("mov x8, 139", "svc 0", "brk 0")
}

static HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sig(_s: i32) {
    HITS.store(HITS.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

fn sigaction(sig: u32, handler: u64, flags: u64) {
    let a = SigAction { handler, flags: flags | SA_RESTORER, restorer: restorer as *const () as u64, mask: 0 };
    sys_rt_sigaction(sig, &a as *const SigAction as u64, 0, 8);
}

static mut DEST_PORT: u16 = 0;

/// Child: after 150 ms signal the parent; after 300 ms send it a datagram
fn signal_then_send() -> ! {
    msleep(150);
    sys_kill(sys_getppid(), SIGUSR1);
    msleep(150);
    let fd = udp();
    send_to(fd, b"late", LO, unsafe { DEST_PORT }, 0);
    sys_exit(0)
}

/// One blocking recv while a child signals and then sends
fn recv_with_signal(flags: u64, timeo_ms: u64) -> i64 {
    let (fd, p) = udp_lo();
    if timeo_ms != 0 {
        set_timeo(fd, timeo_ms);
    }
    unsafe { DEST_PORT = p };
    sigaction(SIGUSR1, on_sig as *const () as u64, flags);
    let pid = sys_fork();
    if pid == 0 {
        signal_then_send();
    }
    let mut buf = [0u8; 8];
    let r = recv(fd, &mut buf, 0);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    sigaction(SIGUSR1, SIG_DFL, 0);
    close(fd);
    r
}

/// Signals: EINTR without SA_RESTART; restarted with SA_RESTART (the
/// later datagram is returned); EINTR with SA_RESTART when SO_RCVTIMEO
/// is set (Linux sock_intr_errno)
fn test_signals() {
    let mut t = T::new(b"NONBLOCK_EINTR");
    HITS.store(0, Ordering::Relaxed);
    t.eq(b"no SA_RESTART", recv_with_signal(0, 0), EINTR);
    t.eq(b"SA_RESTART", recv_with_signal(SA_RESTART, 0), 4);
    t.eq(b"SA_RESTART + timeout", recv_with_signal(SA_RESTART, 5000), EINTR);
    t.eq(b"handler runs", HITS.load(Ordering::Relaxed) as i64, 3);
    t.done();
}

/// FIONREAD: UDP = first datagram's size, TCP = queued bytes;
/// SIOCOUTQ is 0 once sent
fn test_fionread() {
    let mut t = T::new(b"NONBLOCK_FIONREAD");
    let (a, _) = udp_lo();
    let (b, pb) = udp_lo();
    send_to(a, &[1u8; 10], LO, pb, 0);
    send_to(a, &[2u8; 20], LO, pb, 0);
    let mut v = -1i32;
    t.eq(b"ioctl", sys_ioctl(b, FIONREAD, &mut v as *mut i32 as u64), 0);
    t.eq(b"udp first", v as i64, 10);
    sys_ioctl(a, SIOCOUTQ, &mut v as *mut i32 as u64);
    t.eq(b"outq", v as i64, 0);
    close(a);
    close(b);
    let (l, c, s) = tcp_pair();
    send(c, b"0123456", 0);
    msleep(50);
    sys_ioctl(s, FIONREAD, &mut v as *mut i32 as u64);
    t.eq(b"tcp bytes", v as i64, 7);
    for f in [l, c, s] {
        close(f);
    }
    t.done();
}

/// A connected TCP pair over lo: (listener, client, server side)
fn tcp_pair() -> (i32, i32, i32) {
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, 4);
    let c = tcp();
    connect(c, LO, port(l));
    let s = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    (l, c, s)
}

/// Sending after SHUT_WR: EPIPE; SIGPIPE kills unless MSG_NOSIGNAL or
/// SIGPIPE is ignored (checked in children: init ignores SIGPIPE)
fn test_epipe() {
    let mut t = T::new(b"NONBLOCK_EPIPE");
    let pid = sys_fork();
    if pid == 0 {
        let (_l, c, _s) = tcp_pair();
        sys_shutdown(c, SHUT_WR);
        if send(c, b"x", MSG_NOSIGNAL) != EPIPE {
            sys_exit(1);
        }
        sigaction(SIGPIPE, SIG_IGN, 0);
        if send(c, b"x", 0) != EPIPE {
            sys_exit(2);
        }
        sigaction(SIGPIPE, SIG_DFL, 0);
        send(c, b"x", 0);
        sys_exit(3);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"killed by SIGPIPE", (st & 0x7f) as i64, SIGPIPE as i64);
    t.done();
}

/// Non-blocking accept: EAGAIN, then POLLIN on the listener once a
/// connection is pending; accept4 flags land on the new descriptor
fn test_tcp_accept() {
    let mut t = T::new(b"NONBLOCK_ACCEPT");
    let l = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0) as i32;
    bind(l, LO, 0);
    sys_listen(l, 4);
    t.eq(b"EAGAIN", sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()), EAGAIN);
    t.eq(b"poll idle", poll1(l, POLLIN, 0).0, 0);
    let c = tcp();
    connect(c, LO, port(l));
    let (n, ev) = poll1(l, POLLIN, 2000);
    t.ok(b"poll ready", n == 1 && ev & POLLIN != 0, ev as i64);
    t.eq(b"accept4 bad flags", sys_accept4(l, core::ptr::null_mut(), core::ptr::null_mut(), 1), EINVAL);
    let s = sys_accept4(l, core::ptr::null_mut(), core::ptr::null_mut(), SOCK_NONBLOCK | SOCK_CLOEXEC) as i32;
    t.ok(b"accept4", s >= 0, s as i64);
    t.ok(b"new O_NONBLOCK", sys_fcntl(s, F_GETFL, 0) & O_NONBLOCK as i64 != 0, 0);
    t.eq(b"new FD_CLOEXEC", sys_fcntl(s, F_GETFD, 0), 1);
    for f in [l, c, s] {
        close(f);
    }
    t.done();
}

static mut PEER_FD: i32 = -1;

/// TCP receive flags: MSG_PEEK leaves data queued; MSG_WAITALL waits
/// for the whole request across several sends (from a child)
fn test_tcp_recv_flags() {
    let mut t = T::new(b"NONBLOCK_TCP_RECV_FLAGS");
    let (l, c, s) = tcp_pair();
    send(c, b"abcd", 0);
    msleep(20);
    let mut buf = [0u8; 16];
    t.eq(b"peek", recv(s, &mut buf, MSG_PEEK), 4);
    t.eq(b"after peek", recv(s, &mut buf, 0), 4);
    unsafe { PEER_FD = c };
    let pid = sys_fork();
    if pid == 0 {
        for chunk in [b"0123", b"4567", b"89ab"] {
            msleep(50);
            send(unsafe { PEER_FD }, chunk, 0);
        }
        sys_exit(0);
    }
    let n = recv(s, &mut buf[..12], MSG_WAITALL);
    t.ok(b"waitall", n == 12 && &buf[..12] == b"0123456789ab", n);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    for f in [l, c, s] {
        close(f);
    }
    t.done();
}

/// After the peer's SHUT_WR: POLLIN|POLLRDHUP and recv returns 0
fn test_tcp_rdhup() {
    let mut t = T::new(b"NONBLOCK_TCP_RDHUP");
    let (l, c, s) = tcp_pair();
    sys_shutdown(c, SHUT_WR);
    let (n, ev) = poll1(s, POLLIN | POLLRDHUP, 2000);
    t.ok(b"poll", n == 1 && ev & POLLIN != 0 && ev & POLLRDHUP != 0, ev as i64);
    let mut buf = [0u8; 4];
    t.eq(b"eof", recv(s, &mut buf, 0), 0);
    t.ok(b"writable", poll1(s, POLLOUT, 0).1 & POLLOUT != 0, 0);
    for f in [l, c, s] {
        close(f);
    }
    t.done();
}

/// Non-blocking connect to a listener: EINPROGRESS (or done at once),
/// then POLLOUT and SO_ERROR 0; the next connect reports completion (0),
/// then EISCONN
fn test_tcp_nb_connect() {
    let mut t = T::new(b"NONBLOCK_CONNECT");
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, 4);
    let c = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0) as i32;
    let r = connect(c, LO, port(l));
    t.ok(b"connect", r == 0 || r == EINPROGRESS, r);
    let (n, ev) = poll1(c, POLLOUT, 2000);
    t.ok(b"pollout", n == 1 && ev & POLLOUT != 0, ev as i64);
    t.eq(b"SO_ERROR", getint(c, SOL_SOCKET, SO_ERROR).1 as i64, 0);
    // Linux SS_CONNECTING: the next connect reports success, then EISCONN
    if r == EINPROGRESS {
        t.eq(b"completion", connect(c, LO, port(l)), 0);
    }
    t.eq(b"again", connect(c, LO, port(l)), EISCONN);
    close(c);
    close(l);
    t.done();
}
