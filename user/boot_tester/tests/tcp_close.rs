//! Releasing lingering TCP sockets (hk and Linux): a close or dup2
//! whose SO_LINGER wait blocks never stalls other tasks sharing the
//! descriptor table (CLONE_FILES); an exiting process never lingers.

use hk_syscall::{
    Timespec, sys_clone, sys_close, sys_exit, sys_fcntl, sys_fork, sys_listen, sys_nanosleep,
    sys_pipe, sys_read, sys_write,
};

use super::sk::*;
use super::tcp_xfer::{accept, set_timeo, wait_child};

const CLONE_FILES: u64 = 0x400;
const SIGCHLD: u64 = 17;
const F_DUPFD: i32 = 0;
/// SO_LINGER {1, LINGER_S}
const LINGER_S: i32 = 5;

pub fn run_tests() {
    super::helpers::println(b"=== TCP Close Tests ===");
    test_close_linger();
    test_dup2_linger();
    test_exit_linger();
}

fn msleep(ms: u64) {
    let ts = Timespec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// A listener whose connections get a small receive buffer
fn small_listener() -> i32 {
    let l = tcp();
    setint(l, SOL_SOCKET, SO_RCVBUF, 4096);
    bind(l, LO, 0);
    sys_listen(l, 4);
    l
}

/// Connect to `l` and fill the connection (the server never reads),
/// so FIN waits behind unacknowledged data; SO_LINGER {1, LINGER_S}
fn stuck_client(l: i32) -> i32 {
    let c = tcp();
    setint(c, SOL_SOCKET, SO_SNDBUF, 4096);
    set_timeo(c, 10_000);
    connect(c, LO, port(l));
    let buf = [0x5au8; 1024];
    let t0 = now_ms();
    while send(c, &buf, MSG_DONTWAIT) > 0 && now_ms() - t0 < 5000 {}
    // Let the window close (the last segments reach the peer)
    msleep(50);
    let lg = [1i32, LINGER_S];
    hk_syscall::sys_setsockopt(c, SOL_SOCKET, SO_LINGER, lg.as_ptr() as *const u8, 8);
    c
}

/// A connection whose client end cannot finish closing: (listener,
/// client, server)
fn stuck_conn() -> (i32, i32, i32) {
    let l = small_listener();
    let c = stuck_client(l);
    (l, c, accept(l))
}

/// A task sharing our descriptor table: once `go` is readable it waits
/// 300 ms (the parent is in its blocking close by then), then times 50
/// dup/close rounds; exit 0 if they took under 1.5 s
fn sibling(go: i32) -> i64 {
    let pid = sys_clone(CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    if pid != 0 {
        return pid;
    }
    let mut b = [0u8; 1];
    sys_read(go as u64, b.as_mut_ptr(), 1);
    msleep(300);
    let t0 = now_ms();
    for _ in 0..50 {
        let fd = sys_fcntl(go, F_DUPFD, 0);
        if fd < 0 {
            sys_exit(2);
        }
        sys_close(fd as u64);
    }
    sys_exit(if now_ms() - t0 < 1500 { 0 } else { 1 });
}

/// Run `release` on the client of a stuck connection while a CLONE_FILES
/// sibling uses the table; returns (release result, its ms, sibling
/// status, client fd)
fn with_sibling(release: impl FnOnce(i32) -> i64) -> (i64, u64, i32, i32) {
    let (l, c, s) = stuck_conn();
    let mut p = [-1i32; 2];
    sys_pipe(p.as_mut_ptr());
    let pid = sibling(p[0]);
    sys_write(p[1] as u64, b"g".as_ptr(), 1);
    let t0 = now_ms();
    let r = release(c);
    let ms = now_ms() - t0;
    let st = wait_child(pid);
    close(p[0]);
    close(p[1]);
    close(s);
    close(l);
    (r, ms, st, c)
}

/// close() of a lingering socket blocks for the linger time (Linux
/// sk_stream_wait_close) without holding the descriptor table: the
/// sibling's dup/close calls finish meanwhile
fn test_close_linger() {
    let mut t = T::new(b"TCP_CLOSE_LINGER_SIBLING");
    let (r, ms, st, _) = with_sibling(|c| sys_close(c as u64));
    t.eq(b"close", r, 0);
    t.eq(b"sibling not blocked", st as i64, 0);
    t.ok(b"lingered", ms >= 3000 && ms < 15_000, ms as i64);
    t.done();
}

/// dup2 over a lingering socket releases it like close (Linux do_dup2
/// -> filp_close after unlocking the table)
fn test_dup2_linger() {
    let mut t = T::new(b"TCP_DUP2_LINGER_SIBLING");
    let mut q = [-1i32; 2];
    sys_pipe(q.as_mut_ptr());
    let (r, ms, st, c) = with_sibling(|c| dup2(q[0], c));
    t.ok(b"dup2", r >= 0 && r as i32 == c, r);
    t.eq(b"sibling not blocked", st as i64, 0);
    t.ok(b"lingered", ms >= 3000 && ms < 15_000, ms as i64);
    t.eq(
        b"not a socket now",
        getint(c, SOL_SOCKET, SO_TYPE).0,
        ENOTSOCK,
    );
    close(c);
    close(q[0]);
    close(q[1]);
    t.done();
}

/// _exit with a lingering socket does not wait (Linux inet_release
/// skips the linger time under PF_EXITING): the child is reaped at once
fn test_exit_linger() {
    let mut t = T::new(b"TCP_EXIT_NO_LINGER");
    let l = small_listener();
    let mut p = [-1i32; 2];
    sys_pipe(p.as_mut_ptr());
    let pid = sys_fork();
    if pid == 0 {
        let _c = stuck_client(l);
        sys_write(p[1] as u64, b"x".as_ptr(), 1);
        sys_exit(0);
    }
    set_timeo(l, 10_000);
    let s = accept(l);
    let mut b = [0u8; 1];
    t.eq(b"ready", sys_read(p[0] as u64, b.as_mut_ptr(), 1), 1);
    let t0 = now_ms();
    let st = wait_child(pid);
    let ms = now_ms() - t0;
    t.eq(b"status", st as i64, 0);
    t.ok(b"prompt exit", ms < 2000, ms as i64);
    close(s);
    close(p[0]);
    close(p[1]);
    close(l);
    t.done();
}

#[cfg(target_arch = "x86_64")]
fn dup2(old: i32, new: i32) -> i64 {
    hk_syscall::sys_dup2(old, new)
}

/// aarch64 has no dup2: dup3 shares its replace path
#[cfg(not(target_arch = "x86_64"))]
fn dup2(old: i32, new: i32) -> i64 {
    hk_syscall::sys_dup3(old, new, 0)
}
