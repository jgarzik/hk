//! TCP data transfer (hk and Linux): 2 MB each way over lo, 2 MB through
//! the slirp echo peer on eth0, a slow reader closing and reopening the
//! window, MSG_WAITALL across sends, MSG_PEEK, EFAULT keeping data
//! queued, and 50 concurrent connections.

use hk_syscall::{
    SHUT_WR, Timespec, sys_accept, sys_exit, sys_fork, sys_listen, sys_nanosleep, sys_setsockopt,
    sys_shutdown, sys_wait4,
};

use super::sk::*;

/// slirp guestfwd echo service (tools/qemu-net.sh)
const ECHO: [u8; 4] = [10, 0, 2, 100];
const MB: usize = 1024 * 1024;

pub fn run_tests() {
    super::helpers::println(b"=== TCP Transfer Tests ===");
    test_lo_2mb();
    test_slow_reader();
    test_waitall();
    test_many();
    test_echo_2mb();
}

fn msleep(ms: u64) {
    let ts = Timespec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// SO_RCVTIMEO / SO_SNDTIMEO of `ms`
pub fn set_timeo(fd: i32, ms: u64) {
    let tv = [(ms / 1000) as i64, ((ms % 1000) * 1000) as i64];
    for opt in [SO_RCVTIMEO, SO_SNDTIMEO] {
        sys_setsockopt(fd, SOL_SOCKET, opt, tv.as_ptr() as *const u8, 16);
    }
}

/// Byte `i` of a test stream (`seed` tells streams apart)
pub fn pat(seed: usize, i: usize) -> u8 {
    (i.wrapping_mul(7) ^ (i >> 9) ^ seed) as u8
}

/// Send `total` pattern bytes; returns bytes sent or -errno
pub fn send_pat(fd: i32, seed: usize, total: usize) -> i64 {
    let mut buf = [0u8; 16384];
    let mut off = 0;
    while off < total {
        let n = (total - off).min(buf.len());
        for (k, b) in buf[..n].iter_mut().enumerate() {
            *b = pat(seed, off + k);
        }
        let mut done = 0;
        while done < n {
            let r = send(fd, &buf[done..n], MSG_NOSIGNAL);
            if r <= 0 {
                return if off + done > 0 {
                    (off + done) as i64
                } else {
                    r
                };
            }
            done += r as usize;
        }
        off += n;
    }
    total as i64
}

/// Receive and check pattern bytes until `total` or EOF/error, reading
/// at most `step` bytes per call: (bytes, first bad offset or -1, last
/// return)
pub fn recv_pat(fd: i32, seed: usize, total: usize, step: usize) -> (usize, i64, i64) {
    let mut buf = [0u8; 16384];
    let step = step.min(buf.len());
    let (mut got, mut bad) = (0usize, -1i64);
    loop {
        if got >= total {
            return (got, bad, 0);
        }
        let r = recv(fd, &mut buf[..step.min(total - got)], 0);
        if r <= 0 {
            return (got, bad, r);
        }
        for (k, &b) in buf[..r as usize].iter().enumerate() {
            if bad < 0 && b != pat(seed, got + k) {
                bad = (got + k) as i64;
            }
        }
        got += r as usize;
    }
}

/// A listener on 127.0.0.1 (ephemeral port, backlog `n`)
pub fn listener(n: i32) -> (i32, u16) {
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, n);
    (l, port(l))
}

pub fn accept(l: i32) -> i32 {
    sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32
}

pub fn wait_child(pid: i64) -> i32 {
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

/// 2 MB client -> server, then 2 MB back, both checked byte by byte
fn test_lo_2mb() {
    let mut t = T::new(b"TCP_LO_2MB");
    let (l, p) = listener(4);
    let pid = sys_fork();
    if pid == 0 {
        let c = tcp();
        set_timeo(c, 30_000);
        if connect(c, LO, p) != 0 {
            sys_exit(1);
        }
        if send_pat(c, 1, 2 * MB) != (2 * MB) as i64 {
            sys_exit(2);
        }
        let (n, bad, _) = recv_pat(c, 2, 2 * MB, 16384);
        sys_exit(if n != 2 * MB {
            3
        } else if bad >= 0 {
            4
        } else {
            0
        });
    }
    let s = accept(l);
    set_timeo(s, 30_000);
    let (n, bad, last) = recv_pat(s, 1, 2 * MB, 16384);
    t.eq(b"server got", n as i64, (2 * MB) as i64);
    t.eq(b"server data", bad, -1);
    if n != 2 * MB {
        t.eq(b"server last", last, 0);
    }
    t.eq(b"server sent", send_pat(s, 2, 2 * MB), (2 * MB) as i64);
    t.eq(b"client status", wait_child(pid) as i64, 0);
    close(s);
    close(l);
    t.done();
}

/// A receiver with a 4 KB buffer that sleeps, then reads in small
/// pieces: the window closes (sender blocks, zero-window probes) and
/// reopens; all 300 KB arrive in order
fn test_slow_reader() {
    let mut t = T::new(b"TCP_ZERO_WINDOW");
    const LEN: usize = 300 * 1024;
    let l = tcp();
    setint(l, SOL_SOCKET, SO_RCVBUF, 4096);
    bind(l, LO, 0);
    sys_listen(l, 4);
    let p = port(l);
    let pid = sys_fork();
    if pid == 0 {
        let c = tcp();
        set_timeo(c, 60_000);
        if connect(c, LO, p) != 0 {
            sys_exit(1);
        }
        let r = send_pat(c, 3, LEN);
        sys_exit(if r == LEN as i64 { 0 } else { 2 });
    }
    let s = accept(l);
    set_timeo(s, 60_000);
    msleep(400);
    // Little got through while nobody read
    let mut q = 0i32;
    hk_syscall::sys_ioctl(s, 0x541B /* FIONREAD */, &mut q as *mut i32 as u64);
    t.ok(b"queued while stalled", q > 0 && q <= 64 * 1024, q as i64);
    let (n, bad, _) = recv_pat(s, 3, LEN, 1000);
    t.eq(b"got", n as i64, LEN as i64);
    t.eq(b"data", bad, -1);
    t.eq(b"sender status", wait_child(pid) as i64, 0);
    close(s);
    close(l);
    t.done();
}

/// MSG_WAITALL collects 150 KB sent in three delayed pieces; MSG_PEEK
/// leaves data queued
fn test_waitall() {
    let mut t = T::new(b"TCP_WAITALL_PEEK");
    let (l, p) = listener(4);
    let pid = sys_fork();
    if pid == 0 {
        let c = tcp();
        set_timeo(c, 30_000);
        if connect(c, LO, p) != 0 {
            sys_exit(1);
        }
        let mut buf = [0u8; 16384];
        let mut off = 0;
        for _ in 0..3 {
            msleep(100);
            let end = off + 50_000;
            while off < end {
                let n = (end - off).min(buf.len());
                for (k, b) in buf[..n].iter_mut().enumerate() {
                    *b = pat(4, off + k);
                }
                if send(c, &buf[..n], 0) != n as i64 {
                    sys_exit(2);
                }
                off += n;
            }
        }
        msleep(100);
        send(c, b"xyz", 0);
        msleep(200);
        sys_exit(0);
    }
    let s = accept(l);
    set_timeo(s, 30_000);
    // 150000 bytes in one call (a static buffer: too big for the stack
    // of a forked child is not an issue here, the parent has 1 MB)
    static mut BIG: [u8; 150_000] = [0; 150_000];
    let big = unsafe { &mut *core::ptr::addr_of_mut!(BIG) };
    let n = recv(s, big, MSG_WAITALL);
    t.eq(b"waitall", n, 150_000);
    let bad = (0..150_000).find(|&i| big[i] != pat(4, i));
    t.ok(b"waitall data", bad.is_none(), bad.map_or(0, |b| b as i64));
    let mut b = [0u8; 8];
    t.eq(b"peek", recv(s, &mut b, MSG_PEEK), 3);
    // A faulting copy leaves the data queued
    let r = hk_syscall::sys_recvfrom(
        s,
        BAD as *mut u8,
        8,
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    t.eq(b"efault", r, EFAULT);
    t.eq(b"peek again", recv(s, &mut b, MSG_PEEK), 3);
    t.eq(b"read", recv(s, &mut b, 0), 3);
    t.ok(b"bytes", &b[..3] == b"xyz", 0);
    t.eq(b"child", wait_child(pid) as i64, 0);
    close(s);
    close(l);
    t.done();
}

/// 50 connections open at once, each carrying data both ways
fn test_many() {
    let mut t = T::new(b"TCP_50_CONNECTIONS");
    const N: usize = 50;
    let (l, p) = listener(64);
    let mut c = [-1i32; N];
    let mut s = [-1i32; N];
    for i in 0..N {
        c[i] = tcp();
        if !t.eq(b"connect", connect(c[i], LO, p), 0) {
            break;
        }
    }
    for i in 0..N {
        s[i] = accept(l);
        if !t.ok(b"accept", s[i] >= 0, s[i] as i64) {
            break;
        }
        set_timeo(s[i], 10_000);
        set_timeo(c[i], 10_000);
    }
    for i in 0..N {
        let msg = [i as u8; 100];
        send(c[i], &msg, 0);
        send(s[i], &msg, 0);
    }
    let mut buf = [0u8; 100];
    for i in 0..N {
        for fd in [s[i], c[i]] {
            let n = recv(fd, &mut buf, MSG_WAITALL);
            if !t.eq(b"recv", n, 100) || !t.ok(b"data", buf.iter().all(|&b| b == i as u8), i as i64)
            {
                break;
            }
        }
    }
    for i in 0..N {
        close(c[i]);
        close(s[i]);
    }
    close(l);
    t.done();
}

/// 2 MB through the echo peer: a child sends and half-closes, the
/// parent reads the echo until EOF
fn test_echo_2mb() {
    let mut t = T::new(b"TCP_ECHO_2MB");
    if let Err(e) = super::nl::net_setup_eth0() {
        t.ok(e.as_bytes(), false, 0);
        return t.done();
    }
    let fd = tcp();
    set_timeo(fd, 30_000);
    let r = connect(fd, ECHO, 7);
    if !t.eq(b"connect", r, 0) {
        close(fd);
        return t.done();
    }
    let pid = sys_fork();
    if pid == 0 {
        let r = send_pat(fd, 5, 2 * MB);
        sys_shutdown(fd, SHUT_WR);
        sys_exit(if r == (2 * MB) as i64 { 0 } else { 1 });
    }
    let (n, bad, last) = recv_pat(fd, 5, 2 * MB + 1, 16384);
    t.eq(b"echoed", n as i64, (2 * MB) as i64);
    t.eq(b"data", bad, -1);
    t.eq(b"eof", last, 0);
    t.eq(b"sender", wait_child(pid) as i64, 0);
    close(fd);
    t.done();
}
