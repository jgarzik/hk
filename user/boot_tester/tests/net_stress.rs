//! Network concurrency stress (hk and Linux): processes churn TCP and
//! UDP sockets over lo and eth0 (slirp echo peer) while another changes
//! the configuration (addresses, routes, eth0 down/up) and another
//! passes descriptors over unix sockets; plus TCP readers racing
//! MSG_TRUNC discards on one connection. Pass = every worker finishes
//! in time with no unexpected error and the stack still works after.
//! (Run with `make check LOCKDEP=1` to check lock order and sleeping
//! under spinlocks along the way.)

use hk_syscall::{
    AF_UNIX, IoVec, MsgHdr, SOCK_DGRAM, sys_accept, sys_exit, sys_fork, sys_kill, sys_listen,
    sys_pipe, sys_recvmsg, sys_setsockopt, sys_socketpair, sys_wait4,
};

use super::nl::{Nl, addr, first_ether, msleep, net_setup_eth0, route, set_link_up};
use super::sk::*;
use super::tcp_xfer::set_timeo;

const ECHO: [u8; 4] = [10, 0, 2, 100];
/// How long the churn workers run
const RUN_MS: u64 = 3000;
/// Connections per TCP worker: each active close leaves a TIME_WAIT
/// entry for 60 s (about 2 KB of hk's small x86 heap)
const MAX_CONNS: u32 = 40;
/// Whole stress bound (a hang fails instead of stalling the suite)
const LIMIT_MS: u64 = 60_000;
const WNOHANG: i32 = 1;
const SIGKILL: u32 = 9;

pub fn run_tests() {
    super::helpers::println(b"=== Network Stress Tests ===");
    test_churn();
    test_trunc_race();
}

/// Run `f` in a child; returns its pid
fn spawn(f: fn(u64) -> i32, until: u64) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f(until) as u64);
    }
    pid
}

/// Reap `pids` within LIMIT_MS: (all exited, worst status)
fn reap(pids: &[i64]) -> (bool, i32) {
    let t0 = now_ms();
    let mut left = pids.len();
    let mut done = [false; 16];
    let mut worst = 0;
    while left > 0 && now_ms() - t0 < LIMIT_MS {
        for (i, &p) in pids.iter().enumerate() {
            if done[i] {
                continue;
            }
            let mut st = 0i32;
            if sys_wait4(p, &mut st, WNOHANG, 0) == p {
                done[i] = true;
                left -= 1;
                if st != 0 && worst == 0 {
                    worst = st;
                }
            }
        }
        msleep(20);
    }
    for (i, &p) in pids.iter().enumerate() {
        if !done[i] {
            sys_kill(p, SIGKILL);
            let mut st = 0i32;
            sys_wait4(p, &mut st, 0, 0);
        }
    }
    (left == 0, worst)
}

/// One lo TCP connection: connect, 4 KB each way, close (sometimes
/// with SO_LINGER {1,1} or {1,0}); 1 on an unexpected error
fn tcp_lo_once(l: i32, port: u16, i: u32) -> i32 {
    let c = tcp();
    set_timeo(c, 5000);
    if connect(c, LO, port) != 0 {
        close(c);
        return 1;
    }
    let s = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    if s < 0 {
        close(c);
        return 1;
    }
    set_timeo(s, 5000);
    let buf = [i as u8; 4096];
    let mut r = [0u8; 4096];
    let ok = send(c, &buf, 0) == 4096
        && recv(s, &mut r, MSG_WAITALL) == 4096
        && send(s, &r, 0) == 4096
        && recv(c, &mut r, MSG_WAITALL) == 4096
        && r[0] == i as u8;
    let lg = [1i32, (i % 2) as i32];
    if i % 3 == 0 {
        sys_setsockopt(c, SOL_SOCKET, SO_LINGER, lg.as_ptr() as *const u8, 8);
    }
    close(c);
    close(s);
    if ok { 0 } else { 1 }
}

fn w_tcp_lo(until: u64) -> i32 {
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, 8);
    let port = super::sk::port(l);
    set_timeo(l, 5000);
    let mut i = 0;
    while now_ms() < until && i < MAX_CONNS {
        if tcp_lo_once(l, port, i) != 0 {
            return 1;
        }
        i += 1;
    }
    close(l);
    0
}

fn w_udp_lo(until: u64) -> i32 {
    let mut b = [0u8; 512];
    while now_ms() < until {
        let (a, pa) = udp_lo();
        let c = udp();
        set_timeo(a, 2000);
        connect(c, LO, pa);
        if send(c, &b, 0) != 512 || recv(a, &mut b, 0) != 512 {
            return 1;
        }
        close(c);
        close(a);
    }
    0
}

/// eth0 echo through slirp; failures are expected while the config
/// worker has the link down, only a hang matters
fn w_tcp_eth(until: u64) -> i32 {
    let msg = [0x42u8; 1024];
    let mut r = [0u8; 1024];
    let mut n = 0;
    while now_ms() < until && n < MAX_CONNS {
        n += 1;
        let c = tcp();
        set_timeo(c, 1000);
        if connect(c, ECHO, 7) == 0 && send(c, &msg, 0) == 1024 {
            let _ = recv(c, &mut r, MSG_WAITALL);
        }
        close(c);
        msleep(10);
    }
    0
}

/// Addresses and routes on lo, eth0 down/up (NETLINK_ROUTE)
fn w_config(until: u64) -> i32 {
    const NLM_F_CREATE: u16 = 0x400;
    let Some(mut nl) = Nl::open() else {
        return 1;
    };
    let eth = first_ether(&mut nl).map(|l| l.index);
    let mut i = 0u32;
    while now_ms() < until {
        let a = [10, 77, (i % 200) as u8, 1];
        addr(&mut nl, true, 1, a, 24, NLM_F_CREATE);
        route(
            &mut nl,
            true,
            [10, 78, (i % 200) as u8, 0],
            24,
            [0; 4],
            1,
            NLM_F_CREATE,
        );
        route(
            &mut nl,
            false,
            [10, 78, (i % 200) as u8, 0],
            24,
            [0; 4],
            1,
            0,
        );
        addr(&mut nl, false, 1, a, 24, 0);
        if let Some(e) = eth
            && i % 8 == 7
        {
            set_link_up(&mut nl, e, false);
            msleep(20);
            set_link_up(&mut nl, e, true);
        }
        i += 1;
        msleep(5);
    }
    0
}

/// SCM_RIGHTS churn: another socket pair's ends in flight, received or
/// released with the receiving socket (not pipes: each pipe leaks its
/// file ops today, see BUGS.md; not the pair itself: a socket in flight
/// in its own queue is a cycle only a unix GC frees)
fn w_unix(until: u64) -> i32 {
    let mut i = 0u32;
    while now_ms() < until {
        let mut sv = [-1i32; 2];
        let mut x = [-1i32; 2];
        if sys_socketpair(AF_UNIX, SOCK_DGRAM, 0, &mut sv) != 0
            || sys_socketpair(AF_UNIX, SOCK_DGRAM, 0, &mut x) != 0
        {
            return 1;
        }
        if super::unix::send_fds(sv[0], b"f", &[x[0], x[1]]) < 0 {
            return 1;
        }
        // Receive one message out of two: the other stays in flight
        // and is released with the receiving socket
        if i % 2 == 0 {
            let mut b = [0u8; 4];
            let mut ctl = [0u8; 128];
            let mut iov = IoVec {
                iov_base: b.as_mut_ptr(),
                iov_len: 4,
            };
            let mut m = MsgHdr::new(&mut iov, 1);
            m.msg_control = ctl.as_mut_ptr();
            m.msg_controllen = ctl.len();
            if sys_recvmsg(sv[1], &mut m, 0) > 0 {
                let (fd, n) = super::unix::got_fds(&ctl, m.msg_controllen);
                for k in 0..n as i32 {
                    close(fd + k);
                }
            }
        }
        for fd in [x[0], x[1], sv[0], sv[1]] {
            close(fd);
        }
        i += 1;
    }
    0
}

/// Many processes at once on every path; the stack works afterwards
fn test_churn() {
    let mut t = T::new(b"NET_STRESS_CHURN");
    // No Ethernet link: the eth0 workers just fail their connects
    let _ = net_setup_eth0();
    let until = now_ms() + RUN_MS;
    let workers: [fn(u64) -> i32; 8] = [
        w_tcp_lo, w_tcp_lo, w_tcp_lo, w_udp_lo, w_tcp_eth, w_tcp_eth, w_config, w_unix,
    ];
    let mut pids = [0i64; 8];
    for (i, w) in workers.iter().enumerate() {
        pids[i] = spawn(*w, until);
    }
    let (all, worst) = reap(&pids);
    t.ok(b"all workers finished", all, 0);
    t.eq(b"worker status", worst as i64, 0);
    // Restore the Ethernet configuration later tests rely on
    let _ = net_setup_eth0();
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, 4);
    set_timeo(l, 5000);
    t.eq(
        b"lo works after",
        tcp_lo_once(l, super::sk::port(l), 7) as i64,
        0,
    );
    close(l);
    t.done();
}

/// Readers race on one connection: two copy, one discards with
/// MSG_TRUNC; every byte is consumed exactly once (a 4-byte sequence
/// number stream read in whole words: copied words strictly increase,
/// consecutive within a read; counts add up)
fn test_trunc_race() {
    let mut t = T::new(b"NET_STRESS_TRUNC_RACE");
    const WORDS: u32 = 64 * 1024;
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, 4);
    let port = super::sk::port(l);
    let c = tcp();
    set_timeo(c, 10_000);
    connect(c, LO, port);
    let s = sys_accept(l, core::ptr::null_mut(), core::ptr::null_mut()) as i32;
    set_timeo(s, 2000);
    // Counts come back through a pipe: (copied words, discarded words)
    let mut p = [-1i32; 2];
    sys_pipe(p.as_mut_ptr());
    let mut pids = [0i64; 3];
    for (k, pid) in pids.iter_mut().enumerate() {
        *pid = sys_fork();
        if *pid == 0 {
            close(c);
            let r = trunc_reader(s, k == 2);
            let b = r.to_ne_bytes();
            hk_syscall::sys_write(p[1] as u64, b.as_ptr(), 8);
            sys_exit(if r < 0 { 1 } else { 0 });
        }
    }
    close(s);
    let mut buf = [0u8; 4096];
    let mut n = 0u32;
    while n < WORDS {
        for w in 0..1024u32 {
            buf[(w * 4) as usize..(w * 4 + 4) as usize].copy_from_slice(&(n + w).to_be_bytes());
        }
        if send(c, &buf, 0) != 4096 {
            break;
        }
        n += 1024;
    }
    hk_syscall::sys_shutdown(c, hk_syscall::SHUT_WR);
    let (all, worst) = reap(&pids);
    let mut total = 0i64;
    for _ in 0..3 {
        let mut b = [0u8; 8];
        if hk_syscall::sys_read(p[0] as u64, b.as_mut_ptr(), 8) == 8 {
            total += i64::from_ne_bytes(b).max(0);
        }
    }
    t.ok(b"readers finished", all, 0);
    t.eq(b"reader status", worst as i64, 0);
    t.eq(b"words consumed", total, WORDS as i64);
    for fd in [c, l, p[0], p[1]] {
        close(fd);
    }
    t.done();
}

/// Read 4-word-aligned pieces until EOF: Some count, -1 on a broken
/// sequence; `trunc` discards with MSG_TRUNC instead of copying
fn trunc_reader(s: i32, trunc: bool) -> i64 {
    let mut b = [0u8; 1024];
    let mut words = 0i64;
    let mut last: i64 = -1;
    loop {
        let flags = MSG_WAITALL | if trunc { MSG_TRUNC } else { 0 };
        let n = recv(s, &mut b[..256], flags);
        if n <= 0 {
            return if n == 0 || n == EAGAIN { words } else { -1 };
        }
        if n % 4 != 0 {
            return -1;
        }
        words += n as i64 / 4;
        if trunc {
            continue;
        }
        // Stream order: every word later than the last one this reader
        // saw. Not contiguous within one recv: MSG_WAITALL waits with
        // the socket unlocked (Linux sk_wait_data), so another reader
        // may take the bytes in between (the writer's 4096-byte sends
        // keep that word-aligned)
        for w in b[..n as usize].chunks(4) {
            let v = u32::from_be_bytes([w[0], w[1], w[2], w[3]]) as i64;
            if v <= last {
                return -1;
            }
            last = v;
        }
    }
}
