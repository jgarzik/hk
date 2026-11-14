//! SIGIO from a packet tap that a TCP transmit feeds: the tap's wakeup
//! runs inside the sender's transmit, under its socket's spin locks
//! (Linux kill_fasync under RCU, send_sigio under fown->lock and
//! tasklist_lock, its entry GFP_ATOMIC).
//!
//! - FASYNC_TAP: an ETH_P_ALL packet socket on lo, armed for SIGIO with
//!   this process as owner; a TCP connect and send over lo leave SIGIO
//!   pending (a LOCKDEP boot also checks nothing slept under the
//!   transmit's locks)
//! - FASYNC_TAP_KILL: the same in a child that keeps SIGIO's default
//!   action: its own send kills it with SIGIO (a group kill decided
//!   inside the transmit)
//! - FASYNC_TAP_PGRP: the tap's owner is a process group of two; both
//!   get SIGIO from the first one's send

use crate::harness::T;
use crate::net::sk::{LO, bind, close, connect, port, send, tcp};
use hk_syscall::{
    SOCK_RAW, SigInfo, Zeroable, sys_bind, sys_close, sys_exit, sys_fcntl, sys_fork, sys_getpid,
    sys_ioctl, sys_listen, sys_pipe2, sys_read, sys_rt_sigprocmask, sys_rt_sigtimedwait,
    sys_setpgid, sys_socket, sys_wait4, sys_write,
};

const SIGIO: u32 = 29;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const F_SETOWN: i32 = 8;
const O_ASYNC: u64 = 0o20000;
const AF_PACKET: i32 = 17;
const ETH_P_ALL: u16 = 0x0003;
const SIG_BLOCK: i32 = 0;
const SIG_SETMASK: i32 = 2;

pub fn run_tests() {
    tap();
    tap_kill();
    tap_pgrp();
}

/// lo's interface index (SIOCGIFINDEX)
fn lo_index() -> i32 {
    let mut ifr = [0u8; 40];
    ifr[..2].copy_from_slice(b"lo");
    let u = sys_socket(2, 2, 0) as i32;
    sys_ioctl(u, 0x8933, ifr.as_mut_ptr() as u64);
    sys_close(u as u64);
    i32::from_ne_bytes([ifr[16], ifr[17], ifr[18], ifr[19]])
}

/// A packet socket seeing every frame of lo, armed for SIGIO to `owner`
/// (a pid, or a negative process group); its fd or -errno
fn armed_tap(owner: i64) -> i64 {
    let p = sys_socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be() as i32);
    if p < 0 {
        return p;
    }
    let p = p as i32;
    let mut sll = [0u8; 20];
    sll[0..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
    sll[2..4].copy_from_slice(&ETH_P_ALL.to_be_bytes());
    sll[4..8].copy_from_slice(&lo_index().to_ne_bytes());
    let steps = [
        sys_bind(p, sll.as_ptr(), 20),
        sys_fcntl(p, F_SETOWN, owner as u64),
    ];
    if let Some(&e) = steps.iter().find(|&&r| r < 0) {
        sys_close(p as u64);
        return e;
    }
    let fl = sys_fcntl(p, F_GETFL, 0);
    let r = sys_fcntl(p, F_SETFL, fl as u64 | O_ASYNC);
    if r < 0 {
        sys_close(p as u64);
        return r;
    }
    i64::from(p)
}

/// A TCP connection over lo and a send on it: the transmits the tap sees
fn tcp_traffic() -> (i64, i64) {
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, 4);
    let c = tcp();
    let rc = connect(c, LO, port(l));
    let rs = send(c, &[0x5a; 512], 0);
    close(c);
    close(l);
    (rc, rs)
}

fn block_sigio() -> u64 {
    let mask = 1u64 << (SIGIO - 1);
    let mut old = 0u64;
    sys_rt_sigprocmask(
        SIG_BLOCK,
        &mask as *const u64 as u64,
        &mut old as *mut u64 as u64,
        8,
    );
    old
}

fn set_mask(m: u64) {
    sys_rt_sigprocmask(SIG_SETMASK, &m as *const u64 as u64, 0, 8);
}

/// SIGIO pending or arriving within `secs`: the signal or -errno
fn take_sigio(secs: i64) -> i64 {
    let mask = 1u64 << (SIGIO - 1);
    let mut info = SigInfo::zeroed();
    let ts = [secs, 0i64];
    sys_rt_sigtimedwait(
        &mask as *const u64 as u64,
        &mut info as *mut SigInfo as u64,
        ts.as_ptr() as u64,
        8,
    )
}

/// Every SIGIO pending, taken (later frames may raise more)
fn drain_sigio() {
    while take_sigio(0) > 0 {}
}

fn tap() {
    let mut t = T::new(b"FASYNC_TAP");
    let old = block_sigio();
    let p = armed_tap(sys_getpid());
    if t.ok(b"armed tap", p >= 0, p) {
        let (rc, rs) = tcp_traffic();
        t.eq(b"connect", rc, 0);
        t.eq(b"send", rs, 512);
        t.eq(b"SIGIO", take_sigio(1), i64::from(SIGIO));
        sys_close(p as u64);
    }
    drain_sigio();
    set_mask(old);
    t.done();
}

fn tap_kill() {
    let mut t = T::new(b"FASYNC_TAP_KILL");
    let pid = sys_fork();
    if pid == 0 {
        // SIGIO's default action (terminate), not blocked
        let p = armed_tap(sys_getpid());
        if p < 0 {
            sys_exit(1);
        }
        tcp_traffic();
        // Delivered on the way back from the send at the latest
        sys_exit(2);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    // Killed by SIGIO (WIFSIGNALED, WTERMSIG)
    t.eq(b"killed by SIGIO", i64::from(st & 0x7f), i64::from(SIGIO));
    t.done();
}

fn tap_pgrp() {
    let mut t = T::new(b"FASYNC_TAP_PGRP");
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(pgrp_leader() as u64);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"group", i64::from(st), 0);
    t.done();
}

/// A process group of this process and a child, both with SIGIO
/// blocked; the tap owned by the group; this one sends. 0 if both got
/// SIGIO, else the failing step.
fn pgrp_leader() -> i32 {
    sys_setpgid(0, 0);
    block_sigio();
    let mut fds = [0i32; 2];
    if sys_pipe2(fds.as_mut_ptr(), 0) != 0 {
        return 1;
    }
    let child = sys_fork();
    if child == 0 {
        // Wait for the leader's send, then look for SIGIO
        let mut b = [0u8; 1];
        sys_read(fds[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(if take_sigio(1) == i64::from(SIGIO) {
            0
        } else {
            3
        });
    }
    let p = armed_tap(-sys_getpid());
    if p < 0 {
        sys_write(fds[1] as u64, b"x".as_ptr(), 1);
        return 2;
    }
    tcp_traffic();
    let mine = take_sigio(1) == i64::from(SIGIO);
    sys_write(fds[1] as u64, b"x".as_ptr(), 1);
    let mut st = 0i32;
    sys_wait4(child, &mut st, 0, 0);
    sys_close(p as u64);
    if !mine {
        return 4;
    }
    if st != 0 { 5 } else { 0 }
}
