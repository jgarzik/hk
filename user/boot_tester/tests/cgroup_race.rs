//! The pids controller charges a fork before the child exists, in the
//! child's target cgroup (Linux cgroup_can_fork / pids_try_charge).
//!
//! - PIDS_MAX_FORK: with pids.max=2 and one member, one fork succeeds
//!   and the next is EAGAIN.
//! - PIDS_INTO_CGROUP: clone3(CLONE_INTO_CGROUP) into a cgroup whose
//!   pids.max is 0 is EAGAIN, though the parent's own cgroup has room,
//!   and leaves pids.current at 0.
//! - PIDS_MAX_RACE: two members fork concurrently into pids.max=8 with
//!   three members already there: exactly five forks succeed (the charge
//!   is added and checked in one step; nothing passes the limit). The
//!   forkers start together once both exist; afterwards the cgroup is
//!   empty (rmdir works).
//! - PIDS_EXIT_REAP: children reaped the moment they exit leave their
//!   cgroup: pids.current is back to 0 and rmdir works (Linux
//!   cgroup_exit runs before exit_notify makes a task reapable).
//!
//!
//! cgroup_mutex and dead cgroups (Linux cgroup_kn_lock_live,
//! cgroup_destroy_locked):
//! - CGROUP_DEAD_ENODEV: after rmdir, a write to the cgroup's open
//!   cgroup.procs is ENODEV and clone3 into its open directory ENOENT.
//! - CGROUP_RMDIR_RACE: a child joining a cgroup while it is removed:
//!   either the join or the rmdir fails, never both succeed (an emptiness
//!   check and an attach cannot interleave).
//! - CGROUP_PROCS_TGID: writing a non-leader thread's tid to
//!   cgroup.procs moves its whole thread group, and cgroup.procs lists
//!   the process once (Linux: threadgroup migration under
//!   cgroup_threadgroup_rwsem).
//! - CGROUP_PROCS_EXITED_LEADER: a process whose main thread has exited
//!   is moved by its remaining thread: the exited leader is skipped
//!   (Linux: PF_EXITING), so once the process is gone the cgroup is
//!   empty (rmdir works) and its pids charge is back to 0.
//! - CGROUP_SUBTREE_CONTROL: a cgroup may enable for its children only a
//!   controller it has itself (ENOENT otherwise); an unknown token is
//!   EINVAL (Linux cgroup_subtree_control_write).
//!
//! - PIDS_EVENTS: a fork refused by a cgroup's pids.max counts in its
//!   pids.events.local and in pids.events there and above (not below):
//!   refused at the child, both count 1 in the child and the parent's
//!   pids.events 1; refused at the parent, only the parent's counters
//!   move (Linux 6.11+ pids_event; skipped on older hosts).
//! - CPU_MAX_RW: cpu.max reads back what was written ("max" keeps the
//!   period; out of Linux's bounds is EINVAL); on hk, while one process
//!   rewrites it with two values, a reader only ever sees one of them
//!   whole, never one's quota with the other's period (Linux
//!   cpu_max_show reads the two unlocked and may tear, so not there).
//!
//! Runs after cgroup.rs, which mounts cgroup2 at /sys/fs/cgroup and
//! enables +pids at the root.

use core::sync::atomic::{AtomicI32, Ordering};

use super::helpers::{print, print_num, println};
use hk_syscall::{
    CloneArgs, MAP_ANONYMOUS, MAP_SHARED, O_DIRECTORY, O_RDONLY, O_WRONLY, PROT_READ, PROT_WRITE,
    sys_clone3, sys_close, sys_exit, sys_fork, sys_getpid, sys_kill, sys_mkdir, sys_mmap,
    sys_munmap, sys_open, sys_pause, sys_read, sys_rmdir, sys_sched_yield, sys_wait4, sys_write,
};

const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;

pub fn run_tests() {
    report(b"PIDS_MAX_FORK", pids_max_fork());
    report(b"PIDS_INTO_CGROUP", pids_into_cgroup());
    report(b"PIDS_MAX_RACE", pids_max_race());
    report(b"PIDS_EXIT_REAP", pids_exit_reap());
    report(b"CGROUP_DEAD_ENODEV", cgroup_dead_enodev());
    report(b"CGROUP_RMDIR_RACE", cgroup_rmdir_race());
    report(b"CGROUP_PROCS_TGID", in_child(cgroup_procs_tgid));
    report(b"CGROUP_PROCS_EXITED_LEADER", procs_exited_leader());
    report(b"CGROUP_SUBTREE_CONTROL", subtree_control());
    // Hierarchical pids.events and pids.events.local: Linux 6.11
    // (3f26a885a068); CI's reference kernel may be older
    if super::helpers::linux_at_least(6, 11) {
        report(b"PIDS_EVENTS", pids_events());
    } else {
        super::helpers::skip(b"PIDS_EVENTS", b"Linux 6.11 pids events");
    }
    report(b"CPU_MAX_RW", cpu_max_rw());
}

/// The count in "max N" of `file` of cgroup `name`, -1 if unreadable
fn read_max_event(name: &[u8], file: &[u8]) -> i64 {
    let mut d = [0u8; 32];
    let n = read_raw(name, file, &mut d);
    let Some(rest) = d[..n.max(0) as usize].strip_prefix(b"max ") else {
        return -1;
    };
    let mut v = 0i64;
    for &c in rest.iter().take_while(|c| c.is_ascii_digit()) {
        v = v * 10 + (c - b'0') as i64;
    }
    v
}

/// clone3(CLONE_INTO_CGROUP) into `name`; the child exits at once.
/// The result (EAGAIN when refused)
fn clone_into(name: &[u8]) -> i64 {
    let mut b = [0u8; 96];
    let fd = sys_open(path(&mut b, name, b"").as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return fd;
    }
    let args = CloneArgs {
        flags: 0x2_0000_0000, // CLONE_INTO_CGROUP
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: 17,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: fd as u64,
    };
    let r = sys_clone3(&args, core::mem::size_of::<CloneArgs>());
    if r == 0 {
        sys_exit(0);
    }
    sys_close(fd as u64);
    if r > 0 {
        let mut ws = 0;
        sys_wait4(r, &mut ws, 0, 0);
    }
    r
}

fn pids_events() -> i64 {
    const P: &[u8] = b"pev";
    const C: &[u8] = b"pev/c";
    let mut b = [0u8; 96];
    sys_mkdir(path(&mut b, P, b"").as_ptr(), 0o755);
    write_file(P, b"cgroup.subtree_control", b"+pids");
    sys_mkdir(path(&mut b, C, b"").as_ptr(), 0o755);
    let step = (|| {
        let ev = |cg, f| read_max_event(cg, f);
        if write_file(C, b"pids.max", b"0") < 0 {
            return 1;
        }
        if clone_into(C) != EAGAIN {
            return 2;
        }
        let got = [
            ev(C, b"pids.events"),
            ev(C, b"pids.events.local"),
            ev(P, b"pids.events"),
            ev(P, b"pids.events.local"),
        ];
        if got != [1, 1, 1, 0] {
            return 10 + got.iter().fold(0, |a, &x| a * 10 + x);
        }
        write_file(C, b"pids.max", b"max");
        write_file(P, b"pids.max", b"0");
        if clone_into(C) != EAGAIN {
            return 3;
        }
        let got = [
            ev(C, b"pids.events"),
            ev(C, b"pids.events.local"),
            ev(P, b"pids.events"),
            ev(P, b"pids.events.local"),
        ];
        if got != [1, 1, 2, 1] {
            return 100_000 + got.iter().fold(0, |a, &x| a * 10 + x);
        }
        0
    })();
    sys_rmdir(path(&mut b, C, b"").as_ptr());
    sys_rmdir(path(&mut b, P, b"").as_ptr());
    step
}

/// The whole of `file` of cgroup `name` in `d`; its length or -errno
fn read_raw(name: &[u8], file: &[u8], d: &mut [u8]) -> i64 {
    let mut b = [0u8; 96];
    let fd = sys_open(path(&mut b, name, file).as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let n = sys_read(fd as u64, d.as_mut_ptr(), d.len() as u64);
    sys_close(fd as u64);
    n
}

fn cpu_max_rw() -> i64 {
    const CG: &[u8] = b"cpumax";
    const A: &[u8] = b"10000 20000\n";
    const B: &[u8] = b"30000 40000\n";
    if write_file(b"", b"cgroup.subtree_control", b"+cpu") < 0 {
        return 1;
    }
    let mut b = [0u8; 96];
    sys_mkdir(path(&mut b, CG, b"").as_ptr(), 0o755);
    let mut d = [0u8; 64];
    let step = (|| {
        if write_file(CG, b"cpu.max", b"50000 100000") < 0 {
            return 2;
        }
        let n = read_raw(CG, b"cpu.max", &mut d);
        if n < 0 || &d[..n as usize] != b"50000 100000\n" {
            return 3;
        }
        write_file(CG, b"cpu.max", b"max");
        let n = read_raw(CG, b"cpu.max", &mut d);
        if n < 0 || &d[..n as usize] != b"max 100000\n" {
            return 4;
        }
        // Linux tg_set_bandwidth bounds: EINVAL, nothing changed
        for bad in [&b"max 0"[..], b"0 100000", b"500 100000", b"max 2000000"] {
            if write_file(CG, b"cpu.max", bad) != EINVAL {
                return 6;
            }
        }
        let n = read_raw(CG, b"cpu.max", &mut d);
        if n < 0 || &d[..n as usize] != b"max 100000\n" {
            return 7;
        }
        write_file(CG, b"cpu.max", A);
        let pid = sys_fork();
        if pid == 0 {
            for i in 0..400 {
                write_file(CG, b"cpu.max", if i % 2 == 0 { B } else { A });
            }
            sys_exit(0);
        }
        let mut bad = 0;
        for _ in 0..400 {
            let n = read_raw(CG, b"cpu.max", &mut d);
            let got = &d[..n.max(0) as usize];
            if got != A && got != B && !super::helpers::host_mode() {
                bad = 5;
            }
        }
        let mut st = 0;
        sys_wait4(pid, &mut st, 0, 0);
        bad
    })();
    write_file(CG, b"cpu.max", b"max 100000");
    sys_rmdir(path(&mut b, CG, b"").as_ptr());
    step
}

fn report(name: &[u8], step: i64) {
    print(name);
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
}

/// "/sys/fs/cgroup/<name>/<file>\0" in `buf`
fn path<'a>(buf: &'a mut [u8; 96], name: &[u8], file: &[u8]) -> &'a [u8] {
    let mut n = 0;
    for part in [&b"/sys/fs/cgroup/"[..], name, b"/", file] {
        buf[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    if file.is_empty() {
        n -= 1; // no trailing slash
    }
    buf[n] = 0;
    &buf[..=n]
}

fn write_file(name: &[u8], file: &[u8], data: &[u8]) -> i64 {
    let mut b = [0u8; 96];
    let fd = sys_open(path(&mut b, name, file).as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let r = sys_write(fd as u64, data.as_ptr(), data.len() as u64);
    sys_close(fd as u64);
    r
}

fn read_num(name: &[u8], file: &[u8]) -> i64 {
    let mut b = [0u8; 96];
    let fd = sys_open(path(&mut b, name, file).as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut d = [0u8; 32];
    let n = sys_read(fd as u64, d.as_mut_ptr(), d.len() as u64);
    sys_close(fd as u64);
    let mut v = 0i64;
    for &c in &d[..n.max(0) as usize] {
        if !c.is_ascii_digit() {
            break;
        }
        v = v * 10 + (c - b'0') as i64;
    }
    v
}

/// A cgroup `name` with pids.max = `max`
fn make_cgroup(name: &[u8], max: &[u8]) -> bool {
    let mut b = [0u8; 96];
    sys_mkdir(path(&mut b, name, b"").as_ptr(), 0o755);
    write_file(name, b"pids.max", max) > 0
}

fn remove_cgroup(name: &[u8]) {
    let mut b = [0u8; 96];
    sys_rmdir(path(&mut b, name, b"").as_ptr());
}

/// Move the calling process into `name`
fn join(name: &[u8]) -> bool {
    let mut d = [0u8; 12];
    let mut n = d.len();
    let mut v = sys_getpid() as u64;
    loop {
        n -= 1;
        d[n] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    write_file(name, b"cgroup.procs", &d[n..]) > 0
}

/// A child that sleeps until killed
fn sleeper() -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        loop {
            sys_pause();
        }
    }
    pid
}

fn reap(pid: i64) {
    if pid > 0 {
        sys_kill(pid, 9);
        let mut ws = 0;
        sys_wait4(pid, &mut ws, 0, 0);
    }
}

/// `f`'s verdict from a child
fn in_child(f: impl Fn() -> i64) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        // The whole process: f may have started threads
        hk_syscall::sys_exit_group(f() as u64);
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    if ws & 0x7f != 0 {
        101
    } else {
        (ws >> 8) as i64 & 0xff
    }
}

fn pids_max_fork() -> i64 {
    let cg = b"pl_fork";
    if !make_cgroup(cg, b"2") {
        return 90;
    }
    let r = in_child(|| {
        if !join(cg) {
            return 1;
        }
        let a = sleeper();
        let b = sleeper();
        let verdict = if a <= 0 {
            2
        } else if b != EAGAIN {
            3
        } else {
            0
        };
        reap(a);
        reap(b);
        verdict
    });
    remove_cgroup(cg);
    r
}

fn pids_into_cgroup() -> i64 {
    let cg = b"pl_into";
    if !make_cgroup(cg, b"0") {
        return 90;
    }
    let mut b = [0u8; 96];
    let fd = sys_open(path(&mut b, cg, b"").as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        remove_cgroup(cg);
        return 91;
    }
    let args = CloneArgs {
        flags: 0x2_0000_0000, // CLONE_INTO_CGROUP
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: 17,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: fd as u64,
    };
    let r = sys_clone3(&args, core::mem::size_of::<CloneArgs>());
    if r == 0 {
        sys_exit(0);
    }
    sys_close(fd as u64);
    let verdict = if r > 0 {
        let mut ws = 0;
        sys_wait4(r, &mut ws, 0, 0);
        1
    } else if r != EAGAIN {
        2
    } else if read_num(cg, b"pids.current") != 0 {
        3
    } else {
        0
    };
    remove_cgroup(cg);
    verdict
}

const RACE_MAX: i64 = 8;
const WNOHANG: i32 = 1;

/// Fork sleepers until EAGAIN, then wait for the other forker to be
/// done too (so no slot frees early), then reap: the count in `out[1+i]`
fn forker(i: usize, out: &[AtomicI32]) -> ! {
    // Both forkers exist before either forks (out[0]: go)
    while out[0].load(Ordering::Acquire) == 0 {
        sys_sched_yield();
    }
    let mut kids = [0i64; RACE_MAX as usize];
    let mut n = 0;
    loop {
        let p = sleeper();
        if p <= 0 {
            break;
        }
        if n < kids.len() {
            kids[n] = p;
        }
        n += 1;
    }
    out[1 + i].store(n as i32, Ordering::Release);
    out[3 + i].store(1, Ordering::Release);
    while out[3 + (1 - i)].load(Ordering::Acquire) == 0 {
        sys_sched_yield();
    }
    for &k in kids.iter().take(n.min(kids.len())) {
        reap(k);
    }
    sys_exit(0)
}

fn pids_max_race() -> i64 {
    let cg = b"pl_race";
    if !make_cgroup(cg, b"8") {
        return 90;
    }
    let p = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p <= 0 {
        remove_cgroup(cg);
        return 91;
    }
    // SAFETY: a fresh MAP_SHARED page of 5 i32s, unmapped below
    let sh = unsafe { core::slice::from_raw_parts(p as *const AtomicI32, 5) };
    let r = in_child(|| {
        // This process and its two forkers: three members
        if !join(cg) {
            return 1;
        }
        let f: [i64; 2] = core::array::from_fn(|i| {
            let pid = sys_fork();
            if pid == 0 {
                forker(i, sh);
            }
            pid
        });
        sh[0].store(1, Ordering::Release);
        for pid in f {
            let mut ws = 0;
            sys_wait4(pid, &mut ws, 0, 0);
        }
        if f.iter().any(|&p| p <= 0) {
            return 2;
        }
        let total = sh[1].load(Ordering::Acquire) as i64 + sh[2].load(Ordering::Acquire) as i64;
        if total != RACE_MAX - 3 {
            return 10 + total;
        }
        0
    });
    sys_munmap(p as u64, 4096);
    let mut b = [0u8; 96];
    if sys_rmdir(path(&mut b, cg, b"").as_ptr()) != 0 && r == 0 {
        return 3;
    }
    r
}

/// In a child that joined a fresh cgroup: children each exit at
/// once while the child polls wait4 for them (1000 times); then pids.current is 0 and the
/// cgroup can be removed
fn pids_exit_reap() -> i64 {
    let cg = b"pl_reap";
    if !make_cgroup(cg, b"max") {
        return 90;
    }
    let r = in_child(|| {
        if !join(cg) {
            return 1;
        }
        for _ in 0..1000 {
            let pid = sys_fork();
            if pid == 0 {
                sys_exit(0);
            }
            if pid < 0 {
                return 2;
            }
            // Polled, so a reap can come the moment it is a zombie
            let mut ws = 0;
            while sys_wait4(pid, &mut ws, WNOHANG, 0) == 0 {}
        }
        0
    });
    let cur = read_num(cg, b"pids.current");
    let mut b = [0u8; 96];
    let rm = sys_rmdir(path(&mut b, cg, b"").as_ptr());
    if r != 0 {
        r
    } else if cur != 0 {
        10 + cur
    } else if rm != 0 {
        rm
    } else {
        0
    }
}

fn clone3_into(fd: i64) -> i64 {
    let args = CloneArgs {
        flags: 0x2_0000_0000, // CLONE_INTO_CGROUP
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: 17,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: fd as u64,
    };
    let r = sys_clone3(&args, core::mem::size_of::<CloneArgs>());
    if r == 0 {
        sys_exit(0);
    }
    if r > 0 {
        let mut ws = 0;
        sys_wait4(r, &mut ws, 0, 0);
    }
    r
}

fn cgroup_dead_enodev() -> i64 {
    let cg = b"pl_dead";
    let mut b = [0u8; 96];
    if sys_mkdir(path(&mut b, cg, b"").as_ptr(), 0o755) != 0 {
        return 90;
    }
    let procs = sys_open(path(&mut b, cg, b"cgroup.procs").as_ptr(), O_WRONLY, 0);
    let dir = sys_open(path(&mut b, cg, b"").as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    let rm = sys_rmdir(path(&mut b, cg, b"").as_ptr());
    let pid = b"1";
    let w = sys_write(procs as u64, pid.as_ptr(), 1);
    let c = clone3_into(dir);
    sys_close(procs as u64);
    sys_close(dir as u64);
    if procs < 0 || dir < 0 || rm != 0 {
        return 1;
    }
    if w != -19 {
        return 2;
    }
    if c != -2 {
        return 3;
    }
    0
}

const RMDIR_ROUNDS: i32 = 200;

fn cgroup_rmdir_race() -> i64 {
    let cg = b"pl_rmrace";
    let p = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p <= 0 {
        return 90;
    }
    // [0]: round started, [1]: the child's join result, [2]: rmdir done
    // SAFETY: a fresh MAP_SHARED page of 3 i32s, unmapped below
    let sh = unsafe { core::slice::from_raw_parts(p as *const AtomicI32, 3) };
    let mut bad = 0;
    for round in 1..=RMDIR_ROUNDS {
        let mut b = [0u8; 96];
        sys_mkdir(path(&mut b, cg, b"").as_ptr(), 0o755);
        sh[1].store(0, Ordering::Relaxed);
        sh[2].store(0, Ordering::Relaxed);
        let child = sys_fork();
        if child == 0 {
            while sh[0].load(Ordering::Acquire) != round {
                sys_sched_yield();
            }
            sh[1].store(if join(cg) { 1 } else { -1 }, Ordering::Release);
            // Stay a member until the rmdir has run
            while sh[2].load(Ordering::Acquire) == 0 {
                sys_sched_yield();
            }
            sys_exit(0);
        }
        sh[0].store(round, Ordering::Release);
        let rm = sys_rmdir(path(&mut b, cg, b"").as_ptr());
        while sh[1].load(Ordering::Acquire) == 0 {
            sys_sched_yield();
        }
        let joined = sh[1].load(Ordering::Acquire) == 1;
        sh[2].store(1, Ordering::Release);
        let mut ws = 0;
        sys_wait4(child, &mut ws, 0, 0);
        if joined && rm == 0 {
            bad = round as i64;
            break;
        }
        if rm != 0 {
            sys_rmdir(path(&mut b, cg, b"").as_ptr());
        }
    }
    sys_munmap(p as u64, 4096);
    remove_cgroup(cg);
    bad
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;

extern "C" fn idle_thread(_: u64) -> ! {
    loop {
        sys_pause();
    }
}

/// "<file> of /proc/self/task/<tid>" names cgroup `pl_tg`
fn in_tg_cgroup(tid: i64) -> bool {
    let mut p = [0u8; 64];
    let mut n = 0;
    for part in [&b"/proc/self/task/"[..]] {
        p[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    let mut d = [0u8; 12];
    let mut k = d.len();
    let mut v = tid as u64;
    loop {
        k -= 1;
        d[k] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    p[n..n + d.len() - k].copy_from_slice(&d[k..]);
    n += d.len() - k;
    let tail = b"/cgroup\0";
    p[n..n + tail.len()].copy_from_slice(tail);
    let fd = sys_open(p.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return false;
    }
    let mut b = [0u8; 64];
    let r = sys_read(fd as u64, b.as_mut_ptr(), b.len() as u64);
    sys_close(fd as u64);
    r > 0 && b[..r as usize].ends_with(b"/pl_tg\n")
}

/// In a child: a second thread, then its tid written to cgroup.procs
fn cgroup_procs_tgid() -> i64 {
    let cg = b"pl_tg";
    let mut b = [0u8; 96];
    sys_mkdir(path(&mut b, cg, b"").as_ptr(), 0o755);
    // SAFETY: the thread runs on its own static stack until the process
    // exits, and CTID is its clear-child-tid word
    let tid = unsafe {
        let top = (&raw mut STACK as *mut u8).add(16384) as u64;
        super::fork_mm::spawn_thread(top, idle_thread, 0, &raw mut CTID)
    };
    if tid <= 0 {
        return 1;
    }
    let mut d = [0u8; 12];
    let mut k = d.len();
    let mut v = tid as u64;
    loop {
        k -= 1;
        d[k] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if write_file(cg, b"cgroup.procs", &d[k..]) <= 0 {
        return 2;
    }
    if !in_tg_cgroup(sys_getpid()) || !in_tg_cgroup(tid) {
        return 3;
    }
    // One line, the process
    let fd = sys_open(path(&mut b, cg, b"cgroup.procs").as_ptr(), O_RDONLY, 0);
    let mut buf = [0u8; 64];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    sys_close(fd as u64);
    let lines = buf[..n.max(0) as usize]
        .iter()
        .filter(|&&c| c == b'\n')
        .count();
    if lines != 1 {
        return 4;
    }
    0
}

static mut STACK2: Stack = Stack([0; 16384]);
static mut CTID2: u32 = 0;
static mut LEADER: u64 = 0;

/// The remaining thread: wait for the leader's exit, move the process,
/// end it (exit status 0 if the write worked)
extern "C" fn mover_thread(_: u64) -> ! {
    // SAFETY: LEADER was set before this thread was created
    let pid = unsafe { LEADER };
    let ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
    let mut d = [0u8; 12];
    let mut k = d.len();
    let mut v = pid;
    loop {
        k -= 1;
        d[k] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let ok = write_file(b"pl_lead", b"cgroup.procs", &d[k..]) > 0;
    hk_syscall::sys_exit_group(!ok as u64)
}

fn procs_exited_leader() -> i64 {
    let cg = b"pl_lead";
    let mut b = [0u8; 96];
    if sys_mkdir(path(&mut b, cg, b"").as_ptr(), 0o755) != 0 {
        return 90;
    }
    let pid = sys_fork();
    if pid == 0 {
        // SAFETY: set before the thread exists; the thread runs on its
        // own static stack until the group exits
        unsafe {
            LEADER = sys_getpid() as u64;
            let top = (&raw mut STACK2 as *mut u8).add(16384) as u64;
            super::fork_mm::spawn_thread(top, mover_thread, 0, &raw mut CTID2);
        }
        // The main thread alone ends
        sys_exit(0);
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    let current = read_num(cg, b"pids.current");
    let rm = sys_rmdir(path(&mut b, cg, b"").as_ptr());
    if ws != 0 {
        return 1;
    }
    if current != 0 {
        return 10 + current;
    }
    if rm != 0 {
        return 2;
    }
    0
}

/// pl_sub has pids (the root enables it) and nothing else
fn subtree_control() -> i64 {
    let cg = b"pl_sub";
    let mut b = [0u8; 96];
    if sys_mkdir(path(&mut b, cg, b"").as_ptr(), 0o755) != 0 {
        return 90;
    }
    let ok = write_file(cg, b"cgroup.subtree_control", b"+pids");
    let bogus = write_file(cg, b"cgroup.subtree_control", b"+bogus");
    let missing = write_file(cg, b"cgroup.subtree_control", b"+io");
    write_file(cg, b"cgroup.subtree_control", b"-pids");
    remove_cgroup(cg);
    if ok <= 0 {
        return 1;
    }
    if bogus != -22 {
        return 2;
    }
    if missing != -2 {
        return 3;
    }
    0
}
