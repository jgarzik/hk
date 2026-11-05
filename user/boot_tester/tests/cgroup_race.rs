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
//!   is added and checked in one step; nothing passes the limit).
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

pub fn run_tests() {
    report(b"PIDS_MAX_FORK", pids_max_fork());
    report(b"PIDS_INTO_CGROUP", pids_into_cgroup());
    report(b"PIDS_MAX_RACE", pids_max_race());
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
        sys_exit(f() as u64);
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

/// Fork sleepers until EAGAIN, then wait for the other forker to be
/// done too (so no slot frees early), then reap: the count in `out[1+i]`
fn forker(i: usize, out: &[AtomicI32]) -> ! {
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
        for pid in f {
            let mut ws = 0;
            sys_wait4(pid, &mut ws, 0, 0);
        }
        let total = sh[1].load(Ordering::Acquire) as i64 + sh[2].load(Ordering::Acquire) as i64;
        if total != RACE_MAX - 3 {
            return 10 + total;
        }
        0
    });
    sys_munmap(p as u64, 4096);
    remove_cgroup(cg);
    r
}
