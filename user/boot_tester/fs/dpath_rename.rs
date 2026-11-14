//! getcwd's and is_subdir's lockless walks race renames (Linux
//! prepend_path and is_subdir: a pass under RCU with rename_lock's
//! sequence checked after, again under the lock if a rename raced).
//!
//! - DPATH_RENAME: a child process stands at the bottom of a chain of
//!   directories under /tmp/dr/p/a and loops getcwd while the parent
//!   moves the chain's top to /tmp/dr/q/b and back. Every name is the
//!   chain's path under one of the two, never a mix (/tmp/dr/p/b,
//!   /tmp/dr/q/a) or a cut one.
//!   Each round the parent also tries to rename the chain's top onto
//!   its own bottom, which is EINVAL (is_subdir) every time.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::harness::T;
use crate::net::sk::now_ms;
use hk_syscall::{
    MAP_ANONYMOUS, MAP_SHARED, PROT_READ, PROT_WRITE, sys_chdir, sys_exit, sys_fork, sys_getcwd,
    sys_mkdir, sys_mmap, sys_munmap, sys_rename, sys_rmdir, sys_sched_yield, sys_wait4,
};

/// Directories below /tmp/dr/p/a: a walk long enough to be raced
const DEPTH: usize = 60;
/// Renames there and back
const ROUNDS: u32 = 1000;
const EINVAL: i64 = -22;

/// Shared between the two processes (written by one side each)
struct Sh {
    /// The walker is to stop (parent)
    stop: AtomicU32,
    /// The walker stands in the chain (walker)
    ready: AtomicU32,
    /// getcwd calls made (walker)
    calls: AtomicU32,
    /// getcwd results that were neither name (walker)
    bad: AtomicU32,
}

/// Spin (yielding) until `f`, false after 10 s
fn wait(f: impl Fn() -> bool) -> bool {
    let t0 = now_ms();
    while !f() {
        if now_ms() - t0 > 10_000 {
            return false;
        }
        sys_sched_yield();
    }
    true
}

/// Length of a chain's path with its NUL
const LEN: usize = 11 + 2 * DEPTH + 1;

/// /tmp/dr/p/a/d/.../d (`p`) or /tmp/dr/q/b/d/.../d, NUL included, in
/// `buf`
fn chain(buf: &mut [u8; LEN], p: bool) -> &[u8] {
    buf[..11].copy_from_slice(if p { b"/tmp/dr/p/a" } else { b"/tmp/dr/q/b" });
    let mut n = 11;
    for _ in 0..DEPTH {
        buf[n] = b'/';
        buf[n + 1] = b'd';
        n += 2;
    }
    buf[n] = 0;
    &buf[..=n]
}

pub fn run_tests() {
    let mut t = T::new(b"DPATH_RENAME");
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    for d in [
        &b"/tmp/dr\0"[..],
        b"/tmp/dr/p\0",
        b"/tmp/dr/q\0",
        b"/tmp/dr/p/a\0",
    ] {
        sys_mkdir(d.as_ptr(), 0o755);
    }
    sys_chdir(b"/tmp/dr/p/a\0".as_ptr());
    let mut made = 0;
    while made < DEPTH && sys_mkdir(b"d\0".as_ptr(), 0o755) == 0 && sys_chdir(b"d\0".as_ptr()) == 0
    {
        made += 1;
    }
    sys_chdir(b"/\0".as_ptr());
    if t.eq(b"chain", made as i64, DEPTH as i64) {
        race(&mut t);
    }
    // Bottom up, from whichever name the top has now
    let mut buf = [0u8; LEN];
    let c = chain(&mut buf, true);
    let mut path = [0u8; LEN];
    let mut n = c.len() - 1;
    path[..=n].copy_from_slice(c);
    for _ in 0..DEPTH {
        sys_rmdir(path.as_ptr());
        n -= 2;
        path[n] = 0;
    }
    for d in [
        &b"/tmp/dr/p/a\0"[..],
        b"/tmp/dr/p\0",
        b"/tmp/dr/q\0",
        b"/tmp/dr\0",
    ] {
        sys_rmdir(d.as_ptr());
    }
    t.done();
}

fn race(t: &mut T) {
    let p = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if !t.ok(b"mmap", p > 0, p) {
        return;
    }
    // SAFETY: a fresh shared zeroed page, larger than Sh; atomics only
    let sh = unsafe { &*(p as *const Sh) };
    let pid = sys_fork();
    if pid == 0 {
        walker(sh);
    }
    let mut einval = true;
    if t.ok(
        b"walker ready",
        wait(|| sh.ready.load(Ordering::Acquire) != 0),
        0,
    ) {
        let mut bottom = [0u8; LEN];
        for _ in 0..ROUNDS {
            sys_rename(b"/tmp/dr/p/a\0".as_ptr(), b"/tmp/dr/q/b\0".as_ptr());
            // The top into its own bottom: a loop (Linux is_subdir)
            let c = chain(&mut bottom, false);
            let r = sys_rename(b"/tmp/dr/q/b\0".as_ptr(), c.as_ptr());
            einval &= r == EINVAL;
            sys_rename(b"/tmp/dr/q/b\0".as_ptr(), b"/tmp/dr/p/a\0".as_ptr());
        }
    }
    sh.stop.store(1, Ordering::Release);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"walker status", i64::from(st), 0);
    t.ok(b"rename into itself EINVAL", einval, 0);
    t.ok(
        b"getcwd calls",
        sh.calls.load(Ordering::Acquire) > 0,
        i64::from(sh.calls.load(Ordering::Acquire)),
    );
    t.eq(
        b"getcwd names",
        i64::from(sh.bad.load(Ordering::Acquire)),
        0,
    );
    sys_munmap(p as u64, 4096);
}

/// The child: stand at the chain's bottom and name it until told to
/// stop
fn walker(sh: &Sh) -> ! {
    let mut ca = [0u8; LEN];
    let mut cb = [0u8; LEN];
    let (a, b) = (chain(&mut ca, true), chain(&mut cb, false));
    if sys_chdir(a.as_ptr()) != 0 {
        sys_exit(1);
    }
    sh.ready.store(1, Ordering::Release);
    let mut buf = [0u8; 4096];
    let (mut calls, mut bad) = (0u32, 0u32);
    while sh.stop.load(Ordering::Acquire) == 0 {
        let r = sys_getcwd(buf.as_mut_ptr(), buf.len());
        let name = &buf[..a.len()];
        if r != a.len() as i64 || (name != a && name != b) {
            bad += 1;
        }
        calls += 1;
        // Stores only: the parent reads them after the stop
        sh.calls.store(calls, Ordering::Release);
        sh.bad.store(bad, Ordering::Release);
    }
    sys_exit(0);
}
