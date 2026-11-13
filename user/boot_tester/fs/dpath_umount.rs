//! getcwd's name walk races a lazy unmount of the mount it climbs
//! through (Linux prepend_path under mount_lock and rename_lock, no
//! references taken).
//!
//! - DPATH_UMOUNT: a child process stands in a ramfs mounted at the
//!   bottom of a deep directory chain on vda1's vfat and loops getcwd,
//!   whose walk climbs out of the ramfs into the vfat mount; the parent
//!   meanwhile detaches the vfat mount (MNT_DETACH), so the last
//!   reference to it can go while a walk is inside it. Its teardown
//!   (releasing the block device) must not run inside the walk, which
//!   holds spin locks: a LOCKDEP boot reports it there. Each round
//!   remounts both; at the end the chain is removed.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::harness::T;
use crate::helpers::{BlkDev, find_blkdev};
use crate::net::sk::now_ms;
use hk_syscall::{
    MAP_ANONYMOUS, MAP_SHARED, PROT_READ, PROT_WRITE, sys_chdir, sys_exit, sys_fork, sys_getcwd,
    sys_mkdir, sys_mmap, sys_mount, sys_munmap, sys_rmdir, sys_sched_yield, sys_umount2, sys_wait4,
};

/// Directories in the chain: enough that one walk takes long enough
/// for the unmount to land inside it
const DEPTH: usize = 1200;
const ROUNDS: u32 = 20;
/// getcwd calls per round
const CALLS: u32 = 200;
const MNT_DETACH: u64 = 2;
const DIR: &[u8] = b"/tmp/dpm\0";

/// Shared between the two processes (written by one side each)
struct Sh {
    /// Round the walker is to run (parent)
    go: AtomicU32,
    /// Round the walker has entered the ramfs for (walker)
    ready: AtomicU32,
    /// Round the walker has finished (walker)
    done: AtomicU32,
    /// getcwd calls made (walker)
    calls: AtomicU32,
}

/// vda1's vfat, mounted at /tmp/dpm
fn mount_vfat(dev: &BlkDev) -> i64 {
    let mut p = [0u8; 48];
    sys_mount(
        dev.path(&mut p).as_ptr(),
        DIR.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        0,
    )
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

/// /tmp/dpm/d/d/.../d/c, NUL included, in `buf`
fn chain(buf: &mut [u8; 9 + 2 * DEPTH + 3]) -> &[u8] {
    buf[..8].copy_from_slice(b"/tmp/dpm");
    let mut n = 8;
    for _ in 0..DEPTH {
        buf[n] = b'/';
        buf[n + 1] = b'd';
        n += 2;
    }
    buf[n..n + 3].copy_from_slice(b"/c\0");
    &buf[..n + 3]
}

pub fn run_tests() {
    let mut t = T::new(b"DPATH_UMOUNT");
    let Some(dev) = find_blkdev(b"vd", 32768) else {
        t.ok(b"no vda1", false, 0);
        t.done();
        return;
    };
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(DIR.as_ptr(), 0o755);
    if !t.eq(b"mount", mount_vfat(&dev), 0) {
        t.done();
        return;
    }
    if build_chain(&mut t) {
        race(&mut t, &dev);
    }
    // The device is free again once every lazily detached mount's
    // teardown ran (the last one when its walker left)
    t.eq(b"remount", mount_vfat(&dev), 0);
    remove_chain(&mut t);
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
    t.done();
}

/// The chain under the vfat root, one level at a time
fn build_chain(t: &mut T) -> bool {
    sys_chdir(DIR.as_ptr());
    let mut ok = true;
    for _ in 0..DEPTH {
        if !t.eq(b"mkdir d", sys_mkdir(b"d\0".as_ptr(), 0o755), 0)
            || !t.eq(b"chdir d", sys_chdir(b"d\0".as_ptr()), 0)
        {
            ok = false;
            break;
        }
    }
    ok = ok && t.eq(b"mkdir c", sys_mkdir(b"c\0".as_ptr(), 0o755), 0);
    sys_chdir(b"/\0".as_ptr());
    ok
}

/// Remove what `build_chain` made, bottom up
fn remove_chain(t: &mut T) {
    let mut buf = [0u8; 9 + 2 * DEPTH + 3];
    let c = chain(&mut buf);
    // The chain's bottom directory, without "/c"
    let mut bottom = [0u8; 9 + 2 * DEPTH + 3];
    let n = c.len() - 3;
    bottom[..n].copy_from_slice(&c[..n]);
    if !t.eq(b"chdir bottom", sys_chdir(bottom.as_ptr()), 0) {
        return;
    }
    t.eq(b"rmdir c", sys_rmdir(b"c\0".as_ptr()), 0);
    for _ in 0..DEPTH {
        sys_chdir(b"..\0".as_ptr());
        if !t.eq(b"rmdir d", sys_rmdir(b"d\0".as_ptr()), 0) {
            break;
        }
    }
    sys_chdir(b"/\0".as_ptr());
}

fn race(t: &mut T, dev: &BlkDev) {
    let mut buf = [0u8; 9 + 2 * DEPTH + 3];
    let c = chain(&mut buf);
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
        walker(sh, c);
    }
    for round in 1..=ROUNDS {
        if round > 1 && !t.eq(b"remount", mount_vfat(dev), 0) {
            break;
        }
        let r = sys_mount(b"none\0".as_ptr(), c.as_ptr(), b"ramfs\0".as_ptr(), 0, 0);
        if !t.eq(b"mount ramfs", r, 0) {
            sys_umount2(DIR.as_ptr(), 0);
            break;
        }
        sh.go.store(round, Ordering::Release);
        if !t.ok(
            b"walker ready",
            wait(|| sh.ready.load(Ordering::Acquire) == round),
            0,
        ) {
            break;
        }
        // Inside a batch of walks, detach the mount they climb through
        let base = sh.calls.load(Ordering::Acquire);
        wait(|| sh.calls.load(Ordering::Acquire) >= base + 2);
        if !t.eq(b"umount2", sys_umount2(DIR.as_ptr(), MNT_DETACH), 0) {
            break;
        }
        if !t.ok(
            b"walker done",
            wait(|| sh.done.load(Ordering::Acquire) == round),
            0,
        ) {
            break;
        }
    }
    // Stop the walker (a round past the last ends it)
    sh.go.store(ROUNDS + 1, Ordering::Release);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"walker status", i64::from(st), 0);
    sys_munmap(p as u64, 4096);
}

/// The child: each round, stand in the ramfs and walk out of it
fn walker(sh: &Sh, c: &[u8]) -> ! {
    let mut buf = [0u8; 4096];
    let mut last = 0;
    loop {
        if !wait(|| sh.go.load(Ordering::Acquire) != last) {
            sys_exit(1);
        }
        last = sh.go.load(Ordering::Acquire);
        if last > ROUNDS {
            sys_exit(0);
        }
        sys_chdir(c.as_ptr());
        sh.ready.store(last, Ordering::Release);
        for _ in 0..CALLS {
            sys_getcwd(buf.as_mut_ptr(), buf.len());
            // The only writer: no read-modify-write needed
            let n = sh.calls.load(Ordering::Relaxed);
            sh.calls.store(n + 1, Ordering::Release);
        }
        sys_chdir(b"/\0".as_ptr());
        sh.done.store(last, Ordering::Release);
    }
}
