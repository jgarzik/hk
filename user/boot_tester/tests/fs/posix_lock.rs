//! POSIX advisory byte-range lock tests (fcntl F_GETLK/F_SETLK/F_SETLKW)
//!
//! Tests:
//! - Test F_SETLK with F_WRLCK (write lock) and F_UNLCK
//! - Test F_SETLK with F_RDLCK (read lock)
//! - Test F_GETLK returns F_UNLCK when no conflict
//! - Test partial unlock (range splitting)
//! - Test F_SETLK returns EBADF for invalid fd
//! - POSIX_LOCK_CLONE_FILES: a CLONE_FILES child (another process) owns
//!   its parent's locks too (Linux fl_owner is the files table): it may
//!   take the same lock, and F_GETLK elsewhere reports the parent's pid
//! - POSIX_LOCK_UNSHARE: close_range(CLOSE_RANGE_UNSHARE) on a table no
//!   one shares keeps it (Linux unshare_fd: count > 1), so its locks
//!   stay the caller's: it unlocks them, and they go at its exit

use crate::tests::helpers::{print, print_num, println};
use hk_syscall::{O_CREAT, O_RDWR, O_TRUNC, sys_close, sys_fcntl, sys_mkdir, sys_open, sys_write};

// fcntl commands for POSIX locks
const F_GETLK: i32 = 5;
const F_SETLK: i32 = 6;
#[allow(dead_code)]
const F_SETLKW: i32 = 7;

// Lock types
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

// Whence values
const SEEK_SET: i16 = 0;

// Error codes
const EBADF: i64 = -9;

/// struct flock (Linux ABI)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

/// Run all POSIX lock tests
pub fn run_tests() {
    // Create /tmp directory for test files (ignore error if exists)
    let _ = sys_mkdir(b"/tmp\0".as_ptr(), 0o755);

    test_setlk_wrlck();
    test_setlk_range_limits();
    test_setlk_rdlck();
    test_getlk_no_conflict();
    test_setlk_unlock();
    test_setlk_ebadf();
    test_lock_exec();
    test_lock_close_any();
    test_blocking();
    test_contended_waiters();
    test_flock_upgrade();
    test_lock_clone_files();
    test_lock_unshare();
}

/// Test F_SETLK with F_WRLCK (write lock) and F_UNLCK
fn test_setlk_wrlck() {
    let path = b"/tmp/posix_lock_test\0";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"POSIX_SETLK_WRLCK:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Write some data
    let _ = sys_write(fd as u64, b"test data".as_ptr(), 9);

    // Acquire write lock on bytes 0-100
    let mut flock = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 100,
        l_pid: 0,
    };

    let ret = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_SETLK_WRLCK:FAIL: fcntl(F_SETLK) returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Unlock
    flock.l_type = F_UNLCK;
    let ret = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_SETLK_WRLCK:FAIL: fcntl(F_UNLCK) returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"POSIX_SETLK_WRLCK:OK");
}

/// Test F_SETLK with F_RDLCK (read lock)
fn test_setlk_rdlck() {
    let path = b"/tmp/posix_rdlock_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"POSIX_SETLK_RDLCK:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Acquire read lock
    let mut flock = Flock {
        l_type: F_RDLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 50,
        l_pid: 0,
    };

    let ret = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_SETLK_RDLCK:FAIL: fcntl(F_SETLK) returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Unlock
    flock.l_type = F_UNLCK;
    let _ = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);

    sys_close(fd as u64);
    println(b"POSIX_SETLK_RDLCK:OK");
}

/// Test F_GETLK returns F_UNLCK when no conflict
fn test_getlk_no_conflict() {
    let path = b"/tmp/posix_getlk_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"POSIX_GETLK:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Query for a write lock - should report no conflict
    let mut flock = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 100,
        l_pid: 0,
    };

    let ret = sys_fcntl(fd as i32, F_GETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_GETLK:FAIL: fcntl(F_GETLK) returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // l_type should be F_UNLCK (no conflict)
    if flock.l_type != F_UNLCK {
        print(b"POSIX_GETLK:FAIL: expected l_type=F_UNLCK, got ");
        print_num(flock.l_type as i64);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"POSIX_GETLK:OK");
}

/// Test partial unlock (range splitting)
fn test_setlk_unlock() {
    let path = b"/tmp/posix_unlock_test\0";

    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"POSIX_UNLOCK:FAIL: open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Lock bytes 0-100
    let mut flock = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 100,
        l_pid: 0,
    };
    let _ = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);

    // Unlock bytes 25-75 (partial unlock)
    flock.l_type = F_UNLCK;
    flock.l_start = 25;
    flock.l_len = 50;
    let ret = sys_fcntl(fd as i32, F_SETLK, &mut flock as *mut Flock as u64);
    if ret != 0 {
        print(b"POSIX_UNLOCK:FAIL: partial unlock returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"POSIX_UNLOCK:OK");
}

/// Test F_SETLK returns EBADF for invalid fd
fn test_setlk_ebadf() {
    let mut flock = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 100,
        l_pid: 0,
    };

    let ret = sys_fcntl(9999, F_SETLK, &mut flock as *mut Flock as u64);
    if ret == EBADF {
        println(b"POSIX_SETLK_EBADF:OK");
    } else {
        print(b"POSIX_SETLK_EBADF:FAIL: expected -9, got ");
        print_num(ret);
        println(b"");
    }
}

/// F_GETLK of a write lock over the whole file: (l_type, l_pid)
fn getlk(path: &[u8]) -> (i16, i32) {
    let fd = sys_open(path.as_ptr(), O_RDWR, 0);
    let mut fl = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    let r = sys_fcntl(fd as i32, F_GETLK, &mut fl as *mut Flock as u64);
    sys_close(fd as u64);
    if r != 0 {
        (-1, 0)
    } else {
        (fl.l_type, fl.l_pid)
    }
}

/// Take a write lock over the whole file through `fd`
fn wrlock(fd: i64) -> i64 {
    let mut fl = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    sys_fcntl(fd as i32, F_SETLK, &mut fl as *mut Flock as u64)
}

/// POSIX_LOCK_EXEC: a lock survives its holder's exec (Linux keeps them;
/// only closed descriptors drop theirs)
fn test_lock_exec() {
    use hk_syscall::{sys_execve, sys_exit, sys_fork, sys_kill, sys_pipe2, sys_read, sys_wait4};
    const O_CLOEXEC: u32 = 0o2000000;
    let path = b"/tmp/posix_exec_test\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    sys_close(fd as u64);
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), O_CLOEXEC);
    let pid = sys_fork();
    if pid == 0 {
        sys_close(p[0] as u64);
        let fd = sys_open(path.as_ptr(), O_RDWR, 0);
        if wrlock(fd) != 0 {
            sys_exit(1);
        }
        let argv: [*const u8; 3] = [b"sleep\0".as_ptr(), b"10\0".as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        sys_execve(b"/bin/busybox\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(127);
    }
    sys_close(p[1] as u64);
    let mut c = [0u8; 1];
    let eof = sys_read(p[0] as u64, c.as_mut_ptr(), 1);
    sys_close(p[0] as u64);
    let (ty, owner) = getlk(path);
    sys_kill(pid, 9);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if eof == 0 && ty == F_WRLCK && owner as i64 == pid {
        println(b"POSIX_LOCK_EXEC:OK");
    } else {
        print(b"POSIX_LOCK_EXEC:FAIL l_type ");
        print_num(ty as i64);
        println(b"");
    }
}

/// POSIX_LOCK_CLOSE_ANY: closing any descriptor of the file drops the
/// process's locks on it, though the locking one is still open
fn test_lock_close_any() {
    use hk_syscall::{sys_exit, sys_fork, sys_pipe2, sys_read, sys_wait4, sys_write};
    let path = b"/tmp/posix_close_test\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    sys_close(fd as u64);
    let mut ready = [0i32; 2];
    let mut done = [0i32; 2];
    sys_pipe2(ready.as_mut_ptr(), 0);
    sys_pipe2(done.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        let fd1 = sys_open(path.as_ptr(), O_RDWR, 0);
        let locked = wrlock(fd1) == 0;
        let fd2 = sys_open(path.as_ptr(), O_RDWR, 0);
        sys_close(fd2 as u64);
        sys_write(ready[1] as u64, b"x".as_ptr(), 1);
        let mut c = [0u8; 1];
        sys_read(done[0] as u64, c.as_mut_ptr(), 1);
        sys_exit(if locked { 0 } else { 1 });
    }
    let mut c = [0u8; 1];
    sys_read(ready[0] as u64, c.as_mut_ptr(), 1);
    let (ty, _) = getlk(path);
    sys_write(done[1] as u64, b"x".as_ptr(), 1);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    for f in [ready[0], ready[1], done[0], done[1]] {
        sys_close(f as u64);
    }
    if st == 0 && ty == F_UNLCK {
        println(b"POSIX_LOCK_CLOSE_ANY:OK");
    } else {
        print(b"POSIX_LOCK_CLOSE_ANY:FAIL l_type ");
        print_num(ty as i64);
        println(b"");
    }
}

fn now_ms() -> i64 {
    let mut ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    hk_syscall::sys_clock_gettime(1, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

fn sleep_ms(ms: i64) {
    let ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: ms * 1_000_000,
    };
    hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
}

fn wrlck(fd: i32, cmd: i32, start: i64) -> i64 {
    let mut fl = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: start,
        l_len: 1,
        l_pid: 0,
    };
    sys_fcntl(fd, cmd, &mut fl as *mut Flock as u64)
}

fn verdict(name: &[u8], ok: bool, a: i64, b: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(a);
        print(b" ");
        print_num(b);
        println(b"");
    }
}

/// Blocking locks wait for the holder (Linux flock_lock_inode_wait,
/// F_SETLKW): a child holds the lock 200 ms; the parent's blocking
/// request returns 0 only after the child lets go. Two processes each
/// holding a byte and waiting for the other's: EDEADLK for the second.
fn test_blocking() {
    use hk_syscall::{sys_exit, sys_flock, sys_fork, sys_wait4};
    const LOCK_EX: i32 = 2;
    const LOCK_UN: i32 = 8;
    let path = b"/tmp/posix_block_test\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644) as i32;
    sys_write(fd as u64, b"0123456789".as_ptr(), 10);

    // flock: child takes LOCK_EX on its own open, holds 200 ms
    let pid = sys_fork();
    if pid == 0 {
        let c = sys_open(path.as_ptr(), O_RDWR, 0) as i32;
        sys_flock(c, LOCK_EX);
        sleep_ms(200);
        sys_flock(c, LOCK_UN);
        sys_exit(0);
    }
    sleep_ms(50);
    let t0 = now_ms();
    let r = sys_flock(fd, LOCK_EX);
    let waited = now_ms() - t0;
    sys_flock(fd, LOCK_UN);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    verdict(b"FLOCK_BLOCK", r == 0 && waited >= 100, r, waited);

    // F_SETLKW: the same with a byte-range lock
    let pid = sys_fork();
    if pid == 0 {
        wrlck(fd, F_SETLK, 0);
        sleep_ms(200);
        sys_exit(0);
    }
    sleep_ms(50);
    let t0 = now_ms();
    let r = wrlck(fd, F_SETLKW, 0);
    let waited = now_ms() - t0;
    sys_wait4(pid, &mut st, 0, 0);
    verdict(b"SETLKW_BLOCK", r == 0 && waited >= 100, r, waited);
    let mut un = Flock {
        l_type: F_UNLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    sys_fcntl(fd, F_SETLK, &mut un as *mut Flock as u64);

    // Deadlock: parent holds byte 0, child byte 1; each then waits for
    // the other's: whichever request closes the cycle is EDEADLK (Linux
    // posix_locks_deadlock), the other gets its lock once that one gives
    // up (the child exits, releasing byte 1)
    wrlck(fd, F_SETLK, 0);
    let mut p = [0i32; 2];
    hk_syscall::sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        wrlck(fd, F_SETLK, 1);
        sys_write(p[1] as u64, b"x".as_ptr(), 1);
        let r = wrlck(fd, F_SETLKW, 0);
        sys_exit(if r == 0 { 0 } else { (-r) as u64 });
    }
    let mut b = [0u8; 1];
    hk_syscall::sys_read(p[0] as u64, b.as_mut_ptr(), 1);
    sleep_ms(100);
    let dl = wrlck(fd, F_SETLKW, 1);
    sys_fcntl(fd, F_SETLK, &mut un as *mut Flock as u64);
    sys_wait4(pid, &mut st, 0, 0);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    sys_close(fd as u64);
    hk_syscall::sys_unlink(path.as_ptr());
    let child = (st >> 8) & 0xff;
    let ok = (dl == -35 && child == 0) || (dl == 0 && child == 35);
    verdict(b"SETLKW_EDEADLK", ok, dl, child as i64);
}

/// Two F_SETLKW waiters behind one holder sleep (no busy retry): a
/// refused attempt does not wake the other waiter. Their CPU time while
/// the holder keeps the lock 300 ms stays far below that.
fn test_contended_waiters() {
    use hk_syscall::{sys_exit, sys_fork, sys_getrusage, sys_wait4};
    let path = b"/tmp/posix_contend_test\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644) as i32;
    // struct rusage: ru_utime, ru_stime (timeval) first; children's
    // totals so far, subtracted below
    let cpu = || {
        let mut ru = [0i64; 18];
        sys_getrusage(-1, ru.as_mut_ptr() as *mut u8);
        (ru[0] + ru[2]) * 1000 + (ru[1] + ru[3]) / 1000
    };
    let before = cpu();
    let holder = sys_fork();
    if holder == 0 {
        wrlck(fd, F_SETLK, 0);
        sleep_ms(300);
        sys_exit(0);
    }
    sleep_ms(50);
    let mut pids = [0i64; 2];
    for p in pids.iter_mut() {
        *p = sys_fork();
        if *p == 0 {
            let r = wrlck(fd, F_SETLKW, 0);
            sys_exit(if r == 0 { 0 } else { 1 });
        }
    }
    let mut st = 0i32;
    let mut bad = 0;
    for p in [holder, pids[0], pids[1]] {
        sys_wait4(p, &mut st, 0, 0);
        bad += ((st >> 8) & 0xff) as i64;
    }
    let cpu_ms = cpu() - before;
    sys_close(fd as u64);
    hk_syscall::sys_unlink(path.as_ptr());
    verdict(b"SETLKW_NO_SPIN", bad == 0 && cpu_ms < 150, bad, cpu_ms);
}

/// A flock conversion drops the old lock first (Linux
/// flock_lock_inode): two holders of LOCK_SH both asking for LOCK_EX do
/// not deadlock. The child's blocking LOCK_EX gives up its shared lock,
/// so the parent's LOCK_EX|LOCK_NB then succeeds; the child gets the
/// lock once the parent lets go.
fn test_flock_upgrade() {
    use hk_syscall::{sys_exit, sys_flock, sys_fork, sys_pipe2, sys_read, sys_wait4};
    const LOCK_SH: i32 = 1;
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    const LOCK_UN: i32 = 8;
    let path = b"/tmp/flock_upgrade_test\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644) as i32;
    sys_flock(fd, LOCK_SH);
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        let c = sys_open(path.as_ptr(), O_RDWR, 0) as i32;
        sys_flock(c, LOCK_SH);
        sys_write(p[1] as u64, b"s".as_ptr(), 1);
        let r = sys_flock(c, LOCK_EX);
        sys_exit(if r == 0 { 0 } else { 1 });
    }
    let mut b = [0u8; 1];
    sys_read(p[0] as u64, b.as_mut_ptr(), 1);
    let mut got = -1;
    for _ in 0..200 {
        got = sys_flock(fd, LOCK_EX | LOCK_NB);
        if got == 0 {
            break;
        }
        sleep_ms(10);
    }
    sys_flock(fd, LOCK_UN);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    sys_close(fd as u64);
    hk_syscall::sys_unlink(path.as_ptr());
    verdict(b"FLOCK_UPGRADE", got == 0 && st == 0, got, st as i64);
}

/// Lock ranges past OFFSET_MAX are EOVERFLOW, ones reaching below 0
/// EINVAL (Linux flock64_to_posix_lock)
fn test_setlk_range_limits() {
    const EINVAL: i64 = -22;
    const EOVERFLOW: i64 = -75;
    let path = b"/tmp/posix_lock_range\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644) as i32;
    let try_lock = |l_start: i64, l_len: i64| {
        let mut fl = Flock {
            l_type: F_WRLCK,
            l_whence: SEEK_SET,
            l_start,
            l_len,
            l_pid: 0,
        };
        sys_fcntl(fd, F_SETLK, &mut fl as *mut Flock as u64)
    };
    let step = if fd < 0 {
        1
    } else if try_lock(i64::MAX, 2) != EOVERFLOW {
        2
    } else if try_lock(3, i64::MIN) != EINVAL {
        3
    } else if try_lock(i64::MAX, 1) != 0 {
        4
    } else {
        0
    };
    if fd >= 0 {
        sys_close(fd as u64);
    }
    print(b"POSIX_SETLK_RANGE_LIMITS");
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
}

/// A parent locks a file; a child cloned with CLONE_FILES (a process of
/// its own, sharing the descriptor table) takes the same write lock
/// without conflict, since both are one lock owner; a forked process
/// sees the lock held, by the parent's pid
fn test_lock_clone_files() {
    use hk_syscall::{sys_clone, sys_exit, sys_fork, sys_getpid, sys_wait4};
    const CLONE_FILES: u64 = 0x400;
    const SIGCHLD: u64 = 17;
    let path = b"/tmp/posix_clone_files\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    let mut ok = wrlock(fd) == 0;
    let pid = sys_clone(CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    if pid == 0 {
        sys_exit(if wrlock(fd) == 0 { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    ok &= st == 0;
    let me = sys_getpid();
    let other = sys_fork();
    if other == 0 {
        let (t, p) = getlk(path);
        sys_exit(if t == F_WRLCK && i64::from(p) == me {
            0
        } else {
            2
        });
    }
    let mut st2 = 0i32;
    sys_wait4(other, &mut st2, 0, 0);
    ok &= st2 == 0;
    sys_close(fd as u64);
    hk_syscall::sys_unlink(path.as_ptr());
    if ok {
        println(b"POSIX_LOCK_CLONE_FILES:OK");
    } else {
        print(b"POSIX_LOCK_CLONE_FILES:FAIL child ");
        print_num(i64::from(st));
        print(b" getlk ");
        print_num(i64::from(st2));
        println(b"");
    }
}

/// A child locks, unshares its private table with close_range, then
/// unlocks: the parent gets the lock; a second child locks and exits
/// without unlocking: the parent gets it too
fn test_lock_unshare() {
    use hk_syscall::{sys_close_range, sys_exit, sys_fork, sys_wait4};
    const CLOSE_RANGE_UNSHARE: u32 = 2;
    let path = b"/tmp/posix_unshare\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    let child = |unlock: bool| {
        let pid = sys_fork();
        if pid == 0 {
            let l = wrlock(fd);
            let u = sys_close_range(10, !0, CLOSE_RANGE_UNSHARE);
            if unlock {
                let mut fl = Flock {
                    l_type: F_UNLCK,
                    l_whence: SEEK_SET,
                    l_start: 0,
                    l_len: 0,
                    l_pid: 0,
                };
                sys_fcntl(fd as i32, F_SETLK, &mut fl as *mut Flock as u64);
            }
            sys_exit(if l == 0 && u == 0 { 0 } else { 1 });
        }
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
        st
    };
    let a = child(true);
    let after_unlock = wrlock(fd);
    let mut fl = Flock {
        l_type: F_UNLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    sys_fcntl(fd as i32, F_SETLK, &mut fl as *mut Flock as u64);
    let b = child(false);
    let after_exit = wrlock(fd);
    sys_close(fd as u64);
    hk_syscall::sys_unlink(path.as_ptr());
    if a == 0 && b == 0 && after_unlock == 0 && after_exit == 0 {
        println(b"POSIX_LOCK_UNSHARE:OK");
    } else {
        print(b"POSIX_LOCK_UNSHARE:FAIL child ");
        print_num(i64::from(a) * 1000 + i64::from(b));
        print(b" parent ");
        print_num(after_unlock * 100 + after_exit);
        println(b"");
    }
}
