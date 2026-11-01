//! Faulting in a range for mlock / MAP_POPULATE (Linux mm/gup.c
//! __get_user_pages, __mm_populate; mm/mlock.c
//! __mlock_posix_error_return)
//!
//! Tests:
//! - MLOCK_BEYOND_EOF: mlock of a shared file mapping that runs past
//!   the file's end stops at the first page that cannot be faulted in
//!   (SIGBUS): ENOMEM. MAP_POPULATE of the same mapping still succeeds
//!   (mmap ignores populate errors).
//! - MLOCK_KILLABLE: SIGKILL ends a process in the middle of mlock of a
//!   large range: it dies long before the mlock would have finished
//!   (timed against a full mlock of the same size; skipped when that
//!   takes under 100 ms)

use super::helpers::{print, print_num, println, skip};
use super::mm_life::meminfo;
use super::sk::now_ms;
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, O_CREAT, O_RDWR, PROT_READ, PROT_WRITE, Timespec,
    sys_close, sys_exit, sys_fork, sys_ftruncate, sys_kill, sys_mlock, sys_mmap, sys_munlock,
    sys_munmap, sys_nanosleep, sys_open, sys_pipe2, sys_read, sys_unlink, sys_wait4, sys_write,
};

const PAGE: u64 = 4096;
const MAP_POPULATE: u32 = 0x8000;
const MAP_NORESERVE: u32 = 0x4000;
const ENOMEM: i64 = -12;
const SIGKILL: u32 = 9;

pub fn run_tests() {
    beyond_eof();
    killable();
}

fn report(name: &[u8], ok: bool, v: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(v);
        println(b"");
    }
}

fn beyond_eof() {
    let path = b"/mlock_eof\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR, 0o600);
    if fd < 0 || sys_ftruncate(fd as i32, PAGE as i64) != 0 {
        sys_close(fd as u64);
        return report(b"MLOCK_BEYOND_EOF", false, -1);
    }
    let len = 16 * PAGE;
    let p = sys_mmap(0, len, PROT_READ, MAP_SHARED, fd as i32, 0);
    let lock = if p >= 0 {
        sys_mlock(p as u64, len)
    } else {
        p
    };
    if p >= 0 {
        sys_munlock(p as u64, len);
        sys_munmap(p as u64, len);
    }
    let q = sys_mmap(0, len, PROT_READ, MAP_SHARED | MAP_POPULATE, fd as i32, 0);
    if q >= 0 {
        sys_munmap(q as u64, len);
    }
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    report(
        b"MLOCK_BEYOND_EOF",
        lock == ENOMEM && q >= 0,
        if lock != ENOMEM { lock } else { 1000 + q },
    );
}

/// Child: map and mlock `len` bytes; reports the ms it took on `fd`
fn mlock_child(len: u64, fd: i32) -> ! {
    let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    let p = sys_mmap(0, len, PROT_READ | PROT_WRITE, flags, -1, 0);
    if p < 0 {
        sys_exit(2);
    }
    let t0 = now_ms();
    let r = sys_mlock(p as u64, len);
    let ms = [(now_ms() - t0) as i64];
    sys_write(fd as u64, ms.as_ptr() as *const u8, 8);
    sys_exit(if r == 0 { 0 } else { 3 })
}

fn killable() {
    let name = b"MLOCK_KILLABLE";
    let free_kb = meminfo(b"MemFree:");
    if free_kb <= 0 {
        return report(name, false, -1);
    }
    let len = ((free_kb as u64 * 1024 / 2).min(1 << 30)) & !(PAGE - 1);
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    // Calibrate: a full mlock of `len`
    let pid = sys_fork();
    if pid == 0 {
        mlock_child(len, p[1]);
    }
    let mut ms = [0i64; 1];
    let n = sys_read(p[0] as u64, ms.as_mut_ptr() as *mut u8, 8);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let full = ms[0];
    if n != 8 || st != 0 {
        sys_close(p[0] as u64);
        sys_close(p[1] as u64);
        return report(name, false, -2 - st as i64);
    }
    if full < 100 {
        sys_close(p[0] as u64);
        sys_close(p[1] as u64);
        return skip(name, b"a full mlock takes under 100 ms here");
    }
    // Again, killed a tenth of the way in
    let pid = sys_fork();
    if pid == 0 {
        mlock_child(len, p[1]);
    }
    let wait = full / 10;
    let ts = Timespec {
        tv_sec: wait / 1000,
        tv_nsec: (wait % 1000) * 1_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
    let t0 = now_ms();
    sys_kill(pid, SIGKILL);
    sys_wait4(pid, &mut st, 0, 0);
    let took = (now_ms() - t0) as i64;
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    if st & 0x7f != SIGKILL as i32 || took >= full / 2 {
        print(b"MLOCK_KILLABLE: full mlock ms ");
        print_num(full);
        print(b", kill to reap ms ");
        print_num(took);
        println(b"");
        return report(name, false, st as i64);
    }
    report(name, true, 0)
}
