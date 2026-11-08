//! A user struct pointer just below the top of the address space: the
//! struct runs past it, so reading or writing it is EFAULT (Linux
//! access_ok on the whole struct), never a field address wrapped
//! around to the bottom of memory
//!
//! UPTR_TOP_EFAULT: get_robust_list's head pointer, futex and
//! rt_sigtimedwait timeouts, a futex_waitv array and seccomp's struct
//! sock_fprog at 2^64 - 8

use crate::harness::T;
use core::ptr;
use hk_syscall::{
    FUTEX_PRIVATE_FLAG, FUTEX_WAIT, FutexWaitv, Timespec, sys_futex, sys_futex_waitv,
    sys_get_robust_list, sys_rt_sigtimedwait, sys_seccomp,
};

const EFAULT: i64 = -14;
const TOP: u64 = 0xffff_ffff_ffff_fff8;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const CLOCK_MONOTONIC: i32 = 1;

pub fn run_tests() {
    let mut t = T::new(b"UPTR_TOP_EFAULT");
    let mut len = 0usize;
    let r = sys_get_robust_list(0, TOP as *mut _, &mut len);
    t.eq(b"get_robust_list head", r, EFAULT);
    let mut word = 0u32;
    let ts = TOP as *const Timespec;
    let r = sys_futex(
        &mut word,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        0,
        ts,
        ptr::null_mut(),
        0,
    );
    t.eq(b"futex timeout", r, EFAULT);
    let set = 1u64 << 9; // SIGUSR1's bit, never sent here
    let r = sys_rt_sigtimedwait(&set as *const u64 as u64, 0, TOP, 8);
    t.eq(b"rt_sigtimedwait timeout", r, EFAULT);
    let waiters = (TOP - 16) as *const FutexWaitv;
    let r = sys_futex_waitv(waiters, 1, 0, ptr::null(), CLOCK_MONOTONIC);
    t.eq(b"futex_waitv array", r, EFAULT);
    let r = sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, TOP);
    t.eq(b"seccomp sock_fprog", r, EFAULT);
    t.done();
}
