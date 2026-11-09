//! Alternate signal stack (Linux kernel/signal.c do_sigaltstack)
//!
//! Tests (run as an isolated group: a broken kernel kills a child, not init):
//! - SIGALTSTACK_MODE_ONSTACK: ss_flags SS_ONSTACK enables the stack like
//!   0; a query off the stack reports 0
//! - SIGALTSTACK_MINSIZE: ENOMEM below the arch MINSIGSTKSZ, OK at it

use crate::harness::{R, check, report_r};
use hk_syscall::sys_sigaltstack;

const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
const ENOMEM: i64 = -12;
#[cfg(target_arch = "x86_64")]
const MINSIGSTKSZ: u64 = 2048;
#[cfg(target_arch = "aarch64")]
const MINSIGSTKSZ: u64 = 5120;

const ALT_SIZE: u64 = 65536;

#[repr(C, align(16))]
struct Stack([u8; ALT_SIZE as usize]);
static mut ALT: Stack = Stack([0; ALT_SIZE as usize]);

/// Linux stack_t
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq)]
struct StackT {
    ss_sp: u64,
    ss_flags: i32,
    _pad: i32,
    ss_size: u64,
}

impl StackT {
    const fn new(ss_sp: u64, ss_flags: i32, ss_size: u64) -> Self {
        Self {
            ss_sp,
            ss_flags,
            _pad: 0,
            ss_size,
        }
    }
}

pub fn run_tests() {
    test_mode_onstack();
    test_minsize();
    disable();
}

fn alt() -> u64 {
    (&raw mut ALT) as u64
}

fn set(ss: StackT) -> i64 {
    sys_sigaltstack(&ss as *const StackT as u64, 0)
}

fn get() -> StackT {
    let mut oss = StackT::new(0, -1, 0);
    let r = sys_sigaltstack(0, &mut oss as *mut StackT as u64);
    if r != 0 {
        oss.ss_flags = r as i32;
    }
    oss
}

fn disable() {
    set(StackT::new(0, SS_DISABLE, 0));
}

fn test_mode_onstack() {
    report_r(b"SIGALTSTACK_MODE_ONSTACK", mode_onstack());
    disable();
}

fn mode_onstack() -> R {
    let r = set(StackT::new(alt(), SS_ONSTACK, ALT_SIZE));
    check(b"set SS_ONSTACK", r == 0, r)?;
    let q = get();
    check(b"sp", q.ss_sp == alt(), q.ss_sp as i64)?;
    check(b"size", q.ss_size == ALT_SIZE, q.ss_size as i64)?;
    check(b"flags off the stack", q.ss_flags == 0, q.ss_flags as i64)
}

fn test_minsize() {
    report_r(b"SIGALTSTACK_MINSIZE", minsize());
    disable();
}

fn minsize() -> R {
    let r = set(StackT::new(alt(), 0, MINSIGSTKSZ - 1));
    check(b"below MINSIGSTKSZ", r == ENOMEM, r)?;
    let r = set(StackT::new(alt(), 0, MINSIGSTKSZ));
    check(b"at MINSIGSTKSZ", r == 0, r)
}
