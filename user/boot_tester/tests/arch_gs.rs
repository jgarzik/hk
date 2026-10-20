//! User GS base (x86-64 only): arch_prctl(ARCH_SET_GS / ARCH_GET_GS)
//!
//! Tests:
//! - ARCH_GS: set GS to a buffer and read gs:0; the value survives a
//!   syscall, a yield and a context switch (the parent blocks in wait4
//!   while a fork child runs); ARCH_GET_GS returns the base; the fork
//!   child inherits it (Linux copy_thread); a kernel address is EPERM.
//!   The kernel's own per-CPU GS base is swapped in on every entry, so
//!   none of this can redirect it (GS_SELECTOR_CREDS covers `mov gs`).

use super::helpers::{print, print_num, println};
use hk_syscall::{
    ARCH_GET_GS, ARCH_SET_GS, sys_arch_prctl, sys_exit, sys_fork, sys_getpid, sys_sched_yield,
    sys_wait4,
};

const EPERM: i64 = 1;
const MAGIC: u64 = 0x6873_5f67_735f_6f6b; // "ko_sg_sh"

/// What gs:0 points at once ARCH_SET_GS took the buffer
#[repr(C, align(64))]
struct GsArea([u64; 8]);

static mut AREA: GsArea = GsArea([MAGIC, 1, 2, 3, 4, 5, 6, 7]);

/// Read the quadword at gs:0
fn gs0() -> u64 {
    let v: u64;
    // SAFETY: GS points at AREA (ARCH_SET_GS)
    unsafe { core::arch::asm!("mov {}, gs:[0]", out(reg) v, options(nostack, readonly)) };
    v
}

/// Run the GS base tests
pub fn run_tests() {
    match check() {
        Ok(()) => println(b"ARCH_GS:OK"),
        Err((step, v)) => {
            print(b"ARCH_GS:FAIL step ");
            print_num(step);
            print(b" value ");
            print_num(v);
            println(b"");
        }
    }
    // Back to no user GS base, as at exec
    sys_arch_prctl(ARCH_SET_GS, 0);
}

fn check() -> Result<(), (i64, i64)> {
    let area = &raw const AREA as u64;
    let r = sys_arch_prctl(ARCH_SET_GS, area);
    if r != 0 {
        return Err((1, r));
    }
    if gs0() != MAGIC {
        return Err((2, gs0() as i64));
    }
    let mut got: u64 = 0;
    let r = sys_arch_prctl(ARCH_GET_GS, &raw mut got as u64);
    if r != 0 || got != area {
        return Err((3, r));
    }
    sys_getpid();
    if gs0() != MAGIC {
        return Err((4, gs0() as i64));
    }
    sys_sched_yield();
    if gs0() != MAGIC {
        return Err((5, gs0() as i64));
    }
    // The child inherits the base; the parent sleeps in wait4 while it
    // runs (a switch away and back)
    let pid = sys_fork();
    if pid == 0 {
        sys_sched_yield();
        sys_exit(if gs0() == MAGIC { 0 } else { 1 });
    }
    let mut status: i32 = 0;
    let r = sys_wait4(pid, &mut status, 0, 0);
    if r != pid || status != 0 {
        return Err((6, status as i64));
    }
    if gs0() != MAGIC {
        return Err((7, gs0() as i64));
    }
    // A kernel address is refused (Linux: >= TASK_SIZE_MAX, EPERM) and
    // leaves the base alone
    let r = sys_arch_prctl(ARCH_SET_GS, 0xffff_8000_0000_0000);
    if r != -EPERM {
        return Err((8, r));
    }
    if gs0() != MAGIC {
        return Err((9, gs0() as i64));
    }
    Ok(())
}
