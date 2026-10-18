//! User GS selector loads (x86-64 only)
//!
//! A user `mov gs, <selector>` reloads the GS base from the descriptor
//! (0 for the flat user data segment). On Linux that is harmless (the
//! kernel swaps in its own GS base on entry); the kernel's per-CPU data
//! and the caller's credentials must not depend on it.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_geteuid, sys_open, sys_read, sys_setresuid, sys_setuid,
    sys_wait4,
};

const EFAULT: i64 = 14;
/// Never mapped in the boot tester (the first page above NULL)
const UNMAPPED: u64 = 0x1000;

/// Run the GS selector tests
pub fn run_tests() {
    test_gs_load_keeps_creds();
}

/// Load the user data selector (the one in SS: hk 0x1b, Linux 0x2b
/// __USER_DS) into GS, which reloads the GS base from its descriptor (0)
fn load_gs_user_ds() {
    // SAFETY: SS holds a valid DPL-3 data selector; nothing in this
    // program uses GS
    unsafe {
        core::arch::asm!(
            "mov {0:x}, ss",
            "mov gs, {0:x}",
            out(reg) _,
            options(nostack, preserves_flags)
        )
    };
}

/// An unprivileged child loads a user selector into GS: a syscall that
/// faults in kernel mode on a user pointer (read into an unmapped
/// buffer: EFAULT) still finds its per-CPU data, and the child keeps
/// its uid (geteuid 1000) and stays unprivileged (setuid(0) EPERM)
fn test_gs_load_keeps_creds() {
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(3);
        }
        load_gs_user_ds();
        let fd = sys_open(b"/dev/zero\0".as_ptr(), 0, 0);
        if fd < 0 {
            sys_exit(4);
        }
        load_gs_user_ds();
        if sys_read(fd as u64, UNMAPPED as *mut u8, 16) != -EFAULT {
            sys_exit(5);
        }
        sys_close(fd as u64);
        load_gs_user_ds();
        if sys_geteuid() != 1000 {
            sys_exit(1);
        }
        if sys_setuid(0) == 0 {
            sys_exit(2);
        }
        sys_exit(0);
    }
    let mut status: i32 = 0;
    let r = sys_wait4(pid, &mut status, 0, 0);
    if r == pid && status == 0 {
        println(b"GS_SELECTOR_CREDS:OK");
    } else {
        print(b"GS_SELECTOR_CREDS:FAIL: wait ");
        print_num(r);
        print(b" status ");
        print_num(status as i64);
        println(b"");
    }
}
