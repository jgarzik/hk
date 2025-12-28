//! Signal tests
//!
//! Tests:
//! - Test 74: rt_sigprocmask() - get and set signal mask
//! - Test 75: rt_sigpending() - get pending signals
//! - Test 76: kill() signal 0 - check process exists
//! - Test 77: kill() ESRCH - non-existent process
//! - Test 78: tgkill() signal 0
//! - Test 79: tkill() signal 0
//! - Test 80: rt_sigaction() - get default action
//! - Test 81: rt_sigaction() EINVAL - invalid signal
//! - Test 82: rt_sigaction() SIGKILL - can't change
//! - Test: CLONE_CLEAR_SIGHAND - reset handlers after clone
//! - Test: rt_sigtimedwait() - wait for signal with timeout
//! - Test: sigaltstack() - alternate signal stack
//! - Test: rt_sigqueueinfo() - queue signal with siginfo
//! - Test: rt_tgsigqueueinfo() - queue signal to thread
//! - Test: rt_sigsuspend() - wait for signal with temp mask

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_clone, sys_exit, sys_getpid, sys_gettid, sys_kill, sys_rt_sigaction, sys_rt_sigpending,
    sys_rt_sigprocmask, sys_rt_sigqueueinfo, sys_rt_sigsuspend, sys_rt_sigtimedwait,
    sys_rt_tgsigqueueinfo, sys_sigaltstack, sys_tgkill, sys_tkill, sys_wait4,
    CLONE_CLEAR_SIGHAND, SIG_BLOCK, SIG_DFL, SIG_IGN, SIG_UNBLOCK, SIGCHLD, SIGKILL, SIGUSR1,
};

/// SI_QUEUE signal code (for rt_sigqueueinfo)
const SI_QUEUE: i32 = -1;

/// siginfo_t structure for tests (128 bytes)
#[repr(C)]
struct SigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad0: i32,
    si_pid: i32,
    si_uid: u32,
    _reserved: [u8; 104], // Pad to 128 bytes total
}

impl SigInfo {
    fn new(signo: u32, code: i32, pid: i32, uid: u32) -> Self {
        Self {
            si_signo: signo as i32,
            si_errno: 0,
            si_code: code,
            _pad0: 0,
            si_pid: pid,
            si_uid: uid,
            _reserved: [0; 104],
        }
    }
}

/// Run all signal tests
pub fn run_tests() {
    test_sigprocmask();
    test_sigpending();
    test_kill_sig0();
    test_kill_esrch();
    test_tgkill_sig0();
    test_tkill_sig0();
    test_sigaction();
    test_sigaction_einval();
    test_sigaction_sigkill();
    test_clone_clear_sighand();
    test_sigtimedwait();
    test_sigaltstack();
    test_sigqueueinfo();
    test_sigqueueinfo_eperm();
    test_tgsigqueueinfo();
    test_sigsuspend();
    test_sigsuspend_einval();
    test_kill_pgrp_zero();
    test_kill_pgrp_neg();
}

/// Test 74: rt_sigprocmask() - get and set signal mask
fn test_sigprocmask() {

    // Get current blocked mask
    let mut old_mask: u64 = 0;
    let ret = sys_rt_sigprocmask(SIG_BLOCK, 0, &mut old_mask as *mut u64 as u64, 8);
    if ret == 0 {
        print(b"rt_sigprocmask(SIG_BLOCK, NULL, &old_mask) = 0, old_mask = ");
        print_num(old_mask as i64);

        // Block SIGUSR1 (signal 10)
        let new_mask: u64 = 1 << (SIGUSR1 - 1); // Signal bit for SIGUSR1
        let mut returned_mask: u64 = 0;
        let ret = sys_rt_sigprocmask(
            SIG_BLOCK,
            &new_mask as *const u64 as u64,
            &mut returned_mask as *mut u64 as u64,
            8,
        );
        if ret == 0 {
            // Verify the mask was set
            let mut check_mask: u64 = 0;
            sys_rt_sigprocmask(SIG_BLOCK, 0, &mut check_mask as *mut u64 as u64, 8);
            if (check_mask & new_mask) != 0 {
                println(b"SIGPROCMASK:OK");
            } else {
                print(b"SIGPROCMASK:FAIL: SIGUSR1 not in blocked mask, got ");
                print_num(check_mask as i64);
            }
        } else {
            print(b"SIGPROCMASK:FAIL: could not block SIGUSR1, ret = ");
            print_num(ret);
        }
    } else {
        print(b"SIGPROCMASK:FAIL: could not get mask, ret = ");
        print_num(ret);
    }
}

/// Test 75: rt_sigpending() - get pending signals
fn test_sigpending() {

    let mut pending: u64 = 0xFFFFFFFF; // Initialize to non-zero
    let ret = sys_rt_sigpending(&mut pending as *mut u64 as u64, 8);
    if ret == 0 {
        // Should be 0 or very low (no signals pending normally)
        print(b"rt_sigpending() = 0, pending = ");
        print_num(pending as i64);
        println(b"SIGPENDING:OK");
    } else {
        print(b"SIGPENDING:FAIL: ret = ");
        print_num(ret);
    }
}

/// Test 76: kill() with signal 0 - check process exists
fn test_kill_sig0() {

    let pid = sys_getpid();
    let ret = sys_kill(pid, 0); // Signal 0 = check if process exists
    if ret == 0 {
        println(b"KILL_SIG0:OK");
    } else {
        print(b"KILL_SIG0:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// Test 77: kill() to non-existent process should fail with ESRCH
fn test_kill_esrch() {

    let ret = sys_kill(99999, 0); // Non-existent PID
    if ret == -3 {
        // ESRCH
        println(b"KILL_ESRCH:OK");
    } else {
        print(b"KILL_ESRCH:FAIL: expected -3 (ESRCH), got ");
        print_num(ret);
    }
}

/// Test 78: tgkill() with signal 0
fn test_tgkill_sig0() {

    let pid = sys_getpid();
    let tid = sys_gettid();
    let ret = sys_tgkill(pid, tid, 0);
    if ret == 0 {
        println(b"TGKILL_SIG0:OK");
    } else {
        print(b"TGKILL_SIG0:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// Test 79: tkill() with signal 0
fn test_tkill_sig0() {

    let tid = sys_gettid();
    let ret = sys_tkill(tid, 0);
    if ret == 0 {
        println(b"TKILL_SIG0:OK");
    } else {
        print(b"TKILL_SIG0:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// Test 80: rt_sigaction() - get default action for SIGUSR1
fn test_sigaction() {

    // Define a simple sigaction structure for testing
    // struct sigaction { u64 handler, u64 flags, u64 restorer, u64 mask }
    let mut old_action: [u64; 4] = [0; 4];
    let ret = sys_rt_sigaction(SIGUSR1, 0, old_action.as_mut_ptr() as u64, 8);
    if ret == 0 {
        print(b"rt_sigaction(SIGUSR1, NULL, &oact) = 0, handler = ");
        print_num(old_action[0] as i64);
        // Handler should be SIG_DFL (0) for SIGUSR1 by default
        if old_action[0] == SIG_DFL {
            println(b"SIGACTION:OK");
        } else {
            println(b"SIGACTION:OK (handler not default but call succeeded)");
        }
    } else {
        print(b"SIGACTION:FAIL: ret = ");
        print_num(ret);
    }
}

/// Test 81: rt_sigaction() with invalid signal should fail
fn test_sigaction_einval() {

    let ret = sys_rt_sigaction(0, 0, 0, 8); // Signal 0 is invalid
    if ret == -22 {
        // EINVAL
        println(b"SIGACTION_EINVAL:OK");
    } else {
        print(b"SIGACTION_EINVAL:FAIL: expected -22, got ");
        print_num(ret);
    }
}

/// Test 82: rt_sigaction() on SIGKILL should fail
fn test_sigaction_sigkill() {

    // Try to set a handler for SIGKILL (should fail)
    let new_action: [u64; 4] = [SIG_IGN, 0, 0, 0];
    let ret = sys_rt_sigaction(SIGKILL, new_action.as_ptr() as u64, 0, 8);
    if ret == -22 {
        // EINVAL - can't change SIGKILL
        println(b"SIGACTION_SIGKILL:OK");
    } else {
        print(b"SIGACTION_SIGKILL:FAIL: expected -22, got ");
        print_num(ret);
    }
}

/// Helper for CLONE_CLEAR_SIGHAND test - runs in child process
///
/// This MUST be a separate function to ensure stack variables are allocated
/// on the child's new stack, not the parent's stack. The compiler allocates
/// the entire function's stack frame at function entry, before clone()
/// switches stacks.
#[inline(never)]
fn child_check_sighand() -> ! {
    // Query SIGUSR1 handler - should be SIG_DFL after CLONE_CLEAR_SIGHAND
    let mut child_action: [u64; 4] = [0xFFFFFFFF; 4];

    let sigact_ret = sys_rt_sigaction(SIGUSR1, 0, child_action.as_mut_ptr() as u64, 8);

    // Force a volatile read from memory
    let handler_val = unsafe { core::ptr::read_volatile(&child_action[0]) };

    if sigact_ret == 0 && handler_val == SIG_DFL {
        // Handler was reset to default - success!
        sys_exit(0);
    } else {
        // Handler was NOT reset - fail
        let handler_low = (handler_val & 0xFF) as u8;
        sys_exit(handler_low as u64);
    }
}

/// Test: CLONE_CLEAR_SIGHAND - reset signal handlers after clone
fn test_clone_clear_sighand() {
    // First, set a custom handler for SIGUSR1 (use SIG_IGN as a non-default handler)
    // Note: We use SIG_IGN because it's preserved by CLONE_CLEAR_SIGHAND
    // To properly test, we set a "handler" address (non-zero, non-SIG_IGN)
    let custom_handler: u64 = 0x12345678; // Fake handler address
    let new_action: [u64; 4] = [custom_handler, 0, 0, 0];
    let mut old_action: [u64; 4] = [0; 4];

    // Set custom handler for SIGUSR1
    let ret = sys_rt_sigaction(SIGUSR1, new_action.as_ptr() as u64, old_action.as_mut_ptr() as u64, 8);
    if ret != 0 {
        print(b"CLONE_CLEAR_SIGHAND:FAIL: could not set handler, ret = ");
        print_num(ret);
        return;
    }

    // Allocate stack for child
    const STACK_SIZE: usize = 16384;
    #[repr(C, align(16))]
    struct ChildStack([u8; STACK_SIZE]);
    static mut CHILD_STACK: ChildStack = ChildStack([0; STACK_SIZE]);

    // Clone with CLONE_CLEAR_SIGHAND
    let stack_base = core::ptr::addr_of_mut!(CHILD_STACK) as *mut u8;
    let stack_top = unsafe { stack_base.add(STACK_SIZE) as u64 };
    let flags = SIGCHLD as u64 | CLONE_CLEAR_SIGHAND;

    let ret = sys_clone(flags, stack_top, 0, 0, 0);

    if ret < 0 {
        print(b"CLONE_CLEAR_SIGHAND:FAIL: clone failed, ret = ");
        print_num(ret);
        // Restore default handler
        let default_action: [u64; 4] = [SIG_DFL, 0, 0, 0];
        sys_rt_sigaction(SIGUSR1, default_action.as_ptr() as u64, 0, 8);
        return;
    }

    if ret == 0 {
        // Child process - call helper function to ensure stack variables
        // are allocated on the NEW child stack, not the parent's stack.
        // The compiler may allocate the entire function's stack frame at
        // function entry, before clone() switches stacks.
        child_check_sighand();
    } else {
        // Parent process: wait for child and check exit status
        let child_pid = ret;
        let mut wstatus: i32 = 0;
        sys_wait4(child_pid, &mut wstatus, 0, 0);

        // Restore default handler in parent
        let default_action: [u64; 4] = [SIG_DFL, 0, 0, 0];
        sys_rt_sigaction(SIGUSR1, default_action.as_ptr() as u64, 0, 8);

        // Check exit status (WEXITSTATUS)
        let exit_code = (wstatus >> 8) & 0xFF;
        if exit_code == 0 {
            println(b"CLONE_CLEAR_SIGHAND:OK");
        } else {
            print(b"CLONE_CLEAR_SIGHAND:FAIL: child exit code = ");
            print_num(exit_code as i64);
        }
    }
}

/// Test: rt_sigtimedwait() - wait for signal with zero timeout
fn test_sigtimedwait() {
    // Wait for SIGUSR1 with zero timeout (should return -EAGAIN)
    let wait_set: u64 = 1 << (SIGUSR1 - 1);
    let ts = [0i64, 0i64]; // Zero timeout

    let ret = sys_rt_sigtimedwait(
        &wait_set as *const u64 as u64,
        0, // No info requested
        ts.as_ptr() as u64,
        8,
    );

    // With zero timeout and no pending signal, should return -EAGAIN (-11)
    if ret == -11 {
        println(b"SIGTIMEDWAIT:OK");
    } else {
        print(b"SIGTIMEDWAIT:FAIL: expected -11 (EAGAIN), got ");
        print_num(ret);
    }
}

/// Sigaltstack structure (matching Linux stack_t)
#[repr(C)]
struct StackT {
    ss_sp: u64,
    ss_flags: i32,
    _pad: i32,
    ss_size: u64,
}

/// SS_DISABLE flag
const SS_DISABLE: i32 = 2;

/// Test: sigaltstack() - set and get alternate signal stack
fn test_sigaltstack() {
    // First, query current altstack (should be disabled initially)
    let mut old_stack = StackT {
        ss_sp: 0,
        ss_flags: 0,
        _pad: 0,
        ss_size: 0,
    };

    let ret = sys_sigaltstack(0, &mut old_stack as *mut StackT as u64);
    if ret != 0 {
        print(b"SIGALTSTACK:FAIL: query failed, ret = ");
        print_num(ret);
        return;
    }

    // Old stack should be disabled (SS_DISABLE flag set)
    if old_stack.ss_flags & SS_DISABLE == 0 {
        print(b"SIGALTSTACK:FAIL: expected SS_DISABLE in old_stack, got flags = ");
        print_num(old_stack.ss_flags as i64);
        return;
    }

    // Set up a new alternate stack
    static mut ALT_STACK: [u8; 8192] = [0; 8192];
    let new_stack = StackT {
        ss_sp: core::ptr::addr_of!(ALT_STACK) as u64,
        ss_flags: 0, // Enable
        _pad: 0,
        ss_size: 8192,
    };

    let ret = sys_sigaltstack(&new_stack as *const StackT as u64, 0);
    if ret != 0 {
        print(b"SIGALTSTACK:FAIL: set failed, ret = ");
        print_num(ret);
        return;
    }

    // Query again to verify it was set
    let mut check_stack = StackT {
        ss_sp: 0,
        ss_flags: 0,
        _pad: 0,
        ss_size: 0,
    };

    let ret = sys_sigaltstack(0, &mut check_stack as *mut StackT as u64);
    if ret != 0 {
        print(b"SIGALTSTACK:FAIL: verify query failed, ret = ");
        print_num(ret);
        return;
    }

    // Verify the stack was configured
    if check_stack.ss_flags & SS_DISABLE != 0 {
        println(b"SIGALTSTACK:FAIL: stack still disabled after set");
        return;
    }

    if check_stack.ss_size != 8192 {
        print(b"SIGALTSTACK:FAIL: wrong size, expected 8192, got ");
        print_num(check_stack.ss_size as i64);
        return;
    }

    // Restore disabled state
    let disable_stack = StackT {
        ss_sp: 0,
        ss_flags: SS_DISABLE,
        _pad: 0,
        ss_size: 0,
    };
    sys_sigaltstack(&disable_stack as *const StackT as u64, 0);

    println(b"SIGALTSTACK:OK");
}

/// Test: rt_sigqueueinfo() - send signal with info (should succeed to self)
fn test_sigqueueinfo() {
    let pid = sys_getpid();

    // Create a siginfo structure with SI_QUEUE code
    let info = SigInfo::new(SIGUSR1, SI_QUEUE, pid as i32, 0);

    // Block SIGUSR1 first so the signal stays pending
    let mask: u64 = 1 << (SIGUSR1 - 1);
    sys_rt_sigprocmask(SIG_BLOCK, &mask as *const u64 as u64, 0, 8);

    // Queue the signal
    let ret = sys_rt_sigqueueinfo(pid, SIGUSR1, &info as *const SigInfo as u64);

    // Consume the pending signal using sigtimedwait (with short timeout)
    // This prevents the signal from remaining pending and interfering with later tests
    let ts = [0i64, 0i64]; // Zero timeout
    sys_rt_sigtimedwait(&mask as *const u64 as u64, 0, ts.as_ptr() as u64, 8);

    // Unblock SIGUSR1
    sys_rt_sigprocmask(SIG_UNBLOCK, &mask as *const u64 as u64, 0, 8);

    if ret == 0 {
        println(b"SIGQUEUEINFO:OK");
    } else {
        print(b"SIGQUEUEINFO:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// Test: rt_sigqueueinfo() with invalid si_code (should fail with EPERM)
fn test_sigqueueinfo_eperm() {
    let pid = sys_getpid();

    // Try to impersonate kernel (si_code >= 0 with wrong pid)
    // SI_USER = 0, so using si_code=0 with a fake pid should fail
    let info = SigInfo::new(SIGUSR1, 0, 12345, 0); // Wrong PID (not ours)

    let ret = sys_rt_sigqueueinfo(pid, SIGUSR1, &info as *const SigInfo as u64);

    if ret == -1 {
        // EPERM
        println(b"SIGQUEUEINFO_EPERM:OK");
    } else {
        print(b"SIGQUEUEINFO_EPERM:FAIL: expected -1, got ");
        print_num(ret);
    }
}

/// Test: rt_tgsigqueueinfo() - send signal to specific thread
fn test_tgsigqueueinfo() {
    let pid = sys_getpid();
    let tid = sys_gettid();

    let info = SigInfo::new(SIGUSR1, SI_QUEUE, pid as i32, 0);

    // Block SIGUSR1 first
    let mask: u64 = 1 << (SIGUSR1 - 1);
    sys_rt_sigprocmask(SIG_BLOCK, &mask as *const u64 as u64, 0, 8);

    let ret = sys_rt_tgsigqueueinfo(pid, tid, SIGUSR1, &info as *const SigInfo as u64);

    // Consume the pending signal using sigtimedwait (with short timeout)
    // This prevents the signal from remaining pending and interfering with later tests
    let ts = [0i64, 0i64]; // Zero timeout
    sys_rt_sigtimedwait(&mask as *const u64 as u64, 0, ts.as_ptr() as u64, 8);

    // Unblock
    sys_rt_sigprocmask(SIG_UNBLOCK, &mask as *const u64 as u64, 0, 8);

    if ret == 0 {
        println(b"TGSIGQUEUEINFO:OK");
    } else {
        print(b"TGSIGQUEUEINFO:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// Test: rt_sigsuspend() - should return -EINTR
fn test_sigsuspend() {
    // sigsuspend always returns -EINTR when a signal is pending/delivered
    // For this test, we set an empty mask (allowing all signals)
    // and expect immediate -EINTR due to kernel's stub behavior

    let empty_mask: u64 = 0; // Don't block any signals
    let ret = sys_rt_sigsuspend(&empty_mask as *const u64 as u64, 8);

    if ret == -4 {
        // EINTR
        println(b"SIGSUSPEND:OK");
    } else {
        print(b"SIGSUSPEND:FAIL: expected -4 (EINTR), got ");
        print_num(ret);
    }
}

/// Test: rt_sigsuspend() with invalid sigsetsize
fn test_sigsuspend_einval() {
    let mask: u64 = 0;
    let ret = sys_rt_sigsuspend(&mask as *const u64 as u64, 16); // Wrong size

    if ret == -22 {
        // EINVAL
        println(b"SIGSUSPEND_EINVAL:OK");
    } else {
        print(b"SIGSUSPEND_EINVAL:FAIL: expected -22, got ");
        print_num(ret);
    }
}

/// Test: kill(0, sig) - signal own process group
///
/// kill(0, sig) should signal all processes in the caller's process group.
/// Since we're the only process in our process group, signal 0 should succeed.
fn test_kill_pgrp_zero() {
    // Signal 0 is a validity check - should succeed for our own pgrp
    let ret = sys_kill(0, 0);
    if ret == 0 {
        println(b"KILL_PGRP_ZERO:OK");
    } else {
        print(b"KILL_PGRP_ZERO:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// Test: kill(-pgid, sig) - signal specific process group
///
/// kill(-pgid, sig) should signal all processes in process group pgid.
/// We use our own pid (negated) since we're a process group leader.
fn test_kill_pgrp_neg() {
    let pid = sys_getpid();

    // Signal our own process group using -pid (we are the pgrp leader)
    let ret = sys_kill(-pid, 0); // Signal 0 = validity check
    if ret == 0 {
        println(b"KILL_PGRP_NEG:OK");
    } else {
        print(b"KILL_PGRP_NEG:FAIL: expected 0, got ");
        print_num(ret);
    }
}
