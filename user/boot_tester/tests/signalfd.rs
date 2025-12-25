//! Signalfd tests
//!
//! Tests:
//! - Test signalfd4 creation
//! - Test signalfd read after signal delivery
//! - Test signalfd nonblock (EAGAIN when empty)
//! - Test signalfd poll
//! - Test signalfd mask update

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_close, sys_gettid, sys_poll, sys_read, sys_rt_sigprocmask, sys_tgkill, sys_getpid,
    PollFd, POLLIN, SFD_NONBLOCK, SIG_BLOCK, SIGUSR1,
};

#[cfg(target_arch = "x86_64")]
use hk_syscall::sys_signalfd4;

#[cfg(target_arch = "aarch64")]
use hk_syscall::sys_signalfd4;

/// Run all signalfd tests
pub fn run_tests() {
    test_signalfd_create();
    test_signalfd_nonblock();
    test_signalfd_read();
    test_signalfd_poll();
    test_signalfd_mask_update();
}

/// Test signalfd4 creation
fn test_signalfd_create() {
    // Block SIGUSR1 first (signalfd requires signals to be blocked)
    let mask: u64 = 1 << (SIGUSR1 - 1);
    let mut old_mask: u64 = 0;
    let ret = sys_rt_sigprocmask(SIG_BLOCK, &mask as *const u64 as u64, &mut old_mask as *mut u64 as u64, 8);
    if ret != 0 {
        print(b"SIGNALFD_CREATE:FAIL: sigprocmask returned ");
        print_num(ret);
        return;
    }

    // Create signalfd for SIGUSR1
    let fd = sys_signalfd4(-1, &mask as *const u64, 8, 0);
    if fd < 0 {
        print(b"SIGNALFD_CREATE:FAIL: signalfd4 returned ");
        print_num(fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"SIGNALFD_CREATE:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    println(b"SIGNALFD_CREATE:OK");
}

/// Test signalfd nonblock - should return EAGAIN when no signals pending
fn test_signalfd_nonblock() {
    // Block SIGUSR1
    let mask: u64 = 1 << (SIGUSR1 - 1);
    let ret = sys_rt_sigprocmask(SIG_BLOCK, &mask as *const u64 as u64, 0, 8);
    if ret != 0 {
        print(b"SIGNALFD_NONBLOCK:FAIL: sigprocmask returned ");
        print_num(ret);
        return;
    }

    // Create signalfd with NONBLOCK
    let fd = sys_signalfd4(-1, &mask as *const u64, 8, SFD_NONBLOCK);
    if fd < 0 {
        print(b"SIGNALFD_NONBLOCK:FAIL: signalfd4 returned ");
        print_num(fd);
        return;
    }

    // Read should return EAGAIN (-11) since no signals pending
    let mut buf = [0u8; 128];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 128);
    sys_close(fd as u64);

    if ret == -11 {
        // EAGAIN
        println(b"SIGNALFD_NONBLOCK:OK");
    } else {
        print(b"SIGNALFD_NONBLOCK:FAIL: expected -11 (EAGAIN), got ");
        print_num(ret);
    }
}

/// Test signalfd read after signal delivery
fn test_signalfd_read() {
    // Block SIGUSR1
    let mask: u64 = 1 << (SIGUSR1 - 1);
    let ret = sys_rt_sigprocmask(SIG_BLOCK, &mask as *const u64 as u64, 0, 8);
    if ret != 0 {
        print(b"SIGNALFD_READ:FAIL: sigprocmask returned ");
        print_num(ret);
        return;
    }

    // Create signalfd with NONBLOCK so we don't block forever if signal not delivered
    let fd = sys_signalfd4(-1, &mask as *const u64, 8, SFD_NONBLOCK);
    if fd < 0 {
        print(b"SIGNALFD_READ:FAIL: signalfd4 returned ");
        print_num(fd);
        return;
    }

    // Send SIGUSR1 to ourselves
    let pid = sys_getpid();
    let tid = sys_gettid();
    let ret = sys_tgkill(pid, tid, SIGUSR1);
    if ret != 0 {
        print(b"SIGNALFD_READ:FAIL: tgkill returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Read should return signalfd_siginfo (128 bytes)
    let mut buf = [0u8; 128];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 128);
    sys_close(fd as u64);

    if ret != 128 {
        print(b"SIGNALFD_READ:FAIL: read returned ");
        print_num(ret);
        return;
    }

    // Check signal number (first 4 bytes of signalfd_siginfo.ssi_signo)
    let signo = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if signo != SIGUSR1 {
        print(b"SIGNALFD_READ:FAIL: expected signal ");
        print_num(SIGUSR1 as i64);
        print(b", got ");
        print_num(signo as i64);
        return;
    }

    println(b"SIGNALFD_READ:OK");
}

/// Test signalfd poll - POLLIN when signal pending
fn test_signalfd_poll() {
    // Block SIGUSR1
    let mask: u64 = 1 << (SIGUSR1 - 1);
    let ret = sys_rt_sigprocmask(SIG_BLOCK, &mask as *const u64 as u64, 0, 8);
    if ret != 0 {
        print(b"SIGNALFD_POLL:FAIL: sigprocmask returned ");
        print_num(ret);
        return;
    }

    // Create signalfd
    let fd = sys_signalfd4(-1, &mask as *const u64, 8, SFD_NONBLOCK);
    if fd < 0 {
        print(b"SIGNALFD_POLL:FAIL: signalfd4 returned ");
        print_num(fd);
        return;
    }

    // Poll should return 0 (no events, no signal pending)
    let mut pfd = PollFd {
        fd: fd as i32,
        events: POLLIN,
        revents: 0,
    };
    let ret = sys_poll(&mut pfd, 1, 0); // timeout=0 for non-blocking poll
    if ret != 0 || pfd.revents != 0 {
        print(b"SIGNALFD_POLL:FAIL: poll with no signal returned ");
        print_num(ret);
        print(b", revents=");
        print_num(pfd.revents as i64);
        sys_close(fd as u64);
        return;
    }

    // Send SIGUSR1 to ourselves
    let pid = sys_getpid();
    let tid = sys_gettid();
    let ret = sys_tgkill(pid, tid, SIGUSR1);
    if ret != 0 {
        print(b"SIGNALFD_POLL:FAIL: tgkill returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Poll should now return 1 with POLLIN
    pfd.revents = 0;
    let ret = sys_poll(&mut pfd, 1, 0);
    if ret != 1 {
        print(b"SIGNALFD_POLL:FAIL: poll after signal returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    if (pfd.revents & POLLIN) == 0 {
        print(b"SIGNALFD_POLL:FAIL: revents missing POLLIN, got ");
        print_num(pfd.revents as i64);
        sys_close(fd as u64);
        return;
    }

    // Consume the signal
    let mut buf = [0u8; 128];
    sys_read(fd as u64, buf.as_mut_ptr(), 128);
    sys_close(fd as u64);

    println(b"SIGNALFD_POLL:OK");
}

/// Test signalfd mask update
fn test_signalfd_mask_update() {
    // Block SIGUSR1
    let mask1: u64 = 1 << (SIGUSR1 - 1);
    let ret = sys_rt_sigprocmask(SIG_BLOCK, &mask1 as *const u64 as u64, 0, 8);
    if ret != 0 {
        print(b"SIGNALFD_MASK_UPDATE:FAIL: sigprocmask returned ");
        print_num(ret);
        return;
    }

    // Create signalfd for SIGUSR1
    let fd = sys_signalfd4(-1, &mask1 as *const u64, 8, SFD_NONBLOCK);
    if fd < 0 {
        print(b"SIGNALFD_MASK_UPDATE:FAIL: signalfd4 returned ");
        print_num(fd);
        return;
    }

    // Update mask to empty (no signals monitored)
    let mask2: u64 = 0;
    let ret = sys_signalfd4(fd as i32, &mask2 as *const u64, 8, 0);
    if ret != fd {
        print(b"SIGNALFD_MASK_UPDATE:FAIL: update returned ");
        print_num(ret);
        print(b", expected ");
        print_num(fd);
        sys_close(fd as u64);
        return;
    }

    // Send SIGUSR1 - it should not be readable via signalfd now (empty mask)
    let pid = sys_getpid();
    let tid = sys_gettid();
    sys_tgkill(pid, tid, SIGUSR1);

    // Read should return EAGAIN since mask is empty
    let mut buf = [0u8; 128];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 128);
    sys_close(fd as u64);

    if ret == -11 {
        // EAGAIN - empty mask means no signals match
        println(b"SIGNALFD_MASK_UPDATE:OK");
    } else {
        print(b"SIGNALFD_MASK_UPDATE:FAIL: expected -11 (EAGAIN), got ");
        print_num(ret);
    }
}
