//! Eventfd tests
//!
//! Tests:
//! - Test eventfd2 creation
//! - Test eventfd read/write
//! - Test eventfd counter accumulation
//! - Test eventfd semaphore mode
//! - Test eventfd nonblock
//! - Test eventfd poll
//! - Blocking read woken by a write; blocking write woken by a read

use crate::harness::pass;
use crate::helpers::{print, print_num, println};
use hk_syscall::{
    EFD_NONBLOCK, EFD_SEMAPHORE, POLLIN, PollFd, Timespec, sys_close, sys_eventfd2, sys_exit,
    sys_fork, sys_nanosleep, sys_poll, sys_read, sys_wait4, sys_write,
};

/// Run all eventfd tests
pub fn run_tests() {
    test_eventfd_create();
    test_eventfd_read_write();
    test_eventfd_counter_add();
    test_eventfd_semaphore();
    test_eventfd_nonblock();
    test_eventfd_poll();
    test_eventfd_block_read();
    test_eventfd_block_write();
}

/// Test eventfd2 creation
fn test_eventfd_create() {
    let fd = sys_eventfd2(0, 0);
    if fd < 0 {
        print(b"EVENTFD_CREATE:FAIL: returned ");
        print_num(fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"EVENTFD_CREATE:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    pass(b"EVENTFD_CREATE");
}

/// Test eventfd read/write with initial value
fn test_eventfd_read_write() {
    // Create eventfd with initial value 42
    let fd = sys_eventfd2(42, 0);
    if fd < 0 {
        print(b"EVENTFD_RW:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Read should return 42 and reset to 0
    let mut buf = [0u8; 8];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    if ret != 8 {
        print(b"EVENTFD_RW:FAIL: read returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    let value = u64::from_le_bytes(buf);
    if value != 42 {
        print(b"EVENTFD_RW:FAIL: expected 42, got ");
        print_num(value as i64);
        sys_close(fd as u64);
        return;
    }

    // Write a new value
    let write_val: u64 = 100;
    let write_buf = write_val.to_le_bytes();
    let ret = sys_write(fd as u64, write_buf.as_ptr(), 8);
    if ret != 8 {
        print(b"EVENTFD_RW:FAIL: write returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Read it back
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    if ret != 8 {
        print(b"EVENTFD_RW:FAIL: read2 returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    let value = u64::from_le_bytes(buf);
    if value != 100 {
        print(b"EVENTFD_RW:FAIL: expected 100, got ");
        print_num(value as i64);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"EVENTFD_RW");
}

/// Test eventfd counter accumulation (multiple writes add up)
fn test_eventfd_counter_add() {
    let fd = sys_eventfd2(0, 0);
    if fd < 0 {
        print(b"EVENTFD_ADD:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Write 10 three times
    let write_val: u64 = 10;
    let write_buf = write_val.to_le_bytes();
    for _ in 0..3 {
        let ret = sys_write(fd as u64, write_buf.as_ptr(), 8);
        if ret != 8 {
            print(b"EVENTFD_ADD:FAIL: write returned ");
            print_num(ret);
            sys_close(fd as u64);
            return;
        }
    }

    // Read should return 30 (10 + 10 + 10)
    let mut buf = [0u8; 8];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    if ret != 8 {
        print(b"EVENTFD_ADD:FAIL: read returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    let value = u64::from_le_bytes(buf);
    if value != 30 {
        print(b"EVENTFD_ADD:FAIL: expected 30, got ");
        print_num(value as i64);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"EVENTFD_ADD");
}

/// Test eventfd semaphore mode (read returns 1, decrements by 1)
fn test_eventfd_semaphore() {
    let fd = sys_eventfd2(3, EFD_SEMAPHORE);
    if fd < 0 {
        print(b"EVENTFD_SEM:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // First read should return 1 (not 3), counter becomes 2
    let mut buf = [0u8; 8];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    if ret != 8 {
        print(b"EVENTFD_SEM:FAIL: read1 returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    let value = u64::from_le_bytes(buf);
    if value != 1 {
        print(b"EVENTFD_SEM:FAIL: expected 1, got ");
        print_num(value as i64);
        sys_close(fd as u64);
        return;
    }

    // Second read should return 1, counter becomes 1
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    if ret != 8 {
        print(b"EVENTFD_SEM:FAIL: read2 returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    let value = u64::from_le_bytes(buf);
    if value != 1 {
        print(b"EVENTFD_SEM:FAIL: expected 1, got ");
        print_num(value as i64);
        sys_close(fd as u64);
        return;
    }

    // Third read should return 1, counter becomes 0
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    if ret != 8 {
        print(b"EVENTFD_SEM:FAIL: read3 returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    let value = u64::from_le_bytes(buf);
    if value != 1 {
        print(b"EVENTFD_SEM:FAIL: expected 1, got ");
        print_num(value as i64);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"EVENTFD_SEM");
}

/// Test eventfd with EFD_NONBLOCK returns EAGAIN when empty
fn test_eventfd_nonblock() {
    let fd = sys_eventfd2(0, EFD_NONBLOCK);
    if fd < 0 {
        print(b"EVENTFD_NONBLOCK:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Try to read from empty eventfd - should return EAGAIN (-11)
    let mut buf = [0u8; 8];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);

    if ret == -11 {
        // EAGAIN
        pass(b"EVENTFD_NONBLOCK");
    } else {
        print(b"EVENTFD_NONBLOCK:FAIL: read returned ");
        print_num(ret);
    }

    sys_close(fd as u64);
}

/// Test eventfd with poll
fn test_eventfd_poll() {
    // Create with initial value > 0 so it's immediately readable
    let fd = sys_eventfd2(1, 0);
    if fd < 0 {
        print(b"EVENTFD_POLL:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Poll should return POLLIN since count > 0
    let mut fds = [PollFd {
        fd: fd as i32,
        events: POLLIN,
        revents: 0,
    }];

    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);
    if ret < 0 {
        print(b"EVENTFD_POLL:FAIL: poll returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    if fds[0].revents & POLLIN == 0 {
        print(b"EVENTFD_POLL:FAIL: POLLIN not set, revents=");
        print_num(fds[0].revents as i64);
        sys_close(fd as u64);
        return;
    }

    // Read the value to empty it
    let mut buf = [0u8; 8];
    sys_read(fd as u64, buf.as_mut_ptr(), 8);

    // Now poll with timeout=0 should return 0 (no events ready)
    fds[0].revents = 0;
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);
    if ret != 0 {
        // Expect no fds ready
        print(b"EVENTFD_POLL:FAIL: poll after read returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"EVENTFD_POLL");
}

/// A child that sleeps 20 ms, then runs `f` on `fd` and exits 0 if it
/// returns true
fn after_delay(fd: i64, f: fn(i64) -> bool) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let ts = Timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        sys_nanosleep(&ts, core::ptr::null_mut());
        sys_exit(if f(fd) { 0 } else { 1 });
    }
    pid
}

fn reaped_ok(pid: i64) -> bool {
    let mut status = 0i32;
    sys_wait4(pid, &mut status, 0, 0) == pid && status == 0
}

/// A read of an empty eventfd sleeps until another process writes
fn test_eventfd_block_read() {
    let fd = sys_eventfd2(0, 0);
    let pid = after_delay(fd, |fd| {
        sys_write(fd as u64, 5u64.to_ne_bytes().as_ptr(), 8) == 8
    });
    let mut buf = [0u8; 8];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    let ok = reaped_ok(pid);
    sys_close(fd as u64);
    if ret == 8 && u64::from_ne_bytes(buf) == 5 && ok {
        pass(b"EVENTFD_BLOCK_READ");
    } else {
        print(b"EVENTFD_BLOCK_READ:FAIL: read returned ");
        print_num(ret);
    }
}

/// A write that would pass ULLONG_MAX - 1 sleeps until a read drains
/// the counter
fn test_eventfd_block_write() {
    let fd = sys_eventfd2(0, 0);
    let full = (u64::MAX - 1).to_ne_bytes();
    if sys_write(fd as u64, full.as_ptr(), 8) != 8 {
        println(b"EVENTFD_BLOCK_WRITE:FAIL: fill");
        sys_close(fd as u64);
        return;
    }
    let pid = after_delay(fd, |fd| {
        let mut b = [0u8; 8];
        sys_read(fd as u64, b.as_mut_ptr(), 8) == 8 && u64::from_ne_bytes(b) == u64::MAX - 1
    });
    let ret = sys_write(fd as u64, 3u64.to_ne_bytes().as_ptr(), 8);
    let ok = reaped_ok(pid);
    let mut buf = [0u8; 8];
    let got = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    sys_close(fd as u64);
    if ret == 8 && ok && got == 8 && u64::from_ne_bytes(buf) == 3 {
        pass(b"EVENTFD_BLOCK_WRITE");
    } else {
        print(b"EVENTFD_BLOCK_WRITE:FAIL: write returned ");
        print_num(ret);
    }
}
