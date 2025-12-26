//! Eventfd tests
//!
//! Tests:
//! - Test eventfd2 creation
//! - Test eventfd read/write
//! - Test eventfd counter accumulation
//! - Test eventfd semaphore mode
//! - Test eventfd nonblock
//! - Test eventfd poll

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_close, sys_read, sys_write, sys_eventfd2, sys_poll,
    EFD_SEMAPHORE, EFD_NONBLOCK, PollFd, POLLIN,
};

/// Run all eventfd tests
pub fn run_tests() {
    test_eventfd_create();
    test_eventfd_read_write();
    test_eventfd_counter_add();
    test_eventfd_semaphore();
    test_eventfd_nonblock();
    test_eventfd_poll();
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

    println(b"EVENTFD_CREATE:OK");
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
    println(b"EVENTFD_RW:OK");
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
    println(b"EVENTFD_ADD:OK");
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
    println(b"EVENTFD_SEM:OK");
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
        println(b"EVENTFD_NONBLOCK:OK");
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
    println(b"EVENTFD_POLL:OK");
}
