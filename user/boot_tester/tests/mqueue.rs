//! POSIX Message Queue tests
//!
//! Tests:
//! - Test mq_open creates a new queue
//! - Test mq_open opens existing queue
//! - Test mq_open with O_CREAT|O_EXCL returns EEXIST
//! - Test mq_open without O_CREAT returns ENOENT
//! - Test mq_unlink removes queue
//! - Test mq_send and mq_receive
//! - Test mq_priority ordering
//! - Test mq_nonblock returns EAGAIN
//! - Test mq_getsetattr
//! - Test mq_close fd
//! - Test mq_emsgsize

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_close, sys_mq_open, sys_mq_unlink, sys_mq_timedsend, sys_mq_timedreceive,
    sys_mq_getsetattr, MqAttr, O_RDWR, O_CREAT, O_NONBLOCK, O_EXCL,
};

// Error codes
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
#[allow(dead_code)] // Available for future tests
const EINVAL: i64 = -22;
const EMSGSIZE: i64 = -90;

// Access modes for future tests
#[allow(dead_code)]
const O_RDONLY: i32 = 0;
#[allow(dead_code)]
const O_WRONLY: i32 = 1;

/// Run all mqueue tests
pub fn run_tests() {
    test_mq_open_create();
    test_mq_open_existing();
    test_mq_open_excl();
    test_mq_open_enoent();
    test_mq_unlink();
    test_mq_send_receive();
    test_mq_priority_ordering();
    test_mq_nonblock_eagain();
    test_mq_getsetattr();
    test_mq_close_fd();
    test_mq_emsgsize();
}

/// Test mq_open creates a new queue
fn test_mq_open_create() {
    let name = b"/test_mq_create\0";

    // Create a new queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);

    if fd < 0 {
        print(b"MQ_OPEN_CREATE:FAIL: returned ");
        print_num(fd);
        return;
    }

    // Clean up
    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());

    println(b"MQ_OPEN_CREATE:OK");
}

/// Test mq_open opens existing queue
fn test_mq_open_existing() {
    let name = b"/test_mq_existing\0";

    // Create the queue first
    let attr = MqAttr::new(10, 256);
    let fd1 = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd1 < 0 {
        print(b"MQ_OPEN_EXISTING:FAIL: create returned ");
        print_num(fd1);
        return;
    }

    // Open the same queue again (without O_CREAT)
    let fd2 = sys_mq_open(name.as_ptr(), O_RDWR as i32, 0, core::ptr::null());
    if fd2 < 0 {
        print(b"MQ_OPEN_EXISTING:FAIL: reopen returned ");
        print_num(fd2);
        sys_close(fd1 as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Both should be valid (different fds)
    if fd1 != fd2 && fd2 >= 0 {
        println(b"MQ_OPEN_EXISTING:OK");
    } else {
        print(b"MQ_OPEN_EXISTING:FAIL: fd1=");
        print_num(fd1);
        print(b" fd2=");
        print_num(fd2);
    }

    sys_close(fd1 as u64);
    sys_close(fd2 as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_open with O_CREAT|O_EXCL returns EEXIST if queue exists
fn test_mq_open_excl() {
    let name = b"/test_mq_excl\0";

    // Create the queue first
    let attr = MqAttr::new(10, 256);
    let fd1 = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd1 < 0 {
        print(b"MQ_OPEN_EXCL:FAIL: first create returned ");
        print_num(fd1);
        return;
    }

    // Try to create again with O_EXCL - should fail
    let fd2 = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32 | O_EXCL as i32, 0o644, &attr);
    if fd2 == EEXIST {
        println(b"MQ_OPEN_EXCL:OK");
    } else {
        print(b"MQ_OPEN_EXCL:FAIL: expected -17, got ");
        print_num(fd2);
    }

    sys_close(fd1 as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_open without O_CREAT returns ENOENT for non-existent queue
fn test_mq_open_enoent() {
    let name = b"/test_mq_nonexistent\0";

    // Try to open non-existent queue without O_CREAT
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32, 0, core::ptr::null());
    if fd == ENOENT {
        println(b"MQ_OPEN_ENOENT:OK");
    } else {
        print(b"MQ_OPEN_ENOENT:FAIL: expected -2, got ");
        print_num(fd);
        if fd >= 0 {
            sys_close(fd as u64);
            sys_mq_unlink(name.as_ptr());
        }
    }
}

/// Test mq_unlink removes queue
fn test_mq_unlink() {
    let name = b"/test_mq_unlink\0";

    // Create queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_UNLINK:FAIL: create returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Unlink it
    let ret = sys_mq_unlink(name.as_ptr());
    if ret != 0 {
        print(b"MQ_UNLINK:FAIL: unlink returned ");
        print_num(ret);
        return;
    }

    // Try to open again - should fail with ENOENT
    let fd2 = sys_mq_open(name.as_ptr(), O_RDWR as i32, 0, core::ptr::null());
    if fd2 == ENOENT {
        println(b"MQ_UNLINK:OK");
    } else {
        print(b"MQ_UNLINK:FAIL: reopen expected -2, got ");
        print_num(fd2);
        if fd2 >= 0 {
            sys_close(fd2 as u64);
            sys_mq_unlink(name.as_ptr());
        }
    }
}

/// Test mq_send and mq_receive
fn test_mq_send_receive() {
    let name = b"/test_mq_sendrecv\0";
    let msg = b"Hello, mqueue!";

    // Create queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_SEND_RECEIVE:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Send message
    let ret = sys_mq_timedsend(fd as i32, msg.as_ptr(), msg.len(), 0, core::ptr::null());
    if ret != 0 {
        print(b"MQ_SEND_RECEIVE:FAIL: send returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Receive message
    let mut buf = [0u8; 256];
    let mut prio: u32 = 0;
    let ret = sys_mq_timedreceive(fd as i32, buf.as_mut_ptr(), buf.len(), &mut prio, core::ptr::null());
    if ret < 0 {
        print(b"MQ_SEND_RECEIVE:FAIL: receive returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Verify message
    if ret as usize == msg.len() && &buf[..msg.len()] == msg {
        println(b"MQ_SEND_RECEIVE:OK");
    } else {
        print(b"MQ_SEND_RECEIVE:FAIL: message mismatch, len=");
        print_num(ret);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_priority ordering (higher priority received first)
fn test_mq_priority_ordering() {
    let name = b"/test_mq_priority\0";
    let msg_lo = b"low priority";
    let msg_hi = b"high priority";

    // Create queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_PRIORITY:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Send low priority first
    let ret = sys_mq_timedsend(fd as i32, msg_lo.as_ptr(), msg_lo.len(), 1, core::ptr::null());
    if ret != 0 {
        print(b"MQ_PRIORITY:FAIL: send low returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Send high priority second
    let ret = sys_mq_timedsend(fd as i32, msg_hi.as_ptr(), msg_hi.len(), 10, core::ptr::null());
    if ret != 0 {
        print(b"MQ_PRIORITY:FAIL: send high returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Receive - should get high priority first
    let mut buf = [0u8; 256];
    let mut prio: u32 = 0;
    let ret = sys_mq_timedreceive(fd as i32, buf.as_mut_ptr(), buf.len(), &mut prio, core::ptr::null());
    if ret < 0 {
        print(b"MQ_PRIORITY:FAIL: receive returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Should be high priority message (prio=10)
    if prio == 10 && ret as usize == msg_hi.len() && &buf[..msg_hi.len()] == msg_hi {
        println(b"MQ_PRIORITY:OK");
    } else {
        print(b"MQ_PRIORITY:FAIL: expected prio=10, got ");
        print_num(prio as i64);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_nonblock returns EAGAIN on empty queue
fn test_mq_nonblock_eagain() {
    let name = b"/test_mq_nonblock\0";

    // Create queue with O_NONBLOCK
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32 | O_NONBLOCK as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_NONBLOCK:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Try to receive from empty queue - should return EAGAIN
    let mut buf = [0u8; 256];
    let mut prio: u32 = 0;
    let ret = sys_mq_timedreceive(fd as i32, buf.as_mut_ptr(), buf.len(), &mut prio, core::ptr::null());
    if ret == EAGAIN {
        println(b"MQ_NONBLOCK:OK");
    } else {
        print(b"MQ_NONBLOCK:FAIL: expected -11, got ");
        print_num(ret);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq_getsetattr
fn test_mq_getsetattr() {
    let name = b"/test_mq_attr\0";

    // Create queue
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_GETSETATTR:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Get current attributes
    let mut old_attr = MqAttr::default();
    let ret = sys_mq_getsetattr(fd as i32, core::ptr::null(), &mut old_attr);
    if ret != 0 {
        print(b"MQ_GETSETATTR:FAIL: getattr returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_mq_unlink(name.as_ptr());
        return;
    }

    // Verify attributes match what we set
    if old_attr.mq_maxmsg == 10 && old_attr.mq_msgsize == 256 {
        println(b"MQ_GETSETATTR:OK");
    } else {
        print(b"MQ_GETSETATTR:FAIL: maxmsg=");
        print_num(old_attr.mq_maxmsg);
        print(b" msgsize=");
        print_num(old_attr.mq_msgsize);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

/// Test mq operations on closed fd returns EBADF
fn test_mq_close_fd() {
    let name = b"/test_mq_close\0";

    // Create and immediately close
    let attr = MqAttr::new(10, 256);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_CLOSE_FD:FAIL: create returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Try to use closed fd - should return EBADF
    let mut buf = [0u8; 256];
    let mut prio: u32 = 0;
    let ret = sys_mq_timedreceive(fd as i32, buf.as_mut_ptr(), buf.len(), &mut prio, core::ptr::null());
    if ret == EBADF {
        println(b"MQ_CLOSE_FD:OK");
    } else {
        print(b"MQ_CLOSE_FD:FAIL: expected -9, got ");
        print_num(ret);
    }

    sys_mq_unlink(name.as_ptr());
}

/// Test mq_send with message too large returns EMSGSIZE
fn test_mq_emsgsize() {
    let name = b"/test_mq_msgsize\0";

    // Create queue with small message size
    let attr = MqAttr::new(10, 16); // Only 16 bytes max
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o644, &attr);
    if fd < 0 {
        print(b"MQ_EMSGSIZE:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Try to send message larger than max
    let msg = b"This message is way too long for the queue!";
    let ret = sys_mq_timedsend(fd as i32, msg.as_ptr(), msg.len(), 0, core::ptr::null());
    if ret == EMSGSIZE {
        println(b"MQ_EMSGSIZE:OK");
    } else {
        print(b"MQ_EMSGSIZE:FAIL: expected -90, got ");
        print_num(ret);
    }

    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}
