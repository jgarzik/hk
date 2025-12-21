//! IPC Tests - pipe, poll, select
//!
//! Tests for inter-process communication primitives.

use crate::syscall::{
    sys_close, sys_pipe, sys_poll, sys_read, sys_select, sys_write,
    FdSet, PollFd, Timeval, POLLIN, POLLNVAL, POLLOUT,
};
use super::helpers::{print, println, print_num};

/// Run all IPC tests
pub fn run_tests() {
    println(b"=== IPC Tests ===");

    test_pipe_basic();
    test_pipe_read_write();
    test_poll_data_ready();
    test_poll_no_data();
    test_poll_invalid_fd();
    test_poll_write_ready();
    test_select_data_ready();
    test_select_no_data();
}

/// Test basic pipe creation
fn test_pipe_basic() {

    let mut pipefd: [i32; 2] = [0, 0];
    let ret = sys_pipe(pipefd.as_mut_ptr());

    print(b"pipe() returned ");
    print_num(ret);
    print(b", fds=[");
    print_num(pipefd[0] as i64);
    print(b", ");
    print_num(pipefd[1] as i64);
    println(b"]");

    if ret == 0 && pipefd[0] > 0 && pipefd[1] > 0 {
        // Clean up
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        println(b"PIPE_CREATE:OK");
    } else {
        println(b"PIPE_CREATE:FAIL");
    }
}

/// Test pipe read/write
fn test_pipe_read_write() {

    let mut pipefd: [i32; 2] = [0, 0];
    let ret = sys_pipe(pipefd.as_mut_ptr());
    if ret != 0 {
        print(b"pipe() failed with ");
        print_num(ret);
        println(b"PIPE_RW:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Write "hello" to the pipe
    let msg = b"hello";
    let written = sys_write(write_fd as u64, msg.as_ptr(), msg.len() as u64);

    print(b"write() returned ");
    print_num(written);

    if written != 5 {
        println(b"PIPE_RW:FAIL");
        sys_close(read_fd as u64);
        sys_close(write_fd as u64);
        return;
    }

    // Read it back
    let mut buf: [u8; 16] = [0; 16];
    let read_bytes = sys_read(read_fd as u64, buf.as_mut_ptr(), 16);

    print(b"read() returned ");
    print_num(read_bytes);

    if read_bytes != 5 {
        println(b"PIPE_RW:FAIL");
        sys_close(read_fd as u64);
        sys_close(write_fd as u64);
        return;
    }

    // Verify data matches
    let matches = buf[0] == b'h' && buf[1] == b'e' && buf[2] == b'l'
                  && buf[3] == b'l' && buf[4] == b'o';

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    if matches {
        println(b"PIPE_RW:OK");
    } else {
        println(b"PIPE_RW:FAIL");
    }
}

/// Test poll with data ready
fn test_poll_data_ready() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"POLL_DATA:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Write data to pipe
    let msg = b"x";
    sys_write(write_fd as u64, msg.as_ptr(), 1);

    // Poll for read readiness with timeout 0 (immediate)
    let mut fds = [PollFd::new(read_fd, POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    print(b"poll() returned ");
    print_num(ret);
    print(b", revents=");
    print_num(fds[0].revents as i64);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 1 (one fd ready) with POLLIN set
    if ret == 1 && (fds[0].revents & POLLIN) != 0 {
        println(b"POLL_DATA:OK");
    } else {
        println(b"POLL_DATA:FAIL");
    }
}

/// Test poll with no data (should timeout)
fn test_poll_no_data() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"POLL_TIMEOUT:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Don't write any data
    // Poll with timeout 0 (immediate return)
    let mut fds = [PollFd::new(read_fd, POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    print(b"poll() returned ");
    print_num(ret);
    print(b", revents=");
    print_num(fds[0].revents as i64);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 0 (no fds ready, timeout)
    if ret == 0 {
        println(b"POLL_TIMEOUT:OK");
    } else {
        println(b"POLL_TIMEOUT:FAIL");
    }
}

/// Test poll with invalid fd
fn test_poll_invalid_fd() {

    // Poll a clearly invalid fd
    let mut fds = [PollFd::new(9999, POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    print(b"poll() returned ");
    print_num(ret);
    print(b", revents=");
    print_num(fds[0].revents as i64);

    // poll() should return 1 with POLLNVAL set in revents (not EBADF)
    if ret == 1 && (fds[0].revents & POLLNVAL) != 0 {
        println(b"POLL_INVALID:OK");
    } else {
        println(b"POLL_INVALID:FAIL");
    }
}

/// Test poll for write readiness on pipe
fn test_poll_write_ready() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"POLL_WRITE:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Poll write end - should be ready (buffer empty)
    let mut fds = [PollFd::new(write_fd, POLLOUT)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    print(b"poll() returned ");
    print_num(ret);
    print(b", revents=");
    print_num(fds[0].revents as i64);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 1 (write fd ready) with POLLOUT set
    if ret == 1 && (fds[0].revents & POLLOUT) != 0 {
        println(b"POLL_WRITE:OK");
    } else {
        println(b"POLL_WRITE:FAIL");
    }
}

/// Test select with data ready
fn test_select_data_ready() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"SELECT_DATA:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Write data to pipe
    let msg = b"x";
    sys_write(write_fd as u64, msg.as_ptr(), 1);

    // Set up fd_set for read_fd
    let mut readfds = FdSet::new();
    readfds.zero(); // Ensure proper zeroing (volatile writes)
    readfds.set(read_fd);

    // Timeout 0 (immediate)
    let mut tv = Timeval { tv_sec: 0, tv_usec: 0 };

    let ret = sys_select(read_fd + 1, &mut readfds, core::ptr::null_mut(), core::ptr::null_mut(), &mut tv);

    print(b"select() returned ");
    print_num(ret);
    print(b", is_set=");
    print_num(if readfds.is_set(read_fd) { 1 } else { 0 });

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 1 (one fd ready) with read_fd still set
    if ret == 1 && readfds.is_set(read_fd) {
        println(b"SELECT_DATA:OK");
    } else {
        println(b"SELECT_DATA:FAIL");
    }
}

/// Test select with no data
fn test_select_no_data() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"SELECT_TIMEOUT:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Don't write data
    let mut readfds = FdSet::new();
    readfds.zero(); // Ensure proper zeroing (volatile writes)
    readfds.set(read_fd);

    // Timeout 0 (immediate)
    let mut tv = Timeval { tv_sec: 0, tv_usec: 0 };

    let ret = sys_select(read_fd + 1, &mut readfds, core::ptr::null_mut(), core::ptr::null_mut(), &mut tv);

    print(b"select() returned ");
    print_num(ret);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 0 (timeout, no fds ready)
    // Note: select clears the fd_set on timeout
    if ret == 0 {
        println(b"SELECT_TIMEOUT:OK");
    } else {
        println(b"SELECT_TIMEOUT:FAIL");
    }
}
