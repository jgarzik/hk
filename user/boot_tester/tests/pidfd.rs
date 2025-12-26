//! Pidfd tests
//!
//! Tests:
//! - Test pidfd_open for current process
//! - Test pidfd_open with invalid pid returns ESRCH
//! - Test pidfd_open with invalid flags returns EINVAL
//! - Test pidfd_send_signal
//! - Test pidfd poll for exit
//! - Test procfs /proc/<pid>/fdinfo/<pidfd> shows Pid line
//! - Test waitid with P_PIDFD

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_fork, sys_getpid, sys_open, sys_poll, sys_read, sys_wait4, sys_waitid,
    sys_pidfd_open, sys_pidfd_send_signal,
    PollFd, SigInfo, POLLIN, P_PIDFD, WEXITED,
};

/// Run all pidfd tests
pub fn run_tests() {
    test_pidfd_open_self();
    test_pidfd_open_invalid_pid();
    test_pidfd_open_invalid_flags();
    test_pidfd_send_signal();
    test_pidfd_poll_exit();
    test_pidfd_fdinfo();
    test_waitid_p_pidfd();
}

/// Test pidfd_open for current process
fn test_pidfd_open_self() {
    let pid = sys_getpid();
    let fd = sys_pidfd_open(pid as i32, 0);

    if fd < 0 {
        print(b"PIDFD_OPEN_SELF:FAIL: returned ");
        print_num(fd);
        println(b"");
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"PIDFD_OPEN_SELF:FAIL: close returned ");
        print_num(close_ret);
        println(b"");
        return;
    }

    println(b"PIDFD_OPEN_SELF:OK");
}

/// Test pidfd_open with invalid (nonexistent) pid returns ESRCH (-3)
fn test_pidfd_open_invalid_pid() {
    let fd = sys_pidfd_open(99999, 0);

    if fd == -3 {
        // ESRCH
        println(b"PIDFD_OPEN_INVALID:OK");
    } else {
        print(b"PIDFD_OPEN_INVALID:FAIL: expected -3 (ESRCH), got ");
        print_num(fd);
        println(b"");
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
}

/// Test pidfd_open with invalid flags returns EINVAL (-22)
fn test_pidfd_open_invalid_flags() {
    let pid = sys_getpid();
    // Use an invalid flag (not O_NONBLOCK)
    let fd = sys_pidfd_open(pid as i32, 0xFFFF);

    if fd == -22 {
        // EINVAL
        println(b"PIDFD_OPEN_FLAGS:OK");
    } else {
        print(b"PIDFD_OPEN_FLAGS:FAIL: expected -22 (EINVAL), got ");
        print_num(fd);
        println(b"");
        if fd >= 0 {
            sys_close(fd as u64);
        }
    }
}

/// Test pidfd_send_signal sends signal 0 (null signal for permission check)
fn test_pidfd_send_signal() {
    let pid = sys_getpid();
    let fd = sys_pidfd_open(pid as i32, 0);
    if fd < 0 {
        print(b"PIDFD_SIGNAL:FAIL: pidfd_open returned ");
        print_num(fd);
        println(b"");
        return;
    }

    // Send signal 0 (null signal - just checks permissions)
    let ret = sys_pidfd_send_signal(fd as i32, 0, core::ptr::null(), 0);
    if ret != 0 {
        print(b"PIDFD_SIGNAL:FAIL: pidfd_send_signal returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"PIDFD_SIGNAL:OK");
}

/// Test pidfd poll returns POLLIN when process exits
fn test_pidfd_poll_exit() {
    // Fork a child that will exit immediately
    let fork_ret = sys_fork();
    if fork_ret < 0 {
        print(b"PIDFD_POLL:FAIL: fork returned ");
        print_num(fork_ret);
        println(b"");
        return;
    }

    if fork_ret == 0 {
        // Child - exit immediately with status 42
        hk_syscall::sys_exit(42);
    }

    // Parent - create pidfd for child
    let child_pid = fork_ret;
    let pidfd = sys_pidfd_open(child_pid as i32, 0);
    if pidfd < 0 {
        print(b"PIDFD_POLL:FAIL: pidfd_open returned ");
        print_num(pidfd);
        println(b"");
        // Reap the child
        sys_wait4(-1, core::ptr::null_mut(), 0, 0);
        return;
    }

    // Poll with a short timeout - child should exit and pidfd become readable
    let mut fds = [PollFd {
        fd: pidfd as i32,
        events: POLLIN,
        revents: 0,
    }];

    let ret = sys_poll(fds.as_mut_ptr(), 1, 1000); // 1 second timeout
    if ret < 0 {
        print(b"PIDFD_POLL:FAIL: poll returned ");
        print_num(ret);
        println(b"");
        sys_close(pidfd as u64);
        sys_wait4(-1, core::ptr::null_mut(), 0, 0);
        return;
    }

    if ret == 0 {
        println(b"PIDFD_POLL:FAIL: poll timed out");
        sys_close(pidfd as u64);
        sys_wait4(-1, core::ptr::null_mut(), 0, 0);
        return;
    }

    if fds[0].revents & POLLIN == 0 {
        print(b"PIDFD_POLL:FAIL: POLLIN not set, revents=");
        print_num(fds[0].revents as i64);
        println(b"");
        sys_close(pidfd as u64);
        sys_wait4(-1, core::ptr::null_mut(), 0, 0);
        return;
    }

    sys_close(pidfd as u64);
    // Reap the child
    sys_wait4(-1, core::ptr::null_mut(), 0, 0);
    println(b"PIDFD_POLL:OK");
}

/// Test that /proc/<pid>/fdinfo/<pidfd> contains "Pid:" line for pidfds
fn test_pidfd_fdinfo() {
    let pid = sys_getpid();
    let pidfd = sys_pidfd_open(pid as i32, 0);
    if pidfd < 0 {
        print(b"PIDFD_FDINFO:FAIL: pidfd_open returned ");
        print_num(pidfd);
        println(b"");
        return;
    }

    // Build path: /proc/<pid>/fdinfo/<fd>
    let mut path = [0u8; 64];
    let prefix = b"/proc/";
    let mid = b"/fdinfo/";

    let mut pos = 0;
    for b in prefix {
        path[pos] = *b;
        pos += 1;
    }

    // Write pid as string
    pos = write_num_to_buf(&mut path, pos, pid as u64);

    for b in mid {
        path[pos] = *b;
        pos += 1;
    }

    // Write fd as string
    pos = write_num_to_buf(&mut path, pos, pidfd as u64);
    path[pos] = 0; // null terminate

    // Open and read the fdinfo file
    let fd = sys_open(path.as_ptr(), 0, 0);
    if fd < 0 {
        print(b"PIDFD_FDINFO:FAIL: open returned ");
        print_num(fd);
        println(b"");
        sys_close(pidfd as u64);
        return;
    }

    let mut buf = [0u8; 256];
    let bytes_read = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    sys_close(fd as u64);

    if bytes_read < 0 {
        print(b"PIDFD_FDINFO:FAIL: read returned ");
        print_num(bytes_read);
        println(b"");
        sys_close(pidfd as u64);
        return;
    }

    // Look for "Pid:" in the output
    let content = &buf[..bytes_read as usize];
    let needle = b"Pid:";
    let found = find_bytes(content, needle);

    sys_close(pidfd as u64);

    if found {
        println(b"PIDFD_FDINFO:OK");
    } else {
        println(b"PIDFD_FDINFO:FAIL: Pid: line not found in fdinfo");
    }
}

/// Test waitid with P_PIDFD
fn test_waitid_p_pidfd() {
    // Fork a child that will exit
    let fork_ret = sys_fork();
    if fork_ret < 0 {
        print(b"WAITID_PIDFD:FAIL: fork returned ");
        print_num(fork_ret);
        println(b"");
        return;
    }

    if fork_ret == 0 {
        // Child - exit with status 77
        hk_syscall::sys_exit(77);
    }

    // Parent - create pidfd for child
    let child_pid = fork_ret;
    let pidfd = sys_pidfd_open(child_pid as i32, 0);
    if pidfd < 0 {
        print(b"WAITID_PIDFD:FAIL: pidfd_open returned ");
        print_num(pidfd);
        println(b"");
        // Reap the child with wait4 as fallback
        sys_wait4(-1, core::ptr::null_mut(), 0, 0);
        return;
    }

    // Use waitid with P_PIDFD
    let mut info = SigInfo {
        si_signo: 0,
        si_errno: 0,
        si_code: 0,
        _pad0: 0,
        si_pid: 0,
        si_uid: 0,
        si_status: 0,
        _pad: [0u8; 128 - 28],
    };
    let ret = sys_waitid(P_PIDFD, pidfd as u64, &mut info, WEXITED);

    sys_close(pidfd as u64);

    if ret < 0 {
        print(b"WAITID_PIDFD:FAIL: waitid returned ");
        print_num(ret);
        println(b"");
        // Try to reap with wait4 as fallback
        sys_wait4(-1, core::ptr::null_mut(), 0, 0);
        return;
    }

    // Check that si_pid matches child_pid
    if info.si_pid != child_pid as i32 {
        print(b"WAITID_PIDFD:FAIL: si_pid=");
        print_num(info.si_pid as i64);
        print(b" expected ");
        print_num(child_pid);
        println(b"");
        return;
    }

    println(b"WAITID_PIDFD:OK");
}

// Helper: write a number to a buffer as ASCII digits, return new position
fn write_num_to_buf(buf: &mut [u8], start: usize, num: u64) -> usize {
    if num == 0 {
        buf[start] = b'0';
        return start + 1;
    }

    let mut n = num;
    let mut digits = [0u8; 20];
    let mut count = 0;

    while n > 0 {
        digits[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }

    let mut pos = start;
    for i in (0..count).rev() {
        buf[pos] = digits[i];
        pos += 1;
    }
    pos
}

// Helper: find needle bytes in haystack
fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }

    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
    }
    false
}
