//! Pidfd tests
//!
//! Tests:
//! - Test pidfd_open for current process
//! - Test pidfd_open with invalid pid returns ESRCH
//! - Test pidfd_open with invalid flags returns EINVAL
//! - Test pidfd_send_signal
//! - Test pidfd poll for exit
//! - Test pidfd poll for the exit of a child reaped at once (SIGCHLD
//!   ignored)
//! - Test procfs /proc/<pid>/fdinfo/<pidfd> shows Pid line
//! - Test waitid with P_PIDFD
//! - WAITID_PIDFD_NONBLOCK: waitid(P_PIDFD) of an O_NONBLOCK pidfd is
//!   EAGAIN while the child runs (Linux kernel_waitid adds WNOHANG)
//! - Test pidfd_getfd to get own fd via pidfd
//! - Test pidfd_getfd with invalid flags returns EINVAL
//! - PIDFD_POLL_GROUP: a process whose leader exits first is not
//!   readable while another thread (here a traced zombie) is listed;
//!   readable once that one is reaped, POLLHUP once the process is
//!   (Linux pidfd_poll: delay_group_leader, no task)
//! - PIDFD_OPEN_THREAD: pidfd_open of a non-leader thread without
//!   PIDFD_THREAD fails (ENOENT since 6.16, EINVAL before)
//! - PIDFD_OPEN_CLOEXEC: the new descriptor is close-on-exec

use crate::harness::{fail_num, pass, verdict};
use crate::helpers::{linux_at_least, msleep, print, print_num, println};
use crate::mm::fork_mm::{join, spawn_thread};
use hk_syscall::{
    O_NONBLOCK, P_PIDFD, POLLHUP, POLLIN, PollFd, SIGKILL, SigInfo, WEXITED, sys_close, sys_exit,
    sys_exit_group, sys_fcntl, sys_fork, sys_getpid, sys_kill, sys_open, sys_pidfd_getfd,
    sys_pidfd_open, sys_pidfd_send_signal, sys_pipe2, sys_poll, sys_ptrace, sys_read,
    sys_rt_sigaction, sys_wait4, sys_waitid, sys_write,
};

/// Run all pidfd tests
pub fn run_tests() {
    test_pidfd_open_self();
    test_pidfd_open_invalid_pid();
    test_pidfd_open_invalid_flags();
    test_pidfd_send_signal();
    test_pidfd_poll_exit();
    test_pidfd_poll_autoreap();
    test_pidfd_fdinfo();
    test_waitid_p_pidfd();
    test_waitid_pidfd_nonblock();
    test_pidfd_getfd_self();
    test_pidfd_getfd_invalid_flags();
    test_pidfd_poll_group();
    test_pidfd_open_thread();
    test_pidfd_open_cloexec();
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;

/// Start `f(arg)` as a second thread of this process: its tid
fn start(f: extern "C" fn(u64) -> !, arg: u64) -> i64 {
    let top = unsafe { (&raw mut STACK as *mut u8).add(16384) as u64 };
    // Nonzero until the thread's exit clears it (no CLONE_CHILD_SETTID)
    unsafe { core::ptr::write_volatile(&raw mut CTID, 1) };
    unsafe { spawn_thread(top, f, arg, &raw mut CTID) }
}

/// Read a byte from `fd`, then exit the thread with status 3
extern "C" fn exit3_after(fd: u64) -> ! {
    let mut c = [0u8; 1];
    sys_read(fd, c.as_mut_ptr(), 1);
    sys_exit(3)
}

/// The events of `fd` within `ms` (0 on timeout)
fn poll_in(fd: i64, ms: i32) -> i16 {
    let mut fds = [PollFd {
        fd: fd as i32,
        events: POLLIN,
        revents: 0,
    }];
    if sys_poll(fds.as_mut_ptr(), 1, ms) == 1 {
        fds[0].revents
    } else {
        0
    }
}

/// PIDFD_POLL_GROUP, in a helper process (it traces its child's thread)
fn test_pidfd_poll_group() {
    let h = sys_fork();
    if h == 0 {
        sys_exit_group(poll_group() as u64);
    }
    let mut st = 0i32;
    sys_wait4(h, &mut st, 0, 0);
    verdict(b"PIDFD_POLL_GROUP", st == 0, i64::from(st));
}

/// [`test_pidfd_poll_group`]'s helper: its child's second thread,
/// traced from here, exits, then the child's leader; 0 if the pidfd
/// becomes readable only once the thread is reaped, and hangs up once
/// the child is; else the failed step
fn poll_group() -> i32 {
    const PTRACE_SEIZE: i64 = 0x4206;
    const WALL: i32 = 0x4000_0000;
    let mut tids = [0i32; 2];
    let mut block = [0i32; 2];
    let mut lead = [0i32; 2];
    sys_pipe2(tids.as_mut_ptr(), 0);
    sys_pipe2(block.as_mut_ptr(), 0);
    sys_pipe2(lead.as_mut_ptr(), 0);
    let c = sys_fork();
    if c == 0 {
        let t = [start(exit3_after, block[0] as u64)];
        sys_write(tids[1] as u64, t.as_ptr() as *const u8, 8);
        let mut b = [0u8; 1];
        sys_read(lead[0] as u64, b.as_mut_ptr(), 1);
        // The leader alone: the thread is still listed
        sys_exit(0);
    }
    let pidfd = sys_pidfd_open(c as i32, 0);
    let mut t = [0i64; 1];
    sys_read(tids[0] as u64, t.as_mut_ptr() as *mut u8, 8);
    let seized = sys_ptrace(PTRACE_SEIZE, t[0], 0, 0);
    sys_write(block[1] as u64, b"t".as_ptr(), 1);
    sys_write(lead[1] as u64, b"l".as_ptr(), 1);
    let r = if pidfd < 0 || t[0] <= 0 || seized != 0 {
        1
    } else if poll_in(pidfd, 300) != 0 {
        // Leader exited, traced zombie thread still listed
        2
    } else {
        let mut st = 0i32;
        let w = sys_wait4(t[0], &mut st, WALL, 0);
        let ev = poll_in(pidfd, 2000);
        if w != t[0] {
            3
        } else if ev & POLLIN == 0 || ev & POLLHUP != 0 {
            4
        } else {
            sys_wait4(c, &mut st, 0, 0);
            let ev = poll_in(pidfd, 0);
            // POLLHUP for a reaped process since Linux 6.9
            let hup = !linux_at_least(6, 9) || ev & POLLHUP != 0;
            if ev & POLLIN == 0 || !hup { 5 } else { 0 }
        }
    };
    if r != 0 {
        // The traced thread first: the child is not reaped before it
        hk_syscall::sys_kill(c, 9);
        sys_wait4(t[0], core::ptr::null_mut(), WALL, 0);
        sys_wait4(c, core::ptr::null_mut(), 0, 0);
    }
    r
}

/// Read a byte from `fd`, then exit the thread
extern "C" fn exit_after(fd: u64) -> ! {
    let mut c = [0u8; 1];
    sys_read(fd, c.as_mut_ptr(), 1);
    sys_exit(0)
}

/// PIDFD_OPEN_THREAD: in a helper process, pidfd_open of its second
/// thread without PIDFD_THREAD (Linux pidfd_prepare: not a thread-group
/// leader's pid; ENOENT since 6.16, EINVAL before)
fn test_pidfd_open_thread() {
    let h = sys_fork();
    if h == 0 {
        let mut go = [0i32; 2];
        sys_pipe2(go.as_mut_ptr(), 0);
        let t = start(exit_after, go[0] as u64);
        let r = sys_pidfd_open(t as i32, 0);
        sys_write(go[1] as u64, b"x".as_ptr(), 1);
        join(&raw mut CTID);
        let want = if linux_at_least(6, 16) { -2 } else { -22 };
        sys_exit_group(if t > 0 && r == want { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(h, &mut st, 0, 0);
    verdict(b"PIDFD_OPEN_THREAD", st == 0, i64::from(st));
}

/// PIDFD_OPEN_CLOEXEC: pidfd_open's descriptor is close-on-exec
/// (Linux pidfd_prepare: get_unused_fd_flags(O_CLOEXEC))
fn test_pidfd_open_cloexec() {
    const F_GETFD: i32 = 1;
    let fd = sys_pidfd_open(sys_getpid() as i32, 0);
    let fl = if fd >= 0 {
        sys_fcntl(fd as i32, F_GETFD, 0)
    } else {
        fd
    };
    if fd >= 0 {
        sys_close(fd as u64);
    }
    verdict(b"PIDFD_OPEN_CLOEXEC", fl == 1, fl);
}

/// Test pidfd_open for current process
fn test_pidfd_open_self() {
    let pid = sys_getpid();
    let fd = sys_pidfd_open(pid as i32, 0);

    if fd < 0 {
        fail_num(b"PIDFD_OPEN_SELF:FAIL: returned ", fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        fail_num(b"PIDFD_OPEN_SELF:FAIL: close returned ", close_ret);
        return;
    }

    pass(b"PIDFD_OPEN_SELF");
}

/// Test pidfd_open with invalid (nonexistent) pid returns ESRCH (-3)
fn test_pidfd_open_invalid_pid() {
    let fd = sys_pidfd_open(99999, 0);

    if fd == -3 {
        // ESRCH
        pass(b"PIDFD_OPEN_INVALID");
    } else {
        fail_num(b"PIDFD_OPEN_INVALID:FAIL: expected -3 (ESRCH), got ", fd);
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
        pass(b"PIDFD_OPEN_FLAGS");
    } else {
        fail_num(b"PIDFD_OPEN_FLAGS:FAIL: expected -22 (EINVAL), got ", fd);
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
        fail_num(b"PIDFD_SIGNAL:FAIL: pidfd_open returned ", fd);
        return;
    }

    // Send signal 0 (null signal - just checks permissions)
    let ret = sys_pidfd_send_signal(fd as i32, 0, core::ptr::null(), 0);
    if ret != 0 {
        fail_num(b"PIDFD_SIGNAL:FAIL: pidfd_send_signal returned ", ret);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"PIDFD_SIGNAL");
}

/// Test pidfd poll returns POLLIN when process exits
fn test_pidfd_poll_exit() {
    // Fork a child that will exit immediately
    let fork_ret = sys_fork();
    if fork_ret < 0 {
        fail_num(b"PIDFD_POLL:FAIL: fork returned ", fork_ret);
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
        fail_num(b"PIDFD_POLL:FAIL: pidfd_open returned ", pidfd);
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
        fail_num(b"PIDFD_POLL:FAIL: poll returned ", ret);
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
        fail_num(
            b"PIDFD_POLL:FAIL: POLLIN not set, revents=",
            fds[0].revents as i64,
        );
        sys_close(pidfd as u64);
        sys_wait4(-1, core::ptr::null_mut(), 0, 0);
        return;
    }

    sys_close(pidfd as u64);
    // Reap the child
    sys_wait4(-1, core::ptr::null_mut(), 0, 0);
    pass(b"PIDFD_POLL");
}

/// A child its parent does not wait for (SIGCHLD ignored) is reaped at
/// its exit, and its pidfd still becomes readable (Linux: the pidfd is
/// woken before the autoreap, and a pid with no task polls POLLIN). In
/// a helper process, so no other child of ours is reaped at once.
fn test_pidfd_poll_autoreap() {
    let h = sys_fork();
    if h == 0 {
        sys_exit_group(autoreap_poll() as u64);
    }
    let mut st = 0i32;
    sys_wait4(h, &mut st, 0, 0);
    verdict(b"PIDFD_POLL_AUTOREAP", st == 0, i64::from(st));
}

/// [`test_pidfd_poll_autoreap`]'s helper: 0 if the pidfd of its child,
/// reaped at its exit, is readable within 2 s; else a code
fn autoreap_poll() -> i32 {
    const SIGCHLD: u32 = 17;
    const SIG_IGN: u64 = 1;
    let ign: [u64; 4] = [SIG_IGN, 0, 0, 0];
    sys_rt_sigaction(SIGCHLD, ign.as_ptr() as u64, 0, 8);
    let mut go = [0i32; 2];
    sys_pipe2(go.as_mut_ptr(), 0);
    let c = sys_fork();
    if c == 0 {
        // Exit once the parent closes the pipe
        sys_close(go[1] as u64);
        let mut b = [0u8; 1];
        sys_read(go[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let pidfd = sys_pidfd_open(c as i32, 0);
    sys_close(go[0] as u64);
    sys_close(go[1] as u64);
    if pidfd < 0 {
        return 1;
    }
    let mut fds = [PollFd {
        fd: pidfd as i32,
        events: POLLIN,
        revents: 0,
    }];
    let r = sys_poll(fds.as_mut_ptr(), 1, 2000);
    if r != 1 {
        return 2;
    }
    if fds[0].revents & POLLIN == 0 {
        return 3;
    }
    0
}

/// Test that /proc/<pid>/fdinfo/<pidfd> contains "Pid:" line for pidfds
fn test_pidfd_fdinfo() {
    let pid = sys_getpid();
    let pidfd = sys_pidfd_open(pid as i32, 0);
    if pidfd < 0 {
        fail_num(b"PIDFD_FDINFO:FAIL: pidfd_open returned ", pidfd);
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
        fail_num(b"PIDFD_FDINFO:FAIL: open returned ", fd);
        sys_close(pidfd as u64);
        return;
    }

    let mut buf = [0u8; 256];
    let bytes_read = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    sys_close(fd as u64);

    if bytes_read < 0 {
        fail_num(b"PIDFD_FDINFO:FAIL: read returned ", bytes_read);
        sys_close(pidfd as u64);
        return;
    }

    // Look for "Pid:" in the output
    let content = &buf[..bytes_read as usize];
    let needle = b"Pid:";
    let found = find_bytes(content, needle);

    sys_close(pidfd as u64);

    if found {
        pass(b"PIDFD_FDINFO");
    } else {
        println(b"PIDFD_FDINFO:FAIL: Pid: line not found in fdinfo");
    }
}

/// Test waitid with P_PIDFD
fn test_waitid_p_pidfd() {
    // Fork a child that will exit
    let fork_ret = sys_fork();
    if fork_ret < 0 {
        fail_num(b"WAITID_PIDFD:FAIL: fork returned ", fork_ret);
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
        fail_num(b"WAITID_PIDFD:FAIL: pidfd_open returned ", pidfd);
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
    let ret = sys_waitid(P_PIDFD, pidfd as u64, &mut info, WEXITED, 0);

    sys_close(pidfd as u64);

    if ret < 0 {
        fail_num(b"WAITID_PIDFD:FAIL: waitid returned ", ret);
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

    pass(b"WAITID_PIDFD");
}

/// An empty siginfo for waitid
fn siginfo() -> SigInfo {
    SigInfo {
        si_signo: 0,
        si_errno: 0,
        si_code: 0,
        _pad0: 0,
        si_pid: 0,
        si_uid: 0,
        si_status: 0,
        _pad: [0u8; 128 - 28],
    }
}

/// waitid(P_PIDFD) of an O_NONBLOCK pidfd (PIDFD_NONBLOCK) waits as
/// with WNOHANG (Linux kernel_waitid_prepare): EAGAIN while the child
/// runs and WNOHANG was not asked, 0 with an empty siginfo when it was,
/// and the child once it is dead
fn test_waitid_pidfd_nonblock() {
    const NAME: &[u8] = b"WAITID_PIDFD_NONBLOCK";
    const WNOHANG: i32 = 1;
    const EAGAIN: i64 = -11;
    let pid = sys_fork();
    if pid < 0 {
        fail_num(b"WAITID_PIDFD_NONBLOCK:FAIL fork ", pid);
        return;
    }
    if pid == 0 {
        // Bounded, so a kernel that blocks still finishes the test
        msleep(2000);
        sys_exit(0);
    }
    let fd = sys_pidfd_open(pid as i32, O_NONBLOCK);
    if fd < 0 {
        sys_kill(pid, SIGKILL);
        sys_wait4(pid, core::ptr::null_mut(), 0, 0);
        fail_num(b"WAITID_PIDFD_NONBLOCK:FAIL pidfd_open ", fd);
        return;
    }
    let mut info = siginfo();
    let busy = sys_waitid(P_PIDFD, fd as u64, &mut info, WEXITED, 0);
    let mut nohang_info = siginfo();
    nohang_info.si_pid = -1;
    let nohang = sys_waitid(P_PIDFD, fd as u64, &mut nohang_info, WEXITED | WNOHANG, 0);
    sys_kill(pid, SIGKILL);
    // EAGAIN until it is a zombie
    let mut dead_info = siginfo();
    let mut dead = EAGAIN;
    for _ in 0..1000 {
        dead = sys_waitid(P_PIDFD, fd as u64, &mut dead_info, WEXITED, 0);
        if dead != EAGAIN {
            break;
        }
        msleep(1);
    }
    sys_close(fd as u64);
    if busy == 0 {
        // Reaped by the blocking wait (a kernel without the rule)
        dead = 0;
        dead_info.si_pid = pid as i32;
    } else if dead == EAGAIN {
        sys_wait4(pid, core::ptr::null_mut(), 0, 0);
    }
    if busy != EAGAIN {
        fail_num(b"WAITID_PIDFD_NONBLOCK:FAIL running: waitid ", busy);
    } else if nohang != 0 || nohang_info.si_pid != 0 {
        fail_num(b"WAITID_PIDFD_NONBLOCK:FAIL WNOHANG: waitid ", nohang);
    } else if dead != 0 || dead_info.si_pid != pid as i32 {
        fail_num(b"WAITID_PIDFD_NONBLOCK:FAIL dead: waitid ", dead);
    } else {
        pass(NAME);
    }
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

// =============================================================================
// pidfd_getfd tests
// =============================================================================

/// Test pidfd_getfd to get own file descriptor via pidfd
///
/// Creates a pidfd for the current process, then uses pidfd_getfd
/// to duplicate fd 0 (stdin) via the pidfd. This tests the basic
/// functionality without requiring a separate process.
fn test_pidfd_getfd_self() {
    let pid = sys_getpid();
    let pidfd = sys_pidfd_open(pid as i32, 0);

    if pidfd < 0 {
        fail_num(b"PIDFD_GETFD_SELF:FAIL: pidfd_open returned ", pidfd);
        return;
    }

    // Get fd 0 (stdin) via pidfd_getfd
    // Note: fd 0 should always exist as stdin
    let new_fd = sys_pidfd_getfd(pidfd as i32, 0, 0);

    let _ = sys_close(pidfd as u64);

    if new_fd < 0 {
        fail_num(b"PIDFD_GETFD_SELF:FAIL: pidfd_getfd returned ", new_fd);
        return;
    }

    // Close the duplicated fd
    let _ = sys_close(new_fd as u64);

    pass(b"PIDFD_GETFD_SELF");
}

/// Test pidfd_getfd with invalid flags returns EINVAL
fn test_pidfd_getfd_invalid_flags() {
    let pid = sys_getpid();
    let pidfd = sys_pidfd_open(pid as i32, 0);

    if pidfd < 0 {
        println(b"PIDFD_GETFD_FLAGS:SKIP (pidfd_open failed)");
        return;
    }

    // Try with invalid flags (should return EINVAL = -22)
    let ret = sys_pidfd_getfd(pidfd as i32, 0, 0xFFFF);

    let _ = sys_close(pidfd as u64);

    if ret == -22 {
        // EINVAL
        pass(b"PIDFD_GETFD_FLAGS");
    } else {
        fail_num(b"PIDFD_GETFD_FLAGS:FAIL: expected -22, got ", ret);
    }
}
