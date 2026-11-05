//! Poll/Select tests
//!
//! Tests:
//! - Test poll() basic functionality with pipes
//! - Test poll() timeout behavior (immediate, short timeout)
//! - Test poll() POLLNVAL for bad fd
//! - Test select() basic functionality with pipes
//! - Test select() timeout behavior
//! - Test ppoll() with NULL sigmask
//! - Test pselect6() with NULL sigmask

use super::helpers::{print, print_num, println};
use hk_syscall::{
    FdSet, POLLIN, POLLNVAL, POLLOUT, PollFd, Timespec, Timeval, sys_close, sys_pipe2, sys_poll,
    sys_ppoll, sys_pselect6, sys_read, sys_select, sys_write,
};

/// Run all poll/select tests
pub fn run_tests() {
    test_poll_pipe_readable();
    test_poll_timeout_zero();
    test_poll_bad_fd();
    test_poll_write_ready();
    test_select_pipe_readable();
    test_select_timeout_zero();
    test_ppoll_null_sigmask();
    test_ppoll_with_timeout();
    test_pselect6_null_sigmask();
    report_nfds(in_child_nfds());
}

/// poll takes up to RLIMIT_NOFILE entries (EINVAL past it), select any
/// nfds up to the table's size (Linux do_sys_poll, core_sys_select);
/// both past the old fixed 1024. In a child that raises RLIMIT_NOFILE
fn in_child_nfds() -> i64 {
    let pid = hk_syscall::sys_fork();
    if pid == 0 {
        hk_syscall::sys_exit(nfds_check() as u64);
    }
    let mut st = 0i32;
    hk_syscall::sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        80
    } else {
        ((st >> 8) & 0xff) as i64
    }
}

fn nfds_check() -> i64 {
    const RLIMIT_NOFILE: u32 = 7;
    const N: usize = 4097;
    let lim = hk_syscall::RLimit {
        rlim_cur: 4096,
        rlim_max: 4096,
    };
    if hk_syscall::sys_setrlimit(RLIMIT_NOFILE, &lim) != 0 {
        return 1;
    }
    let efd = hk_syscall::sys_eventfd2(1, 0) as i32;
    let size = core::mem::size_of::<PollFd>();
    let buf = hk_syscall::sys_mmap(0, (N * size) as u64, 3, 0x22, -1, 0);
    if efd < 0 || buf < 0 {
        return 2;
    }
    // SAFETY: the mapping just made, N entries
    let fds = unsafe { core::slice::from_raw_parts_mut(buf as *mut PollFd, N) };
    for f in fds.iter_mut() {
        f.fd = -1;
        f.events = 0;
        f.revents = 0;
    }
    fds[1999].fd = efd;
    fds[1999].events = POLLIN as i16;
    if sys_poll(fds.as_mut_ptr(), 2000, 0) != 1 {
        return 3;
    }
    if sys_poll(fds.as_mut_ptr(), N as u32, 0) != -22 {
        return 4;
    }
    // select with nfds 2000 and the eventfd at 1500
    if hk_syscall::sys_dup3(efd, 1500, 0) != 1500 {
        return 5;
    }
    let mut set = [0u64; 32];
    set[1500 / 64] |= 1 << (1500 % 64);
    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let r = sys_select(
        2000,
        set.as_mut_ptr() as *mut FdSet,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut tv,
    );
    if r != 1 || set[1500 / 64] & (1 << (1500 % 64)) == 0 {
        return 6;
    }
    0
}

fn report_nfds(step: i64) {
    print(b"POLL_SELECT_NFDS");
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
}

/// Test poll() with a readable pipe
fn test_poll_pipe_readable() {
    // Create pipe
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"POLL_PIPE_READ:FAIL pipe2 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Write data to pipe to make it readable
    let data = b"x";
    let wret = sys_write(pipefd[1] as u64, data.as_ptr(), 1);
    if wret != 1 {
        print(b"POLL_PIPE_READ:FAIL write returned ");
        print_num(wret);
        println(b"");
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Poll for read readiness with timeout=0 (immediate)
    let mut fds = [PollFd::new(pipefd[0], POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    if ret == 1 && (fds[0].revents & POLLIN) != 0 {
        println(b"POLL_PIPE_READ:OK");
    } else {
        print(b"POLL_PIPE_READ:FAIL ret=");
        print_num(ret);
        print(b" revents=");
        print_num(fds[0].revents as i64);
        println(b"");
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
}

/// Test poll() with timeout=0 on non-ready fd
fn test_poll_timeout_zero() {
    // Create pipe (no data written, so not readable)
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"POLL_TIMEOUT_ZERO:FAIL pipe2 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Poll with timeout=0 should return 0 immediately
    let mut fds = [PollFd::new(pipefd[0], POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    if ret == 0 {
        println(b"POLL_TIMEOUT_ZERO:OK");
    } else {
        print(b"POLL_TIMEOUT_ZERO:FAIL expected 0, got ");
        print_num(ret);
        println(b"");
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
}

/// Test poll() with bad fd returns POLLNVAL
fn test_poll_bad_fd() {
    // Poll on fd 9999 which should be invalid
    let mut fds = [PollFd::new(9999, POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    // poll returns 1 (one fd with events) and sets POLLNVAL
    if ret == 1 && (fds[0].revents & POLLNVAL) != 0 {
        println(b"POLL_BAD_FD:OK");
    } else {
        print(b"POLL_BAD_FD:FAIL ret=");
        print_num(ret);
        print(b" revents=");
        print_num(fds[0].revents as i64);
        println(b"");
    }
}

/// Test poll() for write readiness on pipe
fn test_poll_write_ready() {
    // Create pipe
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"POLL_WRITE_READY:FAIL pipe2 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Write end should be immediately writable (buffer not full)
    let mut fds = [PollFd::new(pipefd[1], POLLOUT)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    if ret == 1 && (fds[0].revents & POLLOUT) != 0 {
        println(b"POLL_WRITE_READY:OK");
    } else {
        print(b"POLL_WRITE_READY:FAIL ret=");
        print_num(ret);
        print(b" revents=");
        print_num(fds[0].revents as i64);
        println(b"");
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
}

/// Test select() with a readable pipe
fn test_select_pipe_readable() {
    // Create pipe
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"SELECT_PIPE_READ:FAIL pipe2 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Write data to pipe
    let data = b"y";
    let wret = sys_write(pipefd[1] as u64, data.as_ptr(), 1);
    if wret != 1 {
        print(b"SELECT_PIPE_READ:FAIL write returned ");
        print_num(wret);
        println(b"");
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Set up read fd_set
    let mut readfds = FdSet::new();
    readfds.set(pipefd[0]);

    // Select with timeout=0
    let mut timeout = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let nfds = pipefd[0] + 1;
    let ret = sys_select(
        nfds,
        &mut readfds as *mut FdSet,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut timeout as *mut Timeval,
    );

    if ret == 1 && readfds.is_set(pipefd[0]) {
        println(b"SELECT_PIPE_READ:OK");
    } else {
        print(b"SELECT_PIPE_READ:FAIL ret=");
        print_num(ret);
        print(b" fd0=");
        print_num(pipefd[0] as i64);
        print(b" fd1=");
        print_num(pipefd[1] as i64);
        print(b" nfds=");
        print_num(nfds as i64);
        println(b"");
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
}

/// Test select() with timeout=0 on non-ready fd
fn test_select_timeout_zero() {
    // Create pipe (no data)
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"SELECT_TIMEOUT_ZERO:FAIL pipe2 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    let mut readfds = FdSet::new();
    readfds.set(pipefd[0]);

    let mut timeout = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let nfds = pipefd[0] + 1;
    let ret = sys_select(
        nfds,
        &mut readfds as *mut FdSet,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut timeout as *mut Timeval,
    );

    // Should return 0 (no fds ready)
    if ret == 0 {
        println(b"SELECT_TIMEOUT_ZERO:OK");
    } else {
        print(b"SELECT_TIMEOUT_ZERO:FAIL expected 0, got ");
        print_num(ret);
        println(b"");
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
}

/// Test ppoll() with NULL sigmask
fn test_ppoll_null_sigmask() {
    // Create pipe and write data
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"PPOLL_NULL_SIGMASK:FAIL pipe2 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    let data = b"z";
    sys_write(pipefd[1] as u64, data.as_ptr(), 1);

    // ppoll with timeout=0 and NULL sigmask
    let mut fds = [PollFd::new(pipefd[0], POLLIN)];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = sys_ppoll(fds.as_mut_ptr(), 1, &timeout, 0, 0);

    if ret == 1 && (fds[0].revents & POLLIN) != 0 {
        println(b"PPOLL_NULL_SIGMASK:OK");
    } else {
        print(b"PPOLL_NULL_SIGMASK:FAIL ret=");
        print_num(ret);
        print(b" revents=");
        print_num(fds[0].revents as i64);
        println(b"");
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
}

/// Test ppoll() with a small timeout
fn test_ppoll_with_timeout() {
    // Create pipe (no data)
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"PPOLL_TIMEOUT:FAIL pipe2 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // ppoll with 1ms timeout, no data - should timeout
    let mut fds = [PollFd::new(pipefd[0], POLLIN)];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000, // 1ms
    };
    let ret = sys_ppoll(fds.as_mut_ptr(), 1, &timeout, 0, 0);

    // Should return 0 (timeout, no fds ready)
    if ret == 0 {
        println(b"PPOLL_TIMEOUT:OK");
    } else {
        print(b"PPOLL_TIMEOUT:FAIL expected 0, got ");
        print_num(ret);
        println(b"");
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
}

/// Test pselect6() with NULL sigmask
fn test_pselect6_null_sigmask() {
    // Create pipe and write data
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"PSELECT6_NULL_SIGMASK:FAIL pipe2 returned ");
        print_num(ret);
        println(b"");
        return;
    }

    let data = b"w";
    let w1 = sys_write(pipefd[1] as u64, data.as_ptr(), 1);
    if w1 != 1 {
        print(b"PSELECT6_NULL_SIGMASK:FAIL write1 returned ");
        print_num(w1);
        println(b"");
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Drain the pipe to verify we can read
    let mut buf = [0u8; 1];
    let r1 = sys_read(pipefd[0] as u64, buf.as_mut_ptr(), 1);
    if r1 != 1 {
        print(b"PSELECT6_NULL_SIGMASK:FAIL read returned ");
        print_num(r1);
        println(b"");
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Write again for the actual test
    let w2 = sys_write(pipefd[1] as u64, data.as_ptr(), 1);
    if w2 != 1 {
        print(b"PSELECT6_NULL_SIGMASK:FAIL write2 returned ");
        print_num(w2);
        println(b"");
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    let mut readfds = FdSet::new();
    readfds.set(pipefd[0]);

    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let nfds = pipefd[0] + 1;
    let ret = sys_pselect6(
        nfds,
        &mut readfds as *mut FdSet,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &timeout,
        0, // NULL sigmask
    );

    if ret == 1 && readfds.is_set(pipefd[0]) {
        println(b"PSELECT6_NULL_SIGMASK:OK");
    } else {
        print(b"PSELECT6_NULL_SIGMASK:FAIL ret=");
        print_num(ret);
        print(b" fd0=");
        print_num(pipefd[0] as i64);
        print(b" fd1=");
        print_num(pipefd[1] as i64);
        print(b" nfds=");
        print_num(nfds as i64);
        println(b"");
    }

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
}
