//! A file's last close (Linux fput, fput_close_sync, task_work): the
//! release a close(2) or an exit causes is done when the call returns
//! or the parent sees the exit, even when it is deferred; releases that
//! cascade (an SCM_RIGHTS chain) finish too.
//!
//! - LAST_CLOSE_PIPE_EOF: the reader sees EOF right after the writer's
//!   close, and right after a child holding the write end exited
//! - LAST_CLOSE_SCM_CHAIN: a pipe read end in flight on a socket in
//!   flight on another is released when the receiver closes the outer
//!   one: the writer sees POLLERR (no reader)
//! - LAST_CLOSE_EPOLL: the last close of a watched file removes it from
//!   the epoll set

use crate::harness::{R, check, report_r};
use crate::net::unix::send_fds;
use hk_syscall::{
    AF_UNIX, EPOLL_CTL_ADD, EPOLLIN, EpollEvent, O_NONBLOCK, POLLERR, POLLOUT, PollFd, SOCK_DGRAM,
    sys_close, sys_epoll_create1, sys_epoll_ctl, sys_epoll_wait, sys_exit, sys_fork, sys_pipe2,
    sys_poll, sys_read, sys_socketpair, sys_wait4, sys_write,
};

pub fn run_tests() {
    report_r(b"LAST_CLOSE_PIPE_EOF", pipe_eof());
    report_r(b"LAST_CLOSE_SCM_CHAIN", scm_chain());
    report_r(b"LAST_CLOSE_EPOLL", epoll());
}

/// Descriptors closed on drop
struct Fds<const N: usize>([i32; N]);

impl<const N: usize> Drop for Fds<N> {
    fn drop(&mut self) {
        for &fd in &self.0 {
            if fd >= 0 {
                sys_close(fd as u64);
            }
        }
    }
}

impl<const N: usize> Fds<N> {
    /// Close descriptor `i` now
    fn close(&mut self, i: usize) {
        sys_close(self.0[i] as u64);
        self.0[i] = -1;
    }
}

fn pipe() -> Result<Fds<2>, (&'static [u8], i64)> {
    let mut p = [0i32; 2];
    let r = sys_pipe2(p.as_mut_ptr(), O_NONBLOCK);
    check(b"pipe2", r == 0, r)?;
    Ok(Fds(p))
}

fn read1(fd: i32) -> i64 {
    let mut b = [0u8; 1];
    sys_read(fd as u64, b.as_mut_ptr(), 1)
}

/// EOF (not EAGAIN) once the only write end is closed, by close(2) or
/// by its holder's exit
fn pipe_eof() -> R {
    let mut p = pipe()?;
    check(b"write", sys_write(p.0[1] as u64, b"x".as_ptr(), 1) == 1, 0)?;
    p.close(1);
    let n = read1(p.0[0]);
    check(b"data", n == 1, n)?;
    let n = read1(p.0[0]);
    check(b"eof after close", n == 0, n)?;

    let mut p = pipe()?;
    let pid = sys_fork();
    if pid == 0 {
        // The child exits holding the write end (and the read end)
        sys_exit(0);
    }
    check(b"fork", pid > 0, pid)?;
    p.close(1);
    let mut st = 0i32;
    let w = sys_wait4(pid, &mut st, 0, 0);
    check(b"wait4", w == pid, w)?;
    let n = read1(p.0[0]);
    check(b"eof after exit", n == 0, n)
}

/// A socket queues a pipe's read end; another queues that socket; the
/// last close of the outer receiver releases the chain
fn scm_chain() -> R {
    let mut p = pipe()?;
    let mut s1 = [0i32; 2];
    let r = sys_socketpair(AF_UNIX, SOCK_DGRAM, 0, &mut s1);
    check(b"socketpair 1", r == 0, r)?;
    let mut s1 = Fds(s1);
    let mut s2 = [0i32; 2];
    let r = sys_socketpair(AF_UNIX, SOCK_DGRAM, 0, &mut s2);
    check(b"socketpair 2", r == 0, r)?;
    let mut s2 = Fds(s2);
    // The read end in flight to s2[1], s2[1] in flight to s1[1]
    let r = send_fds(s2.0[0], b"r", &[p.0[0]]);
    check(b"send read end", r == 1, r)?;
    p.close(0);
    s2.close(0);
    let r = send_fds(s1.0[0], b"s", &[s2.0[1]]);
    check(b"send socket", r == 1, r)?;
    s2.close(1);
    let mut pf = PollFd {
        fd: p.0[1],
        events: POLLOUT,
        revents: 0,
    };
    let n = sys_poll(&mut pf, 1, 0);
    check(
        b"reader in flight",
        n == 1 && pf.revents & POLLERR == 0,
        i64::from(pf.revents),
    )?;
    s1.close(1);
    pf.revents = 0;
    let n = sys_poll(&mut pf, 1, 0);
    check(
        b"reader released",
        n == 1 && pf.revents & POLLERR != 0,
        i64::from(pf.revents),
    )
}

/// A ready watched pipe end is reported until its last close, then not
fn epoll() -> R {
    let ep = sys_epoll_create1(0);
    check(b"epoll_create1", ep >= 0, ep)?;
    let ep = Fds([ep as i32]);
    let mut p = pipe()?;
    let ev = EpollEvent::new(EPOLLIN, 7);
    let r = sys_epoll_ctl(ep.0[0], EPOLL_CTL_ADD, p.0[0], &ev);
    check(b"epoll_ctl", r == 0, r)?;
    check(b"write", sys_write(p.0[1] as u64, b"x".as_ptr(), 1) == 1, 0)?;
    let mut out = [EpollEvent::new(0, 0); 2];
    let n = sys_epoll_wait(ep.0[0], out.as_mut_ptr(), 2, 0);
    check(b"ready", n == 1, n)?;
    p.close(0);
    let n = sys_epoll_wait(ep.0[0], out.as_mut_ptr(), 2, 0);
    check(b"gone after close", n == 0, n)
}
