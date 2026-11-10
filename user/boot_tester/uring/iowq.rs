//! io-wq: requests that would block run in io worker threads of the
//! submitter's process (Linux io_uring/io-wq.c, create_io_thread):
//! - IO_URING_PUNT_PIPE: a read of an empty pipe does not block
//!   io_uring_enter; it completes, into the submitter's buffer, once
//!   data is written
//! - IO_URING_ASYNC_WORKER: an IOSQE_ASYNC request runs in an io worker,
//!   a thread of the process (/proc/self/status Threads)
//! - IO_URING_PUNT_EXIT: a process exiting with a read blocked in a
//!   worker is reaped
//! - IO_URING_DRAIN: an IOSQE_IO_DRAIN request waits for the one before
//!   it without blocking io_uring_enter; the CQEs come in order
//! - IO_URING_LINK: a chain behind a blocked read does not block
//!   io_uring_enter and runs in order
//! - IO_URING_FIXED_PAGES: READ_FIXED of a buffered file fills the
//!   registered buffer's pinned pages, not whatever is mapped at its
//!   address now (Linux ITER_BVEC)

use super::dio::Buf;
use super::wait::now_ms;
use super::{Ring, sqe};
use crate::harness::{R, check, report_r};
use crate::helpers::{msleep, read_file};
use hk_syscall::{
    IORING_ENTER_GETEVENTS, IORING_OP_NOP, IORING_OP_READ, IORING_OP_READ_FIXED,
    IORING_REGISTER_BUFFERS, IoVec, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, PROT_READ, PROT_WRITE,
    sys_close, sys_exit, sys_fork, sys_io_uring_register, sys_kill, sys_memfd_create, sys_mmap,
    sys_pipe2, sys_wait4, sys_write,
};

const IOSQE_IO_DRAIN: u8 = 1 << 1;
const IOSQE_IO_LINK: u8 = 1 << 2;
const IOSQE_ASYNC: u8 = 1 << 4;

pub fn run_tests() {
    let cases: [(&[u8], fn() -> R); 6] = [
        (b"IO_URING_PUNT_PIPE", punt_pipe),
        (b"IO_URING_ASYNC_WORKER", async_worker),
        (b"IO_URING_PUNT_EXIT", punt_exit),
        (b"IO_URING_DRAIN", drain),
        (b"IO_URING_LINK", link),
        (b"IO_URING_FIXED_PAGES", fixed_pages),
    ];
    for (name, t) in cases {
        report_r(name, t());
    }
}

/// A pipe: (read end, write end)
fn pipe() -> Result<(i32, i32), (&'static [u8], i64)> {
    let mut p = [0i32; 2];
    let n = sys_pipe2(p.as_mut_ptr(), 0);
    check(b"pipe2", n == 0, n)?;
    Ok((p[0], p[1]))
}

/// A child that writes `data` to `fd` after `ms` ms, then exits; its pid
fn writer(fd: i32, ms: u64, data: &'static [u8]) -> Result<i64, (&'static [u8], i64)> {
    let pid = sys_fork();
    if pid == 0 {
        msleep(ms);
        sys_write(fd as u64, data.as_ptr(), data.len() as u64);
        sys_exit(0);
    }
    check(b"fork", pid > 0, pid)?;
    Ok(pid)
}

fn reap(pid: i64) {
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
}

/// Wait up to 2 s for `n` CQEs
fn wait(r: &Ring, n: u32) -> i64 {
    let ts = hk_syscall::Timespec {
        tv_sec: 2,
        tv_nsec: 0,
    };
    let arg = [0u64, 0, &ts as *const hk_syscall::Timespec as u64];
    hk_syscall::sys_io_uring_enter(
        r.fd as u32,
        0,
        n,
        IORING_ENTER_GETEVENTS | hk_syscall::IORING_ENTER_EXT_ARG,
        arg.as_ptr() as u64,
        24,
    )
}

/// Submit what is queued; how long io_uring_enter took (ms)
fn submit_timed(r: &Ring, n: u32) -> Result<i64, (&'static [u8], i64)> {
    let t = now_ms();
    let k = r.enter(n, 0, 0);
    let dt = now_ms() - t;
    check(b"submit", k == i64::from(n), k)?;
    Ok(dt)
}

fn punt_pipe() -> R {
    let (rd, wr) = pipe()?;
    let res = (|| {
        let mut r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
        let mut buf = [0u8; 16];
        r.push(sqe(
            IORING_OP_READ,
            rd,
            buf.as_mut_ptr() as u64,
            16,
            u64::MAX,
            1,
        ));
        let pid = writer(wr, 300, b"hello")?;
        let dt = submit_timed(&r, 1)?;
        let early = r.pop();
        let n = wait(&r, 1);
        let c = r.pop();
        reap(pid);
        check(b"enter blocked (ms)", dt < 200, dt)?;
        check(b"cqe before the write", early.is_none(), 0)?;
        check(b"wait", n == 0, n)?;
        let c = c.ok_or((&b"no cqe"[..], 0))?;
        check(b"res", c.res == 5, i64::from(c.res))?;
        check(b"data", &buf[..5] == b"hello", 0)
    })();
    sys_close(rd as u64);
    sys_close(wr as u64);
    res
}

/// This process's threads (/proc/self/status Threads)
fn threads() -> i64 {
    let mut b = [0u8; 2048];
    let n = read_file(b"/proc/self/status\0", &mut b);
    let s = &b[..n.max(0) as usize];
    s.split(|&c| c == b'\n')
        .find(|l| l.starts_with(b"Threads:"))
        .map(|l| {
            l[8..]
                .iter()
                .filter(|c| c.is_ascii_digit())
                .fold(0i64, |v, &c| v * 10 + i64::from(c - b'0'))
        })
        .unwrap_or(-1)
}

/// In a fresh child (no workers yet): an IOSQE_ASYNC read of an empty
/// pipe runs in a new thread; exit code 0 if so
fn async_child(rd: i32, wr: i32) -> u64 {
    let Ok(mut r) = Ring::simple(4) else { return 1 };
    let before = threads();
    let mut buf = [0u8; 8];
    let mut s = sqe(IORING_OP_READ, rd, buf.as_mut_ptr() as u64, 8, u64::MAX, 1);
    s.flags = IOSQE_ASYNC;
    r.push(s);
    if r.enter(1, 0, 0) != 1 {
        return 2;
    }
    msleep(100);
    let during = threads();
    sys_write(wr as u64, b"x".as_ptr(), 1);
    if wait(&r, 1) != 0 {
        return 3;
    }
    match r.pop() {
        Some(c) if c.res == 1 => {}
        _ => return 4,
    }
    if during <= before {
        return 5;
    }
    0
}

fn async_worker() -> R {
    let (rd, wr) = pipe()?;
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(async_child(rd, wr));
    }
    let mut st = 0;
    let w = sys_wait4(pid, &mut st, 0, 0);
    sys_close(rd as u64);
    sys_close(wr as u64);
    check(b"fork", pid > 0 && w == pid, pid)?;
    check(b"child", st >> 8 == 0, i64::from(st >> 8))
}

/// In a child: a read of an empty pipe goes to a worker, then exit
fn exit_child(rd: i32) -> u64 {
    let Ok(mut r) = Ring::simple(4) else { return 1 };
    let mut buf = [0u8; 8];
    r.push(sqe(
        IORING_OP_READ,
        rd,
        buf.as_mut_ptr() as u64,
        8,
        u64::MAX,
        1,
    ));
    if r.enter(1, 0, 0) != 1 {
        return 2;
    }
    core::mem::forget(r);
    0
}

fn punt_exit() -> R {
    let (rd, wr) = pipe()?;
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(exit_child(rd));
    }
    let res = (|| {
        check(b"fork", pid > 0, pid)?;
        let mut st = 0;
        for _ in 0..300 {
            if sys_wait4(pid, &mut st, 1, 0) == pid {
                return check(b"child status", st >> 8 == 0, i64::from(st >> 8));
            }
            msleep(10);
        }
        sys_kill(pid, 9);
        reap(pid);
        check(b"child never exited", false, 0)
    })();
    sys_close(rd as u64);
    sys_close(wr as u64);
    res
}

fn drain() -> R {
    let (rd, wr) = pipe()?;
    let res = (|| {
        let mut r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
        let mut buf = [0u8; 8];
        r.push(sqe(
            IORING_OP_READ,
            rd,
            buf.as_mut_ptr() as u64,
            8,
            u64::MAX,
            1,
        ));
        let mut d = sqe(IORING_OP_NOP, -1, 0, 0, 0, 2);
        d.flags = IOSQE_IO_DRAIN;
        r.push(d);
        let pid = writer(wr, 300, b"y")?;
        let dt = submit_timed(&r, 2)?;
        let early = r.pop();
        let n = wait(&r, 2);
        reap(pid);
        check(b"enter blocked (ms)", dt < 200, dt)?;
        check(b"cqe before the write", early.is_none(), 0)?;
        check(b"wait", n == 0, n)?;
        let a = r.pop().ok_or((&b"no first cqe"[..], 0))?;
        let b = r.pop().ok_or((&b"no second cqe"[..], 0))?;
        check(
            b"read first",
            a.user_data == 1 && a.res == 1,
            a.user_data as i64,
        )?;
        check(
            b"drain second",
            b.user_data == 2 && b.res == 0,
            b.user_data as i64,
        )
    })();
    sys_close(rd as u64);
    sys_close(wr as u64);
    res
}

fn link() -> R {
    let (rd, wr) = pipe()?;
    let res = (|| {
        let mut r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
        let mut buf = [0u8; 8];
        // One byte asked: not short (a short read breaks the chain)
        let mut a = sqe(IORING_OP_READ, rd, buf.as_mut_ptr() as u64, 1, u64::MAX, 1);
        a.flags = IOSQE_IO_LINK;
        r.push(a);
        r.push(sqe(IORING_OP_NOP, -1, 0, 0, 0, 2));
        let pid = writer(wr, 300, b"z")?;
        let dt = submit_timed(&r, 2)?;
        let n = wait(&r, 2);
        reap(pid);
        check(b"enter blocked (ms)", dt < 200, dt)?;
        check(b"wait", n == 0, n)?;
        let a = r.pop().ok_or((&b"no first cqe"[..], 0))?;
        let b = r.pop().ok_or((&b"no second cqe"[..], 0))?;
        check(
            b"read first",
            a.user_data == 1 && a.res == 1,
            a.user_data as i64,
        )?;
        check(
            b"nop second",
            b.user_data == 2 && b.res == 0,
            b.user_data as i64,
        )
    })();
    sys_close(rd as u64);
    sys_close(wr as u64);
    res
}

fn fixed_pages() -> R {
    let fd = sys_memfd_create(b"fx\0".as_ptr(), 0);
    check(b"memfd", fd >= 0, fd)?;
    let fd = fd as i32;
    let res = (|| {
        let data = [0x5au8; 4096];
        let w = sys_write(fd as u64, data.as_ptr(), 4096);
        check(b"write", w == 4096, w)?;
        let mut r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
        let b = Buf::new(4096)?;
        b.bytes(0, 4096).fill(1);
        let iov = IoVec {
            iov_base: b.p,
            iov_len: 4096,
        };
        let n = sys_io_uring_register(
            r.fd as u32,
            IORING_REGISTER_BUFFERS,
            &iov as *const _ as u64,
            1,
        );
        check(b"register", n == 0, n)?;
        // New pages at the buffer's address; the registered ones stay
        // pinned, unmapped
        let p = sys_mmap(
            b.p as u64,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        );
        check(b"remap", p == b.p as i64, p)?;
        r.push(sqe(IORING_OP_READ_FIXED, fd, b.addr(0), 4096, 0, 1));
        let k = r.submit_wait(1, 1);
        check(b"enter", k == 1, k)?;
        let c = r.pop().ok_or((&b"no cqe"[..], 0))?;
        check(b"res", c.res == 4096, i64::from(c.res))?;
        check(
            b"new pages untouched",
            b.bytes(0, 4096).iter().all(|&x| x == 0),
            0,
        )
    })();
    sys_close(fd as u64);
    res
}
