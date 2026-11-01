//! Named pipes (Linux fs/pipe.c fifo_open, pipe_poll)
//!
//! Tests:
//! - FIFO_NODE: mknod(S_IFIFO) makes a FIFO (stat S_IFIFO), not a
//!   regular file
//! - FIFO_NONBLOCK: a nonblocking reader opens without a writer; a
//!   nonblocking writer without a reader is ENXIO; with both, data goes
//!   through, and after the writer closes the reader sees EOF; lseek is
//!   ESPIPE
//! - FIFO_BLOCKING: a blocking reader waits in open until a writer
//!   opens, then both run
//! - FIFO_RDWR: O_RDWR never waits; data left when the last file closes
//!   is gone at the next open
//! - FIFO_POLLHUP: a reader that never had a writer gets no POLLHUP; it
//!   does once a writer came and went

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, PollFd, Stat, Timespec, sys_close, sys_exit,
    sys_fork, sys_lseek, sys_mknod, sys_nanosleep, sys_open, sys_poll, sys_read, sys_stat,
    sys_unlink, sys_wait4, sys_write,
};

const PATH: &[u8] = b"/fifo_test\0";
const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const ENXIO: i64 = -6;
const EAGAIN: i64 = -11;
const ESPIPE: i64 = -29;
const POLLIN: i16 = 1;
const POLLHUP: i16 = 0x10;

pub fn run_tests() {
    sys_unlink(PATH.as_ptr());
    if sys_mknod(PATH.as_ptr(), S_IFIFO | 0o666, 0) != 0 {
        report(b"FIFO_NODE", 1);
        return;
    }
    node();
    nonblock();
    blocking();
    rdwr();
    pollhup();
    sys_unlink(PATH.as_ptr());
}

fn report(name: &[u8], step: i64) {
    print(name);
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
}

fn open(flags: u32) -> i64 {
    sys_open(PATH.as_ptr(), flags, 0)
}

fn close(fd: i64) {
    sys_close(fd as u64);
}

fn node() {
    // SAFETY: plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let r = sys_stat(PATH.as_ptr(), &mut st);
    report(
        b"FIFO_NODE",
        if r == 0 && st.st_mode & S_IFMT == S_IFIFO { 0 } else { 2 },
    );
}

fn nonblock() {
    let n = b"FIFO_NONBLOCK";
    if open(O_WRONLY | O_NONBLOCK) != ENXIO {
        return report(n, 1);
    }
    let r = open(O_RDONLY | O_NONBLOCK);
    if r < 0 {
        return report(n, 2);
    }
    let w = open(O_WRONLY | O_NONBLOCK);
    if w < 0 {
        close(r);
        return report(n, 3);
    }
    let mut buf = [0u8; 16];
    let ok = sys_write(w as u64, b"hello".as_ptr(), 5) == 5
        && sys_read(r as u64, buf.as_mut_ptr(), 16) == 5
        && &buf[..5] == b"hello";
    let seek = sys_lseek(r as i32, 0, 0);
    close(w);
    let eof = sys_read(r as u64, buf.as_mut_ptr(), 16);
    close(r);
    let step = if !ok {
        4
    } else if seek != ESPIPE {
        5
    } else if eof != 0 {
        6
    } else {
        0
    };
    report(n, step);
}

fn blocking() {
    let n = b"FIFO_BLOCKING";
    let pid = sys_fork();
    if pid == 0 {
        // Blocks until the parent opens for writing
        let r = open(O_RDONLY);
        let mut b = [0u8; 4];
        let got = sys_read(r as u64, b.as_mut_ptr(), 4);
        sys_exit(if got == 1 && b[0] == b'x' { 0 } else { 1 });
    }
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
    let w = open(O_WRONLY);
    let wrote = sys_write(w as u64, b"x".as_ptr(), 1);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    close(w);
    report(
        n,
        if w < 0 || wrote != 1 {
            1
        } else if st != 0 {
            2
        } else {
            0
        },
    );
}

fn rdwr() {
    let n = b"FIFO_RDWR";
    let fd = open(O_RDWR | O_NONBLOCK);
    if fd < 0 || sys_write(fd as u64, b"abc".as_ptr(), 3) != 3 {
        return report(n, 1);
    }
    close(fd);
    let fd = open(O_RDWR | O_NONBLOCK);
    let mut b = [0u8; 4];
    let r = sys_read(fd as u64, b.as_mut_ptr(), 4);
    close(fd);
    report(n, if r == EAGAIN { 0 } else { 2 });
}

fn pollhup() {
    let n = b"FIFO_POLLHUP";
    let r = open(O_RDONLY | O_NONBLOCK);
    if r < 0 {
        return report(n, 1);
    }
    let mut p = PollFd::new(r as i32, POLLIN);
    let before = sys_poll(&mut p, 1, 0);
    let early = p.revents;
    let w = open(O_WRONLY | O_NONBLOCK);
    close(w);
    let mut p = PollFd::new(r as i32, POLLIN);
    sys_poll(&mut p, 1, 0);
    close(r);
    let step = if before != 0 || early & POLLHUP != 0 {
        2
    } else if p.revents & POLLHUP == 0 {
        3
    } else {
        0
    };
    report(n, step);
}
