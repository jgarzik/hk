//! TTY tests
//!
//! Tests:
//! - vhangup with capability succeeds
//! - TTY_NOCTTY_ENXIO: /dev/tty without a controlling tty is ENXIO
//! - TTY_IOCTL_EFAULT: a bad user pointer to a tty ioctl is EFAULT
//! - TTY_SIGWINCH: TIOCSWINSZ with a new size signals the foreground
//!   process group
//! - TTY_READ_NONBLOCK: O_NONBLOCK read of the idle serial tty is EAGAIN
//! - TTY_POLL_IDLE: poll of the idle serial tty reports no input
//! - TTY_READ_EINTR: a blocking read sleeps until a signal (EINTR)

use super::helpers::{host_mode, print, print_num, println, skip};
use super::nonblock::{on_sig, sigaction};
use hk_syscall::{
    ITimerVal, O_NONBLOCK, O_RDWR, POLLIN, PollFd, SIG_DFL, Timeval, sys_close, sys_exit, sys_fork,
    sys_ioctl, sys_open, sys_poll, sys_read, sys_rt_sigpending, sys_rt_sigprocmask, sys_setitimer,
    sys_setsid, sys_vhangup, sys_wait4,
};

const O_NOCTTY: u32 = 0o400;
const TCGETS: u64 = 0x5401;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TCSBRK: u64 = 0x5409;
const TIOCNOTTY: u64 = 0x5422;
const SIGHUP: u64 = 1;
const SIGCONT: u64 = 18;
const SIGWINCH: u64 = 28;
const SIGALRM: u32 = 14;
const EINTR: i64 = -4;
const EAGAIN: i64 = -11;
const EIO: i64 = -5;
const ENXIO: i64 = -6;
const EFAULT: i64 = -14;

/// Run all TTY tests
pub fn run_tests() {
    test_vhangup();
    test_noctty_enxio();
    test_ioctl_efault();
    test_read_nonblock();
    test_poll_idle();
    test_read_eintr();
    test_sigwinch();
}

fn report(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL: got ");
        print_num(got);
        println(b"");
    }
}

/// Run `f` in a forked child; its exit code (-1 if fork/wait failed)
fn in_child(f: fn() -> i32) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f() as u64)
    }
    if pid < 0 {
        return -1;
    }
    let mut st = 0i32;
    if sys_wait4(pid, &mut st, 0, 0) != pid || st & 0x7f != 0 {
        return -1;
    }
    ((st >> 8) & 0xff) as i64
}

fn test_noctty_enxio() {
    let code = in_child(|| {
        sys_setsid();
        let fd = sys_open(b"/dev/tty\0".as_ptr(), O_RDWR, 0);
        if fd == ENXIO { 0 } else { 1 }
    });
    report(b"TTY_NOCTTY_ENXIO", code == 0, code);
}

fn test_ioctl_efault() {
    let fd = sys_open(b"/dev/console\0".as_ptr(), O_RDWR | O_NOCTTY, 0);
    if fd < 0 {
        return report(b"TTY_IOCTL_EFAULT", false, fd);
    }
    let fd = fd as i32;
    // Null and an unmapped address
    let r = [
        sys_ioctl(fd, TIOCGWINSZ, 0),
        sys_ioctl(fd, TIOCGWINSZ, 8),
        sys_ioctl(fd, TIOCSWINSZ, 8),
        sys_ioctl(fd, TCGETS, 8),
    ];
    sys_close(fd as u64);
    let bad = r.iter().copied().find(|&e| e != EFAULT);
    report(b"TTY_IOCTL_EFAULT", bad.is_none(), bad.unwrap_or(0));
}

/// The serial tty (Linux names: ttyS0 on x86, ttyAMA0 on arm64)
fn open_serial(flags: u32) -> i64 {
    let fd = sys_open(b"/dev/ttyS0\0".as_ptr(), flags, 0);
    if fd >= 0 {
        return fd;
    }
    sys_open(b"/dev/ttyAMA0\0".as_ptr(), flags, 0)
}

fn test_sigwinch() {
    let probe = open_serial(O_RDWR | O_NOCTTY);
    if probe < 0 {
        return skip(b"TTY_SIGWINCH", b"no serial tty");
    }
    sys_close(probe as u64);
    // A new session leader opening the serial tty takes it as its
    // controlling tty and is its foreground process group. Its exit
    // would hang the tty up, discarding queued console output: drain
    // first, and give the tty up (TIOCNOTTY) before exiting
    let code = in_child(|| {
        sys_ioctl(1, TCSBRK, 1);
        sys_setsid();
        let fd = open_serial(O_RDWR);
        if fd < 0 {
            return 2;
        }
        let fd = fd as i32;
        let set: u64 = 1 << (SIGWINCH - 1);
        let block = set | 1 << (SIGHUP - 1) | 1 << (SIGCONT - 1);
        sys_rt_sigprocmask(0, &block as *const u64 as u64, 0, 8);
        let mut ws = [0u16; 4];
        if sys_ioctl(fd, TIOCGWINSZ, ws.as_mut_ptr() as u64) != 0 {
            return 3;
        }
        let old = ws;
        ws[0] = ws[0].wrapping_add(1);
        let r = sys_ioctl(fd, TIOCSWINSZ, ws.as_ptr() as u64);
        let mut pending: u64 = 0;
        sys_rt_sigpending(&mut pending as *mut u64 as u64, 8);
        sys_ioctl(fd, TIOCSWINSZ, old.as_ptr() as u64);
        sys_ioctl(fd, TIOCNOTTY, 0);
        if r != 0 {
            4
        } else if pending & set == 0 {
            5
        } else {
            0
        }
    });
    report(b"TTY_SIGWINCH", code == 0, code);
}

/// Test vhangup syscall
///
/// Running as init (root), we should have CAP_SYS_TTY_CONFIG,
/// so vhangup should succeed (return 0).
fn test_vhangup() {
    let ret = sys_vhangup();

    if ret == 0 {
        println(b"VHANGUP:OK");
    } else {
        print(b"VHANGUP:FAIL: returned ");
        print_num(ret);
        println(b"");
    }
}

fn test_read_nonblock() {
    let fd = open_serial(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if fd < 0 {
        return skip(b"TTY_READ_NONBLOCK", b"no serial tty");
    }
    let mut b = [0u8; 16];
    let r = sys_read(fd as u64, b.as_mut_ptr(), b.len() as u64);
    sys_close(fd as u64);
    if host_io_error(r) {
        return skip(b"TTY_READ_NONBLOCK", b"host serial tty I/O error");
    }
    report(b"TTY_READ_NONBLOCK", r == EAGAIN, r);
}

fn test_poll_idle() {
    let fd = open_serial(O_RDWR | O_NOCTTY);
    if fd < 0 {
        return skip(b"TTY_POLL_IDLE", b"no serial tty");
    }
    let mut p = PollFd {
        fd: fd as i32,
        events: POLLIN,
        revents: 0,
    };
    let r = sys_poll(&mut p, 1, 0);
    sys_close(fd as u64);
    report(b"TTY_POLL_IDLE", r == 0, r);
}

fn test_read_eintr() {
    let fd = open_serial(O_RDWR | O_NOCTTY);
    if fd < 0 {
        return skip(b"TTY_READ_EINTR", b"no serial tty");
    }
    sigaction(SIGALRM, on_sig as *const () as u64, 0);
    alarm(1);
    let mut b = [0u8; 16];
    let r = sys_read(fd as u64, b.as_mut_ptr(), b.len() as u64);
    alarm(0);
    sigaction(SIGALRM, SIG_DFL, 0);
    sys_close(fd as u64);
    if host_io_error(r) {
        return skip(b"TTY_READ_EINTR", b"host serial tty I/O error");
    }
    report(b"TTY_READ_EINTR", r == EINTR, r);
}

/// SIGALRM after `sec` seconds (0 cancels); arm64 has no alarm(2)
fn alarm(sec: i64) {
    let it = ITimerVal {
        it_interval: Timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: Timeval {
            tv_sec: sec,
            tv_usec: 0,
        },
    };
    sys_setitimer(0, &it, core::ptr::null_mut());
}

/// The Linux reference's arm64 PL011 (QEMU output to a file, no input)
/// fails reads with EIO
fn host_io_error(r: i64) -> bool {
    host_mode() && r == EIO
}
