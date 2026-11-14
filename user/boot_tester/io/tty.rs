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
//! - TTY_WRITE_ATOMIC: a write holds the tty's write lock to its end
//!   (an O_NONBLOCK writer meanwhile gets EAGAIN)
//! - TTY_OUTQ: TIOCOUTQ shows a console write's bytes still queued for
//!   the UART (Linux uart_write into the transmit buffer, drained by the
//!   TX interrupt), at most what was written (NL as CR NL); tcdrain
//!   waits until none
//!   are left
//! - TTY_TCXONC: TCOOFF holds a write's bytes in the UART's queue
//!   (TIOCOUTQ counts all of them) until TCOON; TCIOFF/TCION send
//!   STOP/START outside the queue; an unknown action is EINVAL
//! - TTY_SIGIO_OUT: an O_NONBLOCK write stopped short (TCOOFF, the
//!   UART's queue full) with O_ASYNC armed gets SIGIO POLL_OUT (si_band
//!   POLLOUT|POLLWRNORM|POLLWRBAND) at the driver's next wakeup, an
//!   output flush (Linux TTY_DO_WRITE_WAKEUP, n_tty_write_wakeup), once
//! - TTY_LAST_CLOSE: the last close of a serial tty (ttyS1, x86) with
//!   output stopped by TCOOFF drops it instead of waiting closing_wait
//!   (Linux tty_port_close_start), and the next open finds a fresh tty:
//!   nothing queued, output flowing

use crate::harness::{check, fail_num, pass, report_r};
use crate::helpers::{host_mode, print, println, skip};
use crate::io::nonblock::{on_sig, sigaction};
use hk_syscall::{
    CLOCK_MONOTONIC, ITimerVal, O_NONBLOCK, O_RDWR, O_WRONLY, POLLIN, PollFd, SIG_DFL, Timespec,
    Timeval, sys_clock_gettime, sys_close, sys_exit, sys_fork, sys_ioctl, sys_kill, sys_open,
    sys_poll, sys_read, sys_rt_sigpending, sys_rt_sigprocmask, sys_setitimer, sys_setsid,
    sys_vhangup, sys_wait4, sys_write,
};
use hk_syscall::{SigInfo, Zeroable, sys_fcntl, sys_getpid, sys_rt_sigtimedwait};

const O_NOCTTY: u32 = 0o400;
const TCGETS: u64 = 0x5401;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TCSBRK: u64 = 0x5409;
const TIOCNOTTY: u64 = 0x5422;
const TIOCOUTQ: u64 = 0x5411;
const TCXONC: u64 = 0x540A;
const TCOOFF: u64 = 0;
const TCOON: u64 = 1;
const TCIOFF: u64 = 2;
const TCION: u64 = 3;
const EINVAL: i64 = -22;
const TCFLSH: u64 = 0x540B;
const TCOFLUSH: u64 = 1;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const F_SETOWN: i32 = 8;
const F_SETSIG: i32 = 10;
const O_ASYNC: u64 = 0o20000;
const SIGRT: u32 = 41;
const POLL_OUT: i32 = 2;
const SIGHUP: u64 = 1;
const SIGCONT: u64 = 18;
const SIGWINCH: u64 = 28;
const SIGALRM: u32 = 14;
const SIGKILL: u32 = 9;
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
    test_write_atomic();
    test_outq();
    test_tcxonc();
    test_sigio_out();
    test_last_close();
}

/// Bytes queued for the console's UART
fn outq(fd: i32) -> i64 {
    let mut n = -1i32;
    let r = sys_ioctl(fd, TIOCOUTQ, (&raw mut n) as u64);
    if r < 0 { r } else { i64::from(n) }
}

fn test_outq() {
    const NAME: &[u8] = b"TTY_OUTQ";
    let fd = sys_open(b"/dev/console\0".as_ptr(), O_WRONLY | O_NOCTTY, 0);
    if fd < 0 {
        return report(NAME, false, fd);
    }
    let fd = fd as i32;
    let mut line = [b' '; 1500];
    line[1499] = b'\n';
    // Earlier output (this process's last report) may still be queued
    sys_ioctl(fd, TCSBRK, 1);
    let w = sys_write(fd as u64, line.as_ptr(), line.len() as u64);
    let queued = outq(fd);
    let drained = sys_ioctl(fd, TCSBRK, 1);
    let left = outq(fd);
    sys_close(fd as u64);
    // How much is still queued as the write returns depends on where
    // the TX interrupt runs: QEMU's UARTs send at once, so on the CPU
    // taking it the interrupt re-fires until the queue is empty. OPOST
    // ONLCR: the NL goes out as CR NL
    let n = line.len() as i64;
    let r = check(b"write", w == n, w)
        .and_then(|()| check(b"queued", (0..=n + 1).contains(&queued), queued))
        .and_then(|()| check(b"tcdrain", drained == 0, drained))
        .and_then(|()| check(b"left", left == 0, left));
    report_r(NAME, r);
}

/// Output stopped and restarted (Linux TCXONC). Nothing may print to
/// the console while it is stopped: this process would block
fn test_tcxonc() {
    const NAME: &[u8] = b"TTY_TCXONC";
    let fd = sys_open(b"/dev/console\0".as_ptr(), O_WRONLY | O_NOCTTY, 0);
    if fd < 0 {
        return report(NAME, false, fd);
    }
    let fd = fd as i32;
    sys_ioctl(fd, TCSBRK, 1);
    let off = sys_ioctl(fd, TCXONC, TCOOFF);
    let off2 = sys_ioctl(fd, TCXONC, TCOOFF);
    let line = b"tty tcxonc: held output\n";
    let w = sys_write(fd as u64, line.as_ptr(), line.len() as u64);
    // OPOST|ONLCR: the NL goes out as CR NL
    let held = outq(fd);
    let bad = sys_ioctl(fd, TCXONC, 4);
    let on = sys_ioctl(fd, TCXONC, TCOON);
    let drained = sys_ioctl(fd, TCSBRK, 1);
    let left = outq(fd);
    let ioff = sys_ioctl(fd, TCXONC, TCIOFF);
    let ion = sys_ioctl(fd, TCXONC, TCION);
    let xq = outq(fd);
    sys_close(fd as u64);
    let n = line.len() as i64;
    let r = check(
        b"tcooff",
        off == 0 && off2 == 0,
        if off != 0 { off } else { off2 },
    )
    .and_then(|()| check(b"write", w == n, w))
    .and_then(|()| check(b"held", held == n + 1, held))
    .and_then(|()| check(b"einval", bad == EINVAL, bad))
    .and_then(|()| check(b"tcoon", on == 0, on))
    .and_then(|()| check(b"tcdrain", drained == 0, drained))
    .and_then(|()| check(b"left", left == 0, left))
    .and_then(|()| {
        check(
            b"tcioff",
            ioff == 0 && ion == 0,
            if ioff != 0 { ioff } else { ion },
        )
    })
    .and_then(|()| check(b"xchar queued", xq == 0, xq));
    report_r(NAME, r);
}

/// SIGRT within `secs` seconds (0: pending now): the signal or -errno
fn wait_rt(secs: i64, info: &mut SigInfo) -> i64 {
    let mask = 1u64 << (SIGRT - 1);
    let ts = [secs, 0i64];
    sys_rt_sigtimedwait(
        &mask as *const u64 as u64,
        info as *mut SigInfo as u64,
        ts.as_ptr() as u64,
        8,
    )
}

/// SIGIO POLL_OUT for a short tty write (Linux n_tty_write sets
/// TTY_DO_WRITE_WAKEUP; uart_flush_buffer's tty_wakeup runs
/// n_tty_write_wakeup). Output is stopped meanwhile: nothing may print
fn test_sigio_out() {
    const NAME: &[u8] = b"TTY_SIGIO_OUT";
    let fd = sys_open(
        b"/dev/console\0".as_ptr(),
        O_WRONLY | O_NOCTTY | O_NONBLOCK,
        0,
    );
    if fd < 0 {
        return report(NAME, false, fd);
    }
    let fd = fd as i32;
    let mask = 1u64 << (SIGRT - 1);
    let mut old = 0u64;
    sys_rt_sigprocmask(
        0,
        &mask as *const u64 as u64,
        &mut old as *mut u64 as u64,
        8,
    );
    sys_ioctl(fd, TCSBRK, 1);
    let fl = sys_fcntl(fd, F_GETFL, 0) as u64;
    let armed = sys_fcntl(fd, F_SETFL, fl | O_ASYNC);
    sys_fcntl(fd, F_SETOWN, sys_getpid() as u64);
    sys_fcntl(fd, F_SETSIG, SIGRT as u64);
    sys_ioctl(fd, TCXONC, TCOOFF);
    // Fill the stopped UART's queue (flushed below: none of it goes out)
    let buf = [b' '; 1024];
    let (mut total, mut last) = (0i64, 0i64);
    for _ in 0..64 {
        last = sys_write(fd as u64, buf.as_ptr(), buf.len() as u64);
        if last < 0 {
            break;
        }
        total += last;
    }
    let held = outq(fd);
    let mut info = SigInfo::zeroed();
    let early = wait_rt(0, &mut info);
    let flushed = sys_ioctl(fd, TCFLSH, TCOFLUSH);
    let got = wait_rt(2, &mut info);
    sys_ioctl(fd, TCFLSH, TCOFLUSH);
    let mut info2 = SigInfo::zeroed();
    let again = wait_rt(0, &mut info2);
    sys_ioctl(fd, TCXONC, TCOON);
    sys_fcntl(fd, F_SETFL, fl);
    sys_close(fd as u64);
    sys_rt_sigprocmask(2, &old as *const u64 as u64, 0, 8);
    // struct _sigpoll: si_band at 16 (si_pid's place), si_fd at 24
    let band = info.si_pid as i64;
    let r = check(b"armed", armed == 0, armed)
        .and_then(|()| check(b"eagain", last == EAGAIN, last))
        .and_then(|()| check(b"filled", total > 0 && held == total, held))
        .and_then(|()| check(b"early", early == EAGAIN, early))
        .and_then(|()| check(b"tcflsh", flushed == 0, flushed))
        .and_then(|()| check(b"sigio", got == SIGRT as i64, got))
        .and_then(|()| check(b"code", info.si_code == POLL_OUT, info.si_code as i64))
        .and_then(|()| check(b"band", band == 0x304, band))
        .and_then(|()| check(b"fd", info.si_status == fd, info.si_status as i64))
        .and_then(|()| check(b"once", again == EAGAIN, again));
    report_r(NAME, r);
}

/// Monotonic time in ms
fn now_ms() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

/// The last close of ttyS1, a serial tty nothing else holds open
/// (Linux tty_release -> uart_close -> tty_port_close)
fn test_last_close() {
    const NAME: &[u8] = b"TTY_LAST_CLOSE";
    if cfg!(target_arch = "aarch64") {
        return skip(NAME, b"one UART");
    }
    let path = b"/dev/ttyS1\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_NOCTTY | O_NONBLOCK, 0);
    if fd < 0 {
        return report(NAME, false, fd);
    }
    let fd = fd as i32;
    let off = sys_ioctl(fd, TCXONC, TCOOFF);
    let buf = [b'x'; 100];
    let w = sys_write(fd as u64, buf.as_ptr(), buf.len() as u64);
    let held = outq(fd);
    let t0 = now_ms();
    sys_close(fd as u64);
    let took = now_ms() - t0;
    let fd = sys_open(path.as_ptr(), O_RDWR | O_NOCTTY | O_NONBLOCK, 0);
    if fd < 0 {
        return report(NAME, false, fd);
    }
    let fd = fd as i32;
    let fresh = outq(fd);
    let w2 = sys_write(fd as u64, buf.as_ptr(), 10);
    // Not stopped: the 10 bytes go out (bounded, never a hang)
    let mut left = outq(fd);
    for _ in 0..200 {
        if left == 0 {
            break;
        }
        crate::helpers::msleep(10);
        left = outq(fd);
    }
    sys_close(fd as u64);
    let r = check(b"tcooff", off == 0, off)
        .and_then(|()| check(b"write", w == 100, w))
        .and_then(|()| check(b"held", held == 100, held))
        .and_then(|()| check(b"close ms", took < 5000, took))
        .and_then(|()| check(b"fresh outq", fresh == 0, fresh))
        .and_then(|()| check(b"write2", w2 == 10, w2))
        .and_then(|()| check(b"sent", left == 0, left));
    report_r(NAME, r);
}

fn report(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        fail_num(b":FAIL: got ", got);
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
        pass(b"VHANGUP");
    } else {
        fail_num(b"VHANGUP:FAIL: returned ", ret);
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

/// Monotonic seconds
fn now_sec() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec
}

/// A write of `fd` from an unmapped buffer: EFAULT once the tty's
/// write lock is held, with nothing written to the console
fn write_fault(fd: i64) -> i64 {
    sys_write(fd as u64, 8 as *const u8, 4096)
}

/// A child loops writes to the console that fault inside the write
/// lock (Linux tty_write_lock: trylock, EAGAIN under O_NDELAY); an
/// O_NONBLOCK writer of the same tty sees it held at some point.
/// Without the lock two writers interleave inside one write
fn test_write_atomic() {
    const NAME: &[u8] = b"TTY_WRITE_ATOMIC";
    let flags = O_WRONLY | O_NOCTTY;
    let fd = sys_open(b"/dev/console\0".as_ptr(), flags, 0);
    let nb = sys_open(b"/dev/console\0".as_ptr(), flags | O_NONBLOCK, 0);
    if fd < 0 || nb < 0 {
        return report(NAME, false, fd.min(nb));
    }
    let pid = sys_fork();
    if pid == 0 {
        while write_fault(fd) == EFAULT {}
        sys_exit(1);
    }
    let end = now_sec() + 10;
    let mut r = EFAULT;
    while pid > 0 && r == EFAULT && now_sec() < end {
        r = write_fault(nb);
    }
    let mut st = 0i32;
    if pid > 0 {
        sys_kill(pid, SIGKILL);
        sys_wait4(pid, &mut st, 0, 0);
    }
    sys_close(fd as u64);
    sys_close(nb as u64);
    let child_ok = pid > 0 && st & 0x7f == SIGKILL as i32;
    report(NAME, child_ok && r == EAGAIN, if child_ok { r } else { -1 });
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
