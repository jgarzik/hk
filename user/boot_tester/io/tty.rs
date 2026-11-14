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
//! - TTY_HANGUP: vhangup(2) by a session leader hangs up its
//!   controlling tty (ttyS1 on x86, ttyAMA0 on arm64): its files read
//!   0, write EIO, poll everything, ioctl EIO (TIOCSPGRP ENOTTY), left
//!   the O_ASYNC list (F_SETFL O_ASYNC ENOTTY); the leader got SIGHUP
//!   and SIGCONT and has no controlling tty; a new open works (Linux
//!   __tty_hangup, hung_up_tty_fops)
//! - TTY_HANGUP_EXIT: a session leader's exit hangs up its controlling
//!   tty: a member's open file writes EIO, its foreground group got
//!   SIGHUP and no SIGCONT (Linux disassociate_ctty(1) ->
//!   tty_vhangup_session)
//! - TTY_CTTY_PROC: the controlling tty is per process (Linux
//!   signal->tty): a session member forked before its leader acquired
//!   one has none (/dev/tty ENXIO), one forked after has it; TIOCNOTTY
//!   by a member drops only its own
//! - TTY_OLD_PGRP: a session leader whose tty was hung up (vhangup)
//!   signals its old foreground group SIGHUP and SIGCONT when it exits
//!   (Linux tty_old_pgrp, disassociate_ctty(1)); the hangup itself
//!   signalled only the leader
//! - TTY_SERIAL: TIOCGSERIAL shows the UART (ttyS1 on x86, ttyAMA0 on
//!   arm64) and its tty_port's close timing defaults (0.5 s, 30 s);
//!   TIOCSSERIAL with CAP_SYS_ADMIN sets close_delay and closing_wait
//!   (ASYNC_CLOSING_WAIT_NONE) and refuses a baud_base below 9600;
//!   without it only the user flags and the custom divisor change
//!   (Linux uart_set_info: EPERM)

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
use hk_syscall::{sys_getppid, sys_pipe};

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
    test_serial_info();
    test_hangup();
    test_hangup_exit();
    test_ctty_proc();
    test_old_pgrp();
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

const TIOCGSERIAL: u64 = 0x541E;
const TIOCSSERIAL: u64 = 0x541F;
/// struct serial_struct (Linux uapi/linux/serial.h, 64-bit)
const SS_SIZE: usize = 72;
const SS_TYPE: usize = 0;
const SS_LINE: usize = 4;
const SS_PORT: usize = 8;
const SS_FLAGS: usize = 16;
const SS_FIFO: usize = 20;
const SS_DIVISOR: usize = 24;
const SS_BAUD: usize = 28;
const SS_CLOSE_DELAY: usize = 32;
const SS_CLOSING_WAIT: usize = 40;
const SS_IOMEM: usize = 48;
const ASYNC_CLOSING_WAIT_NONE: u16 = 65535;
const ASYNC_SKIP_TEST: u32 = 1 << 6;
const ASYNC_LOW_LATENCY: u32 = 1 << 13;
const EPERM: i64 = -1;
const CAP_SYS_ADMIN: u32 = 21;

fn ss_get(b: &[u8; SS_SIZE], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn ss_set(b: &mut [u8; SS_SIZE], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}

fn ss_get16(b: &[u8; SS_SIZE], off: usize) -> u16 {
    u16::from_ne_bytes([b[off], b[off + 1]])
}

fn ss_set16(b: &mut [u8; SS_SIZE], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_ne_bytes());
}

/// The UART for TIOC[GS]SERIAL: ttyS1 on x86 (not the console),
/// ttyAMA0 (the console, settings restored) on arm64
fn serial_port_path() -> &'static [u8] {
    if cfg!(target_arch = "aarch64") {
        b"/dev/ttyAMA0\0"
    } else {
        b"/dev/ttyS1\0"
    }
}

/// Without CAP_SYS_ADMIN: a closing_wait change and a non-user flag
/// are EPERM; the low latency flag and a custom divisor go in. 0 if
/// so, else the failing step
fn serial_unprivileged() -> i32 {
    use hk_syscall::{CapUserData, CapUserHeader, sys_capget, sys_capset};
    let mut h = CapUserHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut d = [CapUserData::default(); 2];
    if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
        return 10;
    }
    d[0].effective &= !(1 << CAP_SYS_ADMIN);
    if sys_capset(&h, d.as_ptr()) != 0 {
        return 11;
    }
    let fd = sys_open(
        serial_port_path().as_ptr(),
        O_RDWR | O_NOCTTY | O_NONBLOCK,
        0,
    );
    if fd < 0 {
        return 12;
    }
    let fd = fd as i32;
    let mut ss = [0u8; SS_SIZE];
    if sys_ioctl(fd, TIOCGSERIAL, ss.as_mut_ptr() as u64) != 0 {
        return 13;
    }
    let orig = ss;
    let mut w = ss;
    ss_set16(&mut w, SS_CLOSING_WAIT, 100);
    if sys_ioctl(fd, TIOCSSERIAL, w.as_ptr() as u64) != EPERM {
        return 14;
    }
    let mut w = ss;
    ss_set(&mut w, SS_FLAGS, ss_get(&ss, SS_FLAGS) ^ ASYNC_SKIP_TEST);
    if sys_ioctl(fd, TIOCSSERIAL, w.as_ptr() as u64) != EPERM {
        return 15;
    }
    let mut w = ss;
    ss_set(&mut w, SS_FLAGS, ss_get(&ss, SS_FLAGS) | ASYNC_LOW_LATENCY);
    ss_set(&mut w, SS_DIVISOR, 3);
    if sys_ioctl(fd, TIOCSSERIAL, w.as_ptr() as u64) != 0 {
        return 16;
    }
    let mut got = [0u8; SS_SIZE];
    sys_ioctl(fd, TIOCGSERIAL, got.as_mut_ptr() as u64);
    let set = ss_get(&got, SS_FLAGS) & ASYNC_LOW_LATENCY != 0 && ss_get(&got, SS_DIVISOR) == 3;
    sys_ioctl(fd, TIOCSSERIAL, orig.as_ptr() as u64);
    sys_close(fd as u64);
    if set { 0 } else { 17 }
}

fn test_serial_info() {
    const NAME: &[u8] = b"TTY_SERIAL";
    let arm = cfg!(target_arch = "aarch64");
    let fd = sys_open(
        serial_port_path().as_ptr(),
        O_RDWR | O_NOCTTY | O_NONBLOCK,
        0,
    );
    if fd < 0 {
        return report(NAME, false, fd);
    }
    let fd = fd as i32;
    let mut ss = [0u8; SS_SIZE];
    let g = sys_ioctl(fd, TIOCGSERIAL, ss.as_mut_ptr() as u64);
    let orig = ss;
    // PORT_16550A ttyS1 at 0x2f8, BASE_BAUD; PORT_AMBA at 0x9000000,
    // the 24 MHz APB clock
    let (ty, line, port, baud) = if arm {
        (32, 0, 0, 1_500_000)
    } else {
        (4, 1, 0x2f8, 115_200)
    };
    let iomem = u64::from_ne_bytes(ss[SS_IOMEM..SS_IOMEM + 8].try_into().unwrap_or([0; 8]));
    let mut w = ss;
    ss_set16(&mut w, SS_CLOSE_DELAY, 10);
    ss_set16(&mut w, SS_CLOSING_WAIT, ASYNC_CLOSING_WAIT_NONE);
    let s1 = sys_ioctl(fd, TIOCSSERIAL, w.as_ptr() as u64);
    let mut got = [0u8; SS_SIZE];
    sys_ioctl(fd, TIOCGSERIAL, got.as_mut_ptr() as u64);
    let mut slow = got;
    ss_set(&mut slow, SS_BAUD, 4800);
    let s2 = sys_ioctl(fd, TIOCSSERIAL, slow.as_ptr() as u64);
    let child = in_child(serial_unprivileged);
    let s3 = sys_ioctl(fd, TIOCSSERIAL, orig.as_ptr() as u64);
    let mut back = [0u8; SS_SIZE];
    sys_ioctl(fd, TIOCGSERIAL, back.as_mut_ptr() as u64);
    sys_close(fd as u64);
    let r = check(b"tiocgserial", g == 0, g)
        .and_then(|()| {
            check(
                b"type",
                ss_get(&ss, SS_TYPE) == ty,
                ss_get(&ss, SS_TYPE) as i64,
            )
        })
        .and_then(|()| {
            check(
                b"line",
                ss_get(&ss, SS_LINE) == line,
                ss_get(&ss, SS_LINE) as i64,
            )
        })
        .and_then(|()| {
            check(
                b"port",
                ss_get(&ss, SS_PORT) == port,
                ss_get(&ss, SS_PORT) as i64,
            )
        })
        .and_then(|()| check(b"iomem", !arm || iomem == 0x0900_0000, iomem as i64))
        .and_then(|()| {
            check(
                b"fifo",
                ss_get(&ss, SS_FIFO) == 16,
                ss_get(&ss, SS_FIFO) as i64,
            )
        })
        .and_then(|()| {
            check(
                b"baud",
                ss_get(&ss, SS_BAUD) == baud,
                ss_get(&ss, SS_BAUD) as i64,
            )
        })
        .and_then(|()| {
            let v = ss_get16(&ss, SS_CLOSE_DELAY);
            check(b"close_delay", v == 50, v as i64)
        })
        .and_then(|()| {
            let v = ss_get16(&ss, SS_CLOSING_WAIT);
            check(b"closing_wait", v == 3000, v as i64)
        })
        .and_then(|()| check(b"tiocsserial", s1 == 0, s1))
        .and_then(|()| {
            let (d, cw) = (
                ss_get16(&got, SS_CLOSE_DELAY),
                ss_get16(&got, SS_CLOSING_WAIT),
            );
            check(
                b"set",
                d == 10 && cw == ASYNC_CLOSING_WAIT_NONE,
                i64::from(d) * 100_000 + i64::from(cw),
            )
        })
        .and_then(|()| check(b"slow baud", s2 == EINVAL, s2))
        .and_then(|()| check(b"unprivileged", child == 0, child))
        .and_then(|()| check(b"restore", s3 == 0 && back == orig, s3));
    report_r(NAME, r);
}

const TIOCSPGRP: u64 = 0x5410;
const ENOTTY: i64 = -25;
const SIG_BLOCK: i32 = 0;

/// Block SIGHUP and SIGCONT; the pending set
fn pending_sigs() -> u64 {
    let mut p = 0u64;
    sys_rt_sigpending(&mut p as *mut u64 as u64, 8);
    p
}

fn block_hup_cont() {
    let m: u64 = 1 << (SIGHUP - 1) | 1 << (SIGCONT - 1);
    sys_rt_sigprocmask(SIG_BLOCK, &m as *const u64 as u64, 0, 8);
}

/// The hangup test's tty, made the controlling tty of a new session
fn open_ctty() -> i64 {
    sys_open(serial_port_path().as_ptr(), O_RDWR | O_NONBLOCK, 0)
}

/// In a new session: vhangup of the controlling tty. 0 or the failing
/// step
fn hangup_child() -> i32 {
    // Queued console output would be flushed (arm64: the console tty)
    sys_ioctl(1, TCSBRK, 1);
    block_hup_cont();
    sys_setsid();
    let fd = open_ctty();
    let fd2 = sys_open(
        serial_port_path().as_ptr(),
        O_RDWR | O_NOCTTY | O_NONBLOCK,
        0,
    );
    if fd < 0 || fd2 < 0 {
        return 2;
    }
    let (fd, fd2) = (fd as i32, fd2 as i32);
    let fl = sys_fcntl(fd2, F_GETFL, 0) as u64;
    if sys_fcntl(fd2, F_SETFL, fl | O_ASYNC) != 0 {
        return 3;
    }
    if sys_vhangup() != 0 {
        return 4;
    }
    let mut b = [0u8; 4];
    if sys_read(fd as u64, b.as_mut_ptr(), 4) != 0 {
        return 5;
    }
    if sys_write(fd as u64, b.as_ptr(), 1) != EIO {
        return 6;
    }
    let mut p = PollFd {
        fd,
        events: 0x145,
        revents: 0,
    };
    if sys_poll(&mut p, 1, 0) != 1 || p.revents != 0x15d {
        return 7;
    }
    let mut t = [0u8; 64];
    if sys_ioctl(fd, TCGETS, t.as_mut_ptr() as u64) != EIO {
        return 8;
    }
    let pg = 1i32;
    if sys_ioctl(fd, TIOCSPGRP, &pg as *const i32 as u64) != ENOTTY {
        return 9;
    }
    if sys_fcntl(fd2, F_GETFL, 0) as u64 & O_ASYNC != 0 {
        return 10;
    }
    if sys_fcntl(fd2, F_SETFL, fl | O_ASYNC) != ENOTTY {
        return 11;
    }
    let want = 1 << (SIGHUP - 1) | 1 << (SIGCONT - 1);
    if pending_sigs() & want != want {
        return 12;
    }
    if sys_open(b"/dev/tty\0".as_ptr(), O_RDWR, 0) != ENXIO {
        return 13;
    }
    let fd3 = sys_open(
        serial_port_path().as_ptr(),
        O_RDWR | O_NOCTTY | O_NONBLOCK,
        0,
    );
    if fd3 < 0 || sys_ioctl(fd3 as i32, TCGETS, t.as_mut_ptr() as u64) != 0 {
        return 14;
    }
    0
}

fn test_hangup() {
    let code = in_child(hangup_child);
    report(b"TTY_HANGUP", code == 0, code);
}

/// The leader of a new session with a controlling tty forks a member
/// that keeps the tty open, then exits; the member reports through
/// `res`: its pid and the step that failed (0: none)
fn hangup_exit_leader(res: i32) -> i32 {
    sys_ioctl(1, TCSBRK, 1);
    sys_setsid();
    let fd = open_ctty();
    if fd < 0 {
        return 2;
    }
    let mut ready = [0i32; 2];
    if sys_pipe(ready.as_mut_ptr()) != 0 {
        return 3;
    }
    let leader = sys_getpid();
    let pid = sys_fork();
    if pid == 0 {
        block_hup_cont();
        sys_write(ready[1] as u64, b"r".as_ptr(), 1);
        // Until the leader is gone (reparented)
        for _ in 0..500 {
            if sys_getppid() != leader {
                break;
            }
            crate::helpers::msleep(10);
        }
        let step: u8 = if sys_write(fd as u64, b"x".as_ptr(), 1) != EIO {
            1
        } else if pending_sigs() & 1 << (SIGHUP - 1) == 0 {
            2
        } else if pending_sigs() & 1 << (SIGCONT - 1) != 0 {
            3
        } else {
            0
        };
        let me = sys_getpid() as i32;
        let mut out = [0u8; 5];
        out[..4].copy_from_slice(&me.to_ne_bytes());
        out[4] = step;
        sys_write(res as u64, out.as_ptr(), 5);
        sys_exit(0);
    }
    if pid < 0 {
        return 4;
    }
    let mut b = [0u8; 1];
    sys_read(ready[0] as u64, b.as_mut_ptr(), 1);
    0
}

fn test_hangup_exit() {
    const NAME: &[u8] = b"TTY_HANGUP_EXIT";
    let mut res = [0i32; 2];
    if sys_pipe(res.as_mut_ptr()) != 0 {
        return report(NAME, false, -1);
    }
    let pid = sys_fork();
    if pid == 0 {
        sys_close(res[0] as u64);
        sys_exit(hangup_exit_leader(res[1]) as u64);
    }
    sys_close(res[1] as u64);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let mut out = [0u8; 5];
    let n = sys_read(res[0] as u64, out.as_mut_ptr(), 5);
    sys_close(res[0] as u64);
    if n == 5 {
        let member = i32::from_ne_bytes([out[0], out[1], out[2], out[3]]);
        sys_wait4(member as i64, &mut st, 0, 0);
    }
    let r = check(b"leader", st & 0x7f == 0, i64::from(st))
        .and_then(|()| check(b"report", n == 5, n))
        .and_then(|()| check(b"member", out[4] == 0, i64::from(out[4])));
    report_r(NAME, r);
}

/// /dev/tty opens (the caller has a controlling tty): 0, or -errno
fn dev_tty() -> i64 {
    let fd = sys_open(b"/dev/tty\0".as_ptr(), O_RDWR | O_NONBLOCK, 0);
    if fd >= 0 {
        sys_close(fd as u64);
        return 0;
    }
    fd
}

/// A child of the calling session leader running `f`: its exit code
fn member(f: fn() -> i32) -> i64 {
    in_child(f)
}

fn ctty_proc_child() -> i32 {
    sys_ioctl(1, TCSBRK, 1);
    block_hup_cont();
    sys_setsid();
    let mut go = [0i32; 2];
    if sys_pipe(go.as_mut_ptr()) != 0 {
        return 2;
    }
    let early = sys_fork();
    if early == 0 {
        let mut b = [0u8; 1];
        sys_read(go[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(if dev_tty() == ENXIO { 0 } else { 1 });
    }
    let fd = open_ctty();
    if fd < 0 || early < 0 {
        return 3;
    }
    sys_write(go[1] as u64, b"g".as_ptr(), 1);
    let mut st = 0i32;
    sys_wait4(early, &mut st, 0, 0);
    if st != 0 {
        return 4;
    }
    let late = member(|| {
        if dev_tty() != 0 {
            return 1;
        }
        let fd = sys_open(b"/dev/tty\0".as_ptr(), O_RDWR | O_NONBLOCK, 0);
        if sys_ioctl(fd as i32, TIOCNOTTY, 0) != 0 {
            return 2;
        }
        if dev_tty() != ENXIO { 3 } else { 0 }
    });
    if late != 0 {
        return 10 + late as i32;
    }
    if dev_tty() != 0 {
        return 5;
    }
    sys_ioctl(fd as i32, TIOCNOTTY, 0);
    0
}

fn test_ctty_proc() {
    let code = in_child(ctty_proc_child);
    report(b"TTY_CTTY_PROC", code == 0, code);
}

/// The leader of a new session with a controlling tty forks a member
/// of its foreground group, hangs the tty up (vhangup) and exits; the
/// member reports through `res`: its pid and the step that failed
fn old_pgrp_leader(res: i32) -> i32 {
    sys_ioctl(1, TCSBRK, 1);
    block_hup_cont();
    sys_setsid();
    let fd = open_ctty();
    let (mut ready, mut hung) = ([0i32; 2], [0i32; 2]);
    if fd < 0 || sys_pipe(ready.as_mut_ptr()) != 0 || sys_pipe(hung.as_mut_ptr()) != 0 {
        return 2;
    }
    let leader = sys_getpid();
    let pid = sys_fork();
    if pid == 0 {
        let mut b = [0u8; 1];
        sys_write(ready[1] as u64, b"r".as_ptr(), 1);
        sys_read(hung[0] as u64, b.as_mut_ptr(), 1);
        let want = 1 << (SIGHUP - 1) | 1 << (SIGCONT - 1);
        let mut step: u8 = if pending_sigs() & want != 0 { 1 } else { 0 };
        sys_write(ready[1] as u64, b"c".as_ptr(), 1);
        for _ in 0..500 {
            if sys_getppid() != leader {
                break;
            }
            crate::helpers::msleep(10);
        }
        if step == 0 && pending_sigs() & want != want {
            step = 2;
        }
        let me = sys_getpid() as i32;
        let mut out = [0u8; 5];
        out[..4].copy_from_slice(&me.to_ne_bytes());
        out[4] = step;
        sys_write(res as u64, out.as_ptr(), 5);
        sys_exit(0);
    }
    if pid < 0 {
        return 3;
    }
    let mut b = [0u8; 1];
    sys_read(ready[0] as u64, b.as_mut_ptr(), 1);
    let v = sys_vhangup();
    let gone = dev_tty();
    sys_write(hung[1] as u64, b"h".as_ptr(), 1);
    // Exit only once the member has looked
    sys_read(ready[0] as u64, b.as_mut_ptr(), 1);
    let want = 1 << (SIGHUP - 1) | 1 << (SIGCONT - 1);
    if v != 0 {
        4
    } else if gone != ENXIO {
        5
    } else if pending_sigs() & want != want {
        6
    } else {
        0
    }
}

fn test_old_pgrp() {
    const NAME: &[u8] = b"TTY_OLD_PGRP";
    let mut res = [0i32; 2];
    if sys_pipe(res.as_mut_ptr()) != 0 {
        return report(NAME, false, -1);
    }
    let pid = sys_fork();
    if pid == 0 {
        sys_close(res[0] as u64);
        sys_exit(old_pgrp_leader(res[1]) as u64);
    }
    sys_close(res[1] as u64);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let mut out = [0u8; 5];
    let n = sys_read(res[0] as u64, out.as_mut_ptr(), 5);
    sys_close(res[0] as u64);
    if n == 5 {
        let m = i32::from_ne_bytes([out[0], out[1], out[2], out[3]]);
        let mut st2 = 0i32;
        sys_wait4(m as i64, &mut st2, 0, 0);
    }
    let r = check(b"leader", st == 0, i64::from(st))
        .and_then(|()| check(b"report", n == 5, n))
        .and_then(|()| check(b"member", out[4] == 0, i64::from(out[4])));
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
