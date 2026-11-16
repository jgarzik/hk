//! TTY mode ioctl tests (termios2, termio, exclusive mode), on the
//! console: hk has no ptys yet, and the serial console behaves alike
//! on hk and Linux. Every test puts the console's settings back
//!
//! Tests:
//! - TTY_TERMIOS2: TCGETS2's struct termios2 starts with TCGETS's
//!   struct termios; its speeds are the ones the baud bits name (Linux
//!   set_termios loads them: tty_termios_baud_rate,
//!   tty_termios_input_baud_rate); a TCSETS2 change (VEOL2) reads back
//!   whole through TCGETS2 and shows in TCGETS; an input speed (CIBAUD)
//!   set through TCSETS shows in c_ispeed
//! - TTY_TERMIO: TCGETA's struct termio holds the flags' low halves,
//!   the line discipline and the first 8 control characters, its tail
//!   padding zero; TCSETAW replaces those and keeps the flags' high
//!   halves (Linux user_termio_to_kernel_termios)
//! - TTY_EXCL: TIOCEXCL sets exclusive mode (TIOCGEXCL reads 1): an
//!   open by a process without CAP_SYS_ADMIN is EBUSY, one with it
//!   works (Linux tty_reopen); TIOCNXCL clears it (TIOCGEXCL 0) and the
//!   open works again. CAP_SYS_ADMIN is dropped by capset, the uid kept:
//!   /dev/console is 0600 root on Linux, so another uid's open would be
//!   EACCES before the tty sees it
//! - TTY_EXCL_CTTY: in exclusive mode an open of /dev/tty without
//!   CAP_SYS_ADMIN is EBUSY as well (Linux tty_open_current_tty calls
//!   tty_reopen), one with it works; after TIOCNXCL it works again

use super::tty::{block_hup_cont, dev_tty, in_child, open_ctty, report};
use crate::harness::{R, check, report_r};
use hk_syscall::{
    CapUserData, CapUserHeader, O_RDWR, sys_capget, sys_capset, sys_close, sys_ioctl, sys_open,
    sys_setsid,
};

const O_NOCTTY: u32 = 0o400;
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCGETA: u64 = 0x5405;
const TCSETAW: u64 = 0x5407;
const TCGETS2: u64 = 0x802C_542A;
const TCSETS2: u64 = 0x402C_542B;
const TIOCEXCL: u64 = 0x540C;
const TIOCNXCL: u64 = 0x540D;
const TIOCGEXCL: u64 = 0x8004_5440;
const TIOCNOTTY: u64 = 0x5422;
const TCSBRK: u64 = 0x5409;
const EBUSY: i64 = -16;
const CAP_SYS_ADMIN: u32 = 21;

/// struct termios, termios2 and termio sizes; offsets in them
const T_SIZE: usize = 36;
const T2_SIZE: usize = 44;
const TIO_SIZE: usize = 18;
const C_CFLAG: usize = 8;
const C_LINE: usize = 16;
const C_CC: usize = 17;
const C_ISPEED: usize = 36;
const C_OSPEED: usize = 40;
const TIO_LINE: usize = 8;
const TIO_CC: usize = 9;
const NCC: usize = 8;
const VSWTC: usize = 7;
const VEOL2: usize = 16;
const CBAUD: u32 = 0x100f;
const CBAUDEX: u32 = 0x1000;
const BOTHER: u32 = 0x1000;
const IBSHIFT: u32 = 16;

/// Run the tty mode ioctl tests
pub fn run_tests() {
    test_termios2();
    test_termio();
    test_excl();
    test_excl_ctty();
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn set_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([b[off], b[off + 1]])
}

/// The speed a Bfoo value names (Linux baud_table)
fn baud(cbaud: u32) -> u32 {
    const T: [u32; 31] = [
        0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600,
        115200, 230400, 460800, 500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000,
        2500000, 3000000, 3500000, 4000000,
    ];
    let i = if cbaud & CBAUDEX != 0 {
        (cbaud & !CBAUDEX) + 15
    } else {
        cbaud
    } as usize;
    T.get(i).copied().unwrap_or(0)
}

/// termios2's speeds match its baud bits (BOTHER: any)
fn speeds_ok(t2: &[u8]) -> bool {
    let cflag = u32_at(t2, C_CFLAG);
    let (ob, ib) = (cflag & CBAUD, (cflag >> IBSHIFT) & CBAUD);
    let ospeed = u32_at(t2, C_OSPEED);
    let ispeed = u32_at(t2, C_ISPEED);
    let o_ok = ob == BOTHER || ospeed == baud(ob);
    let i_ok = match ib {
        0 => ispeed == ospeed,
        BOTHER => true,
        b => ispeed == baud(b),
    };
    o_ok && i_ok
}

fn open_console() -> i32 {
    sys_open(b"/dev/console\0".as_ptr(), O_RDWR | O_NOCTTY, 0) as i32
}

fn get<const N: usize>(fd: i32, cmd: u64, b: &mut [u8; N]) -> i64 {
    sys_ioctl(fd, cmd, b.as_mut_ptr() as u64)
}

fn set<const N: usize>(fd: i32, cmd: u64, b: &[u8; N]) -> i64 {
    sys_ioctl(fd, cmd, b.as_ptr() as u64)
}

fn test_termios2() {
    const NAME: &[u8] = b"TTY_TERMIOS2";
    let fd = open_console();
    if fd < 0 {
        return report_r(NAME, Err((b"open", i64::from(fd))));
    }
    let mut orig = [0u8; T2_SIZE];
    let r = termios2_steps(fd, &mut orig);
    set(fd, TCSETS2, &orig);
    sys_close(fd as u64);
    report_r(NAME, r);
}

fn termios2_steps(fd: i32, orig: &mut [u8; T2_SIZE]) -> R {
    let mut t = [0u8; T_SIZE];
    let g = get(fd, TCGETS, &mut t);
    check(b"tcgets", g == 0, g)?;
    let g = get(fd, TCGETS2, orig);
    check(b"tcgets2", g == 0, g)?;
    check(b"same", orig[..T_SIZE] == t, 0)?;
    check(
        b"speeds",
        speeds_ok(orig),
        i64::from(u32_at(orig, C_OSPEED)),
    )?;
    // A control character through TCSETS2
    let mut w = *orig;
    w[C_CC + VEOL2] = 0x0b;
    let s = set(fd, TCSETS2, &w);
    check(b"tcsets2", s == 0, s)?;
    let mut got = [0u8; T2_SIZE];
    get(fd, TCGETS2, &mut got);
    check(b"readback", got == w, i64::from(got[C_CC + VEOL2]))?;
    get(fd, TCGETS, &mut t);
    check(
        b"tcgets veol2",
        t[C_CC + VEOL2] == 0x0b,
        i64::from(t[C_CC + VEOL2]),
    )?;
    // An input speed through the old TCSETS loads c_ispeed
    let cflag = u32_at(orig, C_CFLAG);
    if cflag & CBAUD != BOTHER && cflag & (CBAUD << IBSHIFT) == 0 {
        t.copy_from_slice(&orig[..T_SIZE]);
        set_u32(&mut t, C_CFLAG, cflag | ((cflag & CBAUD) << IBSHIFT));
        let s = set(fd, TCSETS, &t);
        check(b"tcsets cibaud", s == 0, s)?;
        get(fd, TCGETS2, &mut got);
        let ib = (u32_at(&got, C_CFLAG) >> IBSHIFT) & CBAUD;
        check(b"cibaud", ib == cflag & CBAUD, i64::from(ib))?;
        let isp = u32_at(&got, C_ISPEED);
        check(b"ispeed", isp == baud(cflag & CBAUD), i64::from(isp))?;
    }
    Ok(())
}

fn test_termio() {
    const NAME: &[u8] = b"TTY_TERMIO";
    let fd = open_console();
    if fd < 0 {
        return report_r(NAME, Err((b"open", i64::from(fd))));
    }
    let mut orig = [0u8; T_SIZE];
    let g = get(fd, TCGETS, &mut orig);
    let r = check(b"tcgets", g == 0, g).and_then(|()| termio_steps(fd, &orig));
    set(fd, TCSETS, &orig);
    sys_close(fd as u64);
    report_r(NAME, r);
}

fn termio_steps(fd: i32, orig: &[u8; T_SIZE]) -> R {
    let mut v = [0xaau8; TIO_SIZE];
    let g = get(fd, TCGETA, &mut v);
    check(b"tcgeta", g == 0, g)?;
    for i in 0..4 {
        let want = u32_at(orig, i * 4) as u16;
        let got = u16_at(&v, i * 2);
        check(b"flag", got == want, i64::from(got))?;
    }
    check(b"line", v[TIO_LINE] == orig[C_LINE], i64::from(v[TIO_LINE]))?;
    check(b"cc", v[TIO_CC..TIO_CC + NCC] == orig[C_CC..C_CC + NCC], 0)?;
    check(b"pad", v[TIO_SIZE - 1] == 0, i64::from(v[TIO_SIZE - 1]))?;
    // A high cflag half (CIBAUD) for TCSETAW to keep
    let cflag = u32_at(orig, C_CFLAG);
    let hi = (cflag & CBAUD) << IBSHIFT;
    let mut t = *orig;
    set_u32(&mut t, C_CFLAG, cflag | hi);
    let s = set(fd, TCSETS, &t);
    check(b"tcsets", s == 0, s)?;
    v[TIO_CC + VSWTC] = 0x05;
    let s = set(fd, TCSETAW, &v);
    check(b"tcsetaw", s == 0, s)?;
    let mut got = [0u8; T_SIZE];
    get(fd, TCGETS, &mut got);
    let c = u32_at(&got, C_CFLAG);
    check(b"high kept", c == cflag | hi, i64::from(c))?;
    check(
        b"vswtc",
        got[C_CC + VSWTC] == 0x05,
        i64::from(got[C_CC + VSWTC]),
    )?;
    Ok(())
}

/// Drop CAP_SYS_ADMIN from the effective set; 0 if done
fn drop_sys_admin() -> i32 {
    let mut h = CapUserHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut d = [CapUserData::default(); 2];
    if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
        return 1;
    }
    d[0].effective &= !(1 << CAP_SYS_ADMIN);
    if sys_capset(&h, d.as_ptr()) != 0 {
        return 2;
    }
    0
}

/// In a child without CAP_SYS_ADMIN: the open's result as exit code
/// 0 (opened), 1 (EBUSY), else 2+
fn open_unprivileged() -> i64 {
    in_child(|| {
        if drop_sys_admin() != 0 {
            return 3;
        }
        match i64::from(open_console()) {
            EBUSY => 1,
            f if f >= 0 => 0,
            _ => 2,
        }
    })
}

/// In a child without CAP_SYS_ADMIN: /dev/tty's open as exit code 0
/// (opened), 1 (EBUSY), else 2+
fn dev_tty_unprivileged() -> i64 {
    in_child(|| {
        if drop_sys_admin() != 0 {
            return 3;
        }
        match dev_tty() {
            0 => 0,
            EBUSY => 1,
            _ => 2,
        }
    })
}

fn gexcl(fd: i32) -> i64 {
    let mut v = -1i32;
    let r = sys_ioctl(fd, TIOCGEXCL, (&raw mut v) as u64);
    if r < 0 { r } else { i64::from(v) }
}

fn test_excl() {
    const NAME: &[u8] = b"TTY_EXCL";
    let fd = open_console();
    if fd < 0 {
        return report_r(NAME, Err((b"open", i64::from(fd))));
    }
    let r = excl_steps(fd);
    sys_ioctl(fd, TIOCNXCL, 0);
    sys_close(fd as u64);
    report_r(NAME, r);
}

fn excl_steps(fd: i32) -> R {
    let g = gexcl(fd);
    check(b"initial", g == 0, g)?;
    let s = sys_ioctl(fd, TIOCEXCL, 0);
    check(b"tiocexcl", s == 0, s)?;
    let g = gexcl(fd);
    check(b"set", g == 1, g)?;
    let c = open_unprivileged();
    check(b"unprivileged ebusy", c == 1, c)?;
    let fd2 = open_console();
    check(b"admin open", fd2 >= 0, i64::from(fd2))?;
    sys_close(fd2 as u64);
    let s = sys_ioctl(fd, TIOCNXCL, 0);
    check(b"tiocnxcl", s == 0, s)?;
    let g = gexcl(fd);
    check(b"cleared", g == 0, g)?;
    let c = open_unprivileged();
    check(b"unprivileged open", c == 0, c)
}

fn test_excl_ctty() {
    let code = in_child(excl_ctty_child);
    report(b"TTY_EXCL_CTTY", code == 0, code);
}

/// In a new session whose controlling tty is put in exclusive mode:
/// 0, or the failing step
fn excl_ctty_child() -> i32 {
    // Queued console output would be flushed (arm64: the console tty)
    sys_ioctl(1, TCSBRK, 1);
    block_hup_cont();
    sys_setsid();
    let fd = open_ctty();
    if fd < 0 {
        return 2;
    }
    let fd = fd as i32;
    if sys_ioctl(fd, TIOCEXCL, 0) != 0 {
        return 3;
    }
    let busy = dev_tty_unprivileged();
    let admin = dev_tty();
    sys_ioctl(fd, TIOCNXCL, 0);
    let after = dev_tty_unprivileged();
    sys_ioctl(fd, TIOCNOTTY, 0);
    sys_close(fd as u64);
    match (busy, admin, after) {
        (1, 0, 0) => 0,
        (1, 0, a) => 30 + a as i32,
        (1, a, _) => 40 - a as i32,
        (b, _, _) => 10 + b as i32,
    }
}
