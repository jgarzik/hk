//! TTY mode ioctl tests (termios2, termio), on the console: hk has no
//! ptys yet, and the serial console behaves alike on hk and Linux. Every test puts the console's settings back
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

use crate::harness::{R, check, report_r};
use hk_syscall::{O_RDWR, sys_close, sys_ioctl, sys_open};

const O_NOCTTY: u32 = 0o400;
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCGETA: u64 = 0x5405;
const TCSETAW: u64 = 0x5407;
const TCGETS2: u64 = 0x802C_542A;
const TCSETS2: u64 = 0x402C_542B;

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
