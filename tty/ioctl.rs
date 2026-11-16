//! TTY ioctl handlers
//!
//! This module implements TTY-specific ioctl operations following
//! the Linux kernel ABI exactly.
//!
//! Reference: include/uapi/asm-generic/ioctls.h

use super::termios::{CLOCAL, KTermios, N_TTY, Termio, Termios, Winsize};
use super::{Tty, jobctrl};
use crate::fs::File;
use crate::uaccess::{get_user, put_user};
use crate::util::error::KernelError;
use crate::util::pod::{FromBytes, IntoBytes};

// =============================================================================
// TTY ioctl numbers (from include/uapi/asm-generic/ioctls.h)
// =============================================================================

/// Get termios structure
pub const TCGETS: u32 = 0x5401;
/// Set termios structure (immediately)
pub const TCSETS: u32 = 0x5402;
/// Set termios structure (after drain)
pub const TCSETSW: u32 = 0x5403;
/// Set termios structure (after flush)
pub const TCSETSF: u32 = 0x5404;
/// Get termios2 (struct termios2 with the speeds: _IOR('T', 0x2A))
pub const TCGETS2: u32 = 0x802C_542A;
/// Set termios2 (immediately)
pub const TCSETS2: u32 = 0x402C_542B;
/// Set termios2 (after drain)
pub const TCSETSW2: u32 = 0x402C_542C;
/// Set termios2 (after drain, flushing input)
pub const TCSETSF2: u32 = 0x402C_542D;
/// Get termios using termio struct (old interface)
pub const TCGETA: u32 = 0x5405;
/// Set termios using termio struct
pub const TCSETA: u32 = 0x5406;
/// Set termios using termio struct (after drain)
pub const TCSETAW: u32 = 0x5407;
/// Set termios using termio struct (after flush)
pub const TCSETAF: u32 = 0x5408;
/// Send break
pub const TCSBRK: u32 = 0x5409;
/// Software flow control
pub const TCXONC: u32 = 0x540A;
/// Flush queues
pub const TCFLSH: u32 = 0x540B;

/// TCXONC arguments (asm-generic/termbits.h)
const TCOOFF: u64 = 0;
const TCOON: u64 = 1;
const TCIOFF: u64 = 2;
const TCION: u64 = 3;
/// Set exclusive mode
pub const TIOCEXCL: u32 = 0x540C;
/// Clear exclusive mode
pub const TIOCNXCL: u32 = 0x540D;
/// Get exclusive mode (_IOR('T', 0x40, int))
pub const TIOCGEXCL: u32 = 0x8004_5440;
/// Set controlling terminal
pub const TIOCSCTTY: u32 = 0x540E;
/// Get foreground process group
pub const TIOCGPGRP: u32 = 0x540F;
/// Set foreground process group
pub const TIOCSPGRP: u32 = 0x5410;
/// Get output queue size
pub const TIOCOUTQ: u32 = 0x5411;
/// Simulate terminal input
pub const TIOCSTI: u32 = 0x5412;
/// Get window size
pub const TIOCGWINSZ: u32 = 0x5413;
/// Set window size
pub const TIOCSWINSZ: u32 = 0x5414;
/// Get modem bits
pub const TIOCMGET: u32 = 0x5415;
/// Modem lines (TIOCMGET bits)
const TIOCM_DTR: i32 = 0x002;
const TIOCM_RTS: i32 = 0x004;
const TIOCM_CTS: i32 = 0x020;
const TIOCM_CAR: i32 = 0x040;
const TIOCM_DSR: i32 = 0x100;
/// Set modem bits
pub const TIOCMBIS: u32 = 0x5416;
/// Clear modem bits
pub const TIOCMBIC: u32 = 0x5417;
/// Set modem bits
pub const TIOCMSET: u32 = 0x5418;
/// Get software carrier flag
pub const TIOCGSOFTCAR: u32 = 0x5419;
/// Set software carrier flag
pub const TIOCSSOFTCAR: u32 = 0x541A;
/// Get number of bytes in input queue
pub const FIONREAD: u32 = 0x541B;
/// Alias for FIONREAD
pub const TIOCINQ: u32 = FIONREAD;
/// Get serial port settings (struct serial_struct)
pub const TIOCGSERIAL: u32 = 0x541E;
/// Set serial port settings
pub const TIOCSSERIAL: u32 = 0x541F;
/// Give up controlling terminal
pub const TIOCNOTTY: u32 = 0x5422;
/// Set line discipline
pub const TIOCSETD: u32 = 0x5423;
/// Get line discipline
pub const TIOCGETD: u32 = 0x5424;
/// Send break (timed)
pub const TCSBRKP: u32 = 0x5425;
/// Get session ID
pub const TIOCGSID: u32 = 0x5429;
/// Set/clear non-blocking I/O
pub const FIONBIO: u32 = 0x5421;
/// Send break
pub const TIOCSBRK: u32 = 0x5427;
/// Clear break
pub const TIOCCBRK: u32 = 0x5428;

/// Copy `v` out to the user pointer `arg` (EFAULT if bad)
fn put<T: IntoBytes>(arg: u64, v: T) -> Result<i64, KernelError> {
    put_user::<T>(arg, v).map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

/// Copy a `T` in from the user pointer `arg` (EFAULT if bad)
fn get<T: FromBytes>(arg: u64) -> Result<T, KernelError> {
    get_user::<T>(arg).map_err(|_| KernelError::BadAddress)
}

/// Wait until the output is sent (Linux tty_wait_until_sent); a
/// pending signal ends the call with EINTR
fn drain(tty: &Tty) -> Result<(), KernelError> {
    tty.wait_until_sent(0);
    if crate::sync::waitqueue::signal_pending() {
        return Err(KernelError::Interrupted);
    }
    Ok(())
}

/// A command Linux tty_ioctl and tty_jobctrl_ioctl handle themselves,
/// not passing it on to the driver (uart_ioctl) and line discipline
fn tty_own(cmd: u32) -> bool {
    matches!(
        cmd,
        TIOCGWINSZ
            | TIOCSWINSZ
            | TIOCEXCL
            | TIOCNXCL
            | TIOCGEXCL
            | TIOCGETD
            | TIOCSETD
            | TIOCSBRK
            | TIOCCBRK
            | TCSBRK
            | TCSBRKP
            | TIOCMGET
            | TIOCMSET
            | TIOCMBIC
            | TIOCMBIS
            | TIOCGSERIAL
            | TIOCSSERIAL
            | TIOCSCTTY
            | TIOCNOTTY
            | TIOCGPGRP
            | TIOCSPGRP
            | TIOCGSID
    )
}

/// The driver's part of a break or modem line command (Linux
/// uart_break_ctl, uart_tiocmget, uart_tiocmset): EIO while the tty's
/// I/O fails
fn hw(tty: &Tty) -> Result<(), KernelError> {
    if tty.io_error() {
        return Err(KernelError::Io);
    }
    Ok(())
}

/// A tty's ioctl (Linux tty_ioctl, tty_jobctrl_ioctl and
/// n_tty_ioctl_helper); `arg` is a user pointer for most commands
pub fn tty_ioctl(tty: &Tty, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    // While the tty's I/O fails, what reaches the driver's ioctl does
    // too, line discipline commands included (Linux uart_ioctl's
    // TTY_IO_ERROR check); TCFLSH's input flush comes first
    if !tty_own(cmd) && tty.io_error() {
        if cmd == TCFLSH && matches!(arg, 0 | 2) {
            tty.flush_input();
        }
        return Err(KernelError::Io);
    }
    // A background process may not change the tty (Linux
    // tty_check_change in set_termios, n_tty_ioctl_helper, tty_ioctl)
    if matches!(
        cmd,
        TCSETS
            | TCSETSW
            | TCSETSF
            | TCSETS2
            | TCSETSW2
            | TCSETSF2
            | TCSETA
            | TCSETAW
            | TCSETAF
            | TCFLSH
            | TCXONC
            | TCSBRK
            | TCSBRKP
            | TIOCSBRK
            | TIOCCBRK
    ) {
        jobctrl::check_change(tty, crate::signal::SIGTTOU)?;
    }
    match cmd {
        TCGETS => put(arg, tty.get_termios().termios()),
        TCGETS2 => put(arg, tty.get_termios()),
        TCGETA => put(arg, tty.get_termios().termio()),
        TCSETS | TCSETSW | TCSETSF | TCSETS2 | TCSETSW2 | TCSETSF2 | TCSETA | TCSETAW | TCSETAF => {
            set_termios(tty, cmd, arg)
        }
        TIOCGWINSZ => put(arg, tty.get_winsize()),
        TIOCSWINSZ => {
            tty.resize(get::<Winsize>(arg)?);
            Ok(0)
        }
        FIONREAD => put(
            arg,
            i32::try_from(tty.bytes_available()).unwrap_or(i32::MAX),
        ),
        TIOCOUTQ => put(arg, tty.chars_in_buffer().min(i32::MAX as usize) as i32),
        TIOCGPGRP => put(arg, pid_i32(jobctrl::tiocgpgrp(tty)?)),
        TIOCSPGRP => {
            jobctrl::tiocspgrp(tty, get::<i32>(arg)?)?;
            Ok(0)
        }
        TIOCGSID => put(arg, pid_i32(jobctrl::tiocgsid(tty)?)),
        TIOCSCTTY => {
            // The file's tty (Linux file_tty)
            jobctrl::tiocsctty(super::Redirect::tty(file)?, file, arg == 1)?;
            Ok(0)
        }
        TIOCNOTTY => {
            jobctrl::tiocnotty(tty)?;
            Ok(0)
        }
        TIOCGETD => put(arg, i32::from(N_TTY)),
        TIOCSETD => match get::<i32>(arg)? {
            0 => Ok(0), // N_TTY, the only one
            _ => Err(KernelError::InvalidArgument),
        },
        TCFLSH => {
            match arg {
                0 => tty.flush_input(),  // TCIFLUSH
                1 => tty.flush_output(), // TCOFLUSH
                2 => {
                    // TCIOFLUSH
                    tty.flush_input();
                    tty.flush_output();
                }
                _ => return Err(KernelError::InvalidArgument),
            }
            Ok(0)
        }
        // A break (TCSBRK 0, TCSBRKP) is not sent: drain only (tcdrain
        // is TCSBRK 1), then the driver's break (Linux send_break)
        TCSBRK | TCSBRKP => {
            drain(tty)?;
            if cmd == TCSBRKP || arg == 0 {
                hw(tty)?;
            }
            Ok(0)
        }
        TCXONC => tcxonc(tty, arg),
        TIOCGSERIAL => put(arg, tty.get_serial()?),
        TIOCSSERIAL => {
            tty.set_serial(&get::<super::SerialStruct>(arg)?)?;
            Ok(0)
        }
        TIOCSBRK | TIOCCBRK => hw(tty).map(|()| 0),
        TIOCEXCL | TIOCNXCL => {
            tty.set_exclusive(cmd == TIOCEXCL);
            Ok(0)
        }
        TIOCGEXCL => put(arg, i32::from(tty.exclusive())),
        // No modem control: the lines read as asserted, sets are ignored
        TIOCMGET => {
            hw(tty)?;
            put(
                arg,
                TIOCM_DTR | TIOCM_RTS | TIOCM_CTS | TIOCM_CAR | TIOCM_DSR,
            )
        }
        TIOCMBIS | TIOCMBIC | TIOCMSET => {
            get::<i32>(arg)?;
            hw(tty).map(|()| 0)
        }
        // Soft carrier is CLOCAL (Linux tty_change_softcar)
        TIOCGSOFTCAR => put(arg, i32::from(tty.get_termios().c_cflag & CLOCAL != 0)),
        TIOCSSOFTCAR => {
            let on = get::<i32>(arg)? != 0;
            tty.update_termios(|t| t.c_cflag = (t.c_cflag & !CLOCAL) | if on { CLOCAL } else { 0 });
            Ok(0)
        }
        _ => Err(KernelError::NotTty),
    }
}

/// TCSETS*, TCSETS*2, TCSETA* (Linux set_termios): the user's struct
/// termios, termios2 or termio over the tty's settings, the speeds
/// loaded from the baud bits; the W and F forms wait for the output to
/// drain, the F forms then flush input
fn set_termios(tty: &Tty, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    let mut k = tty.get_termios();
    match cmd {
        TCSETS | TCSETSW | TCSETSF => k.set_termios(&get::<Termios>(arg)?),
        TCSETA | TCSETAW | TCSETAF => k.set_termio(&get::<Termio>(arg)?),
        _ => k = get::<KTermios>(arg)?,
    }
    k.set_speeds();
    if !matches!(cmd, TCSETS | TCSETS2 | TCSETA) {
        drain(tty)?;
    }
    if matches!(cmd, TCSETSF | TCSETSF2 | TCSETAF) {
        tty.flush_input();
    }
    tty.set_termios(k);
    Ok(0)
}

/// TCXONC (Linux n_tty_ioctl_helper): stop or restart output, or send
/// the STOP or START character unless disabled (_POSIX_VDISABLE, 0)
fn tcxonc(tty: &Tty, arg: u64) -> Result<i64, KernelError> {
    use crate::tty::termios::{VSTART, VSTOP};
    let xchar = |i: usize| {
        let ch = tty.get_termios().c_cc[i];
        if ch != 0 {
            tty.send_xchar(ch);
        }
    };
    match arg {
        TCOOFF => tty.tcooff(),
        TCOON => tty.tcoon(),
        TCIOFF => xchar(VSTOP),
        TCION => xchar(VSTART),
        _ => return Err(KernelError::InvalidArgument),
    }
    Ok(0)
}

/// A pid as the user's pid_t
fn pid_i32(p: u32) -> i32 {
    i32::try_from(p).unwrap_or(0)
}
