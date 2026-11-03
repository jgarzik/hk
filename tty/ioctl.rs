//! TTY ioctl handlers
//!
//! This module implements TTY-specific ioctl operations following
//! the Linux kernel ABI exactly.
//!
//! Reference: include/uapi/asm-generic/ioctls.h

use super::termios::{CLOCAL, N_TTY, Termios, Winsize};
use super::{Tty, jobctrl};
use crate::arch::Uaccess;
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
/// Set exclusive mode
pub const TIOCEXCL: u32 = 0x540C;
/// Clear exclusive mode
pub const TIOCNXCL: u32 = 0x540D;
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
    put_user::<Uaccess, T>(arg, v).map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

/// Copy a `T` in from the user pointer `arg` (EFAULT if bad)
fn get<T: FromBytes>(arg: u64) -> Result<T, KernelError> {
    get_user::<Uaccess, T>(arg).map_err(|_| KernelError::BadAddress)
}

/// Wait until the output is sent (Linux tty_wait_until_sent); a
/// pending signal ends the call with EINTR
fn drain(tty: &Tty) -> Result<(), KernelError> {
    tty.wait_until_sent();
    if crate::sync::waitqueue::signal_pending() {
        return Err(KernelError::Interrupted);
    }
    Ok(())
}

/// A tty's ioctl (Linux tty_ioctl, tty_jobctrl_ioctl and
/// n_tty_ioctl_helper); `arg` is a user pointer for most commands
pub fn tty_ioctl(tty: &Tty, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    // A background process may not change the tty (Linux
    // tty_check_change in set_termios, n_tty_ioctl_helper, tty_ioctl)
    if matches!(
        cmd,
        TCSETS | TCSETSW | TCSETSF | TCFLSH | TCXONC | TCSBRK | TCSBRKP | TIOCSBRK | TIOCCBRK
    ) {
        jobctrl::check_change(tty, crate::signal::SIGTTOU)?;
    }
    match cmd {
        TCGETS => put(arg, tty.get_termios()),
        TCSETS | TCSETSW | TCSETSF => {
            let t: Termios = get(arg)?;
            if cmd != TCSETS {
                drain(tty)?;
            }
            if cmd == TCSETSF {
                tty.flush_input();
            }
            tty.set_termios(t);
            Ok(0)
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
        TIOCOUTQ => put(arg, 0i32), // output is written synchronously
        TIOCGPGRP => put(arg, pid_i32(jobctrl::tiocgpgrp(tty)?)),
        TIOCSPGRP => {
            jobctrl::tiocspgrp(tty, get::<i32>(arg)?)?;
            Ok(0)
        }
        TIOCGSID => put(arg, pid_i32(jobctrl::tiocgsid(tty)?)),
        TIOCSCTTY => {
            jobctrl::tiocsctty(tty, file, arg == 1)?;
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
        // is TCSBRK 1)
        TCSBRK | TCSBRKP => {
            drain(tty)?;
            Ok(0)
        }
        TIOCSBRK | TIOCCBRK | TCXONC | TIOCEXCL | TIOCNXCL => Ok(0),
        // No modem control: the lines read as asserted, sets are ignored
        TIOCMGET => put(
            arg,
            TIOCM_DTR | TIOCM_RTS | TIOCM_CTS | TIOCM_CAR | TIOCM_DSR,
        ),
        TIOCMBIS | TIOCMBIC | TIOCMSET => get::<i32>(arg).map(|_| 0),
        // Soft carrier is CLOCAL (Linux tty_change_softcar)
        TIOCGSOFTCAR => put(arg, i32::from(tty.get_termios().c_cflag & CLOCAL != 0)),
        TIOCSSOFTCAR => {
            let on = get::<i32>(arg)? != 0;
            let mut t = tty.get_termios();
            t.c_cflag = if on {
                t.c_cflag | CLOCAL
            } else {
                t.c_cflag & !CLOCAL
            };
            tty.set_termios(t);
            Ok(0)
        }
        _ => Err(KernelError::NotTty),
    }
}

/// A pid as the user's pid_t
fn pid_i32(p: u32) -> i32 {
    i32::try_from(p).unwrap_or(0)
}
