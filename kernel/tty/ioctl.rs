//! TTY ioctl handlers
//!
//! This module implements TTY-specific ioctl operations following
//! the Linux kernel ABI exactly.
//!
//! Reference: include/uapi/asm-generic/ioctls.h

use super::Tty;
use super::termios::{Termios, Winsize};
use crate::arch::Uaccess;
use crate::chardev::DeviceError;
use crate::uaccess::{get_user, put_user};

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

/// Handle TTY ioctl for a given TTY device
///
/// # Arguments
/// * `tty` - The TTY device
/// * `cmd` - The ioctl command number
/// * `arg` - The ioctl argument (user pointer)
///
/// # Returns
/// * `Ok(result)` - Success with return value
/// * `Err(DeviceError)` - Error
pub fn tty_ioctl(tty: &Tty, cmd: u32, arg: u64) -> Result<i64, DeviceError> {
    match cmd {
        TCGETS => {
            // Get termios structure
            let termios = tty.get_termios();
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            put_user::<Uaccess, Termios>(arg, termios).map_err(|_| DeviceError::InvalidArg)?;
            Ok(0)
        }

        TCSETS | TCSETSW | TCSETSF => {
            // Set termios structure
            // TCSETS: immediate
            // TCSETSW: after drain
            // TCSETSF: after flush
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            let termios: Termios =
                get_user::<Uaccess, Termios>(arg).map_err(|_| DeviceError::InvalidArg)?;

            // For TCSETSW, we should wait for output to drain
            if cmd == TCSETSW || cmd == TCSETSF {
                tty.wait_until_sent();
            }

            // For TCSETSF, we should also flush input
            if cmd == TCSETSF {
                tty.flush_input();
            }

            tty.set_termios(termios);
            Ok(0)
        }

        TIOCGWINSZ => {
            // Get window size
            let winsize = tty.get_winsize();
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            put_user::<Uaccess, Winsize>(arg, winsize).map_err(|_| DeviceError::InvalidArg)?;
            Ok(0)
        }

        TIOCSWINSZ => {
            // Set window size
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            let winsize: Winsize =
                get_user::<Uaccess, Winsize>(arg).map_err(|_| DeviceError::InvalidArg)?;
            tty.set_winsize(winsize);
            // TODO: Send SIGWINCH to foreground process group
            Ok(0)
        }

        FIONREAD => {
            // Get number of bytes available to read
            let count = tty.bytes_available() as i32;
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            put_user::<Uaccess, i32>(arg, count).map_err(|_| DeviceError::InvalidArg)?;
            Ok(0)
        }

        TIOCGPGRP => {
            // Get foreground process group
            let pgrp = tty.get_foreground_pgrp().unwrap_or(0) as i32;
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            put_user::<Uaccess, i32>(arg, pgrp).map_err(|_| DeviceError::InvalidArg)?;
            Ok(0)
        }

        TIOCSPGRP => {
            // Set foreground process group
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            let pgrp: i32 = get_user::<Uaccess, i32>(arg).map_err(|_| DeviceError::InvalidArg)?;
            if pgrp <= 0 {
                return Err(DeviceError::InvalidArg);
            }
            tty.set_foreground_pgrp(pgrp as u32);
            Ok(0)
        }

        TIOCGSID => {
            // Get session ID
            let sid = tty.get_session().unwrap_or(0) as i32;
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            put_user::<Uaccess, i32>(arg, sid).map_err(|_| DeviceError::InvalidArg)?;
            Ok(0)
        }

        TIOCSCTTY => {
            // Acquire controlling terminal
            // arg is the "steal" flag (0 = normal, 1 = steal from another session)
            // This requires the process to be a session leader
            use crate::task::percpu::{current_pgid, current_pid, current_sid};

            let caller_pid = current_pid();
            let caller_sid = current_sid();
            let caller_pgid = current_pgid();
            let steal = arg != 0;

            // Check if caller is a session leader (pid == sid)
            if caller_pid != caller_sid {
                return Err(DeviceError::InvalidArg); // EPERM - not session leader
            }

            // Check if TTY already has a controlling session
            if let Some(existing_sid) = tty.get_session()
                && existing_sid != 0
                && !steal
            {
                return Err(DeviceError::InvalidArg); // EPERM - already has controlling session
            }

            // Set this process's session as the controlling session
            tty.set_session(caller_sid as u32);
            // Also set the foreground process group to the caller's pgid
            tty.set_foreground_pgrp(caller_pgid as u32);
            Ok(0)
        }

        TIOCNOTTY => {
            // Give up controlling terminal
            // Only the session leader can give up the controlling terminal
            use crate::task::percpu::{current_pid, current_sid};

            let caller_pid = current_pid();
            let caller_sid = current_sid();

            // Check if caller is a session leader
            if caller_pid != caller_sid {
                return Err(DeviceError::InvalidArg); // EPERM - not session leader
            }

            // Check if this is actually our controlling terminal
            if let Some(tty_sid) = tty.get_session()
                && tty_sid as u64 != caller_sid
            {
                return Err(DeviceError::InvalidArg); // Not our controlling terminal
            }

            // Clear the controlling session
            tty.clear_session();
            Ok(0)
        }

        TIOCGETD => {
            // Get line discipline number
            let ldisc = tty.get_line_discipline() as i32;
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            put_user::<Uaccess, i32>(arg, ldisc).map_err(|_| DeviceError::InvalidArg)?;
            Ok(0)
        }

        TIOCSETD => {
            // Set line discipline
            // For now, we only support N_TTY (0)
            if arg == 0 {
                return Err(DeviceError::InvalidArg);
            }
            let ldisc: i32 = get_user::<Uaccess, i32>(arg).map_err(|_| DeviceError::InvalidArg)?;
            if ldisc != 0 {
                // Only N_TTY supported
                return Err(DeviceError::InvalidArg);
            }
            Ok(0)
        }

        TCFLSH => {
            // Flush queues
            // arg: TCIFLUSH (0), TCOFLUSH (1), TCIOFLUSH (2)
            match arg as u32 {
                0 => tty.flush_input(),  // TCIFLUSH
                1 => tty.flush_output(), // TCOFLUSH
                2 => {
                    // TCIOFLUSH
                    tty.flush_input();
                    tty.flush_output();
                }
                _ => return Err(DeviceError::InvalidArg),
            }
            Ok(0)
        }

        FIONBIO => {
            // Set/clear non-blocking I/O
            // This is typically handled at the file descriptor level, not TTY
            // We accept it but don't do anything special
            Ok(0)
        }

        // Unimplemented but return 0 to avoid breaking programs
        TCGETA | TCSETA | TCSETAW | TCSETAF => {
            // Old termio interface - not implemented
            Err(DeviceError::NotSupported)
        }

        TCSBRK | TCSBRKP | TIOCSBRK | TIOCCBRK => {
            // Break handling - not implemented for virtual terminals
            Ok(0)
        }

        TCXONC => {
            // Software flow control - not implemented
            Ok(0)
        }

        TIOCEXCL | TIOCNXCL => {
            // Exclusive mode - not implemented
            Ok(0)
        }

        TIOCOUTQ => {
            // Output queue size - return 0 for now
            if arg != 0 {
                let _ = put_user::<Uaccess, i32>(arg, 0);
            }
            Ok(0)
        }

        TIOCMGET | TIOCMBIS | TIOCMBIC | TIOCMSET => {
            // Modem control lines - not implemented for most TTYs
            Ok(0)
        }

        TIOCGSOFTCAR | TIOCSSOFTCAR => {
            // Software carrier - not implemented
            Ok(0)
        }

        _ => {
            // Unknown ioctl
            Err(DeviceError::NotTty)
        }
    }
}
