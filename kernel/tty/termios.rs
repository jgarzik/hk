//! Linux-Compatible Termios Definitions
//!
//! This module provides exact Linux ABI-compatible termios structures
//! and constants. All values are taken directly from Linux kernel headers:
//! - include/uapi/asm-generic/termbits.h
//! - include/uapi/asm-generic/termbits-common.h
//!
//! IMPORTANT: Do not modify these values - they must match Linux exactly.

/// Number of control characters (Linux NCCS)
pub const NCCS: usize = 19;

/// Termios structure - terminal I/O settings (Linux ABI-compatible)
///
/// This struct matches the Linux `struct termios` exactly.
/// Size: 4 + 4 + 4 + 4 + 1 + 19 = 36 bytes (no padding needed)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Termios {
    /// Input mode flags
    pub c_iflag: u32,
    /// Output mode flags
    pub c_oflag: u32,
    /// Control mode flags
    pub c_cflag: u32,
    /// Local mode flags
    pub c_lflag: u32,
    /// Line discipline
    pub c_line: u8,
    /// Control characters
    pub c_cc: [u8; NCCS],
}

impl Termios {
    /// Create default termios settings (raw mode)
    pub const fn new() -> Self {
        let mut c_cc = [0u8; NCCS];
        // Set default control characters (Linux defaults)
        c_cc[VINTR] = 0x03; // Ctrl-C
        c_cc[VQUIT] = 0x1C; // Ctrl-\
        c_cc[VERASE] = 0x7F; // DEL
        c_cc[VKILL] = 0x15; // Ctrl-U
        c_cc[VEOF] = 0x04; // Ctrl-D
        c_cc[VTIME] = 0;
        c_cc[VMIN] = 1;
        c_cc[VSTART] = 0x11; // Ctrl-Q (XON)
        c_cc[VSTOP] = 0x13; // Ctrl-S (XOFF)
        c_cc[VSUSP] = 0x1A; // Ctrl-Z
        c_cc[VREPRINT] = 0x12; // Ctrl-R
        c_cc[VWERASE] = 0x17; // Ctrl-W
        c_cc[VLNEXT] = 0x16; // Ctrl-V

        Self {
            c_iflag: 0,
            c_oflag: OPOST | ONLCR,         // Output processing, NL -> CR-NL
            c_cflag: CS8 | CREAD | B115200, // 8 bits, enable receiver, 115200 baud
            c_lflag: 0,                     // Raw mode by default
            c_line: 0,                      // N_TTY
            c_cc,
        }
    }

    /// Create cooked (canonical) mode settings
    pub const fn cooked() -> Self {
        let mut t = Self::new();
        t.c_iflag = ICRNL | IXON;
        t.c_oflag = OPOST | ONLCR;
        t.c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
        t
    }
}

impl Default for Termios {
    fn default() -> Self {
        Self::new()
    }
}

/// Extended termios structure with explicit baud rates (Linux termios2)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Termios2 {
    /// Input mode flags
    pub c_iflag: u32,
    /// Output mode flags
    pub c_oflag: u32,
    /// Control mode flags
    pub c_cflag: u32,
    /// Local mode flags
    pub c_lflag: u32,
    /// Line discipline
    pub c_line: u8,
    /// Control characters
    pub c_cc: [u8; NCCS],
    /// Input speed
    pub c_ispeed: u32,
    /// Output speed
    pub c_ospeed: u32,
}

/// Window size structure (Linux ABI-compatible)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Winsize {
    /// Number of rows
    pub ws_row: u16,
    /// Number of columns
    pub ws_col: u16,
    /// Horizontal pixels (unused)
    pub ws_xpixel: u16,
    /// Vertical pixels (unused)
    pub ws_ypixel: u16,
}

impl Winsize {
    /// Default 80x25 terminal size
    pub const fn default_console() -> Self {
        Self {
            ws_row: 25,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

// =============================================================================
// c_cc indices (control characters)
// From: include/uapi/asm-generic/termbits.h
// =============================================================================

/// Interrupt character (Ctrl-C -> SIGINT)
pub const VINTR: usize = 0;
/// Quit character (Ctrl-\ -> SIGQUIT)
pub const VQUIT: usize = 1;
/// Erase character (backspace)
pub const VERASE: usize = 2;
/// Kill line character (Ctrl-U)
pub const VKILL: usize = 3;
/// End-of-file character (Ctrl-D)
pub const VEOF: usize = 4;
/// Read timeout (in 0.1s units)
pub const VTIME: usize = 5;
/// Minimum characters for read
pub const VMIN: usize = 6;
/// Switch character (unused)
pub const VSWTC: usize = 7;
/// Start character (Ctrl-Q, XON)
pub const VSTART: usize = 8;
/// Stop character (Ctrl-S, XOFF)
pub const VSTOP: usize = 9;
/// Suspend character (Ctrl-Z -> SIGTSTP)
pub const VSUSP: usize = 10;
/// End-of-line character
pub const VEOL: usize = 11;
/// Reprint character (Ctrl-R)
pub const VREPRINT: usize = 12;
/// Discard character (Ctrl-O)
pub const VDISCARD: usize = 13;
/// Word erase character (Ctrl-W)
pub const VWERASE: usize = 14;
/// Literal next character (Ctrl-V)
pub const VLNEXT: usize = 15;
/// Second end-of-line character
pub const VEOL2: usize = 16;

// =============================================================================
// c_iflag bits (input modes)
// From: include/uapi/asm-generic/termbits-common.h and termbits.h
// =============================================================================

/// Ignore break condition
pub const IGNBRK: u32 = 0x001;
/// Signal interrupt on break
pub const BRKINT: u32 = 0x002;
/// Ignore characters with parity errors
pub const IGNPAR: u32 = 0x004;
/// Mark parity and framing errors
pub const PARMRK: u32 = 0x008;
/// Enable input parity check
pub const INPCK: u32 = 0x010;
/// Strip 8th bit off characters
pub const ISTRIP: u32 = 0x020;
/// Map NL to CR on input
pub const INLCR: u32 = 0x040;
/// Ignore CR
pub const IGNCR: u32 = 0x080;
/// Map CR to NL on input
pub const ICRNL: u32 = 0x100;
/// Map uppercase to lowercase on input
pub const IUCLC: u32 = 0x200;
/// Enable XON/XOFF flow control on output
pub const IXON: u32 = 0x400;
/// Any character will restart after stop
pub const IXANY: u32 = 0x800;
/// Enable XON/XOFF flow control on input
pub const IXOFF: u32 = 0x1000;
/// Ring bell when input queue is full
pub const IMAXBEL: u32 = 0x2000;
/// Input is UTF-8
pub const IUTF8: u32 = 0x4000;

// =============================================================================
// c_oflag bits (output modes)
// From: include/uapi/asm-generic/termbits-common.h and termbits.h
// =============================================================================

/// Perform output processing
pub const OPOST: u32 = 0x01;
/// Map lowercase to uppercase on output
pub const OLCUC: u32 = 0x02;
/// Map NL to CR-NL on output
pub const ONLCR: u32 = 0x04;
/// Map CR to NL on output
pub const OCRNL: u32 = 0x08;
/// Don't output CR at column 0
pub const ONOCR: u32 = 0x10;
/// Don't output CR
pub const ONLRET: u32 = 0x20;
/// Use fill characters for delay
pub const OFILL: u32 = 0x40;
/// Fill character is DEL (else NUL)
pub const OFDEL: u32 = 0x80;

/// Newline delay mask
pub const NLDLY: u32 = 0x100;
/// Newline delay type 0
pub const NL0: u32 = 0x000;
/// Newline delay type 1
pub const NL1: u32 = 0x100;

/// Carriage return delay mask
pub const CRDLY: u32 = 0x600;
/// CR delay type 0
pub const CR0: u32 = 0x000;
/// CR delay type 1
pub const CR1: u32 = 0x200;
/// CR delay type 2
pub const CR2: u32 = 0x400;
/// CR delay type 3
pub const CR3: u32 = 0x600;

/// Tab delay mask
pub const TABDLY: u32 = 0x1800;
/// Tab delay type 0
pub const TAB0: u32 = 0x0000;
/// Tab delay type 1
pub const TAB1: u32 = 0x0800;
/// Tab delay type 2
pub const TAB2: u32 = 0x1000;
/// Tab delay type 3 (expand tabs to spaces)
pub const TAB3: u32 = 0x1800;
/// Expand tabs to spaces
pub const XTABS: u32 = 0x1800;

/// Backspace delay mask
pub const BSDLY: u32 = 0x2000;
/// Backspace delay type 0
pub const BS0: u32 = 0x0000;
/// Backspace delay type 1
pub const BS1: u32 = 0x2000;

/// Vertical tab delay mask
pub const VTDLY: u32 = 0x4000;
/// VT delay type 0
pub const VT0: u32 = 0x0000;
/// VT delay type 1
pub const VT1: u32 = 0x4000;

/// Form feed delay mask
pub const FFDLY: u32 = 0x8000;
/// FF delay type 0
pub const FF0: u32 = 0x0000;
/// FF delay type 1
pub const FF1: u32 = 0x8000;

// =============================================================================
// c_cflag bits (control modes)
// From: include/uapi/asm-generic/termbits-common.h and termbits.h
// =============================================================================

/// Baud rate mask
pub const CBAUD: u32 = 0x100f;
/// Character size mask
pub const CSIZE: u32 = 0x30;
/// 5 bits per character
pub const CS5: u32 = 0x00;
/// 6 bits per character
pub const CS6: u32 = 0x10;
/// 7 bits per character
pub const CS7: u32 = 0x20;
/// 8 bits per character
pub const CS8: u32 = 0x30;
/// Two stop bits (else one)
pub const CSTOPB: u32 = 0x40;
/// Enable receiver
pub const CREAD: u32 = 0x80;
/// Enable parity generation/checking
pub const PARENB: u32 = 0x100;
/// Odd parity (else even)
pub const PARODD: u32 = 0x200;
/// Hang up on last close
pub const HUPCL: u32 = 0x400;
/// Ignore modem control lines
pub const CLOCAL: u32 = 0x800;
/// Extra baud rate mask
pub const CBAUDEX: u32 = 0x1000;
/// Use custom baud rate
pub const BOTHER: u32 = 0x1000;

// Baud rates (standard)
/// Hang up (0 baud)
pub const B0: u32 = 0x00;
/// 50 baud
pub const B50: u32 = 0x01;
/// 75 baud
pub const B75: u32 = 0x02;
/// 110 baud
pub const B110: u32 = 0x03;
/// 134 baud
pub const B134: u32 = 0x04;
/// 150 baud
pub const B150: u32 = 0x05;
/// 200 baud
pub const B200: u32 = 0x06;
/// 300 baud
pub const B300: u32 = 0x07;
/// 600 baud
pub const B600: u32 = 0x08;
/// 1200 baud
pub const B1200: u32 = 0x09;
/// 1800 baud
pub const B1800: u32 = 0x0a;
/// 2400 baud
pub const B2400: u32 = 0x0b;
/// 4800 baud
pub const B4800: u32 = 0x0c;
/// 9600 baud
pub const B9600: u32 = 0x0d;
/// 19200 baud
pub const B19200: u32 = 0x0e;
/// 38400 baud
pub const B38400: u32 = 0x0f;

// Extended baud rates
/// 57600 baud
pub const B57600: u32 = 0x1001;
/// 115200 baud
pub const B115200: u32 = 0x1002;
/// 230400 baud
pub const B230400: u32 = 0x1003;
/// 460800 baud
pub const B460800: u32 = 0x1004;
/// 500000 baud
pub const B500000: u32 = 0x1005;
/// 576000 baud
pub const B576000: u32 = 0x1006;
/// 921600 baud
pub const B921600: u32 = 0x1007;
/// 1000000 baud
pub const B1000000: u32 = 0x1008;
/// 1152000 baud
pub const B1152000: u32 = 0x1009;
/// 1500000 baud
pub const B1500000: u32 = 0x100a;
/// 2000000 baud
pub const B2000000: u32 = 0x100b;
/// 2500000 baud
pub const B2500000: u32 = 0x100c;
/// 3000000 baud
pub const B3000000: u32 = 0x100d;
/// 3500000 baud
pub const B3500000: u32 = 0x100e;
/// 4000000 baud
pub const B4000000: u32 = 0x100f;

/// Input baud rate mask
pub const CIBAUD: u32 = 0x100f0000;
/// Mark or space (stick) parity
pub const CMSPAR: u32 = 0x40000000;
/// Enable RTS/CTS flow control
pub const CRTSCTS: u32 = 0x80000000;

// =============================================================================
// c_lflag bits (local modes)
// From: include/uapi/asm-generic/termbits.h
// =============================================================================

/// Enable signal generation (INTR, QUIT, SUSP)
pub const ISIG: u32 = 0x001;
/// Canonical mode (line editing)
pub const ICANON: u32 = 0x002;
/// Map uppercase to lowercase on input (obsolete)
pub const XCASE: u32 = 0x004;
/// Echo input characters
pub const ECHO: u32 = 0x008;
/// Echo erase as backspace-space-backspace
pub const ECHOE: u32 = 0x010;
/// Echo NL after KILL character
pub const ECHOK: u32 = 0x020;
/// Echo NL even if ECHO is not set
pub const ECHONL: u32 = 0x040;
/// Don't flush after interrupt/quit/suspend
pub const NOFLSH: u32 = 0x080;
/// Send SIGTTOU for background output
pub const TOSTOP: u32 = 0x100;
/// Echo control characters as ^X
pub const ECHOCTL: u32 = 0x200;
/// Visual erase for line kill
pub const ECHOPRT: u32 = 0x400;
/// Kill whole line on KILL character
pub const ECHOKE: u32 = 0x800;
/// Output being flushed
pub const FLUSHO: u32 = 0x1000;
/// Retype pending input
pub const PENDIN: u32 = 0x4000;
/// Enable implementation-defined input processing
pub const IEXTEN: u32 = 0x8000;
/// External processing
pub const EXTPROC: u32 = 0x10000;

// =============================================================================
// Line disciplines
// =============================================================================

/// N_TTY - standard terminal line discipline
pub const N_TTY: u8 = 0;
/// N_SLIP - SLIP protocol
pub const N_SLIP: u8 = 1;
/// N_MOUSE - Mouse protocol
pub const N_MOUSE: u8 = 2;
/// N_PPP - PPP protocol
pub const N_PPP: u8 = 3;

// =============================================================================
// tcsetattr actions
// =============================================================================

/// Change immediately
pub const TCSANOW: u32 = 0;
/// Change after all output transmitted
pub const TCSADRAIN: u32 = 1;
/// Change after all output transmitted, flush input
pub const TCSAFLUSH: u32 = 2;

// =============================================================================
// tcflow actions
// =============================================================================

/// Suspend output
pub const TCOOFF: u32 = 0;
/// Restart suspended output
pub const TCOON: u32 = 1;
/// Send STOP character
pub const TCIOFF: u32 = 2;
/// Send START character
pub const TCION: u32 = 3;

// =============================================================================
// tcflush queue selectors
// =============================================================================

/// Discard data received but not read
pub const TCIFLUSH: u32 = 0;
/// Discard data written but not sent
pub const TCOFLUSH: u32 = 1;
/// Discard all pending data
pub const TCIOFLUSH: u32 = 2;
