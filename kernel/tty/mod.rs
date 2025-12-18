//! TTY Subsystem
//!
//! This module implements the TTY (teletype) layer, which sits between
//! the character device layer and hardware drivers.
//!
//! ## Architecture (per tty.txt)
//!
//! ```text
//! User space read/write
//!        ↓
//! Character device (/dev/ttyS0, /dev/ttyUSB0)
//!        ↓
//! TTY core (this module) - manages Tty struct, termios
//!        ↓
//! Line discipline - transforms byte streams (echo, editing)
//!        ↓
//! TTY driver - talks to hardware (serial UART, USB CDC-ACM)
//!        ↓
//! Hardware
//! ```
//!
//! ## Current Implementation
//!
//! For MVP, we implement:
//! - Raw line discipline (no editing, minimal echo)
//! - Linux-compatible termios structure
//! - SerialTty driver for NS16550A-compatible UARTs
//! - Tty as both CharDevice and ConsoleDriver
//! - Basic TTY ioctls (TCGETS, TCSETS, TIOCGWINSZ, etc.)

pub mod console_dev;
pub mod ioctl;
pub mod n_tty;
#[cfg(target_arch = "x86_64")]
pub mod serial;
pub mod termios;
pub mod tty_dev;

use spin::Mutex;

use crate::chardev::{CharDevice, DeviceError};
use crate::console::ConsoleDriver;

// Re-export commonly used types
pub use termios::{
    B115200,
    BRKINT,
    CLOCAL,
    CREAD,
    CS5,
    CS6,
    CS7,
    CS8,
    // c_cflag bits
    CSIZE,
    CSTOPB,
    ECHO,
    ECHOCTL,
    ECHOE,
    ECHOK,
    ECHOKE,
    ECHONL,
    HUPCL,
    ICANON,
    // c_iflag bits
    ICRNL,
    IEXTEN,
    IGNBRK,
    IGNCR,
    IGNPAR,
    INLCR,
    INPCK,
    // c_lflag bits
    ISIG,
    ISTRIP,
    IXOFF,
    IXON,
    // line disciplines
    N_TTY,
    NOFLSH,
    OCRNL,
    ONLCR,
    // c_oflag bits
    OPOST,
    PARENB,
    PARMRK,
    PARODD,
    TOSTOP,
    VEOF,
    VERASE,
    // c_cc indices
    VINTR,
    VKILL,
    VMIN,
    VQUIT,
    VSTART,
    VSTOP,
    VSUSP,
    VTIME,
};
pub use termios::{Termios, Winsize};

/// TTY driver trait - hardware interface
///
/// Implementations handle the actual hardware (UART, USB, etc.)
pub trait TtyDriver: Send + Sync {
    /// Driver name for identification
    fn name(&self) -> &str;

    /// Write bytes to hardware
    fn write(&self, data: &[u8]) -> Result<usize, DeviceError>;

    /// Read bytes from hardware (non-blocking)
    fn read(&self, buf: &mut [u8]) -> Result<usize, DeviceError>;

    /// Check if data is available to read
    fn poll_read(&self) -> bool {
        false
    }

    /// Initialize the hardware
    fn init(&self) -> Result<(), DeviceError> {
        Ok(())
    }

    /// Flush transmit buffer - wait for all data to be sent
    fn flush(&self) {}
}

/// Line discipline trait - byte stream processing
///
/// Sits between user I/O and the TTY driver.
pub trait LineDiscipline: Send + Sync {
    /// Process input character from hardware
    fn receive_char(&self, tty: &Tty, ch: u8);

    /// Process output from user write
    fn write(&self, tty: &Tty, buf: &[u8]) -> Result<usize, DeviceError>;
}

/// Raw line discipline - minimal processing
///
/// This is the simplest line discipline:
/// - Input: push directly to read buffer, optional echo
/// - Output: direct to hardware, optional CR-NL translation
pub struct RawLineDiscipline;

impl LineDiscipline for RawLineDiscipline {
    fn receive_char(&self, tty: &Tty, ch: u8) {
        // Push to read buffer
        tty.push_input(ch);

        // Echo if enabled
        if tty.echo_enabled() {
            let _ = tty.driver_write(&[ch]);
        }
    }

    fn write(&self, tty: &Tty, buf: &[u8]) -> Result<usize, DeviceError> {
        let termios = tty.termios.lock();
        let opost = termios.c_oflag & OPOST != 0;
        let onlcr = termios.c_oflag & ONLCR != 0;
        drop(termios);

        if opost && onlcr {
            // CR-NL translation
            for &byte in buf {
                if byte == b'\n' {
                    tty.driver_write(b"\r")?;
                }
                tty.driver_write(&[byte])?;
            }
            Ok(buf.len())
        } else {
            // Direct output
            tty.driver_write(buf)
        }
    }
}

/// Static raw line discipline instance
pub static RAW_LDISC: RawLineDiscipline = RawLineDiscipline;

/// Ring buffer for TTY input
struct InputBuffer {
    data: [u8; 4096],
    head: usize,
    tail: usize,
}

impl InputBuffer {
    const fn new() -> Self {
        Self {
            data: [0; 4096],
            head: 0,
            tail: 0,
        }
    }

    fn push(&mut self, byte: u8) {
        let next = (self.head + 1) % self.data.len();
        if next != self.tail {
            self.data[self.head] = byte;
            self.head = next;
        }
        // If full, drop the byte
    }

    fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail {
            None
        } else {
            let byte = self.data[self.tail];
            self.tail = (self.tail + 1) % self.data.len();
            Some(byte)
        }
    }

    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    fn available(&self) -> usize {
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            self.data.len() - self.tail + self.head
        }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }
}

/// TTY internal state (protected by mutex)
struct TtyState {
    /// Terminal settings
    termios: Termios,
    /// Window size
    winsize: Winsize,
    /// Session ID that owns this TTY
    session: Option<u32>,
    /// Foreground process group ID
    foreground_pgrp: Option<u32>,
}

impl TtyState {
    const fn new() -> Self {
        Self {
            termios: Termios::new(),
            winsize: Winsize::default_console(),
            session: None,
            foreground_pgrp: None,
        }
    }
}

/// TTY device instance
///
/// Combines the driver, line discipline, and termios into a single
/// device that can be accessed via the character device interface.
pub struct Tty {
    /// Device name (e.g., "ttyS0", "ttyUSB0")
    name: &'static str,
    /// Terminal settings (legacy field - use state instead for new code)
    pub termios: Mutex<Termios>,
    /// Line discipline
    ldisc: &'static dyn LineDiscipline,
    /// Hardware driver
    driver: &'static dyn TtyDriver,
    /// Input buffer (from hardware)
    input: Mutex<InputBuffer>,
    /// TTY state (termios, winsize, session info)
    state: Mutex<TtyState>,
}

impl Tty {
    /// Create a new TTY with the given driver (const fn for static init)
    pub const fn new(
        name: &'static str,
        driver: &'static dyn TtyDriver,
        ldisc: &'static dyn LineDiscipline,
    ) -> Self {
        Self {
            name,
            termios: Mutex::new(Termios::new()),
            ldisc,
            driver,
            input: Mutex::new(InputBuffer::new()),
            state: Mutex::new(TtyState::new()),
        }
    }

    /// Check if echo is enabled
    pub fn echo_enabled(&self) -> bool {
        self.termios.lock().c_lflag & ECHO != 0
    }

    /// Push a byte to the input buffer (called by driver/ldisc)
    pub fn push_input(&self, byte: u8) {
        self.input.lock().push(byte);
    }

    /// Write directly to driver (bypassing line discipline)
    pub fn driver_write(&self, data: &[u8]) -> Result<usize, DeviceError> {
        self.driver.write(data)
    }

    // =========================================================================
    // Methods for ioctl support
    // =========================================================================

    /// Get a copy of the termios structure
    pub fn get_termios(&self) -> Termios {
        *self.termios.lock()
    }

    /// Set the termios structure
    pub fn set_termios(&self, termios: Termios) {
        *self.termios.lock() = termios;
        // Also update the state copy
        self.state.lock().termios = termios;
    }

    /// Get the window size
    pub fn get_winsize(&self) -> Winsize {
        self.state.lock().winsize
    }

    /// Set the window size
    pub fn set_winsize(&self, winsize: Winsize) {
        self.state.lock().winsize = winsize;
    }

    /// Get the number of bytes available to read
    pub fn bytes_available(&self) -> usize {
        self.input.lock().available()
    }

    /// Get the foreground process group
    pub fn get_foreground_pgrp(&self) -> Option<u32> {
        self.state.lock().foreground_pgrp
    }

    /// Set the foreground process group
    pub fn set_foreground_pgrp(&self, pgrp: u32) {
        self.state.lock().foreground_pgrp = Some(pgrp);
    }

    /// Get the session ID
    pub fn get_session(&self) -> Option<u32> {
        self.state.lock().session
    }

    /// Set the session ID
    pub fn set_session(&self, sid: u32) {
        self.state.lock().session = Some(sid);
    }

    /// Clear the session ID (give up controlling terminal)
    pub fn clear_session(&self) {
        let mut state = self.state.lock();
        state.session = None;
        state.foreground_pgrp = None;
    }

    /// Get the line discipline number
    pub fn get_line_discipline(&self) -> u8 {
        // Currently always N_TTY (0)
        N_TTY
    }

    /// Wait for output to be sent
    pub fn wait_until_sent(&self) {
        self.driver.flush();
    }

    /// Flush the input buffer
    pub fn flush_input(&self) {
        self.input.lock().clear();
    }

    /// Flush the output buffer (no-op for polled driver)
    pub fn flush_output(&self) {
        self.driver.flush();
    }
}

// Implement CharDevice for Tty
impl CharDevice for Tty {
    fn name(&self) -> &str {
        self.name
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, DeviceError> {
        let mut input = self.input.lock();
        let mut count = 0;

        while count < buf.len() {
            if let Some(byte) = input.pop() {
                buf[count] = byte;
                count += 1;
            } else {
                break;
            }
        }

        if count == 0 && !self.driver.poll_read() {
            // No data available
            return Err(DeviceError::WouldBlock);
        }

        Ok(count)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, DeviceError> {
        self.ldisc.write(self, buf)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, DeviceError> {
        ioctl::tty_ioctl(self, cmd, arg)
    }

    fn poll_read(&self) -> bool {
        !self.input.lock().is_empty() || self.driver.poll_read()
    }
}

// Implement ConsoleDriver for Tty
// This allows a TTY to be used as a kernel console
impl ConsoleDriver for Tty {
    fn name(&self) -> &str {
        self.name
    }

    fn write(&self, data: &[u8]) {
        // Console write bypasses line discipline - direct to hardware
        // But we still do CR-NL translation for readability
        for &byte in data {
            if byte == b'\n' {
                let _ = self.driver.write(b"\r");
            }
            let _ = self.driver.write(&[byte]);
        }
    }

    fn flush(&self) {
        self.driver.flush();
    }
}

// Re-export SerialTty for convenience
#[cfg(target_arch = "x86_64")]
pub use serial::SerialTty;

/// Initialize TTY character devices in the chardev registry
///
/// This registers serial TTYs for each architecture plus special devices
/// like /dev/console and /dev/tty.
/// Called from init_vfs() after heap is available.
pub fn init_tty_chardevs() {
    use crate::chardev::{DevId, major, register_chardev};
    use alloc::sync::Arc;

    // Register platform-specific serial TTYs
    #[cfg(target_arch = "x86_64")]
    serial::register_serial_chardevs();

    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 serial registration will go here when implemented
        // For now, no serial chardev on aarch64
    }

    // Register /dev/tty (major 5, minor 0) - controlling terminal
    let tty_dev = Arc::new(tty_dev::TtyCharDevice::new());
    let _ = register_chardev(DevId::new(major::TTYAUX, 0), tty_dev);

    // Register /dev/console (major 5, minor 1) - kernel console
    let console_dev = Arc::new(console_dev::ConsoleCharDevice::new());
    let _ = register_chardev(DevId::new(major::TTYAUX, 1), console_dev);
}
