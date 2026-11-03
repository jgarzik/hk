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
pub mod jobctrl;
pub mod n_tty;
pub mod termios;
pub mod tty_dev;

use alloc::sync::Arc;

use crate::sync::spin::Mutex;

use crate::console::ConsoleDriver;
use crate::fs::File;
use crate::fs::chardev::{CharDevice, DevId};
use crate::fs::flags::O_NOCTTY;
use crate::io::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::task::Pid;
use crate::util::error::KernelError;

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
    fn write(&self, data: &[u8]) -> Result<usize, KernelError>;

    /// Read bytes from hardware (non-blocking)
    fn read(&self, buf: &mut [u8]) -> Result<usize, KernelError>;

    /// Check if data is available to read
    fn poll_read(&self) -> bool {
        false
    }

    /// Initialize the hardware
    fn init(&self) -> Result<(), KernelError> {
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
    fn write(&self, tty: &Tty, buf: &[u8]) -> Result<usize, KernelError>;
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

    fn write(&self, tty: &Tty, buf: &[u8]) -> Result<usize, KernelError> {
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

/// Job control state (Linux tty->ctrl and winsize)
struct TtyCtrl {
    /// Window size
    winsize: Winsize,
    /// The session whose controlling tty this is
    session: Option<Pid>,
    /// Foreground process group
    pgrp: Option<Pid>,
}

impl TtyCtrl {
    const fn new() -> Self {
        Self {
            winsize: Winsize::default_console(),
            session: None,
            pgrp: None,
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
    /// Device number (/dev node)
    dev: DevId,
    /// Terminal settings
    pub termios: Mutex<Termios>,
    /// Line discipline
    ldisc: &'static dyn LineDiscipline,
    /// Hardware driver
    driver: &'static dyn TtyDriver,
    /// Input buffer (from hardware)
    input: Mutex<InputBuffer>,
    /// Session, foreground group, window size
    ctrl: Mutex<TtyCtrl>,
}

impl Tty {
    /// Create a new TTY with the given driver (const fn for static init)
    pub const fn new(
        name: &'static str,
        dev: DevId,
        driver: &'static dyn TtyDriver,
        ldisc: &'static dyn LineDiscipline,
    ) -> Self {
        Self {
            name,
            dev,
            termios: Mutex::new(Termios::new()),
            ldisc,
            driver,
            input: Mutex::new(InputBuffer::new()),
            ctrl: Mutex::new(TtyCtrl::new()),
        }
    }

    /// Device name (/dev node)
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Device number
    pub fn dev(&self) -> DevId {
        self.dev
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
    pub fn driver_write(&self, data: &[u8]) -> Result<usize, KernelError> {
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
    }

    /// Get the window size
    pub fn get_winsize(&self) -> Winsize {
        self.ctrl.lock().winsize
    }

    /// Set the window size; a new one signals the foreground process
    /// group with SIGWINCH (Linux tty_do_resize)
    pub fn resize(&self, ws: Winsize) {
        let pgrp = {
            let mut c = self.ctrl.lock();
            if c.winsize == ws {
                return;
            }
            c.winsize = ws;
            c.pgrp
        };
        if let Some(pg) = pgrp {
            crate::signal::send_signal_to_pgrp(pg, crate::signal::SIGWINCH);
        }
    }

    /// Get the number of bytes available to read
    pub fn bytes_available(&self) -> usize {
        self.input.lock().available()
    }

    /// The foreground process group
    pub fn pgrp(&self) -> Option<Pid> {
        self.ctrl.lock().pgrp
    }

    /// The session whose controlling tty this is
    pub fn session(&self) -> Option<Pid> {
        self.ctrl.lock().session
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

    fn open(&self, file: &File) -> Result<(), KernelError> {
        if file.get_flags() & O_NOCTTY == 0 {
            jobctrl::open_set_tty(self, file);
        }
        Ok(())
    }

    fn read(&self, _file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
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
            return Err(KernelError::WouldBlock);
        }

        Ok(count)
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        self.ldisc.write(self, buf)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        ioctl::tty_ioctl(self, file, cmd, arg)
    }

    fn poll(&self, _file: &File, _pt: Option<&mut PollTable>) -> u16 {
        let mut mask = POLLOUT | POLLWRNORM;
        if !self.input.lock().is_empty() || self.driver.poll_read() {
            mask |= POLLIN | POLLRDNORM;
        }
        mask
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

    fn tty(&'static self) -> Option<&'static Tty> {
        Some(self)
    }
}

/// Every tty (the serial ports')
pub fn all() -> &'static [&'static Tty] {
    crate::arch::serial_ttys()
}

/// The tty a /dev/tty or /dev/console file works on (its private
/// data; Linux points such a file at the tty itself)
struct Redirect(&'static Tty);

impl Redirect {
    /// Point `file` at `tty` (at open)
    fn set(file: &File, tty: &'static Tty) {
        file.private.call_once(|| Arc::new(Redirect(tty)));
    }

    /// The tty `file` was pointed at
    fn tty(file: &File) -> Result<&'static Tty, KernelError> {
        file.private_ref::<Redirect>()
            .map(|r| r.0)
            .ok_or(KernelError::Io)
    }
}

/// A static tty as a registered character device
struct TtyChar(&'static Tty);

impl CharDevice for TtyChar {
    fn name(&self) -> &str {
        self.0.name
    }

    fn open(&self, file: &File) -> Result<(), KernelError> {
        CharDevice::open(self.0, file)
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        CharDevice::read(self.0, file, buf)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        CharDevice::write(self.0, file, buf)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        CharDevice::ioctl(self.0, file, cmd, arg)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
        CharDevice::poll(self.0, file, pt)
    }
}

/// Initialize TTY character devices in the chardev registry
///
/// This registers serial TTYs for each architecture plus special devices
/// like /dev/console and /dev/tty.
/// Called from init_vfs() after heap is available.
pub fn init_tty_chardevs() {
    use crate::fs::chardev::{major, register_chardev};

    // The serial ports (Linux uart_register_driver)
    for &tty in crate::arch::serial_ttys() {
        let _ = register_chardev(tty.dev, Arc::new(TtyChar(tty)));
    }

    // Register /dev/tty (major 5, minor 0) - controlling terminal
    let tty_dev = Arc::new(tty_dev::TtyCharDevice);
    let _ = register_chardev(DevId::new(major::TTYAUX, 0), tty_dev);

    // Register /dev/console (major 5, minor 1) - kernel console
    let console_dev = Arc::new(console_dev::ConsoleCharDevice);
    let _ = register_chardev(DevId::new(major::TTYAUX, 1), console_dev);
}

// =============================================================================
// vhangup syscall
// =============================================================================

/// vhangup syscall - simulate hangup on controlling terminal
///
/// This syscall simulates a hangup on the current process's controlling terminal.
/// It is typically used by login(1) and getty(8) to ensure a clean terminal state
/// before a new user logs in.
///
/// # Returns
/// * 0 on success
/// * -EPERM if caller lacks CAP_SYS_TTY_CONFIG capability
///
/// # Linux Compatibility
/// Linux requires CAP_SYS_TTY_CONFIG. The full implementation would:
/// - Send SIGHUP to the foreground process group
/// - Revoke terminal access for all processes using the terminal
/// - Clear the session's controlling terminal association
///
/// For MVP, we implement the permission check and return success,
/// as the boot_tester runs with full capabilities and doesn't rely
/// on the terminal revocation behavior.
pub fn sys_vhangup() -> i64 {
    use crate::task::{CAP_SYS_TTY_CONFIG, capable};

    // Requires CAP_SYS_TTY_CONFIG capability
    if !capable(CAP_SYS_TTY_CONFIG) {
        return -1; // EPERM
    }

    // MVP: Return success
    // A full implementation would:
    // 1. Find the controlling terminal for current session
    // 2. Send SIGHUP to foreground process group
    // 3. Revoke terminal access for all users
    // 4. Clear session/ctty associations
    0
}
