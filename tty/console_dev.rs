//! /dev/console Character Device
//!
//! This module implements the /dev/console special character device.
//! /dev/console maps to the kernel's primary console (highest priority
//! registered console).
//!
//! ## Behavior
//!
//! - Writes go to the primary console driver
//! - Reads return ENXIO (console is typically output-only)
//! - ioctls are forwarded to the underlying TTY if applicable
//!
//! ## Linux conventions
//!
//! /dev/console = major 5, minor 1

use crate::console::{console_flush, console_write};
use crate::fs::File;
use crate::fs::chardev::CharDevice;
use crate::io::poll::{POLLOUT, POLLWRNORM, PollTable};
use crate::util::error::KernelError;

/// /dev/console character device
///
/// This device writes to the kernel's primary console.
/// The primary console is determined by the console subsystem
/// (highest priority registered console).
pub struct ConsoleCharDevice;

impl CharDevice for ConsoleCharDevice {
    fn name(&self) -> &str {
        "console"
    }

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, KernelError> {
        // /dev/console is typically output-only on most systems.
        // Linux returns ENXIO for reads on /dev/console when there's
        // no backing input device configured.
        Err(KernelError::OperationNotSupported)
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        // Write to the primary console (all registered consoles receive output)
        console_write(buf);
        Ok(buf.len())
    }

    fn ioctl(&self, _file: &File, _cmd: u32, _arg: u64) -> Result<i64, KernelError> {
        // Console ioctls could forward to the underlying TTY
        // For now, return ENOTTY for most ioctls
        Err(KernelError::NotTty)
    }

    fn poll(&self, _file: &File, _pt: Option<&mut PollTable>) -> u16 {
        // No input available on console; always ready for writing
        POLLOUT | POLLWRNORM
    }
}

impl Default for ConsoleCharDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleCharDevice {
    /// Create a new console character device
    pub const fn new() -> Self {
        Self
    }

    /// Flush the console
    pub fn flush(&self) {
        console_flush();
    }
}

/// Static console device instance
pub static CONSOLE_CHARDEV: ConsoleCharDevice = ConsoleCharDevice::new();
