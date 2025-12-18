//! /dev/tty Character Device
//!
//! This module implements the /dev/tty special character device.
//! /dev/tty is a magic device that refers to the calling process's
//! controlling terminal.
//!
//! ## Behavior
//!
//! - Opens succeed only if the process has a controlling terminal
//! - Reads/writes/ioctls are forwarded to the controlling terminal
//! - Returns ENXIO if no controlling terminal exists
//!
//! ## Linux conventions
//!
//! /dev/tty = major 5, minor 0

use alloc::sync::Arc;

use crate::chardev::{CHARDEV_REGISTRY, CharDevice, DevId, DeviceError, major};
use crate::task::percpu::current_sid;

/// /dev/tty character device
///
/// This is a magic device that refers to the calling process's
/// controlling terminal. It works by looking up the TTY that has
/// the current process's session as its controlling session.
pub struct TtyCharDevice;

impl Default for TtyCharDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl TtyCharDevice {
    /// Create a new /dev/tty device
    pub const fn new() -> Self {
        Self
    }

    /// Find the controlling terminal for the current process
    ///
    /// This searches through registered TTYs to find one whose
    /// session ID matches the current process's session ID.
    fn find_controlling_tty(&self) -> Option<Arc<dyn CharDevice>> {
        let caller_sid = current_sid() as u32;

        // Search through TTY devices (major 4, various minors)
        // Serial TTYs start at minor 64
        let registry = CHARDEV_REGISTRY.read();

        // Check ttyS0 (4, 64)
        if let Some(dev) = registry.get(DevId::new(major::TTYS, 64)) {
            // The chardev is a TTY wrapper - we need to check if it's our controlling tty
            // For now, since we can't easily introspect the TTY's session from the CharDevice
            // interface, we rely on the first serial TTY being the controlling terminal
            // when the process has any session.
            if caller_sid != 0 {
                return Some(dev);
            }
        }

        None
    }
}

impl CharDevice for TtyCharDevice {
    fn name(&self) -> &str {
        "tty"
    }

    fn open(&self, _flags: u32) -> Result<(), DeviceError> {
        // /dev/tty open fails with ENXIO if no controlling terminal
        if self.find_controlling_tty().is_none() {
            return Err(DeviceError::NotFound);
        }
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, DeviceError> {
        match self.find_controlling_tty() {
            Some(tty) => tty.read(buf),
            None => Err(DeviceError::NotFound), // ENXIO
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, DeviceError> {
        match self.find_controlling_tty() {
            Some(tty) => tty.write(buf),
            None => Err(DeviceError::NotFound), // ENXIO
        }
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, DeviceError> {
        match self.find_controlling_tty() {
            Some(tty) => tty.ioctl(cmd, arg),
            None => Err(DeviceError::NotFound), // ENXIO
        }
    }

    fn poll_read(&self) -> bool {
        match self.find_controlling_tty() {
            Some(tty) => tty.poll_read(),
            None => false,
        }
    }

    fn poll_write(&self) -> bool {
        match self.find_controlling_tty() {
            Some(tty) => tty.poll_write(),
            None => false,
        }
    }
}

/// Static /dev/tty device instance
pub static TTY_CHARDEV: TtyCharDevice = TtyCharDevice::new();
