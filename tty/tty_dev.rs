//! /dev/tty (5, 0): the caller's controlling terminal
//!
//! Open fails with ENXIO without one (Linux tty_open_current_tty); the
//! file then works on that tty (Linux points the file at it), even
//! once the session gives it up.

use crate::fs::File;
use crate::fs::chardev::CharDevice;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::io::poll::PollTable;
use crate::util::error::KernelError;

use super::{Redirect, jobctrl};

/// /dev/tty character device
pub struct TtyCharDevice;

impl CharDevice for TtyCharDevice {
    fn name(&self) -> &str {
        "tty"
    }

    fn open(&self, file: &File) -> Result<(), KernelError> {
        let tty = jobctrl::current_tty().ok_or(KernelError::NoDeviceOrAddress)?;
        Redirect::set(file, tty)
    }

    fn read(&self, file: &File, to: &mut IovDest<'_>) -> Result<usize, KernelError> {
        CharDevice::read(Redirect::tty(file)?, file, to)
    }

    fn write(&self, file: &File, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
        CharDevice::write(Redirect::tty(file)?, file, from)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        CharDevice::ioctl(Redirect::tty(file)?, file, cmd, arg)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        match Redirect::tty(file) {
            Ok(t) => CharDevice::poll(t, file, pt),
            Err(_) => crate::io::poll::POLLERR,
        }
    }
}
