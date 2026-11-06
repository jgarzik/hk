//! /dev/console (5, 1): the tty of the first console that has one
//! (Linux console_device)
//!
//! Reads, writes (through its line discipline: OPOST, TOSTOP), ioctls
//! and poll are that tty's; opening it never makes it a controlling tty
//! (Linux noctty for the console).

use crate::console::console_tty;
use crate::fs::File;
use crate::fs::chardev::CharDevice;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::io::poll::PollTable;
use crate::util::error::KernelError;

use super::Redirect;

/// /dev/console character device
pub struct ConsoleCharDevice;

impl CharDevice for ConsoleCharDevice {
    fn name(&self) -> &str {
        "console"
    }

    /// console_fops has tty_poll
    fn can_poll(&self) -> bool {
        true
    }

    fn open(&self, file: &File) -> Result<(), KernelError> {
        let tty = console_tty().ok_or(KernelError::NoDevice)?;
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
