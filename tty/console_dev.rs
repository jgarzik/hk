//! /dev/console (5, 1): the tty of the first console that has one
//! (Linux console_device)
//!
//! Reads, writes (through its line discipline: OPOST, TOSTOP), ioctls
//! and poll are that tty's; opening it never makes it a controlling tty
//! (Linux noctty for the console). Writes are also copied to the other
//! consoles (a screen), which Linux does not do.

use crate::console::{console_tty, console_write_except};
use crate::fs::File;
use crate::fs::chardev::CharDevice;
use crate::io::poll::PollTable;
use crate::util::error::KernelError;

use super::Redirect;

/// /dev/console character device
pub struct ConsoleCharDevice;

impl CharDevice for ConsoleCharDevice {
    fn name(&self) -> &str {
        "console"
    }

    fn open(&self, file: &File) -> Result<(), KernelError> {
        let tty = console_tty().ok_or(KernelError::NoDevice)?;
        Redirect::set(file, tty);
        Ok(())
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        CharDevice::read(Redirect::tty(file)?, file, buf)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let tty = Redirect::tty(file)?;
        let n = CharDevice::write(tty, file, buf)?;
        console_write_except(&buf[..n], tty);
        Ok(n)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        CharDevice::ioctl(Redirect::tty(file)?, file, cmd, arg)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
        match Redirect::tty(file) {
            Ok(t) => CharDevice::poll(t, file, pt),
            Err(_) => crate::io::poll::POLLERR,
        }
    }
}
