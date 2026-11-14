//! Synchronous requests on top of URBs (Linux
//! drivers/usb/core/message.c): submit, sleep until the completion
//! handler signals, copy the data. Thread context, no spinlock held.

use alloc::sync::Arc;

use super::urb::{Pipe, Urb, UrbComplete, usb_kill_urb, usb_submit_urb};
use super::{SetupPacket, UsbDevice, UsbError};
use crate::sync::completion::Completion;
use crate::task::percpu::ms_to_ticks;
use crate::util::kalloc::{try_arc, try_box};

/// Control requests reading data (Linux USB_CTRL_GET_TIMEOUT, ms)
pub const USB_CTRL_GET_TIMEOUT: u64 = 5000;
/// Control requests writing (Linux USB_CTRL_SET_TIMEOUT, ms)
pub const USB_CTRL_SET_TIMEOUT: u64 = 5000;
/// The longest a synchronous request waits (Linux
/// USB_MAX_SYNCHRONOUS_TIMEOUT, ms)
const USB_MAX_SYNCHRONOUS_TIMEOUT: u64 = 60_000;

/// An URB whose completion handler wakes its submitter (Linux
/// usb_api_blocking_completion with struct api_context)
fn blocking_urb(
    dev: &UsbDevice,
    pipe: Pipe,
    setup: Option<SetupPacket>,
    len: usize,
) -> Result<(Arc<Urb>, Arc<Completion>), UsbError> {
    let done = try_arc(Completion::new()).map_err(|_| UsbError::NoResources)?;
    let d = done.clone();
    let complete: UrbComplete =
        try_box(move |_: &Arc<Urb>| d.complete()).map_err(|_| UsbError::NoResources)?;
    let urb = Urb::new(dev, pipe, setup, len, complete).ok_or(UsbError::NoResources)?;
    Ok((urb, done))
}

/// Submit `urb` and wait up to `timeout_ms` (0: the maximum) for it to
/// be given back (Linux usb_start_wait_urb): its status, Timeout if it
/// was not given back in time
fn usb_start_wait_urb(urb: &Arc<Urb>, done: &Completion, timeout_ms: u64) -> Result<(), UsbError> {
    usb_submit_urb(urb)?;
    let ms = match timeout_ms {
        0 => USB_MAX_SYNCHRONOUS_TIMEOUT,
        t => t.min(USB_MAX_SYNCHRONOUS_TIMEOUT),
    };
    if !done.wait_timeout(ms_to_ticks(ms)) {
        // Killed: given back by the time this returns, so the caller
        // owns its buffer again; Timeout unless it completed meanwhile
        usb_kill_urb(urb);
        return match urb.status() {
            Err(UsbError::Killed) => Err(UsbError::Timeout),
            s => s,
        };
    }
    urb.status()
}

/// A control request on the default endpoint (Linux usb_control_msg):
/// `data` is the data stage, received (IN) or sent (OUT), at most
/// `setup.length` bytes. The bytes moved
pub fn usb_control_msg(
    dev: &UsbDevice,
    setup: &SetupPacket,
    data: &mut [u8],
    timeout_ms: u64,
) -> Result<usize, UsbError> {
    let len = usize::from(setup.length).min(data.len());
    let (urb, done) = blocking_urb(dev, Pipe::ctrl(), Some(*setup), len)?;
    if setup.is_in() {
        urb.fill(None, len)?;
    } else {
        urb.fill(Some(&data[..len]), len)?;
    }
    usb_start_wait_urb(&urb, &done, timeout_ms)?;
    if setup.is_in() {
        urb.copy_out(&mut data[..len])
    } else {
        Ok(urb.actual_length())
    }
}

/// A bulk request (Linux usb_bulk_msg): `data` is received (IN pipe)
/// or sent (OUT); the bytes moved
pub fn usb_bulk_msg(
    dev: &UsbDevice,
    pipe: Pipe,
    data: &mut [u8],
    timeout_ms: u64,
) -> Result<usize, UsbError> {
    let (urb, done) = blocking_urb(dev, pipe, None, data.len())?;
    if pipe.is_in() {
        urb.fill(None, data.len())?;
    } else {
        urb.fill(Some(data), data.len())?;
    }
    usb_start_wait_urb(&urb, &done, timeout_ms)?;
    if pipe.is_in() {
        urb.copy_out(data)
    } else {
        Ok(urb.actual_length())
    }
}
