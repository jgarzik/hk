//! FTDI USB serial converter (Linux drivers/usb/serial/ftdi_sio.c):
//! QEMU's usb-serial is an FT232 (0403:6001). `USB_SERIAL_DRIVER`
//! binds its interface on the USB bus as "ftdi_sio".
//!
//! ## Console Integration
//!
//! The port is registered as a console with Normal priority, ahead of
//! the legacy serial port (Fallback priority). Output goes out its
//! bulk OUT endpoint raw (the FT232 frames only its IN data).

use alloc::boxed::Box;
use core::any::Any;

use crate::console::{ConsoleDriver, ConsolePriority, register_console};
use crate::printkln;
use crate::util::error::KernelError;

use super::{UsbDeviceId, UsbIds};

/// FTDI's vendor id and the FT232's product id (Linux FTDI_VID,
/// FTDI_8U232AM_PID)
const FTDI_VID: u16 = 0x0403;
const FTDI_8U232AM_PID: u16 = 0x6001;

/// Devices it drives (a subset of Linux ftdi_sio's id_table_combined)
static FTDI_IDS: [UsbDeviceId; 1] = [UsbDeviceId::device(FTDI_VID, FTDI_8U232AM_PID)];

/// The FTDI serial driver: its port becomes a console
pub static USB_SERIAL_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "ftdi_sio",
    &super::USB_BUS,
    Some("ftdi_sio"),
    &UsbIds::Interface(&FTDI_IDS),
    ftdi_probe,
);

fn ftdi_probe(
    dev: &alloc::sync::Arc<crate::base::Device>,
) -> Result<Box<dyn crate::base::Bound>, KernelError> {
    let (usb_dev, intf) = super::usb_intf(dev).ok_or(KernelError::NoDevice)?;
    let Some((bulk_in_ep, bulk_out_ep)) = intf.bulk_eps() else {
        printkln!("ftdi_sio {}: no bulk endpoints", dev.name());
        return Err(KernelError::NoDevice);
    };
    let serial = UsbSerial {
        slot_id: usb_dev.slot_id,
        bulk_in_ep,
        bulk_out_ep,
    };
    printkln!(
        "ftdi_sio {}: FTDI USB Serial Device converter, bulk in {:#04x}, out {:#04x}",
        dev.name(),
        bulk_in_ep,
        bulk_out_ep
    );
    register_usb_serial_console(&serial);
    Ok(Box::new(serial))
}

/// A bound FTDI port
pub struct UsbSerial {
    /// The device's xHCI slot
    pub slot_id: u8,
    /// Bulk IN endpoint address
    pub bulk_in_ep: u8,
    /// Bulk OUT endpoint address
    pub bulk_out_ep: u8,
}

impl crate::base::Bound for UsbSerial {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Off the console list; a printk holding a snapshot of the list
    /// may still call it, so it stays allocated and just goes quiet
    fn remove(&self) {
        let gone = USB_SERIAL_CONSOLE.lock().take();
        if let Some(c) = gone {
            c.alive.store(false, core::sync::atomic::Ordering::Release);
            crate::console::unregister_console(c.name);
        }
    }
}

/// The registered USB serial console (spin leaf). Consoles are
/// `&'static` (printk writes through a snapshot of the list outside its
/// lock), so each one is leaked: a removed one stays valid, marked dead.
static USB_SERIAL_CONSOLE: crate::sync::spin::Mutex<Option<&'static UsbSerialConsole>> =
    crate::sync::spin::Mutex::new(None);

/// The FTDI port as a console (`ttyUSB0`)
pub struct UsbSerialConsole {
    /// Device name
    name: &'static str,
    /// Slot ID for USB device
    slot_id: u8,
    /// Bulk OUT endpoint
    bulk_out_ep: u8,
    /// The device is still attached
    alive: core::sync::atomic::AtomicBool,
}

impl UsbSerialConsole {
    /// Create from a UsbSerial device
    pub fn from_usb_serial(serial: &UsbSerial) -> Self {
        Self {
            name: "ttyUSB0",
            slot_id: serial.slot_id,
            bulk_out_ep: serial.bulk_out_ep,
            alive: core::sync::atomic::AtomicBool::new(true),
        }
    }
}

impl ConsoleDriver for UsbSerialConsole {
    fn name(&self) -> &str {
        self.name
    }

    fn write(&self, data: &[u8]) {
        use crate::hw::usb::xhci::{is_usb_output_active, usb_console_out};

        // Check recursion guard - if USB output is already active, skip to prevent deadlock
        // This can happen when a printkln! inside USB code tries to write to USB serial
        if is_usb_output_active() || !self.alive.load(core::sync::atomic::Ordering::Acquire) {
            return;
        }

        // The controller DMAs the data, and printk's may be on a kernel
        // stack: send it through a static buffer. Busy (another CPU, or
        // a printk nested in this one): dropped, the console is
        // best-effort like the transfer itself.
        let Some(mut buf) = BOUNCE.try_lock() else {
            return;
        };
        for chunk in data.chunks(buf.len()) {
            buf[..chunk.len()].copy_from_slice(chunk);
            let _ = usb_console_out(self.slot_id, self.bulk_out_ep, &buf[..chunk.len()]);
        }
    }
}

/// The USB serial console's DMA buffer (spin leaf, try_lock only; held
/// across the transfer, which takes `USB_CONTROLLER`)
static BOUNCE: crate::sync::spin::Mutex<[u8; 256]> = crate::sync::spin::Mutex::new([0; 256]);

/// Register a USB serial device as a console
///
/// This is called from the probe function when a USB serial device is detected.
/// The device is registered with Normal priority, allowing it to take precedence
/// over legacy serial (Fallback priority).
pub fn register_usb_serial_console(serial: &UsbSerial) {
    use crate::console::ConsoleFlags;

    let mut cur = USB_SERIAL_CONSOLE.lock();
    if cur.is_some() {
        return; // one ttyUSB0 console at a time
    }
    let console: &'static UsbSerialConsole =
        Box::leak(Box::new(UsbSerialConsole::from_usb_serial(serial)));
    *cur = Some(console);
    drop(cur);
    // Normal priority (above legacy serial's Fallback), no special flags
    register_console(console, ConsolePriority::Normal, ConsoleFlags::empty());
}
