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
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;
use crate::util::kalloc::try_box;

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
    let serial = try_box(UsbSerial {
        slot_id: usb_dev.slot_id,
        bulk_in_ep,
        bulk_out_ep,
    })?;
    printkln!(
        "ftdi_sio {}: FTDI USB Serial Device converter, bulk in {:#04x}, out {:#04x}",
        dev.name(),
        bulk_in_ep,
        bulk_out_ep
    );
    register_usb_serial_console(&serial);
    Ok(serial)
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

    /// Off the console list if it is the console (Linux
    /// usb_serial_console_disconnect); then, under the port lock, which
    /// a write in progress holds, the console loses its device: a
    /// printk still holding a snapshot of the list writes nothing
    fn remove(&self) {
        if PORT.lock().out != Some((self.slot_id, self.bulk_out_ep)) {
            return;
        }
        crate::console::unregister_console(USB_SERIAL_CONSOLE.name());
        PORT.lock().out = None;
    }
}

/// The console's device and DMA buffer
struct Port {
    /// The bound port's slot and bulk OUT endpoint (None: no console)
    out: Option<(u8, u8)>,
    /// Output goes through it: the controller DMAs the data, and a
    /// printk's may be on a kernel stack
    buf: [u8; 256],
}

/// The USB serial console's port (spin leaf but for the transfer: a
/// write holds it across the bulk transfer, so it orders before
/// `USB_CONTROLLER`; `try_lock` there, a busy port drops the output)
static PORT: Mutex<Port> = Mutex::new(Port {
    out: None,
    buf: [0; 256],
});

/// The FTDI port as a console (`ttyUSB0`); one at a time
struct UsbSerialConsole;

static USB_SERIAL_CONSOLE: UsbSerialConsole = UsbSerialConsole;

impl ConsoleDriver for UsbSerialConsole {
    fn name(&self) -> &str {
        "ttyUSB0"
    }

    fn write(&self, data: &[u8]) {
        use crate::hw::usb::xhci::usb_console_out;

        // Busy (another CPU, or a printk nested in this one): dropped,
        // the console is best-effort like the transfer itself
        let Some(mut p) = PORT.try_lock() else {
            return;
        };
        let Some((slot, ep)) = p.out else {
            return;
        };
        for chunk in data.chunks(p.buf.len()) {
            p.buf[..chunk.len()].copy_from_slice(chunk);
            let _ = usb_console_out(slot, ep, &p.buf[..chunk.len()]);
        }
    }
}

/// Make the port the console (`ttyUSB0`) if there is none: Normal
/// priority, above legacy serial's Fallback, no special flags
fn register_usb_serial_console(serial: &UsbSerial) {
    use crate::console::ConsoleFlags;

    let mut p = PORT.lock();
    if p.out.is_some() {
        return;
    }
    p.out = Some((serial.slot_id, serial.bulk_out_ep));
    drop(p);
    register_console(
        &USB_SERIAL_CONSOLE,
        ConsolePriority::Normal,
        ConsoleFlags::empty(),
    );
}
