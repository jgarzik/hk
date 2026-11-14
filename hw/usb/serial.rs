//! FTDI USB serial converter (Linux drivers/usb/serial/ftdi_sio.c):
//! QEMU's usb-serial is an FT232 (0403:6001). `USB_SERIAL_DRIVER`
//! binds its interface on the USB bus as "ftdi_sio".
//!
//! ## Console Integration
//!
//! The port is registered as a console with Normal priority, ahead of
//! the legacy serial port (Fallback priority). As Linux's usb-serial
//! console, a write only queues the output in the port's FIFO (any
//! context, dropping what does not fit); a work item sends it out the
//! bulk OUT endpoint raw (the FT232 frames only its IN data).

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::console::{ConsoleDriver, ConsolePriority, register_console};
use crate::printkln;
use crate::sync::{IrqSpinlock, Mutex};
use crate::task::workqueue::{SYSTEM_WQ, Work};
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_box};
use crate::util::kfifo::Kfifo;

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
    /// usb_serial_console_disconnect); then the port loses its device
    /// and its queued output, and a write transfer in progress is
    /// waited out (Linux usb_serial_disconnect kills the write URBs)
    fn remove(&self) {
        if PORT.lock().out != Some((self.slot_id, self.bulk_out_ep)) {
            return;
        }
        crate::console::unregister_console(USB_SERIAL_CONSOLE.name());
        {
            let mut p = PORT.lock();
            p.out = None;
            p.fifo.reset();
        }
        drop(WRITE_BUF.lock());
    }
}

/// The port's write FIFO (Linux usb-serial's write_fifo, PAGE_SIZE)
const WRITE_FIFO_SIZE: usize = 4096;
/// Bytes per bulk OUT transfer (Linux ftdi_sio's bulk_out_size)
const BULK_OUT_SIZE: usize = 256;

/// The console's port (Linux usb_serial_port: `lock`, `write_fifo`)
struct Port {
    /// The bound port's slot and bulk OUT endpoint (None: no console)
    out: Option<(u8, u8)>,
    /// Output queued for the write work to send
    fifo: Kfifo<WRITE_FIFO_SIZE>,
}

/// The USB serial console's port (Linux port->lock, IRQ-safe leaf: the
/// console write runs in any context, under printk's `OUTPUT_LOCK`)
static PORT: IrqSpinlock<Port> = IrqSpinlock::new(Port {
    out: None,
    fifo: Kfifo::new(),
});

/// The write transfer's buffer (Linux write_urbs[0]->transfer_buffer),
/// held across the transfer: one transfer at a time (Linux
/// USB_SERIAL_WRITE_BUSY), and remove waits one out
static WRITE_BUF: Mutex<[u8; BULK_OUT_SIZE]> = Mutex::new([0; BULK_OUT_SIZE]);

/// The write work (Linux submits the write URB from the console write
/// itself; hk's transfers are synchronous, so a thread sends them)
static WRITE_WORK: spin::Once<Arc<IrqSpinlock<Work>>> = spin::Once::new();

/// The CPU running a write transfer, else `NO_CPU`: what it prints in
/// thread context meanwhile (USB trace, transfer errors) is not queued,
/// or each transfer would feed the next forever (Linux prints a console
/// port's errors once for this: dev_err_console)
static TX_CPU: AtomicU32 = AtomicU32::new(NO_CPU);
const NO_CPU: u32 = u32::MAX;

/// Send the FIFO's contents, a bulk OUT transfer at a time, in thread
/// context (Linux usb_serial_generic_write_start, and the write URB's
/// completion refilling: usb_serial_generic_write_bulk_callback)
fn write_start() {
    use crate::hw::usb::xhci::usb_console_out;

    let mut buf = WRITE_BUF.lock();
    loop {
        let (out, n) = {
            let mut p = PORT.lock();
            let Some(out) = p.out else {
                return;
            };
            (out, p.fifo.pop(&mut buf[..]))
        };
        if n == 0 {
            return;
        }
        // Kernel threads are not preempted: the transfer stays on this CPU
        TX_CPU.store(crate::cpu::this_id(), Ordering::Relaxed);
        // A failed transfer's data is lost, as a failed URB's
        let _ = usb_console_out(out.0, out.1, &buf[..n]);
        TX_CPU.store(NO_CPU, Ordering::Relaxed);
    }
}

/// Queue console output with a CR after each LF (Linux
/// usb_console_write)
fn console_push<const N: usize>(fifo: &mut Kfifo<N>, data: &[u8]) {
    for line in data.split_inclusive(|&b| b == b'\n') {
        fifo.push(line);
        if line.ends_with(b"\n") {
            fifo.push(b"\r");
        }
    }
}

/// The FTDI port as a console (`ttyUSB0`); one at a time
struct UsbSerialConsole;

static USB_SERIAL_CONSOLE: UsbSerialConsole = UsbSerialConsole;

impl ConsoleDriver for UsbSerialConsole {
    fn name(&self) -> &str {
        "ttyUSB0"
    }

    /// Queue `data` in the port's FIFO, dropping what does not fit
    /// (Linux usb_console_write -> usb_serial_generic_write), in any
    /// context; the next tick starts the write work
    fn write(&self, data: &[u8]) {
        if TX_CPU.load(Ordering::Relaxed) == crate::cpu::this_id() && !crate::sync::in_interrupt() {
            return;
        }
        let mut p = PORT.lock();
        if p.out.is_none() {
            return;
        }
        console_push(&mut p.fifo, data);
        drop(p);
        crate::console::console_defer_kick();
    }

    /// Start the write work if output is queued
    fn kick(&self) {
        let queued = !PORT.lock().fifo.is_empty();
        if queued && let Some(w) = WRITE_WORK.get() {
            SYSTEM_WQ.queue_work(w.clone());
        }
    }
}

/// Make the port the console (`ttyUSB0`) if there is none: Normal
/// priority, above legacy serial's Fallback, no special flags
fn register_usb_serial_console(serial: &UsbSerial) {
    use crate::console::ConsoleFlags;

    WRITE_WORK.call_once(|| arc_nofail(IrqSpinlock::new(Work::new(write_start))));
    let mut p = PORT.lock();
    if p.out.is_some() {
        return;
    }
    p.out = Some((serial.slot_id, serial.bulk_out_ep));
    p.fifo.reset();
    drop(p);
    register_console(
        &USB_SERIAL_CONSOLE,
        ConsolePriority::Normal,
        ConsoleFlags::empty(),
    );
}

#[cfg(test)]
mod tests {
    use super::{Kfifo, console_push};

    #[test]
    fn console_cr_after_lf() {
        let mut f = Kfifo::<64>::new();
        console_push(&mut f, b"a\nb\n\nc");
        let mut b = [0u8; 64];
        let n = f.pop(&mut b);
        assert_eq!(&b[..n], b"a\n\rb\n\r\n\rc");
    }
}
