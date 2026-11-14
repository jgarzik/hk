//! FTDI USB serial converter (Linux drivers/usb/serial/ftdi_sio.c):
//! QEMU's usb-serial is an FT232 (0403:6001). `USB_SERIAL_DRIVER`
//! binds its interface on the USB bus as "ftdi_sio".
//!
//! ## Console Integration
//!
//! The port is registered as a console with Normal priority, ahead of
//! the legacy serial port (Fallback priority). As Linux's usb-serial
//! console, a write only queues the output in the port's FIFO (any
//! context, dropping what does not fit); the port's write URB sends it
//! out the bulk OUT endpoint raw (the FT232 frames only its IN data),
//! one chunk at a time, its completion handler submitting the next
//! (Linux usb_serial_generic_write_start and write_bulk_callback).

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::console::{ConsoleDriver, ConsolePriority, register_console};
use crate::printkln;
use crate::sync::{IrqSpinlock, Mutex};
use crate::task::workqueue::{SYSTEM_WQ, Work};
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_box};
use crate::util::kfifo::Kfifo;

use super::{Pipe, Urb, UsbDevice, UsbDeviceId, UsbIds, usb_poison_urb, usb_submit_urb};

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
    // The write URB and its buffer (Linux usb_serial_probe's
    // write_urbs[0], bulk_out_size bytes)
    let complete = try_box(write_bulk_callback)?;
    let urb = Urb::new(
        usb_dev,
        Pipe::bulk_out(bulk_out_ep),
        None,
        BULK_OUT_SIZE,
        complete,
    )
    .ok_or(KernelError::OutOfMemory)?;
    printkln!(
        "ftdi_sio {}: FTDI USB Serial Device converter, bulk in {:#04x}, out {:#04x}",
        dev.name(),
        bulk_in_ep,
        bulk_out_ep
    );
    register_usb_serial_console(&serial, usb_dev, urb);
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
    /// and its queued output, and its write URB is killed (Linux
    /// usb_serial_disconnect: usb_serial_port_poison_urbs)
    fn remove(&self) {
        if PORT.lock().out != Some((self.slot_id, self.bulk_out_ep)) {
            return;
        }
        crate::console::unregister_console(USB_SERIAL_CONSOLE.name());
        let urb = {
            let mut p = PORT.lock();
            p.out = None;
            p.fifo.reset();
            p.urb.take()
        };
        if let Some(urb) = urb {
            usb_poison_urb(&urb);
        }
        *PORT_DEV.lock() = None;
    }
}

/// The port's write FIFO (Linux usb-serial's write_fifo, PAGE_SIZE)
const WRITE_FIFO_SIZE: usize = 4096;
/// Bytes per bulk OUT transfer (Linux ftdi_sio's bulk_out_size)
const BULK_OUT_SIZE: usize = 256;

/// The console's port (Linux usb_serial_port: `lock`, `write_fifo`,
/// `write_urbs[0]`, USB_SERIAL_WRITE_BUSY)
struct Port {
    /// The bound port's slot and bulk OUT endpoint (None: no console)
    out: Option<(u8, u8)>,
    /// Output queued for the write URB
    fifo: Kfifo<WRITE_FIFO_SIZE>,
    /// The write URB (None: no console)
    urb: Option<Arc<Urb>>,
    /// The write URB is submitted (Linux USB_SERIAL_WRITE_BUSY)
    busy: bool,
}

/// The USB serial console's port (Linux port->lock, IRQ-safe leaf: the
/// console write runs in any context, under printk's `OUTPUT_LOCK`)
static PORT: IrqSpinlock<Port> = IrqSpinlock::new(Port {
    out: None,
    fifo: Kfifo::new(),
    urb: None,
    busy: false,
});

/// The console port's device and bulk IN endpoint (Linux
/// port->serial->dev, port->bulk_in_endpointAddress), for the boot
/// self-test
static PORT_DEV: Mutex<Option<(UsbDevice, u8)>> = Mutex::new(None);

/// The write work: the tick's kick starts the write URB from a thread
/// (Linux submits it from the console write itself, GFP_ATOMIC; an hk
/// submission builds its TRBs on the heap, which an interrupt handler
/// does not)
static WRITE_WORK: spin::Once<Arc<IrqSpinlock<Work>>> = spin::Once::new();

/// A failed write transfer was reported: a console port's errors are
/// printed once, or each report would queue the next (Linux
/// dev_err_console)
static ERR_ONCE: AtomicBool = AtomicBool::new(false);

/// Report a failed write once
fn write_error(e: super::UsbError) {
    if !ERR_ONCE.swap(true, Ordering::Relaxed) {
        printkln!(
            "ftdi_sio: write_bulk_callback - nonzero urb status: {:?}",
            e
        );
    }
}

/// Submit the write URB with the FIFO's next chunk, unless it is
/// submitted already or there is nothing to send (Linux
/// usb_serial_generic_write_start); thread context (the write work,
/// the giveback bottom half)
fn write_start() {
    let mut chunk = [0u8; BULK_OUT_SIZE];
    let (urb, n) = {
        let mut p = PORT.lock();
        if p.busy || p.out.is_none() {
            return;
        }
        let Some(urb) = p.urb.clone() else {
            return;
        };
        let n = p.fifo.pop(&mut chunk);
        if n == 0 {
            return;
        }
        p.busy = true;
        (urb, n)
    };
    // A failed submission's data is lost, as a failed URB's
    let r = urb
        .fill(Some(&chunk[..n]), n)
        .and_then(|_| usb_submit_urb(&urb));
    if let Err(e) = r {
        PORT.lock().busy = false;
        // Rejected: poisoned by remove
        if e != super::UsbError::Rejected {
            write_error(e);
        }
    }
}

/// The write URB was given back (Linux
/// usb_serial_generic_write_bulk_callback): the port is free again and
/// the next chunk goes out; a killed URB (remove) sends nothing more.
/// Giveback bottom half: does not sleep
fn write_bulk_callback(urb: &Arc<Urb>) {
    PORT.lock().busy = false;
    match urb.status() {
        Err(super::UsbError::Killed | super::UsbError::Shutdown) => {
            return;
        }
        Err(e) => write_error(e),
        Ok(()) => {}
    }
    // The bottom half does not sleep: GFP_ATOMIC, as Linux's callback
    crate::util::kalloc::with_gfp(crate::mm::page_alloc::Gfp::ATOMIC, write_start);
}

/// The console port's device and bulk IN pipe, for the boot self-test
/// (`urb::urb_selftest`); thread context
pub fn console_in_pipe() -> Option<(UsbDevice, Pipe)> {
    let p = PORT_DEV.lock();
    let (dev, ep) = p.as_ref()?;
    Some((dev.clone(), Pipe::bulk_in(*ep)))
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
        let mut p = PORT.lock();
        if p.out.is_none() {
            return;
        }
        console_push(&mut p.fifo, data);
        drop(p);
        crate::console::console_defer_kick();
    }

    /// Start the write work if output is queued and the write URB idle
    fn kick(&self) {
        let start = {
            let p = PORT.lock();
            !p.fifo.is_empty() && !p.busy
        };
        if start && let Some(w) = WRITE_WORK.get() {
            SYSTEM_WQ.queue_work(w.clone());
        }
    }
}

/// Make the port the console (`ttyUSB0`) if there is none: Normal
/// priority, above legacy serial's Fallback, no special flags
fn register_usb_serial_console(serial: &UsbSerial, dev: &UsbDevice, urb: Arc<Urb>) {
    use crate::console::ConsoleFlags;

    WRITE_WORK.call_once(|| arc_nofail(IrqSpinlock::new(Work::new(write_start))));
    let mut p = PORT.lock();
    if p.out.is_some() {
        // Not the console: its URB is freed here, with the lock dropped
        drop(p);
        drop(urb);
        return;
    }
    p.out = Some((serial.slot_id, serial.bulk_out_ep));
    p.fifo.reset();
    p.urb = Some(urb);
    p.busy = false;
    drop(p);
    *PORT_DEV.lock() = Some((dev.clone(), serial.bulk_in_ep));
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
