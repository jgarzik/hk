//! Serial TTY Driver
//!
//! NS16550A-compatible UART driver implementing TtyDriver.
//!
//! This provides the hardware interface for serial ports like /dev/ttyS0.
#![allow(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use crate::console::{ConsolePriority, register_console};
use crate::util::error::KernelError;

use crate::fs::chardev::{DevId, major};
use crate::tty::{Tty, TtyDriver};

/// NS16550A register offsets
mod regs {
    /// Transmit Holding Register (write) / Receive Buffer Register (read)
    pub const THR: u16 = 0;
    pub const RBR: u16 = 0;
    /// Interrupt Enable Register
    pub const IER: u16 = 1;
    /// Divisor Latch Low (when DLAB=1)
    pub const DLL: u16 = 0;
    /// Divisor Latch High (when DLAB=1)
    pub const DLH: u16 = 1;
    /// FIFO Control Register
    pub const FCR: u16 = 2;
    /// Interrupt Identification Register (read)
    pub const IIR: u16 = 2;
    /// Line Control Register
    pub const LCR: u16 = 3;
    /// Modem Control Register
    pub const MCR: u16 = 4;
    /// Line Status Register
    pub const LSR: u16 = 5;
}

/// Line Status Register bits
mod lsr {
    /// Data Ready
    pub const DR: u8 = 0x01;
    /// Transmitter Holding Register Empty
    pub const THRE: u8 = 0x20;
    /// Transmitter Empty (both THR and shift register empty)
    pub const TEMT: u8 = 0x40;
}

/// Interrupt Enable Register bits
mod ier {
    /// Received Data available Interrupt
    pub const RDI: u8 = 0x01;
}

/// Interrupt Identification Register bits
mod iir {
    /// No interrupt pending
    pub const NO_INT: u8 = 0x01;
}

/// Line Control Register bits
mod lcr {
    /// Divisor Latch Access Bit
    pub const DLAB: u8 = 0x80;
    /// 8 data bits, no parity, 1 stop bit
    pub const MODE_8N1: u8 = 0x03;
}

/// Modem Control Register bits
mod mcr {
    /// Data Terminal Ready
    pub const DTR: u8 = 0x01;
    /// Request To Send
    pub const RTS: u8 = 0x02;
    /// Auxiliary Output 2 (enables interrupts on PC)
    pub const OUT2: u8 = 0x08;
}

/// FIFO Control Register bits
mod fcr {
    /// Enable FIFO
    pub const ENABLE: u8 = 0x01;
    /// Clear receive FIFO
    pub const CLEAR_RX: u8 = 0x02;
    /// Clear transmit FIFO
    pub const CLEAR_TX: u8 = 0x04;
    /// 14-byte trigger level
    pub const TRIGGER_14: u8 = 0xC0;
}

/// Serial port (NS16550A UART) driver
///
/// Output is polled (console-safe); COM1 input comes by interrupt
/// (`rx_irq_init`).
pub struct SerialTty {
    /// I/O port base address
    port: u16,
}

impl SerialTty {
    /// Create a new serial TTY
    ///
    /// `port`: I/O port base address (e.g., 0x3F8 for COM1)
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    /// Initialize the UART hardware
    ///
    /// # Arguments
    /// * `baud_rate` - Desired baud rate (e.g., 115200)
    pub fn init_hardware(&self, baud_rate: u32) {
        // Calculate divisor: 115200 base clock / baud_rate
        let divisor = 115200 / baud_rate;

        unsafe {
            // Disable interrupts
            self.outb(regs::IER, 0x00);

            // Enable DLAB to set divisor
            self.outb(regs::LCR, lcr::DLAB);

            // Set divisor
            self.outb(regs::DLL, (divisor & 0xFF) as u8);
            self.outb(regs::DLH, ((divisor >> 8) & 0xFF) as u8);

            // Set 8N1, disable DLAB
            self.outb(regs::LCR, lcr::MODE_8N1);

            // Enable and clear FIFOs, 14-byte trigger
            self.outb(
                regs::FCR,
                fcr::ENABLE | fcr::CLEAR_RX | fcr::CLEAR_TX | fcr::TRIGGER_14,
            );

            // Enable DTR, RTS, and OUT2 (for interrupts)
            self.outb(regs::MCR, mcr::DTR | mcr::RTS | mcr::OUT2);
        }
    }

    /// Write a byte (polled, waits for TX ready)
    fn write_byte(&self, byte: u8) {
        unsafe {
            // Wait for transmit buffer empty
            while self.inb(regs::LSR) & lsr::THRE == 0 {
                core::hint::spin_loop();
            }
            // Send byte
            self.outb(regs::THR, byte);
        }
    }

    /// Read a byte if available
    fn read_byte(&self) -> Option<u8> {
        unsafe {
            if self.inb(regs::LSR) & lsr::DR != 0 {
                Some(self.inb(regs::RBR))
            } else {
                None
            }
        }
    }

    /// Drain the receive FIFO into `tty`'s flip buffer (IRQ context;
    /// Linux serial8250_rx_chars). True if the UART had an interrupt
    /// pending
    fn rx_chars(&self, tty: &Tty) -> bool {
        // SAFETY: IIR is a register of this UART
        if unsafe { self.inb(regs::IIR) } & iir::NO_INT != 0 {
            return false;
        }
        let mut buf = [0u8; 64];
        loop {
            let mut n = 0;
            while n < buf.len()
                && let Some(b) = self.read_byte()
            {
                buf[n] = b;
                n += 1;
            }
            crate::tty::flip::receive(tty, &buf[..n]);
            if n < buf.len() {
                return true;
            }
        }
    }

    /// Enable the receive interrupt (IER.RDI; MCR.OUT2 is set already)
    fn enable_rx_irq(&self) {
        // SAFETY: IER is a register of this UART
        unsafe { self.outb(regs::IER, ier::RDI) };
    }

    /// Wait for transmitter to be completely empty (all bytes sent)
    fn flush(&self) {
        unsafe {
            // Wait for TEMT (Transmitter Empty) - both THR and shift register empty
            while self.inb(regs::LSR) & lsr::TEMT == 0 {
                core::hint::spin_loop();
            }
        }
    }

    /// Write byte to I/O port
    ///
    /// # Safety
    /// `offset` is a register of this UART's port range.
    #[inline]
    unsafe fn outb(&self, offset: u16, value: u8) {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.port + offset,
                in("al") value,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Read byte from I/O port
    ///
    /// # Safety
    /// As [`Self::outb`].
    #[inline]
    unsafe fn inb(&self, offset: u16) -> u8 {
        let value: u8;
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") self.port + offset,
                out("al") value,
                options(nostack, preserves_flags)
            );
        }
        value
    }
}

impl TtyDriver for SerialTty {
    fn write(&self, data: &[u8]) -> Result<usize, KernelError> {
        for &byte in data {
            self.write_byte(byte);
        }
        Ok(data.len())
    }

    fn flush(&self) {
        SerialTty::flush(self);
    }
}

/// Standard COM port addresses
pub mod ports {
    /// COM1 - Primary serial port
    pub const COM1: u16 = 0x3F8;
    /// COM2 - Secondary serial port
    pub const COM2: u16 = 0x2F8;
    /// COM3 - Tertiary serial port
    pub const COM3: u16 = 0x3E8;
    /// COM4 - Quaternary serial port
    pub const COM4: u16 = 0x2E8;
}

/// Static serial hardware driver instances for standard COM ports
static SERIAL_DRIVER_S0: SerialTty = SerialTty::new(ports::COM1);
static SERIAL_DRIVER_S1: SerialTty = SerialTty::new(ports::COM2);

/// Static TTY instances wrapping the serial drivers
///
/// These provide the proper layer separation: Console → TTY → Driver
pub static SERIAL_TTY_S0: Tty = Tty::new("ttyS0", ttys_dev(0), &SERIAL_DRIVER_S0);
pub static SERIAL_TTY_S1: Tty = Tty::new("ttyS1", ttys_dev(1), &SERIAL_DRIVER_S1);

/// ttyS<n> is (4, 64 + n) (Linux devices.txt)
const fn ttys_dev(n: u16) -> DevId {
    DevId::new(major::TTYS, 64 + n)
}

/// Initialize the primary serial console
///
/// This initializes COM1 hardware and registers the TTY as a console
/// with Fallback priority. USB serial (if present) will have Normal
/// priority and take precedence.
///
/// Marked as BOOT console - this is the early serial output during boot.
/// When a real console (graphics, USB serial) registers with CONSDEV,
/// boot consoles are typically demoted or unregistered.
pub fn init_serial_console() {
    use crate::console::ConsoleFlags;

    // Initialize hardware
    SERIAL_DRIVER_S0.init_hardware(115200);

    // Register the TTY (not raw driver) as console with Fallback priority
    // BOOT flag indicates this is an early boot console
    register_console(
        &SERIAL_TTY_S0,
        ConsolePriority::Fallback,
        ConsoleFlags::BOOT,
    );
}

/// Write a byte directly to COM1 for panic output
///
/// This bypasses all locking and goes directly to hardware.
/// Only use during panic when normal printk path may deadlock.
#[cfg(target_arch = "x86_64")]
pub fn write_byte_com1(byte: u8) {
    SERIAL_DRIVER_S0.write_byte(byte);
}

/// COM1's interrupt handler (IRQ context): input to ttyS0
fn com1_irq(_irq: u32, _data: *mut ()) -> bool {
    SERIAL_DRIVER_S0.rx_chars(&SERIAL_TTY_S0)
}

/// Take COM1's input by interrupt (Linux serial8250_startup); `irq` is
/// its PIC line
pub fn rx_irq_init(irq: u32) {
    let id = usize::from(ports::COM1);
    if let Err(e) = crate::arch::irq::register_irq_handler(irq, com1_irq, core::ptr::null_mut(), id)
    {
        crate::printkln!("ttyS0: no IRQ {}: {}", irq, e);
        return;
    }
    SERIAL_DRIVER_S0.enable_rx_irq();
}

/// The serial ports' ttys (Linux serial8250 ports)
pub fn serial_ttys() -> &'static [&'static Tty] {
    static TTYS: [&Tty; 2] = [&SERIAL_TTY_S0, &SERIAL_TTY_S1];
    &TTYS
}

/// The 8250 platform driver (Linux serial8250_isa_driver): its ports'
/// ttys go below the device; COM1's input by interrupt
pub static SERIAL8250_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "serial8250",
    &crate::base::platform::PLATFORM_BUS,
    None,
    &crate::base::platform::Names(&["serial8250"]),
    serial8250_probe,
);

/// A bound 8250 device: its ports' tty devices
struct Serial8250 {
    _ttys: alloc::vec::Vec<alloc::sync::Arc<crate::base::Device>>,
}

impl crate::base::Bound for Serial8250 {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

fn serial8250_probe(
    dev: &alloc::sync::Arc<crate::base::Device>,
) -> Result<alloc::boxed::Box<dyn crate::base::Bound>, crate::util::error::KernelError> {
    if let Some(irq) = crate::base::platform::pdev(dev).and_then(|p| p.irq) {
        rx_irq_init(irq);
    }
    let ttys = serial_ttys()
        .iter()
        .filter_map(|t| crate::tty::tty_register_device(t, dev))
        .collect();
    Ok(alloc::boxed::Box::new(Serial8250 { _ttys: ttys }))
}
