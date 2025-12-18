//! Serial TTY Driver
//!
//! NS16550A-compatible UART driver implementing TtyDriver.
//!
//! This provides the hardware interface for serial ports like /dev/ttyS0.

use crate::chardev::DeviceError;
use crate::console::{ConsolePriority, register_console};

use super::{RAW_LDISC, Tty, TtyDriver};

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
/// This is a polled driver suitable for console use.
/// For interrupt-driven operation, see the platform serial driver.
pub struct SerialTty {
    /// I/O port base address
    port: u16,
    /// Device name
    name: &'static str,
}

impl SerialTty {
    /// Create a new serial TTY
    ///
    /// # Arguments
    /// * `port` - I/O port base address (e.g., 0x3F8 for COM1)
    /// * `name` - Device name (e.g., "ttyS0")
    pub const fn new(port: u16, name: &'static str) -> Self {
        Self { port, name }
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

    /// Check if data is available
    fn data_available(&self) -> bool {
        unsafe { self.inb(regs::LSR) & lsr::DR != 0 }
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
    #[inline]
    unsafe fn outb(&self, offset: u16, value: u8) {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.port + offset,
                in("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    /// Read byte from I/O port
    #[inline]
    unsafe fn inb(&self, offset: u16) -> u8 {
        let value: u8;
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") self.port + offset,
                out("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }
}

impl TtyDriver for SerialTty {
    fn name(&self) -> &str {
        self.name
    }

    fn write(&self, data: &[u8]) -> Result<usize, DeviceError> {
        for &byte in data {
            self.write_byte(byte);
        }
        Ok(data.len())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, DeviceError> {
        let mut count = 0;
        while count < buf.len() {
            if let Some(byte) = self.read_byte() {
                buf[count] = byte;
                count += 1;
            } else {
                break;
            }
        }
        Ok(count)
    }

    fn poll_read(&self) -> bool {
        self.data_available()
    }

    fn init(&self) -> Result<(), DeviceError> {
        self.init_hardware(115200);
        Ok(())
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
static SERIAL_DRIVER_S0: SerialTty = SerialTty::new(ports::COM1, "ttyS0");
static SERIAL_DRIVER_S1: SerialTty = SerialTty::new(ports::COM2, "ttyS1");

/// Static TTY instances wrapping the serial drivers
///
/// These provide the proper layer separation: Console → TTY → Driver
pub static SERIAL_TTY_S0: Tty = Tty::new("ttyS0", &SERIAL_DRIVER_S0, &RAW_LDISC);
pub static SERIAL_TTY_S1: Tty = Tty::new("ttyS1", &SERIAL_DRIVER_S1, &RAW_LDISC);

/// Initialize the primary serial console
///
/// This initializes COM1 hardware and registers the TTY as a console
/// with Fallback priority. USB serial (if present) will have Normal
/// priority and take precedence.
pub fn init_serial_console() {
    // Initialize hardware
    SERIAL_DRIVER_S0.init_hardware(115200);

    // Register the TTY (not raw driver) as console with Fallback priority
    register_console(&SERIAL_TTY_S0, ConsolePriority::Fallback);
}

/// Write a byte directly to COM1 for panic output
///
/// This bypasses all locking and goes directly to hardware.
/// Only use during panic when normal printk path may deadlock.
#[cfg(target_arch = "x86_64")]
pub fn write_byte_com1(byte: u8) {
    SERIAL_DRIVER_S0.write_byte(byte);
}

use crate::chardev::{CharDevice, DevId, major, register_chardev};
use alloc::sync::Arc;

/// Wrapper to allow static TTY to be registered as Arc<dyn CharDevice>
struct StaticTtyWrapper(&'static Tty);

impl CharDevice for StaticTtyWrapper {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, DeviceError> {
        self.0.read(buf)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, DeviceError> {
        self.0.write(buf)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, DeviceError> {
        self.0.ioctl(cmd, arg)
    }

    fn poll_read(&self) -> bool {
        self.0.poll_read()
    }

    fn poll_write(&self) -> bool {
        self.0.poll_write()
    }
}

/// Register serial TTYs in the chardev registry
///
/// This must be called after the heap allocator is available.
/// Creates entries for /dev/ttyS0, /dev/ttyS1 with major=4.
pub fn register_serial_chardevs() {
    // ttyS0 = major 4, minor 64 (Linux convention)
    let tty_s0 = Arc::new(StaticTtyWrapper(&SERIAL_TTY_S0));
    let _ = register_chardev(DevId::new(major::TTYS, 64), tty_s0);

    // ttyS1 = major 4, minor 65
    let tty_s1 = Arc::new(StaticTtyWrapper(&SERIAL_TTY_S1));
    let _ = register_chardev(DevId::new(major::TTYS, 65), tty_s1);
}
