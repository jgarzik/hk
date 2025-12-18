//! PL011 UART driver for AArch64
//!
//! This is a simple polled driver for the ARM PL011 UART found in
//! QEMU's virt machine and many real ARM platforms.

use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};

/// PL011 UART base address on QEMU virt machine
const PL011_BASE: usize = 0x0900_0000;

/// PL011 register offsets
mod regs {
    /// Data Register (read/write)
    pub const DR: usize = 0x000;
    /// Flag Register (read only)
    pub const FR: usize = 0x018;
    /// Integer Baud Rate Register
    pub const IBRD: usize = 0x024;
    /// Fractional Baud Rate Register
    pub const FBRD: usize = 0x028;
    /// Line Control Register
    pub const LCR_H: usize = 0x02C;
    /// Control Register
    pub const CR: usize = 0x030;
    /// Interrupt Mask Set/Clear Register
    pub const IMSC: usize = 0x038;
}

/// Flag Register bits
mod fr {
    /// Transmit FIFO full
    pub const TXFF: u32 = 1 << 5;
    /// UART busy
    pub const BUSY: u32 = 1 << 3;
}

/// Line Control Register bits
mod lcr {
    /// Enable FIFOs
    pub const FEN: u32 = 1 << 4;
    /// Word length 8 bits
    pub const WLEN_8: u32 = 0b11 << 5;
}

/// Control Register bits
mod cr {
    /// UART enable
    pub const UARTEN: u32 = 1 << 0;
    /// Transmit enable
    pub const TXE: u32 = 1 << 8;
    /// Receive enable
    pub const RXE: u32 = 1 << 9;
}

/// PL011 UART driver
pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    /// Create a new PL011 driver instance
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Read a register
    #[inline]
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    /// Write a register
    #[inline]
    fn write_reg(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Initialize the UART
    ///
    /// Note: QEMU's PL011 comes pre-initialized, but we configure it anyway
    /// for completeness and to ensure consistent behavior.
    pub fn init(&self) {
        // Disable UART while configuring
        self.write_reg(regs::CR, 0);

        // Wait for any current transmission to complete
        while self.read_reg(regs::FR) & fr::BUSY != 0 {
            core::hint::spin_loop();
        }

        // Disable all interrupts
        self.write_reg(regs::IMSC, 0);

        // Set baud rate to 115200 (assuming 24MHz clock, QEMU default)
        // Divisor = 24000000 / (16 * 115200) = 13.0208
        // IBRD = 13, FBRD = round(0.0208 * 64) = 1
        self.write_reg(regs::IBRD, 13);
        self.write_reg(regs::FBRD, 1);

        // Set 8N1, enable FIFOs
        self.write_reg(regs::LCR_H, lcr::WLEN_8 | lcr::FEN);

        // Enable UART, TX, and RX
        self.write_reg(regs::CR, cr::UARTEN | cr::TXE | cr::RXE);
    }

    /// Write a single byte, waiting if necessary
    pub fn write_byte(&self, byte: u8) {
        // Wait until TX FIFO has space
        while self.read_reg(regs::FR) & fr::TXFF != 0 {
            core::hint::spin_loop();
        }
        self.write_reg(regs::DR, byte as u32);
    }

    /// Write a string
    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

impl Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Pl011::write_str(self, s);
        Ok(())
    }
}

/// Global UART instance
static mut UART: Pl011 = Pl011::new(PL011_BASE);

/// Initialize the serial console
pub fn init() {
    unsafe {
        (*core::ptr::addr_of_mut!(UART)).init();
    }
}

/// Write a string to the serial console
pub fn write_str(s: &str) {
    unsafe {
        (*core::ptr::addr_of_mut!(UART)).write_str(s);
    }
}

/// Write a single byte to the serial console
pub fn write_byte(byte: u8) {
    unsafe {
        (*core::ptr::addr_of_mut!(UART)).write_byte(byte);
    }
}

/// Boot-time writer for direct serial output
///
/// This implements fmt::Write to allow formatted output during early boot
/// when the printk buffer may not be flushed to console yet.
pub struct BootWriter;

impl fmt::Write for BootWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// Macro for early boot printing before the kernel heap is available
#[macro_export]
macro_rules! early_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!(unsafe { &mut *core::ptr::addr_of_mut!($crate::arch::aarch64::serial::UART) }, $($arg)*);
    }};
}

/// Macro for early boot printing with newline
#[macro_export]
macro_rules! early_println {
    () => {
        $crate::early_print!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::early_print!($($arg)*);
        $crate::early_print!("\n");
    }};
}
