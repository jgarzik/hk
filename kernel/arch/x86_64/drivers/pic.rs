//! 8259 PIC driver (Programmable Interrupt Controller)
//!
//! Platform bus driver for the Intel 8259 PIC.

use alloc::boxed::Box;
use core::any::Any;

use crate::arch::x86_64::io::{inb, io_wait, outb};
use crate::bus::BusContext;
use crate::bus::driver::{Device, DriverError, InterruptController};
use crate::bus::platform::{PlatformBusDriver, PlatformDevice};
use crate::impl_platform_bus_driver;

/// PIC I/O ports
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// PIC initialization constants
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;
const PIC_EOI: u8 = 0x20;

/// Remapped IRQ offsets
const PIC1_OFFSET: u8 = 32; // IRQ 0-7 -> vectors 32-39
const PIC2_OFFSET: u8 = 40; // IRQ 8-15 -> vectors 40-47

/// 8259 PIC platform bus driver
pub struct Pic8259PlatformDriver;

impl PlatformBusDriver for Pic8259PlatformDriver {
    fn name(&self) -> &str {
        "pic8259-driver"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["intel,8259"]
    }

    fn probe_platform(
        &self,
        _device: &PlatformDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        let pic = Pic8259::new();
        pic.remap();
        Ok(Box::new(pic))
    }
}

impl_platform_bus_driver!(Pic8259PlatformDriver);

/// 8259 PIC device instance
pub struct Pic8259 {
    /// Cached interrupt mask (0 = enabled, 1 = disabled)
    #[allow(dead_code)]
    mask: u16,
}

impl Pic8259 {
    /// Create a new PIC instance
    pub fn new() -> Self {
        Self { mask: 0xFFFF } // All interrupts masked initially
    }

    /// Remap the PIC to avoid conflicts with CPU exceptions
    pub fn remap(&self) {
        // Save masks
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        // Start initialization sequence
        outb(PIC1_COMMAND, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(PIC2_COMMAND, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // Set vector offsets
        outb(PIC1_DATA, PIC1_OFFSET);
        io_wait();
        outb(PIC2_DATA, PIC2_OFFSET);
        io_wait();

        // Tell PICs about each other
        outb(PIC1_DATA, 4); // Slave on IRQ2
        io_wait();
        outb(PIC2_DATA, 2); // Cascade identity
        io_wait();

        // Set 8086 mode
        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Restore saved masks
        outb(PIC1_DATA, mask1);
        outb(PIC2_DATA, mask2);
    }
}

impl Default for Pic8259 {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for Pic8259 {
    fn name(&self) -> &str {
        "pic8259"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl InterruptController for Pic8259 {
    fn enable_irq(&self, irq: u8) {
        if irq < 8 {
            let mask = inb(PIC1_DATA);
            outb(PIC1_DATA, mask & !(1 << irq));
        } else if irq < 16 {
            let mask = inb(PIC2_DATA);
            outb(PIC2_DATA, mask & !(1 << (irq - 8)));
            // Also ensure cascade IRQ (2) is enabled
            let mask1 = inb(PIC1_DATA);
            outb(PIC1_DATA, mask1 & !(1 << 2));
        }
    }

    fn disable_irq(&self, irq: u8) {
        if irq < 8 {
            let mask = inb(PIC1_DATA);
            outb(PIC1_DATA, mask | (1 << irq));
        } else if irq < 16 {
            let mask = inb(PIC2_DATA);
            outb(PIC2_DATA, mask | (1 << (irq - 8)));
        }
    }

    fn send_eoi(&self, irq: u8) {
        if irq >= 8 {
            outb(PIC2_COMMAND, PIC_EOI);
        }
        outb(PIC1_COMMAND, PIC_EOI);
    }
}
