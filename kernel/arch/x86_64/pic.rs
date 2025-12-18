//! 8259 Programmable Interrupt Controller (PIC) driver
//!
//! The 8259 PIC is used in legacy PC systems to handle hardware interrupts.
//! There are two PICs in a PC: master (IRQ 0-7) and slave (IRQ 8-15).
//!
//! By default, the PIC maps IRQs to vectors 8-15 and 0x70-0x77, which
//! conflicts with CPU exceptions. We remap them to vectors 32-47.

use super::io::{inb, io_wait, outb};

/// Master PIC I/O ports
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;

/// Slave PIC I/O ports
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// PIC commands
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;
const PIC_EOI: u8 = 0x20;

/// Interrupt vector offset for master PIC (IRQ 0 = vector 32)
const PIC1_OFFSET: u8 = 32;

/// Interrupt vector offset for slave PIC (IRQ 8 = vector 40)
const PIC2_OFFSET: u8 = 40;

/// Initialize and remap the PICs
///
/// Remaps master PIC to vectors 32-39, slave to 40-47.
/// Masks all interrupts initially.
pub fn init() {
    // Save current masks
    let mask1 = inb(PIC1_DATA);
    let mask2 = inb(PIC2_DATA);

    // ICW1: Initialize + expect ICW4
    outb(PIC1_COMMAND, ICW1_INIT | ICW1_ICW4);
    io_wait();
    outb(PIC2_COMMAND, ICW1_INIT | ICW1_ICW4);
    io_wait();

    // ICW2: Interrupt vector offsets
    outb(PIC1_DATA, PIC1_OFFSET);
    io_wait();
    outb(PIC2_DATA, PIC2_OFFSET);
    io_wait();

    // ICW3: Master/slave wiring
    // Master: slave PIC at IRQ2 (bit 2)
    outb(PIC1_DATA, 0x04);
    io_wait();
    // Slave: cascade identity (IRQ2)
    outb(PIC2_DATA, 0x02);
    io_wait();

    // ICW4: 8086 mode
    outb(PIC1_DATA, ICW4_8086);
    io_wait();
    outb(PIC2_DATA, ICW4_8086);
    io_wait();

    // Mask all interrupts initially
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);

    // Restore masks (or keep all masked)
    let _ = mask1;
    let _ = mask2;
}

/// Enable a specific IRQ
pub fn enable_irq(irq: u8) {
    if irq < 8 {
        // Master PIC
        let mask = inb(PIC1_DATA);
        outb(PIC1_DATA, mask & !(1 << irq));
    } else {
        // Slave PIC - also enable cascade (IRQ2) on master
        let irq = irq - 8;
        let mask = inb(PIC2_DATA);
        outb(PIC2_DATA, mask & !(1 << irq));

        // Enable cascade on master
        let mask = inb(PIC1_DATA);
        outb(PIC1_DATA, mask & !(1 << 2));
    }
}

/// Send End of Interrupt (EOI) signal
pub fn send_eoi(irq: u8) {
    if irq >= 8 {
        // Slave PIC needs EOI too
        outb(PIC2_COMMAND, PIC_EOI);
    }
    outb(PIC1_COMMAND, PIC_EOI);
}
