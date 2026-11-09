//! Device IRQ lines of the legacy 8259 PIC (`crate::irq` keeps the
//! handler table)
//!
//! IRQs 0-15 are the PIC lines. PCI INTx: with QEMU `pc` and legacy BIOS
//! routing the firmware writes the PIC line into the config-space
//! Interrupt Line register, which is what `pci_intx_irq` returns. Real
//! hardware with APIC-mode routing (e.g. the Dell OptiPlex 3020 target)
//! needs IOAPIC + ACPI `_PRT` support instead (not implemented).

use super::{X86_64Arch, pic};
use crate::arch::IrqChipOps;

impl IrqChipOps for X86_64Arch {
    const FIRST_IRQ: u32 = 0;
    const NR_IRQS: usize = 16;

    // The table passes lines below NR_IRQS only: `as u8` keeps them
    fn irq_unmask(irq: u32) {
        pic::enable_irq(irq as u8);
    }

    fn irq_mask(irq: u32) {
        pic::disable_irq(irq as u8);
    }

    /// The firmware-assigned PIC line from config space, if the device
    /// uses a pin and the line is valid
    fn pci_intx_irq(_bus: u8, _device: u8, _function: u8, pin: u8, line: u8) -> Option<u32> {
        if pin == 0 || usize::from(line) >= Self::NR_IRQS {
            return None;
        }
        Some(u32::from(line))
    }
}
