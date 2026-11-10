//! Device IRQ lines of the GICv3: shared peripheral interrupts
//! (`crate::irq` keeps the handler table)
//!
//! ARM GIC interrupt number ranges:
//! - SGI (Software Generated Interrupts): 0-15 (used for IPIs)
//! - PPI (Private Peripheral Interrupts): 16-31 (per-CPU, e.g., timer)
//! - SPI (Shared Peripheral Interrupts): 32-1019 (shared across CPUs)
//!
//! Device IRQs are SPIs 32-287. Unmasking configures the SPI first
//! (level-triggered, routed to CPU 0).

use super::{Aarch64Arch, gic};
use crate::arch::IrqChipOps;

impl IrqChipOps for Aarch64Arch {
    const FIRST_IRQ: u32 = 32;
    const NR_IRQS: usize = 256;

    fn irq_unmask(irq: u32) {
        gic::enable_spi(irq);
    }

    fn irq_mask(irq: u32) {
        gic::disable_spi(irq);
    }

    /// The host bridge's DT `interrupt-map`, else the QEMU virt swizzle
    fn pci_intx_irq(bus: u8, device: u8, function: u8, pin: u8, _line: u8) -> Option<u32> {
        super::pci_irq::intx_to_intid(bus, device, function, pin)
    }

    /// MSI needs the GICv3 ITS (or a GICv2m frame), which hk does not
    /// drive: PCI functions stay on INTx
    fn msi_alloc(_cpu: u32) -> Option<(u32, crate::irq::MsiMsg)> {
        None
    }

    fn msi_free(_irq: u32) {}
}
