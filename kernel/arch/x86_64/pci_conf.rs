//! PCI configuration access through I/O ports CF8/CFC (PCI Local Bus
//! configuration mechanism #1; Linux arch/x86/pci/direct.c)
//!
//! Locking: `PCI_LOCK` (Linux pci_lock), an `IrqSpinlock` leaf around
//! each address/data pair.

use crate::bus::pci::PciConfigAccess;

/// PCI configuration address port
const PCI_CONFIG_ADDR: u16 = 0x0CF8;
/// PCI configuration data port
const PCI_CONFIG_DATA: u16 = 0x0CFC;

/// The port I/O accessor (installed by `bus::pci::init_port_io`)
pub static PORT_IO: PortIoConfigAccess = PortIoConfigAccess;

/// Port I/O based PCI config access (x86 legacy)
///
/// Uses CF8/CFC port I/O mechanism for PCI configuration space access.
pub struct PortIoConfigAccess;

impl PortIoConfigAccess {
    /// Encode BDF + offset into config address
    #[inline]
    fn encode_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        0x8000_0000
            | ((bus as u32) << 16)
            | ((dev as u32) << 11)
            | ((func as u32) << 8)
            | ((offset as u32) & 0xFC)
    }
}

/// Serializes the CF8 address / CFC data pair (Linux pci_lock): another
/// CPU's access between the two would redirect this one
static PCI_LOCK: crate::arch::IrqSpinlock<()> = crate::arch::IrqSpinlock::new(());

impl PortIoConfigAccess {
    /// Select the register; the data port then reads/writes it, at
    /// CFC + the offset's low bits for a byte or word
    fn select(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
        crate::arch::outl(PCI_CONFIG_ADDR, Self::encode_addr(bus, dev, func, offset));
        PCI_CONFIG_DATA + (offset & 3) as u16
    }
}

impl PciConfigAccess for PortIoConfigAccess {
    fn read32(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        let _g = PCI_LOCK.lock();
        crate::arch::inl(Self::select(bus, dev, func, offset & 0xFC))
    }

    fn write32(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
        let _g = PCI_LOCK.lock();
        crate::arch::outl(Self::select(bus, dev, func, offset & 0xFC), val);
    }

    fn read16(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
        let _g = PCI_LOCK.lock();
        crate::arch::inw(Self::select(bus, dev, func, offset & 0xFE))
    }

    fn read8(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
        let _g = PCI_LOCK.lock();
        crate::arch::inb(Self::select(bus, dev, func, offset))
    }

    fn write16(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
        let _g = PCI_LOCK.lock();
        crate::arch::outw(Self::select(bus, dev, func, offset & 0xFE), val);
    }

    fn write8(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u8) {
        let _g = PCI_LOCK.lock();
        crate::arch::outb(Self::select(bus, dev, func, offset), val);
    }
}
