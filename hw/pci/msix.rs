//! MSI-X (PCI Local Bus 3.0 section 6.8.2; Linux drivers/pci/msi/msi.c
//! msix_capability_init, pci_alloc_irq_vectors_affinity, pci_free_irq_vectors)
//!
//! [`MsixVectors::enable`] allocates one interrupt per vector, each
//! aimed at a CPU the driver picks (Linux managed affinity), writes the
//! table entries masked, turns MSI-X on and INTx off. A driver
//! registers its handler on a vector's IRQ, then unmasks the entry
//! ([`MsixVectors::request`], Linux request_irq's irq_startup through
//! the MSI irq_chip); dropping the registration masks it first. Each
//! registration holds the vectors, so their last drop comes after every
//! handler is gone: it masks every entry, turns MSI-X off and INTx back
//! on, and frees the interrupts (Linux pci_msix_shutdown,
//! pci_free_irq_vectors).
//!
//! ## Locking
//!
//! None of its own: enable and drop run in the driver's probe and
//! remove (thread context, the device lock); a vector's mask bit is
//! written by its own `request` and the drop of its registration.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{PciDevice, cap_id, command};
use crate::hw::mmio::IoMem;
use crate::irq::{IrqHandler, IrqRegistration, MsiIrq, msi_alloc, request_irq};
use crate::util::error::KernelError;
use crate::util::kmem::KVec;

/// Capability registers (offsets from the capability)
const CTRL: u8 = 2;
const TABLE: u8 = 4;
/// Message Control bits
const CTRL_ENABLE: u16 = 1 << 15;
const CTRL_MASKALL: u16 = 1 << 14;
const CTRL_QSIZE: u16 = 0x7ff;
/// Table entry: address low/high, data, vector control (masked bit)
const ENTRY: usize = 16;
const E_ADDR_LO: usize = 0;
const E_ADDR_HI: usize = 4;
const E_DATA: usize = 8;
const E_CTRL: usize = 12;
const E_MASKED: u32 = 1;
/// PCI command register offset
const PCI_COMMAND: u8 = 0x04;

/// A function's MSI-X vectors, enabled (Linux msix_enabled with its
/// msi_desc list)
pub struct MsixVectors {
    pci: PciDevice,
    cap: u8,
    table: IoMem,
    /// One interrupt per vector, in table order
    irqs: Vec<MsiIrq>,
}

/// A handler on one MSI-X vector: dropping it masks the entry, then
/// frees the handler (Linux free_irq: irq_shutdown masks the message),
/// then lets go of the vectors
#[must_use]
pub struct MsixHandler<T: IrqHandler + 'static> {
    vecs: Arc<MsixVectors>,
    entry: usize,
    reg: Option<IrqRegistration<T>>,
}

impl<T: IrqHandler + 'static> Drop for MsixHandler<T> {
    fn drop(&mut self) {
        mask(&self.vecs.table, self.entry);
        drop(self.reg.take());
    }
}

/// Mask entry `i`; the read flushes the write (Linux pci_msix_mask)
fn mask(table: &IoMem, i: usize) {
    table.write32(i * ENTRY + E_CTRL, E_MASKED);
    let _ = table.read32(i * ENTRY + E_CTRL);
}

impl MsixVectors {
    /// One vector per CPU of `cpus`, interrupt `i` aimed at `cpus[i]`
    /// (Linux pci_alloc_irq_vectors_affinity with min = max). NoDevice
    /// without MSI-X, or with fewer vectors than asked, or no table
    /// mapping; ENOSPC when the interrupt controller has no room
    pub fn enable(pci: &PciDevice, cpus: &[u32]) -> Result<Self, KernelError> {
        let cap = pci
            .caps()
            .find(|&(_, id)| id == cap_id::MSIX)
            .map(|(pos, _)| pos)
            .ok_or(KernelError::NoDevice)?;
        let ctrl = pci.cfg_read16(cap + CTRL);
        let size = usize::from(ctrl & CTRL_QSIZE) + 1;
        if cpus.is_empty() || cpus.len() > size {
            return Err(KernelError::NoDevice);
        }
        let table = map_table(pci, cap, size)?;
        let mut irqs = KVec::try_with_capacity(cpus.len())?;
        for &cpu in cpus {
            irqs.try_push(msi_alloc(cpu).ok_or(KernelError::NoSpace)?)?;
        }
        let v = Self {
            pci: pci.clone(),
            cap,
            table,
            irqs: irqs.into_vec(),
        };
        v.start(ctrl);
        Ok(v)
    }

    /// Program the table with every entry masked, then switch MSI-X on
    /// and INTx off (Linux msix_capability_init, pci_intx_for_msi)
    fn start(&self, ctrl: u16) {
        self.pci
            .cfg_write16(self.cap + CTRL, ctrl | CTRL_ENABLE | CTRL_MASKALL);
        for (i, irq) in self.irqs.iter().enumerate() {
            let m = irq.msg();
            let e = i * ENTRY;
            self.table.write32(e + E_CTRL, E_MASKED);
            // Splitting the 64-bit address into its halves
            self.table.write32(e + E_ADDR_LO, m.addr as u32);
            self.table.write32(e + E_ADDR_HI, (m.addr >> 32) as u32);
            self.table.write32(e + E_DATA, m.data);
        }
        let cmd = self.pci.cfg_read16(PCI_COMMAND);
        self.pci
            .cfg_write16(PCI_COMMAND, cmd | command::INTERRUPT_DISABLE);
        self.pci.cfg_write16(self.cap + CTRL, ctrl | CTRL_ENABLE);
    }

    /// Vectors enabled
    pub fn len(&self) -> usize {
        self.irqs.len()
    }

    /// Never: `enable` refuses zero vectors
    pub fn is_empty(&self) -> bool {
        self.irqs.is_empty()
    }

    /// Register `handler` on vector `i` and unmask it (Linux request_irq
    /// on pci_irq_vector); EINVAL for a vector out of range
    pub fn request<T: IrqHandler + 'static>(
        self: &Arc<Self>,
        i: usize,
        handler: Arc<T>,
    ) -> Result<MsixHandler<T>, KernelError> {
        let irq = self.irqs.get(i).ok_or(KernelError::InvalidArgument)?;
        let reg = request_irq(irq.irq(), handler)?;
        self.table.write32(i * ENTRY + E_CTRL, 0);
        Ok(MsixHandler {
            vecs: self.clone(),
            entry: i,
            reg: Some(reg),
        })
    }
}

impl Drop for MsixVectors {
    /// Linux pci_msix_shutdown + pci_free_irq_vectors: the handlers are
    /// gone already (each holds the vectors)
    fn drop(&mut self) {
        for i in 0..self.irqs.len() {
            mask(&self.table, i);
        }
        let ctrl = self.pci.cfg_read16(self.cap + CTRL);
        self.pci
            .cfg_write16(self.cap + CTRL, ctrl & !(CTRL_ENABLE | CTRL_MASKALL));
        let cmd = self.pci.cfg_read16(PCI_COMMAND);
        self.pci
            .cfg_write16(PCI_COMMAND, cmd & !command::INTERRUPT_DISABLE);
        // The interrupts are freed with `irqs`
    }
}

/// ioremap the table: `size` entries at the offset and BAR the
/// capability names (Linux msix_map_region)
fn map_table(pci: &PciDevice, cap: u8, size: usize) -> Result<IoMem, KernelError> {
    let t = pci.cfg_read32(cap + TABLE);
    let bar = (t & 7) as usize;
    let off = u64::from(t & !7);
    let len = size * ENTRY;
    let base = match pci.bar_address(bar) {
        Some(b) if pci.bar_is_mmio(bar) => b,
        _ => return Err(KernelError::NoDevice),
    };
    if off + len as u64 > pci.bar_size(bar) {
        return Err(KernelError::NoDevice);
    }
    // SAFETY: the MSI-X table inside a memory BAR of this device, within
    // its probed size: registers, not RAM
    unsafe { IoMem::ioremap(base + off, len) }.ok_or(KernelError::NoDevice)
}
