//! Device IRQ lines: the legacy 8259 PIC and MSI vectors (`crate::irq`
//! keeps the handler table)
//!
//! IRQs 0-15 are the PIC lines. PCI INTx: with QEMU `pc` and legacy BIOS
//! routing the firmware writes the PIC line into the config-space
//! Interrupt Line register, which is what `pci_intx_irq` returns. Real
//! hardware with APIC-mode routing (e.g. the Dell OptiPlex 3020 target)
//! needs IOAPIC + ACPI `_PRT` support instead (not implemented).
//!
//! IRQs from 16 are MSI lines (Linux arch/x86/kernel/apic/vector.c, the
//! x86 vector domain under the PCI MSI domain): each is one vector of
//! one CPU's LAPIC, `FIRST_DEV_VECTOR..=LAST_DEV_VECTOR`, aimed there by
//! the message's destination APIC id (physical destination mode, fixed
//! delivery, edge; Linux __irq_msi_compose_msg). An x2APIC id above 255
//! cannot be named without interrupt remapping: no MSI for that CPU.
//! The line's mask is the device's (the MSI-X entry, `hw::pci::msix`),
//! so the chip's mask and unmask leave MSI lines alone.
//!
//! ## Locking
//!
//! `MATRIX` (spin `Mutex`, thread context, leaf; Linux vector_lock with
//! the irq_matrix) hands out lines and vectors in `msi_alloc` and takes
//! them back in `msi_free`. Each CPU's `VECTOR_IRQ` table (Linux
//! per-CPU vector_irq) maps its vectors to lines: written under
//! `MATRIX`, read lock-free by the interrupt entry on that CPU (an
//! acquire load: a vector set before its message is programmed into the
//! device is seen by its first interrupt).

use core::sync::atomic::{AtomicU16, Ordering};

use super::{X86_64Arch, pic};
use crate::arch::IrqChipOps;
use crate::cpu::PerCpu;
use crate::irq::MsiMsg;
use crate::sync::spin::Mutex;
use crate::util::cpumask::NR_CPUS;

/// Device vectors (Linux FIRST_EXTERNAL_VECTOR..FIRST_SYSTEM_VECTOR;
/// below are the PIC's 0x20-0x2f and the timer's 0x40, above the IPIs
/// and APIC error/spurious vectors)
pub const FIRST_DEV_VECTOR: u8 = 0x50;
pub const LAST_DEV_VECTOR: u8 = 0xef;
const NR_DEV_VECTORS: usize = (LAST_DEV_VECTOR - FIRST_DEV_VECTOR) as usize + 1;
const WORDS: usize = NR_DEV_VECTORS.div_ceil(64);
/// PIC lines, then MSI lines
const NR_PIC: u32 = 16;
const NR_MSI: usize = 240;
/// LAPIC MSI address: 0xfee, the destination APIC id at bit 12 (Intel
/// SDM 11.11.1)
const MSI_ADDR_BASE: u64 = 0xfee0_0000;

/// Per CPU, the line on each device vector (0: none)
static VECTOR_IRQ: PerCpu<[AtomicU16; NR_DEV_VECTORS]> =
    crate::percpu![[const { AtomicU16::new(0) }; NR_DEV_VECTORS]];

/// Vectors in use per CPU and each MSI line's (CPU, vector index)
/// (Linux irq_matrix)
struct Matrix {
    used: [[u64; WORDS]; NR_CPUS],
    lines: [Option<(u16, u8)>; NR_MSI],
}

static MATRIX: Mutex<Matrix> = Mutex::new(Matrix::new());

impl Matrix {
    const fn new() -> Self {
        Self {
            used: [[0; WORDS]; NR_CPUS],
            lines: [None; NR_MSI],
        }
    }

    /// Take a free line and a free vector of `cpu` (< NR_CPUS): (line
    /// index, vector index)
    fn alloc(&mut self, cpu: usize) -> Option<(usize, usize)> {
        let line = self.lines.iter().position(Option::is_none)?;
        let used = &mut self.used[cpu];
        let v = (0..NR_DEV_VECTORS).find(|&v| used[v / 64] & (1 << (v % 64)) == 0)?;
        used[v / 64] |= 1 << (v % 64);
        // cpu < NR_CPUS (256 fits u16) and v < NR_DEV_VECTORS fit
        self.lines[line] = Some((cpu as u16, v as u8));
        Some((line, v))
    }

    /// Give line `line` and its vector back: its (CPU, vector index)
    fn free(&mut self, line: usize) -> Option<(usize, usize)> {
        let (cpu, v) = self.lines.get_mut(line)?.take()?;
        let (cpu, v) = (usize::from(cpu), usize::from(v));
        self.used[cpu][v / 64] &= !(1 << (v % 64));
        Some((cpu, v))
    }
}

/// The MSI line on device vector `vector` of this CPU (interrupt entry)
pub fn vector_irq(vector: u8) -> Option<u32> {
    let i = usize::from(vector.checked_sub(FIRST_DEV_VECTOR)?);
    match VECTOR_IRQ.this().get(i)?.load(Ordering::Acquire) {
        0 => None,
        irq => Some(u32::from(irq)),
    }
}

impl IrqChipOps for X86_64Arch {
    const FIRST_IRQ: u32 = 0;
    const NR_IRQS: usize = NR_PIC as usize + NR_MSI;

    // PIC lines are below 16: `as u8` keeps them
    fn irq_unmask(irq: u32) {
        if irq < NR_PIC {
            pic::enable_irq(irq as u8);
        }
    }

    fn irq_mask(irq: u32) {
        if irq < NR_PIC {
            pic::disable_irq(irq as u8);
        }
    }

    /// The firmware-assigned PIC line from config space, if the device
    /// uses a pin and the line is valid
    fn pci_intx_irq(_bus: u8, _device: u8, _function: u8, pin: u8, line: u8) -> Option<u32> {
        if pin == 0 || u32::from(line) >= NR_PIC {
            return None;
        }
        Some(u32::from(line))
    }

    /// Linux x86_vector_alloc_irqs + __irq_msi_compose_msg
    fn msi_alloc(cpu: u32) -> Option<(u32, MsiMsg)> {
        if cpu >= crate::cpu::nr_cpu_ids() {
            return None;
        }
        let apic = super::percpu::get_percpu(cpu)
            .apic_id
            .load(Ordering::Relaxed);
        if apic > 0xff {
            return None;
        }
        let mut m = MATRIX.lock();
        let (line, v) = m.alloc(cpu as usize)?;
        // line < NR_MSI: the line fits u16
        let irq = NR_PIC + line as u32;
        VECTOR_IRQ.get(cpu)[v].store(irq as u16, Ordering::Release);
        drop(m);
        let msg = MsiMsg {
            addr: MSI_ADDR_BASE | (u64::from(apic) << 12),
            // v < NR_DEV_VECTORS: the vector fits u8
            data: u32::from(FIRST_DEV_VECTOR) + v as u32,
        };
        Some((irq, msg))
    }

    /// Linux x86_vector_free_irqs: an interrupt still on its way finds
    /// no line and is acknowledged as spurious
    fn msi_free(irq: u32) {
        let Some(line) = irq.checked_sub(NR_PIC) else {
            return;
        };
        let mut m = MATRIX.lock();
        if let Some((cpu, v)) = m.free(line as usize) {
            // cpu < NR_CPUS
            VECTOR_IRQ.get(cpu as u32)[v].store(0, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_lines_and_vectors() {
        let mut m = alloc::boxed::Box::new(Matrix::new());
        assert_eq!(m.alloc(1), Some((0, 0)));
        assert_eq!(m.alloc(1), Some((1, 1)));
        assert_eq!(m.alloc(2), Some((2, 0)));
        assert_eq!(m.free(1), Some((1, 1)));
        assert_eq!(m.free(1), None);
        // The freed line and vector come back first
        assert_eq!(m.alloc(1), Some((1, 1)));
        // A CPU's vectors run out
        let mut n = 0;
        while m.alloc(3).is_some() {
            n += 1;
        }
        assert_eq!(n, NR_DEV_VECTORS);
    }
}
