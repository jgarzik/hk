//! IRQ Handler Registration and Dispatch (legacy 8259 PIC)
//!
//! Drivers register handlers for hardware IRQs 0-15; several handlers may
//! share a line (each returns whether it handled the interrupt). The first
//! handler unmasks the line at the PIC, the last one to go masks it.
//!
//! PCI INTx: with QEMU `pc` and legacy BIOS routing the firmware writes the
//! PIC line into the config-space Interrupt Line register, which is what
//! `pci_intx_irq` returns. Real hardware with APIC-mode routing (e.g. the
//! Dell OptiPlex 3020 target) needs IOAPIC + ACPI `_PRT` support instead
//! (not implemented).
//!
//! Locking: `IRQ_TABLE` is an `IrqSpinlock` (taken by `dispatch_irq` in IRQ
//! context, by register/unregister in process context). Handlers run with
//! it held and must not register/unregister.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::irq::IrqHandler;
use crate::sync::IrqSpinlock;
use crate::util::error::KernelError;

/// Number of legacy PIC lines
const NR_IRQS: usize = 16;

/// Entry in the IRQ handler table
struct IrqEntry {
    handler: Arc<dyn IrqHandler>,
    id: usize,
}

/// One PIC line
struct IrqLine {
    handlers: Vec<IrqEntry>,
    spurious: crate::irq::Spurious,
}

/// IRQ handler table - 16 lines
struct IrqTable {
    lines: [IrqLine; NR_IRQS],
}

impl IrqTable {
    const fn new() -> Self {
        const EMPTY: IrqLine = IrqLine {
            handlers: Vec::new(),
            spurious: crate::irq::Spurious::new(),
        };
        Self {
            lines: [EMPTY; NR_IRQS],
        }
    }
}

/// Global IRQ handler table
static IRQ_TABLE: IrqSpinlock<IrqTable> = IrqSpinlock::new(IrqTable::new());

/// Register a (shareable) handler for IRQ `irq` (0-15) and unmask it
pub fn register_irq_handler(
    irq: u32,
    handler: Arc<dyn IrqHandler>,
    id: usize,
) -> Result<(), KernelError> {
    if irq as usize >= NR_IRQS {
        return Err(KernelError::InvalidArgument);
    }
    let mut table = IRQ_TABLE.lock();
    let line = &mut table.lines[irq as usize];
    if line.handlers.iter().any(|e| e.id == id) {
        return Err(KernelError::Busy);
    }
    line.handlers.push(IrqEntry { handler, id });
    line.spurious.reset();
    if line.handlers.len() == 1 {
        super::pic::enable_irq(irq as u8);
    }
    Ok(())
}

/// Unregister a handler; the line is masked when its last handler goes
pub fn unregister_irq_handler(irq: u32, id: usize) -> Result<Arc<dyn IrqHandler>, KernelError> {
    if irq as usize >= NR_IRQS {
        return Err(KernelError::InvalidArgument);
    }
    let mut table = IRQ_TABLE.lock();
    let line = &mut table.lines[irq as usize];
    let pos = line
        .handlers
        .iter()
        .position(|e| e.id == id)
        .ok_or(KernelError::NotFound)?;
    let e = line.handlers.remove(pos);
    if line.handlers.is_empty() {
        super::pic::disable_irq(irq as u8);
    }
    Ok(e.handler)
}

/// Dispatch an IRQ to registered handlers (IRQ context)
///
/// # Returns
/// `true` if any handler claimed the interrupt
pub fn dispatch_irq(irq: u8) -> bool {
    if irq as usize >= NR_IRQS {
        return false;
    }
    let mut table = IRQ_TABLE.lock();
    let line = &mut table.lines[irq as usize];

    // Every handler of a shared line gets a look
    let mut handled = false;
    for entry in &line.handlers {
        crate::sync::lockdep::irq_enter();
        handled |= entry.handler.handle(u32::from(irq));
        crate::sync::lockdep::irq_exit();
    }
    // A line without handlers is masked already (spurious IRQ7/15)
    let bad = !line.handlers.is_empty() && line.spurious.note(handled, crate::time::monotonic_ns);
    if bad {
        super::pic::disable_irq(irq);
    }
    drop(table);
    if bad {
        crate::irq::report_nobody_cared(u32::from(irq));
    }
    handled
}

/// IRQ for a PCI device's INTx pin: the firmware-assigned PIC line from
/// config space (`line`), if the device uses a pin and the line is valid
pub fn pci_intx_irq(_bus: u8, _device: u8, _function: u8, pin: u8, line: u8) -> Option<u32> {
    if pin == 0 || line >= NR_IRQS as u8 {
        return None;
    }
    Some(u32::from(line))
}
