//! IRQ Handler Registration and Dispatch (GICv3 SPIs)
//!
//! Drivers register handlers for shared peripheral interrupts; several
//! handlers may share one line (each returns whether it handled the
//! interrupt). Registering the first handler configures and unmasks the SPI
//! (level-triggered, routed to CPU 0); removing the last masks it.
//!
//! ARM GIC interrupt number ranges:
//! - SGI (Software Generated Interrupts): 0-15 (used for IPIs)
//! - PPI (Private Peripheral Interrupts): 16-31 (per-CPU, e.g., timer)
//! - SPI (Shared Peripheral Interrupts): 32-1019 (shared across CPUs)
//!
//! Locking: `IRQ_TABLE` is an `IrqSpinlock` (taken by `dispatch_irq` in IRQ
//! context, by register/unregister in process context). Handlers run with it
//! held and must not register/unregister.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::gic;
use crate::irq::IrqHandler;
use crate::sync::IrqSpinlock;
use crate::util::error::KernelError;

/// Maximum number of SPI interrupts supported
const MAX_SPI: usize = 256;

/// Entry in the IRQ handler table
struct IrqEntry {
    handler: Arc<dyn IrqHandler>,
    id: usize,
}

/// One SPI line
struct IrqLine {
    handlers: Vec<IrqEntry>,
    spurious: crate::irq::Spurious,
}

/// IRQ handler table for SPIs (32-287)
struct IrqTable {
    lines: [IrqLine; MAX_SPI],
}

impl IrqTable {
    const fn new() -> Self {
        const EMPTY: IrqLine = IrqLine {
            handlers: Vec::new(),
            spurious: crate::irq::Spurious::new(),
        };
        Self {
            lines: [EMPTY; MAX_SPI],
        }
    }
}

/// Global IRQ handler table for SPIs
static IRQ_TABLE: IrqSpinlock<IrqTable> = IrqSpinlock::new(IrqTable::new());

fn spi_index(irq: u32) -> Result<usize, KernelError> {
    if irq < 32 {
        return Err(KernelError::InvalidArgument);
    }
    let index = (irq - 32) as usize;
    if index >= MAX_SPI {
        return Err(KernelError::InvalidArgument);
    }
    Ok(index)
}

/// Register a (shareable) handler for an SPI and unmask it
///
/// # Arguments
/// - `irq`: GIC INTID (32-287)
/// - `handler`: the handler and its device state
/// - `id`: Unique identifier for unregistration (typically device address)
pub fn register_irq_handler(
    irq: u32,
    handler: Arc<dyn IrqHandler>,
    id: usize,
) -> Result<(), KernelError> {
    let index = spi_index(irq)?;
    let first = {
        let mut table = IRQ_TABLE.lock();
        let line = &mut table.lines[index];
        if line.handlers.iter().any(|e| e.id == id) {
            return Err(KernelError::Busy);
        }
        line.handlers.push(IrqEntry { handler, id });
        line.spurious.reset();
        line.handlers.len() == 1
    };
    if first {
        gic::enable_spi(irq);
    }
    Ok(())
}

/// Unregister a handler; the SPI is masked when its last handler goes
pub fn unregister_irq_handler(irq: u32, id: usize) -> Result<Arc<dyn IrqHandler>, KernelError> {
    let index = spi_index(irq)?;
    let mut table = IRQ_TABLE.lock();
    let line = &mut table.lines[index];
    let pos = line
        .handlers
        .iter()
        .position(|e| e.id == id)
        .ok_or(KernelError::NotFound)?;
    let e = line.handlers.remove(pos);
    if line.handlers.is_empty() {
        gic::disable_spi(irq);
    }
    Ok(e.handler)
}

/// Dispatch an SPI to registered handlers (IRQ context)
///
/// # Returns
/// `true` if any handler claimed the interrupt
pub fn dispatch_irq(irq: u32) -> bool {
    let Ok(index) = spi_index(irq) else {
        return false;
    };
    let mut table = IRQ_TABLE.lock();
    let line = &mut table.lines[index];

    // Every handler of a shared line gets a look
    let mut handled = false;
    for entry in &line.handlers {
        crate::sync::lockdep::irq_enter();
        handled |= entry.handler.handle(irq);
        crate::sync::lockdep::irq_exit();
    }
    let bad = !line.handlers.is_empty() && line.spurious.note(handled, crate::time::monotonic_ns);
    if bad || line.handlers.is_empty() {
        gic::disable_spi(irq);
    }
    drop(table);
    if bad {
        crate::irq::report_nobody_cared(irq);
    }
    handled
}

/// GIC INTID for a PCI device's INTx pin
///
/// `pin` is the config-space Interrupt Pin (1 = INTA .. 4 = INTD; 0 = none).
/// Uses the host bridge's DT `interrupt-map`, else the QEMU virt swizzle.
pub fn pci_intx_irq(bus: u8, device: u8, function: u8, pin: u8, _line: u8) -> Option<u32> {
    super::pci_irq::intx_to_intid(bus, device, function, pin)
}
