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

use alloc::vec::Vec;

use super::gic::{self, Trigger};
use crate::arch::IrqSpinlock;

/// Maximum number of SPI interrupts supported
const MAX_SPI: usize = 256;

/// IRQ handler function signature (same on all arches)
///
/// Arguments:
/// - `irq`: The IRQ number (GIC INTID)
/// - `data`: Opaque pointer to driver instance state
///
/// Returns `true` if the interrupt was handled by this driver
pub type IrqHandler = fn(irq: u32, data: *mut ()) -> bool;

/// Entry in the IRQ handler table
struct IrqEntry {
    handler: IrqHandler,
    data: *mut (),
    id: usize,
}

// SAFETY: IrqEntry is only accessed under the IRQ_TABLE lock
unsafe impl Send for IrqEntry {}
unsafe impl Sync for IrqEntry {}

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

fn spi_index(irq: u32) -> Result<usize, &'static str> {
    if irq < 32 {
        return Err("only SPIs (>= 32) can be registered");
    }
    let index = (irq - 32) as usize;
    if index >= MAX_SPI {
        return Err("IRQ number out of range");
    }
    Ok(index)
}

/// Register a (shareable) handler for an SPI and unmask it
///
/// # Arguments
/// - `irq`: GIC INTID (32-287)
/// - `handler`: Handler function
/// - `data`: Opaque pointer to driver state (passed to handler)
/// - `id`: Unique identifier for unregistration (typically device address)
pub fn register_irq_handler(
    irq: u32,
    handler: IrqHandler,
    data: *mut (),
    id: usize,
) -> Result<(), &'static str> {
    let index = spi_index(irq)?;
    let first = {
        let mut table = IRQ_TABLE.lock();
        let line = &mut table.lines[index];
        if line.handlers.iter().any(|e| e.id == id) {
            return Err("Handler with this ID already registered");
        }
        line.handlers.push(IrqEntry { handler, data, id });
        line.spurious.reset();
        line.handlers.len() == 1
    };
    if first {
        gic::enable_spi(irq, Trigger::Level);
    }
    Ok(())
}

/// Unregister a handler; the SPI is masked when its last handler goes
pub fn unregister_irq_handler(irq: u32, id: usize) -> Result<(), &'static str> {
    let index = spi_index(irq)?;
    let mut table = IRQ_TABLE.lock();
    let line = &mut table.lines[index];
    let pos = line
        .handlers
        .iter()
        .position(|e| e.id == id)
        .ok_or("Handler not found")?;
    line.handlers.remove(pos);
    if line.handlers.is_empty() {
        gic::disable_spi(irq);
    }
    Ok(())
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
        handled |= (entry.handler)(irq, entry.data);
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
