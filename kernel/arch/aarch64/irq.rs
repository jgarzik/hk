//! IRQ Handler Registration and Dispatch
//!
//! Provides a mechanism for drivers to register handlers for hardware IRQs.
//! Supports IRQ sharing via handler chaining - each handler returns whether
//! it handled the interrupt.
//!
//! ARM GIC interrupt number ranges:
//! - SGI (Software Generated Interrupts): 0-15 (used for IPIs)
//! - PPI (Private Peripheral Interrupts): 16-31 (per-CPU, e.g., timer)
//! - SPI (Shared Peripheral Interrupts): 32-1019 (shared across CPUs)

use alloc::vec::Vec;
use spin::Mutex;

/// Maximum number of SPI interrupts supported
const MAX_SPI: usize = 256;

/// IRQ handler function signature
///
/// Arguments:
/// - `irq`: The IRQ number
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

// SAFETY: IrqEntry is only accessed with interrupts disabled (in ISR context)
// or under the IRQ_TABLE lock
unsafe impl Send for IrqEntry {}
unsafe impl Sync for IrqEntry {}

/// IRQ handler table for SPIs (32-287)
struct IrqTable {
    handlers: [Vec<IrqEntry>; MAX_SPI],
}

impl IrqTable {
    const fn new() -> Self {
        // Initialize array with empty Vecs
        // Using const fn so we need this verbose initialization
        const EMPTY: Vec<IrqEntry> = Vec::new();
        Self {
            handlers: [EMPTY; MAX_SPI],
        }
    }
}

/// Global IRQ handler table for SPIs
static IRQ_TABLE: Mutex<IrqTable> = Mutex::new(IrqTable::new());

/// Register an IRQ handler for an SPI (32+)
///
/// # Arguments
/// - `irq`: IRQ number (32-287 for SPIs)
/// - `handler`: Handler function
/// - `data`: Opaque pointer to driver state (passed to handler)
/// - `id`: Unique identifier for unregistration (typically device address)
///
/// # Returns
/// `Ok(())` on success, `Err` with description on failure
pub fn register_irq_handler(
    irq: u32,
    handler: IrqHandler,
    data: *mut (),
    id: usize,
) -> Result<(), &'static str> {
    // Only handle SPIs (32+) in this table
    // PPIs are per-CPU and handled differently
    if irq < 32 {
        return Err("Use register_ppi_handler for PPIs (< 32)");
    }

    let index = (irq - 32) as usize;
    if index >= MAX_SPI {
        return Err("IRQ number out of range");
    }

    let mut table = IRQ_TABLE.lock();
    let handlers = &mut table.handlers[index];

    // Check for duplicate registration
    if handlers.iter().any(|e| e.id == id) {
        return Err("Handler with this ID already registered");
    }

    handlers.push(IrqEntry { handler, data, id });

    Ok(())
}

/// Unregister an IRQ handler
///
/// # Arguments
/// - `irq`: IRQ number
/// - `id`: The ID that was used during registration
#[allow(dead_code)]
pub fn unregister_irq_handler(irq: u32, id: usize) -> Result<(), &'static str> {
    if irq < 32 {
        return Err("Use unregister_ppi_handler for PPIs (< 32)");
    }

    let index = (irq - 32) as usize;
    if index >= MAX_SPI {
        return Err("IRQ number out of range");
    }

    let mut table = IRQ_TABLE.lock();
    let handlers = &mut table.handlers[index];

    if let Some(pos) = handlers.iter().position(|e| e.id == id) {
        handlers.remove(pos);
        Ok(())
    } else {
        Err("Handler not found")
    }
}

/// Dispatch an SPI to registered handlers
///
/// Called from the IRQ handler in interrupt context.
/// Uses `try_lock()` to avoid blocking in ISR.
///
/// # Returns
/// `true` if any handler claimed the interrupt
pub fn dispatch_irq(irq: u32) -> bool {
    // Only handle SPIs here
    if irq < 32 {
        return false;
    }

    let index = (irq - 32) as usize;
    if index >= MAX_SPI {
        return false;
    }

    // Use try_lock to avoid blocking in interrupt context
    let table = match IRQ_TABLE.try_lock() {
        Some(t) => t,
        None => {
            // Table is locked - this shouldn't happen in normal operation
            // since we're in ISR context and the lock holder should have
            // completed quickly. Log and return.
            return false;
        }
    };

    let handlers = &table.handlers[index];

    // Call each handler until one claims the interrupt
    for entry in handlers {
        if (entry.handler)(irq, entry.data) {
            return true;
        }
    }

    false
}
