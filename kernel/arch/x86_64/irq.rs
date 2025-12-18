//! IRQ Handler Registration and Dispatch
//!
//! Provides a mechanism for drivers to register handlers for hardware IRQs.
//! Supports IRQ sharing via handler chaining - each handler returns whether
//! it handled the interrupt.

use alloc::vec::Vec;
use spin::Mutex;

/// IRQ handler function signature
///
/// Arguments:
/// - `irq`: The IRQ number (0-15)
/// - `data`: Opaque pointer to driver instance state
///
/// Returns `true` if the interrupt was handled by this driver
pub type IrqHandler = fn(irq: u8, data: *mut ()) -> bool;

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

/// IRQ handler table - 16 entries for IRQs 0-15
struct IrqTable {
    handlers: [Vec<IrqEntry>; 16],
}

impl IrqTable {
    const fn new() -> Self {
        Self {
            handlers: [
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ],
        }
    }
}

/// Global IRQ handler table
static IRQ_TABLE: Mutex<IrqTable> = Mutex::new(IrqTable::new());

/// Register an IRQ handler
///
/// # Arguments
/// - `irq`: IRQ number (0-15)
/// - `handler`: Handler function
/// - `data`: Opaque pointer to driver state (passed to handler)
/// - `id`: Unique identifier for unregistration (typically device address)
///
/// # Returns
/// `Ok(())` on success, `Err` with description on failure
pub fn register_irq_handler(
    irq: u8,
    handler: IrqHandler,
    data: *mut (),
    id: usize,
) -> Result<(), &'static str> {
    if irq >= 16 {
        return Err("IRQ number out of range (0-15)");
    }

    let mut table = IRQ_TABLE.lock();
    let handlers = &mut table.handlers[irq as usize];

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
/// - `irq`: IRQ number (0-15)
/// - `id`: The ID that was used during registration
#[allow(dead_code)]
pub fn unregister_irq_handler(irq: u8, id: usize) -> Result<(), &'static str> {
    if irq >= 16 {
        return Err("IRQ number out of range (0-15)");
    }

    let mut table = IRQ_TABLE.lock();
    let handlers = &mut table.handlers[irq as usize];

    if let Some(pos) = handlers.iter().position(|e| e.id == id) {
        handlers.remove(pos);
        Ok(())
    } else {
        Err("Handler not found")
    }
}

/// Dispatch an IRQ to registered handlers
///
/// Called from the IRQ handler stub in interrupt context.
/// Uses `try_lock()` to avoid blocking in ISR.
///
/// # Returns
/// `true` if any handler claimed the interrupt
pub fn dispatch_irq(irq: u8) -> bool {
    if irq >= 16 {
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

    let handlers = &table.handlers[irq as usize];

    // Call each handler until one claims the interrupt
    for entry in handlers {
        if (entry.handler)(irq, entry.data) {
            return true;
        }
    }

    false
}
