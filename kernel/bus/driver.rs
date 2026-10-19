//! Device driver traits

use core::any::Any;

/// Driver error
#[derive(Debug)]
pub enum DriverError {
    /// Required resource missing from device tree
    MissingResource,
    /// Device initialization failed
    InitFailed,
    /// Unsupported device
    Unsupported,
    /// Device removal failed
    RemovalFailed,
    /// Device is in use (cannot be removed)
    InUse,
}

/// A device instance
pub trait Device: Send + Sync {
    /// Device name
    fn name(&self) -> &str;

    /// For downcasting to concrete types
    fn as_any(&self) -> &dyn Any;

    /// Device-specific cleanup before removal (hotplug support)
    ///
    /// Called before the device is removed from the system.
    /// Default implementation does nothing.
    fn shutdown(&self) {}

    /// Get the bus ID this device instance is bound to
    ///
    /// Used for matching during device removal. Returns None if
    /// this device doesn't track its bus binding.
    fn bus_id(&self) -> Option<&str> {
        None
    }
}

/// Interrupt controller device trait
pub trait InterruptController: Device {
    /// Enable an IRQ
    fn enable_irq(&self, irq: u8);

    /// Disable an IRQ
    fn disable_irq(&self, irq: u8);

    /// Send end-of-interrupt signal
    fn send_eoi(&self, irq: u8);
}

/// Timer device trait
pub trait Timer: Device {
    /// Initialize the timer for periodic interrupts at the given frequency
    fn init(&self, frequency_hz: u32);

    /// Get the current tick count
    fn ticks(&self) -> u64;
}
