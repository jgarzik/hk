//! Device driver traits

use core::any::Any;

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
