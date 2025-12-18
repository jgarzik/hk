//! Device driver traits

use alloc::{boxed::Box, vec::Vec};
use core::any::Any;

use crate::dt::registry::DeviceInfo;

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

/// Device driver that can match and probe devices from device tree
pub trait Driver: Send + Sync {
    /// Compatible strings this driver handles
    fn compatible(&self) -> &'static [&'static str];

    /// Probe and initialize a device
    fn probe(&self, dev: &DeviceInfo) -> Result<Box<dyn Device>, DriverError>;
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

/// Driver registry for matching drivers to device tree nodes
pub struct DriverRegistry {
    drivers: Vec<Box<dyn Driver>>,
}

impl DriverRegistry {
    /// Create a new empty driver registry
    pub fn new() -> Self {
        Self {
            drivers: Vec::new(),
        }
    }

    /// Register a driver
    pub fn register(&mut self, driver: Box<dyn Driver>) {
        self.drivers.push(driver);
    }

    /// Find a driver that matches the given compatible string
    pub fn find_driver(&self, compatible: &str) -> Option<&dyn Driver> {
        for driver in &self.drivers {
            for compat in driver.compatible() {
                if *compat == compatible {
                    return Some(driver.as_ref());
                }
            }
        }
        None
    }

    /// Probe a device using the appropriate driver
    pub fn probe(&self, dev: &DeviceInfo) -> Result<Box<dyn Device>, DriverError> {
        if let Some(driver) = self.find_driver(&dev.compatible) {
            return driver.probe(dev);
        }
        Err(DriverError::Unsupported)
    }
}

impl Default for DriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}
