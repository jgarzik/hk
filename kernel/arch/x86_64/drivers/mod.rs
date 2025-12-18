//! x86-64 Platform Drivers
//!
//! Architecture-specific drivers for x86-64 platform devices.
//! These drivers register with the platform bus during arch_init().

extern crate alloc;

pub mod pic;
pub mod pit;
pub mod serial;

use alloc::boxed::Box;

use crate::bus::BusManager;

pub use pic::Pic8259PlatformDriver;
pub use pit::Pit8254PlatformDriver;
pub use serial::SerialPlatformDriver;

/// Register all x86-64 platform drivers with the bus manager
pub fn register_platform_drivers(bus_manager: &mut BusManager) {
    bus_manager.register_driver("platform", Box::new(Pic8259PlatformDriver));
    bus_manager.register_driver("platform", Box::new(Pit8254PlatformDriver));
    bus_manager.register_driver("platform", Box::new(SerialPlatformDriver));
}
