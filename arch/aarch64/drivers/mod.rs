//! AArch64 Platform Drivers
//!
//! Architecture-specific drivers for ARM platform devices.
//! These drivers register with the platform bus during arch_bus_init().

extern crate alloc;

pub mod gic;
pub mod rtc;
pub mod serial;

use alloc::boxed::Box;

use crate::bus::BusManager;

pub use gic::Gicv3PlatformDriver;
pub use rtc::Pl031PlatformDriver;
pub use serial::Pl011PlatformDriver;

/// Register all aarch64 platform drivers with the bus manager
pub fn register_platform_drivers(bus_manager: &mut BusManager) {
    bus_manager.register_driver("platform", Box::new(Gicv3PlatformDriver));
    bus_manager.register_driver("platform", Box::new(Pl011PlatformDriver));
    bus_manager.register_driver("platform", Box::new(Pl031PlatformDriver));
}
