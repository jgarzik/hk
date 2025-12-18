//! Bus infrastructure
//!
//! Provides device driver traits, bus abstractions, and platform enumeration.

use alloc::boxed::Box;

#[allow(clippy::module_inception)]
pub mod bus;
pub mod driver;
pub mod pci;
pub mod platform;

pub use bus::{Bus, BusContext, BusDevice, BusDriver, BusManager, FrameAllocWrapper};
pub use driver::{Device, Driver, DriverError, DriverRegistry, InterruptController, Timer};
pub use pci::{PciBus, PciDevice, PciHostController, PciHostDriver};
pub use platform::{PlatformBus, PlatformBusDriver, PlatformDevice};

/// Register all platform drivers (PCI/USB)
pub fn register_drivers(registry: &mut DriverRegistry) {
    registry.register(Box::new(PciHostDriver));
    registry.register(Box::new(crate::usb::xhci::XhciDriver));
    registry.register(Box::new(crate::usb::serial::UsbSerialDriver));
}
