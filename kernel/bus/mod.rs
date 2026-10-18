//! Bus infrastructure
//!
//! Provides device driver traits, bus abstractions, and platform enumeration.

#[allow(clippy::module_inception)]
pub mod bus;
pub mod driver;
pub mod pci;
pub mod pci_intx;
pub mod platform;

pub use bus::{Bus, BusContext, BusDevice, BusDriver, BusManager, FrameAllocWrapper};
pub use driver::{Device, DriverError, InterruptController, Timer};
pub use pci::{PciBus, PciDevice};
pub use platform::{PlatformBus, PlatformBusDriver, PlatformDevice};
