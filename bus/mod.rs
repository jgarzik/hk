//! Bus infrastructure
//!
//! Provides device driver traits, bus abstractions, and platform enumeration.

#[allow(clippy::module_inception)]
pub mod bus;
pub mod driver;
pub mod platform;

pub use bus::{Bus, BusContext, BusDevice, BusDriver, BusManager, FrameAllocWrapper};
pub use driver::{Device, DriverError, InterruptController, Timer};
pub use platform::{PlatformBus, PlatformBusDriver, PlatformDevice};
