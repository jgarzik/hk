//! Bus infrastructure
//!
//! Provides device driver traits and bus abstractions.

#[allow(clippy::module_inception)]
pub mod bus;
pub mod driver;

pub use bus::{Bus, BusContext, BusDevice, BusDriver, BusManager, FrameAllocWrapper};
pub use driver::Device;
