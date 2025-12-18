//! PL011 UART Platform Driver
//!
//! Platform bus driver wrapper for the ARM PL011 serial console.
//! This wraps the standalone serial module for use with the platform bus.

use alloc::boxed::Box;
use core::any::Any;

use crate::bus::BusContext;
use crate::bus::driver::{Device, DriverError};
use crate::bus::platform::{PlatformBusDriver, PlatformDevice};
use crate::impl_platform_bus_driver;

/// PL011 UART platform bus driver
pub struct Pl011PlatformDriver;

impl PlatformBusDriver for Pl011PlatformDriver {
    fn name(&self) -> &str {
        "pl011-uart-driver"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["arm,pl011"]
    }

    fn probe_platform(
        &self,
        _device: &PlatformDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        // PL011 is already initialized during early boot via serial::init()
        Ok(Box::new(Pl011Device))
    }
}

impl_platform_bus_driver!(Pl011PlatformDriver);

/// PL011 UART device instance
pub struct Pl011Device;

impl Device for Pl011Device {
    fn name(&self) -> &str {
        "pl011-uart"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
