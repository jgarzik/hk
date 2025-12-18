//! Serial console driver (ns16550a)
//!
//! Platform bus driver for NS16550A compatible serial ports.

use alloc::boxed::Box;
use core::any::Any;

use crate::bus::BusContext;
use crate::bus::driver::{Device, DriverError};
use crate::bus::platform::{PlatformBusDriver, PlatformDevice};
use crate::impl_platform_bus_driver;

/// NS16550A compatible serial platform bus driver
pub struct SerialPlatformDriver;

impl PlatformBusDriver for SerialPlatformDriver {
    fn name(&self) -> &str {
        "serial-driver"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["ns16550a", "ns16550"]
    }

    fn probe_platform(
        &self,
        device: &PlatformDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        let base = device.base_addr().ok_or(DriverError::MissingResource)?;
        Ok(Box::new(SerialConsole::new(base as u16)))
    }
}

impl_platform_bus_driver!(SerialPlatformDriver);

/// Serial console device
pub struct SerialConsole;

impl SerialConsole {
    /// Create a new serial console at the given I/O port
    pub fn new(_port: u16) -> Self {
        Self
    }
}

impl Device for SerialConsole {
    fn name(&self) -> &str {
        "serial"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
