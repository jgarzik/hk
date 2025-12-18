//! PL031 RTC Platform Driver
//!
//! Platform bus driver wrapper for the ARM PL031 real-time clock.
//! This wraps the standalone rtc module for use with the platform bus.
//!
//! Note: PL031 is a real-time clock, not a programmable interval timer.
//! It provides wall-clock time, not periodic timer functionality.
//! For periodic timing, use the ARM Generic Timer instead.

use alloc::boxed::Box;
use core::any::Any;

use crate::arch::aarch64::rtc;
use crate::bus::BusContext;
use crate::bus::driver::{Device, DriverError, Timer};
use crate::bus::platform::{PlatformBusDriver, PlatformDevice};
use crate::impl_platform_bus_driver;

/// PL031 RTC platform bus driver
pub struct Pl031PlatformDriver;

impl PlatformBusDriver for Pl031PlatformDriver {
    fn name(&self) -> &str {
        "pl031-rtc-driver"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["arm,pl031"]
    }

    fn probe_platform(
        &self,
        _device: &PlatformDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        // RTC is already initialized during early boot via rtc::init()
        Ok(Box::new(Pl031Device))
    }
}

impl_platform_bus_driver!(Pl031PlatformDriver);

/// PL031 RTC device instance
pub struct Pl031Device;

impl Device for Pl031Device {
    fn name(&self) -> &str {
        "pl031-rtc"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Timer implementation for PL031
///
/// Note: PL031 is an RTC, not a programmable interval timer. The Timer trait
/// implementation provides compatibility with the platform bus driver model,
/// but for actual periodic timing, the ARM Generic Timer should be used.
impl Timer for Pl031Device {
    fn init(&self, _frequency_hz: u32) {
        // PL031 doesn't support programmable frequency - it's an RTC
        // that increments once per second. Ensure it's enabled.
        rtc::init();
    }

    fn ticks(&self) -> u64 {
        // For RTC, we return the current Unix timestamp in seconds
        // This is different from a PIT which counts periodic interrupts
        rtc::read_rtc() as u64
    }
}
