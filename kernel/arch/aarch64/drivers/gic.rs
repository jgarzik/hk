//! GICv3 Platform Driver
//!
//! Platform bus driver wrapper for the ARM GICv3 interrupt controller.

use alloc::boxed::Box;
use core::any::Any;

use crate::arch::aarch64::gic;
use crate::bus::BusContext;
use crate::bus::driver::{Device, DriverError, InterruptController};
use crate::bus::platform::{PlatformBusDriver, PlatformDevice};
use crate::impl_platform_bus_driver;

/// GICv3 interrupt controller platform bus driver
pub struct Gicv3PlatformDriver;

impl PlatformBusDriver for Gicv3PlatformDriver {
    fn name(&self) -> &str {
        "gicv3-driver"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["arm,gic-v3"]
    }

    fn probe_platform(
        &self,
        _device: &PlatformDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        // GIC is already initialized during early boot via gic::init()
        Ok(Box::new(Gicv3Device))
    }
}

impl_platform_bus_driver!(Gicv3PlatformDriver);

/// GICv3 interrupt controller device instance
pub struct Gicv3Device;

impl Device for Gicv3Device {
    fn name(&self) -> &str {
        "gicv3"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl InterruptController for Gicv3Device {
    fn enable_irq(&self, irq: u8) {
        // For PPIs (< 32), use the redistributor enable
        if irq < 32 {
            gic::enable_ppi(irq as u32);
        }
        // SPIs (32+) would need distributor enable - not yet implemented
        // as the current GIC driver focuses on per-CPU initialization
    }

    fn disable_irq(&self, _irq: u8) {
        // Not yet implemented - would need GICD_ICENABLER for SPIs
        // or GICR_ICENABLER0 for PPIs
    }

    fn send_eoi(&self, irq: u8) {
        gic::end_interrupt(irq as u32);
    }
}
