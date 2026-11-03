//! Platform Bus
//!
//! A bus for platform devices with fixed addresses (not discoverable via PCI/USB).
//! On x86-64, this includes legacy devices like PIC, PIT, and serial ports.
//!
//! The platform bus is a root bus that holds statically-defined devices
//! and matches them against registered drivers using compatible strings.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use core::any::Any;

use crate::printkln;

use super::bus::{Bus, BusContext, BusDevice, BusDriver};
use super::driver::{Device, DriverError};

/// A platform device with fixed resources
///
/// Platform devices are discovered statically (e.g., from device tree or
/// architecture-specific knowledge) rather than through bus enumeration.
pub struct PlatformDevice {
    /// Compatible string for driver matching (e.g., "intel,8259")
    compatible: &'static str,
    /// Base I/O port or MMIO address
    base_addr: Option<u64>,
    /// IRQ number if applicable
    irq: Option<u8>,
}

impl PlatformDevice {
    /// Create a new platform device
    pub fn new(compatible: &'static str, base_addr: Option<u64>, irq: Option<u8>) -> Self {
        Self {
            compatible,
            base_addr,
            irq,
        }
    }

    /// Get the compatible string
    pub fn compatible(&self) -> &'static str {
        self.compatible
    }

    /// Get the base address
    pub fn base_addr(&self) -> Option<u64> {
        self.base_addr
    }

    /// Get the IRQ number
    pub fn irq(&self) -> Option<u8> {
        self.irq
    }
}

impl BusDevice for PlatformDevice {
    fn name(&self) -> &str {
        self.compatible
    }

    fn bus_id(&self) -> String {
        if let Some(addr) = self.base_addr {
            alloc::format!("platform:{:04x}", addr)
        } else {
            alloc::format!("platform:{}", self.compatible)
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Platform bus for devices with fixed addresses
pub struct PlatformBus {
    /// Devices on this bus
    devices: Vec<PlatformDevice>,
    /// Registered drivers
    drivers: Vec<Box<dyn BusDriver>>,
    /// Probed device instances
    probed_devices: Vec<Box<dyn Device>>,
}

impl PlatformBus {
    /// Create a new platform bus with the given devices
    pub fn new(devices: Vec<PlatformDevice>) -> Self {
        Self {
            devices,
            drivers: Vec::new(),
            probed_devices: Vec::new(),
        }
    }
}

impl Bus for PlatformBus {
    fn name(&self) -> &str {
        "platform"
    }

    fn register_driver(&mut self, driver: Box<dyn BusDriver>) {
        printkln!("platform: Registering driver '{}'", driver.name());
        self.drivers.push(driver);
    }

    fn enumerate(&mut self, ctx: &mut BusContext) {
        printkln!("platform: Enumerating {} devices", self.devices.len());

        for device in &self.devices {
            // Try to match against registered drivers
            let mut matched = false;
            for driver in &self.drivers {
                if driver.matches(device) {
                    printkln!(
                        "platform: Probing {} with {}",
                        device.compatible(),
                        driver.name()
                    );
                    match driver.probe(device, ctx) {
                        Ok(dev) => {
                            printkln!("platform: {} probed successfully", device.compatible());
                            self.probed_devices.push(dev);
                            matched = true;
                            break;
                        }
                        Err(e) => {
                            printkln!("platform: Failed to probe {}: {:?}", device.compatible(), e);
                        }
                    }
                }
            }
            if !matched {
                printkln!("platform: No driver for {}", device.compatible());
            }
        }
    }

    fn is_root(&self) -> bool {
        true
    }

    fn probed_devices(&self) -> &[Box<dyn Device>] {
        &self.probed_devices
    }
}

/// Trait for platform bus drivers
///
/// Platform drivers match devices by compatible string and probe them
/// using the device's fixed resources.
pub trait PlatformBusDriver: Send + Sync {
    /// Driver name
    fn name(&self) -> &str;

    /// Compatible strings this driver supports
    fn compatible(&self) -> &'static [&'static str];

    /// Probe a platform device
    fn probe_platform(
        &self,
        device: &PlatformDevice,
        ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError>;
}

/// Helper macro to implement BusDriver for PlatformBusDriver types
#[macro_export]
macro_rules! impl_platform_bus_driver {
    ($driver:ty) => {
        impl $crate::bus::BusDriver for $driver {
            fn name(&self) -> &str {
                <Self as $crate::bus::platform::PlatformBusDriver>::name(self)
            }

            fn matches(&self, device: &dyn $crate::bus::BusDevice) -> bool {
                use $crate::bus::platform::PlatformBusDriver;
                if let Some(platform_dev) = device
                    .as_any()
                    .downcast_ref::<$crate::bus::PlatformDevice>()
                {
                    self.compatible().contains(&platform_dev.compatible())
                } else {
                    false
                }
            }

            fn probe(
                &self,
                device: &dyn $crate::bus::BusDevice,
                ctx: &mut $crate::bus::BusContext,
            ) -> Result<
                alloc::boxed::Box<dyn $crate::bus::driver::Device>,
                $crate::bus::driver::DriverError,
            > {
                use $crate::bus::platform::PlatformBusDriver;
                let platform_dev = device
                    .as_any()
                    .downcast_ref::<$crate::bus::PlatformDevice>()
                    .ok_or($crate::bus::driver::DriverError::Unsupported)?;
                self.probe_platform(platform_dev, ctx)
            }
        }
    };
}
