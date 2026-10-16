//! Virtio core: device status, feature negotiation, driver registry
//!
//! Linux reference: drivers/virtio/virtio.c; virtio 1.2 sections 2-3.
//!
//! Transports (`pci`: modern virtio-PCI only, no legacy) discover a device,
//! negotiate features against the driver registered for its device ID and
//! hand the driver an `Arc<VirtioDevice>`. Drivers set up their queues
//! (`setup_vq`), register an interrupt callback (`request_irq`) and call
//! `ready()` (DRIVER_OK). Queues are split rings (`ring`) in coherent DMA
//! memory, addressed only through the DMA API.

pub mod pci;
pub mod ring;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::spin::Mutex;

use crate::bus::driver::{Device, DriverError};

pub use pci::{VirtioDevice, VirtioPciDriver, Virtqueue};

/// Device status bits (virtio 1.2 section 2.1)
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const NEEDS_RESET: u8 = 0x40;
    pub const FAILED: u8 = 0x80;
}

/// Device-independent feature bits (virtio 1.2 section 6)
pub mod feature {
    pub const VERSION_1: u32 = 32;
    pub const ACCESS_PLATFORM: u32 = 33;
}

/// Device IDs (virtio 1.2 section 5)
pub mod id {
    pub const NET: u32 = 1;
    pub const BLOCK: u32 = 2;
}

/// Transport feature bits a driver always accepts when offered
///
/// VERSION_1 is required (no legacy). ACCESS_PLATFORM (the device's DMA
/// goes through platform translation) is accepted when offered, as Linux
/// does: every address hk gives a device comes from the DMA API, which is
/// correct both with and without it.
pub fn transport_features() -> u64 {
    (1 << feature::VERSION_1) | (1 << feature::ACCESS_PLATFORM)
}

/// Features to accept: what both sides support
pub fn negotiate(device: u64, driver: u64) -> Result<u64, DriverError> {
    let f = device & (driver | transport_features());
    if f & (1 << feature::VERSION_1) == 0 {
        return Err(DriverError::Unsupported);
    }
    Ok(f)
}

/// Interrupt callbacks of a virtio driver (IRQ context: lock-free only)
pub trait VirtioIrq: Send + Sync {
    /// A used buffer may be available on some queue
    fn vq_interrupt(&self);
    /// The device configuration changed
    fn config_changed(&self);
}

/// A driver for one virtio device type (Linux struct virtio_driver)
pub trait VirtioDriver: Send + Sync {
    fn name(&self) -> &'static str;
    /// Virtio device ID handled
    fn device_id(&self) -> u32;
    /// Device-specific feature bits the driver supports
    fn features(&self) -> u64;
    /// Bind to a device whose features are negotiated (FEATURES_OK set);
    /// the driver must call `ready()` before returning success
    fn probe(&self, vdev: Arc<VirtioDevice>) -> Result<Box<dyn Device>, DriverError>;
}

/// Registered virtio drivers (written at boot before bus enumeration)
static DRIVERS: Mutex<Vec<&'static dyn VirtioDriver>> = Mutex::new(Vec::new());

/// Register a virtio driver (Linux register_virtio_driver)
pub fn register_driver(drv: &'static dyn VirtioDriver) {
    DRIVERS.lock().push(drv);
}

/// The driver for device ID `id`
pub fn find_driver(id: u32) -> Option<&'static dyn VirtioDriver> {
    DRIVERS.lock().iter().copied().find(|d| d.device_id() == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_requires_version_1() {
        let v1 = 1u64 << feature::VERSION_1;
        let ap = 1u64 << feature::ACCESS_PLATFORM;
        let mac = 1u64 << 5;
        assert!(negotiate(mac, mac).is_err());
        assert_eq!(negotiate(v1 | mac | (1 << 15), mac).unwrap(), v1 | mac);
        assert_eq!(negotiate(v1 | ap, 0).unwrap(), v1 | ap);
        // Never accept what the device does not offer
        assert_eq!(negotiate(v1, mac).unwrap(), v1);
    }
}
