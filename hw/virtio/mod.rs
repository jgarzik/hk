//! Virtio core: the virtio bus, device status, feature negotiation
//!
//! Linux reference: drivers/virtio/virtio.c; virtio 1.2 sections 2-3.
//!
//! Transports (`pci`: modern virtio-PCI only, no legacy) register each
//! device as virtio<N> on the virtio bus; binding negotiates features
//! against the matching driver and hands it an `Arc<VirtioDevice>`. Drivers set up their queues
//! (`setup_vq`), register an interrupt callback (`request_irq`) and call
//! `ready()` (DRIVER_OK). Queues are split rings (`ring`) in coherent DMA
//! memory, addressed only through the DMA API.

pub mod blk;
pub mod pci;
pub mod ring;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::base::bus::BusType;
use crate::base::{Device, DeviceInfo, Driver, device_create};
use crate::fs::kernfs;
use crate::printkln;
use crate::util::error::KernelError;

pub use pci::{VIRTIO_PCI_DRIVER, VirtioDevice, Virtqueue};

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
pub fn negotiate(device: u64, driver: u64) -> Result<u64, KernelError> {
    let f = device & (driver | transport_features());
    if f & (1 << feature::VERSION_1) == 0 {
        return Err(KernelError::NoDevice);
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
    /// Device-specific feature bits the driver supports
    fn features(&self) -> u64;
    /// Bind to a device whose features are negotiated (FEATURES_OK set);
    /// the driver must call `ready()` before returning success
    fn probe(&self, vdev: Arc<VirtioDevice>) -> Result<Box<dyn crate::base::Bound>, KernelError>;
}

/// Matches any vendor (Linux VIRTIO_DEV_ANY_ID)
pub const VIRTIO_DEV_ANY_ID: u32 = !0;

/// A virtio driver's id table and callbacks (Linux virtio_driver's
/// id_table and probe)
pub struct VirtioIds {
    /// (device id, vendor id) pairs
    pub ids: &'static [(u32, u32)],
    pub drv: &'static dyn VirtioDriver,
}

pub static VIRTIO_BUS: BusType = BusType::new("virtio", virtio_match, Some(virtio_uevent));

/// Linux virtio_init: the bus
pub fn virtio_init() {
    VIRTIO_BUS.register();
}

fn ids_of(drv: &'static Driver) -> Option<&'static VirtioIds> {
    drv.ids.downcast_ref::<VirtioIds>()
}

/// Linux virtio_dev_match / virtio_id_match
fn virtio_match(dev: &Device, drv: &'static Driver) -> bool {
    let (Some(v), Some(ids)) = (dev.data::<VirtioDevice>(), ids_of(drv)) else {
        return false;
    };
    ids.ids
        .iter()
        .any(|&(d, ven)| d == v.id() && (ven == VIRTIO_DEV_ANY_ID || ven == v.vendor()))
}

fn modalias(v: &VirtioDevice) -> String {
    format!("virtio:d{:08X}v{:08X}", v.id(), v.vendor())
}

/// Linux virtio_uevent
fn virtio_uevent(dev: &Device, env: &mut Vec<Vec<u8>>) {
    if let Some(v) = dev.data::<VirtioDevice>() {
        env.push(format!("MODALIAS={}", modalias(v)).into_bytes());
    }
}

/// Linux virtio_dev_probe: DRIVER, features, then the driver's probe
pub fn virtio_dev_probe(dev: &Arc<Device>) -> Result<Box<dyn crate::base::Bound>, KernelError> {
    let vdev = dev
        .data_arc::<VirtioDevice>()
        .ok_or(KernelError::NoDevice)?;
    let ids = dev.driver().and_then(ids_of).ok_or(KernelError::NoDevice)?;
    vdev.add_status(status::DRIVER);
    if let Err(e) = vdev.negotiate(ids.drv.features()) {
        vdev.add_status(status::FAILED);
        return Err(e);
    }
    printkln!(
        "virtio: {} ({}) device {} features {:#x}",
        dev.name(),
        vdev.bus_id(),
        vdev.id(),
        vdev.features()
    );
    ids.drv.probe(vdev.clone()).inspect_err(|_| {
        vdev.add_status(status::FAILED);
    })
}

/// A virtio device's attributes (Linux virtio_dev_groups)
fn virtio_attrs(dev: &Arc<Device>) -> Result<(), KernelError> {
    let v = dev
        .data_arc::<VirtioDevice>()
        .ok_or(KernelError::NoDevice)?;
    let text: [(&[u8], String); 3] = [
        (b"device", format!("0x{:04x}\n", v.id())),
        (b"vendor", format!("0x{:04x}\n", v.vendor())),
        (b"modalias", format!("{}\n", modalias(&v))),
    ];
    for (name, s) in text {
        dev.create_file(name, 0o444, kernfs::show(move |o| o.bytes(s.as_bytes())))?;
    }
    let st = v.clone();
    dev.create_file(
        b"status",
        0o444,
        kernfs::show(move |o| {
            let _ = writeln!(o, "0x{:08x}", st.status());
        }),
    )?;
    // Linux features_show: the first 64 bits, one digit each
    dev.create_file(
        b"features",
        0o444,
        kernfs::show(move |o| {
            let f = v.features();
            for i in 0..64 {
                o.bytes(if f & (1 << i) != 0 { b"1" } else { b"0" });
            }
            o.bytes(b"\n");
        }),
    )?;
    Ok(())
}

/// Next virtio index (Linux virtio_index_ida)
static INDEX: AtomicU32 = AtomicU32::new(0);

/// Register a transport's device as virtio<N> below it (Linux
/// register_virtio_device)
pub fn register_virtio_device(
    parent: &Arc<Device>,
    vdev: Arc<VirtioDevice>,
) -> Result<Arc<Device>, KernelError> {
    let n = INDEX.fetch_add(1, Ordering::Relaxed);
    device_create(DeviceInfo {
        parent: Some(parent),
        bus: Some(&VIRTIO_BUS),
        data: Some(vdev),
        attrs: Some(virtio_attrs),
        ..DeviceInfo::named(&format!("virtio{}", n))
    })
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
