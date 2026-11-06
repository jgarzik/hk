//! The platform bus (Linux drivers/base/platform.c): devices with fixed
//! resources, below /sys/devices/platform, matched by name or DT
//! compatible string.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Once;

use super::bus::BusType;
use super::core::{Device, DeviceInfo, device_create};
use super::driver::Driver;
use crate::fs::KernelError;
use crate::util::kalloc::try_arc;

pub static PLATFORM_BUS: BusType = BusType::new("platform", platform_match, Some(platform_uevent));

/// /sys/devices/platform (Linux platform_bus)
static PLATFORM_ROOT: Once<Arc<Device>> = Once::new();

/// Linux platform_bus_init
pub fn platform_bus_init() {
    PLATFORM_ROOT
        .call_once(|| device_create(DeviceInfo::named("platform")).expect("/sys/devices/platform"));
    PLATFORM_BUS.register();
}

/// A platform device's resources (Linux struct platform_device)
pub struct PlatformDevice {
    /// Driver-matching name (Linux pdev->name)
    pub name: &'static str,
    /// DT compatible strings, most specific first
    pub compatible: &'static [&'static str],
    /// Base I/O port or MMIO address
    pub base: Option<u64>,
    pub irq: Option<u32>,
}

/// A platform driver's id table: device names or DT compatible strings
pub struct Names(pub &'static [&'static str]);

/// The platform resources of `dev`
pub fn pdev(dev: &Device) -> Option<&PlatformDevice> {
    dev.data::<PlatformDevice>()
}

/// Linux platform_match: a DT compatible string, else the name
fn platform_match(dev: &Device, drv: &'static Driver) -> bool {
    let Some(p) = pdev(dev) else { return false };
    let Some(Names(names)) = drv.ids.downcast_ref::<Names>() else {
        return false;
    };
    if !p.compatible.is_empty() {
        return p.compatible.iter().any(|c| names.contains(c));
    }
    names.contains(&p.name)
}

/// Linux platform_uevent: MODALIAS=of:N..T..C.. for DT devices (Linux
/// of_device_uevent_modalias), else platform:<name>
fn platform_uevent(dev: &Device, env: &mut Vec<Vec<u8>>) {
    let Some(p) = pdev(dev) else { return };
    if p.compatible.is_empty() {
        env.push(format!("MODALIAS=platform:{}", p.name).into_bytes());
        return;
    }
    let mut m = format!("MODALIAS=of:N{}T(null)", p.name);
    for c in p.compatible {
        m.push('C');
        m.push_str(c);
    }
    env.push(m.into_bytes());
}

/// Register `p` as `<base>.<name>` for DT devices, else `name` (Linux
/// platform_device_register, PLATFORM_DEVID_NONE / of_device_make_bus_id)
pub fn platform_device_register(p: PlatformDevice) -> Result<Arc<Device>, KernelError> {
    let name: String = match (p.compatible.is_empty(), p.base) {
        (false, Some(b)) => format!("{:x}.{}", b, p.name),
        _ => p.name.into(),
    };
    let root = PLATFORM_ROOT.get().ok_or(KernelError::NoDevice)?;
    device_create(DeviceInfo {
        parent: Some(root),
        bus: Some(&PLATFORM_BUS),
        data: Some(try_arc(p)?),
        ..DeviceInfo::named(&name)
    })
}
