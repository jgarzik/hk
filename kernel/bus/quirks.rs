//! PCI fixups (Linux drivers/pci/quirks.c, DECLARE_PCI_FIXUP_*)
//!
//! A fixup runs on every PCI function that matches its vendor, device and
//! class, before any driver probes it. The final fixups
//! (DECLARE_PCI_FIXUP_FINAL) run once a bus is scanned and its BARs
//! assigned and decoding: firmware hand-offs and chipset workarounds that
//! must happen whether or not a driver for the device exists. Each hook
//! also gets every function of the bus, for companion-device checks.
//!
//! Locking: run during bus enumeration, which is single-threaded (boot).

use super::pci::PciDevice;

/// Match any vendor or device ID (Linux PCI_ANY_ID)
pub const ANY_ID: Option<u16> = None;

/// One fixup (Linux struct pci_fixup)
pub struct PciFixup {
    pub vendor: Option<u16>,
    pub device: Option<u16>,
    /// Class code to match after shifting the function's 24-bit class
    /// right by `class_shift` (Linux DECLARE_PCI_FIXUP_CLASS_*)
    pub class: u32,
    pub class_shift: u8,
    pub hook: fn(dev: &PciDevice, all: &[PciDevice]),
}

impl PciFixup {
    fn matches(&self, dev: &PciDevice) -> bool {
        self.vendor.is_none_or(|v| v == dev.header.vendor_id)
            && self.device.is_none_or(|d| d == dev.header.device_id)
            && dev.class24() >> self.class_shift == self.class
    }
}

/// The final fixups, in order
static FIXUPS_FINAL: &[PciFixup] = &[crate::usb::pci_quirks::EARLY_HANDOFF];

/// Run the final fixups on each function of a scanned bus (Linux
/// pci_fixup_device(pci_fixup_final, ...) from pci_bus_add_device)
pub fn fixup_final(devices: &[PciDevice]) {
    for dev in devices {
        for f in FIXUPS_FINAL.iter().filter(|f| f.matches(dev)) {
            (f.hook)(dev, devices);
        }
    }
}
