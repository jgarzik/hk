//! USB host controller hand-off from firmware (Linux
//! drivers/usb/host/pci-quirks.c, quirk_usb_early_handoff)
//!
//! Boot firmware drives the USB controllers itself (USB keyboard, boot
//! from a USB disk) and keeps doing so after the OS starts: "USB legacy
//! support" emulates a PS/2 keyboard from System Management Mode, entered
//! through SMIs the controllers raise. An OS that resets a controller
//! underneath it leaves an SMI handler working on state that no longer
//! exists, which can hang every CPU in SMM. So before any driver probes
//! (a final PCI fixup), every USB controller is taken over: the OS asks
//! for ownership through the controller's semaphore, waits for the
//! firmware to let go, turns off its SMIs, and halts the controller.
//!
//! xHCI and EHCI are handled; UHCI and OHCI (USB 1.1 companions, gone
//! from current chipsets) are not.
//!
//! Locking: runs during bus enumeration (single-threaded, boot).

use crate::arch::{CurrentArch, IoremapOps};
use crate::bus::pci::PciDevice;
use crate::bus::{BusDevice, pci};
use crate::delay::{Clock, Monotonic, poll_on};
use crate::printkln;

use super::ext_caps::{self, Mmio};
use super::xhci::{PCI_VENDOR_INTEL, XHCI_IRQS, XHCI_MAX_HALT_US};

/// Programming interfaces of class 0x0c03 (serial bus, USB)
const PROG_IF_EHCI: u8 = 0x20;
const PROG_IF_XHCI: u8 = 0x30;

/// The final fixup for every USB controller (Linux
/// DECLARE_PCI_FIXUP_CLASS_FINAL(PCI_ANY_ID, PCI_ANY_ID,
/// PCI_CLASS_SERIAL_USB, 8, quirk_usb_early_handoff))
pub const EARLY_HANDOFF: crate::bus::quirks::PciFixup = crate::bus::quirks::PciFixup {
    vendor: crate::bus::quirks::ANY_ID,
    device: crate::bus::quirks::ANY_ID,
    class: 0x0c03,
    class_shift: 8,
    hook: quirk_usb_early_handoff,
};

/// Take a USB controller over from the firmware (Linux
/// quirk_usb_early_handoff)
fn quirk_usb_early_handoff(dev: &PciDevice, all: &[PciDevice]) {
    if !matches!(dev.header.prog_if, PROG_IF_EHCI | PROG_IF_XHCI) {
        return;
    }
    // Its registers must decode (Linux mmio_resource_enabled)
    let mem = dev.cfg_read16(0x04) & pci::command::MEMORY_SPACE != 0;
    let Some(bar) = mem.then(|| Bar::map(dev)).flatten() else {
        printkln!(
            "{}: USB BIOS handoff skipped: BAR0 not decoding",
            dev.bus_id()
        );
        return;
    };
    if dev.header.prog_if == PROG_IF_EHCI {
        quirk_usb_disable_ehci(dev, &bar);
    } else {
        quirk_usb_handoff_xhci(dev, all, &bar);
    }
}

/// PCI config space of one function (the device, or a host-test double)
pub trait Config {
    fn read32(&self, off: u8) -> u32;
    fn write32(&self, off: u8, val: u32);
    fn write8(&self, off: u8, val: u8);
}

impl Config for PciDevice {
    fn read32(&self, off: u8) -> u32 {
        self.cfg_read32(off)
    }
    fn write32(&self, off: u8, val: u32) {
        self.cfg_write32(off, val)
    }
    fn write8(&self, off: u8, val: u8) {
        self.cfg_write8(off, val)
    }
}

/// A mapped memory BAR, unmapped on drop
struct Bar {
    virt: *mut u8,
    len: u32,
}

impl Bar {
    /// Map BAR0 of `dev`
    fn map(dev: &PciDevice) -> Option<Self> {
        let phys = dev.bar_address(0).filter(|&a| a != 0)?;
        let len = dev.bar_size(0).min(u32::MAX as u64);
        if len < 0x100 || !dev.bar_is_mmio(0) {
            return None;
        }
        let virt = CurrentArch::ioremap(phys, len).ok()?;
        Some(Self {
            virt,
            len: len as u32,
        })
    }
}

impl Drop for Bar {
    fn drop(&mut self) {
        CurrentArch::iounmap(self.virt, self.len as u64);
    }
}

impl Mmio for Bar {
    fn read32(&self, off: u32) -> u32 {
        debug_assert!(off + 4 <= self.len);
        // SAFETY: inside the mapping (callers check against len)
        unsafe { core::ptr::read_volatile(self.virt.add(off as usize) as *const u32) }
    }

    fn write32(&self, off: u32, val: u32) {
        debug_assert!(off + 4 <= self.len);
        // SAFETY: as read32
        unsafe { core::ptr::write_volatile(self.virt.add(off as usize) as *mut u32, val) }
    }

    fn len(&self) -> u32 {
        self.len
    }
}

// ---------------------------------------------------------------------------
// xHCI (xHCI spec 7.1, USB Legacy Support Capability; Linux
// quirk_usb_handoff_xhci)

/// USBLEGSUP: HC BIOS Owned and HC OS Owned semaphores
const XHCI_HC_BIOS_OWNED: u32 = 1 << 16;
const XHCI_HC_OS_OWNED: u32 = 1 << 24;

/// USBLEGCTLSTS, the second dword of the capability
const XHCI_LEGACY_CONTROL: u32 = 4;

/// USBLEGCTLSTS bits kept when turning SMIs off: the reserved ones. The
/// SMI enables (bits 0, 4, 13-16) are cleared (Linux
/// XHCI_LEGACY_DISABLE_SMI)
const XHCI_LEGACY_DISABLE_SMI: u32 = (0x7 << 1) + (0xff << 5) + (0x7 << 17);

/// USBLEGCTLSTS SMI event status bits, write-1-to-clear (Linux
/// XHCI_LEGACY_SMI_EVENTS)
const XHCI_LEGACY_SMI_EVENTS: u32 = 0x7 << 29;

/// Operational registers: USBCMD and USBSTS
const XHCI_CMD: u32 = 0x00;
const XHCI_STS: u32 = 0x04;
const XHCI_CMD_RUN: u32 = 1 << 0;
const XHCI_STS_HALT: u32 = 1 << 0;
const XHCI_STS_CNR: u32 = 1 << 11;

/// Wait for the firmware to release the controller (Linux: 1 s, polled
/// every 10 us)
const XHCI_HANDOFF_US: u64 = 1_000_000;
/// Wait for Controller Not Ready to clear (Linux: 5 s)
const XHCI_CNR_US: u64 = 5_000_000;

/// What the xHCI hand-off found and did, for the report
#[derive(Debug, Default, PartialEq, Eq)]
pub struct XhciHandoff {
    /// Offset of the USB Legacy Support capability (0: none)
    pub legacy: u32,
    /// USBLEGSUP as found
    pub legsup: u32,
    /// The firmware owned the controller and released it when asked
    /// (false: it had to be taken)
    pub released: bool,
    /// USBLEGCTLSTS before and after turning the SMIs off
    pub smi: (u32, u32),
    /// Controller Not Ready cleared in time
    pub ready: bool,
    /// The controller halted in time
    pub halted: bool,
}

/// Take an xHCI controller over (Linux quirk_usb_handoff_xhci): with a
/// legacy capability, set the OS semaphore and wait for the BIOS one to
/// clear (else take it), then disable and acknowledge every SMI; in any
/// case wait for the controller to be ready, then halt it with its
/// interrupts off. `force`: controllers whose firmware never answers
/// (TI 8241, Renesas 0014) are taken outright. `hc_init` runs once the
/// firmware is out, before the controller is touched (Linux hc_init:
/// the Intel port switch).
pub fn handoff_xhci(
    r: &impl Mmio,
    clock: &mut impl Clock,
    force: bool,
    hc_init: impl FnOnce(),
) -> XhciHandoff {
    let mut out = XhciHandoff::default();
    let ext = ext_caps::find_ext_cap(r, 0, ext_caps::CAP_LEGACY);
    if ext != 0 && ext + 8 <= r.len() {
        out.legacy = ext;
        let mut val = r.read32(ext);
        out.legsup = val;
        if force {
            val = (val | XHCI_HC_OS_OWNED) & !XHCI_HC_BIOS_OWNED;
            r.write32(ext, val);
        }
        if val & XHCI_HC_BIOS_OWNED != 0 {
            r.write32(ext, val | XHCI_HC_OS_OWNED);
            let done = || r.read32(ext) & XHCI_HC_BIOS_OWNED == 0;
            out.released = poll_on(clock, XHCI_HANDOFF_US, 10, done).is_ok();
            if !out.released {
                // A BIOS that never answers: take the controller anyway
                // (Linux clears only BIOS_OWNED; OS_OWNED stays set here,
                // the state a completed hand-off leaves)
                r.write32(ext, (val | XHCI_HC_OS_OWNED) & !XHCI_HC_BIOS_OWNED);
            }
        }
        let ctl = r.read32(ext + XHCI_LEGACY_CONTROL);
        let off = (ctl & XHCI_LEGACY_DISABLE_SMI) | XHCI_LEGACY_SMI_EVENTS;
        r.write32(ext + XHCI_LEGACY_CONTROL, off);
        out.smi = (ctl, r.read32(ext + XHCI_LEGACY_CONTROL));
    }
    hc_init();
    halt_xhci(r, clock, &mut out);
    out
}

/// Wait for the controller to be ready, then stop it with interrupts
/// off (Linux quirk_usb_handoff_xhci from hc_init)
fn halt_xhci(r: &impl Mmio, clock: &mut impl Clock, out: &mut XhciHandoff) {
    let op = r.read32(0) & 0xff;
    if op + 8 > r.len() {
        return;
    }
    // No operational register but USBSTS may be written before CNR
    // clears
    let ready = || r.read32(op + XHCI_STS) & XHCI_STS_CNR == 0;
    out.ready = poll_on(clock, XHCI_CNR_US, 10, ready).is_ok();
    let cmd = r.read32(op + XHCI_CMD);
    r.write32(op + XHCI_CMD, cmd & !(XHCI_CMD_RUN | XHCI_IRQS));
    let halted = || r.read32(op + XHCI_STS) & XHCI_STS_HALT != 0;
    out.halted = poll_on(clock, XHCI_MAX_HALT_US, 125, halted).is_ok();
}

/// Controllers whose firmware never completes the hand-off (Linux
/// quirk_usb_handoff_xhci: TI 8241, Renesas 0014)
fn xhci_force_handoff(dev: &PciDevice) -> bool {
    matches!(
        (dev.header.vendor_id, dev.header.device_id),
        (0x104c, 0x8241) | (0x1912, 0x0014)
    )
}

fn quirk_usb_handoff_xhci(dev: &PciDevice, all: &[PciDevice], bar: &Bar) {
    let mut ports = None;
    let switch = || {
        if dev.header.vendor_id == PCI_VENDOR_INTEL {
            ports = usb_enable_intel_xhci_ports(dev, all);
        }
    };
    let h = handoff_xhci(bar, &mut Monotonic::new(), xhci_force_handoff(dev), switch);
    let id = dev.bus_id();
    if let Some((ss, hs)) = ports {
        printkln!(
            "{}: xHCI: ports switched from EHCI: USB3_PSSEN {:#x} XUSB2PR {:#x}",
            id,
            ss,
            hs
        );
    }
    if h.legacy == 0 {
        printkln!("{}: xHCI: no legacy support capability", id);
    } else if h.legsup & XHCI_HC_BIOS_OWNED == 0 {
        printkln!(
            "{}: xHCI: not BIOS-owned (USBLEGSUP {:#010x})",
            id,
            h.legsup
        );
    } else if h.released {
        printkln!("{}: xHCI: BIOS handoff done", id);
    } else {
        printkln!(
            "{}: xHCI BIOS handoff failed (BIOS bug?) {:#010x}",
            id,
            h.legsup
        );
    }
    if h.legacy != 0 {
        printkln!(
            "{}: xHCI: SMIs off: USBLEGCTLSTS {:#010x} -> {:#010x}",
            id,
            h.smi.0,
            h.smi.1
        );
    }
    if !h.ready {
        printkln!("{}: xHCI HW not ready after 5 sec (HC bug?)", id);
    }
    if !h.halted {
        printkln!(
            "{}: xHCI HW did not halt within {} usec",
            id,
            XHCI_MAX_HALT_US
        );
    }
}

// ---------------------------------------------------------------------------
// Intel EHCI/xHCI port routing (Linux usb_enable_intel_xhci_ports)
//
// Intel chipsets from Panther Point on (the Dell's Lynx Point included)
// pair an xHCI with EHCI controllers that share ports; each port is
// routed to one of them by xHCI config registers, and firmware leaves
// them on EHCI. hk drives the xHCI only, so devices on routed ports
// would be invisible: switch every switchable port to the xHCI, the
// SuperSpeed terminations first so USB 3 devices connect at
// SuperSpeed, before any driver probes.

/// xHC USB 2.0 Port Routing, and the mask of ports the OS may route
const USB_INTEL_XUSB2PR: u8 = 0xD0;
const USB_INTEL_USB2PRM: u8 = 0xD4;
/// USB 3.0 Port SuperSpeed Enable, and the mask of ports the OS may
/// enable
const USB_INTEL_USB3_PSSEN: u8 = 0xD8;
const USB_INTEL_USB3PRM: u8 = 0xDC;

/// The class of an EHCI controller (Linux PCI_CLASS_SERIAL_USB_EHCI)
const CLASS_EHCI: u32 = 0x0c0320;

/// Route the switchable ports to the xHCI: (USB3_PSSEN, XUSB2PR) as
/// read back
pub fn switch_intel_ports(cfg: &impl Config) -> (u32, u32) {
    let ss = cfg.read32(USB_INTEL_USB3PRM);
    cfg.write32(USB_INTEL_USB3_PSSEN, ss);
    let ss = cfg.read32(USB_INTEL_USB3_PSSEN);
    let hs = cfg.read32(USB_INTEL_USB2PRM);
    cfg.write32(USB_INTEL_XUSB2PR, hs);
    (ss, cfg.read32(USB_INTEL_XUSB2PR))
}

/// Route ports back to EHCI (Linux usb_disable_xhci_ports)
pub fn disable_intel_ports(cfg: &impl Config) {
    cfg.write32(USB_INTEL_USB3_PSSEN, 0);
    cfg.write32(USB_INTEL_XUSB2PR, 0);
}

/// Switch an Intel xHCI's ports over, if an Intel EHCI shares them
/// (Linux usb_enable_intel_xhci_ports). Sony VAIO T-series (subsystem
/// 104d:90a8) cannot switch.
fn usb_enable_intel_xhci_ports(xhci: &PciDevice, all: &[PciDevice]) -> Option<(u32, u32)> {
    let h = &xhci.header;
    if (h.subsystem_vendor_id, h.subsystem_id) == (0x104d, 0x90a8) {
        return None;
    }
    let ehci = |d: &PciDevice| d.class24() == CLASS_EHCI && d.header.vendor_id == PCI_VENDOR_INTEL;
    all.iter().any(ehci).then(|| switch_intel_ports(xhci))
}

// ---------------------------------------------------------------------------
// EHCI (EHCI spec 2.1.7-2.1.8 and 5.1, USBLEGSUP/USBLEGCTLSTS in config
// space; Linux quirk_usb_disable_ehci, ehci_bios_handoff)

/// HCCPARAMS (capability register): EHCI Extended Capabilities Pointer
/// in bits 15:8, a config space offset
const EHCI_HCC_PARAMS: u32 = 0x08;
/// Extended capability ID of USBLEGSUP
const EHCI_CAP_LEGACY: u32 = 1;
/// USBLEGSUP: HC BIOS Owned semaphore (bit 16, byte 2) and HC OS Owned
/// semaphore (bit 24, byte 3)
const EHCI_USBLEGSUP_BIOS: u32 = 1 << 16;
/// USBLEGCTLSTS: SMI enables and status, after USBLEGSUP
const EHCI_USBLEGCTLSTS: u8 = 4;
/// Operational registers
const EHCI_USBCMD: u32 = 0x00;
const EHCI_USBSTS: u32 = 0x04;
const EHCI_USBINTR: u32 = 0x08;
const EHCI_CONFIGFLAG: u32 = 0x40;
const EHCI_USBCMD_RUN: u32 = 1 << 0;
const EHCI_USBSTS_HALTED: u32 = 1 << 12;
/// USBSTS interrupt status bits, write-1-to-clear
const EHCI_USBSTS_INTS: u32 = 0x3f;

/// Wait for the firmware to release the controller (Linux: 1 s, every
/// 10 ms)
const EHCI_HANDOFF_US: u64 = 1_000_000;
const EHCI_HANDOFF_POLL_US: u64 = 10_000;
/// Wait for the halt (Linux: 2 ms, every 100 us)
const EHCI_HALT_US: u64 = 2_000;

/// What the EHCI hand-off found and did, for the report
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EhciHandoff {
    /// Config offset of USBLEGSUP (0: none)
    pub legacy: u8,
    /// The firmware owned the controller
    pub bios_owned: bool,
    /// ... and released it when asked (false: it had to be taken)
    pub released: bool,
    /// Extended capabilities with other IDs (reported, skipped)
    pub unknown: u32,
    /// The controller halted in time
    pub halted: bool,
}

/// Take an EHCI controller over (Linux quirk_usb_disable_ehci): hand off
/// through each USBLEGSUP in the extended capability list, then halt
/// the controller and disable its interrupts
pub fn handoff_ehci(r: &impl Mmio, cfg: &impl Config, clock: &mut impl Clock) -> EhciHandoff {
    let mut out = EhciHandoff::default();
    let op = r.read32(0) & 0xff;
    if op + EHCI_CONFIGFLAG + 4 > r.len() {
        return out;
    }
    // The list lives in config space after the standard header; at most
    // 64 entries (Linux: count = 256/4)
    let mut offset = ((r.read32(EHCI_HCC_PARAMS) >> 8) & 0xff) as u8;
    for _ in 0..64 {
        if offset < 0x40 {
            break;
        }
        let cap = cfg.read32(offset);
        match cap & 0xff {
            EHCI_CAP_LEGACY => ehci_bios_handoff(r, op, cfg, offset, cap, clock, &mut out),
            0 => break, // reserved ID: a broken list
            _ => out.unknown += 1,
        }
        offset = (cap >> 8) as u8;
    }
    halt_ehci(r, op, clock, &mut out);
    out
}

/// Hand-off through the USBLEGSUP at config `offset` (Linux
/// ehci_bios_handoff). Linux skips it on a few ancient boards (a DMI
/// table for ICH 283a/27cc tablets that hang on the semaphore); none is
/// a hk target.
fn ehci_bios_handoff(
    r: &impl Mmio,
    op: u32,
    cfg: &impl Config,
    offset: u8,
    mut cap: u32,
    clock: &mut impl Clock,
    out: &mut EhciHandoff,
) {
    out.legacy = offset;
    out.bios_owned = cap & EHCI_USBLEGSUP_BIOS != 0;
    if out.bios_owned {
        // The OS semaphore alone, by a byte write: some firmware gets
        // upset when the semaphores are written for any other reason
        cfg.write8(offset + 3, 1);
        let done = || {
            cap = cfg.read32(offset);
            cap & EHCI_USBLEGSUP_BIOS == 0
        };
        out.released = poll_on(clock, EHCI_HANDOFF_US, EHCI_HANDOFF_POLL_US, done).is_ok();
        if !out.released {
            // A buggy BIOS: clear its semaphore and hope for the best
            cfg.write8(offset + 2, 0);
        }
    }
    // Always disable the SMIs
    cfg.write32(offset + EHCI_USBLEGCTLSTS, 0);
    // Firmware ran the ports: their power sessions are not to be trusted
    if out.bios_owned {
        r.write32(op + EHCI_CONFIGFLAG, 0);
    }
}

/// Halt the controller and disable and acknowledge its interrupts, in
/// any case (Linux quirk_usb_disable_ehci)
fn halt_ehci(r: &impl Mmio, op: u32, clock: &mut impl Clock, out: &mut EhciHandoff) {
    let sts = r.read32(op + EHCI_USBSTS);
    if sts & EHCI_USBSTS_HALTED == 0 {
        let cmd = r.read32(op + EHCI_USBCMD);
        r.write32(op + EHCI_USBCMD, cmd & !EHCI_USBCMD_RUN);
        let halted = || {
            r.write32(op + EHCI_USBSTS, EHCI_USBSTS_INTS);
            let sts = r.read32(op + EHCI_USBSTS);
            sts == !0 || sts & EHCI_USBSTS_HALTED != 0
        };
        out.halted = poll_on(clock, EHCI_HALT_US, 100, halted).is_ok();
    } else {
        out.halted = true;
    }
    r.write32(op + EHCI_USBINTR, 0);
    r.write32(op + EHCI_USBSTS, EHCI_USBSTS_INTS);
}

fn quirk_usb_disable_ehci(dev: &PciDevice, bar: &Bar) {
    let h = handoff_ehci(bar, dev, &mut Monotonic::new());
    let id = dev.bus_id();
    if h.unknown != 0 {
        printkln!("{}: EHCI: {} unrecognized capabilities", id, h.unknown);
    }
    if h.legacy == 0 {
        printkln!("{}: EHCI: no legacy support capability", id);
    } else if !h.bios_owned {
        printkln!("{}: EHCI: not BIOS-owned, SMIs off", id);
    } else if h.released {
        printkln!("{}: EHCI: BIOS handoff done, SMIs off", id);
    } else {
        printkln!("{}: EHCI: BIOS handoff failed (BIOS bug?), SMIs off", id);
    }
    if !h.halted {
        printkln!("{}: EHCI: did not halt within {} usec", id, EHCI_HALT_US);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delay::tests::FakeClock;
    use crate::usb::ext_caps::tests::FakeRegs;
    use core::cell::Cell;

    const LEG: u32 = 0x500;
    const OP: u32 = 0x80;

    /// An xHCI whose firmware lets go `release_after` reads after the OS
    /// asks (None: never), and that halts when RUN is cleared
    struct FakeXhci {
        regs: FakeRegs,
        release_after: Option<u32>,
        reads: Cell<u32>,
    }

    impl FakeXhci {
        fn new(legsup: Option<u32>, release_after: Option<u32>) -> Self {
            let regs = FakeRegs::new(0x1000);
            regs.set(0, OP); // CAPLENGTH
            regs.set(OP + XHCI_CMD, XHCI_CMD_RUN | XHCI_IRQS);
            if let Some(l) = legsup {
                regs.set(ext_caps::HCC_PARAMS1, (LEG / 4) << 16);
                regs.set(LEG, l | ext_caps::CAP_LEGACY as u32);
                regs.set(LEG + 4, 0xe001_e011); // SMIs on, events pending
            }
            Self {
                regs,
                release_after,
                reads: Cell::new(0),
            }
        }
    }

    impl Mmio for FakeXhci {
        fn read32(&self, off: u32) -> u32 {
            let v = self.regs.get(off);
            if off == LEG && v & XHCI_HC_OS_OWNED != 0 {
                self.reads.set(self.reads.get() + 1);
                if self.release_after.is_some_and(|n| self.reads.get() >= n) {
                    self.regs.set(LEG, v & !XHCI_HC_BIOS_OWNED);
                }
            }
            self.regs.get(off)
        }
        fn write32(&self, off: u32, val: u32) {
            if off == LEG + 4 {
                // RW1C event bits clear, the rest is written
                self.regs.set(off, val & !XHCI_LEGACY_SMI_EVENTS);
                return;
            }
            self.regs.set(off, val);
            if off == OP + XHCI_CMD && val & XHCI_CMD_RUN == 0 {
                self.regs.set(OP + XHCI_STS, XHCI_STS_HALT);
            }
        }
        fn len(&self) -> u32 {
            self.regs.len()
        }
    }

    fn clock() -> FakeClock {
        FakeClock { now: 0, step: 1000 }
    }

    #[test]
    fn bios_releases() {
        let x = FakeXhci::new(Some(XHCI_HC_BIOS_OWNED), Some(3));
        let h = handoff_xhci(&x, &mut clock(), false, || {});
        assert_eq!(h.legacy, LEG);
        assert!(h.released && h.ready && h.halted);
        let l = x.regs.get(LEG);
        assert_eq!(
            l & (XHCI_HC_BIOS_OWNED | XHCI_HC_OS_OWNED),
            XHCI_HC_OS_OWNED
        );
        // SMI enables off, reserved bits kept, events acknowledged
        assert_eq!(x.regs.get(LEG + 4), 0xe001_e011 & XHCI_LEGACY_DISABLE_SMI);
        assert_eq!(x.regs.get(OP + XHCI_CMD) & (XHCI_CMD_RUN | XHCI_IRQS), 0);
    }

    #[test]
    fn bios_never_releases() {
        let x = FakeXhci::new(Some(XHCI_HC_BIOS_OWNED), None);
        let mut c = clock();
        let h = handoff_xhci(&x, &mut c, false, || {});
        assert!(!h.released);
        // Gave up after about a second, took it
        assert!(c.now >= 1_000_000_000 && c.now < 1_100_000_000);
        let l = x.regs.get(LEG);
        assert_eq!(
            l & (XHCI_HC_BIOS_OWNED | XHCI_HC_OS_OWNED),
            XHCI_HC_OS_OWNED
        );
        assert!(h.halted);
    }

    #[test]
    fn not_bios_owned() {
        let x = FakeXhci::new(Some(0), Some(1));
        let h = handoff_xhci(&x, &mut clock(), false, || {});
        assert!(!h.released);
        assert_eq!(x.regs.get(LEG) & XHCI_HC_OS_OWNED, 0);
        assert_eq!(x.regs.get(LEG + 4), 0xe001_e011 & XHCI_LEGACY_DISABLE_SMI);
        assert!(h.halted);
    }

    /// No legacy capability (QEMU's xHCI): only the halt
    #[test]
    fn no_legacy_cap() {
        let x = FakeXhci::new(None, None);
        let h = handoff_xhci(&x, &mut clock(), false, || {});
        assert_eq!(h.legacy, 0);
        assert!(h.ready && h.halted);
        assert_eq!(x.regs.get(OP + XHCI_CMD) & XHCI_CMD_RUN, 0);
    }

    #[test]
    fn forced() {
        let x = FakeXhci::new(Some(XHCI_HC_BIOS_OWNED), None);
        let mut c = clock();
        let h = handoff_xhci(&x, &mut c, true, || {});
        assert_eq!(x.regs.get(LEG) & XHCI_HC_BIOS_OWNED, 0);
        assert!(c.now < 1_000_000_000); // no wait
        assert!(h.halted);
    }

    /// Controller Not Ready never clears: waits 5 s, halts anyway
    #[test]
    fn never_ready() {
        let x = FakeXhci::new(None, None);
        x.regs.set(OP + XHCI_STS, XHCI_STS_CNR);
        let mut c = clock();
        let h = handoff_xhci(&x, &mut c, false, || {});
        assert!(!h.ready && h.halted);
        assert!(c.now >= 5_000_000_000);
    }

    const EECP: u8 = 0x68;
    const EOP: u32 = 0x20;

    /// EHCI config space: USBLEGSUP at EECP; the firmware lets go
    /// `release_after` reads after the OS asks (None: never)
    struct FakeCfg {
        mem: core::cell::RefCell<[u8; 256]>,
        release_after: Option<u32>,
        reads: Cell<u32>,
        byte_writes: core::cell::RefCell<alloc::vec::Vec<(u8, u8)>>,
    }

    impl FakeCfg {
        fn new(legsup: u32, release_after: Option<u32>) -> Self {
            let c = Self {
                mem: core::cell::RefCell::new([0; 256]),
                release_after,
                reads: Cell::new(0),
                byte_writes: core::cell::RefCell::new(alloc::vec::Vec::new()),
            };
            c.put(EECP, legsup | EHCI_CAP_LEGACY);
            c.put(EECP + 4, 0x003f_e03f); // SMIs on
            c
        }
        fn put(&self, off: u8, v: u32) {
            self.mem.borrow_mut()[off as usize..off as usize + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn get(&self, off: u8) -> u32 {
            let m = self.mem.borrow();
            u32::from_le_bytes(m[off as usize..off as usize + 4].try_into().unwrap())
        }
    }

    impl Config for FakeCfg {
        fn read32(&self, off: u8) -> u32 {
            if off == EECP && self.get(EECP) & (1 << 24) != 0 {
                self.reads.set(self.reads.get() + 1);
                if self.release_after.is_some_and(|n| self.reads.get() >= n) {
                    self.mem.borrow_mut()[EECP as usize + 2] = 0;
                }
            }
            self.get(off)
        }
        fn write32(&self, off: u8, val: u32) {
            self.put(off, val)
        }
        fn write8(&self, off: u8, val: u8) {
            self.byte_writes.borrow_mut().push((off, val));
            self.mem.borrow_mut()[off as usize] = val;
        }
    }

    /// A running EHCI that halts when RUN is cleared
    struct FakeEhci(FakeRegs);

    impl FakeEhci {
        fn new() -> Self {
            let r = FakeRegs::new(0x400);
            r.set(0, EOP);
            r.set(EHCI_HCC_PARAMS, (EECP as u32) << 8);
            r.set(EOP + EHCI_USBCMD, EHCI_USBCMD_RUN);
            r.set(EOP + EHCI_USBINTR, 0x3f);
            r.set(EOP + EHCI_CONFIGFLAG, 1);
            Self(r)
        }
    }

    impl Mmio for FakeEhci {
        fn read32(&self, off: u32) -> u32 {
            self.0.get(off)
        }
        fn write32(&self, off: u32, val: u32) {
            if off == EOP + EHCI_USBSTS {
                let v = self.0.get(off) & !(val & EHCI_USBSTS_INTS);
                self.0.set(off, v);
                return;
            }
            self.0.set(off, val);
            if off == EOP + EHCI_USBCMD && val & EHCI_USBCMD_RUN == 0 {
                self.0.set(EOP + EHCI_USBSTS, EHCI_USBSTS_HALTED);
            }
        }
        fn len(&self) -> u32 {
            self.0.len()
        }
    }

    fn ehci_halted_and_quiet(r: &FakeEhci) {
        assert_eq!(r.0.get(EOP + EHCI_USBCMD) & EHCI_USBCMD_RUN, 0);
        assert_eq!(r.0.get(EOP + EHCI_USBINTR), 0);
    }

    #[test]
    fn ehci_bios_releases() {
        let (r, c) = (FakeEhci::new(), FakeCfg::new(EHCI_USBLEGSUP_BIOS, Some(2)));
        let h = handoff_ehci(&r, &c, &mut clock());
        assert_eq!(h.legacy, EECP);
        assert!(h.bios_owned && h.released && h.halted);
        // Only the OS semaphore byte was written
        assert_eq!(*c.byte_writes.borrow(), alloc::vec![(EECP + 3, 1)]);
        assert_eq!(c.get(EECP + 4), 0);
        assert_eq!(r.0.get(EOP + EHCI_CONFIGFLAG), 0);
        ehci_halted_and_quiet(&r);
    }

    #[test]
    fn ehci_bios_never_releases() {
        let (r, c) = (FakeEhci::new(), FakeCfg::new(EHCI_USBLEGSUP_BIOS, None));
        let mut ck = clock();
        let h = handoff_ehci(&r, &c, &mut ck);
        assert!(h.bios_owned && !h.released);
        assert!(ck.now >= 1_000_000_000);
        assert_eq!(
            *c.byte_writes.borrow(),
            alloc::vec![(EECP + 3, 1), (EECP + 2, 0)]
        );
        assert_eq!(c.get(EECP + 4), 0);
        ehci_halted_and_quiet(&r);
    }

    /// Not BIOS-owned: no semaphore writes, CONFIGFLAG kept, SMIs off
    #[test]
    fn ehci_not_owned() {
        let (r, c) = (FakeEhci::new(), FakeCfg::new(0, None));
        let h = handoff_ehci(&r, &c, &mut clock());
        assert!(!h.bios_owned);
        assert!(c.byte_writes.borrow().is_empty());
        assert_eq!(c.get(EECP + 4), 0);
        assert_eq!(r.0.get(EOP + EHCI_CONFIGFLAG), 1);
        ehci_halted_and_quiet(&r);
    }

    /// No extended capabilities (QEMU's EHCI): only the halt
    #[test]
    fn ehci_no_caps() {
        let (r, c) = (FakeEhci::new(), FakeCfg::new(0, None));
        r.0.set(EHCI_HCC_PARAMS, 0);
        let h = handoff_ehci(&r, &c, &mut clock());
        assert_eq!(h.legacy, 0);
        assert_eq!(c.get(EECP + 4), 0x003f_e03f);
        ehci_halted_and_quiet(&r);
    }

    /// An unknown capability is skipped, a looping list ends
    #[test]
    fn ehci_cap_list() {
        let (r, c) = (FakeEhci::new(), FakeCfg::new(0, None));
        c.put(EECP, ((EECP as u32) << 8) | 0x0a); // unknown, points at itself
        let h = handoff_ehci(&r, &c, &mut clock());
        assert_eq!(h.legacy, 0);
        assert_eq!(h.unknown, 64);
        ehci_halted_and_quiet(&r);
    }

    /// Writable bits of the routing registers follow their masks
    struct FakePorts {
        regs: core::cell::RefCell<[u32; 4]>, // XUSB2PR, USB2PRM, PSSEN, USB3PRM
    }

    impl Config for FakePorts {
        fn read32(&self, off: u8) -> u32 {
            self.regs.borrow()[((off - 0xD0) / 4) as usize]
        }
        fn write32(&self, off: u8, val: u32) {
            let mut r = self.regs.borrow_mut();
            let i = ((off - 0xD0) / 4) as usize;
            r[i] = val & r[i + 1]; // only the masked ports take
        }
        fn write8(&self, _: u8, _: u8) {
            unreachable!()
        }
    }

    #[test]
    fn intel_port_switch() {
        let p = FakePorts {
            regs: core::cell::RefCell::new([0, 0x7fff, 0, 0x3f]),
        };
        assert_eq!(switch_intel_ports(&p), (0x3f, 0x7fff));
        disable_intel_ports(&p);
        assert_eq!(*p.regs.borrow(), [0, 0x7fff, 0, 0x3f]);
    }

    /// The hc_init hook runs after the SMIs are off, before the halt
    #[test]
    fn hc_init_order() {
        let x = FakeXhci::new(Some(XHCI_HC_BIOS_OWNED), Some(1));
        let seen = Cell::new((0, 0));
        handoff_xhci(&x, &mut clock(), false, || {
            seen.set((x.regs.get(LEG + 4), x.regs.get(OP + XHCI_CMD)))
        });
        let (smi, cmd) = seen.get();
        assert_eq!(smi, 0xe001_e011 & XHCI_LEGACY_DISABLE_SMI);
        assert_ne!(cmd & XHCI_CMD_RUN, 0);
    }
}
