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

/// Programming interface of class 0x0c03 (serial bus, USB)
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
fn quirk_usb_early_handoff(dev: &PciDevice, _all: &[PciDevice]) {
    if dev.header.prog_if != PROG_IF_XHCI {
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
    quirk_usb_handoff_xhci(dev, &bar);
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
/// Interrupter, host system error and wrap event enables (Linux
/// XHCI_IRQS)
const XHCI_IRQS: u32 = (1 << 2) | (1 << 3) | (1 << 10);
const XHCI_STS_HALT: u32 = 1 << 0;
const XHCI_STS_CNR: u32 = 1 << 11;

/// Wait for the firmware to release the controller (Linux: 1 s, polled
/// every 10 us)
const XHCI_HANDOFF_US: u64 = 1_000_000;
/// Wait for Controller Not Ready to clear (Linux: 5 s)
const XHCI_CNR_US: u64 = 5_000_000;
/// Wait for the halt (Linux XHCI_MAX_HALT_USEC, polled per microframe)
const XHCI_MAX_HALT_US: u64 = 32_000;

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
/// (TI 8241, Renesas 0014) are taken outright.
pub fn handoff_xhci(r: &impl Mmio, clock: &mut impl Clock, force: bool) -> XhciHandoff {
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

fn quirk_usb_handoff_xhci(dev: &PciDevice, bar: &Bar) {
    let h = handoff_xhci(bar, &mut Monotonic::new(), xhci_force_handoff(dev));
    let id = dev.bus_id();
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
        let h = handoff_xhci(&x, &mut clock(), false);
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
        let h = handoff_xhci(&x, &mut c, false);
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
        let h = handoff_xhci(&x, &mut clock(), false);
        assert!(!h.released);
        assert_eq!(x.regs.get(LEG) & XHCI_HC_OS_OWNED, 0);
        assert_eq!(x.regs.get(LEG + 4), 0xe001_e011 & XHCI_LEGACY_DISABLE_SMI);
        assert!(h.halted);
    }

    /// No legacy capability (QEMU's xHCI): only the halt
    #[test]
    fn no_legacy_cap() {
        let x = FakeXhci::new(None, None);
        let h = handoff_xhci(&x, &mut clock(), false);
        assert_eq!(h.legacy, 0);
        assert!(h.ready && h.halted);
        assert_eq!(x.regs.get(OP + XHCI_CMD) & XHCI_CMD_RUN, 0);
    }

    #[test]
    fn forced() {
        let x = FakeXhci::new(Some(XHCI_HC_BIOS_OWNED), None);
        let mut c = clock();
        let h = handoff_xhci(&x, &mut c, true);
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
        let h = handoff_xhci(&x, &mut c, false);
        assert!(!h.ready && h.halted);
        assert!(c.now >= 5_000_000_000);
    }
}
