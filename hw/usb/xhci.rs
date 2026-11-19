//! xHCI USB 3.0 Host Controller Driver (Linux drivers/usb/host/xhci.c,
//! xhci-mem.c, xhci-pci.c; the rings, commands and events are in
//! `xhci_ring.rs`, Linux xhci-ring.c)
//!
//! `XHCI_PCI_DRIVER` binds the controller on the PCI bus. Each bound
//! controller is an `Arc<Xhci>`, the `Hcd` of the USB devices below
//! it: their URBs are queued on the endpoint rings and given back from
//! the interrupt handler, which consumes the event ring.
//!
//! ## Locking (doc/LOCKING.md 3.10)
//!
//! `Xhci.lock` (`IrqSpinlock`, Linux xhci->lock) holds the rings, the
//! command list, the devices' endpoint state and TD lists: taken by the
//! interrupt handler (under the line's `IrqDesc.lock`), by URB
//! submission and by command queueing. `Xhci.mutex` (sleeping, Linux
//! xhci->mutex) serializes slot and context commands (Enable Slot,
//! Address Device, Evaluate Context, Configure Endpoint, Disable Slot)
//! whose waits sleep: order `Xhci.mutex` -> `Xhci.lock`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::any::Any;
use core::mem::MaybeUninit;
use core::ptr::{NonNull, read_volatile, write_volatile};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering, fence};

use crate::arch::phys_to_virt;
use crate::hw::dma::DmaCoherent;
use crate::hw::mmio::IoMem;
use crate::hw::pci::PciDevice;
use crate::irq::IrqRegistration;
use crate::printkln;
use crate::sync::IrqSpinlock;
use crate::sync::completion::Completion;
use crate::task::workqueue::DelayedWork;
use crate::time::delay::{poll_timeout, udelay};
use crate::trace::{TraceEvent, TraceSystem};
use crate::util::error::KernelError;
use crate::util::kalloc::{try_arc, try_box};

use super::context::{EpParams, InputContext, OutputDeviceContext, endpoint_to_dci};
use super::hcd::{GivebackBh, Hcd, HcdRef};
use super::message::{USB_CTRL_GET_TIMEOUT, USB_CTRL_SET_TIMEOUT, usb_control_msg};
use super::transfer::{TransferRing, Trb};
use super::urb::Urb;
use super::{
    EndpointType, SetupPacket, UsbDevice, UsbEndpoint, UsbError, UsbSpeed, config, descriptor_type,
};

/// Halt and start handshakes (Linux XHCI_MAX_HALT_USEC)
pub(super) const XHCI_MAX_HALT_US: u64 = 32_000;
/// Reset handshakes at initialization (Linux XHCI_RESET_LONG_USEC)
const XHCI_RESET_LONG_US: u64 = 10_000_000;
/// Reset handshakes later on (Linux XHCI_RESET_SHORT_USEC)
pub(super) const XHCI_RESET_SHORT_US: u64 = 250_000;
/// Root port reset (Linux HUB_RESET_TIMEOUT)
const PORT_RESET_US: u64 = 800_000;

pub(super) const PCI_VENDOR_INTEL: u16 = 0x8086;

/// USBCMD interrupter, host system error and wrap event enables (Linux
/// XHCI_IRQS)
pub(super) const XHCI_IRQS: u32 = (1 << 2) | (1 << 3) | (1 << 10);

/// Chipset quirks, set once from the PCI IDs (Linux xhci_pci_quirks)
pub(super) mod quirk {
    use super::PCI_VENDOR_INTEL;
    use crate::hw::pci::PciDevice;

    /// Intel host: 1 ms after HCRST before any register access
    pub const INTEL_HOST: u32 = 1 << 0;
    /// Ports go back to EHCI at shutdown, or the machine powers back on
    pub const SPURIOUS_REBOOT: u32 = 1 << 1;
    /// Reset and D3hot at shutdown, or spurious wakeups follow
    pub const SPURIOUS_WAKEUP: u32 = 1 << 2;
    /// No soft retry of a transaction error (Linux XHCI_NO_SOFT_RETRY)
    pub const NO_SOFT_RETRY: u32 = 1 << 3;
    /// A success event may follow a short transfer's (Linux
    /// XHCI_SPURIOUS_SUCCESS)
    pub const SPURIOUS_SUCCESS: u32 = 1 << 4;

    /// From the PCI IDs and the interface version: xHCI 1.0 hosts send
    /// the spurious success, as does the ASMedia 1042 that says 0.96
    /// (Linux xhci_gen_setup, xhci_pci_quirks)
    pub fn of(dev: &PciDevice, hci_version: u16) -> u32 {
        let q = if hci_version > 0x96 {
            SPURIOUS_SUCCESS
        } else {
            0
        };
        let (vendor, device) = (dev.header.vendor_id, dev.header.device_id);
        match (vendor, device) {
            // Etron EJ168, EJ188; AMD Promontory A
            (0x1b6f, 0x7023 | 0x7052) | (0x1022, 0x43b9 | 0x43bb) => return q | NO_SOFT_RETRY,
            // ASMedia 1042
            (0x1b21, 0x1042) => return q | SPURIOUS_SUCCESS,
            _ => {}
        }
        if vendor != PCI_VENDOR_INTEL {
            return q;
        }
        q | INTEL_HOST
            | match dev.header.device_id {
                0x1e31 => SPURIOUS_REBOOT,                            // Panther Point
                0x9c31 | 0x9cb1 => SPURIOUS_REBOOT | SPURIOUS_WAKEUP, // LPT-LP, WPT-LP
                _ => 0,
            }
    }
}

/// Scratchpad buffers the controller needs, from HCSPARAMS2 (Linux
/// HCS_MAX_SCRATCHPAD: bits 25:21 high, 31:27 low)
fn hcs_max_scratchpad(params2: u32) -> u32 {
    ((params2 >> 21) & 0x1f) << 5 | (params2 >> 27)
}

/// DMA mask from HCCPARAMS1: AC64 (bit 0) means 64-bit addressing,
/// else only 32 (Linux xhci_gen_setup, HCC_64BIT_ADDR)
fn hcc_dma_mask(params1: u32) -> u64 {
    if params1 & 1 != 0 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    }
}

/// The xHCI trace events (Linux xhci-trace.h, system "xhci-hcd"; the
/// debug messages as xhci_dbg_trace's events): to the trace ring, never
/// printk, so the USB serial console's own transfers can be traced
pub(super) static HANDLE_EVENT: TraceEvent = TraceEvent::new("xhci_handle_event");
pub(super) static HANDLE_TRANSFER: TraceEvent = TraceEvent::new("xhci_handle_transfer");
pub(super) static URB_ENQUEUE: TraceEvent = TraceEvent::new("xhci_urb_enqueue");
pub(super) static QUEUE_TRB: TraceEvent = TraceEvent::new("xhci_queue_trb");
pub(super) static URB_GIVEBACK: TraceEvent = TraceEvent::new("xhci_urb_giveback");
pub(super) static DBG_CANCEL_URB: TraceEvent = TraceEvent::new("xhci_dbg_cancel_urb");

/// The "xhci-hcd" trace system
pub static TRACE_SYSTEM: TraceSystem = TraceSystem {
    name: "xhci-hcd",
    events: &[
        &HANDLE_EVENT,
        &HANDLE_TRANSFER,
        &URB_ENQUEUE,
        &QUEUE_TRB,
        &URB_GIVEBACK,
        &DBG_CANCEL_URB,
    ],
};

/// Record an xHCI trace event, if enabled (emit checks; the arguments
/// are formatted only then)
macro_rules! xhci_trace {
    ($ev:ident, $($arg:tt)*) => {
        crate::trace::emit(&crate::hw::usb::xhci::$ev, format_args!($($arg)*))
    };
}
pub(super) use xhci_trace;

// ============================================================================
// xHCI PCI driver
// ============================================================================

/// The xHCI PCI driver (Linux xhci-pci: class 0C:03:30)
pub static XHCI_PCI_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "xhci_hcd",
    &crate::hw::pci::driver::PCI_BUS,
    Some("xhci_pci"),
    &crate::hw::pci::driver::PciIds(&[crate::hw::pci::driver::PciDeviceId::class(
        0x0c0330, 0xffffff,
    )]),
    xhci_probe,
);

/// Bring the controller up, enumerate its ports and register the USB
/// devices below it (Linux usb_add_hcd: its IRQ requested, xhci_run,
/// then the root hub and hub_event)
fn xhci_probe(
    dev: &alloc::sync::Arc<crate::base::Device>,
) -> Result<Box<dyn crate::base::Bound>, KernelError> {
    let pci_dev = crate::hw::pci::driver::pci_dev(dev).ok_or(KernelError::NoDevice)?;
    let mmio_base = pci_dev.bar_address(0).ok_or(KernelError::NoDevice)?;
    // The binding's memory first: nothing to undo should it fail
    let slot = try_box(MaybeUninit::<XhciDeviceHandle>::uninit())?;
    pci_dev.enable_memory_space();
    pci_dev.enable_bus_master();
    printkln!(
        "xHCI: Probing PCI device at {}, BAR0=0x{:x}",
        pci_dev.bus_id(),
        mmio_base
    );
    let xhci = match Xhci::setup(pci_dev.clone(), mmio_base) {
        Ok(x) => try_arc(x)?,
        Err(e) => {
            printkln!("xHCI: Failed to initialize controller: {:?}", e);
            pci_disable_device(pci_dev);
            return Err(KernelError::Io);
        }
    };
    let irq = match xhci.start() {
        Ok(irq) => irq,
        Err(e) => {
            printkln!("xHCI: Failed to start controller: {:?}", e);
            xhci.stop();
            pci_disable_device(pci_dev);
            return Err(KernelError::Io);
        }
    };
    printkln!("xHCI: Controller initialized and running");
    let usb_devices = xhci.enumerate();
    let usb = match super::usb_register_devices(dev, usb_devices) {
        Ok(u) => u,
        Err(e) => {
            xhci.stop();
            drop(irq);
            pci_disable_device(pci_dev);
            return Err(e);
        }
    };
    Ok(Box::write(
        slot,
        XhciDeviceHandle {
            xhci,
            irq: crate::sync::spin::Mutex::new(Some(irq)),
            usb,
        },
    ))
}

/// Bus mastering off (Linux pci_disable_device)
fn pci_disable_device(pci_dev: &PciDevice) {
    let cmd = pci_dev.cfg_read16(0x04);
    pci_dev.cfg_write16(0x04, cmd & !crate::hw::pci::command::BUS_MASTER);
}

/// A bound xHCI: the controller, its interrupt handler and its USB
/// devices (the root hub last)
struct XhciDeviceHandle {
    xhci: Arc<Xhci>,
    /// The handler (Linux hcd->irq); taken at remove
    irq: crate::sync::spin::Mutex<Option<IrqRegistration<Xhci>>>,
    usb: super::usbcore::UsbBus,
}

impl crate::base::Bound for XhciDeviceHandle {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Linux xhci_pci_remove, usb_remove_hcd: the root hub disconnects
    /// (its devices and their interfaces unbind and go, bottom-up),
    /// then the controller is stopped: slots disabled, halted and
    /// reset, what is still queued given back, its IRQ freed (which
    /// waits out a running handler) and bus mastering turned off. Its
    /// memory goes with the last reference (URBs a driver still holds
    /// keep it)
    fn remove(&self) {
        super::usbcore::usb_unregister_devices(&self.usb);
        self.xhci.stop();
        let irq = self.irq.lock().take();
        drop(irq);
        pci_disable_device(&self.xhci.pci_dev);
        printkln!("xHCI: {} stopped", self.xhci.pci_dev.bus_id());
    }

    /// Power-off/restart (Linux xhci_pci_shutdown)
    fn shutdown(&self) {
        self.xhci.shutdown_hc();
    }
}

/// USBCMD register bits
pub(super) mod usbcmd {
    pub const RUN_STOP: u32 = 1 << 0;
    pub const HCRST: u32 = 1 << 1;
    pub const INTE: u32 = 1 << 2;
}

/// USBSTS register bits
pub(super) mod usbsts {
    pub const HCH: u32 = 1 << 0; // Host Controller Halted
    pub const HSE: u32 = 1 << 2; // Host System Error
    pub const EINT: u32 = 1 << 3; // Event Interrupt
    pub const CNR: u32 = 1 << 11; // Controller Not Ready
    pub const HCE: u32 = 1 << 12; // Host Controller Error
}

/// Operational register offsets
pub(super) mod op {
    pub const USBCMD: usize = 0x00;
    pub const USBSTS: usize = 0x04;
    pub const PAGESIZE: usize = 0x08;
    pub const CRCR: usize = 0x18;
    pub const DCBAAP: usize = 0x30;
    pub const CONFIG: usize = 0x38;
}

/// Interrupter 0's runtime register offsets
pub(super) mod ir {
    pub const IMAN: usize = 0x20;
    pub const ERSTSZ: usize = 0x28;
    pub const ERSTBA: usize = 0x30;
    pub const ERDP: usize = 0x38;
    /// IMAN: interrupt pending (RW1C), enable
    pub const IMAN_IP: u32 = 1 << 0;
    pub const IMAN_IE: u32 = 1 << 1;
    /// ERDP: event handler busy (RW1C)
    pub const ERDP_EHB: u64 = 1 << 3;
}

/// Port status register bits
mod portsc {
    pub const CCS: u32 = 1 << 0; // Current Connect Status
    pub const PED: u32 = 1 << 1; // Port Enabled/Disabled
    pub const PR: u32 = 1 << 4; // Port Reset
    pub const CSC: u32 = 1 << 17; // Connect Status Change
    pub const PRC: u32 = 1 << 21; // Port Reset Change

    pub fn speed(portsc: u32) -> u8 {
        ((portsc >> 10) & 0xF) as u8
    }

    /// Read-only bits, written back as read: connect status, over-
    /// current, speed, device removable (Linux XHCI_PORT_RO)
    const RO: u32 = (1 << 0) | (1 << 3) | (0xf << 10) | (1 << 30);
    /// Read/write bits, written back as read: link state, port power,
    /// indicator, wake enables (Linux XHCI_PORT_RWS)
    const RWS: u32 = (0xf << 5) | (1 << 9) | (0x3 << 14) | (0x7 << 25);

    /// A PORTSC value that changes nothing when written (Linux
    /// xhci_port_state_to_neutral): writing back what was read would
    /// clear every pending change bit and, through PED (write 1 to
    /// clear), disable the port; masking would drop port power
    pub fn to_neutral(portsc: u32) -> u32 {
        portsc & (RO | RWS)
    }
}

/// Command TRB types
pub(super) mod trb_type {
    pub const ENABLE_SLOT: u8 = 9;
    pub const DISABLE_SLOT: u8 = 10;
    pub const ADDRESS_DEVICE: u8 = 11;
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    pub const EVALUATE_CONTEXT: u8 = 13;
    pub const RESET_ENDPOINT: u8 = 14;
    pub const STOP_ENDPOINT: u8 = 15;
    pub const SET_TR_DEQUEUE: u8 = 16;
    pub const CMD_NOOP: u8 = 23;
    pub const TRANSFER_EVENT: u8 = 32;
    pub const COMMAND_COMPLETION: u8 = 33;
    pub const PORT_STATUS_CHANGE: u8 = 34;
}

/// A ring's TRB array (DMA memory, reached only through its owner's
/// lock, `Xhci.lock`)
struct TrbPtr(*mut Trb);

// SAFETY: an address; the TRBs are touched only under `Xhci.lock`
unsafe impl Send for TrbPtr {}
// SAFETY: as above
unsafe impl Sync for TrbPtr {}

/// Command ring (Linux xhci->cmd_ring): one segment of `SIZE` TRBs,
/// the last a Link TRB back to the start
pub(super) struct CommandRing {
    phys: u64,
    trbs: TrbPtr,
    /// Next TRB to fill
    enqueue: usize,
    /// The oldest command not yet completed (Linux cmd_ring->dequeue)
    dequeue: usize,
    /// Producer cycle state
    cycle: bool,
}

impl CommandRing {
    const SIZE: usize = 64;

    /// A ring in the zeroed frame at `phys`
    fn new(phys: u64) -> Self {
        // SAFETY: the zeroed frame, in the direct map, is the ring's
        unsafe { Self::from_parts(phys_to_virt(phys).cast::<Trb>(), phys) }
    }

    /// A ring of zeroed TRBs at `trbs`, device address `phys`
    ///
    /// # Safety
    /// `trbs` points at `SIZE` zeroed TRBs kept for the ring.
    unsafe fn from_parts(trbs: *mut Trb, phys: u64) -> Self {
        let mut link = Trb::link(phys, true);
        link.set_cycle(true);
        // SAFETY: the last of the caller's SIZE TRBs
        unsafe { write_volatile(trbs.add(Self::SIZE - 1), link) };
        Self {
            phys,
            trbs: TrbPtr(trbs),
            enqueue: 0,
            dequeue: 0,
            cycle: true,
        }
    }

    fn dma_of(&self, i: usize) -> u64 {
        self.phys + (i * 16) as u64
    }

    /// Room for one more command
    pub(super) fn has_room(&self) -> bool {
        let used = (self.enqueue + Self::SIZE - 1 - self.dequeue) % (Self::SIZE - 1);
        used < Self::SIZE - 2
    }

    /// Queue `trb` (the caller checked `has_room`): its device address
    pub(super) fn enqueue(&mut self, mut trb: Trb) -> u64 {
        let i = self.enqueue;
        trb.set_cycle(self.cycle);
        // SAFETY: TRB i < SIZE - 1 of the ring's frame; fields of it,
        // the control word (cycle bit) last
        unsafe {
            let p = self.trbs.0.add(i);
            write_volatile(&raw mut (*p).parameter, trb.parameter);
            write_volatile(&raw mut (*p).status, trb.status);
            fence(Ordering::SeqCst);
            write_volatile(&raw mut (*p).control, trb.control);
        }
        fence(Ordering::SeqCst);
        self.enqueue += 1;
        if self.enqueue == Self::SIZE - 1 {
            self.enqueue = 0;
            // SAFETY: the Link TRB of the ring's frame
            unsafe {
                let link = self.trbs.0.add(Self::SIZE - 1);
                let mut l = read_volatile(link);
                l.set_cycle(self.cycle);
                write_volatile(link, l);
            }
            self.cycle = !self.cycle;
        }
        self.dma_of(i)
    }

    /// The oldest outstanding command's TRB and device address
    pub(super) fn dequeue_trb(&self) -> (Trb, u64) {
        // SAFETY: TRB dequeue < SIZE - 1 of the ring's frame
        let t = unsafe { read_volatile(self.trbs.0.add(self.dequeue)) };
        (t, self.dma_of(self.dequeue))
    }

    /// The oldest command completed (Linux inc_deq on the command ring)
    pub(super) fn inc_deq(&mut self) {
        self.dequeue = (self.dequeue + 1) % (Self::SIZE - 1);
    }

    /// No command outstanding
    pub(super) fn is_empty(&self) -> bool {
        self.enqueue == self.dequeue
    }

    /// The device address of the TRB after the dequeue position (Linux
    /// xhci_abort_cmd_ring's new_deq, the Link TRB skipped)
    pub(super) fn next_dma(&self) -> u64 {
        self.dma_of((self.dequeue + 1) % (Self::SIZE - 1))
    }

    /// Turn the command at device address `dma` into a No-op command,
    /// its cycle bit kept (Linux trb_to_noop with TRB_CMD_NOOP)
    pub(super) fn noop_at(&mut self, dma: u64) {
        let Some(i) = dma
            .checked_sub(self.phys)
            .map(|o| (o / 16) as usize)
            .filter(|&i| i < Self::SIZE - 1)
        else {
            return;
        };
        // SAFETY: TRB i of the ring's frame
        unsafe {
            let p = self.trbs.0.add(i);
            let cycle = read_volatile(&raw const (*p).control) & 1;
            let mut t = Trb::new();
            t.set_type(trb_type::CMD_NOOP);
            t.control |= cycle;
            write_volatile(p, t);
        }
    }
}

/// Event ring segment table entry
#[derive(Clone, Copy, Default)]
#[repr(C, align(16))]
struct ErstEntry {
    ring_segment_base: u64,
    ring_segment_size: u16,
    _reserved: [u8; 6],
}

/// Event ring of interrupter 0 (one segment)
pub(super) struct EventRing {
    phys: u64,
    trbs: TrbPtr,
    /// Dequeue pointer index
    dequeue: usize,
    /// Consumer cycle state
    cycle: bool,
    /// ERST physical address
    erst_phys: u64,
}

impl EventRing {
    const SIZE: usize = 64;

    /// A ring in the zeroed frame at `phys`, its segment table in the
    /// zeroed frame at `erst_phys`
    fn new(phys: u64, erst_phys: u64) -> Self {
        // SAFETY: the zeroed ERST frame: entry 0
        unsafe {
            let erst = phys_to_virt(erst_phys).cast::<ErstEntry>();
            (*erst).ring_segment_base = phys;
            (*erst).ring_segment_size = Self::SIZE as u16;
        }
        Self {
            phys,
            trbs: TrbPtr(phys_to_virt(phys).cast::<Trb>()),
            dequeue: 0,
            cycle: true,
            erst_phys,
        }
    }

    /// The next event the controller handed over, if any (Linux
    /// unhandled_event_trb), consumed
    pub(super) fn dequeue(&mut self) -> Option<Trb> {
        // SAFETY: TRB dequeue < SIZE of the ring's frame
        let trb_ptr = unsafe { self.trbs.0.add(self.dequeue) };
        // The cycle bit first, then the rest (Linux xhci_handle_event:
        // flags, rmb, fields): read in one go, the parameter could predate
        // the controller's write of the control word that made it valid,
        // and a completion would not match its TRB
        // SAFETY: as above
        let control = unsafe { read_volatile(&raw const (*trb_ptr).control) };
        if (control & 1 != 0) != self.cycle {
            return None;
        }
        fence(Ordering::Acquire);
        // SAFETY: as above
        let trb = unsafe { read_volatile(trb_ptr) };
        self.dequeue += 1;
        if self.dequeue >= Self::SIZE {
            self.dequeue = 0;
            self.cycle = !self.cycle;
        }
        Some(trb)
    }

    pub(super) fn dequeue_phys(&self) -> u64 {
        self.phys + (self.dequeue * 16) as u64
    }
}

/// Operational registers before the port register sets (xHCI 5.4)
const OP_PORTS: usize = 0x400;
/// Bytes per port register set (PORTSC, PORTPMSC, PORTLI, PORTHLPMC)
const PORT_STRIDE: usize = 0x10;
/// Runtime registers through interrupter 0's set (MFINDEX, then
/// IMAN..ERDP at 0x20..0x40; xHCI 5.5)
const RT_IR0_END: usize = 0x40;

/// The controller's register windows, carved out of BAR0 at the offsets
/// the controller reports (xHCI 5.3-5.6). Each is checked against the
/// BAR when it is made, and every access against its window, so a
/// device reporting a bad CAPLENGTH, DBOFF, RTSOFF or MaxPorts cannot
/// steer an access outside its registers.
#[derive(Clone, Copy)]
pub(super) struct Regs {
    cap: IoMem,
    pub(super) op: IoMem,
    port: IoMem,
    db: IoMem,
    pub(super) rt: IoMem,
}

impl Regs {
    /// The windows inside BAR0's mapping `bar`; None if one does not fit
    fn map(bar: IoMem) -> Option<Self> {
        let caplen = (bar.try_read32(0)? & 0xff) as usize;
        // The capability registers run through HCCPARAMS2 (0x1c); the
        // operational ones are dword registers
        if caplen < 0x20 || !caplen.is_multiple_of(4) {
            return None;
        }
        let cap = bar.sub(0, caplen)?;
        let hcs1 = cap.read32(0x04);
        let slots = (hcs1 & 0xff) as usize;
        let ports = (hcs1 >> 24) as usize;
        let op = bar.sub(caplen, OP_PORTS + ports * PORT_STRIDE)?;
        let port = op.sub(OP_PORTS, ports * PORT_STRIDE)?;
        // DBOFF bits 1:0 and RTSOFF bits 4:0 are reserved (xHCI 5.3.7-8);
        // doorbell 0 is the host's, then one per slot
        let db = bar.sub((cap.read32(0x14) & !0x3) as usize, (slots + 1) * 4)?;
        let rt = bar.sub((cap.read32(0x18) & !0x1f) as usize, RT_IR0_END)?;
        Some(Self {
            cap,
            op,
            port,
            db,
            rt,
        })
    }
}

/// What the controller was given, freed when the last reference to it
/// goes (Linux xhci_mem_cleanup, iounmap): the register mapping and the
/// frames of the DCBAA, scratchpads, command and event rings
struct XhciMem {
    /// The register mapping (0: none)
    mmio_virt: u64,
    mmio_len: u64,
    frames: Vec<u64>,
}

impl XhciMem {
    /// A zeroed frame, kept until the controller goes
    fn frame(&mut self) -> Result<u64, UsbError> {
        self.frames
            .try_reserve(1)
            .map_err(|_| UsbError::NoResources)?;
        let phys = crate::FRAME_ALLOCATOR
            .alloc()
            .ok_or(UsbError::NoResources)?;
        // SAFETY: a fresh frame, in the direct map
        unsafe { core::ptr::write_bytes(phys_to_virt(phys), 0, 4096) };
        self.frames.push(phys);
        Ok(phys)
    }
}

impl Drop for XhciMem {
    fn drop(&mut self) {
        for f in self.frames.drain(..) {
            crate::FRAME_ALLOCATOR.free(f);
        }
        if self.mmio_len != 0 {
            // SAFETY: the controller's registers, mapped at setup; the
            // last reference to the controller is gone, and with it
            // every register window
            unsafe { crate::mm::ioremap::iounmap(self.mmio_virt as *mut u8, self.mmio_len) };
        }
    }
}

/// `Xhci.lock`'s `xhc_state` bits (Linux XHCI_STATE_*)
pub(super) mod xhc_state {
    /// Dead: nothing more is queued or completed
    pub const DYING: u32 = 1 << 0;
    /// Halted by the driver
    pub const HALTED: u32 = 1 << 1;
    /// Being removed
    pub const REMOVING: u32 = 1 << 2;
}

/// Command ring states (Linux CMD_RING_STATE_*)
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CmdRingState {
    Running,
    Aborted,
    Stopped,
}

/// A queued command (Linux struct xhci_command)
pub(super) struct XhciCommand {
    /// The command TRB as queued
    pub(super) trb: Trb,
    /// Its device address on the command ring
    pub(super) trb_dma: AtomicU64,
    /// Completion code (Linux cmd->status; COMMAND_ABORTED marks one
    /// the timeout aborts)
    pub(super) status: AtomicU8,
    /// Enable Slot's slot
    pub(super) slot_id: AtomicU8,
    /// Time out at this monotonic ns (set when it becomes the oldest)
    pub(super) deadline: AtomicU64,
    /// A waiter's (Linux cmd->completion; None: freed on completion)
    pub(super) completion: Option<Completion>,
}

impl XhciCommand {
    pub(super) fn new_cmd(trb: Trb, waiter: bool) -> Self {
        Self {
            trb,
            trb_dma: AtomicU64::new(0),
            status: AtomicU8::new(0),
            slot_id: AtomicU8::new(0),
            deadline: AtomicU64::new(0),
            completion: waiter.then(Completion::new),
        }
    }

    /// The command TRB's type
    pub(super) fn ty(&self) -> u8 {
        self.trb.get_type()
    }
}

/// Cancellation state of a TD (Linux enum xhci_cancelled_td_status)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum TdCancel {
    /// Not cancelled
    None,
    /// Cancelled, still on the ring as queued
    Dirty,
    /// The endpoint halted on it
    Halted,
    /// Turned into No-ops; a Set TR Dequeue Pointer moves past it
    ClearingCache,
    /// Turned into No-ops, past the controller: to be given back
    Cleared,
}

/// A transfer descriptor: one URB's TRBs on its endpoint ring (Linux
/// struct xhci_td)
pub(super) struct Td {
    pub(super) urb: Arc<Urb>,
    pub(super) span: super::transfer::TdSpan,
    pub(super) cancel: TdCancel,
    /// Status to give back with (Linux td->status)
    pub(super) status: Result<(), UsbError>,
    /// A control data stage set the length (Linux urb_length_set)
    pub(super) urb_length_set: bool,
}

impl Td {
    /// Still on the TD list proper: not yet invalidated (Linux: on
    /// ring->td_list)
    pub(super) fn on_ring(&self) -> bool {
        matches!(
            self.cancel,
            TdCancel::None | TdCancel::Dirty | TdCancel::Halted
        )
    }
}

/// `VirtEp.ep_state` bits (Linux EP_*)
pub(super) mod ep_state {
    /// Set TR Dequeue Pointer queued
    pub const SET_DEQ_PENDING: u32 = 1 << 0;
    /// Halted, Reset Endpoint queued
    pub const EP_HALTED: u32 = 1 << 1;
    /// Stop Endpoint queued
    pub const EP_STOP_CMD_PENDING: u32 = 1 << 2;
    /// A hard Reset Endpoint reset the toggle: the next endpoint_reset
    /// has nothing to do
    pub const EP_HARD_CLEAR_TOGGLE: u32 = 1 << 3;
    /// endpoint_reset is stopping and reconfiguring it: no queueing
    pub const EP_SOFT_CLEAR_TOGGLE: u32 = 1 << 4;
}

/// TDs an endpoint's list has room for when its ring is made, one per
/// TRB of the first segment; queueing past them grows the list
const MAX_TDS: usize = TransferRing::SEG_TRBS;

/// An endpoint of a device (Linux struct xhci_virt_ep)
pub(super) struct VirtEp {
    pub(super) ring: Option<TransferRing>,
    /// Its TDs in ring order, room for `MAX_TDS` reserved with the ring
    /// (Linux ring->td_list and
    /// ep->cancelled_td_list, the latter as `Td.cancel`)
    pub(super) tds: alloc::collections::VecDeque<Td>,
    pub(super) ep_state: u32,
    /// Where the queued Set TR Dequeue Pointer moves the dequeue (Linux
    /// queued_deq_ptr)
    pub(super) queued_deq: Option<usize>,
    /// wMaxPacketSize (TD Size)
    pub(super) maxp: u16,
    /// When its last Stop Endpoint was queued (monotonic ns; Linux
    /// ep->stop_time)
    pub(super) stop_time: u64,
    /// Transaction errors soft-retried in a row (Linux ep->err_count)
    pub(super) err_count: u32,
    /// The completion code of the last event that found its TD (Linux
    /// ring->old_trb_comp_code)
    pub(super) old_cc: u8,
}

impl VirtEp {
    const fn new() -> Self {
        Self {
            ring: None,
            tds: alloc::collections::VecDeque::new(),
            ep_state: 0,
            queued_deq: None,
            maxp: 0,
            stop_time: 0,
            err_count: 0,
            old_cc: 0,
        }
    }

    /// An endpoint with `ring`, its TD list's room reserved
    fn with_ring(ring: TransferRing, maxp: u16) -> Result<Self, UsbError> {
        let mut tds = alloc::collections::VecDeque::new();
        tds.try_reserve_exact(MAX_TDS)
            .map_err(|_| UsbError::NoResources)?;
        Ok(Self {
            ring: Some(ring),
            tds,
            ep_state: 0,
            queued_deq: None,
            maxp,
            stop_time: 0,
            err_count: 0,
            old_cc: 0,
        })
    }
}

/// A device's controller state (Linux struct xhci_virt_device)
pub(super) struct VirtDev {
    /// Output Device Context (the controller writes it)
    pub(super) out_ctx: OutputDeviceContext,
    /// Input Context (Address Device, Evaluate Context, Configure
    /// Endpoint)
    in_ctx: InputContext,
    /// By DCI - 1 (Linux ep_index)
    pub(super) eps: Vec<VirtEp>,
    speed: UsbSpeed,
    port: u8,
}

/// What `Xhci.lock` guards (Linux the xhci_hcd fields under xhci->lock)
pub(super) struct XhciState {
    pub(super) xhc_state: u32,
    pub(super) cmd_ring: CommandRing,
    pub(super) cmd_ring_state: CmdRingState,
    /// Commands in ring order, room reserved for a full ring (Linux
    /// cmd_list)
    pub(super) cmd_list: alloc::collections::VecDeque<Arc<XhciCommand>>,
    pub(super) event_ring: EventRing,
    /// By slot id (Linux xhci->devs)
    pub(super) devs: Vec<Option<Box<VirtDev>>>,
}

impl XhciState {
    /// Slot `slot`'s device
    pub(super) fn dev(&mut self, slot: u8) -> Option<&mut VirtDev> {
        self.devs.get_mut(usize::from(slot))?.as_deref_mut()
    }

    /// Endpoint `dci` of slot `slot`
    pub(super) fn ep(&mut self, slot: u8, dci: u8) -> Option<&mut VirtEp> {
        let i = usize::from(dci).checked_sub(1)?;
        self.dev(slot)?.eps.get_mut(i)
    }
}

/// An xHCI host controller (Linux struct xhci_hcd with its usb_hcd)
pub struct Xhci {
    pub(super) pci_dev: PciDevice,
    pub(super) regs: Regs,
    pub(super) quirks: u32,
    pub(super) hci_version: u16,
    max_slots: u8,
    max_ports: u8,
    pub(super) ctx_size: usize,
    dcbaa_phys: u64,
    #[expect(dead_code, reason = "owns the mapping and frames, freed on drop")]
    mem: XhciMem,
    /// Linux xhci->lock
    pub(super) lock: IrqSpinlock<XhciState>,
    /// Linux xhci->mutex
    mutex: crate::sync::Mutex<()>,
    bh: GivebackBh,
    /// The command timeout (Linux xhci->cmd_timer), on the system
    /// workqueue
    pub(super) cmd_timer: spin::Once<Arc<IrqSpinlock<DelayedWork>>>,
    /// The command ring stopped after an abort (Linux
    /// cmd_ring_stop_completion)
    pub(super) cmd_ring_stop: Completion,
}

impl Xhci {
    /// Map, halt and reset the controller and give it its memory (Linux
    /// xhci_gen_setup, xhci_init, xhci_mem_init); not yet running
    fn setup(pci_dev: PciDevice, mmio_base: u64) -> Result<Self, UsbError> {
        let bar_size = pci_dev.bar_size(0);
        // SAFETY: BAR0 of this xHCI, its register space
        let virt = unsafe { crate::mm::ioremap::ioremap(mmio_base, bar_size) }.map_err(|e| {
            printkln!("xHCI: Failed to ioremap MMIO region: {:?}", e);
            UsbError::NoResources
        })?;
        let mut mem = XhciMem {
            mmio_virt: virt as u64,
            mmio_len: bar_size,
            frames: Vec::new(),
        };
        let len = usize::try_from(bar_size).unwrap_or(0);
        // SAFETY: ioremap mapped BAR0's `bar_size` bytes of registers
        // at `virt`, unmapped only when `mem` (owned with the windows by
        // the controller) goes
        let bar = NonNull::new(virt).map(|p| unsafe { IoMem::new(p, len) });
        let Some(regs) = bar.and_then(Regs::map) else {
            printkln!(
                "xHCI: register offsets outside the {:#x}-byte BAR0",
                bar_size
            );
            return Err(UsbError::NoResources);
        };
        let hciversion = regs.cap.read32(0) >> 16;
        let hcsparams1 = regs.cap.read32(0x04);
        let hccparams1 = regs.cap.read32(0x10);
        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        let ctx_size = super::context::ctx_size(hccparams1);
        // Contexts, transfer rings and bulk buffers may sit above 4GB:
        // under the default 32-bit mask their DMA mapping fails
        let mut pci_dev = pci_dev;
        pci_dev.set_dma_mask_and_coherent(hcc_dma_mask(hccparams1));
        printkln!(
            "xHCI: version={:x}.{:x}, max_slots={}, max_ports={}, context={} bytes",
            (hciversion >> 8) & 0xFF,
            hciversion & 0xFF,
            max_slots,
            max_ports,
            ctx_size
        );
        let mut devs = Vec::new();
        devs.try_reserve_exact(usize::from(max_slots) + 1)
            .map_err(|_| UsbError::NoResources)?;
        devs.resize_with(usize::from(max_slots) + 1, || None);
        let mut cmd_list = alloc::collections::VecDeque::new();
        cmd_list
            .try_reserve_exact(CommandRing::SIZE)
            .map_err(|_| UsbError::NoResources)?;
        let quirks = quirk::of(&pci_dev, hciversion as u16);
        halt_regs(&regs)?;
        reset_regs(&regs, quirks, XHCI_RESET_LONG_US)?;
        let dcbaa_phys = mem.frame()?;
        alloc_scratchpads(&regs, &mut mem, dcbaa_phys)?;
        let cmd_ring = CommandRing::new(mem.frame()?);
        let event_ring = EventRing::new(mem.frame()?, mem.frame()?);
        let bh = GivebackBh::new().map_err(|_| UsbError::NoResources)?;
        let x = Self {
            pci_dev,
            regs,
            quirks,
            hci_version: hciversion as u16,
            max_slots,
            max_ports,
            ctx_size,
            dcbaa_phys,
            mem,
            lock: IrqSpinlock::new(XhciState {
                xhc_state: 0,
                cmd_ring,
                cmd_ring_state: CmdRingState::Running,
                cmd_list,
                event_ring,
                devs,
            }),
            mutex: crate::sync::Mutex::new(()),
            bh,
            cmd_timer: spin::Once::new(),
            cmd_ring_stop: Completion::new(),
        };
        x.configure();
        Ok(x)
    }

    pub(super) fn read_op(&self, offset: usize) -> u32 {
        self.regs.op.read32(offset)
    }

    pub(super) fn write_op(&self, offset: usize, value: u32) {
        self.regs.op.write32(offset, value);
    }

    /// Offset of `port`'s (1-based) register at `offset` in the port
    /// window; past MaxPorts the window check refuses it
    fn port_off(port: u8, offset: usize) -> Option<usize> {
        Some(usize::from(port).checked_sub(1)? * PORT_STRIDE + offset)
    }

    /// Read port register (all ones for a port the controller lacks)
    fn read_port(&self, port: u8, offset: usize) -> u32 {
        Self::port_off(port, offset)
            .and_then(|o| self.regs.port.try_read32(o))
            .unwrap_or(!0)
    }

    /// Write port register (nothing for a port the controller lacks)
    fn write_port(&self, port: u8, offset: usize, value: u32) {
        if let Some(o) = Self::port_off(port, offset) {
            self.regs.port.try_write32(o, value);
        }
    }

    /// Ring doorbell `slot` (0: the host's) for `target`, after the
    /// TRB and context writes (a slot past MaxSlots rings nothing)
    pub(super) fn ring_doorbell(&self, slot: u8, target: u8) {
        fence(Ordering::Release);
        self.regs
            .db
            .try_write32(usize::from(slot) * 4, u32::from(target));
    }

    /// Program the rings and interrupter 0 (Linux xhci_init,
    /// xhci_mem_init's register writes)
    fn configure(&self) {
        self.write_op(op::CONFIG, u32::from(self.max_slots));
        self.write_op(op::DCBAAP, (self.dcbaa_phys & 0xFFFF_FFFF) as u32);
        self.write_op(op::DCBAAP + 4, (self.dcbaa_phys >> 32) as u32);
        let st = self.lock.lock();
        let crcr = st.cmd_ring.phys | 1; // ring cycle state
        self.write_op(op::CRCR, (crcr & 0xFFFF_FFFF) as u32);
        self.write_op(op::CRCR + 4, (crcr >> 32) as u32);
        self.regs.rt.write32(ir::ERSTSZ, 1);
        self.regs.rt.write64(ir::ERDP, st.event_ring.phys);
        self.regs.rt.write64(ir::ERSTBA, st.event_ring.erst_phys);
    }

    /// Request the interrupt and start the controller (Linux
    /// usb_add_hcd's request_irq, then xhci_run): interrupter 0 and
    /// USBCMD's interrupts enabled, then Run. No interrupt line: the
    /// controller is not started (Linux xhci_try_enable_msi fails
    /// without one: "No msi-x/msi found and no IRQ in BIOS")
    fn start(self: &Arc<Self>) -> Result<IrqRegistration<Xhci>, UsbError> {
        let weak = Arc::downgrade(self);
        let timer = try_arc(IrqSpinlock::new(DelayedWork::new(move || {
            if let Some(x) = weak.upgrade() {
                x.handle_command_timeout();
            }
        })))
        .map_err(|_| UsbError::NoResources)?;
        self.cmd_timer.call_once(|| timer);
        let irq = self.pci_dev.request_irq(self.clone()).map_err(|e| {
            printkln!("xHCI: no IRQ ({:?})", e);
            UsbError::NoDevice
        })?;
        printkln!("xHCI: Registered IRQ {}", irq.irq());
        let iman = self.regs.rt.read32(ir::IMAN);
        self.regs.rt.write32(ir::IMAN, iman | ir::IMAN_IE);
        let cmd = self.read_op(op::USBCMD);
        self.write_op(op::USBCMD, cmd | usbcmd::INTE | usbcmd::RUN_STOP);
        let running = || self.read_op(op::USBSTS) & usbsts::HCH == 0;
        poll_timeout(XHCI_MAX_HALT_US, 10, running).map_err(|_| {
            printkln!("xHCI: Timeout waiting for start");
            UsbError::Timeout
        })?;
        Ok(irq)
    }

    /// Halt the controller with interrupts off (Linux xhci_halt)
    pub(super) fn halt(&self) -> Result<(), UsbError> {
        halt_regs(&self.regs)
    }

    /// Stop the controller for good (Linux usb_remove_hcd's xhci_stop,
    /// after xhci_free_dev for each device): slots disabled, halted and
    /// reset under the lock, its TDs given back (Shutdown) and its
    /// commands completed, the command timer cancelled
    pub(super) fn stop(&self) {
        // One slot at a time, nothing collected under the lock (Linux
        // usb_disconnect walks the hub's children)
        let nslots = self.lock.lock().devs.len();
        for slot in 1..nslots {
            if self.lock.lock().devs[slot].is_some() {
                self.free_dev(slot as u8);
            }
        }
        let mut st = self.lock.lock();
        st.xhc_state |= xhc_state::HALTED | xhc_state::REMOVING;
        st.cmd_ring_state = CmdRingState::Stopped;
        let _ = self.halt();
        let _ = reset_regs(&self.regs, self.quirks, XHCI_RESET_SHORT_US);
        self.hc_died(&mut st);
        drop(st);
        if let Some(t) = self.cmd_timer.get() {
            crate::task::workqueue::SYSTEM_WQ.cancel_delayed_work(t);
        }
    }

    /// Quiesce the controller for power-off or restart (Linux
    /// xhci_shutdown, xhci_pci_shutdown): no freeing, the machine goes
    /// down next. Ports routed back to EHCI on the Intel chipsets that
    /// otherwise power back on (XHCI_SPURIOUS_REBOOT); halted with
    /// interrupts off; reset and put in D3hot where the halt alone
    /// leaves spurious wakeups (XHCI_SPURIOUS_WAKEUP). Transfers fail
    /// from here on.
    fn shutdown_hc(&self) {
        let spurious_wakeup = self.quirks & quirk::SPURIOUS_WAKEUP != 0;
        if self.quirks & quirk::SPURIOUS_REBOOT != 0 {
            super::pci_quirks::disable_intel_ports(&self.pci_dev);
        }
        let mut st = self.lock.lock();
        st.xhc_state |= xhc_state::HALTED;
        let _ = self.halt();
        if spurious_wakeup {
            let _ = reset_regs(&self.regs, self.quirks, XHCI_RESET_SHORT_US);
        }
        drop(st);
        if spurious_wakeup {
            self.pci_dev.set_power_d3hot();
        }
    }

    /// Issue a command and sleep until it completes (Linux
    /// xhci_queue_*, xhci_ring_cmd_db and wait_for_completion: the
    /// command timer aborts one the controller sits on). A completion
    /// code other than success fails it
    fn command(&self, trb: Trb, what: &str) -> Result<Arc<XhciCommand>, UsbError> {
        let cmd = try_arc(XhciCommand::new_cmd(trb, true)).map_err(|_| UsbError::NoResources)?;
        {
            let mut st = self.lock.lock();
            self.queue_command(&mut st, cmd.clone())?;
        }
        if let Some(c) = &cmd.completion {
            c.wait();
        }
        let cc = cmd.status.load(Ordering::Acquire);
        if cc != super::transfer::CompletionCode::SUCCESS {
            printkln!("xHCI: {} failed with code {}", what, cc);
            return Err(UsbError::TransferError(cc));
        }
        Ok(cmd)
    }

    /// Enable a device slot (Linux xhci_alloc_dev)
    fn enable_slot(&self) -> Result<u8, UsbError> {
        let cmd = self.command(slot_trb(trb_type::ENABLE_SLOT, 0, 0, 0), "Enable Slot")?;
        let slot_id = cmd.slot_id.load(Ordering::Acquire);
        if slot_id == 0 || slot_id > self.max_slots {
            return Err(UsbError::NoResources);
        }
        printkln!("xHCI: Enabled slot {}", slot_id);
        Ok(slot_id)
    }

    /// Scan ports for connected devices
    fn scan_ports(&self) -> Vec<(u8, UsbSpeed)> {
        let mut found = Vec::new();
        for port in 1..=self.max_ports {
            let portsc = self.read_port(port, 0);
            if (portsc & portsc::CCS) != 0
                && let Some(usb_speed) = UsbSpeed::from_xhci_speed(portsc::speed(portsc))
            {
                printkln!(
                    "xHCI: Port {} connected, speed={:?}, portsc=0x{:08x}",
                    port,
                    usb_speed,
                    portsc
                );
                found.push((port, usb_speed));
            }
        }
        found
    }

    /// Reset a root port (Linux hub_port_reset through xhci_hub_control:
    /// PORTSC written under the lock)
    fn reset_port(&self, port: u8) -> Result<(), UsbError> {
        {
            let _st = self.lock.lock();
            let portsc = self.read_port(port, 0);
            self.write_port(port, 0, portsc::to_neutral(portsc) | portsc::PR);
        }
        // Linux hub_port_wait_reset: HUB_RESET_TIMEOUT
        let mut portsc = 0;
        let done = || {
            portsc = self.read_port(port, 0);
            portsc & portsc::PR == 0 && portsc & portsc::PED != 0
        };
        poll_timeout(PORT_RESET_US, 100, done).map_err(|_| UsbError::Timeout)?;
        // Acknowledge the connect and reset changes (write 1 to clear)
        let _st = self.lock.lock();
        let portsc = self.read_port(port, 0);
        self.write_port(
            port,
            0,
            portsc::to_neutral(portsc) | portsc::CSC | portsc::PRC,
        );
        Ok(())
    }

    /// Address a device: its contexts and EP0 ring set up, then Address
    /// Device (Linux xhci_alloc_virt_device, xhci_setup_device)
    fn address_device(&self, slot_id: u8, port: u8, speed: UsbSpeed) -> Result<(), UsbError> {
        let out_ctx = OutputDeviceContext::new(&self.pci_dev).ok_or(UsbError::NoResources)?;
        let mut in_ctx =
            InputContext::new(&self.pci_dev, self.ctx_size).ok_or(UsbError::NoResources)?;
        let ep0_ring = TransferRing::new(&self.pci_dev).ok_or(UsbError::NoResources)?;
        in_ctx.clear();
        in_ctx.control_mut().add_slot();
        in_ctx.control_mut().add_endpoint(1);
        fill_slot(in_ctx.slot_mut(), speed, port, 1);
        let max_packet = speed.default_max_packet_size();
        in_ctx
            .endpoint_mut(1)
            .ok_or(UsbError::NoResources)?
            .configure_control(max_packet, ep0_ring.dma_addr());
        let in_addr = in_ctx.dma_addr();
        let out_addr = out_ctx.dma_addr();
        // On the heap: 31 endpoints are too big for a probe's stack
        let mut eps = Vec::new();
        eps.try_reserve_exact(31)
            .map_err(|_| UsbError::NoResources)?;
        eps.push(VirtEp::with_ring(ep0_ring, max_packet)?);
        eps.resize_with(31, VirtEp::new);
        let dev = try_box(VirtDev {
            out_ctx,
            in_ctx,
            eps,
            speed,
            port,
        })
        .map_err(|_| UsbError::NoResources)?;
        {
            let mut st = self.lock.lock();
            let s = st
                .devs
                .get_mut(usize::from(slot_id))
                .ok_or(UsbError::NoDevice)?;
            *s = Some(dev);
            // SAFETY: entry slot_id (<= MaxSlots) of the DCBAA frame
            unsafe {
                let dcbaa = phys_to_virt(self.dcbaa_phys).cast::<u64>();
                write_volatile(dcbaa.add(usize::from(slot_id)), out_addr);
            }
        }
        fence(Ordering::SeqCst);
        self.command(
            slot_trb(trb_type::ADDRESS_DEVICE, slot_id, 0, in_addr),
            "Address Device",
        )?;
        printkln!("xHCI: Device slot {} addressed", slot_id);
        Ok(())
    }

    /// Slot `slot_id`'s input context cleared, with `f` filling it under
    /// the lock: its DMA address
    fn fill_input_ctx(
        &self,
        slot_id: u8,
        f: impl FnOnce(&mut VirtDev) -> Result<(), UsbError>,
    ) -> Result<u64, UsbError> {
        let mut st = self.lock.lock();
        let dev = st.dev(slot_id).ok_or(UsbError::NoDevice)?;
        dev.in_ctx.clear();
        f(dev)?;
        Ok(dev.in_ctx.dma_addr())
    }

    /// Evaluate Context: EP0's max packet size once the device
    /// descriptor gives it (Linux xhci_check_maxpacket)
    fn evaluate_ep0(&self, slot_id: u8, mps: u16) -> Result<(), UsbError> {
        let addr = self.fill_input_ctx(slot_id, |dev| {
            let ring = dev.eps[0]
                .ring
                .as_ref()
                .ok_or(UsbError::NoDevice)?
                .dma_addr();
            dev.eps[0].maxp = mps;
            dev.in_ctx.control_mut().add_endpoint(1);
            dev.in_ctx
                .endpoint_mut(1)
                .ok_or(UsbError::NoResources)?
                .configure_control(mps, ring);
            Ok(())
        })?;
        self.command(
            slot_trb(trb_type::EVALUATE_CONTEXT, slot_id, 0, addr),
            "Evaluate Context",
        )
        .map(|_| ())
    }

    /// Configure Endpoint: add the endpoints of the configuration being
    /// set (Linux usb_hcd_alloc_bandwidth: xhci_add_endpoint for each,
    /// then xhci_check_bandwidth). Bulk and interrupt endpoints only:
    /// others are skipped (BUGS.md)
    fn configure_endpoints(&self, slot_id: u8, eps: &[UsbEndpoint]) -> Result<(), UsbError> {
        let speed = self
            .lock
            .lock()
            .dev(slot_id)
            .ok_or(UsbError::NoDevice)?
            .speed;
        let mut add = Vec::new();
        for ep in eps {
            let Some(ty) = ep_ctx_type(ep) else {
                printkln!(
                    "xHCI: slot {} endpoint {:#04x}: {:?} unsupported",
                    slot_id,
                    ep.address,
                    ep.ep_type
                );
                continue;
            };
            // Never EP0's context or a ring the device may be using
            // (the parser already drops such descriptors)
            let dci = endpoint_to_dci(ep.address);
            let taken = self
                .lock
                .lock()
                .ep(slot_id, dci)
                .is_some_and(|e| e.ring.is_some());
            if dci <= 1 || taken || add.iter().any(|a: &(u8, u8, EpParams, VirtEp)| a.0 == dci) {
                continue;
            }
            let ring = TransferRing::new(&self.pci_dev).ok_or(UsbError::NoResources)?;
            add.push((
                dci,
                ty,
                ep_params(ep, speed),
                VirtEp::with_ring(ring, ep.maxp())?,
            ));
        }
        if add.is_empty() {
            return Ok(());
        }
        let addr = self.fill_input_ctx(slot_id, |dev| {
            let ctx = &mut dev.in_ctx;
            ctx.control_mut().add_slot();
            let mut last = 1;
            for (dci, ty, p, vep) in &add {
                let ring = vep.ring.as_ref().ok_or(UsbError::NoResources)?.dma_addr();
                ctx.control_mut().add_endpoint(*dci);
                ctx.endpoint_mut(*dci)
                    .ok_or(UsbError::NoResources)?
                    .configure(*ty, p, ring);
                last = last.max(*dci);
            }
            fill_slot(ctx.slot_mut(), dev.speed, dev.port, last);
            Ok(())
        })?;
        self.command(
            slot_trb(trb_type::CONFIGURE_ENDPOINT, slot_id, 0, addr),
            "Configure Endpoint",
        )?;
        let mut st = self.lock.lock();
        for (dci, _, _, vep) in add {
            if let Some(e) = st.ep(slot_id, dci) {
                *e = vep;
            }
        }
        Ok(())
    }

    /// Reset endpoint `ep`'s data toggle or sequence number, its halt
    /// cleared on the device (Linux xhci_endpoint_reset): nothing to do
    /// after a hard Reset Endpoint (EP_HARD_CLEAR_TOGGLE); else the idle
    /// endpoint is stopped (the controller updates its output context)
    /// and dropped and added back as it is by a Configure Endpoint. EP0
    /// has no toggle to reset
    fn endpoint_reset(&self, slot: u8, ep: u8) {
        let dci = endpoint_to_dci(ep);
        if dci <= 1 {
            return;
        }
        {
            let mut st = self.lock.lock();
            let Some(e) = st.ep(slot, dci) else {
                return;
            };
            if e.ep_state & ep_state::EP_HARD_CLEAR_TOGGLE != 0 {
                e.ep_state &= !ep_state::EP_HARD_CLEAR_TOGGLE;
                return;
            }
            if e.ring.is_none() {
                return;
            }
            if !e.tds.is_empty() {
                printkln!(
                    "xHCI: slot {} ep {:#04x}: EP not empty, refuse reset",
                    slot,
                    ep
                );
                return;
            }
            e.ep_state |= ep_state::EP_SOFT_CLEAR_TOGGLE;
        }
        let ctx_size = self.ctx_size;
        {
            // The device's input context, as every other command filling
            // it (Linux gives the command its own)
            let _m = self.mutex.lock();
            // Configured whatever the stop completed with (an endpoint
            // already stopped answers Context State Error), as Linux;
            // only one never queued gives up
            let stop = self.command(
                slot_trb(trb_type::STOP_ENDPOINT, slot, dci, 0),
                "Stop Endpoint",
            );
            if matches!(stop, Ok(_) | Err(UsbError::TransferError(_))) {
                let _ = self
                    .fill_input_ctx(slot, |dev| {
                        dev.out_ctx.copy_for_reset(ctx_size, dci, &mut dev.in_ctx);
                        Ok(())
                    })
                    .and_then(|addr| {
                        self.command(
                            slot_trb(trb_type::CONFIGURE_ENDPOINT, slot, 0, addr),
                            "Configure Endpoint",
                        )
                    });
            }
        }
        if let Some(e) = self.lock.lock().ep(slot, dci) {
            e.ep_state &= !ep_state::EP_SOFT_CLEAR_TOGGLE;
        }
    }

    /// Disable a slot and free its state (Linux xhci_free_dev,
    /// xhci_disable_slot): what is still queued on it is given back
    /// (Shutdown)
    fn free_dev(&self, slot_id: u8) {
        let _m = self.mutex.lock();
        printkln!("xHCI: Disabling slot {}", slot_id);
        let _ = self.command(
            slot_trb(trb_type::DISABLE_SLOT, slot_id, 0, 0),
            "Disable Slot",
        );
        let dev = {
            let mut st = self.lock.lock();
            if let Some(d) = st.dev(slot_id) {
                for ep in d.eps.iter_mut() {
                    super::xhci_ring::kill_ep_tds(ep, Err(UsbError::Shutdown));
                }
            }
            // SAFETY: entry slot_id (<= MaxSlots) of the DCBAA frame
            unsafe {
                let dcbaa = phys_to_virt(self.dcbaa_phys).cast::<u64>();
                write_volatile(dcbaa.add(usize::from(slot_id)), 0);
            }
            st.devs.get_mut(usize::from(slot_id)).and_then(Option::take)
        };
        // Its contexts and rings, freed with no lock held
        drop(dev);
    }

    /// GET_DESCRIPTOR of `len` bytes: what the device sent
    fn get_descriptor(&self, dev: &UsbDevice, ty: u8, len: usize) -> Result<Vec<u8>, UsbError> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(len)
            .map_err(|_| UsbError::NoResources)?;
        buf.resize(len, 0);
        let setup = SetupPacket::get_descriptor(ty, 0, len as u16);
        let n = usb_control_msg(dev, &setup, &mut buf, USB_CTRL_GET_TIMEOUT)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// EP0's max packet size from the first 8 bytes of the device
    /// descriptor, below SuperSpeed (Linux hub_port_init): Evaluate
    /// Context when it differs from the default
    fn ep0_maxpacket(&self, dev: &UsbDevice) -> Result<(), UsbError> {
        let speed = dev.speed;
        if speed.is_super() {
            return Ok(());
        }
        let d = self.get_descriptor(dev, descriptor_type::DEVICE, 8)?;
        let mps = u16::from(*d.get(7).ok_or(UsbError::BufferError)?);
        if mps == speed.default_max_packet_size() {
            return Ok(());
        }
        if speed == UsbSpeed::Low || !matches!(mps, 8 | 16 | 32 | 64) {
            printkln!("xHCI: slot {}: invalid ep0 maxpacket {}", dev.slot_id, mps);
            return Err(UsbError::InvalidParam);
        }
        let _m = self.mutex.lock();
        self.evaluate_ep0(dev.slot_id, mps)
    }

    /// Read the device's descriptors (Linux hub_port_init,
    /// usb_get_configuration): an undescribed device is not enumerated
    fn describe(&self, dev: &mut UsbDevice) -> Result<(), UsbError> {
        self.ep0_maxpacket(dev)?;
        let d = self.get_descriptor(dev, descriptor_type::DEVICE, config::USB_DT_DEVICE_SIZE)?;
        if !config::parse_device(dev, &d) {
            return Err(UsbError::BufferError);
        }
        if dev.num_configurations == 0 {
            return Ok(());
        }
        let c = self.get_descriptor(
            dev,
            descriptor_type::CONFIGURATION,
            config::USB_DT_CONFIG_SIZE,
        )?;
        let total = config::config_total_length(&c).ok_or(UsbError::BufferError)? as usize;
        let c = self.get_descriptor(
            dev,
            descriptor_type::CONFIGURATION,
            total.max(config::USB_DT_CONFIG_SIZE),
        )?;
        let (cfg, intfs) = config::parse_config(&c).ok_or(UsbError::BufferError)?;
        if let Err(e) = self.set_configuration(dev, cfg.value, &intfs) {
            // Registered unconfigured, as Linux after a failed
            // usb_set_configuration
            printkln!(
                "xHCI: slot {}: set configuration failed: {:?}",
                dev.slot_id,
                e
            );
            return Ok(());
        }
        dev.config = cfg;
        dev.interfaces = intfs;
        Ok(())
    }

    /// Make configuration `value` active: its interfaces' endpoints in
    /// the controller, then SET_CONFIGURATION (Linux
    /// usb_set_configuration: usb_hcd_alloc_bandwidth, then the request)
    fn set_configuration(
        &self,
        dev: &UsbDevice,
        value: u8,
        intfs: &[super::UsbInterface],
    ) -> Result<(), UsbError> {
        let eps: Vec<UsbEndpoint> = super::usbcore::cur_altsettings(intfs)
            .iter()
            .flat_map(|f| f.endpoints.iter().cloned())
            .collect();
        {
            let _m = self.mutex.lock();
            self.configure_endpoints(dev.slot_id, &eps)?;
        }
        let setup = SetupPacket::set_configuration(value);
        usb_control_msg(dev, &setup, &mut [], USB_CTRL_SET_TIMEOUT).map(|_| ())
    }

    /// Enumerate the devices on the root ports (Linux hub_event's
    /// hub_port_connect: port reset, slot, address, descriptors)
    #[inline(never)] // its frame stays off the device registration's stack (Linux noinline_for_stack)
    fn enumerate(self: &Arc<Self>) -> Vec<UsbDevice> {
        let mut devices = Vec::new();
        for (port, speed) in self.scan_ports() {
            if let Err(e) = self.reset_port(port) {
                printkln!("xHCI: Failed to reset port {}: {:?}", port, e);
                continue;
            }
            let slot_id = {
                let _m = self.mutex.lock();
                let slot = match self.enable_slot() {
                    Ok(id) => id,
                    Err(e) => {
                        printkln!("xHCI: Failed to enable slot for port {}: {:?}", port, e);
                        continue;
                    }
                };
                if let Err(e) = self.address_device(slot, port, speed) {
                    printkln!("xHCI: Failed to address device on port {}: {:?}", port, e);
                    drop(_m);
                    self.free_dev(slot);
                    continue;
                }
                slot
            };
            let mut device = UsbDevice::new(slot_id, port, speed);
            let hcd: Arc<dyn Hcd> = self.clone();
            device.bus = HcdRef::new(hcd);
            if let Err(e) = self.describe(&mut device) {
                // Linux: "unable to enumerate USB device"
                printkln!("xHCI: port {}: unable to enumerate: {:?}", port, e);
                self.free_dev(slot_id);
                continue;
            }
            printkln!(
                "xHCI: port {} slot {} {:?}: {:04x}:{:04x} class {:02x}, configuration {}, {} interfaces",
                port,
                slot_id,
                speed,
                device.vendor_id,
                device.product_id,
                device.device_class,
                device.config.value,
                device.interfaces.len()
            );
            devices.push(device);
        }
        devices
    }
}

impl Hcd for Xhci {
    fn urb_enqueue(&self, urb: &Arc<Urb>) -> Result<(), UsbError> {
        self.xhci_urb_enqueue(urb)
    }

    fn urb_dequeue(&self, urb: &Arc<Urb>, status: UsbError) -> Result<(), UsbError> {
        self.xhci_urb_dequeue(urb, status)
    }

    fn bh(&self) -> &GivebackBh {
        &self.bh
    }

    fn endpoint_reset(&self, dev: &UsbDevice, ep: u8) {
        self.endpoint_reset(dev.slot_id, ep);
    }

    /// Coherent memory no TRB buffer of which crosses a 64 KiB boundary
    /// within its first 64 KiB: aligned to its size rounded up to a
    /// power of two, at most 64 KiB (a control data stage is one TRB)
    fn buffer_alloc(&self, size: usize) -> Option<DmaCoherent> {
        let align = size
            .next_power_of_two()
            .clamp(crate::mm::frame_alloc::FRAME_SIZE, 1 << 16);
        crate::hw::dma::dma_alloc_coherent_aligned(&self.pci_dev, size, align)
    }

    unsafe fn buffer_free(&self, buf: DmaCoherent) {
        // SAFETY: the caller's: the device is done with it
        unsafe { crate::hw::dma::dma_free_coherent(&self.pci_dev, buf) };
    }
}

/// Halt with interrupts off and wait for HCH, polled per microframe
/// (Linux xhci_halt, xhci_quiesce)
fn halt_regs(regs: &Regs) -> Result<(), UsbError> {
    let cmd = regs.op.read32(op::USBCMD);
    regs.op
        .write32(op::USBCMD, cmd & !(usbcmd::RUN_STOP | XHCI_IRQS));
    let halted = || regs.op.read32(op::USBSTS) & usbsts::HCH != 0;
    poll_timeout(XHCI_MAX_HALT_US, 125, halted).map_err(|_| {
        printkln!("xHCI: Timeout waiting for halt");
        UsbError::Timeout
    })
}

/// Reset the halted controller (Linux xhci_reset)
fn reset_regs(regs: &Regs, quirks: u32, timeout_us: u64) -> Result<(), UsbError> {
    let sts = regs.op.read32(op::USBSTS);
    if sts == !0 {
        printkln!("xHCI: Host not accessible, reset failed.");
        return Err(UsbError::NoDevice);
    }
    if sts & usbsts::HCH == 0 {
        printkln!("xHCI: Host controller not halted, aborting reset.");
        return Err(UsbError::Timeout);
    }
    let cmd = regs.op.read32(op::USBCMD);
    regs.op.write32(op::USBCMD, cmd | usbcmd::HCRST);
    // Intel xHCs need 1 ms after setting HCRST before any register
    // access, or that access "may result in a system hang very
    // rarely" (Linux XHCI_INTEL_HOST)
    if quirks & quirk::INTEL_HOST != 0 {
        udelay(1000);
    }
    let reset_done = || regs.op.read32(op::USBCMD) & usbcmd::HCRST == 0;
    // No register but USBSTS until Controller Not Ready clears
    let ready = || regs.op.read32(op::USBSTS) & usbsts::CNR == 0;
    poll_timeout(timeout_us, 10, reset_done)
        .and_then(|()| poll_timeout(timeout_us, 10, ready))
        .map_err(|_| {
            printkln!("xHCI: Timeout waiting for reset");
            UsbError::Timeout
        })
}

/// Give the controller the scratchpad memory it asks for (xHCI 4.20,
/// Linux scratchpad_alloc): zeroed pages, listed in an array that
/// DCBAA entry 0 points at. The controller keeps internal state there;
/// without it, it would take entry 0 - zero - as the array's address
/// and use whatever that memory holds as page pointers.
fn alloc_scratchpads(regs: &Regs, mem: &mut XhciMem, dcbaa: u64) -> Result<(), UsbError> {
    let n = hcs_max_scratchpad(regs.cap.read32(0x08));
    if n == 0 {
        return Ok(());
    }
    // PAGESIZE bit 0: 4 KiB pages, the frame size; the array (8 bytes
    // per buffer) must fit one frame
    let pagesize = regs.op.read32(op::PAGESIZE);
    if pagesize & 1 == 0 || n > 512 {
        printkln!(
            "xHCI: unsupported scratchpad layout: {} buffers, PAGESIZE {:#x}",
            n,
            pagesize
        );
        return Err(UsbError::NoResources);
    }
    let array = mem.frame()?;
    let entries = phys_to_virt(array).cast::<u64>();
    for i in 0..n {
        let buf = mem.frame()?;
        // SAFETY: entry i of the array frame (n <= 512)
        unsafe { write_volatile(entries.add(i as usize), buf) };
    }
    // SAFETY: entry 0 of the DCBAA frame
    unsafe { write_volatile(phys_to_virt(dcbaa).cast::<u64>(), array) };
    printkln!("xHCI: {} scratchpad buffers", n);
    Ok(())
}

/// A command TRB for `slot` (bits 31:24), endpoint `dci` (20:16)
pub(super) fn slot_trb(ty: u8, slot: u8, dci: u8, parameter: u64) -> Trb {
    let mut trb = Trb::new();
    trb.parameter = parameter;
    trb.set_type(ty);
    trb.control |= u32::from(slot) << 24 | u32::from(dci) << 16;
    trb
}

/// A root-port device's slot context (route string 0)
fn fill_slot(slot: &mut super::context::SlotContext, speed: UsbSpeed, port: u8, entries: u8) {
    slot.set_route_string(0);
    slot.set_speed(speed as u8);
    slot.set_context_entries(entries);
    slot.set_root_hub_port(port);
}

/// An endpoint's context type, if supported (bulk, interrupt)
fn ep_ctx_type(ep: &UsbEndpoint) -> Option<u8> {
    use super::context::EndpointType as T;
    Some(match (ep.ep_type, ep.is_in()) {
        (EndpointType::Bulk, true) => T::BULK_IN,
        (EndpointType::Bulk, false) => T::BULK_OUT,
        (EndpointType::Interrupt, true) => T::INTERRUPT_IN,
        (EndpointType::Interrupt, false) => T::INTERRUPT_OUT,
        _ => return None,
    })
}

/// Linux fls
fn fls(x: u32) -> i32 {
    32 - x.leading_zeros() as i32
}

/// An endpoint context's parameters from its descriptors (Linux
/// xhci_endpoint_init: xhci_get_endpoint_interval,
/// xhci_get_endpoint_max_burst, xhci_get_max_esit_payload)
fn ep_params(ep: &UsbEndpoint, speed: UsbSpeed) -> EpParams {
    let periodic = matches!(
        ep.ep_type,
        EndpointType::Interrupt | EndpointType::Isochronous
    );
    let burst = match speed {
        _ if speed.is_super() => ep.max_burst,
        UsbSpeed::High if periodic => ep.mult(),
        _ => 0,
    };
    let interval = match speed {
        _ if !periodic => 0,
        // xhci_parse_exponent_interval: 2^(bInterval-1) microframes
        UsbSpeed::High | UsbSpeed::Super | UsbSpeed::SuperPlus => ep.interval.clamp(1, 16) - 1,
        // xhci_parse_frame_interval: bInterval frames, as an exponent
        _ => (fls(u32::from(ep.interval) * 8) - 1).clamp(3, 10) as u8,
    };
    let esit = match speed {
        _ if !periodic => 0,
        _ if speed.is_super() => u32::from(ep.bytes_per_interval),
        _ => u32::from(ep.maxp()) * (u32::from(burst) + 1),
    };
    EpParams {
        max_packet: ep.maxp(),
        burst,
        interval,
        esit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Neutral keeps power and status, never writes PED, PR or the
    /// change bits
    #[test]
    fn portsc_neutral() {
        let live = 0x0002_1203 | portsc::PRC | (1 << 9); // connected, enabled, changes pending, powered
        let n = portsc::to_neutral(live);
        assert_eq!(n & (1 << 9), 1 << 9);
        assert_eq!(n & portsc::CCS, portsc::CCS);
        assert_eq!(
            n & (portsc::PED | portsc::PR | portsc::CSC | portsc::PRC),
            0
        );
    }

    #[test]
    fn scratchpad_count() {
        assert_eq!(hcs_max_scratchpad(0), 0);
        assert_eq!(hcs_max_scratchpad(4 << 27), 4);
        assert_eq!(hcs_max_scratchpad(1 << 21), 32);
        assert_eq!(hcs_max_scratchpad(0xffff_ffff), 1023);
    }

    fn ep(ep_type: EndpointType, max_packet_size: u16, interval: u8) -> UsbEndpoint {
        UsbEndpoint {
            address: 0x81,
            ep_type,
            max_packet_size,
            interval,
            max_burst: 0,
            bytes_per_interval: 0,
        }
    }

    #[test]
    fn endpoint_params() {
        // full-speed interrupt, 10 ms: 80 microframes -> 2^6
        let p = ep_params(&ep(EndpointType::Interrupt, 8, 10), UsbSpeed::Full);
        assert_eq!((p.interval, p.esit, p.burst), (6, 8, 0));
        // clamped to 2^3..2^10 microframes
        let low = ep_params(&ep(EndpointType::Interrupt, 8, 1), UsbSpeed::Low);
        assert_eq!(low.interval, 3);
        let long = ep_params(&ep(EndpointType::Interrupt, 8, 255), UsbSpeed::Full);
        assert_eq!(long.interval, 10);
        // high speed, 2 extra transactions: burst 2, payload 3 packets
        let hs = ep(EndpointType::Interrupt, 1024 | (2 << 11), 4);
        let p = ep_params(&hs, UsbSpeed::High);
        assert_eq!(
            (p.max_packet, p.burst, p.interval, p.esit),
            (1024, 2, 3, 3072)
        );
        // bulk: no interval or payload; SuperSpeed burst from the companion
        let mut b = ep(EndpointType::Bulk, 1024, 0);
        b.max_burst = 15;
        let p = ep_params(&b, UsbSpeed::Super);
        assert_eq!(
            (p.max_packet, p.burst, p.interval, p.esit),
            (1024, 15, 0, 0)
        );
        assert_eq!(ep_params(&b, UsbSpeed::High).burst, 0);
    }

    #[test]
    fn command_trb() {
        let t = slot_trb(trb_type::RESET_ENDPOINT, 3, 1, 0);
        assert_eq!(t.get_type(), trb_type::RESET_ENDPOINT);
        assert_eq!(t.control >> 24, 3);
        assert_eq!((t.control >> 16) & 0x1f, 1);
    }

    /// A fake 16KiB BAR (QEMU qemu-xhci's layout) with the given
    /// CAPLENGTH, HCSPARAMS1, DBOFF and RTSOFF, carved into windows
    fn regs_of(caplen: u32, hcs1: u32, dboff: u32, rtsoff: u32) -> Option<Regs> {
        let mut bar = alloc::vec![0u32; 0x1000].into_boxed_slice();
        bar[0] = caplen;
        bar[1] = hcs1;
        bar[5] = dboff;
        bar[6] = rtsoff;
        let p = NonNull::new(Box::leak(bar).as_mut_ptr().cast::<u8>()).unwrap();
        // SAFETY: 16KiB of leaked heap, never freed: as good as a
        // permanently mapped register block for a test
        Regs::map(unsafe { IoMem::new(p, 0x4000) })
    }

    #[test]
    fn regs_inside_bar() {
        // 64 slots, 8 ports, doorbells at 0x2000, runtime at 0x1000
        let r = regs_of(0x40, (8 << 24) | 64, 0x2000, 0x1000).unwrap();
        assert_eq!(r.op.len(), 0x400 + 8 * 0x10);
        assert_eq!(r.port.len(), 8 * 0x10);
        assert_eq!(r.db.len(), 65 * 4);
        assert_eq!(r.rt.addr() - r.cap.addr(), 0x1000);
        // reserved offset bits are ignored
        assert!(regs_of(0x40, (8 << 24) | 64, 0x2003, 0x101f).is_some());
    }

    #[test]
    fn regs_outside_bar_refused() {
        let ok = (8 << 24) | 64;
        assert!(regs_of(0x10, ok, 0x2000, 0x1000).is_none()); // CAPLENGTH short
        assert!(regs_of(0x42, ok, 0x2000, 0x1000).is_none()); // misaligned
        assert!(regs_of(0x40, ok, 0x3ff0, 0x1000).is_none()); // doorbells past it
        assert!(regs_of(0x40, ok, 0x2000, 0x3fe0).is_none()); // runtime past it
        assert!(regs_of(0x40, ok, 0xffff_fffc, 0x1000).is_none());
        // the most a byte CAPLENGTH and MaxPorts can claim still fits
        assert!(regs_of(0xfc, (255 << 24) | 64, 0x2000, 0x1000).is_some());
    }

    #[test]
    fn dma_mask() {
        assert_eq!(hcc_dma_mask(0), 0xffff_ffff);
        assert_eq!(hcc_dma_mask(0x0008_0001), u64::MAX); // QEMU qemu-xhci
        assert_eq!(hcc_dma_mask(!1), 0xffff_ffff);
    }

    /// The command ring wraps past its Link TRB, toggling the cycle
    /// state, and has room for SIZE - 2 outstanding commands
    #[test]
    fn command_ring_room() {
        let mem = alloc::vec![Trb::new(); CommandRing::SIZE].leak();
        // SAFETY: SIZE zeroed TRBs, leaked
        let mut r = unsafe { CommandRing::from_parts(mem.as_mut_ptr(), 0x1000) };
        for _ in 0..CommandRing::SIZE - 2 {
            assert!(r.has_room());
            r.enqueue(slot_trb(trb_type::ENABLE_SLOT, 0, 0, 0));
        }
        assert!(!r.has_room());
        r.inc_deq();
        assert!(r.has_room());
        assert!(!r.is_empty());
    }
}
