//! xHCI USB 3.0 Host Controller Driver
//!
//! Implements the USB host controller interface for xHCI (eXtensible Host Controller Interface).
//!
//! `XHCI_PCI_DRIVER` binds the controller on the PCI bus.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use core::any::Any;
use core::mem::MaybeUninit;
use core::ptr::{NonNull, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};

use crate::sync::spin::Mutex;

use crate::arch::FrameAlloc;
use crate::arch::phys_to_virt;
use crate::hw::mmio::IoMem;
use crate::hw::pci::PciDevice;
use crate::irq::{IrqFn, IrqRegistration, IrqReturn};
use crate::printkln;
use crate::time::delay::{poll_timeout, udelay};
use crate::util::error::KernelError;
use crate::util::kalloc::{try_arc, try_box};

/// Halt and start handshakes (Linux XHCI_MAX_HALT_USEC)
pub(super) const XHCI_MAX_HALT_US: u64 = 32_000;
/// Reset handshakes at initialization (Linux XHCI_RESET_LONG_USEC)
const XHCI_RESET_LONG_US: u64 = 10_000_000;
/// Reset handshakes later on (Linux XHCI_RESET_SHORT_USEC)
const XHCI_RESET_SHORT_US: u64 = 250_000;
/// Command completion (Linux XHCI_CMD_DEFAULT_TIMEOUT)
const XHCI_CMD_US: u64 = 5_000_000;
/// Transfer completion (Linux USB_CTRL_GET_TIMEOUT)
const XHCI_TRANSFER_US: u64 = 5_000_000;
/// USB serial console transfer completion
const XHCI_CONSOLE_US: u64 = 100_000;
/// Root port reset (Linux HUB_RESET_TIMEOUT)
const PORT_RESET_US: u64 = 800_000;

pub(super) const PCI_VENDOR_INTEL: u16 = 0x8086;

/// USBCMD interrupter, host system error and wrap event enables (Linux
/// XHCI_IRQS)
pub(super) const XHCI_IRQS: u32 = (1 << 2) | (1 << 3) | (1 << 10);

/// Chipset quirks, set once from the PCI IDs (Linux xhci_pci_quirks)
mod quirk {
    use super::PCI_VENDOR_INTEL;
    use crate::hw::pci::PciDevice;

    /// Intel host: 1 ms after HCRST before any register access
    pub const INTEL_HOST: u32 = 1 << 0;
    /// Ports go back to EHCI at shutdown, or the machine powers back on
    pub const SPURIOUS_REBOOT: u32 = 1 << 1;
    /// Reset and D3hot at shutdown, or spurious wakeups follow
    pub const SPURIOUS_WAKEUP: u32 = 1 << 2;

    pub fn of(dev: &PciDevice) -> u32 {
        if dev.header.vendor_id != PCI_VENDOR_INTEL {
            return 0;
        }
        INTEL_HOST
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

use super::context::EpParams;
use super::context::{InputContext, OutputDeviceContext, endpoint_to_dci};
use super::transfer::{CompletionCode, TransferRing, Trb as TransferTrb, TrbType};
use super::{
    EndpointType, SetupPacket, UsbController, UsbDevice, UsbEndpoint, UsbError, UsbSpeed, config,
    descriptor_type,
};

// ============================================================================
// Global USB Host Access
// ============================================================================

/// Check if USB tracing is enabled (uses generic USB stack flag)
#[inline]
fn usb_trace() -> bool {
    super::usb_trace_enabled()
}

/// A trace event (Linux xhci-trace.h tracepoints, xhci_dbg_trace): to
/// the trace ring, never printk, so the USB serial console's own
/// transfers can be traced
macro_rules! xhci_trace {
    ($name:literal, $($arg:tt)*) => {
        crate::trace::emit($name, format_args!($($arg)*))
    };
}

/// Global USB host controller for access from USB drivers (like MSC)
static USB_CONTROLLER: Mutex<Option<XhciController>> = Mutex::new(None);

// ============================================================================
// Interrupt Support
// ============================================================================

/// xHCI interrupt state - accessible from ISR without locking
///
/// This is separate from the controller so the ISR can access MMIO registers
/// without holding the controller lock.
struct XhciIrqState {
    /// Operational registers base (set during init)
    op_regs: AtomicU64,
    /// Runtime registers base (set during init)
    rt_regs: AtomicU64,
    /// Interrupt pending flag (set by ISR, cleared by waiters)
    interrupt_pending: AtomicBool,
    /// Whether interrupt mode is enabled
    enabled: AtomicBool,
}

impl XhciIrqState {
    const fn new() -> Self {
        Self {
            op_regs: AtomicU64::new(0),
            rt_regs: AtomicU64::new(0),
            interrupt_pending: AtomicBool::new(false),
            enabled: AtomicBool::new(false),
        }
    }
}

/// Global xHCI interrupt state for ISR access
static XHCI_IRQ_STATE: XhciIrqState = XhciIrqState::new();

/// Transfer counter for debugging
static TRANSFER_COUNT: AtomicUsize = AtomicUsize::new(0);

/// xHCI interrupt handler
///
/// Called from the IRQ dispatch system when the xHCI's IRQ fires.
fn xhci_irq_handler(_irq: u32) -> IrqReturn {
    xhci_irq_handler_common().into()
}

/// Common IRQ handler logic (arch-independent)
fn xhci_irq_handler_common() -> bool {
    // Only handle if we're initialized
    if !XHCI_IRQ_STATE.enabled.load(Ordering::Acquire) {
        return false;
    }

    let op_regs = XHCI_IRQ_STATE.op_regs.load(Ordering::Acquire);
    let rt_regs = XHCI_IRQ_STATE.rt_regs.load(Ordering::Acquire);

    if op_regs == 0 || rt_regs == 0 {
        return false;
    }

    // Check USBSTS.EINT (Event Interrupt) - bit 3
    let usbsts = unsafe { read_volatile((op_regs + 0x04) as *const u32) };
    if (usbsts & (1 << 3)) == 0 {
        return false; // Not our interrupt
    }

    // Clear USBSTS.EINT by writing 1 to bit 3 (RW1C)
    unsafe {
        write_volatile((op_regs + 0x04) as *mut u32, 1 << 3);
    }

    // Clear IMAN.IP (Interrupt Pending) for interrupter 0
    // IMAN is at rt_regs + 0x20, IP is bit 0 (RW1C)
    let iman = unsafe { read_volatile((rt_regs + 0x20) as *const u32) };
    unsafe {
        write_volatile((rt_regs + 0x20) as *mut u32, iman | 1);
    }

    // Signal waiters
    XHCI_IRQ_STATE
        .interrupt_pending
        .store(true, Ordering::Release);

    true // We handled the interrupt
}

/// The controller lock (thread context only; a printk under it only
/// queues the USB console's output, which its write work sends later)
fn acquire_usb_controller() -> crate::sync::spin::MutexGuard<'static, Option<XhciController>> {
    USB_CONTROLLER.lock()
}

/// Perform a bulk OUT transfer (host to device)
pub fn usb_bulk_out(slot_id: u8, endpoint: u8, data: &[u8]) -> Result<usize, UsbError> {
    let mut guard = acquire_usb_controller();
    let controller = guard.as_mut().ok_or(UsbError::NoDevice)?;
    controller.do_bulk_out(slot_id, endpoint, data, XHCI_TRANSFER_US)
}

/// A bulk OUT transfer for the USB serial console's write work: a short
/// timeout, so a stalled console device holds the controller little
pub fn usb_console_out(slot_id: u8, endpoint: u8, data: &[u8]) -> Result<usize, UsbError> {
    let mut guard = acquire_usb_controller();
    let controller = guard.as_mut().ok_or(UsbError::NoDevice)?;
    controller.do_bulk_out(slot_id, endpoint, data, XHCI_CONSOLE_US)
}

/// Perform a bulk IN transfer (device to host)
pub fn usb_bulk_in(slot_id: u8, endpoint: u8, data: &mut [u8]) -> Result<usize, UsbError> {
    let mut guard = acquire_usb_controller();
    let controller = guard.as_mut().ok_or(UsbError::NoDevice)?;
    controller.do_bulk_in(slot_id, endpoint, data, XHCI_TRANSFER_US)
}

/// Store the USB host controller for global access
fn store_usb_host(controller: XhciController) {
    *acquire_usb_controller() = Some(controller);
}

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
/// devices below it (Linux usb_add_hcd: root hub, then hub_event)
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

    let mut controller = XhciController::new(mmio_base, pci_dev.clone());
    let mut fa = crate::mm::frame_alloc::FrameAllocRef(&crate::FRAME_ALLOCATOR);
    if let Err(e) = controller.init_with_frame_alloc(&mut fa) {
        printkln!("xHCI: Failed to initialize controller: {:?}", e);
        controller.stop();
        return Err(KernelError::Io);
    }
    let usb_devices = controller.enumerate_devices().unwrap_or_else(|e| {
        printkln!("xHCI: Failed to enumerate devices: {:?}", e);
        Vec::new()
    });
    // Stored for global access (the USB drivers' transfers)
    store_usb_host(controller);
    let usb = super::usb_register_devices(dev, usb_devices);
    Ok(Box::write(
        slot,
        XhciDeviceHandle {
            usb,
            bdf: (pci_dev.bus, pci_dev.device, pci_dev.function),
        },
    ))
}

/// A bound xHCI: its USB devices (the root hub last)
struct XhciDeviceHandle {
    usb: Vec<alloc::sync::Arc<crate::base::Device>>,
    /// Its PCI function: bus, device, function
    bdf: (u8, u8, u8),
}

impl crate::base::Bound for XhciDeviceHandle {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Linux xhci_pci_remove, usb_remove_hcd: the root hub disconnects
    /// (its devices and their interfaces unbind and go, bottom-up),
    /// then the controller is taken from the drivers' reach and
    /// stopped: slots disabled, halted and reset, its IRQ freed, its
    /// memory released
    fn remove(&self) {
        super::usbcore::usb_unregister_devices(&self.usb);
        let hc = {
            let mut g = acquire_usb_controller();
            // Not a second xHCI's, which replaced this one (BUGS.md);
            // matched by address, nothing allocated under the lock
            match g.as_ref() {
                Some(c) if (c.pci_dev.bus, c.pci_dev.device, c.pci_dev.function) == self.bdf => {
                    g.take()
                }
                _ => None,
            }
        };
        if let Some(mut hc) = hc {
            hc.stop();
        }
    }

    /// Power-off/restart (Linux xhci_pci_shutdown)
    fn shutdown(&self) {
        let mut guard = acquire_usb_controller();
        if let Some(controller) = guard.as_mut() {
            controller.shutdown_hc();
        }
    }
}

/// USBCMD register bits
mod usbcmd {
    pub const RUN_STOP: u32 = 1 << 0;
    pub const HCRST: u32 = 1 << 1;
}

/// USBSTS register bits
mod usbsts {
    pub const HCH: u32 = 1 << 0; // Host Controller Halted
    pub const CNR: u32 = 1 << 11; // Controller Not Ready
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

/// A ring's TRB array (DMA memory, reached only through its owner's
/// lock, the controller lock)
struct TrbPtr(*mut Trb);

// SAFETY: an address; the TRBs are touched only under the controller
// lock (USB_CONTROLLER)
unsafe impl Send for TrbPtr {}
// SAFETY: as above
unsafe impl Sync for TrbPtr {}

/// Transfer Request Block (TRB)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(16))]
struct Trb {
    /// Parameter (data pointer or other info)
    parameter: u64,
    /// Status field
    status: u32,
    /// Control field (includes TRB type and flags)
    control: u32,
}

impl Trb {
    const fn new() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
        }
    }

    fn set_type(&mut self, trb_type: u8) {
        self.control = (self.control & !0xFC00) | (u32::from(trb_type) << 10);
    }

    fn get_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    fn set_cycle(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }
}

/// TRB types
mod trb_type {
    pub const LINK: u8 = 6;
    pub const ENABLE_SLOT: u8 = 9;
    pub const DISABLE_SLOT: u8 = 10;
    pub const ADDRESS_DEVICE: u8 = 11;
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    pub const EVALUATE_CONTEXT: u8 = 13;
    pub const RESET_ENDPOINT: u8 = 14;
    pub const STOP_ENDPOINT: u8 = 15;
    pub const SET_TR_DEQUEUE: u8 = 16;
    pub const COMMAND_COMPLETION: u8 = 33;
    pub const TRANSFER_EVENT: u8 = 32;
}

/// Per-device xHCI state
///
/// Tracks the Device Context, Input Context, and Transfer Rings for each endpoint.
struct DeviceState {
    /// Output Device Context (xHCI writes device state here)
    #[expect(
        dead_code,
        reason = "owns the DMA buffer the DCBAA entry points the controller at"
    )]
    output_ctx: OutputDeviceContext,
    /// Input Context (for Address Device and Configure Endpoint)
    input_ctx: InputContext,
    /// Transfer Rings per endpoint (indexed by DCI: 1=EP0, 2=EP1OUT, 3=EP1IN, etc.)
    transfer_rings: BTreeMap<u8, TransferRing>,
    /// Whether the device has been addressed
    addressed: bool,
    /// Speed and root hub port (the slot context)
    speed: UsbSpeed,
    port: u8,
}

/// TRB completion codes
mod completion_code {
    pub const SUCCESS: u8 = 1;
}

/// Command ring
struct CommandRing {
    /// Physical address of TRB array
    phys: u64,
    /// Virtual address of TRB array
    trbs: TrbPtr,
    /// Number of TRBs in ring
    size: usize,
    /// Enqueue pointer index
    enqueue: usize,
    /// Cycle bit state
    cycle: bool,
}

impl CommandRing {
    const SIZE: usize = 64;

    fn new_with_wrapper(
        frame_alloc: &mut crate::mm::frame_alloc::FrameAllocRef<'_>,
    ) -> Option<Self> {
        let phys = frame_alloc.alloc_frame()?;
        Self::init_from_phys(phys)
    }

    fn init_from_phys(phys: u64) -> Option<Self> {
        // Zero the memory
        unsafe {
            core::ptr::write_bytes(phys_to_virt(phys), 0, 4096);
        }

        // Set up link TRB at end of ring (points back to start)
        let trbs = phys_to_virt(phys).cast::<Trb>();
        unsafe {
            let link = trbs.add(Self::SIZE - 1);
            (*link).parameter = phys;
            (*link).set_type(trb_type::LINK);
            (*link).control |= 1 << 5; // Toggle cycle bit
            (*link).set_cycle(true);
        }

        Some(Self {
            phys,
            trbs: TrbPtr(trbs),
            size: Self::SIZE,
            enqueue: 0,
            cycle: true,
        })
    }

    fn enqueue(&mut self, trb: Trb) -> u64 {
        let index = self.enqueue;
        let trb_ptr = unsafe { self.trbs.0.add(index) };

        // Write TRB (set cycle bit last to make it valid)
        let mut trb = trb;
        trb.set_cycle(self.cycle);

        unsafe {
            write_volatile(trb_ptr, trb);
        }
        fence(Ordering::SeqCst);

        // Advance enqueue pointer
        self.enqueue += 1;
        if self.enqueue >= self.size - 1 {
            // Wrap around (skip link TRB)
            self.enqueue = 0;
            self.cycle = !self.cycle;

            // Update link TRB cycle bit
            unsafe {
                let link = self.trbs.0.add(self.size - 1);
                if self.cycle {
                    (*link).control |= 1;
                } else {
                    (*link).control &= !1;
                }
            }
        }

        self.phys + (index * 16) as u64
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

/// Event ring
struct EventRing {
    /// Physical address of TRB array
    phys: u64,
    /// Virtual address of TRB array
    trbs: TrbPtr,
    /// Number of TRBs
    size: usize,
    /// Dequeue pointer index
    dequeue: usize,
    /// Cycle bit state
    cycle: bool,
    /// ERST physical address
    erst_phys: u64,
}

impl EventRing {
    const SIZE: usize = 64;

    fn new_with_wrapper(
        frame_alloc: &mut crate::mm::frame_alloc::FrameAllocRef<'_>,
    ) -> Option<Self> {
        let phys = frame_alloc.alloc_frame()?;
        let Some(erst_phys) = frame_alloc.alloc_frame() else {
            frame_alloc.free_frame(phys);
            return None;
        };
        Self::init_from_phys(phys, erst_phys)
    }

    fn init_from_phys(phys: u64, erst_phys: u64) -> Option<Self> {
        // Zero event ring memory
        unsafe {
            core::ptr::write_bytes(phys_to_virt(phys), 0, 4096);
        }

        // Zero and initialize ERST (Event Ring Segment Table)
        unsafe {
            core::ptr::write_bytes(phys_to_virt(erst_phys), 0, 4096);

            // Set up single ERST entry
            let erst = phys_to_virt(erst_phys).cast::<ErstEntry>();
            (*erst).ring_segment_base = phys;
            (*erst).ring_segment_size = Self::SIZE as u16;
        }

        Some(Self {
            phys,
            trbs: TrbPtr(phys_to_virt(phys).cast::<Trb>()),
            size: Self::SIZE,
            dequeue: 0,
            cycle: true,
            erst_phys,
        })
    }

    fn dequeue(&mut self) -> Option<Trb> {
        let trb_ptr = unsafe { self.trbs.0.add(self.dequeue) };
        // The cycle bit first, then the rest (Linux xhci_handle_event:
        // flags, rmb, fields): read in one go, the parameter could predate
        // the controller's write of the control word that made it valid,
        // and a completion would not match its TRB
        let control = unsafe { read_volatile(&raw const (*trb_ptr).control) };
        if (control & 1 != 0) != self.cycle {
            return None;
        }
        fence(Ordering::Acquire);
        let trb = unsafe { read_volatile(trb_ptr) };

        // Advance dequeue pointer
        self.dequeue += 1;
        if self.dequeue >= self.size {
            self.dequeue = 0;
            self.cycle = !self.cycle;
        }

        Some(trb)
    }

    fn dequeue_phys(&self) -> u64 {
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
struct Regs {
    cap: IoMem,
    op: IoMem,
    port: IoMem,
    db: IoMem,
    rt: IoMem,
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

/// xHCI controller state
pub struct XhciController {
    /// MMIO base address
    mmio_base: u64,
    /// PCI device info
    pci_dev: PciDevice,
    /// Register windows (None until BAR0 is mapped and checked, and
    /// again once the controller is stopped)
    regs: Option<Regs>,
    /// Command ring
    cmd_ring: Option<CommandRing>,
    /// Event ring
    event_ring: Option<EventRing>,
    /// Device Context Base Address Array (physical)
    dcbaa_phys: u64,
    /// Maximum device slots
    max_slots: u8,
    /// Maximum ports
    max_ports: u8,
    /// Bytes per device context (HCCPARAMS1.CSZ)
    ctx_size: usize,
    /// Chipset quirks (`quirk::*`), from the PCI IDs at creation
    quirks: u32,
    /// HCIVERSION
    hci_version: u16,
    /// Initialized flag
    initialized: bool,
    /// Connected devices
    devices: Vec<UsbDevice>,
    /// Per-device state (slot_id -> DeviceState)
    device_states: BTreeMap<u8, DeviceState>,
    /// The INTx handler (if interrupt mode enabled)
    irq: Option<IrqRegistration<IrqFn>>,
    /// Size of the register mapping at `mmio_base` (0: not mapped)
    mmio_len: u64,
    /// Scratchpad frames: the array, then its buffers
    scratch: Vec<u64>,
}

impl XhciController {
    /// Create a new xHCI controller (not yet initialized)
    pub fn new(mmio_base: u64, pci_dev: PciDevice) -> Self {
        Self {
            mmio_base,
            quirks: quirk::of(&pci_dev),
            pci_dev,
            regs: None,
            cmd_ring: None,
            event_ring: None,
            dcbaa_phys: 0,
            max_slots: 0,
            max_ports: 0,
            ctx_size: 32,
            hci_version: 0,
            initialized: false,
            devices: Vec::new(),
            device_states: BTreeMap::new(),
            irq: None,
            mmio_len: 0,
            scratch: Vec::new(),
        }
    }

    /// Read capability register (all ones before the BAR is mapped,
    /// like a read from a missing device)
    fn read_cap(&self, offset: usize) -> u32 {
        self.regs.map_or(!0, |r| r.cap.read32(offset))
    }

    /// Read operational register
    fn read_op(&self, offset: usize) -> u32 {
        self.regs.map_or(!0, |r| r.op.read32(offset))
    }

    /// Write operational register
    fn write_op(&self, offset: usize, value: u32) {
        if let Some(r) = self.regs {
            r.op.write32(offset, value);
        }
    }

    /// Offset of `port`'s (1-based) register at `offset` in the port
    /// window; past MaxPorts the window check refuses it
    fn port_off(port: u8, offset: usize) -> Option<usize> {
        Some(usize::from(port).checked_sub(1)? * PORT_STRIDE + offset)
    }

    /// Read port register (all ones for a port the controller lacks)
    fn read_port(&self, port: u8, offset: usize) -> u32 {
        Self::port_off(port, offset)
            .zip(self.regs)
            .and_then(|(o, r)| r.port.try_read32(o))
            .unwrap_or(!0)
    }

    /// Write port register (nothing for a port the controller lacks)
    fn write_port(&self, port: u8, offset: usize, value: u32) {
        if let (Some(o), Some(r)) = (Self::port_off(port, offset), self.regs) {
            r.port.try_write32(o, value);
        }
    }

    /// Ring doorbell register
    ///
    /// Note: A write memory barrier is required before ringing the doorbell
    /// to ensure the xHC sees all TRB/context updates. The enqueue() functions
    /// already include this barrier, so this is just the doorbell write itself.
    /// A slot past MaxSlots (an id the controller made up) rings nothing.
    fn ring_doorbell(&self, slot: u8, target: u8) {
        // Write barrier to ensure all TRB writes are visible to device
        fence(Ordering::Release);
        if let Some(r) = self.regs {
            r.db.try_write32(usize::from(slot) * 4, u32::from(target));
        }
    }

    /// Write runtime register
    fn write_rt(&self, offset: usize, value: u32) {
        if let Some(r) = self.regs {
            r.rt.write32(offset, value);
        }
    }

    /// Write 64-bit runtime register
    fn write_rt64(&self, offset: usize, value: u64) {
        if let Some(r) = self.regs {
            r.rt.write64(offset, value);
        }
    }

    /// Initialize, allocating rings and contexts from `frame_alloc`
    fn init_with_frame_alloc(
        &mut self,
        frame_alloc: &mut crate::mm::frame_alloc::FrameAllocRef<'_>,
    ) -> Result<(), UsbError> {
        // Map MMIO region using ioremap (allocates virtual addresses from dedicated region)
        let bar_size = self.pci_dev.bar_size(0);

        // SAFETY: BAR0 of this xHCI, its register space
        match unsafe { crate::mm::ioremap::ioremap(self.mmio_base, bar_size) } {
            Ok(virt) => {
                // Update all base addresses to virtual address
                let virt_base = virt as u64;
                self.mmio_base = virt_base;
                self.mmio_len = bar_size;
                let len = usize::try_from(bar_size).unwrap_or(0);
                // SAFETY: ioremap mapped BAR0's `bar_size` bytes of
                // registers at `virt`; the windows are dropped (stop()
                // clears `regs`) before mem_cleanup unmaps them
                let bar = NonNull::new(virt).map(|p| unsafe { IoMem::new(p, len) });
                self.regs = bar.and_then(Regs::map);
            }
            Err(e) => {
                printkln!("xHCI: Failed to ioremap MMIO region: {:?}", e);
                return Err(UsbError::NoResources);
            }
        }
        // frame_alloc still used for device context allocations below
        if self.regs.is_none() {
            printkln!(
                "xHCI: register offsets outside the {:#x}-byte BAR0",
                bar_size
            );
            return Err(UsbError::NoResources);
        }

        // Read capability registers
        let hciversion = self.read_cap(0) >> 16;
        self.hci_version = hciversion as u16;
        let hcsparams1 = self.read_cap(0x04);

        self.max_slots = (hcsparams1 & 0xFF) as u8;
        let hccparams1 = self.read_cap(0x10);
        self.ctx_size = super::context::ctx_size(hccparams1);
        // Contexts, transfer rings and bulk buffers may sit above 4GB:
        // under the default 32-bit mask their DMA mapping fails
        self.pci_dev
            .set_dma_mask_and_coherent(hcc_dma_mask(hccparams1));
        self.max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

        printkln!(
            "xHCI: version={:x}.{:x}, max_slots={}, max_ports={}, context={} bytes",
            (hciversion >> 8) & 0xFF,
            hciversion & 0xFF,
            self.max_slots,
            self.max_ports,
            self.ctx_size
        );

        // Stop controller if running
        self.halt()?;

        // Reset controller
        self.reset_controller(XHCI_RESET_LONG_US)?;

        // Allocate Device Context Base Address Array
        let dcbaa_phys = frame_alloc.alloc_frame().ok_or(UsbError::NoResources)?;
        unsafe {
            core::ptr::write_bytes(phys_to_virt(dcbaa_phys), 0, 4096);
        }
        self.dcbaa_phys = dcbaa_phys;
        self.alloc_scratchpads(frame_alloc)?;

        // Allocate command ring
        self.cmd_ring =
            Some(CommandRing::new_with_wrapper(frame_alloc).ok_or(UsbError::NoResources)?);

        // Allocate event ring
        self.event_ring =
            Some(EventRing::new_with_wrapper(frame_alloc).ok_or(UsbError::NoResources)?);

        // Configure controller
        self.configure()?;

        // Enable interrupt mode (optional - falls back to polling if IRQ unavailable)
        self.enable_interrupts()?;

        // Start controller
        self.start_controller()?;

        self.initialized = true;
        printkln!("xHCI: Controller initialized and running");

        Ok(())
    }

    /// Give the controller the scratchpad memory it asks for (xHCI 4.20,
    /// Linux scratchpad_alloc): zeroed pages, listed in an array that
    /// DCBAA entry 0 points at. The controller keeps internal state
    /// there; without it, it would take entry 0 - zero - as the array's
    /// address and use whatever that memory holds as page pointers.
    fn alloc_scratchpads(
        &mut self,
        frame_alloc: &mut crate::mm::frame_alloc::FrameAllocRef<'_>,
    ) -> Result<(), UsbError> {
        let n = hcs_max_scratchpad(self.read_cap(0x08));
        if n == 0 {
            return Ok(());
        }
        // PAGESIZE bit 0: 4 KiB pages, the frame size; the array (8
        // bytes per buffer) must fit one frame
        if self.read_op(0x08) & 1 == 0 || n > 512 {
            printkln!(
                "xHCI: unsupported scratchpad layout: {} buffers, PAGESIZE {:#x}",
                n,
                self.read_op(0x08)
            );
            return Err(UsbError::NoResources);
        }
        let zeroed = |fa: &mut crate::mm::frame_alloc::FrameAllocRef<'_>| {
            let phys = fa.alloc_frame()?;
            // SAFETY: a fresh frame, in the direct map
            unsafe { core::ptr::write_bytes(phys_to_virt(phys), 0, 4096) };
            Some(phys)
        };
        let array = zeroed(frame_alloc).ok_or(UsbError::NoResources)?;
        self.scratch.push(array);
        let entries = phys_to_virt(array).cast::<u64>();
        for i in 0..n {
            let buf = zeroed(frame_alloc).ok_or(UsbError::NoResources)?;
            self.scratch.push(buf);
            // SAFETY: entry i of the array frame (n <= 512)
            unsafe { write_volatile(entries.add(i as usize), buf) };
        }
        // SAFETY: entry 0 of the DCBAA frame
        unsafe { write_volatile(phys_to_virt(self.dcbaa_phys).cast::<u64>(), array) };
        printkln!("xHCI: {} scratchpad buffers", n);
        Ok(())
    }

    /// Halt the controller
    fn halt(&self) -> Result<(), UsbError> {
        // Stop, with interrupts off (Linux xhci_halt, xhci_quiesce)
        let cmd = self.read_op(0x00);
        self.write_op(0x00, cmd & !(usbcmd::RUN_STOP | XHCI_IRQS));

        // Wait for HCH (halted) bit, polled per microframe (Linux
        // xhci_halt)
        let halted = || self.read_op(0x04) & usbsts::HCH != 0;
        poll_timeout(XHCI_MAX_HALT_US, 125, halted).map_err(|_| {
            printkln!("xHCI: Timeout waiting for halt");
            UsbError::Timeout
        })
    }

    /// Reset the halted controller (Linux xhci_reset)
    fn reset_controller(&self, timeout_us: u64) -> Result<(), UsbError> {
        let sts = self.read_op(0x04);
        if sts == !0 {
            printkln!("xHCI: Host not accessible, reset failed.");
            return Err(UsbError::NoDevice);
        }
        if sts & usbsts::HCH == 0 {
            printkln!("xHCI: Host controller not halted, aborting reset.");
            return Err(UsbError::Timeout);
        }
        let cmd = self.read_op(0x00);
        self.write_op(0x00, cmd | usbcmd::HCRST);

        // Intel xHCs need 1 ms after setting HCRST before any register
        // access, or that access "may result in a system hang very
        // rarely" (Linux XHCI_INTEL_HOST)
        if self.quirks & quirk::INTEL_HOST != 0 {
            udelay(1000);
        }

        let reset_done = || self.read_op(0x00) & usbcmd::HCRST == 0;
        // No register but USBSTS until Controller Not Ready clears
        let ready = || self.read_op(0x04) & usbsts::CNR == 0;
        poll_timeout(timeout_us, 10, reset_done)
            .and_then(|()| poll_timeout(timeout_us, 10, ready))
            .map_err(|_| {
                printkln!("xHCI: Timeout waiting for reset");
                UsbError::Timeout
            })
    }

    /// Configure the controller
    fn configure(&mut self) -> Result<(), UsbError> {
        // Set max device slots
        self.write_op(0x38, u32::from(self.max_slots));

        // Set DCBAAP
        self.write_op(0x30, (self.dcbaa_phys & 0xFFFF_FFFF) as u32);
        self.write_op(0x34, (self.dcbaa_phys >> 32) as u32);

        // Set command ring
        let cmd_ring = self.cmd_ring.as_ref().unwrap();
        let crcr = cmd_ring.phys | 1; // Set cycle bit
        self.write_op(0x18, (crcr & 0xFFFF_FFFF) as u32);
        self.write_op(0x1C, (crcr >> 32) as u32);

        // Configure event ring (interrupter 0)
        let event_ring = self.event_ring.as_ref().unwrap();

        // ERSTSZ (Event Ring Segment Table Size)
        self.write_rt(0x28, 1);

        // ERDP (Event Ring Dequeue Pointer)
        self.write_rt64(0x38, event_ring.phys);

        // ERSTBA (Event Ring Segment Table Base Address)
        self.write_rt64(0x30, event_ring.erst_phys);

        // Enable interrupts:
        // IMAN.IE (Interrupt Enable) for interrupter 0
        // IMAN is at rt_regs + 0x20, IE is bit 1
        self.write_rt(0x20, 0x2); // IE=1, IP=0

        Ok(())
    }

    /// Enable xHCI interrupt mode
    ///
    /// Registers the IRQ handler and enables USBCMD.INTE.
    /// Must be called after configure() and before start_controller().
    fn enable_interrupts(&mut self) -> Result<(), UsbError> {
        // Store register addresses for ISR access: the windows' bases,
        // checked at mapping to hold USBSTS and interrupter 0's IMAN
        let r = self.regs.ok_or(UsbError::NoResources)?;
        XHCI_IRQ_STATE
            .op_regs
            .store(r.op.addr() as u64, Ordering::Release);
        XHCI_IRQ_STATE
            .rt_regs
            .store(r.rt.addr() as u64, Ordering::Release);

        // Register IRQ handler with PCI device
        let h = try_arc(IrqFn(xhci_irq_handler));
        match h.and_then(|h| self.pci_dev.request_irq(h)) {
            Ok(irq) => {
                printkln!("xHCI: Registered IRQ {}", irq.irq());
                self.irq = Some(irq);

                // Enable USBCMD.INTE (Interrupter Enable) - bit 2
                let cmd = self.read_op(0x00);
                self.write_op(0x00, cmd | (1 << 2));

                // Mark interrupt mode as enabled
                XHCI_IRQ_STATE.enabled.store(true, Ordering::Release);
            }
            Err(e) => {
                printkln!("xHCI: Failed to register IRQ handler: {:?}", e);
                // Not fatal - we can fall back to polling
            }
        }

        Ok(())
    }

    /// Start the controller
    fn start_controller(&self) -> Result<(), UsbError> {
        // Set run bit
        let cmd = self.read_op(0x00);
        self.write_op(0x00, cmd | usbcmd::RUN_STOP);

        // Wait for not halted (Linux xhci_start)
        let running = || self.read_op(0x04) & usbsts::HCH == 0;
        poll_timeout(XHCI_MAX_HALT_US, 10, running).map_err(|_| {
            printkln!("xHCI: Timeout waiting for start");
            UsbError::Timeout
        })
    }

    /// Wait for a command completion event
    fn wait_for_command(&mut self, _trb_addr: u64) -> Result<Trb, UsbError> {
        // Always poll the event ring - interrupt is just an optimization hint
        // to reduce polling frequency when we know hardware hasn't signaled yet
        let mut result = None;
        let _ = poll_timeout(XHCI_CMD_US, 0, || {
            // Clear any pending interrupt flag (to allow future interrupts)
            let _ = XHCI_IRQ_STATE
                .interrupt_pending
                .swap(false, Ordering::AcqRel);
            result = self.try_dequeue_command_event();
            result.is_some()
        });
        result.unwrap_or(Err(UsbError::Timeout))
    }

    /// Try to dequeue a command completion event
    /// Consumes and discards any non-command events (e.g., Port Status Change)
    fn try_dequeue_command_event(&mut self) -> Option<Result<Trb, UsbError>> {
        // Process all available events until we find a command completion
        loop {
            let event_ring = self.event_ring.as_mut()?;
            let trb = event_ring.dequeue()?;

            let trb_type = trb.get_type();
            if usb_trace() {
                xhci_trace!(
                    "xhci_handle_event",
                    "type={} ctrl=0x{:08x} status=0x{:08x}",
                    trb_type,
                    trb.control,
                    trb.status
                );
            }

            // Update ERDP after every dequeue
            let dequeue_phys = self.event_ring.as_ref().unwrap().dequeue_phys();
            self.write_rt64(0x38, dequeue_phys | (1 << 3));

            if trb_type == trb_type::COMMAND_COMPLETION {
                return Some(Ok(trb));
            }
            // Continue loop - consume and discard non-command events (e.g., port status change)
        }
    }

    /// Enable a device slot
    fn enable_slot(&mut self) -> Result<u8, UsbError> {
        let cmd_ring = self.cmd_ring.as_mut().unwrap();

        let mut trb = Trb::new();
        trb.set_type(trb_type::ENABLE_SLOT);
        let trb_addr = cmd_ring.enqueue(trb);

        // Ring doorbell 0 (host controller)
        self.ring_doorbell(0, 0);

        // Wait for completion
        let event = self.wait_for_command(trb_addr)?;

        let completion_code = ((event.status >> 24) & 0xFF) as u8;
        if completion_code != completion_code::SUCCESS {
            printkln!("xHCI: Enable slot failed with code {}", completion_code);
            return Err(UsbError::TransferError(completion_code));
        }

        let slot_id = ((event.control >> 24) & 0xFF) as u8;
        printkln!("xHCI: Enabled slot {}", slot_id);
        Ok(slot_id)
    }

    /// Scan ports for connected devices
    pub fn scan_ports(&mut self) -> Vec<(u8, UsbSpeed)> {
        let mut found = Vec::new();

        for port in 1..=self.max_ports {
            let portsc = self.read_port(port, 0);

            if (portsc & portsc::CCS) != 0 {
                let speed = portsc::speed(portsc);
                if let Some(usb_speed) = UsbSpeed::from_xhci_speed(speed) {
                    printkln!(
                        "xHCI: Port {} connected, speed={:?}, portsc=0x{:08x}",
                        port,
                        usb_speed,
                        portsc
                    );
                    found.push((port, usb_speed));
                }
            }
        }

        found
    }

    /// Reset a port
    fn reset_port(&self, port: u8) -> Result<(), UsbError> {
        // Set port reset, writing every other bit back neutrally
        let portsc = self.read_port(port, 0);
        self.write_port(port, 0, portsc::to_neutral(portsc) | portsc::PR);

        // Wait for reset to complete (Linux hub_port_wait_reset:
        // HUB_RESET_TIMEOUT)
        let mut portsc = 0;
        let done = || {
            portsc = self.read_port(port, 0);
            portsc & portsc::PR == 0 && portsc & portsc::PED != 0
        };
        poll_timeout(PORT_RESET_US, 100, done).map_err(|_| UsbError::Timeout)?;
        // Acknowledge the connect and reset changes (write 1 to clear)
        self.write_port(
            port,
            0,
            portsc::to_neutral(portsc) | portsc::CSC | portsc::PRC,
        );
        Ok(())
    }

    /// Address a device (xHCI Address Device command)
    ///
    /// This sets up the Device Context and Control Endpoint (EP0) for the device.
    fn address_device(&mut self, slot_id: u8, port: u8, speed: UsbSpeed) -> Result<(), UsbError> {
        // Create Device State with contexts
        let output_ctx = OutputDeviceContext::new(&self.pci_dev).ok_or(UsbError::NoResources)?;
        let mut input_ctx =
            InputContext::new(&self.pci_dev, self.ctx_size).ok_or(UsbError::NoResources)?;

        // Create Transfer Ring for EP0 (Control Endpoint)
        let ep0_ring = TransferRing::new(&self.pci_dev).ok_or(UsbError::NoResources)?;

        // Configure Input Context
        input_ctx.clear();

        // Add Slot Context and EP0 Context
        {
            let control = input_ctx.control_mut();
            control.add_slot();
            control.add_endpoint(1); // DCI 1 = EP0
        }

        // Slot Context: slot + EP0
        fill_slot(input_ctx.slot_mut(), speed, port, 1);

        // Configure EP0 Context (Control Endpoint)
        {
            let max_packet = speed.default_max_packet_size();
            let ep0 = input_ctx.endpoint_mut(1).ok_or(UsbError::NoResources)?;
            ep0.configure_control(max_packet, ep0_ring.dma_addr());
        }

        // Set DCBAA entry for this slot
        unsafe {
            let dcbaa = phys_to_virt(self.dcbaa_phys).cast::<u64>();
            write_volatile(dcbaa.add(slot_id as usize), output_ctx.dma_addr());
        }
        fence(Ordering::SeqCst);

        // Issue Address Device command
        let cmd_ring = self.cmd_ring.as_mut().ok_or(UsbError::NoResources)?;
        let mut trb = Trb::new();
        trb.parameter = input_ctx.dma_addr();
        trb.set_type(trb_type::ADDRESS_DEVICE);
        trb.control |= u32::from(slot_id) << 24; // Slot ID in bits 31:24

        let trb_addr = cmd_ring.enqueue(trb);
        self.ring_doorbell(0, 0); // Host controller doorbell

        // Wait for completion
        let event = self.wait_for_command(trb_addr)?;
        let cc = ((event.status >> 24) & 0xFF) as u8;
        if cc != completion_code::SUCCESS {
            printkln!("xHCI: Address Device failed with code {}", cc);
            return Err(UsbError::TransferError(cc));
        }

        // Store device state
        let mut transfer_rings = BTreeMap::new();
        transfer_rings.insert(1, ep0_ring); // DCI 1 = EP0

        let state = DeviceState {
            output_ctx,
            input_ctx,
            transfer_rings,
            addressed: true,
            speed,
            port,
        };
        self.device_states.insert(slot_id, state);

        printkln!("xHCI: Device slot {} addressed", slot_id);
        Ok(())
    }

    /// Issue a command and wait for its completion event; a completion
    /// code other than success fails it
    fn command(&mut self, trb: Trb, what: &str) -> Result<Trb, UsbError> {
        let cmd_ring = self.cmd_ring.as_mut().ok_or(UsbError::NoResources)?;
        let addr = cmd_ring.enqueue(trb);
        self.ring_doorbell(0, 0);
        let event = self.wait_for_command(addr)?;
        let cc = ((event.status >> 24) & 0xFF) as u8;
        if cc != completion_code::SUCCESS {
            printkln!("xHCI: {} failed with code {}", what, cc);
            return Err(UsbError::TransferError(cc));
        }
        Ok(event)
    }

    /// The state of addressed `slot_id` with its input context cleared,
    /// and the context's DMA address
    fn input_ctx(&mut self, slot_id: u8) -> Result<(&mut DeviceState, u64), UsbError> {
        let state = self
            .device_states
            .get_mut(&slot_id)
            .ok_or(UsbError::NoDevice)?;
        if !state.addressed {
            return Err(UsbError::NoDevice);
        }
        state.input_ctx.clear();
        let addr = state.input_ctx.dma_addr();
        Ok((state, addr))
    }

    /// Evaluate Context: EP0's max packet size once the device
    /// descriptor gives it (Linux xhci_check_maxpacket)
    fn evaluate_ep0(&mut self, slot_id: u8, mps: u16) -> Result<(), UsbError> {
        let (state, addr) = self.input_ctx(slot_id)?;
        let ring = state
            .transfer_rings
            .get(&1)
            .ok_or(UsbError::NoDevice)?
            .dma_addr();
        state.input_ctx.control_mut().add_endpoint(1);
        state
            .input_ctx
            .endpoint_mut(1)
            .ok_or(UsbError::NoResources)?
            .configure_control(mps, ring);
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
    fn configure_endpoints(&mut self, slot_id: u8, eps: &[UsbEndpoint]) -> Result<(), UsbError> {
        let speed = self
            .device_states
            .get(&slot_id)
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
                .device_states
                .get(&slot_id)
                .is_some_and(|st| st.transfer_rings.contains_key(&dci));
            if dci <= 1 || taken || add.iter().any(|a: &(u8, _, _, _)| a.0 == dci) {
                continue;
            }
            let ring = TransferRing::new(&self.pci_dev).ok_or(UsbError::NoResources)?;
            add.push((dci, ty, ep_params(ep, speed), ring));
        }
        if add.is_empty() {
            return Ok(());
        }
        let (state, addr) = self.input_ctx(slot_id)?;
        let (speed, port) = (state.speed, state.port);
        let ctx = &mut state.input_ctx;
        ctx.control_mut().add_slot();
        let mut last = 1;
        for (dci, ty, p, ring) in &add {
            ctx.control_mut().add_endpoint(*dci);
            ctx.endpoint_mut(*dci)
                .ok_or(UsbError::NoResources)?
                .configure(*ty, p, ring.dma_addr());
            last = last.max(*dci);
        }
        fill_slot(ctx.slot_mut(), speed, port, last);
        self.command(
            slot_trb(trb_type::CONFIGURE_ENDPOINT, slot_id, 0, addr),
            "Configure Endpoint",
        )?;
        let state = self
            .device_states
            .get_mut(&slot_id)
            .ok_or(UsbError::NoDevice)?;
        for (dci, _, _, ring) in add {
            state.transfer_rings.insert(dci, ring);
        }
        Ok(())
    }

    /// Recover a halted endpoint: Reset Endpoint, then its dequeue
    /// pointer past what was queued (Linux xhci_handle_halted_endpoint,
    /// the failed TD dropped)
    fn reset_ep(&mut self, slot_id: u8, dci: u8) -> Result<(), UsbError> {
        self.command(
            slot_trb(trb_type::RESET_ENDPOINT, slot_id, dci, 0),
            "Reset Endpoint",
        )?;
        let deq = self
            .device_states
            .get(&slot_id)
            .and_then(|s| s.transfer_rings.get(&dci))
            .ok_or(UsbError::NoDevice)?
            .enqueue_ptr();
        self.command(
            slot_trb(trb_type::SET_TR_DEQUEUE, slot_id, dci, deq),
            "Set TR Dequeue Pointer",
        )
        .map(|_| ())
    }

    /// A control transfer on EP0 (Linux xhci_queue_ctrl_tx): Setup,
    /// optional Data and Status stages as one TD; `buf` receives (IN)
    /// or supplies (OUT) the data stage, of at most a page. A timeout
    /// leaves the TD queued and leaks its bounce buffer, as the bulk
    /// path; any other failure halts EP0, which is reset
    fn do_control(
        &mut self,
        slot_id: u8,
        setup: &SetupPacket,
        buf: &mut [u8],
        timeout_us: u64,
    ) -> Result<usize, UsbError> {
        if !self.initialized {
            return Err(UsbError::NoDevice);
        }
        let len = (setup.length as usize).min(buf.len());
        if len > crate::mm::frame_alloc::FRAME_SIZE {
            return Err(UsbError::InvalidParam);
        }
        let has_ep0 = self
            .device_states
            .get(&slot_id)
            .is_some_and(|s| s.transfer_rings.contains_key(&1));
        if !has_ep0 {
            return Err(UsbError::NoDevice);
        }
        let is_in = setup.is_in();
        let bounce = match len {
            0 => None,
            n => Some(
                crate::hw::dma::dma_alloc_coherent(&self.pci_dev, n)
                    .ok_or(UsbError::NoResources)?,
            ),
        };
        if let Some(b) = &bounce
            && !is_in
        {
            // SAFETY: a fresh allocation of `len` bytes, not yet the
            // device's
            unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), b.cpu_addr(), len) };
        }
        // Transfer type (TRT) from xHCI 1.0 on: 3 IN data, 2 OUT, 0 none
        let trt = match (self.hci_version >= 0x100, &bounce, is_in) {
            (true, Some(_), true) => 3,
            (true, Some(_), false) => 2,
            _ => 0,
        };
        let mut trbs = Vec::with_capacity(3);
        trbs.push(TransferTrb::setup_stage(&setup.bytes(), trt));
        if let Some(b) = &bounce {
            trbs.push(TransferTrb::data_stage(
                b.dma_addr().as_u64(),
                len as u32,
                is_in,
            ));
        }
        // Status in the opposite direction of the data, IN without any
        trbs.push(TransferTrb::status_stage(!(bounce.is_some() && is_in)));
        let ring = self
            .device_states
            .get_mut(&slot_id)
            .and_then(|s| s.transfer_rings.get_mut(&1))
            .ok_or(UsbError::NoDevice)?;
        let addrs = ring.enqueue_td(&trbs);
        self.ring_doorbell(slot_id, 1);

        let status = addrs[addrs.len() - 1];
        let data = bounce.as_ref().map(|_| addrs[1]);
        let mut done = len;
        let failed = loop {
            // A timeout returns here: `bounce` is leaked, never reused
            let (at, residue, cc) = self.wait_for_trbs(slot_id, 1, &addrs, timeout_us)?;
            let ok = cc == CompletionCode::SUCCESS || cc == CompletionCode::SHORT_PACKET;
            if !ok {
                break Some(cc);
            }
            if Some(at) == data {
                done = len - (residue as usize).min(len);
            }
            if at == status {
                break None;
            }
        };
        if let Some(ring) = self
            .device_states
            .get_mut(&slot_id)
            .and_then(|s| s.transfer_rings.get_mut(&1))
        {
            addrs.iter().for_each(|_| ring.advance_dequeue());
        }
        fence(Ordering::Acquire);
        if let Some(b) = bounce {
            if failed.is_none() && is_in {
                // SAFETY: the TD completed: the device is done writing
                // (ordered by the fence above); `done` <= len fits both
                unsafe { core::ptr::copy_nonoverlapping(b.cpu_addr(), buf.as_mut_ptr(), done) };
            }
            // SAFETY: the TD completed or halted the endpoint: the
            // device no longer touches the buffer
            unsafe { crate::hw::dma::dma_free_coherent(&self.pci_dev, b) };
        }
        match failed {
            None => Ok(if is_in { done } else { len }),
            Some(cc) => {
                let _ = self.reset_ep(slot_id, 1);
                Err(if cc == CompletionCode::STALL_ERROR {
                    UsbError::Stall
                } else {
                    UsbError::TransferError(cc)
                })
            }
        }
    }

    /// GET_DESCRIPTOR of `len` bytes: what the device sent
    fn get_descriptor(&mut self, slot_id: u8, ty: u8, len: usize) -> Result<Vec<u8>, UsbError> {
        let mut buf = alloc::vec![0u8; len];
        let setup = SetupPacket::get_descriptor(ty, 0, len as u16);
        let n = self.do_control(slot_id, &setup, &mut buf, XHCI_TRANSFER_US)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// EP0's max packet size from the first 8 bytes of the device
    /// descriptor, below SuperSpeed (Linux hub_port_init): Evaluate
    /// Context when it differs from the default
    fn ep0_maxpacket(&mut self, slot_id: u8, speed: UsbSpeed) -> Result<(), UsbError> {
        if speed.is_super() {
            return Ok(());
        }
        let d = self.get_descriptor(slot_id, descriptor_type::DEVICE, 8)?;
        let mps = u16::from(*d.get(7).ok_or(UsbError::BufferError)?);
        if mps == speed.default_max_packet_size() {
            return Ok(());
        }
        if speed == UsbSpeed::Low || !matches!(mps, 8 | 16 | 32 | 64) {
            printkln!("xHCI: slot {}: invalid ep0 maxpacket {}", slot_id, mps);
            return Err(UsbError::InvalidParam);
        }
        self.evaluate_ep0(slot_id, mps)
    }

    /// Read the device's descriptors (Linux hub_port_init,
    /// usb_get_configuration): an undescribed device is not enumerated
    fn describe(&mut self, dev: &mut UsbDevice) -> Result<(), UsbError> {
        let slot = dev.slot_id;
        self.ep0_maxpacket(slot, dev.speed)?;
        let d = self.get_descriptor(slot, descriptor_type::DEVICE, config::USB_DT_DEVICE_SIZE)?;
        if !config::parse_device(dev, &d) {
            return Err(UsbError::BufferError);
        }
        if dev.num_configurations == 0 {
            return Ok(());
        }
        let c = self.get_descriptor(
            slot,
            descriptor_type::CONFIGURATION,
            config::USB_DT_CONFIG_SIZE,
        )?;
        let total = config::config_total_length(&c).ok_or(UsbError::BufferError)? as usize;
        let max = crate::mm::frame_alloc::FRAME_SIZE;
        let c = self.get_descriptor(
            slot,
            descriptor_type::CONFIGURATION,
            total.clamp(config::USB_DT_CONFIG_SIZE, max),
        )?;
        let (cfg, intfs) = config::parse_config(&c).ok_or(UsbError::BufferError)?;
        if let Err(e) = self.set_configuration(slot, cfg.value, &intfs) {
            // Registered unconfigured, as Linux after a failed
            // usb_set_configuration
            printkln!("xHCI: slot {}: set configuration failed: {:?}", slot, e);
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
        &mut self,
        slot_id: u8,
        value: u8,
        intfs: &[super::UsbInterface],
    ) -> Result<(), UsbError> {
        let eps: Vec<UsbEndpoint> = super::usbcore::cur_altsettings(intfs)
            .iter()
            .flat_map(|f| f.endpoints.iter().cloned())
            .collect();
        self.configure_endpoints(slot_id, &eps)?;
        let setup = SetupPacket::set_configuration(value);
        self.do_control(slot_id, &setup, &mut [], XHCI_TRANSFER_US)
            .map(|_| ())
    }

    /// Wait for a transfer completion event
    ///
    /// Only the completion of the TRB at DMA address `trb` ends the wait:
    /// completions of other TRBs of the endpoint (a late one for a
    /// timed-out transfer) are consumed and dropped
    fn wait_for_trb(
        &mut self,
        slot_id: u8,
        ep_dci: u8,
        trb: u64,
        timeout_us: u64,
    ) -> Result<(u32, u8), UsbError> {
        self.wait_for_trbs(slot_id, ep_dci, &[trb], timeout_us)
            .map(|(_, residue, cc)| (residue, cc))
    }

    /// Wait for the completion event of any TRB in `want`: the TRB's
    /// address, its residue and completion code
    fn wait_for_trbs(
        &mut self,
        slot_id: u8,
        ep_dci: u8,
        want: &[u64],
        timeout_us: u64,
    ) -> Result<(u64, u32, u8), UsbError> {
        // Always poll the event ring - interrupt is just an optimization hint
        let mut result = None;
        let _ = poll_timeout(timeout_us, 0, || {
            // Clear any pending interrupt flag
            let _ = XHCI_IRQ_STATE
                .interrupt_pending
                .swap(false, Ordering::AcqRel);
            result = self.try_dequeue_transfer_event(slot_id, ep_dci, want);
            result.is_some()
        });
        if let Some(result) = result {
            TRANSFER_COUNT.fetch_add(1, Ordering::Relaxed);
            if usb_trace() {
                xhci_trace!("xhci_urb_giveback", "slot={} dci={}", slot_id, ep_dci);
            }
            return result;
        }

        // A timed-out transfer is the caller's to report (Linux
        // usb_start_wait_urb returns -ETIMEDOUT); the details are traced
        let count = TRANSFER_COUNT.load(Ordering::Relaxed);
        xhci_trace!(
            "xhci_urb_timeout",
            "slot={} dci={} after {} transfers",
            slot_id,
            ep_dci,
            count
        );
        // Dump event ring state on first timeout only
        if count == 393 {
            if let Some(event_ring) = self.event_ring.as_ref() {
                xhci_trace!(
                    "xhci_urb_timeout",
                    "event_ring dequeue={} cycle={}",
                    event_ring.dequeue,
                    event_ring.cycle
                );
            }
            // Dump transfer ring state
            if let Some(state) = self.device_states.get(&slot_id)
                && let Some(ring) = state.transfer_rings.get(&ep_dci)
            {
                let (enqueue, dequeue, cycle) = ring.debug_state();
                xhci_trace!(
                    "xhci_urb_timeout",
                    "transfer_ring enqueue={} dequeue={} cycle={}",
                    enqueue,
                    dequeue,
                    cycle
                );
            }
        }
        Err(UsbError::Timeout)
    }

    /// Try to dequeue a transfer completion event
    /// Consumes and discards any non-matching events
    fn try_dequeue_transfer_event(
        &mut self,
        slot_id: u8,
        ep_dci: u8,
        want: &[u64],
    ) -> Option<Result<(u64, u32, u8), UsbError>> {
        // Process all available events until we find a matching transfer event
        loop {
            let event_ring = self.event_ring.as_mut()?;
            let trb = event_ring.dequeue()?;

            // Update ERDP after every dequeue
            let dequeue_phys = self.event_ring.as_ref().unwrap().dequeue_phys();
            self.write_rt64(0x38, dequeue_phys | (1 << 3));

            let trb_type = trb.get_type();

            if trb_type == trb_type::TRANSFER_EVENT {
                let event_slot = ((trb.control >> 24) & 0xFF) as u8;
                let event_ep = ((trb.control >> 16) & 0x1F) as u8;
                let cc = ((trb.status >> 24) & 0xFF) as u8;
                let transferred = trb.status & 0xFFFFFF;

                if usb_trace() {
                    xhci_trace!(
                        "xhci_handle_transfer",
                        "slot={} ep={} cc={} residue={} (want slot={} ep={})",
                        event_slot,
                        event_ep,
                        cc,
                        transferred,
                        slot_id,
                        ep_dci
                    );
                }

                // The event's parameter is the address of the TRB it
                // completes
                if event_slot == slot_id && event_ep == ep_dci && want.contains(&trb.parameter) {
                    return Some(Ok((trb.parameter, transferred, cc)));
                }
                // Transfer for different slot/ep - continue consuming events
            } else if usb_trace() {
                xhci_trace!("xhci_handle_event", "non-transfer type={}", trb_type);
            }
            // Non-transfer event (command completion, port status, etc.) - continue consuming
        }
    }

    /// Perform a bulk OUT transfer
    fn do_bulk_out(
        &mut self,
        slot_id: u8,
        endpoint: u8,
        data: &[u8],
        timeout_us: u64,
    ) -> Result<usize, UsbError> {
        if !self.initialized {
            return Err(UsbError::NoDevice);
        }
        let ep_dci = endpoint_to_dci(endpoint);

        if usb_trace() {
            xhci_trace!(
                "xhci_urb_enqueue",
                "bulk_out slot={} ep=0x{:02x} dci={} len={}",
                slot_id,
                endpoint,
                ep_dci,
                data.len()
            );
        }

        // The endpoint must exist before the device gets a buffer
        let ring_ok = self
            .device_states
            .get(&slot_id)
            .map(|s| s.transfer_rings.contains_key(&ep_dci));
        match ring_ok {
            None => return Err(UsbError::NoDevice),
            Some(false) => return Err(UsbError::NoResources),
            Some(true) => {}
        }

        // The transfer goes through a driver-owned DMA buffer, not the
        // caller's: a timeout leaves the TRB queued, and the controller
        // may still write it later (the buffer is then leaked, never
        // reused; BUGS.md, xHCI gaps)
        let bounce = crate::hw::dma::dma_alloc_coherent(&self.pci_dev, data.len().max(1))
            .ok_or(UsbError::NoResources)?;
        let dma_addr = bounce.dma_addr();
        // SAFETY: a fresh allocation of at least data.len() bytes, not
        // yet given to the device
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), bounce.cpu_addr(), data.len()) };

        if usb_trace() {
            xhci_trace!("xhci_queue_trb", "bulk_out dma=0x{:x}", dma_addr.as_u64());
        }

        // Get the transfer ring
        let state = self
            .device_states
            .get_mut(&slot_id)
            .ok_or(UsbError::NoDevice)?;
        let ring = state
            .transfer_rings
            .get_mut(&ep_dci)
            .ok_or(UsbError::NoResources)?;

        // Enqueue Normal TRB
        let mut trb = TransferTrb::new();
        trb.parameter = dma_addr.as_u64();
        trb.set_transfer_length(data.len() as u32);
        trb.set_type(TrbType::NORMAL);
        trb.set_ioc(true); // Interrupt on completion
        let trb_addr = ring.enqueue(trb);

        // Ring doorbell for this endpoint
        self.ring_doorbell(slot_id, ep_dci);

        // Wait for this TRB's completion (others are dropped). On a
        // timeout the TRB is still queued and the controller may write
        // `bounce` later: the early return leaks it (DmaCoherent frees
        // only explicitly), never reused
        let (residue, cc) = self.wait_for_trb(slot_id, ep_dci, trb_addr, timeout_us)?;

        // Advance transfer ring dequeue pointer to track completion
        if let Some(state) = self.device_states.get_mut(&slot_id)
            && let Some(ring) = state.transfer_rings.get_mut(&ep_dci)
        {
            ring.advance_dequeue();
        }

        // SAFETY: the transfer completed: the device is done with it
        unsafe { crate::hw::dma::dma_free_coherent(&self.pci_dev, bounce) };

        if cc != CompletionCode::SUCCESS && cc != CompletionCode::SHORT_PACKET {
            xhci_trace!("xhci_urb_giveback", "bulk_out failed cc={}", cc);
            return Err(UsbError::TransferError(cc));
        }

        // Calculate actual transferred bytes
        let transferred = data.len().saturating_sub(residue as usize);
        Ok(transferred)
    }

    /// Perform a bulk IN transfer
    fn do_bulk_in(
        &mut self,
        slot_id: u8,
        endpoint: u8,
        data: &mut [u8],
        timeout_us: u64,
    ) -> Result<usize, UsbError> {
        if !self.initialized {
            return Err(UsbError::NoDevice);
        }
        let ep_dci = endpoint_to_dci(endpoint | 0x80); // IN direction

        if usb_trace() {
            xhci_trace!(
                "xhci_urb_enqueue",
                "bulk_in slot={} ep=0x{:02x} dci={} len={}",
                slot_id,
                endpoint,
                ep_dci,
                data.len()
            );
        }

        // The endpoint must exist before the device gets a buffer
        let ring_ok = self
            .device_states
            .get(&slot_id)
            .map(|s| s.transfer_rings.contains_key(&ep_dci));
        match ring_ok {
            None => return Err(UsbError::NoDevice),
            Some(false) => return Err(UsbError::NoResources),
            Some(true) => {}
        }

        // The transfer goes through a driver-owned DMA buffer, not the
        // caller's: a timeout leaves the TRB queued, and the controller
        // may still write it later (the buffer is then leaked, never
        // reused; BUGS.md, xHCI gaps)
        let bounce = crate::hw::dma::dma_alloc_coherent(&self.pci_dev, data.len().max(1))
            .ok_or(UsbError::NoResources)?;
        let dma_addr = bounce.dma_addr();

        if usb_trace() {
            xhci_trace!("xhci_queue_trb", "bulk_in dma=0x{:x}", dma_addr.as_u64());
        }

        // Get the transfer ring
        let state = self
            .device_states
            .get_mut(&slot_id)
            .ok_or(UsbError::NoDevice)?;
        let ring = state
            .transfer_rings
            .get_mut(&ep_dci)
            .ok_or(UsbError::NoResources)?;

        // Enqueue Normal TRB
        let mut trb = TransferTrb::new();
        trb.parameter = dma_addr.as_u64();
        trb.set_transfer_length(data.len() as u32);
        trb.set_type(TrbType::NORMAL);
        trb.set_ioc(true);
        let trb_addr = ring.enqueue(trb);

        // Ring doorbell
        self.ring_doorbell(slot_id, ep_dci);

        // Wait for this TRB's completion (others are dropped). On a
        // timeout the TRB is still queued and the controller may write
        // `bounce` later: the early return leaks it (DmaCoherent frees
        // only explicitly), never reused
        let (residue, cc) = self.wait_for_trb(slot_id, ep_dci, trb_addr, timeout_us)?;

        // Advance transfer ring dequeue pointer to track completion
        if let Some(state) = self.device_states.get_mut(&slot_id)
            && let Some(ring) = state.transfer_rings.get_mut(&ep_dci)
        {
            ring.advance_dequeue();
        }

        // Read barrier: ensure we see all device writes to DMA buffer
        // before CPU accesses the data
        fence(Ordering::Acquire);

        let transferred = data.len().saturating_sub(residue as usize);
        // SAFETY: the transfer completed (the device is done writing the
        // bounce buffer, ordered by the fence above); `transferred` fits
        // both buffers
        unsafe {
            core::ptr::copy_nonoverlapping(bounce.cpu_addr(), data.as_mut_ptr(), transferred);
            crate::hw::dma::dma_free_coherent(&self.pci_dev, bounce);
        }

        if cc != CompletionCode::SUCCESS && cc != CompletionCode::SHORT_PACKET {
            xhci_trace!("xhci_urb_giveback", "bulk_in failed cc={}", cc);
            return Err(UsbError::TransferError(cc));
        }

        Ok(transferred)
    }

    /// Stop all endpoints for a device (hotplug removal)
    ///
    /// Issues STOP_ENDPOINT commands for each configured endpoint.
    /// This ensures no pending transfers complete after device removal.
    fn stop_device_endpoints(&mut self, slot_id: u8) -> Result<(), UsbError> {
        let Some(state) = self.device_states.get(&slot_id) else {
            // No state = nothing to stop
            return Ok(());
        };

        // The configured endpoints, as a mask of DCIs 1..=31 (Linux walks
        // the fixed virt_dev->eps array; nothing allocated)
        let dcis = state
            .transfer_rings
            .keys()
            .filter(|&&d| (1..32).contains(&d))
            .fold(0u32, |m, &d| m | 1 << d);

        for dci in (1..32u8).filter(|d| dcis & (1 << d) != 0) {
            printkln!("xHCI: Stopping endpoint DCI {} for slot {}", dci, slot_id);

            // Issue STOP_ENDPOINT command
            let Some(cmd_ring) = self.cmd_ring.as_mut() else {
                return Err(UsbError::NoResources);
            };

            let mut trb = Trb::new();
            trb.set_type(trb_type::STOP_ENDPOINT);
            trb.control |= u32::from(slot_id) << 24; // Slot ID in bits 31:24
            trb.control |= u32::from(dci) << 16; // Endpoint ID in bits 20:16

            let trb_addr = cmd_ring.enqueue(trb);
            self.ring_doorbell(0, 0);

            // Wait for completion (ignore errors - device may already be gone)
            let _ = self.wait_for_command(trb_addr);
        }

        Ok(())
    }

    /// Disable a device slot (hotplug removal)
    ///
    /// Issues DISABLE_SLOT command to free the slot for reuse.
    fn disable_slot(&mut self, slot_id: u8) -> Result<(), UsbError> {
        printkln!("xHCI: Disabling slot {}", slot_id);

        let Some(cmd_ring) = self.cmd_ring.as_mut() else {
            return Err(UsbError::NoResources);
        };

        let mut trb = Trb::new();
        trb.set_type(trb_type::DISABLE_SLOT);
        trb.control |= u32::from(slot_id) << 24; // Slot ID in bits 31:24

        let trb_addr = cmd_ring.enqueue(trb);
        self.ring_doorbell(0, 0);

        // Wait for completion (ignore timeout - device may already be gone)
        let _ = self.wait_for_command(trb_addr);

        // Clear DCBAA entry for this slot
        unsafe {
            let dcbaa = phys_to_virt(self.dcbaa_phys).cast::<u64>();
            write_volatile(dcbaa.add(slot_id as usize), 0);
        }
        fence(Ordering::SeqCst);

        Ok(())
    }

    /// Remove a USB device from this controller (hotplug removal)
    ///
    /// Following xHCI spec section 4.6.4 (Disable Slot):
    /// 1. Stop all endpoints for this device
    /// 2. Issue DISABLE_SLOT command
    /// 3. Free device context and transfer rings
    /// 4. Remove from internal tracking
    pub fn remove_device(&mut self, slot_id: u8) -> Result<(), UsbError> {
        printkln!("xHCI: Removing device slot {}", slot_id);

        // Step 1: Stop all endpoints
        self.stop_device_endpoints(slot_id)?;

        // Step 2: Disable the slot
        self.disable_slot(slot_id)?;

        // Step 3: Clean up device state
        // Note: Transfer rings and contexts use DMA allocations that will
        // be freed when DeviceState is dropped
        self.device_states.remove(&slot_id);

        // Step 4: Remove from devices list
        self.devices.retain(|d| d.slot_id != slot_id);

        printkln!("xHCI: Device slot {} removed", slot_id);
        Ok(())
    }

    /// Quiesce the controller for power-off or restart (Linux
    /// xhci_shutdown, xhci_pci_shutdown): no freeing, the machine goes
    /// down next. Ports routed back to EHCI on the Intel chipsets that
    /// otherwise power back on (XHCI_SPURIOUS_REBOOT); halted with
    /// interrupts off; reset and put in D3hot where the halt alone
    /// leaves spurious wakeups (XHCI_SPURIOUS_WAKEUP). Transfers fail
    /// from here on.
    fn shutdown_hc(&mut self) {
        let spurious_wakeup = self.quirks & quirk::SPURIOUS_WAKEUP != 0;
        if self.quirks & quirk::SPURIOUS_REBOOT != 0 {
            super::pci_quirks::disable_intel_ports(&self.pci_dev);
        }
        let _ = self.halt();
        if spurious_wakeup {
            let _ = self.reset_controller(XHCI_RESET_SHORT_US);
        }
        self.initialized = false;
        XHCI_IRQ_STATE.enabled.store(false, Ordering::Release);
        if spurious_wakeup {
            self.pci_dev.set_power_d3hot();
        }
    }

    /// Release the controller, running or partly set up (Linux
    /// usb_remove_hcd's xhci_stop, free_irq, then xhci_mem_cleanup,
    /// iounmap and pci_disable_device): the devices' slots disabled
    /// (Linux xhci_free_dev at each disconnect), halted with interrupts
    /// off and reset, so it neither DMAs nor interrupts, its handler
    /// unregistered (which waits out one running), then its memory freed
    /// and bus mastering turned off
    fn stop(&mut self) {
        if self.initialized {
            let slots: Vec<u8> = self.device_states.keys().copied().collect();
            for slot in slots {
                let _ = self.remove_device(slot);
            }
        }
        self.initialized = false;
        if self.regs.is_some() {
            let _ = self.halt();
            let _ = self.reset_controller(XHCI_RESET_SHORT_US);
        }
        XHCI_IRQ_STATE.enabled.store(false, Ordering::Release);
        self.irq = None;
        XHCI_IRQ_STATE.op_regs.store(0, Ordering::Release);
        XHCI_IRQ_STATE.rt_regs.store(0, Ordering::Release);
        // The windows go before mem_cleanup unmaps what they cover
        self.regs = None;
        self.mem_cleanup();
        // PCI_COMMAND: bus mastering off (pci_disable_device)
        let cmd = self.pci_dev.cfg_read16(0x04);
        self.pci_dev
            .cfg_write16(0x04, cmd & !crate::hw::pci::command::BUS_MASTER);
        printkln!("xHCI: {} stopped", self.pci_dev.bus_id());
    }

    /// Free what the controller was given (Linux xhci_mem_cleanup): the
    /// devices' contexts and rings (coherent DMA, freed on drop), the
    /// command and event rings, scratchpads, DCBAA, register mapping
    fn mem_cleanup(&mut self) {
        self.devices.clear();
        self.device_states.clear();
        let mut fa = crate::mm::frame_alloc::FrameAllocRef(&crate::FRAME_ALLOCATOR);
        if let Some(r) = self.cmd_ring.take() {
            fa.free_frame(r.phys);
        }
        if let Some(r) = self.event_ring.take() {
            fa.free_frame(r.phys);
            fa.free_frame(r.erst_phys);
        }
        for f in self.scratch.drain(..) {
            fa.free_frame(f);
        }
        if self.dcbaa_phys != 0 {
            fa.free_frame(self.dcbaa_phys);
            self.dcbaa_phys = 0;
        }
        if self.mmio_len != 0 {
            // SAFETY: the controller's registers, mapped at probe and
            // no longer used (the device is stopped)
            unsafe { crate::mm::ioremap::iounmap(self.mmio_base as *mut u8, self.mmio_len) };
            self.mmio_len = 0;
        }
    }
}

/// A command TRB for `slot` (bits 31:24), endpoint `dci` (20:16)
fn slot_trb(ty: u8, slot: u8, dci: u8, parameter: u64) -> Trb {
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

impl UsbController for XhciController {
    fn reset(&mut self) -> Result<(), UsbError> {
        self.halt()?;
        self.reset_controller(XHCI_RESET_SHORT_US)
    }

    fn start(&mut self) -> Result<(), UsbError> {
        self.start_controller()
    }

    fn enumerate_devices(&mut self) -> Result<Vec<UsbDevice>, UsbError> {
        if !self.initialized {
            return Err(UsbError::NoDevice);
        }

        self.devices.clear();
        self.device_states.clear();

        // Scan for connected ports
        let connected = self.scan_ports();

        for (port, speed) in connected {
            // Reset port
            if let Err(e) = self.reset_port(port) {
                printkln!("xHCI: Failed to reset port {}: {:?}", port, e);
                continue;
            }

            // Enable slot for this device
            let slot_id = match self.enable_slot() {
                Ok(id) => id,
                Err(e) => {
                    printkln!("xHCI: Failed to enable slot for port {}: {:?}", port, e);
                    continue;
                }
            };

            // Address the device (sets up Device Context and EP0)
            if let Err(e) = self.address_device(slot_id, port, speed) {
                printkln!("xHCI: Failed to address device on port {}: {:?}", port, e);
                continue;
            }

            let mut device = UsbDevice::new(slot_id, port, speed);
            if let Err(e) = self.describe(&mut device) {
                // Linux: "unable to enumerate USB device"
                printkln!("xHCI: port {}: unable to enumerate: {:?}", port, e);
                let _ = self.remove_device(slot_id);
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
            self.devices.push(device);
        }

        Ok(self.devices.clone())
    }

    fn control_transfer(
        &mut self,
        device: &UsbDevice,
        setup: &SetupPacket,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        let buf = data.unwrap_or(&mut []);
        self.do_control(device.slot_id, setup, buf, XHCI_TRANSFER_US)
    }

    fn bulk_out(
        &mut self,
        device: &UsbDevice,
        endpoint: u8,
        data: &[u8],
    ) -> Result<usize, UsbError> {
        self.do_bulk_out(device.slot_id, endpoint, data, XHCI_TRANSFER_US)
    }

    fn bulk_in(
        &mut self,
        device: &UsbDevice,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        self.do_bulk_in(device.slot_id, endpoint, data, XHCI_TRANSFER_US)
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
}
