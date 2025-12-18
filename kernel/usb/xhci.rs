//! xHCI USB 3.0 Host Controller Driver
//!
//! Implements the USB host controller interface for xHCI (eXtensible Host Controller Interface).
//!
//! Also implements `BusDriver` for the PCI bus, so xHCI controllers are discovered
//! automatically during PCI enumeration.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use core::any::Any;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};

use spin::Mutex;

use crate::arch::{CurrentArch, FrameAlloc, IoremapOps};
use crate::bus::bus::{BusContext, BusDevice, BusDriver};
use crate::bus::driver::{Device, Driver, DriverError};
use crate::bus::pci::{self, PciDevice};
use crate::dma::{DmaDirection, dma_map_single, dma_unmap_single};
use crate::downcast_bus_device;
use crate::dt::registry::DeviceInfo;
use crate::printkln;

use super::context::{InputContext, OutputDeviceContext, endpoint_to_dci};
use super::transfer::{CompletionCode, TransferRing, Trb as TransferTrb, TrbType};
use super::{SetupPacket, UsbBus, UsbController, UsbDevice, UsbError, UsbSpeed};

// ============================================================================
// Global USB Host Access
// ============================================================================

/// Recursion guard for USB output
///
/// When set, USB serial console will not attempt USB writes.
/// This prevents deadlock when printkln! is called while holding USB_CONTROLLER lock,
/// since USB serial console output would try to re-acquire the same lock.
///
/// This is the same pattern Linux uses - console drivers must be careful about
/// what locks they acquire, and USB console uses deferred output to avoid
/// holding USB locks during console writes.
static USB_OUTPUT_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Check if USB tracing is enabled (uses generic USB stack flag)
#[inline]
fn usb_trace() -> bool {
    super::usb_trace_enabled()
}

/// Check if we're in a USB output operation (for console recursion prevention)
pub fn is_usb_output_active() -> bool {
    USB_OUTPUT_ACTIVE.load(Ordering::Acquire)
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
#[cfg(target_arch = "x86_64")]
fn xhci_irq_handler(_irq: u8, _data: *mut ()) -> bool {
    xhci_irq_handler_common()
}

#[cfg(target_arch = "aarch64")]
fn xhci_irq_handler(_irq: u32, _data: *mut ()) -> bool {
    xhci_irq_handler_common()
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

/// Configure bulk endpoints for a USB device
///
/// Must be called before bulk_in/bulk_out operations.
/// Returns Ok(()) on success, or error if configuration failed.
pub fn usb_configure_endpoints(
    slot_id: u8,
    bulk_in_ep: u8,
    bulk_out_ep: u8,
    max_packet: u16,
) -> Result<(), UsbError> {
    let mut guard = acquire_usb_controller();
    let controller = guard.as_mut().ok_or(UsbError::NoDevice)?;
    controller.configure_bulk_endpoints(slot_id, bulk_in_ep, bulk_out_ep, max_packet)
}

/// RAII guard that manages USB_OUTPUT_ACTIVE flag alongside the mutex guard
struct UsbControllerGuard {
    guard: spin::MutexGuard<'static, Option<XhciController>>,
}

impl core::ops::Deref for UsbControllerGuard {
    type Target = Option<XhciController>;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl core::ops::DerefMut for UsbControllerGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for UsbControllerGuard {
    fn drop(&mut self) {
        // Clear recursion guard when releasing the lock
        USB_OUTPUT_ACTIVE.store(false, Ordering::Release);
    }
}

/// Acquire the USB_CONTROLLER lock with recursion guard
///
/// Sets USB_OUTPUT_ACTIVE before acquiring the lock to prevent USB serial
/// console from attempting USB writes while we hold the lock (which would deadlock).
fn acquire_usb_controller() -> UsbControllerGuard {
    // Set recursion guard BEFORE acquiring lock
    // This ensures any printkln! during lock acquisition won't try USB output
    USB_OUTPUT_ACTIVE.store(true, Ordering::Release);

    let guard = USB_CONTROLLER.lock();
    UsbControllerGuard { guard }
}

/// Perform a bulk OUT transfer (host to device)
pub fn usb_bulk_out(slot_id: u8, endpoint: u8, data: &[u8]) -> Result<usize, UsbError> {
    let mut guard = acquire_usb_controller();
    let controller = guard.as_mut().ok_or(UsbError::NoDevice)?;
    controller.do_bulk_out(slot_id, endpoint, data)
}

/// Perform a bulk IN transfer (device to host)
pub fn usb_bulk_in(slot_id: u8, endpoint: u8, data: &mut [u8]) -> Result<usize, UsbError> {
    let mut guard = acquire_usb_controller();
    let controller = guard.as_mut().ok_or(UsbError::NoDevice)?;
    controller.do_bulk_in(slot_id, endpoint, data)
}

/// Store the USB host controller for global access
fn store_usb_host(controller: XhciController) {
    // Direct lock here is safe - no USB serial console registered yet during probe
    *USB_CONTROLLER.lock() = Some(controller);
}

/// Clear the USB host controller (hotplug removal)
fn clear_usb_host() {
    let mut guard = acquire_usb_controller();
    if let Some(ref mut controller) = *guard {
        controller.shutdown();
    }
    *guard = None;
}

/// xHCI driver that registers with the driver subsystem (legacy Driver trait)
pub struct XhciDriver;

impl Driver for XhciDriver {
    fn compatible(&self) -> &'static [&'static str] {
        &["pci:class:0c:03:30"]
    }

    fn probe(&self, _dev: &DeviceInfo) -> Result<Box<dyn Device>, DriverError> {
        // Find xHCI PCI device
        let pci_devs = pci::find_xhci_controllers();
        if pci_devs.is_empty() {
            return Err(DriverError::Unsupported);
        }

        let pci_dev = &pci_devs[0];

        // Get BAR0 for MMIO
        let mmio_base = pci_dev.bar_address(0).ok_or(DriverError::MissingResource)?;

        // Enable memory space and bus mastering
        pci_dev.enable_memory_space();
        pci_dev.enable_bus_master();

        printkln!(
            "xHCI: Probing device at {:02x}:{:02x}.{}, BAR0=0x{:x}",
            pci_dev.bus,
            pci_dev.device,
            pci_dev.function,
            mmio_base
        );

        // Create controller (will be initialized later when we have frame allocator)
        let controller = XhciController::new(mmio_base, pci_dev.clone());
        Ok(Box::new(controller))
    }
}

// ============================================================================
// xHCI PCI Bus Driver (Bus/Driver Model)
// ============================================================================

/// xHCI PCI driver for the bus/driver model
///
/// This driver matches PCI devices with class 0C:03:30 (xHCI USB controller)
/// and creates a USB bus instance when probed.
pub struct XhciPciDriver;

impl BusDriver for XhciPciDriver {
    fn name(&self) -> &str {
        "xhci-pci"
    }

    fn matches(&self, device: &dyn BusDevice) -> bool {
        // Downcast to PciDevice and check class code
        if let Some(pci_dev) = downcast_bus_device!(device, PciDevice) {
            return pci_dev.is_xhci();
        }
        false
    }

    /// Remove the xHCI controller (hotplug/driver unload)
    ///
    /// Called when the PCI device is being removed. Performs full cleanup:
    /// 1. Shutdown all USB devices
    /// 2. Halt controller
    /// 3. Unregister IRQ
    /// 4. Clear global state
    fn remove(&self, device: &dyn BusDevice) -> Result<(), DriverError> {
        let pci_dev = downcast_bus_device!(device, PciDevice).ok_or(DriverError::Unsupported)?;
        printkln!(
            "xHCI: Removing PCI device at {}",
            BusDevice::bus_id(pci_dev)
        );

        // Clear the global USB controller (calls shutdown)
        clear_usb_host();

        printkln!("xHCI: PCI device removed");
        Ok(())
    }

    fn probe(
        &self,
        device: &dyn BusDevice,
        ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        let pci_dev = downcast_bus_device!(device, PciDevice).ok_or(DriverError::Unsupported)?;

        // Get BAR0 for MMIO
        let mmio_base = pci_dev.bar_address(0).ok_or(DriverError::MissingResource)?;

        // Enable memory space and bus mastering
        pci_dev.enable_memory_space();
        pci_dev.enable_bus_master();

        printkln!(
            "xHCI: Probing PCI device at {}, BAR0=0x{:x}",
            BusDevice::bus_id(pci_dev),
            mmio_base
        );

        // Create and initialize controller
        let mut controller = XhciController::new(mmio_base, pci_dev.clone());

        // Initialize with frame allocator from context
        if let Err(e) = controller.init_from_context(ctx) {
            printkln!("xHCI: Failed to initialize controller: {:?}", e);
            return Err(DriverError::InitFailed);
        }

        // Enumerate USB devices
        let usb_devices = match controller.enumerate_devices() {
            Ok(devices) => devices,
            Err(e) => {
                printkln!("xHCI: Failed to enumerate devices: {:?}", e);
                Vec::new()
            }
        };

        // Store controller for global access (USB MSC driver needs this)
        let num_devices = controller.devices.len();
        store_usb_host(controller);

        // Create USB bus with discovered devices
        let usb_bus = UsbBus::new(usb_devices);

        // Register the USB bus (will be added to BusManager)
        ctx.new_buses.push(("usb", Box::new(usb_bus)));
        printkln!("xHCI: Created USB bus with {} device(s)", num_devices);

        // Return a wrapper device
        Ok(Box::new(XhciDeviceHandle))
    }
}

/// Device handle returned from xHCI probe
struct XhciDeviceHandle;

impl Device for XhciDeviceHandle {
    fn name(&self) -> &str {
        "xhci"
    }

    fn as_any(&self) -> &dyn Any {
        self
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
}

/// Wrapper around raw pointer for Send+Sync
/// SAFETY: We only access this from kernel context with proper synchronization
struct TrbPtr(*mut Trb);

unsafe impl Send for TrbPtr {}
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
        self.control = (self.control & !0xFC00) | ((trb_type as u32) << 10);
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

    fn get_cycle(&self) -> bool {
        (self.control & 1) != 0
    }
}

/// TRB types
mod trb_type {
    pub const LINK: u8 = 6;
    pub const ENABLE_SLOT: u8 = 9;
    pub const DISABLE_SLOT: u8 = 10;
    pub const ADDRESS_DEVICE: u8 = 11;
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    pub const STOP_ENDPOINT: u8 = 15;
    pub const COMMAND_COMPLETION: u8 = 33;
    pub const TRANSFER_EVENT: u8 = 32;
}

/// Per-device xHCI state
///
/// Tracks the Device Context, Input Context, and Transfer Rings for each endpoint.
struct DeviceState {
    /// Slot ID assigned by xHCI
    #[allow(dead_code)]
    slot_id: u8,
    /// Output Device Context (xHCI writes device state here)
    #[allow(dead_code)]
    output_ctx: OutputDeviceContext,
    /// Input Context (for Address Device and Configure Endpoint)
    input_ctx: InputContext,
    /// Transfer Rings per endpoint (indexed by DCI: 1=EP0, 2=EP1OUT, 3=EP1IN, etc.)
    transfer_rings: BTreeMap<u8, TransferRing>,
    /// Whether the device has been addressed
    addressed: bool,
    /// Whether endpoints have been configured
    configured: bool,
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

    fn new<FA: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut FA) -> Option<Self> {
        // Allocate a page for command ring
        let phys = frame_alloc.alloc_frame()?;
        Self::init_from_phys(phys)
    }

    fn new_with_wrapper(frame_alloc: &mut dyn crate::bus::bus::FrameAllocWrapper) -> Option<Self> {
        let phys = frame_alloc.alloc_frame()?;
        Self::init_from_phys(phys)
    }

    fn init_from_phys(phys: u64) -> Option<Self> {
        // Zero the memory
        unsafe {
            core::ptr::write_bytes(phys as *mut u8, 0, 4096);
        }

        // Set up link TRB at end of ring (points back to start)
        let trbs = phys as *mut Trb;
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

    fn new<FA: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut FA) -> Option<Self> {
        let phys = frame_alloc.alloc_frame()?;
        let erst_phys = frame_alloc.alloc_frame()?;
        Self::init_from_phys(phys, erst_phys)
    }

    fn new_with_wrapper(frame_alloc: &mut dyn crate::bus::bus::FrameAllocWrapper) -> Option<Self> {
        let phys = frame_alloc.alloc_frame()?;
        let erst_phys = frame_alloc.alloc_frame()?;
        Self::init_from_phys(phys, erst_phys)
    }

    fn init_from_phys(phys: u64, erst_phys: u64) -> Option<Self> {
        // Zero event ring memory
        unsafe {
            core::ptr::write_bytes(phys as *mut u8, 0, 4096);
        }

        // Zero and initialize ERST (Event Ring Segment Table)
        unsafe {
            core::ptr::write_bytes(erst_phys as *mut u8, 0, 4096);

            // Set up single ERST entry
            let erst = erst_phys as *mut ErstEntry;
            (*erst).ring_segment_base = phys;
            (*erst).ring_segment_size = Self::SIZE as u16;
        }

        Some(Self {
            phys,
            trbs: TrbPtr(phys as *mut Trb),
            size: Self::SIZE,
            dequeue: 0,
            cycle: true,
            erst_phys,
        })
    }

    fn dequeue(&mut self) -> Option<Trb> {
        let trb_ptr = unsafe { self.trbs.0.add(self.dequeue) };
        let trb = unsafe { read_volatile(trb_ptr) };

        // Check if this TRB is valid (cycle bit matches expected)
        if trb.get_cycle() != self.cycle {
            return None;
        }

        // Read barrier: ensure we see all fields of the event TRB
        // that were written by the xHC before we process them
        fence(Ordering::Acquire);

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

/// xHCI controller state
pub struct XhciController {
    /// MMIO base address
    mmio_base: u64,
    /// PCI device info
    pci_dev: PciDevice,
    /// Capability registers offset
    cap_regs: u64,
    /// Operational registers offset
    op_regs: u64,
    /// Doorbell registers offset
    db_regs: u64,
    /// Runtime registers offset
    rt_regs: u64,
    /// Port registers offset
    port_regs: u64,
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
    /// Initialized flag
    initialized: bool,
    /// Connected devices
    devices: Vec<UsbDevice>,
    /// Per-device state (slot_id -> DeviceState)
    device_states: BTreeMap<u8, DeviceState>,
    /// Assigned IRQ (if interrupt mode enabled)
    irq: Option<u8>,
}

impl XhciController {
    /// Create a new xHCI controller (not yet initialized)
    pub fn new(mmio_base: u64, pci_dev: PciDevice) -> Self {
        Self {
            mmio_base,
            pci_dev,
            cap_regs: mmio_base,
            op_regs: 0,
            db_regs: 0,
            rt_regs: 0,
            port_regs: 0,
            cmd_ring: None,
            event_ring: None,
            dcbaa_phys: 0,
            max_slots: 0,
            max_ports: 0,
            initialized: false,
            devices: Vec::new(),
            device_states: BTreeMap::new(),
            irq: None,
        }
    }

    /// Read capability register
    fn read_cap(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.cap_regs + offset as u64) as *const u32) }
    }

    /// Read operational register
    fn read_op(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.op_regs + offset as u64) as *const u32) }
    }

    /// Write operational register
    fn write_op(&self, offset: usize, value: u32) {
        unsafe {
            write_volatile((self.op_regs + offset as u64) as *mut u32, value);
        }
    }

    /// Read port register
    fn read_port(&self, port: u8, offset: usize) -> u32 {
        let port_offset = self.port_regs + ((port as u64 - 1) * 0x10);
        unsafe { read_volatile((port_offset + offset as u64) as *const u32) }
    }

    /// Write port register
    fn write_port(&self, port: u8, offset: usize, value: u32) {
        let port_offset = self.port_regs + ((port as u64 - 1) * 0x10);
        unsafe {
            write_volatile((port_offset + offset as u64) as *mut u32, value);
        }
    }

    /// Ring doorbell register
    ///
    /// Note: A write memory barrier is required before ringing the doorbell
    /// to ensure the xHC sees all TRB/context updates. The enqueue() functions
    /// already include this barrier, so this is just the doorbell write itself.
    fn ring_doorbell(&self, slot: u8, target: u8) {
        // Write barrier to ensure all TRB writes are visible to device
        fence(Ordering::Release);
        let db_offset = self.db_regs + (slot as u64 * 4);
        unsafe {
            write_volatile(db_offset as *mut u32, target as u32);
        }
    }

    /// Write runtime register
    fn write_rt(&self, offset: usize, value: u32) {
        unsafe {
            write_volatile((self.rt_regs + offset as u64) as *mut u32, value);
        }
    }

    /// Write 64-bit runtime register
    fn write_rt64(&self, offset: usize, value: u64) {
        unsafe {
            write_volatile((self.rt_regs + offset as u64) as *mut u64, value);
        }
    }

    /// Initialize the controller from a BusContext
    pub fn init_from_context(&mut self, ctx: &mut BusContext) -> Result<(), UsbError> {
        self.init_with_frame_alloc(ctx.frame_alloc)
    }

    /// Initialize with a frame allocator wrapper (from BusContext)
    fn init_with_frame_alloc(
        &mut self,
        frame_alloc: &mut dyn crate::bus::bus::FrameAllocWrapper,
    ) -> Result<(), UsbError> {
        // Map MMIO region using ioremap (allocates virtual addresses from dedicated region)
        let bar_size = self.pci_dev.bar_size(0);

        match CurrentArch::ioremap(self.mmio_base, bar_size) {
            Ok(virt) => {
                // Update all base addresses to virtual address
                let virt_base = virt as u64;
                self.mmio_base = virt_base;
                self.cap_regs = virt_base;
            }
            Err(e) => {
                printkln!("xHCI: Failed to ioremap MMIO region: {:?}", e);
                return Err(UsbError::NoResources);
            }
        }
        // frame_alloc still used for device context allocations below

        // Read capability registers
        let caplength = (self.read_cap(0) & 0xFF) as u64;
        let hciversion = self.read_cap(0) >> 16;
        let hcsparams1 = self.read_cap(0x04);
        let dboff = self.read_cap(0x14);
        let rtsoff = self.read_cap(0x18);

        self.max_slots = (hcsparams1 & 0xFF) as u8;
        self.max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

        // Calculate register offsets
        self.op_regs = self.mmio_base + caplength;
        self.db_regs = self.mmio_base + (dboff as u64);
        self.rt_regs = self.mmio_base + (rtsoff as u64);
        self.port_regs = self.op_regs + 0x400;

        printkln!(
            "xHCI: version={:x}.{:x}, max_slots={}, max_ports={}",
            (hciversion >> 8) & 0xFF,
            hciversion & 0xFF,
            self.max_slots,
            self.max_ports
        );

        // Stop controller if running
        self.halt()?;

        // Reset controller
        self.reset_controller()?;

        // Allocate Device Context Base Address Array
        let dcbaa_phys = frame_alloc.alloc_frame().ok_or(UsbError::NoResources)?;
        unsafe {
            core::ptr::write_bytes(dcbaa_phys as *mut u8, 0, 4096);
        }
        self.dcbaa_phys = dcbaa_phys;

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

    /// Initialize the controller with a frame allocator
    pub fn init<FA: FrameAlloc<PhysAddr = u64>>(
        &mut self,
        frame_alloc: &mut FA,
    ) -> Result<(), UsbError> {
        // Map MMIO region using ioremap (allocates virtual addresses from dedicated region)
        let bar_size = self.pci_dev.bar_size(0);
        match CurrentArch::ioremap(self.mmio_base, bar_size) {
            Ok(virt) => {
                // Update all base addresses to virtual address
                let virt_base = virt as u64;
                self.mmio_base = virt_base;
                self.cap_regs = virt_base;
            }
            Err(e) => {
                printkln!("xHCI: Failed to ioremap MMIO region: {:?}", e);
                return Err(UsbError::NoResources);
            }
        }
        // frame_alloc still used for device context allocations below

        // Read capability registers
        let caplength = (self.read_cap(0) & 0xFF) as u64;
        let hciversion = self.read_cap(0) >> 16;
        let hcsparams1 = self.read_cap(0x04);
        let dboff = self.read_cap(0x14);
        let rtsoff = self.read_cap(0x18);

        self.max_slots = (hcsparams1 & 0xFF) as u8;
        self.max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

        // Calculate register offsets
        self.op_regs = self.mmio_base + caplength;
        self.db_regs = self.mmio_base + (dboff as u64);
        self.rt_regs = self.mmio_base + (rtsoff as u64);
        self.port_regs = self.op_regs + 0x400; // Port registers start at offset 0x400

        printkln!(
            "xHCI: version={:x}.{:x}, max_slots={}, max_ports={}",
            (hciversion >> 8) & 0xFF,
            hciversion & 0xFF,
            self.max_slots,
            self.max_ports
        );

        // Stop controller if running
        self.halt()?;

        // Reset controller
        self.reset_controller()?;

        // Allocate Device Context Base Address Array
        let dcbaa_phys = frame_alloc.alloc_frame().ok_or(UsbError::NoResources)?;
        unsafe {
            core::ptr::write_bytes(dcbaa_phys as *mut u8, 0, 4096);
        }
        self.dcbaa_phys = dcbaa_phys;

        // Allocate command ring
        self.cmd_ring = Some(CommandRing::new(frame_alloc).ok_or(UsbError::NoResources)?);

        // Allocate event ring
        self.event_ring = Some(EventRing::new(frame_alloc).ok_or(UsbError::NoResources)?);

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

    /// Halt the controller
    fn halt(&self) -> Result<(), UsbError> {
        // Clear run bit
        let cmd = self.read_op(0x00);
        self.write_op(0x00, cmd & !usbcmd::RUN_STOP);

        // Wait for HCH (halted) bit
        for _ in 0..1000 {
            if (self.read_op(0x04) & usbsts::HCH) != 0 {
                return Ok(());
            }
            // Small delay
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        printkln!("xHCI: Timeout waiting for halt");
        Err(UsbError::Timeout)
    }

    /// Reset the controller
    fn reset_controller(&self) -> Result<(), UsbError> {
        // Set reset bit
        self.write_op(0x00, usbcmd::HCRST);

        // Wait for reset to complete
        for _ in 0..1000 {
            let cmd = self.read_op(0x00);
            let sts = self.read_op(0x04);
            if (cmd & usbcmd::HCRST) == 0 && (sts & usbsts::CNR) == 0 {
                return Ok(());
            }
            // Small delay
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        printkln!("xHCI: Timeout waiting for reset");
        Err(UsbError::Timeout)
    }

    /// Configure the controller
    fn configure(&mut self) -> Result<(), UsbError> {
        // Set max device slots
        self.write_op(0x38, self.max_slots as u32);

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
        // Store register addresses for ISR access
        XHCI_IRQ_STATE
            .op_regs
            .store(self.op_regs, Ordering::Release);
        XHCI_IRQ_STATE
            .rt_regs
            .store(self.rt_regs, Ordering::Release);

        // Register IRQ handler with PCI device
        match self
            .pci_dev
            .register_irq_handler(xhci_irq_handler, core::ptr::null_mut())
        {
            Ok(irq) => {
                self.irq = Some(irq);
                printkln!("xHCI: Registered IRQ {}", irq);

                // Enable USBCMD.INTE (Interrupter Enable) - bit 2
                let cmd = self.read_op(0x00);
                self.write_op(0x00, cmd | (1 << 2));

                // Mark interrupt mode as enabled
                XHCI_IRQ_STATE.enabled.store(true, Ordering::Release);
            }
            Err(e) => {
                printkln!("xHCI: Failed to register IRQ handler: {}", e);
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

        // Wait for not halted
        for _ in 0..1000 {
            if (self.read_op(0x04) & usbsts::HCH) == 0 {
                return Ok(());
            }
            // Small delay
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        printkln!("xHCI: Timeout waiting for start");
        Err(UsbError::Timeout)
    }

    /// Wait for a command completion event
    fn wait_for_command(&mut self, _trb_addr: u64) -> Result<Trb, UsbError> {
        // Always poll the event ring - interrupt is just an optimization hint
        // to reduce polling frequency when we know hardware hasn't signaled yet
        for _ in 0..10000 {
            // Clear any pending interrupt flag (to allow future interrupts)
            let _ = XHCI_IRQ_STATE
                .interrupt_pending
                .swap(false, Ordering::AcqRel);

            // Always check the event ring
            if let Some(result) = self.try_dequeue_command_event() {
                return result;
            }

            // Small delay between polls
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        Err(UsbError::Timeout)
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
                printkln!(
                    "xHCI: Event TRB type={}, ctrl=0x{:08x}, status=0x{:08x}",
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
        // Read current value and preserve RW1C bits
        let portsc = self.read_port(port, 0);

        // Set port reset, preserve power
        self.write_port(port, 0, (portsc & 0x0E00_00E0) | portsc::PR);

        // Wait for reset to complete
        for _ in 0..1000 {
            let portsc = self.read_port(port, 0);
            if (portsc & portsc::PR) == 0 && (portsc & portsc::PED) != 0 {
                // Clear status change bits
                self.write_port(port, 0, portsc | portsc::CSC | portsc::PRC);
                return Ok(());
            }
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        Err(UsbError::Timeout)
    }

    /// Address a device (xHCI Address Device command)
    ///
    /// This sets up the Device Context and Control Endpoint (EP0) for the device.
    fn address_device(&mut self, slot_id: u8, port: u8, speed: UsbSpeed) -> Result<(), UsbError> {
        // Create Device State with contexts
        let output_ctx = OutputDeviceContext::new(&self.pci_dev).ok_or(UsbError::NoResources)?;
        let mut input_ctx = InputContext::new(&self.pci_dev).ok_or(UsbError::NoResources)?;

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

        // Configure Slot Context
        {
            let slot = input_ctx.slot_mut();
            slot.set_route_string(0); // Root hub device
            slot.set_speed(speed as u8);
            slot.set_context_entries(1); // Only slot + EP0 for now
            slot.set_root_hub_port(port);
        }

        // Configure EP0 Context (Control Endpoint)
        {
            let max_packet = speed.default_max_packet_size();
            let ep0 = input_ctx.endpoint_mut(1).ok_or(UsbError::NoResources)?;
            ep0.configure_control(max_packet, ep0_ring.dma_addr());
        }

        // Set DCBAA entry for this slot
        unsafe {
            let dcbaa = self.dcbaa_phys as *mut u64;
            write_volatile(dcbaa.add(slot_id as usize), output_ctx.dma_addr());
        }
        fence(Ordering::SeqCst);

        // Issue Address Device command
        let cmd_ring = self.cmd_ring.as_mut().ok_or(UsbError::NoResources)?;
        let mut trb = Trb::new();
        trb.parameter = input_ctx.dma_addr();
        trb.set_type(trb_type::ADDRESS_DEVICE);
        trb.control |= (slot_id as u32) << 24; // Slot ID in bits 31:24

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
            slot_id,
            output_ctx,
            input_ctx,
            transfer_rings,
            addressed: true,
            configured: false,
        };
        self.device_states.insert(slot_id, state);

        printkln!("xHCI: Device slot {} addressed", slot_id);
        Ok(())
    }

    /// Configure bulk endpoints for a device
    ///
    /// This must be called after address_device and before bulk transfers.
    fn configure_bulk_endpoints(
        &mut self,
        slot_id: u8,
        bulk_in_ep: u8,
        bulk_out_ep: u8,
        max_packet: u16,
    ) -> Result<(), UsbError> {
        // Calculate DCIs
        let bulk_in_dci = endpoint_to_dci(bulk_in_ep | 0x80);
        let bulk_out_dci = endpoint_to_dci(bulk_out_ep);

        // Create Transfer Rings for bulk endpoints
        let bulk_in_ring = TransferRing::new(&self.pci_dev).ok_or(UsbError::NoResources)?;
        let bulk_out_ring = TransferRing::new(&self.pci_dev).ok_or(UsbError::NoResources)?;

        let bulk_in_ring_addr = bulk_in_ring.dma_addr();
        let bulk_out_ring_addr = bulk_out_ring.dma_addr();

        // Get input context DMA address after configuring it
        let input_ctx_addr = {
            let state = self
                .device_states
                .get_mut(&slot_id)
                .ok_or(UsbError::NoDevice)?;

            if !state.addressed {
                return Err(UsbError::NoDevice);
            }

            // Configure Input Context
            state.input_ctx.clear();

            {
                let control = state.input_ctx.control_mut();
                control.add_slot();
                control.add_endpoint(bulk_in_dci);
                control.add_endpoint(bulk_out_dci);
            }

            // Update Slot Context
            {
                let slot = state.input_ctx.slot_mut();
                let max_dci = bulk_in_dci.max(bulk_out_dci);
                slot.set_context_entries(max_dci);
            }

            // Configure Bulk IN endpoint
            {
                let ep = state
                    .input_ctx
                    .endpoint_mut(bulk_in_dci)
                    .ok_or(UsbError::NoResources)?;
                ep.configure_bulk_in(max_packet, bulk_in_ring_addr);
            }

            // Configure Bulk OUT endpoint
            {
                let ep = state
                    .input_ctx
                    .endpoint_mut(bulk_out_dci)
                    .ok_or(UsbError::NoResources)?;
                ep.configure_bulk_out(max_packet, bulk_out_ring_addr);
            }

            state.input_ctx.dma_addr()
        };

        // Issue Configure Endpoint command (state borrow is released)
        let cmd_ring = self.cmd_ring.as_mut().ok_or(UsbError::NoResources)?;
        let mut trb = Trb::new();
        trb.parameter = input_ctx_addr;
        trb.set_type(trb_type::CONFIGURE_ENDPOINT);
        trb.control |= (slot_id as u32) << 24;

        let trb_addr = cmd_ring.enqueue(trb);

        printkln!(
            "xHCI: Issuing Configure Endpoint command for slot {}",
            slot_id
        );

        self.ring_doorbell(0, 0);

        // Wait for completion
        let event = self.wait_for_command(trb_addr)?;
        let cc = ((event.status >> 24) & 0xFF) as u8;
        if cc != completion_code::SUCCESS {
            printkln!("xHCI: Configure Endpoint failed with code {}", cc);
            return Err(UsbError::TransferError(cc));
        }

        // Store Transfer Rings (reborrow state)
        let state = self
            .device_states
            .get_mut(&slot_id)
            .ok_or(UsbError::NoDevice)?;
        state.transfer_rings.insert(bulk_in_dci, bulk_in_ring);
        state.transfer_rings.insert(bulk_out_dci, bulk_out_ring);
        state.configured = true;

        printkln!(
            "xHCI: Configured bulk endpoints for slot {} (IN DCI={}, OUT DCI={})",
            slot_id,
            bulk_in_dci,
            bulk_out_dci
        );
        Ok(())
    }

    /// Wait for a transfer completion event
    fn wait_for_transfer(&mut self, slot_id: u8, ep_dci: u8) -> Result<(u32, u8), UsbError> {
        // Always poll the event ring - interrupt is just an optimization hint
        for i in 0..100000 {
            // Clear any pending interrupt flag
            let _ = XHCI_IRQ_STATE
                .interrupt_pending
                .swap(false, Ordering::AcqRel);

            // Always check the event ring
            if let Some(result) = self.try_dequeue_transfer_event(slot_id, ep_dci) {
                TRANSFER_COUNT.fetch_add(1, Ordering::Relaxed);
                if usb_trace() {
                    printkln!(
                        "xHCI TRACE: transfer complete slot={} dci={} iter={}",
                        slot_id,
                        ep_dci,
                        i
                    );
                }
                return result;
            }

            // Small delay between polls
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        // More detailed timeout message for debugging
        let count = TRANSFER_COUNT.load(Ordering::Relaxed);
        printkln!(
            "xHCI: wait_for_transfer TIMEOUT slot={} dci={} after {} transfers",
            slot_id,
            ep_dci,
            count
        );
        // Dump event ring state on first timeout only
        if count == 393 {
            if let Some(event_ring) = self.event_ring.as_ref() {
                printkln!(
                    "xHCI: event_ring dequeue={} cycle={}",
                    event_ring.dequeue,
                    event_ring.cycle
                );
            }
            // Dump transfer ring state
            if let Some(state) = self.device_states.get(&slot_id)
                && let Some(ring) = state.transfer_rings.get(&ep_dci)
            {
                let (enqueue, dequeue, cycle) = ring.debug_state();
                printkln!(
                    "xHCI: transfer_ring enqueue={} dequeue={} cycle={}",
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
    ) -> Option<Result<(u32, u8), UsbError>> {
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
                    printkln!(
                        "xHCI TRACE: transfer_event slot={} ep={} cc={} residue={} (want slot={} ep={})",
                        event_slot,
                        event_ep,
                        cc,
                        transferred,
                        slot_id,
                        ep_dci
                    );
                }

                if event_slot == slot_id && event_ep == ep_dci {
                    return Some(Ok((transferred, cc)));
                }
                // Transfer for different slot/ep - continue consuming events
            } else if usb_trace() {
                printkln!("xHCI TRACE: non-transfer event type={}", trb_type);
            }
            // Non-transfer event (command completion, port status, etc.) - continue consuming
        }
    }

    /// Perform a bulk OUT transfer
    fn do_bulk_out(&mut self, slot_id: u8, endpoint: u8, data: &[u8]) -> Result<usize, UsbError> {
        let ep_dci = endpoint_to_dci(endpoint);

        if usb_trace() {
            printkln!(
                "xHCI TRACE: bulk_out slot={} ep=0x{:02x} dci={} len={}",
                slot_id,
                endpoint,
                ep_dci,
                data.len()
            );
        }

        // Map data buffer for DMA
        let dma_addr = dma_map_single(
            &self.pci_dev,
            data.as_ptr(),
            data.len(),
            DmaDirection::ToDevice,
        )
        .ok_or(UsbError::NoResources)?;

        if usb_trace() {
            printkln!("xHCI TRACE: bulk_out DMA addr=0x{:x}", dma_addr.as_u64());
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
        ring.enqueue(trb);

        // Ring doorbell for this endpoint
        self.ring_doorbell(slot_id, ep_dci);

        // Wait for completion
        let (residue, cc) = self.wait_for_transfer(slot_id, ep_dci)?;

        // Advance transfer ring dequeue pointer to track completion
        if let Some(state) = self.device_states.get_mut(&slot_id)
            && let Some(ring) = state.transfer_rings.get_mut(&ep_dci)
        {
            ring.advance_dequeue();
        }

        // Unmap DMA buffer
        dma_unmap_single(&self.pci_dev, dma_addr, data.len(), DmaDirection::ToDevice);

        if cc != CompletionCode::SUCCESS && cc != CompletionCode::SHORT_PACKET {
            printkln!("xHCI: Bulk OUT failed with code {}", cc);
            return Err(UsbError::TransferError(cc));
        }

        // Calculate actual transferred bytes
        let transferred = data.len() - residue as usize;
        Ok(transferred)
    }

    /// Perform a bulk IN transfer
    fn do_bulk_in(
        &mut self,
        slot_id: u8,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        let ep_dci = endpoint_to_dci(endpoint | 0x80); // IN direction

        if usb_trace() {
            printkln!(
                "xHCI TRACE: bulk_in slot={} ep=0x{:02x} dci={} len={}",
                slot_id,
                endpoint,
                ep_dci,
                data.len()
            );
        }

        // Map data buffer for DMA
        let dma_addr = dma_map_single(
            &self.pci_dev,
            data.as_ptr(),
            data.len(),
            DmaDirection::FromDevice,
        )
        .ok_or(UsbError::NoResources)?;

        if usb_trace() {
            printkln!("xHCI TRACE: bulk_in DMA addr=0x{:x}", dma_addr.as_u64());
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
        ring.enqueue(trb);

        // Ring doorbell
        self.ring_doorbell(slot_id, ep_dci);

        // Wait for completion
        let (residue, cc) = self.wait_for_transfer(slot_id, ep_dci)?;

        // Advance transfer ring dequeue pointer to track completion
        if let Some(state) = self.device_states.get_mut(&slot_id)
            && let Some(ring) = state.transfer_rings.get_mut(&ep_dci)
        {
            ring.advance_dequeue();
        }

        // Read barrier: ensure we see all device writes to DMA buffer
        // before CPU accesses the data
        fence(Ordering::Acquire);

        // Unmap DMA buffer
        dma_unmap_single(
            &self.pci_dev,
            dma_addr,
            data.len(),
            DmaDirection::FromDevice,
        );

        if cc != CompletionCode::SUCCESS && cc != CompletionCode::SHORT_PACKET {
            printkln!("xHCI: Bulk IN failed with code {}", cc);
            return Err(UsbError::TransferError(cc));
        }

        let transferred = data.len() - residue as usize;
        Ok(transferred)
    }

    /// Stop all endpoints for a device (hotplug removal)
    ///
    /// Issues STOP_ENDPOINT commands for each configured endpoint.
    /// This ensures no pending transfers complete after device removal.
    fn stop_device_endpoints(&mut self, slot_id: u8) -> Result<(), UsbError> {
        let state = match self.device_states.get(&slot_id) {
            Some(s) => s,
            None => return Ok(()), // No state = nothing to stop
        };

        // Get list of configured endpoint DCIs
        let dcis: Vec<u8> = state.transfer_rings.keys().copied().collect();

        for dci in dcis {
            printkln!("xHCI: Stopping endpoint DCI {} for slot {}", dci, slot_id);

            // Issue STOP_ENDPOINT command
            let cmd_ring = match self.cmd_ring.as_mut() {
                Some(r) => r,
                None => return Err(UsbError::NoResources),
            };

            let mut trb = Trb::new();
            trb.set_type(trb_type::STOP_ENDPOINT);
            trb.control |= (slot_id as u32) << 24; // Slot ID in bits 31:24
            trb.control |= (dci as u32) << 16; // Endpoint ID in bits 20:16

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

        let cmd_ring = match self.cmd_ring.as_mut() {
            Some(r) => r,
            None => return Err(UsbError::NoResources),
        };

        let mut trb = Trb::new();
        trb.set_type(trb_type::DISABLE_SLOT);
        trb.control |= (slot_id as u32) << 24; // Slot ID in bits 31:24

        let trb_addr = cmd_ring.enqueue(trb);
        self.ring_doorbell(0, 0);

        // Wait for completion (ignore timeout - device may already be gone)
        let _ = self.wait_for_command(trb_addr);

        // Clear DCBAA entry for this slot
        unsafe {
            let dcbaa = self.dcbaa_phys as *mut u64;
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

    /// Shutdown the entire xHCI controller (driver unload/hotplug)
    ///
    /// Stops all devices, halts the controller, and unregisters IRQ.
    pub fn shutdown(&mut self) {
        printkln!("xHCI: Shutting down controller");

        // Stop all devices
        let slot_ids: Vec<u8> = self.device_states.keys().copied().collect();
        for slot_id in slot_ids {
            let _ = self.remove_device(slot_id);
        }

        // Halt the controller
        let _ = self.halt();

        // Disable interrupts
        if self.irq.is_some() {
            // Disable USBCMD.INTE
            let cmd = self.read_op(0x00);
            self.write_op(0x00, cmd & !(1 << 2));

            // Unregister IRQ handler
            if let Err(e) = self.pci_dev.unregister_irq_handler() {
                printkln!("xHCI: Failed to unregister IRQ: {}", e);
            }

            self.irq = None;
        }

        // Clear global IRQ state
        XHCI_IRQ_STATE.enabled.store(false, Ordering::Release);
        XHCI_IRQ_STATE.op_regs.store(0, Ordering::Release);
        XHCI_IRQ_STATE.rt_regs.store(0, Ordering::Release);

        self.initialized = false;
        printkln!("xHCI: Controller shutdown complete");
    }
}

impl Device for XhciController {
    fn name(&self) -> &str {
        "xhci"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UsbController for XhciController {
    fn reset(&mut self) -> Result<(), UsbError> {
        self.halt()?;
        self.reset_controller()
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

            // Create device info
            // Note: Full enumeration would read device descriptors via control transfers
            let device = UsbDevice {
                slot_id,
                address: slot_id,
                speed,
                port,
                vendor_id: 0,
                product_id: 0,
                device_class: 0,
                device_subclass: 0,
                device_protocol: 0,
                interfaces: Vec::new(),
            };

            printkln!(
                "xHCI: Device on port {}, slot {}, speed {:?} - addressed",
                port,
                slot_id,
                speed
            );
            self.devices.push(device);
        }

        Ok(self.devices.clone())
    }

    fn control_transfer(
        &mut self,
        _device: &UsbDevice,
        _setup: &SetupPacket,
        _data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        // Full control transfer implementation would go here
        // For now, we have EP0 Transfer Ring but need to implement the TRB submission
        Err(UsbError::NoResources)
    }

    fn bulk_out(
        &mut self,
        device: &UsbDevice,
        endpoint: u8,
        data: &[u8],
    ) -> Result<usize, UsbError> {
        self.do_bulk_out(device.slot_id, endpoint, data)
    }

    fn bulk_in(
        &mut self,
        device: &UsbDevice,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        self.do_bulk_in(device.slot_id, endpoint, data)
    }
}

/// Initialize xHCI and enumerate devices
pub fn init_xhci<FA: FrameAlloc<PhysAddr = u64>>(
    pci_dev: &PciDevice,
    frame_alloc: &mut FA,
) -> Result<XhciController, UsbError> {
    let mmio_base = pci_dev.bar_address(0).ok_or(UsbError::NoResources)?;

    // Enable memory space and bus mastering
    pci_dev.enable_memory_space();
    pci_dev.enable_bus_master();

    let mut controller = XhciController::new(mmio_base, pci_dev.clone());
    controller.init(frame_alloc)?;

    Ok(controller)
}
