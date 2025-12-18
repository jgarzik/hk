//! xHCI Device and Endpoint Context Structures
//!
//! These structures are used by the xHCI controller to track device state
//! and endpoint configuration.
//!
//! Key structures:
//! - SlotContext: Per-device state (speed, route string, ports)
//! - EndpointContext: Per-endpoint configuration (type, max packet, ring)
//! - InputContext: Used for Address Device and Configure Endpoint commands
//! - OutputDeviceContext: Where xHCI writes device state

use crate::dma::{DmaCoherent, DmaDevice, dma_alloc_coherent};

/// Slot Context (32 bytes)
///
/// Contains device-level information like speed, route string, and port number.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(32))]
pub struct SlotContext {
    /// Route String (bits 19:0), Speed (bits 23:20), MTT (bit 25),
    /// Hub (bit 26), Context Entries (bits 31:27)
    pub dword0: u32,
    /// Max Exit Latency (bits 15:0), Root Hub Port Number (bits 23:16),
    /// Number of Ports (bits 31:24)
    pub dword1: u32,
    /// TT Hub Slot ID (bits 7:0), TT Port Number (bits 15:8),
    /// TT Think Time (bits 17:16), Interrupter Target (bits 31:22)
    pub dword2: u32,
    /// USB Device Address (bits 7:0), Slot State (bits 31:27)
    pub dword3: u32,
    /// Reserved
    pub _reserved: [u32; 4],
}

impl SlotContext {
    /// Create a new zeroed slot context
    pub const fn new() -> Self {
        Self {
            dword0: 0,
            dword1: 0,
            dword2: 0,
            dword3: 0,
            _reserved: [0; 4],
        }
    }

    /// Set Route String (20 bits)
    pub fn set_route_string(&mut self, route: u32) {
        self.dword0 = (self.dword0 & !0xFFFFF) | (route & 0xFFFFF);
    }

    /// Set Speed (4 bits: 1=Full, 2=Low, 3=High, 4=Super, 5=SuperPlus)
    pub fn set_speed(&mut self, speed: u8) {
        self.dword0 = (self.dword0 & !(0xF << 20)) | (((speed as u32) & 0xF) << 20);
    }

    /// Set Context Entries (5 bits) - indicates highest valid endpoint context
    pub fn set_context_entries(&mut self, entries: u8) {
        self.dword0 = (self.dword0 & !(0x1F << 27)) | (((entries as u32) & 0x1F) << 27);
    }

    /// Set Root Hub Port Number (8 bits)
    pub fn set_root_hub_port(&mut self, port: u8) {
        self.dword1 = (self.dword1 & !(0xFF << 16)) | (((port as u32) & 0xFF) << 16);
    }

    /// Set Max Exit Latency (16 bits)
    pub fn set_max_exit_latency(&mut self, latency: u16) {
        self.dword1 = (self.dword1 & !0xFFFF) | (latency as u32);
    }

    /// Set Interrupter Target (10 bits)
    pub fn set_interrupter_target(&mut self, target: u16) {
        self.dword2 = (self.dword2 & !(0x3FF << 22)) | (((target as u32) & 0x3FF) << 22);
    }

    /// Get USB Device Address
    pub fn get_device_address(&self) -> u8 {
        (self.dword3 & 0xFF) as u8
    }

    /// Get Slot State (bits 31:27)
    pub fn get_slot_state(&self) -> u8 {
        ((self.dword3 >> 27) & 0x1F) as u8
    }
}

/// Endpoint State values
#[allow(non_snake_case)]
pub mod EndpointState {
    pub const DISABLED: u8 = 0;
    pub const RUNNING: u8 = 1;
    pub const HALTED: u8 = 2;
    pub const STOPPED: u8 = 3;
    pub const ERROR: u8 = 4;
}

/// Endpoint Type values (for EP Context)
#[allow(non_snake_case)]
pub mod EndpointType {
    pub const NOT_VALID: u8 = 0;
    pub const ISOCH_OUT: u8 = 1;
    pub const BULK_OUT: u8 = 2;
    pub const INTERRUPT_OUT: u8 = 3;
    pub const CONTROL: u8 = 4;
    pub const ISOCH_IN: u8 = 5;
    pub const BULK_IN: u8 = 6;
    pub const INTERRUPT_IN: u8 = 7;
}

/// Endpoint Context (32 bytes)
///
/// Contains endpoint-level configuration like transfer type, max packet size,
/// and transfer ring pointer.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(32))]
pub struct EndpointContext {
    /// EP State (bits 2:0), Mult (bits 9:8), MaxPStreams (bits 14:10),
    /// LSA (bit 15), Interval (bits 23:16), Max ESIT Payload Hi (bits 31:24)
    pub dword0: u32,
    /// CErr (bits 2:1), EP Type (bits 5:3), HID (bit 7),
    /// Max Burst Size (bits 15:8), Max Packet Size (bits 31:16)
    pub dword1: u32,
    /// TR Dequeue Pointer Lo (bits 31:4), DCS (bit 0)
    pub tr_dequeue_lo: u32,
    /// TR Dequeue Pointer Hi
    pub tr_dequeue_hi: u32,
    /// Average TRB Length (bits 15:0), Max ESIT Payload Lo (bits 31:16)
    pub dword4: u32,
    /// Reserved
    pub _reserved: [u32; 3],
}

impl EndpointContext {
    /// Create a new zeroed endpoint context
    pub const fn new() -> Self {
        Self {
            dword0: 0,
            dword1: 0,
            tr_dequeue_lo: 0,
            tr_dequeue_hi: 0,
            dword4: 0,
            _reserved: [0; 3],
        }
    }

    /// Set Endpoint Type (3 bits)
    pub fn set_ep_type(&mut self, ep_type: u8) {
        self.dword1 = (self.dword1 & !(0x7 << 3)) | (((ep_type as u32) & 0x7) << 3);
    }

    /// Get Endpoint Type
    pub fn get_ep_type(&self) -> u8 {
        ((self.dword1 >> 3) & 0x7) as u8
    }

    /// Set Max Packet Size (16 bits)
    pub fn set_max_packet_size(&mut self, size: u16) {
        self.dword1 = (self.dword1 & !0xFFFF0000) | ((size as u32) << 16);
    }

    /// Get Max Packet Size
    pub fn get_max_packet_size(&self) -> u16 {
        ((self.dword1 >> 16) & 0xFFFF) as u16
    }

    /// Set Max Burst Size (8 bits) - for USB 3.0 SuperSpeed
    pub fn set_max_burst_size(&mut self, burst: u8) {
        self.dword1 = (self.dword1 & !(0xFF << 8)) | (((burst as u32) & 0xFF) << 8);
    }

    /// Set CErr (Error Count, 2 bits) - usually 3 for bulk/control
    pub fn set_cerr(&mut self, cerr: u8) {
        self.dword1 = (self.dword1 & !(0x3 << 1)) | (((cerr as u32) & 0x3) << 1);
    }

    /// Set Interval (8 bits) - for interrupt/isoch endpoints
    pub fn set_interval(&mut self, interval: u8) {
        self.dword0 = (self.dword0 & !(0xFF << 16)) | (((interval as u32) & 0xFF) << 16);
    }

    /// Set Transfer Ring Dequeue Pointer (64-bit, 16-byte aligned)
    /// The DCS (Dequeue Cycle State) is in bit 0
    pub fn set_tr_dequeue_ptr(&mut self, ptr: u64, dcs: bool) {
        // Low 32 bits (bits 3:0 are reserved/DCS, pointer is 16-byte aligned)
        self.tr_dequeue_lo = (ptr as u32 & !0xF) | if dcs { 1 } else { 0 };
        // High 32 bits
        self.tr_dequeue_hi = (ptr >> 32) as u32;
    }

    /// Get Transfer Ring Dequeue Pointer
    pub fn get_tr_dequeue_ptr(&self) -> u64 {
        ((self.tr_dequeue_hi as u64) << 32) | (self.tr_dequeue_lo as u64 & !0xF)
    }

    /// Get Dequeue Cycle State
    pub fn get_dcs(&self) -> bool {
        (self.tr_dequeue_lo & 1) != 0
    }

    /// Set Average TRB Length (16 bits) - used for bandwidth calculations
    pub fn set_average_trb_length(&mut self, len: u16) {
        self.dword4 = (self.dword4 & !0xFFFF) | (len as u32);
    }

    /// Get Endpoint State
    pub fn get_ep_state(&self) -> u8 {
        (self.dword0 & 0x7) as u8
    }

    /// Configure for Control endpoint (EP0)
    pub fn configure_control(&mut self, max_packet: u16, tr_dequeue: u64) {
        self.set_ep_type(EndpointType::CONTROL);
        self.set_max_packet_size(max_packet);
        self.set_cerr(3); // 3 retries
        self.set_average_trb_length(8); // Control transfers average 8 bytes
        self.set_tr_dequeue_ptr(tr_dequeue, true); // DCS=1 initially
    }

    /// Configure for Bulk IN endpoint
    pub fn configure_bulk_in(&mut self, max_packet: u16, tr_dequeue: u64) {
        self.set_ep_type(EndpointType::BULK_IN);
        self.set_max_packet_size(max_packet);
        self.set_cerr(3);
        self.set_average_trb_length(1024); // Typical bulk transfer
        self.set_tr_dequeue_ptr(tr_dequeue, true);
    }

    /// Configure for Bulk OUT endpoint
    pub fn configure_bulk_out(&mut self, max_packet: u16, tr_dequeue: u64) {
        self.set_ep_type(EndpointType::BULK_OUT);
        self.set_max_packet_size(max_packet);
        self.set_cerr(3);
        self.set_average_trb_length(1024);
        self.set_tr_dequeue_ptr(tr_dequeue, true);
    }

    /// Configure for Interrupt IN endpoint
    pub fn configure_interrupt_in(&mut self, max_packet: u16, interval: u8, tr_dequeue: u64) {
        self.set_ep_type(EndpointType::INTERRUPT_IN);
        self.set_max_packet_size(max_packet);
        self.set_cerr(3);
        self.set_interval(interval);
        self.set_average_trb_length(max_packet);
        self.set_tr_dequeue_ptr(tr_dequeue, true);
    }
}

/// Input Control Context (8 bytes, but padded to 32 for alignment)
///
/// Used with Input Context to indicate which contexts are being modified.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(32))]
pub struct InputControlContext {
    /// Drop Context Flags (bits 31:2) - which contexts to drop
    pub drop_flags: u32,
    /// Add Context Flags (bits 31:0) - which contexts to add
    pub add_flags: u32,
    /// Reserved
    pub _reserved: [u32; 6],
}

impl InputControlContext {
    /// Create a new zeroed input control context
    pub const fn new() -> Self {
        Self {
            drop_flags: 0,
            add_flags: 0,
            _reserved: [0; 6],
        }
    }

    /// Add Slot Context (A0)
    pub fn add_slot(&mut self) {
        self.add_flags |= 1 << 0;
    }

    /// Add Endpoint Context (A1-A31)
    /// ep_index is the DCI (Device Context Index): 1 for EP0, 2 for EP1 OUT, etc.
    pub fn add_endpoint(&mut self, dci: u8) {
        if dci < 32 {
            self.add_flags |= 1 << dci;
        }
    }

    /// Drop Endpoint Context (D2-D31)
    pub fn drop_endpoint(&mut self, dci: u8) {
        if (2..32).contains(&dci) {
            self.drop_flags |= 1 << dci;
        }
    }

    /// Clear all flags
    pub fn clear(&mut self) {
        self.drop_flags = 0;
        self.add_flags = 0;
    }
}

/// Calculate Device Context Index (DCI) from endpoint address
///
/// DCI = (Endpoint Number * 2) + Direction
/// Where Direction is 0 for OUT, 1 for IN
/// EP0 (control) has DCI=1
///
/// Examples:
/// - EP0 (control) -> DCI 1
/// - EP1 OUT -> DCI 2
/// - EP1 IN -> DCI 3
/// - EP2 OUT -> DCI 4
/// - EP2 IN -> DCI 5
pub fn endpoint_to_dci(endpoint_addr: u8) -> u8 {
    let ep_num = endpoint_addr & 0x0F;
    let is_in = (endpoint_addr & 0x80) != 0;

    if ep_num == 0 {
        1 // Control endpoint always DCI 1
    } else {
        (ep_num * 2) + if is_in { 1 } else { 0 }
    }
}

/// Convert DCI back to endpoint address
pub fn dci_to_endpoint(dci: u8) -> u8 {
    if dci <= 1 {
        0 // EP0
    } else {
        let ep_num = dci / 2;
        let is_in = (dci % 2) == 1;
        ep_num | if is_in { 0x80 } else { 0 }
    }
}

/// Input Context
///
/// Used for Address Device and Configure Endpoint commands.
/// Contains Input Control Context, Slot Context, and up to 31 Endpoint Contexts.
///
/// Layout (64-byte aligned):
/// - Offset 0x00: Input Control Context (32 bytes)
/// - Offset 0x20: Slot Context (32 bytes)
/// - Offset 0x40: Endpoint Context 0 (EP0, 32 bytes)
/// - Offset 0x60: Endpoint Context 1 (32 bytes)
/// - ...
/// - Offset 0x3E0: Endpoint Context 30 (32 bytes)
pub struct InputContext {
    /// DMA allocation for the context
    dma: DmaCoherent,
}

impl InputContext {
    /// Size of Input Context in bytes (33 x 32 bytes = 1056 bytes)
    /// We round up to 4096 for page alignment
    pub const SIZE: usize = 4096;

    /// Create a new Input Context
    pub fn new<D: DmaDevice>(dev: &D) -> Option<Self> {
        let dma = dma_alloc_coherent(dev, Self::SIZE)?;
        Some(Self { dma })
    }

    /// Get DMA address
    pub fn dma_addr(&self) -> u64 {
        self.dma.dma_addr.as_u64()
    }

    /// Get mutable pointer to Input Control Context
    pub fn control_mut(&mut self) -> &mut InputControlContext {
        unsafe { &mut *(self.dma.cpu_addr as *mut InputControlContext) }
    }

    /// Get mutable pointer to Slot Context
    pub fn slot_mut(&mut self) -> &mut SlotContext {
        unsafe { &mut *((self.dma.cpu_addr as usize + 0x20) as *mut SlotContext) }
    }

    /// Get mutable pointer to Endpoint Context by DCI (1-31)
    pub fn endpoint_mut(&mut self, dci: u8) -> Option<&mut EndpointContext> {
        if dci == 0 || dci > 31 {
            return None;
        }
        let offset = 0x20 + (dci as usize * 0x20);
        unsafe { Some(&mut *((self.dma.cpu_addr as usize + offset) as *mut EndpointContext)) }
    }

    /// Zero all contexts
    pub fn clear(&mut self) {
        unsafe {
            core::ptr::write_bytes(self.dma.cpu_addr, 0, Self::SIZE);
        }
    }
}

/// Output Device Context (also called Device Context)
///
/// Where xHCI writes the current device state.
/// Same layout as Input Context but without Input Control Context.
///
/// Layout (64-byte aligned):
/// - Offset 0x00: Slot Context (32 bytes)
/// - Offset 0x20: Endpoint Context 0 (EP0, 32 bytes)
/// - Offset 0x40: Endpoint Context 1 (32 bytes)
/// - ...
pub struct OutputDeviceContext {
    /// DMA allocation for the context
    dma: DmaCoherent,
}

impl OutputDeviceContext {
    /// Size of Output Device Context (32 x 32 bytes = 1024 bytes)
    /// We round up to 4096 for page alignment
    pub const SIZE: usize = 4096;

    /// Create a new Output Device Context
    pub fn new<D: DmaDevice>(dev: &D) -> Option<Self> {
        let dma = dma_alloc_coherent(dev, Self::SIZE)?;
        Some(Self { dma })
    }

    /// Get DMA address
    pub fn dma_addr(&self) -> u64 {
        self.dma.dma_addr.as_u64()
    }

    /// Get pointer to Slot Context (read-only, xHCI writes this)
    pub fn slot(&self) -> &SlotContext {
        unsafe { &*(self.dma.cpu_addr as *const SlotContext) }
    }

    /// Get pointer to Endpoint Context by DCI (1-31)
    pub fn endpoint(&self, dci: u8) -> Option<&EndpointContext> {
        if dci == 0 || dci > 31 {
            return None;
        }
        let offset = dci as usize * 0x20;
        unsafe { Some(&*((self.dma.cpu_addr as usize + offset) as *const EndpointContext)) }
    }

    /// Zero all contexts
    pub fn clear(&mut self) {
        unsafe {
            core::ptr::write_bytes(self.dma.cpu_addr, 0, Self::SIZE);
        }
    }
}
