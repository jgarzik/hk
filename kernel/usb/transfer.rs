//! xHCI Transfer Ring
//!
//! Transfer Rings are used for data transfers on bulk, interrupt, and control endpoints.
//! Each active endpoint has its own Transfer Ring.
//!
//! Unlike the Command Ring which is shared across all devices, each endpoint
//! has a dedicated Transfer Ring for submitting transfer TRBs.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use crate::dma::{DmaCoherent, DmaDevice, dma_alloc_coherent};
use crate::frame_alloc::FRAME_SIZE;

/// Transfer Request Block (TRB) - same structure as in xhci.rs
/// but with additional types for data transfers
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(16))]
pub struct Trb {
    /// Parameter (data pointer or other info)
    pub parameter: u64,
    /// Status field (transfer length, etc.)
    pub status: u32,
    /// Control field (TRB type, cycle bit, flags)
    pub control: u32,
}

impl Trb {
    /// Create a new zeroed TRB
    pub const fn new() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
        }
    }

    /// Set TRB type (bits 15:10)
    pub fn set_type(&mut self, trb_type: u8) {
        self.control = (self.control & !0xFC00) | ((trb_type as u32) << 10);
    }

    /// Get TRB type
    pub fn get_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// Set cycle bit (bit 0)
    pub fn set_cycle(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }

    /// Get cycle bit
    pub fn get_cycle(&self) -> bool {
        (self.control & 1) != 0
    }

    /// Set Interrupt On Completion flag (bit 5)
    pub fn set_ioc(&mut self, ioc: bool) {
        if ioc {
            self.control |= 1 << 5;
        } else {
            self.control &= !(1 << 5);
        }
    }

    /// Set Immediate Data flag (bit 6) - data is in parameter field
    pub fn set_idt(&mut self, idt: bool) {
        if idt {
            self.control |= 1 << 6;
        } else {
            self.control &= !(1 << 6);
        }
    }

    /// Set Chain bit (bit 4) - TRB is part of a chain
    pub fn set_chain(&mut self, chain: bool) {
        if chain {
            self.control |= 1 << 4;
        } else {
            self.control &= !(1 << 4);
        }
    }

    /// Set transfer length in status field (bits 16:0)
    pub fn set_transfer_length(&mut self, len: u32) {
        self.status = (self.status & !0x1FFFF) | (len & 0x1FFFF);
    }

    /// Get transfer length from status field
    pub fn get_transfer_length(&self) -> u32 {
        self.status & 0x1FFFF
    }

    /// Get completion code from status field (bits 31:24)
    pub fn get_completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }

    /// Set TD Size field (bits 21:17) - number of remaining packets
    pub fn set_td_size(&mut self, td_size: u8) {
        self.status = (self.status & !(0x1F << 17)) | (((td_size as u32) & 0x1F) << 17);
    }

    /// Set Interrupter Target (bits 31:22)
    pub fn set_interrupter_target(&mut self, target: u16) {
        self.status = (self.status & !(0x3FF << 22)) | (((target as u32) & 0x3FF) << 22);
    }

    /// Create a Normal TRB for data transfer
    pub fn normal(data_ptr: u64, len: u32, ioc: bool, chain: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = data_ptr;
        trb.set_type(TrbType::NORMAL);
        trb.set_transfer_length(len);
        trb.set_ioc(ioc);
        trb.set_chain(chain);
        trb
    }

    /// Create a Link TRB
    pub fn link(target: u64, toggle_cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = target;
        trb.set_type(TrbType::LINK);
        if toggle_cycle {
            trb.control |= 1 << 1; // Toggle Cycle bit
        }
        trb
    }

    /// Create a Setup Stage TRB for control transfers
    pub fn setup_stage(setup: &[u8; 8], transfer_type: u8) -> Self {
        let mut trb = Self::new();
        // Setup data goes in parameter field (8 bytes)
        trb.parameter = u64::from_le_bytes(*setup);
        trb.set_type(TrbType::SETUP_STAGE);
        trb.set_transfer_length(8);
        trb.set_idt(true); // Immediate Data
        // Transfer type: 0=No Data, 2=OUT Data, 3=IN Data
        trb.control |= (transfer_type as u32) << 16;
        trb
    }

    /// Create a Data Stage TRB for control transfers
    pub fn data_stage(data_ptr: u64, len: u32, is_in: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = data_ptr;
        trb.set_type(TrbType::DATA_STAGE);
        trb.set_transfer_length(len);
        if is_in {
            trb.control |= 1 << 16; // Direction bit: 1=IN
        }
        trb
    }

    /// Create a Status Stage TRB for control transfers
    pub fn status_stage(is_in: bool) -> Self {
        let mut trb = Self::new();
        trb.set_type(TrbType::STATUS_STAGE);
        trb.set_ioc(true); // Always want completion for status stage
        if is_in {
            trb.control |= 1 << 16; // Direction bit
        }
        trb
    }
}

/// TRB types
#[allow(non_snake_case)]
pub mod TrbType {
    /// Normal TRB - used for bulk/interrupt data transfers
    pub const NORMAL: u8 = 1;
    /// Setup Stage TRB - first TRB in control transfer
    pub const SETUP_STAGE: u8 = 2;
    /// Data Stage TRB - data phase of control transfer
    pub const DATA_STAGE: u8 = 3;
    /// Status Stage TRB - status phase of control transfer
    pub const STATUS_STAGE: u8 = 4;
    /// Isoch TRB - isochronous transfer
    pub const ISOCH: u8 = 5;
    /// Link TRB - chain to another ring segment
    pub const LINK: u8 = 6;
    /// Event Data TRB - for event data
    pub const EVENT_DATA: u8 = 7;
    /// No Op TRB
    pub const NO_OP: u8 = 8;

    // Command TRB types (for command ring, not transfer ring)
    /// Enable Slot Command
    pub const ENABLE_SLOT: u8 = 9;
    /// Disable Slot Command
    pub const DISABLE_SLOT: u8 = 10;
    /// Address Device Command
    pub const ADDRESS_DEVICE: u8 = 11;
    /// Configure Endpoint Command
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    /// Evaluate Context Command
    pub const EVALUATE_CONTEXT: u8 = 13;
    /// Reset Endpoint Command
    pub const RESET_ENDPOINT: u8 = 14;
    /// Stop Endpoint Command
    pub const STOP_ENDPOINT: u8 = 15;
    /// Set TR Dequeue Pointer Command
    pub const SET_TR_DEQUEUE: u8 = 16;
    /// Reset Device Command
    pub const RESET_DEVICE: u8 = 17;

    // Event TRB types
    /// Transfer Event
    pub const TRANSFER_EVENT: u8 = 32;
    /// Command Completion Event
    pub const COMMAND_COMPLETION: u8 = 33;
    /// Port Status Change Event
    pub const PORT_STATUS_CHANGE: u8 = 34;
    /// Bandwidth Request Event
    pub const BANDWIDTH_REQUEST: u8 = 35;
    /// Doorbell Event
    pub const DOORBELL: u8 = 36;
    /// Host Controller Event
    pub const HOST_CONTROLLER: u8 = 37;
    /// Device Notification Event
    pub const DEVICE_NOTIFICATION: u8 = 38;
    /// MFINDEX Wrap Event
    pub const MFINDEX_WRAP: u8 = 39;
}

/// TRB completion codes
#[allow(non_snake_case)]
pub mod CompletionCode {
    pub const INVALID: u8 = 0;
    pub const SUCCESS: u8 = 1;
    pub const DATA_BUFFER_ERROR: u8 = 2;
    pub const BABBLE_DETECTED: u8 = 3;
    pub const USB_TRANSACTION_ERROR: u8 = 4;
    pub const TRB_ERROR: u8 = 5;
    pub const STALL_ERROR: u8 = 6;
    pub const RESOURCE_ERROR: u8 = 7;
    pub const BANDWIDTH_ERROR: u8 = 8;
    pub const NO_SLOTS_AVAILABLE: u8 = 9;
    pub const INVALID_STREAM_TYPE: u8 = 10;
    pub const SLOT_NOT_ENABLED: u8 = 11;
    pub const ENDPOINT_NOT_ENABLED: u8 = 12;
    pub const SHORT_PACKET: u8 = 13;
    pub const RING_UNDERRUN: u8 = 14;
    pub const RING_OVERRUN: u8 = 15;
    pub const VF_EVENT_RING_FULL: u8 = 16;
    pub const PARAMETER_ERROR: u8 = 17;
    pub const BANDWIDTH_OVERRUN: u8 = 18;
    pub const CONTEXT_STATE_ERROR: u8 = 19;
    pub const NO_PING_RESPONSE: u8 = 20;
    pub const EVENT_RING_FULL: u8 = 21;
    pub const INCOMPATIBLE_DEVICE: u8 = 22;
    pub const MISSED_SERVICE: u8 = 23;
    pub const COMMAND_RING_STOPPED: u8 = 24;
    pub const COMMAND_ABORTED: u8 = 25;
    pub const STOPPED: u8 = 26;
    pub const STOPPED_LENGTH_INVALID: u8 = 27;
    pub const STOPPED_SHORT_PACKET: u8 = 28;
    pub const MAX_EXIT_LATENCY_TOO_LARGE: u8 = 29;
}

/// Transfer Ring for bulk/interrupt/control endpoint transfers
///
/// Each endpoint has its own Transfer Ring. The ring is a circular
/// buffer of TRBs with a Link TRB at the end pointing back to the start.
pub struct TransferRing {
    /// DMA allocation for the ring
    dma: DmaCoherent,
    /// Number of TRBs in ring (excluding link TRB)
    size: usize,
    /// Enqueue pointer index
    enqueue: usize,
    /// Dequeue pointer index (tracks what the HC has consumed)
    dequeue: usize,
    /// Producer Cycle State
    cycle: bool,
}

impl TransferRing {
    /// Default ring size (leaves room for link TRB)
    pub const DEFAULT_SIZE: usize = 255;

    /// Create a new transfer ring using DMA allocation
    pub fn new<D: DmaDevice>(dev: &D) -> Option<Self> {
        // Allocate one page for the ring (4KB = 256 TRBs)
        let dma = dma_alloc_coherent(dev, FRAME_SIZE)?;

        // Zero the memory
        unsafe {
            core::ptr::write_bytes(dma.cpu_addr, 0, FRAME_SIZE);
        }

        let trbs = dma.cpu_addr as *mut Trb;
        let size = Self::DEFAULT_SIZE;

        // Set up Link TRB at the end
        unsafe {
            let link = trbs.add(size);
            let link_trb = Trb::link(dma.dma_addr.as_u64(), true); // Toggle cycle
            write_volatile(link, link_trb);
            // Set initial cycle bit
            (*link).set_cycle(true);
        }

        Some(Self {
            dma,
            size,
            enqueue: 0,
            dequeue: 0,
            cycle: true,
        })
    }

    /// Get the physical/DMA address of the ring
    pub fn dma_addr(&self) -> u64 {
        self.dma.dma_addr.as_u64()
    }

    /// Get the dequeue pointer (DMA address) with cycle bit
    /// This is programmed into the Endpoint Context
    pub fn dequeue_ptr(&self) -> u64 {
        let addr = self.dma.dma_addr.as_u64() + (self.dequeue * 16) as u64;
        // Set DCS (Dequeue Cycle State) in bit 0
        if self.cycle { addr | 1 } else { addr }
    }

    /// Enqueue a TRB and return its DMA address
    pub fn enqueue(&mut self, mut trb: Trb) -> u64 {
        let index = self.enqueue;
        let trbs = self.dma.cpu_addr as *mut Trb;
        let trb_ptr = unsafe { trbs.add(index) };

        // Set cycle bit to make TRB valid
        trb.set_cycle(self.cycle);

        // Memory barrier before writing
        fence(Ordering::SeqCst);

        // Write TRB
        unsafe {
            write_volatile(trb_ptr, trb);
        }

        // Memory barrier after writing
        fence(Ordering::SeqCst);

        let trb_addr = self.dma.dma_addr.as_u64() + (index * 16) as u64;

        // Advance enqueue pointer
        self.enqueue += 1;
        if self.enqueue >= self.size {
            // Wrap around
            self.enqueue = 0;

            // Update Link TRB cycle bit with CURRENT cycle (before toggle).
            // Hardware on the current pass still expects the Link TRB to have
            // the current cycle bit to follow it. The Toggle Cycle (TC) bit
            // in the Link TRB causes hardware to toggle its CCS after following.
            unsafe {
                let link = trbs.add(self.size);
                let mut link_trb = read_volatile(link);
                link_trb.set_cycle(self.cycle);
                fence(Ordering::SeqCst);
                write_volatile(link, link_trb);
                fence(Ordering::SeqCst);
            }

            // NOW toggle cycle bit for new pass
            self.cycle = !self.cycle;
        }

        trb_addr
    }

    /// Enqueue a Normal TRB for bulk/interrupt transfer
    pub fn enqueue_normal(&mut self, data_dma: u64, len: u32, ioc: bool) -> u64 {
        let trb = Trb::normal(data_dma, len, ioc, false);
        self.enqueue(trb)
    }

    /// Enqueue multiple Normal TRBs for a large transfer (chained)
    pub fn enqueue_bulk_transfer(&mut self, data_dma: u64, total_len: u32, max_packet: u32) -> u64 {
        let mut remaining = total_len;
        let mut offset = 0u64;
        let mut first_addr = 0u64;

        while remaining > 0 {
            let chunk = remaining.min(max_packet);
            let is_last = remaining <= max_packet;

            let trb = Trb::normal(
                data_dma + offset,
                chunk,
                is_last,  // IOC on last TRB only
                !is_last, // Chain all but last
            );

            let addr = self.enqueue(trb);
            if first_addr == 0 {
                first_addr = addr;
            }

            offset += chunk as u64;
            remaining -= chunk;
        }

        first_addr
    }

    /// Update dequeue pointer after completion (called when we get Transfer Event)
    pub fn advance_dequeue(&mut self) {
        self.dequeue += 1;
        if self.dequeue >= self.size {
            self.dequeue = 0;
        }
    }

    /// Check if ring is full
    pub fn is_full(&self) -> bool {
        let next = if self.enqueue + 1 >= self.size {
            0
        } else {
            self.enqueue + 1
        };
        next == self.dequeue
    }

    /// Check if ring is empty
    pub fn is_empty(&self) -> bool {
        self.enqueue == self.dequeue
    }

    /// Get number of available slots
    pub fn available(&self) -> usize {
        if self.enqueue >= self.dequeue {
            self.size - (self.enqueue - self.dequeue) - 1
        } else {
            self.dequeue - self.enqueue - 1
        }
    }

    /// Get debug info: (enqueue, dequeue, cycle)
    pub fn debug_state(&self) -> (usize, usize, bool) {
        (self.enqueue, self.dequeue, self.cycle)
    }
}

impl Drop for TransferRing {
    fn drop(&mut self) {
        // DmaCoherent will be freed when dma field is dropped
        // Note: In real implementation, we'd need to ensure no outstanding TRBs
    }
}
