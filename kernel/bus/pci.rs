//! PCI Host Controller Driver
//!
//! Provides PCI configuration space access via I/O ports CF8/CFC
//! and bus enumeration for device discovery.
//!
//! Implements the Bus/Driver model for layered device enumeration.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;

use spin::Once;

use crate::dma::{DmaConfig, DmaDevice};
use crate::dt::registry::DeviceInfo;
use crate::printkln;

use super::bus::{Bus, BusContext, BusDevice, BusDriver};
use super::driver::{Device, Driver, DriverError};

/// PCI configuration address port (x86 port I/O)
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_ADDR: u16 = 0x0CF8;
/// PCI configuration data port (x86 port I/O)
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_DATA: u16 = 0x0CFC;

// ============================================================================
// PCI BAR Allocator (for platforms without firmware BAR assignment)
// ============================================================================

/// Cross-platform BAR address allocator
///
/// On platforms without firmware BAR assignment (ARM with direct kernel boot),
/// the OS must allocate and assign PCI BAR addresses. On platforms with firmware
/// (x86 with BIOS/UEFI), BARs are pre-assigned and this allocator is not used.
///
/// The allocator is called only for BARs with address portion == 0.
mod bar_alloc {
    use core::sync::atomic::{AtomicU64, Ordering};

    // Platform-specific MMIO regions for PCI BAR allocation
    //
    // These ranges must not conflict with other memory mappings.
    // On x86, BIOS typically assigns BARs, so this is a fallback.
    // On ARM QEMU virt, this is the primary PCI MMIO window.

    #[cfg(target_arch = "x86_64")]
    const MMIO_START: u64 = 0xE000_0000; // Below LAPIC/IOAPIC region
    #[cfg(target_arch = "x86_64")]
    const MMIO_END: u64 = 0xFEB0_0000; // Before typical BIOS allocations

    #[cfg(target_arch = "aarch64")]
    const MMIO_START: u64 = 0x1000_0000; // QEMU virt PCI MMIO window
    #[cfg(target_arch = "aarch64")]
    const MMIO_END: u64 = 0x3F00_0000;

    /// Current allocation pointer (atomic for thread-safety)
    static NEXT_ADDR: AtomicU64 = AtomicU64::new(MMIO_START);

    /// Allocate a BAR address with the given size and alignment
    ///
    /// Returns None if the MMIO space is exhausted.
    pub fn allocate(size: u64) -> Option<u64> {
        if size == 0 {
            return None;
        }

        // BARs must be naturally aligned (address aligned to size)
        let align = size;

        loop {
            let current = NEXT_ADDR.load(Ordering::Relaxed);

            // Align up to the required alignment
            let aligned = (current + align - 1) & !(align - 1);
            let next = aligned + size;

            if next > MMIO_END {
                return None; // Out of space
            }

            // Try to update atomically
            match NEXT_ADDR.compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => return Some(aligned),
                Err(_) => continue, // Retry on contention
            }
        }
    }
}

/// PCI class codes
pub mod class {
    pub const MASS_STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
    pub const DISPLAY: u8 = 0x03;
    pub const MULTIMEDIA: u8 = 0x04;
    pub const MEMORY: u8 = 0x05;
    pub const BRIDGE: u8 = 0x06;
    pub const SERIAL_BUS: u8 = 0x0C;
}

/// PCI serial bus subclass codes
pub mod subclass {
    pub const USB: u8 = 0x03;
}

/// USB programming interface codes
pub mod prog_if {
    pub const UHCI: u8 = 0x00;
    pub const OHCI: u8 = 0x10;
    pub const EHCI: u8 = 0x20;
    pub const XHCI: u8 = 0x30;
}

/// PCI configuration space offsets
mod offset {
    pub const VENDOR_ID: u8 = 0x00;
    pub const DEVICE_ID: u8 = 0x02;
    pub const COMMAND: u8 = 0x04;
    pub const STATUS: u8 = 0x06;
    pub const REVISION_ID: u8 = 0x08;
    pub const PROG_IF: u8 = 0x09;
    pub const SUBCLASS: u8 = 0x0A;
    pub const CLASS_CODE: u8 = 0x0B;
    pub const CACHE_LINE_SIZE: u8 = 0x0C;
    pub const LATENCY_TIMER: u8 = 0x0D;
    pub const HEADER_TYPE: u8 = 0x0E;
    pub const BIST: u8 = 0x0F;
    pub const BAR0: u8 = 0x10;
    pub const BAR1: u8 = 0x14;
    pub const BAR2: u8 = 0x18;
    pub const BAR3: u8 = 0x1C;
    pub const BAR4: u8 = 0x20;
    pub const BAR5: u8 = 0x24;
    pub const INTERRUPT_LINE: u8 = 0x3C;
    pub const INTERRUPT_PIN: u8 = 0x3D;
}

/// PCI command register bits
pub mod command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

// ============================================================================
// PCI Configuration Space Access Abstraction
// ============================================================================

/// Trait for PCI configuration space access
///
/// Abstracts the mechanism for accessing PCI config registers:
/// - Port I/O (x86 legacy: CF8/CFC)
/// - ECAM (memory-mapped, PCIe standard)
pub trait PciConfigAccess: Send + Sync {
    /// Read 32-bit value from config space
    fn read32(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u32;

    /// Write 32-bit value to config space
    fn write32(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u32);

    /// Read 16-bit value (default: extract from 32-bit read)
    fn read16(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
        let val = self.read32(bus, dev, func, offset & 0xFC);
        ((val >> ((offset & 2) * 8)) & 0xFFFF) as u16
    }

    /// Read 8-bit value (default: extract from 32-bit read)
    fn read8(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
        let val = self.read32(bus, dev, func, offset & 0xFC);
        ((val >> ((offset & 3) * 8)) & 0xFF) as u8
    }

    /// Write 16-bit value (default: read-modify-write)
    fn write16(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
        let shift = (offset & 2) * 8;
        let mask = !(0xFFFF << shift);
        let old = self.read32(bus, dev, func, offset & 0xFC);
        let new = (old & mask) | ((val as u32) << shift);
        self.write32(bus, dev, func, offset & 0xFC, new);
    }
}

/// Port I/O based PCI config access (x86 legacy)
///
/// Uses CF8/CFC port I/O mechanism for PCI configuration space access.
#[cfg(target_arch = "x86_64")]
pub struct PortIoConfigAccess;

#[cfg(target_arch = "x86_64")]
impl PortIoConfigAccess {
    /// Encode BDF + offset into config address
    #[inline]
    fn encode_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        0x8000_0000
            | ((bus as u32) << 16)
            | ((dev as u32) << 11)
            | ((func as u32) << 8)
            | ((offset as u32) & 0xFC)
    }
}

#[cfg(target_arch = "x86_64")]
impl PciConfigAccess for PortIoConfigAccess {
    fn read32(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        use crate::arch::{inl, outl};
        outl(PCI_CONFIG_ADDR, Self::encode_addr(bus, dev, func, offset));
        inl(PCI_CONFIG_DATA)
    }

    fn write32(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
        use crate::arch::outl;
        outl(PCI_CONFIG_ADDR, Self::encode_addr(bus, dev, func, offset));
        outl(PCI_CONFIG_DATA, val);
    }
}

/// ECAM (Enhanced Configuration Access Mechanism) for PCIe
///
/// Memory-mapped PCI config space access. Works on all architectures.
/// Address formula: Base + (Bus << 20) | (Dev << 15) | (Func << 12) | Offset
pub struct EcamConfigAccess {
    /// Base virtual address of ECAM region
    base: *mut u8,
}

// Safety: ECAM region is device memory, access is synchronized by hardware
unsafe impl Send for EcamConfigAccess {}
unsafe impl Sync for EcamConfigAccess {}

impl EcamConfigAccess {
    /// Create ECAM accessor
    ///
    /// # Safety
    /// base_addr must be a valid mapped ECAM region that remains valid
    /// for the lifetime of this struct.
    pub const unsafe fn new(base_addr: *mut u8) -> Self {
        Self { base: base_addr }
    }

    /// Calculate offset into ECAM space
    #[inline]
    fn offset(bus: u8, dev: u8, func: u8, reg: u8) -> usize {
        ((bus as usize) << 20) | ((dev as usize) << 15) | ((func as usize) << 12) | (reg as usize)
    }
}

impl PciConfigAccess for EcamConfigAccess {
    fn read32(&self, bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        let addr = unsafe { self.base.add(Self::offset(bus, dev, func, offset)) };
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    fn write32(&self, bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
        let addr = unsafe { self.base.add(Self::offset(bus, dev, func, offset)) };
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }
}

// ============================================================================
// Global PCI Config Accessor
// ============================================================================

/// Global PCI config access mechanism
static PCI_CONFIG: Once<&'static dyn PciConfigAccess> = Once::new();

/// Initialize PCI config access with port I/O (x86 legacy)
#[cfg(target_arch = "x86_64")]
pub fn init_port_io() {
    static ACCESSOR: PortIoConfigAccess = PortIoConfigAccess;
    PCI_CONFIG.call_once(|| &ACCESSOR);
}

/// Initialize PCI config access with ECAM (memory-mapped)
///
/// # Safety
/// base_addr must be a valid mapped ECAM region.
pub unsafe fn init_ecam(base_addr: *mut u8) {
    // Leak a box to get 'static lifetime
    // Safety: caller guarantees base_addr is valid
    let accessor = Box::leak(Box::new(unsafe { EcamConfigAccess::new(base_addr) }));
    PCI_CONFIG.call_once(|| accessor as &dyn PciConfigAccess);
}

/// Check if PCI config access has been initialized
pub fn is_initialized() -> bool {
    PCI_CONFIG.get().is_some()
}

/// Get config accessor (panics if not initialized)
fn config() -> &'static dyn PciConfigAccess {
    *PCI_CONFIG
        .get()
        .expect("PCI config access not initialized - call init_port_io() or init_ecam() first")
}

// ============================================================================
// Legacy PCI Config Functions (now use trait)
// ============================================================================

/// Read 32-bit value from PCI configuration space
pub fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    config().read32(bus, dev, func, offset)
}

/// Write 32-bit value to PCI configuration space
pub fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    config().write32(bus, dev, func, offset, val)
}

/// Read 16-bit value from PCI configuration space
pub fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    config().read16(bus, dev, func, offset)
}

/// Write 16-bit value to PCI configuration space
pub fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    config().write16(bus, dev, func, offset, val)
}

/// Read 8-bit value from PCI configuration space
pub fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    config().read8(bus, dev, func, offset)
}

/// PCI device header (Type 0 - standard)
#[derive(Debug, Clone)]
pub struct PciDeviceHeader {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision_id: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class_code: u8,
    pub cache_line_size: u8,
    pub latency_timer: u8,
    pub header_type: u8,
    pub bist: u8,
    pub bar: [u32; 6],
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciDeviceHeader {
    /// Read header from PCI configuration space
    pub fn read(bus: u8, dev: u8, func: u8) -> Self {
        Self {
            vendor_id: pci_read16(bus, dev, func, offset::VENDOR_ID),
            device_id: pci_read16(bus, dev, func, offset::DEVICE_ID),
            command: pci_read16(bus, dev, func, offset::COMMAND),
            status: pci_read16(bus, dev, func, offset::STATUS),
            revision_id: pci_read8(bus, dev, func, offset::REVISION_ID),
            prog_if: pci_read8(bus, dev, func, offset::PROG_IF),
            subclass: pci_read8(bus, dev, func, offset::SUBCLASS),
            class_code: pci_read8(bus, dev, func, offset::CLASS_CODE),
            cache_line_size: pci_read8(bus, dev, func, offset::CACHE_LINE_SIZE),
            latency_timer: pci_read8(bus, dev, func, offset::LATENCY_TIMER),
            header_type: pci_read8(bus, dev, func, offset::HEADER_TYPE),
            bist: pci_read8(bus, dev, func, offset::BIST),
            bar: [
                pci_read32(bus, dev, func, offset::BAR0),
                pci_read32(bus, dev, func, offset::BAR1),
                pci_read32(bus, dev, func, offset::BAR2),
                pci_read32(bus, dev, func, offset::BAR3),
                pci_read32(bus, dev, func, offset::BAR4),
                pci_read32(bus, dev, func, offset::BAR5),
            ],
            interrupt_line: pci_read8(bus, dev, func, offset::INTERRUPT_LINE),
            interrupt_pin: pci_read8(bus, dev, func, offset::INTERRUPT_PIN),
        }
    }

    /// Check if this is a multi-function device
    pub fn is_multifunction(&self) -> bool {
        (self.header_type & 0x80) != 0
    }

    /// Get header type (0, 1, or 2)
    pub fn header_type_number(&self) -> u8 {
        self.header_type & 0x7F
    }
}

/// Represents a discovered PCI device
#[derive(Debug, Clone)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub header: PciDeviceHeader,
    /// DMA configuration (addressing masks)
    pub dma_config: DmaConfig,
}

impl PciDevice {
    /// Read a PCI device from configuration space
    pub fn read(bus: u8, device: u8, function: u8) -> Option<Self> {
        let vendor_id = pci_read16(bus, device, function, offset::VENDOR_ID);
        if vendor_id == 0xFFFF {
            return None;
        }

        Some(Self {
            bus,
            device,
            function,
            header: PciDeviceHeader::read(bus, device, function),
            dma_config: DmaConfig::default(), // 32-bit DMA by default
        })
    }

    /// Set the DMA mask for streaming DMA mappings
    ///
    /// Returns true if the mask is acceptable, false if the device
    /// cannot support the requested addressing width.
    pub fn set_dma_mask(&mut self, mask: u64) -> bool {
        // For MVP, always accept (real impl would check device capability)
        self.dma_config.dma_mask = mask;
        true
    }

    /// Set the coherent DMA mask
    ///
    /// This mask is often more restrictive than the streaming DMA mask.
    pub fn set_coherent_dma_mask(&mut self, mask: u64) -> bool {
        self.dma_config.coherent_dma_mask = mask;
        true
    }

    /// Set both DMA masks at once (common pattern)
    pub fn set_dma_mask_and_coherent(&mut self, mask: u64) -> bool {
        self.set_dma_mask(mask) && self.set_coherent_dma_mask(mask)
    }

    /// Get BAR address (handles 32-bit and 64-bit BARs)
    pub fn bar_address(&self, bar_index: usize) -> Option<u64> {
        if bar_index >= 6 {
            return None;
        }

        let bar = self.header.bar[bar_index];
        if bar == 0 {
            return None;
        }

        // Check if I/O or memory BAR
        if (bar & 1) != 0 {
            // I/O BAR - return I/O port address
            Some((bar & !0x3) as u64)
        } else {
            // Memory BAR
            let bar_type = (bar >> 1) & 0x3;
            match bar_type {
                0 => {
                    // 32-bit BAR
                    Some((bar & !0xF) as u64)
                }
                2 => {
                    // 64-bit BAR - need to read next BAR too
                    if bar_index >= 5 {
                        return None;
                    }
                    let high = self.header.bar[bar_index + 1] as u64;
                    Some((high << 32) | (bar & !0xF) as u64)
                }
                _ => None,
            }
        }
    }

    /// Check if BAR is memory-mapped (vs I/O port)
    pub fn bar_is_mmio(&self, bar_index: usize) -> bool {
        if bar_index >= 6 {
            return false;
        }
        (self.header.bar[bar_index] & 1) == 0
    }

    /// Get BAR size by writing all 1s and reading back
    pub fn bar_size(&self, bar_index: usize) -> u64 {
        if bar_index >= 6 {
            return 0;
        }

        let bar_offset = offset::BAR0 + (bar_index as u8 * 4);

        // Save original value
        let original = pci_read32(self.bus, self.device, self.function, bar_offset);

        // Write all 1s
        pci_write32(
            self.bus,
            self.device,
            self.function,
            bar_offset,
            0xFFFF_FFFF,
        );

        // Read back and restore
        let size_mask = pci_read32(self.bus, self.device, self.function, bar_offset);
        pci_write32(self.bus, self.device, self.function, bar_offset, original);

        if size_mask == 0 {
            return 0;
        }

        // For memory BARs, mask out type bits
        let size_mask = if (original & 1) == 0 {
            size_mask & !0xF
        } else {
            size_mask & !0x3
        };

        // Size is (~mask) + 1
        ((!size_mask) as u64) + 1
    }

    /// Check if a BAR is a 64-bit BAR
    fn bar_is_64bit(&self, bar_index: usize) -> bool {
        if bar_index >= 6 {
            return false;
        }
        let bar = self.header.bar[bar_index];
        // Memory BAR (bit 0 = 0) with type 2 (bits 2:1 = 10) is 64-bit
        (bar & 1) == 0 && ((bar >> 1) & 0x3) == 2
    }

    /// Assign a BAR address (for platforms without firmware BAR assignment)
    ///
    /// On platforms without firmware (e.g., ARM with direct kernel boot),
    /// there's no BIOS to assign BAR addresses. This method allocates an
    /// address from the MMIO region and writes it to the BAR register.
    ///
    /// On platforms with firmware (x86 with BIOS), BARs are pre-assigned
    /// and this is typically not called (checked by assign_all_bars).
    ///
    /// Returns the assigned address, or None if allocation failed.
    pub fn assign_bar(&mut self, bar_index: usize) -> Option<u64> {
        if bar_index >= 6 {
            return None;
        }

        let bar_val = self.header.bar[bar_index];
        let is_io = (bar_val & 1) != 0;
        if is_io {
            // I/O BARs not supported on ARM
            return None;
        }

        let is_64bit = self.bar_is_64bit(bar_index);
        if is_64bit && bar_index >= 5 {
            // 64-bit BAR needs two slots
            return None;
        }

        // Get the BAR size
        let size = self.bar_size(bar_index);
        if size == 0 {
            return None;
        }

        // Allocate address (always use 32-bit range for simplicity)
        let addr = bar_alloc::allocate(size)?;

        // Write address to BAR (preserve type bits)
        let bar_offset = offset::BAR0 + (bar_index as u8 * 4);
        let new_bar = (addr as u32) | (bar_val & 0xF);
        pci_write32(self.bus, self.device, self.function, bar_offset, new_bar);
        self.header.bar[bar_index] = new_bar;

        // For 64-bit BARs, write high 32 bits to next BAR
        if is_64bit {
            let bar_offset_high = offset::BAR0 + ((bar_index + 1) as u8 * 4);
            let high = (addr >> 32) as u32;
            pci_write32(self.bus, self.device, self.function, bar_offset_high, high);
            self.header.bar[bar_index + 1] = high;
        }

        Some(addr)
    }

    /// Assign all unassigned BARs (cross-platform)
    ///
    /// Iterates through all BARs and assigns addresses to any that are
    /// unassigned (address portion == 0). On platforms with firmware (x86 BIOS),
    /// BARs are typically pre-assigned, so this does nothing. On platforms
    /// without firmware (ARM direct boot), this allocates addresses.
    pub fn assign_all_bars(&mut self) {
        let mut i = 0;
        while i < 6 {
            // Check if BAR is unassigned (address portion is 0)
            let bar = self.header.bar[i];
            let is_io = (bar & 1) != 0;
            let addr = if is_io { bar & !0x3 } else { bar & !0xF };
            let is_64bit = self.bar_is_64bit(i);

            if addr == 0 {
                // Try to assign
                if let Some(assigned) = self.assign_bar(i) {
                    printkln!(
                        "PCI: Assigned BAR{} = {:#x} for {}",
                        i,
                        assigned,
                        BusDevice::bus_id(self)
                    );
                }
            }

            // Skip the next BAR slot if this was a 64-bit BAR
            if is_64bit {
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    /// Enable memory space access
    pub fn enable_memory_space(&self) {
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd | command::MEMORY_SPACE,
        );
    }

    /// Enable bus mastering (for DMA)
    pub fn enable_bus_master(&self) {
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd | command::BUS_MASTER,
        );
    }

    /// Register an IRQ handler for this PCI device (x86_64 only)
    ///
    /// # Arguments
    /// - `handler`: IRQ handler function
    /// - `data`: Opaque pointer to driver state (passed to handler)
    ///
    /// # Returns
    /// The IRQ number on success, or an error description
    #[cfg(target_arch = "x86_64")]
    pub fn register_irq_handler(
        &self,
        handler: crate::arch::x86_64::irq::IrqHandler,
        data: *mut (),
    ) -> Result<u8, &'static str> {
        let irq = self.header.interrupt_line;

        // Check for invalid/unassigned IRQ
        if irq == 0xFF || irq >= 16 {
            return Err("No valid IRQ assigned to device");
        }

        // Generate unique ID from device address
        let id =
            ((self.bus as usize) << 16) | ((self.device as usize) << 8) | (self.function as usize);

        // Register with the IRQ subsystem
        crate::arch::x86_64::irq::register_irq_handler(irq, handler, data, id)?;

        // Clear INTERRUPT_DISABLE bit in command register to enable interrupts
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd & !command::INTERRUPT_DISABLE,
        );

        // Enable this IRQ in the PIC
        crate::arch::x86_64::pic::enable_irq(irq);

        Ok(irq)
    }

    /// Register an IRQ handler for this PCI device (ARM/GIC version)
    ///
    /// On ARM, PCI interrupts are routed through the GIC as SPIs.
    /// The interrupt_line field from PCI config space is mapped to GIC SPI.
    #[cfg(target_arch = "aarch64")]
    pub fn register_irq_handler(
        &self,
        handler: crate::arch::aarch64::irq::IrqHandler,
        data: *mut (),
    ) -> Result<u8, &'static str> {
        let irq_line = self.header.interrupt_line;

        // Check for invalid/unassigned IRQ
        if irq_line == 0xFF {
            return Err("No valid IRQ assigned to device");
        }

        // On ARM, PCI interrupts are typically wired to GIC SPIs starting at 32
        // The exact mapping depends on the platform. For QEMU virt, PCI uses SPIs 32+
        let gic_irq = 32 + irq_line as u32;

        // Generate unique ID from device address
        let id =
            ((self.bus as usize) << 16) | ((self.device as usize) << 8) | (self.function as usize);

        // Register with the GIC IRQ subsystem
        crate::arch::aarch64::irq::register_irq_handler(gic_irq, handler, data, id)?;

        // Clear INTERRUPT_DISABLE bit in command register to enable interrupts
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd & !command::INTERRUPT_DISABLE,
        );

        // GIC distributor enables all SPIs during gic::init()

        Ok(irq_line)
    }

    /// Unregister IRQ handler for this PCI device (x86_64 version)
    ///
    /// Called during device removal (hotplug). Disables interrupts at the
    /// device level and unregisters the handler from the IRQ subsystem.
    ///
    /// # Arguments
    /// - None (uses device's IRQ and ID from PCI config)
    ///
    /// # Returns
    /// The IRQ number that was unregistered, or an error
    #[cfg(target_arch = "x86_64")]
    pub fn unregister_irq_handler(&self) -> Result<u8, &'static str> {
        let irq = self.header.interrupt_line;

        // Check for invalid/unassigned IRQ
        if irq == 0xFF || irq >= 16 {
            return Err("No valid IRQ assigned to device");
        }

        // Generate the same unique ID that was used during registration
        let id =
            ((self.bus as usize) << 16) | ((self.device as usize) << 8) | (self.function as usize);

        // Disable interrupts at device level first (set INTERRUPT_DISABLE bit)
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd | command::INTERRUPT_DISABLE,
        );

        // Unregister from the IRQ subsystem
        crate::arch::x86_64::irq::unregister_irq_handler(irq, id)?;

        Ok(irq)
    }

    /// Unregister IRQ handler for this PCI device (ARM/GIC version)
    ///
    /// On ARM, PCI interrupts are routed through the GIC as SPIs.
    #[cfg(target_arch = "aarch64")]
    pub fn unregister_irq_handler(&self) -> Result<u8, &'static str> {
        let irq_line = self.header.interrupt_line;

        // Check for invalid/unassigned IRQ
        if irq_line == 0xFF {
            return Err("No valid IRQ assigned to device");
        }

        // On ARM, PCI interrupts are typically wired to GIC SPIs starting at 32
        let gic_irq = 32 + irq_line as u32;

        // Generate the same unique ID that was used during registration
        let id =
            ((self.bus as usize) << 16) | ((self.device as usize) << 8) | (self.function as usize);

        // Disable interrupts at device level first (set INTERRUPT_DISABLE bit)
        let cmd = pci_read16(self.bus, self.device, self.function, offset::COMMAND);
        pci_write16(
            self.bus,
            self.device,
            self.function,
            offset::COMMAND,
            cmd | command::INTERRUPT_DISABLE,
        );

        // Unregister from the GIC IRQ subsystem
        crate::arch::aarch64::irq::unregister_irq_handler(gic_irq, id)?;

        Ok(irq_line)
    }

    /// Check if this is an xHCI USB controller
    pub fn is_xhci(&self) -> bool {
        self.header.class_code == class::SERIAL_BUS
            && self.header.subclass == subclass::USB
            && self.header.prog_if == prog_if::XHCI
    }

    /// Get a descriptive class name
    pub fn class_name(&self) -> &'static str {
        match (
            self.header.class_code,
            self.header.subclass,
            self.header.prog_if,
        ) {
            (0x0C, 0x03, 0x00) => "USB UHCI",
            (0x0C, 0x03, 0x10) => "USB OHCI",
            (0x0C, 0x03, 0x20) => "USB EHCI",
            (0x0C, 0x03, 0x30) => "USB xHCI",
            (0x0C, 0x03, _) => "USB Controller",
            (0x06, 0x00, _) => "Host Bridge",
            (0x06, 0x01, _) => "ISA Bridge",
            (0x06, 0x04, _) => "PCI Bridge",
            (0x06, _, _) => "Bridge",
            (0x01, _, _) => "Mass Storage",
            (0x02, _, _) => "Network",
            (0x03, _, _) => "Display",
            (0x04, _, _) => "Multimedia",
            _ => "Unknown",
        }
    }
}

/// Implement BusDevice for PciDevice to participate in bus/driver model
impl BusDevice for PciDevice {
    fn name(&self) -> &str {
        self.class_name()
    }

    fn bus_id(&self) -> String {
        use alloc::format;
        format!(
            "{:04x}:{:02x}:{:02x}.{:x}",
            0, // segment
            self.bus,
            self.device,
            self.function
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Enumerate all devices on a PCI bus
pub fn enumerate_bus() -> Vec<PciDevice> {
    let mut devices = Vec::new();

    // Scan bus 0 (we could scan more buses via PCI bridges)
    for dev in 0..32 {
        // Check function 0 first
        if let Some(pci_dev) = PciDevice::read(0, dev, 0) {
            let is_multifunction = pci_dev.header.is_multifunction();
            devices.push(pci_dev);

            // If multi-function, scan other functions
            if is_multifunction {
                for func in 1..8 {
                    if let Some(pci_dev) = PciDevice::read(0, dev, func) {
                        devices.push(pci_dev);
                    }
                }
            }
        }
    }

    devices
}

/// Find all xHCI controllers on the PCI bus
pub fn find_xhci_controllers() -> Vec<PciDevice> {
    enumerate_bus()
        .into_iter()
        .filter(|dev| dev.is_xhci())
        .collect()
}

// ============================================================================
// PCI Bus Implementation (Bus/Driver Model)
// ============================================================================

/// PCI bus implementing the Bus trait for the bus/driver model
pub struct PciBus {
    /// Discovered PCI devices
    devices: Vec<PciDevice>,
    /// Registered drivers for PCI devices
    drivers: Vec<Box<dyn BusDriver>>,
    /// Probed devices (devices that have been matched to drivers)
    probed_devices: Vec<Box<dyn Device>>,
}

impl PciBus {
    /// Create a new PCI bus (does not enumerate yet)
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            drivers: Vec::new(),
            probed_devices: Vec::new(),
        }
    }
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus for PciBus {
    fn name(&self) -> &str {
        "pci"
    }

    fn register_driver(&mut self, driver: Box<dyn BusDriver>) {
        printkln!("PCI: Registered driver '{}'", driver.name());
        self.drivers.push(driver);
    }

    fn enumerate(&mut self, ctx: &mut BusContext) {
        // Initialize PCI config access if not already done
        if !is_initialized() {
            #[cfg(target_arch = "x86_64")]
            {
                init_port_io();
                printkln!("PCI: Using port I/O config access");
            }

            #[cfg(target_arch = "aarch64")]
            {
                use crate::arch::{CurrentArch, IoremapOps};
                // ARM: Use ECAM with QEMU virt address (from DTB: reg = <0x40 0x10000000 ...>)
                // ECAM needs 1MB for bus 0 (32 devices × 8 functions × 4KB)
                let ecam_phys = 0x40_1000_0000u64; // QEMU virt high ECAM
                let ecam_size = 0x10_0000u64; // 1MB for bus 0
                let ecam_virt = CurrentArch::ioremap(ecam_phys, ecam_size)
                    .expect("PCI: Failed to ioremap ECAM region");
                unsafe {
                    init_ecam(ecam_virt);
                }
                printkln!(
                    "PCI: Using ECAM config access at phys {:#x} -> virt {:p}",
                    ecam_phys,
                    ecam_virt
                );
            }
        }

        let _ = ctx; // Suppress unused warning
        printkln!("PCI: Enumerating bus 0...");

        // Scan bus 0 for devices
        for dev in 0..32 {
            if let Some(pci_dev) = PciDevice::read(0, dev, 0) {
                let is_multifunction = pci_dev.header.is_multifunction();

                printkln!(
                    "PCI: Found {} at {}",
                    pci_dev.class_name(),
                    BusDevice::bus_id(&pci_dev)
                );
                self.devices.push(pci_dev);

                // Check other functions if multi-function device
                if is_multifunction {
                    for func in 1..8 {
                        if let Some(pci_dev) = PciDevice::read(0, dev, func) {
                            printkln!(
                                "PCI: Found {} at {}",
                                pci_dev.class_name(),
                                BusDevice::bus_id(&pci_dev)
                            );
                            self.devices.push(pci_dev);
                        }
                    }
                }
            }
        }

        printkln!("PCI: Found {} device(s)", self.devices.len());

        // Assign BAR addresses for any unassigned BARs (cross-platform)
        //
        // On x86 with BIOS: BARs are pre-assigned, this loop does nothing
        // On ARM with direct boot: BARs are 0, this allocates addresses
        //
        // Following Linux kernel pattern: pci_assign_unassigned_resources()
        for device in &mut self.devices {
            device.assign_all_bars();
            // Enable memory space access (needed for newly assigned BARs)
            device.enable_memory_space();
        }

        // Match devices to drivers and probe
        for device in &self.devices {
            for driver in &self.drivers {
                if driver.matches(device) {
                    printkln!(
                        "PCI: Driver '{}' matched device at {}",
                        driver.name(),
                        BusDevice::bus_id(device)
                    );

                    match driver.probe(device, ctx) {
                        Ok(dev_instance) => {
                            printkln!("PCI: Successfully probed '{}'", dev_instance.name());
                            self.probed_devices.push(dev_instance);
                        }
                        Err(e) => {
                            printkln!("PCI: Failed to probe: {:?}", e);
                        }
                    }

                    // Only match first driver per device
                    break;
                }
            }
        }
    }

    fn is_root(&self) -> bool {
        true // PCI is a root bus
    }

    /// Remove a device from this PCI bus (hotplug support)
    ///
    /// Following Linux kernel PCI hotplug patterns:
    /// 1. Find the device by bus_id
    /// 2. Find the driver that probed this device
    /// 3. Call driver.remove() for cleanup
    /// 4. Remove from probed_devices
    /// 5. Remove from devices list
    fn remove_device(&mut self, bus_id: &str) -> Result<(), DriverError> {
        printkln!("PCI: Removing device at {}", bus_id);

        // Find the device index
        let device_idx = self
            .devices
            .iter()
            .position(|d| BusDevice::bus_id(d) == bus_id);

        let device_idx = match device_idx {
            Some(idx) => idx,
            None => {
                printkln!("PCI: Device {} not found", bus_id);
                return Err(DriverError::MissingResource);
            }
        };

        // Get reference to device for driver matching
        let device = &self.devices[device_idx];

        // Find matching driver and call remove()
        for driver in &self.drivers {
            if driver.matches(device) {
                printkln!(
                    "PCI: Calling driver '{}' remove for {}",
                    driver.name(),
                    bus_id
                );

                // Call driver's remove callback
                if let Err(e) = driver.remove(device) {
                    printkln!("PCI: Driver remove failed: {:?}", e);
                    return Err(e);
                }

                break;
            }
        }

        // Remove from probed_devices list
        // The Device trait has bus_id() that returns Option<&str>
        self.probed_devices.retain(|dev| {
            if let Some(dev_bus_id) = dev.bus_id() {
                dev_bus_id != bus_id
            } else {
                true // Keep devices without bus_id tracking
            }
        });

        // Remove from devices list
        self.devices.remove(device_idx);

        printkln!("PCI: Device {} removed successfully", bus_id);
        Ok(())
    }
}

/// PCI Host Controller driver
pub struct PciHostDriver;

impl Driver for PciHostDriver {
    fn compatible(&self) -> &'static [&'static str] {
        &["pci-host-ecam-generic", "pci-host"]
    }

    fn probe(&self, dev: &DeviceInfo) -> Result<Box<dyn Device>, DriverError> {
        // Initialize PCI config access if not already done
        if !is_initialized() {
            #[cfg(target_arch = "x86_64")]
            {
                // x86: Use port I/O by default
                let _ = dev; // Unused on x86
                init_port_io();
                printkln!("PCI: Using port I/O config access");
            }

            #[cfg(target_arch = "aarch64")]
            {
                use crate::arch::{CurrentArch, IoremapOps};
                // ARM: Use ECAM, get base from device info or use QEMU virt default
                let ecam_phys = dev.base_addr.unwrap_or(0x40_1000_0000);
                let ecam_size = 0x10_0000u64; // 1MB for bus 0
                let ecam_virt = CurrentArch::ioremap(ecam_phys, ecam_size)
                    .expect("PCI: Failed to ioremap ECAM region");
                unsafe {
                    init_ecam(ecam_virt);
                }
                printkln!(
                    "PCI: Using ECAM config access at phys {:#x} -> virt {:p}",
                    ecam_phys,
                    ecam_virt
                );
            }
        }

        Ok(Box::new(PciHostController::new()))
    }
}

/// PCI Host Controller device instance
pub struct PciHostController {
    /// Discovered devices (cached)
    devices: Vec<PciDevice>,
}

impl PciHostController {
    /// Create a new PCI host controller and enumerate devices
    pub fn new() -> Self {
        let devices = enumerate_bus();
        Self { devices }
    }

    /// Get all discovered devices
    pub fn devices(&self) -> &[PciDevice] {
        &self.devices
    }

    /// Find a device by class/subclass/prog_if
    pub fn find_by_class(&self, class: u8, subclass: u8, prog_if: u8) -> Option<&PciDevice> {
        self.devices.iter().find(|dev| {
            dev.header.class_code == class
                && dev.header.subclass == subclass
                && dev.header.prog_if == prog_if
        })
    }
}

impl Default for PciHostController {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for PciHostController {
    fn name(&self) -> &str {
        "pci-host"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// DMA Support
// ============================================================================

impl DmaDevice for PciDevice {
    fn dma_config(&self) -> &DmaConfig {
        &self.dma_config
    }

    fn dma_config_mut(&mut self) -> &mut DmaConfig {
        &mut self.dma_config
    }
}
