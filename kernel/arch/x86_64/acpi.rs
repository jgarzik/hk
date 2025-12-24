//! ACPI table parsing for SMP initialization
//!
//! This module parses ACPI tables to find:
//! - RSDP (Root System Description Pointer)
//! - RSDT/XSDT (Root/Extended System Description Table)
//! - MADT (Multiple APIC Description Table)
//!
//! From the MADT we extract CPU and APIC information needed for SMP boot.
//!
//! NOTE: ACPI tables can be located anywhere in physical memory, including
//! above the identity-mapped region. We use ioremap to map tables before
//! accessing them.

use alloc::vec::Vec;
use super::ioremap::{ioremap, iounmap};

/// RSDP signature "RSD PTR "
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// MADT signature "APIC"
const MADT_SIGNATURE: &[u8; 4] = b"APIC";

/// FADT signature "FACP" (Fixed ACPI Description Table)
const FADT_SIGNATURE: &[u8; 4] = b"FACP";

/// MADT entry types
const MADT_ENTRY_LAPIC: u8 = 0;
const MADT_ENTRY_IOAPIC: u8 = 1;
const MADT_ENTRY_ISO: u8 = 2; // Interrupt Source Override
const MADT_ENTRY_LAPIC_NMI: u8 = 4;
const MADT_ENTRY_LAPIC_64: u8 = 5; // Local APIC Address Override

/// Information about a CPU found in MADT
#[derive(Debug, Clone, Copy)]
pub struct CpuInfo {
    /// Local APIC ID
    pub apic_id: u8,
    /// Whether this CPU is enabled
    pub enabled: bool,
    /// Whether this is the bootstrap processor
    pub is_bsp: bool,
}

/// Power management information from FADT
#[derive(Debug, Clone, Copy)]
pub struct PowerInfo {
    /// PM1a Control Block I/O port address
    pub pm1a_cnt_blk: u16,
    /// PM1b Control Block I/O port address (optional)
    pub pm1b_cnt_blk: Option<u16>,
    /// Sleep type value for S5 (soft-off) state
    pub slp_typa: u8,
}

/// ACPI information extracted from tables
#[derive(Debug)]
pub struct AcpiInfo {
    /// Local APIC base address
    pub lapic_base: u64,
    /// List of CPUs found
    pub cpus: Vec<CpuInfo>,
    /// Bootstrap processor's APIC ID
    pub bsp_apic_id: u8,
    /// Power management information (for shutdown/reboot)
    pub power_info: Option<PowerInfo>,
}

/// RSDP structure (ACPI 1.0)
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// RSDP structure (ACPI 2.0+)
#[repr(C, packed)]
struct Rsdp2 {
    // ACPI 1.0 fields
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    // ACPI 2.0+ fields
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// ACPI SDT header (common to all tables)
#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// MADT header (after SDT header)
#[repr(C, packed)]
struct MadtHeader {
    sdt: SdtHeader,
    lapic_address: u32,
    flags: u32,
    // Variable-length entries follow
}

// NOTE: The following ACPI structure definitions are kept as documentation
// but we use byte-offset access with read_unaligned instead of struct casting
// for safety with packed ACPI tables that may be at any physical address.
//
// MADT entry types and their layouts:
// - LAPIC (type 0): header (2) + processor_id (1) + apic_id (1) + flags (4)
// - LAPIC_64 (type 5): header (2) + reserved (2) + address (8)
//
// FADT layout (for power management):
// - pm1a_cnt_blk at offset 64
// - pm1b_cnt_blk at offset 68

/// Map an entire ACPI table given its physical address
/// Returns mapped pointer or error. Caller must iounmap when done.
fn map_acpi_table(phys_addr: u64) -> Result<*mut u8, &'static str> {
    unsafe {
        // First map just the header to read the length
        let header_size = core::mem::size_of::<SdtHeader>() as u64;
        let ptr = ioremap(phys_addr, header_size).map_err(|_| "Failed to ioremap SDT header")?;

        // Read length field using read_unaligned (packed struct)
        let length_ptr = (ptr as *const u8).add(4) as *const u32; // offset of length field
        let length = core::ptr::read_unaligned(length_ptr);
        iounmap(ptr, header_size);

        // Now map the full table
        ioremap(phys_addr, length as u64).map_err(|_| "Failed to ioremap ACPI table")
    }
}

/// Parse ACPI tables and extract SMP and power information
pub fn parse_acpi() -> Result<AcpiInfo, &'static str> {
    // Find RSDP (always in low memory, identity-mapped)
    let rsdp = find_rsdp()?;

    // Get RSDT or XSDT address (physical address, may be above 512MB!)
    let (sdt_phys, is_xsdt) = unsafe {
        if (*rsdp).revision >= 2 {
            let rsdp2 = rsdp as *const Rsdp2;
            if (*rsdp2).xsdt_address != 0 {
                ((*rsdp2).xsdt_address, true)
            } else {
                ((*rsdp).rsdt_address as u64, false)
            }
        } else {
            ((*rsdp).rsdt_address as u64, false)
        }
    };

    // Map and find MADT in RSDT/XSDT
    let madt_phys = find_madt_phys(sdt_phys, is_xsdt)?;

    // Map and parse MADT
    let mut info = parse_madt_mapped(madt_phys)?;

    // Find and parse FADT for power management info
    if let Ok(fadt_phys) = find_fadt_phys(sdt_phys, is_xsdt)
        && let Ok(power_info) = parse_fadt_mapped(fadt_phys)
    {
        info.power_info = Some(power_info);
    }

    Ok(info)
}

/// Find the RSDP by searching known memory locations
fn find_rsdp() -> Result<*const Rsdp, &'static str> {
    // Search EBDA (Extended BIOS Data Area)
    // The EBDA segment is stored at physical address 0x40E
    let ebda_segment = unsafe { core::ptr::read_volatile(0x40E as *const u16) };
    let ebda_addr = (ebda_segment as usize) << 4;

    if ebda_addr != 0
        && ebda_addr < 0xA0000
        && let Some(rsdp) = search_rsdp(ebda_addr, 1024)
    {
        return Ok(rsdp);
    }

    // Search BIOS ROM area: 0xE0000 - 0xFFFFF
    if let Some(rsdp) = search_rsdp(0xE0000, 0x20000) {
        return Ok(rsdp);
    }

    Err("RSDP not found")
}

/// Search for RSDP signature in a memory region
fn search_rsdp(start: usize, length: usize) -> Option<*const Rsdp> {
    // RSDP is always aligned to 16 bytes
    let start_aligned = start & !0xF;
    let end = start + length;

    let mut addr = start_aligned;
    while addr < end {
        // Read signature bytes using volatile reads
        let sig_ptr = addr as *const [u8; 8];
        let signature = unsafe { core::ptr::read_volatile(sig_ptr) };

        if signature == *RSDP_SIGNATURE {
            let ptr = addr as *const Rsdp;
            // Verify checksum
            if checksum_valid(ptr as *const u8, core::mem::size_of::<Rsdp>()) {
                return Some(ptr);
            }
        }
        addr += 16;
    }
    None
}

/// Verify checksum of ACPI structure
fn checksum_valid(ptr: *const u8, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { core::ptr::read_volatile(ptr.add(i)) });
    }
    sum == 0
}

/// Find MADT physical address in RSDT or XSDT (uses ioremap)
fn find_madt_phys(sdt_phys: u64, is_xsdt: bool) -> Result<u64, &'static str> {
    find_table_phys(sdt_phys, is_xsdt, MADT_SIGNATURE)
}

/// Find FADT physical address in RSDT or XSDT (uses ioremap)
fn find_fadt_phys(sdt_phys: u64, is_xsdt: bool) -> Result<u64, &'static str> {
    find_table_phys(sdt_phys, is_xsdt, FADT_SIGNATURE)
}

/// Find a table's physical address in RSDT or XSDT by signature (uses ioremap)
fn find_table_phys(sdt_phys: u64, is_xsdt: bool, signature: &[u8; 4]) -> Result<u64, &'static str> {
    unsafe {
        // Map the RSDT/XSDT
        let sdt_ptr = map_acpi_table(sdt_phys)?;

        // Read length using offset (packed struct)
        let length_ptr = (sdt_ptr as *const u8).add(4) as *const u32;
        let total_length = core::ptr::read_unaligned(length_ptr) as usize;
        let header_size = core::mem::size_of::<SdtHeader>();
        let entry_size = if is_xsdt { 8 } else { 4 };
        let num_entries = (total_length - header_size) / entry_size;

        let entries_start = sdt_ptr.add(header_size);

        let mut result: Option<u64> = None;

        for i in 0..num_entries {
            let entry_ptr = entries_start.add(i * entry_size);
            let entry_phys = if is_xsdt {
                core::ptr::read_unaligned(entry_ptr as *const u64)
            } else {
                core::ptr::read_unaligned(entry_ptr as *const u32) as u64
            };

            // Map just the header of this table to check signature
            let header_size_u64 = core::mem::size_of::<SdtHeader>() as u64;
            if let Ok(entry_header_ptr) = ioremap(entry_phys, header_size_u64) {
                // Read signature (first 4 bytes, no alignment issue)
                let entry_sig_ptr = entry_header_ptr as *const [u8; 4];
                let entry_sig = core::ptr::read_unaligned(entry_sig_ptr);
                iounmap(entry_header_ptr, header_size_u64);

                if &entry_sig == signature {
                    result = Some(entry_phys);
                    break;
                }
            }
        }

        // Unmap the RSDT/XSDT
        iounmap(sdt_ptr, total_length as u64);

        result.ok_or("Table not found in RSDT/XSDT")
    }
}

/// Parse MADT and extract CPU/APIC information (uses ioremap)
fn parse_madt_mapped(madt_phys: u64) -> Result<AcpiInfo, &'static str> {
    unsafe {
        // Map the MADT
        let madt_ptr = map_acpi_table(madt_phys)?;

        // Read fields using offsets (packed struct)
        // MadtHeader layout: SdtHeader (36 bytes) + lapic_address (4) + flags (4)
        let lapic_addr_ptr = madt_ptr.add(36) as *const u32;
        let lapic_base = core::ptr::read_unaligned(lapic_addr_ptr) as u64;

        let mut info = AcpiInfo {
            lapic_base,
            cpus: Vec::new(),
            bsp_apic_id: 0,   // Will be set after LAPIC is mapped
            power_info: None, // Will be set after FADT parsing
        };

        // Read length from SDT header (offset 4)
        let length_ptr = madt_ptr.add(4) as *const u32;
        let madt_length = core::ptr::read_unaligned(length_ptr) as usize;
        let entries_start = madt_ptr.add(core::mem::size_of::<MadtHeader>());
        let entries_end = madt_ptr.add(madt_length);

        let mut ptr = entries_start;
        while ptr < entries_end {
            // MadtEntryHeader: entry_type (1 byte) + length (1 byte)
            let entry_type = core::ptr::read_unaligned(ptr);
            let entry_len = core::ptr::read_unaligned(ptr.add(1)) as usize;

            if entry_len == 0 {
                break; // Prevent infinite loop on malformed tables
            }

            match entry_type {
                MADT_ENTRY_LAPIC => {
                    // MadtLapic: header (2) + processor_id (1) + apic_id (1) + flags (4)
                    let flags = core::ptr::read_unaligned(ptr.add(4) as *const u32);
                    // Bit 0: Processor Enabled
                    // Bit 1: Online Capable (ACPI 6.3+)
                    let enabled = (flags & 0x1) != 0 || (flags & 0x2) != 0;

                    if enabled {
                        let apic_id = core::ptr::read_unaligned(ptr.add(3));
                        info.cpus.push(CpuInfo {
                            apic_id,
                            enabled,
                            is_bsp: false, // Will be set after LAPIC is mapped
                        });
                    }
                }

                MADT_ENTRY_LAPIC_64 => {
                    // MadtLapicAddrOverride: header (2) + reserved (2) + address (8)
                    let addr_ptr = ptr.add(4) as *const u64;
                    info.lapic_base = core::ptr::read_unaligned(addr_ptr);
                }

                MADT_ENTRY_IOAPIC | MADT_ENTRY_ISO | MADT_ENTRY_LAPIC_NMI => {
                    // I/O APIC, Interrupt source override and LAPIC NMI entries
                    // Not needed for basic SMP boot
                }

                _ => {
                    // Unknown entry type, skip
                }
            }

            ptr = ptr.add(entry_len);
        }

        // Unmap the MADT
        iounmap(madt_ptr, madt_length as u64);

        if info.cpus.is_empty() {
            return Err("No CPUs found in MADT");
        }

        Ok(info)
    }
}

/// Parse FADT and extract power management information (uses ioremap)
fn parse_fadt_mapped(fadt_phys: u64) -> Result<PowerInfo, &'static str> {
    unsafe {
        // Map the FADT
        let fadt_ptr = map_acpi_table(fadt_phys)?;

        // Read length from SDT header (offset 4)
        let length_ptr = fadt_ptr.add(4) as *const u32;
        let fadt_length = core::ptr::read_unaligned(length_ptr) as u64;

        // FADT layout: SdtHeader (36) + various fields
        // pm1a_cnt_blk is at offset 64, pm1b_cnt_blk at offset 68
        let pm1a = core::ptr::read_unaligned(fadt_ptr.add(64) as *const u32) as u16;
        let pm1b = core::ptr::read_unaligned(fadt_ptr.add(68) as *const u32);

        let info = PowerInfo {
            pm1a_cnt_blk: pm1a,
            pm1b_cnt_blk: if pm1b != 0 { Some(pm1b as u16) } else { None },
            // Default SLP_TYPa for S5 state
            // QEMU uses 0 for S5; real hardware varies (usually 5 or 7)
            // A full implementation would parse DSDT/SSDT AML _S5 object
            slp_typa: 0,
        };

        // Unmap the FADT
        iounmap(fadt_ptr, fadt_length);

        Ok(info)
    }
}
