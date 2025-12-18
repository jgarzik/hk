//! ACPI table parsing for SMP initialization
//!
//! This module parses ACPI tables to find:
//! - RSDP (Root System Description Pointer)
//! - RSDT/XSDT (Root/Extended System Description Table)
//! - MADT (Multiple APIC Description Table)
//!
//! From the MADT we extract CPU and APIC information needed for SMP boot.

use alloc::vec::Vec;

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

/// MADT entry header
#[repr(C, packed)]
struct MadtEntryHeader {
    entry_type: u8,
    length: u8,
}

/// MADT Local APIC entry
#[repr(C, packed)]
struct MadtLapic {
    header: MadtEntryHeader,
    processor_id: u8,
    apic_id: u8,
    flags: u32,
}

/// MADT Local APIC Address Override entry
#[repr(C, packed)]
struct MadtLapicAddrOverride {
    header: MadtEntryHeader,
    reserved: u16,
    address: u64,
}

/// FADT (Fixed ACPI Description Table) - partial structure
/// We only need the power management register addresses
#[repr(C, packed)]
struct Fadt {
    header: SdtHeader,
    facs_addr: u32,
    dsdt_addr: u32,
    _reserved1: u8,
    preferred_pm_profile: u8,
    sci_interrupt: u16,
    smi_command_port: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_control: u8,
    pm1a_evt_blk: u32,
    pm1b_evt_blk: u32,
    pm1a_cnt_blk: u32, // Power control port A
    pm1b_cnt_blk: u32, // Power control port B (optional)
    pm2_cnt_blk: u32,
    pm_tmr_blk: u32,
    gpe0_blk: u32,
    gpe1_blk: u32,
    pm1_evt_len: u8,
    pm1_cnt_len: u8,
    pm2_cnt_len: u8,
    pm_tmr_len: u8,
    // More fields follow but we don't need them
}

/// Parse ACPI tables and extract SMP and power information
pub fn parse_acpi() -> Result<AcpiInfo, &'static str> {
    // Find RSDP
    let rsdp = find_rsdp()?;

    // Get RSDT or XSDT address
    let (sdt_addr, is_xsdt) = unsafe {
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

    // Find MADT in RSDT/XSDT
    let madt = find_madt(sdt_addr, is_xsdt)?;

    // Parse MADT
    let mut info = parse_madt(madt)?;

    // Find and parse FADT for power management info
    if let Ok(fadt) = find_fadt(sdt_addr, is_xsdt) {
        info.power_info = Some(parse_fadt(fadt));
    }

    Ok(info)
}

/// Find the RSDP by searching known memory locations
fn find_rsdp() -> Result<*const Rsdp, &'static str> {
    // Search EBDA (Extended BIOS Data Area)
    // The EBDA segment is stored at physical address 0x40E
    let ebda_segment = unsafe { *(0x40E as *const u16) };
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

    for addr in (start_aligned..start + length).step_by(16) {
        let ptr = addr as *const Rsdp;
        unsafe {
            if (*ptr).signature == *RSDP_SIGNATURE {
                // Verify checksum
                if checksum_valid(ptr as *const u8, core::mem::size_of::<Rsdp>()) {
                    return Some(ptr);
                }
            }
        }
    }
    None
}

/// Verify checksum of ACPI structure
fn checksum_valid(ptr: *const u8, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum == 0
}

/// Find MADT in RSDT or XSDT
fn find_madt(sdt_addr: u64, is_xsdt: bool) -> Result<*const MadtHeader, &'static str> {
    let header = sdt_addr as *const SdtHeader;

    unsafe {
        let total_length = (*header).length as usize;
        let header_size = core::mem::size_of::<SdtHeader>();
        let entry_size = if is_xsdt { 8 } else { 4 };
        let num_entries = (total_length - header_size) / entry_size;

        let entries_start = (sdt_addr as usize + header_size) as *const u8;

        for i in 0..num_entries {
            let entry_ptr = entries_start.add(i * entry_size);
            let entry_addr = if is_xsdt {
                *(entry_ptr as *const u64)
            } else {
                *(entry_ptr as *const u32) as u64
            };

            let entry_header = entry_addr as *const SdtHeader;
            if (*entry_header).signature == *MADT_SIGNATURE {
                return Ok(entry_addr as *const MadtHeader);
            }
        }
    }

    Err("MADT not found in RSDT/XSDT")
}

/// Parse MADT and extract CPU/APIC information
fn parse_madt(madt: *const MadtHeader) -> Result<AcpiInfo, &'static str> {
    let mut info = AcpiInfo {
        lapic_base: unsafe { (*madt).lapic_address as u64 },
        cpus: Vec::new(),
        bsp_apic_id: 0,   // Will be set after LAPIC is mapped
        power_info: None, // Will be set after FADT parsing
    };

    unsafe {
        let madt_length = (*madt).sdt.length as usize;
        let entries_start = (madt as usize + core::mem::size_of::<MadtHeader>()) as *const u8;
        let entries_end = (madt as usize + madt_length) as *const u8;

        let mut ptr = entries_start;
        while ptr < entries_end {
            let entry = ptr as *const MadtEntryHeader;
            let entry_type = (*entry).entry_type;
            let entry_len = (*entry).length as usize;

            if entry_len == 0 {
                break; // Prevent infinite loop on malformed tables
            }

            match entry_type {
                MADT_ENTRY_LAPIC => {
                    let lapic = ptr as *const MadtLapic;
                    let flags = (*lapic).flags;
                    // Bit 0: Processor Enabled
                    // Bit 1: Online Capable (ACPI 6.3+)
                    let enabled = (flags & 0x1) != 0 || (flags & 0x2) != 0;

                    if enabled {
                        let apic_id = (*lapic).apic_id;
                        info.cpus.push(CpuInfo {
                            apic_id,
                            enabled,
                            is_bsp: false, // Will be set after LAPIC is mapped
                        });
                    }
                }

                MADT_ENTRY_LAPIC_64 => {
                    // Override the 32-bit LAPIC address with 64-bit one
                    let override_entry = ptr as *const MadtLapicAddrOverride;
                    info.lapic_base = (*override_entry).address;
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
    }

    if info.cpus.is_empty() {
        return Err("No CPUs found in MADT");
    }

    Ok(info)
}

/// Find FADT in RSDT or XSDT
fn find_fadt(sdt_addr: u64, is_xsdt: bool) -> Result<*const Fadt, &'static str> {
    let header = sdt_addr as *const SdtHeader;

    unsafe {
        let total_length = (*header).length as usize;
        let header_size = core::mem::size_of::<SdtHeader>();
        let entry_size = if is_xsdt { 8 } else { 4 };
        let num_entries = (total_length - header_size) / entry_size;

        let entries_start = (sdt_addr as usize + header_size) as *const u8;

        for i in 0..num_entries {
            let entry_addr = if is_xsdt {
                *(entries_start.add(i * 8) as *const u64)
            } else {
                *(entries_start.add(i * 4) as *const u32) as u64
            };

            let entry_header = entry_addr as *const SdtHeader;
            if (*entry_header).signature == *FADT_SIGNATURE {
                return Ok(entry_addr as *const Fadt);
            }
        }
    }

    Err("FADT not found in RSDT/XSDT")
}

/// Parse FADT and extract power management information
fn parse_fadt(fadt: *const Fadt) -> PowerInfo {
    unsafe {
        let pm1a = (*fadt).pm1a_cnt_blk as u16;
        let pm1b = (*fadt).pm1b_cnt_blk;

        PowerInfo {
            pm1a_cnt_blk: pm1a,
            pm1b_cnt_blk: if pm1b != 0 { Some(pm1b as u16) } else { None },
            // Default SLP_TYPa for S5 state
            // QEMU uses 0 for S5; real hardware varies (usually 5 or 7)
            // A full implementation would parse DSDT/SSDT AML _S5 object
            slp_typa: 0,
        }
    }
}
