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

use super::ioremap::{ioremap, iounmap};
use crate::acpi::aml::{self, SleepType};
use crate::acpi::hw::PmRegs;
use crate::arch::PowerInfo;
use alloc::vec::Vec;

/// RSDP signature "RSD PTR "
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// MADT signature "APIC"
const MADT_SIGNATURE: &[u8; 4] = b"APIC";

/// FADT signature "FACP" (Fixed ACPI Description Table)
const FADT_SIGNATURE: &[u8; 4] = b"FACP";

/// DSDT signature "DSDT" (Differentiated System Description Table)
const DSDT_SIGNATURE: &[u8; 4] = b"DSDT";

/// SSDT signature "SSDT" (Secondary System Description Table)
const SSDT_SIGNATURE: &[u8; 4] = b"SSDT";

/// SRAT signature "SRAT" (System Resource Affinity Table)
const SRAT_SIGNATURE: &[u8; 4] = b"SRAT";

/// SLIT signature "SLIT" (System Locality Information Table)
const SLIT_SIGNATURE: &[u8; 4] = b"SLIT";

/// MADT entry types
const MADT_ENTRY_LAPIC: u8 = 0;
const MADT_ENTRY_IOAPIC: u8 = 1;
const MADT_ENTRY_ISO: u8 = 2; // Interrupt Source Override
const MADT_ENTRY_LAPIC_NMI: u8 = 4;
const MADT_ENTRY_LAPIC_64: u8 = 5; // Local APIC Address Override
const MADT_ENTRY_X2APIC: u8 = 9; // Processor Local x2APIC

/// SRAT entry types
const SRAT_ENTRY_LAPIC_AFFINITY: u8 = 0; // Processor Local APIC/SAPIC Affinity
const SRAT_ENTRY_MEMORY_AFFINITY: u8 = 1; // Memory Affinity
const SRAT_ENTRY_X2APIC_AFFINITY: u8 = 2; // Processor Local x2APIC Affinity

/// Information about a CPU found in MADT
#[derive(Debug, Clone, Copy)]
pub struct CpuInfo {
    /// Local APIC ID (32-bit for X2APIC support)
    pub apic_id: u32,
    /// Whether this CPU is enabled
    pub enabled: bool,
    /// Whether this is the bootstrap processor
    pub is_bsp: bool,
}

/// Information about an I/O APIC found in MADT
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Fields used for future I/O APIC configuration
pub struct IoApicInfo {
    /// I/O APIC ID
    pub id: u8,
    /// Physical base address
    pub address: u32,
    /// Global System Interrupt base
    pub gsi_base: u32,
}

/// ACPI information extracted from tables
#[derive(Debug)]
pub struct AcpiInfo {
    /// Local APIC base address
    pub lapic_base: u64,
    /// List of CPUs found
    pub cpus: Vec<CpuInfo>,
    /// List of I/O APICs found
    pub ioapics: Vec<IoApicInfo>,
    /// Bootstrap processor's APIC ID (32-bit for X2APIC support)
    pub bsp_apic_id: u32,
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
    // Find RSDP (in low memory, read through the direct map)
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
        && let Ok((pm, dsdt_phys)) = parse_fadt_mapped(fadt_phys)
    {
        let s5 = find_s5(dsdt_phys, sdt_phys, is_xsdt);
        info.power_info = Some(PowerInfo { pm, s5 });
    }

    Ok(info)
}

/// Find the RSDP by searching known memory locations
fn find_rsdp() -> Result<*const Rsdp, &'static str> {
    // Search EBDA (Extended BIOS Data Area)
    // The EBDA segment is stored at physical address 0x40E
    let ebda_segment =
        unsafe { core::ptr::read_volatile(super::paging::phys_to_virt(0x40E) as *const u16) };
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

    // Low memory is read through the direct map
    let virt = |phys: usize| super::paging::phys_to_virt(phys as u64) as usize;
    let mut addr = start_aligned;
    while addr < end {
        // Read signature bytes using volatile reads
        let sig_ptr = virt(addr) as *const [u8; 8];
        let signature = unsafe { core::ptr::read_volatile(sig_ptr) };

        if signature == *RSDP_SIGNATURE {
            let ptr = virt(addr) as *const Rsdp;
            // Verify basic checksum (first 20 bytes)
            if checksum_valid(ptr as *const u8, core::mem::size_of::<Rsdp>()) {
                // For ACPI 2.0+, also verify extended checksum (full 36 bytes)
                let revision = unsafe { core::ptr::read_volatile(virt(addr + 15) as *const u8) };
                if revision >= 2 && !checksum_valid(ptr as *const u8, core::mem::size_of::<Rsdp2>())
                {
                    // Extended checksum failed, keep searching
                    addr += 16;
                    continue;
                }
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

/// Validate checksum of ACPI table, logging warning if invalid (Linux behavior)
///
/// Linux logs a warning but continues processing tables with bad checksums,
/// as many real-world BIOS implementations have buggy ACPI tables.
/// Returns true if checksum is valid, false if invalid (but processing should continue).
fn validate_table_checksum(ptr: *const u8, len: usize, table_name: &str) -> bool {
    if checksum_valid(ptr, len) {
        true
    } else {
        crate::printkln!(
            "ACPI Warning: Incorrect checksum in table [{}] - continuing anyway",
            table_name
        );
        false
    }
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
    let mut found = None;
    for_each_table(sdt_phys, is_xsdt, signature, |phys| {
        found = Some(phys);
        false
    })?;
    found.ok_or("Table not found in RSDT/XSDT")
}

/// Call `f` with the physical address of each RSDT/XSDT table whose
/// signature is `signature`, until it returns false (uses ioremap)
fn for_each_table(
    sdt_phys: u64,
    is_xsdt: bool,
    signature: &[u8; 4],
    mut f: impl FnMut(u64) -> bool,
) -> Result<(), &'static str> {
    unsafe {
        // Map the RSDT/XSDT
        let sdt_ptr = map_acpi_table(sdt_phys)?;

        // Read length using offset (packed struct)
        let length_ptr = (sdt_ptr as *const u8).add(4) as *const u32;
        let total_length = core::ptr::read_unaligned(length_ptr) as usize;

        // Validate RSDT/XSDT checksum (warn but continue per Linux behavior)
        let table_name = if is_xsdt { "XSDT" } else { "RSDT" };
        validate_table_checksum(sdt_ptr as *const u8, total_length, table_name);

        let header_size = core::mem::size_of::<SdtHeader>();
        let entry_size = if is_xsdt { 8 } else { 4 };
        let num_entries = total_length.saturating_sub(header_size) / entry_size;

        let entries_start = sdt_ptr.add(header_size);

        for i in 0..num_entries {
            let entry_ptr = entries_start.add(i * entry_size);
            let entry_phys = if is_xsdt {
                core::ptr::read_unaligned(entry_ptr as *const u64)
            } else {
                core::ptr::read_unaligned(entry_ptr as *const u32) as u64
            };

            if table_signature(entry_phys).as_ref() == Some(signature) && !f(entry_phys) {
                break;
            }
        }

        // Unmap the RSDT/XSDT
        iounmap(sdt_ptr, total_length as u64);
        Ok(())
    }
}

/// The signature of the table at `phys` (maps just its header)
fn table_signature(phys: u64) -> Option<[u8; 4]> {
    let size = core::mem::size_of::<SdtHeader>() as u64;
    let ptr = ioremap(phys, size).ok()?;
    // SAFETY: the header is mapped; the signature is its first 4 bytes
    let sig = unsafe { core::ptr::read_unaligned(ptr as *const [u8; 4]) };
    iounmap(ptr, size);
    Some(sig)
}

/// Parse MADT and extract CPU/APIC information (uses ioremap)
fn parse_madt_mapped(madt_phys: u64) -> Result<AcpiInfo, &'static str> {
    unsafe {
        // Map the MADT
        let madt_ptr = map_acpi_table(madt_phys)?;

        // Read length from SDT header (offset 4) first for checksum validation
        let length_ptr = madt_ptr.add(4) as *const u32;
        let madt_length = core::ptr::read_unaligned(length_ptr) as usize;

        // Validate MADT checksum (warn but continue per Linux behavior)
        validate_table_checksum(madt_ptr as *const u8, madt_length, "MADT");

        // Read fields using offsets (packed struct)
        // MadtHeader layout: SdtHeader (36 bytes) + lapic_address (4) + flags (4)
        let lapic_addr_ptr = madt_ptr.add(36) as *const u32;
        let lapic_base = core::ptr::read_unaligned(lapic_addr_ptr) as u64;

        let mut info = AcpiInfo {
            lapic_base,
            cpus: Vec::new(),
            ioapics: Vec::new(),
            bsp_apic_id: 0,   // Will be set after LAPIC is mapped
            power_info: None, // Will be set after FADT parsing
        };

        let entries_start = madt_ptr.add(core::mem::size_of::<MadtHeader>());
        let entries_end = madt_ptr.add(madt_length);

        // Track if we found LAPIC entries (for X2APIC duplicate filtering)
        let mut has_lapic_cpus = false;

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
                        has_lapic_cpus = true;
                        let apic_id = core::ptr::read_unaligned(ptr.add(3)) as u32;
                        info.cpus.push(CpuInfo {
                            apic_id,
                            enabled,
                            is_bsp: false, // Will be set after LAPIC is mapped
                        });
                    }
                }

                MADT_ENTRY_X2APIC => {
                    // X2APIC: header (2) + reserved (2) + x2apic_id (4) + flags (4) + uid (4)
                    let x2apic_id = core::ptr::read_unaligned(ptr.add(4) as *const u32);
                    let flags = core::ptr::read_unaligned(ptr.add(8) as *const u32);
                    let enabled = (flags & 0x1) != 0 || (flags & 0x2) != 0;

                    // Ignore invalid ID (0xffffffff)
                    if x2apic_id == 0xffffffff {
                        // skip
                    }
                    // Per ACPI spec: if LAPIC entries exist, X2APIC entries with ID < 0xff
                    // are duplicates and should be ignored
                    else if has_lapic_cpus && x2apic_id < 0xff {
                        // skip duplicate
                    } else if enabled {
                        info.cpus.push(CpuInfo {
                            apic_id: x2apic_id,
                            enabled,
                            is_bsp: false,
                        });
                    }
                }

                MADT_ENTRY_IOAPIC => {
                    // IOAPIC: header (2) + id (1) + reserved (1) + address (4) + gsi_base (4)
                    let id = core::ptr::read_unaligned(ptr.add(2));
                    let address = core::ptr::read_unaligned(ptr.add(4) as *const u32);
                    let gsi_base = core::ptr::read_unaligned(ptr.add(8) as *const u32);

                    info.ioapics.push(IoApicInfo {
                        id,
                        address,
                        gsi_base,
                    });
                }

                MADT_ENTRY_LAPIC_64 => {
                    // MadtLapicAddrOverride: header (2) + reserved (2) + address (8)
                    let addr_ptr = ptr.add(4) as *const u64;
                    info.lapic_base = core::ptr::read_unaligned(addr_ptr);
                }

                MADT_ENTRY_ISO | MADT_ENTRY_LAPIC_NMI => {
                    // Interrupt source override and LAPIC NMI entries
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

/// FADT field offsets (ACPI 6.5 table 5.9)
mod fadt {
    pub const DSDT: usize = 40;
    pub const SMI_CMD: usize = 48;
    pub const ACPI_ENABLE: usize = 52;
    pub const PM1A_EVT_BLK: usize = 56;
    pub const PM1B_EVT_BLK: usize = 60;
    pub const PM1A_CNT_BLK: usize = 64;
    pub const PM1B_CNT_BLK: usize = 68;
    pub const GPE0_BLK: usize = 80;
    pub const GPE1_BLK: usize = 84;
    pub const PM1_EVT_LEN: usize = 88;
    pub const GPE0_BLK_LEN: usize = 92;
    pub const GPE1_BLK_LEN: usize = 93;
    pub const X_DSDT: usize = 140;
}

/// A mapped ACPI table, read by offset with bounds checks (fields past
/// its length read as zero, as Linux treats a short FADT)
struct Table {
    ptr: *const u8,
    len: usize,
}

impl Table {
    fn bytes<const N: usize>(&self, off: usize) -> [u8; N] {
        let mut b = [0; N];
        if off + N <= self.len {
            // SAFETY: in bounds of the mapped table
            b = unsafe { core::ptr::read_unaligned(self.ptr.add(off) as *const [u8; N]) };
        }
        b
    }
    fn u8(&self, off: usize) -> u8 {
        self.bytes::<1>(off)[0]
    }
    fn u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.bytes(off))
    }
    fn u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.bytes(off))
    }
    /// A port number from a 32-bit block address field
    fn port(&self, off: usize) -> u16 {
        self.u32(off) as u16
    }
}

/// Parse FADT: power management registers and the DSDT's physical
/// address (X_DSDT if set, as Linux prefers it) (uses ioremap)
fn parse_fadt_mapped(fadt_phys: u64) -> Result<(PmRegs, u64), &'static str> {
    let ptr = map_acpi_table(fadt_phys)?;
    // SAFETY: the header is mapped
    let len = unsafe { core::ptr::read_unaligned(ptr.add(4) as *const u32) } as usize;

    // Validate FADT checksum (warn but continue per Linux behavior)
    validate_table_checksum(ptr, len, "FADT");

    let t = Table { ptr, len };
    let pm = PmRegs {
        pm1a_evt: t.port(fadt::PM1A_EVT_BLK),
        pm1b_evt: t.port(fadt::PM1B_EVT_BLK),
        pm1_evt_len: t.u8(fadt::PM1_EVT_LEN),
        pm1a_cnt: t.port(fadt::PM1A_CNT_BLK),
        pm1b_cnt: t.port(fadt::PM1B_CNT_BLK),
        gpe0: t.port(fadt::GPE0_BLK),
        gpe0_len: t.u8(fadt::GPE0_BLK_LEN),
        gpe1: t.port(fadt::GPE1_BLK),
        gpe1_len: t.u8(fadt::GPE1_BLK_LEN),
        smi_cmd: t.port(fadt::SMI_CMD),
        acpi_enable: t.u8(fadt::ACPI_ENABLE),
    };
    let dsdt = match t.u64(fadt::X_DSDT) {
        0 => t.u32(fadt::DSDT) as u64,
        x => x,
    };

    iounmap(ptr, len as u64);
    Ok((pm, dsdt))
}

/// SLP_TYP for S5: \_S5 in the DSDT, else in an SSDT; 0 (QEMU's value)
/// with a warning if neither has it
fn find_s5(dsdt_phys: u64, sdt_phys: u64, is_xsdt: bool) -> SleepType {
    let mut s5 = table_s5(dsdt_phys, DSDT_SIGNATURE);
    if s5.is_none() {
        let _ = for_each_table(sdt_phys, is_xsdt, SSDT_SIGNATURE, |phys| {
            s5 = table_s5(phys, SSDT_SIGNATURE);
            s5.is_none()
        });
    }
    match s5 {
        Some(t) => {
            crate::printkln!("ACPI: S5 SLP_TYP a={} b={}", t.a, t.b);
            t
        }
        None => {
            crate::printkln!("ACPI Warning: no \\_S5 package found, using SLP_TYP 0");
            SleepType::default()
        }
    }
}

/// The \_S5 package in the AML table at `phys`, if it has signature
/// `sig` (uses ioremap)
fn table_s5(phys: u64, sig: &[u8; 4]) -> Option<SleepType> {
    if phys == 0 || table_signature(phys).as_ref() != Some(sig) {
        return None;
    }
    let ptr = map_acpi_table(phys).ok()?;
    // SAFETY: the header is mapped
    let len = unsafe { core::ptr::read_unaligned(ptr.add(4) as *const u32) } as usize;
    let hdr = core::mem::size_of::<SdtHeader>();
    let s5 = if len > hdr {
        // SAFETY: the whole table is mapped (map_acpi_table maps `len`)
        let body = unsafe { core::slice::from_raw_parts(ptr.add(hdr), len - hdr) };
        aml::find_s5(body)
    } else {
        None
    };
    iounmap(ptr, len as u64);
    s5
}

/// Initialize NUMA topology from ACPI SRAT/SLIT tables
///
/// Called early in boot to discover NUMA topology. If SRAT is not found,
/// returns Ok(false) and caller should use single-node fallback.
pub fn init_numa_topology() -> Result<bool, &'static str> {
    use crate::numa::{LOCAL_DISTANCE, MAX_NUMA_NODES, NUMA_TOPOLOGY, REMOTE_DISTANCE};

    // Find RSDP
    let rsdp = find_rsdp()?;

    // Get RSDT or XSDT address
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

    // Try to find SRAT table
    let srat_phys = match find_table_phys(sdt_phys, is_xsdt, SRAT_SIGNATURE) {
        Ok(addr) => addr,
        Err(_) => {
            // No SRAT table - not an error, just use single-node fallback
            return Ok(false);
        }
    };

    // Parse SRAT to extract NUMA topology
    parse_srat_mapped(srat_phys)?;

    // Optionally parse SLIT for distance matrix
    if let Ok(slit_phys) = find_table_phys(sdt_phys, is_xsdt, SLIT_SIGNATURE) {
        if let Err(e) = parse_slit_mapped(slit_phys) {
            crate::printkln!("NUMA: SLIT parse error (using default distances): {}", e);
        }
    } else {
        // No SLIT, initialize default distances
        let mut topology = NUMA_TOPOLOGY.lock();
        for from in 0..MAX_NUMA_NODES {
            for to in 0..MAX_NUMA_NODES {
                if from == to {
                    topology.set_distance(from, to, LOCAL_DISTANCE);
                } else {
                    topology.set_distance(from, to, REMOTE_DISTANCE);
                }
            }
        }
    }

    // Mark topology as initialized
    {
        let mut topology = NUMA_TOPOLOGY.lock();
        topology.set_initialized();
    }

    Ok(true)
}

/// Parse SRAT table and populate NUMA topology
fn parse_srat_mapped(srat_phys: u64) -> Result<(), &'static str> {
    use crate::cpumask::NR_CPUS as MAX_CPUS;
    use crate::numa::{MAX_NUMA_NODES, NUMA_TOPOLOGY, NumaNode};

    unsafe {
        // Map the SRAT
        let srat_ptr = map_acpi_table(srat_phys)?;

        // Read length from SDT header (offset 4)
        let length_ptr = srat_ptr.add(4) as *const u32;
        let srat_length = core::ptr::read_unaligned(length_ptr) as usize;

        // Validate SRAT checksum
        validate_table_checksum(srat_ptr as *const u8, srat_length, "SRAT");

        // SRAT header: SdtHeader (36) + Reserved (4) + Reserved (8) = 48 bytes
        let entries_start = srat_ptr.add(48);
        let entries_end = srat_ptr.add(srat_length);

        let mut topology = NUMA_TOPOLOGY.lock();

        // First pass: collect memory affinity entries to build nodes
        let mut ptr = entries_start;
        while ptr < entries_end {
            let entry_type = core::ptr::read_unaligned(ptr);
            let entry_len = core::ptr::read_unaligned(ptr.add(1)) as usize;

            if entry_len == 0 {
                break;
            }

            if entry_type == SRAT_ENTRY_MEMORY_AFFINITY {
                // Memory Affinity Structure (length 40):
                // 0: type (1), 1: length (1), 2: proximity_domain_lo (4)
                // 6: reserved (2), 8: base_addr_lo (4), 12: base_addr_hi (4)
                // 16: length_lo (4), 20: length_hi (4), 24: reserved (4)
                // 28: flags (4), 32: reserved (8)
                let prox_domain_lo = core::ptr::read_unaligned(ptr.add(2) as *const u32);
                let base_lo = core::ptr::read_unaligned(ptr.add(8) as *const u32) as u64;
                let base_hi = core::ptr::read_unaligned(ptr.add(12) as *const u32) as u64;
                let len_lo = core::ptr::read_unaligned(ptr.add(16) as *const u32) as u64;
                let len_hi = core::ptr::read_unaligned(ptr.add(20) as *const u32) as u64;
                let flags = core::ptr::read_unaligned(ptr.add(28) as *const u32);

                // Bit 0: Enabled
                let enabled = (flags & 0x1) != 0;

                if enabled {
                    let base_addr = base_lo | (base_hi << 32);
                    let length = len_lo | (len_hi << 32);
                    let node_id = prox_domain_lo as usize;

                    if node_id < MAX_NUMA_NODES && length > 0 {
                        let start_pfn = base_addr / 4096;
                        let end_pfn = (base_addr + length) / 4096;
                        let pages = length / 4096;

                        // Get or create node
                        if topology.nodes[node_id].is_none() {
                            topology.nodes[node_id] = Some(NumaNode::new(node_id as u32));
                            topology.node_online_mask |= 1u64 << node_id;
                        }

                        if let Some(ref mut node) = topology.nodes[node_id] {
                            // Extend node's memory range (SRAT can have multiple entries per node)
                            if node.start_pfn == 0 || start_pfn < node.start_pfn {
                                node.start_pfn = start_pfn;
                            }
                            if end_pfn > node.end_pfn {
                                node.end_pfn = end_pfn;
                            }
                            node.present_pages += pages;
                        }
                    }
                }
            }

            ptr = ptr.add(entry_len);
        }

        // Second pass: collect CPU affinity entries
        ptr = entries_start;
        while ptr < entries_end {
            let entry_type = core::ptr::read_unaligned(ptr);
            let entry_len = core::ptr::read_unaligned(ptr.add(1)) as usize;

            if entry_len == 0 {
                break;
            }

            match entry_type {
                SRAT_ENTRY_LAPIC_AFFINITY => {
                    // Processor Local APIC Affinity (length 16):
                    // 0: type (1), 1: length (1), 2: proximity_domain_lo (1)
                    // 3: apic_id (1), 4: flags (4), 8: sapic_eid (1)
                    // 9: proximity_domain_hi (3), 12: clock_domain (4)
                    let prox_domain_lo = core::ptr::read_unaligned(ptr.add(2)) as u32;
                    let apic_id = core::ptr::read_unaligned(ptr.add(3)) as u32;
                    let flags = core::ptr::read_unaligned(ptr.add(4) as *const u32);
                    let prox_hi_bytes: [u8; 3] = [
                        core::ptr::read_unaligned(ptr.add(9)),
                        core::ptr::read_unaligned(ptr.add(10)),
                        core::ptr::read_unaligned(ptr.add(11)),
                    ];
                    let prox_domain_hi = (prox_hi_bytes[0] as u32)
                        | ((prox_hi_bytes[1] as u32) << 8)
                        | ((prox_hi_bytes[2] as u32) << 16);

                    let enabled = (flags & 0x1) != 0;

                    if enabled {
                        let node_id = (prox_domain_lo | (prox_domain_hi << 8)) as usize;
                        if node_id < MAX_NUMA_NODES && (apic_id as usize) < MAX_CPUS {
                            topology.cpu_to_node[apic_id as usize] = node_id as u8;

                            // Also add CPU to node's cpu_mask
                            if let Some(ref mut node) = topology.nodes[node_id] {
                                node.add_cpu(apic_id);
                            }
                        }
                    }
                }

                SRAT_ENTRY_X2APIC_AFFINITY => {
                    // Processor Local x2APIC Affinity (length 24):
                    // 0: type (1), 1: length (1), 2: reserved (2)
                    // 4: proximity_domain (4), 8: x2apic_id (4)
                    // 12: flags (4), 16: clock_domain (4), 20: reserved (4)
                    let prox_domain = core::ptr::read_unaligned(ptr.add(4) as *const u32);
                    let x2apic_id = core::ptr::read_unaligned(ptr.add(8) as *const u32);
                    let flags = core::ptr::read_unaligned(ptr.add(12) as *const u32);

                    let enabled = (flags & 0x1) != 0;

                    if enabled {
                        let node_id = prox_domain as usize;
                        // x2APIC IDs can be > 255, but we only support up to MAX_CPUS
                        if node_id < MAX_NUMA_NODES && (x2apic_id as usize) < MAX_CPUS {
                            topology.cpu_to_node[x2apic_id as usize] = node_id as u8;

                            // Also add CPU to node's cpu_mask (only if < 64)
                            if x2apic_id < 64
                                && let Some(ref mut node) = topology.nodes[node_id]
                            {
                                node.add_cpu(x2apic_id);
                            }
                        }
                    }
                }

                _ => {}
            }

            ptr = ptr.add(entry_len);
        }

        // Update node count
        topology.nr_nodes = topology.node_online_mask.count_ones() as usize;

        // Unmap the SRAT
        iounmap(srat_ptr, srat_length as u64);

        if topology.nr_nodes == 0 {
            return Err("SRAT contained no valid nodes");
        }

        Ok(())
    }
}

/// Parse SLIT table for inter-node distance matrix
fn parse_slit_mapped(slit_phys: u64) -> Result<(), &'static str> {
    use crate::numa::{MAX_NUMA_NODES, NUMA_TOPOLOGY};

    unsafe {
        // Map the SLIT
        let slit_ptr = map_acpi_table(slit_phys)?;

        // Read length from SDT header (offset 4)
        let length_ptr = slit_ptr.add(4) as *const u32;
        let slit_length = core::ptr::read_unaligned(length_ptr) as usize;

        // Validate SLIT checksum
        validate_table_checksum(slit_ptr as *const u8, slit_length, "SLIT");

        // SLIT header: SdtHeader (36) + Number of System Localities (8)
        let num_localities = core::ptr::read_unaligned(slit_ptr.add(36) as *const u64) as usize;

        if num_localities > MAX_NUMA_NODES {
            iounmap(slit_ptr, slit_length as u64);
            return Err("SLIT has too many localities");
        }

        // Distance matrix starts at offset 44, stored as 1D array [from][to]
        let matrix_start = slit_ptr.add(44);

        let mut topology = NUMA_TOPOLOGY.lock();

        for from in 0..num_localities {
            for to in 0..num_localities {
                let offset = from * num_localities + to;
                let distance = core::ptr::read_unaligned(matrix_start.add(offset));
                topology.set_distance(from, to, distance);
            }
        }

        // Unmap the SLIT
        iounmap(slit_ptr, slit_length as u64);

        Ok(())
    }
}
