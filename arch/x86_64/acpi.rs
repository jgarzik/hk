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
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use super::ioremap::{ioremap, iounmap};
use crate::arch::PowerInfo;
use crate::hw::acpi::aml::{self, SleepType};
use crate::hw::acpi::hw::{PmRegs, ResetReg, Space};
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
#[expect(dead_code)] // Fields used for future I/O APIC configuration
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
        let length_ptr = ptr.cast_const().add(4).cast::<u32>(); // offset of length field
        let length = core::ptr::read_unaligned(length_ptr);
        iounmap(ptr, header_size);

        // Now map the full table
        ioremap(phys_addr, u64::from(length)).map_err(|_| "Failed to ioremap ACPI table")
    }
}

/// Parse ACPI tables and extract SMP and power information
pub fn parse_acpi() -> Result<AcpiInfo, &'static str> {
    // Find RSDP (in low memory, read through the direct map)
    let rsdp = find_rsdp()?;

    // Get RSDT or XSDT address (physical address, may be above 512MB!)
    let (sdt_phys, is_xsdt) = unsafe {
        if (*rsdp).revision >= 2 {
            let rsdp2 = rsdp.cast::<Rsdp2>();
            if (*rsdp2).xsdt_address != 0 {
                ((*rsdp2).xsdt_address, true)
            } else {
                (u64::from((*rsdp).rsdt_address), false)
            }
        } else {
            (u64::from((*rsdp).rsdt_address), false)
        }
    };

    // Map and find MADT in RSDT/XSDT
    let madt_phys = find_madt_phys(sdt_phys, is_xsdt)?;

    // Map and parse MADT
    let mut info = parse_madt_mapped(madt_phys)?;

    // Find and parse FADT for power management info
    if let Ok(fadt_phys) = find_fadt_phys(sdt_phys, is_xsdt)
        && let Ok((mut power, dsdt_phys)) = parse_fadt_mapped(fadt_phys)
    {
        power.s5 = find_s5(dsdt_phys, sdt_phys, is_xsdt);
        info.power_info = Some(power);
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
            if checksum_valid(ptr.cast::<u8>(), core::mem::size_of::<Rsdp>()) {
                // For ACPI 2.0+, also verify extended checksum (full 36 bytes)
                let revision = unsafe { core::ptr::read_volatile(virt(addr + 15) as *const u8) };
                if revision >= 2 && !checksum_valid(ptr.cast::<u8>(), core::mem::size_of::<Rsdp2>())
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
        let length_ptr = sdt_ptr.cast_const().add(4).cast::<u32>();
        let total_length = core::ptr::read_unaligned(length_ptr) as usize;

        // Validate RSDT/XSDT checksum (warn but continue per Linux behavior)
        let table_name = if is_xsdt { "XSDT" } else { "RSDT" };
        validate_table_checksum(sdt_ptr.cast_const(), total_length, table_name);

        let header_size = core::mem::size_of::<SdtHeader>();
        let entry_size = if is_xsdt { 8 } else { 4 };
        let num_entries = total_length.saturating_sub(header_size) / entry_size;

        let entries_start = sdt_ptr.add(header_size);

        for i in 0..num_entries {
            let entry_ptr = entries_start.add(i * entry_size);
            let entry_phys = if is_xsdt {
                core::ptr::read_unaligned(entry_ptr as *const u64)
            } else {
                u64::from(core::ptr::read_unaligned(entry_ptr as *const u32))
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
    // SAFETY: an ACPI table (firmware memory, reserved from RAM use)
    let ptr = unsafe { ioremap(phys, size) }.ok()?;
    // SAFETY: the header is mapped; the signature is its first 4 bytes
    let sig = unsafe { core::ptr::read_unaligned(ptr as *const [u8; 4]) };
    // SAFETY: the mapping just made, no longer used
    unsafe { iounmap(ptr, size) };
    Some(sig)
}

/// Parse MADT and extract CPU/APIC information (uses ioremap)
fn parse_madt_mapped(madt_phys: u64) -> Result<AcpiInfo, &'static str> {
    let ptr = map_acpi_table(madt_phys)?;
    // SAFETY: map_acpi_table mapped the table, header included
    let len = unsafe { core::ptr::read_unaligned(ptr.add(4).cast::<u32>()) } as usize;
    // Validate MADT checksum (warn but continue per Linux behavior)
    validate_table_checksum(ptr.cast_const(), len, "MADT");
    // SAFETY: map_acpi_table mapped the `len` bytes the header claims:
    // firmware's table, which nothing writes; the slice is gone before
    // the iounmap below
    let info = parse_madt(unsafe { core::slice::from_raw_parts(ptr.cast_const(), len) });
    // SAFETY: the table's mapping, no longer used (the slice is gone)
    unsafe { iounmap(ptr, len as u64) };
    info
}

/// Little-endian u32 at `off` in `b` (None past its end)
fn le32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// The subtables of an ACPI table's body (MADT: `[type, length, ...]`
/// each). A length under 2 or past the table is an error, as in Linux
/// acpi_parse_entries_array ("Invalid zero length", an entry past the
/// table end); trailing bytes too short for a header end the walk.
fn subtables(mut b: &[u8]) -> impl Iterator<Item = Result<&[u8], &'static str>> {
    core::iter::from_fn(move || {
        let len = usize::from(*b.get(1)?);
        if len < 2 || len > b.len() {
            b = &[];
            return Some(Err("MADT entry length invalid"));
        }
        let (e, rest) = b.split_at(len);
        b = rest;
        Some(Ok(e))
    })
}

/// The CPUs and I/O APICs of a MADT (`t`: the whole table). Each entry
/// is read only inside the table and only if long enough for its type:
/// a short one fails the table (Linux BAD_MADT_ENTRY in the
/// acpi_parse_lapic/x2apic/ioapic handlers).
fn parse_madt(t: &[u8]) -> Result<AcpiInfo, &'static str> {
    const BAD: &str = "MADT entry too short";
    let hdr = core::mem::size_of::<MadtHeader>();
    if t.len() < hdr {
        return Err("MADT shorter than its header");
    }
    let mut info = AcpiInfo {
        lapic_base: u64::from(le32(t, 36).ok_or(BAD)?),
        cpus: Vec::new(),
        ioapics: Vec::new(),
        bsp_apic_id: 0,   // Will be set after LAPIC is mapped
        power_info: None, // Will be set after FADT parsing
    };
    // Track if we found LAPIC entries (for X2APIC duplicate filtering)
    let mut has_lapic_cpus = false;
    for e in subtables(&t[hdr..]) {
        let e = e?;
        match e[0] {
            MADT_ENTRY_LAPIC => {
                // header (2) + processor_id (1) + apic_id (1) + flags (4)
                let flags = le32(e, 4).ok_or(BAD)?;
                // Bit 0: Processor Enabled; bit 1: Online Capable (ACPI 6.3+)
                if flags & 0x3 != 0 {
                    has_lapic_cpus = true;
                    info.cpus.push(CpuInfo {
                        apic_id: u32::from(e[3]),
                        enabled: true,
                        is_bsp: false, // Will be set after LAPIC is mapped
                    });
                }
            }
            MADT_ENTRY_X2APIC => {
                // header (2) + reserved (2) + x2apic_id (4) + flags (4) + uid (4)
                if e.len() < 16 {
                    return Err(BAD);
                }
                let x2apic_id = le32(e, 4).ok_or(BAD)?;
                let flags = le32(e, 8).ok_or(BAD)?;
                // Ignore the invalid id; per the ACPI spec, with LAPIC
                // entries present an X2APIC id below 0xff is a duplicate
                let dup = x2apic_id == 0xffff_ffff || (has_lapic_cpus && x2apic_id < 0xff);
                if !dup && flags & 0x3 != 0 {
                    info.cpus.push(CpuInfo {
                        apic_id: x2apic_id,
                        enabled: true,
                        is_bsp: false,
                    });
                }
            }
            MADT_ENTRY_IOAPIC => {
                // header (2) + id (1) + reserved (1) + address (4) + gsi_base (4)
                if e.len() < 12 {
                    return Err(BAD);
                }
                info.ioapics.push(IoApicInfo {
                    id: e[2],
                    address: le32(e, 4).ok_or(BAD)?,
                    gsi_base: le32(e, 8).ok_or(BAD)?,
                });
            }
            MADT_ENTRY_LAPIC_64 => {
                // header (2) + reserved (2) + address (8)
                let b = e.get(4..12).ok_or(BAD)?;
                info.lapic_base = u64::from_le_bytes(b.try_into().map_err(|_| BAD)?);
            }
            // Interrupt source overrides, LAPIC NMIs and the rest are not
            // needed for basic SMP boot
            MADT_ENTRY_ISO | MADT_ENTRY_LAPIC_NMI => {}
            _ => {}
        }
    }
    if info.cpus.is_empty() {
        return Err("No CPUs found in MADT");
    }
    Ok(info)
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
    pub const FLAGS: usize = 112;
    pub const RESET_REG: usize = 116;
    pub const RESET_VALUE: usize = 128;
    pub const X_DSDT: usize = 140;

    /// Header revision (the FADT's major version)
    pub const REVISION: usize = 8;
    /// Flags: RESET_REG_SUP
    pub const RESET_REG_SUP: u32 = 1 << 10;
    /// Generic Address Structure: address space ID, then the address at 4
    pub const GAS_SPACE: usize = 0;
    pub const GAS_ADDR: usize = 4;
    pub const SPACE_MEM: u8 = 0;
    pub const SPACE_IO: u8 = 1;
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
            b = unsafe { core::ptr::read_unaligned(self.ptr.add(off).cast::<[u8; N]>()) };
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

/// Parse FADT: power management registers, the reset register, and
/// the DSDT's physical address (X_DSDT if set, as Linux prefers it); S5
/// is left for the caller (uses ioremap)
fn parse_fadt_mapped(fadt_phys: u64) -> Result<(PowerInfo, u64), &'static str> {
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
        0 => u64::from(t.u32(fadt::DSDT)),
        x => x,
    };

    let reset = reset_reg(&t);

    // SAFETY: the table's mapping, no longer used (`t` is done)
    unsafe { iounmap(ptr, len as u64) };
    let power = PowerInfo {
        pm,
        s5: SleepType::default(),
        reset,
    };
    Ok((power, dsdt))
}

/// The FADT reset register, if supported (Linux acpi_reboot: FADT
/// revision 2 or later, RESET_REG_SUP, I/O or memory space)
fn reset_reg(t: &Table) -> Option<ResetReg> {
    if t.u8(fadt::REVISION) < 2 || t.u32(fadt::FLAGS) & fadt::RESET_REG_SUP == 0 {
        return None;
    }
    let space = match t.u8(fadt::RESET_REG + fadt::GAS_SPACE) {
        fadt::SPACE_MEM => Space::Mem,
        fadt::SPACE_IO => Space::Io,
        _ => return None,
    };
    let addr = t.u64(fadt::RESET_REG + fadt::GAS_ADDR);
    let value = t.u8(fadt::RESET_VALUE);
    if addr == 0 {
        return None;
    }
    crate::printkln!(
        "ACPI: reset register {:?} {:#x} value {:#x}",
        space,
        addr,
        value
    );
    Some(ResetReg { space, addr, value })
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
    // SAFETY: the table's mapping, no longer used (`body` is gone)
    unsafe { iounmap(ptr, len as u64) };
    s5
}

/// The SRAT entries in `entries` (the table past its header), each
/// `[type, length, ...]`; a zero or overrunning length ends them
fn srat_entries(mut entries: &[u8]) -> impl Iterator<Item = &[u8]> {
    core::iter::from_fn(move || {
        let len = usize::from(*entries.get(1)?);
        if len < 2 || len > entries.len() {
            return None;
        }
        let (e, rest) = entries.split_at(len);
        entries = rest;
        Some(e)
    })
}

/// Call `f` with the proximity domain of each enabled SRAT entry, in the
/// order Linux numbers them (acpi_numa_init): the CPU affinity entries
/// (local APIC and x2APIC alike) in table order, then the memory ones
fn srat_pxm_order(entries: &[u8], mut f: impl FnMut(u32)) {
    let cpu = |e: &&[u8]| e[0] == SRAT_ENTRY_LAPIC_AFFINITY || e[0] == SRAT_ENTRY_X2APIC_AFFINITY;
    let cpus = srat_entries(entries).filter(cpu);
    let mem = srat_entries(entries).filter(|e| e[0] == SRAT_ENTRY_MEMORY_AFFINITY);
    for pxm in cpus.chain(mem).filter_map(srat_entry_pxm) {
        f(pxm);
    }
}

/// The proximity domain of an enabled SRAT CPU or memory affinity entry
fn srat_entry_pxm(e: &[u8]) -> Option<u32> {
    let rd = |o: usize| Some(u32::from_le_bytes(e.get(o..o + 4)?.try_into().ok()?));
    let b = |o: usize| e.get(o).copied().map(u32::from);
    match e[0] {
        SRAT_ENTRY_LAPIC_AFFINITY if rd(4)? & 1 != 0 => {
            Some(b(2)? | (b(9)? << 8) | (b(10)? << 16) | (b(11)? << 24))
        }
        SRAT_ENTRY_X2APIC_AFFINITY if rd(12)? & 1 != 0 => rd(4),
        SRAT_ENTRY_MEMORY_AFFINITY if rd(28)? & 1 != 0 => rd(2),
        _ => None,
    }
}

/// Initialize NUMA topology from ACPI SRAT/SLIT tables
///
/// Called early in boot to discover NUMA topology. If SRAT is not found,
/// returns Ok(false) and caller should use single-node fallback.
pub fn init_numa_topology() -> Result<bool, &'static str> {
    use crate::mm::numa::{LOCAL_DISTANCE, MAX_NUMA_NODES, NUMA_TOPOLOGY, REMOTE_DISTANCE};

    // Find RSDP
    let rsdp = find_rsdp()?;

    // Get RSDT or XSDT address
    let (sdt_phys, is_xsdt) = unsafe {
        if (*rsdp).revision >= 2 {
            let rsdp2 = rsdp.cast::<Rsdp2>();
            if (*rsdp2).xsdt_address != 0 {
                ((*rsdp2).xsdt_address, true)
            } else {
                (u64::from((*rsdp).rsdt_address), false)
            }
        } else {
            (u64::from((*rsdp).rsdt_address), false)
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
    let ptr = map_acpi_table(srat_phys)?;
    // SAFETY: map_acpi_table mapped the table, header included
    let len = unsafe { core::ptr::read_unaligned(ptr.add(4).cast::<u32>()) } as usize;
    validate_table_checksum(ptr.cast_const(), len, "SRAT");
    // SAFETY: map_acpi_table mapped the `len` bytes the header claims:
    // firmware's table, which nothing writes; the slice is gone before
    // the iounmap below
    let r = parse_srat(unsafe { core::slice::from_raw_parts(ptr.cast_const(), len) });
    // SAFETY: the table's mapping, no longer used (the slice is gone)
    unsafe { iounmap(ptr, len as u64) };
    r
}

/// The SRAT's affinity entries past its 48-byte header (SdtHeader +
/// 12 reserved bytes), each long enough for its type. A bad entry
/// length, or an affinity entry shorter than its structure, rejects the
/// whole table, as Linux's bad_srat() turns SRAT NUMA off
/// (acpi_numa_memory_affinity_init, acpi_numa_processor_affinity_init).
fn srat_body(t: &[u8]) -> Result<&[u8], &'static str> {
    let body = t.get(48..).ok_or("SRAT shorter than its header")?;
    for e in subtables(body) {
        let e = e.map_err(|_| "SRAT entry length invalid")?;
        let need = match e[0] {
            SRAT_ENTRY_LAPIC_AFFINITY => 16,
            SRAT_ENTRY_MEMORY_AFFINITY => 40,
            SRAT_ENTRY_X2APIC_AFFINITY => 24,
            _ => 2,
        };
        if e.len() < need {
            return Err("SRAT entry too short");
        }
    }
    Ok(body)
}

/// Fill NUMA_TOPOLOGY from a SRAT (`t`: the whole table)
fn parse_srat(t: &[u8]) -> Result<(), &'static str> {
    use crate::mm::numa::{MAX_NUMA_NODES, NUMA_TOPOLOGY, NumaNode};

    let entries = srat_body(t)?;
    let mut topology = NUMA_TOPOLOGY.lock();

    // Number the proximity domains first, in Linux's order
    srat_pxm_order(entries, |pxm| {
        let _ = topology.acpi_map_pxm(pxm);
    });

    // First pass: memory affinity entries build the nodes. Memory
    // Affinity Structure (length 40): 0 type, 1 length, 2 proximity
    // domain (4), 8 base lo/hi (8), 16 length lo/hi (8), 28 flags (4)
    for e in srat_entries(entries).filter(|e| e[0] == SRAT_ENTRY_MEMORY_AFFINITY) {
        // srat_body checked the length
        let rd = |o: usize| u64::from(le32(e, o).unwrap_or(0));
        // Bit 0: Enabled
        if rd(28) & 1 == 0 {
            continue;
        }
        let base_addr = rd(8) | (rd(12) << 32);
        let length = rd(16) | (rd(20) << 32);
        let node_id = topology.pxm_to_node(rd(2) as u32).unwrap_or(MAX_NUMA_NODES);
        if node_id >= MAX_NUMA_NODES || length == 0 {
            continue;
        }
        let start_pfn = base_addr / 4096;
        // firmware's numbers: a range past 2^64 ends there
        let end_pfn = base_addr.saturating_add(length) / 4096;
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
            node.present_pages = node.present_pages.saturating_add(pages);
        }
    }

    // Second pass: CPU affinity entries, by APIC id (the logical CPU
    // joins its node at bring-up)
    for e in srat_entries(entries) {
        let hwid = match e[0] {
            // Processor Local APIC Affinity (length 16): 2 proximity
            // domain lo (1), 3 apic_id (1), 4 flags (4), 9 domain hi (3)
            SRAT_ENTRY_LAPIC_AFFINITY => u64::from(e[3]),
            // Processor Local x2APIC Affinity (length 24): 4 proximity
            // domain (4), 8 x2apic_id (4), 12 flags (4)
            SRAT_ENTRY_X2APIC_AFFINITY => u64::from(le32(e, 8).unwrap_or(0)),
            _ => continue,
        };
        // srat_entry_pxm: the domain of an enabled entry (Linux numbering)
        let Some(pxm) = srat_entry_pxm(e) else {
            continue;
        };
        if let Some(node_id) = topology.pxm_to_node(pxm)
            && node_id < MAX_NUMA_NODES
        {
            topology.set_hwid_node(hwid, node_id as u32);
        }
    }

    // Update node count
    topology.nr_nodes = topology.node_online_mask.count_ones() as usize;

    if topology.nr_nodes == 0 {
        return Err("SRAT contained no valid nodes");
    }

    Ok(())
}

/// Parse SLIT table for inter-node distance matrix
fn parse_slit_mapped(slit_phys: u64) -> Result<(), &'static str> {
    use crate::mm::numa::NUMA_TOPOLOGY;

    unsafe {
        // Map the SLIT
        let slit_ptr = map_acpi_table(slit_phys)?;

        // Read length from SDT header (offset 4)
        let length_ptr = slit_ptr.add(4) as *const u32;
        let slit_length = core::ptr::read_unaligned(length_ptr) as usize;

        // Validate SLIT checksum
        validate_table_checksum(slit_ptr.cast_const(), slit_length, "SLIT");

        // SLIT header: SdtHeader (36) + Number of System Localities (8)
        let num_localities = core::ptr::read_unaligned(slit_ptr.add(36) as *const u64) as usize;

        // Distance matrix starts at offset 44, stored as 1D array [from][to]
        if num_localities
            .checked_mul(num_localities)
            .and_then(|m| m.checked_add(44))
            .is_none_or(|end| end > slit_length)
        {
            iounmap(slit_ptr, slit_length as u64);
            return Err("SLIT shorter than its matrix");
        }
        let matrix_start = slit_ptr.add(44);

        let mut topology = NUMA_TOPOLOGY.lock();

        // Localities are proximity domains: only those SRAT numbered
        // have nodes (Linux acpi_parse_slit -> pxm_to_node)
        for from in 0..num_localities {
            for to in 0..num_localities {
                let (Some(f), Some(t)) = (
                    topology.pxm_to_node(from as u32),
                    topology.pxm_to_node(to as u32),
                ) else {
                    continue;
                };
                let offset = from * num_localities + to;
                let distance = core::ptr::read_unaligned(matrix_start.add(offset));
                topology.set_distance(f, t, distance);
            }
        }

        // Unmap the SLIT
        iounmap(slit_ptr, slit_length as u64);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lapic(pxm: u8) -> [u8; 16] {
        let mut e = [0u8; 16];
        e[0] = SRAT_ENTRY_LAPIC_AFFINITY;
        e[1] = 16;
        e[2] = pxm;
        e[4] = 1; // enabled
        e
    }

    fn x2apic(pxm: u32) -> [u8; 24] {
        let mut e = [0u8; 24];
        e[0] = SRAT_ENTRY_X2APIC_AFFINITY;
        e[1] = 24;
        e[4..8].copy_from_slice(&pxm.to_le_bytes());
        e[12] = 1;
        e
    }

    fn mem(pxm: u32, enabled: bool) -> [u8; 40] {
        let mut e = [0u8; 40];
        e[0] = SRAT_ENTRY_MEMORY_AFFINITY;
        e[1] = 40;
        e[2..6].copy_from_slice(&pxm.to_le_bytes());
        e[28] = u8::from(enabled);
        e
    }

    fn order(parts: &[&[u8]]) -> alloc::vec::Vec<u32> {
        let table: alloc::vec::Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
        let mut out = alloc::vec::Vec::new();
        srat_pxm_order(&table, |p| out.push(p));
        out
    }

    /// CPU entries of both kinds in table order, then memory (Linux
    /// acpi_numa_init); disabled entries skipped
    #[test]
    fn pxm_order_is_linux() {
        let got = order(&[
            &mem(9, true),
            &lapic(0),
            &x2apic(7),
            &mem(3, false),
            &lapic(4),
        ]);
        assert_eq!(got, [0, 7, 4, 9]);
        // A zero length ends the walk
        let mut bad = lapic(1);
        bad[1] = 0;
        assert_eq!(order(&[&lapic(2), &bad, &lapic(3)]), [2]);
    }

    /// A table: `hdr` header bytes (lapic_address 0xfee00000 at 36 if
    /// they reach it), then `parts`
    fn table(hdr: usize, parts: &[&[u8]]) -> alloc::vec::Vec<u8> {
        let mut t = alloc::vec![0u8; hdr];
        if hdr >= 40 {
            t[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        }
        t.extend(parts.iter().flat_map(|p| p.iter().copied()));
        t
    }

    const MADT_LAPIC: [u8; 8] = [MADT_ENTRY_LAPIC, 8, 0, 3, 1, 0, 0, 0];
    const MADT_IOAPIC: [u8; 12] = [MADT_ENTRY_IOAPIC, 12, 2, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0];

    #[test]
    fn madt_parses_in_bounds() {
        let i = parse_madt(&table(44, &[&MADT_LAPIC, &MADT_IOAPIC, &[0x7f, 2]])).unwrap();
        assert_eq!(i.lapic_base, 0xfee0_0000);
        assert_eq!((i.cpus.len(), i.cpus[0].apic_id), (1, 3));
        assert_eq!((i.ioapics[0].id, i.ioapics[0].address), (2, 0xfec0_0000));
        // trailing bytes too short for an entry header end the walk
        assert!(parse_madt(&table(44, &[&MADT_LAPIC, &[0]])).is_ok());
    }

    #[test]
    fn madt_rejects_bad_entries() {
        // shorter than its header
        assert!(parse_madt(&table(40, &[])).is_err());
        // an entry running past the table, a zero length
        let mut over = MADT_LAPIC;
        over[1] = 200;
        assert!(parse_madt(&table(44, &[&MADT_LAPIC, &over])).is_err());
        let mut zero = MADT_LAPIC;
        zero[1] = 0;
        assert!(parse_madt(&table(44, &[&MADT_LAPIC, &zero])).is_err());
        // entries too short for their type
        assert!(parse_madt(&table(44, &[&MADT_LAPIC, &[MADT_ENTRY_IOAPIC, 2]])).is_err());
        assert!(parse_madt(&table(44, &[&[MADT_ENTRY_LAPIC, 4, 0, 3]])).is_err());
        assert!(
            parse_madt(&table(
                44,
                &[
                    &MADT_LAPIC,
                    &[MADT_ENTRY_X2APIC, 12, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0]
                ]
            ))
            .is_err()
        );
        assert!(
            parse_madt(&table(
                44,
                &[&MADT_LAPIC, &[MADT_ENTRY_LAPIC_64, 8, 0, 0, 0, 0, 0, 0]]
            ))
            .is_err()
        );
    }

    #[test]
    fn srat_rejects_bad_entries() {
        assert!(srat_body(&table(44, &[])).is_err());
        assert!(srat_body(&table(48, &[&lapic(0), &mem(0, true), &x2apic(1)])).is_ok());
        let mut short = mem(0, true);
        short[1] = 24;
        assert!(srat_body(&table(48, &[&lapic(0), &short[..24]])).is_err());
        let mut over = lapic(0);
        over[1] = 255;
        assert!(srat_body(&table(48, &[&over])).is_err());
    }
}
