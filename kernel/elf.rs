//! ELF64 parser

use alloc::vec::Vec;

/// ELF magic number
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class: 64-bit
pub const ELFCLASS64: u8 = 2;

/// ELF data encoding: little endian
pub const ELFDATA2LSB: u8 = 1;

/// ELF type: executable
pub const ET_EXEC: u16 = 2;

/// ELF type: shared object / PIE
pub const ET_DYN: u16 = 3;

/// ELF machine: x86-64
pub const EM_X86_64: u16 = 62;

/// ELF machine: aarch64
pub const EM_AARCH64: u16 = 183;

/// Program header type: loadable segment
pub const PT_LOAD: u32 = 1;

/// Program header type: dynamic linking info
pub const PT_DYNAMIC: u32 = 2;

/// Relocation type: R_X86_64_RELATIVE (adjust by base address)
pub const R_X86_64_RELATIVE: u32 = 8;

/// Relocation type: R_AARCH64_RELATIVE (adjust by base address)
pub const R_AARCH64_RELATIVE: u32 = 1027; // 0x403

/// Expected ELF machine type for current architecture
#[cfg(target_arch = "x86_64")]
pub const EXPECTED_EM_MACHINE: u16 = EM_X86_64;
#[cfg(target_arch = "aarch64")]
pub const EXPECTED_EM_MACHINE: u16 = EM_AARCH64;

/// Expected relocation type for RELATIVE relocations on current architecture
#[cfg(target_arch = "x86_64")]
pub const R_RELATIVE: u32 = R_X86_64_RELATIVE;
#[cfg(target_arch = "aarch64")]
pub const R_RELATIVE: u32 = R_AARCH64_RELATIVE;

/// Dynamic tag: DT_RELA - address of relocation table
pub const DT_RELA: u64 = 7;
/// Dynamic tag: DT_RELASZ - size of relocation table in bytes
pub const DT_RELASZ: u64 = 8;
/// Dynamic tag: DT_RELAENT - size of each relocation entry
pub const DT_RELAENT: u64 = 9;

/// Segment flags
#[derive(Debug, Clone, Copy)]
pub struct SegmentFlags {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl SegmentFlags {
    pub fn from_elf_flags(flags: u32) -> Self {
        Self {
            execute: flags & 0x1 != 0,
            write: flags & 0x2 != 0,
            read: flags & 0x4 != 0,
        }
    }
}

/// A loadable ELF segment
pub struct ElfSegment<VA> {
    /// Virtual address to load at
    pub vaddr: VA,
    /// Size in memory (may be larger than file size for BSS)
    pub mem_size: usize,
    /// Size in file
    pub file_size: usize,
    /// Segment flags (R/W/X)
    pub flags: SegmentFlags,
    /// Offset in file
    pub offset: u64,
}

/// A relocation entry (RELATIVE type only for PIE)
#[derive(Debug, Clone, Copy)]
pub struct ElfRelocation {
    /// Offset where to apply the relocation (relative to base)
    pub offset: u64,
    /// Addend to add to base address
    pub addend: i64,
}

/// Parsed ELF executable
pub struct ElfExecutable<VA> {
    /// Entry point virtual address (relative to base for PIE)
    pub entry: VA,
    /// Loadable segments
    pub segments: Vec<ElfSegment<VA>>,
    /// True if this is a PIE (position-independent executable)
    /// When true, a base address must be added to all virtual addresses
    pub is_pie: bool,
    /// Relocations to apply (only for PIE, R_X86_64_RELATIVE type)
    pub relocations: Vec<ElfRelocation>,
}

/// ELF parsing error
#[derive(Debug)]
pub enum ElfError {
    /// Invalid magic number
    InvalidMagic,
    /// Not a 64-bit ELF
    Not64Bit,
    /// Not little endian
    NotLittleEndian,
    /// Not an executable
    NotExecutable,
    /// Wrong architecture
    WrongArch,
    /// Buffer too small
    BufferTooSmall,
}

impl<VA: Copy> ElfExecutable<VA> {
    /// Parse an ELF64 executable from bytes
    pub fn parse(data: &[u8], addr_from_u64: fn(u64) -> VA) -> Result<Self, ElfError> {
        // Check minimum size for ELF header
        if data.len() < 64 {
            return Err(ElfError::BufferTooSmall);
        }

        // Check magic
        if data[0..4] != ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }

        // Check class (64-bit)
        if data[4] != ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }

        // Check endianness (little endian)
        if data[5] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }

        // Check type (executable or PIE)
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        let is_pie = match e_type {
            ET_EXEC => false,
            ET_DYN => true,
            _ => return Err(ElfError::NotExecutable),
        };

        // Check machine (must match current architecture)
        let e_machine = u16::from_le_bytes([data[18], data[19]]);
        if e_machine != EXPECTED_EM_MACHINE {
            return Err(ElfError::WrongArch);
        }

        // Get entry point
        let e_entry = u64::from_le_bytes(data[24..32].try_into().unwrap());

        // Get program header offset
        let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;

        // Get program header entry size
        let e_phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;

        // Get number of program headers
        let e_phnum = u16::from_le_bytes([data[56], data[57]]) as usize;

        // Parse program headers
        let mut segments = Vec::new();
        let mut dynamic_offset: Option<usize> = None;
        let mut dynamic_size: usize = 0;

        for i in 0..e_phnum {
            let ph_offset = e_phoff + i * e_phentsize;

            if ph_offset + e_phentsize > data.len() {
                return Err(ElfError::BufferTooSmall);
            }

            let ph = &data[ph_offset..ph_offset + e_phentsize];

            // Check segment type
            let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());

            match p_type {
                PT_LOAD => {
                    let p_flags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
                    let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap());
                    let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
                    let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap());
                    let p_memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());

                    segments.push(ElfSegment {
                        vaddr: addr_from_u64(p_vaddr),
                        mem_size: p_memsz as usize,
                        file_size: p_filesz as usize,
                        flags: SegmentFlags::from_elf_flags(p_flags),
                        offset: p_offset,
                    });
                }
                PT_DYNAMIC => {
                    let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap());
                    let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap());
                    dynamic_offset = Some(p_offset as usize);
                    dynamic_size = p_filesz as usize;
                }
                _ => {}
            }
        }

        // Parse relocations from DYNAMIC segment if this is a PIE
        let mut relocations = Vec::new();
        if is_pie && let Some(dyn_off) = dynamic_offset {
            // Parse DYNAMIC entries to find RELA table
            let mut rela_offset: Option<u64> = None;
            let mut rela_size: u64 = 0;
            let mut rela_entsize: u64 = 24; // Default for Elf64_Rela

            let mut i = 0;
            while i + 16 <= dynamic_size {
                let dyn_entry = &data[dyn_off + i..dyn_off + i + 16];
                let d_tag = u64::from_le_bytes(dyn_entry[0..8].try_into().unwrap());
                let d_val = u64::from_le_bytes(dyn_entry[8..16].try_into().unwrap());

                match d_tag {
                    0 => break, // DT_NULL - end of dynamic section
                    DT_RELA => rela_offset = Some(d_val),
                    DT_RELASZ => rela_size = d_val,
                    DT_RELAENT => rela_entsize = d_val,
                    _ => {}
                }
                i += 16;
            }

            // Parse RELA entries
            if let Some(rela_off) = rela_offset {
                // Find file offset for the rela_off virtual address
                // For PIE, the virtual address in DYNAMIC points to where it would be loaded
                // We need to convert this to file offset using segments
                let mut file_offset = None;
                for seg in &segments {
                    // Convert VA back to u64 - we know it's u64 for now
                    let seg_vaddr = {
                        let ptr = &seg.vaddr as *const VA as *const u64;
                        unsafe { *ptr }
                    };
                    let seg_end = seg_vaddr + seg.file_size as u64;
                    if rela_off >= seg_vaddr && rela_off < seg_end {
                        file_offset = Some(seg.offset + (rela_off - seg_vaddr));
                        break;
                    }
                }

                if let Some(rela_file_off) = file_offset {
                    let rela_file_off = rela_file_off as usize;
                    let mut j = 0;
                    while j < rela_size as usize
                        && rela_file_off + j + rela_entsize as usize <= data.len()
                    {
                        let rela =
                            &data[rela_file_off + j..rela_file_off + j + rela_entsize as usize];
                        let r_offset = u64::from_le_bytes(rela[0..8].try_into().unwrap());
                        let r_info = u64::from_le_bytes(rela[8..16].try_into().unwrap());
                        let r_addend = i64::from_le_bytes(rela[16..24].try_into().unwrap());

                        let r_type = (r_info & 0xffffffff) as u32;

                        // Only handle R_*_RELATIVE for now (architecture-dependent)
                        if r_type == R_RELATIVE {
                            relocations.push(ElfRelocation {
                                offset: r_offset,
                                addend: r_addend,
                            });
                        }

                        j += rela_entsize as usize;
                    }
                }
            }
        }

        Ok(Self {
            entry: addr_from_u64(e_entry),
            segments,
            is_pie,
            relocations,
        })
    }
}
