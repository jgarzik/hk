//! ELF64 executable parser
//!
//! Validates the headers an execve'd file carries before anything is
//! mapped, following Linux fs/binfmt_elf.c (load_elf_binary,
//! load_elf_phdrs): any user can exec a crafted file, so every offset
//! and size is bounds- and overflow-checked and the parser never
//! panics. Errors carry Linux's errno (ENOEXEC for a file that is not
//! a loadable ELF or whose header table is cut short, EIO for an
//! interpreter path past the end of the file, EINVAL for segments that
//! cannot be mapped).

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

/// Program header type: program interpreter
pub const PT_INTERP: u32 = 3;

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

/// Size of an Elf64_Ehdr / Elf64_Phdr / Elf64_Rela / Elf64_Dyn
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const RELA_SIZE: usize = 24;
const DYN_SIZE: usize = 16;

/// Linux load_elf_phdrs: the header table fits in one ELF_MIN_ALIGN page
const MAX_PHDRS_SIZE: usize = 4096;

/// Linux: an interpreter path is at most PATH_MAX and at least 2 bytes
const PATH_MAX: usize = 4096;

/// Page size segments are mapped with
const PAGE: u64 = 4096;

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
pub struct ElfSegment {
    /// Virtual address to load at (before the PIE base)
    pub vaddr: u64,
    /// Size in memory (may be larger than file size for BSS)
    pub mem_size: usize,
    /// Size in file (never more than `mem_size`)
    pub file_size: usize,
    /// Segment flags (R/W/X)
    pub flags: SegmentFlags,
    /// Offset in file
    pub offset: u64,
}

impl ElfSegment {
    /// The file bytes that land in the user page at `page` when the
    /// segment is loaded `base` higher: (offset in the page, offset in
    /// the file, length), clamped to the page, the segment's file part
    /// and the file actually read (`file_len`); None if none do
    pub fn page_fill(
        &self,
        base: u64,
        page: u64,
        file_len: usize,
    ) -> Option<(usize, usize, usize)> {
        let start = self.vaddr.checked_add(base)?;
        if page.checked_add(PAGE)? <= start {
            return None;
        }
        let dst = start.saturating_sub(page);
        let rel = page.saturating_sub(start);
        if rel >= self.file_size as u64 {
            return None;
        }
        let src = usize::try_from(self.offset.checked_add(rel)?).ok()?;
        if src >= file_len {
            return None;
        }
        let len = ((PAGE - dst) as usize)
            .min(self.file_size - rel as usize)
            .min(file_len - src);
        Some((dst as usize, src, len))
    }
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
pub struct ElfExecutable {
    /// Entry point virtual address (relative to base for PIE)
    pub entry: u64,
    /// Loadable segments
    pub segments: Vec<ElfSegment>,
    /// True if this is a PIE (position-independent executable)
    /// When true, a base address must be added to all virtual addresses
    pub is_pie: bool,
    /// Relocations to apply (only for PIE, R_*_RELATIVE type)
    pub relocations: Vec<ElfRelocation>,
    /// Virtual address of the program headers (AT_PHDR, before the PIE
    /// base is added; 0 if no loaded segment holds them)
    pub phdr: u64,
    /// Program header entry size and count (AT_PHENT, AT_PHNUM)
    pub phent: u64,
    pub phnum: u64,
    /// Largest power-of-two PT_LOAD alignment (the PIE base is aligned
    /// to it; Linux maximum_alignment ignores invalid ones)
    pub align: u64,
    /// Requested program interpreter (PT_INTERP), without the NUL
    pub interp: Option<Vec<u8>>,
    /// Highest end of a loaded segment (before the PIE base)
    pub end: u64,
}

/// ELF parsing error, by the errno Linux returns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Not a loadable ELF for this machine (ENOEXEC)
    NotExecutable,
    /// The interpreter path extends past the end of the file (EIO,
    /// Linux elf_read)
    Truncated,
    /// A segment cannot be mapped (EINVAL)
    BadSegment,
}

impl ElfError {
    /// Positive errno
    pub fn errno(self) -> i32 {
        match self {
            ElfError::NotExecutable => 8, // ENOEXEC
            ElfError::Truncated => 5,     // EIO
            ElfError::BadSegment => 22,   // EINVAL
        }
    }
}

/// `len` bytes at `off`, or Truncated
fn bytes(data: &[u8], off: u64, len: usize) -> Result<&[u8], ElfError> {
    let off = usize::try_from(off).map_err(|_| ElfError::Truncated)?;
    let end = off.checked_add(len).ok_or(ElfError::Truncated)?;
    data.get(off..end).ok_or(ElfError::Truncated)
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn u64_at(b: &[u8], i: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(a)
}

/// One program header
struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

impl Phdr {
    fn read(b: &[u8]) -> Self {
        Self {
            kind: u32_at(b, 0),
            flags: u32_at(b, 4),
            offset: u64_at(b, 8),
            vaddr: u64_at(b, 16),
            filesz: u64_at(b, 32),
            memsz: u64_at(b, 40),
            align: u64_at(b, 48),
        }
    }
}

/// The ELF header: (is_pie, entry, phoff, phnum)
fn ehdr(data: &[u8]) -> Result<(bool, u64, u64, usize), ElfError> {
    // Linux reads a zero-padded buffer: a short file just fails the checks
    let h = data.get(..EHDR_SIZE).ok_or(ElfError::NotExecutable)?;
    if h[..4] != ELF_MAGIC || h[4] != ELFCLASS64 || h[5] != ELFDATA2LSB {
        return Err(ElfError::NotExecutable);
    }
    let is_pie = match u16_at(h, 16) {
        ET_EXEC => false,
        ET_DYN => true,
        _ => return Err(ElfError::NotExecutable),
    };
    if u16_at(h, 18) != EXPECTED_EM_MACHINE {
        return Err(ElfError::NotExecutable);
    }
    // load_elf_phdrs: exact entry size, a non-empty table of at most a page
    let phnum = u16_at(h, 56) as usize;
    let size = phnum * PHDR_SIZE;
    if u16_at(h, 54) as usize != PHDR_SIZE || size == 0 || size > MAX_PHDRS_SIZE {
        return Err(ElfError::NotExecutable);
    }
    Ok((is_pie, u64_at(h, 24), u64_at(h, 32), phnum))
}

/// A PT_LOAD segment Linux could map: memory size covers the file
/// part, no address overflow, file offset congruent to the address
fn load_segment(p: &Phdr) -> Result<ElfSegment, ElfError> {
    if p.vaddr.checked_add(p.memsz).is_none() || p.offset.checked_add(p.filesz).is_none() {
        return Err(ElfError::BadSegment);
    }
    if p.filesz > p.memsz || (p.filesz > 0 && !(p.vaddr ^ p.offset).is_multiple_of(PAGE)) {
        return Err(ElfError::BadSegment);
    }
    Ok(ElfSegment {
        vaddr: p.vaddr,
        mem_size: usize::try_from(p.memsz).map_err(|_| ElfError::BadSegment)?,
        file_size: usize::try_from(p.filesz).map_err(|_| ElfError::BadSegment)?,
        flags: SegmentFlags::from_elf_flags(p.flags),
        offset: p.offset,
    })
}

/// PT_INTERP: a NUL-terminated path of 2..=PATH_MAX bytes in the file
fn interp(data: &[u8], p: &Phdr) -> Result<Vec<u8>, ElfError> {
    let len = usize::try_from(p.filesz).map_err(|_| ElfError::NotExecutable)?;
    if !(2..=PATH_MAX).contains(&len) {
        return Err(ElfError::NotExecutable);
    }
    let b = bytes(data, p.offset, len)?;
    if b[len - 1] != 0 {
        return Err(ElfError::NotExecutable);
    }
    Ok(b[..len - 1].to_vec())
}

/// File offset of virtual address `va` within a loaded segment's file part
fn file_offset(segs: &[ElfSegment], va: u64) -> Option<u64> {
    segs.iter().find_map(|s| {
        let rel = va.checked_sub(s.vaddr)?;
        (rel < s.file_size as u64).then(|| s.offset + rel)
    })
}

/// RELATIVE relocations of a PIE (its own DT_RELA table); a malformed
/// table yields fewer relocations, never an out-of-bounds read
fn relocations(data: &[u8], segs: &[ElfSegment], dynamic: &Phdr) -> Vec<ElfRelocation> {
    let mut out = Vec::new();
    let Ok(len) = usize::try_from(dynamic.filesz) else {
        return out;
    };
    let Ok(dynb) = bytes(data, dynamic.offset, len) else {
        return out;
    };
    let (mut rela, mut relasz, mut relaent) = (None, 0u64, RELA_SIZE as u64);
    for d in dynb.as_chunks::<DYN_SIZE>().0 {
        match u64_at(d, 0) {
            0 => break,
            DT_RELA => rela = Some(u64_at(d, 8)),
            DT_RELASZ => relasz = u64_at(d, 8),
            DT_RELAENT => relaent = u64_at(d, 8),
            _ => {}
        }
    }
    if relaent != RELA_SIZE as u64 {
        return out;
    }
    let Some(off) = rela.and_then(|va| file_offset(segs, va)) else {
        return out;
    };
    let Ok(len) = usize::try_from(relasz) else {
        return out;
    };
    let Ok(table) = bytes(data, off, len - len % RELA_SIZE) else {
        return out;
    };
    for r in table.as_chunks::<RELA_SIZE>().0 {
        if u64_at(r, 8) & 0xffff_ffff == R_RELATIVE as u64 {
            out.push(ElfRelocation {
                offset: u64_at(r, 0),
                addend: u64_at(r, 16) as i64,
            });
        }
    }
    out
}

impl ElfExecutable {
    /// Parse and validate an ELF64 executable
    pub fn parse(data: &[u8]) -> Result<Self, ElfError> {
        let (is_pie, entry, phoff, phnum) = ehdr(data)?;
        // Linux load_elf_phdrs fails quietly: a short table is ENOEXEC
        let table = bytes(data, phoff, phnum * PHDR_SIZE).map_err(|_| ElfError::NotExecutable)?;
        let phdrs: Vec<Phdr> = table
            .as_chunks::<PHDR_SIZE>()
            .0
            .iter()
            .map(|b| Phdr::read(b))
            .collect();

        let mut segments = Vec::new();
        let (mut phdr, mut align, mut end) = (0u64, PAGE, 0u64);
        let mut interp_path = None;
        let mut dynamic = None;
        for p in &phdrs {
            match p.kind {
                PT_LOAD => {
                    let seg = load_segment(p)?;
                    if p.align.is_power_of_two() {
                        align = align.max(p.align);
                    }
                    // AT_PHDR: where the header table's file bytes load
                    if (p.offset..p.offset + p.filesz).contains(&phoff) {
                        phdr = p.vaddr + (phoff - p.offset);
                    }
                    end = end.max(p.vaddr + p.memsz);
                    if seg.mem_size > 0 {
                        segments.push(seg);
                    }
                }
                PT_INTERP if interp_path.is_none() => interp_path = Some(interp(data, p)?),
                PT_DYNAMIC => dynamic = Some(p),
                _ => {}
            }
        }
        if segments.is_empty() {
            return Err(ElfError::NotExecutable);
        }

        let relocations = match dynamic {
            Some(d) if is_pie => relocations(data, &segments, d),
            _ => Vec::new(),
        };

        Ok(Self {
            entry,
            segments,
            is_pie,
            relocations,
            phdr,
            phent: PHDR_SIZE as u64,
            phnum: phnum as u64,
            align,
            interp: interp_path,
            end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid ET_EXEC: header, one phdr, one PT_LOAD of the file
    fn exe() -> Vec<u8> {
        let mut f = alloc::vec![0u8; 0x2000];
        f[..4].copy_from_slice(&ELF_MAGIC);
        f[4] = ELFCLASS64;
        f[5] = ELFDATA2LSB;
        f[6] = 1;
        f[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        f[18..20].copy_from_slice(&EXPECTED_EM_MACHINE.to_le_bytes());
        f[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // entry
        f[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        f[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        f[56..58].copy_from_slice(&1u16.to_le_bytes());
        set_phdr(&mut f, 0, PT_LOAD, [0, 0x400000, 0x2000, 0x3000, 0x1000]);
        f
    }

    /// Program header `i`: [offset, vaddr, filesz, memsz, align]
    fn set_phdr(f: &mut [u8], i: usize, kind: u32, v: [u64; 5]) {
        let p = 64 + i * PHDR_SIZE;
        f[p..p + 4].copy_from_slice(&kind.to_le_bytes());
        f[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        for (j, field) in [8, 16, 32, 40, 48].into_iter().enumerate() {
            f[p + field..p + field + 8].copy_from_slice(&v[j].to_le_bytes());
        }
    }

    fn err(f: &[u8]) -> Option<ElfError> {
        ElfExecutable::parse(f).err()
    }

    #[test]
    fn valid_exec() {
        let e = ElfExecutable::parse(&exe()).unwrap();
        assert_eq!(e.segments.len(), 1);
        assert_eq!(e.phdr, 0x400040);
        assert_eq!(e.end, 0x403000);
        assert!(!e.is_pie);
    }

    #[test]
    fn short_and_foreign_files_are_enoexec() {
        let f = exe();
        for n in [0, 3, 4, 20, 63] {
            assert_eq!(err(&f[..n]), Some(ElfError::NotExecutable), "len {n}");
        }
        for (i, v) in [(0, 0u8), (4, 1), (5, 2), (16, 1), (18, 3)] {
            let mut g = f.clone();
            g[i] = v;
            assert_eq!(err(&g), Some(ElfError::NotExecutable), "byte {i}");
        }
    }

    #[test]
    fn phdr_table_limits() {
        let mut f = exe();
        f[54] = 32; // e_phentsize
        assert_eq!(err(&f), Some(ElfError::NotExecutable));
        let mut f = exe();
        f[56..58].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(err(&f), Some(ElfError::NotExecutable));
        let mut f = exe();
        f[56..58].copy_from_slice(&0xffffu16.to_le_bytes());
        assert_eq!(err(&f), Some(ElfError::NotExecutable));
        let mut f = exe();
        f[32..40].copy_from_slice(&0x1fe0u64.to_le_bytes()); // past EOF
        assert_eq!(err(&f), Some(ElfError::NotExecutable));
        let mut f = exe();
        f[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(err(&f), Some(ElfError::NotExecutable));
    }

    #[test]
    fn bad_segments_are_einval() {
        let cases: [[u64; 5]; 4] = [
            [0, 0x400000, 0x3000, 0x2000, 0x1000],        // filesz > memsz
            [0, u64::MAX - 0x10, 0x1000, 0x2000, 0x1000], // vaddr + memsz overflows
            [0x10, 0x400000, 0x1000, 0x1000, 0x1000],     // offset not congruent
            [u64::MAX - 4, 0x400000, 0x1000, 0x1000, 0x1000], // offset + filesz overflows
        ];
        for v in cases {
            let mut f = exe();
            set_phdr(&mut f, 0, PT_LOAD, v);
            assert_eq!(err(&f), Some(ElfError::BadSegment), "{v:x?}");
        }
    }

    #[test]
    fn zero_size_load_and_odd_alignment() {
        let mut f = exe();
        set_phdr(&mut f, 0, PT_LOAD, [0, 0x400000, 0, 0, 3]);
        assert_eq!(err(&f), Some(ElfError::NotExecutable)); // nothing to load
        let mut f = exe();
        set_phdr(&mut f, 0, PT_LOAD, [0, 0x400000, 0x2000, 0x2000, 3]);
        assert_eq!(ElfExecutable::parse(&f).unwrap().align, PAGE);
    }

    #[test]
    fn interpreter_path() {
        let mut f = exe();
        f[56..58].copy_from_slice(&2u16.to_le_bytes());
        f[0x1000..0x100c].copy_from_slice(b"/lib/ld.so\0\0");
        set_phdr(&mut f, 1, PT_INTERP, [0x1000, 0, 11, 11, 1]);
        assert_eq!(
            ElfExecutable::parse(&f).unwrap().interp.unwrap(),
            b"/lib/ld.so"
        );
        set_phdr(&mut f, 1, PT_INTERP, [0x1000, 0, 10, 10, 1]); // unterminated
        assert_eq!(err(&f), Some(ElfError::NotExecutable));
        set_phdr(&mut f, 1, PT_INTERP, [0x1000, 0, 1, 1, 1]); // too short
        assert_eq!(err(&f), Some(ElfError::NotExecutable));
        set_phdr(&mut f, 1, PT_INTERP, [0x1ff0, 0, 0x100, 0x100, 1]); // past EOF
        assert_eq!(err(&f), Some(ElfError::Truncated));
    }

    fn seg(vaddr: u64, offset: u64, file: usize, mem: usize) -> ElfSegment {
        ElfSegment {
            vaddr,
            mem_size: mem,
            file_size: file,
            flags: SegmentFlags::from_elf_flags(4),
            offset,
        }
    }

    #[test]
    fn page_fill_stays_in_bounds() {
        // Unaligned start: first page from its offset, rest of the page
        let s = seg(0x401ff0, 0x1ff0, 0x30, 0x2000);
        assert_eq!(
            s.page_fill(0, 0x401000, 0x10000),
            Some((0xff0, 0x1ff0, 0x10))
        );
        assert_eq!(s.page_fill(0, 0x402000, 0x10000), Some((0, 0x2000, 0x20)));
        // Past the file part: bss only
        assert_eq!(s.page_fill(0, 0x403000, 0x10000), None);
        // Before the segment
        assert_eq!(s.page_fill(0, 0x400000, 0x10000), None);
        // File shorter than p_filesz: clamped to what was read
        assert_eq!(s.page_fill(0, 0x401000, 0x1ff8), Some((0xff0, 0x1ff0, 8)));
        assert_eq!(s.page_fill(0, 0x402000, 0x1ff8), None);
        // Never more than a page, whatever the sizes
        let big = seg(0x400000, 0, usize::MAX, usize::MAX);
        let (d, _, n) = big.page_fill(0, 0x400000, usize::MAX).unwrap();
        assert!(d + n <= PAGE as usize);
        // Overflowing base or offset: nothing, no panic
        assert_eq!(s.page_fill(u64::MAX, 0x401000, 0x10000), None);
        let o = seg(0x400000, u64::MAX - 2, 0x10, 0x10);
        let (_, src, n) = o.page_fill(0, 0x400000, usize::MAX).unwrap();
        assert!(src.checked_add(n).is_some());
        assert_eq!(o.page_fill(0, 0x401000, usize::MAX), None);
        assert_eq!(s.page_fill(0, u64::MAX & !0xfff, 0x10000), None);
    }

    #[test]
    fn malformed_dynamic_never_panics() {
        let mut f = exe();
        f[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        f[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (off, sz) in [(0x1ff8u64, 0x100u64), (u64::MAX, 8), (0x1000, 0x10)] {
            set_phdr(&mut f, 1, PT_DYNAMIC, [off, 0, sz, sz, 8]);
            let e = ElfExecutable::parse(&f).unwrap();
            assert!(e.relocations.is_empty());
        }
        // DT_RELA pointing anywhere, huge DT_RELASZ
        let d = 0x1000;
        f[d..d + 8].copy_from_slice(&DT_RELA.to_le_bytes());
        f[d + 8..d + 16].copy_from_slice(&0x401f00u64.to_le_bytes());
        f[d + 16..d + 24].copy_from_slice(&DT_RELASZ.to_le_bytes());
        f[d + 24..d + 32].copy_from_slice(&u64::MAX.to_le_bytes());
        set_phdr(&mut f, 1, PT_DYNAMIC, [d as u64, 0, 0x30, 0x30, 8]);
        assert!(ElfExecutable::parse(&f).unwrap().relocations.is_empty());
    }
}
