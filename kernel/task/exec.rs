//! execve implementation
//!
//! Replaces the current process image with a new program.

use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use crate::arch::PageTable;
use crate::arch::{FrameAlloc, PageFlags, SchedArch, phys_to_virt};

// Architecture-specific type alias for page tables
#[cfg(target_arch = "x86_64")]
type CurrentArch = crate::arch::x86_64::X86_64Arch;
#[cfg(target_arch = "aarch64")]
type CurrentArch = crate::arch::aarch64::Aarch64Arch;

type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;
use super::percpu;
use crate::elf::ElfExecutable;
use crate::fs::{File, kernel_open_exec};
use crate::mm::{ELF_ET_DYN_BASE, MmLayout, STACK_TOP};

/// Page size constant
const PAGE_SIZE: u64 = 4096;

/// Pages of the main stack's initial VMA when RLIMIT_STACK is
/// unlimited or small (1 MB); only the pages holding the arguments are
/// mapped at exec, the rest fault in, and the VMA grows down on demand
/// up to RLIMIT_STACK (mm::expand_downwards)
const USER_STACK_PAGES: usize = 256;

/// Maximum number of pages for user stack (8MB, matching default RLIMIT_STACK)
const MAX_STACK_PAGES: usize = 2048;

/// Maximum combined size of argv + envp (128KB like Linux's MAX_ARG_STRLEN * MAX_ARG_STRINGS)
const MAX_ARG_PAGES: usize = 32;

/// Error codes for execve
pub const ENOENT: i32 = 2; // No such file or directory
pub const EACCES: i32 = 13; // Permission denied
pub const ENOEXEC: i32 = 8; // Exec format error
pub const ENOMEM: i32 = 12; // Out of memory
pub const EIO: i32 = 5; // I/O error
pub const EFAULT: i32 = 14; // Bad address
pub const E2BIG: i32 = 7; // Argument list too long
pub const EAGAIN: i32 = 11; // Try again
pub const EINVAL: i32 = 22; // Invalid argument
pub const ELOOP: i32 = 40; // Too many levels of symbolic links
pub const ELIBBAD: i32 = 80; // Accessing a corrupted shared library

/// Maximum path length (matching Linux PATH_MAX)
const PATH_MAX: usize = 4096;

/// Copy a null-terminated string from user space (through uaccess, so
/// SMAP/PAN stay enforced and a bad pointer is EFAULT, not a kernel fault)
fn copy_string_from_user(ptr: u64, max_len: usize) -> Result<Vec<u8>, i32> {
    use crate::uaccess::UaccessError;
    crate::uaccess::strndup_user_bytes::<crate::arch::Uaccess>(ptr, max_len).map_err(|e| match e {
        UaccessError::Overflow => E2BIG,
        _ => EFAULT,
    })
}

/// Copy a null-terminated array of string pointers from user space
///
/// Returns a Vec of strings, or an error.
fn copy_string_array_from_user(argv_ptr: u64, max_strings: usize) -> Result<Vec<Vec<u8>>, i32> {
    if argv_ptr == 0 {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    for i in 0..max_strings as u64 {
        let slot = argv_ptr.checked_add(i * 8).ok_or(EFAULT)?;
        let str_ptr =
            crate::uaccess::get_user::<crate::arch::Uaccess, u64>(slot).map_err(|_| EFAULT)?;
        if str_ptr == 0 {
            break;
        }
        result.push(copy_string_from_user(str_ptr, PATH_MAX)?);
    }

    Ok(result)
}

/// Calculate total size of argument/environment strings
fn total_string_bytes(strings: &[Vec<u8>]) -> usize {
    strings.iter().map(|s| s.len() + 1).sum() // +1 for null terminator
}

/// What the new image tells the program through the auxiliary vector
pub struct ExecInfo<'a> {
    /// Entry point (AT_ENTRY)
    pub entry: u64,
    /// Program headers in memory (AT_PHDR, AT_PHENT, AT_PHNUM)
    pub phdr: u64,
    pub phent: u64,
    pub phnum: u64,
    /// Path the program was executed as (AT_EXECFN)
    pub execfn: &'a [u8],
    /// Where the program interpreter was loaded (AT_BASE; 0 without one)
    pub base: u64,
}

/// Writes the initial stack image through the new page table
struct StackWriter<'a> {
    pt: &'a ArchPageTable,
    /// Next free byte below the data written so far
    top: u64,
}

impl StackWriter<'_> {
    /// Copy `data` to user address `va`
    fn write(&self, va: u64, data: &[u8]) -> Result<(), i32> {
        for (i, &b) in data.iter().enumerate() {
            let phys = self.pt.translate(va + i as u64).ok_or(EFAULT)?;
            unsafe { core::ptr::write(phys_to_virt(phys), b) };
        }
        Ok(())
    }

    /// Push bytes below the current top; their address
    fn push(&mut self, data: &[u8]) -> Result<u64, i32> {
        self.top -= data.len() as u64;
        self.write(self.top, data)?;
        Ok(self.top)
    }

    /// Push a NUL-terminated string; its address
    fn push_str(&mut self, s: &[u8]) -> Result<u64, i32> {
        self.push(&[0])?;
        self.push(s)
    }
}

/// Auxiliary vector (Linux fs/binfmt_elf.c create_elf_tables)
/// Entries of the auxiliary vector, AT_NULL included
const AUXV_LEN: usize = 20;

fn auxv(info: &ExecInfo, random: u64, execfn: u64, platform: u64) -> [(u64, u64); AUXV_LEN] {
    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_BASE: u64 = 7;
    const AT_FLAGS: u64 = 8;
    const AT_ENTRY: u64 = 9;
    const AT_UID: u64 = 11;
    const AT_EUID: u64 = 12;
    const AT_GID: u64 = 13;
    const AT_EGID: u64 = 14;
    const AT_PLATFORM: u64 = 15;
    const AT_HWCAP: u64 = 16;
    const AT_CLKTCK: u64 = 17;
    const AT_SECURE: u64 = 23;
    const AT_RANDOM: u64 = 25;
    const AT_HWCAP2: u64 = 26;
    const AT_EXECFN: u64 = 31;
    const AT_MINSIGSTKSZ: u64 = 51;
    let c = crate::task::current_cred();
    let secure = secureexec(&c);
    [
        (AT_HWCAP, crate::arch::elf_hwcap()),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_CLKTCK, 100),
        (AT_PHDR, info.phdr),
        (AT_PHENT, info.phent),
        (AT_PHNUM, info.phnum),
        (AT_BASE, info.base),
        (AT_FLAGS, 0),
        (AT_ENTRY, info.entry),
        (AT_UID, c.uid as u64),
        (AT_EUID, c.euid as u64),
        (AT_GID, c.gid as u64),
        (AT_EGID, c.egid as u64),
        (AT_SECURE, secure as u64),
        (AT_RANDOM, random),
        (AT_HWCAP2, crate::arch::elf_hwcap2()),
        (AT_EXECFN, execfn),
        (AT_MINSIGSTKSZ, crate::arch::min_sigstksz()),
        (AT_PLATFORM, platform),
        (AT_NULL, 0),
    ]
}

/// Map the user stack below STACK_TOP and build the initial process
/// stack (Linux layout): strings and AT_RANDOM bytes at the top, then
/// the auxiliary vector, envp, argv and argc at the 16-byte aligned
/// initial stack pointer.
///
/// Returns (where argv, envp and the SP went, lowest mapped stack
/// address).
fn setup_user_stack<FA: FrameAlloc<PhysAddr = u64>>(
    page_table: &mut ArchPageTable,
    frame_alloc: &mut FA,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    info: &ExecInfo,
) -> Result<(MmLayout, u64), i32> {
    // Calculate stack pages based on RLIMIT_STACK
    let stack_limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_STACK);
    let stack_pages = if stack_limit == crate::rlimit::RLIM_INFINITY {
        USER_STACK_PAGES
    } else {
        ((stack_limit / PAGE_SIZE) as usize).clamp(USER_STACK_PAGES, MAX_STACK_PAGES)
    };
    // Everything must fit in the stack, with room to run
    let strings: usize = argv.iter().chain(envp).map(|s| s.len() + 1).sum();
    let words = 1 + argv.len() + 1 + envp.len() + 1 + 2 * AUXV_LEN;
    let need = strings + info.execfn.len() + 64 + 16 + words * 8 + 64;
    if need > stack_pages * PAGE_SIZE as usize / 2 {
        return Err(E2BIG);
    }

    // Map only what the arguments use (Linux setup_arg_pages: the rest
    // of the stack VMA faults in on first touch)
    let mapped = need.div_ceil(PAGE_SIZE as usize) + 1;
    let map_bottom = STACK_TOP - (mapped as u64 * PAGE_SIZE);
    for i in 0..mapped {
        let va = map_bottom + (i as u64 * PAGE_SIZE);
        let frame = user_frame()?;
        unsafe {
            ::core::ptr::write_bytes(crate::arch::phys_to_virt(frame), 0, PAGE_SIZE as usize);
        }
        let flags = PageFlags::READ | PageFlags::WRITE | PageFlags::USER;
        if page_table
            .map_with_alloc(va, frame, flags, frame_alloc)
            .is_err()
        {
            crate::FRAME_ALLOCATOR.free(frame);
            return Err(ENOMEM);
        }
    }

    let mut w = StackWriter {
        pt: page_table,
        top: STACK_TOP - 8, // NULL end marker (Linux)
    };
    let execfn = w.push_str(info.execfn)?;
    // argv then envp strings, back to back (Linux arg_start..env_end)
    let env_end = w.top;
    let mut envp_addrs = Vec::with_capacity(envp.len());
    for e in envp.iter().rev() {
        envp_addrs.push(w.push_str(e)?);
    }
    envp_addrs.reverse();
    let env_start = w.top;
    let mut argv_addrs = Vec::with_capacity(argv.len());
    for a in argv.iter().rev() {
        argv_addrs.push(w.push_str(a)?);
    }
    argv_addrs.reverse();
    let arg_start = w.top;
    let platform = w.push_str(crate::arch::ELF_PLATFORM)?;
    let mut rnd = [0u8; 16];
    let _ = crate::random::get_random_bytes(&mut rnd, 0);
    w.top &= !15;
    let random = w.push(&rnd)?;

    // argc, argv[], NULL, envp[], NULL, auxv pairs
    let mut v: Vec<u64> = Vec::with_capacity(words);
    v.push(argv.len() as u64);
    v.extend_from_slice(&argv_addrs);
    v.push(0);
    v.extend_from_slice(&envp_addrs);
    v.push(0);
    for (k, val) in auxv(info, random, execfn, platform) {
        v.push(k);
        v.push(val);
    }
    let sp = (w.top - v.len() as u64 * 8) & !15;
    let bytes: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    w.write(sp, &bytes)?;

    // The kernel wrote through the linear map (arm64: clean the data
    // cache for the user mapping)
    let mut va = sp & !(PAGE_SIZE - 1);
    while va < STACK_TOP {
        if let Some(phys) = page_table.translate(va) {
            crate::arch::paging::sync_page(phys & !(PAGE_SIZE - 1), false);
        }
        va += PAGE_SIZE;
    }

    let area = MmLayout {
        arg_start,
        arg_end: env_start,
        env_start,
        env_end,
        start_stack: sp,
        ..MmLayout::default()
    };
    Ok((area, STACK_TOP - (stack_pages as u64 * PAGE_SIZE)))
}

/// Every PT_LOAD segment and the entry point must land in mappable
/// user space: past TASK_SIZE (or overflowing) is EINVAL (Linux
/// BAD_ADDR), below mmap_min_addr EPERM (security_mmap_addr)
fn check_segments(elf: &ElfExecutable, base: u64) -> Result<(), i32> {
    const EINVAL: i32 = 22;
    for seg in &elf.segments {
        let va = seg.vaddr.checked_add(base).ok_or(EINVAL)?;
        let end = va.checked_add(seg.mem_size as u64).ok_or(EINVAL)?;
        if end > crate::mm::TASK_SIZE {
            return Err(EINVAL);
        }
        let start = va & !(PAGE_SIZE - 1);
        crate::mm::check_fixed(start, end - start).map_err(|e| e.errno())?;
    }
    if elf
        .entry
        .checked_add(base)
        .is_none_or(|e| e >= crate::mm::TASK_SIZE)
    {
        return Err(EINVAL);
    }
    // Segments are populated at exec: an image larger than free memory
    // is ENOMEM up front, not after exhausting it
    let pages: u64 = elf
        .segments
        .iter()
        .map(|s| (s.mem_size as u64).div_ceil(PAGE_SIZE) + 1)
        .sum();
    if pages > crate::FRAME_ALLOCATOR.free_frames() as u64 {
        return Err(ENOMEM);
    }
    Ok(())
}

/// Code and data bounds of an image loaded `base` higher (Linux
/// load_elf_binary): code spans the executable segments' file bytes;
/// data runs from the highest segment start to the highest file end
pub fn image_layout(elf: &ElfExecutable, base: u64) -> MmLayout {
    let mut l = MmLayout {
        start_code: u64::MAX,
        ..MmLayout::default()
    };
    for seg in &elf.segments {
        let end = seg.vaddr + seg.file_size as u64;
        if seg.flags.execute {
            l.start_code = l.start_code.min(seg.vaddr);
            l.end_code = l.end_code.max(end);
        }
        l.start_data = l.start_data.max(seg.vaddr);
        l.end_data = l.end_data.max(end);
    }
    if l.start_code == u64::MAX {
        l.start_code = 0;
    }
    for x in [
        &mut l.start_code,
        &mut l.end_code,
        &mut l.start_data,
        &mut l.end_data,
    ] {
        *x += base;
    }
    l
}

/// VMAs of a freshly loaded image: one private anonymous VMA per
/// PT_LOAD segment (pages already populated) and the stack
/// (growsdown), so mprotect/munmap/brk and /proc/<pid>/maps see them
pub fn image_vmas(elf: &ElfExecutable, base: u64, stack_bottom: u64) -> Vec<crate::mm::Vma> {
    use crate::mm::{PROT_READ, PROT_WRITE, VM_GROWSDOWN};
    let mut vmas = segment_vmas(elf, base);
    let mut stack = anon_vma(stack_bottom, STACK_TOP, PROT_READ | PROT_WRITE);
    stack.flags |= VM_GROWSDOWN;
    vmas.push(stack);
    vmas
}

fn anon_vma(start: u64, end: u64, prot: u32) -> crate::mm::Vma {
    use crate::mm::{MAP_ANONYMOUS, MAP_PRIVATE, Vma, anon_vma::AnonVma};
    Vma::new_anon(
        start,
        end,
        prot,
        MAP_PRIVATE | MAP_ANONYMOUS,
        AnonVma::new(),
    )
}

/// One VMA per loaded segment of `elf` at `base`
fn segment_vmas(elf: &ElfExecutable, base: u64) -> Vec<crate::mm::Vma> {
    use crate::mm::{PROT_EXEC, PROT_READ, PROT_WRITE, Vma};
    let anon = anon_vma;
    let mut vmas: Vec<Vma> = Vec::new();
    let mut prev_end = 0;
    for seg in elf.segments.iter().filter(|s| s.mem_size > 0) {
        // A page shared with the previous segment stays in its VMA
        let start = ((seg.vaddr + base) & !(PAGE_SIZE - 1)).max(prev_end);
        let end = (seg.vaddr + base + seg.mem_size as u64).next_multiple_of(PAGE_SIZE);
        if start >= end {
            continue;
        }
        let f = &seg.flags;
        let prot = (f.read as u32 * PROT_READ)
            | (f.write as u32 * PROT_WRITE)
            | (f.execute as u32 * PROT_EXEC);
        vmas.push(anon(start, end, prot));
        prev_end = end;
    }
    vmas
}

/// Where a program interpreter goes (Linux load_elf_interp: the first
/// free area below mmap_base big enough for all its segments, at their
/// alignment); an ET_EXEC interpreter at its link address
fn interp_base(elf: &ElfExecutable) -> u64 {
    if !elf.is_pie {
        return 0;
    }
    let segs = elf.segments.iter().filter(|s| s.mem_size > 0);
    let lo = segs.clone().map(|s| s.vaddr).min().unwrap_or(0) & !(PAGE_SIZE - 1);
    let hi = segs
        .map(|s| s.vaddr + s.mem_size as u64)
        .max()
        .unwrap_or(0)
        .next_multiple_of(PAGE_SIZE);
    let align = elf.align.max(PAGE_SIZE);
    ((crate::mm::mmap_base() - (hi - lo)) & !(align - 1)) - lo
}

/// Load ELF segments into a page table
///
/// Returns the end address of the highest loaded segment (for setting brk).
fn load_elf_segments<FA: FrameAlloc<PhysAddr = u64>>(
    elf: &ElfExecutable,
    image: &FileImage,
    page_table: &mut ArchPageTable,
    frame_alloc: &mut FA,
    base_addr: u64,
) -> Result<u64, i32> {
    let mut highest_end: u64 = 0;

    for segment in &elf.segments {
        if segment.mem_size == 0 {
            continue;
        }

        let seg_start = segment.vaddr + base_addr;
        let seg_end = seg_start + segment.mem_size as u64;
        let page_start = seg_start & !(PAGE_SIZE - 1);
        let page_end = (seg_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Track the highest segment end for brk initialization
        if seg_end > highest_end {
            highest_end = seg_end;
        }

        // Convert ELF flags to PageFlags
        let mut flags = PageFlags::READ | PageFlags::USER;
        if segment.flags.write {
            flags |= PageFlags::WRITE;
        }
        if segment.flags.execute {
            flags |= PageFlags::EXECUTE;
        }

        let mut va = page_start;
        while va < page_end {
            // A page shared with the previous segment is filled in place
            let mapped = page_table.translate(va).map(|p| p & !(PAGE_SIZE - 1));
            let frame = match mapped {
                Some(f) => f,
                None => user_frame()?,
            };

            // Zero a new frame first (for BSS and partial pages)
            if mapped.is_none() {
                unsafe {
                    ::core::ptr::write_bytes(
                        crate::arch::phys_to_virt(frame),
                        0,
                        PAGE_SIZE as usize,
                    );
                }
            }

            // File bytes for this page, bounds-checked against the page,
            // the segment and the file (elf::ElfSegment::page_fill), read
            // straight into the frame (Linux maps the file instead)
            let size = usize::try_from(image.size).unwrap_or(usize::MAX);
            if let Some((dst, src, len)) = segment.page_fill(base_addr, va, size) {
                // SAFETY: our frame, reached through the direct map
                let page = unsafe {
                    core::slice::from_raw_parts_mut(
                        crate::arch::phys_to_virt(frame),
                        PAGE_SIZE as usize,
                    )
                };
                if let Err(e) = image.read_into(&mut page[dst..dst + len], src as u64) {
                    if mapped.is_none() {
                        crate::FRAME_ALLOCATOR.free(frame);
                    }
                    return Err(e);
                }
            }

            // The kernel wrote it: code reaches the instruction caches
            // (arm64; Linux __sync_icache_dcache on the exec mapping)
            crate::arch::paging::sync_page(frame, segment.flags.execute);

            // Map the page (once mapped, the address space frees it)
            if mapped.is_none()
                && page_table
                    .map_with_alloc(va, frame, flags, frame_alloc)
                    .is_err()
            {
                crate::FRAME_ALLOCATOR.free(frame);
                return Err(ENOMEM);
            }

            va += PAGE_SIZE;
        }
    }

    Ok(highest_end)
}

/// Apply ELF relocations for PIE binaries
fn apply_relocations(
    elf: &ElfExecutable,
    image: &FileImage,
    base_addr: u64,
    page_table: &ArchPageTable,
) {
    elf.for_each_relocation(image, &mut |reloc| {
        // The 8-byte store must stay inside one user page of the image:
        // an unaligned or wrapping offset from a crafted file is skipped
        let Some(target_vaddr) = base_addr.checked_add(reloc.offset) else {
            return;
        };
        if !target_vaddr.is_multiple_of(8) || target_vaddr >= crate::mm::TASK_SIZE {
            return;
        }
        let value = (base_addr as i64).wrapping_add(reloc.addend) as u64;

        if let Some(phys) = page_table.translate(target_vaddr) {
            unsafe {
                let ptr = phys_to_virt(phys) as *mut u64;
                core::ptr::write_volatile(ptr, value);
            }
            // Text relocations land in code
            crate::arch::paging::sync_icache(phys, 8);
        }
    });
}

/// The executable being loaded, read in place (Linux bprm->file and
/// elf_read): never copied whole into memory
/// Follow `#!` lines from the opened file to the program that runs
/// (Linux exec_binprm with binfmt_script): each script level puts its
/// interpreter (and argument) in front of argv and opens it; more than
/// MAX_DEPTH levels is ELOOP. A script named through a close-on-exec fd
/// (execveat) cannot be reopened by its interpreter: ENOENT.
fn resolve_scripts(
    mut file: Arc<File>,
    mut argv: Vec<Vec<u8>>,
    path: &[u8],
    path_inaccessible: bool,
) -> Result<(Arc<File>, Vec<Vec<u8>>), i32> {
    use crate::binfmt_script::{BINPRM_BUF_SIZE, MAX_DEPTH, parse, rewrite_argv};
    let mut name = path.to_vec();
    for depth in 0.. {
        let head = {
            let image = FileImage::new(&file)?;
            let n = (image.size as usize).min(BINPRM_BUF_SIZE);
            crate::elf::ElfSource::read_at(&image, 0, n).ok_or(EIO)?
        };
        let (interp, arg) = match parse(&head) {
            None => break,
            Some(r) => r?,
        };
        if depth >= MAX_DEPTH {
            return Err(ELOOP);
        }
        if path_inaccessible {
            return Err(ENOENT);
        }
        argv = rewrite_argv(&argv, interp, arg, &name);
        name = interp.to_vec();
        let p = core::str::from_utf8(interp).map_err(|_| ENOENT)?;
        file = kernel_open_exec(p)?;
    }
    Ok((file, argv))
}

struct FileImage<'a> {
    file: &'a File,
    /// Size when exec opened it (segments past it read as zeros)
    size: u64,
}

impl FileImage<'_> {
    fn new(file: &File) -> Result<FileImage<'_>, i32> {
        let size = file.get_inode().ok_or(ENOENT)?.get_size();
        if size == 0 {
            return Err(ENOEXEC); // Empty file can't be executable
        }
        Ok(FileImage { file, size })
    }

    /// Fill `buf` from offset `off`; the bytes read (fewer at the end
    /// of the file)
    fn read_into(&self, buf: &mut [u8], off: u64) -> Result<usize, i32> {
        let mut done = 0;
        while done < buf.len() {
            let n = self
                .file
                .pread(&mut buf[done..], off + done as u64)
                .map_err(|_| EIO)?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}

impl crate::elf::ElfSource for FileImage<'_> {
    fn read_at(&self, off: u64, len: usize) -> Option<Vec<u8>> {
        let mut v = alloc::vec![0u8; len];
        (self.read_into(&mut v, off).ok()? == len).then_some(v)
    }
}

/// A frame for the new image's user memory: stops at the kernel's
/// reserve like any user page (`mm::fault::alloc_user`), ENOMEM then
fn user_frame() -> Result<u64, i32> {
    crate::mm::fault::alloc_user().ok_or(ENOMEM)
}

/// The new image runs with privileges its caller lacks (Linux
/// bprm->secureexec, AT_SECURE): hk exec keeps the credentials (no
/// set-id or file capabilities yet, BUGS.md), so this is effective ids
/// differing from the real ones
fn secureexec(c: &crate::task::Cred) -> bool {
    c.uid != c.euid || c.gid != c.egid
}

/// Name and dumpability a new image gets (Linux begin_new_exec sets
/// them after exec_mmap, under cred_guard_mutex)
pub struct ExecIdentity {
    pub name: [u8; 16],
    pub dumpable: u8,
}

/// The new image's identity, decided before the point of no return and
/// applied by `exec_replace_image` with the new mm: comm is the file
/// name's last component (at most 15 bytes); the task is non-dumpable
/// (suid_dumpable 0) for a secure exec or an image the caller may not
/// read (would_dump: BINPRM_FLAGS_ENFORCE_NONDUMP, so an execute-only
/// binary cannot be read through ptrace or /proc), else dumpable
fn exec_identity(path: &[u8], file: &File) -> ExecIdentity {
    use super::dumpable::{SUID_DUMP_DISABLE, SUID_DUMP_USER};
    let base = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    let mut name = [0u8; 16];
    let n = base.len().min(15);
    name[..n].copy_from_slice(&base[..n]);
    let readable = file
        .get_inode()
        .is_some_and(|i| crate::fs::dac::permission(&i, crate::fs::MAY_READ).is_ok());
    let c = crate::task::current_cred();
    let dumpable = if readable && !secureexec(&c) {
        SUID_DUMP_USER
    } else {
        SUID_DUMP_DISABLE
    };
    ExecIdentity { name, dumpable }
}

/// End the other threads of the caller's group and wait until they
/// have exited (Linux de_thread); a non-leader caller then takes the
/// leader's place. EAGAIN if the group is exiting, or a fatal signal
/// arrives meanwhile (the caller then dies on its way out). Threads
/// running user code end at their next syscall or fault (P7: IRQ
/// return).
fn de_thread(tid: crate::task::Tid) -> Result<(), i32> {
    use crate::task::percpu::{SleepState, schedule};
    use crate::waitqueue::WaitEntry;

    let tgid = percpu::current_pid();
    let Some(sig) = crate::signal::get_task_signal_struct(tid) else {
        return Ok(());
    };
    if percpu::group_others(tgid, tid) {
        if !sig.start_exec(tid) {
            return Err(EAGAIN);
        }
        crate::signal::zap_group_others(tgid, tid);
        let wq = &crate::task::proc::CHILD_EXIT_WQ;
        let w = core::pin::pin!(WaitEntry::new());
        let r = loop {
            wq.prepare_to_wait(w.as_ref(), SleepState::Killable);
            if !percpu::group_others(tgid, tid) {
                break Ok(());
            }
            if crate::signal::fatal_signal_pending() {
                break Err(EAGAIN);
            }
            schedule();
        };
        wq.finish_wait(w.as_ref());
        sig.end_exec(tid);
        r?;
    }
    // Released after TASKLIST: the old leader and exited threads
    drop(percpu::take_leadership(tgid, tid));
    Ok(())
}

/// Execute a new program, replacing the current process image
///
/// This is the core of execve. It:
/// 1. Reads the executable file
/// 2. Parses the ELF
/// 3. Creates a new address space
/// 4. Loads the program
/// 5. Sets up the stack with argv/envp
/// 6. Updates the current task
///
/// On success, this function never returns - it jumps to the new program.
/// On error, it returns the error code and the process continues.
pub fn do_execve<FA: FrameAlloc<PhysAddr = u64>>(
    path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    frame_alloc: &mut FA,
) -> i32 {
    let open = |p: &[u8]| match core::str::from_utf8(p) {
        Ok(s) => kernel_open_exec(s),
        Err(_) => Err(ENOENT),
    };
    exec_file(path, open, false, argv, envp, frame_alloc)
}

/// do_execve with the file opened by `open` from the name (Linux
/// bprm->filename: the path, or /dev/fd/N[/path] for execveat), once
/// the credential guard is held
fn exec_file<FA, F>(
    path: Vec<u8>,
    open: F,
    path_inaccessible: bool,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    frame_alloc: &mut FA,
) -> i32
where
    FA: FrameAlloc<PhysAddr = u64>,
    F: FnOnce(&[u8]) -> Result<Arc<File>, i32>,
{
    // Linux prepare_bprm_creds: the thread group's cred_guard_mutex from
    // the first credential check until the new image is in place, so
    // ptrace attach and mm_access never see the new mm with the old
    // dumpability or the reverse; dropped on every error return
    let guard = crate::signal::CredGuard::lock(percpu::current_tid());
    if let Err(e) = crate::task::nproc_exec_check() {
        return -e;
    }
    let pathname = &path[..];
    let file = match open(pathname) {
        Ok(f) => f,
        Err(e) => return -e,
    };
    let (file, argv) = match resolve_scripts(file, argv, pathname, path_inaccessible) {
        Ok(r) => r,
        Err(e) => return -e,
    };
    // To the least loaded CPU while the footprint is small (Linux
    // bprm_execve -> sched_exec)
    percpu::sched_exec();

    // The file is read where needed: headers now, segments as they load
    let image = match FileImage::new(&file) {
        Ok(i) => i,
        Err(e) => return -e,
    };

    // Parse ELF
    let elf = match ElfExecutable::parse(&image) {
        Ok(e) => e,
        Err(e) => return -e.errno(),
    };
    // Dynamically linked: the program interpreter (Linux
    // load_elf_binary): ENOENT if missing (open_exec), ELIBBAD if it is
    // not an ELF file for this machine
    let interp_file = match &elf.interp {
        Some(i) => match core::str::from_utf8(i)
            .map_err(|_| ENOENT)
            .and_then(kernel_open_exec)
        {
            Ok(f) => Some(f),
            Err(e) => return -e,
        },
        None => None,
    };
    let interp_image = match interp_file.as_deref().map(FileImage::new).transpose() {
        Ok(i) => i,
        Err(_) => return -ELIBBAD,
    };
    let interp = match interp_image.as_ref().map(ElfExecutable::parse).transpose() {
        Ok(i) => i,
        Err(_) => return -ELIBBAD,
    };
    let interp_base = interp.as_ref().map_or(0, interp_base);
    if let Some(ie) = &interp
        && let Err(e) = check_segments(ie, interp_base)
    {
        return -e;
    }

    // Release all POSIX advisory locks (POSIX semantics: locks released on exec)
    crate::fs::posix_lock::release_all_posix_locks_for_pid(crate::task::percpu::current_pid());

    // PIE images load at ELF_ET_DYN_BASE (aligned to their segments),
    // ET_EXEC at their link address
    let base_addr = if elf.is_pie {
        ELF_ET_DYN_BASE & !(elf.align.max(PAGE_SIZE) - 1)
    } else {
        0
    };
    if let Err(e) = check_segments(&elf, base_addr) {
        return -e;
    }
    // With an interpreter the program starts there; it finds the
    // program's own entry in AT_ENTRY
    let entry_point = match &interp {
        Some(ie) => ie.entry + interp_base,
        None => elf.entry + base_addr,
    };

    // Create new page table for the process
    let mut new_page_table = match ArchPageTable::new_user(frame_alloc) {
        Some(pt) => pt,
        None => return -ENOMEM,
    };

    // Link the kernel half (x86; arm64 keeps the kernel in TTBR1)
    new_page_table.copy_kernel_mappings();

    // The new address space owns the table from here: an error below
    // drops it, freeing whatever was loaded (Linux bprm->mm)
    let mm = crate::mm::mm_alloc(new_page_table.root_table_phys());

    // Load ELF segments and get the end address for brk initialization
    let segments_end =
        match load_elf_segments(&elf, &image, &mut new_page_table, frame_alloc, base_addr) {
            Ok(end) => end,
            Err(e) => return -e,
        };

    if let (Some(ie), Some(iimg)) = (&interp, &interp_image)
        && let Err(e) = load_elf_segments(ie, iimg, &mut new_page_table, frame_alloc, interp_base)
    {
        return -e;
    }

    // A static PIE's relocations (hk's boot programs need them; glibc's
    // relocate themselves, idempotently). Never with an interpreter: it
    // relocates itself and the program (Linux applies none at all).
    if elf.is_pie && interp.is_none() {
        apply_relocations(&elf, &image, base_addr, &new_page_table);
    }

    // Set up user stack with argv, envp and the auxiliary vector
    let info = ExecInfo {
        entry: elf.entry + base_addr,
        base: interp_base,
        phdr: if elf.phdr != 0 {
            elf.phdr + base_addr
        } else {
            0
        },
        phent: elf.phent,
        phnum: elf.phnum,
        execfn: pathname,
    };
    let (args, stack_bottom) =
        match setup_user_stack(&mut new_page_table, frame_alloc, &argv, &envp, &info) {
            Ok(r) => r,
            Err(e) => return -e,
        };
    let user_sp = args.start_stack;

    let ident = exec_identity(pathname, &file);

    let tid = percpu::current_tid();

    // The other threads end before the new image starts (Linux
    // begin_new_exec -> de_thread)
    if let Err(e) = de_thread(tid) {
        return -e;
    }

    // Now we need to update the current task and switch to the new address space
    // This is the point of no return

    // Private fd table without the close-on-exec descriptors
    crate::task::fdtable::exec_task_fd(percpu::current_tid());

    // Signal vfork completion if parent is waiting
    // Must be done before we switch address spaces since parent may be blocked
    percpu::signal_vfork_done();

    // Initialize brk for the new process
    // Calculate page-aligned start_brk (end of loaded segments, rounded up)
    let start_brk = (segments_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // The new image's VMAs
    {
        let mut m = mm.mmap_write();
        m.set_brk(start_brk);
        m.set_exe(file.dentry.full_path());
        let code = image_layout(&elf, base_addr);
        m.set_args(MmLayout {
            start_code: code.start_code,
            end_code: code.end_code,
            start_data: code.start_data,
            end_data: code.end_data,
            ..args
        });
        for vma in image_vmas(&elf, base_addr, stack_bottom) {
            m.insert_vma(vma);
        }
        if let Some(ie) = &interp {
            for vma in segment_vmas(ie, interp_base) {
                m.insert_vma(vma);
            }
        }
    }

    // exec_replace_image never returns: free everything owned here first
    // (the file image alone is megabytes of heap)
    drop(elf);
    drop(interp);
    drop(interp_file);
    drop(file);
    drop(argv);
    drop(envp);
    drop(path);

    // Switch to the new address space and jump to user mode
    percpu::exec_replace_image(mm, entry_point, user_sp, ident, guard);
}

/// sys_execve - execute a program
///
/// # Arguments
/// * `pathname` - Path to the executable
/// * `argv` - Pointer to null-terminated array of argument strings
/// * `envp` - Pointer to null-terminated array of environment strings
///
/// # Returns
/// On success, does not return (new program is executing).
/// On error, returns negative error code.
pub fn sys_execve(pathname: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
    use crate::FRAME_ALLOCATOR;
    use crate::frame_alloc::FrameAllocRef;

    // Copy pathname from user space
    let path = match copy_string_from_user(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };

    // Copy argv from user space
    let argv = match copy_string_array_from_user(argv_ptr, 1024) {
        Ok(a) => a,
        Err(e) => return -(e as i64),
    };

    // Copy envp from user space
    let envp = match copy_string_array_from_user(envp_ptr, 1024) {
        Ok(e) => e,
        Err(e) => return -(e as i64),
    };

    // Check total size of arguments
    let total_bytes = total_string_bytes(&argv) + total_string_bytes(&envp);
    if total_bytes > MAX_ARG_PAGES * PAGE_SIZE as usize {
        return -(E2BIG as i64);
    }

    // Get frame allocator
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);

    // Do the exec - on success this never returns, on error returns negative errno
    let result = do_execve(path, argv, envp, &mut frame_alloc);
    // If we get here, exec failed - result is already negative
    result as i64
}

/// AT_FDCWD - special value meaning current working directory
pub const AT_FDCWD: i32 = -100;

/// AT_EMPTY_PATH - path is empty, use the fd directly
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// AT_SYMLINK_NOFOLLOW - a final symlink is not followed (ELOOP)
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// sys_execveat - execute a program relative to a directory file descriptor
/// (Linux do_execveat_common)
///
/// A relative `pathname` is resolved from `dirfd` (AT_FDCWD: the current
/// directory); an empty one with AT_EMPTY_PATH executes dirfd's own file
/// (fexecve); AT_SYMLINK_NOFOLLOW makes a final symlink ELOOP. Other
/// flags are EINVAL. The program's name (AT_EXECFN, comm) is the path,
/// or "/dev/fd/N" / "/dev/fd/N/path" when it came through dirfd.
///
/// # Returns
/// On success, does not return (new program is executing).
/// On error, returns negative error code.
pub fn sys_execveat(dirfd: i32, pathname: u64, argv_ptr: u64, envp_ptr: u64, flags: i32) -> i64 {
    use crate::FRAME_ALLOCATOR;
    use crate::frame_alloc::FrameAllocRef;

    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
        return -(EINVAL as i64);
    }
    let path = match copy_string_from_user(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    let argv = match copy_string_array_from_user(argv_ptr, 1024) {
        Ok(a) => a,
        Err(e) => return -(e as i64),
    };
    let envp = match copy_string_array_from_user(envp_ptr, 1024) {
        Ok(e) => e,
        Err(e) => return -(e as i64),
    };
    let total_bytes = total_string_bytes(&argv) + total_string_bytes(&envp);
    if total_bytes > MAX_ARG_PAGES * PAGE_SIZE as usize {
        return -(E2BIG as i64);
    }
    let name = exec_name(dirfd, &path);
    // Linux BINPRM_FLAGS_PATH_INACCESSIBLE: the program came through a
    // close-on-exec fd, so a script's interpreter could not open it
    let via_fd = dirfd != AT_FDCWD && path.first() != Some(&b'/');
    let inaccessible = via_fd
        && crate::fs::syscall::current_fd_table()
            .lock()
            .get_fd_flags(dirfd)
            & crate::pipe::FD_CLOEXEC
            != 0;
    let open = |_: &[u8]| exec_lookup(dirfd, &path, flags).and_then(crate::fs::open_exec);
    let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);
    exec_file(name, open, inaccessible, argv, envp, &mut frame_alloc) as i64
}

/// bprm->filename for execveat: the path itself when absolute or from
/// the current directory, else "/dev/fd/N" with "/path" if not empty
fn exec_name(dirfd: i32, path: &[u8]) -> Vec<u8> {
    if dirfd == AT_FDCWD || path.first() == Some(&b'/') {
        return path.to_vec();
    }
    let mut name = alloc::format!("/dev/fd/{dirfd}").into_bytes();
    if !path.is_empty() {
        name.push(b'/');
        name.extend_from_slice(path);
    }
    name
}

/// The dentry execveat runs: `path` from dirfd (or the current
/// directory, or the root if absolute), or with AT_EMPTY_PATH and an
/// empty path dirfd's own file
fn exec_lookup(dirfd: i32, path: &[u8], flags: i32) -> Result<Arc<crate::fs::Dentry>, i32> {
    use crate::fs::path::{LookupFlags, lookup_path_at};
    use crate::fs::path_ref::Path;
    use crate::fs::syscall::current_fd_table;
    let fd_file = || {
        current_fd_table()
            .lock()
            .get(dirfd)
            .ok_or(crate::error::KernelError::BadFd as i32)
    };
    if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        if dirfd == AT_FDCWD {
            return percpu::current_cwd()
                .map(|p| p.dentry.clone())
                .ok_or(ENOENT);
        }
        return Ok(fd_file()?.dentry.clone());
    }
    let path = core::str::from_utf8(path).map_err(|_| ENOENT)?;
    let start = if path.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        percpu::current_cwd()
    } else {
        let file = fd_file()?;
        if !file.is_dir() {
            return Err(crate::error::KernelError::NotDirectory as i32);
        }
        Path::from_dentry(file.dentry.clone())
    };
    let mut lf = LookupFlags::open();
    lf.follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    lookup_path_at(start, path, lf).map_err(|e| e as i32)
}
