//! execve implementation
//!
//! Replaces the current process image with a new program.

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
use crate::mm::{ELF_ET_DYN_BASE, STACK_TOP};

/// Page size constant
const PAGE_SIZE: u64 = 4096;

/// Pages of user stack mapped at exec when RLIMIT_STACK is unlimited
/// (1 MB; the stack does not grow on demand yet, see BUGS.md). It was
/// 16 KB, which deep frames (signal delivery, large locals) overran.
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
fn auxv(info: &ExecInfo, random: u64, execfn: u64, platform: u64) -> [(u64, u64); 19] {
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
    let c = crate::task::current_cred();
    let secure = c.uid != c.euid || c.gid != c.egid;
    [
        (AT_HWCAP, crate::arch::elf_hwcap()),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_CLKTCK, 100),
        (AT_PHDR, info.phdr),
        (AT_PHENT, info.phent),
        (AT_PHNUM, info.phnum),
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, info.entry),
        (AT_UID, c.uid as u64),
        (AT_EUID, c.euid as u64),
        (AT_GID, c.gid as u64),
        (AT_EGID, c.egid as u64),
        (AT_SECURE, secure as u64),
        (AT_RANDOM, random),
        (AT_HWCAP2, 0),
        (AT_EXECFN, execfn),
        (AT_PLATFORM, platform),
        (AT_NULL, 0),
    ]
}

/// Map the user stack below STACK_TOP and build the initial process
/// stack (Linux layout): strings and AT_RANDOM bytes at the top, then
/// the auxiliary vector, envp, argv and argc at the 16-byte aligned
/// initial stack pointer.
///
/// Returns (initial SP, lowest mapped stack address).
fn setup_user_stack<FA: FrameAlloc<PhysAddr = u64>>(
    page_table: &mut ArchPageTable,
    frame_alloc: &mut FA,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    info: &ExecInfo,
) -> Result<(u64, u64), i32> {
    // Calculate stack pages based on RLIMIT_STACK
    let stack_limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_STACK);
    let stack_pages = if stack_limit == crate::rlimit::RLIM_INFINITY {
        USER_STACK_PAGES
    } else {
        ((stack_limit / PAGE_SIZE) as usize).clamp(USER_STACK_PAGES, MAX_STACK_PAGES)
    };
    let stack_bottom = STACK_TOP - (stack_pages as u64 * PAGE_SIZE);

    for i in 0..stack_pages {
        let va = stack_bottom + (i as u64 * PAGE_SIZE);
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

    // Everything must fit in the mapped stack, with room to run
    let strings: usize = argv.iter().chain(envp).map(|s| s.len() + 1).sum();
    let words = 1 + argv.len() + 1 + envp.len() + 1 + 2 * 19;
    let need = strings + info.execfn.len() + 64 + 16 + words * 8 + 64;
    if need > stack_pages * PAGE_SIZE as usize / 2 {
        return Err(E2BIG);
    }

    let mut w = StackWriter {
        pt: page_table,
        top: STACK_TOP - 8, // NULL end marker (Linux)
    };
    let execfn = w.push_str(info.execfn)?;
    let mut envp_addrs = Vec::with_capacity(envp.len());
    for e in envp.iter().rev() {
        envp_addrs.push(w.push_str(e)?);
    }
    envp_addrs.reverse();
    let mut argv_addrs = Vec::with_capacity(argv.len());
    for a in argv.iter().rev() {
        argv_addrs.push(w.push_str(a)?);
    }
    argv_addrs.reverse();
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

    // ARM64: the kernel wrote through the linear map; clean the data
    // cache so the user mapping sees it
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::cache;
        let mut va = sp & !(PAGE_SIZE - 1);
        while va < STACK_TOP {
            if let Some(phys) = page_table.translate(va) {
                cache::cache_clean_range(phys_to_virt(phys) as *const u8, PAGE_SIZE as usize);
            }
            va += PAGE_SIZE;
        }
    }

    Ok((sp, stack_bottom))
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

/// VMAs of a freshly loaded image: one private anonymous VMA per
/// PT_LOAD segment (pages already populated) and the stack
/// (growsdown), so mprotect/munmap/brk and /proc/<pid>/maps see them
pub fn image_vmas(
    pgd: u64,
    elf: &ElfExecutable,
    base: u64,
    stack_bottom: u64,
) -> Vec<crate::mm::Vma> {
    use crate::mm::{
        MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, VM_GROWSDOWN, Vma,
        anon_vma::AnonVma,
    };
    let anon = |start: u64, end: u64, prot: u32| {
        let mut v = Vma::new(start, end, prot, MAP_PRIVATE | MAP_ANONYMOUS);
        let av = AnonVma::new();
        av.add_vma(pgd, start, end);
        v.set_anon_vma(av);
        v
    };
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
    let mut stack = anon(stack_bottom, STACK_TOP, PROT_READ | PROT_WRITE);
    stack.flags |= VM_GROWSDOWN;
    vmas.push(stack);
    vmas
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

            // ARM64: Flush data cache for the frame we just wrote.
            // ARM's D-cache is not coherent across different virtual addresses
            // to the same physical memory. The kernel writes via identity-mapped
            // kernel VA, but user reads via user VA - these may have separate
            // cache entries. We must clean the D-cache to ensure user sees the data.
            #[cfg(target_arch = "aarch64")]
            {
                use crate::arch::aarch64::cache;
                cache::cache_clean_range(
                    crate::arch::phys_to_virt(frame) as *const u8,
                    PAGE_SIZE as usize,
                );
            }

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

                // ARM64: Clean the cache line for this relocation write
                #[cfg(target_arch = "aarch64")]
                {
                    use crate::arch::aarch64::cache;
                    cache::cache_clean_range(ptr as *const u8, 8);
                }
            }
        }
    });
}

/// The executable being loaded, read in place (Linux bprm->file and
/// elf_read): never copied whole into memory
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
    if let Err(e) = crate::task::nproc_exec_check() {
        return -e;
    }
    let pathname = &path[..];
    // Convert pathname to string for VFS lookup
    let path_str = match core::str::from_utf8(pathname) {
        Ok(s) => s,
        Err(_) => return -ENOENT,
    };

    // Open the executable file using the kernel-internal VFS function
    let file = match kernel_open_exec(path_str) {
        Ok(f) => f,
        Err(e) => return -e,
    };

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
    // Dynamically linked: no program interpreter is loaded yet (BUGS.md);
    // a missing one is ENOENT like Linux's open_exec of it
    if let Some(interp) = &elf.interp {
        let found = core::str::from_utf8(interp)
            .ok()
            .is_some_and(|p| kernel_open_exec(p).is_ok());
        return if found { -ENOEXEC } else { -ENOENT };
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
    let entry_point = elf.entry + base_addr;

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

    // Apply relocations for PIE
    if elf.is_pie {
        apply_relocations(&elf, &image, base_addr, &new_page_table);
    }

    // Set up user stack with argv, envp and the auxiliary vector
    let info = ExecInfo {
        entry: entry_point,
        phdr: if elf.phdr != 0 {
            elf.phdr + base_addr
        } else {
            0
        },
        phent: elf.phent,
        phnum: elf.phnum,
        execfn: pathname,
    };
    let (user_sp, stack_bottom) =
        match setup_user_stack(&mut new_page_table, frame_alloc, &argv, &envp, &info) {
            Ok(r) => r,
            Err(e) => return -e,
        };

    // Now we need to update the current task and switch to the new address space
    // This is the point of no return

    let tid = percpu::current_tid();

    // Private fd table without the close-on-exec descriptors
    crate::task::fdtable::exec_task_fd(tid);

    // Signal vfork completion if parent is waiting
    // Must be done before we switch address spaces since parent may be blocked
    percpu::signal_vfork_done(tid);

    // Initialize brk for the new process
    // Calculate page-aligned start_brk (end of loaded segments, rounded up)
    let start_brk = (segments_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // The new image's VMAs
    {
        let mut m = mm.lock();
        m.set_brk(start_brk);
        m.set_exe(file.dentry.full_path());
        for vma in image_vmas(mm.pgd(), &elf, base_addr, stack_bottom) {
            m.insert_vma(vma);
        }
    }

    // exec_replace_image never returns: free everything owned here first
    // (the file image alone is megabytes of heap)
    drop(elf);
    drop(file);
    drop(argv);
    drop(envp);
    drop(path);

    // Switch to the new address space and jump to user mode
    percpu::exec_replace_image(mm, entry_point, user_sp);
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

/// sys_execveat - execute a program relative to a directory file descriptor
///
/// # Arguments
/// * `dirfd` - Directory file descriptor, or AT_FDCWD for current directory
/// * `pathname` - Path to the executable (relative to dirfd, or absolute)
/// * `argv` - Pointer to null-terminated array of argument strings
/// * `envp` - Pointer to null-terminated array of environment strings
/// * `flags` - AT_EMPTY_PATH to execute dirfd itself, 0 otherwise
///
/// # Returns
/// On success, does not return (new program is executing).
/// On error, returns negative error code.
pub fn sys_execveat(dirfd: i32, pathname: u64, argv_ptr: u64, envp_ptr: u64, flags: i32) -> i64 {
    use crate::FRAME_ALLOCATOR;
    use crate::frame_alloc::FrameAllocRef;

    // For now, we only support AT_FDCWD with an absolute path
    // Relative paths need: fd table lookup, directory resolution from fd
    if dirfd != AT_FDCWD && flags & AT_EMPTY_PATH == 0 {
        // We don't support relative paths to arbitrary fds yet
        // Return ENOENT for now
        return -(ENOENT as i64);
    }

    // Copy pathname from user space
    let path = match copy_string_from_user(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };

    // For AT_FDCWD, the path must be absolute or we treat it as relative to cwd
    // Our VFS currently treats relative paths as if relative to /
    // This is a simplification

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
