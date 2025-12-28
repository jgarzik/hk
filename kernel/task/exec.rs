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

/// Page size constant
const PAGE_SIZE: u64 = 4096;

/// User stack virtual address (near top of user space, below canonical hole)
const USER_STACK_TOP: u64 = 0x7FFF_FFFF_F000;

/// Default number of pages for user stack (16KB)
/// This is used if RLIMIT_STACK is larger or infinite.
const USER_STACK_PAGES: usize = 4;

/// Maximum number of pages for user stack (8MB, matching default RLIMIT_STACK)
const MAX_STACK_PAGES: usize = 2048;

/// Base address for loading PIE (position-independent) executables
/// On aarch64, kernel identity maps 0-2GB, so PIE base must be above 2GB.
/// On x86_64, this can be lower, but 2GB is safe for both.
const USER_PIE_BASE: u64 = 0x8000_0000; // 2GB

/// Maximum combined size of argv + envp (128KB like Linux's MAX_ARG_STRLEN * MAX_ARG_STRINGS)
const MAX_ARG_PAGES: usize = 32;

/// Error codes for execve
pub const ENOENT: i32 = 2; // No such file or directory
pub const EACCES: i32 = 13; // Permission denied
pub const ENOEXEC: i32 = 8; // Exec format error
pub const ENOMEM: i32 = 12; // Out of memory
pub const EFAULT: i32 = 14; // Bad address
pub const E2BIG: i32 = 7; // Argument list too long

/// Maximum path length (matching Linux PATH_MAX)
const PATH_MAX: usize = 4096;

/// Copy a null-terminated string from user space
///
/// Returns the string as a Vec<u8> (not including the null terminator)
/// or an error if the string is invalid or too long.
unsafe fn copy_string_from_user(ptr: u64, max_len: usize) -> Result<Vec<u8>, i32> {
    if ptr == 0 {
        return Err(EFAULT);
    }

    let mut result = Vec::new();
    let mut p = ptr as *const u8;

    for _ in 0..max_len {
        let byte = unsafe { *p };
        if byte == 0 {
            return Ok(result);
        }
        result.push(byte);
        p = unsafe { p.add(1) };
    }

    // String too long
    Err(E2BIG)
}

/// Copy a null-terminated array of string pointers from user space
///
/// Returns a Vec of strings, or an error.
unsafe fn copy_string_array_from_user(
    argv_ptr: u64,
    max_strings: usize,
) -> Result<Vec<Vec<u8>>, i32> {
    if argv_ptr == 0 {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    let mut pp = argv_ptr as *const u64;

    for _ in 0..max_strings {
        let str_ptr = unsafe { *pp };
        if str_ptr == 0 {
            break;
        }

        let s = unsafe { copy_string_from_user(str_ptr, PATH_MAX)? };
        result.push(s);
        pp = unsafe { pp.add(1) };
    }

    Ok(result)
}

/// Calculate total size of argument/environment strings
fn total_string_bytes(strings: &[Vec<u8>]) -> usize {
    strings.iter().map(|s| s.len() + 1).sum() // +1 for null terminator
}

/// Set up the user stack with argc, argv, envp, and auxv
///
/// Stack layout (growing down, addresses decrease):
///
/// High addresses (stack top)
/// ```
///   [padding for alignment]
///   [environment strings]
///   [argument strings]
///   [auxv entries] (16 bytes each: type, value)
///   [NULL] (end of envp)
///   [envp[n-1] pointer]
///   ...
///   [envp[0] pointer]
///   [NULL] (end of argv)
///   [argv[argc-1] pointer]
///   ...
///   [argv[0] pointer]
///   [argc]
/// ```
/// Low addresses (initial RSP)
///
/// Returns the initial RSP value.
fn setup_user_stack<FA: FrameAlloc<PhysAddr = u64>>(
    page_table: &mut ArchPageTable,
    frame_alloc: &mut FA,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    entry_point: u64,
) -> Result<u64, i32> {
    // Calculate stack pages based on RLIMIT_STACK
    let stack_limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_STACK);
    let stack_pages = if stack_limit == crate::rlimit::RLIM_INFINITY {
        // Unlimited - use default
        USER_STACK_PAGES
    } else {
        // Limit stack to RLIMIT_STACK bytes, clamped between defaults
        let pages = (stack_limit / PAGE_SIZE) as usize;
        pages.clamp(USER_STACK_PAGES, MAX_STACK_PAGES)
    };

    // Allocate stack pages
    let stack_bottom = USER_STACK_TOP - (stack_pages as u64 * PAGE_SIZE);

    for i in 0..stack_pages {
        let va = stack_bottom + (i as u64 * PAGE_SIZE);
        let frame = frame_alloc.alloc_frame().ok_or(ENOMEM)?;

        // Zero the frame
        unsafe {
            ::core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }

        // Map with read/write/user permissions
        page_table
            .map_with_alloc(
                va,
                frame,
                PageFlags::READ | PageFlags::WRITE | PageFlags::USER,
                frame_alloc,
            )
            .map_err(|_| ENOMEM)?;
    }

    // Start from top of stack and work down
    let mut sp = USER_STACK_TOP;

    // We'll build the stack contents in physical memory
    // For now, translate virtual to physical

    // Calculate string area size
    let argv_strings_size: usize = argv.iter().map(|s| s.len() + 1).sum();
    let envp_strings_size: usize = envp.iter().map(|s| s.len() + 1).sum();
    let strings_size = argv_strings_size + envp_strings_size;

    // Auxiliary vector (minimal for now)
    // AT_NULL (0) terminates, AT_PAGESZ (6), AT_ENTRY (9)
    let auxv_entries: [(u64, u64); 3] = [
        (6, PAGE_SIZE),   // AT_PAGESZ
        (9, entry_point), // AT_ENTRY
        (0, 0),           // AT_NULL (terminator)
    ];
    let auxv_size = auxv_entries.len() * 16;

    // Pointers: argc (8) + argv pointers (argc+1) + envp pointers (envc+1)
    let argc = argv.len();
    let envc = envp.len();
    let pointers_size = 8 + (argc + 1) * 8 + (envc + 1) * 8;

    // Total size (align to 16 bytes)
    let total_size = (strings_size + auxv_size + pointers_size).div_ceil(16) * 16;

    // Check if it fits in stack (using actual allocated pages)
    if total_size > stack_pages * PAGE_SIZE as usize {
        return Err(E2BIG);
    }

    // Move sp down to make room
    sp -= total_size as u64;

    // Align to 16 bytes, then subtract 8 for ABI compliance.
    // x86-64 ABI requires RSP to be 8 bytes below 16-byte alignment at function entry
    // (as if a 'call' had pushed an 8-byte return address).
    sp &= !15;
    sp -= 8;

    // Now write data to the stack
    // We need to translate virtual addresses to physical

    // Helper to write to virtual address via page table
    let write_u64 = |pt: &ArchPageTable, va: u64, val: u64| -> Result<(), i32> {
        if let Some(phys) = pt.translate(va) {
            unsafe {
                let ptr = phys_to_virt(phys) as *mut u64;
                core::ptr::write(ptr, val);
            }
            Ok(())
        } else {
            Err(EFAULT)
        }
    };

    let write_bytes = |pt: &ArchPageTable, va: u64, data: &[u8]| -> Result<(), i32> {
        for (i, &byte) in data.iter().enumerate() {
            let addr = va + i as u64;
            if let Some(phys) = pt.translate(addr) {
                unsafe {
                    let ptr = phys_to_virt(phys);
                    core::ptr::write(ptr, byte);
                }
            } else {
                return Err(EFAULT);
            }
        }
        Ok(())
    };

    // Current position for writing
    let mut ptr = sp;

    // Write argc
    write_u64(page_table, ptr, argc as u64)?;
    ptr += 8;

    // Calculate where strings will be placed
    let strings_base = sp + pointers_size as u64 + auxv_size as u64;
    let mut string_ptr = strings_base;

    // Collect argv string addresses
    let mut argv_addrs = Vec::new();
    for arg in argv {
        argv_addrs.push(string_ptr);
        string_ptr += (arg.len() + 1) as u64; // +1 for null terminator
    }

    // Collect envp string addresses
    let mut envp_addrs = Vec::new();
    for env in envp {
        envp_addrs.push(string_ptr);
        string_ptr += (env.len() + 1) as u64;
    }

    // Write argv pointers
    for addr in &argv_addrs {
        write_u64(page_table, ptr, *addr)?;
        ptr += 8;
    }
    // NULL terminator for argv
    write_u64(page_table, ptr, 0)?;
    ptr += 8;

    // Write envp pointers
    for addr in &envp_addrs {
        write_u64(page_table, ptr, *addr)?;
        ptr += 8;
    }
    // NULL terminator for envp
    write_u64(page_table, ptr, 0)?;
    ptr += 8;

    // Write auxv
    for (tag, val) in &auxv_entries {
        write_u64(page_table, ptr, *tag)?;
        ptr += 8;
        write_u64(page_table, ptr, *val)?;
        ptr += 8;
    }

    // Write argv strings
    let mut string_ptr = strings_base;
    for arg in argv {
        write_bytes(page_table, string_ptr, arg)?;
        write_bytes(page_table, string_ptr + arg.len() as u64, &[0])?; // null terminator
        string_ptr += (arg.len() + 1) as u64;
    }

    // Write envp strings
    for env in envp {
        write_bytes(page_table, string_ptr, env)?;
        write_bytes(page_table, string_ptr + env.len() as u64, &[0])?;
        string_ptr += (env.len() + 1) as u64;
    }

    // ARM64: Flush data cache for all stack pages we just wrote.
    // The kernel writes via phys_to_virt (kernel VA) but user reads via
    // user VA - ARM requires cache flush for coherency across different VAs.
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::cache;
        for i in 0..stack_pages {
            let va = stack_bottom + (i as u64 * PAGE_SIZE);
            if let Some(phys) = page_table.translate(va) {
                cache::cache_clean_range(phys_to_virt(phys) as *const u8, PAGE_SIZE as usize);
            }
        }
    }

    Ok(sp)
}

/// Load ELF segments into a page table
///
/// Returns the end address of the highest loaded segment (for setting brk).
fn load_elf_segments<FA: FrameAlloc<PhysAddr = u64>>(
    elf: &ElfExecutable<u64>,
    elf_data: &[u8],
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
            // Allocate a frame for this page
            let frame = frame_alloc.alloc_frame().ok_or(ENOMEM)?;

            // Zero the frame first (for BSS and partial pages)
            unsafe {
                ::core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
            }

            // Calculate the offset within the page where segment data starts
            // For the first page of a non-page-aligned segment, this is non-zero
            let in_page_offset = if va < seg_start {
                (seg_start - va) as usize
            } else {
                0
            };

            // Calculate the offset into the segment's file data
            let seg_data_offset = va.saturating_sub(seg_start);

            // Calculate file offset
            let file_offset = segment.offset + seg_data_offset;

            // Calculate how much data to copy
            if (file_offset as usize) < elf_data.len() && seg_data_offset < segment.file_size as u64
            {
                let copy_start = file_offset as usize;
                let remaining_file = segment.file_size as u64 - seg_data_offset;
                let available_space = PAGE_SIZE as usize - in_page_offset;
                let copy_len = core::cmp::min(
                    core::cmp::min(available_space as u64, remaining_file),
                    (elf_data.len() - copy_start) as u64,
                ) as usize;

                if copy_len > 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            elf_data.as_ptr().add(copy_start),
                            (frame as *mut u8).add(in_page_offset),
                            copy_len,
                        );
                    }
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
                cache::cache_clean_range(frame as *const u8, PAGE_SIZE as usize);
            }

            // Map the page
            page_table
                .map_with_alloc(va, frame, flags, frame_alloc)
                .map_err(|_| ENOMEM)?;

            va += PAGE_SIZE;
        }
    }

    Ok(highest_end)
}

/// Apply ELF relocations for PIE binaries
fn apply_relocations(elf: &ElfExecutable<u64>, base_addr: u64, page_table: &ArchPageTable) {
    for reloc in &elf.relocations {
        let target_vaddr = base_addr + reloc.offset;
        let value = (base_addr as i64 + reloc.addend) as u64;

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
    }
}

/// Read entire file contents into a Vec
fn read_file_contents(file: &File) -> Result<Vec<u8>, i32> {
    let inode = file.get_inode().ok_or(ENOENT)?;
    let file_size = inode.get_size() as usize;

    if file_size == 0 {
        return Err(ENOEXEC); // Empty file can't be executable
    }

    let mut data = alloc::vec![0u8; file_size];
    let mut total_read = 0;

    while total_read < file_size {
        let n = file.read(&mut data[total_read..]).map_err(|_| ENOENT)?;
        if n == 0 {
            break; // EOF
        }
        total_read += n;
    }

    if total_read < file_size {
        // Didn't read full file - truncate
        data.truncate(total_read);
    }

    Ok(data)
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
    pathname: &[u8],
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    frame_alloc: &mut FA,
) -> i32 {
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

    // Read the entire file into memory
    let elf_data = match read_file_contents(&file) {
        Ok(d) => d,
        Err(e) => return -e,
    };

    // Parse ELF
    fn addr_from_u64(v: u64) -> u64 {
        v
    }
    let elf = match ElfExecutable::<u64>::parse(&elf_data, addr_from_u64) {
        Ok(e) => e,
        Err(_) => return -ENOEXEC,
    };

    // Release all POSIX advisory locks (POSIX semantics: locks released on exec)
    crate::fs::posix_lock::release_all_posix_locks_for_pid(crate::task::percpu::current_pid());

    // Calculate base address
    let base_addr = if elf.is_pie { USER_PIE_BASE } else { 0 };
    let entry_point = elf.entry + base_addr;

    // Create new page table for the process
    let mut new_page_table = match ArchPageTable::new_user(frame_alloc) {
        Some(pt) => pt,
        None => return -ENOMEM,
    };

    // Copy kernel mappings to the new page table
    #[cfg(target_arch = "aarch64")]
    {
        // ARM64: Use dedicated L1 table like fork does, to avoid sharing L1
        // table with parent which can cause TLB coherency issues.
        // When we do tlbi vmalle1is (global TLB invalidate), if we share the L1
        // table with the parent process, the TLB flush affects mappings that the
        // parent is still using, causing the parent's cached data to become stale.
        if new_page_table
            .copy_kernel_mappings_with_alloc(frame_alloc)
            .is_err()
        {
            return -ENOMEM;
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // x86-64: Sharing PML4[0] is safe because x86 has hardware-coherent caches
        // and doesn't have ARM's cache maintenance requirements.
        new_page_table.copy_kernel_mappings();
    }

    // Load ELF segments and get the end address for brk initialization
    let segments_end =
        match load_elf_segments(&elf, &elf_data, &mut new_page_table, frame_alloc, base_addr) {
            Ok(end) => end,
            Err(e) => return -e,
        };

    // Apply relocations for PIE
    if elf.is_pie {
        apply_relocations(&elf, base_addr, &new_page_table);
    }

    // Set up user stack with argv, envp
    let user_sp =
        match setup_user_stack(&mut new_page_table, frame_alloc, &argv, &envp, entry_point) {
            Ok(sp) => sp,
            Err(e) => return -e,
        };

    // Now we need to update the current task and switch to the new address space
    // This is the point of no return

    // Signal vfork completion if parent is waiting
    // Must be done before we switch address spaces since parent may be blocked
    let tid = percpu::current_tid();
    percpu::signal_vfork_done(tid);

    // Initialize brk for the new process
    // Calculate page-aligned start_brk (end of loaded segments, rounded up)
    let start_brk = (segments_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Create fresh MmStruct for the new process (exec replaces address space)
    let mm = crate::mm::create_default_mm();
    mm.lock().set_brk(start_brk);
    crate::mm::init_task_mm(tid, mm);

    // Update the current task's page table and jump to user mode
    // This function never returns on success
    percpu::exec_replace_image(new_page_table, entry_point, user_sp);
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
    let path = match unsafe { copy_string_from_user(pathname, PATH_MAX) } {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };

    // Copy argv from user space
    let argv = match unsafe { copy_string_array_from_user(argv_ptr, 1024) } {
        Ok(a) => a,
        Err(e) => return -(e as i64),
    };

    // Copy envp from user space
    let envp = match unsafe { copy_string_array_from_user(envp_ptr, 1024) } {
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
    let result = do_execve(&path, argv, envp, &mut frame_alloc);
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
    let path = match unsafe { copy_string_from_user(pathname, PATH_MAX) } {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };

    // For AT_FDCWD, the path must be absolute or we treat it as relative to cwd
    // Our VFS currently treats relative paths as if relative to /
    // This is a simplification

    // Copy argv from user space
    let argv = match unsafe { copy_string_array_from_user(argv_ptr, 1024) } {
        Ok(a) => a,
        Err(e) => return -(e as i64),
    };

    // Copy envp from user space
    let envp = match unsafe { copy_string_array_from_user(envp_ptr, 1024) } {
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
    let result = do_execve(&path, argv, envp, &mut frame_alloc);
    // If we get here, exec failed - result is already negative
    result as i64
}
