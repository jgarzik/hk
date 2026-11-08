//! execve implementation
//!
//! Replaces the current process image with a new program.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use crate::arch::ArchPageTable;
use crate::fs::file::flags::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use crate::arch::PageTable;
use crate::arch::{FrameAlloc, PageFlags, phys_to_virt};

use super::percpu;
use crate::fs::{File, kernel_open_exec};
use crate::mm::{ELF_ET_DYN_BASE, MmLayout, STACK_TOP};
use crate::uaccess::UserPtr;
use crate::util::elf::ElfExecutable;
use crate::util::error::{KernelError, KernelResult};
use core::convert::Infallible;

pub use super::argstr::ArgStrings;

/// Page size constant
const PAGE_SIZE: u64 = 4096;

/// Room for argument and environment strings whatever RLIMIT_STACK
/// (Linux ARG_MAX: 32 pages)
const ARG_MAX: usize = 32 * PAGE_SIZE as usize;

/// Longest argument or environment string, NUL included (Linux
/// MAX_ARG_STRLEN: 32 pages)
const MAX_ARG_STRLEN: usize = 32 * PAGE_SIZE as usize;

/// Most argument or environment strings (Linux MAX_ARG_STRINGS)
const MAX_ARG_STRINGS: usize = 0x7FFF_FFFF;

/// The stack limit the strings may take at most 3/4 of (Linux _STK_LIM)
const STK_LIM: u64 = 8 << 20;

/// Stack room above the arguments in the initial stack VMA (Linux
/// setup_arg_pages: stack_expand)
const STACK_EXPAND_PAGES: usize = 32;

/// The user pointer `i` of a NULL-terminated array (Linux
/// get_user_arg_ptr): EFAULT
fn arg_ptr(argv: UserPtr<u64>, i: usize) -> KernelResult<u64> {
    let p = argv.offset(i).ok_or(KernelError::BadAddress)?;
    Ok(p.read()?)
}

/// The strings in a NULL-terminated user array (Linux count): EFAULT,
/// E2BIG past MAX_ARG_STRINGS; a fatal signal ends the walk
fn count(argv: UserPtr<u64>) -> KernelResult<usize> {
    if argv.is_null() {
        return Ok(0);
    }
    let mut i = 0;
    while arg_ptr(argv, i)? != 0 {
        if i >= MAX_ARG_STRINGS {
            return Err(KernelError::ArgListTooLong);
        }
        i += 1;
        if crate::signal::fatal_signal_pending() {
            return Err(KernelError::RestartNoHand);
        }
        percpu::cond_resched();
    }
    Ok(i)
}

/// Bytes the strings may take on the new stack (Linux
/// bprm_stack_limits): a quarter of RLIMIT_STACK, at most 3/4 of
/// _STK_LIM and at least ARG_MAX, less the argv and envp pointers
/// (argc counted as at least 1); E2BIG if they leave nothing
fn arg_limit(argc: usize, envc: usize) -> KernelResult<usize> {
    use crate::task::rlimit::{RLIMIT_STACK, rlimit};
    let quarter = usize::try_from(rlimit(RLIMIT_STACK) / 4).unwrap_or(usize::MAX);
    let limit = ((STK_LIM / 4 * 3) as usize).min(quarter).max(ARG_MAX);
    let ptrs = argc
        .max(1)
        .checked_add(envc)
        .and_then(|n| n.checked_mul(8))
        .ok_or(KernelError::ArgListTooLong)?;
    limit
        .checked_sub(ptrs)
        .filter(|&l| l > 0)
        .ok_or(KernelError::ArgListTooLong)
}

/// Copy the `n` strings of user array `argv`, packed, each charged
/// with its NUL against `budget` (Linux copy_strings): one longer than
/// MAX_ARG_STRLEN, or past the budget, is E2BIG; EFAULT; ENOMEM
fn copy_strings(argv: UserPtr<u64>, n: usize, budget: &mut usize) -> KernelResult<ArgStrings> {
    let mut out = ArgStrings::new();
    for i in 0..n {
        let p = arg_ptr(argv, i)?;
        if p == 0 {
            return Err(KernelError::BadAddress);
        }
        out.push_user::<crate::arch::Uaccess>(p, MAX_ARG_STRLEN, budget)?;
        if crate::signal::fatal_signal_pending() {
            return Err(KernelError::RestartNoHand);
        }
    }
    Ok(out)
}

/// The argument and environment strings of an exec of `filename`
/// (Linux do_execveat_common): both arrays counted, the room for them
/// worked out from RLIMIT_STACK, then the file name, the environment
/// and the arguments (at least an empty argv[0]) copied against it
fn copy_args(
    filename: &[u8],
    argv: UserPtr<u64>,
    envp: UserPtr<u64>,
) -> KernelResult<(ArgStrings, ArgStrings)> {
    let argc = count(argv)?;
    let envc = count(envp)?;
    let mut budget = arg_limit(argc, envc)?;
    budget = budget
        .checked_sub(filename.len() + 1)
        .ok_or(KernelError::ArgListTooLong)?;
    let envp = copy_strings(envp, envc, &mut budget)?;
    let mut argv = copy_strings(argv, argc, &mut budget)?;
    // No arguments: argv[0] is "", so a program reading from argv[1]
    // does not walk into envp (Linux copy_string_kernel(""), charged)
    if argc == 0 {
        budget.checked_sub(1).ok_or(KernelError::ArgListTooLong)?;
        argv.push(b"")?;
    }
    Ok((argv, envp))
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
    /// Copy `data` to user address `va`, a page at a time
    fn write(&self, va: u64, data: &[u8]) -> KernelResult<()> {
        let mut done = 0;
        while done < data.len() {
            let at = va + done as u64;
            let n = ((PAGE_SIZE - at % PAGE_SIZE) as usize).min(data.len() - done);
            let phys = self.pt.translate(at).ok_or(KernelError::BadAddress)?;
            // SAFETY: `phys` is a stack frame of the new address space,
            // mapped above, and `n` bytes stay within its page
            unsafe {
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), phys_to_virt(phys), n);
            }
            done += n;
        }
        Ok(())
    }

    /// Push bytes below the current top; their address
    fn push(&mut self, data: &[u8]) -> KernelResult<u64> {
        self.top -= data.len() as u64;
        self.write(self.top, data)?;
        Ok(self.top)
    }

    /// Push a NUL-terminated string; its address
    fn push_str(&mut self, s: &[u8]) -> KernelResult<u64> {
        self.push(&[0])?;
        self.push(s)
    }
}

/// Stores consecutive words to the new stack through a small buffer
struct WordWriter<'a, 'b> {
    w: &'a StackWriter<'b>,
    /// Where the buffered words go
    at: u64,
    buf: [u8; 512],
    n: usize,
}

impl<'a, 'b> WordWriter<'a, 'b> {
    fn new(w: &'a StackWriter<'b>, at: u64) -> Self {
        Self {
            w,
            at,
            buf: [0; 512],
            n: 0,
        }
    }

    fn put(&mut self, v: u64) -> KernelResult<()> {
        if self.n == self.buf.len() {
            self.flush()?;
        }
        self.buf[self.n..self.n + 8].copy_from_slice(&v.to_le_bytes());
        self.n += 8;
        Ok(())
    }

    fn flush(&mut self) -> KernelResult<()> {
        self.w.write(self.at, &self.buf[..self.n])?;
        self.at += self.n as u64;
        self.n = 0;
        Ok(())
    }
}

/// Auxiliary vector (Linux fs/binfmt_elf.c create_elf_tables)
/// Entries of the auxiliary vector, AT_NULL included
const AUXV_LEN: usize = 20;

fn auxv(info: &ExecInfo<'_>, random: u64, execfn: u64, platform: u64) -> [(u64, u64); AUXV_LEN] {
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
        (AT_UID, u64::from(c.uid)),
        (AT_EUID, u64::from(c.euid)),
        (AT_GID, u64::from(c.gid)),
        (AT_EGID, u64::from(c.egid)),
        (AT_SECURE, u64::from(secure)),
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
/// Returns where argv, envp and the SP went.
/// The initial stack's pages: those the stack image takes (mapped at
/// exec), and those of its VMA, from RLIMIT_STACK and with room to run
/// above the image (Linux setup_arg_pages: stack_expand)
struct StackSize {
    mapped: usize,
    pages: usize,
    /// Words below the strings: argc, the argv and envp pointers with
    /// their NULLs, the auxiliary vector
    words: usize,
}

impl StackSize {
    fn new(argv: &ArgStrings, envp: &ArgStrings, execfn: &[u8]) -> Self {
        // RLIMIT_STACK in whole pages (Linux rlim_cur & PAGE_MASK)
        let rlim = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_STACK) / PAGE_SIZE;
        let rlim = usize::try_from(rlim).unwrap_or(usize::MAX);
        // What the image holds: its strings were bounded by copy_args
        // (Linux bprm_stack_limits), plus a script's interpreter
        let strings = argv.bytes().len() + envp.bytes().len();
        let words = 1 + argv.len() + 1 + envp.len() + 1 + 2 * AUXV_LEN;
        let need = strings + execfn.len() + 64 + 16 + words * 8 + 64;
        let mapped = need.div_ceil(PAGE_SIZE as usize) + 1;
        // The VMA is the image and stack_expand's room above it, never
        // past RLIMIT_STACK, nor below the image (Linux setup_arg_pages:
        // stack_expand = min(rlim_stack, stack_size + stack_expand), an
        // expand_stack that only grows); faults grow it down from there
        // up to RLIMIT_STACK (mm::expand_downwards)
        Self {
            mapped,
            pages: (mapped + STACK_EXPAND_PAGES).min(rlim).max(mapped),
            words,
        }
    }

    /// The bottom of the stack VMA
    fn bottom(&self) -> u64 {
        STACK_TOP - self.pages as u64 * PAGE_SIZE
    }
}

fn setup_user_stack<FA: FrameAlloc<PhysAddr = u64>>(
    page_table: &mut ArchPageTable,
    frame_alloc: &mut FA,
    argv: &ArgStrings,
    envp: &ArgStrings,
    info: &ExecInfo<'_>,
    size: &StackSize,
) -> KernelResult<MmLayout> {
    // Map only what the image uses (Linux setup_arg_pages: the rest of
    // the stack VMA faults in on first touch)
    let mapped = size.mapped;
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
            return Err(KernelError::OutOfMemory);
        }
    }

    let mut w = StackWriter {
        pt: page_table,
        top: STACK_TOP - 8, // NULL end marker (Linux)
    };
    let execfn = w.push_str(info.execfn)?;
    // argv then envp strings, back to back (Linux arg_start..env_end)
    let env_end = w.top;
    let env_start = w.push(envp.bytes())?;
    let arg_start = w.push(argv.bytes())?;
    let platform = w.push_str(crate::arch::ELF_PLATFORM)?;
    let mut rnd = [0u8; 16];
    let _ = crate::random::get_random_bytes(&mut rnd, 0);
    w.top &= !15;
    let random = w.push(&rnd)?;

    // argc, argv[], NULL, envp[], NULL, auxv pairs, streamed to the
    // stack: each string's address found by walking the NULs
    let sp = (w.top - size.words as u64 * 8) & !15;
    let mut out = WordWriter::new(&w, sp);
    out.put(argv.len() as u64)?;
    for (strs, start) in [(argv, arg_start), (envp, env_start)] {
        let mut at = start;
        for s in strs.iter() {
            out.put(at)?;
            at += s.len() as u64 + 1;
        }
        out.put(0)?;
    }
    for (k, val) in auxv(info, random, execfn, platform) {
        out.put(k)?;
        out.put(val)?;
    }
    out.flush()?;

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
    Ok(area)
}

/// The highest free page below mmap_base clear of `vmas` (Linux
/// get_unmapped_area, top-down)
fn free_page(vmas: &[crate::mm::Vma]) -> Option<u64> {
    let mut spans: Vec<(u64, u64)> = vmas.iter().map(|v| (v.start, v.end)).collect();
    highest_gap(&mut spans, crate::mm::mmap_base(), crate::mm::MMAP_MIN_ADDR)
}

/// The highest page in `[low, top)` that no span `[start, end)` of
/// `spans` overlaps (page-aligned bounds; spans may overlap or nest):
/// walked by start with the highest end so far, each gap below the
/// next start is free (Linux unmapped_area_topdown's gap search)
fn highest_gap(spans: &mut [(u64, u64)], top: u64, low: u64) -> Option<u64> {
    spans.sort_unstable();
    let mut reach = low;
    let mut best = None;
    let ends = spans.iter().copied().chain(core::iter::once((top, top)));
    for (start, end) in ends {
        let hi = start.min(top);
        if hi > reach && hi - reach >= PAGE_SIZE {
            best = Some(hi - PAGE_SIZE);
        }
        reach = reach.max(end);
        if reach >= top {
            break;
        }
    }
    best
}

/// The arch's signal return page, if it has one (arm64: Linux's vDSO
/// sigtramp), mapped read+exec in free space clear of the new image's
/// `vmas`; its VMA
fn map_sigpage<FA: FrameAlloc<PhysAddr = u64>>(
    page_table: &mut ArchPageTable,
    frame_alloc: &mut FA,
    vmas: &[crate::mm::Vma],
) -> KernelResult<Option<crate::mm::Vma>> {
    use crate::mm::{PROT_EXEC, PROT_READ, VM_SIGPAGE};
    let Some(code) = crate::arch::signal::SIGPAGE else {
        return Ok(None);
    };
    let va = free_page(vmas).ok_or(KernelError::OutOfMemory)?;
    let frame = user_frame()?;
    let page = crate::arch::phys_to_virt(frame);
    // SAFETY: a fresh frame of PAGE_SIZE bytes, ours alone, through the
    // linear map
    unsafe {
        ::core::ptr::write_bytes(page, 0, PAGE_SIZE as usize);
        for (i, w) in code.iter().enumerate() {
            ::core::ptr::write_unaligned(page.add(i * 4).cast::<u32>(), w.to_le());
        }
    }
    crate::arch::paging::sync_page(frame, true);
    let flags = PageFlags::READ | PageFlags::EXECUTE | PageFlags::USER;
    if page_table
        .map_with_alloc(va, frame, flags, frame_alloc)
        .is_err()
    {
        crate::FRAME_ALLOCATOR.free(frame);
        return Err(KernelError::OutOfMemory);
    }
    let mut vma = anon_vma(va, va + PAGE_SIZE, PROT_READ | PROT_EXEC);
    vma.flags |= VM_SIGPAGE;
    Ok(Some(vma))
}

/// Every PT_LOAD segment and the entry point must land in mappable
/// user space: past TASK_SIZE (or overflowing) is EINVAL (Linux
/// BAD_ADDR), below mmap_min_addr EPERM (security_mmap_addr), on the
/// stack at or above `stack_bottom` EEXIST (Linux maps the stack first
/// and an image over it fails its MAP_FIXED_NOREPLACE, after the point
/// of no return; hk refuses it before)
fn check_segments(elf: &ElfExecutable, base: u64, stack_bottom: u64) -> KernelResult<()> {
    for seg in &elf.segments {
        let va = seg
            .vaddr
            .checked_add(base)
            .ok_or(KernelError::InvalidArgument)?;
        let end = va
            .checked_add(seg.mem_size as u64)
            .ok_or(KernelError::InvalidArgument)?;
        if end > crate::mm::TASK_SIZE {
            return Err(KernelError::InvalidArgument);
        }
        let start = va & !(PAGE_SIZE - 1);
        crate::mm::check_fixed(start, end - start)?;
        if seg.mem_size > 0 && end > stack_bottom {
            return Err(KernelError::AlreadyExists);
        }
    }
    if elf
        .entry
        .checked_add(base)
        .is_none_or(|e| e >= crate::mm::TASK_SIZE)
    {
        return Err(KernelError::InvalidArgument);
    }
    // Segments are populated at exec: an image larger than free memory
    // is ENOMEM up front, not after exhausting it
    let pages: u64 = elf
        .segments
        .iter()
        .map(|s| (s.mem_size as u64).div_ceil(PAGE_SIZE) + 1)
        .sum();
    if pages > crate::FRAME_ALLOCATOR.free_frames() as u64 {
        return Err(KernelError::OutOfMemory);
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
pub fn image_vmas(
    elf: &ElfExecutable,
    base: u64,
    stack_bottom: u64,
    file: Option<&Arc<File>>,
) -> Vec<crate::mm::Vma> {
    use crate::mm::{PROT_READ, PROT_WRITE, VM_GROWSDOWN};
    let mut vmas = segment_vmas(elf, base, file);
    let mut stack = anon_vma(stack_bottom, STACK_TOP, PROT_READ | PROT_WRITE);
    stack.flags |= VM_GROWSDOWN;
    vmas.push(stack);
    vmas
}

fn anon_vma(start: u64, end: u64, prot: u32) -> crate::mm::Vma {
    use crate::mm::{MAP_ANONYMOUS, MAP_PRIVATE, Vma, anon_vma::AnonVma};
    // Past exec's point of no return: failure cannot be reported
    Vma::new_anon(
        start,
        end,
        prot,
        MAP_PRIVATE | MAP_ANONYMOUS,
        crate::util::kalloc::arc_nofail(AnonVma::default()),
    )
}

/// A run of pages of a loaded image that one PT_LOAD segment owns
/// (`seg`, its index in `elf.segments`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    start: u64,
    end: u64,
    seg: usize,
}

/// The page-aligned [start, end) of segment `seg` loaded `base` higher;
/// None past u64 (check_segments rules that out for a loaded image)
fn seg_pages(seg: &crate::util::elf::ElfSegment, base: u64) -> Option<(u64, u64)> {
    let start = seg.vaddr.checked_add(base)?;
    let end = start
        .checked_add(seg.mem_size as u64)?
        .checked_next_multiple_of(PAGE_SIZE)?;
    Some((start & !(PAGE_SIZE - 1), end))
}

/// The pages of `elf` loaded at `base`, sorted and disjoint, each owned
/// by the last segment in file order that covers it: Linux
/// load_elf_binary maps every PT_LOAD in file order, each MAP_FIXED
/// over what the earlier ones mapped, so the segments may come in any
/// order and overlap (a page shared by two adjacent segments is the
/// later one's)
fn image_spans(elf: &ElfExecutable, base: u64) -> Vec<Span> {
    let mut spans: Vec<Span> = Vec::new();
    for (k, seg) in elf.segments.iter().enumerate() {
        if seg.mem_size == 0 {
            continue;
        }
        let Some((start, end)) = seg_pages(seg, base) else {
            continue;
        };
        let mut next = Vec::with_capacity(spans.len() + 2);
        for sp in spans {
            if sp.end <= start || end <= sp.start {
                next.push(sp);
                continue;
            }
            if sp.start < start {
                next.push(Span { end: start, ..sp });
            }
            if end < sp.end {
                next.push(Span { start: end, ..sp });
            }
        }
        next.push(Span { start, end, seg: k });
        spans = next;
    }
    spans.sort_unstable_by_key(|sp| sp.start);
    spans
}

/// The part of `sp` a private mapping of the file supplies (Linux
/// elf_map): its segment's whole file pages within it, as (start, end,
/// file offset of start)
fn span_file(elf: &ElfExecutable, base: u64, sp: &Span) -> Option<(u64, u64, u64)> {
    let (lo, hi, off) = elf.segments[sp.seg].file_pages(base, 0)?;
    let (a, b) = (lo.max(sp.start), hi.min(sp.end));
    (a < b).then(|| (a, b, off + (a - lo)))
}

/// mmap protection of a segment
fn seg_prot(f: &crate::util::elf::SegmentFlags) -> u32 {
    use crate::mm::{PROT_EXEC, PROT_READ, PROT_WRITE};
    (u32::from(f.read) * PROT_READ)
        | (u32::from(f.write) * PROT_WRITE)
        | (u32::from(f.execute) * PROT_EXEC)
}

/// The VMAs of `elf` loaded at `base`, one per span; with `file` (the
/// image mapped from the page cache) a span's whole file pages are a
/// private file VMA, the rest (a partial page, the bss) anonymous ones
/// around it. They cover exactly the pages `load_elf_segments` maps.
fn segment_vmas(elf: &ElfExecutable, base: u64, file: Option<&Arc<File>>) -> Vec<crate::mm::Vma> {
    use crate::mm::{MAP_PRIVATE, Vma};
    let mut vmas: Vec<Vma> = Vec::new();
    for sp in image_spans(elf, base) {
        let prot = seg_prot(&elf.segments[sp.seg].flags);
        match file.zip(span_file(elf, base, &sp)) {
            Some((f, (a, b, off))) => {
                if sp.start < a {
                    vmas.push(anon_vma(sp.start, a, prot));
                }
                vmas.push(Vma::new_file(a, b, prot, MAP_PRIVATE, f.clone(), off));
                if b < sp.end {
                    vmas.push(anon_vma(b, sp.end, prot));
                }
            }
            None => vmas.push(anon_vma(sp.start, sp.end, prot)),
        }
    }
    vmas
}

/// The page-aligned [lo, hi) of `elf`'s loaded segments (before any
/// load bias); None for an image without one or a span past u64
fn image_span(elf: &ElfExecutable) -> Option<(u64, u64)> {
    let segs = elf.segments.iter().filter(|s| s.mem_size > 0);
    let lo = segs.clone().map(|s| s.vaddr).min()? & !(PAGE_SIZE - 1);
    let hi = segs
        .map(|s| s.vaddr.checked_add(s.mem_size as u64))
        .try_fold(0u64, |m, e| e.map(|e| m.max(e)))?
        .checked_next_multiple_of(PAGE_SIZE)?;
    Some((lo, hi))
}

/// Where a program interpreter goes (Linux load_elf_interp): the first
/// free area below mmap_base big enough for all its segments, at their
/// alignment, and below the program's own image if that is in the way;
/// ENOMEM if there is no such room. An ET_EXEC interpreter goes at its
/// link address, EINVAL if that overlaps the program or the stack area
/// (Linux would map it over them).
fn interp_base(interp: &ElfExecutable, prog: &ElfExecutable, prog_base: u64) -> KernelResult<u64> {
    let (lo, hi) = image_span(interp).ok_or(KernelError::ExecFormat)?;
    let (plo, phi) = image_span(prog).ok_or(KernelError::ExecFormat)?;
    let (plo, phi) = (plo + prog_base, phi + prog_base);
    let top = crate::mm::mmap_base();
    let overlaps = |a: u64, b: u64| a < phi && plo < b;
    if !interp.is_pie {
        if overlaps(lo, hi) || hi > top {
            return Err(KernelError::InvalidArgument);
        }
        return Ok(0);
    }
    let align = interp.align.max(PAGE_SIZE);
    // The highest bias, a multiple of the alignment (so every segment
    // keeps its offset modulo p_align), with the image ending at or
    // below `limit`
    let below = |limit: u64| limit.checked_sub(hi).map(|b| b & !(align - 1));
    let mut bias = below(top).ok_or(KernelError::OutOfMemory)?;
    if overlaps(lo + bias, hi + bias) {
        bias = below(plo).ok_or(KernelError::OutOfMemory)?;
    }
    // Keep clear of the lowest pages (mmap_min_addr)
    if lo + bias < PAGE_SIZE * 16 {
        return Err(KernelError::OutOfMemory);
    }
    Ok(bias)
}

/// Load ELF segments into a page table: every page of every span
/// (`image_spans`), but for those a file mapping supplies when `lazy`
/// (`span_file`), so the VMAs of `segment_vmas` cover each page mapped
///
/// Returns the end address of the highest loaded segment (for setting brk).
fn load_elf_segments<FA: FrameAlloc<PhysAddr = u64>>(
    elf: &ElfExecutable,
    image: &FileImage<'_>,
    page_table: &mut ArchPageTable,
    frame_alloc: &mut FA,
    base_addr: u64,
    lazy: bool,
) -> KernelResult<u64> {
    for sp in image_spans(elf, base_addr) {
        let seg = &elf.segments[sp.seg];
        let file = if lazy {
            span_file(elf, base_addr, &sp)
        } else {
            None
        };
        let mut flags = PageFlags::READ | PageFlags::USER;
        if seg.flags.write {
            flags |= PageFlags::WRITE;
        }
        if seg.flags.execute {
            flags |= PageFlags::EXECUTE;
        }
        let mut va = sp.start;
        while va < sp.end {
            if !file.is_some_and(|(a, b, _)| (a..b).contains(&va)) {
                let frame = fill_page(elf, image, base_addr, va)?;
                // The kernel wrote it: code reaches the instruction
                // caches (arm64; Linux __sync_icache_dcache)
                crate::arch::paging::sync_page(frame, seg.flags.execute);
                // Once mapped, the address space frees it
                if page_table
                    .map_with_alloc(va, frame, flags, frame_alloc)
                    .is_err()
                {
                    crate::FRAME_ALLOCATOR.free(frame);
                    return Err(KernelError::OutOfMemory);
                }
            }
            va += PAGE_SIZE;
        }
    }
    // The highest segment end (Linux elf_brk); check_segments bounded
    // each below TASK_SIZE
    Ok(elf
        .segments
        .iter()
        .filter_map(|s| {
            s.vaddr
                .checked_add(base_addr)?
                .checked_add(s.mem_size as u64)
        })
        .max()
        .unwrap_or(0))
}

/// A new frame for user page `va` of the image: zeroed, then the file
/// bytes of every segment over it, in file order (each page and file
/// range bounds-checked by elf::ElfSegment::page_fill), read straight
/// into it. For the congruent offsets linkers produce this is what the
/// owning segment's file page holds (Linux maps the file instead).
fn fill_page(elf: &ElfExecutable, image: &FileImage<'_>, base: u64, va: u64) -> KernelResult<u64> {
    let frame = user_frame()?;
    // SAFETY: a fresh frame, ours alone, reached through the direct map
    let page = unsafe { core::slice::from_raw_parts_mut(phys_to_virt(frame), PAGE_SIZE as usize) };
    page.fill(0);
    let size = usize::try_from(image.size).unwrap_or(usize::MAX);
    for seg in &elf.segments {
        let covers =
            seg.mem_size > 0 && seg_pages(seg, base).is_some_and(|(lo, hi)| (lo..hi).contains(&va));
        if !covers {
            continue;
        }
        if let Some((dst, src, len)) = seg.page_fill(base, va, size)
            && let Err(e) = image.read_into(&mut page[dst..dst + len], src as u64)
        {
            crate::FRAME_ALLOCATOR.free(frame);
            return Err(e);
        }
    }
    Ok(frame)
}

/// Apply ELF relocations for PIE binaries
fn apply_relocations(
    elf: &ElfExecutable,
    image: &FileImage<'_>,
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
                let ptr = phys_to_virt(phys).cast::<u64>();
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
    mut argv: ArgStrings,
    path: &[u8],
    path_inaccessible: bool,
) -> KernelResult<(Arc<File>, ArgStrings)> {
    use crate::task::binfmt_script::{BINPRM_BUF_SIZE, MAX_DEPTH, parse, rewrite_argv};
    let mut name = path.to_vec();
    for depth in 0.. {
        let head = {
            let image = FileImage::new(&file)?;
            let n = (image.size as usize).min(BINPRM_BUF_SIZE);
            crate::util::elf::ElfSource::read_at(&image, 0, n).ok_or(KernelError::Io)?
        };
        let (interp, arg) = match parse(&head) {
            None => break,
            Some(r) => r?,
        };
        if depth >= MAX_DEPTH {
            return Err(KernelError::TooManySymlinks);
        }
        if path_inaccessible {
            return Err(KernelError::NotFound);
        }
        argv = rewrite_argv(&argv, interp, arg, &name)?;
        name = interp.to_vec();
        file = kernel_open_exec(interp)?;
    }
    Ok((file, argv))
}

struct FileImage<'a> {
    file: &'a File,
    /// Size when exec opened it (segments past it read as zeros)
    size: u64,
}

impl FileImage<'_> {
    fn new(file: &File) -> KernelResult<FileImage<'_>> {
        let size = file.get_inode().ok_or(KernelError::NotFound)?.get_size();
        if size == 0 {
            return Err(KernelError::ExecFormat); // Empty file can't be executable
        }
        Ok(FileImage { file, size })
    }

    /// Fill `buf` from offset `off`; the bytes read (fewer at the end
    /// of the file)
    fn read_into(&self, buf: &mut [u8], off: u64) -> KernelResult<usize> {
        let mut done = 0;
        while done < buf.len() {
            let n = self
                .file
                .pread(&mut buf[done..], off + done as u64)
                .map_err(|_| KernelError::Io)?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}

impl crate::util::elf::ElfSource for FileImage<'_> {
    fn read_at(&self, off: u64, len: usize) -> Option<Vec<u8>> {
        let mut v = alloc::vec![0u8; len];
        (self.read_into(&mut v, off).ok()? == len).then_some(v)
    }
}

/// A frame for the new image's user memory: stops at the kernel's
/// reserve like any user page (`mm::fault::alloc_user`), ENOMEM then
fn user_frame() -> KernelResult<u64> {
    crate::mm::fault::alloc_user().ok_or(KernelError::OutOfMemory)
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
    /// A secure exec (set-id: Linux bprm->secureexec)
    pub secure: bool,
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
    ExecIdentity {
        name,
        dumpable,
        secure: secureexec(&c),
    }
}

/// End the other threads of the caller's group and wait until they
/// have exited and, but for the leader, been released (Linux
/// de_thread: a traced zombie waits for its tracer); a non-leader
/// caller then takes the leader's place. EAGAIN if the group is exiting, or a fatal signal
/// arrives meanwhile (the caller then dies on its way out). Threads
/// running user code end at their next syscall or fault (P7: IRQ
/// return).
fn de_thread(tid: crate::task::Tid) -> KernelResult<()> {
    use crate::sync::waitqueue::WaitEntry;
    use crate::task::percpu::{SleepState, schedule};

    let tgid = percpu::current_pid();
    let Some(sig) = crate::signal::get_task_signal_struct(tid) else {
        return Ok(());
    };
    if percpu::exec_waits(tgid, tid) {
        if !sig.start_exec(tid) {
            return Err(KernelError::WouldBlock);
        }
        crate::signal::zap_group_others(tgid, tid);
        let wq = &crate::task::proc::CHILD_EXIT_WQ;
        let w = core::pin::pin!(WaitEntry::new());
        let r = loop {
            wq.prepare_to_wait(w.as_ref(), SleepState::Killable);
            if !percpu::exec_waits(tgid, tid) {
                break Ok(());
            }
            if crate::signal::fatal_signal_pending() {
                break Err(KernelError::WouldBlock);
            }
            schedule();
        };
        wq.finish_wait(w.as_ref());
        sig.end_exec(tid);
        r?;
    }
    // Released after TASKLIST: the old leader and exited threads; a
    // tracer waiting for the old leader rechecks (Linux de_thread:
    // __wake_up_parent before its silent release)
    let gone = percpu::take_leadership(tgid, tid);
    if !gone.is_empty() {
        drop(gone);
        crate::task::proc::CHILD_EXIT_WQ.wake_all();
    }
    Ok(())
}

/// Exec failed past its point of no return: the old image's other
/// threads may be gone, so the caller dies on its way out (Linux
/// bprm_execve: force_fatal_sig(SIGSEGV) unless a fatal signal is
/// already pending)
fn exec_fatal() {
    if !crate::signal::fatal_signal_pending() {
        crate::signal::force_sigsegv(percpu::current_tid());
    }
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
    argv: ArgStrings,
    envp: ArgStrings,
    frame_alloc: &mut FA,
) -> KernelResult<Infallible> {
    exec_file(path, kernel_open_exec, false, argv, envp, frame_alloc)
}

/// do_execve with the file opened by `open` from the name (Linux
/// bprm->filename: the path, or /dev/fd/N[/path] for execveat), once
/// the credential guard is held
fn exec_file<FA, F>(
    path: Vec<u8>,
    open: F,
    path_inaccessible: bool,
    argv: ArgStrings,
    envp: ArgStrings,
    frame_alloc: &mut FA,
) -> KernelResult<Infallible>
where
    FA: FrameAlloc<PhysAddr = u64>,
    F: FnOnce(&[u8]) -> KernelResult<Arc<File>>,
{
    // Linux prepare_bprm_creds: the thread group's cred_guard_mutex from
    // the first credential check until the new image is in place, so
    // ptrace attach and mm_access never see the new mm with the old
    // dumpability or the reverse; dropped on every error return
    let guard = crate::signal::CredGuard::lock(percpu::current_tid())?;
    crate::task::nproc_exec_check()?;
    let pathname = &path[..];
    let file = open(pathname)?;
    let (file, argv) = resolve_scripts(file, argv, pathname, path_inaccessible)?;
    // No writer while it runs, and none now (Linux do_open_execat ->
    // exe_file_deny_write_access): ETXTBSY if open for writing
    let deny = file
        .get_inode()
        .map(|i| i.deny_write_access())
        .transpose()?;
    // To the least loaded CPU while the footprint is small (Linux
    // bprm_execve -> sched_exec)
    percpu::sched_exec();

    // The file is read where needed: headers now, segments as they load
    let image = FileImage::new(&file)?;

    // Parse ELF
    let elf = ElfExecutable::parse(&image)?;
    // Dynamically linked: the program interpreter (Linux
    // load_elf_binary): ENOENT if missing (open_exec), ELIBBAD if it is
    // not an ELF file for this machine
    let interp_file = match &elf.interp {
        Some(i) => Some(kernel_open_exec(i)?),
        None => None,
    };
    // Denied while it loads (Linux open_exec of the interpreter,
    // allowed again once it is loaded)
    let _interp_deny = interp_file
        .as_ref()
        .and_then(|f| f.get_inode())
        .map(|i| i.deny_write_access())
        .transpose()?;
    let Ok(interp_image) = interp_file.as_deref().map(FileImage::new).transpose() else {
        return Err(KernelError::LibBad);
    };
    let Ok(interp) = interp_image.as_ref().map(ElfExecutable::parse).transpose() else {
        return Err(KernelError::LibBad);
    };

    // PIE images load at ELF_ET_DYN_BASE (aligned to their segments),
    // ET_EXEC at their link address
    let base_addr = if elf.is_pie {
        ELF_ET_DYN_BASE & !(elf.align.max(PAGE_SIZE) - 1)
    } else {
        0
    };
    // The stack VMA's bottom: the image must stay below it
    let stack = StackSize::new(&argv, &envp, pathname);
    check_segments(&elf, base_addr, stack.bottom())?;
    let interp_base = match &interp {
        Some(ie) => interp_base(ie, &elf, base_addr)?,
        None => 0,
    };
    if let Some(ie) = &interp {
        check_segments(ie, interp_base, stack.bottom())?;
    }
    // With an interpreter the program starts there; it finds the
    // program's own entry in AT_ENTRY
    let entry_point = match &interp {
        Some(ie) => ie.entry + interp_base,
        None => elf.entry + base_addr,
    };

    // Create new page table for the process
    let Some(mut new_page_table) = ArchPageTable::new_user(frame_alloc) else {
        return Err(KernelError::OutOfMemory);
    };

    // Link the kernel half (x86; arm64 keeps the kernel in TTBR1)
    new_page_table.copy_kernel_mappings();

    // The new address space owns the table from here: an error below
    // drops it, freeing whatever was loaded (Linux bprm->mm)
    let mm = crate::mm::mm_alloc(new_page_table.root_table_phys());

    // Load ELF segments and get the end address for brk initialization
    // The image is mapped from the page cache (Linux elf_map: private
    // file mappings, the text shared by every process running it) when
    // its filesystem maps its cache and the kernel writes nothing into
    // it: a static PIE without an interpreter is relocated here, so its
    // pages are private copies made now
    let maps = |f: &File| f.get_inode().is_some_and(|i| i.i_op.maps_cache());
    let exe_map = (maps(&file) && !(elf.is_pie && interp.is_none())).then_some(&file);
    let interp_map = interp_file.as_ref().filter(|f| maps(f));
    let segments_end = load_elf_segments(
        &elf,
        &image,
        &mut new_page_table,
        frame_alloc,
        base_addr,
        exe_map.is_some(),
    )?;

    if let (Some(ie), Some(iimg)) = (&interp, &interp_image) {
        load_elf_segments(
            ie,
            iimg,
            &mut new_page_table,
            frame_alloc,
            interp_base,
            interp_map.is_some(),
        )?;
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
    let args = setup_user_stack(
        &mut new_page_table,
        frame_alloc,
        &argv,
        &envp,
        &info,
        &stack,
    )?;
    // The new image's VMAs, then the signal page in the free space they
    // leave (Linux arch_setup_additional_pages: get_unmapped_area and a
    // special mapping once the image and stack are in place)
    let mut vmas = image_vmas(&elf, base_addr, stack.bottom(), exe_map);
    if let Some(ie) = &interp {
        vmas.extend(segment_vmas(ie, interp_base, interp_map));
    }
    if let Some(v) = map_sigpage(&mut new_page_table, frame_alloc, &vmas)? {
        vmas.push(v);
    }
    let user_sp = args.start_stack;

    let ident = exec_identity(pathname, &file);

    let tid = percpu::current_tid();

    // The point of no return (Linux begin_new_exec sets
    // point_of_no_return before de_thread): from here a failure kills
    // the process instead of returning to the old image

    // The other threads end before the new image starts (Linux
    // begin_new_exec -> de_thread)
    if let Err(e) = de_thread(tid) {
        exec_fatal();
        return Err(e);
    }
    // Handlers, alternate stack and timers of the old image go
    if let Err(e) = crate::signal::exec_signals() {
        exec_fatal();
        return Err(e);
    }

    // Now we need to update the current task and switch to the new address space

    // The thread and process keyrings are not for the new image (Linux
    // prepare_exec_creds)
    crate::keys::keyring::exec_keyrings(&percpu::current());

    // What the process registered before (an mq_notify) is not for the
    // new image (Linux setup_new_exec: self_exec_id++); after de_thread
    // the caller leads the process
    if let Ok(nr) = u32::try_from(percpu::current_pid())
        && let Some(p) = crate::task::pid::find_pid(&crate::ns::INIT_PID_NS, nr)
    {
        p.exec_done();
    }

    // Linux begin_new_exec clears PF_FORKNOEXEC before it closes the
    // close-on-exec descriptors: whoever sees one of them close (EOF on
    // a pipe) sees the exec, and its setpgid is EACCES
    percpu::current().clear_flag(crate::task::pf::FORKNOEXEC);

    // Private fd table without the close-on-exec descriptors
    crate::task::fdtable::exec_task_fd();

    // Signal vfork completion if parent is waiting
    // Must be done before we switch address spaces since parent may be blocked
    percpu::signal_vfork_done();

    // Initialize brk for the new process
    // Calculate page-aligned start_brk (end of loaded segments, rounded up)
    // (segments end below TASK_SIZE: check_segments)
    let start_brk = segments_end
        .checked_next_multiple_of(PAGE_SIZE)
        .unwrap_or(crate::mm::TASK_SIZE);

    // The new image's VMAs
    {
        let mut m = mm.mmap_write();
        m.set_brk(start_brk);
        let exe = match (file.f_path(), crate::fs::namei::nd_root()) {
            (Some(p), Ok(root)) => crate::fs::dentry::d_path(&p, &root).0,
            _ => alloc::vec::Vec::new(),
        };
        m.set_exe(exe.into(), deny);
        let code = image_layout(&elf, base_addr);
        m.set_args(MmLayout {
            start_code: code.start_code,
            end_code: code.end_code,
            start_data: code.start_data,
            end_data: code.end_data,
            ..args
        });
        for vma in vmas {
            if vma.flags & crate::mm::VM_SIGPAGE != 0 {
                mm.set_sigpage(vma.start);
            }
            m.insert_vma(vma);
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
pub fn sys_execve(
    pathname: UserPtr<u8>,
    argv: UserPtr<u64>,
    envp: UserPtr<u64>,
) -> KernelResult<i64> {
    let path = crate::fs::namei::getname(pathname, false)?;
    let (argv, envp) = copy_args(&path, argv, envp)?;
    let mut frame_alloc = crate::mm::frame_alloc::FrameAllocRef(&crate::FRAME_ALLOCATOR);
    match do_execve(path, argv, envp, &mut frame_alloc)? {}
}

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
pub fn sys_execveat(
    dirfd: i32,
    pathname: UserPtr<u8>,
    argv: UserPtr<u64>,
    envp: UserPtr<u64>,
    flags: i32,
) -> KernelResult<i64> {
    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let path = crate::fs::namei::getname(pathname, flags & AT_EMPTY_PATH != 0)?;
    let name = exec_name(dirfd, &path);
    let (argv, envp) = copy_args(&name, argv, envp)?;
    // Linux BINPRM_FLAGS_PATH_INACCESSIBLE: the program came through a
    // close-on-exec fd, so a script's interpreter could not open it
    let via_fd = dirfd != AT_FDCWD && path.first() != Some(&b'/');
    let inaccessible = via_fd
        && crate::fs::syscall::current_fd_table()
            .lock()
            .get_fd_flags(dirfd)
            & crate::io::pipe::FD_CLOEXEC
            != 0;
    let open = |_: &[u8]| exec_lookup(dirfd, &path, flags).and_then(crate::fs::open_exec);
    let mut frame_alloc = crate::mm::frame_alloc::FrameAllocRef(&crate::FRAME_ALLOCATOR);
    match exec_file(name, open, inaccessible, argv, envp, &mut frame_alloc)? {}
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
fn exec_lookup(dirfd: i32, path: &[u8], flags: i32) -> KernelResult<crate::fs::Path> {
    use crate::fs::namei::{LookupFlags, filename_lookup};
    filename_lookup(dirfd, path, LookupFlags::at(flags))
}

#[cfg(test)]
mod tests {
    use super::{ElfExecutable, PAGE_SIZE, highest_gap, image_spans};

    const P: u64 = PAGE_SIZE;

    #[test]
    fn gap_below_nested() {
        // B nests in A: the page under the top is inside A
        let mut s = [(P, 11 * P), (2 * P, 3 * P)];
        assert_eq!(highest_gap(&mut s, 11 * P, 0), Some(0));
    }

    #[test]
    fn gap_at_top() {
        let mut s = [(P, 2 * P), (4 * P, 5 * P)];
        assert_eq!(highest_gap(&mut s, 8 * P, 0), Some(7 * P));
    }

    #[test]
    fn gap_between() {
        let mut s = [(P, 2 * P), (3 * P, 9 * P), (4 * P, 5 * P)];
        assert_eq!(highest_gap(&mut s, 9 * P, P), Some(2 * P));
    }

    #[test]
    fn gap_none() {
        let mut s = [(P, 4 * P), (2 * P, 9 * P)];
        assert_eq!(highest_gap(&mut s, 9 * P, P), None);
        assert_eq!(highest_gap(&mut [], P, P), None);
    }

    fn elf(segs: &[(u64, usize)]) -> ElfExecutable {
        use crate::util::elf::{ElfSegment, SegmentFlags};
        ElfExecutable {
            entry: 0,
            segments: segs
                .iter()
                .map(|&(vaddr, mem_size)| ElfSegment {
                    vaddr,
                    mem_size,
                    file_size: 0,
                    flags: SegmentFlags::from_elf_flags(4),
                    offset: 0,
                })
                .collect(),
            is_pie: false,
            rela: None,
            phdr: 0,
            phent: 56,
            phnum: segs.len() as u64,
            align: P,
            interp: None,
            end: 0,
        }
    }

    fn spans(segs: &[(u64, usize)]) -> Vec<(u64, u64, usize)> {
        image_spans(&elf(segs), 0)
            .iter()
            .map(|s| (s.start, s.end, s.seg))
            .collect()
    }

    #[test]
    fn spans_sorted_whatever_the_file_order() {
        let s = spans(&[(6 * P, 2 * P as usize), (4 * P, P as usize)]);
        assert_eq!(s, [(4 * P, 5 * P, 1), (6 * P, 8 * P, 0)]);
    }

    #[test]
    fn spans_later_segment_owns_shared_page() {
        // Text ends mid-page, data starts in that page
        let s = spans(&[(4 * P, P as usize + 0x10), (5 * P + 0x10, P as usize)]);
        assert_eq!(s, [(4 * P, 5 * P, 0), (5 * P, 7 * P, 1)]);
    }

    #[test]
    fn spans_overlap_goes_to_the_later() {
        // A later segment inside an earlier one splits it
        let s = spans(&[(4 * P, 4 * P as usize), (5 * P, P as usize), (0, 0)]);
        assert_eq!(s, [(4 * P, 5 * P, 0), (5 * P, 6 * P, 1), (6 * P, 8 * P, 0)]);
        // An earlier one inside a later one vanishes
        let s = spans(&[(5 * P, P as usize), (4 * P, 4 * P as usize)]);
        assert_eq!(s, [(4 * P, 8 * P, 1)]);
    }

    #[test]
    fn gap_span_above_top() {
        let mut s = [(2 * P, 3 * P), (10 * P, 12 * P)];
        assert_eq!(highest_gap(&mut s, 8 * P, 0), Some(7 * P));
    }
}
