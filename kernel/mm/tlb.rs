//! TLB flushing and address-space switching (Linux arch/x86/mm/tlb.c,
//! include/asm-generic/tlb.h)
//!
//! Every flush names its address space: [`flush_tlb_mm_range`],
//! [`flush_tlb_page`], [`flush_tlb_mm`]; [`flush_tlb_kernel_range`] is
//! for the kernel half. Where the hardware broadcasts TLB maintenance
//! (arm64 `TLBI ...IS`) the arch does it all; otherwise (x86) a flush
//! reaches the CPUs that have the address space loaded:
//!
//! - Each [`Mm`] has an [`MmContext`]: `cpumask`, the CPUs it is loaded
//!   on, and `tlb_gen`, bumped by every flush of it.
//! - Each CPU has a [`TlbState`]: the mm it has loaded (`loaded_mm`;
//!   [`SWITCHING`] while [`switch_mm`] changes it) and the `tlb_gen` its
//!   TLB is known to reflect (`loaded_gen`).
//! - A flush bumps `tlb_gen` (a full barrier: the PTE changes before it
//!   are visible to any CPU that then reads the new generation) and
//!   brings this CPU up to date if it has the mm loaded ([`flush_func`]).
//! - [`switch_mm`] follows Linux switch_mm_irqs_off: `loaded_mm` =
//!   SWITCHING, this CPU's cpumask bit set, a full barrier, `tlb_gen`
//!   read, then the table loaded (x86: the CR3 write flushes all) and
//!   `loaded_mm`/`loaded_gen` set. A flusher that misses the bit made
//!   its PTE change before the barrier, so the walk after the load sees
//!   it; one that sees the bit reaches this CPU.
//!
//! - The other CPUs of the cpumask get the flush by IPI
//!   (`smp_call_function_many`, waiting): their handler does the same.
//!
//! Generations order flushes: a CPU whose `loaded_gen` already covers
//! a flush skips it; one more than one generation behind flushes all.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};

use super::Mm;
use crate::arch::{CurrentArch, PerCpuOps, local_irq_restore, local_irq_save, paging};
use crate::cpumask::{CpuMask, NR_CPUS};

use crate::arch::tlb as arch;
pub use crate::arch::tlb::ArchCtx;

/// Stride of a 4KB-page range
pub const PAGE_SHIFT: u32 = 12;
/// Stride of a 2MB-page range
pub const PMD_SHIFT: u32 = 21;
/// `end` of a flush of the whole address space
pub const FLUSH_ALL: u64 = u64::MAX;

/// `TlbState::loaded_mm` while `switch_mm` changes it (never an `Mm`
/// address: those are aligned)
pub const SWITCHING: usize = 1;

/// Source of `MmContext::ctx_id` (Linux last_mm_ctx_id): unique ids
/// across all address spaces need one global counter, taken once per
/// address space
static LAST_CTX_ID: AtomicU64 = AtomicU64::new(1);

/// TLB state of an address space (Linux mm_context_t)
pub struct MmContext {
    /// CPUs that have it loaded (x86 without PCID: a CPU that switched
    /// away holds none of its entries, its bit is cleared)
    pub cpumask: CpuMask,
    /// Bumped by every flush (Linux context.tlb_gen)
    pub tlb_gen: AtomicU64,
    /// Never reused, unlike the address of the `Mm`
    pub ctx_id: u64,
    /// Arch state (arm64: the ASID)
    pub arch: ArchCtx,
}

impl MmContext {
    pub fn new() -> Self {
        Self {
            cpumask: CpuMask::new(),
            tlb_gen: AtomicU64::new(0),
            ctx_id: LAST_CTX_ID.fetch_add(1, Ordering::Relaxed),
            arch: ArchCtx::new(),
        }
    }
}

impl Default for MmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// One CPU's TLB state (Linux cpu_tlbstate). Written by its own CPU
/// only, with interrupts disabled (the flush IPI handler runs there
/// too); atomics so that no `unsafe` is needed, Relaxed since no other
/// CPU reads them.
pub struct TlbState {
    /// The `Mm` loaded (its address), 0 for the kernel's table, or
    /// [`SWITCHING`]. The loaded `Mm` stays alive until this CPU
    /// switches away: its task (or an exited task's `DeadTask`) holds a
    /// reference until then.
    loaded_mm: AtomicUsize,
    /// The `tlb_gen` of `loaded_mm` this CPU's TLB reflects
    loaded_gen: AtomicU64,
}

/// Per-CPU TLB state: each CPU's own, no cross-CPU traffic
static TLB_STATE: [TlbState; NR_CPUS] = [const {
    TlbState {
        loaded_mm: AtomicUsize::new(0),
        loaded_gen: AtomicU64::new(0),
    }
}; NR_CPUS];

/// This CPU's id (0 before per-CPU data exists: only the boot CPU runs)
fn this_cpu() -> u32 {
    CurrentArch::try_current_cpu_id().unwrap_or(0)
}

fn this_state() -> &'static TlbState {
    &TLB_STATE[this_cpu() as usize]
}

/// A flush request (Linux flush_tlb_info)
pub struct FlushInfo {
    /// The address space (compared with `loaded_mm`)
    mm: usize,
    start: u64,
    end: u64,
    stride_shift: u32,
    freed_tables: bool,
    /// The generation this flush brings a CPU to
    new_gen: u64,
}

/// Flush [start, end) of `mm` (one entry per `1 << stride_shift`
/// bytes; `freed_tables`: page tables of the range were freed, so the
/// paging-structure caches must go too) on every CPU that may cache it
/// (Linux flush_tlb_mm_range). Thread context; interrupts may be off
/// (a syscall), never under an IrqSpinlock.
pub fn flush_tlb_mm_range(mm: &Mm, start: u64, end: u64, stride_shift: u32, freed_tables: bool) {
    let ctx = mm.context();
    if arch::flush_mm_range(&ctx.arch, start, end, stride_shift, freed_tables) {
        return;
    }
    // Full barrier: the PTE changes are visible before the generation,
    // and before the cpumask is read
    let new_gen = ctx.tlb_gen.fetch_add(1, Ordering::SeqCst) + 1;
    let info = FlushInfo {
        mm: mm as *const Mm as usize,
        start,
        end,
        stride_shift,
        freed_tables,
        new_gen,
    };
    let cpu = this_cpu();
    let irq = local_irq_save();
    if ctx.cpumask.test(cpu) {
        flush_func(&info);
    }
    local_irq_restore(irq);
    // The other CPUs that have it loaded (Linux native_flush_tlb_multi);
    // `info` stays alive: the call waits for all of them
    let mut others = ctx.cpumask.snapshot();
    others.clear(cpu);
    if !others.is_empty() {
        let p = &info as *const FlushInfo as usize;
        crate::smp::smp_call_function_many(&others, flush_ipi, p, true);
    }
}

/// `flush_func` on a target CPU (call-function IPI, interrupts off)
fn flush_ipi(info: usize) {
    // SAFETY: the sender's FlushInfo, alive until every target returned
    flush_func(unsafe { &*(info as *const FlushInfo) });
}

/// Flush the page at `va` of `mm`
pub fn flush_tlb_page(mm: &Mm, va: u64) {
    let va = va & !(paging::PAGE_SIZE - 1);
    flush_tlb_mm_range(mm, va, va + paging::PAGE_SIZE, PAGE_SHIFT, false);
}

/// Flush all of `mm`, paging-structure caches included
pub fn flush_tlb_mm(mm: &Mm) {
    flush_tlb_mm_range(mm, 0, FLUSH_ALL, PAGE_SHIFT, true);
}

/// Flush the kernel range [start, end) on every CPU (Linux
/// flush_tlb_kernel_range): the shared kernel half (vmalloc/ioremap
/// window) changed. Thread context.
pub fn flush_tlb_kernel_range(start: u64, end: u64) {
    if arch::flush_kernel_range(start, end) {
        return;
    }
    // Every CPU, this one included: kernel threads run everywhere
    let range = (start, end);
    crate::smp::on_each_cpu(kernel_flush_ipi, &range as *const (u64, u64) as usize);
}

/// The kernel-range flush on one CPU (interrupts off)
fn kernel_flush_ipi(info: usize) {
    // SAFETY: the sender's range, alive until every CPU returned
    let (start, end) = unsafe { *(info as *const (u64, u64)) };
    local_flush(start, end, PAGE_SHIFT);
}

/// Flush [start, end) on this CPU, everything past `FLUSH_CEILING`
fn local_flush(start: u64, end: u64, shift: u32) {
    if end == FLUSH_ALL || end.saturating_sub(start) >> shift > arch::FLUSH_CEILING {
        arch::local_flush_all();
        return;
    }
    let mut va = start & !((1u64 << shift) - 1);
    while va < end {
        arch::local_flush_one(va);
        va += 1 << shift;
    }
}

/// Bring this CPU's TLB up to date for `f` (Linux flush_tlb_func), with
/// interrupts disabled: nothing if the mm is not loaded here (it is
/// flushed at its next load) or this CPU already reflects `f.new_gen`;
/// a ranged flush if `f` is the only generation it misses, else all.
fn flush_func(f: &FlushInfo) {
    let st = this_state();
    if st.loaded_mm.load(Ordering::Relaxed) != f.mm {
        return;
    }
    // SAFETY: `f.mm` is loaded here, so alive (see TlbState::loaded_mm)
    let ctx = unsafe { &*(f.mm as *const Mm) }.context();
    let mm_gen = ctx.tlb_gen.load(Ordering::Acquire);
    let local = st.loaded_gen.load(Ordering::Relaxed);
    if local >= mm_gen || f.new_gen <= local {
        return;
    }
    let partial = f.end != FLUSH_ALL && f.new_gen == local + 1 && f.new_gen == mm_gen;
    if partial {
        local_flush(f.start, f.end, f.stride_shift);
        st.loaded_gen.store(f.new_gen, Ordering::Relaxed);
    } else {
        arch::local_flush_all();
        st.loaded_gen.store(mm_gen, Ordering::Relaxed);
    }
    let _ = f.freed_tables; // x86 INVLPG drops the paging-structure caches too
}

/// This CPU starts taking flush IPIs (`smp::set_active`): drop what it
/// may have cached before, which a kernel-range flush did not reach
pub fn cpu_active() {
    let irq = local_irq_save();
    arch::local_flush_all();
    local_irq_restore(irq);
}

/// Switch this CPU to the address space `next` (None: the kernel's
/// table, for kernel threads) (Linux switch_mm_irqs_off). Called by the
/// scheduler before a context switch and by exec; interrupts are
/// disabled for the switch.
pub fn switch_mm(next: Option<&Mm>) {
    let irq = local_irq_save();
    switch_mm_irqs_off(next);
    local_irq_restore(irq);
}

fn switch_mm_irqs_off(next: Option<&Mm>) {
    let cpu = this_cpu();
    let st = this_state();
    let next_ptr = next.map_or(0, |m| m as *const Mm as usize);
    let prev = st.loaded_mm.load(Ordering::Relaxed);
    if prev == next_ptr {
        // Same address space (threads of one process, or kernel threads):
        // flushes of it reach this CPU while its bit is set
        return;
    }
    st.loaded_mm.store(SWITCHING, Ordering::Relaxed);
    if prev > SWITCHING {
        // SAFETY: the previous mm is still loaded here, so alive
        unsafe { &*(prev as *const Mm) }
            .context()
            .cpumask
            .clear(cpu);
    }
    let (root, cur_gen) = match next {
        Some(mm) => {
            mm.context().cpumask.set(cpu);
            // Pairs with the flusher's tlb_gen increment: either it
            // sees our bit, or we see its PTE changes after the load
            fence(Ordering::SeqCst);
            (mm.pgd(), mm.context().tlb_gen.load(Ordering::Acquire))
        }
        None => (kernel_root(), 0),
    };
    arch::load_mm(root, next.map(|m| &m.context().arch));
    st.loaded_gen.store(cur_gen, Ordering::Relaxed);
    st.loaded_mm.store(next_ptr, Ordering::Relaxed);
}

/// The table kernel threads run on (x86 swapper, arm64 empty TTBR0)
fn kernel_root() -> u64 {
    use crate::arch::SchedArch;
    <CurrentArch as SchedArch>::SchedPageTable::kernel_identity().root_table_phys()
}
