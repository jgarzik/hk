//! Per-CPU data structures
//!
//! This module provides per-CPU data storage accessed via the GS segment.
//! Each CPU has its own `PerCpu` structure containing CPU-local state.
//!
//! GS follows Linux's SWAPGS model: in the kernel MSR_GS_BASE holds this
//! CPU's `PerCpu` and MSR_KERNEL_GS_BASE the user's GS base; every entry
//! from user mode (syscall, IDT stubs when the saved CS is a user
//! selector) runs `swapgs` first and every return to user mode runs it
//! last, so user code has its own GS base (`mov gs`, ARCH_SET_GS) and
//! can never redirect the kernel's. NMI, #DF and #MC may arrive in the
//! instructions around those swaps: their (paranoid) entries read
//! MSR_GS_BASE instead (a kernel address is negative; a user one is
//! below TASK_SIZE).

use ::core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Per-CPU data slots (logical CPU ids are below this)
pub const MAX_CPUS: usize = crate::cpumask::NR_CPUS;

/// Per-CPU data structure
///
/// Accessed via the GS segment base register. The first field must be
/// a self-pointer so that `mov rax, gs:0` gives us the PerCpu address.
#[repr(C, align(64))]
pub struct PerCpu {
    /// Self-pointer for GS:0 access
    pub self_ptr: *mut PerCpu,

    /// Top of the current task's kernel stack: `syscall_entry` switches
    /// to it (Linux cpu_current_top_of_stack); set with TSS.RSP0 at
    /// every switch to a user task
    pub top_of_stack: u64,

    /// The user RSP while `syscall_entry` switches stacks (Linux
    /// cpu_tss_rw.x86_tss.sp2 scratch)
    pub user_rsp: u64,

    /// Logical CPU ID (0 = BSP, 1+ = APs)
    pub cpu_id: u32,

    /// Hardware APIC ID
    pub apic_id: u32,

    /// Is this the bootstrap processor?
    pub is_bsp: bool,

    /// Has this CPU completed initialization?
    pub is_online: AtomicBool,

    /// Timer tick count for this CPU
    pub ticks: AtomicU64,

    /// The running task (`*const KernelTask`; 0: the boot task,
    /// `task::percpu::INIT_TASK`), set by the scheduler at each switch
    pub curr: AtomicUsize,

    /// Nesting depth of interrupt handlers (to avoid rescheduling in nested interrupts)
    pub interrupt_depth: AtomicU32,

    /// Preemption count - tracks nested critical sections
    ///
    /// When > 0, preemption is disabled on this CPU. This count includes:
    /// - Explicit preempt_disable() calls
    /// - Spinlock hold counts (each spinlock increments this)
    /// - Interrupt context (optional - some kernels track this separately)
    ///
    /// Preemption is only allowed when this reaches 0 and need_resched is set.
    pub preempt_count: AtomicU32,
}

impl PerCpu {
    /// Create an uninitialized PerCpu
    const fn uninit() -> Self {
        Self {
            self_ptr: core::ptr::null_mut(),
            top_of_stack: 0,
            user_rsp: 0,
            cpu_id: 0,
            apic_id: 0,
            is_bsp: false,
            is_online: AtomicBool::new(false),
            ticks: AtomicU64::new(0),
            curr: AtomicUsize::new(0),
            interrupt_depth: AtomicU32::new(0),
            preempt_count: AtomicU32::new(0),
        }
    }

    /// Initialize the PerCpu structure
    pub fn init(&mut self, cpu_id: u32, apic_id: u32, is_bsp: bool) {
        set_tsc_aux(cpu_id);
        self.self_ptr = self as *mut PerCpu;
        self.cpu_id = cpu_id;
        self.apic_id = apic_id;
        self.is_bsp = is_bsp;
        self.ticks.store(0, Ordering::Relaxed);
        self.curr.store(0, Ordering::Relaxed);
        self.interrupt_depth.store(0, Ordering::Relaxed);
        self.preempt_count.store(0, Ordering::Relaxed);
        // Don't set is_online yet - that happens after full init
    }

    /// Mark this CPU as online
    pub fn set_online(&self) {
        self.is_online.store(true, Ordering::Release);
    }
}

/// Global array of per-CPU data
///
/// This is statically allocated to avoid heap allocation during early boot.
static mut PERCPU_ARRAY: [PerCpu; MAX_CPUS] = [const { PerCpu::uninit() }; MAX_CPUS];

/// Number of CPUs that have come online
pub static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

/// BSP's APIC ID (set during init)
static BSP_APIC_ID: AtomicU32 = AtomicU32::new(0);

/// Get a reference to a CPU's per-CPU data by CPU ID
///
/// # Safety
/// The CPU ID must be valid (< MAX_CPUS).
pub fn get_percpu(cpu_id: u32) -> &'static mut PerCpu {
    assert!((cpu_id as usize) < MAX_CPUS, "CPU ID out of range");
    unsafe { &mut PERCPU_ARRAY[cpu_id as usize] }
}

/// Get a mutable reference to the current CPU's per-CPU data
///
/// # Safety
/// The GS base must have been set up correctly, and the caller must ensure
/// no other references exist.
#[inline]
pub unsafe fn current_cpu_mut() -> &'static mut PerCpu {
    let ptr: *mut PerCpu;
    unsafe {
        ::core::arch::asm!(
            "mov {}, gs:0",
            out(reg) ptr,
            options(pure, nomem, nostack, preserves_flags)
        );
        &mut *ptr
    }
}

/// Try to get current CPU data (None before the boot CPU's per-CPU
/// data exists): a load of gs:0, valid on every CPU running kernel code
/// once `init_bsp` ran (an AP sets its GS base first thing, `init_ap`)
#[inline]
pub fn try_current_cpu() -> Option<&'static PerCpu> {
    if !crate::task::percpu::PERCPU_UP.load(Ordering::Relaxed) {
        return None;
    }
    // SAFETY: GS base is this CPU's PerCpu (see above)
    unsafe { Some(current_cpu_mut()) }
}

/// Initialize per-CPU data for the BSP (CPU 0)
///
/// This must be called early in boot, before any per-CPU access.
pub fn init_bsp(apic_id: u8) {
    BSP_APIC_ID.store(apic_id as u32, Ordering::SeqCst);

    let percpu = get_percpu(0);
    percpu.init(0, apic_id as u32, true);

    // Set GS base to point to our per-CPU data; no user GS base yet
    set_gs_base(percpu as *mut PerCpu as u64);
    write_user_gsbase(0);
    crate::task::percpu::PERCPU_UP.store(true, Ordering::Release);

    // Mark BSP as online
    percpu.set_online();
    CPU_COUNT.store(1, Ordering::SeqCst);
}

/// Initialize per-CPU data for an AP
///
/// Called by the AP after it has set up its GDT and stack.
/// Returns the CPU ID assigned to this AP.
pub fn init_ap(apic_id: u8) -> u32 {
    // Atomically claim the next CPU ID
    let cpu_id = CPU_COUNT.fetch_add(1, Ordering::SeqCst);
    assert!((cpu_id as usize) < MAX_CPUS, "Too many CPUs");

    let percpu = get_percpu(cpu_id);
    percpu.init(cpu_id, apic_id as u32, false);

    // Set GS base to point to our per-CPU data; no user GS base yet
    set_gs_base(percpu as *mut PerCpu as u64);
    write_user_gsbase(0);

    // Mark as online
    percpu.set_online();

    cpu_id
}

/// Get the number of online CPUs
pub fn online_cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Acquire)
}

/// IA32_TSC_AUX: this CPU's index (Linux keeps cpu | node << 12 there for
/// RDTSCP/RDPID getcpu)
const MSR_TSC_AUX: u32 = 0xC0000103;

/// Record this CPU's index in TSC_AUX (user code cannot write it)
fn set_tsc_aux(cpu_id: u32) {
    // SAFETY: TSC_AUX exists (RDTSCP checked at boot)
    unsafe {
        ::core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_TSC_AUX,
            in("eax") cpu_id,
            in("edx") 0u32,
            options(nostack, preserves_flags)
        );
    }
}

/// MSR_GS_BASE: the live GS base (in the kernel: this CPU's PerCpu)
pub const MSR_GS_BASE: u32 = 0xC0000101;
/// MSR_KERNEL_GS_BASE: the base `swapgs` exchanges it with (in the
/// kernel: the user's GS base)
const MSR_KERNEL_GS_BASE: u32 = 0xC0000102;

/// Write an MSR
fn wrmsr(msr: u32, v: u64) {
    // SAFETY: the base MSRs above take any canonical value
    unsafe {
        ::core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") v as u32,
            in("edx") (v >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

/// Read an MSR
fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: reading the base MSRs above
    unsafe {
        ::core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Set the GS base register (this CPU's per-CPU pointer)
pub fn set_gs_base(addr: u64) {
    wrmsr(MSR_GS_BASE, addr);
}

/// The current task's user GS base, while in the kernel (Linux
/// x86_gsbase_read_cpu_inactive)
pub fn read_user_gsbase() -> u64 {
    rdmsr(MSR_KERNEL_GS_BASE)
}

/// Set the user GS base the next return to user mode swaps in (Linux
/// x86_gsbase_write_cpu_inactive); `addr` passed `fs_base_ok`
pub fn write_user_gsbase(addr: u64) {
    wrmsr(MSR_KERNEL_GS_BASE, addr);
}

/// Load the null selector into the user's GS (Linux load_gs_index(0)):
/// the selector load acts on the live GS, so it runs between two
/// `swapgs`, with interrupts off. It may change the user base, which
/// the caller sets next.
pub fn load_user_gs_null() {
    let irq = crate::arch::local_irq_save();
    // SAFETY: interrupts off; the second swapgs restores the kernel GS
    unsafe {
        ::core::arch::asm!(
            "swapgs",
            "mov gs, {0:x}",
            "swapgs",
            in(reg) 0u32,
            options(nostack, preserves_flags)
        );
    }
    crate::arch::local_irq_restore(irq);
}

// ============================================================================
// User Thread-Local Storage (FS base register)
// ============================================================================

/// MSR address for FS base register (user TLS on x86_64)
pub const MSR_FS_BASE: u32 = 0xC0000100;

/// Set the FS base register (user TLS pointer)
///
/// This is used for user-space thread-local storage. The FS segment
/// register's base address is set via this MSR on x86_64. `addr` must
/// pass `fs_base_ok` (a non-canonical base #GPs the WRMSR).
/// A user FS/GS base must lie below TASK_SIZE_MAX (Linux
/// do_arch_prctl_64, putreg)
pub fn fs_base_ok(addr: u64) -> bool {
    addr < crate::arch::x86_64::paging::TASK_SIZE
}

pub fn write_fs_base(addr: u64) {
    unsafe {
        ::core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_FS_BASE,
            in("eax") addr as u32,
            in("edx") (addr >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

/// Read the FS base register
pub fn read_fs_base() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        ::core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_FS_BASE,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

// ============================================================================
// arch_prctl operation codes
// ============================================================================

/// arch_prctl: Set GS base address
pub const ARCH_SET_GS: i32 = 0x1001;
/// arch_prctl: Set FS base address (user TLS)
pub const ARCH_SET_FS: i32 = 0x1002;
/// arch_prctl: Get FS base address
pub const ARCH_GET_FS: i32 = 0x1003;
/// arch_prctl: Get GS base address
pub const ARCH_GET_GS: i32 = 0x1004;
/// arch_prctl: Get CPUID enable state (1 = enabled, 0 = faulting)
pub const ARCH_GET_CPUID: i32 = 0x1011;
/// arch_prctl: Enable (1) or disable/fault (0) the CPUID instruction
pub const ARCH_SET_CPUID: i32 = 0x1012;

// ============================================================================
// Preemption Control
// ============================================================================

/// Disable preemption on the current CPU
///
/// Increments the preempt_count. While preempt_count > 0, the scheduler
/// will not preempt this CPU even if a higher-priority task becomes runnable.
///
/// This is used by spinlocks and other critical sections that cannot be
/// interrupted by a context switch.
///
/// Must be paired with `preempt_enable()`.
#[inline]
pub fn preempt_disable() {
    if let Some(percpu) = try_current_cpu() {
        percpu.preempt_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Enable preemption on the current CPU
///
/// Decrements the preempt_count. If it reaches 0 and need_resched is set,
/// this may trigger a reschedule (depending on implementation).
///
/// Must be paired with `preempt_disable()`.
#[inline]
pub fn preempt_enable() {
    if let Some(percpu) = try_current_cpu() {
        let prev = percpu.preempt_count.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(prev > 0, "preempt_enable called with preempt_count == 0");

        // If preempt_count is now 0 and reschedule is needed, we could
        // trigger a reschedule here. For now, we defer to the existing
        // reschedule check points (timer interrupt exit, yield, etc.)
    }
}

/// Check if preemption is currently disabled
#[inline]
#[allow(dead_code)] // Utility function for future use and debugging
pub fn preempt_disabled() -> bool {
    try_current_cpu()
        .map(|percpu| percpu.preempt_count.load(Ordering::Relaxed) > 0)
        .unwrap_or(true) // Conservative: assume disabled if no per-CPU data
}

/// Get the current preempt_count value (for debugging)
#[inline]
#[allow(dead_code)] // Utility function for future use and debugging
pub fn preempt_count() -> u32 {
    try_current_cpu()
        .map(|percpu| percpu.preempt_count.load(Ordering::Relaxed))
        .unwrap_or(0)
}

// ============================================================================
// PerCpuOps trait implementation
// ============================================================================

use crate::arch::PerCpuOps;

use super::X86_64Arch;

impl PerCpuOps for X86_64Arch {
    #[inline]
    fn try_current_cpu_id() -> Option<u32> {
        try_current_cpu().map(|percpu| percpu.cpu_id)
    }

    #[inline]
    fn current_task_ptr() -> usize {
        match try_current_cpu() {
            Some(p) => p.curr.load(Ordering::Relaxed),
            None => crate::task::percpu::no_percpu_task(),
        }
    }

    #[inline]
    fn set_current_task_ptr(t: usize) {
        if let Some(p) = try_current_cpu() {
            p.curr.store(t, Ordering::Relaxed);
        }
    }

    fn current_task_ptr_of(cpu: u32) -> usize {
        get_percpu(cpu).curr.load(Ordering::Relaxed)
    }

    #[inline]
    fn interrupt_depth() -> u32 {
        try_current_cpu()
            .map(|percpu| percpu.interrupt_depth.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn cpu_online(cpu: u32) -> bool {
        (cpu as usize) < MAX_CPUS && get_percpu(cpu).is_online.load(Ordering::Acquire)
    }
}
