//! Per-CPU data structures for AArch64
//!
//! This module provides per-CPU data storage accessed via the TPIDR_EL1 register.
//! Each CPU has its own `PerCpu` structure containing CPU-local state.

use crate::task::CurrentTask;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 16;

/// Per-CPU data structure
///
/// Accessed via the TPIDR_EL1 system register. The first field must be
/// a self-pointer so that reading TPIDR_EL1 gives us the PerCpu address.
#[repr(C, align(64))]
pub struct PerCpu {
    /// Self-pointer for TPIDR_EL1 access
    pub self_ptr: *mut PerCpu,

    /// Logical CPU ID (0 = BSP, 1+ = APs)
    pub cpu_id: u32,

    /// Hardware MPIDR value (affinity identifier)
    pub mpidr: u64,

    /// Is this the bootstrap processor?
    pub is_bsp: bool,

    /// Has this CPU completed initialization?
    pub is_online: AtomicBool,

    /// Kernel stack top for this CPU
    pub kernel_stack_top: u64,

    /// Timer tick count for this CPU
    pub ticks: AtomicU64,

    /// Currently running task TID (0 = none/idle)
    pub current_tid: AtomicU32,

    /// Flag set by timer interrupt to request reschedule
    pub needs_reschedule: AtomicBool,

    /// Nesting depth of interrupt handlers
    pub interrupt_depth: AtomicU32,

    /// Preemption count - tracks nested critical sections
    pub preempt_count: AtomicU32,

    /// Current task state including credentials
    pub current_task: CurrentTask,

    /// Saved user ELR from syscall entry
    pub syscall_user_elr: u64,

    /// Saved user SPSR from syscall entry
    pub syscall_user_spsr: u64,

    /// Saved user SP from syscall entry
    pub syscall_user_sp: u64,

    /// Saved user GPRs x0-x30 from syscall entry (for fork/clone)
    pub syscall_user_regs: [u64; 31],

    /// Flag set when signal delivery modifies the return context
    /// When true, the syscall return path should update the stack frame from percpu
    pub signal_context_modified: bool,
}

// Safety: PerCpu is only accessed by its owning CPU
unsafe impl Send for PerCpu {}
unsafe impl Sync for PerCpu {}

impl PerCpu {
    /// Create an uninitialized PerCpu
    pub const fn uninit() -> Self {
        Self {
            self_ptr: core::ptr::null_mut(),
            cpu_id: 0,
            mpidr: 0,
            is_bsp: false,
            is_online: AtomicBool::new(false),
            kernel_stack_top: 0,
            ticks: AtomicU64::new(0),
            current_tid: AtomicU32::new(0),
            needs_reschedule: AtomicBool::new(false),
            interrupt_depth: AtomicU32::new(0),
            preempt_count: AtomicU32::new(0),
            current_task: CurrentTask::new(),
            syscall_user_elr: 0,
            syscall_user_spsr: 0,
            syscall_user_sp: 0,
            syscall_user_regs: [0; 31],
            signal_context_modified: false,
        }
    }

    /// Initialize the PerCpu structure
    pub fn init(&mut self, cpu_id: u32, mpidr: u64, is_bsp: bool, kernel_stack_top: u64) {
        self.self_ptr = self as *mut PerCpu;
        self.cpu_id = cpu_id;
        self.mpidr = mpidr;
        self.is_bsp = is_bsp;
        self.kernel_stack_top = kernel_stack_top;
        self.ticks.store(0, Ordering::Relaxed);
        self.current_tid.store(0, Ordering::Relaxed);
        self.needs_reschedule.store(false, Ordering::Relaxed);
        self.interrupt_depth.store(0, Ordering::Relaxed);
        self.preempt_count.store(0, Ordering::Relaxed);
        // Note: For APs, current_task was already zeroed in uninit()
        // Only BSP needs to reinitialize it here
        if is_bsp {
            self.current_task = CurrentTask::new();
        }
        self.syscall_user_elr = 0;
        self.syscall_user_spsr = 0;
        self.syscall_user_sp = 0;
        self.syscall_user_regs = [0; 31];
        self.signal_context_modified = false;
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

/// Set the TPIDR_EL1 register to point to per-CPU data
#[inline]
pub fn set_tpidr_el1(addr: u64) {
    unsafe {
        asm!(
            "msr tpidr_el1, {}",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// Read the TPIDR_EL1 register
#[inline]
pub fn read_tpidr_el1() -> u64 {
    let val: u64;
    unsafe {
        asm!(
            "mrs {}, tpidr_el1",
            out(reg) val,
            options(nostack, preserves_flags, nomem)
        );
    }
    val
}

/// Set the TPIDR_EL0 register (user TLS pointer)
#[inline]
pub fn write_tpidr_el0(value: u64) {
    unsafe {
        asm!(
            "msr tpidr_el0, {}",
            in(reg) value,
            options(nostack, preserves_flags)
        );
    }
}

/// Read the TPIDR_EL0 register (user TLS pointer)
#[inline]
pub fn read_tpidr_el0() -> u64 {
    let val: u64;
    unsafe {
        asm!(
            "mrs {}, tpidr_el0",
            out(reg) val,
            options(nostack, preserves_flags, nomem)
        );
    }
    val
}

/// Get a reference to a CPU's per-CPU data by CPU ID
pub fn get_percpu(cpu_id: u32) -> &'static mut PerCpu {
    assert!((cpu_id as usize) < MAX_CPUS, "CPU ID out of range");
    unsafe { &mut PERCPU_ARRAY[cpu_id as usize] }
}

/// Get a mutable reference to the current CPU's per-CPU data
///
/// # Safety
/// The TPIDR_EL1 must have been set up correctly.
#[inline]
pub unsafe fn current_cpu_mut() -> &'static mut PerCpu {
    let ptr = read_tpidr_el1() as *mut PerCpu;
    unsafe { &mut *ptr }
}

/// Try to get current CPU data (returns None if TPIDR_EL1 not set up)
#[inline]
pub fn try_current_cpu() -> Option<&'static PerCpu> {
    let tpidr = read_tpidr_el1();
    if tpidr == 0 {
        return None;
    }
    unsafe { Some(&*(tpidr as *const PerCpu)) }
}

/// Initialize per-CPU data for the BSP (CPU 0)
///
/// This must be called early in boot, before any per-CPU access.
pub fn init_bsp(mpidr: u64, kernel_stack_top: u64) {
    let percpu = get_percpu(0);
    percpu.init(0, mpidr, true, kernel_stack_top);

    // Set TPIDR_EL1 to point to our per-CPU data
    set_tpidr_el1(percpu as *mut PerCpu as u64);

    // Mark BSP as online
    percpu.set_online();
    CPU_COUNT.store(1, Ordering::SeqCst);
}

/// Initialize per-CPU data for an AP
///
/// Called by the AP after it has set up its stack.
/// Returns the CPU ID assigned to this AP.
pub fn init_ap(mpidr: u64, kernel_stack_top: u64) -> u32 {
    // Atomically claim the next CPU ID
    let cpu_id = CPU_COUNT.fetch_add(1, Ordering::SeqCst);
    assert!((cpu_id as usize) < MAX_CPUS, "Too many CPUs");

    let percpu = get_percpu(cpu_id);
    percpu.init(cpu_id, mpidr, false, kernel_stack_top);

    // Set TPIDR_EL1 to point to our per-CPU data
    set_tpidr_el1(percpu as *mut PerCpu as u64);

    // Mark as online
    percpu.set_online();

    cpu_id
}

/// Get the number of online CPUs
pub fn online_cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Acquire)
}

// ============================================================================
// Preemption control
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
// Syscall user state accessors (for signal handling)
// ============================================================================

/// Get saved syscall user ELR (return address/PC)
#[inline]
pub fn get_syscall_user_elr() -> u64 {
    try_current_cpu()
        .map(|percpu| percpu.syscall_user_elr)
        .unwrap_or(0)
}

/// Get saved syscall user SPSR (processor state)
#[inline]
pub fn get_syscall_user_spsr() -> u64 {
    try_current_cpu()
        .map(|percpu| percpu.syscall_user_spsr)
        .unwrap_or(0)
}

/// Get saved syscall user SP (stack pointer)
#[inline]
pub fn get_syscall_user_sp() -> u64 {
    try_current_cpu()
        .map(|percpu| percpu.syscall_user_sp)
        .unwrap_or(0)
}

/// Get saved syscall user registers (x0-x30)
#[inline]
pub fn get_syscall_user_regs() -> [u64; 31] {
    try_current_cpu()
        .map(|percpu| percpu.syscall_user_regs)
        .unwrap_or([0; 31])
}
