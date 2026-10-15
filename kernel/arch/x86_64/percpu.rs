//! Per-CPU data structures
//!
//! This module provides per-CPU data storage accessed via the GS segment.
//! Each CPU has its own `PerCpu` structure containing CPU-local state.

use crate::task::CurrentTask;
use ::core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 16;

/// Per-CPU data structure
///
/// Accessed via the GS segment base register. The first field must be
/// a self-pointer so that `mov rax, gs:0` gives us the PerCpu address.
#[repr(C, align(64))]
pub struct PerCpu {
    /// Self-pointer for GS:0 access
    pub self_ptr: *mut PerCpu,

    /// Logical CPU ID (0 = BSP, 1+ = APs)
    pub cpu_id: u32,

    /// Hardware APIC ID
    pub apic_id: u32,

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

    /// Current task state including credentials (arch-neutral)
    pub current_task: CurrentTask,

    /// Saved user RIP from syscall entry (RCX register)
    /// Used by clone() to set up child's return address
    pub syscall_user_rip: u64,

    /// Saved user RFLAGS from syscall entry (R11 register)
    /// Used by clone() to set up child's flags
    pub syscall_user_rflags: u64,

    /// Saved user RSP from syscall entry
    /// Used by fork() to inherit parent's stack pointer
    pub syscall_user_rsp: u64,

    /// Saved callee-saved registers from syscall entry
    /// Used by fork() so child inherits parent's register state
    pub syscall_user_rbx: u64,
    pub syscall_user_rbp: u64,
    pub syscall_user_r12: u64,
    pub syscall_user_r13: u64,
    pub syscall_user_r14: u64,
    pub syscall_user_r15: u64,

    /// Saved caller-saved/argument registers from syscall entry
    /// Linux ABI preserves these across syscalls, so fork() child must inherit them
    pub syscall_user_rdi: u64,
    pub syscall_user_rsi: u64,
    pub syscall_user_rdx: u64,
    pub syscall_user_r8: u64,
    pub syscall_user_r9: u64,
    pub syscall_user_r10: u64,

    /// Syscall return value (user RAX), recorded before signal delivery so the
    /// signal frame saves it and rt_sigreturn returns it to the interrupted code
    pub syscall_user_rax: u64,

    /// User RCX/R11. On syscall entry they equal RIP/RFLAGS (the `syscall`
    /// instruction overwrote them); after a fault or rt_sigreturn they are
    /// real values, returned to user mode by the IRETQ exit path
    pub syscall_user_rcx: u64,
    pub syscall_user_r11: u64,

    /// Set by rt_sigreturn: return to user mode with IRETQ restoring every
    /// register (SYSRET would clobber RCX/R11)
    pub syscall_full_restore: bool,

    /// Syscall number of the syscall in progress (for -ERESTART* restarts)
    pub syscall_nr: u64,

    /// Flag set when signal delivery modifies the return context
    /// When true, the syscall return path should update the stack frame from percpu
    pub signal_context_modified: bool,
}

/// Snapshot of the per-CPU syscall user-register block
///
/// The block describes the *current task's* syscall, but lives in per-CPU
/// data; the scheduler saves it on the outgoing task's kernel stack around
/// every context switch so a task that slept inside a syscall still returns
/// (and builds signal frames) with its own registers.
#[derive(Clone, Copy)]
pub struct SyscallUserState {
    regs: [u64; 19],
    modified: bool,
    full_restore: bool,
}

/// Capture the syscall user-register block of this CPU
pub fn save_syscall_user_state() -> SyscallUserState {
    let p = unsafe { current_cpu_mut() };
    SyscallUserState {
        regs: [
            p.syscall_user_rip,
            p.syscall_user_rflags,
            p.syscall_user_rsp,
            p.syscall_user_rbx,
            p.syscall_user_rbp,
            p.syscall_user_r12,
            p.syscall_user_r13,
            p.syscall_user_r14,
            p.syscall_user_r15,
            p.syscall_user_rdi,
            p.syscall_user_rsi,
            p.syscall_user_rdx,
            p.syscall_user_r8,
            p.syscall_user_r9,
            p.syscall_user_r10,
            p.syscall_user_rax,
            p.syscall_nr,
            p.syscall_user_rcx,
            p.syscall_user_r11,
        ],
        modified: p.signal_context_modified,
        full_restore: p.syscall_full_restore,
    }
}

/// Restore a block captured by [`save_syscall_user_state`]
pub fn restore_syscall_user_state(s: &SyscallUserState) {
    let p = unsafe { current_cpu_mut() };
    let r = &s.regs;
    p.syscall_user_rip = r[0];
    p.syscall_user_rflags = r[1];
    p.syscall_user_rsp = r[2];
    p.syscall_user_rbx = r[3];
    p.syscall_user_rbp = r[4];
    p.syscall_user_r12 = r[5];
    p.syscall_user_r13 = r[6];
    p.syscall_user_r14 = r[7];
    p.syscall_user_r15 = r[8];
    p.syscall_user_rdi = r[9];
    p.syscall_user_rsi = r[10];
    p.syscall_user_rdx = r[11];
    p.syscall_user_r8 = r[12];
    p.syscall_user_r9 = r[13];
    p.syscall_user_r10 = r[14];
    p.syscall_user_rax = r[15];
    p.syscall_nr = r[16];
    p.syscall_user_rcx = r[17];
    p.syscall_user_r11 = r[18];
    p.signal_context_modified = s.modified;
    p.syscall_full_restore = s.full_restore;
}

/// Arrange for the current syscall to be re-executed on return to user
/// (-ERESTART* with no handler, or SA_RESTART): back RIP up over the 2-byte
/// `syscall` instruction and put the syscall number back in RAX. Returns the
/// value the syscall must "return" (RAX).
pub fn syscall_restart() -> u64 {
    let p = unsafe { current_cpu_mut() };
    p.syscall_user_rip = p.syscall_user_rip.wrapping_sub(2);
    p.syscall_user_rax = p.syscall_nr;
    p.signal_context_modified = true;
    p.syscall_nr
}

impl PerCpu {
    /// Create an uninitialized PerCpu
    const fn uninit() -> Self {
        Self {
            self_ptr: core::ptr::null_mut(),
            cpu_id: 0,
            apic_id: 0,
            is_bsp: false,
            is_online: AtomicBool::new(false),
            kernel_stack_top: 0,
            ticks: AtomicU64::new(0),
            current_tid: AtomicU32::new(0),
            needs_reschedule: AtomicBool::new(false),
            interrupt_depth: AtomicU32::new(0),
            preempt_count: AtomicU32::new(0),
            current_task: CurrentTask::new(),
            syscall_user_rip: 0,
            syscall_user_rflags: 0,
            syscall_user_rsp: 0,
            syscall_user_rbx: 0,
            syscall_user_rbp: 0,
            syscall_user_r12: 0,
            syscall_user_r13: 0,
            syscall_user_r14: 0,
            syscall_user_r15: 0,
            syscall_user_rdi: 0,
            syscall_user_rsi: 0,
            syscall_user_rdx: 0,
            syscall_user_r8: 0,
            syscall_user_r9: 0,
            syscall_user_r10: 0,
            syscall_user_rax: 0,
            syscall_user_rcx: 0,
            syscall_user_r11: 0,
            syscall_full_restore: false,
            syscall_nr: 0,
            signal_context_modified: false,
        }
    }

    /// Initialize the PerCpu structure
    pub fn init(&mut self, cpu_id: u32, apic_id: u32, is_bsp: bool, kernel_stack_top: u64) {
        self.self_ptr = self as *mut PerCpu;
        self.cpu_id = cpu_id;
        self.apic_id = apic_id;
        self.is_bsp = is_bsp;
        self.kernel_stack_top = kernel_stack_top;
        self.ticks.store(0, Ordering::Relaxed);
        self.current_tid.store(0, Ordering::Relaxed);
        self.needs_reschedule.store(false, Ordering::Relaxed);
        self.interrupt_depth.store(0, Ordering::Relaxed);
        self.preempt_count.store(0, Ordering::Relaxed);
        self.current_task = CurrentTask::new();
        self.syscall_user_rip = 0;
        self.syscall_user_rflags = 0;
        self.syscall_user_rsp = 0;
        self.syscall_user_rbx = 0;
        self.syscall_user_rbp = 0;
        self.syscall_user_r12 = 0;
        self.syscall_user_r13 = 0;
        self.syscall_user_r14 = 0;
        self.syscall_user_r15 = 0;
        self.signal_context_modified = false;
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

/// Try to get current CPU data (returns None if GS not set up)
#[inline]
pub fn try_current_cpu() -> Option<&'static PerCpu> {
    // Read GS base via MSR
    let gs_base = read_gs_base();
    if gs_base == 0 {
        return None;
    }
    unsafe { Some(&*(gs_base as *const PerCpu)) }
}

/// Initialize per-CPU data for the BSP (CPU 0)
///
/// This must be called early in boot, before any per-CPU access.
pub fn init_bsp(apic_id: u8, kernel_stack_top: u64) {
    BSP_APIC_ID.store(apic_id as u32, Ordering::SeqCst);

    let percpu = get_percpu(0);
    percpu.init(0, apic_id as u32, true, kernel_stack_top);

    // Set GS base to point to our per-CPU data
    set_gs_base(percpu as *mut PerCpu as u64);

    // Mark BSP as online
    percpu.set_online();
    CPU_COUNT.store(1, Ordering::SeqCst);
}

/// Initialize per-CPU data for an AP
///
/// Called by the AP after it has set up its GDT and stack.
/// Returns the CPU ID assigned to this AP.
pub fn init_ap(apic_id: u8, kernel_stack_top: u64) -> u32 {
    // Atomically claim the next CPU ID
    let cpu_id = CPU_COUNT.fetch_add(1, Ordering::SeqCst);
    assert!((cpu_id as usize) < MAX_CPUS, "Too many CPUs");

    let percpu = get_percpu(cpu_id);
    percpu.init(cpu_id, apic_id as u32, false, kernel_stack_top);

    // Set GS base to point to our per-CPU data
    set_gs_base(percpu as *mut PerCpu as u64);

    // Mark as online
    percpu.set_online();

    cpu_id
}

/// Get the number of online CPUs
pub fn online_cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Acquire)
}

/// Set the GS base register (MSR 0xC0000101)
pub fn set_gs_base(addr: u64) {
    const MSR_GS_BASE: u32 = 0xC0000101;
    unsafe {
        ::core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_GS_BASE,
            in("eax") addr as u32,
            in("edx") (addr >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

/// Read the GS base register
pub fn read_gs_base() -> u64 {
    const MSR_GS_BASE: u32 = 0xC0000101;
    let low: u32;
    let high: u32;
    unsafe {
        ::core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_GS_BASE,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

// ============================================================================
// User Thread-Local Storage (FS base register)
// ============================================================================

/// MSR address for FS base register (user TLS on x86_64)
pub const MSR_FS_BASE: u32 = 0xC0000100;

/// Set the FS base register (user TLS pointer)
///
/// This is used for user-space thread-local storage. The FS segment
/// register's base address is set via this MSR on x86_64.
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

/// Save syscall entry state (user RIP, RFLAGS, RSP, and callee-saved regs) for clone()/fork()
///
/// Called from syscall entry before dispatching. Stores the user's
/// return address (RCX), flags (R11), stack pointer, and all callee-saved
/// registers in per-CPU data so clone()/fork() can use them to set up
/// the child's TrapFrame.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn save_syscall_state(
    user_rip: u64,
    user_rflags: u64,
    user_rsp: u64,
    user_rbx: u64,
    user_rbp: u64,
    user_r12: u64,
    user_r13: u64,
    user_r14: u64,
    user_r15: u64,
) {
    if let Some(_percpu) = try_current_cpu() {
        unsafe {
            let percpu_mut = current_cpu_mut();
            percpu_mut.syscall_user_rip = user_rip;
            percpu_mut.syscall_user_rflags = user_rflags;
            // `syscall` put RIP/RFLAGS in RCX/R11
            percpu_mut.syscall_user_rcx = user_rip;
            percpu_mut.syscall_user_r11 = user_rflags;
            percpu_mut.syscall_user_rsp = user_rsp;
            percpu_mut.syscall_user_rbx = user_rbx;
            percpu_mut.syscall_user_rbp = user_rbp;
            percpu_mut.syscall_user_r12 = user_r12;
            percpu_mut.syscall_user_r13 = user_r13;
            percpu_mut.syscall_user_r14 = user_r14;
            percpu_mut.syscall_user_r15 = user_r15;
        }
    }
}

/// Get saved syscall user RIP
#[inline]
pub fn get_syscall_user_rip() -> u64 {
    try_current_cpu()
        .map(|percpu| percpu.syscall_user_rip)
        .unwrap_or(0)
}

/// Get saved syscall user RFLAGS
#[inline]
pub fn get_syscall_user_rflags() -> u64 {
    try_current_cpu()
        .map(|percpu| percpu.syscall_user_rflags)
        .unwrap_or(0)
}

/// Get saved syscall user RSP (stack pointer)
#[inline]
pub fn get_syscall_user_rsp() -> u64 {
    try_current_cpu()
        .map(|percpu| percpu.syscall_user_rsp)
        .unwrap_or(0)
}

/// Get saved syscall user callee-saved registers
/// Returns (rbx, rbp, r12, r13, r14, r15)
#[inline]
pub fn get_syscall_user_callee_saved() -> (u64, u64, u64, u64, u64, u64) {
    try_current_cpu()
        .map(|percpu| {
            (
                percpu.syscall_user_rbx,
                percpu.syscall_user_rbp,
                percpu.syscall_user_r12,
                percpu.syscall_user_r13,
                percpu.syscall_user_r14,
                percpu.syscall_user_r15,
            )
        })
        .unwrap_or((0, 0, 0, 0, 0, 0))
}

/// Save caller-saved/argument registers for fork()
///
/// Linux syscall ABI preserves these across syscalls, so the child
/// must inherit the parent's values. Called from syscall entry.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn save_syscall_caller_saved(
    user_rdi: u64,
    user_rsi: u64,
    user_rdx: u64,
    user_r8: u64,
    user_r9: u64,
    user_r10: u64,
) {
    if let Some(_percpu) = try_current_cpu() {
        unsafe {
            let percpu_mut = current_cpu_mut();
            percpu_mut.syscall_user_rdi = user_rdi;
            percpu_mut.syscall_user_rsi = user_rsi;
            percpu_mut.syscall_user_rdx = user_rdx;
            percpu_mut.syscall_user_r8 = user_r8;
            percpu_mut.syscall_user_r9 = user_r9;
            percpu_mut.syscall_user_r10 = user_r10;
        }
    }
}

/// Get saved syscall user caller-saved registers
/// Returns (rdi, rsi, rdx, r8, r9, r10)
#[inline]
pub fn get_syscall_user_caller_saved() -> (u64, u64, u64, u64, u64, u64) {
    try_current_cpu()
        .map(|percpu| {
            (
                percpu.syscall_user_rdi,
                percpu.syscall_user_rsi,
                percpu.syscall_user_rdx,
                percpu.syscall_user_r8,
                percpu.syscall_user_r9,
                percpu.syscall_user_r10,
            )
        })
        .unwrap_or((0, 0, 0, 0, 0, 0))
}

/// Update syscall return frame from percpu saved state
///
/// Called from syscall exit path to apply any modifications made by
/// signal delivery (setup_rt_frame) to the stack frame that will be
/// restored on return to userspace.
///
/// Only updates the frame if signal_context_modified is set, indicating
/// that signal delivery has redirected execution to a handler.
///
/// Stack frame layout (passed as frame_base):
///   frame_base+0:  r9
///   frame_base+8:  r8
///   frame_base+16: r10
///   frame_base+24: rdx
///   frame_base+32: rsi
///   frame_base+40: rdi
///   frame_base+48: rax (return value)
///   frame_base+56: r15
///   frame_base+64: r14
///   frame_base+72: r13
///   frame_base+80: r12
///   frame_base+88: rbp
///   frame_base+96: rbx
///   frame_base+104: r11 (user RFLAGS)
///   frame_base+112: rcx (user RIP)
///   frame_base+120: user_rsp
///
/// Returns 1 if the syscall must return through IRETQ with every register
/// (incl. RCX/R11) taken from the per-CPU block (see [`fill_iret_frame`]),
/// 0 for the normal SYSRET exit.
#[inline]
pub extern "C" fn update_syscall_return_frame(frame_base: *mut u64) -> u64 {
    if let Some(_percpu) = try_current_cpu() {
        unsafe {
            let percpu_mut = current_cpu_mut();
            // Only update if signal delivery modified the context
            if !percpu_mut.signal_context_modified {
                return 0;
            }
            // Clear the flag
            percpu_mut.signal_context_modified = false;

            // Update RIP (stored in RCX slot for sysretq)
            *frame_base.add(14) = percpu_mut.syscall_user_rip; // offset 112
            // Update RFLAGS (stored in R11 slot for sysretq)
            *frame_base.add(13) = percpu_mut.syscall_user_rflags; // offset 104
            // Update RSP
            *frame_base.add(15) = percpu_mut.syscall_user_rsp; // offset 120
            // Update argument registers (for signal handler args)
            *frame_base.add(5) = percpu_mut.syscall_user_rdi; // offset 40
            *frame_base.add(4) = percpu_mut.syscall_user_rsi; // offset 32
            *frame_base.add(3) = percpu_mut.syscall_user_rdx; // offset 24
            *frame_base.add(1) = percpu_mut.syscall_user_r8; // offset 8
            *frame_base.add(0) = percpu_mut.syscall_user_r9; // offset 0
            *frame_base.add(2) = percpu_mut.syscall_user_r10; // offset 16
            // Update callee-saved registers (needed for rt_sigreturn context restore)
            *frame_base.add(12) = percpu_mut.syscall_user_rbx; // offset 96
            *frame_base.add(11) = percpu_mut.syscall_user_rbp; // offset 88
            *frame_base.add(10) = percpu_mut.syscall_user_r12; // offset 80
            *frame_base.add(9) = percpu_mut.syscall_user_r13; // offset 72
            *frame_base.add(8) = percpu_mut.syscall_user_r14; // offset 64
            *frame_base.add(7) = percpu_mut.syscall_user_r15; // offset 56
            if core::mem::take(&mut percpu_mut.syscall_full_restore) {
                return 1;
            }
        }
    }
    0
}

/// IRETQ exit of a syscall (after rt_sigreturn): fill `out` with the IRET
/// frame (RIP, CS, RFLAGS, RSP, SS) followed by the user RCX and R11
pub extern "C" fn fill_iret_frame(out: *mut u64) {
    let p = unsafe { current_cpu_mut() };
    let vals = [
        p.syscall_user_rip,
        super::cpu::USER_CODE_SELECTOR as u64,
        p.syscall_user_rflags,
        p.syscall_user_rsp,
        super::cpu::USER_DATA_SELECTOR as u64,
        p.syscall_user_rcx,
        p.syscall_user_r11,
    ];
    for (i, v) in vals.iter().enumerate() {
        unsafe { *out.add(i) = *v };
    }
}

/// Load the per-CPU user-register block from the trap frame of a user
/// fault, so signal delivery builds its frame from the faulting context
pub fn load_user_regs_from_trapframe(f: &super::X86_64TrapFrame) {
    let p = unsafe { current_cpu_mut() };
    p.syscall_user_rip = f.rip;
    p.syscall_user_rflags = f.rflags;
    p.syscall_user_rsp = f.rsp;
    p.syscall_user_rax = f.rax;
    p.syscall_user_rbx = f.rbx;
    p.syscall_user_rcx = f.rcx;
    p.syscall_user_rdx = f.rdx;
    p.syscall_user_rsi = f.rsi;
    p.syscall_user_rdi = f.rdi;
    p.syscall_user_rbp = f.rbp;
    p.syscall_user_r8 = f.r8;
    p.syscall_user_r9 = f.r9;
    p.syscall_user_r10 = f.r10;
    p.syscall_user_r11 = f.r11;
    p.syscall_user_r12 = f.r12;
    p.syscall_user_r13 = f.r13;
    p.syscall_user_r14 = f.r14;
    p.syscall_user_r15 = f.r15;
    p.signal_context_modified = false;
    p.syscall_full_restore = false;
}

/// Write back a user context changed by signal delivery into the trap
/// frame the fault returns through (IRETQ restores every register)
pub fn store_user_regs_to_trapframe(f: &mut super::X86_64TrapFrame) {
    let p = unsafe { current_cpu_mut() };
    if !core::mem::take(&mut p.signal_context_modified) {
        return;
    }
    p.syscall_full_restore = false;
    f.rip = p.syscall_user_rip;
    f.rflags = p.syscall_user_rflags;
    f.rsp = p.syscall_user_rsp;
    f.rax = p.syscall_user_rax;
    f.rbx = p.syscall_user_rbx;
    f.rcx = p.syscall_user_rcx;
    f.rdx = p.syscall_user_rdx;
    f.rsi = p.syscall_user_rsi;
    f.rdi = p.syscall_user_rdi;
    f.rbp = p.syscall_user_rbp;
    f.r8 = p.syscall_user_r8;
    f.r9 = p.syscall_user_r9;
    f.r10 = p.syscall_user_r10;
    f.r11 = p.syscall_user_r11;
    f.r12 = p.syscall_user_r12;
    f.r13 = p.syscall_user_r13;
    f.r14 = p.syscall_user_r14;
    f.r15 = p.syscall_user_r15;
}

// ============================================================================
// PerCpuOps trait implementation
// ============================================================================

use crate::arch::PerCpuOps;
use crate::task::Tid;

use super::X86_64Arch;

impl PerCpuOps for X86_64Arch {
    const MAX_CPUS: usize = MAX_CPUS;

    #[inline]
    fn try_current_cpu_id() -> Option<u32> {
        try_current_cpu().map(|percpu| percpu.cpu_id)
    }

    #[inline]
    fn current_tid() -> Tid {
        try_current_cpu()
            .map(|percpu| percpu.current_tid.load(Ordering::Relaxed) as Tid)
            .unwrap_or(0)
    }

    #[inline]
    fn set_current_tid(tid: Tid) {
        if try_current_cpu().is_some() {
            unsafe {
                current_cpu_mut()
                    .current_tid
                    .store(tid as u32, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    fn needs_reschedule() -> bool {
        try_current_cpu()
            .map(|percpu| percpu.needs_reschedule.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    #[inline]
    fn clear_needs_reschedule() -> bool {
        try_current_cpu()
            .map(|percpu| percpu.needs_reschedule.swap(false, Ordering::Relaxed))
            .unwrap_or(false)
    }

    #[inline]
    fn set_needs_reschedule(val: bool) {
        if try_current_cpu().is_some() {
            unsafe {
                current_cpu_mut()
                    .needs_reschedule
                    .store(val, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    fn interrupt_depth() -> u32 {
        try_current_cpu()
            .map(|percpu| percpu.interrupt_depth.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    #[inline]
    fn get_current_task() -> CurrentTask {
        try_current_cpu()
            .map(|percpu| percpu.current_task)
            .unwrap_or_default()
    }

    #[inline]
    fn set_current_task(task: &CurrentTask) {
        if try_current_cpu().is_some() {
            unsafe {
                current_cpu_mut().current_task.set(
                    task.tid, task.pid, task.ppid, task.pgid, task.sid, task.cred,
                );
                current_cpu_mut().current_task.exiting = task.exiting;
            }
        }
    }

    #[inline]
    fn get_syscall_user_rip() -> u64 {
        get_syscall_user_rip()
    }

    #[inline]
    fn get_syscall_user_rflags() -> u64 {
        get_syscall_user_rflags()
    }

    #[inline]
    fn get_syscall_user_rsp() -> u64 {
        get_syscall_user_rsp()
    }

    fn cpu_online(cpu: u32) -> bool {
        (cpu as usize) < MAX_CPUS && get_percpu(cpu).is_online.load(Ordering::Acquire)
    }

    type SyscallUserState = SyscallUserState;

    fn save_syscall_user_state() -> SyscallUserState {
        save_syscall_user_state()
    }

    fn restore_syscall_user_state(state: &SyscallUserState) {
        restore_syscall_user_state(state)
    }

    fn set_syscall_return(val: u64) {
        unsafe { current_cpu_mut().syscall_user_rax = val };
    }

    fn syscall_restart() -> u64 {
        syscall_restart()
    }
}
