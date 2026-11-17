//! User FP/SIMD state (Linux arch/arm64/kernel/fpsimd.c)
//!
//! The kernel is built general-regs-only (`aarch64-unknown-none-softfloat`,
//! Linux -mgeneral-regs-only): kernel code never touches v0-v31, FPCR or
//! FPSR, so exception entry saves none of them and a task's user FP/SIMD
//! state stays live in the registers while it runs in the kernel. It goes
//! to memory (`ThreadStruct`, Linux thread.uw.fpsimd_state) only when the
//! registers are about to hold something else, and comes back lazily on
//! the way to user mode:
//!
//! - `thread_switch` (Linux fpsimd_thread_switch) saves the outgoing
//!   task's registers, through the CPU's binding `fpsimd_last_state`,
//!   unless they are not its own (TIF_FOREIGN_FPSTATE), and sets the
//!   incoming task's TIF_FOREIGN_FPSTATE unless this CPU's registers
//!   still hold its state: the binding names its state and the task's
//!   `fpsimd_cpu` names this CPU.
//! - `exit_to_user_mode_work` (Linux fpsimd_restore_current_state) loads
//!   the task's saved state if TIF_FOREIGN_FPSTATE is set, and binds it
//!   to this CPU.
//! - Readers and writers of the saved state (signal frames, fork, exec)
//!   first save and unbind the live registers
//!   (`save_and_flush_current_state`, `flush_thread`): from then until the
//!   return to user mode, the memory copy is the task's state.
//!
//! There is no kernel-mode NEON user (Linux kernel_neon_begin/end): no
//! kernel code may use the FP/SIMD registers.
//!
//! The CPU's FP context is claimed with preemption disabled (Linux
//! get_cpu_fpsimd_context in its PREEMPT_RT form: hk has no softirqs and
//! no kernel-mode NEON to exclude); `thread_switch` runs with interrupts
//! off under the rq lock.
//!
//! # Invariants
//! While the running task's TIF_FOREIGN_FPSTATE is clear, its CPU's
//! `fpsimd_last_state` points to that task's own state: only
//! `bind_task_to_cpu` (the task itself, on its way to user mode) and
//! `thread_switch` (only when the binding already names the incoming
//! task's state on this CPU) clear the flag. So a save through the
//! binding writes the running task's state, alive while it runs. A
//! binding left behind by a task that moved on or exited is only
//! compared, never followed: the running task there is foreign to it,
//! and a new task at a reused address has no `fpsimd_cpu`.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering, compiler_fence};

use super::percpu::{PerCpu, try_current_cpu};
use crate::task::{Task, tif};

/// The user FP/SIMD registers (Linux struct user_fpsimd_state)
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct UserFpsimdState {
    /// v0-v31
    pub vregs: [u128; 32],
    /// Floating-point status register
    pub fpsr: u32,
    /// Floating-point control register
    pub fpcr: u32,
    _reserved: [u32; 2],
}

const _: () = assert!(core::mem::size_of::<UserFpsimdState>() == 528);
const _: () = assert!(core::mem::offset_of!(UserFpsimdState, fpsr) == 512);
const _: () = assert!(core::mem::offset_of!(UserFpsimdState, fpcr) == 516);

impl UserFpsimdState {
    /// All zero: a new program's state
    pub const ZERO: Self = Self {
        vregs: [0; 32],
        fpsr: 0,
        fpcr: 0,
        _reserved: [0; 2],
    };
}

/// `fpsimd_cpu` of a state bound to no CPU (Linux NR_CPUS)
const NO_CPU: u32 = u32::MAX;

/// A task's arch thread state (Linux struct thread_struct): its user
/// FP/SIMD state while that is not live in a CPU's registers
///
/// # Invariants
/// Once the task runs, only the task itself accesses `fpsimd_state`: it
/// saves into it (`save_user_state`: with its CPU's FP context claimed or
/// interrupts off, and only while TIF_FOREIGN_FPSTATE is clear, its own
/// registers live) and loads, zeroes or replaces it (with
/// TIF_FOREIGN_FPSTATE set, which only its own return to user mode
/// clears). Before the task first runs, only its creator writes it
/// (`dup_thread`). `fpsimd_cpu` is written by the task under the same
/// rules and read by the CPU switching to it (`thread_switch`), ordered
/// by the rq lock handoff.
pub struct ThreadStruct {
    /// Saved user FP/SIMD registers (Linux thread.uw.fpsimd_state)
    fpsimd_state: UnsafeCell<UserFpsimdState>,
    /// The CPU whose registers it was last loaded into (Linux
    /// thread.fpsimd_cpu), `NO_CPU` if none may hold it
    fpsimd_cpu: AtomicU32,
}

// SAFETY: `fpsimd_state` is accessed by one task at a time (type
// invariant); `fpsimd_cpu` is atomic
unsafe impl Sync for ThreadStruct {}

impl ThreadStruct {
    /// A new task's: zero state, bound to no CPU
    pub const fn new() -> Self {
        Self {
            fpsimd_state: UnsafeCell::new(UserFpsimdState::ZERO),
            fpsimd_cpu: AtomicU32::new(NO_CPU),
        }
    }

    /// The saved state's address
    fn st(&self) -> *mut UserFpsimdState {
        self.fpsimd_state.get()
    }
}

impl Default for ThreadStruct {
    fn default() -> Self {
        Self::new()
    }
}

/// This CPU's FP context claimed (Linux get_cpu_fpsimd_context /
/// put_cpu_fpsimd_context): no switch until it drops
struct CpuFpContext;

impl CpuFpContext {
    fn get() -> Self {
        crate::arch::preempt_disable();
        Self
    }
}

impl Drop for CpuFpContext {
    fn drop(&mut self) {
        crate::arch::preempt_enable();
    }
}

/// This CPU's per-CPU data
fn this_cpu() -> &'static PerCpu {
    try_current_cpu().expect("fpsimd: no per-CPU data")
}

/// Store the FP/SIMD registers at `st` (Linux fpsimd_save_state)
///
/// # Safety
/// `st` is valid for writes and nothing else accesses it meanwhile.
unsafe fn save_state(st: *mut UserFpsimdState) {
    // SAFETY: stores to `st` only (the caller's contract); the kernel
    // code around never uses the registers read
    unsafe {
        core::arch::asm!(
            ".arch_extension fp",
            ".arch_extension simd",
            "stp q0, q1, [{s}, #16 * 0]",
            "stp q2, q3, [{s}, #16 * 2]",
            "stp q4, q5, [{s}, #16 * 4]",
            "stp q6, q7, [{s}, #16 * 6]",
            "stp q8, q9, [{s}, #16 * 8]",
            "stp q10, q11, [{s}, #16 * 10]",
            "stp q12, q13, [{s}, #16 * 12]",
            "stp q14, q15, [{s}, #16 * 14]",
            "stp q16, q17, [{s}, #16 * 16]",
            "stp q18, q19, [{s}, #16 * 18]",
            "stp q20, q21, [{s}, #16 * 20]",
            "stp q22, q23, [{s}, #16 * 22]",
            "stp q24, q25, [{s}, #16 * 24]",
            "stp q26, q27, [{s}, #16 * 26]",
            "stp q28, q29, [{s}, #16 * 28]",
            "stp q30, q31, [{s}, #16 * 30]",
            "mrs {t}, fpsr",
            "str {t:w}, [{s}, #512]",
            "mrs {t}, fpcr",
            "str {t:w}, [{s}, #516]",
            s = in(reg) st,
            t = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// Load the FP/SIMD registers from `st` (Linux fpsimd_load_state)
///
/// # Safety
/// `st` is valid for reads and nothing writes it meanwhile.
unsafe fn load_state(st: *const UserFpsimdState) {
    // SAFETY: loads from `st` only (the caller's contract); no kernel
    // code uses the registers written
    unsafe {
        core::arch::asm!(
            ".arch_extension fp",
            ".arch_extension simd",
            "ldp q0, q1, [{s}, #16 * 0]",
            "ldp q2, q3, [{s}, #16 * 2]",
            "ldp q4, q5, [{s}, #16 * 4]",
            "ldp q6, q7, [{s}, #16 * 6]",
            "ldp q8, q9, [{s}, #16 * 8]",
            "ldp q10, q11, [{s}, #16 * 10]",
            "ldp q12, q13, [{s}, #16 * 12]",
            "ldp q14, q15, [{s}, #16 * 14]",
            "ldp q16, q17, [{s}, #16 * 16]",
            "ldp q18, q19, [{s}, #16 * 18]",
            "ldp q20, q21, [{s}, #16 * 20]",
            "ldp q22, q23, [{s}, #16 * 22]",
            "ldp q24, q25, [{s}, #16 * 24]",
            "ldp q26, q27, [{s}, #16 * 26]",
            "ldp q28, q29, [{s}, #16 * 28]",
            "ldp q30, q31, [{s}, #16 * 30]",
            "ldr {t:w}, [{s}, #512]",
            "msr fpsr, {t}",
            "ldr {t:w}, [{s}, #516]",
            "msr fpcr, {t}",
            s = in(reg) st,
            t = out(reg) _,
            options(nostack, preserves_flags, readonly),
        );
    }
}

/// Save the live registers through this CPU's binding unless they are
/// not the running task's (Linux fpsimd_save_user_state: `last->st`);
/// its CPU's FP context claimed or interrupts off
fn save_user_state() {
    if crate::task::percpu::current().has_tif(tif::FOREIGN_FPSTATE) {
        return;
    }
    let last = this_cpu().fpsimd_last_state.load(Ordering::Relaxed);
    // SAFETY: the running task's registers are live, so the binding is
    // its own state (module invariant), alive while it runs; only the
    // task accesses it (`ThreadStruct` invariant), under the CPU's FP
    // context
    unsafe { save_state(last) };
}

/// The context switch to `next`, interrupts off, `current` still the
/// outgoing task (Linux fpsimd_thread_switch): save the outgoing task's
/// live registers, and mark `next`'s registers foreign unless this CPU
/// still holds its state. For a kernel thread `wrong_task` or
/// `wrong_cpu` always holds.
///
/// # Safety
/// Interrupts are off, `current` is the outgoing task and the switch to
/// `next` (not running) follows on this CPU.
pub unsafe fn thread_switch(next: &Task) {
    save_user_state();
    let cpu = this_cpu();
    let wrong_task = cpu.fpsimd_last_state.load(Ordering::Relaxed) != next.thread.st();
    let wrong_cpu = next.thread.fpsimd_cpu.load(Ordering::Relaxed) != cpu.id();
    if wrong_task || wrong_cpu {
        next.set_tif(tif::FOREIGN_FPSTATE);
    } else {
        next.clear_tif(tif::FOREIGN_FPSTATE);
    }
}

/// Make this CPU's registers `me`'s, the running task's (Linux
/// fpsimd_bind_task_to_cpu); its CPU's FP context claimed
fn bind_task_to_cpu(me: &Task) {
    let cpu = this_cpu();
    // INVARIANT: the binding is the running task's state, which its
    // caller is about to make live (module invariant)
    cpu.fpsimd_last_state
        .store(me.thread.st(), Ordering::Relaxed);
    me.thread.fpsimd_cpu.store(cpu.id(), Ordering::Relaxed);
}

/// Thread flags of the arch work on the way to user mode (Linux
/// ARCH_EXIT_TO_USER_MODE_WORK)
pub const EXIT_WORK: u32 = tif::FOREIGN_FPSTATE;

/// The arch work on the way to user mode, interrupts on (Linux
/// arch_exit_to_user_mode_work): load the task's FP/SIMD state if the
/// registers do not hold it (Linux fpsimd_restore_current_state)
pub fn exit_to_user_mode_work(work: u32) {
    if work & tif::FOREIGN_FPSTATE == 0 {
        return;
    }
    let me = crate::task::percpu::current();
    let _ctx = CpuFpContext::get();
    if me.test_and_clear_tif(tif::FOREIGN_FPSTATE) {
        // SAFETY: the running task's own state, under the CPU's FP
        // context: nothing writes it
        unsafe { load_state(me.thread.st()) };
        bind_task_to_cpu(&me);
    }
}

/// Make every CPU's copy of `t`'s state stale (Linux
/// fpsimd_flush_task_state): it is loaded from memory on its next return
/// to user mode. `t` is the running task or one not running.
fn flush_task_state(t: &Task) {
    t.thread.fpsimd_cpu.store(NO_CPU, Ordering::Relaxed);
    // Linux barrier()s: an interrupt-time switch sees `fpsimd_cpu` before
    // the flag, and code after sees the flag set
    compiler_fence(Ordering::SeqCst);
    t.set_tif(tif::FOREIGN_FPSTATE);
    compiler_fence(Ordering::SeqCst);
}

/// Save the running task's live registers and unbind them (Linux
/// fpsimd_save_and_flush_current_state): until its return to user mode
/// its state is the memory copy (`with_current_state`,
/// `update_current_state`)
pub fn save_and_flush_current_state() {
    let _ctx = CpuFpContext::get();
    save_user_state();
    flush_task_state(&crate::task::percpu::current());
}

/// Run `f` on the running task's saved FP/SIMD state, flushed by
/// `save_and_flush_current_state` (checked)
///
/// # Safety
/// `f` does not change the running task's FP/SIMD state (it may sleep:
/// a switch saves nothing into a flushed state).
pub unsafe fn with_current_state<R>(f: impl FnOnce(&UserFpsimdState) -> R) -> R {
    let me = crate::task::percpu::current();
    assert!(
        me.has_tif(tif::FOREIGN_FPSTATE),
        "fpsimd: state not flushed"
    );
    // SAFETY: flushed, only this task accesses it (type invariant), and
    // `f` does not write it (the caller's contract)
    f(unsafe { &*me.thread.st() })
}

/// Replace the running task's saved FP/SIMD state, flushed by
/// `save_and_flush_current_state` (checked): its return to user mode
/// loads it (Linux fpsimd_update_current_state)
pub fn update_current_state(state: &UserFpsimdState) {
    let me = crate::task::percpu::current();
    assert!(
        me.has_tif(tif::FOREIGN_FPSTATE),
        "fpsimd: state not flushed"
    );
    // SAFETY: flushed, only this task accesses it (type invariant); no
    // reference to it is live outside `with_current_state`, whose `f`
    // may not call this
    unsafe { *me.thread.st() = *state };
}

/// The new program image's initial FP/SIMD state: all zero (Linux
/// flush_thread -> fpsimd_flush_thread), loaded on the return to user
/// mode
pub fn flush_thread() {
    let me = crate::task::percpu::current();
    let _ctx = CpuFpContext::get();
    flush_task_state(&me);
    // SAFETY: the running task's own state, flushed: only it accesses it
    // (type invariant)
    unsafe { *me.thread.st() = UserFpsimdState::ZERO };
}

/// A fork child `child` gets the running task's FP/SIMD state (Linux
/// arch_dup_task_struct: fpsimd_save_and_flush_current_state, then the
/// copy; copy_thread: fpsimd_flush_task_state)
///
/// # Safety
/// `child` was made by the running task and has not run.
pub unsafe fn dup_thread(child: &Task) {
    save_and_flush_current_state();
    let me = crate::task::percpu::current();
    // SAFETY: the parent's state is flushed and its own; the child has
    // not run: only its creator, the running task, accesses its state
    // (type invariant, the caller's contract)
    unsafe { core::ptr::copy_nonoverlapping(me.thread.st(), child.thread.st(), 1) };
    flush_task_state(child);
}
