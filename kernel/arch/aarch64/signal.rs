//! aarch64 signal frame structures and delivery
//!
//! This module provides the architecture-specific signal frame layout
//! for aarch64, matching the Linux ABI for signal delivery.
//!
//! On aarch64, the signal frame is structured differently from x86_64:
//! - Uses x0-x30 general purpose registers
//! - Stack must be 128-byte aligned for signal delivery
//! - Extension records for SVE, FPU state, etc.
//! - Return address is in x30 (LR)

#![allow(dead_code)]

use crate::arch::Uaccess;
use crate::signal::{SigAction, SigHandler, SigSet, sa_flags};
use crate::uaccess::{UaccessArch, copy_from_user, copy_to_user};

// =============================================================================
// Signal Context (sigcontext)
// =============================================================================

/// aarch64 signal context (matches Linux struct sigcontext)
///
/// This is the saved register state from when the signal was delivered.
/// Note: Linux's sigcontext has a 4096-byte __reserved field for FP/SIMD state,
/// but we use a minimal version since we don't save FP state during signals.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SigContext {
    /// Fault address (if applicable)
    pub fault_address: u64,
    /// General purpose registers x0-x30
    pub regs: [u64; 31],
    /// Stack pointer (SP_EL0)
    pub sp: u64,
    /// Program counter (ELR_EL1)
    pub pc: u64,
    /// Processor state (PSTATE)
    pub pstate: u64,
    /// Reserved space - minimal version (just a null terminator record)
    /// Linux uses 4096 bytes for FP/SIMD, SVE, etc.
    /// We use 16 bytes (enough for a null _aarch64_ctx record)
    pub _reserved: [u8; 16],
}

// =============================================================================
// Stack Info (stack_t)
// =============================================================================

/// Stack info structure (matches Linux stack_t)
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct StackT {
    /// Stack base address
    pub ss_sp: u64,
    /// Flags
    pub ss_flags: i32,
    /// Padding
    pub _pad: i32,
    /// Stack size
    pub ss_size: u64,
}

// =============================================================================
// User Context (ucontext_t)
// =============================================================================

/// aarch64 ucontext structure (matches Linux struct ucontext)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct UContext {
    /// Flags
    pub uc_flags: u64,
    /// Link to next context
    pub uc_link: u64,
    /// Alternate signal stack
    pub uc_stack: StackT,
    /// Signal mask
    pub uc_sigmask: SigSet,
    /// Padding to align mcontext
    pub _pad: [u8; 120],
    /// Machine context
    pub uc_mcontext: SigContext,
}

impl Default for UContext {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: StackT::default(),
            uc_sigmask: SigSet::EMPTY,
            _pad: [0; 120],
            uc_mcontext: SigContext::default(),
        }
    }
}

// =============================================================================
// Signal Info (siginfo_t)
// =============================================================================

/// siginfo_t structure (simplified, same as x86_64)
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SigInfo {
    /// Signal number
    pub si_signo: i32,
    /// Error number
    pub si_errno: i32,
    /// Signal code
    pub si_code: i32,
    /// Padding
    pub _pad: i32,
    /// Signal-specific fields
    pub _fields: [u64; 14],
}

// =============================================================================
// RT Signal Frame
// =============================================================================

/// aarch64 RT signal frame (pushed on user stack)
///
/// On aarch64, the trampoline address is set in x30 (LR), not pushed
/// as a return address like on x86_64. The frame structure is simpler.
#[repr(C)]
pub struct RtSigFrame {
    /// Signal info
    pub info: SigInfo,
    /// User context
    pub uc: UContext,
}

// =============================================================================
// Constants
// =============================================================================

/// Signal frame must be 128-byte aligned on aarch64
pub const SIGNAL_FRAME_ALIGN: usize = 128;

/// Calculate signal frame size (128-byte aligned)
pub const fn signal_frame_size() -> usize {
    let size = core::mem::size_of::<RtSigFrame>();
    (size + SIGNAL_FRAME_ALIGN - 1) & !(SIGNAL_FRAME_ALIGN - 1)
}

// =============================================================================
// Signal Frame Setup
// =============================================================================

/// Signal sent by kill/sigsend/raise
const SI_USER: i32 = 0;

/// SS_DISABLE flag for stack_t
const SS_DISABLE: i32 = 2;

/// Set up signal frame on user stack
///
/// This function:
/// 1. Calculates frame location on user stack (128-byte aligned)
/// 2. Builds siginfo and ucontext from saved registers
/// 3. Writes frame to user memory
/// 4. Updates percpu saved state to redirect to handler
///
/// On aarch64:
/// - x0 = signal number
/// - x1 = &siginfo
/// - x2 = &ucontext
/// - x30 (LR) = restorer trampoline
/// - PC = handler
///
/// Returns Ok(()) on success, Err(errno) on failure.
pub fn setup_rt_frame(sig: u32, action: &SigAction, blocked: SigSet) -> Result<(), i32> {
    use super::percpu;

    // Get saved user state from percpu
    let user_elr = percpu::get_syscall_user_elr();
    let user_spsr = percpu::get_syscall_user_spsr();
    let user_sp = percpu::get_syscall_user_sp();
    let user_regs = percpu::get_syscall_user_regs();

    // Get handler address
    let handler = match action.handler {
        SigHandler::Handler(addr) => addr,
        _ => return Err(-22), // EINVAL - not a handler
    };

    // Get restorer (trampoline that calls rt_sigreturn)
    let restorer = if action.flags & sa_flags::SA_RESTORER != 0 {
        action.restorer
    } else {
        // No restorer provided - signal delivery will fail
        return Err(-22); // EINVAL
    };

    // Calculate frame size and location on user stack
    // Frame must be 128-byte aligned on aarch64
    let frame_size = signal_frame_size();
    let frame_addr = (user_sp - frame_size as u64) & !(SIGNAL_FRAME_ALIGN as u64 - 1);

    // Validate user stack address
    if !Uaccess::access_ok(frame_addr, frame_size) {
        return Err(-14); // EFAULT
    }

    // Build SigContext from saved registers
    let sigctx = SigContext {
        fault_address: 0,
        regs: user_regs,
        sp: user_sp,
        pc: user_elr,
        pstate: user_spsr,
        _reserved: [0; 16],
    };

    // Build SigInfo
    let siginfo = SigInfo {
        si_signo: sig as i32,
        si_errno: 0,
        si_code: SI_USER,
        _pad: 0,
        _fields: [0; 14],
    };

    // Build StackT for ucontext
    let stack_t = StackT {
        ss_sp: 0,
        ss_flags: SS_DISABLE,
        _pad: 0,
        ss_size: 0,
    };

    // Build UContext
    let ucontext = UContext {
        uc_flags: 0,
        uc_link: 0,
        uc_stack: stack_t,
        uc_sigmask: blocked,
        _pad: [0; 120],
        uc_mcontext: sigctx,
    };

    // Build the complete frame
    let frame = RtSigFrame {
        info: siginfo,
        uc: ucontext,
    };

    // Copy frame to user stack
    let frame_bytes = unsafe {
        core::slice::from_raw_parts(&frame as *const RtSigFrame as *const u8, frame_size)
    };

    if copy_to_user::<Uaccess>(frame_addr, frame_bytes).is_err() {
        return Err(-14); // EFAULT
    }

    // Calculate addresses of info and ucontext within the frame
    let info_offset = core::mem::offset_of!(RtSigFrame, info);
    let uc_offset = core::mem::offset_of!(RtSigFrame, uc);
    let info_addr = frame_addr + info_offset as u64;
    let uc_addr = frame_addr + uc_offset as u64;

    // Update percpu saved state to redirect execution to handler
    // On aarch64:
    // - x0 = signal number (first argument)
    // - x1 = &siginfo (second argument)
    // - x2 = &ucontext (third argument)
    // - x30 = restorer (return address in LR)
    // - SP = frame_addr
    // - ELR = handler (program counter)
    unsafe {
        let percpu_mut = percpu::current_cpu_mut();
        percpu_mut.syscall_user_sp = frame_addr;
        percpu_mut.syscall_user_elr = handler;
        percpu_mut.syscall_user_regs[0] = sig as u64; // x0 = signal number
        percpu_mut.syscall_user_regs[1] = info_addr; // x1 = &siginfo
        percpu_mut.syscall_user_regs[2] = uc_addr; // x2 = &ucontext
        percpu_mut.syscall_user_regs[30] = restorer; // x30 (LR) = restorer
        // Clear other argument registers for security
        percpu_mut.syscall_user_regs[3] = 0;
        percpu_mut.syscall_user_regs[4] = 0;
        percpu_mut.syscall_user_regs[5] = 0;
        percpu_mut.syscall_user_regs[6] = 0;
        percpu_mut.syscall_user_regs[7] = 0;
        // Signal that the return context was modified
        percpu_mut.signal_context_modified = true;
    }

    Ok(())
}

/// Minimal sigcontext for reading (without the large _reserved array)
/// This avoids stack overflow when reading from user space
#[repr(C)]
struct SigContextMinimal {
    pub fault_address: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    // Skip _reserved - we don't need it for context restore
}

/// Restore context from signal frame (sys_rt_sigreturn)
///
/// This function:
/// 1. Reads the UContext from user stack
/// 2. Restores blocked signal mask
/// 3. Restores all saved registers to percpu
///
/// Returns the value that should be in x0 (return value),
/// or error code if restore fails.
pub fn sys_rt_sigreturn() -> i64 {
    use super::percpu;
    use crate::signal::SigSet;

    // The current SP points to the signal frame
    let frame_addr = percpu::get_syscall_user_sp();

    // Calculate offsets to read just the parts we need
    // RtSigFrame layout: { info: SigInfo, uc: UContext }
    // UContext layout: { uc_flags, uc_link, uc_stack, uc_sigmask, _pad, uc_mcontext }
    let uc_offset = core::mem::offset_of!(RtSigFrame, uc);
    let uc_addr = frame_addr + uc_offset as u64;

    // Read uc_sigmask from ucontext
    let sigmask_offset = core::mem::offset_of!(UContext, uc_sigmask);
    let sigmask_addr = uc_addr + sigmask_offset as u64;

    // Validate address for sigmask
    if !Uaccess::access_ok(sigmask_addr, core::mem::size_of::<SigSet>()) {
        return -14; // EFAULT
    }

    const SIGMASK_SIZE: usize = core::mem::size_of::<SigSet>();
    let mut sigmask_bytes = [0u8; SIGMASK_SIZE];
    if copy_from_user::<Uaccess>(&mut sigmask_bytes, sigmask_addr, SIGMASK_SIZE).is_err() {
        return -14; // EFAULT
    }
    let sigmask: SigSet = unsafe { core::ptr::read(sigmask_bytes.as_ptr() as *const SigSet) };

    // Read the minimal sigcontext (without _reserved array to avoid stack overflow)
    let mcontext_offset = core::mem::offset_of!(UContext, uc_mcontext);
    let mcontext_addr = uc_addr + mcontext_offset as u64;
    let minimal_size = core::mem::size_of::<SigContextMinimal>();

    if !Uaccess::access_ok(mcontext_addr, minimal_size) {
        return -14; // EFAULT
    }

    let mut sc_bytes = [0u8; core::mem::size_of::<SigContextMinimal>()];
    if copy_from_user::<Uaccess>(&mut sc_bytes, mcontext_addr, minimal_size).is_err() {
        return -14; // EFAULT
    }
    let sc: SigContextMinimal =
        unsafe { core::ptr::read(sc_bytes.as_ptr() as *const SigContextMinimal) };

    // Restore blocked signal mask
    let tid = crate::task::percpu::current_tid();
    crate::signal::with_task_signal_state(tid, |state| {
        state.blocked = sigmask;
        state.recalc_sigpending();
    });

    // Restore all registers from sigcontext to percpu
    unsafe {
        let percpu_mut = percpu::current_cpu_mut();
        percpu_mut.syscall_user_elr = sc.pc;
        percpu_mut.syscall_user_spsr = sc.pstate;
        percpu_mut.syscall_user_sp = sc.sp;
        percpu_mut.syscall_user_regs = sc.regs;
        // Signal that the return context was modified
        percpu_mut.signal_context_modified = true;
    }

    // Return x0 from saved context
    sc.regs[0] as i64
}
