//! x86-64 signal frame structures and delivery
//!
//! This module provides the architecture-specific signal frame layout
//! for x86-64, matching the Linux ABI for signal delivery.
//!
//! When a signal is delivered, the kernel:
//! 1. Saves the current user context (registers, stack, flags) to a signal frame
//! 2. Pushes the frame onto the user stack
//! 3. Sets up RIP to point to the signal handler
//! 4. Sets up RSP to point to the signal frame (with pretcode as return address)
//!
//! When the handler returns, it executes the trampoline which calls rt_sigreturn
//! to restore the original context.

// Signal frame structures are infrastructure for future signal delivery.
// They will be used when we implement setup_rt_frame() and rt_sigreturn.
#![allow(dead_code)]

use crate::signal::SigSet;

// =============================================================================
// Signal Context (sigcontext)
// =============================================================================

/// x86_64 signal context (matches Linux struct sigcontext)
///
/// This is the saved register state from when the signal was delivered.
/// The signal handler can read/modify this to affect the return state.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SigContext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    /// Pointer to FPU/SSE state, or 0 if none saved
    pub fpstate: u64,
    pub reserved: [u64; 8],
}

// =============================================================================
// Stack Info (stack_t)
// =============================================================================

/// Stack info structure (matches Linux stack_t)
///
/// Describes an alternate signal stack.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct StackT {
    /// Stack base address
    pub ss_sp: u64,
    /// Flags (SS_DISABLE, SS_ONSTACK, SS_AUTODISARM)
    pub ss_flags: i32,
    /// Padding for alignment
    pub _pad: i32,
    /// Stack size
    pub ss_size: u64,
}

/// Alternate stack is disabled
pub const SS_DISABLE: i32 = 2;
/// Currently executing on alternate stack
pub const SS_ONSTACK: i32 = 1;

// =============================================================================
// User Context (ucontext_t)
// =============================================================================

/// x86_64 ucontext structure (matches Linux struct ucontext)
///
/// This is the complete context saved for signal handling.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct UContext {
    /// Context flags
    pub uc_flags: u64,
    /// Pointer to next context in chain (usually 0)
    pub uc_link: u64,
    /// Alternate signal stack info
    pub uc_stack: StackT,
    /// Machine context (saved registers)
    pub uc_mcontext: SigContext,
    /// Signal mask at time of signal
    pub uc_sigmask: SigSet,
    // Extended FPU state would follow
}

impl Default for UContext {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: StackT::default(),
            uc_mcontext: SigContext::default(),
            uc_sigmask: SigSet::EMPTY,
        }
    }
}

// =============================================================================
// Signal Info (siginfo_t)
// =============================================================================

/// siginfo_t structure (simplified)
///
/// Contains information about why a signal was raised.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SigInfo {
    /// Signal number
    pub si_signo: i32,
    /// Error number (if applicable)
    pub si_errno: i32,
    /// Signal code (SI_USER, SI_KERNEL, etc.)
    pub si_code: i32,
    /// Padding for alignment
    pub _pad: i32,
    /// Union of signal-specific fields
    pub _fields: [u64; 14],
}

/// Signal sent by kill/sigsend/raise
pub const SI_USER: i32 = 0;
/// Signal sent by kernel
pub const SI_KERNEL: i32 = 128;
/// Signal sent by timer expiration
pub const SI_TIMER: i32 = -2;
/// Signal sent by sigqueue
pub const SI_QUEUE: i32 = -1;
/// Signal sent by async I/O completion
pub const SI_ASYNCIO: i32 = -4;
/// Signal sent by queued message arrival
pub const SI_MESGQ: i32 = -3;

// =============================================================================
// RT Signal Frame
// =============================================================================

/// x86_64 RT signal frame (pushed on user stack)
///
/// This is the frame structure that gets pushed onto the user stack
/// when delivering a signal. The pretcode field serves as the return
/// address, pointing to the signal trampoline that calls rt_sigreturn.
#[repr(C)]
pub struct RtSigFrame {
    /// Return address (points to restorer trampoline)
    /// When handler does `ret`, it returns here
    pub pretcode: u64,
    /// Signal info (siginfo_t)
    pub info: SigInfo,
    /// User context for rt_sigreturn
    pub uc: UContext,
    // FPU state would follow if needed
}

// =============================================================================
// Signal Frame Setup (stub - full implementation requires uaccess)
// =============================================================================

/// Calculate signal frame size
pub const fn signal_frame_size() -> usize {
    core::mem::size_of::<RtSigFrame>()
}

/// Set up signal frame on user stack (stub)
///
/// This function would:
/// 1. Calculate frame location on user stack (aligned)
/// 2. Build siginfo and ucontext from current registers
/// 3. Write frame to user memory
/// 4. Return (new_rsp, handler_rip)
///
/// For now this is a stub - actual implementation requires:
/// - Access to current trap frame
/// - uaccess to write to user stack
/// - Proper error handling for invalid stack
#[allow(dead_code)]
pub fn setup_rt_frame(
    _sig: u32,
    _handler: u64,
    _restorer: u64,
    _user_rsp: u64,
    _user_rip: u64,
    _user_rflags: u64,
    _blocked: SigSet,
) -> Result<(u64, u64), i32> {
    // TODO: Full implementation
    Err(-38) // ENOSYS
}
