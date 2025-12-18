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

// Signal frame structures are infrastructure for future signal delivery.
// They will be used when we implement setup_rt_frame() and rt_sigreturn.
#![allow(dead_code)]

use crate::signal::SigSet;

// =============================================================================
// Signal Context (sigcontext)
// =============================================================================

/// aarch64 signal context (matches Linux struct sigcontext)
///
/// This is the saved register state from when the signal was delivered.
#[repr(C)]
#[derive(Debug, Clone)]
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
    /// Reserved space (256 bytes in Linux for __reserved)
    /// This holds extension records (FP/SIMD, SVE, etc.)
    pub _reserved: [u8; 4096],
}

impl Default for SigContext {
    fn default() -> Self {
        Self {
            fault_address: 0,
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            _reserved: [0; 4096],
        }
    }
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
// Signal Frame Setup (stub)
// =============================================================================

/// Set up signal frame on user stack (stub)
///
/// This function would:
/// 1. Calculate frame location on user stack (128-byte aligned)
/// 2. Build siginfo and ucontext from current registers
/// 3. Write frame to user memory
/// 4. Set x0 = signal number
/// 5. Set x30 (LR) = restorer trampoline
/// 6. Return (new_sp, handler_pc)
#[allow(dead_code)]
pub fn setup_rt_frame(
    _sig: u32,
    _handler: u64,
    _restorer: u64,
    _user_sp: u64,
    _user_pc: u64,
    _user_pstate: u64,
    _blocked: SigSet,
) -> Result<(u64, u64), i32> {
    // TODO: Full implementation
    Err(-38) // ENOSYS
}
