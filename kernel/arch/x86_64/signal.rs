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

#![allow(dead_code)]

use crate::arch::Uaccess;
use crate::signal::{KSigInfo, SigAction, SigHandler, SigSet, sa_flags};
use crate::uaccess::{UaccessArch, copy_from_user, copy_to_user};

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
    /// User context for rt_sigreturn
    pub uc: UContext,
    /// Signal info (siginfo_t)
    pub info: SigInfo,
    // The FP image (sigcontext.fpstate) lives above the frame, 64-aligned
}

/// uc_flags: the FP image is in XSAVE format with `_fpx_sw_bytes`
const UC_FP_XSTATE: u64 = 0x1;
/// uc_flags: sigcontext.ss is valid / must be restored strictly
const UC_SIGCONTEXT_SS: u64 = 0x2;
const UC_STRICT_RESTORE_SS: u64 = 0x4;

/// RFLAGS bits user code may change through rt_sigreturn (Linux FIX_EFLAGS:
/// AC, OF, DF, TF, SF, ZF, AF, PF, CF, RF)
const FIX_EFLAGS: u64 = 0x5_0dd5;
/// RFLAGS bits cleared for the handler (DF, TF, RF)
const HANDLER_CLEAR_EFLAGS: u64 = 0x400 | 0x100 | 0x1_0000;

/// First non-canonical user address: RIP must stay below it (SYSRET/IRET
/// to a non-canonical RIP faults in kernel mode)
const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;

// =============================================================================
// Signal Frame Setup
// =============================================================================

/// Calculate signal frame size
pub const fn signal_frame_size() -> usize {
    core::mem::size_of::<RtSigFrame>()
}

/// User code segment selector
const USER_CS: u16 = 0x23; // RPL=3, index=4
/// User data segment selector
const USER_SS: u16 = 0x1b; // RPL=3, index=3

/// Set up signal frame on user stack
///
/// Linux get_sigframe layout, from the interrupted RSP down: the 128-byte
/// red zone, the FP image (64-byte aligned; `sigcontext.fpstate` points to
/// it), then the `RtSigFrame` placed so the handler starts as if called
/// (RSP + 8 is 16-byte aligned; `pretcode` is its "return address").
///
/// On success the handler runs with the initial FP state, and the per-CPU
/// user-register block is redirected to it:
/// - RIP = handler, RSP = frame, RDI = signo, RSI = &info, RDX = &uc
///
/// Returns Ok(()) on success, Err(errno) on failure.
pub fn setup_rt_frame(
    sig: u32,
    action: &SigAction,
    blocked: SigSet,
    info: &KSigInfo,
) -> Result<(), i32> {
    use super::fpu;
    use super::percpu;

    // Get saved user state from percpu
    let user_rip = percpu::get_syscall_user_rip();
    let user_rflags = percpu::get_syscall_user_rflags();
    let user_rsp = percpu::get_syscall_user_rsp();
    let (rbx, rbp, r12, r13, r14, r15) = percpu::get_syscall_user_callee_saved();
    let (rdi, rsi, rdx, r8, r9, r10) = percpu::get_syscall_user_caller_saved();
    let (rax, rcx, r11) = {
        let p = unsafe { percpu::current_cpu_mut() };
        (p.syscall_user_rax, p.syscall_user_rcx, p.syscall_user_r11)
    };

    // Get handler address
    let handler = match action.handler {
        SigHandler::Handler(addr) if addr < USER_ADDR_LIMIT => addr,
        _ => return Err(-22), // EINVAL - not a (usable) handler
    };

    // Get restorer (trampoline that calls rt_sigreturn)
    // If SA_RESTORER is set, use the provided restorer address
    // Otherwise we'd need to provide a default trampoline
    let restorer = if action.flags & sa_flags::SA_RESTORER != 0 {
        action.restorer
    } else {
        // No restorer provided - signal delivery will fail
        // In a real kernel we'd provide a VDSO trampoline
        return Err(-22); // EINVAL
    };

    // user_rsp is user-controlled: an underflow means no room (EFAULT, and
    // the caller forces SIGSEGV), never a wrapped address
    let frame_size = signal_frame_size();
    let fp_size = fpu::sigframe_size();
    let Some(fpstate_addr) = user_rsp.checked_sub(128 + fp_size as u64).map(|a| a & !63) else {
        return Err(-14);
    };
    let Some(frame_addr) = fpstate_addr
        .checked_sub(frame_size as u64)
        .and_then(|a| (a & !0xF).checked_sub(8))
    else {
        return Err(-14);
    };
    let total = (fpstate_addr + fp_size as u64 - frame_addr) as usize;

    // Validate user stack address
    if !Uaccess::access_ok(frame_addr, total) {
        return Err(-14); // EFAULT
    }

    // FP image of the interrupted code (live in the registers: the kernel
    // does not use them)
    let mut fp_area = fpu::FpuArea::init();
    let fp_len = fpu::save_sigframe(&mut fp_area);
    if copy_to_user::<Uaccess>(fpstate_addr, &fp_area.0[..fp_len]).is_err() {
        return Err(-14);
    }

    // Build SigContext from saved registers
    let sigctx = SigContext {
        r8,
        r9,
        r10,
        r11,
        r12,
        r13,
        r14,
        r15,
        rdi,
        rsi,
        rbp,
        rbx,
        rdx,
        rax,
        rcx,
        rsp: user_rsp,
        rip: user_rip,
        eflags: user_rflags,
        cs: USER_CS,
        gs: 0,
        fs: 0,
        ss: USER_SS,
        err: info.error,
        trapno: info.trapno,
        oldmask: blocked.bits(),
        // CR2 is reported for page faults (vector 14)
        cr2: if info.trapno == 14 { info.addr } else { 0 },
        fpstate: fpstate_addr,
        reserved: [0; 8],
    };

    // Build SigInfo (si_addr is the first union field)
    let mut fields = [0u64; 14];
    fields[0] = info.addr;
    let siginfo = SigInfo {
        si_signo: sig as i32,
        si_errno: 0,
        si_code: info.code,
        _pad: 0,
        _fields: fields,
    };

    // Build StackT for ucontext (current stack info)
    let stack_t = StackT {
        ss_sp: 0,
        ss_flags: SS_DISABLE,
        _pad: 0,
        ss_size: 0,
    };

    let mut uc_flags = UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS;
    if fpu::use_xsave() {
        uc_flags |= UC_FP_XSTATE;
    }

    // Build the complete frame
    let frame = RtSigFrame {
        pretcode: restorer,
        uc: UContext {
            uc_flags,
            uc_link: 0,
            uc_stack: stack_t,
            uc_mcontext: sigctx,
            uc_sigmask: blocked,
        },
        info: siginfo,
    };

    // Copy frame to user stack
    let frame_bytes = unsafe {
        core::slice::from_raw_parts(&frame as *const RtSigFrame as *const u8, frame_size)
    };

    if copy_to_user::<Uaccess>(frame_addr, frame_bytes).is_err() {
        return Err(-14); // EFAULT
    }

    // Calculate addresses of info and ucontext within the frame
    let info_addr = frame_addr + core::mem::offset_of!(RtSigFrame, info) as u64;
    let uc_addr = frame_addr + core::mem::offset_of!(RtSigFrame, uc) as u64;

    // The handler starts with a clean FP state (Linux fpu__clear_user_states)
    fpu::load_init_state();

    // Update percpu saved state to redirect execution to handler
    unsafe {
        let percpu_mut = percpu::current_cpu_mut();
        percpu_mut.syscall_user_rsp = frame_addr;
        percpu_mut.syscall_user_rip = handler;
        percpu_mut.syscall_user_rflags = user_rflags & !HANDLER_CLEAR_EFLAGS;
        percpu_mut.syscall_user_rdi = sig as u64;
        percpu_mut.syscall_user_rsi = info_addr;
        percpu_mut.syscall_user_rdx = uc_addr;
        // RAX = 0 for handlers without SA_SIGINFO (Linux: regs->ax = 0)
        percpu_mut.syscall_user_rax = 0;
        // Clear other argument registers for security
        percpu_mut.syscall_user_r8 = 0;
        percpu_mut.syscall_user_r9 = 0;
        percpu_mut.syscall_user_r10 = 0;
        // Signal that the return context was modified
        percpu_mut.signal_context_modified = true;
    }

    Ok(())
}

/// Load the FP state saved at `fpstate` by [`setup_rt_frame`] (0 = none:
/// initial state). False for an unreadable or malformed image.
fn restore_sigframe_fpu(fpstate: u64) -> bool {
    use super::fpu;

    if fpstate == 0 {
        fpu::load_init_state();
        return true;
    }
    let mut area = fpu::FpuArea::init();
    // The legacy 512 bytes always; the XSAVE part if the frame says so
    if copy_from_user::<Uaccess>(&mut area.0[..512], fpstate, 512).is_err() {
        return false;
    }
    let sw = &area.0[464..468];
    if fpu::use_xsave() && u32::from_le_bytes(sw.try_into().unwrap()) == fpu::FP_XSTATE_MAGIC1 {
        let size = fpu::sigframe_size();
        let Some(rest) = fpstate.checked_add(512) else {
            return false;
        };
        if copy_from_user::<Uaccess>(&mut area.0[512..size], rest, size - 512).is_err() {
            return false;
        }
    }
    if !fpu::sanitize_sigframe(&mut area) {
        return false;
    }
    fpu::restore(&area);
    true
}

/// Restore context from signal frame (sys_rt_sigreturn)
///
/// This function:
/// 1. Reads the UContext from user stack
/// 2. Restores the FP state and the blocked signal mask
/// 3. Restores all saved registers to percpu; the syscall returns through
///    IRETQ so RCX/R11 are restored too
///
/// Returns the value that should be in RAX (usually -EINTR for interrupted syscall),
/// or error code if restore fails.
pub fn sys_rt_sigreturn() -> i64 {
    use super::percpu;

    // When the signal handler returns (via `ret`), the restorer's return address
    // (pretcode) has been popped from the stack, so RSP has moved up by 8 bytes.
    // The signal frame is 8 bytes below the current RSP.
    // This matches Linux: frame = (struct rt_sigframe __user *)(regs->sp - sizeof(long))
    // User-controlled: never let the arithmetic wrap (badframe instead)
    let uc_offset = core::mem::offset_of!(RtSigFrame, uc);
    let Some(uc_addr) = percpu::get_syscall_user_rsp()
        .checked_sub(8)
        .and_then(|frame| frame.checked_add(uc_offset as u64))
    else {
        return crate::signal::sigreturn_badframe();
    };
    let uc_size = core::mem::size_of::<UContext>();

    // Validate address
    if !Uaccess::access_ok(uc_addr, uc_size) {
        return crate::signal::sigreturn_badframe();
    }

    // Read UContext from user stack
    let mut uc_bytes = [0u8; core::mem::size_of::<UContext>()];
    if copy_from_user::<Uaccess>(&mut uc_bytes, uc_addr, uc_size).is_err() {
        return crate::signal::sigreturn_badframe();
    }

    // Safety: UContext is repr(C) and we read the correct size
    let uc: UContext = unsafe { core::ptr::read(uc_bytes.as_ptr() as *const UContext) };
    let sc = &uc.uc_mcontext;

    // A non-canonical RIP would fault on the return to user mode itself
    if sc.rip >= USER_ADDR_LIMIT || !restore_sigframe_fpu(sc.fpstate) {
        return crate::signal::sigreturn_badframe();
    }

    // Restore blocked signal mask
    let tid = crate::task::percpu::current_tid();
    crate::signal::with_task_signal_state(tid, |state| {
        state.blocked = uc.uc_sigmask;
        state.recalc_sigpending();
    });

    // Restore all registers from sigcontext to percpu
    unsafe {
        let percpu_mut = percpu::current_cpu_mut();
        percpu_mut.syscall_user_rip = sc.rip;
        // Only the user-modifiable flags come from the frame (no IOPL etc.)
        percpu_mut.syscall_user_rflags =
            (percpu_mut.syscall_user_rflags & !FIX_EFLAGS) | (sc.eflags & FIX_EFLAGS);
        percpu_mut.syscall_user_rsp = sc.rsp;
        percpu_mut.syscall_user_rbx = sc.rbx;
        percpu_mut.syscall_user_rbp = sc.rbp;
        percpu_mut.syscall_user_r12 = sc.r12;
        percpu_mut.syscall_user_r13 = sc.r13;
        percpu_mut.syscall_user_r14 = sc.r14;
        percpu_mut.syscall_user_r15 = sc.r15;
        percpu_mut.syscall_user_rdi = sc.rdi;
        percpu_mut.syscall_user_rsi = sc.rsi;
        percpu_mut.syscall_user_rdx = sc.rdx;
        percpu_mut.syscall_user_r8 = sc.r8;
        percpu_mut.syscall_user_r9 = sc.r9;
        percpu_mut.syscall_user_r10 = sc.r10;
        percpu_mut.syscall_user_rax = sc.rax;
        percpu_mut.syscall_user_rcx = sc.rcx;
        percpu_mut.syscall_user_r11 = sc.r11;
        // Signal that the return context was modified; return via IRETQ
        percpu_mut.signal_context_modified = true;
        percpu_mut.syscall_full_restore = true;
    }

    // Return RAX from saved context
    // This allows signal handler to modify the return value
    sc.rax as i64
}
