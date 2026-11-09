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

use crate::arch::Uaccess;
use crate::signal::siginfo::UserSigInfo;
use crate::signal::{SigAction, SigHandler, SigInfo, SigSet, Signal, Trap, sa_flags};
use crate::uaccess::{access_ok, copy_from_user, copy_to_user};
use crate::util::error::{KernelError, KernelResult};
use crate::util::pod::{FromBytes, IntoBytes};

// =============================================================================
// Signal Context (sigcontext)
// =============================================================================

/// x86_64 signal context (matches Linux struct sigcontext)
///
/// This is the saved register state from when the signal was delivered.
/// The signal handler can read/modify this to affect the return state.
#[repr(C)]
#[derive(Debug, Clone, Default, Copy)]
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
crate::pod!(SigContext {
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
    rsp,
    rip,
    eflags,
    cs,
    gs,
    fs,
    ss,
    err,
    trapno,
    oldmask,
    cr2,
    fpstate,
    reserved
});

// =============================================================================
// Stack Info (stack_t)
// =============================================================================

/// Stack info structure (matches Linux stack_t)
///
/// Describes an alternate signal stack.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
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
crate::pod!(StackT {
    ss_sp,
    ss_flags,
    _pad,
    ss_size
});

/// Alternate stack is disabled
pub const SS_DISABLE: i32 = 2;

// =============================================================================
// User Context (ucontext_t)
// =============================================================================

/// x86_64 ucontext structure (matches Linux struct ucontext)
///
/// This is the complete context saved for signal handling.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
crate::pod!(UContext {
    uc_flags,
    uc_link,
    uc_stack,
    uc_mcontext,
    uc_sigmask
});

// =============================================================================
// RT Signal Frame
// =============================================================================

/// x86_64 RT signal frame (pushed on user stack)
///
/// This is the frame structure that gets pushed onto the user stack
/// when delivering a signal. The pretcode field serves as the return
/// address, pointing to the signal trampoline that calls rt_sigreturn.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtSigFrame {
    /// Return address (points to restorer trampoline)
    /// When handler does `ret`, it returns here
    pub pretcode: u64,
    /// User context for rt_sigreturn
    pub uc: UContext,
    /// Signal info (siginfo_t)
    pub info: UserSigInfo,
    // The FP image (sigcontext.fpstate) lives above the frame, 64-aligned
}
crate::pod!(RtSigFrame { pretcode, uc, info });

// Layouts match Linux (arch/x86/include/uapi/asm/sigcontext.h, ucontext.h,
// asm-generic siginfo, rt_sigframe) and every byte is a named field: the
// frame is copied whole to user memory, so implicit padding would leak
// kernel stack
const _: () = assert!(core::mem::size_of::<SigContext>() == 256);
const _: () = assert!(core::mem::offset_of!(SigContext, cs) == 144);
const _: () = assert!(core::mem::offset_of!(SigContext, err) == 152);
const _: () = assert!(core::mem::size_of::<StackT>() == 24);
const _: () = assert!(core::mem::size_of::<SigSet>() == 8);
const _: () = assert!(core::mem::offset_of!(UContext, uc_mcontext) == 40);
const _: () = assert!(core::mem::offset_of!(UContext, uc_sigmask) == 296);
const _: () = assert!(core::mem::size_of::<UContext>() == 304);
const _: () = assert!(core::mem::offset_of!(RtSigFrame, uc) == 8);
const _: () = assert!(core::mem::offset_of!(RtSigFrame, info) == 312);
const _: () = assert!(core::mem::size_of::<RtSigFrame>() == 440);

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

/// No exec-time signal return page: x86-64 handlers need SA_RESTORER
/// (Linux x86-64 too; glibc always sets it)
pub const SIGPAGE: Option<[u32; 2]> = None;

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
/// On success the handler runs with the initial FP state, and the task's
/// pt_regs are redirected to it:
/// - RIP = handler, RSP = frame, RDI = signo, RSI = &info, RDX = &uc
///
/// Returns Ok(()) on success, Err(errno) on failure.
pub fn setup_rt_frame(
    sig: Signal,
    action: &SigAction,
    blocked: SigSet,
    info: &SigInfo,
    trap: &Trap,
    uframe: &crate::arch::UserFrame,
) -> KernelResult<()> {
    use super::fpu;

    // A copy, written back once the handler frame is in place
    let mut r = uframe.get();
    let regs = &mut r;

    // The interrupted user context (the task's pt_regs)
    let user_rip = regs.rip;
    let user_rflags = regs.rflags;
    let user_rsp = regs.rsp;

    // Get handler address
    let handler = match action.handler {
        SigHandler::Handler(addr) if addr < USER_ADDR_LIMIT => addr,
        _ => return Err(KernelError::InvalidArgument), // not a (usable) handler
    };

    // Get restorer (trampoline that calls rt_sigreturn)
    // If SA_RESTORER is set, use the provided restorer address
    // Otherwise we'd need to provide a default trampoline
    let restorer = if action.flags & sa_flags::SA_RESTORER != 0 {
        action.restorer
    } else {
        // No restorer provided - signal delivery will fail
        // In a real kernel we'd provide a VDSO trampoline
        return Err(KernelError::InvalidArgument);
    };

    // user_rsp is user-controlled: an underflow means no room (EFAULT, and
    // the caller forces SIGSEGV), never a wrapped address
    let frame_size = signal_frame_size();
    let fp_size = fpu::sigframe_size();
    let Some(fpstate_addr) = user_rsp.checked_sub(128 + fp_size as u64).map(|a| a & !63) else {
        return Err(KernelError::BadAddress);
    };
    let Some(frame_addr) = fpstate_addr
        .checked_sub(frame_size as u64)
        .and_then(|a| (a & !0xF).checked_sub(8))
    else {
        return Err(KernelError::BadAddress);
    };
    let total = (fpstate_addr + fp_size as u64 - frame_addr) as usize;

    // Validate user stack address
    if !access_ok(frame_addr, total) {
        return Err(KernelError::BadAddress);
    }

    // FP image of the interrupted code (live in the registers: the kernel
    // does not use them)
    let mut fp_area = fpu::FpuArea::init();
    let fp_len = fpu::save_sigframe(&mut fp_area);
    if copy_to_user::<Uaccess>(fpstate_addr, &fp_area.0[..fp_len]).is_err() {
        return Err(KernelError::BadAddress);
    }

    // Build SigContext from saved registers
    let sigctx = SigContext {
        r8: regs.r8,
        r9: regs.r9,
        r10: regs.r10,
        r11: regs.r11,
        r12: regs.r12,
        r13: regs.r13,
        r14: regs.r14,
        r15: regs.r15,
        rdi: regs.rdi,
        rsi: regs.rsi,
        rbp: regs.rbp,
        rbx: regs.rbx,
        rdx: regs.rdx,
        rax: regs.rax,
        rcx: regs.rcx,
        rsp: user_rsp,
        rip: user_rip,
        eflags: user_rflags,
        cs: USER_CS,
        ss: USER_SS,
        err: trap.error,
        trapno: trap.trapno,
        oldmask: blocked.bits(),
        cr2: trap.addr,
        fpstate: fpstate_addr,
        ..FromBytes::zeroed()
    };

    // Build StackT for ucontext (current stack info)
    let stack_t = StackT {
        ss_flags: SS_DISABLE,
        ..FromBytes::zeroed()
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
        info: info.to_user(),
    };

    // Copy frame to user stack
    if copy_to_user::<Uaccess>(frame_addr, &frame.as_bytes()[..frame_size]).is_err() {
        return Err(KernelError::BadAddress);
    }

    // Calculate addresses of info and ucontext within the frame
    let info_addr = frame_addr + core::mem::offset_of!(RtSigFrame, info) as u64;
    let uc_addr = frame_addr + core::mem::offset_of!(RtSigFrame, uc) as u64;

    // The handler starts with a clean FP state (Linux fpu__clear_user_states)
    fpu::load_init_state();

    // Redirect the return to user mode to the handler (Linux
    // __setup_rt_frame); RCX no longer equals RIP, so it goes through
    // IRET with every register
    regs.rsp = frame_addr;
    regs.rip = handler;
    regs.rflags = user_rflags & !HANDLER_CLEAR_EFLAGS;
    regs.rdi = u64::from(sig.nr());
    regs.rsi = info_addr;
    regs.rdx = uc_addr;
    // RAX = 0 for handlers without SA_SIGINFO (Linux: regs->ax = 0)
    regs.rax = 0;
    // Clear other argument registers for security
    regs.r8 = 0;
    regs.r9 = 0;
    regs.r10 = 0;
    uframe.set(r);

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
/// 3. Restores all saved registers to the task's pt_regs; the syscall
///    returns through IRETQ so RCX/R11 are restored too
///
/// Returns the value that should be in RAX (usually -EINTR for interrupted syscall),
/// or error code if restore fails.
pub fn sys_rt_sigreturn() -> crate::util::error::KernelResult<i64> {
    let frame = crate::task::percpu::current_pt_regs();
    // A copy, written back once the whole context is restored
    let mut r = frame.get();
    let regs = &mut r;

    // When the signal handler returns (via `ret`), the restorer's return address
    // (pretcode) has been popped from the stack, so RSP has moved up by 8 bytes.
    // The signal frame is 8 bytes below the current RSP.
    // This matches Linux: frame = (struct rt_sigframe __user *)(regs->sp - sizeof(long))
    // User-controlled: never let the arithmetic wrap (badframe instead)
    let uc_offset = core::mem::offset_of!(RtSigFrame, uc);
    let Some(uc_addr) = regs
        .rsp
        .checked_sub(8)
        .and_then(|frame| frame.checked_add(uc_offset as u64))
    else {
        return Err(crate::signal::sigreturn_badframe());
    };

    // Read UContext from user stack (any alignment: copied as bytes)
    let Ok(uc) = crate::uaccess::copy_val_from_user::<Uaccess, UContext>(uc_addr) else {
        return Err(crate::signal::sigreturn_badframe());
    };
    let sc = &uc.uc_mcontext;

    // Any RIP is taken, as by Linux restore_sigcontext: a non-canonical
    // one makes the return's IRET fault, which entry.rs turns into the
    // task's #GP (SIGSEGV; fixup_bad_iret)
    if !restore_sigframe_fpu(sc.fpstate) {
        return Err(crate::signal::sigreturn_badframe());
    }

    // Restore blocked signal mask
    crate::signal::with_task_signal_state(&crate::task::percpu::current(), |state| {
        // SIGKILL/SIGSTOP can never be blocked, even via a crafted frame
        state.blocked = uc.uc_sigmask.blockable();
    });

    // Restore all registers from sigcontext to pt_regs (Linux
    // restore_sigcontext); the syscall returns through IRET unless the
    // frame happens to fit SYSRET
    regs.rip = sc.rip;
    // Only the user-modifiable flags come from the frame (no IOPL etc.)
    regs.rflags = (regs.rflags & !FIX_EFLAGS) | (sc.eflags & FIX_EFLAGS);
    regs.rsp = sc.rsp;
    regs.rbx = sc.rbx;
    regs.rbp = sc.rbp;
    regs.r12 = sc.r12;
    regs.r13 = sc.r13;
    regs.r14 = sc.r14;
    regs.r15 = sc.r15;
    regs.rdi = sc.rdi;
    regs.rsi = sc.rsi;
    regs.rdx = sc.rdx;
    regs.r8 = sc.r8;
    regs.r9 = sc.r9;
    regs.r10 = sc.r10;
    regs.rax = sc.rax;
    regs.rcx = sc.rcx;
    regs.r11 = sc.r11;
    // No syscall to restart from here on (Linux: regs->orig_ax = -1)
    regs.orig_rax = u64::MAX;
    frame.set(r);

    // Return RAX from saved context
    // This allows signal handler to modify the return value
    Ok(sc.rax as i64)
}
