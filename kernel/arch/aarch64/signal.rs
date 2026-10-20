//! aarch64 signal frame structures and delivery
//!
//! This module provides the architecture-specific signal frame layout
//! for aarch64, matching the Linux ABI for signal delivery
//! (arch/arm64/include/uapi/asm/{ucontext,sigcontext}.h,
//! arch/arm64/kernel/signal.c):
//!
//! ```text
//! frame record {x29, x30}       <- handler's x29 (16-byte aligned)
//! rt_sigframe {
//!     siginfo info;             <- x1
//!     ucontext uc {             <- x2
//!         uc_flags, uc_link, uc_stack, uc_sigmask, __unused[120],
//!         sigcontext uc_mcontext (16-byte aligned) {
//!             fault_address, regs[31], sp, pc, pstate,
//!             __reserved[4096]: fpsimd_context, terminator record
//!         }
//!     }
//! }                             <- handler's sp
//! ```
//!
//! The FP/SIMD registers come from (and rt_sigreturn writes them back to)
//! the task's EL0 trap frame, where they live while it is in the kernel.

#![allow(dead_code)]

use super::Aarch64TrapFrame;
use crate::arch::Uaccess;
use crate::signal::{KSigInfo, SigAction, SigHandler, SigSet, sa_flags};
use crate::uaccess::{UaccessArch, copy_from_user, copy_to_user};

// =============================================================================
// Signal Context (sigcontext)
// =============================================================================

/// aarch64 signal context without `__reserved` (Linux struct sigcontext;
/// the 4096-byte `__reserved` area follows at [`RESERVED_OFFSET`])
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default)]
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
    /// Explicit (zeroed) padding up to the 16-byte aligned `__reserved`;
    /// implicit padding would copy uninitialized kernel stack to user
    pub _pad: u64,
}

/// Size of `sigcontext.__reserved`
pub const RESERVED_SIZE: usize = 4096;

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

/// aarch64 ucontext structure (matches Linux struct ucontext up to
/// `uc_mcontext.__reserved`)
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
    /// Padding: Linux's 120-byte `__unused` (1024 bits of sigset_t space)
    /// plus the 8 alignment bytes before the 16-byte aligned
    /// `uc_mcontext`, explicit so they are zeroed, never stack garbage
    pub _pad: [u8; 128],
    /// Machine context (16-byte aligned, starts at offset 176)
    pub uc_mcontext: SigContext,
}

impl Default for UContext {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: StackT::default(),
            uc_sigmask: SigSet::EMPTY,
            _pad: [0; 128],
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

/// aarch64 RT signal frame up to `__reserved` (pushed on user stack)
///
/// On aarch64, the trampoline address is set in x30 (LR), not pushed
/// as a return address like on x86_64.
#[repr(C)]
pub struct RtSigFrame {
    /// Signal info
    pub info: SigInfo,
    /// User context
    pub uc: UContext,
}

/// Offset of `uc.uc_mcontext.__reserved` in the frame
pub const RESERVED_OFFSET: usize = core::mem::size_of::<RtSigFrame>();

// Layouts match Linux (arch/arm64/include/uapi/asm/{sigcontext,ucontext}.h,
// asm-generic siginfo) and every byte is a named field: the frame is
// copied whole to user memory, so implicit padding would leak kernel stack
const _: () = assert!(core::mem::size_of::<SigContext>() == 8 + 31 * 8 + 3 * 8 + 8);
const _: () = assert!(core::mem::size_of::<StackT>() == 24);
const _: () = assert!(core::mem::size_of::<SigSet>() == 8);
const _: () = assert!(core::mem::size_of::<SigInfo>() == 128);
const _: () = assert!(core::mem::offset_of!(UContext, uc_stack) == 16);
const _: () = assert!(core::mem::offset_of!(UContext, uc_sigmask) == 40);
const _: () = assert!(core::mem::offset_of!(UContext, _pad) == 48);
const _: () = assert!(core::mem::size_of::<UContext>() == 176 + core::mem::size_of::<SigContext>());
const _: () = assert!(core::mem::offset_of!(RtSigFrame, uc) == 128);
const _: () = assert!(core::mem::size_of::<CtxHead>() == 8);
const _: () = assert!(core::mem::size_of::<EsrContext>() == 16);
const _: () = assert!(core::mem::offset_of!(UContext, uc_mcontext) == 176);
const _: () = assert!(RESERVED_OFFSET == 128 + 176 + 288);

/// Context record header in `__reserved` (struct _aarch64_ctx)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CtxHead {
    magic: u32,
    size: u32,
}

/// FP/SIMD record (struct fpsimd_context)
#[repr(C)]
#[derive(Clone, Copy)]
struct FpsimdContext {
    head: CtxHead,
    fpsr: u32,
    fpcr: u32,
    vregs: [u128; 32],
}

/// Fault syndrome record (struct esr_context)
#[repr(C)]
#[derive(Clone, Copy)]
struct EsrContext {
    head: CtxHead,
    esr: u64,
}

/// fpsimd_context magic
pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
/// esr_context magic
pub const ESR_MAGIC: u32 = 0x4553_5201;

const FPSIMD_SIZE: usize = core::mem::size_of::<FpsimdContext>();
const _: () = assert!(FPSIMD_SIZE == 528);

// =============================================================================
// Constants
// =============================================================================

/// Signal frame alignment (Linux: 16)
pub const SIGNAL_FRAME_ALIGN: u64 = 16;

/// Full signal frame size (header + __reserved)
pub const fn signal_frame_size() -> usize {
    RESERVED_OFFSET + RESERVED_SIZE
}

// =============================================================================
// Signal Frame Setup
// =============================================================================

/// SS_DISABLE flag for stack_t
const SS_DISABLE: i32 = 2;

/// PSTATE bits user code may set through rt_sigreturn: NZCV, SSBS, BTYPE,
/// DIT, TCO. Mode (EL0t), DAIF and everything else are forced to 0.
const PSTATE_USER_MASK: u64 = 0xF000_0000 | (1 << 12) | (3 << 10) | (1 << 24) | (1 << 25);

/// Set up signal frame on user stack
///
/// This function:
/// 1. Calculates frame location on user stack (Linux get_sigframe)
/// 2. Builds siginfo and ucontext (with the FP/SIMD record) from saved registers
/// 3. Writes frame to user memory
/// 4. Redirects the task's pt_regs (`regs`) to the handler
///
/// On aarch64:
/// - x0 = signal number
/// - x1 = &siginfo
/// - x2 = &ucontext
/// - x29 = frame record {x29, x30}
/// - x30 (LR) = restorer trampoline
/// - PC = handler
///
/// Returns Ok(()) on success, Err(errno) on failure.
pub fn setup_rt_frame(
    sig: u32,
    action: &SigAction,
    blocked: SigSet,
    info: &KSigInfo,
    regs: &mut Aarch64TrapFrame,
) -> Result<(), i32> {
    // The interrupted user context (the task's pt_regs)
    let user_elr = regs.elr;
    let user_spsr = regs.spsr;
    let user_sp = regs.sp;
    let user_regs = regs.x;

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

    // Frame record, then the frame below it, both 16-byte aligned.
    // user_sp is user-controlled: an underflow means no room (EFAULT, and
    // the caller forces SIGSEGV), never a wrapped address
    let frame_size = signal_frame_size() as u64;
    let Some(record_addr) = user_sp
        .checked_sub(16)
        .map(|a| a & !(SIGNAL_FRAME_ALIGN - 1))
    else {
        return Err(-14);
    };
    let Some(frame_addr) = record_addr
        .checked_sub(frame_size)
        .map(|a| a & !(SIGNAL_FRAME_ALIGN - 1))
    else {
        return Err(-14);
    };

    // Validate user stack address
    if !Uaccess::access_ok(frame_addr, (record_addr + 16 - frame_addr) as usize) {
        return Err(-14); // EFAULT
    }

    // __reserved: the FP/SIMD record of the interrupted code, an
    // esr_context for faults, then the terminating null record
    let fpsimd = FpsimdContext {
        head: CtxHead {
            magic: FPSIMD_MAGIC,
            size: FPSIMD_SIZE as u32,
        },
        fpsr: regs.fpsr,
        fpcr: regs.fpcr,
        vregs: regs.v,
    };
    let reserved_addr = frame_addr + RESERVED_OFFSET as u64;
    let mut end = reserved_addr + FPSIMD_SIZE as u64;
    if copy_to_user::<Uaccess>(reserved_addr, as_bytes(&fpsimd)).is_err() {
        return Err(-14);
    }
    if info.error != 0 {
        let esr = EsrContext {
            head: CtxHead {
                magic: ESR_MAGIC,
                size: core::mem::size_of::<EsrContext>() as u32,
            },
            esr: info.error,
        };
        if copy_to_user::<Uaccess>(end, as_bytes(&esr)).is_err() {
            return Err(-14);
        }
        end += core::mem::size_of::<EsrContext>() as u64;
    }
    if copy_to_user::<Uaccess>(end, as_bytes(&CtxHead::default())).is_err() {
        return Err(-14);
    }

    // Frame record for unwinders: {x29, x30} of the interrupted code
    let record = [user_regs[29], user_regs[30]];
    if copy_to_user::<Uaccess>(record_addr, as_bytes(&record)).is_err() {
        return Err(-14);
    }

    // Build the frame header (siginfo + ucontext up to __reserved);
    // si_addr is the first union field
    let mut fields = [0u64; 14];
    fields[0] = info.addr;
    let frame = RtSigFrame {
        info: SigInfo {
            si_signo: sig as i32,
            si_errno: 0,
            si_code: info.code,
            _pad: 0,
            _fields: fields,
        },
        uc: UContext {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: StackT {
                ss_sp: 0,
                ss_flags: SS_DISABLE,
                _pad: 0,
                ss_size: 0,
            },
            uc_sigmask: blocked,
            _pad: [0; 128],
            uc_mcontext: SigContext {
                // FAR of a data/instruction abort
                fault_address: if info.error != 0 { info.addr } else { 0 },
                regs: user_regs,
                sp: user_sp,
                pc: user_elr,
                pstate: user_spsr,
                _pad: 0,
            },
        },
    };
    if copy_to_user::<Uaccess>(frame_addr, as_bytes(&frame)).is_err() {
        return Err(-14); // EFAULT
    }

    // Calculate addresses of info and ucontext within the frame
    let info_addr = frame_addr + core::mem::offset_of!(RtSigFrame, info) as u64;
    let uc_addr = frame_addr + core::mem::offset_of!(RtSigFrame, uc) as u64;

    // Redirect the return to user mode to the handler (Linux
    // setup_return)
    regs.sp = frame_addr;
    regs.elr = handler;
    regs.x[0] = sig as u64; // x0 = signal number
    regs.x[1] = info_addr; // x1 = &siginfo
    regs.x[2] = uc_addr; // x2 = &ucontext
    regs.x[29] = record_addr; // x29 = frame record
    regs.x[30] = restorer; // x30 (LR) = restorer
    // Clear other argument registers for security
    regs.x[3..8].fill(0);

    Ok(())
}

/// View a plain-data value as bytes
fn as_bytes<T>(v: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) }
}

/// Read a plain-data `T` from user memory
fn read_user<T: Copy>(addr: u64) -> Option<T> {
    let mut v = core::mem::MaybeUninit::<T>::uninit();
    let buf = unsafe {
        core::slice::from_raw_parts_mut(v.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    copy_from_user::<Uaccess>(buf, addr, buf.len()).ok()?;
    Some(unsafe { v.assume_init() })
}

/// Walk the `__reserved` records at `addr` (Linux parse_user_sigframe):
/// returns the FP/SIMD record, which must be present; ESR records are
/// skipped; anything else is a bad frame.
fn parse_reserved(addr: u64) -> Option<FpsimdContext> {
    let mut off = 0usize;
    let mut fpsimd = None;
    while off + 8 <= RESERVED_SIZE {
        let head: CtxHead = read_user(addr + off as u64)?;
        let size = head.size as usize;
        match head.magic {
            0 if size == 0 => return fpsimd,
            FPSIMD_MAGIC if size == FPSIMD_SIZE && fpsimd.is_none() => {
                if off + size > RESERVED_SIZE {
                    return None;
                }
                fpsimd = Some(read_user::<FpsimdContext>(addr + off as u64)?);
            }
            ESR_MAGIC if size == 16 => {}
            _ => return None,
        }
        off += size;
    }
    None
}

/// Restore context from signal frame (sys_rt_sigreturn)
///
/// This function:
/// 1. Reads the UContext from user stack
/// 2. Restores blocked signal mask
/// 3. Restores all saved registers and the FP/SIMD record to the task's
///    pt_regs
///
/// Returns the value that should be in x0 (return value),
/// or error code if restore fails.
pub fn sys_rt_sigreturn() -> i64 {
    let tf = crate::task::percpu::current_pt_regs();

    // The current SP points to the signal frame
    let frame_addr = tf.sp;
    if !frame_addr.is_multiple_of(SIGNAL_FRAME_ALIGN) {
        return crate::signal::sigreturn_badframe();
    }
    let Some(end) = frame_addr.checked_add(signal_frame_size() as u64) else {
        return crate::signal::sigreturn_badframe();
    };
    if !Uaccess::access_ok(frame_addr, (end - frame_addr) as usize) {
        return crate::signal::sigreturn_badframe();
    }

    let uc_addr = frame_addr + core::mem::offset_of!(RtSigFrame, uc) as u64;
    let Some(sigmask) =
        read_user::<SigSet>(uc_addr + core::mem::offset_of!(UContext, uc_sigmask) as u64)
    else {
        return crate::signal::sigreturn_badframe();
    };
    let Some(sc) =
        read_user::<SigContext>(uc_addr + core::mem::offset_of!(UContext, uc_mcontext) as u64)
    else {
        return crate::signal::sigreturn_badframe();
    };
    let Some(fpsimd) = parse_reserved(frame_addr + RESERVED_OFFSET as u64) else {
        return crate::signal::sigreturn_badframe();
    };

    // Restore blocked signal mask
    let tid = crate::task::percpu::current_tid();
    crate::signal::with_task_signal_state(tid, |state| {
        state.blocked = sigmask;
        state.recalc_sigpending();
    });

    // Everything goes back into the pt_regs the syscall returns through
    // (Linux restore_sigframe)
    tf.fpsr = fpsimd.fpsr;
    tf.fpcr = fpsimd.fpcr;
    tf.v = fpsimd.vregs;
    tf.elr = sc.pc;
    // Return to EL0t only, with interrupts unmasked
    tf.spsr = sc.pstate & PSTATE_USER_MASK;
    tf.sp = sc.sp;
    tf.x = sc.regs;
    // No syscall to restart from here on (Linux forget_syscall)
    tf.syscallno = super::NO_SYSCALL;

    // Return x0 from saved context
    sc.regs[0] as i64
}
