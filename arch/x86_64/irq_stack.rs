//! This CPU's IRQ stack (Linux arch/x86/include/asm/irq_stack.h,
//! kernel/irq_64.c): the switch onto it

use super::X86_64Arch;
use crate::arch::IrqStackOps;

impl IrqStackOps for X86_64Arch {
    #[inline]
    fn stack_pointer() -> u64 {
        let sp: u64;
        // SAFETY: a register read
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        sp
    }

    unsafe fn call_on_stack(top: u64, f: extern "C" fn(*mut ()), arg: *mut ()) {
        // SAFETY: the caller's guarantee
        unsafe { call_on_stack(top, f, arg) }
    }
}

/// Call `f(arg)` on the stack whose top is `top` (Linux call_on_stack):
/// a frame on the old stack, the old RSP in the new stack's top word
/// (the backtrace's way back, Linux's "next_sp"), `f` called with RSP
/// 16-byte aligned below it; `f`'s frame links to ours, so a
/// frame-pointer walk crosses back over
///
/// # Safety
/// As [`IrqStackOps::call_on_stack`].
#[unsafe(naked)]
unsafe extern "C" fn call_on_stack(top: u64, f: extern "C" fn(*mut ()), arg: *mut ()) {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "mov [rdi - 8], rsp",
        "lea rsp, [rdi - 16]",
        "mov rax, rsi",
        "mov rdi, rdx",
        "call rax",
        "leave",
        "ret",
    );
}
