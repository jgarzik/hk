//! This CPU's IRQ stack (Linux arch/arm64/kernel/irq.c, entry.S
//! call_on_irq_stack): the switch onto it

use super::Aarch64Arch;
use crate::arch::IrqStackOps;

impl IrqStackOps for Aarch64Arch {
    #[inline]
    fn stack_pointer() -> u64 {
        let sp: u64;
        // SAFETY: a register read
        unsafe {
            core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        sp
    }

    unsafe fn call_on_stack(top: u64, f: extern "C" fn(*mut ()), arg: *mut ()) {
        // SAFETY: the caller's guarantee
        unsafe { call_on_stack(top, f, arg) }
    }
}

/// Call `f(arg)` on the stack whose top is `top` (Linux
/// call_on_irq_stack): a frame record on the old stack holds LR and,
/// through FP, the old SP; `f`'s record links to it, so a frame walk
/// crosses back over
///
/// # Safety
/// As [`IrqStackOps::call_on_stack`].
#[unsafe(naked)]
unsafe extern "C" fn call_on_stack(top: u64, f: extern "C" fn(*mut ()), arg: *mut ()) {
    core::arch::naked_asm!(
        "stp x29, x30, [sp, #-16]!",
        "mov x29, sp",
        "mov sp, x0",
        "mov x0, x2",
        "blr x1",
        "mov sp, x29",
        "ldp x29, x30, [sp], #16",
        "ret",
    );
}
