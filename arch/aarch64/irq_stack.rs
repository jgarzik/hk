//! This CPU's IRQ stack (Linux arch/arm64/kernel/irq.c, entry.S
//! call_on_irq_stack): `PerCpu.irq_stack`, and the switch onto it

use core::sync::atomic::Ordering;

use super::Aarch64Arch;
use super::percpu::{get_percpu, try_current_cpu};
use crate::arch::IrqStackOps;

/// Give CPU `cpu` (not running yet, or the caller) its IRQ stack
/// (Linux init_irq_stacks); false if out of memory
pub fn init(cpu: u32) -> bool {
    let Some(top) = crate::mm::vmstack::alloc_percpu() else {
        return false;
    };
    get_percpu(cpu).irq_stack.store(top, Ordering::Relaxed);
    true
}

impl IrqStackOps for Aarch64Arch {
    #[inline]
    fn irq_stack_top() -> u64 {
        try_current_cpu().map_or(0, |p| p.irq_stack.load(Ordering::Relaxed))
    }

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
