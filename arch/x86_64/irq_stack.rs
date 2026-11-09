//! This CPU's IRQ stack (Linux arch/x86/include/asm/irq_stack.h,
//! kernel/irq_64.c): `PerCpu.irq_stack`, and the switch onto it

use core::sync::atomic::Ordering;

use super::X86_64Arch;
use super::percpu::{get_percpu, try_current_cpu};
use crate::arch::IrqStackOps;

/// Give CPU `cpu` (not running yet, or the caller) its IRQ stack
/// (Linux irq_init_percpu_irqstack); false if out of memory
pub fn init(cpu: u32) -> bool {
    let Some(top) = crate::mm::vmstack::alloc_percpu() else {
        return false;
    };
    get_percpu(cpu).irq_stack.store(top, Ordering::Relaxed);
    true
}

impl IrqStackOps for X86_64Arch {
    #[inline]
    fn irq_stack_top() -> u64 {
        try_current_cpu().map_or(0, |p| p.irq_stack.load(Ordering::Relaxed))
    }

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
