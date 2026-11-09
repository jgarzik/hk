//! Interrupt flag primitives (Linux arch/x86/include/asm/irqflags.h)
//!
//! The saved state is RFLAGS; IF (bit 9) set means interrupts were on.

use crate::arch::IrqFlagsOps;

use super::X86_64Arch;

/// RFLAGS.IF
const X86_EFLAGS_IF: u64 = 1 << 9;

impl IrqFlagsOps for X86_64Arch {
    type Flags = u64;

    #[inline]
    fn local_save_flags() -> u64 {
        let flags: u64;
        // SAFETY: reads RFLAGS through the stack; no memory is touched
        // besides the push/pop pair and no flag changes
        unsafe {
            core::arch::asm!("pushfq", "pop {0}", out(reg) flags, options(nomem, preserves_flags));
        }
        flags
    }

    #[inline]
    fn local_irq_save() -> u64 {
        let flags: u64;
        // SAFETY: reads RFLAGS and masks interrupts on this CPU; the
        // caller restores the state with `local_irq_restore`
        unsafe {
            core::arch::asm!("pushfq", "pop {0}", "cli", out(reg) flags);
        }
        flags
    }

    /// Linux arch_local_irq_restore: interrupts back on only if they were
    #[inline]
    fn local_irq_restore(flags: u64) {
        if !Self::irqs_disabled_flags(flags) {
            // SAFETY: interrupts were on when `flags` was saved, so this
            // context runs with them on
            unsafe {
                core::arch::asm!("sti", options(nostack));
            }
        }
    }

    #[inline]
    fn irqs_disabled_flags(flags: u64) -> bool {
        flags & X86_EFLAGS_IF == 0
    }
}
