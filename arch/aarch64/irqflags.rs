//! Interrupt flag primitives (Linux arch/arm64/include/asm/irqflags.h)
//!
//! The saved state is DAIF: [9]=D (Debug), [8]=A (SError), [7]=I (IRQ),
//! [6]=F (FIQ); I set means IRQs are masked.

use crate::arch::IrqFlagsOps;

use super::Aarch64Arch;

/// DAIF.I
const PSR_I_BIT: u64 = 1 << 7;

impl IrqFlagsOps for Aarch64Arch {
    type Flags = u64;

    #[inline]
    fn local_save_flags() -> u64 {
        let daif: u64;
        // SAFETY: reads DAIF; no memory or flags are touched
        unsafe {
            core::arch::asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack, preserves_flags));
        }
        daif
    }

    #[inline]
    fn local_irq_save() -> u64 {
        let daif = Self::local_save_flags();
        // SAFETY: masks IRQs on this CPU; the caller restores the state
        // with `local_irq_restore`
        unsafe {
            core::arch::asm!("msr daifset, #2", options(nostack, preserves_flags));
        }
        daif
    }

    #[inline]
    fn local_irq_restore(daif: u64) {
        // SAFETY: `daif` was read from DAIF by `local_irq_save` on this
        // CPU: writing it back is the state this context ran with
        unsafe {
            core::arch::asm!("msr daif, {}", in(reg) daif, options(nostack, preserves_flags));
        }
    }

    #[inline]
    fn irqs_disabled_flags(daif: u64) -> bool {
        daif & PSR_I_BIT != 0
    }
}
