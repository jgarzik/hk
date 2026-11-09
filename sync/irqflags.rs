//! This CPU's interrupt state (Linux include/linux/irqflags.h) over the
//! arch primitives (`arch::IrqFlagsOps`)

use crate::arch::IrqFlagsOps;

#[cfg(not(test))]
type Arch = crate::arch::CurrentArch;

/// Host unit tests run in userspace, where IRQ masking is privileged:
/// saving and restoring do nothing and interrupts read as on
#[cfg(test)]
type Arch = Host;

#[cfg(test)]
pub(super) struct Host;

#[cfg(test)]
impl IrqFlagsOps for Host {
    type Flags = ();
    fn local_save_flags() {}
    fn local_irq_save() {}
    fn local_irq_restore(_: ()) {}
    fn irqs_disabled_flags(_: ()) -> bool {
        false
    }
}

/// The arch's saved state, for the lock guards that carry it
pub(super) type Raw = <Arch as IrqFlagsOps>::Flags;

/// Mask interrupts, returning the previous state
#[inline]
pub(super) fn save() -> Raw {
    Arch::local_irq_save()
}

/// Restore a state from [`save`]
#[inline]
pub(super) fn restore(f: Raw) {
    Arch::local_irq_restore(f)
}

/// `f` has interrupts on
#[inline]
pub(super) fn enabled(f: Raw) -> bool {
    !Arch::irqs_disabled_flags(f)
}

/// Interrupts are masked on this CPU (Linux irqs_disabled; lockdep's
/// might_sleep check)
#[inline]
pub fn irqs_disabled() -> bool {
    Arch::irqs_disabled_flags(Arch::local_save_flags())
}

/// Saved interrupt state of this CPU (Linux local_irq_save flags)
#[must_use]
pub struct IrqFlags(Raw);

/// Disable interrupts on this CPU, returning the previous state (Linux
/// local_irq_save)
#[inline]
pub fn local_irq_save() -> IrqFlags {
    IrqFlags(save())
}

/// Restore the state saved by [`local_irq_save`]
#[inline]
pub fn local_irq_restore(f: IrqFlags) {
    restore(f.0)
}
