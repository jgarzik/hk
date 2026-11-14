//! Per-CPU IRQ stacks (Linux x86 hardirq_stack_ptr, kernel/irq_64.c;
//! arm64 irq_stack_ptr, kernel/irq.c)
//!
//! Interrupt handlers (device IRQs, the timer, IPIs) run on a stack of
//! their CPU's own, not on the interrupted task's, so the deepest
//! syscall and the deepest handler do not share one 16 KiB stack. Each
//! CPU's is a `mm::vmstack` stack (`THREAD_SIZE`, Linux IRQ_STACK_SIZE),
//! kept in [`IRQ_STACK`] (Linux hardirq_stack_ptr / irq_stack_ptr), given
//! by the arch `smp::init` ([`set`]) before the CPU takes interrupts: a guard
//! gap lies below it, arm64's entry overflow check holds on it, and an
//! overflow into the gap says it was the IRQ stack ([`overflowed`]).
//!
//! [`run_softirq`] runs a task's inline network receive work there too
//! (Linux do_softirq_own_stack). The arch entry code calls [`run`] around
//! the handlers only, not the return-to-user work (which may schedule): x86 for an interrupt from
//! kernel mode (Linux run_irq_on_irqstack_cond: from user mode the task
//! stack is empty), arm64 for any (Linux do_interrupt_handler).
//! Exceptions stay on the task stack, as in Linux. Handlers run with
//! interrupts off, so only an exception lands on the IRQ stack while it
//! is in use (x86 NMI, #DF and #MC have IST stacks); whatever runs there
//! stays there: `run` switches only when SP is not on it already (Linux
//! hardirq_stack_inuse, on_thread_stack).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{CurrentArch, IrqStackOps};
use crate::cpu::PerCpu;
use crate::mm::vmstack::{self, THREAD_SIZE, VmStack};

/// Each CPU's IRQ stack top, 0 until [`set`]: written once, for a CPU
/// not running yet (its start orders the store before its reads) or by
/// the CPU itself
static IRQ_STACK: PerCpu<AtomicU64> = crate::percpu![AtomicU64::new(0)];

/// Give CPU `cpu` (not running yet, or the caller) the IRQ stack `s`,
/// for good (Linux irq_init_percpu_irqstack, init_irq_stacks)
pub fn set(cpu: u32, s: VmStack) {
    let top = s.leak() + THREAD_SIZE as u64;
    IRQ_STACK.get(cpu).store(top, Ordering::Relaxed);
}

/// Give CPU `cpu` a new IRQ stack; false if out of memory
pub fn init(cpu: u32) -> bool {
    vmstack::alloc().map(|s| set(cpu, s)).is_some()
}

/// Top of this CPU's IRQ stack, 0 before it has one (or before per-CPU
/// data exists)
#[inline]
pub fn top() -> u64 {
    crate::cpu::try_this_id().map_or(0, |c| IRQ_STACK.get(c).load(Ordering::Relaxed))
}

/// `sp` is on the stack whose top is `top` (0: none)
fn within(top: u64, sp: u64) -> bool {
    top != 0 && (top - THREAD_SIZE as u64..top).contains(&sp)
}

/// SP is on this CPU's IRQ stack
pub fn on_irq_stack() -> bool {
    within(top(), CurrentArch::stack_pointer())
}

/// Run `f`, an interrupt's handlers (interrupts off), on this CPU's IRQ
/// stack: directly if SP is on it already, or before it has one
pub fn run<F: FnOnce()>(f: F) {
    let top = top();
    if top == 0 || within(top, CurrentArch::stack_pointer()) {
        return f();
    }
    debug_assert!(crate::sync::irqs_disabled());
    let mut f = Some(f);
    // SAFETY: this CPU's IRQ stack, mapped for good (a leaked vmstack
    // stack, 16-byte aligned top) and unused: SP is not on it, and with
    // interrupts off nothing else on this CPU switches to it before the
    // call returns. `f` outlives the call.
    unsafe { CurrentArch::call_on_stack(top, call_once::<F>, (&raw mut f).cast()) };
}

/// Run `f`, deferred network work a task does inline (Linux pending
/// softirqs run at local_bh_enable), on this CPU's IRQ stack as Linux
/// do_softirq_own_stack: interrupts are masked for the switch and
/// restored on the IRQ stack (Linux __do_softirq's local_irq_enable),
/// so an interrupt meanwhile nests there; preemption stays off, so
/// nothing else on this CPU uses the stack, and `f` must not sleep.
/// Directly if SP is on it already.
pub fn run_softirq<F: FnOnce()>(f: F) {
    let mut saved = Some(crate::sync::local_irq_save());
    crate::arch::preempt_disable();
    run(|| {
        if let Some(s) = saved.take() {
            crate::sync::local_irq_restore(s);
        }
        f();
        saved = Some(crate::sync::local_irq_save());
    });
    crate::arch::preempt_enable();
    if let Some(s) = saved.take() {
        crate::sync::local_irq_restore(s);
    }
}

/// `run`'s `f`, on the IRQ stack
extern "C" fn call_once<F: FnOnce()>(arg: *mut ()) {
    // SAFETY: `run` passes its `Option<F>`, live and not otherwise
    // borrowed until the call returns
    let f = unsafe { &mut *arg.cast::<Option<F>>() };
    if let Some(f) = f.take() {
        f();
    }
}

/// Which stack a fault at `addr` in a guard gap overflowed, for the
/// panic message
pub fn overflowed(addr: u64) -> &'static str {
    let top = top();
    if top != 0 && vmstack::overflowed(addr) == Some(top - THREAD_SIZE as u64) {
        "IRQ stack"
    } else {
        "kernel stack"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_bounds() {
        let top = 0x1_0000_4000;
        assert!(!within(0, 8));
        assert!(within(top, top - 8));
        assert!(within(top, top - THREAD_SIZE as u64));
        assert!(!within(top, top));
        assert!(!within(top, top - THREAD_SIZE as u64 - 8));
    }
}
