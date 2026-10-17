//! AArch64 IPIs for `smp`: GICv3 SGIs (Linux arch/arm64/kernel/smp.c)

/// SGI numbers (Linux enum ipi_msg_type)
pub const SGI_RESCHEDULE: u32 = 0;
pub const SGI_CALL_FUNCTION: u32 = 1;

/// MPIDR of logical CPU `cpu`
fn mpidr(cpu: u32) -> u64 {
    super::percpu::get_percpu(cpu).mpidr
}

/// Raise the call-function SGI on `cpu` (`smp::call_function_interrupt`)
pub fn send_call_function(cpu: u32) {
    super::gic::send_sgi(mpidr(cpu), SGI_CALL_FUNCTION);
}

/// Raise the reschedule SGI on `cpu` (`smp::reschedule_interrupt`)
pub fn send_reschedule(cpu: u32) {
    super::gic::send_sgi(mpidr(cpu), SGI_RESCHEDULE);
}

/// SGI `intid` taken (IRQ entry, interrupts off): run its handler as an
/// interrupt (lockdep's interrupt context counts it)
pub fn handle_sgi(intid: u32) {
    let f: fn() = match intid {
        SGI_RESCHEDULE => crate::smp::reschedule_interrupt,
        SGI_CALL_FUNCTION => crate::smp::call_function_interrupt,
        _ => return,
    };
    crate::sync::lockdep::irq_enter();
    f();
    crate::sync::lockdep::irq_exit();
}
