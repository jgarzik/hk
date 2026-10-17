//! x86-64 IPIs for `smp` (Linux arch/x86/kernel/smp.c)

use super::interrupts::{CALL_FUNCTION_VECTOR, RESCHEDULE_VECTOR};

/// APIC id of logical CPU `cpu`
fn apic_id(cpu: u32) -> u32 {
    super::percpu::get_percpu(cpu).apic_id
}

/// Raise the call-function IPI on `cpu` (`smp::call_function_interrupt`)
pub fn send_call_function(cpu: u32) {
    super::lapic::send_ipi(apic_id(cpu), CALL_FUNCTION_VECTOR);
}

/// Raise the reschedule IPI on `cpu` (`smp::reschedule_interrupt`)
pub fn send_reschedule(cpu: u32) {
    super::lapic::send_ipi(apic_id(cpu), RESCHEDULE_VECTOR);
}
