//! The system's lifecycle state (Linux enum system_states,
//! include/linux/kernel.h)
//!
//! `Booting` until the scheduler can run tasks (interrupts on, the kernel
//! threads started: Linux rest_init's SYSTEM_SCHEDULING), `Running` just
//! before init is executed (Linux kernel_init), then the shutdown state
//! reboot(2) is heading for (Linux kernel_shutdown_prepare). The
//! sleep and allocation checks (`might_sleep`, lockdep's might_alloc)
//! are quiet while booting and once shutting down, as Linux's
//! __might_resched is: boot runs single-threaded with interrupts off,
//! and shutdown stops CPUs under locks.

use core::sync::atomic::{AtomicU8, Ordering};

/// Linux enum system_states (the states hk passes through)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum SystemState {
    Booting = 0,
    Scheduling = 1,
    Running = 2,
    Halt = 3,
    PowerOff = 4,
    Restart = 5,
}

static STATE: AtomicU8 = AtomicU8::new(SystemState::Booting as u8);

/// The current state
pub fn system_state() -> SystemState {
    match STATE.load(Ordering::Acquire) {
        0 => SystemState::Booting,
        1 => SystemState::Scheduling,
        2 => SystemState::Running,
        3 => SystemState::Halt,
        4 => SystemState::PowerOff,
        _ => SystemState::Restart,
    }
}

/// Enter `s` (boot and reboot(2) only, each state once, in order)
pub fn set_system_state(s: SystemState) {
    STATE.store(s as u8, Ordering::Release);
}

/// The sleep and allocation checks apply (Linux __might_resched's
/// system_state test: not while booting or shutting down)
pub fn checks_apply() -> bool {
    matches!(
        system_state(),
        SystemState::Scheduling | SystemState::Running
    )
}
