//! membarrier system call implementation
//!
//! The membarrier() system call helps distribute memory barriers across
//! multiple CPUs for userspace-RCU (read-copy-update) algorithms. It provides
//! ordering guarantees across multiple threads without requiring expensive
//! explicit memory barriers in critical fast paths.
//!
//! Linux reference: kernel/sched/membarrier.c

use core::sync::atomic::{Ordering, fence};

// =============================================================================
// membarrier commands (Linux ABI)
// =============================================================================

/// Query supported commands
pub const MEMBARRIER_CMD_QUERY: i32 = 0;
/// Execute a memory barrier on all running threads
pub const MEMBARRIER_CMD_GLOBAL: i32 = 1 << 0;
/// Execute memory barrier on registered threads (expedited)
pub const MEMBARRIER_CMD_GLOBAL_EXPEDITED: i32 = 1 << 1;
/// Register for expedited global barriers
pub const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: i32 = 1 << 2;
/// Execute memory barrier on caller's process threads (expedited)
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED: i32 = 1 << 3;
/// Register for expedited private barriers
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;
/// Execute memory barrier with core serialization
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 5;
/// Register for expedited sync core barriers
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 6;
/// Execute memory barrier for rseq critical sections
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 7;
/// Register for expedited rseq barriers
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 8;
/// Query current registrations
pub const MEMBARRIER_CMD_GET_REGISTRATIONS: i32 = 1 << 9;

/// Flag to target specific CPU
pub const MEMBARRIER_CMD_FLAG_CPU: u32 = 1 << 0;

/// Internal flags (Linux MEMBARRIER_FLAG_*)
const FLAG_SYNC_CORE: u32 = 1 << 0;

// Address-space registration state (Linux MEMBARRIER_STATE_*,
// `Mm::membarrier_state`)
const STATE_PRIVATE_EXPEDITED_READY: u32 = 1 << 0;
const STATE_PRIVATE_EXPEDITED: u32 = 1 << 1;
const STATE_GLOBAL_EXPEDITED_READY: u32 = 1 << 2;
const STATE_GLOBAL_EXPEDITED: u32 = 1 << 3;
const STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY: u32 = 1 << 4;
const STATE_PRIVATE_EXPEDITED_SYNC_CORE: u32 = 1 << 5;

/// Commands answered (Linux MEMBARRIER_CMD_BITMASK without the RSEQ
/// pair: hk has no rseq, as Linux without CONFIG_RSEQ)
const SUPPORTED_CMDS: i32 = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_GET_REGISTRATIONS;

const EINVAL: i64 = -22;
const EPERM: i64 = -1;

/// membarrier(cmd, flags, cpu_id) (Linux kernel/sched/membarrier.c)
///
/// The expedited commands make every other CPU run a full barrier (an
/// IPI, waited for) before returning. Linux interrupts only the CPUs
/// running a thread of the target address space (or of a registered
/// one); hk interrupts every active CPU, which orders a superset.
/// MEMBARRIER_CMD_GLOBAL is Linux's synchronize_rcu: hk has no RCU, and
/// the same barrier on every CPU orders every running thread.
pub fn sys_membarrier(cmd: i32, flags: u32, _cpu_id: i32) -> i64 {
    let flags_ok = match cmd {
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ => flags == 0 || flags == MEMBARRIER_CMD_FLAG_CPU,
        _ => flags == 0,
    };
    if !flags_ok {
        return EINVAL;
    }
    match cmd {
        MEMBARRIER_CMD_QUERY => SUPPORTED_CMDS as i64,
        MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
            barrier_others(ipi_mb);
            0
        }
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED => {
            register(STATE_GLOBAL_EXPEDITED, STATE_GLOBAL_EXPEDITED_READY)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED => private_expedited(0),
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            register(STATE_PRIVATE_EXPEDITED, STATE_PRIVATE_EXPEDITED_READY)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => private_expedited(FLAG_SYNC_CORE),
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => register(
            STATE_PRIVATE_EXPEDITED | STATE_PRIVATE_EXPEDITED_SYNC_CORE,
            STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY,
        ),
        MEMBARRIER_CMD_GET_REGISTRATIONS => registrations(),
        _ => EINVAL,
    }
}

/// Full barrier, run on each interrupted CPU (Linux ipi_mb)
fn ipi_mb(_: usize) {
    fence(Ordering::SeqCst);
}

/// Full barrier plus instruction-stream serialization (Linux
/// ipi_sync_core)
fn ipi_sync_core(_: usize) {
    fence(Ordering::SeqCst);
    crate::arch::barrier::sync_core();
}

/// Run `f` on every other active CPU and wait for all, between full
/// barriers on this one (Linux guard(mb) around smp_call_function_many)
fn barrier_others(f: fn(usize)) {
    fence(Ordering::SeqCst);
    crate::smp::smp_call_function_many(&crate::smp::active_cpus(), f, 0, true);
    fence(Ordering::SeqCst);
}

/// The calling task's address-space registration state; None for a
/// task without one (kernel threads never call this)
fn state() -> Option<u32> {
    let mm = crate::task::percpu::current().mm()?;
    Some(mm.membarrier_state().load(Ordering::Acquire))
}

/// Linux membarrier_private_expedited (no FLAG_CPU: only RSEQ takes it)
fn private_expedited(flags: u32) -> i64 {
    let ready = if flags == FLAG_SYNC_CORE {
        STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY
    } else {
        STATE_PRIVATE_EXPEDITED_READY
    };
    if state().unwrap_or(0) & ready == 0 {
        return EPERM;
    }
    if flags == FLAG_SYNC_CORE {
        // This CPU too (Linux on_each_cpu_mask): the caller may move and
        // another thread of the address space take its place here
        barrier_others(ipi_sync_core);
        ipi_sync_core(0);
    } else {
        barrier_others(ipi_mb);
    }
    0
}

/// Linux membarrier_register_{private,global}_expedited: set `set`,
/// then `ready` once every CPU would see it (hk interrupts every CPU on
/// each command, so there is nothing to synchronize first)
fn register(set: u32, ready: u32) -> i64 {
    let Some(mm) = crate::task::percpu::current().mm() else {
        return EINVAL;
    };
    mm.membarrier_state()
        .fetch_or(set | ready, Ordering::AcqRel);
    0
}

/// Linux membarrier_get_registrations
fn registrations() -> i64 {
    let st = state().unwrap_or(0);
    let mut mask = 0;
    for (bits, cmd) in [
        (
            STATE_GLOBAL_EXPEDITED | STATE_GLOBAL_EXPEDITED_READY,
            MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
        ),
        (
            STATE_PRIVATE_EXPEDITED | STATE_PRIVATE_EXPEDITED_READY,
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
        ),
        (
            STATE_PRIVATE_EXPEDITED_SYNC_CORE | STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY,
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
        ),
    ] {
        if st & bits != 0 {
            mask |= cmd;
        }
    }
    mask as i64
}
