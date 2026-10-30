//! membarrier system call implementation
//!
//! The membarrier() system call helps distribute memory barriers across
//! multiple CPUs for userspace-RCU (read-copy-update) algorithms. It provides
//! ordering guarantees across multiple threads without requiring expensive
//! explicit memory barriers in critical fast paths.
//!
//! Linux reference: kernel/sched/membarrier.c

use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};

use crate::cpumask::CpuSet;
use crate::mm::Mm;
use crate::sync::Mutex;
use crate::task::percpu::PerCpuScheduler;

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

/// Serializes the commands that interrupt other CPUs (Linux
/// membarrier_ipi_mutex): concurrent callers cannot multiply the IPIs
static IPI_MUTEX: Mutex<()> = Mutex::new(());

/// membarrier(cmd, flags, cpu_id) (Linux kernel/sched/membarrier.c)
///
/// The expedited commands make the CPUs that matter run a full barrier
/// (an IPI, waited for), as in Linux: PRIVATE the CPUs running the
/// caller's address space, GLOBAL_EXPEDITED those running a registered
/// one. MEMBARRIER_CMD_GLOBAL is Linux's synchronize_rcu; hk has no
/// RCU, so it interrupts every CPU running a user address space and
/// then sleeps a tick under the mutex, which keeps it as slow as a
/// grace period and bounds the IPIs any caller can cause.
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
        MEMBARRIER_CMD_GLOBAL => global(),
        MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
            let _g = IPI_MUTEX.lock();
            barrier_cpus(ipi_mb, |s| {
                s.membarrier_state.load(Ordering::Relaxed) & STATE_GLOBAL_EXPEDITED != 0
            });
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

/// Refresh this CPU's cached registrations if it runs address space
/// `mm` (Linux ipi_sync_rq_state)
fn ipi_sync_state(mm: usize) {
    if let Some(s) = crate::task::percpu::current_percpu_sched()
        && s.curr_mm.load(Ordering::Relaxed) == mm
    {
        // SAFETY: the registering caller runs in `mm` and waits for us
        let st = unsafe { &*(mm as *const Mm) }
            .membarrier_state()
            .load(Ordering::Relaxed);
        s.membarrier_state.store(st, Ordering::Relaxed);
    }
}

/// Run `f` on the other active CPUs whose scheduler `pick` selects and
/// wait for all, between full barriers on this one (Linux guard(mb)
/// around smp_call_function_many)
fn barrier_cpus(f: fn(usize), pick: impl Fn(&PerCpuScheduler) -> bool) {
    fence(Ordering::SeqCst);
    let mut mask = CpuSet::default();
    for cpu in crate::smp::active_cpus().iter() {
        if crate::task::percpu::cpu_sched(cpu).is_some_and(&pick) {
            mask.set(cpu);
        }
    }
    crate::smp::smp_call_function_many(&mask, f, 0, true);
    fence(Ordering::SeqCst);
}

/// MEMBARRIER_CMD_GLOBAL (see `sys_membarrier`)
fn global() -> i64 {
    let _g = IPI_MUTEX.lock();
    barrier_cpus(ipi_mb, |s| s.curr_mm.load(Ordering::Relaxed) != 0);
    crate::task::percpu::sleep_current_until(crate::task::percpu::get_ticks() + 1);
    0
}

/// Linux membarrier_private_expedited (no FLAG_CPU: only RSEQ takes it)
fn private_expedited(flags: u32) -> i64 {
    let Some(mm) = crate::task::percpu::current().mm() else {
        return EINVAL;
    };
    let ready = if flags == FLAG_SYNC_CORE {
        STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY
    } else {
        STATE_PRIVATE_EXPEDITED_READY
    };
    if mm.membarrier_state().load(Ordering::Acquire) & ready == 0 {
        return EPERM;
    }
    // No other thread can run in it (Linux: mm_users == 1)
    if flags != FLAG_SYNC_CORE && mm.users() == 1 {
        return 0;
    }
    let me = Arc::as_ptr(&mm) as usize;
    let _g = IPI_MUTEX.lock();
    if flags == FLAG_SYNC_CORE {
        // This CPU too (Linux on_each_cpu_mask): the caller may move and
        // another thread of the address space take its place here
        barrier_cpus(ipi_sync_core, |s| s.curr_mm.load(Ordering::Relaxed) == me);
        ipi_sync_core(0);
    } else {
        barrier_cpus(ipi_mb, |s| s.curr_mm.load(Ordering::Relaxed) == me);
    }
    0
}

/// Linux membarrier_register_{private,global}_expedited: set the state
/// bits, update the cached copy of every CPU running the address space
/// (Linux sync_runqueues_membarrier_state), then mark it ready
fn register(set: u32, ready: u32) -> i64 {
    let Some(mm) = crate::task::percpu::current().mm() else {
        return EINVAL;
    };
    let st = mm.membarrier_state();
    if st.load(Ordering::Acquire) & ready == ready {
        return 0;
    }
    st.fetch_or(set, Ordering::AcqRel);
    let me = Arc::as_ptr(&mm) as usize;
    {
        let _g = IPI_MUTEX.lock();
        ipi_sync_state(me);
        fence(Ordering::SeqCst);
        let mut mask = CpuSet::default();
        for cpu in crate::smp::active_cpus().iter() {
            if crate::task::percpu::cpu_sched(cpu)
                .is_some_and(|s| s.curr_mm.load(Ordering::Relaxed) == me)
            {
                mask.set(cpu);
            }
        }
        crate::smp::smp_call_function_many(&mask, ipi_sync_state, me, true);
    }
    st.fetch_or(ready, Ordering::AcqRel);
    0
}

/// Linux membarrier_get_registrations
fn registrations() -> i64 {
    let st = crate::task::percpu::current()
        .mm()
        .map_or(0, |mm| mm.membarrier_state().load(Ordering::Acquire));
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
