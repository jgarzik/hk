//! Kernel threads (subset of Linux kernel/kthread.c)
//!
//! ```ignore
//! fn worker(arg: usize) {
//!     while !kthread_should_stop() {
//!         WQ.wait_event(|| work_ready() || kthread_should_stop());
//!         if kthread_should_park() { kthread_parkme(); }
//!         // ...
//!     }
//! }
//! let k = kthread_run("worker", worker, 0, Some(1))?;   // bound to CPU 1
//! kthread_stop(&k);                                     // waits for exit
//! ```
//!
//! Kernel threads run in kernel mode only, with pid 0 (user pids are
//! unaffected), the kernel page table and no user resources. A thread is
//! bound to one CPU for its life (hk tasks never migrate).
//!
//! ## Locking
//!
//! `KTHREADS` (spin::Mutex, process context only) maps tid -> control
//! block; it is never held across a wakeup or sleep. Stop/park requests are
//! atomics plus a direct `wake_up_task`; requesters wait on the control
//! block's `WaitQueue` for the thread to acknowledge.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use crate::error::KernelError;
use crate::task::percpu::{
    SleepState, WakeMode, cpu_has_scheduler, create_kthread_task, current_tid, schedule,
    set_current_state, wake_up_task,
};
use crate::task::{PRIORITY_NORMAL, Priority, Tid};
use crate::waitqueue::WaitQueue;

/// Kernel thread control block (Linux struct kthread)
pub struct KThread {
    /// Thread name (also the task comm)
    pub name: &'static str,
    /// Task id (set before the thread first runs)
    tid: AtomicU32,
    /// CPU the thread is bound to
    pub cpu: u32,
    func: fn(usize),
    arg: usize,
    should_stop: AtomicBool,
    should_park: AtomicBool,
    parked: AtomicBool,
    exited: AtomicBool,
    /// Stop/park requesters wait here for `parked` / `exited`
    ack: WaitQueue,
}

impl KThread {
    /// Task id of the thread
    pub fn tid(&self) -> Tid {
        self.tid.load(Ordering::Acquire) as Tid
    }

    fn wake(&self) {
        wake_up_task(self.tid(), self.cpu, WakeMode::Any);
    }
}

/// Registry of live kernel threads (process context only)
static KTHREADS: Mutex<Vec<Arc<KThread>>> = Mutex::new(Vec::new());

/// Round-robin cursor for unbound threads
static NEXT_CPU: AtomicU32 = AtomicU32::new(0);

/// Control block of the current task, if it is a kthread
pub fn current_kthread() -> Option<Arc<KThread>> {
    let tid = current_tid();
    KTHREADS.lock().iter().find(|k| k.tid() == tid).cloned()
}

/// Create and start a kernel thread running `func(arg)`
///
/// `cpu`: bind to that CPU, or `None` to pick one round-robin among CPUs
/// that run a scheduler. Returns the control block for stop/park.
pub fn kthread_run(
    name: &'static str,
    func: fn(usize),
    arg: usize,
    cpu: Option<u32>,
) -> Result<Arc<KThread>, KernelError> {
    kthread_run_prio(name, func, arg, cpu, PRIORITY_NORMAL)
}

/// [`kthread_run`] with an explicit scheduling priority
pub fn kthread_run_prio(
    name: &'static str,
    func: fn(usize),
    arg: usize,
    cpu: Option<u32>,
    priority: Priority,
) -> Result<Arc<KThread>, KernelError> {
    let cpu = match cpu {
        Some(c) if cpu_has_scheduler(c) => c,
        Some(_) => return Err(KernelError::InvalidArgument),
        None => pick_cpu(),
    };
    let k = Arc::new(KThread {
        name,
        tid: AtomicU32::new(0),
        cpu,
        func,
        arg,
        should_stop: AtomicBool::new(false),
        should_park: AtomicBool::new(false),
        parked: AtomicBool::new(false),
        exited: AtomicBool::new(false),
        ack: WaitQueue::new(),
    });
    // The task is created asleep: register it before it can look itself up
    let tid = create_kthread_task(cpu, name, kthread_entry as *const () as usize, priority)
        .map_err(|_| KernelError::OutOfMemory)?;
    k.tid.store(tid as u32, Ordering::Release);
    KTHREADS.lock().push(k.clone());
    k.wake();
    Ok(k)
}

/// CPU for an unbound thread: round-robin over the APs (CPU 0 runs all
/// user tasks, and scheduling is cooperative), CPU 0 if there are none
fn pick_cpu() -> u32 {
    let ncpu = crate::task::percpu::MAX_SCHED_CPUS as u32;
    for _ in 0..ncpu {
        let c = NEXT_CPU.load(Ordering::Relaxed) % ncpu;
        NEXT_CPU.store(c + 1, Ordering::Relaxed);
        if c != 0 && cpu_has_scheduler(c) {
            return c;
        }
    }
    0
}

/// First code run by every kernel thread
extern "C" fn kthread_entry() -> ! {
    use crate::arch::{CpuOps, CurrentArch};
    // The switch that started us left interrupts disabled
    CurrentArch::enable_interrupts();

    if let Some(k) = current_kthread() {
        (k.func)(k.arg);
        k.exited.store(true, Ordering::Release);
        k.ack.wake_all();
        let tid = k.tid();
        KTHREADS.lock().retain(|t| t.tid() != tid);
    }
    kthread_exit()
}

/// Terminate the current kernel thread (nobody reaps kernel threads, so the
/// task leaves the task table at once; its stack is freed once the CPU
/// has switched away)
fn kthread_exit() -> ! {
    let tid = current_tid();
    crate::task::percpu::TASK_TABLE
        .lock()
        .tasks
        .retain(|t| t.tid != tid);
    crate::task::percpu::exit_current(None)
}

/// True once `kthread_stop` was called on the current thread
pub fn kthread_should_stop() -> bool {
    current_kthread().is_some_and(|k| k.should_stop.load(Ordering::Acquire))
}

/// True while a park is requested for the current thread
pub fn kthread_should_park() -> bool {
    current_kthread().is_some_and(|k| k.should_park.load(Ordering::Acquire))
}

/// Park the current thread until `kthread_unpark` (or `kthread_stop`)
pub fn kthread_parkme() {
    let Some(k) = current_kthread() else { return };
    loop {
        set_current_state(SleepState::Uninterruptible);
        if !k.should_park.load(Ordering::Acquire) || k.should_stop.load(Ordering::Acquire) {
            break;
        }
        if !k.parked.swap(true, Ordering::AcqRel) {
            k.ack.wake_all();
        }
        schedule();
    }
    set_current_state(SleepState::Running);
    k.parked.store(false, Ordering::Release);
}

/// Ask `k` to park and wait until it has (it must call `kthread_parkme`)
pub fn kthread_park(k: &KThread) {
    k.should_park.store(true, Ordering::Release);
    k.wake();
    k.ack
        .wait_event(|| k.parked.load(Ordering::Acquire) || k.exited.load(Ordering::Acquire));
}

/// Let a parked thread continue
pub fn kthread_unpark(k: &KThread) {
    k.should_park.store(false, Ordering::Release);
    k.wake();
}

/// Ask `k` to stop and wait for its function to return
pub fn kthread_stop(k: &KThread) {
    k.should_stop.store(true, Ordering::Release);
    k.should_park.store(false, Ordering::Release);
    k.wake();
    k.ack.wait_event(|| k.exited.load(Ordering::Acquire));
}
