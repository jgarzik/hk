//! POSIX CPU-time timers (Linux kernel/time/posix-cpu-timers.c, with
//! CONFIG_POSIX_CPU_TIMERS_TASK_WORK)
//!
//! Timers on a thread or process CPU clock, ITIMER_VIRTUAL/ITIMER_PROF,
//! RLIMIT_CPU and clock_nanosleep on a process CPU clock all run here:
//!
//! - The tick (interrupt context, no locks) compares the running task's
//!   CPU time and, while its thread group has process timers, the
//!   group's running totals with cached expiry times; past one it sets
//!   TIF_NOTIFY_RESUME (`tick`).
//! - On the way back to user mode the task, in its own context, runs
//!   the timers that are due (`run`): it rearms or disarms them, counts
//!   overruns, recomputes the caches and sends the signals once the
//!   registry lock is dropped.
//!
//! A thread timer is checked when its thread runs; a process timer when
//! any thread of the group runs (time only passes while one does).
//!
//! The group totals (Linux thread_group_cputimer) are atomics in the
//! SignalStruct, started from the group's CPU time when the first
//! process timer or a finite RLIMIT_CPU is armed and fed at every
//! accounting point after (`Task::account`), so they are exact to a
//! tick. Thread caches are per-task atomics. Both are hints: a stale
//! one only costs a pass of `run`.
//!
//! Locking: atomics only, except `run` and arming, which hold the
//! group's `posix_timers` while they decide and store the group's state
//! (`run` takes each timer's `inner` and the rlimit lock inside it);
//! the group's CPU time, which may take TASKLIST, is read before it.
//! Signals go out after it is dropped.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::task::Tid;

/// No expiry
pub const NONE: u64 = u64::MAX;

/// What a CPU timer counts (Linux CPUCLOCK_PROF / VIRT; SCHED counts
/// as PROF: hk keeps no separate runtime sum)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sample {
    /// utime + stime
    Prof = 0,
    /// utime
    Virt = 1,
}

impl Sample {
    /// From a CPU clock id's low bits (CPUCLOCK_PROF 0, VIRT 1, SCHED 2)
    pub fn of(which: u8) -> Self {
        if which == 1 {
            Sample::Virt
        } else {
            Sample::Prof
        }
    }

    /// This sample of (utime, stime)
    pub fn pick(self, (u, s): (u64, u64)) -> u64 {
        match self {
            Sample::Prof => u.saturating_add(s),
            Sample::Virt => u,
        }
    }
}

/// The clock a CPU timer runs on: a thread of the owning group, or the
/// group itself
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuClock {
    /// The thread (None: the whole process)
    pub thread: Option<Tid>,
    pub sample: Sample,
}

/// A thread group's CPU timer state (Linux signal->cputimer and the
/// process part of posix_cputimers)
pub struct GroupCputimer {
    /// The totals below are kept (Linux cputimer->running)
    active: AtomicBool,
    /// Group utime, stime (ns) while active
    sums: [AtomicU64; 2],
    /// Earliest process-timer expiry per sample (ns), NONE if none
    next: [AtomicU64; 2],
}

impl GroupCputimer {
    pub const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            sums: [AtomicU64::new(0), AtomicU64::new(0)],
            next: [AtomicU64::new(NONE), AtomicU64::new(NONE)],
        }
    }

    /// A thread of the group ran `delta` ns in user (or kernel) mode
    /// (Linux account_group_*_time)
    pub fn charge(&self, delta: u64, kernel: bool) {
        if self.active.load(Ordering::Relaxed) {
            self.sums[kernel as usize].fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// The group's (utime, stime), if kept
    pub fn totals(&self) -> Option<(u64, u64)> {
        self.active.load(Ordering::Acquire).then(|| {
            (
                self.sums[0].load(Ordering::Relaxed),
                self.sums[1].load(Ordering::Relaxed),
            )
        })
    }

    /// Start keeping totals from the group's CPU time `now` (Linux
    /// thread_group_start_cputime)
    fn start(&self, now: (u64, u64)) {
        if !self.active.load(Ordering::Acquire) {
            self.sums[0].store(now.0, Ordering::Relaxed);
            self.sums[1].store(now.1, Ordering::Relaxed);
            self.active.store(true, Ordering::Release);
        }
    }

    fn stop(&self) {
        self.active.store(false, Ordering::Release);
        for n in &self.next {
            n.store(NONE, Ordering::Relaxed);
        }
    }

    /// Lower the cached expiry of `s` to `at`
    fn arm(&self, s: Sample, at: u64) {
        self.next[s as usize].fetch_min(at, Ordering::Relaxed);
    }

    /// Past a process expiry
    fn due(&self) -> bool {
        self.totals().is_some_and(|t| {
            Sample::Prof.pick(t) >= self.next[0].load(Ordering::Relaxed)
                || Sample::Virt.pick(t) >= self.next[1].load(Ordering::Relaxed)
        })
    }
}

impl Default for GroupCputimer {
    fn default() -> Self {
        Self::new()
    }
}

/// The calling process's SignalStruct
fn my_group() -> Option<Arc<crate::signal::SignalStruct>> {
    crate::task::percpu::current().cpu_group().cloned()
}

/// Group `pid`'s current CPU time, starting its totals if they are not
/// kept yet; the totals after (thread context)
pub fn group_sample(sig: &crate::signal::SignalStruct, pid: crate::task::Pid) -> (u64, u64) {
    if let Some(t) = sig.cputimer.totals() {
        return t;
    }
    let now = crate::task::percpu::get_process_times(pid);
    sig.cputimer.start(now);
    sig.cputimer.totals().unwrap_or(now)
}

/// Thread `tid`'s (utime, stime) now, if it is alive
pub fn thread_sample(tid: Tid) -> Option<(u64, u64)> {
    let now = crate::time::monotonic_ns();
    let me = crate::task::percpu::current();
    if me.tid() == tid {
        return Some(me.cputime(now));
    }
    crate::task::percpu::TASKLIST
        .read()
        .get(tid)
        .map(|t| t.task.cputime(now))
}

/// The value of `clock` now (process: group `pid`'s totals)
pub fn sample_now(clock: CpuClock, pid: crate::task::Pid) -> Option<u64> {
    match clock.thread {
        Some(tid) => thread_sample(tid).map(|t| clock.sample.pick(t)),
        None => my_group().map(|g| clock.sample.pick(group_sample(&g, pid))),
    }
}

/// Lower group `sig`'s cached expiry of `s` to `at`, keeping its totals
/// (restarted from `sample`, a fresh group CPU time, if `run` stopped
/// them meanwhile). Under `posix_timers`, like the end of `run`, so a
/// pass that found nothing armed cannot stop or overwrite this one.
fn arm_group(sig: &crate::signal::SignalStruct, s: Sample, at: u64, sample: (u64, u64)) {
    let _reg = sig.posix_timers.lock();
    sig.cputimer.start(sample);
    sig.cputimer.arm(s, at);
}

/// A timer on `clock` expires at `at`: lower the cache that sees it
pub fn arm(clock: CpuClock, at: u64) {
    match clock.thread {
        Some(tid) => {
            // The thread's task, then its hint under the group's
            // posix_timers (which that thread's `run` holds while it
            // recomputes the hint), so a pass under way cannot erase it
            let me = crate::task::percpu::current();
            let task = if me.tid() == tid {
                Some(crate::task::percpu::task_ref(&me))
            } else {
                crate::task::percpu::TASKLIST
                    .read()
                    .get(tid)
                    .map(|t| crate::task::percpu::task_ref(t.task))
            };
            let (Some(t), Some(g)) = (task, my_group()) else {
                return;
            };
            let _reg = g.posix_timers.lock();
            t.cpu_next[clock.sample as usize].fetch_min(at, Ordering::Relaxed);
        }
        None => {
            if let Some(g) = my_group() {
                let sample = group_sample(&g, crate::task::percpu::current_pid());
                arm_group(&g, clock.sample, at, sample);
            }
        }
    }
}

/// The tick, on task `t` (interrupt context): past an expiry of the
/// thread's own or of its group's, run the timers on the way back to
/// user mode (Linux run_posix_cpu_timers' fastpath + task_work)
pub fn tick(t: &crate::task::Task) {
    let mine = [
        t.cpu_next[0].load(Ordering::Relaxed),
        t.cpu_next[1].load(Ordering::Relaxed),
    ];
    let mut due = false;
    if mine != [NONE, NONE] {
        let c = t.cputime(crate::time::monotonic_ns());
        due = Sample::Prof.pick(c) >= mine[0] || Sample::Virt.pick(c) >= mine[1];
    }
    if !due {
        due = t.cpu_group().is_some_and(|g| g.cputimer.due());
    }
    if due {
        t.set_tif(crate::task::tif::NOTIFY_RESUME);
    }
}

/// What expired timers do once the registry lock is dropped
enum Fire {
    /// Signal `sig` to thread `tid`
    Thread(Tid, u32),
    /// Signal `sig` to the process
    Process(u32),
    /// Wake a clock_nanosleep
    Wake(Arc<crate::time::posix_timer::PosixTimer>),
}

/// Run the calling task's due CPU timers and its group's (task context,
/// on the way back to user mode; Linux handle_posix_cpu_timers)
pub fn run() {
    use crate::task::percpu;
    let me = percpu::current();
    let (tid, pid) = (me.tid(), percpu::current_pid());
    let Some(sig) = me.cpu_group().cloned() else {
        return;
    };
    let mine = me.cputime(crate::time::monotonic_ns());
    let mut fire: Vec<Fire> = Vec::new();
    let mut thread_next = [NONE; 2];
    let mut proc_next = [NONE; 2];
    let mut any_process = false;
    // The whole pass under `posix_timers`: arming (`arm_group`) takes
    // it too, so what is decided below holds until it is stored
    let reg = sig.posix_timers.lock();
    let group = sig.cputimer.totals();
    for t in reg.iter() {
        let Some(clock) = t.cpu_clock() else {
            continue;
        };
        let now = match clock.thread {
            Some(x) if x == tid => clock.sample.pick(mine),
            // Another thread's timer: checked when it runs
            Some(_) => continue,
            None => {
                any_process |= t.armed();
                match group {
                    Some(g) => clock.sample.pick(g),
                    None => continue,
                }
            }
        };
        if let Some(f) = t.cpu_expire(now) {
            fire.push(f.into_fire(t));
        }
        if let Some(at) = t.cpu_expiry() {
            let n = match clock.thread {
                Some(_) => &mut thread_next[clock.sample as usize],
                None => &mut proc_next[clock.sample as usize],
            };
            *n = (*n).min(at);
        }
    }
    // Still under posix_timers: `arm` of a thread timer lowers this
    // under it too
    for (i, n) in thread_next.iter().enumerate() {
        me.cpu_next[i].store(*n, Ordering::Relaxed);
    }
    // RLIMIT_CPU (Linux check_process_timers): SIGXCPU at the soft
    // limit and each second after it (the soft limit moves up a second
    // each time), SIGKILL at the hard limit
    let limited = match group {
        Some(g) => rlimit_cpu(&sig, Sample::Prof.pick(g), &mut fire, &mut proc_next[0]),
        None => rlimit_finite(&sig),
    };
    if any_process || limited {
        for (i, n) in proc_next.iter().enumerate() {
            sig.cputimer.next[i].store(*n, Ordering::Relaxed);
        }
    } else {
        sig.cputimer.stop();
    }
    drop(reg);
    for f in fire {
        match f {
            Fire::Thread(t, s) => {
                crate::signal::send_signal(t, s);
            }
            Fire::Process(s) => {
                crate::signal::send_signal_to_process(pid, s);
            }
            Fire::Wake(t) => t.wake_sleeper(),
        }
    }
}

/// RLIMIT_CPU is finite
fn rlimit_finite(sig: &crate::signal::SignalStruct) -> bool {
    sig.get_rlimit(crate::task::rlimit::RLIMIT_CPU)
        .is_some_and(|r| r.rlim_cur != crate::task::rlimit::RLIM_INFINITY)
}

/// The RLIMIT_CPU part of `run` at process CPU time `prof`; true if the
/// limit is finite (the totals must stay kept)
fn rlimit_cpu(
    sig: &crate::signal::SignalStruct,
    prof: u64,
    fire: &mut Vec<Fire>,
    next: &mut u64,
) -> bool {
    use crate::task::rlimit::{RLIM_INFINITY, RLIMIT_CPU};
    const SEC: u64 = 1_000_000_000;
    let Some(r) = sig.get_rlimit(RLIMIT_CPU) else {
        return false;
    };
    if r.rlim_cur == RLIM_INFINITY {
        return false;
    }
    let secs = prof / SEC;
    if r.rlim_max != RLIM_INFINITY && secs >= r.rlim_max {
        fire.push(Fire::Process(crate::signal::SIGKILL));
        return true;
    }
    let mut soft = r.rlim_cur;
    if secs >= soft {
        fire.push(Fire::Process(crate::signal::SIGXCPU));
        if soft < r.rlim_max {
            soft += 1;
            sig.set_rlimit_cur(RLIMIT_CPU, soft);
        }
    }
    let at = |s: u64| s.saturating_mul(SEC);
    *next = (*next).min(at(soft));
    if r.rlim_max != RLIM_INFINITY {
        *next = (*next).min(at(r.rlim_max));
    }
    true
}

/// setrlimit(RLIMIT_CPU) of process `pid`, or a fork with a finite one
/// (Linux update_rlimit_cpu, posix_cpu_timers_init_group): keep the
/// group's totals and look at the limit at its next tick
pub fn rlimit_cpu_changed(sig: &crate::signal::SignalStruct, pid: crate::task::Pid) {
    if rlimit_finite(sig) {
        let sample = group_sample(sig, pid);
        arm_group(sig, Sample::Prof, 0, sample);
    }
}

/// What an expired CPU timer asks for
pub enum Expired {
    Signal { sig: u32, thread: Option<Tid> },
    Wake,
}

impl Expired {
    fn into_fire(self, t: &Arc<crate::time::posix_timer::PosixTimer>) -> Fire {
        match self {
            Expired::Signal {
                sig,
                thread: Some(x),
            } => Fire::Thread(x, sig),
            Expired::Signal { sig, thread: None } => Fire::Process(sig),
            Expired::Wake => Fire::Wake(t.clone()),
        }
    }
}
