//! Linux-compatible signal infrastructure
//!
//! This module provides POSIX/Linux signal handling including:
//! - Signal sets (SigSet) for 64 signals
//! - Signal actions (SigAction) with handlers, flags, and masks
//! - Per-task signal state (blocked mask, pending signals)
//! - Shared signal handlers (SigHand) for CLONE_SIGHAND
//! - Signal delivery infrastructure
//!
//! # Locking Model
//!
//! - `SigHand.action` uses `IrqSpinlock` because signal handlers may be queried
//!   from interrupt context (page faults, timer interrupts)
//! - A task's handler table (`Task.sighand`) and signal state
//!   (`Task.signal_state`) live in its Task, under TASKLIST; the
//!   thread-group pending set is a `spin::Mutex`, taken under it
//!
//! See doc/LOCKING.md for full lock ordering.

pub mod notify;
pub mod pending;
pub mod siginfo;
pub mod syscall;

pub use pending::{SigPending, SigQueue};

use crate::sync::spin::Mutex;
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::{IrqSpinlock, UserFrame};
use crate::task::{Pid, Tid};

// =============================================================================
// Signal Numbers (Linux x86_64 ABI - same on aarch64)
// =============================================================================

/// Hangup
pub const SIGHUP: u32 = 1;
/// Interrupt (Ctrl+C)
pub const SIGINT: u32 = 2;
/// Quit (Ctrl+\)
pub const SIGQUIT: u32 = 3;
/// Illegal instruction
pub const SIGILL: u32 = 4;
/// Trace/breakpoint trap
pub const SIGTRAP: u32 = 5;
/// Abort
pub const SIGABRT: u32 = 6;
/// Bus error
pub const SIGBUS: u32 = 7;
/// Floating point exception
pub const SIGFPE: u32 = 8;
/// Kill (cannot be caught or ignored)
pub const SIGKILL: u32 = 9;
/// User-defined signal 1
pub const SIGUSR1: u32 = 10;
/// Segmentation fault
pub const SIGSEGV: u32 = 11;
/// User-defined signal 2
pub const SIGUSR2: u32 = 12;
/// Broken pipe
pub const SIGPIPE: u32 = 13;
/// Alarm clock
pub const SIGALRM: u32 = 14;
/// Termination
pub const SIGTERM: u32 = 15;
/// Stack fault (unused on modern Linux)
pub const SIGSTKFLT: u32 = 16;
/// Child stopped or terminated
pub const SIGCHLD: u32 = 17;
/// Continue if stopped
pub const SIGCONT: u32 = 18;
/// Stop (cannot be caught or ignored)
pub const SIGSTOP: u32 = 19;
/// Keyboard stop
pub const SIGTSTP: u32 = 20;
/// Background read from tty
pub const SIGTTIN: u32 = 21;
/// Background write to tty
pub const SIGTTOU: u32 = 22;
/// Urgent condition on socket
pub const SIGURG: u32 = 23;
/// CPU time limit exceeded
pub const SIGXCPU: u32 = 24;
/// File size limit exceeded
pub const SIGXFSZ: u32 = 25;
/// Virtual alarm clock
pub const SIGVTALRM: u32 = 26;
/// Profiling timer expired
pub const SIGPROF: u32 = 27;
/// Window resize
pub const SIGWINCH: u32 = 28;
/// I/O possible
pub const SIGIO: u32 = 29;
/// Power failure
pub const SIGPWR: u32 = 30;
/// Bad system call
pub const SIGSYS: u32 = 31;

/// First real-time signal
pub const SIGRTMIN: u32 = 32;
/// Last real-time signal
pub const SIGRTMAX: u32 = 64;

/// Maximum signal number
pub const NSIG: u32 = 64;

// =============================================================================
// Signal Set
// =============================================================================

/// 64-bit signal set (signals 1-64, bit 0 is signal 1)
///
/// Follows Linux sigset_t representation where bit N-1 corresponds to signal N.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct SigSet(pub u64);

/// Signals a task's own faults raise, delivered before others (Linux
/// SYNCHRONOUS_MASK)
const SYNCHRONOUS_MASK: u64 = 1 << (SIGSEGV - 1)
    | 1 << (SIGBUS - 1)
    | 1 << (SIGILL - 1)
    | 1 << (SIGTRAP - 1)
    | 1 << (SIGFPE - 1)
    | 1 << (SIGSYS - 1);

// SAFETY: repr(transparent) over a u64: any bits valid, no padding
unsafe impl crate::util::pod::FromBytes for SigSet {}
// SAFETY: as above
unsafe impl crate::util::pod::IntoBytes for SigSet {}

impl SigSet {
    /// Empty signal set (no signals)
    pub const EMPTY: Self = Self(0);

    /// Full signal set (all signals)
    pub const FULL: Self = Self(!0);

    /// Create a new empty signal set
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create a signal set from a raw bitmask
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Get the raw bitmask
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Check if signal is in set (signals are 1-indexed)
    pub fn contains(&self, sig: u32) -> bool {
        if sig == 0 || sig > 64 {
            return false;
        }
        (self.0 & (1 << (sig - 1))) != 0
    }

    /// Add signal to set
    pub fn add(&mut self, sig: u32) {
        if sig > 0 && sig <= 64 {
            self.0 |= 1 << (sig - 1);
        }
    }

    /// Remove signal from set
    pub fn remove(&mut self, sig: u32) {
        if sig > 0 && sig <= 64 {
            self.0 &= !(1 << (sig - 1));
        }
    }

    /// Union with another set
    pub fn union(&self, other: &SigSet) -> SigSet {
        SigSet(self.0 | other.0)
    }

    /// Intersection with another set
    pub fn intersect(&self, other: &SigSet) -> SigSet {
        SigSet(self.0 & other.0)
    }

    /// Subtract another set
    pub fn subtract(&self, other: &SigSet) -> SigSet {
        SigSet(self.0 & !other.0)
    }

    /// The set with SIGKILL and SIGSTOP cleared: the only mask that may
    /// become a task's blocked set or a handler's mask (Linux
    /// sigdelsetmask in set_current_blocked / do_sigaction). They can
    /// never be blocked, so every path that stores a blocked mask runs
    /// its input through this.
    pub fn blockable(self) -> SigSet {
        self.subtract(&UNMASKABLE_SIGNALS)
    }

    /// Check if any signals are set
    pub fn any(&self) -> bool {
        self.0 != 0
    }

    /// Check if no signals are set
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Get first set signal (lowest number)
    ///
    /// Returns the signal number (1-64) of the first set bit, or None if empty.
    pub fn first(&self) -> Option<u32> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() + 1)
        }
    }
}

/// Signals that cannot be caught, blocked, or ignored
pub const UNMASKABLE_SIGNALS: SigSet = SigSet((1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1)));

// =============================================================================
// Signal Action Flags (SA_*)
// =============================================================================

/// Signal action flags
pub mod sa_flags {
    /// Don't send SIGCHLD when children stop
    pub const SA_NOCLDSTOP: u64 = 1;
    /// Don't create zombie on child death
    pub const SA_NOCLDWAIT: u64 = 2;
    /// Call handler with siginfo_t
    pub const SA_SIGINFO: u64 = 4;
    /// Use alternate signal stack
    pub const SA_ONSTACK: u64 = 0x08000000;
    /// Restart syscalls if possible
    pub const SA_RESTART: u64 = 0x10000000;
    /// Don't block signal during handler
    pub const SA_NODEFER: u64 = 0x40000000;
    /// Reset handler to default after handling
    pub const SA_RESETHAND: u64 = 0x80000000;
    /// Handler has restorer function
    pub const SA_RESTORER: u64 = 0x04000000;
}

// =============================================================================
// Signal information (siginfo)
// =============================================================================

pub use siginfo::{SigFields, SigInfo, si_code};

/// The arch details of a fault that go into the signal frame's
/// sigcontext, not into siginfo (Linux thread.trap_nr and error_code on
/// x86-64, thread.fault_code on arm64)
#[derive(Debug, Clone, Copy, Default)]
pub struct Trap {
    /// x86-64: sigcontext.trapno (exception vector)
    pub trapno: u64,
    /// x86-64: sigcontext.err (exception error code); arm64: ESR_EL1
    /// (reported in an esr_context record when non-zero)
    pub error: u64,
}

/// si_code for a SIGSEGV at user address `addr` (Linux bad_area vs
/// bad_area_access_error): SEGV_ACCERR if a VMA of the current task
/// covers it, else SEGV_MAPERR
pub fn segv_code(addr: u64) -> i32 {
    let tid = crate::task::percpu::current_tid();
    let mapped =
        crate::mm::get_task_mm(tid).is_some_and(|mm| mm.mmap_read().find_vma(addr).is_some());
    if mapped {
        si_code::SEGV_ACCERR
    } else {
        si_code::SEGV_MAPERR
    }
}

// =============================================================================
// Signal Handler
// =============================================================================

/// Special handler value: default action
pub const SIG_DFL: u64 = 0;
/// Special handler value: ignore signal
pub const SIG_IGN: u64 = 1;
/// Special handler value: error
pub const SIG_ERR: u64 = !0;

/// Signal disposition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigHandler {
    /// Default action for this signal
    #[default]
    Default,
    /// Ignore signal
    Ignore,
    /// User handler function at this address
    Handler(u64),
}

impl From<u64> for SigHandler {
    fn from(val: u64) -> Self {
        match val {
            SIG_DFL => Self::Default,
            SIG_IGN => Self::Ignore,
            addr => Self::Handler(addr),
        }
    }
}

impl From<SigHandler> for u64 {
    fn from(handler: SigHandler) -> u64 {
        match handler {
            SigHandler::Default => SIG_DFL,
            SigHandler::Ignore => SIG_IGN,
            SigHandler::Handler(addr) => addr,
        }
    }
}

// =============================================================================
// Signal Action
// =============================================================================

/// Signal action (kernel-internal representation)
///
/// This is the kernel's view of a signal action, similar to Linux's
/// `struct k_sigaction`.
#[derive(Debug, Clone)]
pub struct SigAction {
    /// Handler function or disposition
    pub handler: SigHandler,
    /// Flags (SA_*)
    pub flags: u64,
    /// Address of signal trampoline (for SA_RESTORER)
    pub restorer: u64,
    /// Signals to block during handler execution
    pub mask: SigSet,
}

impl SigAction {
    /// Create a new signal action with default handler
    pub const fn new() -> Self {
        Self {
            handler: SigHandler::Default,
            flags: 0,
            restorer: 0,
            mask: SigSet::EMPTY,
        }
    }

    /// Create a signal action to ignore the signal
    pub const fn ignore() -> Self {
        Self {
            handler: SigHandler::Ignore,
            flags: 0,
            restorer: 0,
            mask: SigSet::EMPTY,
        }
    }

    /// Check if this action ignores the signal
    pub fn is_ignore(&self) -> bool {
        matches!(self.handler, SigHandler::Ignore)
    }

    /// Check if this action uses the default behavior
    pub fn is_default(&self) -> bool {
        matches!(self.handler, SigHandler::Default)
    }
}

impl Default for SigAction {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Shared Signal Handlers (SigHand)
// =============================================================================

/// Shared signal handlers (for CLONE_SIGHAND)
///
/// Contains the signal action table for a task or group of tasks sharing
/// handlers. Protected by IrqSpinlock because signal handlers may be queried
/// from interrupt context (e.g., page faults generating SIGSEGV).
pub struct SigHand {
    /// Signal actions indexed by signal number (index 0 unused, 1-64
    /// valid), built in the heap: a 65-entry array moved through fork's
    /// stack frames used ~9 KB of the 16 KB kernel stack
    action: IrqSpinlock<Box<[SigAction]>>,
    /// Readers and pollers of a signalfd among the tasks sharing this
    /// table (Linux sighand->signalfd_wqh): woken by every signal sent
    /// to one of them
    pub signalfd_wq: crate::sync::waitqueue::WaitQueue,
}

/// A handler table with every action at its default
fn default_actions() -> Box<[SigAction]> {
    alloc::vec![SigAction::new(); 65].into_boxed_slice()
}

impl SigHand {
    /// Create a new signal handler table with all defaults
    pub fn new() -> Self {
        Self {
            action: IrqSpinlock::new(default_actions()),
            signalfd_wq: crate::sync::waitqueue::WaitQueue::new(),
        }
    }

    /// Get action for a signal
    pub fn get_action(&self, sig: u32) -> Option<SigAction> {
        if sig == 0 || sig > 64 {
            return None;
        }
        let actions = self.action.lock();
        Some(actions[sig as usize].clone())
    }

    /// Set action for a signal
    ///
    /// Returns the old action on success, or EINVAL if signal is invalid
    /// or cannot have its action changed (SIGKILL, SIGSTOP).
    pub fn set_action(&self, sig: u32, action: SigAction) -> Result<SigAction, i32> {
        if sig == 0 || sig > 64 {
            return Err(22); // EINVAL
        }
        if sig == SIGKILL || sig == SIGSTOP {
            return Err(22); // EINVAL - can't change these
        }

        let mut actions = self.action.lock();
        let old = actions[sig as usize].clone();
        actions[sig as usize] = action;
        Ok(old)
    }

    /// Deep clone for fork (without CLONE_SIGHAND)
    ///
    /// Creates a new SigHand with copies of all signal actions.
    pub fn deep_clone(self: &Arc<Self>) -> Result<Arc<Self>, KernelError> {
        // Allocated before the lock is taken: SigHand.action stays a leaf
        let mut actions = default_actions();
        actions.clone_from_slice(&self.action.lock());
        try_arc(Self {
            action: IrqSpinlock::new(actions),
            signalfd_wq: crate::sync::waitqueue::WaitQueue::new(),
        })
    }

    /// Reset all signal handlers to default (for CLONE_CLEAR_SIGHAND)
    ///
    /// This resets signal handlers following Linux semantics:
    /// - Handlers set to SIG_IGN remain SIG_IGN (intentional - some signals must stay ignored)
    /// - All other handlers (custom handlers and SIG_DFL) become SIG_DFL
    /// - sa_flags are cleared to 0
    /// - sa_mask is emptied (all signals unmasked in handler context)
    /// - restorer is cleared
    ///
    /// This is called when CLONE_CLEAR_SIGHAND is used during clone.
    pub fn flush_handlers(&self) {
        let mut actions = self.action.lock();
        // Signals 1-64 (index 0 is unused)
        for sig in 1..=64 {
            let action = &mut actions[sig];
            // Preserve SIG_IGN, reset everything else to default
            if action.handler != SigHandler::Ignore {
                action.handler = SigHandler::Default;
            }
            action.flags = 0;
            action.restorer = 0;
            action.mask = SigSet::EMPTY;
        }
    }
}

impl Default for SigHand {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Per-Task Signal State
// =============================================================================

// =============================================================================
// Signal Alternate Stack (sigaltstack)
// =============================================================================

/// Signal stack flags
pub mod ss_flags {
    /// Currently executing on signal stack
    pub const SS_ONSTACK: i32 = 1;
    /// Disable signal stack
    pub const SS_DISABLE: i32 = 2;
    /// Auto-disarm after signal handler
    pub const SS_AUTODISARM: i32 = 1 << 31;
    /// Valid flags mask (includes internal SS_FLAG_BITS)
    pub const SS_FLAG_BITS: i32 = SS_AUTODISARM;
}

/// Minimum signal stack size (MINSIGSTKSZ on Linux)
pub const MINSIGSTKSZ: usize = 2048;

/// Default signal stack size (SIGSTKSZ on Linux)
pub const SIGSTKSZ: usize = 8192;

/// Alternate signal stack state
#[derive(Clone, Debug)]
pub struct AltStack {
    /// Stack pointer (base address)
    pub ss_sp: u64,
    /// Stack size
    pub ss_size: usize,
    /// Flags (SS_DISABLE, SS_AUTODISARM, etc.)
    pub ss_flags: i32,
}

impl AltStack {
    /// Create new disabled alternate stack
    pub const fn new() -> Self {
        Self {
            ss_sp: 0,
            ss_size: 0,
            ss_flags: ss_flags::SS_DISABLE,
        }
    }

    /// Check if alternate stack is enabled
    pub fn is_enabled(&self) -> bool {
        self.ss_flags & ss_flags::SS_DISABLE == 0
    }
}

impl Default for AltStack {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-task signal state (NOT shared via CLONE_SIGHAND)
///
/// Each task has its own blocked mask and private pending signals.
/// The shared_pending is shared with other threads in the same thread group.
pub struct TaskSignalState {
    /// Blocked signal mask
    pub blocked: SigSet,
    /// The mask before a syscall's temporary one (rt_sigsuspend, ppoll,
    /// pselect6, epoll_pwait): valid while the task's TIF_RESTORE_SIGMASK
    /// is set (Linux saved_sigmask)
    pub saved_sigmask: SigSet,
    /// Pending signals for this task (private)
    pub pending: SigPending,
    /// Shared pending signals (for thread group)
    pub shared_pending: SharedPending,
    /// Alternate signal stack
    pub altstack: AltStack,
    /// The mask before sigtimedwait unblocked the awaited signals
    /// (Linux real_blocked): such a signal does not kill on arrival
    pub real_blocked: SigSet,
    /// A traced task's queued fault: its signal and sigcontext details,
    /// for the frame when that signal is delivered (Linux
    /// thread.trap_nr, error_code; its siginfo rides in the queue)
    pub trap: Option<(u32, Trap)>,
}

/// A thread group's shared pending set (Linux signal->shared_pending):
/// shared by CLONE_THREAD; none for the boot task, which reads as empty
#[derive(Clone)]
pub struct SharedPending(Option<Arc<Mutex<SigPending>>>);

/// What the boot task's (absent) shared set reads as
static NO_SHARED: Mutex<SigPending> = Mutex::new(SigPending::new());

impl SharedPending {
    /// A new set where failure cannot be reported (the boot-time init
    /// task, and the exiting task's state handed back by `mem::take`)
    pub fn new() -> Self {
        Self(Some(arc_nofail(Mutex::new(SigPending::new()))))
    }

    /// A new set, or ENOMEM
    pub fn try_new() -> Result<Self, KernelError> {
        Ok(Self(Some(try_arc(Mutex::new(SigPending::new()))?)))
    }

    pub fn lock(&self) -> crate::sync::spin::MutexGuard<'_, SigPending> {
        self.0.as_deref().unwrap_or(&NO_SHARED).lock()
    }
}

impl Default for SharedPending {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskSignalState {
    /// The boot task's (const: no shared set)
    pub const fn boot() -> Self {
        Self {
            blocked: SigSet::EMPTY,
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(),
            shared_pending: SharedPending(None),
            altstack: AltStack::new(),
            real_blocked: SigSet::EMPTY,
            trap: None,
        }
    }

    /// Create new task signal state (infallible: see `SharedPending::new`)
    pub fn new() -> Self {
        Self::with_shared(SharedPending::new())
    }

    /// Create new task signal state, or ENOMEM
    pub fn try_new() -> Result<Self, KernelError> {
        Ok(Self::with_shared(SharedPending::try_new()?))
    }

    fn with_shared(shared_pending: SharedPending) -> Self {
        Self {
            blocked: SigSet::EMPTY,
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(),
            shared_pending,
            altstack: AltStack::new(),
            real_blocked: SigSet::EMPTY,
            trap: None,
        }
    }

    /// Check if there are deliverable signals
    pub fn has_deliverable_signals(&self) -> bool {
        // Check private pending
        if self.pending.signal.subtract(&self.blocked).any() {
            return true;
        }
        // Check shared pending
        let shared = self.shared_pending.lock();
        shared.signal.subtract(&self.blocked).any()
    }
}

impl Default for TaskSignalState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Task signal accessors - uses Task struct fields directly via TASKLIST
// =============================================================================

use crate::task::percpu::TASKLIST;

// =============================================================================
// Task Signal APIs
// =============================================================================

/// Initialize signal state for a new task
///
/// Called when creating the init process at boot (failure cannot be
/// reported). Also initializes the SignalStruct (which contains rlimits).
pub fn init_task_signal(tid: Tid, sighand: Arc<SigHand>) {
    // Built before TASKLIST is taken; Linux fork_init gives init_task
    // RLIMIT_NPROC and RLIMIT_SIGPENDING of half max_threads, which
    // every task inherits
    let s = SignalStruct::new();
    let half = crate::task::rlimit::max_threads() / 2;
    for r in [RLIMIT_NPROC, RLIMIT_SIGPENDING] {
        s.rlim.lock()[r as usize] = RLimit::new(half, half);
    }
    let s = arc_nofail(s);
    let mut table = TASKLIST.write();
    if let Some(mut task) = table.get_mut(tid) {
        task.sighand = Some(sighand);
        *task.task.sig.lock() = TaskSignalState::new();
        task.task.set_sigpending(false);
        task.task.set_cpu_group(&s);
        task.signal = Some(s);
    }
}

/// Get a task's signal handlers
pub fn get_task_sighand(tid: Tid) -> Option<Arc<SigHand>> {
    let table = TASKLIST.read();
    table.get(tid).and_then(|t| t.sighand.clone())
}

/// How the current task takes `sig` (for tty job control)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Blocked or SIG_IGN (Linux is_ignored in tty_jobctrl.c)
    Ignored,
    /// A handler runs
    Caught,
    /// SIG_DFL
    Default,
}

/// The current task's disposition of `sig`
pub fn disposition(sig: u32) -> Disposition {
    let tid = crate::task::percpu::current_tid();
    if with_task_signal_state(tid, |st| st.blocked.contains(sig)).unwrap_or(false) {
        return Disposition::Ignored;
    }
    match get_task_sighand(tid)
        .and_then(|h| h.get_action(sig))
        .map(|a| a.handler)
    {
        Some(SigHandler::Ignore) => Disposition::Ignored,
        Some(SigHandler::Handler(_)) => Disposition::Caught,
        _ => Disposition::Default,
    }
}

/// Access a task's signal state for modification
///
/// Afterwards the task's TIF_SIGPENDING flag is recomputed, so it always
/// means "a signal is deliverable under the current blocked mask" (what
/// interruptible sleeps test via `signal_pending()`).
pub fn with_task_signal_state<F, R>(tid: Tid, f: F) -> Option<R>
where
    F: FnOnce(&mut TaskSignalState) -> R,
{
    with_task_sig(tid, |_, s| f(s))
}

/// [`with_task_signal_state`], `f` also given the task
fn with_task_sig<F, R>(tid: Tid, f: F) -> Option<R>
where
    F: FnOnce(&crate::task::Task, &mut TaskSignalState) -> R,
{
    // The current task's own state needs no TASKLIST: it cannot leave
    // the task list while it runs
    let me = crate::task::percpu::current();
    let t = if me.tid() == tid && tid != 0 {
        crate::task::percpu::task_ref(&me)
    } else {
        TASKLIST.read().task(tid)?
    };
    let mut s = t.sig.lock();
    let r = f(&t, &mut s);
    t.set_sigpending(s.has_deliverable_signals());
    Some(r)
}

/// A child's shared signal objects, built by `fork_signal` before the
/// child exists and attached by `install_fork_signal`
pub struct ForkSignal {
    sighand: Arc<SigHand>,
    signal: Arc<SignalStruct>,
    /// CLONE_THREAD
    share_signal: bool,
    /// `signal` is the parent's: the child is one more live thread
    joined: bool,
}

/// Build a child's signal state for fork/clone, or ENOMEM (Linux
/// copy_sighand, copy_signal): its per-task state (for `Task::new`) and
/// its shared objects
///
/// If `share_sighand` is true (CLONE_SIGHAND), share the Arc<SigHand>.
/// Otherwise, deep clone the signal handlers.
///
/// If `share_pending` is true (CLONE_THREAD), share the thread-group pending.
///
/// If `clear_sighand` is true (CLONE_CLEAR_SIGHAND), reset all handlers to default
/// after cloning (except SIG_IGN handlers which are preserved).
pub fn fork_signal(
    parent_tid: Tid,
    share_sighand: bool,
    share_pending: bool,
    clear_sighand: bool,
) -> Result<(TaskSignalState, ForkSignal), KernelError> {
    // Get parent's sighand and signal_state
    // The parent's blocked mask and shared set (no queued info is
    // copied: a child starts with nothing pending)
    let (parent_sighand, parent_state) = {
        let table = TASKLIST.read();
        let parent = table.get(parent_tid);
        (
            parent.and_then(|p| p.sighand.clone()),
            parent.map(|p| {
                let s = p.task.sig.lock();
                (s.blocked, s.shared_pending.clone())
            }),
        )
    };

    let child_sighand = if share_sighand {
        // CLONE_SIGHAND: share the same SigHand
        match parent_sighand {
            Some(sh) => sh,
            None => try_arc(SigHand::new())?,
        }
    } else {
        // Fork: deep clone handlers
        let sighand = match parent_sighand {
            Some(sh) => sh.deep_clone()?,
            None => try_arc(SigHand::new())?,
        };

        // CLONE_CLEAR_SIGHAND: reset handlers to default (except SIG_IGN)
        if clear_sighand {
            sighand.flush_handlers();
        }

        sighand
    };

    // Clone per-task signal state
    let child_state = if let Some((blocked, shared)) = parent_state {
        TaskSignalState {
            blocked, // Inherit blocked mask
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(), // Fresh private pending
            shared_pending: if share_pending {
                // CLONE_THREAD: share thread-group pending
                shared
            } else {
                SharedPending::try_new()?
            },
            altstack: AltStack::new(), // Child starts with no altstack
            real_blocked: SigSet::EMPTY,
            trap: None,
        }
    } else {
        TaskSignalState::try_new()?
    };

    // Clone or share SignalStruct (contains rlimits)
    // CLONE_THREAD (share_pending) implies threads share SignalStruct
    let (signal, joined) = fork_signal_struct(parent_tid, share_pending)?;
    let fork = ForkSignal {
        sighand: child_sighand,
        signal,
        share_signal: share_pending,
        joined,
    };
    Ok((child_state, fork))
}

/// Attach a new task's shared signal objects, once it is in TASKLIST
pub fn install_fork_signal(child_tid: Tid, f: ForkSignal) {
    if f.joined {
        // CLONE_THREAD: one more live thread
        f.signal.thread_added();
    }
    if !f.share_signal {
        // An inherited finite RLIMIT_CPU is watched from the start (Linux
        // posix_cpu_timers_init_group)
        crate::time::cpu_timer::rlimit_cpu_changed(&f.signal, child_tid);
    }
    let mut table = TASKLIST.write();
    if let Some(mut child) = table.get_mut(child_tid) {
        child.sighand = Some(f.sighand);
        child.task.set_cpu_group(&f.signal);
        child.signal = Some(f.signal);
    }
}

/// Clean up signal state on task exit
pub fn exit_task_signal(tid: Tid) {
    // Released after TASKLIST (nothing is released under it): the
    // queued signals with the rest (Linux flush_sigqueue in
    // __exit_signal); an exiting task gets no more queued (send_locked)
    let _old = {
        let mut table = TASKLIST.write();
        table.get_mut(tid).map(|mut task| {
            let old = core::mem::replace(&mut *task.task.sig.lock(), TaskSignalState::boot());
            task.task.set_sigpending(false);
            // A zombie leader keeps the group's SignalStruct (its exit
            // status; Linux frees signal_struct with the reaped leader)
            let signal = if task.leader {
                None
            } else {
                // Its CPU time stays the group's (Linux __exit_signal)
                let t = task.task.cputime(crate::time::monotonic_ns());
                if let Some(s) = &task.signal {
                    s.add_dead_times(t);
                }
                task.signal.take()
            };
            (task.sighand.take(), signal, old)
        })
    };
}

// =============================================================================
// Signal Sending
// =============================================================================

/// SIGKILL is pending for the current task (Linux
/// fatal_signal_pending): killable sleeps end on it
pub fn fatal_signal_pending() -> bool {
    let me = crate::task::percpu::current();
    // SIGKILL cannot be blocked: pending, it sets TIF_SIGPENDING
    if !me.sigpending() {
        return false;
    }
    let s = me.sig.lock();
    s.pending.signal.contains(SIGKILL) || s.shared_pending.lock().signal.contains(SIGKILL)
}

/// Check if a task has pending signals (fast path)
pub fn has_pending_signals(tid: Tid) -> bool {
    // The current task's TIF_SIGPENDING, lock-free
    let me = crate::task::percpu::current();
    if me.tid() == tid {
        return me.sigpending();
    }
    let table = TASKLIST.read();
    table.get(tid).map(|t| t.task.sigpending()).unwrap_or(false)
}

/// Whether `sig` would be discarded on arrival (Linux sig_ignored): its
/// handler is SIG_IGN, or SIG_DFL with an "ignore" default (SIGCHLD,
/// SIGURG, SIGWINCH, and SIGCONT, which hk does not act on), and it is not
/// blocked (a blocked signal stays queued: the handler may change), nor
/// awaited by sigtimedwait (blocked before it: real_blocked)
fn sig_ignored(state: &TaskSignalState, sighand: Option<&Arc<SigHand>>, sig: u32) -> bool {
    let held = state.blocked.contains(sig) || state.real_blocked.contains(sig);
    if held || sig == SIGKILL || sig == SIGSTOP {
        return false;
    }
    let Some(action) = sighand.and_then(|h| h.get_action(sig)) else {
        return false;
    };
    match action.handler {
        SigHandler::Ignore => true,
        SigHandler::Default => matches!(
            default_action(sig),
            DefaultAction::Ignore | DefaultAction::Continue
        ),
        SigHandler::Handler(_) => false,
    }
}

/// The global init lost SIGNAL_UNKILLABLE (Linux
/// force_sig_info_to_task clears it when the kernel forces a signal
/// whose action is SIG_DFL): one flag, as there is one global init
static INIT_KILLABLE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether `tid` is a thread of the global init (pid 1 of the initial
/// pid namespace; Linux is_global_init) and still SIGNAL_UNKILLABLE
fn init_unkillable(tid: Tid) -> bool {
    !INIT_KILLABLE.load(core::sync::atomic::Ordering::Acquire)
        && TASKLIST.read().get(tid).is_some_and(|t| t.task.pid == 1)
}

/// Linux sig_task_ignored for the global init: SIGKILL and SIGSTOP never
/// reach it, nor any signal whose action is SIG_DFL (so a stray SIGTERM
/// or SIGPIPE does not kill it). A blocked signal is still queued (its
/// action may change before it is unblocked). A kernel-forced signal
/// never gets here: it lifts the protection (`send_signal_force`).
fn init_ignores(state: &TaskSignalState, sighand: Option<&Arc<SigHand>>, sig: u32) -> bool {
    let kernel_only = sig == SIGKILL || sig == SIGSTOP;
    if kernel_only {
        return true;
    }
    if state.blocked.contains(sig) || state.real_blocked.contains(sig) {
        return false;
    }
    let action = sighand.and_then(|h| h.get_action(sig)).unwrap_or_default();
    action.handler == SigHandler::Default
}

/// What a signal is sent with (Linux send_signal_locked's info: a
/// kernel_siginfo, or the SEND_SIG_NOINFO / SEND_SIG_PRIV specials)
#[derive(Clone, Copy, Debug)]
pub enum SendInfo {
    /// From the current task, as kill sends (SEND_SIG_NOINFO: SI_USER,
    /// its pid and uid)
    User,
    /// From the kernel (SEND_SIG_PRIV: SI_KERNEL)
    Kernel,
    /// This info
    Info(SigInfo),
}

impl SendInfo {
    /// The info queued for `sig` (Linux __send_signal_locked's switch);
    /// pids are root-namespace numbers
    fn resolve(&self, sig: u32) -> SigInfo {
        match self {
            Self::User => {
                let pid = crate::task::percpu::current_pid() as i32;
                SigInfo::kill(sig, si_code::SI_USER, pid, crate::task::current_cred().uid)
            }
            Self::Kernel => SigInfo::kill(sig, si_code::SI_KERNEL, 0, 0),
            Self::Info(i) => *i,
        }
    }

    /// A non-RT signal's entry may pass RLIMIT_SIGPENDING unless a user
    /// queued it (si_code < 0); an RT one never does (Linux
    /// __send_signal_locked's override_rlimit)
    fn override_rlimit(&self, sig: u32) -> bool {
        sig < SIGRTMIN && !matches!(self, Self::Info(i) if i.code < 0)
    }

    /// With no entry, the send fails with EAGAIN: an RT signal a user
    /// queued with info other than kill's (Linux: queue overflow)
    fn must_queue(&self, sig: u32) -> bool {
        sig >= SIGRTMIN && matches!(self, Self::Info(i) if i.code != si_code::SI_USER)
    }
}

/// Send a signal to a specific task (thread), from the current task
/// (`SendInfo::User`)
///
/// Queues the signal and, if it is deliverable, wakes the task from an
/// interruptible sleep (Linux signal_wake_up) so the blocked syscall can
/// return -ERESTART*/-EINTR and the signal is delivered on the way out.
/// Process context only (takes TASKLIST).
///
/// Returns 0 on success, negative errno on error.
pub fn send_signal(tid: Tid, sig: u32) -> i32 {
    send_sig_info(tid, sig, SendInfo::User)
}

/// Send `sig` with `info` to thread `tid` (Linux send_sig_info): 0,
/// ESRCH, EINVAL, or EAGAIN when an RT signal's info cannot be queued
pub fn send_sig_info(tid: Tid, sig: u32, info: SendInfo) -> i32 {
    send_signal_force(tid, sig, info, PidType::Pid, false)
}

/// Whom a signal is for (Linux enum pid_type, the two a send uses)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidType {
    /// The thread (PIDTYPE_PID)
    Pid,
    /// Its whole thread group (PIDTYPE_TGID)
    Tgid,
}

/// The receiver of a send, read under TASKLIST: a kernel thread, the
/// global init, its group exiting, its real uid and RLIMIT_SIGPENDING
struct Target {
    kthread: bool,
    init: bool,
    group_exit: bool,
    uid: crate::task::Uid,
    limit: u64,
}

fn target(tid: Tid) -> Option<Target> {
    let table = TASKLIST.read();
    let t = table.get(tid)?;
    let limit = t
        .signal
        .as_ref()
        .and_then(|s| s.get_rlimit(RLIMIT_SIGPENDING));
    Some(Target {
        kthread: t.task.has_flag(crate::task::pf::KTHREAD),
        init: t.task.pid == 1,
        group_exit: t
            .signal
            .as_ref()
            .is_some_and(|s| matches!(s.group_exit(), GroupExit::Exit(_))),
        uid: t.cred_arc().uid,
        limit: limit.map_or(0, |r| r.rlim_cur),
    })
}

/// How a send went under the receiver's lock
enum Sent {
    /// Discarded on arrival, or already pending (a non-RT signal)
    Dropped,
    /// No entry for an RT signal that needed one
    Overflow,
    /// Pending: (deliverable now, fatal on arrival unless awaited)
    Queued(bool, bool),
}

/// send_sig_info; `force` (a kernel-forced signal, Linux force_sig) is
/// delivered to the global init even with its action SIG_DFL
fn send_signal_force(tid: Tid, sig: u32, info: SendInfo, ty: PidType, force: bool) -> i32 {
    check_send_context();
    if sig == 0 {
        // Signal 0 is null signal - just check if task exists
        let table = TASKLIST.read();
        return if table.iter().any(|t| t.task.tid() == tid) {
            0
        } else {
            -3 // ESRCH
        };
    }

    if sig > 64 {
        return -22; // EINVAL
    }

    // Kernel threads ignore every signal (Linux ignore_signals in
    // kthreadd): they are processes now (pid == tid), reachable by
    // kill(-1) and kill(pid). One lookup also finds the global init.
    let Some(tg) = target(tid) else {
        return -3; // ESRCH
    };
    // A dying group takes no more signals (Linux prepare_signal:
    // SIGNAL_GROUP_EXIT; its threads have SIGKILL)
    if tg.kthread || tg.group_exit {
        return 0;
    }
    // A forced signal whose action is SIG_DFL (a blocked or ignored one
    // was reset by the caller) lifts the global init's protection (Linux
    // force_sig_info_to_task); one init handles leaves it protected. The
    // flag is read once here.
    let dfl = || {
        get_task_sighand(tid)
            .and_then(|h| h.get_action(sig))
            .is_none_or(|a| a.handler == SigHandler::Default)
    };
    let init = if tg.init && force && dfl() {
        INIT_KILLABLE.store(true, core::sync::atomic::Ordering::Release);
        false
    } else {
        tg.init && !INIT_KILLABLE.load(core::sync::atomic::Ordering::Acquire)
    };

    // The info's entry, made before the receiver's lock is taken; SIGKILL
    // needs none (Linux __send_signal_locked). Unused, it is freed after
    // the lock is dropped.
    let mut q = if sig == SIGKILL {
        None
    } else {
        SigQueue::alloc(
            info.resolve(sig),
            tg.uid,
            tg.limit,
            info.override_rlimit(sig),
        )
    };
    let sighand = get_task_sighand(tid);
    let sent = with_task_sig(tid, |t, state| {
        send_locked(t, state, sighand.as_ref(), sig, init, &info, ty, &mut q)
    });
    drop(q);

    let (deliverable, may_kill) = match sent {
        None => return -3, // ESRCH
        Some(Sent::Dropped) => return 0,
        Some(Sent::Overflow) => return -11, // EAGAIN
        Some(Sent::Queued(d, k)) => (d, k),
    };
    if may_kill && fatal(sighand.as_ref(), sig) {
        group_kill(tid, sig);
    }

    // Signalfd readers of the target's handler table recheck (Linux
    // signalfd_notify)
    if let Some(h) = &sighand {
        h.signalfd_wq.wake_all();
    }

    if deliverable {
        use crate::task::percpu::WakeMode;
        let mode = if sig == SIGKILL {
            WakeMode::Fatal
        } else {
            WakeMode::Interruptible
        };
        signal_wake_up(tid, mode);
    }

    0
}

/// Queue `sig` for task `t` under its Task.sig (Linux
/// __send_signal_locked): dropped if ignored (`init`: the global init's
/// protection applies) or a non-RT signal already pending, else marked
/// pending with entry `q` queued, which it takes. A signal for an
/// exiting thread itself is dropped (its queue was flushed: Linux
/// task_can_queue_signal); one for its group gets no entry. A send
/// whose entry could not be had goes on without; an RT signal a user
/// queued then fails.
#[expect(clippy::too_many_arguments)]
fn send_locked(
    t: &crate::task::Task,
    state: &mut TaskSignalState,
    sighand: Option<&Arc<SigHand>>,
    sig: u32,
    init: bool,
    info: &SendInfo,
    ty: PidType,
    q: &mut Option<Box<SigQueue>>,
) -> Sent {
    let exiting = t.has_flag(crate::task::pf::EXITING);
    if exiting && ty == PidType::Pid {
        return Sent::Dropped;
    }
    if sig_ignored(state, sighand, sig) || (init && init_ignores(state, sighand, sig)) {
        return Sent::Dropped;
    }
    if state.pending.legacy(sig) {
        return Sent::Dropped;
    }
    if !exiting {
        match q.take() {
            Some(e) => state.pending.queue(e),
            None if info.must_queue(sig) => return Sent::Overflow,
            None => {}
        }
    }
    state.pending.add(sig);
    // Deliverable now; fatal on arrival unless awaited in sigtimedwait
    let d = !state.blocked.contains(sig);
    Sent::Queued(d, d && !state.real_blocked.contains(sig))
}

/// A signal for `tid` is deliverable (Linux signal_wake_up_state): wake
/// it from a sleep `mode` ends, else, if it runs on another CPU, kick it
/// into the kernel so its return to user mode delivers the signal
/// (kick_process). Process context, TASKLIST not held.
fn signal_wake_up(tid: Tid, mode: crate::task::percpu::WakeMode) {
    let Some(t) = crate::task::percpu::TASKLIST.read().task(tid) else {
        return;
    };
    if !crate::task::percpu::try_to_wake_up(&t, mode) {
        crate::task::percpu::kick_process(&t);
    }
}

/// Signals are sent from thread context only: Task.sig and the shared
/// pending set are non-IRQ spin locks (an interrupt handler that must
/// signal defers to a thread). Reported once as SIGNAL:FAIL otherwise.
fn check_send_context() {
    use crate::arch::{CurrentArch, PerCpuOps};
    if CurrentArch::interrupt_depth() > 0 {
        static REPORTED: core::sync::atomic::AtomicBool =
            core::sync::atomic::AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            crate::printkln!("SIGNAL:FAIL send_signal from interrupt context");
        }
    }
}

/// Send signal to a process (any thread in the thread group)
///
/// It goes to the leader, or to a thread still running if the leader
/// has exited (Linux complete_signal picks a thread that wants it).
pub fn send_signal_to_process(pid: Pid, sig: u32) -> i32 {
    kill_proc_info(pid, sig, SendInfo::User)
}

/// [`send_signal_to_process`] with `info` (Linux kill_proc_info)
pub fn kill_proc_info(pid: Pid, sig: u32, info: SendInfo) -> i32 {
    let tid = {
        let table = crate::task::percpu::TASKLIST.read();
        let leader = table.get(pid);
        match leader {
            Some(l) if task_live(&l) => Some(l.task.tid()),
            _ => table
                .threads(pid)
                .find(task_live)
                .or(leader)
                .map(|t| t.task.tid()),
        }
    };

    match tid {
        Some(tid) => send_signal_force(tid, sig, info, PidType::Tgid, false),
        None => -3, // ESRCH - no such process
    }
}

/// Send signal to all processes in a process group, from the kernel
/// (no permission check: Linux kill_pgrp with SEND_SIG_PRIV)
///
/// This is used by TTY signal generation (SIGINT, SIGTSTP, etc.)
/// when control characters are received.
///
/// Returns 0 on success, negative errno on error.
pub fn send_signal_to_pgrp(pgid: Pid, sig: u32) -> i32 {
    if sig == 0 || sig > 64 {
        return -22; // EINVAL
    }
    kill_pgrp(pgid, sig, SendInfo::Kernel, |_| 0)
}

/// `sig` from the kernel to each process of the group `pg` names (Linux
/// kill_pgrp(struct pid *)): unlike a number, the reference cannot come
/// to name another group
pub fn kill_pgrp_pid(pg: &crate::task::pid::Pid, sig: u32) {
    for pid in crate::task::percpu::pgrp_members(pg) {
        kill_proc_info(pid, sig, SendInfo::Kernel);
    }
}

/// `sig` with `info` once to each process of group `pgid` (Linux __kill_pgrp_info:
/// its leader on the group's list, the signal process-directed), after
/// `check(pid)` allows it; signal 0 only checks. 0 if any process got
/// it, else the last error (ESRCH for an empty group).
pub fn kill_pgrp(pgid: Pid, sig: u32, info: SendInfo, check: impl Fn(Pid) -> i32) -> i32 {
    let mut ret = -3; // ESRCH
    let mut ok = false;
    for pid in crate::task::percpu::pgrp_pids(pgid) {
        ret = match check(pid) {
            0 if sig != 0 => kill_proc_info(pid, sig, info),
            e => e,
        };
        ok |= ret == 0;
    }
    if ok { 0 } else { ret }
}

// =============================================================================
// Thread-group exit
// =============================================================================

/// `sig` kills the receiver's whole group on arrival (Linux sig_fatal in
/// complete_signal): SIGKILL, or a SIG_DFL signal whose default is to
/// terminate (core-dump signals end the group at delivery)
fn fatal(sighand: Option<&Arc<SigHand>>, sig: u32) -> bool {
    if sig == SIGKILL {
        return true;
    }
    let dfl = sighand
        .and_then(|h| h.get_action(sig))
        .is_some_and(|a| a.handler == SigHandler::Default);
    dfl && default_action(sig) == DefaultAction::Terminate
}

/// A fatal signal reached `tid`: its group exits with that status and
/// every thread gets SIGKILL (Linux complete_signal; a traced target
/// sees anything but SIGKILL first). Not once every thread of the group
/// has started exiting (Linux complete_signal finds no thread that
/// wants it): the status the last thread set stays. Decided under the
/// same TASKLIST hold as the group lookup, so a process-directed signal
/// whose chosen thread began exiting after it was picked still ends
/// the threads left. Unlike Linux, a thread-directed one to an exiting
/// thread with live siblings ends them too.
fn group_kill(tid: Tid, sig: u32) {
    let found = {
        let table = TASKLIST.read();
        table.get(tid).and_then(|t| {
            let pid = t.task.pid;
            table
                .threads(pid)
                .any(|u| task_live(&u))
                .then(|| (pid, t.ptrace != 0, group_signal(&table, pid)))
        })
    };
    let Some((tgid, traced, Some(s))) = found else {
        return;
    };
    if (sig == SIGKILL || !traced) && s.start_exit(sig as i32, true) {
        zap_threads(tgid, None);
    }
}

/// `t` has not started exiting (Linux !PF_EXITING, not a zombie)
pub fn task_live(t: &crate::task::percpu::TaskView<'_>) -> bool {
    !t.task.has_flag(crate::task::pf::EXITING)
        && !matches!(t.state, crate::task::TaskState::Zombie(_))
}

/// The SignalStruct of thread group `tgid` (its leader keeps it until
/// reaped; a thread's after a de_thread in progress)
fn group_signal(
    table: &crate::task::percpu::GlobalTaskTable,
    tgid: Pid,
) -> Option<Arc<SignalStruct>> {
    table
        .get(tgid)
        .and_then(|t| t.signal.clone())
        .or_else(|| table.threads(tgid).find_map(|t| t.signal.clone()))
}

/// SIGKILL every thread of `tgid` that has not started exiting, but
/// `except` (Linux zap_other_threads): queued privately, then woken
/// from interruptible and killable sleeps once TASKLIST is dropped.
/// A thread running user code dies on its next return to user mode (a
/// tick or a kick IPI interrupts it: `entry::exit_to_user_mode`).
fn zap_threads(tgid: Pid, except: Option<Tid>) {
    let tids: alloc::vec::Vec<Tid> = {
        let mut table = TASKLIST.write();
        let tids: alloc::vec::Vec<Tid> = table
            .threads(tgid)
            .filter(|t| Some(t.task.tid()) != except && task_live(t))
            .map(|t| t.task.tid())
            .collect();
        for &t in &tids {
            if let Some(mut v) = table.get_mut(t) {
                sigkill_task(&mut v);
            }
        }
        tids
    };
    for t in tids {
        signal_wake_up(t, crate::task::percpu::WakeMode::Fatal);
    }
}

/// SIGKILL every other thread of `tgid` (exec's de_thread)
pub fn zap_group_others(tgid: Pid, tid: Tid) {
    zap_threads(tgid, Some(tid));
}

/// Queue SIGKILL for `t` (TASKLIST held)
fn sigkill_task(t: &mut crate::task::percpu::TaskViewMut<'_>) {
    let mut s = t.task.sig.lock();
    s.pending.add(SIGKILL);
    t.task.set_sigpending(true);
}

/// A thread just cloned into `parent`'s group dies with it if the group
/// is exiting (Linux copy_process: fatal_signal_pending under siglock).
/// Its signal state is set up (`clone_task_signal`), so a zap that ran
/// before saw it or is seen here.
pub fn zap_new_thread(parent: Tid, child: Tid) {
    let dying = get_task_signal_struct(parent).is_some_and(|s| s.group_exit() != GroupExit::None);
    if dying && let Some(mut t) = TASKLIST.write().get_mut(child) {
        sigkill_task(&mut t);
    }
}

/// The current thread's group is exiting, or another thread's exec is
/// ending it (Linux signal_group_exit): it must die
fn group_dying(tid: Tid) -> bool {
    match get_task_signal_struct(tid).map(|s| s.group_exit()) {
        Some(GroupExit::Exit(_)) => true,
        Some(GroupExit::Exec(t)) => t != tid,
        _ => false,
    }
}

/// End the whole thread group with wait status `status` (Linux
/// do_group_exit): the first exit sets the group's status and kills the
/// other threads; a thread dying in a group exit already under way
/// takes its status, one ended by another thread's exec exits with 0
pub fn do_group_exit(status: i32) -> ! {
    let tid = crate::task::percpu::current_tid();
    let code = match get_task_signal_struct(tid) {
        Some(s) => loop {
            match s.group_exit() {
                GroupExit::Exit(code) => break code,
                GroupExit::Exec(_) => break 0,
                GroupExit::None if s.start_exit(status, false) => {
                    zap_threads(crate::task::percpu::current_pid(), Some(tid));
                    break status;
                }
                // Lost a race with another exit or an exec: look again
                GroupExit::None => {}
            }
        },
        None => status,
    };
    crate::task::proc::do_exit(code)
}

// =============================================================================
// Signal Delivery
// =============================================================================

/// Dequeue the next deliverable signal of task `tid` and its action
/// (Linux get_signal's dequeue): a queued fault first, then the next of
/// its own, then the thread group's
pub fn get_signal_to_deliver(tid: Tid) -> Option<(SigAction, SigInfo)> {
    let sighand = get_task_sighand(tid)?;
    let d = with_task_signal_state(tid, |state| {
        let blocked = state.blocked;
        state
            .pending
            .dequeue_sync(&blocked)
            .or_else(|| dequeue_locked(state, &blocked))
    })??;
    // The entry is freed here, with Task.sig dropped
    let info = d.info();
    Some((sighand.get_action(info.sig()).unwrap_or_default(), info))
}

/// The next signal not in `skip`, the task's own first, then its
/// group's (Linux dequeue_signal)
fn dequeue_locked(state: &mut TaskSignalState, skip: &SigSet) -> Option<pending::Dequeued> {
    if let Some(d) = state.pending.dequeue(skip) {
        return Some(d);
    }
    state.shared_pending.lock().dequeue(skip)
}

/// Dequeue the current task's next pending signal of `wanted`, with its
/// info (Linux dequeue_signal with the complement of `wanted`:
/// sigtimedwait, signalfd)
pub fn dequeue_signal(wanted: &SigSet) -> Option<SigInfo> {
    let skip = SigSet(!wanted.0);
    let tid = crate::task::percpu::current_tid();
    let d = with_task_signal_state(tid, |state| dequeue_locked(state, &skip))??;
    Some(d.info())
}

/// Default action for a signal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    /// Terminate the process
    Terminate,
    /// Terminate and dump core
    Core,
    /// Ignore the signal
    Ignore,
    /// Stop the process
    Stop,
    /// Continue the process
    Continue,
}

/// Get the default action for a signal
pub fn default_action(sig: u32) -> DefaultAction {
    match sig {
        // Terminate
        SIGHUP | SIGINT | SIGPIPE | SIGALRM | SIGTERM | SIGUSR1 | SIGUSR2 | SIGPOLL | SIGPROF
        | SIGVTALRM => DefaultAction::Terminate,

        // Terminate + core
        SIGQUIT | SIGILL | SIGABRT | SIGFPE | SIGSEGV | SIGBUS | SIGSYS | SIGTRAP | SIGXCPU
        | SIGXFSZ => DefaultAction::Core,

        // Ignore
        SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,

        // Stop
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,

        // Continue
        SIGCONT => DefaultAction::Continue,

        // Real-time signals default to terminate
        _ => DefaultAction::Terminate,
    }
}

// Alias for SIGIO
const SIGPOLL: u32 = SIGIO;

// =============================================================================
// SignalStruct - Per-Process Structure (mirrors Linux signal_struct)
// =============================================================================

use crate::task::rlimit::{RLIM_NLIMITS, RLIMIT_NPROC, RLIMIT_SIGPENDING, RLimit, default_rlimits};

/// Per-process signal structure (mirrors Linux signal_struct)
///
/// This structure is shared by all threads in a thread group (CLONE_THREAD).
/// It contains:
/// - Resource limits (rlimits)
/// - Future: Process-wide signal state, group exit state, etc.
///
/// Protected by IrqSpinlock for access from interrupt context.
///
/// # Linux Compatibility
///
/// Linux stores rlimits in `signal_struct->rlim[RLIM_NLIMITS]`. We mirror
/// this exactly so that:
/// - Threads share rlimits (because they share SignalStruct via Arc)
/// - Fork creates independent rlimits copies (deep clone)
/// - prlimit64 can modify limits for the whole thread group
pub struct SignalStruct {
    /// Resource limits for this process
    rlim: IrqSpinlock<[RLimit; RLIM_NLIMITS]>,
    /// Linux signal->cred_guard_mutex (sleeping, thread context only,
    /// outermost): held by exec from its first check until the new
    /// image is in place, and by ptrace attach around its decision
    cred_guard: crate::sync::Mutex<()>,
    /// Linux signal->exec_update_lock (sleeping RwSem, thread context
    /// only, just inside cred_guard): exec holds it for writing while it
    /// installs the new mm, name and dumpability; the mm_access checks
    /// (process_vm, /proc/<pid> mm files, stat) for reading around their
    /// decision and the mm they take
    exec_update: crate::sync::RwSem,
    /// Group exit state (Linux SIGNAL_GROUP_EXIT + group_exit_code, and
    /// group_exec_task): 0, GROUP_EXIT | wait status, or GROUP_EXEC |
    /// the exec'ing tid. Changed by compare-and-swap only, no lock.
    group_exit: AtomicU64,
    /// POSIX timers and ITIMER_REAL (Linux signal->posix_timers,
    /// real_timer): spin leaf, thread context only
    pub posix_timers: Mutex<crate::time::posix_timer::PosixTimerRegistry>,
    /// Threads not yet exiting (Linux signal->live): +1 at each
    /// CLONE_THREAD, -1 when a thread starts its exit; the thread that
    /// takes it to 0 is the group's last (group_dead)
    live: AtomicU32,
    /// CPU time (ns) of the group's threads already gone (Linux
    /// signal->utime/stime): added when one leaves the group
    dead_times: [AtomicU64; 2],
    /// CPU time (ns) of reaped children and theirs (Linux
    /// signal->cutime/cstime)
    child_times: [AtomicU64; 2],
    /// Process CPU timers' state (Linux signal->cputimer)
    pub cputimer: crate::time::cpu_timer::GroupCputimer,
}

const GROUP_EXIT: u64 = 1 << 63;
const GROUP_EXEC: u64 = 1 << 62;

/// Where a thread group is in its exit
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupExit {
    /// Running
    None,
    /// Every thread dies with this wait status (Linux SIGNAL_GROUP_EXIT)
    Exit(i32),
    /// Thread `Tid`'s exec ends the others (Linux group_exec_task)
    Exec(Tid),
}

/// A thread group's exec_update_lock held for reading, until dropped
pub struct ExecUpdateRead(Option<Arc<SignalStruct>>);

impl ExecUpdateRead {
    /// Take task `tid`'s (none for a task without a SignalStruct)
    pub fn lock(tid: Tid) -> Self {
        let s = get_task_signal_struct(tid);
        if let Some(s) = &s {
            s.exec_update.down_read();
        }
        Self(s)
    }
}

impl Drop for ExecUpdateRead {
    fn drop(&mut self) {
        if let Some(s) = &self.0 {
            // SAFETY: taken in ExecUpdateRead::lock by this task
            unsafe { s.exec_update.up_read() };
        }
    }
}

impl CredGuard {
    /// Run `f` with this thread group's exec_update_lock held for
    /// writing (exec only, inside its cred_guard)
    pub fn exec_update<R>(&self, f: impl FnOnce() -> R) -> R {
        let Some(s) = &self.0 else {
            return f();
        };
        s.exec_update.down_write();
        let r = f();
        // SAFETY: taken just above by this task
        unsafe { s.exec_update.up_write() };
        r
    }
}

/// A thread group's cred_guard_mutex, held until dropped
pub struct CredGuard(Option<Arc<SignalStruct>>);

impl CredGuard {
    /// Take task `tid`'s (none for a task without a SignalStruct),
    /// sleeping interruptibly (Linux prepare_bprm_creds, ptrace_attach):
    /// a thread waiting here while its group's exec waits in de_thread
    /// for it to die must see the SIGKILL. A signal gives
    /// ERESTARTNOINTR (the syscall restarts once the signal is handled).
    pub fn lock(tid: Tid) -> Result<Self, crate::util::error::KernelError> {
        let s = get_task_signal_struct(tid);
        if let Some(s) = &s {
            s.cred_guard
                .lock_raw_interruptible()
                .map_err(|_| crate::util::error::KernelError::RestartNoIntr)?;
        }
        Ok(Self(s))
    }
}

impl Drop for CredGuard {
    fn drop(&mut self) {
        if let Some(s) = &self.0 {
            // SAFETY: taken in CredGuard::lock by this task
            unsafe { s.cred_guard.unlock_raw() };
        }
    }
}

impl SignalStruct {
    /// Create new SignalStruct with default rlimits
    pub fn new() -> Self {
        Self {
            rlim: IrqSpinlock::new(default_rlimits()),
            cred_guard: crate::sync::Mutex::new(()),
            exec_update: crate::sync::RwSem::new(()),
            group_exit: AtomicU64::new(0),
            posix_timers: Mutex::new(crate::time::posix_timer::PosixTimerRegistry::new()),
            live: AtomicU32::new(1),
            dead_times: [AtomicU64::new(0), AtomicU64::new(0)],
            child_times: [AtomicU64::new(0), AtomicU64::new(0)],
            cputimer: crate::time::cpu_timer::GroupCputimer::new(),
        }
    }

    /// A thread leaving the group takes its (utime, stime) here (Linux
    /// __exit_signal)
    pub fn add_dead_times(&self, (u, s): (u64, u64)) {
        self.dead_times[0].fetch_add(u, Ordering::Relaxed);
        self.dead_times[1].fetch_add(s, Ordering::Relaxed);
    }

    /// (utime, stime) of the group's threads already gone
    pub fn dead_times(&self) -> (u64, u64) {
        (
            self.dead_times[0].load(Ordering::Relaxed),
            self.dead_times[1].load(Ordering::Relaxed),
        )
    }

    /// A reaped child's own and its children's (utime, stime) (Linux
    /// wait_task_zombie: psig->cutime += ...)
    pub fn add_child_times(&self, (u, s): (u64, u64)) {
        self.child_times[0].fetch_add(u, Ordering::Relaxed);
        self.child_times[1].fetch_add(s, Ordering::Relaxed);
    }

    /// (cutime, cstime)
    pub fn child_times(&self) -> (u64, u64) {
        (
            self.child_times[0].load(Ordering::Relaxed),
            self.child_times[1].load(Ordering::Relaxed),
        )
    }

    /// A thread joins the group (CLONE_THREAD)
    pub fn thread_added(&self) {
        self.live.fetch_add(1, Ordering::AcqRel);
    }

    /// A thread starts its exit with wait status `code`; true if it was
    /// the group's last live one (Linux do_exit: group_dead =
    /// atomic_dec_and_test(&live)). The last one with no group exit
    /// under way makes its status the group's (Linux
    /// synchronize_group_exit, quick_threads): a fatal signal after
    /// that starts nothing.
    pub fn thread_exiting(&self, code: Option<i32>) -> bool {
        let dead = self.live.fetch_sub(1, Ordering::AcqRel) == 1;
        if dead && let Some(c) = code {
            self.start_exit(c, true);
        }
        dead
    }

    /// The group's exit state
    pub fn group_exit(&self) -> GroupExit {
        let v = self.group_exit.load(Ordering::Acquire);
        if v & GROUP_EXIT != 0 {
            GroupExit::Exit(v as u32 as i32)
        } else if v & GROUP_EXEC != 0 {
            GroupExit::Exec(v & !GROUP_EXEC)
        } else {
            GroupExit::None
        }
    }

    /// Start a group exit with wait status `code`: false if one is under
    /// way. A fatal signal (`over_exec`) also overrides an exec's
    /// de_thread (Linux complete_signal), exit_group does not.
    fn start_exit(&self, code: i32, over_exec: bool) -> bool {
        let mut cur = self.group_exit.load(Ordering::Acquire);
        loop {
            if cur & GROUP_EXIT != 0 || (cur & GROUP_EXEC != 0 && !over_exec) {
                return false;
            }
            let new = GROUP_EXIT | u64::from(code as u32);
            match self
                .group_exit
                .compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }

    /// Start `tid`'s exec ending the other threads (de_thread): false if
    /// the group is exiting or another thread is exec'ing
    pub fn start_exec(&self, tid: Tid) -> bool {
        self.group_exit
            .compare_exchange(0, GROUP_EXEC | tid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// `tid`'s de_thread is over (unless a fatal signal took over)
    pub fn end_exec(&self, tid: Tid) {
        let _ = self.group_exit.compare_exchange(
            GROUP_EXEC | tid,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Get a resource limit
    pub fn get_rlimit(&self, resource: u32) -> Option<RLimit> {
        if resource as usize >= RLIM_NLIMITS {
            return None;
        }
        let rlim = self.rlim.lock();
        Some(rlim[resource as usize])
    }

    /// Set a limit's soft value with no checks (kernel-internal, Linux
    /// writing signal->rlim directly: acct lifts RLIMIT_FSIZE around its
    /// write); the old value
    pub fn swap_rlimit_cur(&self, resource: u32, cur: u64) -> u64 {
        let mut rlim = self.rlim.lock();
        core::mem::replace(&mut rlim[resource as usize].rlim_cur, cur)
    }

    /// Set a soft limit (RLIMIT_CPU's moves up as SIGXCPU is sent)
    pub fn set_rlimit_cur(&self, resource: u32, cur: u64) {
        if let Some(r) = self.rlim.lock().get_mut(resource as usize) {
            r.rlim_cur = cur;
        }
    }

    /// Set a resource limit (Linux do_prlimit's update): EINVAL for a
    /// bad resource or cur above max; raising the hard limit needs
    /// CAP_SYS_RESOURCE (EPERM). The old value, the decision and the
    /// store are one hold of `rlim`, as Linux under task_lock, so a
    /// racing change cannot slip a raise past the check (capable()
    /// takes no lock: a credential reference and a task flag). Returns
    /// the limit replaced.
    pub fn set_rlimit(&self, resource: u32, new: RLimit) -> Result<RLimit, i32> {
        let r = resource as usize;
        if r >= RLIM_NLIMITS || new.rlim_cur > new.rlim_max {
            return Err(-22); // EINVAL
        }
        let mut rlim = self.rlim.lock();
        let old = rlim[r];
        if new.rlim_max > old.rlim_max && !crate::task::capable(crate::task::CAP_SYS_RESOURCE) {
            return Err(-1); // EPERM
        }
        rlim[r] = new;
        Ok(old)
    }

    /// Deep clone for fork (without CLONE_THREAD)
    pub fn deep_clone(self: &Arc<Self>) -> Result<Arc<Self>, KernelError> {
        let rlim = self.rlim.lock();
        let mut new_rlim = [RLimit::default(); RLIM_NLIMITS];
        new_rlim.copy_from_slice(&*rlim);
        try_arc(Self {
            rlim: IrqSpinlock::new(new_rlim),
            cred_guard: crate::sync::Mutex::new(()),
            exec_update: crate::sync::RwSem::new(()),
            group_exit: AtomicU64::new(0),
            // Timers are not inherited (Linux copy_signal)
            posix_timers: Mutex::new(crate::time::posix_timer::PosixTimerRegistry::new()),
            live: AtomicU32::new(1),
            dead_times: [AtomicU64::new(0), AtomicU64::new(0)],
            child_times: [AtomicU64::new(0), AtomicU64::new(0)],
            cputimer: crate::time::cpu_timer::GroupCputimer::new(),
        })
    }
}

impl Default for SignalStruct {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TASK_SIGNAL Global Table
// =============================================================================

// Task.signal field accessors (SignalStruct - shared by thread group)

/// Get a task's signal struct
pub fn get_task_signal_struct(tid: Tid) -> Option<Arc<SignalStruct>> {
    let table = TASKLIST.read();
    table.get(tid).and_then(|t| t.signal.clone())
}

/// A new task's signal struct for fork/clone, and whether it is the
/// parent's; ENOMEM
///
/// If `share_signal` is true (CLONE_THREAD), share the Arc<SignalStruct>
/// (`install_fork_signal` counts the new thread live). Otherwise, deep
/// clone the signal struct.
fn fork_signal_struct(
    parent_tid: Tid,
    share_signal: bool,
) -> Result<(Arc<SignalStruct>, bool), KernelError> {
    match get_task_signal_struct(parent_tid) {
        // CLONE_THREAD: share the same SignalStruct
        Some(s) if share_signal => Ok((s, true)),
        // Fork: deep clone
        Some(s) => Ok((s.deep_clone()?, false)),
        None => Ok((try_arc(SignalStruct::new())?, false)),
    }
}

// =============================================================================
// Signal Delivery Entry Point
// =============================================================================

/// Let the tracer of a traced task see `sig` before it is delivered:
/// None if the tracer cancelled it, or if it changed it to one now
/// blocked (queued again, as Linux ptrace_signal does)
fn traced_signal(tid: Tid, info: SigInfo, action: SigAction) -> Option<(SigInfo, SigAction)> {
    let sig = info.sig();
    if sig == SIGKILL {
        return Some((info, action));
    }
    let new = crate::task::ptrace::ptrace_signal(sig);
    if new == sig {
        return Some((info, action));
    }
    if new == 0 {
        return None;
    }
    // A changed signal is the tracer's (Linux ptrace_signal)
    let info = tracer_info(tid, new);
    let blocked = with_task_signal_state(tid, |state| state.blocked.contains(new)).unwrap_or(false);
    if blocked {
        send_sig_info(tid, new, SendInfo::Info(info));
        return None;
    }
    let action = get_task_sighand(tid)?.get_action(new).unwrap_or_default();
    Some((info, action))
}

/// `sig` as the tracer of `tid` gives it: SI_USER from the tracer's
/// process and uid (Linux ptrace_signal)
fn tracer_info(tid: Tid, sig: u32) -> SigInfo {
    let tracer = TASKLIST.read().get(tid).and_then(|t| t.tracer());
    let uid = tracer.as_ref().and_then(|tr| {
        let table = TASKLIST.read();
        table.get(tr.tid()).map(|v| v.cred_arc().uid)
    });
    let pid = tracer.as_ref().map_or(0, |tr| tr.pid as i32);
    SigInfo::kill(sig, si_code::SI_USER, pid, uid.unwrap_or(0))
}

/// Signal work on the way back to user mode (Linux
/// arch_do_signal_or_restart), on the task's user registers `regs`
///
/// Delivers pending signals (handler frame, default action or ignore).
/// If `regs` is a syscall's (`in_syscall`; not rt_sigreturn's, which
/// restored a whole user context), its return value gets the restart
/// rules for the kernel-internal codes, once (`forget_syscall`):
///
/// | result         | handler runs                     | no handler |
/// |----------------|----------------------------------|------------|
/// | -ERESTARTSYS   | restart if SA_RESTART, else EINTR| restart    |
/// | -ERESTARTNOINTR| restart                          | restart    |
/// | -ERESTARTNOHAND| EINTR                            | restart    |
///
/// "Restart" backs the user PC up over the syscall instruction and restores
/// the syscall's first register, so the syscall runs again (after the
/// handler, if any).
///
/// If a syscall left a temporary mask in place (TIF_RESTORE_SIGMASK,
/// e.g. rt_sigsuspend), signals are dequeued under it and the saved mask
/// goes into the signal frame; with no frame it is restored here.
pub fn do_signal(regs: &UserFrame) {
    use crate::util::error::KernelError;

    const ERESTARTSYS: i64 = KernelError::RestartSys.sysret();
    const ERESTARTNOINTR: i64 = KernelError::RestartNoIntr.sysret();
    const EINTR: u64 = KernelError::Interrupted.sysret() as u64;

    let tid = crate::task::percpu::current_tid();
    let err = regs.ret() as i64;
    let restart = syscall_restarting(regs);
    regs.forget_syscall();

    while has_pending_signals(tid) {
        // A dying group comes before any handler (Linux get_signal)
        if group_dying(tid) {
            do_group_exit(SIGKILL as i32);
        }
        let Some((action, info)) = get_signal_to_deliver(tid) else {
            break;
        };
        // A tracee stops for its tracer first (Linux get_signal ->
        // ptrace_signal), which may cancel or change the signal
        let Some((info, action)) = traced_signal(tid, info, action) else {
            continue;
        };
        let sig = info.sig();
        match action.handler {
            SigHandler::Ignore => continue,
            SigHandler::Default => match default_action(sig) {
                // A signal queued while blocked does not kill the global
                // init either (Linux get_signal: SIGNAL_UNKILLABLE),
                // unless the kernel forced one (it lifts the protection)
                DefaultAction::Terminate | DefaultAction::Core if init_unkillable(tid) => {
                    continue;
                }
                DefaultAction::Terminate | DefaultAction::Core => {
                    // Killed by the signal: wait status = signal number,
                    // for every thread of the group
                    do_group_exit(sig as i32);
                }
                // Stop/continue are not implemented: treat as ignored
                _ => continue,
            },
            SigHandler::Handler(_) => {
                if restart {
                    let restart_now = err == ERESTARTNOINTR
                        || (err == ERESTARTSYS && action.flags & sa_flags::SA_RESTART != 0);
                    if restart_now {
                        regs.restart_syscall();
                    } else {
                        regs.set_ret(EINTR);
                    }
                }
                // A traced task's fault keeps its frame details
                let trap = with_task_signal_state(tid, |s| s.trap.take_if(|(t, _)| *t == sig))
                    .flatten()
                    .map_or(Trap::default(), |(_, t)| t);
                if deliver_to_handler(tid, sig, &action, &info, &trap, regs) {
                    return;
                }
                // Frame setup failed: SIGSEGV was forced; deliver it
                continue;
            }
        }
    }

    // No handler ran: an -ERESTART* syscall runs again (Linux
    // arch_do_signal_or_restart)
    restore_saved_sigmask();
    if restart {
        regs.restart_syscall();
    }
}

/// The syscall returning on `regs` asks for a restart (-ERESTARTSYS,
/// -ERESTARTNOINTR, -ERESTARTNOHAND): only `do_signal` may turn that
/// into a result. A plain register test, no lock.
pub fn syscall_restarting(regs: &UserFrame) -> bool {
    use crate::util::error::KernelError;
    const FIRST: i64 = KernelError::RestartSys.sysret();
    const LAST: i64 = KernelError::RestartNoHand.sysret();
    regs.in_syscall() && (LAST..=FIRST).contains(&(regs.ret() as i64))
}

/// Install `new` as a temporary mask for the current syscall (Linux
/// set_user_sigmask after copy-in): the old one goes to `saved_sigmask`
/// and TIF_RESTORE_SIGMASK, put back on the way out or saved in a
/// handler's frame. Returns the old mask.
pub fn set_temp_sigmask(new: SigSet) -> Option<SigSet> {
    let me = crate::task::percpu::current();
    let old = with_task_signal_state(me.tid(), |state| {
        state.saved_sigmask = state.blocked;
        state.blocked = new.blockable();
        state.saved_sigmask
    })?;
    me.set_tif(crate::task::tif::RESTORE_SIGMASK);
    Some(old)
}

/// Read a sigset_t from user memory and install it as the syscall's
/// temporary mask (Linux set_user_sigmask); a null `umask` changes
/// nothing. Errors: EINVAL (size), EFAULT.
pub fn set_user_sigmask(
    umask: u64,
    sigsetsize: u64,
) -> Result<(), crate::util::error::KernelError> {
    use crate::util::error::KernelError;
    if umask == 0 {
        return Ok(());
    }
    if sigsetsize != 8 {
        return Err(KernelError::InvalidArgument);
    }
    let bits = crate::uaccess::get_user::<crate::arch::Uaccess, u64>(umask)
        .map_err(|_| KernelError::BadAddress)?;
    set_temp_sigmask(SigSet::from_bits(bits));
    Ok(())
}

/// Put back the mask a syscall replaced, if it did (Linux
/// restore_saved_sigmask): lock-free when TIF_RESTORE_SIGMASK is clear
pub fn restore_saved_sigmask() {
    let me = crate::task::percpu::current();
    if me.test_and_clear_tif(crate::task::tif::RESTORE_SIGMASK) {
        with_task_signal_state(me.tid(), |state| state.blocked = state.saved_sigmask);
    }
}

/// Like [`restore_saved_sigmask`], unless the syscall was `interrupted`
/// by a signal: then the temporary mask stays for its delivery, and
/// `do_signal` saves or restores the old one (Linux
/// restore_saved_sigmask_unless)
pub fn restore_saved_sigmask_unless(interrupted: bool) {
    if !interrupted {
        restore_saved_sigmask();
    }
}

/// Set up the handler frame for `sig` on `regs`; false if that failed
/// (SIGSEGV forced)
fn deliver_to_handler(
    tid: Tid,
    sig: u32,
    action: &SigAction,
    info: &SigInfo,
    trap: &Trap,
    regs: &UserFrame,
) -> bool {
    use crate::arch::signal;

    // Mask to save in the frame (restored by rt_sigreturn): the
    // pre-syscall mask if a temporary one is in effect, else current
    // (Linux sigmask_to_save)
    let me = crate::task::percpu::current();
    let restore = me.has_tif(crate::task::tif::RESTORE_SIGMASK);
    let frame_mask = with_task_signal_state(tid, |state| {
        if restore {
            state.saved_sigmask
        } else {
            state.blocked
        }
    })
    .unwrap_or(SigSet::EMPTY);

    match signal::setup_rt_frame(sig, action, frame_mask, info, trap, regs) {
        Ok(()) => {
            // The saved mask now lives in the frame (Linux
            // signal_delivered -> clear_restore_sigmask)
            me.clear_tif(crate::task::tif::RESTORE_SIGMASK);
            // Block action.mask and the signal itself (unless SA_NODEFER)
            with_task_signal_state(tid, |state| {
                state.blocked = state.blocked.union(&action.mask);
                if action.flags & sa_flags::SA_NODEFER == 0 {
                    state.blocked.add(sig);
                }
                // SIGKILL/SIGSTOP are never blockable, whatever sa_mask
                // or the signal is
                state.blocked = state.blocked.blockable();
            });
            true
        }
        Err(_) => {
            // Frame setup failed (invalid stack) - force SIGSEGV
            restore_saved_sigmask();
            force_sigsegv(tid);
            false
        }
    }
}

/// Force `sig` on task `tid` (Linux force_sig_info_to_task with
/// HANDLER_CURRENT): if blocked or ignored, its action goes back to
/// SIG_DFL and it is unblocked, so it cannot be dodged; a handler that
/// is not blocked still runs. Delivered on the way back to user mode.
pub fn force_sig(tid: Tid, sig: u32) {
    force_send(tid, sig, SendInfo::Kernel);
}

/// [`force_sig`] with `info` (Linux force_sig_info)
pub fn force_sig_info(tid: Tid, info: SigInfo) {
    force_send(tid, info.sig(), SendInfo::Info(info));
}

fn force_send(tid: Tid, sig: u32, info: SendInfo) {
    let sighand = get_task_sighand(tid);
    let ignored = sighand
        .as_ref()
        .and_then(|h| h.get_action(sig))
        .is_some_and(|a| a.handler == SigHandler::Ignore);
    let blocked = with_task_signal_state(tid, |s| s.blocked.contains(sig)).unwrap_or(false);
    if blocked || ignored {
        if let Some(h) = &sighand {
            let _ = h.set_action(sig, SigAction::default());
        }
        with_task_signal_state(tid, |s| s.blocked.remove(sig));
    }
    send_signal_force(tid, sig, info, PidType::Pid, true);
}

/// Force delivery of SIGSEGV (for stack errors during signal setup)
///
/// Like Linux force_sigsegv: the handler is reset to SIG_DFL and SIGSEGV is
/// unblocked, so the task is killed on its way back to user space.
pub fn force_sigsegv(tid: Tid) {
    // Reset SIGSEGV to default action
    if let Some(sighand) = get_task_sighand(tid) {
        let _ = sighand.set_action(SIGSEGV, SigAction::default());
    }
    with_task_signal_state(tid, |state| state.blocked.remove(SIGSEGV));
    // Send SIGSEGV to self, forced: it kills even the global init (Linux
    // force_sig_info_to_task clears SIGNAL_UNKILLABLE for SIG_DFL)
    send_signal_force(tid, SIGSEGV, SendInfo::Kernel, PidType::Pid, true);
}

/// A synchronous fault in user mode (page fault, illegal instruction, ...)
///
/// Linux force_sig_fault semantics, delivered at once (the faulting
/// instruction must not run again first):
/// - a handler that is not blocked: its frame is set up now, on `regs`
///   (the fault's user registers, the task's pt_regs), which the return
///   to user mode then enters. If the frame cannot be written the task
///   dies by SIGSEGV (force_sigsegv).
/// - blocked or ignored: the action is reset to SIG_DFL and the signal
///   unblocked (force_sig_info_to_task); the default action of every
///   synchronous fault signal (SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP) kills
///   the task, as does SIG_DFL.
///
/// Process context (the faulting task), interrupts enabled.
pub fn force_sig_fault(info: SigInfo, trap: Trap, regs: &UserFrame) {
    let do_exit = do_group_exit;
    let sig = info.sig();

    let tid = crate::task::percpu::current_tid();
    // A traced task's fault signal is queued like any other, so the
    // tracer sees its signal-delivery stop first (Linux force_sig_fault
    // -> get_signal -> ptrace_signal); delivered on the way back to user
    // space, it is unblocked and not ignored, as force_sig makes it
    if crate::task::ptrace::is_traced(tid) {
        with_task_signal_state(tid, |s| s.trap = Some((sig, trap)));
        force_sig_info(tid, info);
        return;
    }
    let sighand = get_task_sighand(tid);
    let action = sighand
        .as_ref()
        .and_then(|h| h.get_action(sig))
        .unwrap_or_default();
    let blocked = with_task_signal_state(tid, |s| s.blocked.contains(sig)).unwrap_or(true);

    if let SigHandler::Handler(_) = action.handler
        && !blocked
    {
        if deliver_to_handler(tid, sig, &action, &info, &trap, regs) {
            return;
        }
        // No room for the frame: SIGSEGV was reset to SIG_DFL and queued
        do_exit(SIGSEGV as i32);
    }

    if blocked || action.handler == SigHandler::Ignore {
        if let Some(h) = &sighand {
            let _ = h.set_action(sig, SigAction::default());
        }
        with_task_signal_state(tid, |s| {
            s.blocked.remove(sig);
        });
    }
    do_exit(sig as i32);
}

/// rt_sigreturn found an unusable frame (Linux badframe): kill the caller
/// with SIGSEGV. Returns -EFAULT for the (never seen) syscall result.
pub fn sigreturn_badframe() -> i64 {
    force_sigsegv(crate::task::percpu::current_tid());
    -14 // EFAULT
}
