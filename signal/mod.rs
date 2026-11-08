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
mod sig;
pub mod siginfo;
pub mod syscall;

pub use pending::{SigPending, SigQueue};
pub use sig::*;

use crate::sync::spin::Mutex;
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::{IrqSpinlock, UserFrame};
use crate::task::{Pid, Tid};

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
const SYNCHRONOUS_MASK: u64 =
    SIGSEGV.bit() | SIGBUS.bit() | SIGILL.bit() | SIGTRAP.bit() | SIGFPE.bit() | SIGSYS.bit();

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

    /// `sig` is in the set
    pub const fn contains(&self, sig: Signal) -> bool {
        self.0 & sig.bit() != 0
    }

    /// Add `sig`
    pub fn add(&mut self, sig: Signal) {
        self.0 |= sig.bit();
    }

    /// Remove `sig`
    pub fn remove(&mut self, sig: Signal) {
        self.0 &= !sig.bit();
    }

    /// The set of `sig` alone (Linux sigmask)
    pub const fn of(sig: Signal) -> SigSet {
        SigSet(sig.bit())
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

    /// The lowest signal in the set
    pub fn first(&self) -> Option<Signal> {
        Signal::new(self.0.trailing_zeros() + 1)
    }
}

/// Signals that cannot be caught, blocked, or ignored
pub const UNMASKABLE_SIGNALS: SigSet = SigSet(SIGKILL.bit() | SIGSTOP.bit());

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

pub use siginfo::{SigFields, SigInfo, UserSigInfo, si_code};

/// A thread's last fault's arch details, which every signal frame's
/// sigcontext reports, not siginfo (Linux thread.trap_nr, error_code
/// and cr2 on x86-64, thread.fault_code and fault_address on arm64)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Trap {
    /// x86-64: sigcontext.trapno (exception vector)
    pub trapno: u64,
    /// x86-64: sigcontext.err (exception error code); arm64: ESR_EL1
    /// (reported in an esr_context record when non-zero)
    pub error: u64,
    /// x86-64: sigcontext.cr2; arm64: sigcontext.fault_address
    pub addr: u64,
}

impl Trap {
    /// No fault yet
    pub const NONE: Self = Self {
        trapno: 0,
        error: 0,
        addr: 0,
    };
}

/// What a fault changes of its thread's [`Trap`]
#[derive(Debug, Clone, Copy)]
pub enum TrapSet {
    /// Nothing (arm64 BRK: Linux arm64_force_sig_fault alone)
    Keep,
    /// The vector and error code, not the address (x86-64 do_trap)
    Code { trapno: u64, error: u64 },
    /// Everything (a page fault: set_signal_archinfo, set_thread_esr;
    /// arm64_notify_die with address 0)
    All(Trap),
}

impl TrapSet {
    fn apply(self, t: &mut Trap) {
        match self {
            Self::Keep => {}
            Self::Code { trapno, error } => {
                t.trapno = trapno;
                t.error = error;
            }
            Self::All(n) => *t = n,
        }
    }
}

/// si_code for a SIGSEGV at user address `addr` (Linux bad_area vs
/// bad_area_access_error): SEGV_ACCERR if a VMA of the current task
/// covers it, else SEGV_MAPERR
pub fn segv_code(addr: u64) -> i32 {
    let mapped = crate::task::percpu::current()
        .mm()
        .is_some_and(|mm| mm.mmap_read().find_vma(addr).is_some());
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

    /// As `sig`'s action, it discards it (Linux sig_handler_ignored):
    /// SIG_IGN, or SIG_DFL for a signal whose default is to ignore it
    pub fn ignores(&self, sig: Signal) -> bool {
        match self.handler {
            SigHandler::Ignore => true,
            SigHandler::Default => sig.kernel_ignore(),
            SigHandler::Handler(_) => false,
        }
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
    /// Signal actions, one per signal at [`Signal::idx`] (Linux
    /// action[sig - 1]), built in the heap: the array moved through
    /// fork's stack frames used ~9 KB of the 16 KB kernel stack
    action: IrqSpinlock<Box<[SigAction]>>,
    /// Readers and pollers of a signalfd among the tasks sharing this
    /// table (Linux sighand->signalfd_wqh): woken by every signal sent
    /// to one of them
    pub signalfd_wq: crate::sync::waitqueue::WaitQueue,
    /// Tasks whose `Task.sighand` it is (Linux sighand->count), changed
    /// and read under TASKLIST with that field
    users: crate::task::TableCell<u32>,
}

/// A handler table with every action at its default
fn default_actions() -> Box<[SigAction]> {
    alloc::vec![SigAction::new(); NSIG as usize].into_boxed_slice()
}

impl SigHand {
    /// Create a new signal handler table with all defaults
    pub fn new() -> Self {
        Self {
            action: IrqSpinlock::new(default_actions()),
            signalfd_wq: crate::sync::waitqueue::WaitQueue::new(),
            users: crate::task::TableCell::new(0),
        }
    }

    /// One more task uses it (under TASKLIST's write lock)
    fn get(&self, table: &mut crate::task::percpu::GlobalTaskTable) {
        *self.users.access_mut(table) += 1;
    }

    /// One task fewer uses it (under TASKLIST's write lock)
    fn put(&self, table: &mut crate::task::percpu::GlobalTaskTable) {
        let n = self.users.access_mut(table);
        *n = n.saturating_sub(1);
    }

    /// `sig`'s action
    pub fn get_action(&self, sig: Signal) -> SigAction {
        self.action.lock()[sig.idx()].clone()
    }

    /// The (ignored, caught) masks: signals whose handler is SIG_IGN, and
    /// those with a handler of their own (Linux collect_sigign_sigcatch),
    /// read in one hold of the table
    pub fn ign_cgt(&self) -> (u64, u64) {
        let (mut ign, mut cgt) = (0, 0);
        for (i, a) in self.action.lock().iter().enumerate() {
            let bit = 1 << i;
            match a.handler {
                SigHandler::Ignore => ign |= bit,
                SigHandler::Handler(_) => cgt |= bit,
                SigHandler::Default => {}
            }
        }
        (ign, cgt)
    }

    /// Set `sig`'s action; the old one, or EINVAL for SIGKILL and
    /// SIGSTOP, whose action cannot change (Linux do_sigaction)
    pub fn set_action(&self, sig: Signal, action: SigAction) -> Result<SigAction, KernelError> {
        if sig.kernel_only() {
            return Err(KernelError::InvalidArgument);
        }
        let mut actions = self.action.lock();
        Ok(core::mem::replace(&mut actions[sig.idx()], action))
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
            users: crate::task::TableCell::new(0),
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
        for action in actions.iter_mut() {
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

/// Per-task signal state (NOT shared via CLONE_SIGHAND)
///
/// Each task has its own blocked mask and private pending signals;
/// `shared_pending` reaches its thread group's (in its SignalStruct).
pub struct TaskSignalState {
    /// Blocked signal mask
    pub blocked: SigSet,
    /// The mask before a syscall's temporary one (rt_sigsuspend, ppoll,
    /// pselect6, epoll_pwait): valid while the task's TIF_RESTORE_SIGMASK
    /// is set (Linux saved_sigmask)
    pub saved_sigmask: SigSet,
    /// Pending signals for this task (private)
    pub pending: SigPending,
    /// Its thread group's pending signals
    pub shared_pending: SharedPending,
    /// Alternate signal stack
    pub altstack: AltStack,
    /// The mask before sigtimedwait unblocked the awaited signals
    /// (Linux real_blocked): such a signal does not kill on arrival
    pub real_blocked: SigSet,
    /// The last fault's sigcontext details (Linux thread.trap_nr,
    /// error_code, cr2 / fault_code, fault_address)
    pub trap: Trap,
}

/// A thread group's pending signals (Linux signal->shared_pending) and
/// the thread that last took one (signal->curr_target)
pub struct GroupPending {
    pub pending: SigPending,
    curr_target: Tid,
}

impl GroupPending {
    const fn new() -> Self {
        Self {
            pending: SigPending::new(),
            curr_target: 0,
        }
    }
}

impl core::ops::Deref for GroupPending {
    type Target = SigPending;
    fn deref(&self) -> &SigPending {
        &self.pending
    }
}

impl core::ops::DerefMut for GroupPending {
    fn deref_mut(&mut self) -> &mut SigPending {
        &mut self.pending
    }
}

/// A task's thread group, for its shared pending set (Linux t->signal):
/// none for a kernel thread or an exited task, which read as empty
#[derive(Clone, Default)]
pub struct SharedPending(Option<Arc<SignalStruct>>);

/// What an absent group's set reads as; nothing is ever queued on it
static NO_SHARED: Mutex<GroupPending> = Mutex::new(GroupPending::new());

impl SharedPending {
    /// The group's set
    pub fn lock(&self) -> crate::sync::spin::MutexGuard<'_, GroupPending> {
        self.0.as_ref().map_or(&NO_SHARED, |s| &s.shared).lock()
    }

    /// The group's set, if the task has a group
    fn group(&self) -> Option<crate::sync::spin::MutexGuard<'_, GroupPending>> {
        self.0.as_ref().map(|s| s.shared.lock())
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
            trap: Trap::NONE,
        }
    }

    /// A task's state with no group yet (a kernel thread; a user task
    /// gets its group from `fork_signal` or `init_task_signal`)
    pub fn new() -> Self {
        Self::with_shared(SharedPending(None))
    }

    fn with_shared(shared_pending: SharedPending) -> Self {
        Self {
            blocked: SigSet::EMPTY,
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(),
            shared_pending,
            altstack: AltStack::new(),
            real_blocked: SigSet::EMPTY,
            trap: Trap::NONE,
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

// =============================================================================
// Task signal accessors - uses Task struct fields directly via TASKLIST
// =============================================================================

use crate::task::Task;
use crate::task::percpu::{TASKLIST, TaskRef};

// =============================================================================
// Task Signal APIs
// =============================================================================

/// Initialize signal state for new task `t`
///
/// Called when creating the init process at boot (failure cannot be
/// reported). Also initializes the SignalStruct (which contains rlimits).
pub fn init_task_signal(t: &Task, sighand: Arc<SigHand>) {
    // Built before TASKLIST is taken, with init's limits (init_rlimits)
    let s = arc_nofail(SignalStruct::new());
    // The global init (Linux init_signals: SIGNAL_UNKILLABLE)
    s.set_unkillable();
    let state = TaskSignalState::with_shared(SharedPending(Some(s.clone())));
    let mut table = TASKLIST.write();
    if table.view(t).is_some() {
        sighand.get(&mut table);
    }
    if let Some(mut task) = table.view_mut(t) {
        task.set_sighand(sighand);
        *task.task.sig.lock() = state;
        task.task.set_sigpending(false);
        task.task.set_cpu_group(&s);
        task.set_signal(s);
    }
}

/// Task `t`'s signal handlers
pub fn get_task_sighand(t: &Task) -> Option<Arc<SigHand>> {
    TASKLIST.read().view(t)?.sighand().cloned()
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
pub fn disposition(sig: Signal) -> Disposition {
    let me = crate::task::percpu::current();
    if with_task_signal_state(&me, |st| st.blocked.contains(sig)).unwrap_or(false) {
        return Disposition::Ignored;
    }
    match get_task_sighand(&me).map(|h| h.get_action(sig).handler) {
        Some(SigHandler::Ignore) => Disposition::Ignored,
        Some(SigHandler::Handler(_)) => Disposition::Caught,
        _ => Disposition::Default,
    }
}

/// Access task `t`'s signal state for modification; None once it is
/// reaped
///
/// Afterwards the task's TIF_SIGPENDING flag is recomputed, so it always
/// means "a signal is deliverable under the current blocked mask" (what
/// interruptible sleeps test via `signal_pending()`).
pub fn with_task_signal_state<F, R>(t: &Task, f: F) -> Option<R>
where
    F: FnOnce(&mut TaskSignalState) -> R,
{
    // The current task's own state needs no TASKLIST: it cannot leave
    // the task list while it runs
    let me = crate::task::percpu::current();
    let listed = (me.is(t) && t.tid() != 0) || TASKLIST.read().view(t).is_some();
    listed.then(|| with_sig(t, |_, s| f(s)))
}

/// Run `f` on task `t`'s signal state under its Task.sig, then
/// recompute its TIF_SIGPENDING; group signals it newly blocked go to
/// another thread (Linux __set_task_blocked: retarget_shared_pending)
fn with_sig<F, R>(t: &Task, f: F) -> R
where
    F: FnOnce(&Task, &mut TaskSignalState) -> R,
{
    let mut s = t.sig.lock();
    let old = s.blocked;
    let r = f(t, &mut s);
    let newly = s.blocked.subtract(&old);
    let moved = if newly.any() {
        s.shared_pending.lock().signal.intersect(&newly)
    } else {
        SigSet::EMPTY
    };
    t.set_sigpending(s.has_deliverable_signals());
    drop(s);
    if moved.any() {
        retarget(t, moved);
    }
    r
}

/// Group signals `which` that `t` will not take (blocked, or exiting):
/// wake other threads that will (Linux retarget_shared_pending)
fn retarget(t: &Task, which: SigSet) {
    let others = crate::task::percpu::GlobalTaskTable::collect_threads(t.pid, |_, u| {
        (!core::ptr::eq(u.task, t)).then(|| crate::task::percpu::task_ref(u.task))
    });
    let mut left = which;
    for u in others {
        if u.has_flag(crate::task::pf::EXITING) {
            continue;
        }
        let blocked = u.sig.lock().blocked;
        if left.subtract(&blocked).is_empty() {
            continue;
        }
        // It takes those it does not block
        left = left.intersect(&blocked);
        if !u.sigpending() {
            with_sig(&u, |_, _| ());
            signal_wake_task(&u, crate::task::percpu::WakeMode::Interruptible);
        }
        if left.is_empty() {
            break;
        }
    }
}

/// The current thread starts its exit: group signals it would have
/// taken go to another thread (Linux exit_signals)
#[inline(never)]
pub fn exit_signals() {
    let me = crate::task::percpu::current();
    if !me.sigpending() {
        return;
    }
    let which = {
        let s = me.sig.lock();
        let shared = s.shared_pending.lock().signal;
        shared.subtract(&s.blocked)
    };
    if which.any() {
        retarget(&me, which);
    }
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
    parent: &Task,
    share_sighand: bool,
    share_pending: bool,
    clear_sighand: bool,
) -> Result<(TaskSignalState, ForkSignal), KernelError> {
    // Get parent's sighand and signal_state
    // The parent's blocked mask and shared set (no queued info is
    // copied: a child starts with nothing pending)
    let (parent_sighand, parent_state) = {
        let table = TASKLIST.read();
        let parent = table.view(parent);
        (
            parent.and_then(|p| p.sighand().cloned()),
            parent.map(|p| {
                let s = p.task.sig.lock();
                (s.blocked, s.trap)
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

    // Clone or share SignalStruct (contains rlimits and the shared
    // pending set): CLONE_THREAD shares it
    let (signal, joined) = fork_signal_struct(parent, share_pending)?;

    // Clone per-task signal state
    let shared_pending = SharedPending(Some(signal.clone()));
    let child_state = match parent_state {
        Some((blocked, trap)) => TaskSignalState {
            blocked, // Inherit blocked mask
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(), // Fresh private pending
            shared_pending,
            altstack: AltStack::new(), // Child starts with no altstack
            real_blocked: SigSet::EMPTY,
            // The thread struct is copied (Linux arch_dup_task_struct)
            trap,
        },
        None => TaskSignalState::with_shared(shared_pending),
    };
    let fork = ForkSignal {
        sighand: child_sighand,
        signal,
        share_signal: share_pending,
        joined,
    };
    Ok((child_state, fork))
}

impl ForkSignal {
    /// The new process is its pid namespace's init (Linux
    /// copy_process: SIGNAL_UNKILLABLE for is_child_reaper), set
    /// before it is visible
    pub fn set_unkillable(&self) {
        self.signal.set_unkillable();
    }
}

/// Attach new task `child`'s shared signal objects, once it is in
/// TASKLIST
pub fn install_fork_signal(child: &Task, f: ForkSignal) {
    if f.joined {
        // CLONE_THREAD: one more live thread
        f.signal.thread_added();
    }
    if !f.share_signal {
        // An inherited finite RLIMIT_CPU is watched from the start (Linux
        // posix_cpu_timers_init_group)
        crate::time::cpu_timer::rlimit_cpu_changed(&f.signal, child.tid());
    }
    let mut table = TASKLIST.write();
    if table.view(child).is_some() {
        f.sighand.get(&mut table);
    }
    if let Some(mut c) = table.view_mut(child) {
        c.set_sighand(f.sighand);
        c.task.set_cpu_group(&f.signal);
        c.set_signal(f.signal);
    }
}

/// Clean up task `t`'s signal state on its exit
pub fn exit_task_signal(t: &Task) {
    // Released after TASKLIST (nothing is released under it): the
    // queued signals with the rest (Linux flush_sigqueue in
    // __exit_signal); an exiting task gets no more queued (send_locked)
    let _old = {
        let mut table = TASKLIST.write();
        let old = table.view_mut(t).map(|mut task| {
            let old = core::mem::replace(&mut *task.task.sig.lock(), TaskSignalState::boot());
            task.task.set_sigpending(false);
            // A zombie leader keeps the group's SignalStruct (its exit
            // status; Linux frees signal_struct with the reaped leader)
            let signal = if task.leader() {
                None
            } else {
                // Its CPU time stays the group's (Linux __exit_signal)
                let t = task.task.cputime(crate::time::monotonic_ns());
                if let Some(s) = task.signal() {
                    s.add_dead_times(t);
                }
                task.take_signal()
            };
            (task.take_sighand(), signal, old)
        });
        if let Some((Some(h), _, _)) = &old {
            h.put(&mut table);
        }
        old
    };
}

// =============================================================================
// Signal Sending
// =============================================================================

/// What an exec does to the caller's signals (Linux begin_new_exec):
/// a handler table shared with another process (CLONE_SIGHAND) is
/// copied first (unshare_sighand: ENOMEM), then caught signals go back
/// to SIG_DFL (flush_signal_handlers; ignored ones stay ignored), the
/// alternate stack is forgotten (sas_ss_sp = 0), and the process's
/// timer_create timers are deleted with their queued signals
/// (posixtimer_exec). Blocked and pending signals stay. The caller is
/// its process's only thread (after de_thread).
pub fn exec_signals() -> Result<(), KernelError> {
    let me = crate::task::percpu::current();
    let Some(old) = get_task_sighand(&me) else {
        return Ok(());
    };
    // Shared with another task (Linux unshare_sighand: sighand->count
    // above one)
    let shared = *old.users.access(&TASKLIST.read()) > 1;
    if shared {
        let new = old.deep_clone()?;
        // The old reference goes after TASKLIST
        let _old = {
            let mut table = TASKLIST.write();
            if table.view(&me).is_some() {
                new.get(&mut table);
            }
            let prev = table.view_mut(&me).and_then(|mut t| t.set_sighand(new));
            if let Some(p) = &prev {
                p.put(&mut table);
            }
            prev
        };
    }
    if let Some(h) = get_task_sighand(&me) {
        h.flush_handlers();
    }
    if let Some(sig) = get_task_signal_struct(&me) {
        crate::time::posix_timer::exec_timers(&sig);
    }
    let _gone = with_task_signal_state(&me, |s| {
        s.altstack = AltStack::new();
        let shared = s.shared_pending.lock().flush_timers();
        (s.pending.flush_timers(), shared)
    });
    Ok(())
}

/// The current thread group's pending `sig` is discarded, every queued
/// instance with it (Linux do_sigaction once the action ignores it:
/// POSIX, whether or not it is blocked)
pub fn flush_group_signal(sig: Signal) {
    let mask = SigSet::of(sig);
    // The group's set through its SignalStruct, not a thread's view of
    // it (an exited leader's reads as empty); freed after the lock
    if let Some(s) = get_task_signal_struct(&crate::task::percpu::current()) {
        let _gone = s.shared.lock().flush_mask(&mask);
    }
    let threads = crate::task::percpu::GlobalTaskTable::collect_threads(
        crate::task::percpu::current_pid(),
        |_, t| Some(crate::task::percpu::task_ref(t.task)),
    );
    for t in &threads {
        // Freed here, after the thread's lock is dropped
        let _gone = with_task_signal_state(t, |s| s.pending.flush_mask(&mask));
    }
}

/// SIGKILL is pending for the current task (Linux
/// fatal_signal_pending): killable sleeps end on it
pub fn fatal_signal_pending() -> bool {
    task_fatal_pending(&crate::task::percpu::current())
}

/// SIGKILL is pending for task `t` (Linux __fatal_signal_pending)
pub fn task_fatal_pending(t: &crate::task::Task) -> bool {
    // SIGKILL cannot be blocked: pending, it sets TIF_SIGPENDING
    if !t.sigpending() {
        return false;
    }
    let s = t.sig.lock();
    s.pending.signal.contains(SIGKILL) || s.shared_pending.lock().signal.contains(SIGKILL)
}

/// Whether `sig` would be discarded on arrival (Linux sig_ignored): its
/// handler is SIG_IGN, or SIG_DFL with an "ignore" default (SIGCHLD,
/// SIGURG, SIGWINCH, and SIGCONT, which hk does not act on), and it is not
/// blocked (a blocked signal stays queued: the handler may change), nor
/// awaited by sigtimedwait (blocked before it: real_blocked)
fn sig_ignored(state: &TaskSignalState, sighand: Option<&Arc<SigHand>>, sig: Signal) -> bool {
    let held = state.blocked.contains(sig) || state.real_blocked.contains(sig);
    if held || sig.kernel_only() {
        return false;
    }
    sighand.is_some_and(|h| h.get_action(sig).ignores(sig))
}

/// The current thread's group is a namespace init's, still
/// SIGNAL_UNKILLABLE (Linux get_signal's check)
fn current_unkillable(me: &Task) -> bool {
    get_task_signal_struct(me).is_some_and(|s| s.unkillable())
}

/// Linux sig_task_ignored for a protected init (`Send.init`): SIGKILL
/// and SIGSTOP never reach it, nor any signal whose action is SIG_DFL
/// (so a stray SIGTERM or SIGPIPE does not kill it). A blocked signal
/// is still queued (its action may change before it is unblocked). A
/// kernel-forced signal never gets here: it lifts the protection
/// (`send_signal_force`), and SIGKILL or SIGSTOP from an ancestor
/// namespace is not protected against ([`Target::protects`]).
fn init_ignores(state: &TaskSignalState, sighand: Option<&Arc<SigHand>>, sig: Signal) -> bool {
    if sig.kernel_only() {
        return true;
    }
    if state.blocked.contains(sig) || state.real_blocked.contains(sig) {
        return false;
    }
    sighand.is_none_or(|h| h.get_action(sig).is_default())
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
    /// The info queued for `sig` at a receiver in pid namespace `ns`
    /// (Linux __send_signal_locked's switch: SEND_SIG_NOINFO names the
    /// sender's process as `ns` numbers it)
    fn resolve(&self, sig: Signal, ns: &crate::ns::PidNamespace) -> SigInfo {
        match self {
            Self::User => {
                let me = crate::task::percpu::current_pid();
                let pid = crate::task::pid::nr_ns(me, ns) as i32;
                SigInfo::kill(sig, si_code::SI_USER, pid, crate::task::current_cred().uid)
            }
            Self::Kernel => SigInfo::kill(sig, si_code::SI_KERNEL, 0, 0),
            Self::Info(i) => *i,
        }
    }

    /// [`resolve`](Self::resolve) for a send that checks its sender
    /// (Linux send_signal_locked): an info whose sender `ns` does not
    /// see names none
    /// SIGKILL and SIGSTOP with it reach a namespace init (Linux
    /// send_signal_locked's `force`): from the kernel, or from a sender
    /// outside the receiver's namespace `ns` (an ancestor's), with an
    /// info that names its sender
    fn forces(&self, ns: &crate::ns::PidNamespace) -> bool {
        let outside = || !crate::task::pid::current_in(ns);
        match self {
            Self::User => outside(),
            Self::Kernel => true,
            Self::Info(i) => i.has_sender() && (i.code == si_code::SI_KERNEL || outside()),
        }
    }

    fn resolve_checked(&self, sig: Signal, ns: &crate::ns::PidNamespace) -> SigInfo {
        let mut i = self.resolve(sig, ns);
        if matches!(self, Self::Info(_))
            && ns.level != 0
            && crate::task::pid::nr_ns(crate::task::percpu::current_tid(), ns) == 0
        {
            i.hide_sender();
        }
        i
    }

    /// A non-RT signal's entry may pass RLIMIT_SIGPENDING unless a user
    /// queued it (si_code < 0); an RT one never does (Linux
    /// __send_signal_locked's override_rlimit)
    fn override_rlimit(&self, sig: Signal) -> bool {
        !sig.is_rt() && !matches!(self, Self::Info(i) if i.code < 0)
    }

    /// With no entry, the send fails with EAGAIN: an RT signal a user
    /// queued with info other than kill's (Linux: queue overflow)
    fn must_queue(&self, sig: Signal) -> bool {
        sig.is_rt() && matches!(self, Self::Info(i) if i.code != si_code::SI_USER)
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
/// ESRCH or EAGAIN as [`send_sig_info`].
pub fn send_signal(t: &Task, sig: Signal) -> KernelResult<()> {
    send_sig_info(t, sig, SendInfo::User)
}

/// Send `sig` with `info` to task `t` alone (Linux send_sig_info,
/// PIDTYPE_PID, with no permission check): ESRCH (reaped), EINVAL, or
/// EAGAIN when an RT signal's info cannot be queued
pub fn send_sig_info(t: &Task, sig: Signal, info: SendInfo) -> KernelResult<()> {
    send_task(t, sig, info, PidType::Pid, false)
}

/// Whom a signal is for (Linux enum pid_type, the two a send uses)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidType {
    /// The thread (PIDTYPE_PID)
    Pid,
    /// Its whole thread group (PIDTYPE_TGID)
    Tgid,
}

/// The receiver of a send, read under TASKLIST while it is still listed
/// (a reaped task is gone, whatever reuses its number): a kernel
/// thread, the global init, its group exiting, in a ptrace stop, its
/// real uid, RLIMIT_SIGPENDING, handlers and group
struct Target {
    kthread: bool,
    /// A thread of the global init (Linux is_global_init)
    global: bool,
    group_exit: bool,
    stopped: bool,
    uid: crate::task::Uid,
    limit: u64,
    sighand: Option<Arc<SigHand>>,
    signal: Option<Arc<SignalStruct>>,
}

impl Target {
    /// An init's protection applies to `sig` (Linux sig_task_ignored):
    /// SIGKILL and SIGSTOP never reach the global init; a
    /// SIGNAL_UNKILLABLE group takes no signal whose action is SIG_DFL
    /// but SIGKILL or SIGSTOP from the kernel or an ancestor namespace
    /// (`forced`, [`SendInfo::forces`])
    fn protects(&self, sig: Signal, forced: bool) -> bool {
        let kernel_only = sig.kernel_only();
        let unkillable = self.signal.as_ref().is_some_and(|s| s.unkillable());
        (self.global && kernel_only) || (unkillable && !(forced && kernel_only))
    }
}

fn target(t: &Task) -> Option<Target> {
    target_in(&TASKLIST.read(), t)
}

/// [`target`] under TASKLIST held by the caller
fn target_in(table: &crate::task::percpu::GlobalTaskTable, t: &Task) -> Option<Target> {
    let v = table.view(t)?;
    let sig = v.signal();
    let limit = sig.and_then(|s| s.get_rlimit(RLIMIT_SIGPENDING));
    Some(Target {
        kthread: v.task.has_flag(crate::task::pf::KTHREAD),
        global: v.task.pid == 1,
        group_exit: sig.is_some_and(|s| matches!(s.group_exit(), GroupExit::Exit(_))),
        stopped: matches!(v.state(), crate::task::TaskState::Traced(_)),
        uid: v.cred_arc().uid,
        limit: limit.map_or(0, |r| r.rlim_cur),
        sighand: v.sighand().cloned(),
        signal: sig.cloned(),
    })
}

/// How a send went under the receiver's lock
enum Sent {
    /// Discarded on arrival, or already pending (a non-RT signal)
    Dropped,
    /// No entry for an RT signal that needed one
    Overflow,
    /// Pending; the receiver itself wants it (Linux wants_signal)
    Queued(bool),
}

/// Send `sig` with `info` to task `t`, for it (`ty` Pid) or its thread
/// group (Linux send_signal_locked, complete_signal); `force` (a
/// kernel-forced signal, Linux force_sig) is delivered to a namespace
/// init even with its action SIG_DFL. ESRCH once `t` is reaped.
fn send_task(t: &Task, sig: Signal, info: SendInfo, ty: PidType, force: bool) -> KernelResult<()> {
    check_send_context();
    // Kernel threads ignore every signal (Linux ignore_signals in
    // kthreadd): they are processes now (pid == tid), reachable by
    // kill(-1) and kill(pid). One lookup also finds the global init.
    let Some(tg) = target(t) else {
        return Err(KernelError::NoProcess);
    };
    // A dying group takes no more signals (Linux prepare_signal:
    // SIGNAL_GROUP_EXIT; its threads have SIGKILL)
    if tg.kthread || tg.group_exit {
        return Ok(());
    }
    // A forced signal whose action is SIG_DFL (a blocked or ignored one
    // was reset by the caller) lifts a namespace init's protection
    // (Linux force_sig_info_to_task: SIGNAL_UNKILLABLE cleared); one
    // init handles leaves it protected
    let dfl = || {
        tg.sighand
            .as_ref()
            .is_none_or(|h| h.get_action(sig).is_default())
    };
    if force
        && let Some(s) = tg.signal.as_ref()
        && s.unkillable()
        && dfl()
    {
        s.clear_unkillable();
    }
    let init = tg.protects(sig, info.forces(t.pid_ns()));

    let sighand = tg.sighand.as_ref();
    let to = Send {
        sig,
        init,
        info: &info,
        ty,
        stopped: tg.stopped,
    };
    // A signal that would be dropped makes and charges no entry (Linux
    // prepare_signal and legacy_queue come before __sigqueue_alloc);
    // send_locked decides again under the lock
    if sig != SIGKILL && drops(t, &t.sig.lock(), sighand, &to) {
        return Ok(());
    }

    // The info's entry, made before the receiver's lock is taken; SIGKILL
    // needs none (Linux __send_signal_locked). Unused, it is freed after
    // the lock is dropped.
    let mut q = if sig == SIGKILL {
        None
    } else {
        SigQueue::alloc(
            sig,
            info.resolve_checked(sig, t.pid_ns()),
            tg.uid,
            tg.limit,
            info.override_rlimit(sig),
        )
    };
    let sent = with_sig(t, |t, state| send_locked(t, state, sighand, &to, &mut q));
    drop(q);

    let wants = match sent {
        Sent::Dropped => return Ok(()),
        Sent::Overflow => return Err(KernelError::WouldBlock),
        Sent::Queued(w) => w,
    };
    // Signalfd readers of the target's handler table recheck (Linux
    // signalfd_notify)
    if let Some(h) = sighand {
        h.signalfd_wq.wake_all();
    }
    complete_signal(t, sig, ty, wants, sighand, to.init);
    Ok(())
}

/// Signal `sig` with `info` to task `t` or its group (`ty`), queued
/// under TASKLIST held by the caller (Linux do_notify_parent's
/// __group_send_sig_info, exit_ptrace's send_sig_info, under
/// tasklist_lock): `q` is its entry, made before TASKLIST was taken
/// (SIGKILL needs none), which it takes if queued; an unused one is the
/// caller's to free after unlocking. Signalfd readers and the thread
/// that takes it are woken by [`Posted::finish`], after TASKLIST is
/// dropped.
fn send_held(
    table: &crate::task::percpu::GlobalTaskTable,
    t: &TaskRef,
    sig: Signal,
    info: SendInfo,
    ty: PidType,
    q: &mut Option<Box<SigQueue>>,
) -> Option<Posted> {
    check_send_context();
    let tg = target_in(table, t)?;
    if tg.kthread || tg.group_exit {
        return None;
    }
    let to = Send {
        sig,
        init: tg.protects(sig, info.forces(t.pid_ns())),
        info: &info,
        ty,
        stopped: tg.stopped,
    };
    if let Some(e) = q.as_mut() {
        // Numbered in the receiver's namespace by the sender already
        // (Linux do_notify_parent: __send_signal_locked, no check)
        e.set_info(info.resolve(sig, t.pid_ns()));
    }
    // A send changes no blocked mask: with_sig retargets nothing (which
    // would take TASKLIST)
    let sighand = tg.sighand.as_ref();
    let sent = with_sig(t, |t, state| send_locked(t, state, sighand, &to, q));
    let Sent::Queued(wants) = sent else {
        return None;
    };
    // The thread that takes it, and whether it ends the group, are
    // decided now, as it is queued (Linux complete_signal under
    // siglock): a mask changed after this, or the signal taken, by the
    // time the wakeup runs changes nothing
    let chosen = choose(table, t, sig, ty, wants, sighand, to.init);
    Some(Posted {
        t: t.clone(),
        sig,
        chosen,
        sighand: tg.sighand,
    })
}

/// SIGKILL from the kernel to thread `t`, under TASKLIST held by the
/// caller (Linux exit_ptrace: send_sig_info(SIGKILL, SEND_SIG_PRIV)
/// under tasklist_lock); SIGKILL needs no queue entry, so nothing
/// allocates. Its wakeups wait for [`Posted::finish`].
pub fn sigkill_held(table: &crate::task::percpu::GlobalTaskTable, t: &TaskRef) -> Option<Posted> {
    send_held(table, t, SIGKILL, SendInfo::Kernel, PidType::Pid, &mut None)
}

/// A signal [`send_held`] queued, whose wakeups wait for TASKLIST to be
/// dropped
#[must_use]
pub struct Posted {
    t: TaskRef,
    sig: Signal,
    chosen: Option<Chosen>,
    sighand: Option<Arc<SigHand>>,
}

impl Posted {
    /// Wake its signalfd readers and the thread chosen to take it,
    /// ending the group if that was decided (Linux signalfd_notify,
    /// complete_signal); TASKLIST not held
    pub fn finish(self) {
        if let Some(h) = self.sighand.as_ref() {
            h.signalfd_wq.wake_all();
        }
        deliver(&self.t, self.sig, self.chosen);
    }
}

/// What a send is, for its locked part
struct Send<'a> {
    sig: Signal,
    /// An init's protection applies (`Target::protects`)
    init: bool,
    info: &'a SendInfo,
    ty: PidType,
    /// The receiver is in a ptrace stop
    stopped: bool,
}

/// Queue `to.sig` for task `t` under its Task.sig (Linux
/// __send_signal_locked), on its own set or its group's: dropped if
/// ignored or a non-RT signal already pending there, else marked
/// pending with entry `q` queued, which it takes. A signal for an
/// exiting thread itself is dropped (its queue was flushed: Linux
/// task_can_queue_signal), as is one for a task with no group. A send
/// whose entry could not be had goes on without; an RT signal a user
/// queued then fails.
fn send_locked(
    t: &crate::task::Task,
    state: &mut TaskSignalState,
    sighand: Option<&Arc<SigHand>>,
    to: &Send<'_>,
    q: &mut Option<Box<SigQueue>>,
) -> Sent {
    let sig = to.sig;
    if drops(t, state, sighand, to) {
        return Sent::Dropped;
    }
    let exiting = t.has_flag(crate::task::pf::EXITING);
    // Linux wants_signal, before this signal marks it
    let wants = !state.blocked.contains(sig)
        && !exiting
        && (sig == SIGKILL || (!to.stopped && (t.se.on_cpu() || !t.sigpending())));
    let TaskSignalState {
        pending,
        shared_pending,
        ..
    } = state;
    let mut group;
    let pending = match to.ty {
        PidType::Pid => pending,
        PidType::Tgid => match shared_pending.group() {
            Some(g) => {
                group = g;
                &mut group.pending
            }
            None => return Sent::Dropped,
        },
    };
    match q.take() {
        Some(e) => pending.queue(e),
        None if to.info.must_queue(sig) => return Sent::Overflow,
        None => {}
    }
    pending.add(sig);
    Sent::Queued(wants)
}

/// `to.sig` for task `t` is dropped, `state` its Task.sig's: its own
/// signal while it exits, ignored, a non-RT signal already pending
/// where it would go, or a group signal for a task with no group
/// (Linux task_can_queue_signal, prepare_signal, legacy_queue)
fn drops(
    t: &crate::task::Task,
    state: &TaskSignalState,
    sighand: Option<&Arc<SigHand>>,
    to: &Send<'_>,
) -> bool {
    let sig = to.sig;
    if to.ty == PidType::Pid && t.has_flag(crate::task::pf::EXITING) {
        return true;
    }
    if sig_ignored(state, sighand, sig) || (to.init && init_ignores(state, sighand, sig)) {
        return true;
    }
    match to.ty {
        PidType::Pid => state.pending.legacy(sig),
        PidType::Tgid => state
            .shared_pending
            .group()
            .is_none_or(|g| g.pending.legacy(sig)),
    }
}

/// Find a thread to take `sig` just queued for `p` and wake it (Linux
/// complete_signal), the choice made under TASKLIST's read lock
/// ([`choose`]); `init`: an init's protection applied to the
/// send
fn complete_signal(
    p: &Task,
    sig: Signal,
    ty: PidType,
    p_wants: bool,
    sighand: Option<&Arc<SigHand>>,
    init: bool,
) {
    let chosen = choose(&TASKLIST.read(), p, sig, ty, p_wants, sighand, init);
    deliver(p, sig, chosen);
}

/// The thread [`choose`] picked for a signal, and whether the signal
/// ends its group
struct Chosen {
    t: TaskRef,
    kill: bool,
}

/// Under TASKLIST: the thread to take `sig` just queued for `p` (Linux
/// complete_signal): `p` if it wanted it when queued (`p_wants`), else
/// for a group signal the next thread from the group's curr_target
/// that does; a fatal one ends the group, never a protected init's
/// while protected (`init`: Linux queues it a fatal signal only while
/// blocked, which no thread wants)
fn choose(
    table: &crate::task::percpu::GlobalTaskTable,
    p: &Task,
    sig: Signal,
    ty: PidType,
    p_wants: bool,
    sighand: Option<&Arc<SigHand>>,
    init: bool,
) -> Option<Chosen> {
    let t = if p_wants {
        crate::task::percpu::task_ref(p)
    } else if ty == PidType::Pid {
        return None;
    } else {
        pick_thread(table, p, sig)?
    };
    let awaited = t.sig.lock().real_blocked.contains(sig);
    let kill = !init && fatal(sighand, sig) && !awaited;
    Some(Chosen { t, kill })
}

/// Act on [`choose`]'s choice for `sig` queued for `p` (TASKLIST not
/// held): end the group if decided, mark and wake the chosen thread
fn deliver(p: &Task, sig: Signal, chosen: Option<Chosen>) {
    let Some(Chosen { t: c, kill }) = chosen else {
        return;
    };
    if kill {
        group_kill(p, sig);
    }
    if !core::ptr::eq(Arc::as_ptr(&c), p) {
        with_sig(&c, |_, _| ());
    }
    use crate::task::percpu::WakeMode;
    let mode = if sig == SIGKILL {
        WakeMode::Fatal
    } else {
        WakeMode::Interruptible
    };
    signal_wake_task(&c, mode);
}

/// Under TASKLIST: the thread of `p`'s group, from its curr_target on,
/// that wants `sig` (Linux complete_signal's loop): it becomes
/// curr_target
fn pick_thread(
    table: &crate::task::percpu::GlobalTaskTable,
    p: &Task,
    sig: Signal,
) -> Option<TaskRef> {
    table.threads(p.pid).nth(1)?;
    let cur = p.sig.lock().shared_pending.lock().curr_target;
    let wants = |v: &crate::task::percpu::TaskView<'_>| {
        wants_signal(
            v.task,
            matches!(v.state(), crate::task::TaskState::Traced(_)),
            sig,
        )
    };
    let v = table
        .threads(p.pid)
        .skip_while(|v| v.task.tid() != cur)
        .find(wants)
        .or_else(|| {
            table
                .threads(p.pid)
                .take_while(|v| v.task.tid() != cur)
                .find(wants)
        })?;
    let t = crate::task::percpu::task_ref(v.task);
    p.sig.lock().shared_pending.lock().curr_target = t.tid();
    Some(t)
}

/// `t` should be woken for `sig` (Linux wants_signal)
fn wants_signal(t: &crate::task::Task, stopped: bool, sig: Signal) -> bool {
    if t.sig.lock().blocked.contains(sig) || t.has_flag(crate::task::pf::EXITING) {
        return false;
    }
    if sig == SIGKILL {
        return true;
    }
    !stopped && (t.se.on_cpu() || !t.sigpending())
}

/// A signal for `t` is deliverable (Linux signal_wake_up_state): wake
/// it from a sleep `mode` ends, else, if it runs on another CPU, kick it
/// into the kernel so its return to user mode delivers the signal
/// (kick_process); nothing once it is reaped. Process context, TASKLIST
/// not held.
fn signal_wake_up(t: &TaskRef, mode: crate::task::percpu::WakeMode) {
    if TASKLIST.read().view(t).is_some() {
        signal_wake_task(t, mode);
    }
}

fn signal_wake_task(t: &TaskRef, mode: crate::task::percpu::WakeMode) {
    if !crate::task::percpu::try_to_wake_up(t, mode) {
        crate::task::percpu::kick_process(t);
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

/// A kill-family signal number as given: None (0) probes; EINVAL past
/// NSIG, reported where Linux checks it (check_kill_permission, once
/// the receiver is found: no receiver is ESRCH whatever the number)
pub type KillSig = KernelResult<Option<Signal>>;

/// The receiver of a group signal `sig` to process `pid` (a number a
/// syscall was given, Linux kill_proc_info's find_vpid), once `check`
/// of it allows it ([`group_task`]): ESRCH, EINVAL, or `check`'s error
pub fn proc_target(
    pid: Pid,
    sig: KillSig,
    check: impl Fn(&crate::task::percpu::TaskView<'_>, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<TaskRef> {
    let table = TASKLIST.read();
    checked(&table, table.get(pid), PidType::Tgid, sig, check)
}

/// The receiver of `sig` to `v` (`ty` Pid) or its group (Tgid), under
/// TASKLIST: ESRCH if there is none, then a bad number's EINVAL (Linux
/// check_kill_permission: valid_signal first), then `check`'s error
fn checked(
    table: &crate::task::percpu::GlobalTaskTable,
    v: Option<crate::task::percpu::TaskView<'_>>,
    ty: PidType,
    sig: KillSig,
    check: impl Fn(&crate::task::percpu::TaskView<'_>, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<TaskRef> {
    let v = v.ok_or(KernelError::NoProcess)?;
    check(&v, sig?)?;
    let t = match ty {
        PidType::Pid => Some(crate::task::percpu::task_ref(v.task)),
        PidType::Tgid => group_task(table, Some(v)),
    };
    t.ok_or(KernelError::NoProcess)
}

/// The task a group signal to the process `leader` heads is checked
/// against: the leader, or a thread still running once it has exited
/// (Linux takes the leader; its zombie keeps the group's handlers,
/// hk's does not)
pub fn group_task(
    table: &crate::task::percpu::GlobalTaskTable,
    leader: Option<crate::task::percpu::TaskView<'_>>,
) -> Option<TaskRef> {
    let l = leader?;
    let t = if task_live(&l) {
        l.task
    } else {
        table
            .threads(l.task.pid)
            .find(task_live)
            .map_or(l.task, |t| t.task)
    };
    Some(crate::task::percpu::task_ref(t))
}

/// `sig` with `info` to task `t`'s thread group, received as `t`
/// (Linux do_send_sig_info, PIDTYPE_TGID, with no permission check)
pub fn send_group_signal(t: &Task, sig: Signal, info: SendInfo) -> KernelResult<()> {
    send_task(t, sig, info, PidType::Tgid, false)
}

/// `sig` with `info` to task `t`'s process, received as a signal to the
/// process is ([`group_task`] of its leader; Linux group_send_sig_info,
/// with no permission check): ESRCH once the process is gone
pub fn group_send_sig_info(t: &Task, sig: Signal, info: SendInfo) -> KernelResult<()> {
    let to = {
        let table = TASKLIST.read();
        group_task(&table, table.get(t.pid))
    };
    let to = to.ok_or(KernelError::NoProcess)?;
    send_group_signal(&to, sig, info)
}

/// `sig` with `info` to the process struct pid `pid` names, after
/// `check` of it allows it (Linux kill_pid_info: the struct pid, never
/// a number a reaped process freed for reuse)
pub fn kill_pid_info(
    pid: &crate::task::pid::Pid,
    sig: Signal,
    info: SendInfo,
    check: impl Fn(&crate::task::percpu::TaskView<'_>, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<()> {
    kill_pid_info_type(pid, Ok(Some(sig)), info, PidType::Tgid, check)
}

/// `sig` with `info` to the task struct pid `pid` names (`ty` Pid) or
/// its thread group (`ty` Tgid), after `check` of that task allows it
/// (Linux kill_pid_info_type); `sig` None only checks, a bad number is
/// EINVAL once the task is found
pub fn kill_pid_info_type(
    pid: &crate::task::pid::Pid,
    sig: KillSig,
    info: SendInfo,
    ty: PidType,
    check: impl Fn(&crate::task::percpu::TaskView<'_>, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<()> {
    let t = {
        let table = TASKLIST.read();
        let found = table.pid_tid(pid).and_then(|tid| table.get(tid));
        checked(&table, found, ty, sig, check)?
    };
    send_or_probe(&t, sig, info, ty)
}

/// [`send_task`] of `sig` to `t`, found and checked; None is a probe
/// that sends nothing (Linux: the null signal), a bad number EINVAL
fn send_or_probe(t: &Task, sig: KillSig, info: SendInfo, ty: PidType) -> KernelResult<()> {
    sig?.map_or(Ok(()), |s| send_task(t, s, info, ty, false))
}

/// `sig` with `info` once to each process of the group struct pid `pg`
/// names, after `check` of its leader allows it (Linux kill_pgrp_info:
/// the reference cannot come to name another group); `sig` None only
/// checks, a bad number is EINVAL for each process. 0 if any process
/// got it, else the last error (ESRCH for an empty group).
pub fn kill_pgrp_info(
    pg: &crate::task::pid::Pid,
    sig: KillSig,
    info: SendInfo,
    check: impl Fn(&crate::task::percpu::TaskView<'_>, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<()> {
    let procs = crate::task::percpu::GlobalTaskTable::collect_pgrp(pg, |table, t| {
        Some((sig.and_then(|s| check(t, s)), group_task(table, Some(*t))))
    });
    let mut ret = Err(KernelError::NoProcess);
    let mut ok = false;
    for (e, t) in &procs {
        ret = match (t, e) {
            (Some(t), Ok(())) => send_or_probe(t, sig, info, PidType::Tgid),
            (Some(_), Err(e)) => Err(*e),
            (None, _) => Err(KernelError::NoProcess),
        };
        ok |= ret.is_ok();
    }
    if ok { Ok(()) } else { ret }
}

/// Send signal to all processes in a process group, from the kernel
/// (no permission check: Linux kill_pgrp with SEND_SIG_PRIV)
///
/// This is used by TTY signal generation (SIGINT, SIGTSTP, etc.)
/// when control characters are received.
///
/// As [`kill_pgrp`].
pub fn send_signal_to_pgrp(pgid: Pid, sig: Signal) -> KernelResult<()> {
    kill_pgrp(pgid, Ok(Some(sig)), SendInfo::Kernel, |_, _| Ok(()))
}

/// `sig` from the kernel to each process of the group `pg` names (Linux
/// kill_pgrp(struct pid *)): unlike a number, the reference cannot come
/// to name another group
pub fn kill_pgrp_pid(pg: &crate::task::pid::Pid, sig: Signal) {
    let procs = crate::task::percpu::GlobalTaskTable::collect_pgrp(pg, |table, t| {
        group_task(table, Some(*t))
    });
    for t in &procs {
        let _ = send_group_signal(t, sig, SendInfo::Kernel);
    }
}

/// `sig` with `info` once to each process of group `pgid` (Linux __kill_pgrp_info:
/// its leader on the group's list, the signal process-directed), after
/// `check` of it allows it; `sig` None only checks, a bad number is
/// EINVAL for each process. 0 if any process got it, else the last
/// error (ESRCH for an empty group).
pub fn kill_pgrp(
    pgid: Pid,
    sig: KillSig,
    info: SendInfo,
    check: impl Fn(&crate::task::percpu::TaskView<'_>, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<()> {
    let mut ret = Err(KernelError::NoProcess);
    let mut ok = false;
    for pid in crate::task::percpu::pgrp_pids(pgid) {
        ret =
            proc_target(pid, sig, &check).and_then(|t| send_or_probe(&t, sig, info, PidType::Tgid));
        ok |= ret.is_ok();
    }
    if ok { Ok(()) } else { ret }
}

// =============================================================================
// Thread-group exit
// =============================================================================

/// `sig` kills the receiver's whole group on arrival (Linux sig_fatal
/// and !sig_kernel_coredump in complete_signal): SIGKILL, or a SIG_DFL
/// signal whose default is to terminate (core-dump signals end the
/// group at delivery)
fn fatal(sighand: Option<&Arc<SigHand>>, sig: Signal) -> bool {
    if sig == SIGKILL {
        return true;
    }
    let dfl = sighand.is_some_and(|h| h.get_action(sig).is_default());
    dfl && !sig.kernel_ignore() && !sig.kernel_stop() && !sig.kernel_coredump()
}

/// A fatal signal reached `p`: its group exits with that status and
/// every thread gets SIGKILL (Linux complete_signal; a traced target
/// sees anything but SIGKILL first). Not once every thread of the group
/// has started exiting (Linux complete_signal finds no thread that
/// wants it): the status the last thread set stays. Decided under the
/// same TASKLIST hold as the group lookup, so a process-directed signal
/// whose chosen thread began exiting after it was picked still ends
/// the threads left. Unlike Linux, a thread-directed one to an exiting
/// thread with live siblings ends them too.
fn group_kill(p: &Task, sig: Signal) {
    let found = {
        let table = TASKLIST.read();
        table.view(p).and_then(|t| {
            let pid = t.task.pid;
            table
                .threads(pid)
                .any(|u| task_live(&u))
                .then(|| (pid, t.ptrace() != 0, group_signal(&table, pid)))
        })
    };
    let Some((tgid, traced, Some(s))) = found else {
        return;
    };
    if (sig == SIGKILL || !traced) && s.start_exit(sig.into(), true) {
        zap_threads(tgid, None);
    }
}

/// `t` has not started exiting (Linux !PF_EXITING, not a zombie)
pub fn task_live(t: &crate::task::percpu::TaskView<'_>) -> bool {
    !t.task.has_flag(crate::task::pf::EXITING)
        && !matches!(t.state(), crate::task::TaskState::Zombie(_))
}

/// The SignalStruct of thread group `tgid` (its leader keeps it until
/// reaped; a thread's after a de_thread in progress)
fn group_signal(
    table: &crate::task::percpu::GlobalTaskTable,
    tgid: Pid,
) -> Option<Arc<SignalStruct>> {
    table
        .get(tgid)
        .and_then(|t| t.signal().cloned())
        .or_else(|| table.threads(tgid).find_map(|t| t.signal().cloned()))
}

/// SIGKILL every thread of `tgid` that has not started exiting, but
/// `except` (Linux zap_other_threads): queued privately, then woken
/// from interruptible and killable sleeps once TASKLIST is dropped.
/// A thread running user code dies on its next return to user mode (a
/// tick or a kick IPI interrupts it: `entry::exit_to_user_mode`).
fn zap_threads(tgid: Pid, except: Option<&Task>) {
    // Room made before the write lock (nothing allocates under
    // TASKLIST), again if the group grew
    let mut room = TASKLIST.read().threads(tgid).count();
    let zapped = loop {
        let mut zapped: alloc::vec::Vec<TaskRef> = alloc::vec::Vec::with_capacity(room);
        let mut table = TASKLIST.write();
        let n = table.threads(tgid).count();
        if n > room {
            drop(table);
            room = n;
            continue;
        }
        for t in table.threads(tgid) {
            if !except.is_some_and(|e| core::ptr::eq(t.task, e)) && task_live(&t) {
                zapped.push(crate::task::percpu::task_ref(t.task));
            }
        }
        for t in &zapped {
            if let Some(mut v) = table.view_mut(t) {
                sigkill_task(&mut v);
            }
        }
        drop(table);
        break zapped;
    };
    for t in &zapped {
        signal_wake_up(t, crate::task::percpu::WakeMode::Fatal);
    }
}

/// SIGKILL every other thread of task `t`'s group (exec's de_thread)
pub fn zap_group_others(t: &Task) {
    zap_threads(t.pid, Some(t));
}

/// Queue SIGKILL for `t` (TASKLIST held); a ptrace stop it is in ends
/// here, no longer reported to its tracer's wait (Linux
/// signal_wake_up(t, fatal) clears JOBCTL_TRACED with the signal
/// queued), so a wait after the kill finds its exit, never the stop;
/// unless its tracer is inside a request on it (frozen), whose end
/// does that
fn sigkill_task(t: &mut crate::task::percpu::TaskViewMut<'_>) {
    let mut s = t.task.sig.lock();
    s.pending.add(SIGKILL);
    t.task.set_sigpending(true);
    drop(s);
    if !t.ptrace_frozen() {
        t.end_trace_stop();
    }
}

/// A thread just cloned into `parent`'s group dies with it if the group
/// is exiting (Linux copy_process: fatal_signal_pending under siglock).
/// Its signal state is set up (`install_fork_signal`), so a zap that ran
/// before saw it or is seen here.
pub fn zap_new_thread(parent: &Task, child: &Task) {
    let dying = get_task_signal_struct(parent).is_some_and(|s| s.group_exit() != GroupExit::None);
    if dying && let Some(mut t) = TASKLIST.write().view_mut(child) {
        sigkill_task(&mut t);
    }
}

/// The current thread's group is exiting, or another thread's exec is
/// ending it (Linux signal_group_exit): it must die
fn group_dying(me: &Task) -> bool {
    match get_task_signal_struct(me).map(|s| s.group_exit()) {
        Some(GroupExit::Exit(_)) => true,
        Some(GroupExit::Exec(t)) => t != me.tid(),
        _ => false,
    }
}

/// End the whole thread group with wait status `status` (Linux
/// do_group_exit): the first exit sets the group's status and kills the
/// other threads; a thread dying in a group exit already under way
/// takes its status, one ended by another thread's exec exits with 0
pub fn do_group_exit(status: i32) -> ! {
    let me = crate::task::percpu::current();
    let code = match get_task_signal_struct(&me) {
        Some(s) => loop {
            match s.group_exit() {
                GroupExit::Exit(code) => break code,
                GroupExit::Exec(_) => break 0,
                GroupExit::None if s.start_exit(status, false) => {
                    zap_threads(crate::task::percpu::current_pid(), Some(&*me));
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

/// Dequeue the next deliverable signal of task `t` with its action and
/// info (Linux get_signal's dequeue): a queued fault first, then the
/// next of its own, then the thread group's
pub fn get_signal_to_deliver(t: &Task) -> Option<(Signal, SigAction, SigInfo)> {
    let sighand = get_task_sighand(t)?;
    loop {
        let (d, alrm) = with_task_signal_state(t, |state| {
            let blocked = state.blocked;
            match state.pending.dequeue_sync(&blocked) {
                Some(d) => Some((d, false)),
                None => dequeue_locked(state, &blocked),
            }
        })??;
        // With Task.sig dropped: the entry is freed (or a timer's goes
        // back to it), ITIMER_REAL rearms on a group SIGALRM
        if alrm {
            crate::time::posix_timer::rearm_itimer_real();
        }
        let sig = d.sig();
        if let Some(info) = d.info() {
            return Some((sig, sighand.get_action(sig), info));
        }
    }
}

/// The next signal not in `skip`, the task's own first, then its
/// group's (Linux dequeue_signal); true if that was the group's SIGALRM
fn dequeue_locked(state: &mut TaskSignalState, skip: &SigSet) -> Option<(pending::Dequeued, bool)> {
    if let Some(d) = state.pending.dequeue(skip) {
        return Some((d, false));
    }
    let d = state.shared_pending.lock().dequeue(skip)?;
    let alrm = d.sig() == SIGALRM;
    Some((d, alrm))
}

/// Dequeue the current task's next pending signal of `wanted`, with its
/// info (Linux dequeue_signal with the complement of `wanted`:
/// sigtimedwait, signalfd)
pub fn dequeue_signal(wanted: &SigSet) -> Option<(Signal, SigInfo)> {
    let skip = SigSet(!wanted.0);
    let me = crate::task::percpu::current();
    loop {
        let (d, alrm) = with_task_signal_state(&me, |state| dequeue_locked(state, &skip))??;
        if alrm {
            crate::time::posix_timer::rearm_itimer_real();
        }
        let sig = d.sig();
        if let Some(info) = d.info() {
            return Some((sig, info));
        }
    }
}

/// Queue POSIX timer entry `q` for task `tid` or its group (Linux
/// posixtimer_send_sigqueue): no legacy check (the entry is the
/// timer's one instance), `ty` Pid not on an exiting thread; then the
/// thread choice of any group signal. The entry comes back if it was
/// not queued, with whether the signal was ignored.
pub fn send_timer_sigqueue(
    pid: &crate::task::pid::Pid,
    ty: PidType,
    q: Box<SigQueue>,
) -> Result<(), (Box<SigQueue>, bool)> {
    let sig = q.sig();
    let me = crate::task::percpu::current();
    // The task its struct pid names now, if any (Linux pid_task); a
    // group signal is taken by the current thread if it is in the
    // group (posixtimer_get_target)
    let t = {
        let table = TASKLIST.read();
        let tid = table.pid_tid(pid);
        match tid {
            None => None,
            Some(tid) if ty == PidType::Pid => table.task(tid),
            Some(tid) if me.pid == tid && !me.has_flag(crate::task::pf::EXITING) => {
                Some(crate::task::percpu::task_ref(&me))
            }
            Some(tid) => group_task(&table, table.get(tid)),
        }
    };
    let Some(t) = t else {
        return Err((q, false));
    };
    let Some(tg) = target(&t) else {
        return Err((q, false));
    };
    if tg.kthread || tg.group_exit {
        return Err((q, true));
    }
    let sighand = tg.sighand.as_ref();
    let stopped = tg.stopped;
    let mut q = Some(q);
    let r = with_sig(&t, |task, state| {
        let exiting = task.has_flag(crate::task::pf::EXITING);
        if exiting && ty == PidType::Pid {
            return Err(false);
        }
        if sig_ignored(state, sighand, sig) {
            return Err(true);
        }
        let wants = !state.blocked.contains(sig)
            && !exiting
            && !stopped
            && (task.se.on_cpu() || !task.sigpending());
        let Some(e) = q.take() else {
            return Err(false);
        };
        match ty {
            PidType::Pid => state.pending.queue(e),
            PidType::Tgid => match state.shared_pending.group() {
                Some(mut g) => g.queue(e),
                None => {
                    q = Some(e);
                    return Err(false);
                }
            },
        }
        Ok(wants)
    });
    match r {
        Ok(wants) => {
            if let Some(h) = sighand {
                h.signalfd_wq.wake_all();
            }
            let init = tg.protects(sig, false);
            complete_signal(&t, sig, ty, wants, sighand, init);
            Ok(())
        }
        Err(ignored) => Err((q.expect("an unqueued entry comes back"), ignored)),
    }
}

// =============================================================================
// SignalStruct - Per-Process Structure (mirrors Linux signal_struct)
// =============================================================================

use crate::task::rlimit::{RLIM_NLIMITS, RLIMIT_SIGPENDING, RLimit};

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
    /// The group's pending signals (Linux signal->shared_pending, and
    /// curr_target): spin, under the receiving thread's Task.sig
    shared: Mutex<GroupPending>,
    /// PR_SET_CHILD_SUBREAPER (Linux signal->is_child_subreaper): the
    /// process adopts its descendants' orphans; set by any thread,
    /// under TASKLIST's write lock, read under its read lock by the
    /// reparenting it decides (find_reaper). Not inherited by fork.
    subreaper: crate::task::TableCell<bool>,
    /// The group is a pid namespace's init and takes no signal whose
    /// action is SIG_DFL from its namespace (Linux SIGNAL_UNKILLABLE):
    /// set before the group is visible, cleared once and for good when
    /// the kernel forces such a signal on it (force_sig_info_to_task).
    /// A monotonic flag no other state is ordered with: an atomic.
    unkillable: AtomicBool,
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
    /// Take task `t`'s (none once it is reaped or for a task without a
    /// SignalStruct)
    pub fn lock(t: &Task) -> Self {
        let s = get_task_signal_struct(t);
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
    /// Take task `t`'s (none once it is reaped or for a task without a
    /// SignalStruct), sleeping interruptibly (Linux prepare_bprm_creds,
    /// ptrace_attach): a thread waiting here while its group's exec
    /// waits in de_thread for it to die must see the SIGKILL. A signal
    /// gives ERESTARTNOINTR (the syscall restarts once the signal is
    /// handled).
    pub fn lock(t: &Task) -> Result<Self, crate::util::error::KernelError> {
        let s = get_task_signal_struct(t);
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
    /// A new SignalStruct with the global init's rlimits (Linux
    /// INIT_RLIMITS as fork_init leaves them)
    pub fn new() -> Self {
        Self {
            rlim: IrqSpinlock::new(crate::task::rlimit::init_rlimits()),
            cred_guard: crate::sync::Mutex::new(()),
            exec_update: crate::sync::RwSem::new(()),
            group_exit: AtomicU64::new(0),
            posix_timers: Mutex::new(crate::time::posix_timer::PosixTimerRegistry::new()),
            live: AtomicU32::new(1),
            dead_times: [AtomicU64::new(0), AtomicU64::new(0)],
            child_times: [AtomicU64::new(0), AtomicU64::new(0)],
            cputimer: crate::time::cpu_timer::GroupCputimer::new(),
            shared: Mutex::new(GroupPending::new()),
            subreaper: crate::task::TableCell::new(false),
            unkillable: AtomicBool::new(false),
        }
    }

    /// The group is a pid namespace's init, protected from SIG_DFL
    /// signals (Linux SIGNAL_UNKILLABLE)
    pub fn unkillable(&self) -> bool {
        self.unkillable.load(Ordering::Acquire)
    }

    /// Make the group a namespace init's, before it is visible (Linux
    /// copy_process for is_child_reaper; the global init at boot)
    pub fn set_unkillable(&self) {
        self.unkillable.store(true, Ordering::Release);
    }

    /// The kernel forced a SIG_DFL signal on it: protected no more
    /// (Linux force_sig_info_to_task)
    fn clear_unkillable(&self) {
        self.unkillable.store(false, Ordering::Release);
    }

    /// The group's wait status becomes `code` whatever ended it (Linux
    /// zap_pid_ns_processes: group_exit_code = pid_ns->reboot)
    pub fn set_exit_code(&self, code: i32) {
        self.group_exit
            .store(GROUP_EXIT | u64::from(code as u32), Ordering::Release);
    }

    /// The process is a child subreaper (TASKLIST held)
    pub fn subreaper(&self, table: &crate::task::percpu::GlobalTaskTable) -> bool {
        *self.subreaper.access(table)
    }

    /// Make the process a child subreaper or not (TASKLIST held for
    /// writing; Linux PR_SET_CHILD_SUBREAPER)
    pub fn set_subreaper(&self, table: &mut crate::task::percpu::GlobalTaskTable, on: bool) {
        *self.subreaper.access_mut(table) = on;
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

    /// Its threads that have not started exiting, the caller included if
    /// it has not (Linux atomic_read(&signal->live))
    pub fn live(&self) -> u32 {
        self.live.load(Ordering::Acquire)
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

    /// Start task `t`'s exec ending the other threads (de_thread): false
    /// if the group is exiting or another thread is exec'ing
    pub fn start_exec(&self, t: &Task) -> bool {
        let v = GROUP_EXEC | t.tid();
        self.group_exit
            .compare_exchange(0, v, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Task `t`'s de_thread is over (unless a fatal signal took over)
    pub fn end_exec(&self, t: &Task) {
        let _ = self.group_exit.compare_exchange(
            GROUP_EXEC | t.tid(),
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
    pub fn set_rlimit(&self, resource: u32, new: RLimit) -> Result<RLimit, KernelError> {
        let r = resource as usize;
        if r >= RLIM_NLIMITS || new.rlim_cur > new.rlim_max {
            return Err(KernelError::InvalidArgument);
        }
        let mut rlim = self.rlim.lock();
        let old = rlim[r];
        if new.rlim_max > old.rlim_max && !crate::task::capable(crate::task::CAP_SYS_RESOURCE) {
            return Err(KernelError::NotPermitted);
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
            shared: Mutex::new(GroupPending::new()),
            // Linux copy_signal: is_child_subreaper is not inherited
            subreaper: crate::task::TableCell::new(false),
            unkillable: AtomicBool::new(false),
        })
    }
}

// =============================================================================
// TASK_SIGNAL Global Table
// =============================================================================

// Task.signal field accessors (SignalStruct - shared by thread group)

/// Task `t`'s signal struct (none once it is reaped)
pub fn get_task_signal_struct(t: &Task) -> Option<Arc<SignalStruct>> {
    TASKLIST.read().view(t)?.signal().cloned()
}

/// A new task's signal struct for fork/clone, and whether it is the
/// parent's; ENOMEM
///
/// If `share_signal` is true (CLONE_THREAD), share the Arc<SignalStruct>
/// (`install_fork_signal` counts the new thread live). Otherwise, deep
/// clone the signal struct.
fn fork_signal_struct(
    parent: &Task,
    share_signal: bool,
) -> Result<(Arc<SignalStruct>, bool), KernelError> {
    match get_task_signal_struct(parent) {
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

/// Let the tracer of a traced task see `sig` with `info` before it is
/// delivered: None if the tracer cancelled it, or if it changed it to
/// one now blocked (queued again, as Linux ptrace_signal does)
fn traced_signal(
    me: &Task,
    sig: Signal,
    info: SigInfo,
    action: SigAction,
) -> Option<(Signal, SigInfo, SigAction)> {
    if sig == SIGKILL {
        return Some((sig, info, action));
    }
    // The tracer may change the info too (PTRACE_SETSIGINFO)
    let mut info = info;
    let new = crate::task::ptrace::ptrace_signal(&mut info, sig)?;
    if new == sig && info.sig() == Some(sig) {
        let action = get_task_sighand(me)?.get_action(new);
        return Some((new, info, action));
    }
    // A signal other than the info's is the tracer's (Linux
    // ptrace_signal: signr != info->si_signo)
    if info.sig() != Some(new) {
        info = tracer_info(me, new);
    }
    let blocked = with_task_signal_state(me, |state| state.blocked.contains(new)).unwrap_or(false);
    if blocked {
        let _ = send_sig_info(me, new, SendInfo::Info(info));
        return None;
    }
    let action = get_task_sighand(me)?.get_action(new);
    Some((new, info, action))
}

/// `sig` as the tracer of `t` gives it: SI_USER from the tracer's
/// process and uid (Linux ptrace_signal)
fn tracer_info(t: &Task, sig: Signal) -> SigInfo {
    let tracer = TASKLIST.read().view(t).and_then(|v| v.tracer());
    let uid = tracer.as_ref().and_then(|tr| {
        let table = TASKLIST.read();
        table.view(tr).map(|v| v.cred_arc().uid)
    });
    // The tracer as the tracee numbers it (Linux ptrace_signal:
    // task_pid_vnr(current->parent))
    let pid = tracer
        .as_ref()
        .map_or(0, |tr| crate::task::pid::vnr(tr.pid) as i32);
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

    let me = crate::task::percpu::current();
    let err = regs.ret() as i64;
    let restart = syscall_restarting(regs);
    regs.forget_syscall();

    while me.sigpending() {
        // A dying group comes before any handler (Linux get_signal)
        if group_dying(&me) {
            do_group_exit(SIGKILL.into());
        }
        let Some((sig, action, info)) = get_signal_to_deliver(&me) else {
            break;
        };
        // A tracee stops for its tracer first (Linux get_signal ->
        // ptrace_signal), which may cancel or change the signal
        let Some((sig, info, action)) = traced_signal(&me, sig, info, action) else {
            continue;
        };
        match action.handler {
            SigHandler::Ignore => continue,
            SigHandler::Default => {
                // Ignored by default; stops are not implemented: as
                // ignored (Linux get_signal: sig_kernel_ignore,
                // sig_kernel_stop)
                if sig.kernel_ignore() || sig.kernel_stop() {
                    continue;
                }
                // A signal queued while blocked does not kill a
                // namespace init either (Linux get_signal:
                // SIGNAL_UNKILLABLE and not sig_kernel_only), unless the
                // kernel forced one (it lifts the protection); SIGKILL
                // here came from the kernel or an ancestor namespace
                if sig != SIGKILL && current_unkillable(&me) {
                    continue;
                }
                // Killed by the signal: wait status = signal number,
                // for every thread of the group
                do_group_exit(sig.into());
            }
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
                if deliver_to_handler(&me, sig, &action, &info, regs) {
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
    let old = with_task_signal_state(&me, |state| {
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
        with_task_signal_state(&me, |state| state.blocked = state.saved_sigmask);
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
    me: &Task,
    sig: Signal,
    action: &SigAction,
    info: &SigInfo,
    regs: &UserFrame,
) -> bool {
    use crate::arch::signal;

    // Mask to save in the frame (restored by rt_sigreturn): the
    // pre-syscall mask if a temporary one is in effect, else current
    // (Linux sigmask_to_save)
    let restore = me.has_tif(crate::task::tif::RESTORE_SIGMASK);
    let (frame_mask, trap) = with_task_signal_state(me, |state| {
        let mask = if restore {
            state.saved_sigmask
        } else {
            state.blocked
        };
        (mask, state.trap)
    })
    .unwrap_or_default();

    match signal::setup_rt_frame(sig, action, frame_mask, info, &trap, regs) {
        Ok(()) => {
            // The saved mask now lives in the frame (Linux
            // signal_delivered -> clear_restore_sigmask)
            me.clear_tif(crate::task::tif::RESTORE_SIGMASK);
            // Block action.mask and the signal itself (unless SA_NODEFER)
            with_task_signal_state(me, |state| {
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
            force_sigsegv(me);
            false
        }
    }
}

/// Force `sig` on task `t` (Linux force_sig_info_to_task with
/// HANDLER_CURRENT): if blocked or ignored, its action goes back to
/// SIG_DFL and it is unblocked, so it cannot be dodged; a handler that
/// is not blocked still runs. Delivered on the way back to user mode.
pub fn force_sig(t: &Task, sig: Signal) {
    force_send(t, sig, SendInfo::Kernel);
}

/// [`force_sig`] with `info` (Linux force_sig_info)
pub fn force_sig_info(t: &Task, sig: Signal, info: SigInfo) {
    force_send(t, sig, SendInfo::Info(info.with_sig(sig)));
}

fn force_send(t: &Task, sig: Signal, info: SendInfo) {
    let sighand = get_task_sighand(t);
    let ignored = sighand
        .as_ref()
        .is_some_and(|h| h.get_action(sig).is_ignore());
    let blocked = with_task_signal_state(t, |s| s.blocked.contains(sig)).unwrap_or(false);
    if blocked || ignored {
        if let Some(h) = &sighand {
            let _ = h.set_action(sig, SigAction::default());
        }
        with_task_signal_state(t, |s| s.blocked.remove(sig));
    }
    let _ = send_task(t, sig, info, PidType::Pid, true);
}

/// Force delivery of SIGSEGV on task `t` (for stack errors during
/// signal setup)
///
/// Like Linux force_sigsegv: the handler is reset to SIG_DFL and SIGSEGV is
/// unblocked, so the task is killed on its way back to user space.
pub fn force_sigsegv(t: &Task) {
    // Reset SIGSEGV to default action
    if let Some(sighand) = get_task_sighand(t) {
        let _ = sighand.set_action(SIGSEGV, SigAction::default());
    }
    with_task_signal_state(t, |state| state.blocked.remove(SIGSEGV));
    // Send SIGSEGV to self, forced: it kills even a namespace init (Linux
    // force_sig_info_to_task clears SIGNAL_UNKILLABLE for SIG_DFL)
    let _ = send_task(t, SIGSEGV, SendInfo::Kernel, PidType::Pid, true);
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
pub fn force_sig_fault(sig: Signal, code: i32, addr: u64, trap: TrapSet, regs: &UserFrame) {
    let do_exit = do_group_exit;
    let info = SigInfo::fault(sig, code, addr);

    let me = crate::task::percpu::current();
    with_task_signal_state(&me, |s| trap.apply(&mut s.trap));
    // A traced task's fault signal is queued like any other, so the
    // tracer sees its signal-delivery stop first (Linux force_sig_fault
    // -> get_signal -> ptrace_signal); delivered on the way back to user
    // space, it is unblocked and not ignored, as force_sig makes it
    if crate::task::ptrace::is_traced(&me) {
        force_sig_info(&me, sig, info);
        return;
    }
    let sighand = get_task_sighand(&me);
    let action = sighand
        .as_ref()
        .map(|h| h.get_action(sig))
        .unwrap_or_default();
    let blocked = with_task_signal_state(&me, |s| s.blocked.contains(sig)).unwrap_or(true);

    if let SigHandler::Handler(_) = action.handler
        && !blocked
    {
        if deliver_to_handler(&me, sig, &action, &info, regs) {
            return;
        }
        // No room for the frame: SIGSEGV was reset to SIG_DFL and queued
        do_exit(SIGSEGV.into());
    }

    if blocked || action.handler == SigHandler::Ignore {
        if let Some(h) = &sighand {
            let _ = h.set_action(sig, SigAction::default());
        }
        with_task_signal_state(&me, |s| {
            s.blocked.remove(sig);
        });
    }
    do_exit(sig.into());
}

/// rt_sigreturn found an unusable frame (Linux badframe): kill the caller
/// with SIGSEGV. Returns EFAULT for the (never seen) syscall result.
pub fn sigreturn_badframe() -> KernelError {
    force_sigsegv(&crate::task::percpu::current());
    KernelError::BadAddress
}
