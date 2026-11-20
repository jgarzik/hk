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
//! - Linux sighand->siglock: a handler table's actions, the per-task
//!   state of the tasks naming it (`Task.sig`) and their group's
//!   pending and job-control state are under its siglock
//!   (`lock_task_sighand`)
//!
//! See doc/LOCKING.md for full lock ordering.

pub mod notify;
pub mod pending;
mod sig;
pub mod siginfo;
pub mod stop;
pub mod syscall;

pub use pending::{SigPending, SigQueue};
pub use sig::*;

use crate::sync::spin::Mutex;
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::UserFrame;
use crate::sync::IrqSpinlock;
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
/// handlers, under its siglock (Linux sighand->action).
pub struct SigHand {
    /// Readers and pollers of a signalfd among the tasks sharing this
    /// table (Linux sighand->signalfd_wqh): woken by every signal sent
    /// to one of them
    pub signalfd_wq: crate::sync::waitqueue::WaitQueue,
    /// Tasks whose `Task.sighand` it is (Linux sighand->count), changed
    /// and read under TASKLIST with that field
    users: crate::task::TableCell<u32>,
    /// Linux sighand->siglock: held, with TASKLIST's write lock, while
    /// a task's `Task.sighand` stops naming this table (exec's unshare,
    /// release), so a holder that found it through a task still sees
    /// it there, and while a thread list of a group whose threads name
    /// it changes (`SignalStruct.threads`); held across a send (Linux
    /// send_signal_locked). Thread context only (hk sends no signal
    /// from an interrupt handler: `check_send_context`; Linux
    /// PREEMPT_RT's model), after TASKLIST. Its data is the action
    /// table, one per signal at [`Signal::idx`] (Linux action[sig - 1]),
    /// built in the heap: the array moved through fork's stack frames
    /// used ~9 KB of the 16 KB kernel stack
    siglock: crate::sync::spin::Mutex<Box<[SigAction]>>,
    /// References dropped a grace period late: a table a task stops
    /// naming may still be read under RCU (Linux frees it
    /// SLAB_TYPESAFE_BY_RCU)
    puts: crate::sync::rcu::RcuPuts,
}

crate::rcu_puts!(SigHand, puts);
crate::instance_lock!(SigHand, siglock, Box<[SigAction]>);

/// A table's siglock held (Linux spin_lock(&sighand->siglock)): the
/// proof its siglock-owned state checks (`SignalStruct.threads`)
pub type SigGuard<'a> = crate::sync::InstanceGuard<'a, SigHand>;

/// A table's siglock over its actions, one lockdep class for every table
fn new_siglock(actions: Box<[SigAction]>) -> crate::sync::spin::Mutex<Box<[SigAction]>> {
    crate::sync::spin::Mutex::new(actions)
}

/// `sig`'s action in the table whose siglock `g` holds (Linux
/// t->sighand->action[sig - 1] under siglock)
pub fn action(g: &SigGuard<'_>, sig: Signal) -> SigAction {
    g[sig.idx()].clone()
}

/// A handler table with every action at its default. Out of line: the
/// fill, unrolled, takes a stack slot per action, ~2 KB of frame in
/// every caller fork inlines it into (debug-assertion builds)
#[inline(never)]
fn default_actions() -> Box<[SigAction]> {
    alloc::vec![SigAction::new(); NSIG as usize].into_boxed_slice()
}

impl SigHand {
    /// Create a new signal handler table with all defaults
    pub fn new() -> Self {
        Self::with_actions(default_actions())
    }

    /// A table with `actions`
    fn with_actions(actions: Box<[SigAction]>) -> Self {
        Self {
            signalfd_wq: crate::sync::waitqueue::WaitQueue::new(),
            users: crate::task::TableCell::new(0),
            siglock: new_siglock(actions),
            puts: crate::sync::rcu::RcuPuts::new(),
        }
    }

    /// Task `t` names `new` in place of this table (or none), under
    /// TASKLIST's write lock (`table`) and this table's siglock (`g`;
    /// Linux unshare_sighand, __exit_signal); the old reference is
    /// dropped a grace period later
    pub(crate) fn leave(
        &self,
        t: &Task,
        new: Option<Arc<SigHand>>,
        table: &mut crate::task::tasklist::GlobalTaskTable,
        g: &SigGuard<'_>,
    ) {
        assert!(
            core::ptr::eq(g.owner(), self),
            "leave: not this table's siglock"
        );
        self.put(table);
        t.sighand.replace(new, table).defer_put();
    }

    /// One more task uses it (under TASKLIST's write lock)
    fn get(&self, table: &mut crate::task::tasklist::GlobalTaskTable) {
        *self.users.access_mut(table) += 1;
    }

    /// One task fewer uses it (under TASKLIST's write lock)
    fn put(&self, table: &mut crate::task::tasklist::GlobalTaskTable) {
        let n = self.users.access_mut(table);
        *n = n.saturating_sub(1);
    }

    /// `sig`'s action, under this table's siglock (the caller holds
    /// none: [`action`] under a held one)
    pub fn get_action(&self, sig: Signal) -> SigAction {
        action(&SigGuard::lock(self), sig)
    }

    /// The (ignored, caught) masks: signals whose handler is SIG_IGN, and
    /// those with a handler of their own (Linux collect_sigign_sigcatch),
    /// read in one hold of its siglock
    pub fn ign_cgt(&self) -> (u64, u64) {
        let (mut ign, mut cgt) = (0, 0);
        for (i, a) in SigGuard::lock(self).iter().enumerate() {
            let bit = 1 << i;
            match a.handler {
                SigHandler::Ignore => ign |= bit,
                SigHandler::Handler(_) => cgt |= bit,
                SigHandler::Default => {}
            }
        }
        (ign, cgt)
    }

    /// Set `sig`'s action under its siglock; the old one, or EINVAL for
    /// SIGKILL and SIGSTOP, whose action cannot change (Linux
    /// do_sigaction)
    pub fn set_action(&self, sig: Signal, action: SigAction) -> Result<SigAction, KernelError> {
        if sig.kernel_only() {
            return Err(KernelError::InvalidArgument);
        }
        let mut g = SigGuard::lock(self);
        Ok(core::mem::replace(&mut g[sig.idx()], action))
    }

    /// Deep clone for fork (without CLONE_SIGHAND)
    ///
    /// Creates a new SigHand with copies of all signal actions.
    pub fn deep_clone(self: &Arc<Self>) -> Result<Arc<Self>, KernelError> {
        // Allocated before the siglock is taken: nothing allocates
        // under it but a send's queue entry
        let mut actions = default_actions();
        actions.clone_from_slice(&SigGuard::lock(self));
        try_arc(Self::with_actions(actions))
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
        let mut g = SigGuard::lock(self);
        for action in g.iter_mut() {
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

/// User `stack_t` (sigaltstack, ucontext uc_stack)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserStack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub _pad: i32,
    pub ss_size: u64,
}
crate::pod!(UserStack {
    ss_sp,
    ss_flags,
    _pad,
    ss_size
});
const _: () = assert!(core::mem::size_of::<UserStack>() == 24);

/// Alternate signal stack state (Linux task sas_ss_sp, sas_ss_size,
/// sas_ss_flags)
#[derive(Clone, Copy, Debug)]
pub struct AltStack {
    /// Stack pointer (base address)
    pub ss_sp: u64,
    /// Stack size (0: none)
    pub ss_size: usize,
    /// The flags it was set with (mode word and SS_AUTODISARM)
    pub ss_flags: i32,
}

impl AltStack {
    /// None (Linux sas_ss_reset)
    pub const fn new() -> Self {
        Self {
            ss_sp: 0,
            ss_size: 0,
            ss_flags: ss_flags::SS_DISABLE,
        }
    }

    /// `sp` lies on it (Linux __on_sig_stack; the stack grows down)
    pub fn contains(&self, sp: u64) -> bool {
        sp > self.ss_sp && sp - self.ss_sp <= self.ss_size as u64
    }

    /// A thread at `sp` runs on it (Linux on_sig_stack): never with
    /// SS_AUTODISARM, which disarmed it on entry
    pub fn on(&self, sp: u64) -> bool {
        self.ss_flags & ss_flags::SS_AUTODISARM == 0 && self.contains(sp)
    }

    /// Its state seen from `sp` (Linux sas_ss_flags): SS_DISABLE,
    /// SS_ONSTACK or 0
    pub fn flags_at(&self, sp: u64) -> i32 {
        if self.ss_size == 0 {
            ss_flags::SS_DISABLE
        } else if self.on(sp) {
            ss_flags::SS_ONSTACK
        } else {
            0
        }
    }

    /// Its top, where a handler's frame starts
    pub fn top(&self) -> u64 {
        self.ss_sp.wrapping_add(self.ss_size as u64)
    }

    /// The stack a handler with `sa_flags` starts on, interrupting `sp`
    /// (Linux sigsp), and whether that enters this one: its top for
    /// SA_ONSTACK unless it is absent or already in use
    pub fn sigsp(&self, sp: u64, sa_flags: u64) -> (u64, bool) {
        if sa_flags & sa_flags::SA_ONSTACK != 0 && self.flags_at(sp) == 0 {
            (self.top(), true)
        } else {
            (sp, false)
        }
    }

    /// Its `uc_stack` in a handler frame (Linux __save_altstack: the
    /// stored flags, not whether the handler runs on it)
    pub fn save(&self) -> UserStack {
        UserStack {
            ss_sp: self.ss_sp,
            ss_flags: self.ss_flags,
            _pad: 0,
            ss_size: self.ss_size as u64,
        }
    }
}

/// Per-task signal state (NOT shared via CLONE_SIGHAND)
///
/// Each task has its own blocked mask and private pending signals; its
/// thread group's are in its SignalStruct (`Task::cpu_group`, Linux
/// t->signal->shared_pending).
pub struct TaskSignalState {
    /// Blocked signal mask
    pub blocked: SigSet,
    /// The mask before a syscall's temporary one (rt_sigsuspend, ppoll,
    /// pselect6, epoll_pwait): valid while the task's TIF_RESTORE_SIGMASK
    /// is set (Linux saved_sigmask)
    pub saved_sigmask: SigSet,
    /// Pending signals for this task (private)
    pub pending: SigPending,
    /// Alternate signal stack
    pub altstack: AltStack,
    /// The mask before sigtimedwait unblocked the awaited signals
    /// (Linux real_blocked): such a signal does not kill on arrival
    pub real_blocked: SigSet,
    /// The last fault's sigcontext details (Linux thread.trap_nr,
    /// error_code, cr2 / fault_code, fault_address)
    pub trap: Trap,
    /// Job control bits (Linux task->jobctl, under siglock): [`jobctl`]
    pub jobctl: u32,
    /// A ptrace stop's code (Linux exit_code, under siglock while
    /// traced): the stop's signal until the tracer's wait reports it
    /// (then 0), then the signal the tracer's resume leaves to deliver
    /// (0: none)
    pub ptrace_code: u32,
    /// The siginfo of the ptrace stop it is in, which PTRACE_GETSIGINFO
    /// reads and PTRACE_SETSIGINFO replaces (Linux last_siginfo); none
    /// outside a ptrace stop
    pub last_siginfo: Option<SigInfo>,
}

/// [`TaskSignalState::jobctl`] bits (Linux JOBCTL_*, same positions)
pub mod jobctl {
    /// The stop signal of a pending group stop (Linux
    /// JOBCTL_STOP_SIGMASK)
    pub const STOP_SIGMASK: u32 = 0xffff;
    /// A stop signal was dequeued (Linux JOBCTL_STOP_DEQUEUED): SIGCONT
    /// or SIGKILL since then clears it, cancelling the stop
    pub const STOP_DEQUEUED: u32 = 1 << 16;
    /// To stop for the group (Linux JOBCTL_STOP_PENDING)
    pub const STOP_PENDING: u32 = 1 << 17;
    /// Counted in the group stop (Linux JOBCTL_STOP_CONSUME)
    pub const STOP_CONSUME: u32 = 1 << 18;
    /// A ptrace trap for the group stop is due (Linux JOBCTL_TRAP_STOP)
    pub const TRAP_STOP: u32 = 1 << 19;
    /// A seized tracee is to report a job-control change (Linux
    /// JOBCTL_TRAP_NOTIFY)
    pub const TRAP_NOTIFY: u32 = 1 << 20;
    /// An attach waits for it to enter its trap (Linux JOBCTL_TRAPPING)
    pub const TRAPPING: u32 = 1 << 21;
    /// Its seized tracer listens for job-control events in its
    /// PTRACE_EVENT_STOP trap (Linux JOBCTL_LISTENING): a NOTIFY ends
    /// the trap, and wait and ptrace requests no longer see it
    pub const LISTENING: u32 = 1 << 22;
    /// In a group stop (Linux JOBCTL_STOPPED)
    pub const STOPPED: u32 = 1 << 26;
    /// In a ptrace stop (Linux JOBCTL_TRACED)
    pub const TRACED: u32 = 1 << 27;
    /// Its tracer is inside a ptrace request on it (Linux
    /// JOBCTL_PTRACE_FROZEN): SIGKILL leaves the stop alone until the
    /// request ends
    pub const PTRACE_FROZEN: u32 = 1 << 28;
    /// Linux JOBCTL_TRAP_MASK
    pub const TRAP_MASK: u32 = TRAP_STOP | TRAP_NOTIFY;
    /// Linux JOBCTL_PENDING_MASK: work for the signal path
    pub const PENDING_MASK: u32 = STOP_PENDING | TRAP_MASK;
}

/// The stop signals (Linux SIG_KERNEL_STOP_MASK)
pub const STOP_SIGNALS: SigSet =
    SigSet(SIGSTOP.bit() | SIGTSTP.bit() | SIGTTIN.bit() | SIGTTOU.bit());

/// A thread group's pending signals (Linux signal->shared_pending), the
/// thread that last took one (signal->curr_target) and its forks in
/// progress (signal->multiprocess)
pub struct GroupPending {
    pub pending: SigPending,
    curr_target: Tid,
    /// Each fork's [`ForkDelay`] node, linked from the fork's start to
    /// the child's attach (or the fork's failure)
    multiprocess: crate::util::list::List<DelayLink>,
}

impl GroupPending {
    const fn new() -> Self {
        Self {
            pending: SigPending::new(),
            curr_target: 0,
            multiprocess: crate::util::list::List::new(),
        }
    }

    /// Multiprocess signal `sig`, just queued for the group, appears to
    /// every fork in progress as sent after it (Linux
    /// __send_signal_locked: type > PIDTYPE_TGID): its child gets it
    /// too; a stop signal cancels a delayed SIGCONT and SIGCONT the
    /// delayed stop signals, as they would pending
    fn delay(&self, sig: Signal) {
        for d in self.multiprocess.iter() {
            let mut s = SigSet(d.signal.load(Ordering::Relaxed));
            if sig == SIGCONT {
                s = s.subtract(&STOP_SIGNALS);
            } else if sig.kernel_stop() {
                s.remove(SIGCONT);
            }
            s.add(sig);
            d.signal.store(s.0, Ordering::Relaxed);
        }
    }
}

/// A fork's set of delayed signals (Linux struct multiprocess_signals),
/// on its group's `GroupPending.multiprocess`
struct DelayNode {
    /// Changed under the group's `SignalStruct.shared`
    signal: AtomicU64,
    link: crate::util::list::Link,
}

crate::adapter!(DelayLink, DelayNode, link);

/// A fork in progress (Linux copy_process's `delayed`): signals sent to
/// the forking process as one of several (`PidType::Pgid`) after its
/// start are recorded for the child, which gets them pending at its
/// attach, so they appear sent after the fork ([`fork_signals_begin`])
pub struct ForkDelay {
    /// The forking process's group, while `node` is on its list
    group: Option<Arc<SignalStruct>>,
    node: Box<DelayNode>,
}

impl ForkDelay {
    /// The signals delayed so far, the node off the list (TASKLIST
    /// held for writing: the child's attach)
    fn take(&mut self) -> SigSet {
        let Some(grp) = self.group.take() else {
            return SigSet::EMPTY;
        };
        // Under the forking task's siglock (Linux copy_process, and its
        // failure path: hlist_del_init(&delayed.node) under siglock); its
        // group keeps that table while it lives
        let me = crate::task::percpu::current();
        let rcu = crate::sync::rcu::read_lock();
        let g = lock_task_sighand(&me, &rcu).expect("a forking task names a table");
        let mut gp = grp.shared(&g);
        // SAFETY: linked by fork_signals_begin, still (`group` was set)
        unsafe { gp.multiprocess.remove(&raw const *self.node) };
        SigSet(self.node.signal.load(Ordering::Relaxed))
    }
}

impl Drop for ForkDelay {
    /// A failed fork's node leaves the list before it is freed
    fn drop(&mut self) {
        let _ = self.take();
    }
}

/// A fork starts (Linux copy_process): a new process's fork records the
/// multiprocess signals sent to the caller's group from now on; then a
/// signal the caller must handle first is ERESTARTNOINTR (Linux
/// recalc_sigpending, task_sigpending), so the fork restarts after it
/// and the signal comes before the fork. ENOMEM.
pub fn fork_signals_begin(me: &Task, thread: bool) -> KernelResult<ForkDelay> {
    let node = crate::util::kalloc::try_box(DelayNode {
        signal: AtomicU64::new(0),
        link: crate::util::list::Link::new(),
    })?;
    let mut d = ForkDelay { group: None, node };
    // Linux copy_process: the caller's siglock across both
    let rcu = crate::sync::rcu::read_lock();
    let Some(sg) = lock_task_sighand(me, &rcu) else {
        return Ok(d);
    };
    let s = me.sig.borrow(&sg);
    if !thread && let Some(g) = me.cpu_group() {
        let mut gp = g.shared(&sg);
        // SAFETY: boxed (it never moves), and ForkDelay unlinks it
        // (`take`) before the box is freed
        unsafe { gp.multiprocess.push_back(&raw const *d.node) };
        d.group = Some(g.clone());
    }
    let pending = s.has_deliverable_signals(&sg, me);
    me.set_sigpending(pending);
    drop(s);
    drop(sg);
    if pending {
        return Err(KernelError::RestartNoIntr);
    }
    Ok(d)
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

/// Task `t`'s thread group's pending set (Linux t->signal->shared_pending,
/// reached through its fixed signal struct), under its table's siglock
/// `g`; none for a task with no group
pub fn group_pending<'a>(
    g: &'a SigGuard<'_>,
    t: &'a Task,
) -> Option<crate::sync::InstanceRefMut<'a, GroupPending>> {
    t.cpu_group().map(|s| s.shared(g))
}

/// Task `t`'s group's pending signals under `g` (empty with no group)
fn shared_signal(g: &SigGuard<'_>, t: &Task) -> SigSet {
    group_pending(g, t).map_or(SigSet::EMPTY, |p| p.signal)
}

/// Task `t`'s signal state under its table's siglock `g` (Linux: its
/// fields under t->sighand->siglock); panics for another table's
#[inline]
pub fn sig_of<'a>(
    t: &'a Task,
    g: &'a SigGuard<'_>,
) -> crate::sync::InstanceRefMut<'a, TaskSignalState> {
    t.sig.borrow_mut(g)
}

/// Task `t`'s table locked under TASKLIST (`table`; Linux
/// spin_lock(&t->sighand->siglock) under tasklist_lock: the table
/// changes only under its write lock); None once released, or for a
/// kernel thread (no table)
pub fn lock_sighand_in<'a>(
    t: &'a Task,
    table: &'a crate::task::tasklist::GlobalTaskTable,
) -> Option<SigGuard<'a>> {
    t.sighand.protected(table).map(SigGuard::lock)
}

/// /proc's view of task `t`'s signal state under TASKLIST (`table`):
/// blocked, private and group pending masks, in a ptrace stop, in a
/// group stop (Linux task_sig, task_state: under lock_task_sighand);
/// none once released
pub fn proc_sig(
    table: &crate::task::tasklist::GlobalTaskTable,
    t: &Task,
) -> (u64, u64, u64, bool, bool) {
    lock_sighand_in(t, table).map_or((0, 0, 0, false, false), |g| {
        let s = sig_of(t, &g);
        (
            s.blocked.0,
            s.pending.signal.0,
            shared_signal(&g, t).0,
            s.traced(),
            s.jobctl & jobctl::STOPPED != 0,
        )
    })
}

/// Recompute task `t`'s TIF_SIGPENDING from its signal state `s`, its
/// table's siglock held (Linux recalc_sigpending_tsk)
pub fn recalc_sigpending_tsk(g: &SigGuard<'_>, t: &Task, s: &TaskSignalState) {
    t.set_sigpending(s.has_deliverable_signals(g, t));
}

impl TaskSignalState {
    /// The boot task's (const: no shared set)
    pub const fn boot() -> Self {
        Self {
            blocked: SigSet::EMPTY,
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(),
            altstack: AltStack::new(),
            real_blocked: SigSet::EMPTY,
            trap: Trap::NONE,
            jobctl: 0,
            ptrace_code: 0,
            last_siginfo: None,
        }
    }

    /// A task's state with nothing pending or blocked (a kernel thread;
    /// a user task's comes from `fork_signal` or `init_task_signal`)
    pub fn new() -> Self {
        Self::boot()
    }

    /// Check if there are deliverable signals, or job-control work, for
    /// task `t` whose state this is (Linux recalc_sigpending_tsk:
    /// JOBCTL_PENDING_MASK)
    pub fn has_deliverable_signals(&self, g: &SigGuard<'_>, t: &Task) -> bool {
        if self.jobctl & jobctl::PENDING_MASK != 0 {
            return true;
        }
        // Check private pending
        if self.pending.signal.subtract(&self.blocked).any() {
            return true;
        }
        // Check shared pending
        shared_signal(g, t).subtract(&self.blocked).any()
    }

    /// In a ptrace stop (Linux task_is_traced: JOBCTL_TRACED)
    pub fn traced(&self) -> bool {
        self.jobctl & jobctl::TRACED != 0
    }

    /// In a ptrace stop or a group stop (Linux task_is_stopped_or_traced)
    pub fn stopped_or_traced(&self) -> bool {
        self.jobctl & (jobctl::TRACED | jobctl::STOPPED) != 0
    }

    /// Its tracer's request holds its ptrace stop (JOBCTL_PTRACE_FROZEN)
    pub fn frozen(&self) -> bool {
        self.jobctl & jobctl::PTRACE_FROZEN != 0
    }

    /// SIGKILL is pending in its private set (Linux
    /// __fatal_signal_pending; a group kill queues it there for every
    /// thread), the lock held
    pub fn fatal_pending(&self) -> bool {
        self.pending.signal.contains(SIGKILL)
    }

    /// End a ptrace stop it is in: nothing for its tracer's wait (Linux
    /// signal_wake_up_state clearing JOBCTL_TRACED)
    pub fn end_trace_stop(&mut self) {
        if self.traced() {
            self.jobctl &= !jobctl::TRACED;
            self.ptrace_code = 0;
        }
    }
}

// =============================================================================
// Task signal accessors - uses Task struct fields directly via TASKLIST
// =============================================================================

use crate::task::Task;
use crate::task::tasklist::{TASKLIST, TaskRef};

// =============================================================================
// Task Signal APIs
// =============================================================================

/// Initialize signal state for new task `t`
///
/// Called when creating the init process at boot (failure cannot be
/// reported). Also initializes the SignalStruct (which contains rlimits).
pub fn init_task_signal(t: &Task, sighand: Arc<SigHand>) {
    // Built before TASKLIST is taken, with init's limits (init_rlimits)
    let s = SignalStruct::alloc_nofail();
    // The global init (Linux init_signals: SIGNAL_UNKILLABLE)
    s.set_unkillable();
    let state = TaskSignalState::new();
    let mut table = TASKLIST.write();
    if table.view(t).is_some() {
        sighand.get(&mut table);
        // The group's thread list, under its table's siglock (Linux
        // init_signals: thread_head holds init_task)
        let mut g = SigGuard::lock(&sighand);
        s.set_owner(&mut table, &mut g, &sighand);
        let me = crate::task::tasklist::task_ref(t);
        s.threads.access_mut(&mut table, &mut g).push_back(me);
        // Its own state is the table's from now on
        t.sig.set_owner(&mut g, &sighand);
        *sig_of(t, &g) = state;
        t.set_sigpending(false);
        drop(g);
        // Named before anyone can lock it
        t.sighand.replace(Some(sighand), &mut table).defer_put();
    }
    if let Some(task) = table.view_mut(t) {
        task.task.set_cpu_group(&s);
    }
    let pid = table.view(t).and_then(|v| v.thread_pid());
    s.set_leader_pid(&mut table, pid);
}

/// Task `t`'s signal handlers, read under RCU (Linux
/// rcu_dereference(t->sighand))
pub fn get_task_sighand(t: &Task) -> Option<Arc<SigHand>> {
    t.sighand.get(&crate::sync::rcu::read_lock())
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

/// Access task `t`'s signal state for modification under its table's
/// siglock (Linux lock_task_sighand); None once it is released
///
/// Afterwards the task's TIF_SIGPENDING flag is recomputed, so it always
/// means "a signal is deliverable under the current blocked mask" (what
/// interruptible sleeps test via `signal_pending()`).
pub fn with_task_signal_state<F, R>(t: &Task, f: F) -> Option<R>
where
    F: FnOnce(&mut TaskSignalState) -> R,
{
    let rcu = crate::sync::rcu::read_lock();
    let g = lock_task_sighand(t, &rcu)?;
    Some(with_sig(&g, t, |_, s| f(s)))
}

/// [`with_task_signal_state`] with its group's pending set too (Linux
/// t->signal->shared_pending under the same siglock); None for the set
/// of a task with no group
pub fn with_task_sig_group<F, R>(t: &Task, f: F) -> Option<R>
where
    F: FnOnce(&mut TaskSignalState, Option<&mut GroupPending>) -> R,
{
    let rcu = crate::sync::rcu::read_lock();
    let g = lock_task_sighand(t, &rcu)?;
    Some(with_sig(&g, t, |t, s| {
        f(s, group_pending(&g, t).as_deref_mut())
    }))
}

/// Run `f` on task `t`'s signal state under its table's siglock `g`,
/// then recompute its TIF_SIGPENDING; group signals it newly blocked go
/// to another thread, in the same hold (Linux __set_task_blocked:
/// retarget_shared_pending under siglock)
fn with_sig<F, R>(g: &SigGuard<'_>, t: &Task, f: F) -> R
where
    F: FnOnce(&Task, &mut TaskSignalState) -> R,
{
    let mut s = sig_of(t, g);
    let old = s.blocked;
    let r = f(t, &mut s);
    let newly = s.blocked.subtract(&old);
    let moved = if newly.any() {
        shared_signal(g, t).intersect(&newly)
    } else {
        SigSet::EMPTY
    };
    recalc_sigpending_tsk(g, t, &s);
    drop(s);
    if moved.any() {
        retarget(g, t, moved);
    }
    r
}

/// [`with_sig`] for a send, which changes no blocked mask and so
/// retargets nothing
fn with_sig_send<F, R>(g: &SigGuard<'_>, t: &Task, f: F) -> R
where
    F: FnOnce(&Task, &mut TaskSignalState) -> R,
{
    let mut s = sig_of(t, g);
    let r = f(t, &mut s);
    recalc_sigpending_tsk(g, t, &s);
    r
}

/// Group signals `which` that `t` will not take (blocked, or exiting):
/// wake other threads that will, its group's thread list walked under
/// its table's siglock `g` (Linux retarget_shared_pending)
fn retarget(g: &SigGuard<'_>, t: &Task, which: SigSet) {
    let Some(group) = t.cpu_group() else {
        return;
    };
    let mut left = which;
    for u in group.threads(g) {
        if core::ptr::eq(u, t) || u.has_flag(crate::task::pf::EXITING) {
            continue;
        }
        let s = sig_of(u, g);
        if left.subtract(&s.blocked).is_empty() {
            continue;
        }
        // It takes those it does not block, marked and woken (Linux
        // retarget_shared_pending: signal_wake_up under siglock)
        left = left.intersect(&s.blocked);
        if !u.sigpending() {
            recalc_sigpending_tsk(g, u, &s);
            signal_wake_task(u, crate::task::percpu::WakeMode::Interruptible);
        }
        drop(s);
        if left.is_empty() {
            break;
        }
    }
}

/// The current thread starts its exit: PF_EXITING set under its
/// siglock ([`stop::exit_participate`]), then group signals it would
/// have taken go to another thread (Linux exit_signals)
#[inline(never)]
pub fn exit_signals() {
    let me = crate::task::percpu::current();
    stop::exit_participate();
    if !me.sigpending() {
        return;
    }
    let rcu = crate::sync::rcu::read_lock();
    let Some(g) = lock_task_sighand(&me, &rcu) else {
        return;
    };
    let which = {
        let s = sig_of(&me, &g);
        shared_signal(&g, &me).subtract(&s.blocked)
    };
    if which.any() {
        retarget(&g, &me, which);
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
///
/// The child inherits the alternate stack unless `reset_sas` (Linux
/// copy_process: a CLONE_VM child without CLONE_VFORK runs on the same
/// memory at once, so it starts without one).
pub fn fork_signal(
    parent: &Task,
    share_sighand: bool,
    share_pending: bool,
    clear_sighand: bool,
    reset_sas: bool,
) -> Result<(TaskSignalState, ForkSignal), KernelError> {
    // Get parent's sighand and signal_state
    // The parent's blocked mask and shared set (no queued info is
    // copied: a child starts with nothing pending)
    let (parent_sighand, parent_state) = {
        let table = TASKLIST.read();
        let parent = table.view(parent);
        (
            parent.and_then(|p| p.sighand()),
            parent.and_then(|p| {
                let g = lock_sighand_in(p.task, &table)?;
                let s = sig_of(p.task, &g);
                Some((s.blocked, s.trap, s.altstack))
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
    let child_state = match parent_state {
        Some((blocked, trap, altstack)) => TaskSignalState {
            blocked, // Inherit blocked mask
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(), // Fresh private pending
            altstack: if reset_sas { AltStack::new() } else { altstack },
            real_blocked: SigSet::EMPTY,
            // The thread struct is copied (Linux arch_dup_task_struct)
            trap,
            // In no ptrace stop: the parent, running fork, is in none
            jobctl: 0,
            ptrace_code: 0,
            last_siginfo: None,
        },
        None => TaskSignalState::new(),
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

/// Before TASKLIST: an inherited finite RLIMIT_CPU is watched from the
/// start (Linux posix_cpu_timers_init_group)
pub fn fork_cpu_watch(child: &Task, f: &ForkSignal) {
    if !f.share_signal {
        crate::time::cpu_timer::rlimit_cpu_changed(&f.signal, child.tid());
    }
}

/// Attach new task `child`'s shared signal objects in the TASKLIST
/// write section (`table`) that lists it, before anyone can find it
/// (Linux copy_process: copy_sighand / copy_signal before, the group's
/// pending set under tasklist_lock and siglock).
/// The multiprocess signals the fork recorded (`delay`) become the new
/// process's pending signals, in the same TASKLIST hold that makes it
/// reachable by a send (Linux copy_process: shared_pending.signal =
/// delayed.signal under siglock and tasklist_lock), and its first
/// return to user mode looks for them (Linux schedule_tail:
/// calculate_sigpending).
pub fn install_fork_signal(
    table: &mut crate::task::tasklist::GlobalTaskTable,
    child: &Task,
    f: ForkSignal,
    mut delay: ForkDelay,
) {
    if f.joined {
        // CLONE_THREAD: one more live thread
        f.signal.thread_added();
    }
    // The parent's siglock taken and dropped before the child's (one
    // table for a thread)
    let delayed = delay.take();
    if table.view(child).is_some() {
        f.sighand.get(table);
        // On its group's thread list, under TASKLIST's write lock and
        // its table's siglock (Linux copy_process: list_add_tail_rcu of
        // thread_node; a new group's list starts with its leader); a
        // thread shares its group's table (CLONE_THREAD needs
        // CLONE_SIGHAND), the list's owner
        let mut g = SigGuard::lock(&f.sighand);
        if !f.share_signal {
            f.signal.set_owner(table, &mut g, &f.sighand);
            // The multiprocess signals the fork recorded
            if delayed.any() {
                let mut gp = f.signal.shared(&g);
                gp.pending.signal = gp.pending.signal.union(&delayed);
                child.set_sigpending(true);
            }
        }
        let c = crate::task::tasklist::task_ref(child);
        f.signal.threads.access_mut(table, &mut g).push_back(c);
        // Its own state, set up unseen, is the table's from now on
        child.sig.set_owner(&mut g, &f.sighand);
        drop(g);
        // Not named before (the child is new): nothing to retire
        child.sighand.replace(Some(f.sighand), table).defer_put();
    }
    // A new process: the child leads it, with its parent's controlling
    // tty (Linux copy_process, under tasklist_lock)
    if !f.share_signal {
        let pid = table.view(child).and_then(|c| c.thread_pid());
        f.signal.set_leader_pid(table, pid);
        let me = crate::task::percpu::current();
        if let Some(ps) = table.view(&me).and_then(|p| p.signal().cloned()) {
            // One ctty lock at a time: it is a leaf
            let tty = ps.ctty.lock().tty();
            f.signal.ctty.lock().inherit(tty);
        }
    }
    if table.view(child).is_some() {
        child.set_cpu_group(&f.signal);
    }
}

// =============================================================================
// Signal Sending
// =============================================================================

/// What an exec does to the caller's signals (Linux begin_new_exec):
/// a handler table shared with another process (CLONE_SIGHAND) is
/// copied first (unshare_sighand: ENOMEM), then caught signals go back
/// to SIG_DFL (flush_signal_handlers; ignored ones stay ignored), the
/// alternate stack is forgotten (sas_ss_sp and sas_ss_size 0, its
/// flags kept), and the process's
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
        // Allocated before the locks (Linux unshare_sighand:
        // kmem_cache_alloc, then the actions copied under the old
        // siglock)
        let mut new = try_arc(SigHand::new())?;
        // The old reference goes after TASKLIST
        // Under TASKLIST's write lock and the old table's siglock
        // (Linux unshare_sighand)
        let mut table = TASKLIST.write();
        if table.view(&me).is_some()
            && let Some(prev) = me.sighand.get_protected(&table)
        {
            let mut g = SigGuard::lock(&prev);
            // Not shared yet: its actions are written without its lock
            Arc::get_mut(&mut new)
                .expect("a new table is unshared")
                .siglock
                .get_mut()
                .clone_from_slice(&g);
            new.get(&mut table);
            // Its group's list (the caller alone, after de_thread) is
            // the new table's from now on
            if let Some(s) = me.cpu_group() {
                s.set_owner(&mut table, &mut g, &new);
            }
            // Its own state follows its table (Linux: task fields under
            // whichever siglock me->sighand names)
            me.sig.set_owner(&mut g, &new);
            prev.leave(&me, Some(new), &mut table, &g);
            drop(g);
            drop(table);
            drop(prev);
        }
    }
    if let Some(h) = get_task_sighand(&me) {
        h.flush_handlers();
    }
    if let Some(sig) = get_task_signal_struct(&me) {
        crate::time::posix_timer::exec_timers(&sig);
    }
    let _gone = with_task_sig_group(&me, |s, group| {
        // No stack, its flags kept (Linux begin_new_exec zeroes
        // sas_ss_sp and sas_ss_size only)
        s.altstack = AltStack {
            ss_sp: 0,
            ss_size: 0,
            ..s.altstack
        };
        let shared = group.map(|p| p.flush_timers());
        (s.pending.flush_timers(), shared)
    });
    Ok(())
}

/// Group `s`'s pending `sig` is discarded, every queued instance with
/// it, from its set and each thread's, under its siglock `g` (Linux
/// do_sigaction once the action ignores it: flush_sigqueue_mask on
/// shared_pending and for_each_thread; POSIX, whether or not it is
/// blocked); a timer's entry goes back to it, the rest to `gone`
fn flush_group_signal(g: &SigGuard<'_>, s: &SignalStruct, sig: Signal, gone: &mut SigPending) {
    let mask = SigSet::of(sig);
    s.shared(g).flush_mask_into(&mask, gone);
    for t in s.threads(g) {
        with_sig_send(g, t, |_, st| st.pending.flush_mask_into(&mask, gone));
    }
    crate::time::posix_timer::flush_ignored(g, s, gone);
}

/// Install `new` as the current process's action for `sig` (not
/// SIGKILL or SIGSTOP), the old one returned (Linux do_sigaction), in
/// one hold of its siglock: the install, the flush of what it now
/// ignores, or the requeue of interval timers whose signal it no
/// longer ignores (Linux posixtimer_sig_unignore). Flushed entries are
/// freed after it. ESRCH if the caller has no table.
pub fn do_sigaction(sig: Signal, new: SigAction) -> KernelResult<SigAction> {
    if sig.kernel_only() {
        return Err(KernelError::InvalidArgument);
    }
    let me = crate::task::percpu::current();
    let mut gone = SigPending::new();
    let rcu = crate::sync::rcu::read_lock();
    let mut g = lock_task_sighand(&me, &rcu).ok_or(KernelError::NoProcess)?;
    let ignores = new.ignores(sig);
    let old = core::mem::replace(&mut g[sig.idx()], new);
    if let Some(s) = me.cpu_group() {
        if ignores {
            flush_group_signal(&g, s, sig, &mut gone);
        } else if old.is_ignore() {
            crate::time::posix_timer::sig_unignore(&g, s, sig);
        }
    }
    drop(g);
    Ok(old)
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
    let rcu = crate::sync::rcu::read_lock();
    lock_task_sighand(t, &rcu).is_some_and(|g| sig_of(t, &g).fatal_pending())
}

/// Whether `sig` would be discarded on arrival (Linux sig_ignored): its
/// handler is SIG_IGN, or SIG_DFL with an "ignore" default (SIGCHLD,
/// SIGURG, SIGWINCH, and SIGCONT once its prepare is done), and it is
/// not blocked (a blocked signal stays queued: the handler may change),
/// awaited by sigtimedwait (blocked before it: real_blocked), nor for a
/// `traced` task, whose tracer sees it first
fn sig_ignored(state: &TaskSignalState, g: &SigGuard<'_>, sig: Signal, traced: bool) -> bool {
    let held = state.blocked.contains(sig) || state.real_blocked.contains(sig);
    // A tracer sees even an ignored signal, but SIGKILL (never ignored)
    if held || traced || sig.kernel_only() {
        return false;
    }
    action(g, sig).ignores(sig)
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
fn init_ignores(state: &TaskSignalState, g: &SigGuard<'_>, sig: Signal) -> bool {
    if sig.kernel_only() {
        return true;
    }
    if state.blocked.contains(sig) || state.real_blocked.contains(sig) {
        return false;
    }
    action(g, sig).is_default()
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
    /// A child's notice to its parent or tracer, numbered for the
    /// receiver already (Linux do_notify_parent's __send_signal_locked):
    /// queued as given, its sender never checked or forcing
    Notice(SigInfo),
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
            Self::Info(i) | Self::Notice(i) => *i,
        }
    }

    /// SIGKILL and SIGSTOP with it reach a namespace init (Linux
    /// send_signal_locked's `force`): from the kernel, or from a sender
    /// the receiver's namespace `ns` does not number (an ancestor's, or
    /// one whose pid is already detached), with an info that names its
    /// sender
    fn forces(&self, ns: &PidNs) -> bool {
        let unseen = || sender_nr(ns) == 0;
        match self {
            Self::User => unseen(),
            Self::Kernel => true,
            Self::Info(i) => i.has_sender() && (i.code == si_code::SI_KERNEL || unseen()),
            Self::Notice(_) => false,
        }
    }

    /// [`resolve`](Self::resolve) for a send that checks its sender
    /// (Linux send_signal_locked): an info naming its sender names none
    /// if the receiver's namespace `ns` does not number the sending
    /// task, in any namespace (an ancestor's sender, or one whose pid
    /// is already detached)
    fn resolve_checked(&self, sig: Signal, ns: &PidNs) -> SigInfo {
        let mut i = self.resolve(sig, ns);
        if matches!(self, Self::Info(_)) && sender_nr(ns) == 0 {
            i.hide_sender();
        }
        i
    }

    /// A non-RT signal's entry may pass RLIMIT_SIGPENDING unless a user
    /// queued it (si_code < 0); an RT one never does (Linux
    /// __send_signal_locked's override_rlimit)
    fn override_rlimit(&self, sig: Signal) -> bool {
        !sig.is_rt() && !matches!(self, Self::Info(i) | Self::Notice(i) if i.code < 0)
    }

    /// With no entry, the send fails with EAGAIN: an RT signal a user
    /// queued with info other than kill's (Linux: queue overflow)
    fn must_queue(&self, sig: Signal) -> bool {
        sig.is_rt() && matches!(self, Self::Info(i) | Self::Notice(i) if i.code != si_code::SI_USER)
    }
}

type PidNs = crate::ns::PidNamespace;

/// The current task's thread pid as `ns` numbers it, 0 if `ns` does not
/// see it or it is detached (no longer listed: Linux task_pid_nr_ns(
/// current, ns) after release_task's detach_pid), read under RCU
fn sender_nr(ns: &PidNs) -> u32 {
    let g = crate::sync::rcu::read_lock();
    crate::task::percpu::current().pid_nr_ns(ns, &g)
}

/// Lock task `t`'s handler table (Linux lock_task_sighand): the table it
/// names under RCU (`g`), its siglock taken, then checked still to be
/// the one `t` names (a racing exec's unshare or `t`'s release changed
/// it under that siglock: again); None once `t` is released (Linux
/// ESRCH). A table read here stays allocated for `g`'s life (its
/// references go through `put_rcu`).
pub fn lock_task_sighand<'a>(
    t: &'a Task,
    g: &'a crate::sync::rcu::RcuReadGuard,
) -> Option<SigGuard<'a>> {
    loop {
        let h = t.sighand.read(g)?;
        let sg = SigGuard::lock(h);
        // Changes only under that siglock, now held
        if core::ptr::eq(t.sighand.as_ptr(), h) {
            return Some(sg);
        }
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
/// PIDTYPE_PID, with no permission check): ESRCH (reaped), or EAGAIN
/// when an RT signal's info cannot be queued; a [`Signal`] is always
/// a valid number
pub fn send_sig_info(t: &Task, sig: Signal, info: SendInfo) -> KernelResult<()> {
    send_task(t, sig, info, PidType::Pid, false)
}

/// Whom a signal is for (Linux enum pid_type, as a send uses it)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidType {
    /// The thread (PIDTYPE_PID)
    Pid,
    /// Its whole thread group (PIDTYPE_TGID)
    Tgid,
    /// Its whole thread group, one of the several processes the signal
    /// goes to: a process group, a session, or every process (Linux
    /// PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX: type > PIDTYPE_TGID); a
    /// fork in progress delays it for its child ([`ForkDelay`])
    Pgid,
}

/// The receiver of a send, read under its siglock (it is not released:
/// its table is still the one locked): the global init, its real uid,
/// RLIMIT_SIGPENDING, handlers and group
struct Target {
    /// A thread of the global init (Linux is_global_init)
    global: bool,
    /// Traced: it ignores no signal but SIGKILL (Linux sig_ignored)
    traced: bool,
    /// The receiver's real uid's counters (Linux task_ucounts)
    ucounts: crate::task::UcountsRef,
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

/// The receiver `t` of a send, its siglock held, under RCU (`g`): its
/// credentials under RCU, its ptrace flags racily (Linux sig_ignored
/// reads t->ptrace under siglock)
fn target(t: &Task, g: &crate::sync::rcu::RcuReadGuard) -> Target {
    let sig = t.cpu_group();
    let limit = sig.and_then(|s| s.get_rlimit(RLIMIT_SIGPENDING));
    Target {
        global: t.pid == 1,
        traced: t.ptrace() != 0,
        ucounts: t.cred_rcu(g).ucounts.clone(),
        limit: limit.map_or(0, |r| r.rlim_cur),
        sighand: t.sighand.get(g),
        signal: sig.cloned(),
    }
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
/// init even with its action SIG_DFL. ESRCH once `t` is released.
fn send_task(t: &Task, sig: Signal, info: SendInfo, ty: PidType, force: bool) -> KernelResult<()> {
    // Flushed entries go after the siglock
    let mut gone = SigPending::new();
    send_task_in(t, sig, info, ty, force, &mut gone)
}

/// [`send_task`], the entries a stop signal or SIGCONT flushes left in
/// `gone` for the caller to drop with no lock held (Linux
/// do_send_sig_info: lock_task_sighand, send_signal_locked): the whole
/// send, its thread choice, wakeup and any group kill done under the
/// receiver's siglock, reached under RCU; nothing allocated but its
/// queue entry, under the receiver's Task.sig with GFP_ATOMIC. No
/// TASKLIST: a caller holding it (a process-group walk, a child's
/// notice, exit_ptrace, send_sigio, as Linux send_signal_locked under
/// tasklist_lock) sends in place, the siglock taken inside it.
fn send_task_in(
    t: &Task,
    sig: Signal,
    info: SendInfo,
    ty: PidType,
    force: bool,
    gone: &mut SigPending,
) -> KernelResult<()> {
    check_send_context();
    // Kernel threads ignore every signal (Linux ignore_signals in
    // kthreadd): they are processes now (pid == tid), reachable by
    // kill(-1) and kill(pid); hk gives them no handler table
    if t.has_flag(crate::task::pf::KTHREAD) {
        return Ok(());
    }
    let rcu = crate::sync::rcu::read_lock();
    let Some(g) = lock_task_sighand(t, &rcu) else {
        return Err(KernelError::NoProcess);
    };
    let tg = target(t, &rcu);
    // A dying group takes no more signals (Linux prepare_signal:
    // SIGNAL_GROUP_EXIT under siglock; its threads have SIGKILL)
    if tg
        .signal
        .as_ref()
        .is_some_and(|s| matches!(s.group_exit(), GroupExit::Exit(_)))
    {
        return Ok(());
    }
    // A forced signal whose action is SIG_DFL (a blocked or ignored one
    // was reset by the caller) lifts a namespace init's protection
    // (Linux force_sig_info_to_task: SIGNAL_UNKILLABLE cleared); one
    // init handles leaves it protected
    let dfl = || action(&g, sig).is_default();
    if force
        && let Some(s) = tg.signal.as_ref()
        && s.unkillable()
        && dfl()
    {
        s.clear_unkillable();
    }
    let init = tg.protects(sig, info.forces(t.pid_ns()));
    let sighand = tg.sighand.as_ref();
    // Its entry is made under the receiver's lock, GFP_ATOMIC, once the
    // signal is known to be queued (Linux __send_signal_locked); SIGKILL
    // needs none
    let entry = (sig != SIGKILL).then(|| EntryOf {
        info: info.resolve_checked(sig, t.pid_ns()),
        ucounts: &tg.ucounts,
        limit: tg.limit,
        override_rlimit: info.override_rlimit(sig),
    });
    let to = Send {
        sig,
        init,
        info: &info,
        ty,
        traced: tg.traced,
        entry,
    };
    // Job control's process-wide effects, whether or not the signal is
    // then ignored, and the send, under the group lock
    let Ok(_j) = prepare_signal(&g, tg.signal.as_ref(), sig, gone) else {
        return Ok(());
    };
    if let Some(s) = tg.signal.as_ref() {
        crate::time::posix_timer::flush_ignored(&g, s, gone);
    }
    let sent = with_sig_send(&g, t, |t, state| send_locked(&g, t, state, &to));

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
    complete_signal(&g, t, sig, ty, wants, to.init);
    Ok(())
}

/// A stop signal or SIGCONT for group `sig_struct`: its process-wide
/// effects ([`stop::prepare`]), under its table's siglock `g` and the
/// group lock, returned held for the rest of the send. Err: the group
/// is exiting, the signal is dropped with no effect (Linux
/// prepare_signal: SIGNAL_GROUP_EXIT under siglock; a group exit starts
/// under the group lock, `SignalStruct::start_exit`).
fn prepare_signal<'a>(
    g: &'a SigGuard<'_>,
    sig_struct: Option<&'a Arc<SignalStruct>>,
    sig: Signal,
    gone: &mut SigPending,
) -> Result<Option<crate::sync::InstanceRefMut<'a, stop::GroupStop>>, ()> {
    if !sig.kernel_stop() && sig != SIGCONT {
        return Ok(None);
    }
    let Some(s) = sig_struct else {
        return Ok(None);
    };
    let mut j = s.jobctl(g);
    if matches!(s.group_exit(), GroupExit::Exit(_)) {
        return Err(());
    }
    stop::prepare(g, s, &mut j, sig, gone);
    Ok(Some(j))
}

/// What a send is, for its locked part
struct Send<'a> {
    sig: Signal,
    /// An init's protection applies (`Target::protects`)
    init: bool,
    info: &'a SendInfo,
    ty: PidType,
    /// The receiver is traced (`Target::traced`)
    traced: bool,
    /// What its queue entry is made of, if it gets one (SIGKILL needs
    /// none)
    entry: Option<EntryOf<'a>>,
}

/// A queue entry's makings (Linux __sigqueue_alloc's arguments): the
/// info as the receiver's namespace numbers it, and the receiver's user
/// it is charged to within RLIMIT_SIGPENDING
struct EntryOf<'a> {
    info: SigInfo,
    ucounts: &'a crate::task::UcountsRef,
    limit: u64,
    override_rlimit: bool,
}

impl EntryOf<'_> {
    /// The entry, made under the receiver's Task.sig with GFP_ATOMIC
    /// (Linux __send_signal_locked: __sigqueue_alloc(.., GFP_ATOMIC, ..));
    /// None past the limit or without memory
    fn make(&self, sig: Signal) -> Option<Box<SigQueue>> {
        crate::util::kalloc::with_gfp(crate::mm::page_alloc::Gfp::ATOMIC, || {
            SigQueue::alloc(
                sig,
                self.info,
                self.ucounts,
                self.limit,
                self.override_rlimit,
            )
        })
    }
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
    g: &SigGuard<'_>,
    t: &crate::task::Task,
    state: &mut TaskSignalState,
    to: &Send<'_>,
) -> Sent {
    let sig = to.sig;
    if drops(g, t, state, to) {
        return Sent::Dropped;
    }
    let exiting = t.has_flag(crate::task::pf::EXITING);
    // Linux wants_signal, before this signal marks it
    let wants = !state.blocked.contains(sig)
        && !exiting
        && (sig == SIGKILL || (!state.stopped_or_traced() && (t.se.on_cpu() || !t.sigpending())));
    let mut group = None;
    let pending = match to.ty {
        PidType::Pid => &mut state.pending,
        PidType::Tgid | PidType::Pgid => match t.cpu_group() {
            Some(s) => &mut group.insert(s.shared(g)).pending,
            None => return Sent::Dropped,
        },
    };
    match to.entry.as_ref().and_then(|e| e.make(sig)) {
        Some(e) => pending.queue(e),
        None if to.info.must_queue(sig) => return Sent::Overflow,
        None => {}
    }
    pending.add(sig);
    // Let multiprocess signals appear after forks in progress (Linux)
    if to.ty == PidType::Pgid
        && let Some(p) = &group
    {
        p.delay(sig);
    }
    Sent::Queued(wants)
}

/// `to.sig` for task `t` is dropped, `state` its Task.sig's: its own
/// signal while it exits, ignored, a non-RT signal already pending
/// where it would go, or a group signal for a task with no group
/// (Linux task_can_queue_signal, prepare_signal, legacy_queue)
fn drops(g: &SigGuard<'_>, t: &crate::task::Task, state: &TaskSignalState, to: &Send<'_>) -> bool {
    let sig = to.sig;
    if to.ty == PidType::Pid && t.has_flag(crate::task::pf::EXITING) {
        return true;
    }
    if sig_ignored(state, g, sig, to.traced) || (to.init && init_ignores(state, g, sig)) {
        return true;
    }
    match to.ty {
        PidType::Pid => state.pending.legacy(sig),
        PidType::Tgid | PidType::Pgid => t
            .cpu_group()
            .is_none_or(|s| s.shared(g).pending.legacy(sig)),
    }
}

/// Find a thread to take `sig` just queued for `p` and wake it (Linux
/// complete_signal), under its table's siglock `g` ([`choose`],
/// [`deliver`]); `init`: an init's protection applied to the send
fn complete_signal(
    g: &SigGuard<'_>,
    p: &Task,
    sig: Signal,
    ty: PidType,
    p_wants: bool,
    init: bool,
) {
    let chosen = choose(g, p, sig, ty, p_wants, init);
    deliver(g, p, sig, chosen);
}

/// The thread [`choose`] picked for a signal, and whether the signal
/// ends its group
struct Chosen {
    t: TaskRef,
    kill: bool,
}

/// Under siglock: the thread to take `sig` just queued for `p` (Linux
/// complete_signal): `p` if it wanted it when queued (`p_wants`), else
/// for a group signal the next thread from the group's curr_target
/// that does; a fatal one ends the group, never a protected init's
/// while protected (`init`: Linux queues it a fatal signal only while
/// blocked, which no thread wants)
fn choose(
    g: &SigGuard<'_>,
    p: &Task,
    sig: Signal,
    ty: PidType,
    p_wants: bool,
    init: bool,
) -> Option<Chosen> {
    let t = if p_wants {
        crate::task::tasklist::task_ref(p)
    } else if ty == PidType::Pid {
        return None;
    } else {
        pick_thread(g, p, sig)?
    };
    let awaited = sig_of(&t, g).real_blocked.contains(sig);
    let kill = !init && fatal(g, sig) && !awaited;
    Some(Chosen { t, kill })
}

/// Act on [`choose`]'s choice for `sig` queued for `p`, under its
/// table's siglock `g`: end the group if decided, mark and wake the
/// chosen thread
fn deliver(g: &SigGuard<'_>, p: &Task, sig: Signal, chosen: Option<Chosen>) {
    let Some(Chosen { t: c, kill }) = chosen else {
        return;
    };
    if kill {
        group_kill(g, p, sig);
    }
    use crate::task::percpu::WakeMode;
    let mode = if sig == SIGKILL {
        WakeMode::Fatal
    } else {
        WakeMode::Interruptible
    };
    // Marked and woken under siglock (Linux complete_signal:
    // signal_wake_up)
    let s = sig_of(&c, g);
    recalc_sigpending_tsk(g, &c, &s);
    signal_wake_task(&c, mode);
    drop(s);
}

/// Under siglock (`g`): the thread of `p`'s group, from its
/// curr_target on, that wants `sig` (Linux complete_signal's loop over
/// signal->thread_head): it becomes curr_target
fn pick_thread(g: &SigGuard<'_>, p: &Task, sig: Signal) -> Option<TaskRef> {
    let s = p.cpu_group()?;
    s.threads(g).nth(1)?;
    let cur = s.shared(g).curr_target;
    let wants = |t: &&Task| wants_signal(g, t, sig);
    let t = s
        .threads(g)
        .skip_while(|t| t.tid() != cur)
        .find(wants)
        .or_else(|| s.threads(g).take_while(|t| t.tid() != cur).find(wants))?;
    let t = crate::task::tasklist::task_ref(t);
    s.shared(g).curr_target = t.tid();
    Some(t)
}

/// `t` should be woken for `sig` (Linux wants_signal, under its table's
/// siglock `g`: a ptrace or group stop is JOBCTL_TRACED or
/// JOBCTL_STOPPED)
fn wants_signal(g: &SigGuard<'_>, t: &crate::task::Task, sig: Signal) -> bool {
    let s = sig_of(t, g);
    if s.blocked.contains(sig) || t.has_flag(crate::task::pf::EXITING) {
        return false;
    }
    if sig == SIGKILL {
        return true;
    }
    !s.stopped_or_traced() && (t.se.on_cpu() || !t.sigpending())
}

/// A signal for `t` is deliverable (Linux signal_wake_up_state): wake
/// it from a sleep `mode` ends, else, if it runs on another CPU, kick it
/// into the kernel so its return to user mode delivers the signal
/// (kick_process). Any context a send runs in, TASKLIST held or not.
fn signal_wake_task(t: &Task, mode: crate::task::percpu::WakeMode) {
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
/// syscall was given, Linux kill_proc_info's find_vpid and pid_task),
/// once `check` of it allows it: ESRCH, EINVAL, or `check`'s error
pub fn proc_target(
    pid: Pid,
    sig: KillSig,
    check: impl Fn(&Task, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<TaskRef> {
    let g = crate::sync::rcu::read_lock();
    let t = crate::task::tasklist::pid_ns_task(pid, &crate::ns::INIT_PID_NS, &g);
    checked(t, sig, check)
}

/// The receiver of `sig`, `t` itself (for it or its group: Linux
/// sends a group signal to the task pid_task found, a zombie leader
/// included, whose group set it reaches), found under RCU or TASKLIST:
/// ESRCH if there is none, then a bad number's EINVAL (Linux
/// check_kill_permission: valid_signal first), then `check`'s error
fn checked(
    t: Option<&Task>,
    sig: KillSig,
    check: impl Fn(&Task, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<TaskRef> {
    let t = t.ok_or(KernelError::NoProcess)?;
    check(t, sig?)?;
    Ok(crate::task::tasklist::task_ref(t))
}

/// `sig` with `info` to task `t`'s thread group, received as `t`
/// (Linux do_send_sig_info, PIDTYPE_TGID, with no permission check)
pub fn send_group_signal(t: &Task, sig: Signal, info: SendInfo) -> KernelResult<()> {
    send_task(t, sig, info, PidType::Tgid, false)
}

/// [`send_group_signal`] as one of a signal to every process (Linux
/// kill_something_info: group_send_sig_info(.., PIDTYPE_MAX)): a fork
/// in progress delays it for its child
pub fn send_all_signal(t: &Task, sig: Signal, info: SendInfo) -> KernelResult<()> {
    send_task(t, sig, info, PidType::Pgid, false)
}

/// `sig` with `info` to task `t` (`ty` Pid) or its thread group (Tgid),
/// with no permission check, by a caller that may hold TASKLIST (read
/// or write) or spin locks: sent in place under `t`'s siglock, nothing
/// allocated but its queue entry (Linux send_signal_locked under
/// tasklist_lock: send_sigio_to_task, ptrace_attach's SIGSTOP,
/// exit_ptrace's SIGKILL); entries a stop signal or SIGCONT flushes go
/// to `gone`, dropped with no lock held
pub fn send_sig_info_in(
    t: &Task,
    sig: Signal,
    info: SendInfo,
    ty: PidType,
    gone: &mut SigPending,
) -> KernelResult<()> {
    send_task_in(t, sig, info, ty, false, gone)
}

/// `sig` with `info` to the process struct pid `pid` names, after
/// `check` of it allows it (Linux kill_pid_info: the struct pid, never
/// a number a reaped process freed for reuse)
pub fn kill_pid_info(
    pid: &crate::task::pid::Pid,
    sig: Signal,
    info: SendInfo,
    check: impl Fn(&Task, Option<Signal>) -> KernelResult<()>,
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
    check: impl Fn(&Task, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<()> {
    // Found and checked under RCU (Linux kill_pid_info_type:
    // rcu_read_lock, pid_task), then sent under its siglock
    let t = {
        let g = crate::sync::rcu::read_lock();
        checked(pid.task(&g), sig, check)?
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
///
/// The group is walked under TASKLIST's read lock and each process
/// sent to in place (Linux __kill_pgrp_info: do_each_pid_task under
/// tasklist_lock), nothing allocated but each signal's queue entry
/// (GFP_ATOMIC, under its receiver's Task.sig).
pub fn kill_pgrp_info(
    pg: &crate::task::pid::Pid,
    sig: KillSig,
    info: SendInfo,
    check: impl Fn(&Task, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<()> {
    // Flushed entries go after TASKLIST
    let mut gone = SigPending::new();
    let table = TASKLIST.read();
    pgrp_send(&table, pg, sig, info, &check, &mut gone)
}

/// [`kill_pgrp_info`] to the caller's own group, read in the TASKLIST
/// hold that walks it (Linux kill_something_info with pid 0:
/// __kill_pgrp_info(task_pgrp(current)) under tasklist_lock)
pub fn kill_own_pgrp(
    sig: KillSig,
    info: SendInfo,
    check: impl Fn(&Task, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<()> {
    let mut gone = SigPending::new();
    let table = TASKLIST.read();
    let me = crate::task::percpu::current();
    let pg = table.view(&me).and_then(|t| t.pgrp());
    let pg = pg.ok_or(KernelError::NoProcess)?;
    pgrp_send(&table, pg, sig, info, &check, &mut gone)
}

/// [`kill_pgrp_info`]'s walk of group `pg`, under the caller's TASKLIST
/// read hold; flushed entries go to `gone`
fn pgrp_send(
    table: &crate::task::tasklist::GlobalTaskTable,
    pg: &crate::task::pid::Pid,
    sig: KillSig,
    info: SendInfo,
    check: &impl Fn(&Task, Option<Signal>) -> KernelResult<()>,
    gone: &mut SigPending,
) -> KernelResult<()> {
    let mut ret = Err(KernelError::NoProcess);
    let mut ok = false;
    for v in table.pgrp(pg) {
        ret = checked(Some(v.task), sig, check).and_then(|t| {
            sig?.map_or(Ok(()), |s| {
                send_task_in(&t, s, info, PidType::Pgid, false, gone)
            })
        });
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
    let _ = kill_pgrp_info(pg, Ok(Some(sig)), SendInfo::Kernel, |_, _| Ok(()));
}

/// `sig` with `info` once to each process of group `pgid` (Linux
/// kill_something_info: __kill_pgrp_info of find_vpid's struct pid, its
/// processes' leaders on the group's list, the signal
/// process-directed), as [`kill_pgrp_info`]: ESRCH if no group has
/// that number
pub fn kill_pgrp(
    pgid: Pid,
    sig: KillSig,
    info: SendInfo,
    check: impl Fn(&Task, Option<Signal>) -> KernelResult<()>,
) -> KernelResult<()> {
    // The struct pid found before TASKLIST (PIDMAP_LOCK), dropped after
    let pg =
        crate::task::pid::find_pgrp(&crate::ns::INIT_PID_NS, pgid).ok_or(KernelError::NoProcess)?;
    kill_pgrp_info(&pg, sig, info, check)
}

// =============================================================================
// Thread-group exit
// =============================================================================

/// `sig` kills the receiver's whole group on arrival (Linux sig_fatal
/// and !sig_kernel_coredump in complete_signal): SIGKILL, or a SIG_DFL
/// signal whose default is to terminate (core-dump signals end the
/// group at delivery)
fn fatal(g: &SigGuard<'_>, sig: Signal) -> bool {
    if sig == SIGKILL {
        return true;
    }
    let dfl = action(g, sig).is_default();
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
/// thread with live siblings ends them too. Under the group's siglock
/// `g` (its thread walk) and TASKLIST held by the caller (read or
/// write), as the send's: it takes only the threads' Task.sig, so the
/// whole kill completes in place (Linux under siglock).
fn group_kill(g: &SigGuard<'_>, p: &Task, sig: Signal) {
    let Some(s) = p.cpu_group() else {
        return;
    };
    if !s.threads(g).any(|u| !u.has_flag(crate::task::pf::EXITING)) {
        return;
    }
    if (sig == SIGKILL || p.ptrace() == 0) && s.start_exit(g, sig.into(), true) {
        zap_threads(g, s, None);
    }
}

/// `t` has not started exiting (Linux !PF_EXITING, not a zombie)
pub fn task_live(t: &crate::task::tasklist::TaskView<'_>) -> bool {
    !t.task.has_flag(crate::task::pf::EXITING)
        && !matches!(t.state(), crate::task::TaskState::Zombie(_))
}

/// SIGKILL every thread of group `s` that has not started exiting
/// (PF_EXITING: a zombie has it too), but `except` (Linux
/// zap_other_threads): queued privately and woken from interruptible
/// and killable sleeps under its table's siglock `g`. A thread running
/// user code dies on its next return to user mode (a tick or a kick
/// IPI interrupts it: `entry::exit_to_user_mode`).
fn zap_threads(g: &SigGuard<'_>, s: &SignalStruct, except: Option<&Task>) {
    // The thread list walked under siglock, each thread killed and
    // woken under its Task.sig, a ptrace stop ended there too (Linux
    // zap_other_threads under siglock: no allocation, so it may run
    // where a send does, under a caller's spin lock); a wakeup under
    // them is allowed (it takes only pi_lock and run-queue locks)
    // The group stop ends (Linux: group_stop_count = 0, each thread's
    // JOBCTL_PENDING_MASK cleared), under the group lock
    let mut j = s.jobctl(g);
    stop::end_for_kill(&mut j);
    for t in s.threads(g) {
        if except.is_some_and(|e| core::ptr::eq(t, e)) {
            continue;
        }
        if t.has_flag(crate::task::pf::EXITING) {
            stop::clear_pending(&mut sig_of(t, g), jobctl::PENDING_MASK);
            continue;
        }
        let mut ts = sigkill_task(g, t);
        stop::clear_pending(&mut ts, jobctl::PENDING_MASK);
        signal_wake_task(t, crate::task::percpu::WakeMode::Fatal);
        drop(ts);
    }
    drop(j);
}

/// [`zap_threads`] of task `t`'s group but `except`, under its table's
/// siglock (Linux do_group_exit, de_thread: siglock alone)
fn zap_group(t: &Task, except: Option<&Task>) {
    let rcu = crate::sync::rcu::read_lock();
    if let (Some(g), Some(s)) = (lock_task_sighand(t, &rcu), t.cpu_group()) {
        zap_threads(&g, s, except);
    }
}

/// SIGKILL every other thread of task `t`'s group (exec's de_thread)
pub fn zap_group_others(t: &Task) {
    zap_group(t, Some(t));
}

/// Queue SIGKILL for `t` under its table's siglock `g` (Linux sigaddset SIGKILL,
/// signal_wake_up(t, fatal)); a ptrace stop it is in ends here, no
/// longer reported to its tracer's wait (signal_wake_up_state clears
/// JOBCTL_TRACED with the signal queued), so a wait after the kill
/// finds its exit, never the stop; unless its tracer is inside a
/// request on it (JOBCTL_PTRACE_FROZEN), whose end does that. Its
/// state comes back borrowed, for the caller's wakeup.
fn sigkill_task<'a>(
    g: &'a SigGuard<'_>,
    t: &'a Task,
) -> crate::sync::InstanceRefMut<'a, TaskSignalState> {
    let mut s = sig_of(t, g);
    s.pending.add(SIGKILL);
    t.set_sigpending(true);
    if !s.frozen() {
        s.jobctl &= !jobctl::STOPPED;
        s.end_trace_stop();
    }
    s
}

/// A thread just cloned into `parent`'s group dies with it if the group
/// is exiting (Linux copy_process: fatal_signal_pending under siglock).
/// Its signal state is set up (`install_fork_signal`), so a zap that ran
/// before saw it or is seen here.
pub fn zap_new_thread(parent: &Task, child: &Task) {
    let dying = get_task_signal_struct(parent).is_some_and(|s| s.group_exit() != GroupExit::None);
    let rcu = crate::sync::rcu::read_lock();
    if dying && let Some(g) = lock_task_sighand(child, &rcu) {
        drop(sigkill_task(&g, child));
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
    let code = group_exit_code(status);
    crate::task::proc::do_exit(code)
}

/// [`do_group_exit`]'s status, the exit started and the other threads
/// killed under the caller's siglock (Linux do_group_exit: siglock
/// across the SIGNAL_GROUP_EXIT check, its setting and
/// zap_other_threads)
fn group_exit_code(status: i32) -> i32 {
    let me = crate::task::percpu::current();
    let Some(s) = me.cpu_group() else {
        return status;
    };
    let rcu = crate::sync::rcu::read_lock();
    let Some(g) = lock_task_sighand(&me, &rcu) else {
        return status;
    };
    loop {
        match s.group_exit() {
            GroupExit::Exit(code) => break code,
            GroupExit::Exec(_) => break 0,
            GroupExit::None if s.start_exit(&g, status, false) => {
                zap_threads(&g, s, Some(&*me));
                break status;
            }
            // Lost a race with an exec's start (no siglock): look again
            GroupExit::None => {}
        }
    }
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
        let (d, alrm) = with_task_sig_group(t, |state, group| {
            let blocked = state.blocked;
            match state.pending.dequeue_sync(&blocked) {
                Some(d) => Some((d, false)),
                None => dequeue_locked(state, group, &blocked),
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
fn dequeue_locked(
    state: &mut TaskSignalState,
    group: Option<&mut GroupPending>,
    skip: &SigSet,
) -> Option<(pending::Dequeued, bool)> {
    let (d, alrm) = match state.pending.dequeue(skip) {
        Some(d) => (d, false),
        None => {
            let d = group?.dequeue(skip)?;
            let alrm = d.sig() == SIGALRM;
            (d, alrm)
        }
    };
    // A stop signal on its way: a SIGCONT or SIGKILL meanwhile cancels
    // the stop (Linux dequeue_signal: JOBCTL_STOP_DEQUEUED)
    if d.sig().kernel_stop() {
        state.jobctl |= jobctl::STOP_DEQUEUED;
    }
    Some((d, alrm))
}

/// Dequeue the current task's next pending signal of `wanted`, with its
/// info (Linux dequeue_signal with the complement of `wanted`:
/// sigtimedwait, signalfd)
pub fn dequeue_signal(wanted: &SigSet) -> Option<(Signal, SigInfo)> {
    let skip = SigSet(!wanted.0);
    let me = crate::task::percpu::current();
    loop {
        let (d, alrm) =
            with_task_sig_group(&me, |state, group| dequeue_locked(state, group, &skip))??;
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
/// thread choice of any group signal. An ignored signal's entry goes
/// back to its timer under the siglock ([`posix_timer::sig_ignore`]);
/// one that could not be queued otherwise comes back.
///
/// [`posix_timer::sig_ignore`]: crate::time::posix_timer::sig_ignore
pub fn send_timer_sigqueue(
    pid: &crate::task::pid::Pid,
    ty: PidType,
    q: Box<SigQueue>,
) -> Result<(), Box<SigQueue>> {
    let sig = q.sig();
    let me = crate::task::percpu::current();
    // The task its struct pid names now, if any (Linux pid_task under
    // RCU); a group signal is taken by the current thread if it is in
    // the group (posixtimer_get_target)
    let rcu = crate::sync::rcu::read_lock();
    let Some(found) = pid.task(&rcu) else {
        return Err(q);
    };
    let t: &Task =
        if ty != PidType::Pid && me.pid == found.tid() && !me.has_flag(crate::task::pf::EXITING) {
            &me
        } else {
            found
        };
    // The send and its thread choice under its siglock (Linux
    // posixtimer_send_sigqueue: lock_task_sighand); flushed entries go
    // after it
    let mut gone = SigPending::new();
    let Some(g) = lock_task_sighand(t, &rcu) else {
        return Err(q);
    };
    let tg = target(t, &rcu);
    let Some(group) = tg.signal.as_ref() else {
        return Err(q);
    };
    if t.has_flag(crate::task::pf::KTHREAD) {
        return Err(q);
    }
    let ignore = |q| {
        crate::time::posix_timer::sig_ignore(&g, group, q);
        Ok(())
    };
    // A dying group ignores it (Linux prepare_signal)
    if matches!(group.group_exit(), GroupExit::Exit(_)) {
        return ignore(q);
    }
    let sighand = tg.sighand.as_ref();
    let Ok(_j) = prepare_signal(&g, Some(group), sig, &mut gone) else {
        return ignore(q);
    };
    crate::time::posix_timer::flush_ignored(&g, group, &mut gone);
    let mut q = Some(q);
    let r = with_sig_send(&g, t, |task, state| {
        let exiting = task.has_flag(crate::task::pf::EXITING);
        if exiting && ty == PidType::Pid {
            return Err(false);
        }
        if sig_ignored(state, &g, sig, tg.traced) {
            return Err(true);
        }
        let wants = !state.blocked.contains(sig)
            && !exiting
            && !state.stopped_or_traced()
            && (task.se.on_cpu() || !task.sigpending());
        let Some(e) = q.take() else {
            return Err(false);
        };
        match ty {
            PidType::Pid => state.pending.queue(e),
            PidType::Tgid | PidType::Pgid => match task.cpu_group() {
                Some(s) => s.shared(&g).queue(e),
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
            complete_signal(&g, t, sig, ty, wants, init);
            Ok(())
        }
        Err(true) => ignore(q.expect("an unqueued entry comes back")),
        Err(false) => Err(q.expect("an unqueued entry comes back")),
    }
}

/// Queue timer entry `q` for the task `pid` names, of the process whose
/// table's siglock `g` is held, or its group (`ty`; Linux
/// posixtimer_get_unignore_target, posixtimer_queue_sigqueue: no
/// ignore or legacy check), then its thread choice; the entry comes
/// back if that task cannot take it (gone, another table's, or an
/// exiting thread for its own signal)
pub fn queue_timer_locked(
    g: &SigGuard<'_>,
    pid: &crate::task::pid::Pid,
    ty: PidType,
    q: Box<SigQueue>,
) -> Result<(), Box<SigQueue>> {
    let me = crate::task::percpu::current();
    let rcu = crate::sync::rcu::read_lock();
    let Some(found) = pid.task(&rcu) else {
        return Err(q);
    };
    let t: &Task =
        if ty != PidType::Pid && me.pid == found.tid() && !me.has_flag(crate::task::pf::EXITING) {
            &me
        } else {
            found
        };
    let exiting = t.has_flag(crate::task::pf::EXITING);
    let ours = core::ptr::eq(t.sighand.as_ptr(), g.owner());
    let Some(group) = t
        .cpu_group()
        .filter(|_| ours && !(exiting && ty == PidType::Pid))
    else {
        return Err(q);
    };
    let sig = q.sig();
    let wants = with_sig_send(g, t, |task, state| {
        let wants = !state.blocked.contains(sig)
            && !exiting
            && !state.stopped_or_traced()
            && (task.se.on_cpu() || !task.sigpending());
        match ty {
            PidType::Pid => state.pending.queue(q),
            PidType::Tgid | PidType::Pgid => group.shared(g).queue(q),
        }
        wants
    });
    g.owner().signalfd_wq.wake_all();
    let init = target(t, &rcu).protects(sig, false);
    complete_signal(g, t, sig, ty, wants, init);
    Ok(())
}

/// Timer `t` leaves the current process's ignored list, under its
/// siglock (Linux posix_timer_cleanup_ignored under
/// current->sighand->siglock): it is being deleted by one of that
/// process's threads (`PosixTimer::delete`; a process with none left
/// puts its list in `posix_timer::drop_timers`)
pub fn cleanup_ignored(t: &crate::time::posix_timer::PosixTimer) {
    let me = crate::task::percpu::current();
    let rcu = crate::sync::rcu::read_lock();
    if let (Some(g), Some(s)) = (lock_task_sighand(&me, &rcu), me.cpu_group())
        && let Some(r) = s.ignored_timers(&g).remove(t)
    {
        crate::sync::rcu::put_rcu(r);
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
    /// The timer_create timers (Linux signal->posix_timers): spin,
    /// thread context only
    pub posix_timers: Mutex<crate::time::posix_timer::PosixTimerRegistry>,
    /// The interval timers (Linux signal->real_timer, signal->it[]),
    /// made with the SignalStruct, so setitimer cannot fail
    pub itimers: crate::time::posix_timer::ITimers,
    /// The group leader's struct pid (Linux signal->pids[PIDTYPE_TGID]),
    /// whom ITIMER_REAL signals and by which getppid and /proc number
    /// a parent: set under TASKLIST's write lock when the group's first
    /// task is attached (fork, the global init), cleared there when the
    /// group is released (its leader's `remove`, Linux __unhash_process
    /// detach_pid(PIDTYPE_TGID)), the reference dropped a grace period
    /// later; read under RCU. An exec by another thread keeps it (that
    /// thread takes the leader's pid, exchange_tids).
    pub leader_pid: crate::sync::rcu::RcuLockedArc<
        crate::task::pid::Pid,
        crate::task::tasklist::GlobalTaskTable,
    >,
    /// Threads not yet exiting (Linux signal->live): +1 at each
    /// CLONE_THREAD, -1 when a thread starts its exit; the thread that
    /// takes it to 0 is the group's last (group_dead)
    live: AtomicU32,
    /// CPU time (ns) of the group's threads already gone (Linux
    /// signal->utime, stime, sum_sched_runtime): added when one leaves
    /// the group, under TASKLIST's write lock; read under its read lock
    dead_times: [AtomicU64; 3],
    /// CPU time (ns) of reaped children and theirs (Linux
    /// signal->cutime/cstime)
    child_times: [AtomicU64; 2],
    /// Process CPU timers' state (Linux signal->cputimer)
    pub cputimer: crate::time::cpu_timer::GroupCputimer,
    /// The group's utime/stime last reported, adjusted (Linux
    /// signal->prev_cputime)
    pub prev_cputime: crate::task::cputime::PrevCputime,
    /// The group's pending signals (Linux signal->shared_pending, and
    /// curr_target, multiprocess): under the siglock of the table its
    /// threads name (the cell's owner, moved with `threads`)
    shared: crate::sync::InstanceCell<GroupPending, SigHand>,
    /// Its threads (Linux signal->thread_head, their `thread_node`), one
    /// strong reference each: changed under TASKLIST's write lock and
    /// the siglock of the table they all name (the cell's owner, moved
    /// by exec's unshare), walked under either (`GlobalTaskTable::
    /// threads`, [`SignalStruct::threads`]). A task joins in the section
    /// that lists it (fork) or names its group (the global init) and
    /// leaves at release (`unhash`)
    pub threads: crate::sync::LockedByBoth<
        crate::util::list::OwnedList<crate::task::ThreadNode>,
        crate::task::tasklist::GlobalTaskTable,
        SigHand,
    >,
    /// Job-control state (Linux signal->flags' stop bits,
    /// group_stop_count, group_exit_code): under the siglock of the
    /// table its threads name, as `shared`
    pub jobctl: crate::sync::InstanceCell<stop::GroupStop, SigHand>,
    /// Interval timers whose signal was ignored, waiting for the action
    /// to stop ignoring it (Linux signal->ignored_posix_timers), one
    /// reference each: under siglock, as `shared`
    ignored_timers: crate::sync::InstanceCell<
        crate::util::list::OwnedList<crate::time::posix_timer::IgnoredAdapter>,
        SigHand,
    >,
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
    /// The process's controlling tty and the group of one a hangup took
    /// (Linux signal->tty, signal->tty_old_pgrp, under siglock): spin
    /// leaf, thread context, under TASKLIST when held
    pub ctty: Mutex<crate::tty::jobctrl::Ctty>,
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
    /// INIT_RLIMITS as fork_init leaves them), its itimers included;
    /// ENOMEM
    pub fn alloc() -> Result<Arc<Self>, KernelError> {
        let a = crate::util::kalloc::try_arc_uninit::<Self>()?;
        Ok(Self::owned(Self::init(a)))
    }

    /// [`alloc`](Self::alloc) at boot, where failure cannot be reported
    fn alloc_nofail() -> Arc<Self> {
        Self::alloc().expect("boot: SignalStruct allocation")
    }

    /// Fill the new block `a` in place (the struct is large: built on
    /// the stack it cost fork ~3 KB of frame on arm64, as Inode::alloc)
    fn init(mut a: Arc<core::mem::MaybeUninit<Self>>) -> Arc<Self> {
        let p = Arc::get_mut(&mut a)
            .expect("SignalStruct: a new Arc is unshared")
            .as_mut_ptr();
        // SAFETY: `p` is the new block, unshared, valid for writes; it
        // stays in this Arc (never moved) and `owned` runs before it is
        // shared (ITimers::new's contract)
        unsafe { Self::init_at(p) };
        // SAFETY: `init_at` wrote every field
        unsafe { a.assume_init() }
    }

    /// Its itimers pointed at it, in its Arc
    fn owned(s: Arc<Self>) -> Arc<Self> {
        s.itimers.own(Arc::as_ptr(&s));
        s
    }

    /// Its group's first task, with pid `pid`, is being attached
    /// (TASKLIST held for writing)
    fn set_leader_pid(
        &self,
        table: &mut crate::task::tasklist::GlobalTaskTable,
        pid: Option<Arc<crate::task::pid::Pid>>,
    ) {
        self.leader_pid.replace(pid, table).defer_put();
    }

    /// Write every field of a new SignalStruct at `p`, one at a time,
    /// so it never sits on the stack whole
    ///
    /// # Safety
    /// `p` is valid for writes of a `SignalStruct`, unshared; the value
    /// is never moved after and `owned` runs on it before it is shared
    /// (`ITimers::new`).
    unsafe fn init_at(p: *mut Self) {
        // Each field written once, and every field: the pattern names
        // the same list without `..`, so a field missed or named twice
        // fails to build
        macro_rules! init {
            ($($f:ident: $v:expr),* $(,)?) => {
                $(
                    // SAFETY: `p` is valid for writes of a SignalStruct
                    // (the caller's contract); a field write drops nothing
                    unsafe { (&raw mut (*p).$f).write($v) };
                )*
                let _ = |s: &Self| {
                    let Self { $($f: _),* } = s;
                };
            };
        }
        // SAFETY: the caller's promise (never moved after the write
        // below, `owned` before sharing)
        let itimers = unsafe { crate::time::posix_timer::ITimers::new() };
        init! {
            rlim: IrqSpinlock::new(crate::task::rlimit::init_rlimits()),
            cred_guard: crate::sync::Mutex::new(()),
            exec_update: crate::sync::RwSem::new(()),
            group_exit: AtomicU64::new(0),
            posix_timers: Mutex::new(crate::time::posix_timer::PosixTimerRegistry::new()),
            itimers: itimers,
            leader_pid: crate::sync::rcu::RcuLockedArc::none(),
            live: AtomicU32::new(1),
            dead_times: [const { AtomicU64::new(0) }; 3],
            child_times: [AtomicU64::new(0), AtomicU64::new(0)],
            cputimer: crate::time::cpu_timer::GroupCputimer::new(),
            prev_cputime: crate::task::cputime::PrevCputime::new(),
            shared: crate::sync::InstanceCell::new(GroupPending::new()),
            threads: crate::sync::LockedByBoth::new(crate::util::list::OwnedList::new()),
            jobctl: crate::sync::InstanceCell::new(stop::GroupStop::new()),
            ignored_timers: crate::sync::InstanceCell::new(crate::util::list::OwnedList::new()),
            subreaper: crate::task::TableCell::new(false),
            unkillable: AtomicBool::new(false),
            ctty: Mutex::new(crate::tty::jobctrl::Ctty::new()),
        }
    }

    /// Its threads, under its table's siglock `g` (Linux for_each_thread
    /// under siglock); panics for another table's
    pub fn threads<'a>(&'a self, g: &'a SigGuard<'_>) -> impl Iterator<Item = &'a Task> + 'a {
        self.threads.access_b(g).iter()
    }

    /// Its pending set, under its table's siglock `g` (Linux
    /// signal->shared_pending under siglock); panics for another
    /// table's
    pub fn shared<'a>(
        &'a self,
        g: &'a SigGuard<'_>,
    ) -> crate::sync::InstanceRefMut<'a, GroupPending> {
        self.shared.borrow_mut(g)
    }

    /// Its ignored interval timers, under its table's siglock `g`
    pub fn ignored_timers<'a>(
        &'a self,
        g: &'a SigGuard<'_>,
    ) -> crate::sync::InstanceRefMut<
        'a,
        crate::util::list::OwnedList<crate::time::posix_timer::IgnoredAdapter>,
    > {
        self.ignored_timers.borrow_mut(g)
    }

    /// Its ignored interval timers, through exclusive access (it is
    /// going: `posix_timer::drop_timers`)
    pub fn ignored_timers_mut(
        &mut self,
    ) -> &mut crate::util::list::OwnedList<crate::time::posix_timer::IgnoredAdapter> {
        self.ignored_timers.get_mut()
    }

    /// Its job-control state, under its table's siglock `g`
    pub fn jobctl<'a>(
        &'a self,
        g: &'a SigGuard<'_>,
    ) -> crate::sync::InstanceRefMut<'a, stop::GroupStop> {
        self.jobctl.borrow_mut(g)
    }

    /// Its siglock-owned state (thread list, pending set, job control)
    /// is table `new`'s from now on, under TASKLIST's write lock and the
    /// old table's siglock `g` (any while it has none: a new group)
    fn set_owner(
        &self,
        table: &mut crate::task::tasklist::GlobalTaskTable,
        g: &mut SigGuard<'_>,
        new: &SigHand,
    ) {
        self.threads.set_owner(table, g, new);
        self.shared.set_owner(g, new);
        self.jobctl.set_owner(g, new);
        self.ignored_timers.set_owner(g, new);
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
    pub fn subreaper(&self, table: &crate::task::tasklist::GlobalTaskTable) -> bool {
        *self.subreaper.access(table)
    }

    /// Make the process a child subreaper or not (TASKLIST held for
    /// writing; Linux PR_SET_CHILD_SUBREAPER)
    pub fn set_subreaper(&self, table: &mut crate::task::tasklist::GlobalTaskTable, on: bool) {
        *self.subreaper.access_mut(table) = on;
    }

    /// A thread leaving the group takes its CPU time here (Linux
    /// __exit_signal), TASKLIST held for writing: the only writer, so a
    /// load and a store
    pub fn add_dead_times(&self, t: crate::task::cputime::TaskCputime) {
        use crate::sync::Sole;
        self.dead_times[0].sole_add(t.utime);
        self.dead_times[1].sole_add(t.stime);
        self.dead_times[2].sole_add(t.sum_exec_runtime);
    }

    /// The CPU time of the group's threads already gone
    pub fn dead_times(&self) -> crate::task::cputime::TaskCputime {
        crate::task::cputime::TaskCputime {
            utime: self.dead_times[0].load(Ordering::Relaxed),
            stime: self.dead_times[1].load(Ordering::Relaxed),
            sum_exec_runtime: self.dead_times[2].load(Ordering::Relaxed),
        }
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
    pub fn thread_exiting(&self, me: &Task, code: Option<i32>) -> bool {
        let dead = self.live.fetch_sub(1, Ordering::AcqRel) == 1;
        // Linux synchronize_group_exit: under siglock
        if dead && let Some(c) = code {
            let rcu = crate::sync::rcu::read_lock();
            if let Some(g) = lock_task_sighand(me, &rcu) {
                self.start_exit(&g, c, true);
            }
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
    /// de_thread (Linux complete_signal), exit_group does not. Under its
    /// table's siglock `g` (Linux sets SIGNAL_GROUP_EXIT under siglock),
    /// so a stop signal or SIGCONT whose effects are applied under it
    /// either sees the exit or comes before it (`prepare_signal`).
    fn start_exit(&self, g: &SigGuard<'_>, code: i32, over_exec: bool) -> bool {
        // The owner check (panics for another table's guard)
        let _ = self.threads(g);
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

    /// Deep clone for fork (without CLONE_THREAD): allocated first,
    /// then the limits copied under `rlim` (Linux copy_signal: the
    /// zeroed signal_struct, then the memcpy of rlim under task_lock),
    /// so the leaf lock is held across no allocation. Timers and the
    /// subreaper flag are not inherited.
    pub fn deep_clone(self: &Arc<Self>) -> Result<Arc<Self>, KernelError> {
        let new = Self::alloc()?;
        let lim = *self.rlim.lock();
        *new.rlim.lock() = lim;
        Ok(new)
    }
}

/// ITIMER_REAL's callback reaches the SignalStruct by its address: it
/// is waited out before any field goes (Linux cancels real_timer at the
/// group's exit, `exit_itimers`, before the struct is freed); timers
/// and ignored-list entries left by a racing last exit go with it
/// (`posix_timer::drop_timers`, no siglock: nothing else reaches it)
impl Drop for SignalStruct {
    fn drop(&mut self) {
        crate::time::posix_timer::drop_timers(self);
    }
}

// =============================================================================
// TASK_SIGNAL Global Table
// =============================================================================

// Task.signal field accessors (SignalStruct - shared by thread group)

/// The calling process's signal struct (Linux current->signal); None
/// for a kernel thread without one
pub fn current_signal() -> Option<Arc<SignalStruct>> {
    crate::task::percpu::current().cpu_group().cloned()
}

/// `f` on the calling process's signal struct, borrowed: no reference
/// taken (Linux reads current->signal in place)
pub fn with_current_signal<R>(f: impl FnOnce(&SignalStruct) -> R) -> Option<R> {
    crate::task::percpu::current().cpu_group().map(|s| f(s))
}

/// Task `t`'s signal struct (Linux t->signal: fixed for the task's
/// life; none for a kernel thread)
pub fn get_task_signal_struct(t: &Task) -> Option<Arc<SignalStruct>> {
    t.cpu_group().cloned()
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
        None => Ok((SignalStruct::alloc()?, false)),
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
/// thread and uid (Linux ptrace_signal: task_pid_vnr(current->parent)
/// and task_uid under rcu_read_lock)
fn tracer_info(t: &Task, sig: Signal) -> SigInfo {
    let (pid, uid) = {
        let g = crate::sync::rcu::read_lock();
        t.tracer(&g).map_or((0, 0), |tr| {
            (tr.pid_nr_ns(t.pid_ns(), &g), tr.cred_rcu(&g).uid)
        })
    };
    SigInfo::kill(sig, si_code::SI_USER, pid as i32, uid)
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
    // Queued callbacks run before any signal (Linux get_signal)
    if me.has_tif(crate::task::tif::NOTIFY_SIGNAL) {
        crate::task::task_work::task_work_run();
    }
    let err = regs.ret() as i64;
    let restart = syscall_restarting(regs);
    regs.forget_syscall();

    loop {
        // A notice SIGCONT left to the first thread out (Linux
        // get_signal: SIGNAL_CLD_MASK)
        stop::notify_cld();
        // A dying group comes before any handler (Linux get_signal)
        if group_dying(&me) {
            do_group_exit(SIGKILL.into());
        }
        // A group stop to join, a job-control ptrace trap
        if stop::pending_step() {
            continue;
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
                // Ignored by default (Linux get_signal: sig_kernel_ignore)
                if sig.kernel_ignore() {
                    continue;
                }
                // A signal queued while blocked does not kill or stop a
                // namespace init either (Linux get_signal:
                // SIGNAL_UNKILLABLE and not sig_kernel_only), unless the
                // kernel forced one (it lifts the protection); SIGKILL
                // and SIGSTOP here came from the kernel or an ancestor
                // namespace
                if sig != SIGKILL && sig != SIGSTOP && current_unkillable(&me) {
                    continue;
                }
                // Stop the group (Linux get_signal: do_signal_stop), but
                // not for SIGTSTP/SIGTTIN/SIGTTOU in an orphaned process
                // group; whether or not it stopped, look again
                if sig.kernel_stop() {
                    if stop::stop_applies(sig) {
                        stop::do_signal_stop(Some(sig));
                    }
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
    let bits = crate::uaccess::get_user::<u64>(umask).map_err(|_| KernelError::BadAddress)?;
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
    let (frame_mask, trap, alt) = with_task_signal_state(me, |state| {
        let mask = if restore {
            state.saved_sigmask
        } else {
            state.blocked
        };
        (mask, state.trap, state.altstack)
    })
    .unwrap_or((SigSet::EMPTY, Trap::NONE, AltStack::new()));

    match signal::setup_rt_frame(sig, action, frame_mask, info, &trap, &alt, regs) {
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
                // SS_AUTODISARM gives the stack up while the handler
                // runs (Linux signal_delivered -> sas_ss_reset);
                // rt_sigreturn reinstalls it from uc_stack
                if state.altstack.ss_flags & ss_flags::SS_AUTODISARM != 0 {
                    state.altstack = AltStack::new();
                }
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
