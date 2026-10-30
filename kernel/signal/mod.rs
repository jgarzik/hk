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

pub mod syscall;

use crate::sync::spin::Mutex;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::{IrqSpinlock, PtRegs, UserRegs};
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

/// siginfo `si_code` values (include/uapi/asm-generic/siginfo.h)
pub mod si_code {
    /// Sent by kill/raise
    pub const SI_USER: i32 = 0;
    /// Sent by the kernel
    pub const SI_KERNEL: i32 = 0x80;
    /// SIGILL: illegal opcode / illegal operand
    pub const ILL_ILLOPC: i32 = 1;
    pub const ILL_ILLOPN: i32 = 2;
    /// SIGFPE codes
    pub const FPE_INTDIV: i32 = 1;
    pub const FPE_INTOVF: i32 = 2;
    pub const FPE_FLTDIV: i32 = 3;
    pub const FPE_FLTOVF: i32 = 4;
    pub const FPE_FLTUND: i32 = 5;
    pub const FPE_FLTRES: i32 = 6;
    pub const FPE_FLTINV: i32 = 7;
    /// SIGSEGV: address not mapped / no permission for the mapping
    pub const SEGV_MAPERR: i32 = 1;
    pub const SEGV_ACCERR: i32 = 2;
    /// SIGBUS: invalid alignment / nonexistent physical address
    pub const BUS_ADRALN: i32 = 1;
    pub const BUS_ADRERR: i32 = 2;
    /// SIGTRAP: breakpoint / trace trap
    pub const TRAP_BRKPT: i32 = 1;
    pub const TRAP_TRACE: i32 = 2;
}

/// What the signal frame reports about a signal (Linux kernel_siginfo
/// subset, plus the arch fault details of sigcontext)
#[derive(Debug, Clone, Copy, Default)]
pub struct KSigInfo {
    /// si_code
    pub code: i32,
    /// si_addr: faulting address or instruction (fault signals)
    pub addr: u64,
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
// Pending Signals
// =============================================================================

/// Pending signals for a task or thread group
#[derive(Debug, Clone, Default)]
pub struct SigPending {
    /// Bitmask of pending signals
    pub signal: SigSet,
    // Future: Vec<SigInfo> for queued real-time signals
}

impl SigPending {
    /// Create empty pending set
    pub const fn new() -> Self {
        Self {
            signal: SigSet::EMPTY,
        }
    }

    /// Check if any signals are pending
    pub fn any(&self) -> bool {
        self.signal.any()
    }

    /// Add a pending signal
    pub fn add(&mut self, sig: u32) {
        self.signal.add(sig);
    }

    /// Remove a signal from pending
    pub fn remove(&mut self, sig: u32) {
        self.signal.remove(sig);
    }

    /// Get next deliverable signal (not in blocked set)
    ///
    /// Removes and returns the lowest-numbered pending signal that is not blocked.
    pub fn dequeue(&mut self, blocked: &SigSet) -> Option<u32> {
        // Find first pending signal not in blocked set
        let deliverable = self.signal.subtract(blocked);
        if let Some(sig) = deliverable.first() {
            self.signal.remove(sig);
            Some(sig)
        } else {
            None
        }
    }

    /// Check if a specific signal is pending
    pub fn is_pending(&self, sig: u32) -> bool {
        self.signal.contains(sig)
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
    pub fn deep_clone(self: &Arc<Self>) -> Arc<Self> {
        // Allocated before the lock is taken: SigHand.action stays a leaf
        let mut actions = default_actions();
        actions.clone_from_slice(&self.action.lock());
        Arc::new(Self {
            action: IrqSpinlock::new(actions),
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
#[derive(Clone)]
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
}

/// A thread group's shared pending set (Linux signal->shared_pending):
/// shared by CLONE_THREAD; none for the boot task, which reads as empty
#[derive(Clone)]
pub struct SharedPending(Option<Arc<Mutex<SigPending>>>);

/// What the boot task's (absent) shared set reads as
static NO_SHARED: Mutex<SigPending> = Mutex::new(SigPending::new());

impl SharedPending {
    pub fn new() -> Self {
        Self(Some(Arc::new(Mutex::new(SigPending::new()))))
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
        }
    }

    /// Create new task signal state
    pub fn new() -> Self {
        Self {
            blocked: SigSet::EMPTY,
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(),
            shared_pending: SharedPending::new(),
            altstack: AltStack::new(),
            real_blocked: SigSet::EMPTY,
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
/// Called when creating a new process (init, fork without CLONE_SIGHAND).
/// Also initializes the SignalStruct (which contains rlimits).
pub fn init_task_signal(tid: Tid, sighand: Arc<SigHand>) {
    let mut table = TASKLIST.write();
    if let Some(mut task) = table.get_mut(tid) {
        task.sighand = Some(sighand);
        *task.task.sig.lock() = TaskSignalState::new();
        task.task.set_sigpending(false);
        task.signal = Some(Arc::new(SignalStruct::new()));
    }
}

/// Get a task's signal handlers
pub fn get_task_sighand(tid: Tid) -> Option<Arc<SigHand>> {
    let table = TASKLIST.read();
    table.get(tid).and_then(|t| t.sighand.clone())
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
    // The current task's own state needs no TASKLIST: it cannot leave
    // the task list while it runs
    let me = crate::task::percpu::current();
    let t = if me.tid() == tid && tid != 0 {
        crate::task::percpu::task_ref(&me)
    } else {
        TASKLIST.read().task(tid)?
    };
    let mut s = t.sig.lock();
    let r = f(&mut s);
    t.set_sigpending(s.has_deliverable_signals());
    Some(r)
}

/// Clone signal state for fork/clone
///
/// If `share_sighand` is true (CLONE_SIGHAND), share the Arc<SigHand>.
/// Otherwise, deep clone the signal handlers.
///
/// If `share_pending` is true (CLONE_THREAD), share the thread-group pending.
///
/// If `clear_sighand` is true (CLONE_CLEAR_SIGHAND), reset all handlers to default
/// after cloning (except SIG_IGN handlers which are preserved).
pub fn clone_task_signal(
    parent_tid: Tid,
    child_tid: Tid,
    share_sighand: bool,
    share_pending: bool,
    clear_sighand: bool,
) {
    // Get parent's sighand and signal_state
    let (parent_sighand, parent_state) = {
        let table = TASKLIST.read();
        let parent = table.get(parent_tid);
        (
            parent.and_then(|p| p.sighand.clone()),
            parent.map(|p| p.task.sig.lock().clone()),
        )
    };

    let child_sighand = if share_sighand {
        // CLONE_SIGHAND: share the same SigHand
        parent_sighand.unwrap_or_else(|| Arc::new(SigHand::new()))
    } else {
        // Fork: deep clone handlers
        let sighand = parent_sighand
            .as_ref()
            .map(|sh| sh.deep_clone())
            .unwrap_or_else(|| Arc::new(SigHand::new()));

        // CLONE_CLEAR_SIGHAND: reset handlers to default (except SIG_IGN)
        if clear_sighand {
            sighand.flush_handlers();
        }

        sighand
    };

    // Clone per-task signal state
    let child_state = if let Some(parent_state) = parent_state {
        TaskSignalState {
            blocked: parent_state.blocked, // Inherit blocked mask
            saved_sigmask: SigSet::EMPTY,
            pending: SigPending::new(), // Fresh private pending
            shared_pending: if share_pending {
                // CLONE_THREAD: share thread-group pending
                parent_state.shared_pending.clone()
            } else {
                SharedPending::new()
            },
            altstack: AltStack::new(), // Child starts with no altstack
            real_blocked: SigSet::EMPTY,
        }
    } else {
        TaskSignalState::new()
    };

    // Update child task
    {
        let mut table = TASKLIST.write();
        if let Some(mut child) = table.get_mut(child_tid) {
            child.sighand = Some(child_sighand);
            *child.task.sig.lock() = child_state;
            child.task.set_sigpending(false);
        }
    }

    // Clone or share SignalStruct (contains rlimits)
    // CLONE_THREAD (share_pending) implies threads share SignalStruct
    clone_task_signal_struct(parent_tid, child_tid, share_pending);
}

/// Clean up signal state on task exit
pub fn exit_task_signal(tid: Tid) {
    // Released after TASKLIST (nothing is released under it)
    let _old = {
        let mut table = TASKLIST.write();
        table.get_mut(tid).map(|mut task| {
            let old = core::mem::take(&mut *task.task.sig.lock());
            task.task.set_sigpending(false);
            // A zombie leader keeps the group's SignalStruct (its exit
            // status; Linux frees signal_struct with the reaped leader)
            let signal = if task.leader {
                None
            } else {
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
/// blocked (a blocked signal stays queued: the handler may change)
fn sig_ignored(state: &TaskSignalState, sighand: Option<&Arc<SigHand>>, sig: u32) -> bool {
    if state.blocked.contains(sig) || sig == SIGKILL || sig == SIGSTOP {
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

/// Send a signal to a specific task (thread)
///
/// Queues the signal and, if it is deliverable, wakes the task from an
/// interruptible sleep (Linux signal_wake_up) so the blocked syscall can
/// return -ERESTART*/-EINTR and the signal is delivered on the way out.
/// Process context only (takes TASKLIST).
///
/// Returns 0 on success, negative errno on error.
pub fn send_signal(tid: Tid, sig: u32) -> i32 {
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
    // kill(-1) and kill(pid)
    let kthread = TASKLIST
        .read()
        .get(tid)
        .map(|t| t.task.has_flag(crate::task::pf::KTHREAD));
    match kthread {
        None => return -3, // ESRCH
        Some(true) => return 0,
        Some(false) => {}
    }

    // Queue unless ignored; note whether it is deliverable now
    let sighand = get_task_sighand(tid);
    let result = with_task_signal_state(tid, |state| {
        if sig_ignored(state, sighand.as_ref(), sig) {
            return (false, false);
        }
        state.pending.add(sig);
        // Deliverable now; fatal on arrival unless awaited in sigtimedwait
        let d = !state.blocked.contains(sig);
        (d, d && !state.real_blocked.contains(sig))
    });

    let (deliverable, may_kill) = match result {
        None => return -3, // ESRCH
        Some(d) => d,
    };
    if may_kill && fatal(sighand.as_ref(), sig) {
        group_kill(tid, sig);
    }

    // Wake any signalfds monitoring this signal
    crate::signalfd::wake_signalfds_for_signal(tid, sig);

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
    let tid = {
        let table = crate::task::percpu::TASKLIST.read();
        let live = |t: &crate::task::percpu::TaskView<'_>| {
            !t.task.has_flag(crate::task::pf::EXITING)
                && !matches!(t.state, crate::task::TaskState::Zombie(_))
        };
        let leader = table.get(pid);
        match leader {
            Some(l) if live(&l) => Some(l.task.tid()),
            _ => table
                .threads(pid)
                .find(live)
                .or(leader)
                .map(|t| t.task.tid()),
        }
    };

    match tid {
        Some(tid) => send_signal(tid, sig),
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
    kill_pgrp(pgid, sig, |_| 0)
}

/// `sig` once to each process of group `pgid` (Linux __kill_pgrp_info:
/// its leader on the group's list, the signal process-directed), after
/// `check(pid)` allows it; signal 0 only checks. 0 if any process got
/// it, else the last error (ESRCH for an empty group).
pub fn kill_pgrp(pgid: Pid, sig: u32, check: impl Fn(Pid) -> i32) -> i32 {
    let mut ret = -3; // ESRCH
    let mut ok = false;
    for pid in crate::task::percpu::pgrp_pids(pgid) {
        ret = match check(pid) {
            0 if sig != 0 => send_signal_to_process(pid, sig),
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
/// sees anything but SIGKILL first)
fn group_kill(tid: Tid, sig: u32) {
    let found = {
        let table = TASKLIST.read();
        table
            .get(tid)
            .map(|t| (t.task.pid, t.ptrace != 0, group_signal(&table, t.task.pid)))
    };
    let Some((tgid, traced, Some(s))) = found else {
        return;
    };
    if (sig == SIGKILL || !traced) && s.start_exit(sig as i32, true) {
        zap_threads(tgid, None);
    }
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
            .filter(|t| {
                Some(t.task.tid()) != except
                    && !t.task.has_flag(crate::task::pf::EXITING)
                    && !matches!(t.state, crate::task::TaskState::Zombie(_))
            })
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

/// Get next deliverable signal for a task
///
/// Returns the signal number and its action, or None if no signals are deliverable.
pub fn get_signal_to_deliver(tid: Tid) -> Option<(u32, SigAction)> {
    let sighand = get_task_sighand(tid)?;

    with_task_signal_state(tid, |state| {
        // Try private pending first
        if let Some(sig) = state.pending.dequeue(&state.blocked) {
            let action = sighand.get_action(sig).unwrap_or_default();
            return Some((sig, action));
        }

        // Then shared pending (thread group signals)
        let sig = state.shared_pending.lock().dequeue(&state.blocked)?;
        Some((sig, sighand.get_action(sig).unwrap_or_default()))
    })?
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

use crate::rlimit::{RLIM_NLIMITS, RLimit, default_rlimits};

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
    pub posix_timers: Mutex<crate::posix_timer::PosixTimerRegistry>,
    /// Threads not yet exiting (Linux signal->live): +1 at each
    /// CLONE_THREAD, -1 when a thread starts its exit; the thread that
    /// takes it to 0 is the group's last (group_dead)
    live: AtomicU32,
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
    /// Take task `tid`'s (none for a task without a SignalStruct)
    pub fn lock(tid: Tid) -> Self {
        let s = get_task_signal_struct(tid);
        if let Some(s) = &s {
            s.cred_guard.lock_raw();
        }
        Self(s)
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
            posix_timers: Mutex::new(crate::posix_timer::PosixTimerRegistry::new()),
            live: AtomicU32::new(1),
        }
    }

    /// A thread joins the group (CLONE_THREAD)
    pub fn thread_added(&self) {
        self.live.fetch_add(1, Ordering::AcqRel);
    }

    /// A thread starts its exit; true if it was the group's last live
    /// one (Linux do_exit: group_dead = atomic_dec_and_test(&live))
    pub fn thread_exiting(&self) -> bool {
        self.live.fetch_sub(1, Ordering::AcqRel) == 1
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
            let new = GROUP_EXIT | code as u32 as u64;
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

    /// Set a resource limit (with permission checks)
    ///
    /// Validates:
    /// - rlim_cur <= rlim_max
    /// - Only CAP_SYS_RESOURCE can raise hard limit
    pub fn set_rlimit(
        &self,
        resource: u32,
        new: RLimit,
        old: &RLimit,
        has_cap_sys_resource: bool,
    ) -> Result<(), i32> {
        if resource as usize >= RLIM_NLIMITS {
            return Err(-22); // EINVAL
        }

        // cur must be <= max
        if new.rlim_cur > new.rlim_max {
            return Err(-22); // EINVAL
        }

        // Check if raising hard limit (requires CAP_SYS_RESOURCE)
        if new.rlim_max > old.rlim_max && !has_cap_sys_resource {
            return Err(-1); // EPERM
        }

        let mut rlim = self.rlim.lock();
        rlim[resource as usize] = new;
        Ok(())
    }

    /// Deep clone for fork (without CLONE_THREAD)
    pub fn deep_clone(self: &Arc<Self>) -> Arc<Self> {
        let rlim = self.rlim.lock();
        let mut new_rlim = [RLimit::default(); RLIM_NLIMITS];
        new_rlim.copy_from_slice(&*rlim);
        Arc::new(Self {
            rlim: IrqSpinlock::new(new_rlim),
            cred_guard: crate::sync::Mutex::new(()),
            exec_update: crate::sync::RwSem::new(()),
            group_exit: AtomicU64::new(0),
            // Timers are not inherited (Linux copy_signal)
            posix_timers: Mutex::new(crate::posix_timer::PosixTimerRegistry::new()),
            live: AtomicU32::new(1),
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

/// Clone signal struct for fork/clone
///
/// If `share_signal` is true (CLONE_THREAD), share the Arc<SignalStruct>.
/// Otherwise, deep clone the signal struct.
fn clone_task_signal_struct(parent_tid: Tid, child_tid: Tid, share_signal: bool) {
    let parent_signal = get_task_signal_struct(parent_tid);

    let child_signal = if share_signal {
        // CLONE_THREAD: share the same SignalStruct, one more live thread
        match parent_signal {
            Some(s) => {
                s.thread_added();
                s
            }
            None => Arc::new(SignalStruct::new()),
        }
    } else {
        // Fork: deep clone
        parent_signal
            .as_ref()
            .map(|s| s.deep_clone())
            .unwrap_or_else(|| Arc::new(SignalStruct::new()))
    };

    let mut table = TASKLIST.write();
    if let Some(mut child) = table.get_mut(child_tid) {
        child.signal = Some(child_signal);
    }
}

// =============================================================================
// Signal Delivery Entry Point
// =============================================================================

/// Let the tracer of a traced task see `sig` before it is delivered:
/// None if the tracer cancelled it, or if it changed it to one now
/// blocked (queued again, as Linux ptrace_signal does)
fn traced_signal(tid: Tid, sig: u32, action: SigAction) -> Option<(u32, SigAction)> {
    if sig == SIGKILL {
        return Some((sig, action));
    }
    let new = crate::task::ptrace::ptrace_signal(sig);
    if new == sig {
        return Some((sig, action));
    }
    if new == 0 {
        return None;
    }
    let blocked = with_task_signal_state(tid, |state| state.blocked.contains(new)).unwrap_or(false);
    if blocked {
        send_signal(tid, new);
        return None;
    }
    let action = get_task_sighand(tid)?.get_action(new).unwrap_or_default();
    Some((new, action))
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
pub fn do_signal(regs: &mut PtRegs) {
    use crate::error::KernelError;

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
        let Some((sig, action)) = get_signal_to_deliver(tid) else {
            break;
        };
        // A tracee stops for its tracer first (Linux get_signal ->
        // ptrace_signal), which may cancel or change the signal
        let Some((sig, action)) = traced_signal(tid, sig, action) else {
            continue;
        };
        match action.handler {
            SigHandler::Ignore => continue,
            SigHandler::Default => match default_action(sig) {
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
                if deliver_to_handler(tid, sig, &action, &KSigInfo::default(), regs) {
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
pub fn syscall_restarting(regs: &PtRegs) -> bool {
    use crate::error::KernelError;
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
        state.blocked = new.subtract(&UNMASKABLE_SIGNALS);
        state.saved_sigmask
    })?;
    me.set_tif(crate::task::tif::RESTORE_SIGMASK);
    Some(old)
}

/// Read a sigset_t from user memory and install it as the syscall's
/// temporary mask (Linux set_user_sigmask); a null `umask` changes
/// nothing. Errors: EINVAL (size), EFAULT.
pub fn set_user_sigmask(umask: u64, sigsetsize: u64) -> Result<(), crate::error::KernelError> {
    use crate::error::KernelError;
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
    info: &KSigInfo,
    regs: &mut PtRegs,
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

    match signal::setup_rt_frame(sig, action, frame_mask, info, regs) {
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
    // Send SIGSEGV to self
    send_signal(tid, SIGSEGV);
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
pub fn force_sig_fault(sig: u32, info: KSigInfo, regs: &mut PtRegs) {
    let do_exit = do_group_exit;

    let tid = crate::task::percpu::current_tid();
    let sighand = get_task_sighand(tid);
    let action = sighand
        .as_ref()
        .and_then(|h| h.get_action(sig))
        .unwrap_or_default();
    let blocked = with_task_signal_state(tid, |s| s.blocked.contains(sig)).unwrap_or(true);

    if let SigHandler::Handler(_) = action.handler
        && !blocked
    {
        if deliver_to_handler(tid, sig, &action, &info, regs) {
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
