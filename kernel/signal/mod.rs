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
//! - `TASK_SIGHAND` and `TASK_SIGNAL_STATE` use `Mutex` as they are only
//!   accessed from process context
//!
//! See doc/LOCKING.md for full lock ordering.

pub mod syscall;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::arch::IrqSpinlock;
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
    pub fn new() -> Self {
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
    /// Signal actions indexed by signal number (index 0 unused, 1-64 valid)
    action: IrqSpinlock<[SigAction; 65]>,
}

impl SigHand {
    /// Create a new signal handler table with all defaults
    pub fn new() -> Self {
        Self {
            action: IrqSpinlock::new(core::array::from_fn(|_| SigAction::new())),
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
        let actions = self.action.lock();
        let mut new_actions: [SigAction; 65] = core::array::from_fn(|_| SigAction::new());
        for i in 0..65 {
            new_actions[i] = actions[i].clone();
        }
        Arc::new(Self {
            action: IrqSpinlock::new(new_actions),
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
    /// Pending signals for this task (private)
    pub pending: SigPending,
    /// Shared pending signals (for thread group)
    pub shared_pending: Arc<Mutex<SigPending>>,
    /// Flag indicating signals need processing
    pub sigpending: bool,
    /// Alternate signal stack
    pub altstack: AltStack,
}

impl TaskSignalState {
    /// Create new task signal state
    pub fn new() -> Self {
        Self {
            blocked: SigSet::EMPTY,
            pending: SigPending::new(),
            shared_pending: Arc::new(Mutex::new(SigPending::new())),
            sigpending: false,
            altstack: AltStack::new(),
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

    /// Recalculate sigpending flag
    pub fn recalc_sigpending(&mut self) {
        self.sigpending = self.has_deliverable_signals();
    }
}

impl Default for TaskSignalState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Task signal accessors - uses Task struct fields directly via TASK_TABLE
// =============================================================================

use crate::task::percpu::TASK_TABLE;

// =============================================================================
// Task Signal APIs
// =============================================================================

/// Initialize signal state for a new task
///
/// Called when creating a new process (init, fork without CLONE_SIGHAND).
/// Also initializes the SignalStruct (which contains rlimits).
pub fn init_task_signal(tid: Tid, sighand: Arc<SigHand>) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.sighand = Some(sighand);
        task.signal_state = TaskSignalState::new();
        task.tif_sigpending = AtomicBool::new(false);
        task.signal = Some(Arc::new(SignalStruct::new()));
    }
}

/// Get a task's signal handlers
pub fn get_task_sighand(tid: Tid) -> Option<Arc<SigHand>> {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .and_then(|t| t.sighand.clone())
}

/// Access a task's signal state for modification
pub fn with_task_signal_state<F, R>(tid: Tid, f: F) -> Option<R>
where
    F: FnOnce(&mut TaskSignalState) -> R,
{
    let mut table = TASK_TABLE.lock();
    table
        .tasks
        .iter_mut()
        .find(|t| t.tid == tid)
        .map(|t| f(&mut t.signal_state))
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
        let table = TASK_TABLE.lock();
        let parent = table.tasks.iter().find(|t| t.tid == parent_tid);
        (
            parent.and_then(|p| p.sighand.clone()),
            parent.map(|p| p.signal_state.clone()),
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
            pending: SigPending::new(),    // Fresh private pending
            shared_pending: if share_pending {
                // CLONE_THREAD: share thread-group pending
                parent_state.shared_pending.clone()
            } else {
                Arc::new(Mutex::new(SigPending::new()))
            },
            sigpending: false,
            altstack: AltStack::new(), // Child starts with no altstack
        }
    } else {
        TaskSignalState::new()
    };

    // Update child task
    {
        let mut table = TASK_TABLE.lock();
        if let Some(child) = table.tasks.iter_mut().find(|t| t.tid == child_tid) {
            child.sighand = Some(child_sighand);
            child.signal_state = child_state;
            child.tif_sigpending = AtomicBool::new(false);
        }
    }

    // Clone or share SignalStruct (contains rlimits)
    // CLONE_THREAD (share_pending) implies threads share SignalStruct
    clone_task_signal_struct(parent_tid, child_tid, share_pending);
}

/// Clean up signal state on task exit
pub fn exit_task_signal(tid: Tid) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.sighand = None;
        task.signal_state = TaskSignalState::new();
        task.tif_sigpending = AtomicBool::new(false);
        task.signal = None;
    }
}

// =============================================================================
// Signal Sending
// =============================================================================

/// Set TIF_SIGPENDING flag for a task
fn set_tif_sigpending(tid: Tid) {
    let table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter().find(|t| t.tid == tid) {
        task.tif_sigpending.store(true, Ordering::Release);
    }
}

/// Clear TIF_SIGPENDING flag for a task
#[allow(dead_code)]
fn clear_tif_sigpending(tid: Tid) {
    let table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter().find(|t| t.tid == tid) {
        task.tif_sigpending.store(false, Ordering::Release);
    }
}

/// Check if a task has pending signals (fast path)
pub fn has_pending_signals(tid: Tid) -> bool {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| t.tif_sigpending.load(Ordering::Acquire))
        .unwrap_or(false)
}

/// Send a signal to a specific task (thread)
///
/// Returns 0 on success, negative errno on error.
pub fn send_signal(tid: Tid, sig: u32) -> i32 {
    if sig == 0 {
        // Signal 0 is null signal - just check if task exists
        let table = TASK_TABLE.lock();
        return if table.tasks.iter().any(|t| t.tid == tid) {
            0
        } else {
            -3 // ESRCH
        };
    }

    if sig > 64 {
        return -22; // EINVAL
    }

    // Add to pending
    let result = with_task_signal_state(tid, |state| {
        state.pending.add(sig);
        state.recalc_sigpending();
    });

    if result.is_none() {
        return -3; // ESRCH
    }

    // Set TIF_SIGPENDING flag
    set_tif_sigpending(tid);

    // Wake any signalfds monitoring this signal
    crate::signalfd::wake_signalfds_for_signal(tid, sig);

    0
}

/// Send signal to a process (any thread in the thread group)
///
/// This looks up the main thread's TID for the given PID and sends the signal there.
pub fn send_signal_to_process(pid: Pid, sig: u32) -> i32 {
    // Look up the TID for this PID from the task table
    let tid = {
        let table = crate::task::percpu::TASK_TABLE.lock();
        table.tasks.iter().find(|t| t.pid == pid).map(|t| t.tid)
    };

    match tid {
        Some(tid) => send_signal(tid, sig),
        None => -3, // ESRCH - no such process
    }
}

/// Send signal to all processes in a process group
///
/// This is used by TTY signal generation (SIGINT, SIGTSTP, etc.)
/// when control characters are received.
///
/// Returns 0 on success, negative errno on error.
pub fn send_signal_to_pgrp(pgid: Pid, sig: u32) -> i32 {
    use crate::task::percpu::TASK_TABLE;

    if sig == 0 || sig > 64 {
        return -22; // EINVAL
    }

    // Find all processes in this process group
    let tids: alloc::vec::Vec<Tid> = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .filter(|t| t.pgid == pgid)
            .map(|t| t.tid)
            .collect()
    };

    if tids.is_empty() {
        return -3; // ESRCH - no such process group
    }

    // Send signal to each process
    let mut sent = 0;
    for tid in tids {
        if send_signal(tid, sig) == 0 {
            sent += 1;
        }
    }

    if sent > 0 {
        0
    } else {
        -3 // ESRCH
    }
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
            state.recalc_sigpending();
            return Some((sig, action));
        }

        // Check shared pending (thread group signals)
        let shared_result = {
            let mut shared = state.shared_pending.lock();
            if let Some(sig) = shared.dequeue(&state.blocked) {
                let action = sighand.get_action(sig).unwrap_or_default();
                Some((sig, action))
            } else {
                None
            }
        };

        // Now that shared lock is dropped, we can call recalc_sigpending
        if let Some(result) = shared_result {
            state.recalc_sigpending();
            return Some(result);
        }

        state.recalc_sigpending();
        None
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
}

impl SignalStruct {
    /// Create new SignalStruct with default rlimits
    pub fn new() -> Self {
        Self {
            rlim: IrqSpinlock::new(default_rlimits()),
        }
    }

    /// Get a resource limit
    pub fn get_rlimit(&self, resource: u32) -> Option<RLimit> {
        if resource as usize >= RLIM_NLIMITS {
            return None;
        }
        let rlim = self.rlim.lock();
        Some(rlim[resource as usize])
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
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .and_then(|t| t.signal.clone())
}

/// Clone signal struct for fork/clone
///
/// If `share_signal` is true (CLONE_THREAD), share the Arc<SignalStruct>.
/// Otherwise, deep clone the signal struct.
fn clone_task_signal_struct(parent_tid: Tid, child_tid: Tid, share_signal: bool) {
    let parent_signal = get_task_signal_struct(parent_tid);

    let child_signal = if share_signal {
        // CLONE_THREAD: share the same SignalStruct
        parent_signal.unwrap_or_else(|| Arc::new(SignalStruct::new()))
    } else {
        // Fork: deep clone
        parent_signal
            .as_ref()
            .map(|s| s.deep_clone())
            .unwrap_or_else(|| Arc::new(SignalStruct::new()))
    };

    let mut table = TASK_TABLE.lock();
    if let Some(child) = table.tasks.iter_mut().find(|t| t.tid == child_tid) {
        child.signal = Some(child_signal);
    }
}
