//! Timer file descriptor (timerfd) implementation
//!
//! Provides file descriptor-based timers compatible with Linux timerfd API.
//!
//! ## Architecture
//!
//! ```text
//! User Process
//!     |
//!     v
//! timerfd_create() -> fd
//!     |
//!     v
//! timerfd_settime(fd, ...)  -> Arms timer
//!     |
//!     v
//! read(fd) -> Blocks until timer fires, returns expiration count
//! ```
//!
//! ## Key Features
//!
//! - One-shot and periodic timers
//! - Blocking and non-blocking reads
//! - poll() support for integration with select/poll/epoll
//! - CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME and the alarm clocks

use crate::fs::FileRef;
use crate::util::kalloc::try_arc;
use crate::util::list::Link;
use crate::util::rculist::RcuList;
use alloc::sync::Arc;
use core::pin::Pin;

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, RwFlags, flags, nowait_rw};
use crate::fs::iov_iter::IovDest;
use crate::io::poll::{POLLIN, POLLRDNORM, PollTable};
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::time::hrtimer::{HRTIMER_HARD, HrClock, HrTimer};
use crate::time::time_syscall::LinuxTimespec;

/// Timerfd create flags
pub mod tfd_flags {
    /// Set close-on-exec flag
    pub const TFD_CLOEXEC: i32 = 0o2000000;
    /// Set non-blocking flag
    pub const TFD_NONBLOCK: i32 = 0o4000;
}

/// Timerfd settime flags
pub mod tfd_timer_flags {
    /// Time value is absolute
    pub const TFD_TIMER_ABSTIME: i32 = 1;
    /// A CLOCK_REALTIME absolute timer's read fails with ECANCELED
    /// once the clock is set
    pub const TFD_TIMER_CANCEL_ON_SET: i32 = 2;
}

/// Linux itimerspec structure
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ITimerSpec {
    /// Interval for periodic timer (0 = one-shot)
    pub it_interval: LinuxTimespec,
    /// Initial expiration time
    pub it_value: LinuxTimespec,
}
crate::pod!(ITimerSpec {
    it_interval,
    it_value
});

impl ITimerSpec {
    /// Check if this timer spec represents a disarmed timer
    pub fn is_disarmed(&self) -> bool {
        self.it_value.tv_sec == 0 && self.it_value.tv_nsec == 0
    }

    /// Convert it_value to nanoseconds
    pub fn value_to_ns(&self) -> u64 {
        crate::time::timespec_to_ns(self.it_value.tv_sec, self.it_value.tv_nsec)
    }

    /// Convert it_interval to nanoseconds
    pub fn interval_to_ns(&self) -> u64 {
        crate::time::timespec_to_ns(self.it_interval.tv_sec, self.it_interval.tv_nsec)
    }

    /// Linux itimerspec64_valid: no negative seconds, nanoseconds < 1e9
    pub fn is_valid(&self) -> bool {
        let ok = |t: &LinuxTimespec| t.tv_sec >= 0 && (0..1_000_000_000).contains(&t.tv_nsec);
        ok(&self.it_value) && ok(&self.it_interval)
    }

    /// Create from nanosecond values
    pub fn from_ns(value_ns: u64, interval_ns: u64) -> Self {
        Self {
            it_value: LinuxTimespec {
                tv_sec: (value_ns / 1_000_000_000) as i64,
                tv_nsec: (value_ns % 1_000_000_000) as i64,
            },
            it_interval: LinuxTimespec {
                tv_sec: (interval_ns / 1_000_000_000) as i64,
                tv_nsec: (interval_ns % 1_000_000_000) as i64,
            },
        }
    }
}

/// Internal timerfd state
struct TimerfdInner {
    /// Clock ID (CLOCK_REALTIME or CLOCK_MONOTONIC)
    clockid: i32,
    /// Next expiration time (absolute ns on `clock`, 0 if disarmed)
    expires_ns: u64,
    /// The clock `expires_ns` is on: CLOCK_REALTIME only for an
    /// absolute realtime timer (Linux: relative timers run on
    /// CLOCK_MONOTONIC)
    clock: HrClock,
    /// Interval for periodic timers (0 = one-shot)
    interval_ns: u64,
    /// Number of expirations since last read
    ticks: u64,
    /// A periodic timer expired and waits to be re-armed by a read or
    /// gettime (Linux ctx->expired)
    expired: bool,
    /// settime flags (TFD_TIMER_ABSTIME, etc.)
    settime_flags: i32,
    /// TFD_TIMER_CANCEL_ON_SET armed (Linux ctx->might_cancel): the
    /// clock being set cancels it
    might_cancel: bool,
    /// On `CANCEL_LIST`: from its first cancel-on-set settime until its
    /// release (a reader skips it while `might_cancel` is off)
    listed: bool,
    /// The realtime offset when armed; None once the clock was set
    /// (Linux moffs == KTIME_MAX)
    moffs: Option<i64>,
}

impl TimerfdInner {
    fn new(clockid: i32) -> Self {
        Self {
            clockid,
            expires_ns: 0,
            clock: HrClock::Monotonic,
            interval_ns: 0,
            ticks: 0,
            expired: false,
            settime_flags: 0,
            might_cancel: false,
            listed: false,
            moffs: Some(0),
        }
    }
}

/// Timerfd structure
pub struct Timerfd {
    /// Inner state protected by IRQ spinlock
    inner: IrqSpinlock<TimerfdInner>,
    /// Wait queue for blocking reads
    wait_queue: WaitQueue,
    /// Its expiry timer (HARD, like Linux timerfd_tmrproc: the callback
    /// takes `inner`, an IrqSpinlock, and wakes readers; data: this
    /// timerfd, which outlives it: dropping the timer waits out its
    /// callback)
    timer: HrTimer,
    /// Its link on `CANCEL_LIST` (Linux ctx->clist)
    clist: Link,
}

crate::adapter!(ClistAdapter, Timerfd, clist);

impl Timerfd {
    /// Create a new timerfd, or ENOMEM
    pub fn new(clockid: i32) -> Result<Arc<Self>, KernelError> {
        let timerfd = try_arc(Self {
            inner: IrqSpinlock::new(TimerfdInner::new(clockid)),
            wait_queue: WaitQueue::new(),
            timer: HrTimer::new(timerfd_fire, HRTIMER_HARD),
            clist: Link::new(),
        })?;
        timerfd.timer.set_data(Arc::as_ptr(&timerfd) as usize);
        Ok(timerfd)
    }

    /// Its timer (pinned: the timerfd lives in an Arc)
    fn timer(&self) -> Pin<&HrTimer> {
        // SAFETY: an Arc's contents never move
        unsafe { Pin::new_unchecked(&self.timer) }
    }

    /// Arm the timer
    ///
    /// # Arguments
    /// * `new_value` - New timer specification
    /// * `flags` - TFD_TIMER_ABSTIME for absolute time
    ///
    /// # Returns
    /// Previous timer value
    pub fn settime(self: &Arc<Self>, new_value: &ITimerSpec, flags: i32) -> ITimerSpec {
        // Cancel the existing timer, waiting out its callback (it takes
        // `inner`)
        self.timer.cancel_sync();
        self.setup_cancel(flags);
        let mut inner = self.inner.lock();

        // Save old value
        let old_value = self.get_current_value_locked(&inner);

        // Reset ticks
        inner.ticks = 0;
        inner.expired = false;
        inner.settime_flags = flags;
        inner.moffs = Some(crate::time::real_offset());

        // Check if disarming
        if new_value.is_disarmed() {
            inner.expires_ns = 0;
            inner.interval_ns = 0;
            return old_value;
        }

        // Calculate expiration time
        let value_ns = new_value.value_to_ns();
        inner.interval_ns = new_value.interval_to_ns();

        let (expires_ns, clock) = if flags & tfd_timer_flags::TFD_TIMER_ABSTIME != 0 {
            // Absolute, kept on its clock: a realtime one follows
            // clock_settime
            (value_ns, clock_of(inner.clockid))
        } else {
            // Relative time (saturates: a huge value never fires)
            let now = crate::time::monotonic_ns();
            (
                crate::time::deadline_after(now, value_ns),
                HrClock::Monotonic,
            )
        };

        inner.expires_ns = expires_ns;
        inner.clock = clock;
        self.timer().start(expires_ns, clock);

        old_value
    }

    /// Get current timer value
    pub fn gettime(&self) -> ITimerSpec {
        let mut inner = self.inner.lock();
        let more = self.restart(&mut inner);
        inner.ticks = inner.ticks.saturating_add(more);
        self.get_current_value_locked(&inner)
    }

    /// Get current value while holding the lock
    fn get_current_value_locked(&self, inner: &TimerfdInner) -> ITimerSpec {
        if inner.expires_ns == 0 {
            return ITimerSpec::default();
        }

        let remaining = inner.expires_ns.saturating_sub(inner.clock.now());
        ITimerSpec::from_ns(remaining, inner.interval_ns)
    }

    /// Read the timerfd (returns expiration count)
    ///
    /// Blocks until timer expires (unless O_NONBLOCK is set).
    /// Returns the number of expirations as an 8-byte u64.
    pub fn read(&self, nonblock: bool) -> Result<u64, KernelError> {
        loop {
            if !nonblock {
                // Until it expires (Linux waits even while disarmed)
                self.wait_queue
                    .wait_event_interruptible(|| self.inner.lock().ticks > 0)?;
            }
            let mut inner = self.inner.lock();
            // The clock was set: the ticks do not count (Linux
            // timerfd_canceled)
            if inner.might_cancel && inner.moffs.is_none() {
                inner.moffs = Some(crate::time::real_offset());
                inner.ticks = 0;
                inner.expired = false;
                return Err(KernelError::Canceled);
            }
            if inner.ticks > 0 {
                let n = core::mem::take(&mut inner.ticks);
                return Ok(n.saturating_add(self.restart(&mut inner)));
            }
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            // Another reader took them
        }
    }

    /// Poll for readiness
    pub fn poll(&self, pt: Option<&mut PollTable<'_>>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.wait_queue);
        }

        let inner = self.inner.lock();
        if inner.ticks > 0 {
            POLLIN | POLLRDNORM
        } else {
            0
        }
    }

    /// Called when timer expires (from timer callback): one more tick; a
    /// periodic timer is re-armed by the next read or gettime (Linux
    /// timerfd_tmrproc)
    fn on_expire(&self) {
        {
            let mut inner = self.inner.lock();
            if inner.expires_ns == 0 {
                return;
            }
            inner.ticks = inner.ticks.saturating_add(1);
            if inner.interval_ns == 0 {
                inner.expires_ns = 0;
            } else {
                inner.expired = true;
            }
        }

        // Wake any waiting readers
        self.wait_queue.wake_poll(u32::from(POLLIN));
    }

    /// Re-arm an expired periodic timer for the first period end after
    /// now; returns the periods missed beyond the one counted at expiry
    /// (Linux timerfd_hrtimer_restart). Re-arming here rather than in
    /// the callback bounds a tiny period to one expiry per read.
    fn restart(&self, inner: &mut TimerfdInner) -> u64 {
        if !inner.expired || inner.interval_ns == 0 {
            return 0;
        }
        inner.expired = false;
        let now = inner.clock.now();
        let (missed, next) = crate::time::timer::forward(inner.expires_ns, inner.interval_ns, now);
        match next {
            Some(n) => {
                inner.expires_ns = n;
                self.timer().start(n, inner.clock);
            }
            None => inner.expires_ns = 0,
        }
        missed - 1
    }

    /// Release the timerfd (Linux timerfd_release): cancel the timer,
    /// waiting out its callback, and leave the cancel list; the entry
    /// goes after a grace period (`RcuUnlinked`, close: thread context,
    /// no lock held)
    fn release(self: &Arc<Self>) {
        self.timer.cancel_sync();
        let listed = {
            let mut inner = self.inner.lock();
            inner.might_cancel = false;
            core::mem::take(&mut inner.listed)
        };
        if listed {
            let _gone = CANCEL_LIST.remove_first(|t| core::ptr::eq(t, Arc::as_ptr(self)));
        }
    }

    /// Arm or disarm cancel-on-set for `flags` (Linux
    /// timerfd_setup_cancel): realtime, absolute, CANCEL_ON_SET. Decided
    /// under `inner`; the first one to arm it puts it on the cancel list
    /// after (a settime under way when the clock is set may miss it, as
    /// in Linux), where it stays until its release: a timerfd whose
    /// cancel-on-set is turned off again is skipped by
    /// `clock_was_set` (`might_cancel`), so a second settime never
    /// re-links an entry still in its grace period.
    fn setup_cancel(self: &Arc<Self>, flags: i32) {
        use tfd_timer_flags::{TFD_TIMER_ABSTIME, TFD_TIMER_CANCEL_ON_SET};
        let link = {
            let mut inner = self.inner.lock();
            let want = flags & TFD_TIMER_ABSTIME != 0
                && flags & TFD_TIMER_CANCEL_ON_SET != 0
                && clock_of(inner.clockid) == HrClock::Realtime;
            inner.might_cancel = want;
            let link = want && !inner.listed;
            inner.listed |= want;
            link
        };
        if link {
            CANCEL_LIST.push_back(self.clone());
        }
    }

    /// The realtime clock was set (`clock_was_set`)
    fn clock_was_set(&self, moffs: i64) {
        {
            let mut inner = self.inner.lock();
            if !inner.might_cancel || inner.moffs == Some(moffs) {
                return;
            }
            inner.moffs = None;
            inner.ticks = inner.ticks.saturating_add(1);
        }
        self.wait_queue.wake_poll(u32::from(POLLIN));
    }
}

/// The timer clock of a timerfd clock id
fn clock_of(clockid: i32) -> HrClock {
    crate::time::time_syscall::PosixClock::decode(clockid)
        .and_then(|c| c.timer_base())
        .unwrap_or(HrClock::Monotonic)
}

/// Timerfds that armed TFD_TIMER_CANCEL_ON_SET (Linux cancel_list): an
/// RCU list, walked by `clock_was_set` with no lock and no allocation
static CANCEL_LIST: RcuList<ClistAdapter> = RcuList::new();

/// CLOCK_REALTIME was set: fail the reads of cancel-on-set timerfds
/// whose offset changed (Linux timerfd_clock_was_set: the list walked
/// under rcu_read_lock, each one's lock taken in turn)
pub fn clock_was_set() {
    let moffs = crate::time::real_offset();
    let g = crate::sync::rcu::read_lock();
    for t in CANCEL_LIST.iter(&g) {
        t.clock_was_set(moffs);
    }
}

/// The timer of a timerfd expired (timer interrupt)
fn timerfd_fire(t: &HrTimer) {
    // SAFETY: `data` is the timerfd owning `t` (see `Timerfd::timer`)
    unsafe { &*(t.data() as *const Timerfd) }.on_expire();
}

/// File operations for timerfd
pub struct TimerfdFileOps;

static TIMERFD_FOPS: TimerfdFileOps = TimerfdFileOps;

impl FileOps for TimerfdFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// The expiration count, 8 bytes; a smaller buffer is EINVAL. The
    /// ticks are taken under the lock and copied out after it.
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let nb = nowait_rw(file, at, flags)?;
        let timerfd = file.private_ref::<Timerfd>().ok_or(KernelError::BadFd)?;
        if to.len() < 8 {
            return Err(KernelError::InvalidArgument);
        }
        let count = timerfd.read(nb)?;
        to.copy_to_full(&count.to_le_bytes())?;
        Ok(8)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(timerfd) = file.private_ref::<Timerfd>() else {
            return crate::io::poll::POLLERR;
        };
        timerfd.poll(pt)
    }

    fn release(&self, file: &File) -> Result<(), KernelError> {
        let timerfd = file.private_arc::<Timerfd>().ok_or(KernelError::BadFd)?;
        timerfd.release();
        Ok(())
    }
}

/// Create a timerfd file
///
/// # Arguments
/// * `clockid` - CLOCK_REALTIME (0) or CLOCK_MONOTONIC (1)
/// * `flags` - TFD_CLOEXEC | TFD_NONBLOCK
///
/// # Returns
/// FileRef for the new timerfd
pub fn create_timerfd(clockid: i32, tfd_flags: i32) -> Result<FileRef, KernelError> {
    let timerfd = Timerfd::new(clockid)?;

    // Create dummy dentry for timerfd

    // Determine file flags
    let mut file_flags = flags::O_RDONLY;
    if tfd_flags & tfd_flags::TFD_NONBLOCK != 0 {
        file_flags |= flags::O_NONBLOCK;
    }

    let file = crate::fs::anon_inodes::anon_inode_getfile(
        "[timerfd]",
        &TIMERFD_FOPS,
        timerfd,
        file_flags,
    )?;
    Ok(file)
}

/// Get the Timerfd from a File (for syscall implementations)
pub fn get_timerfd(file: &File) -> Option<Arc<Timerfd>> {
    file.private_arc::<Timerfd>()
}
