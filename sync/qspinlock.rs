//! Queued spin lock (Linux kernel/locking/qspinlock.c, the native path)
//!
//! One 32-bit word (Linux struct qspinlock, NR_CPUS < 16K layout):
//!
//! ```text
//!  0- 7: locked byte
//!  8-15: pending byte
//! 16-17: tail index (the waiter's nesting level)
//! 18-31: tail CPU + 1
//! ```
//!
//! Uncontended, a lock is one compare-exchange 0 -> locked and an unlock
//! one byte store-release. The first contender sets the pending bit and
//! spins on the word; further ones queue on per-CPU MCS nodes and each
//! spins on its own node, so a contended lock moves no shared line
//! between waiters, and the lock is granted in FIFO order. A CPU has
//! four nodes, one per context that can be spinning at once (task,
//! softirq, hardirq, NMI: Linux _Q_MAX_NODES); a deeper nesting falls
//! back to trylock spinning.
//!
//! Callers keep preemption off from before `lock` to after `unlock`
//! (every lock type here raises the preempt count first), so a queued
//! node stays this CPU's.
//!
//! The byte and halfword accesses Linux makes on the word (unlock,
//! `set_locked`, `clear_pending_set_locked`, `xchg_tail`) are arch
//! instructions (`arch::qspin`): Rust's memory model has no mixed-size
//! atomics, the hardware's does.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

const LOCKED_OFFSET: u32 = 0;
const LOCKED_VAL: u32 = 1 << LOCKED_OFFSET;
const LOCKED_MASK: u32 = 0xff;
const PENDING_OFFSET: u32 = 8;
const PENDING_VAL: u32 = 1 << PENDING_OFFSET;
const PENDING_MASK: u32 = 0xff << PENDING_OFFSET;
const LOCKED_PENDING_MASK: u32 = LOCKED_MASK | PENDING_MASK;
const TAIL_IDX_OFFSET: u32 = 16;
const TAIL_IDX_MASK: u32 = 0x3 << TAIL_IDX_OFFSET;
const TAIL_CPU_OFFSET: u32 = 18;
const TAIL_MASK: u32 = !LOCKED_PENDING_MASK;

/// Nodes per CPU (Linux _Q_MAX_NODES): task, softirq, hardirq, NMI
const MAX_NODES: usize = 4;

/// Spins of a lone pending holder before queueing (Linux
/// _Q_PENDING_LOOPS: 1 generically, 512 on x86)
#[cfg(target_arch = "x86_64")]
const PENDING_LOOPS: u32 = 512;
#[cfg(not(target_arch = "x86_64"))]
const PENDING_LOOPS: u32 = 1;

/// The lock word (Linux struct qspinlock)
#[repr(C, align(4))]
pub struct QSpinLock {
    val: AtomicU32,
}

/// An MCS queue node (Linux struct mcs_spinlock in struct qnode)
struct QNode {
    next: AtomicPtr<QNode>,
    /// Set by the predecessor when this node heads the queue
    locked: AtomicU32,
    /// Nodes in use on this CPU (node 0's only: Linux qnodes[0].count);
    /// this CPU's alone, nested contexts restore it
    count: AtomicU32,
}

impl QNode {
    const fn new() -> Self {
        Self {
            next: AtomicPtr::new(core::ptr::null_mut()),
            locked: AtomicU32::new(0),
            count: AtomicU32::new(0),
        }
    }
}

#[cfg(not(test))]
crate::percpu! {
    /// Each CPU's queue nodes (Linux qnodes, DEFINE_PER_CPU_ALIGNED)
    static QNODES: [QNode; MAX_NODES] = [const { QNode::new() }; MAX_NODES];
}

/// This CPU's nodes and id (+1 for the tail: 0 means no tail)
#[cfg(not(test))]
fn this_nodes() -> (&'static [QNode; MAX_NODES], u32) {
    let cpu = crate::cpu::this_id();
    (QNODES.get(cpu), cpu)
}

/// CPU `cpu`'s node `idx`
#[cfg(not(test))]
fn node_of(cpu: u32, idx: u32) -> &'static QNode {
    &QNODES.get(cpu)[idx as usize]
}

// Host unit tests: each thread is a "CPU" with nodes of its own
#[cfg(test)]
std::thread_local! {
    static TEST_NODES: &'static [QNode; MAX_NODES] =
        Box::leak(Box::new([const { QNode::new() }; MAX_NODES]));
}

#[cfg(test)]
static TEST_REG: std::sync::Mutex<alloc::vec::Vec<usize>> =
    std::sync::Mutex::new(alloc::vec::Vec::new());

#[cfg(test)]
fn this_nodes() -> (&'static [QNode; MAX_NODES], u32) {
    let n = TEST_NODES.with(|n| *n);
    let mut reg = TEST_REG.lock().unwrap();
    let p = n as *const _ as usize;
    let id = match reg.iter().position(|&x| x == p) {
        Some(i) => i,
        None => {
            reg.push(p);
            reg.len() - 1
        }
    };
    (n, id as u32)
}

#[cfg(test)]
fn node_of(cpu: u32, idx: u32) -> &'static QNode {
    let p = TEST_REG.lock().unwrap()[cpu as usize];
    // SAFETY: a leaked thread's nodes, never freed
    unsafe { &(*(p as *const [QNode; MAX_NODES]))[idx as usize] }
}

/// The tail code of CPU `cpu`'s node `idx` (Linux encode_tail)
fn encode_tail(cpu: u32, idx: u32) -> u32 {
    ((cpu + 1) << TAIL_CPU_OFFSET) | (idx << TAIL_IDX_OFFSET)
}

/// The node a tail code names (Linux decode_tail)
fn decode_tail(tail: u32) -> &'static QNode {
    let cpu = (tail >> TAIL_CPU_OFFSET) - 1;
    let idx = (tail & TAIL_IDX_MASK) >> TAIL_IDX_OFFSET;
    node_of(cpu, idx)
}

/// Spin until `cond` holds of the word, loads `ord` (Linux
/// atomic_cond_read_relaxed / _acquire)
#[inline]
fn cond_read(a: &AtomicU32, ord: Ordering, mut cond: impl FnMut(u32) -> bool) -> u32 {
    loop {
        let v = a.load(ord);
        if cond(v) {
            return v;
        }
        core::hint::spin_loop();
    }
}

impl QSpinLock {
    pub const fn new() -> Self {
        Self {
            val: AtomicU32::new(0),
        }
    }

    fn locked_ptr(&self) -> *mut u8 {
        // Little-endian: byte 0 of the word
        self.val.as_ptr().cast::<u8>()
    }

    fn locked_pending_ptr(&self) -> *mut u16 {
        self.val.as_ptr().cast::<u16>()
    }

    fn tail_ptr(&self) -> *mut u16 {
        // SAFETY of the arithmetic: halfword 1 of the 4-byte word
        self.val.as_ptr().cast::<u16>().wrapping_add(1)
    }

    /// Held (Linux queued_spin_is_locked)
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.val.load(Ordering::Relaxed) != 0
    }

    /// Take it if free (Linux queued_spin_trylock)
    #[inline]
    pub fn try_lock(&self) -> bool {
        let v = self.val.load(Ordering::Relaxed);
        v == 0
            && self
                .val
                .compare_exchange(0, LOCKED_VAL, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
    }

    /// Take it (Linux queued_spin_lock)
    #[inline]
    pub fn lock(&self) {
        if let Err(v) =
            self.val
                .compare_exchange(0, LOCKED_VAL, Ordering::Acquire, Ordering::Relaxed)
        {
            self.lock_slowpath(v);
        }
    }

    /// Release it (Linux queued_spin_unlock: a byte store-release)
    ///
    /// # Safety
    /// The caller holds it.
    #[inline]
    pub unsafe fn unlock(&self) {
        // SAFETY: the locked byte of this live word; only the holder
        // writes it now
        unsafe { crate::arch::qspin::store_release_u8(self.locked_ptr(), 0) };
    }

    /// Linux set_locked: WRITE_ONCE(lock->locked, _Q_LOCKED_VAL)
    fn set_locked(&self) {
        // SAFETY: the locked byte of this live word; the queue head is
        // the only writer of it now
        unsafe { crate::arch::qspin::store_u8(self.locked_ptr(), LOCKED_VAL as u8) };
    }

    /// Linux clear_pending_set_locked: WRITE_ONCE(lock->locked_pending,
    /// _Q_LOCKED_VAL)
    fn clear_pending_set_locked(&self) {
        // SAFETY: the low halfword of this live word; the pending owner
        // is its only writer now
        unsafe { crate::arch::qspin::store_u16(self.locked_pending_ptr(), LOCKED_VAL as u16) };
    }

    /// Linux clear_pending: WRITE_ONCE(lock->pending, 0)
    fn clear_pending(&self) {
        // SAFETY: the pending byte of this live word; its setter alone
        // clears it
        unsafe { crate::arch::qspin::store_u8(self.locked_ptr().wrapping_add(1), 0) };
    }

    /// Put `tail` in the tail, the old word's tail bits (Linux
    /// xchg_tail: xchg_relaxed of the tail halfword)
    fn xchg_tail(&self, tail: u32) -> u32 {
        // SAFETY: the tail halfword of this live word
        let old = unsafe { crate::arch::qspin::xchg_u16(self.tail_ptr(), (tail >> 16) as u16) };
        u32::from(old) << 16
    }

    /// Linux queued_fetch_set_pending_acquire: the old word
    fn fetch_set_pending_acquire(&self) -> u32 {
        self.val.fetch_or(PENDING_VAL, Ordering::Acquire)
    }

    /// Linux queued_spin_lock_slowpath (native: no paravirt, no
    /// virt_spin_lock)
    #[cold]
    fn lock_slowpath(&self, mut val: u32) {
        // A pending-to-locked hand-over in progress: wait a moment
        if val == PENDING_VAL {
            let mut cnt = PENDING_LOOPS;
            val = cond_read(&self.val, Ordering::Relaxed, |v| {
                let done = v != PENDING_VAL || cnt == 0;
                cnt = cnt.saturating_sub(1);
                done
            });
        }
        // Any contention (pending or a queue): queue
        if val & !LOCKED_MASK == 0 {
            // Become the pending waiter
            val = self.fetch_set_pending_acquire();
            if val & !LOCKED_MASK == 0 {
                // Wait for the owner to go, then take it over
                if val & LOCKED_MASK != 0 {
                    // Linux smp_cond_load_acquire(&lock->locked, !VAL)
                    cond_read(&self.val, Ordering::Acquire, |v| v & LOCKED_MASK == 0);
                }
                self.clear_pending_set_locked();
                return;
            }
            // Someone queued or pended meanwhile: undo ours, then queue
            if val & PENDING_MASK == 0 {
                self.clear_pending();
            }
        }
        self.queue();
    }

    /// The MCS part of the slow path (Linux queued_spin_lock_slowpath
    /// from `queue:`)
    fn queue(&self) {
        let (nodes, cpu) = this_nodes();
        let head = &nodes[0];
        // This CPU's nesting level: only it (and its nested contexts,
        // which restore it) changes the count
        let idx = head.count.load(Ordering::Relaxed);
        head.count.store(idx + 1, Ordering::Relaxed);
        if idx as usize >= MAX_NODES {
            // Nested past the nodes (Linux lock_no_node): spin on trylock
            while !self.try_lock() {
                core::hint::spin_loop();
            }
            head.count.store(idx, Ordering::Relaxed);
            return;
        }
        let tail = encode_tail(cpu, idx);
        let node = &nodes[idx as usize];
        node.locked.store(0, Ordering::Relaxed);
        node.next.store(core::ptr::null_mut(), Ordering::Relaxed);

        // The node set up may have taken a while: try once more
        if self.try_lock() {
            head.count.store(idx, Ordering::Relaxed);
            return;
        }
        // Linux smp_wmb(): the node's fields before its publication
        core::sync::atomic::fence(Ordering::Release);

        let old = self.xchg_tail(tail);
        let mut next: *mut QNode = core::ptr::null_mut();
        if old & TAIL_MASK != 0 {
            let prev = decode_tail(old);
            prev.next
                .store(core::ptr::from_ref(node).cast_mut(), Ordering::Relaxed);
            // Linux arch_mcs_spin_lock_contended: until the predecessor
            // hands over (Acquire)
            cond_read(&node.locked, Ordering::Acquire, |v| v != 0);
            next = node.next.load(Ordering::Relaxed);
        }

        // Head of the queue: wait for owner and pending to go (Linux
        // atomic_cond_read_acquire(&lock->val, !(VAL &
        // _Q_LOCKED_PENDING_MASK)))
        let val = cond_read(&self.val, Ordering::Acquire, |v| {
            v & LOCKED_PENDING_MASK == 0
        });

        // Last in the queue: take the lock and clear the tail at once
        if val & TAIL_MASK == tail
            && self
                .val
                .compare_exchange(val, LOCKED_VAL, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            head.count.store(idx, Ordering::Relaxed);
            return;
        }
        // Others queued behind: take the lock, then hand the head on
        self.set_locked();
        if next.is_null() {
            // Linux smp_cond_load_relaxed(&node->next, VAL)
            loop {
                next = node.next.load(Ordering::Relaxed);
                if !next.is_null() {
                    break;
                }
                core::hint::spin_loop();
            }
        }
        // SAFETY: the successor's node, queued behind ours: it spins on
        // its `locked` until this store, so it is live
        let n = unsafe { &*next };
        // Linux arch_mcs_spin_unlock_contended: smp_store_release
        n.locked.store(1, Ordering::Release);
        head.count.store(idx, Ordering::Relaxed);
    }
}

impl Default for QSpinLock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::cell::UnsafeCell;

    struct Counter {
        lock: QSpinLock,
        n: UnsafeCell<u64>,
    }
    // SAFETY: `n` is touched only under `lock`
    unsafe impl Sync for Counter {}

    #[test]
    fn uncontended() {
        let l = QSpinLock::new();
        assert!(!l.is_locked());
        l.lock();
        assert!(l.is_locked());
        assert!(!l.try_lock());
        // SAFETY: held
        unsafe { l.unlock() };
        assert!(l.try_lock());
        // SAFETY: held
        unsafe { l.unlock() };
        assert_eq!(l.val.load(Ordering::Relaxed), 0);
    }

    /// Many threads incrementing under the lock lose no increment, and
    /// the word ends free with no tail
    #[test]
    fn contended() {
        const THREADS: usize = 8;
        const ITERS: u64 = 20_000;
        let c = Arc::new(Counter {
            lock: QSpinLock::new(),
            n: UnsafeCell::new(0),
        });
        let hs: alloc::vec::Vec<_> = (0..THREADS)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for _ in 0..ITERS {
                        c.lock.lock();
                        // SAFETY: under the lock
                        unsafe { *c.n.get() += 1 };
                        // SAFETY: held
                        unsafe { c.lock.unlock() };
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        // SAFETY: every thread is done
        assert_eq!(unsafe { *c.n.get() }, THREADS as u64 * ITERS);
        assert_eq!(c.lock.val.load(Ordering::Relaxed), 0);
    }
}
