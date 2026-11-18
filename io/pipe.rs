//! Pipe Implementation
//!
//! This module implements Unix pipes following Linux semantics exactly.
//!
//! ## Architecture
//!
//! ```text
//! Process A                    Process B
//!     |                            |
//!     v                            v
//! write(pipe_w)               read(pipe_r)
//!     |                            |
//!     v                            v
//! write file               read file
//!     |                            |
//!     +-----> Arc<Pipe> <----------+
//!              |
//!              v
//!     Page-based Ring Buffer
//!         Wait Queue
//! ```
//!
//! ## Key Features
//!
//! - PIPE_BUF (4096) byte atomic writes
//! - poll() support with wait queue integration
//! - POLLHUP when other end closes
//! - O_NONBLOCK support
//! - Zero-copy splice/tee/vmsplice support via page-based buffers
//!
//! ## Locking
//!
//! `Pipe.inner` is a sleeping mutex (Linux pipe->mutex, `Pipe::lock`):
//! its holder may allocate pages, and read and write copy between the
//! pipe pages and the caller's iterator under it (a user copy may
//! fault: -> mmap_lock, as in Linux). Wait conditions and poll never take
//! it (poll runs under epoll's spin lock): like Linux pipe_readable /
//! pipe_writable they read the ring indices `Pipe.head_tail` (one
//! word, stored as the guard unlocks or before a wakeup made under
//! it), the usable slots `Pipe.max_usage` and the reader/writer counts,
//! all written under `Pipe.inner`. Wakeups follow the unlock where Linux's do (read, write,
//! most of splice). O_ASYNC files are on `fasync_readers` /
//! `fasync_writers` (by access mode; changed under `Pipe.inner`, Linux
//! pipe_fasync); their SIGIO goes with the wakeups (Linux pipe_read,
//! pipe_write: after the unlock), and a FIFO release's under
//! `Pipe.inner` with its count change (Linux pipe_release).
//! splice/tee lock two pipes in address order (Linux pipe_double_lock).
//!
//! ## Reference
//!
//! - `./select-poll.md` - Implementation guide
//! - Linux pipe(7) man page
//! - Linux fs/pipe.c

use crate::fs::FileRef;
use crate::sync::{Mutex, MutexGuard};
use crate::util::error::KernelResult;
use crate::util::kalloc::try_arc;
use alloc::sync::Arc;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, RwFlags, flags};
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::io::fasync::{FasyncList, POLL_IN, POLL_OUT, fasync_helper, kill_fasync};
use crate::io::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::mm::filemap::PAGE_SIZE;
use crate::sync::waitqueue::WaitQueue;
use crate::task::UcountsRef;

/// Pipe buffer size (matches Linux PIPE_BUF for atomic writes)
pub const PIPE_BUF: usize = 4096;

/// Buffer slots of a new pipe (Linux PIPE_DEF_BUFFERS)
pub const PIPE_DEF_BUFFERS: usize = 16;

/// fs.pipe-max-size: the largest size F_SETPIPE_SZ grants without
/// CAP_SYS_RESOURCE (Linux pipe_max_size, 1 MiB)
static PIPE_MAX_SIZE: AtomicUsize = AtomicUsize::new(1 << 20);

/// fs.pipe-user-pages-hard and -soft (Linux pipe_user_pages_hard,
/// _soft): the slots a user's pipes may hold in all, 0 for no limit
static PIPE_USER_PAGES_HARD: AtomicUsize = AtomicUsize::new(0);
static PIPE_USER_PAGES_SOFT: AtomicUsize = AtomicUsize::new(16384);

/// Slots of a new pipe of a user over the soft limit (Linux
/// PIPE_MIN_DEF_BUFFERS)
const PIPE_MIN_DEF_BUFFERS: usize = 2;

/// Move `user`'s charge for one pipe from `old` slots to `new`; the
/// user's slots now (Linux account_pipe_buffers)
fn account_pipe_buffers(user: &UcountsRef, old: usize, new: usize) -> usize {
    use crate::task::ucount::Ucount;
    if new >= old {
        user.inc(Ucount::PipeBufs, (new - old) as u64) as usize
    } else {
        user.sub(Ucount::PipeBufs, (old - new) as u64) as usize
    }
}

/// Over a limit (Linux too_many_pipe_buffers_soft/_hard: 0 is none)
fn over(limit: &AtomicUsize, user_bufs: usize) -> bool {
    let l = limit.load(Ordering::Relaxed);
    l != 0 && user_bufs > l
}

/// Neither CAP_SYS_RESOURCE nor CAP_SYS_ADMIN (Linux
/// pipe_is_unprivileged_user)
fn unprivileged() -> bool {
    !crate::task::capable(crate::task::CAP_SYS_RESOURCE)
        && !crate::task::capable(crate::task::CAP_SYS_ADMIN)
}

/// A requested pipe size rounded up to a power of two pages, at least
/// one; 0 past 2^31 (Linux round_pipe_size)
fn round_pipe_size(size: u64) -> usize {
    if size > 1 << 31 {
        return 0;
    }
    (size as usize).max(PAGE_SIZE).next_power_of_two()
}

/// /proc/sys/fs/pipe-* (Linux fs/pipe.c fs_pipe_sysctls)
pub static PIPE_CTLS: &[crate::sysctl::Ctl] = &[
    crate::sysctl::Ctl {
        path: "fs/pipe-max-size",
        mode: 0o644,
        show: || alloc::vec![PIPE_MAX_SIZE.load(Ordering::Relaxed) as i64],
        // Linux proc_dopipe_max_size: an unsigned int, rounded
        store: |v| {
            let n = u32::try_from(v[0]).map_err(|_| KernelError::InvalidArgument)?;
            match round_pipe_size(u64::from(n)) {
                0 => Err(KernelError::InvalidArgument),
                r => {
                    PIPE_MAX_SIZE.store(r, Ordering::Relaxed);
                    Ok(())
                }
            }
        },
        text: None,
    },
    crate::sysctl::Ctl {
        path: "fs/pipe-user-pages-hard",
        mode: 0o644,
        show: || alloc::vec![PIPE_USER_PAGES_HARD.load(Ordering::Relaxed) as i64],
        store: |v| {
            let n = usize::try_from(v[0]).map_err(|_| KernelError::InvalidArgument)?;
            PIPE_USER_PAGES_HARD.store(n, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
    crate::sysctl::Ctl {
        path: "fs/pipe-user-pages-soft",
        mode: 0o644,
        show: || alloc::vec![PIPE_USER_PAGES_SOFT.load(Ordering::Relaxed) as i64],
        store: |v| {
            let n = usize::try_from(v[0]).map_err(|_| KernelError::InvalidArgument)?;
            PIPE_USER_PAGES_SOFT.store(n, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
];

/// Pipe buffer flags
pub mod pipe_buf_flags {
    /// Page is in LRU (can be reclaimed)
    pub const LRU: u32 = 0x01;
    /// Page was atomically mapped
    pub const ATOMIC: u32 = 0x02;
    /// User donated this page (for vmsplice with SPLICE_F_GIFT)
    pub const GIFT: u32 = 0x04;
    /// Pages are a packet (for packet mode)
    pub const PACKET: u32 = 0x08;
    /// Can merge with previous buffer
    pub const CAN_MERGE: u32 = 0x10;
    /// This buffer was created by the kernel (owned)
    pub const OWNED: u32 = 0x20;
}

/// A page of pipe data (Linux the page of a pipe_buffer): shared by
/// the buffers that hold it (tee, splice), freed with the last
pub struct PipePage {
    pub frame: u64,
}

impl PipePage {
    pub fn new(frame: u64) -> Self {
        Self { frame }
    }

    /// Its bytes
    ///
    /// # Safety
    /// Under the pipe's `Pipe.inner`; written only while no other buffer
    /// shares the page (CAN_MERGE).
    #[expect(clippy::mut_from_ref)]
    pub unsafe fn bytes(&self) -> &mut [u8] {
        // SAFETY: the page's own frame; the caller's contract
        unsafe { crate::mm::page::frame_bytes(self.frame) }
    }
}

impl Drop for PipePage {
    fn drop(&mut self) {
        crate::FRAME_ALLOCATOR.free(self.frame);
    }
}

/// A single buffer slot in a pipe
///
/// Similar to Linux's struct pipe_buffer, this holds a reference to a page
/// along with offset and length information for the valid data region.
pub struct PipeBuffer {
    /// Page holding the buffer data
    /// None if this slot is empty, Some if it contains data
    pub page: Option<Arc<PipePage>>,
    /// Offset within the page where data starts
    pub offset: u32,
    /// Length of valid data in this buffer
    pub len: u32,
    /// Buffer flags (see pipe_buf_flags)
    pub flags: u32,
}

impl PipeBuffer {
    /// Create an empty pipe buffer slot
    pub const fn empty() -> Self {
        Self {
            page: None,
            offset: 0,
            len: 0,
            flags: 0,
        }
    }

    /// Create a new pipe buffer with a page
    pub fn new(page: Arc<PipePage>, offset: u32, len: u32, flags: u32) -> Self {
        Self {
            page: Some(page),
            offset,
            len,
            flags,
        }
    }

    /// Check if this buffer slot is empty
    pub fn is_empty(&self) -> bool {
        self.page.is_none() || self.len == 0
    }

    /// Check if this buffer can be merged with new data
    pub fn can_merge(&self) -> bool {
        if self.page.is_none() {
            return false;
        }
        // Can merge if CAN_MERGE flag is set and there's space at the end
        (self.flags & pipe_buf_flags::CAN_MERGE != 0)
            && ((self.offset + self.len) as usize) < PAGE_SIZE
    }

    /// Get remaining space in this buffer for merging
    pub fn space_available(&self) -> usize {
        if self.page.is_none() {
            return 0;
        }
        PAGE_SIZE - (self.offset + self.len) as usize
    }

    /// Release the page reference
    pub fn release(&mut self) {
        if let Some(ref page) = self.page {
            // The Arc counts every buffer sharing the page (tee)
            let _ = page;
        }
        self.page = None;
        self.offset = 0;
        self.len = 0;
        self.flags = 0;
    }
}

/// Internal pipe state shared between read and write ends
///
/// Uses page-based ring buffer to support zero-copy splice operations.
/// Public for splice module access.
pub struct PipeInner {
    /// Ring of buffer slots, a power of two (Linux pipe->bufs,
    /// ring_size); index `i` is slot `i & (len - 1)`
    bufs: alloc::boxed::Box<[PipeBuffer]>,
    /// Head index, free-running (Linux pipe->head): the next slot
    /// written
    pub head: usize,
    /// Tail index, free-running (Linux pipe->tail): the next slot read
    pub tail: usize,
    /// Total bytes in all buffers
    pub total_len: usize,
}

/// A ring of `n` empty slots (`n` a power of two), or ENOMEM (Linux
/// kcalloc: past the largest allocation too)
fn new_ring(n: usize) -> Result<alloc::boxed::Box<[PipeBuffer]>, KernelError> {
    Ok(crate::util::kmem::try_vec_with(n, PipeBuffer::empty)?.into_boxed_slice())
}

impl PipeInner {
    /// An empty pipe of `slots` (a power of two), charged for them
    fn new(slots: usize) -> Result<Self, KernelError> {
        Ok(Self {
            bufs: new_ring(slots)?,
            head: 0,
            tail: 0,
            total_len: 0,
        })
    }

    /// The slot of index `i`
    pub fn buf(&self, i: usize) -> &PipeBuffer {
        &self.bufs[i & (self.bufs.len() - 1)]
    }

    /// The slot of index `i`, to change
    pub fn buf_mut(&mut self, i: usize) -> &mut PipeBuffer {
        let mask = self.bufs.len() - 1;
        &mut self.bufs[i & mask]
    }

    /// Slots that may be in use (Linux max_usage), also those charged
    /// to the creator (nr_accounted): the ring's (no watch queues)
    pub fn max_usage(&self) -> usize {
        self.bufs.len()
    }

    /// A ring of `slots` (a power of two) holding what is buffered at
    /// its start (Linux pipe_resize_ring): EBUSY if that does not fit
    fn resize(&mut self, slots: usize) -> Result<(), KernelError> {
        let n = self.buffer_count();
        if slots < n {
            return Err(KernelError::Busy);
        }
        let mut bufs = new_ring(slots)?;
        for (i, b) in bufs.iter_mut().take(n).enumerate() {
            *b = core::mem::replace(self.buf_mut(self.tail.wrapping_add(i)), PipeBuffer::empty());
        }
        self.bufs = bufs;
        self.tail = 0;
        self.head = n;
        Ok(())
    }

    /// Check if pipe is empty
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Check if pipe is full (all buffer slots used)
    pub fn is_full(&self) -> bool {
        self.buffer_count() >= self.max_usage()
    }

    /// Number of used buffer slots
    pub fn buffer_count(&self) -> usize {
        self.head.wrapping_sub(self.tail)
    }

    /// Bytes available for reading
    pub fn bytes_available(&self) -> usize {
        self.total_len
    }

    /// Get the tail buffer (for reading)
    pub fn tail_buf(&self) -> Option<&PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            Some(self.buf(self.tail))
        }
    }

    /// Get mutable tail buffer
    pub fn tail_buf_mut(&mut self) -> Option<&mut PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            Some(self.buf_mut(self.tail))
        }
    }

    /// Get the head buffer for writing (last used slot, for merging)
    pub fn head_buf_for_merge(&self) -> Option<&PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            // Head is the next free slot: the last one written is before
            Some(self.buf(self.head.wrapping_sub(1)))
        }
    }

    /// Get mutable head buffer for merging
    fn head_buf_for_merge_mut(&mut self) -> Option<&mut PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            Some(self.buf_mut(self.head.wrapping_sub(1)))
        }
    }

    /// Advance tail after consuming a buffer
    pub fn advance_tail(&mut self, bytes: usize) {
        self.total_len = self.total_len.saturating_sub(bytes);
        self.tail = self.tail.wrapping_add(1);
    }

    /// Add a buffer at head position
    pub fn push_buffer(&mut self, buf: PipeBuffer) -> Result<(), PipeBuffer> {
        if self.is_full() {
            return Err(buf);
        }
        let bytes = buf.len as usize;
        *self.buf_mut(self.head) = buf;
        self.head = self.head.wrapping_add(1);
        self.total_len += bytes;
        Ok(())
    }

    /// Append from `from` (Linux anon_pipe_write's copies): with
    /// `merge` (a write's first pass), the part past whole pages goes into
    /// the head buffer if it may merge and that part fits whole; then new
    /// pages while slots are free, each a packet buffer for a `packet`
    /// writer (Linux is_packetized), else one later writes may merge
    /// into. A page copy cut short by a fault is dropped. Returns the
    /// bytes taken and the error that stopped it early (EFAULT, ENOMEM),
    /// if any.
    fn write_from(
        &mut self,
        from: &mut IovSource<'_>,
        packet: bool,
        merge: bool,
    ) -> (usize, Option<KernelError>) {
        let mut written = 0;
        if merge {
            match self.merge_from(from) {
                Ok(c) => written = c,
                Err(e) => return (0, Some(e)),
            }
            self.total_len += written;
        }
        let flags = pipe_buf_flags::OWNED
            | if packet {
                pipe_buf_flags::PACKET
            } else {
                pipe_buf_flags::CAN_MERGE
            };
        while !from.is_empty() && !self.is_full() {
            let Some(page) = allocate_pipe_page() else {
                return (written, Some(KernelError::OutOfMemory));
            };
            let n = from.len().min(PAGE_SIZE);
            // SAFETY: a page just allocated for this buffer, under Pipe.inner
            let r = from.copy_from(unsafe { &mut page.bytes()[..n] });
            match r {
                Ok(c) if c == n => {}
                _ => return (written, Some(KernelError::BadAddress)),
            }
            if self
                .push_buffer(PipeBuffer::new(page, 0, n as u32, flags))
                .is_err()
            {
                break;
            }
            written += n;
        }
        (written, None)
    }

    /// Linux anon_pipe_write's merge: the write's length past whole pages
    /// is copied into the head buffer if it may merge (it is unshared) and
    /// has room for all of it; the bytes copied, EFAULT if the copy came
    /// up short (nothing is kept)
    fn merge_from(&mut self, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
        let chars = from.len() & (PAGE_SIZE - 1);
        if chars == 0 {
            return Ok(0);
        }
        let Some(buf) = self.head_buf_for_merge_mut() else {
            return Ok(0);
        };
        let off = (buf.offset + buf.len) as usize;
        if buf.flags & pipe_buf_flags::CAN_MERGE == 0 || off + chars > PAGE_SIZE {
            return Ok(0);
        }
        let Some(page) = buf.page.as_ref() else {
            return Ok(0);
        };
        // SAFETY: under Pipe.inner, an unshared CAN_MERGE page
        let c = from.copy_from(unsafe { &mut page.bytes()[off..off + chars] })?;
        if c < chars {
            return Err(KernelError::BadAddress);
        }
        buf.len += c as u32;
        Ok(c)
    }

    /// Consume into `to` from the tail on (Linux pipe_read's
    /// copy_page_to_iter), up to the end of the first packet buffer: the
    /// bytes copied, EFAULT if a fault stopped it before the first
    fn read_to(&mut self, to: &mut IovDest<'_>) -> Result<usize, KernelError> {
        let (mut read, mut dropped) = (0, 0);
        while !to.is_empty() && !self.is_empty() {
            let tail = self.tail;
            let buf = self.buf_mut(tail);
            let Some(page) = buf.page.as_ref().filter(|_| buf.len > 0) else {
                // An empty slot: skip it
                self.tail = tail.wrapping_add(1);
                continue;
            };
            let (off, len) = (buf.offset as usize, buf.len as usize);
            let want = len.min(to.len());
            // SAFETY: read under Pipe.inner
            let c = to
                .copy_to(unsafe { &page.bytes()[off..off + want] })
                .unwrap_or(0);
            // A short copy (a fault) consumes nothing of this buffer;
            // EFAULT if nothing was read (Linux pipe_read)
            if c < want {
                if read == 0 {
                    return Err(KernelError::BadAddress);
                }
                break;
            }
            buf.offset += c as u32;
            buf.len -= c as u32;
            read += c;
            // A packet ends the read; what did not fit is dropped (Linux
            // PIPE_BUF_FLAG_PACKET)
            let packet = buf.flags & pipe_buf_flags::PACKET != 0;
            if packet {
                dropped += buf.len as usize;
                buf.len = 0;
            }
            if buf.len == 0 {
                buf.release();
                self.tail = tail.wrapping_add(1);
            }
            if packet {
                break;
            }
        }
        self.total_len = self.total_len.saturating_sub(read + dropped);
        Ok(read)
    }
}

/// Allocate a page for pipe buffer data
///
/// Creates a page for holding pipe data.
fn allocate_pipe_page() -> Option<Arc<PipePage>> {
    use crate::FRAME_ALLOCATOR;

    // Allocate a physical frame
    // User data (Linux GFP_HIGHUSER | __GFP_ACCOUNT): stops at the low
    // watermark like the user pages it was copied from
    let frame = FRAME_ALLOCATOR.alloc_gfp(crate::mm::page_alloc::Gfp::HIGHUSER_MOVABLE)?;

    try_arc(PipePage::new(frame)).ok()
}

/// Shared pipe structure
pub struct Pipe {
    /// Pipe buffer (Linux pipe->mutex); taken through [`Pipe::lock`]
    inner: Mutex<PipeInner>,
    /// The user charged for its slots (Linux pipe->user)
    user: UcountsRef,
    /// The ring indices in one word, head low and tail high (Linux
    /// pipe->head_tail): stored under `inner` as the ring changes
    /// (`PipeGuard::publish`), read with one load by lockless readers
    /// (pipe_readable, pipe_writable), so head and tail are of one moment
    head_tail: AtomicU64,
    /// `inner.max_usage()`, stored under `inner` where it changes
    /// (`set_size`), read by lockless readers
    max_usage: AtomicUsize,
    /// Wait queue for readers/writers
    pub wait_queue: WaitQueue,
    /// Read and write ends (Linux pipe->readers / writers), opens of a
    /// FIFO for reading and writing so far (r_counter / w_counter: an
    /// opener waiting for its partner wakes when the other count
    /// moves): changed under `inner` (pipe_release, fifo_open), read
    /// with a plain load by lockless readers (READ_ONCE)
    readers: AtomicU32,
    r_counter: AtomicU32,
    w_counter: AtomicU32,
    writers: AtomicU32,
    /// O_ASYNC files open for reading / writing (Linux
    /// fasync_readers / fasync_writers)
    fasync_readers: FasyncList,
    fasync_writers: FasyncList,
}

impl Pipe {
    /// Create a new pipe
    /// A new pipe charged to the caller's user (Linux alloc_pipe_info):
    /// PIPE_DEF_BUFFERS slots, fewer if fs.pipe-max-size is smaller
    /// (without CAP_SYS_RESOURCE); PIPE_MIN_DEF_BUFFERS for an
    /// unprivileged user over fs.pipe-user-pages-soft, ENFILE over -hard
    pub fn new() -> Result<Arc<Self>, KernelError> {
        let user = crate::task::current_cred().ucounts;
        let max_size = PIPE_MAX_SIZE.load(Ordering::Relaxed);
        let mut slots = PIPE_DEF_BUFFERS;
        if slots * PAGE_SIZE > max_size && !crate::task::capable(crate::task::CAP_SYS_RESOURCE) {
            slots = max_size / PAGE_SIZE;
        }
        let mut user_bufs = account_pipe_buffers(&user, 0, slots);
        if over(&PIPE_USER_PAGES_SOFT, user_bufs) && unprivileged() {
            user_bufs = account_pipe_buffers(&user, slots, PIPE_MIN_DEF_BUFFERS);
            slots = PIPE_MIN_DEF_BUFFERS;
        }
        let inner = if over(&PIPE_USER_PAGES_HARD, user_bufs) && unprivileged() {
            Err(KernelError::SystemFileLimit)
        } else {
            PipeInner::new(slots)
        };
        let inner = match inner {
            Ok(i) => i,
            Err(e) => {
                account_pipe_buffers(&user, slots, 0);
                return Err(e);
            }
        };
        // From here the pipe's drop gives the charge back
        try_arc(Self {
            inner: Mutex::new(inner),
            user,
            head_tail: AtomicU64::new(0),
            max_usage: AtomicUsize::new(slots),
            wait_queue: WaitQueue::new(),
            readers: AtomicU32::new(1),
            writers: AtomicU32::new(1),
            r_counter: AtomicU32::new(0),
            w_counter: AtomicU32::new(0),
            fasync_readers: FasyncList::new(),
            fasync_writers: FasyncList::new(),
        })
    }

    /// F_GETPIPE_SZ: the pipe's size in bytes (Linux pipe_fcntl:
    /// max_usage pages)
    pub fn size(&self) -> usize {
        self.lock().max_usage() * PAGE_SIZE
    }

    /// F_SETPIPE_SZ (Linux pipe_set_size): `arg` rounded up to a power
    /// of two pages (EINVAL past 2^31); growing above fs.pipe-max-size
    /// needs CAP_SYS_RESOURCE, and past the user's soft or hard limit
    /// CAP_SYS_RESOURCE or CAP_SYS_ADMIN (EPERM); fewer slots than are
    /// in use is EBUSY. The new size in bytes; writers waiting for room
    /// are woken
    pub fn set_size(&self, arg: u64) -> Result<usize, KernelError> {
        let size = round_pipe_size(arg);
        let slots = size / PAGE_SIZE;
        if slots == 0 {
            return Err(KernelError::InvalidArgument);
        }
        let mut g = self.lock();
        let grow = slots > g.max_usage();
        if grow
            && size > PIPE_MAX_SIZE.load(Ordering::Relaxed)
            && !crate::task::capable(crate::task::CAP_SYS_RESOURCE)
        {
            return Err(KernelError::NotPermitted);
        }
        let old = g.max_usage();
        let user_bufs = account_pipe_buffers(&self.user, old, slots);
        let over_limit =
            over(&PIPE_USER_PAGES_HARD, user_bufs) || over(&PIPE_USER_PAGES_SOFT, user_bufs);
        let r = if grow && over_limit && unprivileged() {
            Err(KernelError::NotPermitted)
        } else {
            g.resize(slots)
        };
        if let Err(e) = r {
            account_pipe_buffers(&self.user, slots, old);
            return Err(e);
        }
        self.max_usage.store(g.max_usage(), Ordering::Relaxed);
        let n = g.max_usage() * PAGE_SIZE;
        drop(g);
        self.wait_queue.wake_all();
        Ok(n)
    }

    /// Lock the buffer (Linux pipe_lock); may sleep. Wake waiters only
    /// after dropping the guard: it publishes the ring indices then.
    pub fn lock(&self) -> PipeGuard<'_> {
        PipeGuard {
            pipe: self,
            g: self.inner.lock(),
        }
    }

    /// Used slots, without the lock: head and tail of one moment (Linux
    /// pipe_occupancy of one READ_ONCE(pipe->head_tail))
    fn occupancy(&self) -> usize {
        let ht = self.head_tail.load(Ordering::Acquire);
        (ht as u32).wrapping_sub((ht >> 32) as u32) as usize
    }

    /// No buffered data, without the lock
    pub fn ring_empty(&self) -> bool {
        self.occupancy() == 0
    }

    /// Every slot used, without the lock
    pub fn ring_full(&self) -> bool {
        self.occupancy() >= self.max_usage.load(Ordering::Relaxed)
    }

    /// A reader need not wait (Linux pipe_readable): data or no writer
    fn readable(&self) -> bool {
        !self.ring_empty() || !self.has_writers()
    }

    /// A writer need not wait (Linux pipe_writable): room or no reader
    fn writable(&self) -> bool {
        !self.ring_full() || !self.has_readers()
    }

    /// Locked with data in the ring, for a splice or tee reading it
    /// (Linux splice_from_pipe_next, ipipe_prep): None when it is empty
    /// with no writer (EOF, decided under the lock); else empty waits,
    /// EAGAIN if `nonblock`; a signal ends the wait
    pub fn lock_data(&self, nonblock: bool) -> KernelResult<Option<PipeGuard<'_>>> {
        loop {
            let g = self.lock();
            if !g.is_empty() {
                return Ok(Some(g));
            }
            if !self.has_writers() {
                return Ok(None);
            }
            drop(g);
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            self.wait_queue
                .wait_event_interruptible(|| self.readable())?;
        }
    }

    /// Locked with room in the ring, for a splice, tee or vmsplice
    /// filling it (Linux wait_for_space, opipe_prep): no reader is
    /// SIGPIPE and EPIPE; else full waits, EAGAIN if `nonblock`; a signal
    /// ends the wait
    pub fn lock_room(&self, nonblock: bool) -> KernelResult<PipeGuard<'_>> {
        loop {
            let g = self.lock();
            // Decided under the mutex (Linux wait_for_space)
            if !self.has_readers() {
                drop(g);
                sigpipe();
                return Err(KernelError::BrokenPipe);
            }
            if !g.is_full() {
                return Ok(g);
            }
            drop(g);
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            self.wait_queue
                .wait_event_interruptible(|| self.writable())?;
        }
    }

    /// A read end is open (exact under `inner`, a snapshot without)
    pub fn has_readers(&self) -> bool {
        self.readers.load(Ordering::Relaxed) > 0
    }

    /// A write end is open (exact under `inner`, a snapshot without)
    pub fn has_writers(&self) -> bool {
        self.writers.load(Ordering::Relaxed) > 0
    }

    /// Wake readers' waits and polls (rd_wait with EPOLLIN | EPOLLRDNORM)
    fn wake_rd(&self) {
        self.wait_queue.wake_poll(u32::from(POLLIN | POLLRDNORM));
    }

    /// Wake writers' waits and polls (wr_wait with EPOLLOUT | EPOLLWRNORM)
    fn wake_wr(&self) {
        self.wait_queue.wake_poll(u32::from(POLLOUT | POLLWRNORM));
    }

    /// SIGIO to the O_ASYNC readers (Linux kill_fasync(fasync_readers,
    /// SIGIO, POLL_IN))
    fn kill_readers(&self) {
        kill_fasync(&self.fasync_readers, crate::signal::SIGIO, POLL_IN);
    }

    /// SIGIO to the O_ASYNC writers (POLL_OUT)
    fn kill_writers(&self) {
        kill_fasync(&self.fasync_writers, crate::signal::SIGIO, POLL_OUT);
    }

    /// Data for readers (Linux splice's wakeup_pipe_readers)
    pub fn wake_readers(&self) {
        self.wake_rd();
        self.kill_readers();
    }

    /// Room for writers (Linux splice's wakeup_pipe_writers)
    pub fn wake_writers(&self) {
        self.wake_wr();
        self.kill_writers();
    }
}

/// Linux pipe_fasync: a reader on the readers' list, a writer on the
/// writers', O_RDWR on both (a failed second add undoes the first);
/// under `Pipe.inner` like Linux pipe->mutex
fn pipe_fasync(pipe: &Pipe, file: &File, fd: i32, on: bool) -> Result<(), KernelError> {
    let _g = pipe.lock();
    let rd = file.is_readable();
    if rd {
        fasync_helper(&pipe.fasync_readers, file, fd, on)?;
    }
    if file.is_writable()
        && let Err(e) = fasync_helper(&pipe.fasync_writers, file, fd, on)
    {
        if rd {
            let _ = fasync_helper(&pipe.fasync_readers, file, -1, false);
        }
        return Err(e);
    }
    Ok(())
}

impl Drop for Pipe {
    /// Give the creator's charge back (Linux free_pipe_info)
    fn drop(&mut self) {
        let n = self.inner.get_mut().max_usage();
        account_pipe_buffers(&self.user, n, 0);
    }
}

/// A locked pipe buffer ([`Pipe::lock`])
pub struct PipeGuard<'a> {
    pipe: &'a Pipe,
    g: MutexGuard<'a, PipeInner>,
}

impl Deref for PipeGuard<'_> {
    type Target = PipeInner;
    fn deref(&self) -> &PipeInner {
        &self.g
    }
}

impl DerefMut for PipeGuard<'_> {
    fn deref_mut(&mut self) -> &mut PipeInner {
        &mut self.g
    }
}

impl PipeGuard<'_> {
    /// Publish the ring indices for lockless readers (Linux's stores to
    /// pipe->head / pipe->tail); a wakeup made under the lock follows
    /// it, so the woken see the change
    pub fn publish(&self) {
        let ht = u64::from(self.g.head as u32) | (u64::from(self.g.tail as u32) << 32);
        if self.pipe.head_tail.load(Ordering::Relaxed) != ht {
            self.pipe.head_tail.store(ht, Ordering::Release);
        }
    }

    /// Change one of the pipe's counts (`readers`, `writers`,
    /// `r_counter`, `w_counter`) by `d`: under `inner` (this guard), so a
    /// load and a store
    fn count(&self, c: &AtomicU32, d: i32) {
        crate::sync::Sole::sole_add(c, d as u32);
    }
}

impl Drop for PipeGuard<'_> {
    /// Publish the ring indices, then unlock (the mutex guard field
    /// drops after this)
    fn drop(&mut self) {
        self.publish();
    }
}

/// Linux pipe_read: wait for data unless `nonblock`; a read takes what
/// is there (at most `to`'s room) and returns, 0 at EOF (no writers).
/// The copy runs under the sleeping `Pipe.inner` (it may fault). Every
/// read that gets that far, whatever its result, then signals the
/// O_ASYNC writers (Linux pipe_read's kill_fasync); one a signal
/// interrupts in its wait returns before (Linux: -ERESTARTSYS).
pub(crate) fn pipe_read(
    pipe: &Pipe,
    to: &mut IovDest<'_>,
    nonblock: bool,
) -> Result<usize, KernelError> {
    if to.is_empty() {
        return Ok(0);
    }
    let r = loop {
        let mut inner = pipe.lock();
        if !inner.is_empty() {
            let r = inner.read_to(to);
            drop(inner);
            // Room for writers (Linux pipe_read)
            pipe.wake_wr();
            break r;
        }
        // EOF is decided under the lock that saw the ring empty (Linux
        // pipe_read checks pipe->writers under pipe->mutex): a writer's
        // last write unlocks before its close drops the count, so data
        // written before the close is never mistaken for EOF
        if !pipe.has_writers() {
            break Ok(0);
        }
        drop(inner);
        if nonblock {
            break Err(KernelError::WouldBlock);
        }
        // Block until data or EOF; a signal ends the wait (-ERESTARTSYS)
        pipe.wait_queue
            .wait_event_interruptible(|| pipe.readable())?;
    };
    pipe.kill_writers();
    r
}

/// EPIPE's SIGPIPE to the writing thread
pub fn sigpipe() {
    use crate::signal::{SIGPIPE, send_signal};
    let _ = send_signal(&crate::task::percpu::current(), SIGPIPE);
}

/// Linux pipe_write: a blocking writer stays until everything is
/// written; a signal, `nonblock`, a fault or no memory ends it early,
/// returning the bytes written so far if any. Writes of at most PIPE_BUF
/// bytes are never split (any free slot takes them whole). No reader:
/// SIGPIPE and EPIPE. The copy runs under the sleeping `Pipe.inner`.
/// The O_ASYNC readers are signalled before each sleep and at the end,
/// whatever the result (Linux pipe_write's kill_fasync).
fn pipe_write(
    pipe: &Pipe,
    from: &mut IovSource<'_>,
    nonblock: bool,
    packet: bool,
) -> Result<usize, KernelError> {
    if from.is_empty() {
        return Ok(0);
    }
    let r = pipe_write_wait(pipe, from, nonblock, packet);
    pipe.kill_readers();
    r
}

/// pipe_write's copy and waits for room
fn pipe_write_wait(
    pipe: &Pipe,
    from: &mut IovSource<'_>,
    nonblock: bool,
    packet: bool,
) -> Result<usize, KernelError> {
    let partial = |done: usize, e| if done > 0 { Ok(done) } else { Err(e) };
    let mut done = 0;
    let mut first = true;
    loop {
        let mut inner = pipe.lock();
        // Decided under the mutex (Linux pipe_write)
        if !pipe.has_readers() {
            drop(inner);
            sigpipe();
            return partial(done, KernelError::BrokenPipe);
        }
        let (n, err) = inner.write_from(from, packet, core::mem::take(&mut first));
        drop(inner);
        done += n;
        if n > 0 {
            // Data for readers (Linux pipe_write)
            pipe.wake_rd();
        }
        if let Some(e) = err {
            return partial(done, e);
        }
        if from.is_empty() {
            return Ok(done);
        }
        if nonblock {
            return partial(done, KernelError::WouldBlock);
        }
        // Block until space or no readers; a signal ends the wait
        pipe.kill_readers();
        if let Err(e) = pipe.wait_queue.wait_event_interruptible(|| pipe.writable()) {
            return partial(done, e);
        }
    }
}

/// File operations for pipe read end (the pipe is the file's private
/// data, like Linux file->private_data = pipe)
pub struct PipeReadFileOps;

static PIPE_READ_FOPS: PipeReadFileOps = PipeReadFileOps;

impl FileOps for PipeReadFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        pipe_ioctl(file, cmd, arg)
    }

    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if at.is_some() {
            return Err(KernelError::OperationNotSupported);
        }
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0 || rw.nowait();
        pipe_read(pipe_of(file)?, to, nonblock)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(pipe) = file.private_ref::<Pipe>() else {
            return POLLERR;
        };
        // Register on wait queue if poll table provided
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&pipe.wait_queue);
        }

        // Lockless, like Linux pipe_poll (epoll polls under a spin lock)
        let mut mask = 0u16;
        if !pipe.ring_empty() {
            mask |= POLLIN | POLLRDNORM;
        }
        // Write end closed: EOF once drained
        if !pipe.has_writers() && mask == 0 {
            mask |= POLLHUP;
        }
        mask
    }

    /// One reader fewer, and one file of the inode's pipe (Linux
    /// pipe_release), as a FIFO's release
    fn release(&self, file: &File) -> Result<(), KernelError> {
        let pipe = pipe_of(file)?;
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        fifo_put(&inode, pipe, flags::O_RDONLY);
        Ok(())
    }

    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        Some(pipe_of(file).and_then(|p| pipe_fasync(p, file, fd, on)))
    }
}

/// File operations for pipe write end
pub struct PipeWriteFileOps;

static PIPE_WRITE_FOPS: PipeWriteFileOps = PipeWriteFileOps;

impl FileOps for PipeWriteFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        pipe_ioctl(file, cmd, arg)
    }

    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if at.is_some() {
            return Err(KernelError::OperationNotSupported);
        }
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0 || rw.nowait();
        // Packet mode: the file's O_DIRECT (Linux is_packetized), in
        // the I/O flags
        let packet = rw.contains(RwFlags::DIRECT);
        pipe_write(pipe_of(file)?, from, nonblock, packet)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(pipe) = file.private_ref::<Pipe>() else {
            return POLLERR;
        };
        // Register on wait queue if poll table provided
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&pipe.wait_queue);
        }

        // Lockless, like Linux pipe_poll
        let mut mask = 0u16;
        if !pipe.ring_full() {
            mask |= POLLOUT | POLLWRNORM;
        }

        // Check if read end closed (EPIPE)
        if !pipe.has_readers() {
            mask |= POLLERR;
        }

        mask
    }

    /// One writer fewer, and one file of the inode's pipe (Linux
    /// pipe_release), as a FIFO's release
    fn release(&self, file: &File) -> Result<(), KernelError> {
        let pipe = pipe_of(file)?;
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        fifo_put(&inode, pipe, flags::O_WRONLY);
        Ok(())
    }

    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        Some(pipe_of(file).and_then(|p| pipe_fasync(p, file, fd, on)))
    }
}

// =============================================================================
// Pipe Creation
// =============================================================================

/// FIONREAD: the bytes buffered, under the pipe's lock (Linux
/// pipe_ioctl); anything else ENOTTY
fn pipe_ioctl(file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
    if cmd != crate::fs::file::FIONREAD {
        return Err(KernelError::NotTty);
    }
    let n = pipe_of(file)?.lock().bytes_available();
    crate::fs::file::put_fionread(arg, n as i64)
}

/// The pipe behind a pipe file or an open FIFO
pub fn pipe_of(file: &File) -> Result<&Pipe, KernelError> {
    file.private_ref::<Pipe>()
        .or_else(|| file.private_ref::<FifoFile>().map(|f| &*f.pipe))
        .ok_or(KernelError::BadFd)
}

// =============================================================================
// FIFOs (Linux fs/pipe.c fifo_open)
// =============================================================================

/// An open FIFO: its inode's pipe, and the write-open count when it was
/// opened (POLLHUP needs a writer to have come and gone since)
pub struct FifoFile {
    pipe: Arc<Pipe>,
    w_version: u32,
}

impl FifoFile {
    /// The FIFO's pipe (splice and tee treat a FIFO as a pipe)
    pub fn pipe(&self) -> Arc<Pipe> {
        self.pipe.clone()
    }
}

/// File operations of a FIFO: read and write per open mode, like the
/// two ends of a pipe
pub struct FifoFileOps;

pub static FIFO_FOPS: FifoFileOps = FifoFileOps;

fn fifo_of(file: &File) -> Result<&FifoFile, KernelError> {
    file.private_ref::<FifoFile>().ok_or(KernelError::BadFd)
}

/// Sleep until `counter` moves from `seen` (Linux wait_for_partner)
fn wait_for_partner(pipe: &Pipe, counter: &AtomicU32, seen: u32) -> Result<(), KernelError> {
    pipe.wait_queue
        .wait_event_interruptible(|| counter.load(Ordering::Acquire) != seen)
}

impl FileOps for FifoFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        pipe_ioctl(file, cmd, arg)
    }

    /// Linux fifo_open: a reader waits for a writer and a writer for a
    /// reader, unless O_NONBLOCK (a nonblocking writer without readers
    /// is ENXIO); O_RDWR never waits. The pipe exists while any file
    /// has the FIFO open; its data goes with the last close.
    fn open(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        let mode = file.get_flags() & flags::O_ACCMODE;
        // A FIFO with no pipe gets one allocated with the slot unlocked,
        // installed if still none (Linux fifo_open: alloc_pipe_info with
        // i_lock dropped, then recheck); a pipe another open installed
        // first wins, and ours is freed after the unlock
        let mut fresh: Option<Arc<Pipe>> = None;
        let pipe = {
            let mut slot = loop {
                let mut slot = inode.i_pipe.lock();
                if slot.is_none() {
                    let Some(p) = fresh.take() else {
                        drop(slot);
                        let p = Pipe::new()?;
                        p.readers.store(0, Ordering::Relaxed);
                        p.writers.store(0, Ordering::Relaxed);
                        fresh = Some(p);
                        continue;
                    };
                    *slot = Some((p, 0));
                }
                break slot;
            };
            let Some((p, files)) = slot.as_mut() else {
                unreachable!("fifo slot filled above");
            };
            // Linux pipe->files, under i_lock
            *files += 1;
            p.clone()
        };
        // Another open's pipe won: ours goes with the lock released
        drop(fresh);
        // The counts and the decisions on them under the pipe's mutex
        // (Linux fifo_open: __pipe_lock): a partner that opens, even and
        // closes, after the unlock moves the counter this waits on, so the
        // wait ends at once
        let (wait, w_version) = {
            let g = pipe.lock();
            if mode == flags::O_WRONLY && nonblock && !pipe.has_readers() {
                drop(g);
                fifo_put_file(&inode);
                return Err(KernelError::NoDeviceOrAddress);
            }
            if mode != flags::O_WRONLY {
                g.count(&pipe.readers, 1);
                g.count(&pipe.r_counter, 1);
            }
            if mode != flags::O_RDONLY {
                g.count(&pipe.writers, 1);
                g.count(&pipe.w_counter, 1);
            }
            let wait = match mode {
                flags::O_RDONLY if !nonblock && !pipe.has_writers() => {
                    Some((true, pipe.w_counter.load(Ordering::Relaxed)))
                }
                flags::O_WRONLY if !pipe.has_readers() => {
                    Some((false, pipe.r_counter.load(Ordering::Relaxed)))
                }
                _ => None,
            };
            // Linux f_version: a nonblocking reader that found no writer
            // gets POLLHUP only after one comes and goes; any other open
            // compares against 0, so POLLHUP shows once writers are gone
            let w_version = if mode == flags::O_RDONLY && nonblock && !pipe.has_writers() {
                pipe.w_counter.load(Ordering::Relaxed)
            } else {
                0
            };
            (wait, w_version)
        };
        pipe.wait_queue.wake_all();
        let waited = match wait {
            Some((true, seen)) => wait_for_partner(&pipe, &pipe.w_counter, seen),
            Some((false, seen)) => wait_for_partner(&pipe, &pipe.r_counter, seen),
            None => Ok(()),
        };
        if let Err(e) = waited {
            // Interrupted: undo this open (release without a file)
            fifo_put(&inode, &pipe, mode);
            return Err(e);
        }
        let f = match try_arc(FifoFile {
            pipe: pipe.clone(),
            w_version,
        }) {
            Ok(f) => f,
            Err(e) => {
                fifo_put(&inode, &pipe, mode);
                return Err(e);
            }
        };
        file.private.call_once(|| f);
        Ok(())
    }

    /// A FIFO has no FMODE_NOWAIT (Linux sets it only on pipe() files),
    /// so RWF_NOWAIT is EOPNOTSUPP (kiocb_set_rw_flags)
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if rw.nowait() || at.is_some() {
            return Err(KernelError::OperationNotSupported);
        }
        if file.get_flags() & flags::O_ACCMODE == flags::O_WRONLY {
            return Err(KernelError::BadFd);
        }
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        pipe_read(&fifo_of(file)?.pipe, to, nonblock)
    }

    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        rw: RwFlags,
    ) -> Result<usize, KernelError> {
        if rw.nowait() || at.is_some() {
            return Err(KernelError::OperationNotSupported);
        }
        if file.get_flags() & flags::O_ACCMODE == flags::O_RDONLY {
            return Err(KernelError::BadFd);
        }
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        let packet = rw.contains(RwFlags::DIRECT);
        pipe_write(&fifo_of(file)?.pipe, from, nonblock, packet)
    }

    fn llseek(&self, _file: &File, _offset: i64, _whence: i32) -> Result<u64, KernelError> {
        Err(KernelError::IllegalSeek)
    }

    /// Linux pipe_poll for a FIFO: POLLHUP only once a writer has come
    /// and gone since this reader opened
    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Ok(f) = fifo_of(file) else {
            return POLLERR;
        };
        let pipe = &f.pipe;
        if let Some(pt) = pt {
            pt.poll_wait(&pipe.wait_queue);
        }
        let mode = file.get_flags() & flags::O_ACCMODE;
        let mut mask = 0u16;
        if mode != flags::O_WRONLY {
            if !pipe.ring_empty() {
                mask |= POLLIN | POLLRDNORM;
            }
            if !pipe.has_writers() && pipe.w_counter.load(Ordering::Acquire) != f.w_version {
                mask |= POLLHUP;
            }
        }
        if mode != flags::O_RDONLY {
            if !pipe.ring_full() {
                mask |= POLLOUT | POLLWRNORM;
            }
            if !pipe.has_readers() {
                mask |= POLLERR;
            }
        }
        mask
    }

    fn release(&self, file: &File) -> Result<(), KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        let f = fifo_of(file)?;
        fifo_put(&inode, &f.pipe, file.get_flags() & flags::O_ACCMODE);
        Ok(())
    }

    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        Some(pipe_of(file).and_then(|p| pipe_fasync(p, file, fd, on)))
    }
}

/// Drop one open of a FIFO in `mode` (Linux pipe_release): its
/// reader/writer counts under the pipe's mutex (waking the other side;
/// if that was the last reader or writer but not both, the O_ASYNC
/// files of both sides learn it), then the inode's pipe with the last
/// file (`fifo_put_file`)
fn fifo_put(inode: &crate::fs::inode::Inode, pipe: &Pipe, mode: u32) {
    {
        let g = pipe.lock();
        if mode != flags::O_WRONLY {
            g.count(&pipe.readers, -1);
        }
        if mode != flags::O_RDONLY {
            g.count(&pipe.writers, -1);
        }
        if pipe.has_readers() != pipe.has_writers() {
            pipe.kill_readers();
            pipe.kill_writers();
        }
    }
    pipe.wait_queue.wake_all();
    fifo_put_file(inode);
}

/// One file of the FIFO less (Linux put_pipe_info, under i_lock): the
/// inode's pipe goes with the last
fn fifo_put_file(inode: &crate::fs::inode::Inode) {
    let mut slot = inode.i_pipe.lock();
    if let Some((_, files)) = slot.as_mut() {
        *files -= 1;
        if *files == 0 {
            *slot = None;
        }
    }
}

/// Create a pipe and return (read_file, write_file)
///
/// The returned files should be added to the process's fd table.
pub fn create_pipe(pipe_flags: u32) -> Result<(FileRef, FileRef), KernelError> {
    let pipe = Pipe::new()?;
    let (mnt, dentry) = create_pipe_path()?.into_parts();
    // The inode holds the pipe while either file is open (Linux
    // inode->i_pipe, pipe->files = 2), so an open of the pipe's path (a
    // /proc fd link, O_EMPTYPATH) joins it as a FIFO open would
    if let Some(i) = dentry.get_inode() {
        *i.i_pipe.lock() = Some((pipe.clone(), 2));
    }

    // Determine file flags
    let read_flags = flags::O_RDONLY | (pipe_flags & flags::O_NONBLOCK);
    // O_DIRECT (packet mode) on the write end only (Linux
    // create_pipe_files)
    let write_flags = flags::O_WRONLY | (pipe_flags & (flags::O_NONBLOCK | flags::O_DIRECT));

    let read_file = File::new_anon(
        dentry.clone(),
        Some(mnt.clone()),
        read_flags,
        &PIPE_READ_FOPS,
        pipe.clone(),
    )
    .alloc()?;
    let write_file =
        File::new_anon(dentry, Some(mnt), write_flags, &PIPE_WRITE_FOPS, pipe).alloc()?;

    Ok((read_file, write_file))
}

/// A new pipefs inode and its path (Linux get_pipe_inode: its own
/// number, the creator's fsuid/fsgid, the current time; then
/// alloc_file_pseudo)
fn create_pipe_path() -> Result<crate::fs::Path, KernelError> {
    use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS};
    use crate::fs::pseudo::PIPEFS;

    let cred = crate::task::percpu::current_cred();
    let inode = Inode::alloc(Inode::new(
        crate::fs::anon_inodes::get_next_ino(),
        InodeMode::fifo(0o600),
        cred.fsuid,
        cred.fsgid,
        0,
        crate::time::TIMEKEEPER.current_time(),
        Some(&PIPEFS.sb()?),
        &NULL_INODE_OPS,
    ))?;
    PIPEFS.path("", inode)
}

// =============================================================================
// FD flags
// =============================================================================

/// File descriptor flag: close on exec
pub const FD_CLOEXEC: u32 = 1;
