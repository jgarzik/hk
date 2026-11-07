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
//! PipeWriteEnd             PipeReadEnd
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
//! pipe_writable they read the ring indices `Pipe.head`/`Pipe.tail`,
//! which the guard publishes as it unlocks. Wakeups follow the unlock.
//! splice/tee lock two pipes in address order (Linux pipe_double_lock).
//!
//! ## Reference
//!
//! - `./select-poll.md` - Implementation guide
//! - Linux pipe(7) man page
//! - Linux fs/pipe.c

use crate::sync::{Mutex, MutexGuard};
use crate::util::kalloc::try_arc;
use alloc::sync::Arc;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, RwFlags, flags};
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::io::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::mm::filemap::PAGE_SIZE;
use crate::sync::waitqueue::WaitQueue;

/// Pipe buffer size (matches Linux PIPE_BUF for atomic writes)
pub const PIPE_BUF: usize = 4096;

/// Number of buffer slots in a pipe (like Linux's PIPE_DEF_BUFFERS)
pub const PIPE_BUFFERS: usize = 16;

/// Ring slots: one more than the capacity, so a full ring (head one
/// behind tail) is distinguishable from an empty one (head == tail)
pub const PIPE_RING: usize = PIPE_BUFFERS + 1;

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
    /// Ring of buffer slots (like Linux's struct pipe_inode_info.bufs)
    pub bufs: [PipeBuffer; PIPE_RING],
    /// Head index - producer writes here (mod PIPE_RING)
    pub head: usize,
    /// Tail index - consumer reads from here (mod PIPE_RING)
    pub tail: usize,
    /// Total bytes in all buffers
    pub total_len: usize,
}

impl PipeInner {
    /// Create a new empty pipe inner
    fn new() -> Self {
        // Initialize all buffer slots as empty
        const EMPTY_BUF: PipeBuffer = PipeBuffer::empty();
        Self {
            bufs: [EMPTY_BUF; PIPE_RING],
            head: 0,
            tail: 0,
            total_len: 0,
        }
    }

    /// Check if pipe is empty
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Check if pipe is full (all buffer slots used)
    pub fn is_full(&self) -> bool {
        self.buffer_count() >= PIPE_BUFFERS
    }

    /// Number of used buffer slots
    pub fn buffer_count(&self) -> usize {
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            PIPE_RING - self.tail + self.head
        }
    }

    /// Number of free buffer slots
    #[expect(dead_code)]
    fn free_slots(&self) -> usize {
        PIPE_BUFFERS - self.buffer_count()
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
            Some(&self.bufs[self.tail])
        }
    }

    /// Get mutable tail buffer
    pub fn tail_buf_mut(&mut self) -> Option<&mut PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            Some(&mut self.bufs[self.tail])
        }
    }

    /// Get the head buffer for writing (last used slot, for merging)
    pub fn head_buf_for_merge(&self) -> Option<&PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            // Head points to next free slot, so previous slot is (head - 1)
            let prev = if self.head == 0 {
                PIPE_RING - 1
            } else {
                self.head - 1
            };
            Some(&self.bufs[prev])
        }
    }

    /// Get mutable head buffer for merging
    fn head_buf_for_merge_mut(&mut self) -> Option<&mut PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            let prev = if self.head == 0 {
                PIPE_RING - 1
            } else {
                self.head - 1
            };
            Some(&mut self.bufs[prev])
        }
    }

    /// Advance tail after consuming a buffer
    pub fn advance_tail(&mut self, bytes: usize) {
        self.total_len = self.total_len.saturating_sub(bytes);
        self.tail = (self.tail + 1) % PIPE_RING;
    }

    /// Add a buffer at head position
    pub fn push_buffer(&mut self, buf: PipeBuffer) -> Result<(), PipeBuffer> {
        if self.is_full() {
            return Err(buf);
        }
        let bytes = buf.len as usize;
        self.bufs[self.head] = buf;
        self.head = (self.head + 1) % PIPE_RING;
        self.total_len += bytes;
        Ok(())
    }

    /// Append from `from` (Linux pipe_write's copy_page_from_iter):
    /// into the head buffer while it may merge, then into new pages
    /// while slots are free. Returns the bytes taken and the error that
    /// stopped it early (EFAULT, ENOMEM), if any.
    fn write_from(&mut self, from: &mut IovSource<'_>) -> (usize, Option<KernelError>) {
        let written = match self.merge_from(from) {
            Ok(c) => c,
            Err(e) => return (0, Some(e)),
        };
        self.total_len += written;
        if !from.is_empty() && self.head_buf_for_merge().is_some_and(|b| b.can_merge()) {
            // The merge copy stopped short: a fault
            return (written, Some(KernelError::BadAddress));
        }
        let mut written = written;
        while !from.is_empty() && !self.is_full() {
            let Some(page) = allocate_pipe_page() else {
                return (written, Some(KernelError::OutOfMemory));
            };
            let n = from.len().min(PAGE_SIZE);
            // SAFETY: a page just allocated for this buffer, under Pipe.inner
            let r = from.copy_from(unsafe { &mut page.bytes()[..n] });
            let c = match r {
                Ok(c) if c > 0 => c,
                Ok(_) | Err(_) => return (written, Some(KernelError::BadAddress)),
            };
            let flags = pipe_buf_flags::OWNED | pipe_buf_flags::CAN_MERGE;
            if self
                .push_buffer(PipeBuffer::new(page, 0, c as u32, flags))
                .is_err()
            {
                break;
            }
            written += c;
            if c < n {
                return (written, Some(KernelError::BadAddress));
            }
        }
        (written, None)
    }

    /// Append to the head buffer while it may merge (it is unshared):
    /// the bytes copied
    fn merge_from(&mut self, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
        let Some(buf) = self.head_buf_for_merge_mut().filter(|b| b.can_merge()) else {
            return Ok(0);
        };
        let Some(page) = buf.page.as_ref() else {
            return Ok(0);
        };
        let off = (buf.offset + buf.len) as usize;
        let n = from.len().min(PAGE_SIZE - off);
        // SAFETY: under Pipe.inner, an unshared CAN_MERGE page
        let c = from.copy_from(unsafe { &mut page.bytes()[off..off + n] })?;
        buf.len += c as u32;
        Ok(c)
    }

    /// Consume into `to` from the tail on (Linux pipe_read's
    /// copy_page_to_iter): the bytes copied, EFAULT if a fault stopped
    /// it before the first
    fn read_to(&mut self, to: &mut IovDest<'_>) -> Result<usize, KernelError> {
        let mut read = 0;
        while !to.is_empty() && !self.is_empty() {
            let tail = self.tail;
            let buf = &mut self.bufs[tail];
            let Some(page) = buf.page.as_ref().filter(|_| buf.len > 0) else {
                // An empty slot: skip it
                self.tail = (tail + 1) % PIPE_RING;
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
            if buf.len == 0 {
                buf.release();
                self.tail = (tail + 1) % PIPE_RING;
            }
        }
        self.total_len = self.total_len.saturating_sub(read);
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
    /// `inner.head` and `inner.tail` as of the last unlock, for lockless
    /// readers (Linux READ_ONCE(pipe->head/tail))
    head: AtomicUsize,
    tail: AtomicUsize,
    /// Wait queue for readers/writers
    pub wait_queue: WaitQueue,
    /// Number of read end references
    readers: AtomicU32,
    /// Opens of a FIFO for reading and writing so far (Linux
    /// r_counter/w_counter): an opener waiting for its partner wakes
    /// when the other count moves
    r_counter: AtomicU32,
    w_counter: AtomicU32,
    /// Number of write end references
    writers: AtomicU32,
}

impl Pipe {
    /// Create a new pipe
    pub fn new() -> Result<Arc<Self>, KernelError> {
        try_arc(Self::default())
    }

    /// Lock the buffer (Linux pipe_lock); may sleep. Wake waiters only
    /// after dropping the guard: it publishes the ring indices then.
    pub fn lock(&self) -> PipeGuard<'_> {
        PipeGuard {
            pipe: self,
            g: self.inner.lock(),
        }
    }

    /// Used slots, without the lock (a snapshot)
    fn occupancy(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        (head + PIPE_RING - tail) % PIPE_RING
    }

    /// No buffered data, without the lock
    pub fn ring_empty(&self) -> bool {
        self.occupancy() == 0
    }

    /// Every slot used, without the lock
    pub fn ring_full(&self) -> bool {
        self.occupancy() >= PIPE_BUFFERS
    }

    /// A reader need not wait (Linux pipe_readable): data or no writer
    fn readable(&self) -> bool {
        !self.ring_empty() || !self.has_writers()
    }

    /// A writer need not wait (Linux pipe_writable): room or no reader
    fn writable(&self) -> bool {
        !self.ring_full() || !self.has_readers()
    }

    /// Check if there are any readers
    pub fn has_readers(&self) -> bool {
        self.readers.load(Ordering::Acquire) > 0
    }

    /// Check if there are any writers
    pub fn has_writers(&self) -> bool {
        self.writers.load(Ordering::Acquire) > 0
    }

    /// Increment reader count
    pub fn add_reader(&self) {
        self.readers.fetch_add(1, Ordering::AcqRel);
    }

    /// Decrement reader count
    pub fn remove_reader(&self) {
        let prev = self.readers.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // Last reader closed - wake writers so they can see POLLHUP/EPIPE
            self.wait_queue.wake_all();
        }
    }

    /// Increment writer count
    pub fn add_writer(&self) {
        self.writers.fetch_add(1, Ordering::AcqRel);
    }

    /// Decrement writer count
    pub fn remove_writer(&self) {
        let prev = self.writers.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // Last writer closed - wake readers so they can see EOF
            self.wait_queue.wake_all();
        }
    }

    /// Data for readers (Linux wakeup_pipe_readers: rd_wait with
    /// EPOLLIN | EPOLLRDNORM)
    pub fn wake_readers(&self) {
        self.wait_queue.wake_poll(u32::from(POLLIN | POLLRDNORM));
    }

    /// Room for writers (Linux wakeup_pipe_writers: wr_wait with
    /// EPOLLOUT | EPOLLWRNORM)
    pub fn wake_writers(&self) {
        self.wait_queue.wake_poll(u32::from(POLLOUT | POLLWRNORM));
    }
}

impl Default for Pipe {
    fn default() -> Self {
        Self {
            inner: Mutex::new(PipeInner::new()),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            wait_queue: WaitQueue::new(),
            readers: AtomicU32::new(1),
            writers: AtomicU32::new(1),
            r_counter: AtomicU32::new(0),
            w_counter: AtomicU32::new(0),
        }
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

impl Drop for PipeGuard<'_> {
    /// Publish the ring indices for lockless readers, then unlock (the
    /// mutex guard field drops after this)
    fn drop(&mut self) {
        self.pipe.head.store(self.g.head, Ordering::Release);
        self.pipe.tail.store(self.g.tail, Ordering::Release);
    }
}

/// Linux pipe_read: wait for data unless `nonblock`; a read takes what
/// is there (at most `to`'s room) and returns, 0 at EOF (no writers).
/// The copy runs under the sleeping `Pipe.inner` (it may fault).
fn pipe_read(pipe: &Pipe, to: &mut IovDest<'_>, nonblock: bool) -> Result<usize, KernelError> {
    if to.is_empty() {
        return Ok(0);
    }
    loop {
        let mut inner = pipe.lock();
        if !inner.is_empty() {
            let r = inner.read_to(to);
            drop(inner);
            // Room for writers (Linux pipe_read)
            pipe.wake_writers();
            return r;
        }
        drop(inner);
        if !pipe.has_writers() {
            return Ok(0);
        }
        if nonblock {
            return Err(KernelError::WouldBlock);
        }
        // Block until data or EOF; a signal ends the wait (-ERESTARTSYS)
        pipe.wait_queue
            .wait_event_interruptible(|| pipe.readable())?;
    }
}

/// EPIPE's SIGPIPE to the writing thread
fn sigpipe() {
    use crate::signal::{SIGPIPE, send_signal};
    let _ = send_signal(crate::task::percpu::current_tid(), SIGPIPE);
}

/// Linux pipe_write: a blocking writer stays until everything is
/// written; a signal, `nonblock`, a fault or no memory ends it early,
/// returning the bytes written so far if any. Writes of at most PIPE_BUF
/// bytes are never split (any free slot takes them whole). No reader:
/// SIGPIPE and EPIPE. The copy runs under the sleeping `Pipe.inner`.
fn pipe_write(pipe: &Pipe, from: &mut IovSource<'_>, nonblock: bool) -> Result<usize, KernelError> {
    if from.is_empty() {
        return Ok(0);
    }
    let partial = |done: usize, e| if done > 0 { Ok(done) } else { Err(e) };
    let mut done = 0;
    loop {
        if !pipe.has_readers() {
            sigpipe();
            return partial(done, KernelError::BrokenPipe);
        }
        let mut inner = pipe.lock();
        if !inner.is_full() {
            let (n, err) = inner.write_from(from);
            drop(inner);
            done += n;
            if n > 0 {
                // Data for readers (Linux pipe_write)
                pipe.wake_readers();
            }
            if let Some(e) = err {
                return partial(done, e);
            }
        } else {
            drop(inner);
        }
        if from.is_empty() {
            return Ok(done);
        }
        if nonblock {
            return partial(done, KernelError::WouldBlock);
        }
        // Block until space or no readers; a signal ends the wait
        if let Err(e) = pipe.wait_queue.wait_event_interruptible(|| pipe.writable()) {
            return partial(done, e);
        }
    }
}

// =============================================================================
// Pipe Read End
// =============================================================================

/// Read end of a pipe
pub struct PipeReadEnd {
    pipe: Arc<Pipe>,
}

impl PipeReadEnd {
    /// Create a new read end for a pipe
    pub fn new(pipe: Arc<Pipe>) -> Self {
        Self { pipe }
    }
}

impl Clone for PipeReadEnd {
    fn clone(&self) -> Self {
        self.pipe.add_reader();
        Self {
            pipe: Arc::clone(&self.pipe),
        }
    }
}

impl Drop for PipeReadEnd {
    fn drop(&mut self) {
        self.pipe.remove_reader();
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
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0 || rw.nowait;
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

    fn release(&self, file: &File) -> Result<(), KernelError> {
        let pipe = pipe_of(file)?;
        // Decrement reader count when file is closed
        pipe.remove_reader();
        Ok(())
    }
}

// =============================================================================
// Pipe Write End
// =============================================================================

/// Write end of a pipe
pub struct PipeWriteEnd {
    pipe: Arc<Pipe>,
}

impl PipeWriteEnd {
    /// Create a new write end for a pipe
    pub fn new(pipe: Arc<Pipe>) -> Self {
        Self { pipe }
    }
}

impl Clone for PipeWriteEnd {
    fn clone(&self) -> Self {
        self.pipe.add_writer();
        Self {
            pipe: Arc::clone(&self.pipe),
        }
    }
}

impl Drop for PipeWriteEnd {
    fn drop(&mut self) {
        self.pipe.remove_writer();
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
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0 || rw.nowait;
        pipe_write(pipe_of(file)?, from, nonblock)
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

    fn release(&self, file: &File) -> Result<(), KernelError> {
        let pipe = pipe_of(file)?;
        // Decrement writer count when file is closed
        pipe.remove_writer();
        Ok(())
    }
}

// =============================================================================
// Pipe Creation
// =============================================================================

use crate::fs::dentry::Dentry;

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
        let pipe = {
            let mut slot = inode.i_pipe.lock();
            let (p, files) = match slot.take() {
                Some(s) => slot.insert(s),
                None => {
                    let p = Pipe::new()?;
                    p.readers.store(0, Ordering::Relaxed);
                    p.writers.store(0, Ordering::Relaxed);
                    slot.insert((p, 0))
                }
            };
            if mode == flags::O_WRONLY && nonblock && !p.has_readers() {
                if *files == 0 {
                    *slot = None;
                }
                return Err(KernelError::NoDeviceOrAddress);
            }
            *files += 1;
            match mode {
                flags::O_RDONLY => {
                    p.readers.fetch_add(1, Ordering::AcqRel);
                    p.r_counter.fetch_add(1, Ordering::AcqRel);
                }
                flags::O_WRONLY => {
                    p.writers.fetch_add(1, Ordering::AcqRel);
                    p.w_counter.fetch_add(1, Ordering::AcqRel);
                }
                _ => {
                    p.readers.fetch_add(1, Ordering::AcqRel);
                    p.writers.fetch_add(1, Ordering::AcqRel);
                    p.r_counter.fetch_add(1, Ordering::AcqRel);
                    p.w_counter.fetch_add(1, Ordering::AcqRel);
                }
            }
            // Decided under the slot lock, as every open changes the
            // counters under it (Linux holds pipe->mutex until it sleeps):
            // a partner that opens, even and closes, after the unlock moves
            // the counter this waits on, so the wait ends at once
            let wait = match mode {
                flags::O_RDONLY if !nonblock && !p.has_writers() => {
                    Some((true, p.w_counter.load(Ordering::Acquire)))
                }
                flags::O_WRONLY if !p.has_readers() => {
                    Some((false, p.r_counter.load(Ordering::Acquire)))
                }
                _ => None,
            };
            // Linux f_version: a nonblocking reader that found no writer
            // gets POLLHUP only after one comes and goes; any other open
            // compares against 0, so POLLHUP shows once writers are gone
            let w_version = if mode == flags::O_RDONLY && nonblock && !p.has_writers() {
                p.w_counter.load(Ordering::Acquire)
            } else {
                0
            };
            (p.clone(), wait, w_version)
        };
        let (pipe, wait, w_version) = pipe;
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
        if rw.nowait || at.is_some() {
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
        if rw.nowait || at.is_some() {
            return Err(KernelError::OperationNotSupported);
        }
        if file.get_flags() & flags::O_ACCMODE == flags::O_RDONLY {
            return Err(KernelError::BadFd);
        }
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        pipe_write(&fifo_of(file)?.pipe, from, nonblock)
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
}

/// Drop one open of a FIFO in `mode`: its reader/writer counts (waking
/// the other side), and the inode's pipe with the last file; all under
/// the slot lock, like the open side
fn fifo_put(inode: &crate::fs::inode::Inode, pipe: &Pipe, mode: u32) {
    let mut slot = inode.i_pipe.lock();
    if mode != flags::O_WRONLY {
        pipe.remove_reader();
    }
    if mode != flags::O_RDONLY {
        pipe.remove_writer();
    }
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
pub fn create_pipe(pipe_flags: u32) -> Result<(Arc<File>, Arc<File>), KernelError> {
    let pipe = Pipe::new()?;

    // We need a dummy dentry for pipe files
    // Pipes don't have a filesystem path, but File requires a dentry
    let dummy_dentry = create_pipe_dentry()?;

    // Determine file flags
    let read_flags = flags::O_RDONLY | (pipe_flags & flags::O_NONBLOCK);
    let write_flags = flags::O_WRONLY | (pipe_flags & flags::O_NONBLOCK);

    let read_file = try_arc(File::new_anon(
        Arc::clone(&dummy_dentry),
        read_flags,
        &PIPE_READ_FOPS,
        pipe.clone(),
    ))?;
    let write_file = try_arc(File::new_anon(
        dummy_dentry,
        write_flags,
        &PIPE_WRITE_FOPS,
        pipe,
    ))?;

    Ok((read_file, write_file))
}

/// Create a dummy dentry for pipes
///
/// Pipes don't have a real filesystem entry, but our File struct
/// requires a dentry. This creates a minimal anonymous dentry.
fn create_pipe_dentry() -> Result<Arc<Dentry>, KernelError> {
    use crate::fs::dentry::Dentry;
    use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS};
    use alloc::sync::Weak;

    // A pipefs inode (Linux get_pipe_inode): its own number, the
    // creator's fsuid/fsgid, the current time
    let cred = crate::task::percpu::current_cred();
    let inode = try_arc(Inode::new(
        crate::fs::anon_inodes::get_next_ino(),
        InodeMode::fifo(0o600),
        cred.fsuid,
        cred.fsgid,
        0,
        crate::time::TIMEKEEPER.current_time(),
        Weak::new(),
        &NULL_INODE_OPS,
    ))?;

    // Create anonymous dentry
    let dentry = try_arc(Dentry::new_anonymous("pipe".into(), Some(inode)))?;

    Ok(dentry)
}

// =============================================================================
// FD flags
// =============================================================================

/// File descriptor flag: close on exec
pub const FD_CLOEXEC: u32 = 1;
