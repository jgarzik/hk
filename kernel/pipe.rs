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
//! ## Reference
//!
//! - `./select-poll.md` - Implementation guide
//! - Linux pipe(7) man page
//! - Linux fs/pipe.c

use crate::sync::spin::Mutex;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, RwFlags, flags};
use crate::mm::page_cache::{CachedPage, PAGE_SIZE};
use crate::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::waitqueue::WaitQueue;

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

/// A single buffer slot in a pipe
///
/// Similar to Linux's struct pipe_buffer, this holds a reference to a page
/// along with offset and length information for the valid data region.
pub struct PipeBuffer {
    /// Page holding the buffer data
    /// None if this slot is empty, Some if it contains data
    pub page: Option<Arc<CachedPage>>,
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
    pub fn new(page: Arc<CachedPage>, offset: u32, len: u32, flags: u32) -> Self {
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
            // Only call put() if we own the page (OWNED flag)
            // For splice'd pages, the caller manages the refcount
            if self.flags & pipe_buf_flags::OWNED != 0 {
                page.put();
            }
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
    #[allow(dead_code)]
    fn free_slots(&self) -> usize {
        PIPE_BUFFERS - self.buffer_count()
    }

    /// Bytes available for reading
    #[allow(dead_code)]
    pub fn bytes_available(&self) -> usize {
        self.total_len
    }

    /// Get the tail buffer (for reading)
    #[allow(dead_code)]
    pub fn tail_buf(&self) -> Option<&PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            Some(&self.bufs[self.tail])
        }
    }

    /// Get mutable tail buffer
    #[allow(dead_code)]
    pub fn tail_buf_mut(&mut self) -> Option<&mut PipeBuffer> {
        if self.is_empty() {
            None
        } else {
            Some(&mut self.bufs[self.tail])
        }
    }

    /// Get the head buffer for writing (last used slot, for merging)
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

    /// Write data to the pipe using page-based buffers
    ///
    /// Allocates pages as needed. Returns number of bytes written.
    fn write(&mut self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        let mut written = 0;

        // First, try to merge with existing head buffer
        if let Some(buf) = self.head_buf_for_merge_mut()
            && buf.can_merge()
        {
            let space = buf.space_available();
            let to_write = data.len().min(space);
            if to_write > 0 {
                // Get page frame and write data
                if let Some(ref page) = buf.page {
                    let offset = (buf.offset + buf.len) as usize;
                    let dst_addr = crate::arch::phys_to_virt(page.frame) as usize + offset;
                    unsafe {
                        let dst = dst_addr as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, to_write);
                    }
                    buf.len += to_write as u32;
                    self.total_len += to_write;
                    written += to_write;
                }
            }
        }

        // Write remaining data to new buffers
        while written < data.len() && !self.is_full() {
            // Allocate a new page for this buffer
            let page = match allocate_pipe_page() {
                Some(p) => p,
                None => break, // Out of memory
            };

            let remaining = data.len() - written;
            let to_write = remaining.min(PAGE_SIZE);

            // Copy data to the new page
            unsafe {
                let dst = crate::arch::phys_to_virt(page.frame);
                core::ptr::copy_nonoverlapping(data[written..].as_ptr(), dst, to_write);
            }

            // Create buffer with OWNED and CAN_MERGE flags
            let buf = PipeBuffer::new(
                page,
                0,
                to_write as u32,
                pipe_buf_flags::OWNED | pipe_buf_flags::CAN_MERGE,
            );

            if self.push_buffer(buf).is_err() {
                break;
            }

            written += to_write;
        }

        written
    }

    /// Read data from the pipe
    ///
    /// Returns number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }

        let mut read = 0;

        while read < buf.len() && !self.is_empty() {
            // Get the current tail index
            let tail_idx = self.tail;
            let pipe_buf = &mut self.bufs[tail_idx];

            if pipe_buf.is_empty() {
                // Empty buffer slot, advance and try next
                self.tail = (self.tail + 1) % PIPE_RING;
                continue;
            }

            let available = pipe_buf.len as usize;
            let to_read = (buf.len() - read).min(available);

            // Copy data from page to user buffer
            if let Some(ref page) = pipe_buf.page {
                let src_addr =
                    crate::arch::phys_to_virt(page.frame) as usize + pipe_buf.offset as usize;
                unsafe {
                    let src = src_addr as *const u8;
                    core::ptr::copy_nonoverlapping(src, buf[read..].as_mut_ptr(), to_read);
                }

                pipe_buf.offset += to_read as u32;
                pipe_buf.len -= to_read as u32;
                read += to_read;

                // If buffer is now empty, release it and advance tail
                if pipe_buf.len == 0 {
                    pipe_buf.release();
                    self.tail = (self.tail + 1) % PIPE_RING;
                }
            } else {
                // Shouldn't happen, but handle gracefully
                self.tail = (self.tail + 1) % PIPE_RING;
            }
        }

        // Update total length after all reads
        self.total_len = self.total_len.saturating_sub(read);
        read
    }
}

/// Allocate a page for pipe buffer data
///
/// Creates an anonymous CachedPage for holding pipe data.
fn allocate_pipe_page() -> Option<Arc<CachedPage>> {
    use crate::FRAME_ALLOCATOR;
    use crate::mm::page_cache::FileId;

    // Allocate a physical frame
    let frame = FRAME_ALLOCATOR.alloc()?;

    // Create an anonymous CachedPage (file_id 0, offset 0)
    let page = Arc::new(CachedPage::new(frame, FileId::anonymous(), 0));

    Some(page)
}

/// Shared pipe structure
pub struct Pipe {
    /// Pipe buffer (protected by mutex)
    /// Public for splice module access
    pub inner: Mutex<PipeInner>,
    /// Wait queue for readers/writers
    pub wait_queue: WaitQueue,
    /// Number of read end references
    readers: AtomicU32,
    /// Number of write end references
    writers: AtomicU32,
}

impl Pipe {
    /// Create a new pipe
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PipeInner::new()),
            wait_queue: WaitQueue::new(),
            readers: AtomicU32::new(1),
            writers: AtomicU32::new(1),
        })
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
}

impl Default for Pipe {
    fn default() -> Self {
        Self {
            inner: Mutex::new(PipeInner::new()),
            wait_queue: WaitQueue::new(),
            readers: AtomicU32::new(1),
            writers: AtomicU32::new(1),
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

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let pipe = pipe_of(file)?;
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;

        loop {
            // Try to read
            {
                let mut inner = pipe.inner.lock();
                if !inner.is_empty() {
                    let n = inner.read(buf);
                    // Wake writers - there's now space
                    pipe.wait_queue.wake_all();
                    return Ok(n);
                }
            }

            // Buffer is empty
            if !pipe.has_writers() {
                // EOF - no more writers
                return Ok(0);
            }

            if nonblock {
                return Err(KernelError::WouldBlock);
            }

            // Block until data or EOF; a signal ends the wait (-ERESTARTSYS)
            pipe.wait_queue.wait_event_interruptible(|| {
                !pipe.inner.lock().is_empty() || !pipe.has_writers()
            })?;
        }
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // Cannot write to read end
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
        let Some(pipe) = file.private_ref::<Pipe>() else {
            return POLLERR;
        };
        // Register on wait queue if poll table provided
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&pipe.wait_queue);
        }

        let mut mask = 0u16;
        let inner = pipe.inner.lock();

        // Check if data available
        if !inner.is_empty() {
            mask |= POLLIN | POLLRDNORM;
        }

        // Check if write end closed (EOF)
        if !pipe.has_writers() {
            if inner.is_empty() {
                mask |= POLLHUP;
            } else {
                // Data still available to read
                mask |= POLLIN | POLLRDNORM;
            }
        }

        mask
    }

    fn release(&self, file: &File) -> Result<(), KernelError> {
        let pipe = pipe_of(file)?;
        // Decrement reader count when file is closed
        pipe.remove_reader();
        Ok(())
    }

    fn read_with_flags(
        &self,
        file: &File,
        buf: &mut [u8],
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let pipe = pipe_of(file)?;
        if flags.nowait {
            // Check if data is available without blocking
            let inner = pipe.inner.lock();
            if inner.is_empty() {
                // No data available
                if !pipe.has_writers() {
                    return Ok(0); // EOF - write end closed
                }
                return Err(KernelError::WouldBlock);
            }
            drop(inner); // Release lock before doing the actual read
        }
        self.read(file, buf)
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

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, KernelError> {
        // Cannot read from write end
        Err(KernelError::InvalidArgument)
    }

    /// Linux pipe_write: a blocking writer stays until everything is
    /// written; a signal or O_NONBLOCK ends it early, returning the bytes
    /// written so far if any. Writes of at most PIPE_BUF bytes are never
    /// split (any free slot takes them whole).
    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        let pipe = pipe_of(file)?;
        if buf.is_empty() {
            return Ok(0);
        }

        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;
        let mut done = 0;

        loop {
            // Check for EPIPE (no readers)
            if !pipe.has_readers() {
                // Send SIGPIPE to calling thread
                use crate::signal::{SIGPIPE, send_signal};
                use crate::task::percpu::current_tid;
                let _ = send_signal(current_tid(), SIGPIPE);
                return if done > 0 {
                    Ok(done)
                } else {
                    Err(KernelError::BrokenPipe)
                };
            }

            // Try to write
            {
                let mut inner = pipe.inner.lock();
                if !inner.is_full() {
                    let n = inner.write(&buf[done..]);
                    if n == 0 {
                        // No page for a free slot
                        drop(inner);
                        return if done > 0 {
                            Ok(done)
                        } else {
                            Err(KernelError::OutOfMemory)
                        };
                    }
                    done += n;
                    // Wake readers - there's data available
                    pipe.wait_queue.wake_all();
                }
            }
            if done == buf.len() {
                return Ok(done);
            }

            if nonblock {
                return if done > 0 {
                    Ok(done)
                } else {
                    Err(KernelError::WouldBlock)
                };
            }

            // Block until space or no readers; a signal ends the wait
            let r = pipe
                .wait_queue
                .wait_event_interruptible(|| !pipe.inner.lock().is_full() || !pipe.has_readers());
            match r {
                Err(_) if done > 0 => return Ok(done),
                Err(e) => return Err(e),
                Ok(()) => {}
            }
        }
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable>) -> u16 {
        let Some(pipe) = file.private_ref::<Pipe>() else {
            return POLLERR;
        };
        // Register on wait queue if poll table provided
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&pipe.wait_queue);
        }

        let mut mask = 0u16;
        let inner = pipe.inner.lock();

        // Check if space available
        if !inner.is_full() {
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

    fn write_with_flags(
        &self,
        file: &File,
        buf: &[u8],
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let pipe = pipe_of(file)?;
        if flags.nowait {
            // Check for no readers (EPIPE)
            if !pipe.has_readers() {
                // Send SIGPIPE to calling thread
                use crate::signal::{SIGPIPE, send_signal};
                use crate::task::percpu::current_tid;
                let _ = send_signal(current_tid(), SIGPIPE);
                return Err(KernelError::BrokenPipe);
            }
            // Check if buffer has space without blocking
            let inner = pipe.inner.lock();
            if inner.is_full() {
                return Err(KernelError::WouldBlock);
            }
            drop(inner); // Release lock before doing the actual write
        }
        self.write(file, buf)
    }
}

// =============================================================================
// Pipe Creation
// =============================================================================

use crate::fs::dentry::Dentry;

/// The pipe behind a pipe file
pub fn pipe_of(file: &File) -> Result<&Pipe, KernelError> {
    file.private_ref::<Pipe>().ok_or(KernelError::BadFd)
}

/// Create a pipe and return (read_file, write_file)
///
/// The returned files should be added to the process's fd table.
pub fn create_pipe(pipe_flags: u32) -> Result<(Arc<File>, Arc<File>), KernelError> {
    let pipe = Pipe::new();

    // We need a dummy dentry for pipe files
    // Pipes don't have a filesystem path, but File requires a dentry
    let dummy_dentry = create_pipe_dentry()?;

    // Determine file flags
    let read_flags = flags::O_RDONLY | (pipe_flags & flags::O_NONBLOCK);
    let write_flags = flags::O_WRONLY | (pipe_flags & flags::O_NONBLOCK);

    let read_file = Arc::new(File::new_anon(
        Arc::clone(&dummy_dentry),
        read_flags,
        &PIPE_READ_FOPS,
        pipe.clone(),
    ));
    let write_file = Arc::new(File::new_anon(
        dummy_dentry,
        write_flags,
        &PIPE_WRITE_FOPS,
        pipe,
    ));

    Ok((read_file, write_file))
}

/// Create a dummy dentry for pipes
///
/// Pipes don't have a real filesystem entry, but our File struct
/// requires a dentry. This creates a minimal anonymous dentry.
fn create_pipe_dentry() -> Result<Arc<Dentry>, KernelError> {
    use crate::fs::dentry::Dentry;
    use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec};
    use alloc::string::String;
    use alloc::sync::Weak;

    // Create anonymous inode for pipe
    let mode = InodeMode::fifo(0o600);
    let inode = Arc::new(Inode::new(
        0, // ino=0 for anonymous
        mode,
        0,                      // uid (root)
        0,                      // gid (root)
        0,                      // size
        Timespec::from_secs(0), // mtime
        Weak::new(),            // no superblock for anonymous inode
        &NULL_INODE_OPS,
    ));

    // Create anonymous dentry
    let dentry = Arc::new(Dentry::new_anonymous(String::from("pipe"), Some(inode)));

    Ok(dentry)
}

// =============================================================================
// FD flags
// =============================================================================

/// File descriptor flag: close on exec
pub const FD_CLOEXEC: u32 = 1;
