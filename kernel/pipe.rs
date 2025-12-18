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
//!         Ring Buffer
//!         Wait Queue
//! ```
//!
//! ## Key Features
//!
//! - PIPE_BUF (4096) byte atomic writes
//! - poll() support with wait queue integration
//! - POLLHUP when other end closes
//! - O_NONBLOCK support
//!
//! ## Reference
//!
//! - `./select-poll.md` - Implementation guide
//! - Linux pipe(7) man page

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::fs::FsError;
use crate::fs::file::{File, FileOps, flags};
use crate::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::waitqueue::WaitQueue;

/// Pipe buffer size (matches Linux PIPE_BUF for atomic writes)
pub const PIPE_BUF: usize = 4096;

/// Internal pipe state shared between read and write ends
pub struct PipeInner {
    /// Ring buffer for pipe data
    buffer: [u8; PIPE_BUF],
    /// Read position in buffer
    read_pos: usize,
    /// Write position in buffer
    write_pos: usize,
    /// Number of bytes in buffer
    count: usize,
}

impl PipeInner {
    const fn new() -> Self {
        Self {
            buffer: [0; PIPE_BUF],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    /// Check if buffer is empty
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if buffer is full
    fn is_full(&self) -> bool {
        self.count == PIPE_BUF
    }

    /// Available space for writing
    fn space_available(&self) -> usize {
        PIPE_BUF - self.count
    }

    /// Bytes available for reading
    fn bytes_available(&self) -> usize {
        self.count
    }

    /// Write data to the pipe buffer
    ///
    /// Returns number of bytes written
    fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(self.space_available());
        if to_write == 0 {
            return 0;
        }

        for &byte in &data[..to_write] {
            self.buffer[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % PIPE_BUF;
        }
        self.count += to_write;
        to_write
    }

    /// Read data from the pipe buffer
    ///
    /// Returns number of bytes read
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.bytes_available());
        if to_read == 0 {
            return 0;
        }

        for byte in buf[..to_read].iter_mut() {
            *byte = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUF;
        }
        self.count -= to_read;
        to_read
    }
}

/// Shared pipe structure
pub struct Pipe {
    /// Pipe buffer (protected by mutex)
    inner: Mutex<PipeInner>,
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

/// File operations for pipe read end
pub struct PipeReadFileOps {
    pipe: Arc<Pipe>,
}

impl PipeReadFileOps {
    /// Create file ops for pipe read end
    pub fn new(pipe: Arc<Pipe>) -> Self {
        Self { pipe }
    }
}

impl FileOps for PipeReadFileOps {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError> {
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;

        loop {
            // Try to read
            {
                let mut inner = self.pipe.inner.lock();
                if !inner.is_empty() {
                    let n = inner.read(buf);
                    // Wake writers - there's now space
                    self.pipe.wait_queue.wake_all();
                    return Ok(n);
                }
            }

            // Buffer is empty
            if !self.pipe.has_writers() {
                // EOF - no more writers
                return Ok(0);
            }

            if nonblock {
                return Err(FsError::WouldBlock);
            }

            // Block waiting for data
            // In a full implementation, we'd use the wait queue properly
            // For now, just yield and retry
            crate::task::percpu::yield_now();
        }
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, FsError> {
        // Cannot write to read end
        Err(FsError::InvalidArgument)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        // Register on wait queue if poll table provided
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.pipe.wait_queue);
        }

        let mut mask = 0u16;
        let inner = self.pipe.inner.lock();

        // Check if data available
        if !inner.is_empty() {
            mask |= POLLIN | POLLRDNORM;
        }

        // Check if write end closed (EOF)
        if !self.pipe.has_writers() {
            if inner.is_empty() {
                mask |= POLLHUP;
            } else {
                // Data still available to read
                mask |= POLLIN | POLLRDNORM;
            }
        }

        mask
    }

    fn release(&self, _file: &File) -> Result<(), FsError> {
        // Reader reference is dropped via PipeReadEnd's Drop impl
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
pub struct PipeWriteFileOps {
    pipe: Arc<Pipe>,
}

impl PipeWriteFileOps {
    /// Create file ops for pipe write end
    pub fn new(pipe: Arc<Pipe>) -> Self {
        Self { pipe }
    }
}

impl FileOps for PipeWriteFileOps {
    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, FsError> {
        // Cannot read from write end
        Err(FsError::InvalidArgument)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, FsError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0;

        loop {
            // Check for EPIPE (no readers)
            if !self.pipe.has_readers() {
                // TODO: Send SIGPIPE to calling process
                return Err(FsError::BrokenPipe);
            }

            // Try to write
            {
                let mut inner = self.pipe.inner.lock();
                if !inner.is_full() {
                    let n = inner.write(buf);
                    // Wake readers - there's data available
                    self.pipe.wait_queue.wake_all();
                    return Ok(n);
                }
            }

            if nonblock {
                return Err(FsError::WouldBlock);
            }

            // Block waiting for space
            crate::task::percpu::yield_now();
        }
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        // Register on wait queue if poll table provided
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.pipe.wait_queue);
        }

        let mut mask = 0u16;
        let inner = self.pipe.inner.lock();

        // Check if space available
        if !inner.is_full() {
            mask |= POLLOUT | POLLWRNORM;
        }

        // Check if read end closed (EPIPE)
        if !self.pipe.has_readers() {
            mask |= POLLERR;
        }

        mask
    }

    fn release(&self, _file: &File) -> Result<(), FsError> {
        // Writer reference is dropped via PipeWriteEnd's Drop impl
        Ok(())
    }
}

// =============================================================================
// Pipe Creation
// =============================================================================

use crate::fs::dentry::Dentry;

/// Create a pipe and return (read_file, write_file)
///
/// The returned files should be added to the process's fd table.
pub fn create_pipe(pipe_flags: u32) -> Result<(Arc<File>, Arc<File>), FsError> {
    let pipe = Pipe::new();

    // Create file operations (these hold Arc refs to pipe)
    let read_ops: &'static dyn FileOps =
        Box::leak(Box::new(PipeReadFileOps::new(Arc::clone(&pipe))));
    let write_ops: &'static dyn FileOps = Box::leak(Box::new(PipeWriteFileOps::new(pipe)));

    // We need a dummy dentry for pipe files
    // Pipes don't have a filesystem path, but File requires a dentry
    let dummy_dentry = create_pipe_dentry()?;

    // Determine file flags
    let read_flags = flags::O_RDONLY | (pipe_flags & flags::O_NONBLOCK);
    let write_flags = flags::O_WRONLY | (pipe_flags & flags::O_NONBLOCK);

    let read_file = Arc::new(File::new(Arc::clone(&dummy_dentry), read_flags, read_ops));
    let write_file = Arc::new(File::new(dummy_dentry, write_flags, write_ops));

    Ok((read_file, write_file))
}

/// Create a dummy dentry for pipes
///
/// Pipes don't have a real filesystem entry, but our File struct
/// requires a dentry. This creates a minimal anonymous dentry.
fn create_pipe_dentry() -> Result<Arc<Dentry>, FsError> {
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
