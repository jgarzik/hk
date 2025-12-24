//! Splice, Tee, Sendfile, and Vmsplice syscall implementations
//!
//! This module implements zero-copy data transfer syscalls following Linux semantics.
//!
//! ## Overview
//!
//! - **splice**: Move data between pipe and file/socket without copying through userspace
//! - **tee**: Duplicate data from one pipe to another without consuming source
//! - **sendfile**: Send file data to socket/file (zero-copy when possible)
//! - **vmsplice**: Map user memory into pipe
//!
//! ## Zero-Copy Architecture
//!
//! These syscalls work by manipulating page references rather than copying data:
//!
//! 1. File-to-pipe: Get page from page cache, increment refcount, insert into pipe
//! 2. Pipe-to-file: Extract page from pipe, write to file's page cache
//! 3. Pipe-to-pipe (tee): Increment page refcount, share between pipes
//! 4. User-to-pipe (vmsplice): Copy user data into pipe pages
//!
//! ## References
//!
//! - Linux fs/splice.c
//! - Linux include/linux/pipe_fs_i.h
//! - Linux include/linux/splice.h

use alloc::sync::Arc;

use crate::fs::FsError;
use crate::fs::file::File;
use crate::mm::page_cache::{CachedPage, PAGE_SIZE};
use crate::net::socket_file::SocketFileOps;
use crate::net::tcp;
use crate::pipe::{
    PIPE_BUFFERS, Pipe, PipeBuffer, PipeReadFileOps, PipeWriteFileOps, pipe_buf_flags,
};
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;

// =============================================================================
// Splice flags (from include/linux/splice.h)
// =============================================================================

/// Move pages instead of copying (hint, may not always be honored)
#[allow(dead_code)]
pub const SPLICE_F_MOVE: u32 = 0x01;

/// Don't block on I/O
pub const SPLICE_F_NONBLOCK: u32 = 0x02;

/// Hint that more data is coming (for TCP_CORK)
#[allow(dead_code)]
pub const SPLICE_F_MORE: u32 = 0x04;

/// Pages passed in are a gift (for vmsplice)
#[allow(dead_code)]
pub const SPLICE_F_GIFT: u32 = 0x08;

// =============================================================================
// Error codes
// =============================================================================

/// EBADF - Bad file descriptor
const EBADF: i64 = -9;
/// EINVAL - Invalid argument
const EINVAL: i64 = -22;
/// ESPIPE - Illegal seek
const ESPIPE: i64 = -29;
/// EAGAIN - Resource temporarily unavailable
const EAGAIN: i64 = -11;

// =============================================================================
// Splice helper types
// =============================================================================

/// Direction of splice operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceDirection {
    /// From file/socket to pipe
    ToPipe,
    /// From pipe to file/socket
    FromPipe,
}

// =============================================================================
// Splice operations on pipe
// =============================================================================

/// Insert a page reference into a pipe (for splice file->pipe)
///
/// This is the core zero-copy operation: we take a page from the source
/// (page cache) and insert a reference to it into the pipe without copying.
///
/// # Arguments
/// * `pipe` - Target pipe to insert into
/// * `page` - Page to insert (refcount already incremented by caller)
/// * `offset` - Offset within page where data starts
/// * `len` - Length of valid data
///
/// # Returns
/// Number of bytes inserted, or error
pub fn splice_to_pipe(
    pipe: &Pipe,
    page: Arc<CachedPage>,
    offset: u32,
    len: u32,
) -> Result<usize, FsError> {
    let mut inner = pipe.inner.lock();

    if inner.is_full() {
        return Err(FsError::WouldBlock);
    }

    // Create a pipe buffer for the page
    // Don't set OWNED flag - the page belongs to page cache, not pipe
    let buf = PipeBuffer::new(page, offset, len, 0);

    match inner.push_buffer(buf) {
        Ok(()) => {
            // Wake readers - there's data
            drop(inner);
            pipe.wait_queue.wake_all();
            Ok(len as usize)
        }
        Err(_) => Err(FsError::WouldBlock),
    }
}

/// Extract a page reference from a pipe (for splice pipe->file)
///
/// Returns the next page buffer from the pipe without copying.
///
/// # Arguments
/// * `pipe` - Source pipe to extract from
///
/// # Returns
/// The pipe buffer containing page reference, or None if pipe is empty
pub fn splice_from_pipe(pipe: &Pipe) -> Option<(Arc<CachedPage>, u32, u32)> {
    let mut inner = pipe.inner.lock();

    if inner.is_empty() {
        return None;
    }

    // Get the tail buffer
    let tail_idx = inner.tail;
    let pipe_buf = &mut inner.bufs[tail_idx];

    if pipe_buf.is_empty() {
        inner.tail = (inner.tail + 1) % PIPE_BUFFERS;
        return None;
    }

    // Extract page reference
    let page = pipe_buf.page.clone()?;
    let offset = pipe_buf.offset;
    let len = pipe_buf.len;

    // Consume the buffer
    pipe_buf.release();
    inner.tail = (inner.tail + 1) % PIPE_BUFFERS;
    inner.total_len = inner.total_len.saturating_sub(len as usize);

    // Wake writers - there's now space
    drop(inner);
    pipe.wait_queue.wake_all();

    Some((page, offset, len))
}

/// Link pipe buffers for tee() operation
///
/// Duplicates data from source pipe to destination pipe without consuming
/// the source. This is done by incrementing page refcounts.
///
/// # Arguments
/// * `src` - Source pipe
/// * `dst` - Destination pipe
/// * `len` - Maximum bytes to tee
/// * `_flags` - Splice flags
///
/// # Returns
/// Number of bytes tee'd
pub fn link_pipe(src: &Pipe, dst: &Pipe, len: usize, _flags: u32) -> Result<usize, FsError> {
    // Lock both pipes in consistent order to prevent deadlock
    // Use pointer addresses to determine order
    let src_addr = src as *const Pipe as usize;
    let dst_addr = dst as *const Pipe as usize;

    if src_addr == dst_addr {
        return Err(FsError::InvalidArgument);
    }

    // Lock in address order
    let (src_guard, mut dst_guard) = if src_addr < dst_addr {
        let s = src.inner.lock();
        let d = dst.inner.lock();
        (s, d)
    } else {
        let d = dst.inner.lock();
        let s = src.inner.lock();
        (s, d)
    };

    if src_guard.is_empty() {
        return Ok(0);
    }

    if dst_guard.is_full() {
        return Err(FsError::WouldBlock);
    }

    let mut copied = 0;
    let mut src_idx = src_guard.tail;

    // Iterate through source buffers
    while copied < len && src_idx != src_guard.head && !dst_guard.is_full() {
        let src_buf = &src_guard.bufs[src_idx];

        if let Some(ref page) = src_buf.page {
            let to_copy = (len - copied).min(src_buf.len as usize);

            if to_copy > 0 {
                // Increment page refcount
                page.get();

                // Create new buffer pointing to same page
                // Clear GIFT and CAN_MERGE flags
                let new_buf = PipeBuffer::new(
                    Arc::clone(page),
                    src_buf.offset,
                    to_copy as u32,
                    src_buf.flags & !(pipe_buf_flags::GIFT | pipe_buf_flags::CAN_MERGE),
                );

                if dst_guard.push_buffer(new_buf).is_err() {
                    // Undo the refcount increment
                    page.put();
                    break;
                }

                copied += to_copy;
            }
        }

        src_idx = (src_idx + 1) % PIPE_BUFFERS;
    }

    // Wake readers on destination
    drop(src_guard);
    drop(dst_guard);
    dst.wait_queue.wake_all();

    Ok(copied)
}

// =============================================================================
// Access to pipe internals (needed by splice module)
// =============================================================================

impl Pipe {
    /// Get a reference to the inner pipe data
    #[allow(dead_code)]
    pub fn inner(&self) -> &spin::Mutex<crate::pipe::PipeInner> {
        &self.inner
    }
}

// =============================================================================
// Pipe extraction from FileOps
// =============================================================================

impl PipeReadFileOps {
    /// Get the underlying pipe for splice operations
    pub fn get_pipe(&self) -> &Arc<Pipe> {
        // Access the pipe field - we need to make it accessible
        // This requires the pipe field to be public or have a getter
        &self.pipe
    }
}

impl PipeWriteFileOps {
    /// Get the underlying pipe for splice operations
    pub fn get_pipe(&self) -> &Arc<Pipe> {
        &self.pipe
    }
}

// =============================================================================
// Helper: Extract pipe from file if it's a pipe
// =============================================================================

/// Try to get a Pipe from a file descriptor
fn get_pipe_from_fd(fd: i32) -> Option<Arc<Pipe>> {
    let tid = current_tid();
    let fd_table = get_task_fd(tid)?;
    let file = fd_table.lock().get(fd)?;

    // Try pipe read end
    if let Some(pipe_ops) = file.f_op.as_any().downcast_ref::<PipeReadFileOps>() {
        return Some(Arc::clone(pipe_ops.get_pipe()));
    }

    // Try pipe write end
    if let Some(pipe_ops) = file.f_op.as_any().downcast_ref::<PipeWriteFileOps>() {
        return Some(Arc::clone(pipe_ops.get_pipe()));
    }

    None
}

/// Check if fd is a pipe (either read or write end)
fn is_pipe_fd(fd: i32) -> bool {
    get_pipe_from_fd(fd).is_some()
}

/// Get file from fd
fn get_file_from_fd(fd: i32) -> Option<Arc<File>> {
    let tid = current_tid();
    let fd_table = get_task_fd(tid)?;
    fd_table.lock().get(fd)
}

// =============================================================================
// Splice syscall implementations
// =============================================================================

/// sys_splice - move data between file and pipe
///
/// At least one of fd_in or fd_out must be a pipe.
///
/// # Arguments
/// * `fd_in` - Input file descriptor
/// * `off_in` - Offset for input (NULL=0 to use file position)
/// * `fd_out` - Output file descriptor
/// * `off_out` - Offset for output (NULL=0 to use file position)
/// * `len` - Maximum bytes to transfer
/// * `flags` - Splice flags
///
/// # Returns
/// Number of bytes transferred, or negative errno
pub fn sys_splice(
    fd_in: i32,
    off_in: u64,
    fd_out: i32,
    off_out: u64,
    len: usize,
    flags: u32,
) -> i64 {
    if len == 0 {
        return 0;
    }

    let in_is_pipe = is_pipe_fd(fd_in);
    let out_is_pipe = is_pipe_fd(fd_out);

    // At least one must be a pipe
    if !in_is_pipe && !out_is_pipe {
        return EINVAL;
    }

    // Get the files
    let in_file = match get_file_from_fd(fd_in) {
        Some(f) => f,
        None => return EBADF,
    };
    let out_file = match get_file_from_fd(fd_out) {
        Some(f) => f,
        None => return EBADF,
    };

    // Pipe-to-pipe splice
    if in_is_pipe && out_is_pipe {
        let in_pipe = match get_pipe_from_fd(fd_in) {
            Some(p) => p,
            None => return EBADF,
        };
        let out_pipe = match get_pipe_from_fd(fd_out) {
            Some(p) => p,
            None => return EBADF,
        };

        // Move data from in_pipe to out_pipe
        return do_splice_pipe_to_pipe(&in_pipe, &out_pipe, len, flags);
    }

    // File-to-pipe splice
    if out_is_pipe {
        let out_pipe = match get_pipe_from_fd(fd_out) {
            Some(p) => p,
            None => return EBADF,
        };

        // Pipes don't support offsets
        if off_out != 0 {
            return ESPIPE;
        }

        return do_splice_file_to_pipe(&in_file, off_in, &out_pipe, len, flags);
    }

    // Pipe-to-file splice
    if in_is_pipe {
        let in_pipe = match get_pipe_from_fd(fd_in) {
            Some(p) => p,
            None => return EBADF,
        };

        // Pipes don't support offsets
        if off_in != 0 {
            return ESPIPE;
        }

        return do_splice_pipe_to_file(&in_pipe, &out_file, off_out, len, flags);
    }

    EINVAL
}

/// Splice from pipe to pipe (move buffers)
fn do_splice_pipe_to_pipe(src: &Pipe, dst: &Pipe, len: usize, flags: u32) -> i64 {
    let src_addr = src as *const Pipe as usize;
    let dst_addr = dst as *const Pipe as usize;

    if src_addr == dst_addr {
        return EINVAL;
    }

    let nonblock = flags & SPLICE_F_NONBLOCK != 0;

    // Lock in address order to prevent deadlock
    let (mut src_guard, mut dst_guard) = if src_addr < dst_addr {
        (src.inner.lock(), dst.inner.lock())
    } else {
        let d = dst.inner.lock();
        let s = src.inner.lock();
        (s, d)
    };

    if src_guard.is_empty() {
        if nonblock {
            return EAGAIN;
        }
        return 0; // No data to move
    }

    if dst_guard.is_full() {
        if nonblock {
            return EAGAIN;
        }
        return 0; // No space
    }

    let mut moved = 0;

    while moved < len && !src_guard.is_empty() && !dst_guard.is_full() {
        let tail_idx = src_guard.tail;
        let src_buf = &mut src_guard.bufs[tail_idx];

        if src_buf.is_empty() {
            src_guard.tail = (src_guard.tail + 1) % PIPE_BUFFERS;
            continue;
        }

        let available = src_buf.len as usize;
        let to_move = (len - moved).min(available);

        if let Some(ref page) = src_buf.page {
            // Create new buffer in destination
            let new_buf = PipeBuffer::new(
                Arc::clone(page),
                src_buf.offset,
                to_move as u32,
                src_buf.flags & !pipe_buf_flags::CAN_MERGE,
            );

            if dst_guard.push_buffer(new_buf).is_err() {
                break;
            }

            // Consume from source
            if to_move == available {
                src_buf.release();
                src_guard.tail = (src_guard.tail + 1) % PIPE_BUFFERS;
            } else {
                src_buf.offset += to_move as u32;
                src_buf.len -= to_move as u32;
            }
            src_guard.total_len = src_guard.total_len.saturating_sub(to_move);
            moved += to_move;
        } else {
            src_guard.tail = (src_guard.tail + 1) % PIPE_BUFFERS;
        }
    }

    drop(src_guard);
    drop(dst_guard);

    // Wake up waiters
    src.wait_queue.wake_all();
    dst.wait_queue.wake_all();

    moved as i64
}

/// Splice from file to pipe (read file into pipe)
fn do_splice_file_to_pipe(
    file: &Arc<File>,
    off_in: u64,
    pipe: &Pipe,
    len: usize,
    flags: u32,
) -> i64 {
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;

    // Check pipe has space
    {
        let inner = pipe.inner.lock();
        if inner.is_full() {
            return if nonblock { EAGAIN } else { 0 };
        }
    }

    // For simplicity, we'll read into a temporary buffer and then copy to pipe
    // This isn't true zero-copy, but works for all file types
    // A proper implementation would use page cache pages directly
    let mut buf = [0u8; PAGE_SIZE];
    let to_read = len.min(PAGE_SIZE);

    // Read from file
    let bytes_read = if off_in != 0 {
        // Use pread at specified offset
        match file.pread(&mut buf[..to_read], off_in) {
            Ok(n) => n,
            Err(FsError::WouldBlock) => return if nonblock { EAGAIN } else { 0 },
            Err(_) => return -5, // EIO
        }
    } else {
        // Use regular read (advances file position)
        match file.read(&mut buf[..to_read]) {
            Ok(n) => n,
            Err(FsError::WouldBlock) => return if nonblock { EAGAIN } else { 0 },
            Err(_) => return -5, // EIO
        }
    };

    if bytes_read == 0 {
        return 0;
    }

    // Allocate a pipe page and copy data
    let page = match allocate_pipe_page() {
        Some(p) => p,
        None => return -12, // ENOMEM
    };

    // Copy data to page
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), page.frame as *mut u8, bytes_read);
    }

    // Insert into pipe
    let pipe_buf = PipeBuffer::new(
        page,
        0,
        bytes_read as u32,
        pipe_buf_flags::OWNED | pipe_buf_flags::CAN_MERGE,
    );

    let mut inner = pipe.inner.lock();
    if inner.push_buffer(pipe_buf).is_err() {
        return if nonblock { EAGAIN } else { 0 };
    }
    drop(inner);

    pipe.wait_queue.wake_all();

    bytes_read as i64
}

/// Splice from pipe to file (write pipe contents to file)
fn do_splice_pipe_to_file(
    pipe: &Pipe,
    file: &Arc<File>,
    off_out: u64,
    len: usize,
    flags: u32,
) -> i64 {
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;

    // Check if pipe has data
    {
        let inner = pipe.inner.lock();
        if inner.is_empty() {
            if !pipe.has_writers() {
                return 0; // EOF
            }
            return if nonblock { EAGAIN } else { 0 };
        }
    }

    // Check if output is a socket for zero-copy path
    if let Some(socket_ops) = file.f_op.as_any().downcast_ref::<SocketFileOps>() {
        return do_splice_pipe_to_socket(pipe, socket_ops, len, flags);
    }

    // Regular file path - extract data and write
    let mut written = 0;

    while written < len {
        // Get data from pipe
        let (page, offset, buf_len) = match splice_from_pipe(pipe) {
            Some(data) => data,
            None => break,
        };

        let to_write = (len - written).min(buf_len as usize);

        // Copy data from page to temporary buffer
        let mut buf = [0u8; PAGE_SIZE];
        unsafe {
            let src = (page.frame as *const u8).add(offset as usize);
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), to_write);
        }

        // Write to file
        let bytes_written = if off_out != 0 {
            let actual_offset = off_out + written as u64;
            match file.pwrite(&buf[..to_write], actual_offset) {
                Ok(n) => n,
                Err(_) => {
                    // Put data back? For now, data is lost on error
                    break;
                }
            }
        } else {
            match file.write(&buf[..to_write]) {
                Ok(n) => n,
                Err(_) => break,
            }
        };

        written += bytes_written;

        if bytes_written < to_write {
            break;
        }
    }

    if written == 0 && nonblock {
        return EAGAIN;
    }

    written as i64
}

/// Splice from pipe to socket (zero-copy network send)
fn do_splice_pipe_to_socket(
    pipe: &Pipe,
    socket_ops: &SocketFileOps,
    len: usize,
    flags: u32,
) -> i64 {
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    let socket = socket_ops.socket();

    // Check if socket is ready for writing
    if socket.tcp.is_none() {
        return EINVAL;
    }

    let mut sent = 0;

    while sent < len {
        // Get data from pipe
        let (page, offset, buf_len) = match splice_from_pipe(pipe) {
            Some(data) => data,
            None => break,
        };

        let to_send = (len - sent).min(buf_len as usize);

        // For now, copy to buffer and send via tcp_sendmsg
        // A true zero-copy implementation would pass the page directly
        let mut buf = [0u8; PAGE_SIZE];
        unsafe {
            let src = (page.frame as *const u8).add(offset as usize);
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), to_send);
        }

        match tcp::tcp_sendmsg(socket, &buf[..to_send]) {
            Ok(n) => {
                sent += n;
                if n < to_send {
                    break; // Partial send
                }
            }
            Err(crate::net::NetError::WouldBlock) => {
                if nonblock {
                    break;
                }
                // Would need to wait - for now just return what we've sent
                break;
            }
            Err(_) => break,
        }
    }

    if sent == 0 && nonblock {
        return EAGAIN;
    }

    sent as i64
}

/// Allocate a page for pipe buffer
fn allocate_pipe_page() -> Option<Arc<CachedPage>> {
    use crate::FRAME_ALLOCATOR;
    use crate::mm::page_cache::FileId;

    let frame = FRAME_ALLOCATOR.alloc()?;
    let page = Arc::new(CachedPage::new(frame, FileId::anonymous(), 0));
    Some(page)
}

/// sys_tee - duplicate pipe content
///
/// Both fd_in and fd_out must be pipes.
///
/// # Arguments
/// * `fd_in` - Input pipe file descriptor
/// * `fd_out` - Output pipe file descriptor
/// * `len` - Maximum bytes to duplicate
/// * `flags` - Splice flags
///
/// # Returns
/// Number of bytes duplicated, or negative errno
pub fn sys_tee(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> i64 {
    if len == 0 {
        return 0;
    }

    // Both must be pipes
    let in_pipe = match get_pipe_from_fd(fd_in) {
        Some(p) => p,
        None => return EINVAL,
    };
    let out_pipe = match get_pipe_from_fd(fd_out) {
        Some(p) => p,
        None => return EINVAL,
    };

    // Cannot tee to same pipe
    let in_addr = Arc::as_ptr(&in_pipe) as usize;
    let out_addr = Arc::as_ptr(&out_pipe) as usize;
    if in_addr == out_addr {
        return EINVAL;
    }

    match link_pipe(&in_pipe, &out_pipe, len, flags) {
        Ok(n) => n as i64,
        Err(FsError::WouldBlock) => {
            if flags & SPLICE_F_NONBLOCK != 0 {
                EAGAIN
            } else {
                0
            }
        }
        Err(_) => EINVAL,
    }
}

/// sys_vmsplice - splice user pages into pipe
///
/// # Arguments
/// * `fd` - Pipe file descriptor
/// * `iov` - User iovec array pointer
/// * `nr_segs` - Number of iovec entries
/// * `flags` - Splice flags
///
/// # Returns
/// Number of bytes spliced, or negative errno
pub fn sys_vmsplice(fd: i32, iov: u64, nr_segs: usize, flags: u32) -> i64 {
    if nr_segs == 0 {
        return 0;
    }

    // fd must be a pipe
    let pipe = match get_pipe_from_fd(fd) {
        Some(p) => p,
        None => return EINVAL,
    };

    let nonblock = flags & SPLICE_F_NONBLOCK != 0;

    // Read iovec from user space
    // struct iovec { void *iov_base; size_t iov_len; }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IoVec {
        base: u64,
        len: u64,
    }

    let iov_size = core::mem::size_of::<IoVec>();
    let mut total = 0usize;

    for i in 0..nr_segs {
        let iov_ptr = iov + (i * iov_size) as u64;

        // Read the iovec from user space
        let user_iov = unsafe { *(iov_ptr as *const IoVec) };

        if user_iov.len == 0 {
            continue;
        }

        // Allocate a pipe page
        let page = match allocate_pipe_page() {
            Some(p) => p,
            None => return -12, // ENOMEM
        };

        // Copy user data to page (limited to PAGE_SIZE)
        let to_copy = (user_iov.len as usize).min(PAGE_SIZE);
        unsafe {
            core::ptr::copy_nonoverlapping(
                user_iov.base as *const u8,
                page.frame as *mut u8,
                to_copy,
            );
        }

        // Insert into pipe
        let pipe_buf = PipeBuffer::new(
            page,
            0,
            to_copy as u32,
            pipe_buf_flags::OWNED | pipe_buf_flags::CAN_MERGE,
        );

        let mut inner = pipe.inner.lock();
        if inner.is_full() {
            drop(inner);
            if nonblock {
                return if total > 0 { total as i64 } else { EAGAIN };
            }
            break;
        }

        if inner.push_buffer(pipe_buf).is_err() {
            drop(inner);
            break;
        }
        drop(inner);

        total += to_copy;
    }

    pipe.wait_queue.wake_all();

    total as i64
}

/// sys_sendfile64 - send file data to socket/file
///
/// # Arguments
/// * `out_fd` - Output file descriptor (usually socket)
/// * `in_fd` - Input file descriptor
/// * `offset` - Pointer to offset (NULL=0 to use file position)
/// * `count` - Number of bytes to send
///
/// # Returns
/// Number of bytes sent, or negative errno
pub fn sys_sendfile64(out_fd: i32, in_fd: i32, offset: u64, count: usize) -> i64 {
    if count == 0 {
        return 0;
    }

    // Get input file
    let in_file = match get_file_from_fd(in_fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Get output file
    let out_file = match get_file_from_fd(out_fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Input cannot be a pipe (sendfile is for regular files)
    if is_pipe_fd(in_fd) {
        return EINVAL;
    }

    // Check if output is a socket for optimized path
    if let Some(socket_ops) = out_file.f_op.as_any().downcast_ref::<SocketFileOps>() {
        return do_sendfile_to_socket(&in_file, offset, socket_ops, count);
    }

    // Check if output is a pipe
    if let Some(out_pipe) = get_pipe_from_fd(out_fd) {
        return do_splice_file_to_pipe(&in_file, offset, &out_pipe, count, 0);
    }

    // File to file (rare, but supported)
    do_sendfile_to_file(&in_file, offset, &out_file, count)
}

/// Sendfile to socket
fn do_sendfile_to_socket(
    in_file: &Arc<File>,
    offset: u64,
    socket_ops: &SocketFileOps,
    count: usize,
) -> i64 {
    let socket = socket_ops.socket();

    if socket.tcp.is_none() {
        return EINVAL;
    }

    let mut buf = [0u8; PAGE_SIZE];
    let mut sent = 0;

    while sent < count {
        let to_read = (count - sent).min(PAGE_SIZE);

        // Read from file
        let bytes_read = if offset != 0 {
            let actual_offset = offset + sent as u64;
            match in_file.pread(&mut buf[..to_read], actual_offset) {
                Ok(n) => n,
                Err(_) => break,
            }
        } else {
            match in_file.read(&mut buf[..to_read]) {
                Ok(n) => n,
                Err(_) => break,
            }
        };

        if bytes_read == 0 {
            break; // EOF
        }

        // Send to socket
        match tcp::tcp_sendmsg(socket, &buf[..bytes_read]) {
            Ok(n) => {
                sent += n;
                if n < bytes_read {
                    break; // Partial send
                }
            }
            Err(crate::net::NetError::WouldBlock) => break,
            Err(_) => break,
        }
    }

    // Update offset pointer if provided
    if offset != 0 && sent > 0 {
        // Write back updated offset to user space
        unsafe {
            let offset_ptr = offset as *mut u64;
            *offset_ptr += sent as u64;
        }
    }

    sent as i64
}

/// Sendfile to regular file
fn do_sendfile_to_file(
    in_file: &Arc<File>,
    offset: u64,
    out_file: &Arc<File>,
    count: usize,
) -> i64 {
    let mut buf = [0u8; PAGE_SIZE];
    let mut transferred = 0;

    while transferred < count {
        let to_read = (count - transferred).min(PAGE_SIZE);

        // Read from input file
        let bytes_read = if offset != 0 {
            let actual_offset = offset + transferred as u64;
            match in_file.pread(&mut buf[..to_read], actual_offset) {
                Ok(n) => n,
                Err(_) => break,
            }
        } else {
            match in_file.read(&mut buf[..to_read]) {
                Ok(n) => n,
                Err(_) => break,
            }
        };

        if bytes_read == 0 {
            break; // EOF
        }

        // Write to output file
        match out_file.write(&buf[..bytes_read]) {
            Ok(n) => {
                transferred += n;
                if n < bytes_read {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    transferred as i64
}
