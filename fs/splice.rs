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

use crate::fs::KernelError;
use crate::fs::file::File;
use crate::fs::io::fget;
use crate::fs::io::verify_area;
use crate::fs::iov::IoVec;
use crate::fs::superblock::MAX_LFS_FILESIZE;
use crate::fs::syscall::MAX_RW_COUNT;
use crate::io::pipe::PipePage;
use crate::io::pipe::{
    PIPE_RING, Pipe, PipeBuffer, PipeGuard, PipeReadFileOps, PipeWriteFileOps, pipe_buf_flags,
    sigpipe,
};
use crate::mm::filemap::PAGE_SIZE;
use crate::uaccess::{UserPtr, copy_from_user};
use crate::util::error::KernelResult;
use crate::util::kalloc::try_arc;

// =============================================================================
// Splice flags (from include/linux/splice.h)
// =============================================================================

/// Move pages instead of copying (hint, may not always be honored)
pub const SPLICE_F_MOVE: u32 = 0x01;

/// Don't block on I/O
pub const SPLICE_F_NONBLOCK: u32 = 0x02;

/// Hint that more data is coming (for TCP_CORK)
pub const SPLICE_F_MORE: u32 = 0x04;

/// Pages passed in are a gift (for vmsplice)
pub const SPLICE_F_GIFT: u32 = 0x08;

/// Every splice flag (Linux SPLICE_F_ALL)
const SPLICE_F_ALL: u32 = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;

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
    page: Arc<PipePage>,
    offset: u32,
    len: u32,
) -> Result<usize, KernelError> {
    let mut inner = pipe.lock();

    if inner.is_full() {
        return Err(KernelError::WouldBlock);
    }

    // Create a pipe buffer for the page
    // Don't set OWNED flag - the page belongs to page cache, not pipe
    let buf = PipeBuffer::new(page, offset, len, 0);

    match inner.push_buffer(buf) {
        Ok(()) => {
            // Wake readers - there's data
            drop(inner);
            pipe.wake_readers();
            Ok(len as usize)
        }
        Err(_) => Err(KernelError::WouldBlock),
    }
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
pub fn link_pipe(src: &Pipe, dst: &Pipe, len: usize, _flags: u32) -> Result<usize, KernelError> {
    if core::ptr::eq(src, dst) {
        return Err(KernelError::InvalidArgument);
    }
    let (src_guard, mut dst_guard) = lock_both(src, dst);
    // No reader: EPIPE; nothing to read or no room (after tee's waits)
    // links nothing: 0 (Linux link_pipe)
    if !dst.has_readers() {
        drop((src_guard, dst_guard));
        sigpipe();
        return Err(KernelError::BrokenPipe);
    }

    let mut copied = 0;
    let mut src_idx = src_guard.tail;

    // Iterate through source buffers
    while copied < len && src_idx != src_guard.head && !dst_guard.is_full() {
        let src_buf = &src_guard.bufs[src_idx];

        if let Some(ref page) = src_buf.page {
            let to_copy = (len - copied).min(src_buf.len as usize);

            if to_copy > 0 {
                // Create new buffer pointing to same page
                // Clear GIFT and CAN_MERGE flags
                let new_buf = PipeBuffer::new(
                    Arc::clone(page),
                    src_buf.offset,
                    to_copy as u32,
                    src_buf.flags & !(pipe_buf_flags::GIFT | pipe_buf_flags::CAN_MERGE),
                );

                if dst_guard.push_buffer(new_buf).is_err() {
                    break;
                }

                copied += to_copy;
            }
        }

        src_idx = (src_idx + 1) % PIPE_RING;
    }

    // Wake readers on destination
    drop(src_guard);
    drop(dst_guard);
    dst.wake_readers();

    Ok(copied)
}

// =============================================================================
// Helper: Extract pipe from file if it's a pipe
// =============================================================================

/// The pipe behind `file`, a pipe end or a FIFO (Linux get_pipe_info);
/// callers check the file's direction on the same `File` they looked up
fn pipe_of_file(file: &File) -> Option<Arc<Pipe>> {
    let ops = file.f_op.as_any();
    // A FIFO is a pipe too (Linux get_pipe_info)
    if ops.is::<crate::io::pipe::FifoFileOps>() {
        return file
            .private_arc::<crate::io::pipe::FifoFile>()
            .map(|f| f.pipe());
    }
    if !ops.is::<PipeReadFileOps>() && !ops.is::<PipeWriteFileOps>() {
        return None;
    }
    file.private_arc::<Pipe>()
}

/// Read a user `loff_t *` (NULL = use and advance the file position)
fn read_user_offset(ptr: UserPtr<i64>) -> KernelResult<Option<u64>> {
    if ptr.is_null() {
        return Ok(None);
    }
    let off = ptr.read()?;
    if off < 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(Some(off as u64))
}

/// After a transfer that started at user offset `pos`, store the advanced
/// offset back to `*ptr` (Linux updates `*off_in`/`*off_out`/`*offset`).
fn write_back_offset(
    ptr: UserPtr<i64>,
    pos: Option<u64>,
    ret: KernelResult<usize>,
) -> KernelResult<usize> {
    let n = ret?;
    if let Some(p) = pos
        && n > 0
    {
        ptr.write(&((p + n as u64) as i64))?;
    }
    Ok(n)
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
    off_in: UserPtr<i64>,
    fd_out: i32,
    off_out: UserPtr<i64>,
    len: usize,
    flags: u32,
) -> KernelResult<usize> {
    if len == 0 {
        return Ok(0);
    }
    if flags & !SPLICE_F_ALL != 0 {
        return Err(KernelError::InvalidArgument);
    }

    let in_file = fget(fd_in)?;
    let out_file = fget(fd_out)?;
    // Linux do_splice: read from a readable file, write to a writable
    // one (a FIFO is open one way or both)
    if !in_file.is_readable() || !out_file.is_writable() {
        return Err(KernelError::BadFd);
    }

    // The pipes of the files just checked (one lookup per fd)
    let in_pipe = pipe_of_file(&in_file);
    let out_pipe = pipe_of_file(&out_file);

    // Linux do_splice: O_NONBLOCK on the pipe side's file (either, for
    // pipe to pipe) makes the splice nonblocking
    let len = len.min(MAX_RW_COUNT);

    // Pipe-to-pipe splice: neither side has an offset
    if let (Some(in_pipe), Some(out_pipe)) = (&in_pipe, &out_pipe) {
        if !off_in.is_null() || !off_out.is_null() {
            return Err(KernelError::IllegalSeek);
        }
        let flags = flags
            | if nb(&in_file) || nb(&out_file) {
                SPLICE_F_NONBLOCK
            } else {
                0
            };
        return do_splice_pipe_to_pipe(in_pipe, out_pipe, len, flags);
    }

    // File-to-pipe splice
    if let Some(out_pipe) = out_pipe {
        // Pipes don't support offsets
        if !off_out.is_null() {
            return Err(KernelError::IllegalSeek);
        }

        let pos = read_user_offset(off_in)?;
        verify_area(&in_file, pos, len)?;
        let flags = flags | if nb(&out_file) { SPLICE_F_NONBLOCK } else { 0 };
        let ret = do_splice_file_to_pipe(&in_file, pos, &out_pipe, len, flags);
        return write_back_offset(off_in, pos, ret);
    }

    // Pipe-to-file splice
    if let Some(in_pipe) = in_pipe {
        // Pipes don't support offsets
        if !off_in.is_null() {
            return Err(KernelError::IllegalSeek);
        }

        let pos = read_user_offset(off_out)?;
        // Linux do_splice: an O_APPEND output is EINVAL
        if out_file.get_flags() & crate::fs::file::flags::O_APPEND != 0 {
            return Err(KernelError::InvalidArgument);
        }
        verify_area(&out_file, pos, len)?;
        let flags = flags | if nb(&in_file) { SPLICE_F_NONBLOCK } else { 0 };
        let ret = do_splice_pipe_to_file(&in_pipe, &out_file, pos, len, flags);
        return write_back_offset(off_out, pos, ret);
    }

    Err(KernelError::InvalidArgument)
}

/// Both pipes locked, in address order (Linux pipe_double_lock)
fn lock_both<'a>(a: &'a Pipe, b: &'a Pipe) -> (PipeGuard<'a>, PipeGuard<'a>) {
    if core::ptr::from_ref(a) < core::ptr::from_ref(b) {
        let ga = a.lock();
        (ga, b.lock())
    } else {
        let gb = b.lock();
        (a.lock(), gb)
    }
}

/// Splice from pipe to pipe, moving buffers (Linux
/// splice_pipe_to_pipe): wait for data in `src` and room in `dst` one
/// at a time, then look again under both locks, retrying until one of
/// them gives an answer
fn do_splice_pipe_to_pipe(src: &Pipe, dst: &Pipe, len: usize, flags: u32) -> KernelResult<usize> {
    if core::ptr::eq(src, dst) {
        return Err(KernelError::InvalidArgument);
    }
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    loop {
        drop(src.lock_data(nonblock)?);
        drop(dst.lock_room(nonblock)?);
        let (src_guard, dst_guard) = lock_both(src, dst);
        if !dst.has_readers() {
            drop((src_guard, dst_guard));
            sigpipe();
            return Err(KernelError::BrokenPipe);
        }
        if src_guard.is_empty() && !src.has_writers() {
            return Ok(0);
        }
        if src_guard.is_empty() || dst_guard.is_full() {
            if nonblock {
                return Err(KernelError::WouldBlock);
            }
            continue;
        }
        return Ok(move_bufs(src, src_guard, dst, dst_guard, len));
    }
}

/// Move up to `len` bytes of buffers from `src` to `dst`, both locked
fn move_bufs(
    src: &Pipe,
    mut src_guard: PipeGuard<'_>,
    dst: &Pipe,
    mut dst_guard: PipeGuard<'_>,
    len: usize,
) -> usize {
    let mut moved = 0;

    while moved < len && !src_guard.is_empty() && !dst_guard.is_full() {
        let tail_idx = src_guard.tail;
        let src_buf = &mut src_guard.bufs[tail_idx];

        if src_buf.is_empty() {
            src_guard.tail = (src_guard.tail + 1) % PIPE_RING;
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
                src_guard.tail = (src_guard.tail + 1) % PIPE_RING;
            } else {
                src_buf.offset += to_move as u32;
                src_buf.len -= to_move as u32;
            }
            src_guard.total_len = src_guard.total_len.saturating_sub(to_move);
            moved += to_move;
        } else {
            src_guard.tail = (src_guard.tail + 1) % PIPE_RING;
        }
    }

    drop(src_guard);
    drop(dst_guard);

    // Wake up waiters
    src.wake_writers();
    dst.wake_readers();
    moved
}

/// errno of a failed read feeding a splice: the read's own, except that
/// a file without a read is EINVAL (Linux do_splice_read: no
/// ->splice_read)
fn read_err(e: KernelError) -> KernelError {
    match e {
        KernelError::OperationNotSupported => KernelError::InvalidArgument,
        e => e,
    }
}

/// O_NONBLOCK on `f`, which makes a splice or tee of its pipe
/// nonblocking (Linux do_splice, do_tee)
fn nb(f: &File) -> bool {
    f.get_flags() & crate::fs::file::flags::O_NONBLOCK != 0
}

/// Splice from file to pipe (Linux splice_file_to_pipe): once the
/// pipe has room, the file is read under its lock, so nothing read can
/// find the pipe full
fn do_splice_file_to_pipe(
    file: &Arc<File>,
    off_in: Option<u64>,
    pipe: &Pipe,
    len: usize,
    flags: u32,
) -> KernelResult<usize> {
    let page = allocate_pipe_page().ok_or(KernelError::OutOfMemory)?;
    let mut g = pipe.lock_room(flags & SPLICE_F_NONBLOCK != 0)?;

    // A copy through a buffer, not page cache pages: works for every file
    let mut buf = [0u8; PAGE_SIZE];
    let to_read = len.min(PAGE_SIZE);
    // pread at the offset, else read (advances the file position)
    let n = match off_in {
        Some(off_in) => file.pread(&mut buf[..to_read], off_in),
        None => file.read(&mut buf[..to_read]),
    }
    .map_err(read_err)?;
    if n == 0 {
        return Ok(0);
    }

    // SAFETY: `page` is a fresh, kernel-mapped frame of PAGE_SIZE bytes
    // owned by this call; `n <= to_read <= PAGE_SIZE` bytes of `buf` are
    // copied in
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), crate::arch::phys_to_virt(page.frame), n);
    }
    let pb = PipeBuffer::new(
        page,
        0,
        n as u32,
        pipe_buf_flags::OWNED | pipe_buf_flags::CAN_MERGE,
    );
    // Room was seen under this lock: the push cannot fail
    if g.push_buffer(pb).is_err() {
        return Err(KernelError::WouldBlock);
    }
    drop(g);
    pipe.wake_readers();
    Ok(n)
}

/// Splice from pipe to file (write pipe contents to file)
fn do_splice_pipe_to_file(
    pipe: &Pipe,
    file: &Arc<File>,
    off_out: Option<u64>,
    len: usize,
    flags: u32,
) -> KernelResult<usize> {
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;

    // Data, or EOF, decided under the lock the writes keep. The pipe
    // stays locked across the writes, and each buffer gives up only the
    // bytes written (Linux iter_file_splice_write under pipe_lock): a
    // short write or `len` leaves the rest in the pipe
    let Some(mut g) = pipe.lock_data(nonblock)? else {
        return Ok(0);
    };
    let mut written = 0;
    let mut err = None;
    while written < len && !g.is_empty() {
        let tail = g.tail;
        let pb = &g.bufs[tail];
        let Some(page) = pb.page.clone().filter(|_| !pb.is_empty()) else {
            g.bufs[tail].release();
            g.tail = (tail + 1) % PIPE_RING;
            continue;
        };
        let (offset, avail) = (pb.offset, pb.len as usize);
        let to_write = (len - written).min(avail);

        let mut buf = [0u8; PAGE_SIZE];
        // SAFETY: the pipe buffer holds `page` (kernel-mapped, PAGE_SIZE)
        // with valid data at `offset..offset + avail` inside it, and
        // `to_write <= avail` bytes of it are copied out
        unsafe {
            let src = crate::arch::phys_to_virt(page.frame)
                .cast_const()
                .add(offset as usize);
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), to_write);
        }

        let r = match off_out {
            Some(o) => file.pwrite(&buf[..to_write], o + written as u64),
            None => file.write(&buf[..to_write]),
        };
        let n = match r {
            Ok(n) => n.min(to_write),
            Err(e) => {
                err = Some(e);
                break;
            }
        };
        // Consume exactly what was written
        let pb = &mut g.bufs[tail];
        if n == avail {
            pb.release();
            g.tail = (tail + 1) % PIPE_RING;
        } else {
            pb.offset += n as u32;
            pb.len -= n as u32;
        }
        g.total_len = g.total_len.saturating_sub(n);
        written += n;
        if n < to_write {
            break;
        }
    }
    drop(g);
    if written > 0 {
        pipe.wake_writers();
    }
    if written == 0
        && let Some(e) = err
    {
        return Err(e);
    }

    if written == 0 && nonblock {
        return Err(KernelError::WouldBlock);
    }

    Ok(written)
}

/// Allocate a page for pipe buffer
fn allocate_pipe_page() -> Option<Arc<PipePage>> {
    use crate::FRAME_ALLOCATOR;

    // User data (Linux GFP_HIGHUSER | __GFP_ACCOUNT): stops at the low
    // watermark like the user pages it was copied from
    let frame = FRAME_ALLOCATOR.alloc_gfp(crate::mm::page_alloc::Gfp::HIGHUSER_MOVABLE)?;
    try_arc(PipePage::new(frame)).ok()
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
pub fn sys_tee(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> KernelResult<usize> {
    if len == 0 {
        return Ok(0);
    }

    // Linux do_tee: EBADF for a bad fd or the wrong direction first
    let in_file = fget(fd_in)?;
    let out_file = fget(fd_out)?;
    if !in_file.is_readable() || !out_file.is_writable() {
        return Err(KernelError::BadFd);
    }

    // Both must be pipes
    let (Some(in_pipe), Some(out_pipe)) = (pipe_of_file(&in_file), pipe_of_file(&out_file)) else {
        return Err(KernelError::InvalidArgument);
    };

    // Cannot tee to same pipe
    if Arc::ptr_eq(&in_pipe, &out_pipe) {
        return Err(KernelError::InvalidArgument);
    }

    // Linux do_tee: O_NONBLOCK on either file, then wait for data and
    // for room (ipipe_prep, opipe_prep) before linking
    let flags = flags
        | if nb(&in_file) || nb(&out_file) {
            SPLICE_F_NONBLOCK
        } else {
            0
        };
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    drop(in_pipe.lock_data(nonblock)?);
    drop(out_pipe.lock_room(nonblock)?);
    link_pipe(&in_pipe, &out_pipe, len, flags)
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
pub fn sys_vmsplice(
    fd: i32,
    iov: UserPtr<IoVec>,
    nr_segs: usize,
    flags: u32,
) -> KernelResult<usize> {
    if flags & !SPLICE_F_ALL != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // A pipe open for writing (Linux vmsplice_to_pipe); vmsplice from
    // a pipe open only for reading (vmsplice_to_user) is not done: EBADF
    let file = fget(fd)?;
    // The segments as readv takes them (Linux import_iovec): EINVAL
    // past IOV_MAX or for a negative length, cut to MAX_RW_COUNT
    let n = i32::try_from(nr_segs).map_err(|_| KernelError::InvalidArgument)?;
    let segs = crate::fs::iov::import_iovec(iov, n)?;
    let pipe = pipe_of_file(&file).ok_or(KernelError::InvalidArgument)?;
    if !file.is_writable() {
        return Err(KernelError::BadFd);
    }

    // Linux vmsplice_to_pipe: wait for room, then fill what fits
    let mut g = pipe.lock_room(flags & SPLICE_F_NONBLOCK != 0)?;
    let r = iter_to_pipe(&mut g, &segs);
    drop(g);
    if matches!(r, Ok(n) if n > 0) {
        pipe.wake_readers();
    }
    r
}

/// Copy the segments into pipe pages, a page at a time, until they or
/// the room run out (Linux iter_to_pipe); a fault or no memory ends it,
/// an error only if nothing was copied
fn iter_to_pipe(g: &mut PipeGuard<'_>, segs: &[IoVec]) -> KernelResult<usize> {
    let mut total = 0usize;
    for seg in segs {
        let mut off = 0u64;
        while off < seg.iov_len {
            if g.is_full() {
                return Ok(total);
            }
            match page_from_user(seg.iov_base + off, seg.iov_len - off) {
                Ok(pb) => {
                    off += u64::from(pb.len);
                    total += pb.len as usize;
                    // Not full, under this lock: the push cannot fail
                    if g.push_buffer(pb).is_err() {
                        return Ok(total);
                    }
                }
                Err(e) if total == 0 => return Err(e),
                Err(_) => return Ok(total),
            }
        }
    }
    Ok(total)
}

/// A pipe buffer holding up to a page of user memory at `addr` (`len`
/// bytes left there): EFAULT, ENOMEM
fn page_from_user(addr: u64, len: u64) -> KernelResult<PipeBuffer> {
    let page = allocate_pipe_page().ok_or(KernelError::OutOfMemory)?;
    let n = len.min(PAGE_SIZE as u64) as usize;
    // SAFETY: page.frame is a freshly allocated, kernel-mapped page of
    // PAGE_SIZE bytes owned by this buffer, and `n <= PAGE_SIZE`
    let dst = unsafe { core::slice::from_raw_parts_mut(crate::arch::phys_to_virt(page.frame), n) };
    copy_from_user(dst, addr, n).map_err(|_| KernelError::BadAddress)?;
    Ok(PipeBuffer::new(
        page,
        0,
        n as u32,
        pipe_buf_flags::OWNED | pipe_buf_flags::CAN_MERGE,
    ))
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
pub fn sys_sendfile64(
    out_fd: i32,
    in_fd: i32,
    offset: UserPtr<i64>,
    count: usize,
) -> KernelResult<usize> {
    let pos = read_user_offset(offset)?;
    let ret = do_sendfile(out_fd, in_fd, pos, count);
    write_back_offset(offset, pos, ret)
}

/// Linux do_sendfile: `count` bytes of `in_fd` at `pos` (None: its
/// position) to `out_fd`, cut to MAX_RW_COUNT and to the smaller
/// s_maxbytes of the two files (EOVERFLOW at or past it)
fn do_sendfile(out_fd: i32, in_fd: i32, pos: Option<u64>, count: usize) -> KernelResult<usize> {
    let in_file = fget(in_fd)?;
    if !in_file.is_readable() {
        return Err(KernelError::BadFd);
    }
    // A pipe has no position (ESPIPE) and no read to splice from
    if pipe_of_file(&in_file).is_some() {
        return Err(if pos.is_some() {
            KernelError::IllegalSeek
        } else {
            KernelError::InvalidArgument
        });
    }
    verify_area(&in_file, pos, count)?;
    let mut count = count.min(MAX_RW_COUNT);
    let out_file = fget(out_fd)?;
    if !out_file.is_writable() {
        return Err(KernelError::BadFd);
    }
    let maxb = |f: &File| f.get_inode().map_or(MAX_LFS_FILESIZE, |i| i.maxbytes());
    let max = maxb(&in_file).min(maxb(&out_file));
    let start = pos.unwrap_or_else(|| in_file.get_pos());
    if start.saturating_add(count as u64) > max {
        if start >= max {
            return Err(KernelError::Overflow);
        }
        count = (max - start) as usize;
    }
    if count == 0 {
        return Ok(0);
    }
    if let Some(out_pipe) = pipe_of_file(&out_file) {
        let nb = out_file.get_flags() & crate::fs::file::flags::O_NONBLOCK != 0;
        let flags = if nb { SPLICE_F_NONBLOCK } else { 0 };
        do_splice_file_to_pipe(&in_file, pos, &out_pipe, count, flags)
    } else {
        verify_area(&out_file, None, count)?;
        do_sendfile_to_file(&in_file, pos, &out_file, count)
    }
}

/// Sendfile to regular file
fn do_sendfile_to_file(
    in_file: &Arc<File>,
    offset: Option<u64>,
    out_file: &Arc<File>,
    count: usize,
) -> KernelResult<usize> {
    let mut buf = [0u8; PAGE_SIZE];
    let mut transferred = 0;

    while transferred < count {
        let to_read = (count - transferred).min(PAGE_SIZE);

        // Read from input file
        let r = match offset {
            Some(o) => in_file.pread(&mut buf[..to_read], o + transferred as u64),
            None => in_file.read(&mut buf[..to_read]),
        };
        let r = r.and_then(|n| match n {
            0 => Ok((0, 0)),
            n => out_file.write(&buf[..n]).map(|w| (n, w)),
        });
        // An error ends the transfer: the error if nothing moved yet
        let (got, put) = match r {
            Ok(r) => r,
            Err(e) if transferred == 0 => return Err(read_err(e)),
            Err(_) => break,
        };
        transferred += put;
        if got == 0 || put < got {
            break;
        }
    }

    Ok(transferred)
}

// =============================================================================
// copy_file_range syscall
// =============================================================================

/// sys_copy_file_range - copy a range between two regular files in the
/// kernel (Linux fs/read_write.c copy_file_range, vfs_copy_file_range)
///
/// NULL offset pointers use and advance the file positions. Errors:
/// EBADF (fds, access mode, O_APPEND output), EINVAL (flags, not
/// regular files, overlapping ranges of one file, an offset the copy
/// would carry negative), EISDIR, EXDEV (different file systems),
/// ETXTBSY (swap files), EOVERFLOW (an offset plus the length wraps),
/// EFBIG (output limits).
pub fn sys_copy_file_range(
    fd_in: i32,
    off_in: UserPtr<i64>,
    fd_out: i32,
    off_out: UserPtr<i64>,
    len: u64,
    flags: u32,
) -> KernelResult<u64> {
    let in_file = fget(fd_in)?;
    let out_file = fget(fd_out)?;
    let at = |ptr: UserPtr<i64>, f: &File| -> KernelResult<i64> {
        if ptr.is_null() {
            return Ok(f.get_pos() as i64);
        }
        Ok(ptr.read()?)
    };
    let pos_in = at(off_in, &in_file)?;
    let pos_out = at(off_out, &out_file)?;
    if flags != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let n = copy_range(&in_file, pos_in, &out_file, pos_out, len)?;
    if n == 0 {
        return Ok(0);
    }
    // Both offsets were checked to stay valid past the copy; both are
    // stored before a fault is returned (Linux copy_file_range)
    let a = store_pos(off_in, &in_file, pos_in as u64 + n);
    let b = store_pos(off_out, &out_file, pos_out as u64 + n);
    a.and(b).map(|()| n)
}

/// After a copy: advance `*ptr`, or the file position when NULL
fn store_pos(ptr: UserPtr<i64>, f: &File, end: u64) -> KernelResult<()> {
    if ptr.is_null() {
        f.set_pos(end);
        return Ok(());
    }
    Ok(ptr.write(&(end as i64))?)
}

/// Linux generic_file_rw_checks: two regular files, readable and
/// writable, the output not O_APPEND; their inodes
fn copy_files_ok(
    fin: &File,
    fout: &File,
) -> Result<(Arc<crate::fs::Inode>, Arc<crate::fs::Inode>), KernelError> {
    let (Some(iin), Some(iout)) = (fin.get_inode(), fout.get_inode()) else {
        return Err(KernelError::InvalidArgument);
    };
    if iin.mode().is_dir() || iout.mode().is_dir() {
        return Err(KernelError::IsDirectory);
    }
    if !iin.mode().is_file() || !iout.mode().is_file() {
        return Err(KernelError::InvalidArgument);
    }
    if !fin.is_readable()
        || !fout.is_writable()
        || fout.get_flags() & crate::fs::file::flags::O_APPEND != 0
    {
        return Err(KernelError::BadFd);
    }
    Ok((iin, iout))
}

/// Linux rw_verify_area for a regular file: `pos` and `pos + count`
/// valid offsets (EINVAL)
fn verify_pos(pos: i64, count: u64) -> Result<(), KernelError> {
    match i64::try_from(count).ok().and_then(|c| pos.checked_add(c)) {
        Some(_) if pos >= 0 => Ok(()),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// The checks and length of a copy (Linux generic_copy_file_checks and
/// vfs_copy_file_range): the length cut to the input's end, the output's
/// limits and MAX_RW_COUNT
fn copy_len(
    fin: &File,
    pos_in: i64,
    fout: &File,
    pos_out: i64,
    len: u64,
) -> Result<u64, KernelError> {
    let (iin, iout) = copy_files_ok(fin, fout)?;
    let same_sb = match (iin.superblock(), iout.superblock()) {
        (Some(a), Some(b)) => Arc::ptr_eq(&a, &b),
        _ => false,
    };
    if !same_sb {
        return Err(KernelError::CrossDevice);
    }
    let swap = |i: &crate::fs::Inode| i.i_swapfile.load(core::sync::atomic::Ordering::Acquire);
    if swap(&iin) || swap(&iout) {
        return Err(KernelError::TextBusy);
    }
    // Offsets that wrap as unsigned 64-bit values (Linux: loff_t plus
    // size_t)
    if (pos_in as u64).checked_add(len).is_none() || (pos_out as u64).checked_add(len).is_none() {
        return Err(KernelError::Overflow);
    }
    // Shorten the copy to the input's end
    let size_in = iin.get_size() as i64;
    let mut count = if pos_in >= size_in {
        0
    } else {
        // pos_in may be negative here: rw_verify_area below refuses it
        len.min((size_in as u64).wrapping_sub(pos_in as u64))
    };
    if let Ok(p) = u64::try_from(pos_out) {
        count = iout.write_limit(p, count as usize)? as u64;
    }
    // Overlapping ranges of one file
    let (i, o, c) = (i128::from(pos_in), i128::from(pos_out), i128::from(count));
    if Arc::ptr_eq(&iin, &iout) && o + c > i && o < i + c {
        return Err(KernelError::InvalidArgument);
    }
    verify_pos(pos_in, count)?;
    verify_pos(pos_out, count)?;
    Ok(count.min(super::syscall::MAX_RW_COUNT as u64))
}

/// Copy up to `len` bytes from `fin` at `pos_in` to `fout` at `pos_out`;
/// the bytes copied
fn copy_range(
    fin: &File,
    pos_in: i64,
    fout: &File,
    pos_out: i64,
    len: u64,
) -> Result<u64, KernelError> {
    let len = copy_len(fin, pos_in, fout, pos_out, len)?;
    // Checked: both offsets stay valid through `len`
    let (pos_in, pos_out) = (pos_in as u64, pos_out as u64);
    let mut buf = [0u8; PAGE_SIZE];
    let mut copied: u64 = 0;
    while copied < len {
        let want = ((len - copied) as usize).min(PAGE_SIZE);
        let step = fin.pread(&mut buf[..want], pos_in + copied).and_then(|n| {
            if n == 0 {
                return Ok((0, 0));
            }
            fout.pwrite(&buf[..n], pos_out + copied).map(|w| (n, w))
        });
        let (got, put) = match step {
            Ok(r) => r,
            Err(e) if copied == 0 => return Err(e),
            Err(_) => break,
        };
        copied += put as u64;
        if got == 0 || put < got {
            break;
        }
    }
    Ok(copied)
}
