//! read/write family (Linux fs/read_write.c): read, write, lseek,
//! pread64, pwrite64 and the shared core used by the vectored calls

use alloc::sync::Arc;
use alloc::vec;

use crate::arch::Uaccess;
use crate::fs::file::WRITE_CHUNK;
use crate::fs::{File, KernelError, RwFlags};
use crate::uaccess::{UaccessArch, copy_from_user_atomic, copy_to_user};

use super::iov::IoVec;
use super::syscall::{MAX_RW_COUNT, current_fd_table};

/// File of `fd`
fn fget(fd: i32) -> Result<Arc<File>, KernelError> {
    current_fd_table().lock().get(fd).ok_or(KernelError::BadFd)
}

/// Bytes the segments cover, capped at MAX_RW_COUNT
fn seg_len(segs: &[IoVec]) -> usize {
    let total = segs.iter().map(|s| s.iov_len as usize).sum::<usize>();
    total.min(MAX_RW_COUNT)
}

/// Position in a list of user segments (Linux iov_iter over user
/// memory)
struct Cursor<'a> {
    segs: &'a [IoVec],
    i: usize,
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(segs: &'a [IoVec]) -> Self {
        Self { segs, i: 0, off: 0 }
    }

    /// Visit the next `len` bytes of user memory as (address, length)
    /// runs and advance past them
    fn step(
        &mut self,
        mut len: usize,
        f: &mut dyn FnMut(u64, usize, usize) -> Result<(), ()>,
    ) -> Result<(), KernelError> {
        let mut done = 0;
        while len > 0 {
            let s = self.segs.get(self.i).ok_or(KernelError::BadAddress)?;
            let n = (s.iov_len as usize - self.off).min(len);
            if n > 0 {
                f(s.iov_base + self.off as u64, n, done).map_err(|_| KernelError::BadAddress)?;
            }
            self.off += n;
            done += n;
            len -= n;
            if self.off == s.iov_len as usize {
                self.i += 1;
                self.off = 0;
            }
        }
        Ok(())
    }

    /// Fill `buf` from the user segments. A file write copies under
    /// i_rwsem: page faults are disabled for the copy and missing pages
    /// faulted in first (`copy_from_user_atomic`, Linux
    /// generic_perform_write)
    fn copy_in(&mut self, buf: &mut [u8]) -> Result<(), KernelError> {
        self.step(buf.len(), &mut |a, n, at| {
            copy_from_user_atomic::<Uaccess>(&mut buf[at..at + n], a, n)
                .map(|_| ())
                .map_err(|_| ())
        })
    }

    /// Copy `data` out to the user segments
    fn copy_out(&mut self, data: &[u8]) -> Result<(), KernelError> {
        self.step(data.len(), &mut |a, n, at| {
            copy_to_user::<Uaccess>(a, &data[at..at + n])
                .map(|_| ())
                .map_err(|_| ())
        })
    }
}

/// Files whose reads return everything asked for unless at EOF (more
/// chunks are read); for others (pipes, sockets, terminals) one chunk is
/// one read, since a second could block although data was returned
fn reads_fully(file: &File) -> bool {
    file.get_inode()
        .is_some_and(|i| i.mode().is_file() || i.mode().is_blkdev())
}

/// Read from `file` into `segs` at `at` (None: the file position)
/// through a kernel buffer of at most `WRITE_CHUNK` bytes (Linux
/// vfs_readv). Data already returned wins over a later error.
pub fn file_readv(
    file: &File,
    segs: &[IoVec],
    at: Option<u64>,
    flags: RwFlags,
) -> Result<usize, KernelError> {
    let total = seg_len(segs);
    let mut buf = vec![0u8; total.min(WRITE_CHUNK)];
    let mut cur = Cursor::new(segs);
    let mut done = 0;
    loop {
        let n = (total - done).min(WRITE_CHUNK);
        let r = match at {
            None => file.read_with_flags(&mut buf[..n], flags),
            Some(o) => file.pread_with_flags(&mut buf[..n], o + done as u64, flags),
        };
        let r = match r {
            Ok(r) => r,
            Err(_) if done > 0 => return Ok(done),
            Err(e) => return Err(e),
        };
        if let Err(e) = cur.copy_out(&buf[..r]) {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
        done += r;
        if r < n || done >= total || !reads_fully(file) {
            return Ok(done);
        }
    }
}

/// Write `segs` to `file` as one write (see `File::write_from`)
pub fn file_writev(
    file: &File,
    segs: &[IoVec],
    at: Option<u64>,
    flags: RwFlags,
    append: Option<bool>,
) -> Result<usize, KernelError> {
    let mut cur = Cursor::new(segs);
    file.write_from(seg_len(segs), at, flags, append, &mut |dst| {
        cur.copy_in(dst)
    })
}

/// errno for a failed read/write: no access is EBADF, a missing op is
/// ESPIPE for positioned I/O and EINVAL otherwise (EOPNOTSUPP stays for
/// RWF_NOWAIT)
fn rw_err(e: KernelError, at: Option<u64>, flags: RwFlags) -> i64 {
    match e {
        KernelError::PermissionDenied => KernelError::BadFd.sysret(),
        KernelError::OperationNotSupported if !flags.nowait => match at {
            Some(_) => KernelError::IllegalSeek.sysret(),
            None => KernelError::InvalidArgument.sysret(),
        },
        e => e.sysret(),
    }
}

/// Read from `fd` into `segs` at `at`, or at the file position (under
/// f_pos_lock, Linux fdget_pos) when None (Linux vfs_readv)
pub fn do_readv(fd: i32, segs: &[IoVec], at: Option<u64>, flags: RwFlags) -> i64 {
    let file = match fget(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }
    let _pos = at.is_none().then(|| file.pos_lock());
    match file_readv(&file, segs, at, flags) {
        Ok(n) => n as i64,
        Err(e) => rw_err(e, at, flags),
    }
}

/// Write `segs` to `fd` as one write at `at`, or at the file position
/// (under f_pos_lock) when None (Linux vfs_writev); `append` as for
/// `File::write_at`
pub fn do_writev(
    fd: i32,
    segs: &[IoVec],
    at: Option<u64>,
    flags: RwFlags,
    append: Option<bool>,
) -> i64 {
    let file = match fget(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    if file.is_dir() {
        return KernelError::IsDirectory.sysret();
    }
    let _pos = at.is_none().then(|| file.pos_lock());
    match file_writev(&file, segs, at, flags, append) {
        Ok(n) => n as i64,
        Err(e) => rw_err(e, at, flags),
    }
}

/// One user buffer as a segment, after the EFAULT check
fn one_seg(buf: u64, count: u64) -> Result<[IoVec; 1], i64> {
    let count = (count as usize).min(MAX_RW_COUNT);
    if !Uaccess::access_ok(buf, count) {
        return Err(KernelError::BadAddress.sysret());
    }
    Ok([IoVec {
        iov_base: buf,
        iov_len: count as u64,
    }])
}

/// Explicit offset of pread/pwrite: negative is EINVAL
fn pos_arg(offset: i64) -> Result<u64, i64> {
    u64::try_from(offset).map_err(|_| KernelError::InvalidArgument.sysret())
}

/// sys_read - read from a file descriptor
pub fn sys_read(fd: i32, buf: u64, count: u64) -> i64 {
    match one_seg(buf, count) {
        Ok(s) => do_readv(fd, &s, None, RwFlags::empty()),
        Err(e) => e,
    }
}

/// sys_write - write to a file descriptor
pub fn sys_write(fd: i32, buf: u64, count: u64) -> i64 {
    match one_seg(buf, count) {
        Ok(s) => do_writev(fd, &s, None, RwFlags::empty(), None),
        Err(e) => e,
    }
}

/// sys_pread64 - read at an offset without moving the file position
pub fn sys_pread64(fd: i32, buf: u64, count: u64, offset: i64) -> i64 {
    match (pos_arg(offset), one_seg(buf, count)) {
        (Ok(o), Ok(s)) => do_readv(fd, &s, Some(o), RwFlags::empty()),
        (Err(e), _) | (_, Err(e)) => e,
    }
}

/// sys_pwrite64 - write at an offset without moving the file position
/// (an O_APPEND file still appends, like Linux)
pub fn sys_pwrite64(fd: i32, buf: u64, count: u64, offset: i64) -> i64 {
    match (pos_arg(offset), one_seg(buf, count)) {
        (Ok(o), Ok(s)) => do_writev(fd, &s, Some(o), RwFlags::empty(), None),
        (Err(e), _) | (_, Err(e)) => e,
    }
}

/// sys_lseek - reposition the file offset (under f_pos_lock)
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    let file = match fget(fd) {
        Ok(f) => f,
        Err(e) => return e.sysret(),
    };
    let _pos = file.pos_lock();
    match file.lseek(offset, whence) {
        Ok(new_pos) => new_pos as i64,
        Err(KernelError::OperationNotSupported) => KernelError::IllegalSeek.sysret(),
        Err(e) => e.sysret(),
    }
}
