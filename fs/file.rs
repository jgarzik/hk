//! File - open file description
//!
//! A File represents an open file handle. Multiple file descriptors
//! can point to the same file (e.g., after dup()).
//!
//! Page-cache file I/O is `mm::filemap` (read_iter, write_iter).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::spin::Mutex;
use ::core::sync::atomic::{AtomicU64, Ordering};

use crate::sync;

use super::KernelError;
use super::dentry::Dentry;
use super::inode::{FileType, Inode, InodeId};
use super::iov_iter::{IovDest, IovSource};
use super::mount::Mount;
use crate::io::poll::{DEFAULT_POLLMASK, POLLERR, POLLHUP, PollTable};

/// Largest kernel buffer a pseudo-file write (sysctl, cgroup attribute)
/// copies in for one store
pub const WRITE_CHUNK: usize = 64 * 1024;

/// Open file flags (Linux O_* flags)
pub mod flags {
    /// Open for reading only
    pub const O_RDONLY: u32 = 0;
    /// Open for writing only
    pub const O_WRONLY: u32 = 1;
    /// Open for reading and writing
    pub const O_RDWR: u32 = 2;
    /// Access mode mask
    pub const O_ACCMODE: u32 = 3;

    /// Create file if it doesn't exist
    pub const O_CREAT: u32 = 0o100;
    /// Fail if file exists (with O_CREAT)
    pub const O_EXCL: u32 = 0o200;
    /// Don't make a tty the controlling terminal
    pub const O_NOCTTY: u32 = 0o400;
    /// Truncate file to zero length
    pub const O_TRUNC: u32 = 0o1000;
    /// Append mode
    pub const O_APPEND: u32 = 0o2000;
    /// Non-blocking mode
    pub const O_NONBLOCK: u32 = 0o4000;
    /// Writes reach storage before returning (O_SYNC includes it)
    pub const O_DSYNC: u32 = 0o10000;
    /// Asynchronous I/O (generate SIGIO)
    pub const O_ASYNC: u32 = 0o20000;
    /// Must be a directory / don't follow symlinks (values differ per arch)
    pub use crate::arch::uapi::{O_DIRECTORY, O_NOFOLLOW};
    /// Close on exec
    pub const O_CLOEXEC: u32 = 0o2000000;

    /// The *at() calls' dirfd for the current directory
    pub const AT_FDCWD: i32 = -100;
    /// Do not follow a final symlink
    pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    /// faccessat: check with the effective ids
    pub const AT_EACCESS: i32 = 0x200;
    /// unlinkat: remove a directory
    pub const AT_REMOVEDIR: i32 = 0x200;
    /// linkat: follow a final symlink
    pub const AT_SYMLINK_FOLLOW: i32 = 0x400;
    /// Do not automount a final component
    pub const AT_NO_AUTOMOUNT: i32 = 0x800;
    /// An empty path names dirfd itself
    pub const AT_EMPTY_PATH: i32 = 0x1000;
}

/// Seek whence values (for lseek)
pub mod seek {
    /// Seek from beginning of file
    pub const SEEK_SET: i32 = 0;
    /// Seek from current position
    pub const SEEK_CUR: i32 = 1;
    /// Seek from end of file
    pub const SEEK_END: i32 = 2;
    /// Next data at or after the offset / next hole
    pub const SEEK_DATA: i32 = 3;
    pub const SEEK_HOLE: i32 = 4;
}

/// Flags for read/write operations (preadv2/pwritev2 RWF_* flags)
#[derive(Debug, Clone, Copy, Default)]
pub struct RwFlags {
    /// RWF_NOWAIT - return EAGAIN if operation would block
    pub nowait: bool,
}

impl RwFlags {
    /// Create empty flags (no special behavior)
    pub const fn empty() -> Self {
        Self { nowait: false }
    }

    /// Create flags with NOWAIT set
    pub const fn with_nowait() -> Self {
        Self { nowait: true }
    }
}

/// Directory entry for getdents
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Inode number
    pub ino: InodeId,
    /// File type
    pub file_type: FileType,
    /// Entry name
    pub name: Vec<u8>,
}

/// Directory iteration state (Linux struct dir_context): `pos` is where
/// iteration starts and, after each accepted entry, the position just
/// past it (that entry's d_off). File systems hand entries to `emit_at`
/// (stable positions, increasing) or `emit` (the n-th entry of a fixed
/// listing order is position n); both skip entries before `pos` and
/// return false once the consumer is full.
pub struct DirContext<'a> {
    /// Current position (resume point)
    pub pos: u64,
    /// Position of the next `emit`
    next: u64,
    /// Consumer: entry and its d_off; false = no room, stop
    actor: &'a mut dyn FnMut(&DirEntry, u64) -> bool,
}

impl<'a> DirContext<'a> {
    /// Iterate from `pos`, feeding `actor`
    pub fn new(pos: u64, actor: &'a mut dyn FnMut(&DirEntry, u64) -> bool) -> Self {
        Self {
            pos,
            next: 0,
            actor,
        }
    }

    /// dir_emit of the entry at position `at`
    pub fn emit_at(&mut self, at: u64, e: DirEntry) -> bool {
        if at < self.pos {
            return true;
        }
        if !(self.actor)(&e, at + 1) {
            return false;
        }
        self.pos = at + 1;
        true
    }

    /// dir_emit of the next entry of a fixed listing order
    pub fn emit(&mut self, e: DirEntry) -> bool {
        let at = self.next;
        self.next += 1;
        self.emit_at(at, e)
    }
}

/// Seek in a file of `size` bytes (Linux generic_file_llseek_size with
/// the filesystem's s_maxbytes): the whole file is data, its end the
/// only hole; a position below 0 or past s_maxbytes is EINVAL, SEEK_DATA
/// / SEEK_HOLE at or past the end ENXIO
pub fn generic_llseek(
    file: &File,
    size: u64,
    offset: i64,
    whence: i32,
) -> Result<u64, KernelError> {
    let max = file.get_inode().map_or(i64::MAX as u64, |i| i.maxbytes());
    let new = match whence {
        seek::SEEK_SET => Some(offset),
        seek::SEEK_CUR => (file.get_pos() as i64).checked_add(offset),
        seek::SEEK_END => (size as i64).checked_add(offset),
        seek::SEEK_DATA | seek::SEEK_HOLE => {
            if offset < 0 || offset as u64 >= size {
                return Err(KernelError::NoDeviceOrAddress);
            }
            Some(if whence == seek::SEEK_DATA {
                offset
            } else {
                size as i64
            })
        }
        _ => return Err(KernelError::InvalidArgument),
    };
    // Linux vfs_setpos
    let pos = match new {
        Some(p) if p >= 0 && p as u64 <= max => p as u64,
        _ => return Err(KernelError::InvalidArgument),
    };
    file.set_pos(pos);
    Ok(pos)
}

/// For `read_iter`/`write_iter` of a file with neither a position nor
/// RWF_NOWAIT support (eventfd, sockets, ...): positioned I/O or
/// RWF_NOWAIT is EOPNOTSUPP, which the syscalls report as ESPIPE resp.
/// EOPNOTSUPP
pub fn stream_rw(at: Option<u64>, flags: RwFlags) -> Result<(), KernelError> {
    if at.is_some() || flags.nowait {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(())
}

/// The default `read_iter`/`write_iter`: no such operation is EINVAL
/// (Linux vfs_read without read_iter), and positioned I/O or RWF_NOWAIT
/// EOPNOTSUPP (the syscalls report ESPIPE resp. EOPNOTSUPP)
fn no_rw(at: Option<u64>, flags: RwFlags) -> Result<usize, KernelError> {
    if at.is_some() || flags.nowait {
        return Err(KernelError::OperationNotSupported);
    }
    Err(KernelError::InvalidArgument)
}

/// For `read_iter`/`write_iter` of a stream that Linux marks
/// FMODE_NOWAIT (eventfd, signalfd, timerfd, sockets): positioned I/O
/// is EOPNOTSUPP (ESPIPE at the syscall); RWF_NOWAIT makes this call
/// nonblocking. True if the call must not block.
pub fn nowait_rw(file: &File, at: Option<u64>, flags: RwFlags) -> Result<bool, KernelError> {
    if at.is_some() {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(flags.nowait || file.get_flags() & self::flags::O_NONBLOCK != 0)
}

/// File operations trait - filesystem-specific behavior for open files
pub trait FileOps: Send + Sync {
    /// Returns self as Any for downcasting to concrete types
    fn as_any(&self) -> &dyn core::any::Any;

    /// Called once when the file is opened, before the descriptor
    /// exists (Linux f_op->open): may refuse the open or set
    /// `file.private`
    fn open(&self, _file: &File) -> Result<(), KernelError> {
        Ok(())
    }

    /// Read into `to` at `at`, or at the file position (advancing it)
    /// when None (Linux f_op->read_iter). Data already copied wins over
    /// a later error. Default: EINVAL from read(2) (no read), ESPIPE
    /// positioned.
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let _ = (file, to);
        no_rw(at, flags)
    }

    /// Write from `from` at `at`, or at the file position (advancing it)
    /// when None (Linux f_op->write_iter); `File::write_iter` has taken
    /// i_rwsem, applied O_APPEND and the size limits. Default: EINVAL
    /// (no write), ESPIPE positioned.
    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let _ = (file, from);
        no_rw(at, flags)
    }

    /// Seek to a position
    fn llseek(&self, file: &File, offset: i64, whence: i32) -> Result<u64, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        generic_llseek(file, inode.get_size(), offset, whence)
    }

    /// Read directory entries from `ctx.pos` on (Linux iterate_shared)
    fn readdir(&self, file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
        let _ = (file, ctx);
        Err(KernelError::NotDirectory)
    }

    /// May the file be mapped (Linux: f_op->mmap exists and accepts
    /// it), shared or private? Default: no mmap, ENODEV from mmap(2)
    fn mmap(&self, _file: &File, _shared: bool) -> Result<(), KernelError> {
        Err(KernelError::NoDevice)
    }

    /// Sync file data to backing store
    fn fsync(&self, _file: &File) -> Result<(), KernelError> {
        Ok(())
    }

    /// A descriptor of the file is being closed (close, dup2 over it,
    /// close-on-exec, the closer's exit), in the closer's context (Linux
    /// f_op->flush): unlike `release`, on every close, not the last
    fn flush(&self, _file: &File) {}

    /// Release file (called when last reference is dropped)
    fn release(&self, _file: &File) -> Result<(), KernelError> {
        Ok(())
    }

    /// Put the file on (`on`) or take it off the object's SIGIO lists
    /// for descriptor `fd` (-1 at the last close), with
    /// `io::fasync::fasync_helper`, which keeps O_ASYNC (Linux
    /// f_op->fasync). None: the file has no fasync (F_SETFL drops
    /// O_ASYNC, FIOASYNC is ENOTTY).
    fn fasync(&self, _file: &File, _fd: i32, _on: bool) -> Option<Result<(), KernelError>> {
        None
    }

    /// Device/file-specific ioctl (Linux f_op->unlocked_ioctl), reached
    /// by `sys_ioctl` after the generic FIO* commands for files that are
    /// not block or character devices (e.g. sockets). Default: ENOTTY.
    fn ioctl(&self, _file: &File, _cmd: u32, _arg: u64) -> Result<i64, KernelError> {
        Err(KernelError::NotTty)
    }

    /// Poll for events (like f_op->poll in Linux)
    ///
    /// Returns mask of ready events (POLLIN, POLLOUT, etc.).
    /// Implementation should:
    /// 1. Call pt.poll_wait() to register on wait queues
    /// 2. Return current ready events mask
    ///
    /// Default: regular files are always readable and writable.
    fn poll(&self, _file: &File, _pt: Option<&mut PollTable<'_>>) -> u16 {
        // Default for regular files - always ready
        DEFAULT_POLLMASK
    }

    /// The file has a poll of its own (Linux file_can_poll: f_op->poll
    /// set): epoll accepts only these (EPERM otherwise); poll and select
    /// see `poll`'s DEFAULT_POLLMASK either way (Linux vfs_poll)
    fn can_poll(&self, _file: &File) -> bool {
        true
    }
}

/// Open file description
///
/// This struct mirrors Linux's `struct file`. It holds references to:
/// - The dentry (f_path.dentry in Linux)
/// - The mount (f_path.mnt in Linux) - increments mnt_count
/// - File position and operations
pub struct File {
    /// Dentry this file was opened from
    pub dentry: Arc<Dentry>,

    /// Mount this file belongs to (like Linux f_path.mnt)
    /// Holds a reference via mntget() - decremented on drop via mntput()
    mnt: Option<Arc<Mount>>,

    /// Current file position
    pos: AtomicU64,

    /// Serializes position updates of read/write/lseek/getdents on
    /// regular files and directories (Linux f_pos_lock, FMODE_ATOMIC_POS)
    f_pos_lock: sync::Mutex<()>,

    /// Open flags (protected by f_lock, like Linux)
    f_lock: Mutex<u32>,

    /// File operations
    pub f_op: &'static dyn FileOps,

    /// SIGIO owner (Linux f_owner), allocated on first use
    /// (`io::fasync`)
    pub(crate) f_owner: spin::Once<Arc<crate::io::fasync::FOwner>>,

    /// Write access to the file system while open for writing (Linux
    /// FMODE_WRITER): a read-only remount is EBUSY until it is released
    pub write_access: Option<super::superblock::WriteAccess>,
    /// The inode's write access (Linux FMODE_WRITER's get_write_access)
    pub i_write: Option<super::inode::InodeWrite>,

    /// Credentials of the opener (Linux file->f_cred): permission checks
    /// that must not be satisfied by whoever later uses the descriptor
    /// (confused deputy), e.g. netlink configuration requests
    pub f_cred: crate::task::Cred,

    /// Per-open state of the file's filesystem (Linux private_data), set
    /// at most once, by `FileOps::open`
    pub private: spin::Once<Arc<dyn core::any::Any + Send + Sync>>,

    /// The epoll items watching this file (Linux f_ep), removed at its
    /// last close (spin leaf)
    pub f_ep: Mutex<alloc::vec::Vec<alloc::sync::Weak<crate::io::epoll::EpItem>>>,
}

impl File {
    /// The file's mount is noexec (Linux path_noexec on f_path.mnt): the
    /// mount chosen when it was opened, in the opener's namespace, so a
    /// file passed to another namespace keeps it. A file with no mount
    /// (an internal object: pipe, memfd) is not noexec.
    pub fn noexec(&self) -> bool {
        self.mnt
            .as_ref()
            .is_some_and(|m| m.flags() & super::mount::MNT_NOEXEC != 0)
    }

    /// The file's path (Linux f_path); a file with no mount (an internal
    /// object) is placed in the namespace's root mount
    pub fn f_path(&self) -> Option<super::Path> {
        match &self.mnt {
            Some(m) => Some(super::Path::new(m.clone(), self.dentry.clone())),
            None => super::Path::from_dentry(self.dentry.clone()),
        }
    }

    /// Write access to what the file is on, through its mount (Linux
    /// mnt_want_write_file); an internal file only checks its superblock
    pub fn want_write(&self) -> Result<super::superblock::WriteAccess, KernelError> {
        match (&self.mnt, self.dentry.get_inode()) {
            (Some(m), _) => m.want_write(),
            (None, Some(i)) => super::dac::want_write(&i),
            (None, None) => Ok(super::superblock::WriteAccess::none()),
        }
    }

    /// Create a new file on `dentry` in mount `mnt` (None: an internal
    /// object), counted in the mount's mnt_count (mntget) so it cannot
    /// be unmounted while this file is open
    pub fn new(
        dentry: Arc<Dentry>,
        mnt: Option<Arc<Mount>>,
        flags: u32,
        f_op: &'static dyn FileOps,
    ) -> Self {
        if let Some(ref m) = mnt {
            m.mntget();
        }

        Self {
            dentry,
            mnt,
            pos: AtomicU64::new(0),
            f_pos_lock: sync::Mutex::new(()),
            f_ep: Mutex::new(alloc::vec::Vec::new()),
            f_lock: Mutex::new(flags),
            f_op,
            f_owner: spin::Once::new(),
            write_access: None,
            i_write: None,
            f_cred: crate::task::current_cred(),
            private: spin::Once::new(),
        }
    }

    /// An anonymous-inode file whose shared state lives in `private`
    /// (Linux anon_inode_getfile priv): the ops stay static, and the
    /// state goes with the last reference to the file
    pub fn new_anon(
        dentry: Arc<Dentry>,
        flags: u32,
        f_op: &'static dyn FileOps,
        private: Arc<dyn core::any::Any + Send + Sync>,
    ) -> Self {
        let f = Self::new(dentry, None, flags, f_op);
        f.private.call_once(|| private);
        f
    }

    /// The per-open state, if it is a `T`
    pub fn private_ref<T: core::any::Any>(&self) -> Option<&T> {
        self.private.get()?.downcast_ref::<T>()
    }

    /// A reference to the per-open state, if it is a `T`
    pub fn private_arc<T: core::any::Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.private.get()?.clone().downcast::<T>().ok()
    }

    /// The inode whose page cache holds the file's data (Linux
    /// f_mapping->host): a block device node's is the device's bdev
    /// inode, every other file's its own
    pub fn mapping_inode(&self) -> Option<Arc<Inode>> {
        if let Some(b) = self.private_ref::<crate::block::BlockDevice>() {
            return Some(b.bd_inode.clone());
        }
        self.get_inode()
    }

    /// Get the inode for this file
    pub fn get_inode(&self) -> Option<Arc<Inode>> {
        self.dentry.get_inode()
    }

    /// Get current file position
    pub fn get_pos(&self) -> u64 {
        self.pos.load(Ordering::Relaxed)
    }

    /// Set file position
    pub fn set_pos(&self, pos: u64) {
        self.pos.store(pos, Ordering::Relaxed);
    }

    /// Take f_pos_lock for a position-based syscall (Linux fdget_pos):
    /// only regular files and directories need it (FMODE_ATOMIC_POS)
    pub fn pos_lock(&self) -> Option<sync::MutexGuard<'_, ()>> {
        let m = self.get_inode()?.mode();
        (m.is_file() || m.is_dir()).then(|| self.f_pos_lock.lock())
    }

    /// Advance file position by n bytes
    pub fn advance_pos(&self, n: u64) -> u64 {
        self.pos.fetch_add(n, Ordering::Relaxed)
    }

    /// Get current flags
    pub fn get_flags(&self) -> u32 {
        *self.f_lock.lock()
    }

    /// Set status flags (for F_SETFL)
    ///
    /// Only O_APPEND, O_NONBLOCK and O_NOATIME can be modified. Access
    /// mode is preserved.
    pub fn set_status_flags(&self, new_status: u32) {
        const SETTABLE_FLAGS: u32 = flags::O_APPEND | flags::O_NONBLOCK | super::dac::O_NOATIME;
        let mut guard = self.f_lock.lock();
        *guard = (*guard & !SETTABLE_FLAGS) | (new_status & SETTABLE_FLAGS);
    }

    /// Check if file is readable
    pub fn is_readable(&self) -> bool {
        let mode = self.get_flags() & flags::O_ACCMODE;
        mode == flags::O_RDONLY || mode == flags::O_RDWR
    }

    /// Check if file is writable
    pub fn is_writable(&self) -> bool {
        let mode = self.get_flags() & flags::O_ACCMODE;
        mode == flags::O_WRONLY || mode == flags::O_RDWR
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.get_inode().map(|i| i.mode().is_dir()).unwrap_or(false)
    }

    /// Get the file operations
    pub fn ops(&self) -> &'static dyn FileOps {
        self.f_op
    }

    /// Set or clear O_ASYNC: only `io::fasync::fasync_helper`, with the
    /// list change, so the flag means "on a fasync list" (Linux
    /// fasync_insert_entry under f_lock)
    pub(crate) fn set_fasync_flag(&self, on: bool) {
        let mut fl = self.f_lock.lock();
        if on {
            *fl |= flags::O_ASYNC;
        } else {
            *fl &= !flags::O_ASYNC;
        }
    }

    /// Turn O_ASYNC on or off for descriptor `fd` (F_SETFL, FIOASYNC)
    /// through `->fasync`: None if the file has none
    pub fn fasync(&self, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        self.f_op.fasync(self, fd, on)
    }

    /// Read from file
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, KernelError> {
        self.read_iter(&mut IovDest::kernel(buf), None, RwFlags::empty())
    }

    /// Read into `to` at `at` (None: the file position, which advances)
    /// (Linux vfs_read / vfs_iter_read)
    pub fn read_iter(
        &self,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        if !self.is_readable() {
            return Err(KernelError::PermissionDenied);
        }
        let want = !to.is_empty();
        let r = self.f_op.read_iter(self, to, at, flags);
        // A regular file read asking for data (Linux filemap_read)
        if want && let Some(i) = self.get_inode().filter(|i| i.mode().is_file()) {
            self.accessed(&i);
        }
        r
    }

    /// An access of the file's data (Linux file_accessed): its atime,
    /// unless opened O_NOATIME or reached without a mount
    pub fn accessed(&self, inode: &Inode) {
        if self.get_flags() & super::dac::O_NOATIME != 0 {
            return;
        }
        if let Some(m) = &self.mnt {
            inode.touch_atime(m);
        }
    }

    /// Write at the file position
    pub fn write(&self, buf: &[u8]) -> Result<usize, KernelError> {
        self.write_at(buf, None, RwFlags::empty(), None)
    }

    /// Positioned read - read at given offset without modifying file position
    pub fn pread(&self, buf: &mut [u8], offset: u64) -> Result<usize, KernelError> {
        self.read_iter(&mut IovDest::kernel(buf), Some(offset), RwFlags::empty())
    }

    /// Positioned write (the file position is not used or changed)
    pub fn pwrite(&self, buf: &[u8], offset: u64) -> Result<usize, KernelError> {
        self.write_at(buf, Some(offset), RwFlags::empty(), None)
    }

    /// Read with RWF flags (for preadv2/pwritev2 with RWF_NOWAIT support)
    pub fn read_with_flags(&self, buf: &mut [u8], flags: RwFlags) -> Result<usize, KernelError> {
        self.read_iter(&mut IovDest::kernel(buf), None, flags)
    }

    /// Positioned read with RWF flags
    pub fn pread_with_flags(
        &self,
        buf: &mut [u8],
        offset: u64,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        self.read_iter(&mut IovDest::kernel(buf), Some(offset), flags)
    }

    /// Write `buf` at `at` (None: the file position, which advances);
    /// see [`File::write_iter`]
    pub fn write_at(
        &self,
        buf: &[u8],
        at: Option<u64>,
        flags: RwFlags,
        append: Option<bool>,
    ) -> Result<usize, KernelError> {
        self.write_iter(&mut IovSource::kernel(buf), at, flags, append)
    }

    /// Write `from` at `at` (None: the file position, which advances)
    /// (Linux vfs_write + generic_file_write_iter). Regular files are
    /// written under the inode's
    /// i_rwsem, held across all chunks: in append mode (`append`:
    /// RWF_APPEND / RWF_NOAPPEND, None = the file's O_APPEND) the data
    /// goes to the current end of file, also for pwrite (Linux), and
    /// position, data and new size change atomically with respect to
    /// other writers and truncate. A short chunk ends the write; an
    /// error after some bytes were written returns their count (Linux).
    pub fn write_iter(
        &self,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        flags: RwFlags,
        append: Option<bool>,
    ) -> Result<usize, KernelError> {
        if !self.is_writable() {
            return Err(KernelError::PermissionDenied);
        }
        let inode = match self.get_inode() {
            Some(i) if i.mode().is_file() => i,
            _ => return self.f_op.write_iter(self, from, at, flags),
        };
        let append = append.unwrap_or(self.get_flags() & flags::O_APPEND != 0);
        let lock = inode.lock();
        let n = (|| {
            // An active swap file (Linux generic_write_checks:
            // IS_SWAPFILE), checked under i_rwsem: swapon sets it there
            if inode.i_swapfile.load(Ordering::Acquire) {
                return Err(KernelError::TextBusy);
            }
            let at = match (append, at) {
                (true, None) => {
                    self.set_pos(inode.get_size());
                    None
                }
                (true, Some(_)) => Some(inode.get_size()),
                (false, at) => at,
            };
            let pos = at.unwrap_or_else(|| self.get_pos());
            // A zero-length write checks nothing (Linux: count 0 returns
            // before generic_write_checks)
            if from.is_empty() {
                return Ok(0);
            }
            from.truncate(inode.write_limit(pos, from.len())?);
            // file_modified: set-id bits go unless CAP_FSETID, then
            // mtime and ctime, before the data
            super::dac::remove_privs(&inode);
            inode.touch_mc();
            self.f_op.write_iter(self, from, at, flags)
        })()?;
        drop(lock);
        // O_DSYNC/O_SYNC or a synchronous mount: the data reaches the
        // storage before the write returns (Linux generic_write_sync,
        // after i_rwsem is released)
        // Only a write that wrote, and the superblock only without O_DSYNC
        let sync = || {
            self.get_flags() & flags::O_DSYNC != 0
                || inode.superblock().is_some_and(|sb| sb.synchronous())
        };
        if n > 0 && sync() {
            self.f_op.fsync(self)?;
        }
        Ok(n)
    }

    /// Seek
    pub fn lseek(&self, offset: i64, whence: i32) -> Result<u64, KernelError> {
        self.f_op.llseek(self, offset, whence)
    }

    /// Read directory entries
    pub fn readdir(&self, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
        if !self.is_dir() {
            return Err(KernelError::NotDirectory);
        }
        let r = self.f_op.readdir(self, ctx);
        // Linux iterate_dir: a directory not yet removed
        if let Some(i) = self.get_inode().filter(|i| !i.is_dead()) {
            self.accessed(&i);
        }
        r
    }

    /// Poll for events
    ///
    /// Returns mask of ready events (POLLIN, POLLOUT, etc.)
    pub fn poll(&self, pt: Option<&mut PollTable<'_>>) -> u16 {
        self.f_op.poll(self, pt)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // Leave every epoll first, while the wait queues the items are
        // registered on still exist (Linux __fput -> eventpoll_release)
        if !self.f_ep.lock().is_empty() {
            crate::io::epoll::eventpoll_release(self);
        }
        // Off every SIGIO list (Linux __fput: ->fasync(-1, file, 0))
        if self.get_flags() & flags::O_ASYNC != 0 {
            let _ = self.f_op.fasync(self, -1, false);
        }
        // Call release on file operations to allow cleanup (e.g., decrement pipe reader/writer counts)
        let _ = self.f_op.release(self);

        // The open file description is gone: its flock locks go (Linux
        // __fput -> locks_remove_file). POSIX locks are the closer's,
        // released at each close (fdtable::FilesGuard), not here (this
        // may run in another process's context)
        super::flock::release_file_locks(self);

        // Decrement mount reference count via mntput
        // This mirrors Linux's fput() -> mntput()
        if let Some(ref mnt) = self.mnt {
            mnt.mntput();
        }
    }
}

/// FIONREAD (Linux ioctl number): bytes ready to read
pub const FIONREAD: u32 = 0x541B;

/// Answer FIONREAD with `n` as the user's int (Linux put_user to an
/// `int __user *`, truncating)
pub fn put_fionread(arg: u64, n: i64) -> Result<i64, KernelError> {
    crate::uaccess::put_user::<crate::arch::Uaccess, i32>(arg, n as i32)
        .map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

/// Null file ops - returns errors for all operations
pub struct NullFileOps;

impl FileOps for NullFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read_iter(
        &self,
        _file: &File,
        _to: &mut IovDest<'_>,
        _at: Option<u64>,
        _flags: RwFlags,
    ) -> Result<usize, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    fn write_iter(
        &self,
        _file: &File,
        _from: &mut IovSource<'_>,
        _at: Option<u64>,
        _flags: RwFlags,
    ) -> Result<usize, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    fn poll(&self, _file: &File, _pt: Option<&mut PollTable<'_>>) -> u16 {
        POLLERR
    }
}

/// Static null file ops
pub static NULL_FILE_OPS: NullFileOps = NullFileOps;

// ============================================================================
// Character Device File Operations
// ============================================================================

use crate::fs::chardev::{CharDevice, get_chardev};

/// Character device file operations.
///
/// Routes VFS file operations to the CharDevice trait via the chardev registry.
/// Device is looked up by major/minor stored in the inode's rdev field.
pub struct CharDevFileOps;

impl CharDevFileOps {
    /// The device `file` was opened on (ENXIO once it is unregistered)
    fn dev(file: &File) -> Result<Arc<dyn CharDevice>, KernelError> {
        let inode = file.get_inode().ok_or(KernelError::BadFd)?;
        get_chardev(inode.rdev).ok_or(KernelError::NoDeviceOrAddress)
    }
}

impl FileOps for CharDevFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn open(&self, file: &File) -> Result<(), KernelError> {
        Self::dev(file)?.open(file)
    }

    fn release(&self, file: &File) -> Result<(), KernelError> {
        if let Ok(d) = Self::dev(file) {
            d.release(file);
        }
        Ok(())
    }

    fn mmap(&self, file: &File, _shared: bool) -> Result<(), KernelError> {
        match Self::dev(file) {
            Ok(d) if d.mmap_ok() => Ok(()),
            _ => Err(KernelError::NoDevice),
        }
    }

    /// Positioned I/O only for a positional device (else ESPIPE from
    /// pread), no RWF_NOWAIT
    fn read_iter(
        &self,
        file: &File,
        to: &mut IovDest<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let dev = Self::dev(file)?;
        if (at.is_some() && !dev.positional()) || flags.nowait {
            return Err(KernelError::OperationNotSupported);
        }
        dev.read(file, to)
    }

    /// As read_iter (ESPIPE from pwrite for a stream)
    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        at: Option<u64>,
        flags: RwFlags,
    ) -> Result<usize, KernelError> {
        let dev = Self::dev(file)?;
        if (at.is_some() && !dev.positional()) || flags.nowait {
            return Err(KernelError::OperationNotSupported);
        }
        dev.write(file, from)
    }

    /// The device's (Linux: ESPIPE without f_op->llseek)
    fn llseek(&self, file: &File, offset: i64, whence: i32) -> Result<u64, KernelError> {
        Self::dev(file)?.llseek(file, offset, whence)
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<i64, KernelError> {
        Self::dev(file)?.ioctl(file, cmd, arg)
    }

    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        match Self::dev(file) {
            Ok(d) => d.poll(file, pt),
            Err(_) => POLLHUP | POLLERR,
        }
    }

    fn can_poll(&self, file: &File) -> bool {
        Self::dev(file).is_ok_and(|d| d.can_poll())
    }
}

/// Static character device file ops
pub static CHAR_FILE_OPS: CharDevFileOps = CharDevFileOps;

// ============================================================================
// Generic Page-Cache File Operations
// ============================================================================

/// A descriptor of `file` in the table whose lock-owner identity is
/// `owner` was closed (Linux filp_flush): that owner's POSIX locks on
/// the inode go, then the file's own flush
pub fn filp_flush(file: &File, owner: u64) {
    crate::fs::posix_lock::release_posix_locks_on_close(file, owner);
    file.f_op.flush(file);
}
