//! File - open file description
//!
//! A File represents an open file handle. Multiple file descriptors
//! can point to the same file (e.g., after dup()).
//!
//! Page-cache file I/O is `mm::filemap` (read_iter, write_iter).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::spin::Mutex;
use ::core::mem::ManuallyDrop;
use ::core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};

use crate::sync;

use super::KernelError;
use super::dentry::DentryRef;
use super::inode::{FileType, Inode, InodeId};
use super::iov_iter::{IovDest, IovSource};
use super::mount::MountRef;
use crate::io::poll::{DEFAULT_POLLMASK, POLLERR, POLLHUP, PollTable};
use crate::sync::IrqSpinlock;
use crate::task::task_work::{CallbackHead, CbAdapter, Twa, task_work_add};
use crate::task::workqueue::{DelayedWork, SYSTEM_WQ};
use crate::util::list::List;

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
    pub use crate::arch::uapi::{O_DIRECT, O_DIRECTORY, O_LARGEFILE, O_NOFOLLOW};
    /// Don't update the access time
    pub const O_NOATIME: u32 = 0o1000000;
    /// Close on exec
    pub const O_CLOEXEC: u32 = 0o2000000;
    /// File integrity sync (O_SYNC is it with O_DSYNC)
    pub const __O_SYNC: u32 = 0o4000000;
    /// A path-only file: a place in the tree, no I/O (asm-generic,
    /// both arches)
    pub const O_PATH: u32 = 0o10000000;
    /// An empty path names dirfd itself (asm-generic, both arches;
    /// Linux 7.2 LOOKUP_EMPTY)
    pub const O_EMPTYPATH: u32 = 1 << 26;
    /// An unnamed file in the directory named (asm-generic __O_TMPFILE;
    /// O_TMPFILE is it with O_DIRECTORY)
    pub const __O_TMPFILE: u32 = 0o20000000;

    /// Every flag open(2) knows (Linux VALID_OPEN_FLAGS; O_NDELAY is
    /// O_NONBLOCK); the old calls drop the rest
    pub const VALID_OPEN_FLAGS: u32 = O_ACCMODE
        | O_CREAT
        | O_EXCL
        | O_NOCTTY
        | O_TRUNC
        | O_APPEND
        | O_NONBLOCK
        | __O_SYNC
        | O_DSYNC
        | O_ASYNC
        | O_DIRECT
        | O_LARGEFILE
        | O_DIRECTORY
        | O_NOFOLLOW
        | O_NOATIME
        | O_CLOEXEC
        | O_PATH
        | __O_TMPFILE
        | O_EMPTYPATH;

    /// What O_PATH keeps (Linux O_PATH_FLAGS)
    pub const O_PATH_FLAGS: u32 = O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC | O_EMPTYPATH;

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

bitflags::bitflags! {
    /// Flags of one read or write (Linux kiocb ki_flags, IOCB_*): the
    /// file's own (`File::iocb_flags`, from O_APPEND, O_DIRECT,
    /// O_DSYNC, __O_SYNC) and the call's RWF_* ones; the values are
    /// Linux's, where the RWF_* flags share them
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct RwFlags: u32 {
        /// RWF_HIPRI: poll for completion
        const HIPRI = 1 << 0;
        /// O_DSYNC / RWF_DSYNC: the data reaches storage before return
        const DSYNC = 1 << 1;
        /// __O_SYNC / RWF_SYNC: the file's metadata too
        const SYNC = 1 << 2;
        /// RWF_NOWAIT: EAGAIN rather than block
        const NOWAIT = 1 << 3;
        /// O_APPEND
        const APPEND = 1 << 4;
        /// O_DIRECT: bypass the page cache
        const DIRECT = 1 << 17;
    }
}

impl RwFlags {
    /// RWF_NOWAIT
    #[inline]
    pub const fn nowait(self) -> bool {
        self.contains(Self::NOWAIT)
    }

    /// The file flags' part (Linux iocb_flags)
    pub const fn from_file(f: u32) -> Self {
        let mut r = Self::empty();
        if f & flags::O_APPEND != 0 {
            r = r.union(Self::APPEND);
        }
        if f & flags::O_DIRECT != 0 {
            r = r.union(Self::DIRECT);
        }
        if f & flags::O_DSYNC != 0 {
            r = r.union(Self::DSYNC);
        }
        if f & flags::__O_SYNC != 0 {
            r = r.union(Self::SYNC);
        }
        r
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
    if at.is_some() || flags.nowait() {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(())
}

/// The default `read_iter`/`write_iter`: no such operation is EINVAL
/// (Linux vfs_read without read_iter), and positioned I/O or RWF_NOWAIT
/// EOPNOTSUPP (the syscalls report ESPIPE resp. EOPNOTSUPP)
fn no_rw(at: Option<u64>, flags: RwFlags) -> Result<usize, KernelError> {
    if at.is_some() || flags.nowait() {
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
    Ok(flags.nowait() || file.get_flags() & self::flags::O_NONBLOCK != 0)
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

    /// May a mapping start at byte `off` of the file (Linux f_op->mmap
    /// looking at vm_pgoff, e.g. io_uring_validate_mmap_request)? Asked
    /// after `mmap` accepted the mapping. Default: any offset.
    fn mmap_offset(&self, _file: &File, _off: u64) -> Result<(), KernelError> {
        Ok(())
    }

    /// A mapping of the file in address space `mm` moved to `start`,
    /// `len` bytes, by mremap (Linux vm_ops->mremap, which has the vma's
    /// vm_mm), before its entries move, the mmap_lock held for writing;
    /// an error refuses the move. Default: any move.
    fn mremap(
        &self,
        _file: &File,
        _mm: &crate::mm::Mm,
        _start: u64,
        _len: u64,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    /// The file's mappings are its driver's pages, inserted at mmap
    /// (`map_page`; Linux vm_insert_pages from f_op->mmap). Default: no.
    fn maps_driver_pages(&self, _file: &File) -> bool {
        false
    }

    /// The kernel page that page `idx` of a mapping made at byte `off`
    /// of the file maps, with a reference taken for its PTE (Linux
    /// vm_insert_pages from f_op->mmap: pages of the driver, not of a
    /// page cache); None past the driver's pages. Asked at mmap, only
    /// for a file that `maps_driver_pages`.
    ///
    /// # Safety
    /// The caller maps the page into user space with the reference
    /// taken here and drops that reference when the mapping goes. The
    /// implementor returns a RAM frame that stays allocated while the
    /// reference is held and holds nothing but what user space may
    /// read and write.
    unsafe fn map_page(
        &self,
        _file: &File,
        _off: u64,
        _idx: u64,
    ) -> Option<Result<u64, KernelError>> {
        None
    }

    /// Sync file data to backing store
    fn fsync(&self, _file: &File) -> Result<(), KernelError> {
        Ok(())
    }

    /// Sync the data of bytes [start, end] (Linux f_op->fsync with a
    /// range, from generic_write_sync); default: the whole file
    fn fsync_range(&self, file: &File, start: u64, end: u64) -> Result<(), KernelError> {
        let _ = (start, end);
        self.fsync(file)
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

    /// O_DIRECT I/O on `file` can be started without waiting
    /// (`dio_submit`; Linux: ->read_iter/->write_iter return -EIOCBQUEUED
    /// for an async IOCB_DIRECT kiocb). Default: no.
    fn can_async_dio(&self, _file: &File) -> bool {
        false
    }

    /// Start O_DIRECT I/O of `io`'s pinned memory at `pos`, a read from
    /// the file or (`write`) a write to it, with the I/O flags `flags`
    /// (the request's whole: the file's and its RWF_* ones, APPEND as
    /// RWF_APPEND / RWF_NOAPPEND left it; Linux ki_flags) (Linux
    /// blkdev_direct_IO on an async kiocb): Ok(None) when queued
    /// (`io` completes later, from any context), Ok(Some(n)) when done at
    /// once (n bytes: nothing to do, the end of the file); an error means
    /// nothing was started (EAGAIN with RWF_NOWAIT where it would wait).
    /// Only called when `can_async_dio`; `io` holds `file` until it
    /// completes (an implementation may drop its own references to the
    /// file's inode in `complete`, any context, knowing they are not the
    /// last).
    fn dio_submit(
        &self,
        _file: &File,
        _io: Arc<dyn crate::block::dio::AsyncIo>,
        _pos: u64,
        _write: bool,
        _flags: RwFlags,
    ) -> Result<Option<usize>, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    /// Polled I/O of the file can be reaped (`iopoll`; Linux
    /// f_op->iopoll is set). Default: no.
    fn can_iopoll(&self, _file: &File) -> bool {
        false
    }

    /// Reap polled I/O of the file once (Linux f_op->iopoll): whether
    /// anything ended. Default: nothing to poll.
    fn iopoll(&self, _file: &File) -> bool {
        false
    }

    /// O_DIRECT may be set on `file`, asked once at the end of its open
    /// (Linux FMODE_CAN_ODIRECT: the mapping has ->direct_IO, or ->open
    /// sets it). Default: no.
    fn can_odirect(&self, _file: &File) -> bool {
        false
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
/// - The mount (f_path.mnt in Linux), a user of it while open
/// - File position and operations
pub struct File {
    /// Dentry this file was opened from
    pub dentry: DentryRef,

    /// Mount this file belongs to (Linux f_path.mnt): a reference, which
    /// makes the mount busy for umount
    mnt: Option<MountRef>,

    /// Current file position
    pos: AtomicU64,

    /// Serializes position updates of read/write/lseek/getdents on
    /// regular files and directories (Linux f_pos_lock, FMODE_ATOMIC_POS)
    f_pos_lock: sync::Mutex<()>,

    /// Open flags (protected by f_lock, like Linux)
    f_lock: Mutex<u32>,

    /// The flags' I/O part (Linux f_iocb_flags, `RwFlags::from_file`):
    /// written under `f_lock` with the flags, read lock-free by each
    /// read and write (a racing F_SETFL may or may not apply to an I/O
    /// already started, as in Linux)
    f_iocb: AtomicU32,

    /// O_DIRECT may be set (Linux FMODE_CAN_ODIRECT): fixed by
    /// `open::dentry_open` from `FileOps::can_odirect`; false for a file
    /// made without an open (memfd, pipe, socket)
    can_odirect: bool,

    /// File operations
    pub f_op: &'static dyn FileOps,

    /// Opened O_PATH (Linux FMODE_PATH): fixed at open
    path_only: bool,

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

    /// The epoll items watching this file (Linux f_ep), linked through
    /// their `fllink` (no allocation), removed at its last close (spin
    /// leaf)
    pub f_ep: Mutex<crate::util::list::ArcList<crate::io::epoll::FlAdapter>>,

    /// The writeback errors of its mapping and filesystem it has seen
    /// (Linux f_wb_err, f_sb_err): sampled at open, advanced by fsync
    /// and syncfs under `f_lock`, read lock-free
    f_wb_err: AtomicU32,
    f_sb_err: AtomicU32,

    /// References (Linux f_ref): one per [`FileRef`]; the last one's
    /// drop releases the file (`fput`), and [`FILE_REF_DEAD`] marks it
    /// released. Atomic like Arc's count: taken and dropped lock-free
    /// from any context.
    f_count: AtomicUsize,

    /// Queues the release on a task or the delayed list (Linux
    /// f_task_work / f_llist): on one list at a time, once
    f_task_work: CallbackHead,
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
    /// object), whose reference keeps the mount busy for umount while
    /// this file is open
    pub fn new(
        dentry: DentryRef,
        mnt: Option<MountRef>,
        flags: u32,
        f_op: &'static dyn FileOps,
    ) -> Self {
        Self {
            dentry,
            mnt,
            pos: AtomicU64::new(0),
            f_pos_lock: sync::Mutex::new(()),
            f_ep: Mutex::new(crate::util::list::ArcList::new()),
            f_lock: Mutex::new(flags),
            f_iocb: AtomicU32::new(RwFlags::from_file(flags).bits()),
            can_odirect: false,
            f_op,
            path_only: flags & flags::O_PATH != 0,
            f_owner: spin::Once::new(),
            write_access: None,
            i_write: None,
            f_cred: crate::task::current_cred(),
            private: spin::Once::new(),
            f_wb_err: AtomicU32::new(0),
            f_sb_err: AtomicU32::new(0),
            f_count: AtomicUsize::new(0),
            f_task_work: CallbackHead::new(____fput),
        }
        .sampled()
    }

    /// With the writeback errors of its mapping and filesystem sampled
    /// (Linux do_dentry_open: filemap_sample_wb_err, file_sample_sb_err)
    fn sampled(self) -> Self {
        self.sample_wb_err();
        self
    }

    /// Sample its mapping's and filesystem's writeback errors: what came
    /// before (and was seen) is not this file's to report (Linux
    /// do_dentry_open; again after ->open, which may change the mapping:
    /// blkdev_open)
    pub fn sample_wb_err(&self) {
        if let Some(i) = self.mapping_inode() {
            self.f_wb_err
                .store(i.i_data.wb_err.sample(), Ordering::Relaxed);
        }
        if let Some(sb) = self.dentry.get_inode().and_then(|i| i.superblock()) {
            self.f_sb_err.store(sb.s_wb_err.sample(), Ordering::Relaxed);
        }
    }

    /// A writeback error of its mapping since it last looked, once
    /// (Linux file_check_and_advance_wb_err)
    pub fn check_and_advance_wb_err(&self) -> Result<(), KernelError> {
        let Some(i) = self.mapping_inode() else {
            return Ok(());
        };
        advance(&i.i_data.wb_err, &self.f_wb_err, &self.f_lock)
    }

    /// A writeback error of its filesystem since it last looked, once
    /// (Linux syncfs: errseq_check_and_advance of s_wb_err, f_sb_err)
    pub fn check_and_advance_sb_err(&self) -> Result<(), KernelError> {
        let Some(sb) = self.dentry.get_inode().and_then(|i| i.superblock()) else {
            return Ok(());
        };
        advance(&sb.s_wb_err, &self.f_sb_err, &self.f_lock)
    }

    /// A file whose shared state lives in `private` (Linux
    /// anon_inode_getfile priv, alloc_file_pseudo): the ops stay static,
    /// and the state goes with the last reference to the file; `mnt` is
    /// its pseudo filesystem's mount
    pub fn new_anon(
        dentry: DentryRef,
        mnt: Option<MountRef>,
        flags: u32,
        f_op: &'static dyn FileOps,
        private: Arc<dyn core::any::Any + Send + Sync>,
    ) -> Self {
        let f = Self::new(dentry, mnt, flags, f_op);
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

    /// Drop open-only flags before the file is shared (Linux
    /// do_dentry_open's f_flags strip)
    pub fn clear_flags(&mut self, f: u32) {
        *self.f_lock.get_mut() &= !f;
    }

    /// Get current flags
    pub fn get_flags(&self) -> u32 {
        *self.f_lock.lock()
    }

    /// Set the status flags F_SETFL may change (Linux SETFL_MASK:
    /// O_APPEND, O_NONBLOCK, O_DIRECT, O_NOATIME), the I/O flags with
    /// them under `f_lock` (Linux setfl)
    pub fn set_status_flags(&self, new_status: u32) {
        const SETFL_MASK: u32 =
            flags::O_APPEND | flags::O_NONBLOCK | flags::O_DIRECT | super::dac::O_NOATIME;
        let mut guard = self.f_lock.lock();
        *guard = (*guard & !SETFL_MASK) | (new_status & SETFL_MASK);
        self.f_iocb
            .store(RwFlags::from_file(*guard).bits(), Ordering::Relaxed);
    }

    /// The file's I/O flags (Linux f_iocb_flags)
    #[inline]
    pub fn iocb_flags(&self) -> RwFlags {
        RwFlags::from_bits_retain(self.f_iocb.load(Ordering::Relaxed))
    }

    /// O_DIRECT may be set on the file (Linux FMODE_CAN_ODIRECT)
    #[inline]
    pub fn can_odirect(&self) -> bool {
        self.can_odirect
    }

    /// Fix FMODE_CAN_ODIRECT at the end of the open, before the file is
    /// shared (`open::dentry_open`)
    pub fn set_can_odirect(&mut self) {
        self.can_odirect = self.f_op.can_odirect(self);
    }

    /// A path-only (O_PATH) file (Linux FMODE_PATH): it names a place
    /// in the tree, for *at() calls, fstat, fchdir, dup; every other use
    /// of the descriptor is EBADF
    #[inline]
    pub fn is_path(&self) -> bool {
        self.path_only
    }

    /// Check if file is readable
    pub fn is_readable(&self) -> bool {
        if self.path_only {
            return false;
        }
        let mode = self.get_flags() & flags::O_ACCMODE;
        mode == flags::O_RDONLY || mode == flags::O_RDWR
    }

    /// Check if file is writable
    pub fn is_writable(&self) -> bool {
        if self.path_only {
            return false;
        }
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

    /// The file's flags under `f_lock` (Linux filp->f_lock), for
    /// `io::fasync::fasync_helper`, which sets or clears O_ASYNC with the
    /// list change under it, so the flag means "on a fasync list" (Linux
    /// fasync_insert_entry / fasync_remove_entry)
    pub(crate) fn f_lock(&self) -> crate::sync::spin::MutexGuard<'_, u32> {
        self.f_lock.lock()
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
        let flags = flags | self.iocb_flags();
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
        let flags = flags | self.iocb_flags();
        let inode = match self.get_inode() {
            Some(i) if i.mode().is_file() => i,
            _ => return self.f_op.write_iter(self, from, at, flags),
        };
        let append = append.unwrap_or(flags.contains(RwFlags::APPEND));
        let lock = inode.lock();
        let (pos, n) = (|| {
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
                return Ok((pos, 0));
            }
            from.truncate(inode.write_limit(pos, from.len())?);
            // file_modified: set-id bits go unless CAP_FSETID, then
            // mtime and ctime, before the data
            super::dac::remove_privs(&inode);
            inode.touch_mc();
            self.f_op
                .write_iter(self, from, at, flags)
                .map(|n| (pos, n))
        })()?;
        drop(lock);
        // After i_rwsem is released; a synchronous mount is Linux IS_SYNC
        let sync =
            flags.contains(RwFlags::DSYNC) || inode.superblock().is_some_and(|sb| sb.synchronous());
        generic_write_sync(self, pos, n, sync)
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

/// Check `seq` against the file's `since` and advance it (lock-free when
/// nothing changed, else under the file's `f_lock`: Linux
/// file_check_and_advance_wb_err)
fn advance(
    seq: &crate::util::errseq::ErrSeq,
    since: &AtomicU32,
    lock: &Mutex<u32>,
) -> Result<(), KernelError> {
    if seq.check(since.load(Ordering::Relaxed)).is_none() {
        return Ok(());
    }
    let _g = lock.lock();
    let mut s = since.load(Ordering::Relaxed);
    let e = seq.check_and_advance(&mut s);
    since.store(s, Ordering::Relaxed);
    e.map_or(Ok(()), Err)
}

impl File {
    /// Release the open file description (Linux __fput): its last
    /// reference went, in a context that may sleep with nothing held
    fn __fput(&self) {
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
        // released at each close (fdtable `filp_close`), not here (this
        // may run in another process's context)
        super::flock::release_file_locks(self);

        // A use of the mount ended: an MNT_EXPIRE mark goes (Linux
        // __fput's mntput)
        if let Some(ref mnt) = self.mnt {
            mnt.clear_expiry();
        }
    }

    /// Give the new file its first reference (Linux alloc_empty_file's
    /// f_ref of one): the one way to a [`FileRef`]; ENOMEM
    pub fn alloc(mut self) -> Result<FileRef, KernelError> {
        *self.f_count.get_mut() = 1;
        crate::util::kalloc::try_arc(self).map(|f| FileRef(ManuallyDrop::new(f)))
    }
}

/// A file never given a reference (dropped before `alloc`: an open that
/// failed) is released here; one that had them was by its last `fput`
/// (`FILE_REF_DEAD`), whoever drops the memory
impl Drop for File {
    fn drop(&mut self) {
        if *self.f_count.get_mut() != FILE_REF_DEAD {
            self.__fput();
        }
    }
}

/// `File.f_count` once the file is released (Linux FILE_REF_DEAD): no
/// reference can be taken again
const FILE_REF_DEAD: usize = usize::MAX;

/// A counted reference to an open file (Linux a `struct file *` holding
/// f_ref): descriptors, mappings, in-flight messages and requests. A
/// clone takes one (get_file); the last one's drop releases the file
/// (`fput`). A holder that must not keep the file open (an epoll item)
/// keeps a `Weak` (`FileRef::downgrade`) and takes a reference with
/// `FileRef::try_get` (Linux epi_fget).
///
/// # Invariants
/// Holds one strong count of its `Arc` and one of the file's `f_count`.
pub struct FileRef(ManuallyDrop<Arc<File>>);

impl FileRef {
    /// A reference to the file `w` names, unless its last one is gone
    /// (Linux file_ref_get). A failure briefly holds an `Arc` that would
    /// drop the file's memory (dentry, private data) if the release had
    /// finished and dropped its own meanwhile (Linux frees a file
    /// through RCU instead): the caller keeps the release from finishing
    /// (epoll calls it under `Eventpoll.mtx`, which the file's
    /// `eventpoll_release` takes for the item)
    pub fn try_get(w: &alloc::sync::Weak<File>) -> Option<FileRef> {
        let f = w.upgrade()?;
        let mut n = f.f_count.load(Ordering::Relaxed);
        loop {
            // Released or being released: dropping this `Arc` never
            // releases it (the releaser holds one until it is DEAD)
            if n == 0 || n == FILE_REF_DEAD {
                return None;
            }
            match f
                .f_count
                .compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return Some(FileRef(ManuallyDrop::new(f))),
                Err(v) => n = v,
            }
        }
    }

    /// A non-owning handle to the file (no reference)
    pub fn downgrade(this: &Self) -> alloc::sync::Weak<File> {
        Arc::downgrade(&this.0)
    }

    /// The file's address (its identity)
    pub fn as_ptr(this: &Self) -> *const File {
        Arc::as_ptr(&this.0)
    }

    /// Both are the same open file
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        Arc::ptr_eq(&a.0, &b.0)
    }

    /// Drop the reference (Linux file_ref_put): its `Arc` back for the
    /// release if it was the last
    fn put(self) -> Option<Arc<File>> {
        let mut me = ManuallyDrop::new(self);
        // SAFETY: taken once; `me` is never dropped
        let f = unsafe { ManuallyDrop::take(&mut me.0) };
        if f.f_count.fetch_sub(1, Ordering::Release) != 1 {
            // Another reference holds an `Arc`: this is not the last
            return None;
        }
        // Every other holder's use comes before the release
        fence(Ordering::Acquire);
        Some(f)
    }
}

impl Clone for FileRef {
    /// Another reference (Linux get_file)
    fn clone(&self) -> Self {
        self.0.f_count.fetch_add(1, Ordering::Relaxed);
        FileRef(self.0.clone())
    }
}

impl core::ops::Deref for FileRef {
    type Target = File;
    fn deref(&self) -> &File {
        &self.0
    }
}

impl Drop for FileRef {
    /// fput: the last reference queues the release
    fn drop(&mut self) {
        // SAFETY: taken once, here; `put` owns it from now on
        let f = FileRef(ManuallyDrop::new(unsafe {
            ManuallyDrop::take(&mut self.0)
        }));
        if let Some(f) = f.put() {
            fput_deferred(f);
        }
    }
}

/// Drop a reference (Linux fput): the last one's release runs later,
/// with nothing held, in the dropping task on its way back to user mode
/// (task_work), or from interrupt context, a kernel thread or a task
/// past `exit_task_work` in the system workqueue (`delayed_fput`)
pub fn fput(f: FileRef) {
    drop(f);
}

/// close(2)'s drop (Linux fput_close_sync): the last reference releases
/// the file before returning, so the close is complete when the call
/// returns (a pipe's reader sees EOF, a socket is gone). The caller
/// holds no lock.
pub fn fput_close_sync(f: FileRef) {
    if let Some(f) = f.put() {
        release(f);
    }
}

/// Release a file whose last reference went, then mark it so its
/// memory's drop does not again (Linux __fput, then file_free)
fn release(f: Arc<File>) {
    crate::sync::might_sleep();
    f.__fput();
    f.f_count.store(FILE_REF_DEAD, Ordering::Release);
}

/// Queue the release of `f` (Linux __fput_deferred)
fn fput_deferred(f: Arc<File>) {
    let me = crate::task::percpu::current();
    let p = Arc::into_raw(f);
    if !crate::sync::in_interrupt() && !me.is_kthread() {
        // SAFETY: `p` is live; its head is on no list (it is queued once,
        // by the last reference's drop); the task's list keeps the
        // reference until `____fput`
        if unsafe { task_work_add(&me, &raw const (*p).f_task_work, Twa::Resume) }.is_ok() {
            return;
        }
        // Past exit_task_work: the delayed list takes it
    }
    let first = {
        let mut l = DELAYED_FPUT.lock();
        let first = l.is_empty();
        // SAFETY: as above; the delayed list keeps the reference until
        // `delayed_fput`
        unsafe { l.push_back(&raw const (*p).f_task_work) };
        first
    };
    if first && let Some(w) = DELAYED_FPUT_WORK.get() {
        // One tick later (Linux schedule_delayed_work(.., 1)): files
        // dropped together are released together
        SYSTEM_WQ.queue_delayed_work(w.clone(), 1);
    }
}

/// The release callback of a file queued by `fput_deferred` (Linux
/// ____fput)
///
/// # Safety
/// `cb` is the `f_task_work` of a file whose `Arc` was handed to the
/// list it came off (`Arc::into_raw`).
unsafe fn ____fput(cb: *const CallbackHead) {
    let off = core::mem::offset_of!(File, f_task_work);
    // SAFETY: the caller's contract: `cb` is inside a File, and its
    // reference is ours
    let f = unsafe { Arc::from_raw(cb.cast::<u8>().sub(off).cast::<File>()) };
    release(f);
}

/// Files whose release waits for the system workqueue (Linux
/// delayed_fput_list): their `f_task_work` heads, each holding its
/// file's `Arc`. IrqSpinlock leaf: added to from any context.
static DELAYED_FPUT: IrqSpinlock<List<CbAdapter>> = IrqSpinlock::new(List::new());

/// The work item that drains `DELAYED_FPUT` (Linux delayed_fput_work),
/// made by `files_init`
static DELAYED_FPUT_WORK: spin::Once<Arc<IrqSpinlock<DelayedWork>>> = spin::Once::new();

/// Held across a drain of `DELAYED_FPUT`, so a flush waits for one in
/// progress (Linux flush_delayed_work in flush_delayed_fput); sleeping,
/// taken with nothing held
static DELAYED_FPUT_RUN: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

/// Release the files on the delayed list (Linux delayed_fput): those
/// there now; ones their releases drop are queued again
fn delayed_fput() {
    let _run = DELAYED_FPUT_RUN.lock();
    let mut l = core::mem::replace(&mut *DELAYED_FPUT.lock(), List::new());
    while let Some(cb) = l.pop_front() {
        // SAFETY: taken off the delayed list, which held its reference
        unsafe { CallbackHead::run(cb) };
    }
}

/// Release every file waiting on the delayed list, and wait for a drain
/// under way (Linux flush_delayed_fput)
pub fn flush_delayed_fput() {
    delayed_fput();
}

/// Make the delayed list's work item (Linux files_init, from
/// vfs_caches_init): before any file is opened
pub fn files_init() {
    let w = DELAYED_FPUT_WORK.call_once(|| {
        crate::util::kalloc::arc_nofail(IrqSpinlock::new(DelayedWork::new(delayed_fput)))
    });
    // Releases queued before the work existed found none to schedule
    if !DELAYED_FPUT.lock().is_empty() {
        SYSTEM_WQ.queue_delayed_work(w.clone(), 1);
    }
}

/// After a write of `n` bytes at `pos` of `file` that must be
/// synchronous (`dsync`: IOCB_DSYNC, or the inode IS_SYNC), those bytes
/// reach the storage before the write returns, and an error doing so is
/// the write's (Linux generic_write_sync: vfs_fsync_range over them)
pub fn generic_write_sync(
    file: &File,
    pos: u64,
    n: usize,
    dsync: bool,
) -> Result<usize, KernelError> {
    if n > 0 && dsync {
        crate::fs::sync::vfs_fsync_range(file, pos, pos.saturating_add(n as u64 - 1))?;
    }
    Ok(n)
}

/// FIONREAD (Linux ioctl number): bytes ready to read
pub const FIONREAD: u32 = 0x541B;

/// Answer FIONREAD with `n` as the user's int (Linux put_user to an
/// `int __user *`, truncating)
pub fn put_fionread(arg: u64, n: i64) -> Result<i64, KernelError> {
    crate::uaccess::put_user::<i32>(arg, n as i32).map_err(|_| KernelError::BadAddress)?;
    Ok(0)
}

/// The operations of a path-only (O_PATH) file (Linux do_dentry_open's
/// empty_fops): none, as no I/O reaches it
pub struct EmptyFileOps;

impl FileOps for EmptyFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

pub static EMPTY_FOPS: EmptyFileOps = EmptyFileOps;

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
        if (at.is_some() && !dev.positional()) || flags.nowait() {
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
        if (at.is_some() && !dev.positional()) || flags.nowait() {
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

    fn fasync(&self, file: &File, fd: i32, on: bool) -> Option<Result<(), KernelError>> {
        match Self::dev(file) {
            Ok(d) => d.fasync(file, fd, on),
            Err(e) => Some(Err(e)),
        }
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
    // A path-only file holds no locks of the closer's (Linux filp_flush
    // skips locks_remove_posix for FMODE_PATH)
    if !file.is_path() {
        crate::fs::posix_lock::release_posix_locks_on_close(file, owner);
    }
    file.f_op.flush(file);
}
