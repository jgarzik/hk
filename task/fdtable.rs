//! Per-task file descriptor tables (Linux files_struct)
//!
//! Each task points at a `Files` table, shared by CLONE_FILES or copied
//! by fork. `Task.files` is under the task's alloc_lock (Linux
//! task_lock; lock-free for the task itself); the table has its own
//! lock.
//!
//! ## Locking
//!
//! `Files` wraps the table's `crate::sync::spin::Mutex` (Linux
//! files->file_lock), a leaf: nothing is allocated, flushed or closed
//! under it. A table too small for a new descriptor is replaced by a
//! bigger one allocated with the lock dropped (Linux expand_files,
//! alloc_fdtable); fork's copy is allocated first and made again if
//! the table grew meanwhile (dup_fd). A new descriptor is reserved
//! under the lock and its file installed later (get_unused_fd_flags,
//! fd_install). Closing detaches the file under the lock and flushes
//! it (the closer's POSIX locks go) after the unlock (Linux
//! file_close_fd_locked, then filp_close after spin_unlock);
//! close_range, exec's close-on-exec and the last reference's close
//! take one descriptor per lock hold. A task's last reference to its
//! table is dropped after its alloc_lock is released, never under it.

use crate::sync::spin::{Mutex, MutexGuard};
use crate::sync::waitqueue::WaitQueue;
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::sync::Arc;

use super::fdbits::{Fdt, NR_OPEN_DEFAULT, Slot};
use super::percpu::current;
use super::{Fd, FdTable, Task};
use crate::fs::FileRef;
use crate::util::error::{KernelError, KernelResult};

/// A descriptor table (Linux files_struct)
pub struct Files {
    table: Mutex<FdTable<FileRef>>,
    /// Its identity as a POSIX lock owner (Linux fl_owner): unique, never
    /// reused, kept across an exec that did not have to copy the table
    id: u64,
    /// Tasks using it (Linux files_struct.count): other `Arc` holders
    /// (a /proc reader, kcmp) do not make it shared
    users: core::sync::atomic::AtomicUsize,
    /// Tasks waiting for another's table growth (Linux
    /// files_struct.resize_wait)
    resize_wait: WaitQueue,
}

/// The locked table (Linux spin_lock(&files->file_lock))
pub type FilesGuard<'a> = MutexGuard<'a, FdTable<FileRef>>;

/// Source of `Files::id`
static NEXT_FILES_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Close a detached descriptor's file (Linux filp_close): it is flushed
/// and `owner`'s POSIX locks on it go; then the reference is put
fn filp_close(f: FileRef, owner: u64) {
    crate::fs::file::filp_flush(&f, owner);
    drop(f);
}

impl Files {
    fn new(t: FdTable<FileRef>) -> Self {
        Self {
            table: Mutex::new(t),
            id: NEXT_FILES_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            users: core::sync::atomic::AtomicUsize::new(0),
            resize_wait: WaitQueue::new(),
        }
    }

    /// An empty table (Linux files_struct's embedded NR_OPEN_DEFAULT
    /// slots); ENOMEM
    fn empty() -> KernelResult<Self> {
        Ok(Self::new(FdTable::new(Fdt::alloc(NR_OPEN_DEFAULT)?)))
    }

    /// More than one task uses it
    fn shared(&self) -> bool {
        self.users.load(core::sync::atomic::Ordering::Acquire) > 1
    }

    /// Its POSIX lock-owner identity
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Lock the table (Linux spin_lock(&files->file_lock)): for lookups
    /// and descriptor flags; descriptors come and go through the
    /// methods below
    pub fn lock(&self) -> FilesGuard<'_> {
        self.table.lock()
    }

    /// Make room for descriptor `nr` (Linux expand_files): one task at
    /// a time grows the table (resize_in_progress; the others sleep on
    /// `resize_wait` until it is done, then look again), allocating the
    /// bigger one with the lock dropped (expand_fdtable). EMFILE at or
    /// past fs.nr_open, ENOMEM.
    fn expand_files<'a>(
        &'a self,
        mut t: FilesGuard<'a>,
        nr: usize,
    ) -> (FilesGuard<'a>, KernelResult<()>) {
        loop {
            if nr < t.max_fds() {
                return (t, Ok(()));
            }
            if t.resize_in_progress {
                drop(t);
                self.resize_wait
                    .wait_event(|| !self.lock().resize_in_progress);
                t = self.lock();
                continue;
            }
            if let Err(e) = t.need_expand(nr) {
                return (t, Err(e));
            }
            t.resize_in_progress = true;
            drop(t);
            let r = self.expand_fdtable(nr);
            self.resize_wait.wake_all();
            t = self.lock();
            if let Err(e) = r {
                return (t, Err(e));
            }
        }
    }

    /// Replace the table, under resize_in_progress, by one that holds
    /// `nr` (Linux expand_fdtable): allocated and the old one freed with
    /// the lock dropped; ENOMEM, EMFILE (fs.nr_open lowered meanwhile)
    fn expand_fdtable(&self, nr: usize) -> KernelResult<()> {
        let new = Fdt::alloc(nr + 1);
        let mut t = self.lock();
        t.resize_in_progress = false;
        let old = t.expand(new?);
        drop(t);
        drop(old);
        Ok(())
    }

    /// Reserve the lowest free descriptor at or above `start` and below
    /// `end` (RLIMIT_NOFILE), FD_CLOEXEC from `flags` (Linux alloc_fd):
    /// EMFILE, ENOMEM
    fn alloc_fd(&self, start: usize, flags: u32, end: u64) -> KernelResult<Fd> {
        let mut t = self.lock();
        loop {
            match t.alloc_fd(start, flags, end)? {
                Slot::Fd(fd) => return Ok(fd),
                Slot::Expand(nr) => {
                    let (g, r) = self.expand_files(t, nr);
                    t = g;
                    r?;
                }
            }
        }
    }

    /// Detach descriptor `fd` for the caller to close after the unlock
    /// (Linux file_close_fd); None (EBADF) if no file is installed there
    pub fn close_fd(&self, fd: Fd) -> Option<FileRef> {
        self.lock().close_fd(fd)
    }

    /// Make `newfd` a copy of `oldfd` with FD_CLOEXEC from `flags`
    /// (Linux ksys_dup3 under file_lock, do_dup2): room for `newfd`
    /// first, then EBADF for no `oldfd` (and for `newfd` past fs.nr_open),
    /// EBUSY for a `newfd` reserved but not installed yet; the file
    /// `newfd` had is closed after the unlock
    pub fn dup3(&self, oldfd: Fd, newfd: usize, flags: u32) -> KernelResult<()> {
        let (mut t, room) = self.expand_files(self.lock(), newfd);
        let file = t.get(oldfd).ok_or(KernelError::BadFd)?;
        room.map_err(|e| match e {
            KernelError::ProcessFileLimit => KernelError::BadFd,
            e => e,
        })?;
        let tofree = t.dup2(newfd, file, flags)?;
        drop(t);
        if let Some(f) = tofree {
            filp_close(f, self.id);
        }
        Ok(())
    }

    /// Close the descriptors in `lo..=hi` (Linux __range_close): one per
    /// lock hold, each closed after the unlock
    pub fn range_close(&self, lo: usize, hi: usize) {
        let mut fd = lo;
        loop {
            let next = self.lock().close_next(fd, hi);
            let Some((n, f)) = next else {
                return;
            };
            filp_close(f, self.id);
            fd = n + 1;
        }
    }

    /// Mark `lo..=hi` close-on-exec (Linux __range_cloexec)
    pub fn range_cloexec(&self, lo: usize, hi: usize) {
        self.lock().range_cloexec(lo, hi);
    }

    /// Close the close-on-exec descriptors (Linux do_close_on_exec): one
    /// per lock hold, each closed after the unlock
    fn close_on_exec(&self) {
        let mut fd = 0;
        loop {
            let next = self.lock().take_cloexec(fd);
            let Some((n, f)) = next else {
                return;
            };
            if let Some(f) = f {
                filp_close(f, self.id);
            }
            fd = n + 1;
        }
    }

    /// A copy, with a new lock-owner identity (Linux dup_fd): its table
    /// is allocated before the lock is taken, and again with the lock
    /// dropped while the open descriptors outgrow it; ENOMEM, EMFILE
    fn dup_fd(&self) -> KernelResult<Files> {
        let mut fdt = Fdt::alloc(NR_OPEN_DEFAULT)?;
        let mut t = self.lock();
        loop {
            let n = t.sane_size();
            if n <= fdt.max_fds() {
                break;
            }
            drop(t);
            fdt = Fdt::alloc(n)?;
            t = self.lock();
        }
        let new = t.dup_into(fdt);
        drop(t);
        Ok(Files::new(new))
    }
}

/// The last reference closes every descriptor, whoever drops it (Linux
/// put_files_struct -> close_files): each is flushed and its POSIX
/// locks owned by this table go
impl Drop for Files {
    fn drop(&mut self) {
        let id = self.id;
        let t = self.table.get_mut();
        let mut fd = 0;
        while let Some((n, f)) = t.close_next(fd, usize::MAX) {
            filp_close(f, id);
            fd = n + 1;
        }
    }
}

/// A descriptor reserved in a table (Linux get_unused_fd_flags):
/// `install` puts its file there (fd_install); dropped unused, it is
/// released (put_unused_fd)
#[must_use]
pub struct UnusedFd {
    files: Option<Arc<Files>>,
    fd: Fd,
}

impl UnusedFd {
    /// Reserve the lowest free descriptor of `files` at or above
    /// `start`, below `end` (RLIMIT_NOFILE), FD_CLOEXEC from `flags`:
    /// EMFILE, ENOMEM
    pub fn alloc(files: Arc<Files>, start: usize, flags: u32, end: u64) -> KernelResult<Self> {
        let fd = files.alloc_fd(start, flags, end)?;
        Ok(Self {
            files: Some(files),
            fd,
        })
    }

    /// Its number
    pub fn fd(&self) -> Fd {
        self.fd
    }

    /// Put `file` in it (Linux fd_install); its number
    pub fn install(mut self, file: FileRef) -> Fd {
        if let Some(files) = self.files.take() {
            files.lock().install(self.fd, file);
        }
        self.fd
    }
}

impl Drop for UnusedFd {
    fn drop(&mut self) {
        if let Some(files) = self.files.take() {
            files.lock().put_unused(self.fd);
        }
    }
}

/// Point `t` (the task itself, or a child not yet run) at `files`;
/// the table it had is dropped after its alloc_lock is released
pub fn init_task_fd(t: &Task, files: Arc<Files>) {
    use core::sync::atomic::Ordering;
    files.users.fetch_add(1, Ordering::AcqRel);
    let old = t.task_lock().set_files(Some(files));
    if let Some(o) = &old {
        o.users.fetch_sub(1, Ordering::AcqRel);
    }
    drop(old);
}

/// The descriptor table of `t` (under its alloc_lock; the current
/// task's is `current().files()`, lock-free)
pub fn get_task_fd(t: &Task) -> Option<Arc<Files>> {
    t.task_lock().files().cloned()
}

/// Exit (Linux exit_files): drop the task's reference; the last one
/// closes every descriptor, after its alloc_lock is released
/// (releasing a socket can sleep)
pub fn exit_task_fd(t: &Task) {
    let files = t.task_lock().set_files(None);
    if let Some(f) = &files {
        f.users.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    }
    // The last reference closes every descriptor (Drop for Files)
    drop(files);
}

/// At exec, past its point of no return: give the calling task a
/// private table (Linux unshare_files: a copy if shared through
/// CLONE_FILES, which stays intact for the other tasks) and close its
/// close-on-exec descriptors (do_close_on_exec), the files closed for
/// the private table's lock owner. ENOMEM, EMFILE (the copy).
pub fn exec_task_fd() -> KernelResult<()> {
    let me = current();
    let Some(old) = me.files() else {
        return Ok(());
    };
    // Not shared: the table itself loses its close-on-exec descriptors,
    // staying the same lock owner (Linux keeps an unshared files_struct)
    let files = if old.shared() {
        let new = try_arc(old.dup_fd()?)?;
        init_task_fd(&me, new.clone());
        drop(old);
        new
    } else {
        old
    };
    files.close_on_exec();
    Ok(())
}

/// Give the calling task a private copy of its table (Linux
/// unshare_fd): the new table is installed and returned, while tasks
/// still sharing the old one through CLONE_FILES keep it. EBADF if it
/// has none, ENOMEM.
pub fn unshare_task_fd() -> Result<Arc<Files>, KernelError> {
    let me = current();
    let old = me.files().ok_or(KernelError::BadFd)?;
    // Only a shared table is copied (Linux unshare_fd: count > 1), so a
    // private one keeps its lock-owner identity
    if !old.shared() {
        return Ok(old);
    }
    let new = try_arc(old.dup_fd()?)?;
    init_task_fd(&me, new.clone());
    drop(old);
    Ok(new)
}

/// The table for a new task, built before it exists (Linux copy_files,
/// reading current->files lock-free; installed with `init_task_fd`):
/// the caller's with CLONE_FILES (`share`), else a copy; ENOMEM, EMFILE
pub fn fork_task_fd(share: bool) -> Result<Arc<Files>, KernelError> {
    match crate::task::percpu::current().files() {
        Some(p) if share => Ok(p),
        Some(p) => try_arc(p.dup_fd()?),
        None => try_arc(Files::empty()?),
    }
}

/// A new empty table for the boot-time init task (init opens its
/// console descriptors itself; failure cannot be reported)
pub fn create_empty_fd_table() -> Arc<Files> {
    arc_nofail(Files::empty().expect("no memory for init's descriptor table"))
}
