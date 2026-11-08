//! Per-task file descriptor tables (Linux files_struct)
//!
//! Each task points at a `Files` table, shared by CLONE_FILES or copied
//! by fork. `Task.files` is under the task's alloc_lock (Linux
//! task_lock; lock-free for the task itself); the table has its own
//! lock.
//!
//! ## Locking
//!
//! `Files` wraps the table's `crate::sync::spin::Mutex` (Linux files->file_lock).
//! Releasing a file can sleep (TCP SO_LINGER, socket release paths), so
//! no file is ever dropped under that lock: the table parks the files
//! it detaches (close, dup2 over an open descriptor, a refused install)
//! and `FilesGuard` drops them after unlocking (Linux
//! file_close_fd_locked, then filp_close/fput after spin_unlock).
//! Likewise a task's last reference to its table is dropped after its
//! alloc_lock is released, never under it.

use crate::sync::spin::{Mutex, MutexGuard};
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

use super::percpu::current;
use super::{FdTable, Task};
use crate::fs::File;
use crate::util::error::KernelError;

/// A descriptor table (Linux files_struct)
pub struct Files {
    table: Mutex<FdTable<File>>,
    /// Its identity as a POSIX lock owner (Linux fl_owner): unique, never
    /// reused, kept across an exec that did not have to copy the table
    id: u64,
    /// Tasks using it (Linux files_struct.count): other `Arc` holders
    /// (a /proc reader, kcmp) do not make it shared
    users: core::sync::atomic::AtomicUsize,
}

/// The locked table; files it detached are released after the unlock
pub struct FilesGuard<'a>(ManuallyDrop<MutexGuard<'a, FdTable<File>>>, u64);

/// Source of `Files::id`
static NEXT_FILES_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

impl Files {
    pub fn new(t: FdTable<File>) -> Self {
        let id = NEXT_FILES_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Self::with_id(t, id)
    }

    /// A table keeping lock-owner identity `id`
    fn with_id(t: FdTable<File>, id: u64) -> Self {
        Self {
            table: Mutex::new(t),
            id,
            users: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// More than one task uses it
    fn shared(&self) -> bool {
        self.users.load(core::sync::atomic::Ordering::Acquire) > 1
    }

    /// Its POSIX lock-owner identity
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Lock the table (Linux spin_lock(&files->file_lock))
    pub fn lock(&self) -> FilesGuard<'_> {
        FilesGuard(ManuallyDrop::new(self.table.lock()), self.id)
    }
}

/// The last reference closes every descriptor, whoever drops it (Linux
/// put_files_struct -> close_files): each is flushed and its POSIX
/// locks owned by this table go
impl Drop for Files {
    fn drop(&mut self) {
        let t = self.table.get_mut();
        let open: alloc::vec::Vec<_> = t.fds().filter_map(|&fd| t.get(fd)).collect();
        for f in &open {
            crate::fs::file::filp_flush(f, self.id);
        }
    }
}

impl Deref for FilesGuard<'_> {
    type Target = FdTable<File>;
    fn deref(&self) -> &FdTable<File> {
        &self.0
    }
}

impl DerefMut for FilesGuard<'_> {
    fn deref_mut(&mut self) -> &mut FdTable<File> {
        &mut self.0
    }
}

impl Drop for FilesGuard<'_> {
    fn drop(&mut self) {
        let dead = self.0.take_dead();
        let closed = self.0.take_closed();
        // SAFETY: dropped exactly once, here
        unsafe { ManuallyDrop::drop(&mut self.0) };
        // A descriptor closed (close, dup2 over it, close_range): the
        // caller's POSIX locks on its inode go and the file's flush runs
        // (Linux filp_flush), however many other descriptors it has.
        // Files refused an install (`dead`) were never the caller's.
        for f in &closed {
            crate::fs::file::filp_flush(f, self.1);
        }
        drop(closed);
        drop(dead);
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

/// At exec's point of no return: give the calling task a private table
/// without its close-on-exec descriptors (Linux unshare_files, then
/// do_close_on_exec). A table shared through CLONE_FILES stays intact
/// for the other tasks; the closed files are released after every lock
/// is dropped.
pub fn exec_task_fd() {
    let me = current();
    let Some(old) = me.files() else {
        return;
    };
    // Not shared: the table itself loses its close-on-exec descriptors,
    // staying the same lock owner (Linux keeps an unshared files_struct);
    // the guard's drop flushes them (do_close_on_exec -> filp_close)
    if !old.shared() {
        let mut t = old.lock();
        let cloexec: alloc::vec::Vec<_> = t
            .fds()
            .filter(|&&fd| t.get_fd_flags(fd) & super::FD_CLOEXEC != 0)
            .copied()
            .collect();
        for fd in cloexec {
            t.close(fd);
        }
        return;
    }
    let (new, cloexec) = {
        let t = old.lock();
        let cloexec: alloc::vec::Vec<_> = t
            .fds()
            .filter(|&&fd| t.get_fd_flags(fd) & super::FD_CLOEXEC != 0)
            .filter_map(|&fd| t.get(fd))
            .collect();
        // Past exec's point of no return: failure cannot be reported
        (arc_nofail(Files::new(t.exec_copy())), cloexec)
    };
    init_task_fd(&me, new);
    // Linux do_close_on_exec closes them (filp_close): their POSIX locks
    // go and they are flushed; every other lock stays across the exec
    let owner = me.files().map_or(0, |f| f.id());
    for f in &cloexec {
        crate::fs::file::filp_flush(f, owner);
    }
    drop(cloexec);
    drop(old);
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
    let new = try_arc(Files::new(old.lock().deep_clone()))?;
    init_task_fd(&me, new.clone());
    drop(old);
    Ok(new)
}

/// The table for a new task, built before it exists (Linux copy_files;
/// installed with `init_task_fd`): `parent`'s with CLONE_FILES
/// (`share`), else a copy; ENOMEM
pub fn fork_task_fd(parent: &Task, share: bool) -> Result<Arc<Files>, KernelError> {
    match get_task_fd(parent) {
        Some(p) if share => Ok(p),
        Some(p) => try_arc(Files::new(p.lock().deep_clone())),
        None => try_arc(Files::new(FdTable::new())),
    }
}

/// A new empty table for the boot-time init task (init opens its
/// console descriptors itself; failure cannot be reported)
pub fn create_empty_fd_table() -> Arc<Files> {
    arc_nofail(Files::new(FdTable::new()))
}
