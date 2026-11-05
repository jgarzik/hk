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
use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

use super::percpu::with_task_lock;
use super::{FdTable, Tid};
use crate::fs::File;

/// A descriptor table (Linux files_struct)
pub struct Files(Mutex<FdTable<File>>);

/// The locked table; files it detached are released after the unlock
pub struct FilesGuard<'a>(ManuallyDrop<MutexGuard<'a, FdTable<File>>>);

impl Files {
    pub fn new(t: FdTable<File>) -> Self {
        Self(Mutex::new(t))
    }

    /// Lock the table (Linux spin_lock(&files->file_lock))
    pub fn lock(&self) -> FilesGuard<'_> {
        FilesGuard(ManuallyDrop::new(self.0.lock()))
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
            crate::fs::file::filp_flush(f);
        }
        drop(closed);
        drop(dead);
    }
}

/// Point `tid` (the task itself, or a child not yet run) at `files`;
/// the table it had is dropped after its alloc_lock is released
pub fn init_task_fd(tid: Tid, files: Arc<Files>) {
    let old = with_task_lock(tid, |a| a.set_files(Some(files)));
    drop(old);
}

/// The descriptor table of `tid` (lock-free for the current task, Linux
/// current->files)
pub fn get_task_fd(tid: Tid) -> Option<Arc<Files>> {
    let me = super::percpu::current();
    if me.tid() == tid {
        return me.files();
    }
    with_task_lock(tid, |a| a.files().cloned()).flatten()
}

/// Exit (Linux exit_files): drop the task's reference; the last one
/// closes every descriptor, after its alloc_lock is released
/// (releasing a socket can sleep)
pub fn exit_task_fd(tid: Tid) {
    let files = with_task_lock(tid, |a| a.set_files(None)).flatten();
    // The last reference closes every descriptor: each is flushed by the
    // exiting task (Linux close_files -> filp_close)
    if let Some(files) = files.and_then(Arc::into_inner) {
        let open: alloc::vec::Vec<_> = {
            let t = files.lock();
            t.fds().filter_map(|&fd| t.get(fd)).collect()
        };
        for f in &open {
            crate::fs::file::filp_flush(f);
        }
        drop(open);
        drop(files);
    }
}

/// At exec's point of no return: give the task a private table without
/// its close-on-exec descriptors (Linux unshare_files, then
/// do_close_on_exec). A table shared through CLONE_FILES stays intact
/// for the other tasks; the closed files are released after every lock
/// is dropped.
pub fn exec_task_fd(tid: Tid) {
    let Some(old) = get_task_fd(tid) else {
        return;
    };
    let (new, cloexec) = {
        let t = old.lock();
        let cloexec: alloc::vec::Vec<_> = t
            .fds()
            .filter(|&&fd| t.get_fd_flags(fd) & super::FD_CLOEXEC != 0)
            .filter_map(|&fd| t.get(fd))
            .collect();
        (Arc::new(Files::new(t.exec_copy())), cloexec)
    };
    init_task_fd(tid, new);
    // Linux do_close_on_exec closes them (filp_close): their POSIX locks
    // go and they are flushed; every other lock stays across the exec
    for f in &cloexec {
        crate::fs::file::filp_flush(f);
    }
    drop(cloexec);
    drop(old);
}

/// Give `tid` a private copy of its table (Linux unshare_fd): the new
/// table is installed and returned, while tasks still sharing the old
/// one through CLONE_FILES keep it.
pub fn unshare_task_fd(tid: Tid) -> Option<Arc<Files>> {
    let old = get_task_fd(tid)?;
    let new = Arc::new(Files::new(old.lock().deep_clone()));
    init_task_fd(tid, new.clone());
    drop(old);
    Some(new)
}

/// Clone the table for fork/clone: shared with CLONE_FILES (`share`),
/// else a copy
pub fn clone_task_fd(parent_tid: Tid, child_tid: Tid, share: bool) {
    let parent = get_task_fd(parent_tid);
    let child = match parent {
        Some(p) if share => p,
        Some(p) => Arc::new(Files::new(p.lock().deep_clone())),
        None => create_empty_fd_table(),
    };
    init_task_fd(child_tid, child);
}

/// A new empty table (init opens its console descriptors itself)
pub fn create_empty_fd_table() -> Arc<Files> {
    Arc::new(Files::new(FdTable::new()))
}
