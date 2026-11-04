//! System V Shared Memory Implementation
//!
//! Provides shared memory segments that can be attached to multiple process
//! address spaces for inter-process communication.
//!
//! A segment's pages live in a shared object (`mm::shmem::Shmem`, as on
//! Linux, where segments are shmem files), faulted in on demand. Each
//! attachment is a VMA holding a [`ShmAttach`]: shm_nattch counts those
//! VMAs (Linux shm_open/shm_close), so fork's copies, split pieces and
//! their removal by munmap, shmdt, exit or exec all keep it right, and the
//! last detach of a segment removed with IPC_RMID destroys it. The pages
//! go when the segment and its last VMA are gone.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, Ordering};

use crate::arch::Uaccess;
use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, IpcOps, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{IPC_64, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Shmid64Ds, current_ipc_ns};
use crate::mm::shmem::Shmem;
use crate::mm::vma::{
    MAP_SHARED, PROT_READ as VMA_PROT_READ, PROT_WRITE as VMA_PROT_WRITE, VM_SHARED, VM_SHM,
};
use crate::mm::{Vma, get_task_mm};
use crate::task::percpu::{current_pid, current_tid};
use crate::time::TIMEKEEPER;
use crate::uaccess::{get_user, put_user};
use crate::util::error::KernelError;

const PAGE_SIZE: usize = 4096;

/// Get current time in seconds
fn current_time_secs() -> i64 {
    TIMEKEEPER.current_time().sec
}

// ============================================================================
// Shared Memory Constants
// ============================================================================

/// Read-only attach
pub const SHM_RDONLY: i32 = 0o10000;
/// Round attach address to SHMLBA
pub const SHM_RND: i32 = 0o20000;
/// Take over region on attach
pub const SHM_REMAP: i32 = 0o40000;
/// Execution access
pub const SHM_EXEC: i32 = 0o100000;

/// Lock segment in memory
pub const SHM_LOCK: i32 = 11;
/// Unlock segment
pub const SHM_UNLOCK: i32 = 12;
/// Get stats by index
pub const SHM_STAT: i32 = 13;
/// Get info
pub const SHM_INFO: i32 = 14;

/// Minimum segment size
pub const SHMMIN: usize = 1;

// ============================================================================
// Shared Memory Segment
// ============================================================================

/// Kernel shared memory segment
pub struct ShmidKernel {
    /// IPC permissions and ID
    pub perm: KernIpcPerm,
    /// Size in bytes
    pub segsz: usize,
    /// Number of current attaches
    pub nattch: AtomicU32,
    /// Last attach time
    pub atim: AtomicI64,
    /// Last detach time
    pub dtim: AtomicI64,
    /// Last change time
    pub ctim: AtomicI64,
    /// Creator PID
    pub cpid: i32,
    /// Last operation PID
    pub lpid: AtomicI32,
    /// The segment's pages
    pub shmem: Arc<Shmem>,
    /// Destroyed (namespace totals given back): at most once
    destroyed: AtomicBool,
    /// Namespace this segment belongs to
    ns: Arc<IpcNamespace>,
}

impl ShmidKernel {
    /// Create a new shared memory segment
    /// (Pages are allocated as they are first touched.)
    pub fn new(key: i32, size: usize, mode: u16, ns: Arc<IpcNamespace>) -> Result<Arc<Self>, i32> {
        let now = current_time_secs();
        let pid = current_pid() as i32;

        Ok(Arc::new(Self {
            perm: KernIpcPerm::new(key, mode),
            segsz: size,
            nattch: AtomicU32::new(0),
            atim: AtomicI64::new(0),
            dtim: AtomicI64::new(0),
            ctim: AtomicI64::new(now),
            cpid: pid,
            lpid: AtomicI32::new(pid),
            shmem: Shmem::new(size.div_ceil(PAGE_SIZE) as u64),
            destroyed: AtomicBool::new(false),
            ns,
        }))
    }

    /// Fill shmid64_ds structure for IPC_STAT
    pub fn fill_shmid64_ds(&self, ds: &mut Shmid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.shm_perm);
        ds.shm_segsz = self.segsz;
        ds.shm_atime = self.atim.load(Ordering::Relaxed);
        ds.shm_dtime = self.dtim.load(Ordering::Relaxed);
        ds.shm_ctime = self.ctim.load(Ordering::Relaxed);
        ds.shm_cpid = self.cpid;
        ds.shm_lpid = self.lpid.load(Ordering::Relaxed);
        ds.shm_nattch = self.nattch.load(Ordering::Relaxed) as u64;
        ds.__unused4 = 0;
        ds.__unused5 = 0;
    }
}

impl IpcObject for ShmidKernel {
    fn perm(&self) -> &KernIpcPerm {
        &self.perm
    }

    /// Linux shm_destroy: once removed (IPC_RMID) and detached. The
    /// pages go with the last reference to the segment's object.
    fn destroy(&self) {
        if self.destroyed.swap(true, Ordering::AcqRel) {
            return;
        }
        let pages = self.segsz.div_ceil(PAGE_SIZE) as u64;
        self.ns.shm_tot.fetch_sub(pages, Ordering::Relaxed);
    }
}

// ============================================================================
// Attachments
// ============================================================================

/// One attachment of a segment, held by its VMA (Linux shm_open /
/// shm_close through the VMA's vm_ops): counted in shm_nattch for as long
/// as the VMA exists. Cloned with the VMA (fork, split) and dropped with
/// it (munmap, shmdt, exit, exec); the last drop of a removed segment
/// destroys it. Takes no lock (safe under the mm lock).
pub struct ShmAttach {
    seg: Arc<ShmidKernel>,
    /// Attached SHM_RDONLY: never writable (Linux: no VM_MAYWRITE)
    rdonly: bool,
}

impl ShmAttach {
    fn new(seg: Arc<ShmidKernel>, rdonly: bool) -> Self {
        let a = Self { seg, rdonly };
        a.open();
        a
    }

    fn shm(&self) -> &ShmidKernel {
        &self.seg
    }

    /// A new attachment, unless the segment was removed meanwhile
    /// (IPC_RMID raced the lookup): then backed out, EINVAL like a
    /// removed id. Pairs with the fence in IPC_RMID.
    fn attach_live(seg: Arc<ShmidKernel>, rdonly: bool) -> Option<Self> {
        let a = Self::new(seg, rdonly);
        core::sync::atomic::fence(Ordering::SeqCst);
        if a.seg.perm().is_deleted() {
            return None; // the drop detaches (and destroys if last)
        }
        Some(a)
    }

    /// Attached read-only (SHM_RDONLY)
    pub fn rdonly(&self) -> bool {
        self.rdonly
    }

    /// Same segment as `other`
    pub fn same(&self, other: &ShmAttach) -> bool {
        Arc::ptr_eq(&self.seg, &other.seg)
    }

    /// Linux shm_open: attach time, last pid, one more attachment
    fn open(&self) {
        let shp = self.shm();
        shp.atim.store(current_time_secs(), Ordering::Relaxed);
        shp.lpid.store(current_pid() as i32, Ordering::Relaxed);
        shp.nattch.fetch_add(1, Ordering::SeqCst);
    }
}

impl Clone for ShmAttach {
    fn clone(&self) -> Self {
        let a = Self {
            seg: self.seg.clone(),
            rdonly: self.rdonly,
        };
        a.open();
        a
    }
}

impl Drop for ShmAttach {
    /// Linux shm_close: detach time, last pid; the last detach of a
    /// removed segment destroys it
    fn drop(&mut self) {
        let shp = self.shm();
        shp.dtim.store(current_time_secs(), Ordering::Relaxed);
        shp.lpid.store(current_pid() as i32, Ordering::Relaxed);
        if shp.nattch.fetch_sub(1, Ordering::SeqCst) == 1 && shp.perm().is_deleted() {
            self.seg.destroy();
        }
    }
}

// ============================================================================
// Syscalls
// ============================================================================

/// Convert Result to syscall return value
fn result_to_i64(res: Result<i32, i32>) -> i64 {
    match res {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
    }
}

/// Convert Result<u64, i32> to syscall return value
fn result_u64_to_i64(res: Result<u64, i32>) -> i64 {
    match res {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
    }
}

/// shmget - get shared memory segment
///
/// # Arguments
/// * `key` - Key to identify segment (IPC_PRIVATE for new private segment)
/// * `size` - Size of segment in bytes
/// * `shmflg` - Flags (IPC_CREAT, IPC_EXCL, permission bits)
pub fn sys_shmget(key: i32, size: usize, shmflg: i32) -> i64 {
    result_to_i64(do_shmget(key, size, shmflg))
}

fn do_shmget(key: i32, size: usize, shmflg: i32) -> Result<i32, i32> {
    let ns = current_ipc_ns();

    // Validate size
    if size < SHMMIN || size > ns.shm_ctlmax {
        return Err(KernelError::InvalidArgument.errno());
    }

    let ns_clone = ns.clone();
    let ns_added = ns.clone();
    let pages = size.div_ceil(PAGE_SIZE) as u64;
    let ops = IpcOps {
        // Linux newseg: ENOSPC past SHMALL
        new: move |k, mode| {
            let tot = ns_clone.shm_tot.load(Ordering::Relaxed);
            if tot
                .checked_add(pages)
                .is_none_or(|t| t > ns_clone.shm_ctlall as u64)
            {
                return Err(KernelError::NoSpace.errno());
            }
            ShmidKernel::new(k, size, mode, ns_clone.clone())
        },
        // Linux shm_more_checks
        more_checks: |shm: &ShmidKernel| {
            if shm.segsz < size {
                return Err(KernelError::InvalidArgument.errno());
            }
            Ok(())
        },
        added: move |_: &ShmidKernel| {
            ns_added.shm_tot.fetch_add(pages, Ordering::Relaxed);
        },
    };
    ipcget(ns.shm_ids(), key, shmflg, ns.shm_ctlmni, ops)
}

/// shmat - attach shared memory segment
///
/// # Arguments
/// * `shmid` - Segment ID from shmget
/// * `shmaddr` - Desired attach address (0 = kernel chooses)
/// * `shmflg` - Flags (SHM_RDONLY, SHM_RND, etc.)
///
/// # Returns
/// * Address where segment was attached
pub fn sys_shmat(shmid: i32, shmaddr: u64, shmflg: i32) -> i64 {
    result_u64_to_i64(do_shmat(shmid, shmaddr, shmflg))
}

fn do_shmat(shmid: i32, shmaddr: u64, shmflg: i32) -> Result<u64, i32> {
    let ns = current_ipc_ns();
    let tid = current_tid();
    let einval = KernelError::InvalidArgument.errno();

    let shm_obj = ns.shm_ids().find_by_id(shmid).ok_or(einval)?;
    let access = if shmflg & SHM_RDONLY != 0 {
        IPC_PERM_READ
    } else {
        IPC_PERM_READ | IPC_PERM_WRITE
    };
    ipc_checkperm(shm_obj.perm(), access)?;
    let shm_kernel: &ShmidKernel = &shm_obj;
    let size = (shm_kernel.segsz as u64).div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;
    let shmem = shm_kernel.shmem.clone();

    // SHM_REMAP needs an address (Linux do_shmat)
    if shmaddr == 0 && shmflg & SHM_REMAP != 0 {
        return Err(einval);
    }
    let mm = get_task_mm(tid).ok_or(KernelError::OutOfMemory.errno())?;
    let mut replaced = Vec::new();
    let mut mm_guard = mm
        .mmap_write_killable()
        .map_err(|_| KernelError::Interrupted.errno())?;
    // RLIMIT_AS, as for any mapping (Linux may_expand_vm)
    let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_AS);
    if limit != crate::task::rlimit::RLIM_INFINITY
        && (mm_guard.total_vm() * PAGE_SIZE as u64).saturating_add(size) > limit
    {
        return Err(KernelError::OutOfMemory.errno());
    }
    let addr = if shmaddr == 0 {
        mm_guard
            .find_free_area(size)
            .ok_or(KernelError::OutOfMemory.errno())?
    } else {
        let aligned = if shmflg & SHM_RND != 0 {
            shmaddr & !(PAGE_SIZE as u64 - 1)
        } else if shmaddr & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(einval);
        } else {
            shmaddr
        };
        // A user address range (Linux do_shmat / do_mmap MAP_FIXED):
        // EINVAL if it wraps, EPERM below mmap_min_addr, ENOMEM past
        // TASK_SIZE
        if aligned.checked_add(size).is_none() {
            return Err(einval);
        }
        crate::mm::check_fixed(aligned, size).map_err(|e| e.errno())?;
        if mm_guard.overlaps(aligned, aligned + size) {
            if shmflg & SHM_REMAP == 0 {
                return Err(einval);
            }
            // SHM_REMAP: unmap what was there (dropped after unlocking)
            replaced =
                crate::mm::syscall::munmap_locked(&mut mm_guard, &mm, aligned, aligned + size);
        }
        aligned
    };
    let prot = if shmflg & SHM_RDONLY != 0 {
        VMA_PROT_READ
    } else {
        VMA_PROT_READ | VMA_PROT_WRITE
    };
    // Pages are faulted in from the segment's object (Linux shm_mmap)
    let mut vma = Vma::new(addr, addr + size, prot, MAP_SHARED | VM_SHARED | VM_SHM);
    vma.shmem = Some(shmem);
    vma.shm =
        Some(ShmAttach::attach_live((*shm_obj).clone(), shmflg & SHM_RDONLY != 0).ok_or(einval)?);
    mm_guard.insert_vma(vma);
    mm_guard.add_total_vm(size / PAGE_SIZE as u64);
    drop(mm_guard);
    drop(replaced);
    Ok(addr)
}

/// shmdt - detach shared memory segment
///
/// # Arguments
/// * `shmaddr` - Address where segment is attached
pub fn sys_shmdt(shmaddr: u64) -> i64 {
    result_to_i64(do_shmdt(shmaddr))
}

/// Linux ksys_shmdt: unmap the attachment starting at `shmaddr`, all of
/// its VMAs (a split one included) up to the segment's size; dropping
/// them updates shm_nattch
fn do_shmdt(shmaddr: u64) -> Result<i32, i32> {
    let einval = KernelError::InvalidArgument.errno();
    let mm = get_task_mm(current_tid()).ok_or(einval)?;
    let gone = {
        let mut map = mm
            .mmap_write_killable()
            .map_err(|_| KernelError::Interrupted.errno())?;
        let first = map.find_vma(shmaddr).ok_or(einval)?;
        let att = first
            .shm
            .as_ref()
            .filter(|_| first.start == shmaddr)
            .ok_or(einval)?;
        let limit =
            shmaddr + (att.shm().segsz as u64).div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;
        // The contiguous VMAs of this attachment
        let mut end = first.end;
        while end < limit {
            match map.find_vma(end) {
                Some(v) if v.shm.as_ref().is_some_and(|b| b.same(att)) => end = v.end,
                _ => break,
            }
        }
        crate::mm::syscall::munmap_locked(&mut map, &mm, shmaddr, end)
    };
    // Dropped unlocked: the last detach may destroy the segment
    drop(gone);
    Ok(0)
}

/// shmctl - shared memory control
///
/// # Arguments
/// * `shmid` - Segment ID
/// * `cmd` - Command (IPC_STAT, IPC_SET, IPC_RMID, etc.)
/// * `buf` - User buffer for data
pub fn sys_shmctl(shmid: i32, cmd: i32, buf: u64) -> i64 {
    result_to_i64(do_shmctl(shmid, cmd, buf))
}

fn do_shmctl(shmid: i32, cmd: i32, buf: u64) -> Result<i32, i32> {
    let ns = current_ipc_ns();
    let cmd_only = cmd & !IPC_64;

    match cmd_only {
        IPC_STAT | SHM_STAT => {
            let shm = ns
                .shm_ids()
                .find_by_id(shmid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            // Check read permission
            ipc_checkperm(shm.perm(), IPC_PERM_READ)?;

            // Fill and copy structure
            let mut ds = Shmid64Ds::default();

            shm.fill_shmid64_ds(&mut ds);

            if buf != 0 {
                put_user::<Uaccess, Shmid64Ds>(buf, ds)
                    .map_err(|_| KernelError::BadAddress.errno())?;
            }

            Ok(0)
        }

        IPC_SET => {
            // Copied in first, before the IPC locks (Linux: the copy
            // may fault)
            let ds: Shmid64Ds =
                get_user::<Uaccess, Shmid64Ds>(buf).map_err(|_| KernelError::BadAddress.errno())?;
            let _w = ns.shm_ids().rwsem.write();
            let shm = ns
                .shm_ids()
                .find_by_id(shmid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            // Must be owner or have CAP_SYS_ADMIN; only uid, gid, mode
            // change
            let uid = crate::task::percpu::current_cred().euid;
            let perm = shm.perm();
            {
                let mut p = perm.lock.lock();
                if !KernIpcPerm::is_owner(&p, perm.cuid, uid) {
                    return Err(KernelError::NotPermitted.errno());
                }
                p.uid = ds.shm_perm.uid;
                p.gid = ds.shm_perm.gid;
                p.mode = ds.shm_perm.mode & 0o777;
            }
            shm.ctim.store(current_time_secs(), Ordering::Relaxed);

            Ok(0)
        }

        IPC_RMID => {
            let _w = ns.shm_ids().rwsem.write();
            // Must be owner or have CAP_SYS_ADMIN
            let shm = ns
                .shm_ids()
                .find_by_id(shmid)
                .ok_or(KernelError::InvalidArgument.errno())?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = shm.perm();
            if !KernIpcPerm::is_owner(&perm.lock.lock(), perm.cuid, uid) {
                return Err(KernelError::NotPermitted.errno());
            }

            // Remove from ID table (marks it deleted). With no attachment
            // destroy it now, else the last detach does; a racing shmat
            // either is seen here or sees the mark and backs out
            // (`attach_live`), so it is destroyed exactly once
            if let Some(removed) = ns.shm_ids().remove(shmid) {
                core::sync::atomic::fence(Ordering::SeqCst);
                if removed.nattch.load(Ordering::SeqCst) == 0 {
                    removed.destroy();
                }
            }

            Ok(0)
        }

        SHM_LOCK | SHM_UNLOCK => {
            // Without CAP_IPC_LOCK only the owner or creator (Linux
            // shmctl_do_lock); nothing to lock (pages are never swapped)
            let shm = ns
                .shm_ids()
                .find_by_id(shmid)
                .ok_or(KernelError::InvalidArgument.errno())?;
            let uid = crate::task::percpu::current_cred().euid;
            let perm = shm.perm();
            let owner = perm.lock.lock().uid;
            if !crate::task::capable(crate::task::CAP_IPC_LOCK) && uid != owner && uid != perm.cuid
            {
                return Err(KernelError::NotPermitted.errno());
            }
            Ok(0)
        }

        _ => Err(KernelError::InvalidArgument.errno()),
    }
}
