//! System V Shared Memory Implementation
//!
//! Provides shared memory segments that can be attached to multiple process
//! address spaces for inter-process communication.
//!
//! A segment is a file on the kernel's tmpfs ("SYSV<key>", Linux
//! shmem_kernel_file_setup), its pages in that file's page cache,
//! faulted in on demand. Each attachment is a VMA mapping the file and
//! holding a [`ShmAttach`]: shm_nattch counts those VMAs (Linux
//! shm_open/shm_close), so fork's copies, split pieces and their removal
//! by munmap, shmdt, exit or exec all keep it right. IPC_RMID of an
//! attached segment marks it SHM_DEST and drops its key; it stays found
//! by id (IPC_STAT, shmat) until the last detach removes and destroys it
//! (Linux do_shm_rmid, shm_close). The pages go with the file, when the
//! segment and its last VMA are gone.
//!
//! Locking: attach, detach and IPC_RMID decide under the segment's
//! `KernIpcPerm.lock` (spin leaf: nattch with SHM_DEST, and the deleted
//! mark), then remove it from the table (`IpcIds.inner`) after releasing
//! it; a detach may run under the mm lock (both are leaves below it).

use crate::util::kalloc::try_arc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, Ordering};

use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, IpcOps, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{IPC_64, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Shmid64Ds, current_ipc_ns};
use crate::mm::Vma;
use crate::mm::vma::{
    MAP_SHARED, PROT_READ as VMA_PROT_READ, PROT_WRITE as VMA_PROT_WRITE, VM_SHARED, VM_SHM,
};
use crate::task::percpu::current_pid;
use crate::time::TIMEKEEPER;
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};

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
/// SHM_STAT without the read permission check
pub const SHM_STAT_ANY: i32 = 15;
/// Limits (Linux IPC_INFO)
pub const IPC_INFO: i32 = 3;
/// Removed, destroyed at its last detach (mode bit)
pub const SHM_DEST: u16 = 0o1000;

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
    /// The segment's file on the kernel's tmpfs (its pages)
    pub file: Arc<crate::fs::File>,
    /// Destroyed (namespace totals given back): at most once
    destroyed: AtomicBool,
    /// Namespace this segment belongs to
    ns: Arc<IpcNamespace>,
}

impl ShmidKernel {
    /// Create a new shared memory segment
    /// (Pages are allocated as they are first touched.)
    pub fn new(key: i32, size: usize, mode: u16, ns: Arc<IpcNamespace>) -> KernelResult<Arc<Self>> {
        let now = current_time_secs();
        let pid = current_pid() as i32;

        try_arc(Self {
            perm: KernIpcPerm::new(key, mode),
            segsz: size,
            nattch: AtomicU32::new(0),
            atim: AtomicI64::new(0),
            dtim: AtomicI64::new(0),
            ctim: AtomicI64::new(now),
            cpid: pid,
            lpid: AtomicI32::new(pid),
            file: crate::fs::tmpfs::shmem_kernel_file_setup(
                alloc::format!("SYSV{:08x}", key as u32).as_bytes(),
                size as u64,
            )?,
            destroyed: AtomicBool::new(false),
            ns,
        })
    }

    /// Fill shmid64_ds structure for IPC_STAT
    pub fn fill_shmid64_ds(&self, ds: &mut Shmid64Ds) {
        self.perm.fill_ipc64_perm(&mut ds.shm_perm);
        ds.shm_segsz = self.segsz;
        ds.shm_atime = self.atim.load(Ordering::Relaxed);
        ds.shm_dtime = self.dtim.load(Ordering::Relaxed);
        ds.shm_ctime = self.ctim.load(Ordering::Relaxed);
        // In the caller's namespace (Linux shm: pid_vnr)
        ds.shm_cpid = crate::task::pid::vnr(self.cpid as u64) as i32;
        ds.shm_lpid = crate::task::pid::vnr(self.lpid.load(Ordering::Relaxed) as u64) as i32;
        ds.shm_nattch = u64::from(self.nattch.load(Ordering::Relaxed));
        ds.__unused4 = 0;
        ds.__unused5 = 0;
    }
}

impl IpcObject for ShmidKernel {
    fn perm(&self) -> &KernIpcPerm {
        &self.perm
    }

    /// Linux shm_destroy: once removed (IPC_RMID) and detached. The
    /// pages go with the last reference to the segment's file.
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
/// destroys it. Takes the segment's perm lock (a leaf; safe under the mm
/// lock).
pub struct ShmAttach {
    seg: Arc<ShmidKernel>,
    /// Attached SHM_RDONLY: never writable (Linux: no VM_MAYWRITE)
    rdonly: bool,
}

impl ShmAttach {
    fn shm(&self) -> &ShmidKernel {
        &self.seg
    }

    /// A new attachment, unless the segment was destroyed meanwhile
    /// (its last detach after IPC_RMID raced the lookup): EINVAL like a
    /// removed id. A removed segment still attached (SHM_DEST) may be
    /// attached again, as Linux.
    fn attach_live(seg: Arc<ShmidKernel>, rdonly: bool) -> Option<Self> {
        {
            let _l = seg.perm().lock.lock();
            if seg.perm().is_deleted() {
                return None;
            }
            seg.nattch.fetch_add(1, Ordering::Relaxed);
        }
        let a = Self { seg, rdonly };
        a.touch();
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

    /// Linux shm_open: attach time, last pid
    fn touch(&self) {
        let shp = self.shm();
        shp.atim.store(current_time_secs(), Ordering::Relaxed);
        shp.lpid.store(current_pid() as i32, Ordering::Relaxed);
    }
}

impl Clone for ShmAttach {
    /// Another VMA of an attachment (fork, split): the segment is
    /// attached, so it is not destroyed
    fn clone(&self) -> Self {
        {
            let _l = self.seg.perm().lock.lock();
            self.seg.nattch.fetch_add(1, Ordering::Relaxed);
        }
        let a = Self {
            seg: self.seg.clone(),
            rdonly: self.rdonly,
        };
        a.touch();
        a
    }
}

impl Drop for ShmAttach {
    /// Linux shm_close: detach time, last pid; the last detach of a
    /// removed (SHM_DEST) segment marks it deleted, then takes it out of
    /// its table and destroys it
    fn drop(&mut self) {
        let shp = self.shm();
        shp.dtim.store(current_time_secs(), Ordering::Relaxed);
        shp.lpid.store(current_pid() as i32, Ordering::Relaxed);
        let last = {
            let p = shp.perm().lock.lock();
            let n = shp.nattch.fetch_sub(1, Ordering::Relaxed) - 1;
            let last = n == 0 && p.mode & SHM_DEST != 0;
            if last {
                shp.perm().mark_deleted();
            }
            last.then_some(p.id)
        };
        if let Some(id) = last {
            shp.ns.shm_ids().remove_obj(id, &self.seg);
            self.seg.destroy();
        }
    }
}

// ============================================================================
// Syscalls
// ============================================================================

/// shmget - get shared memory segment
///
/// # Arguments
/// * `key` - Key to identify segment (IPC_PRIVATE for new private segment)
/// * `size` - Size of segment in bytes
/// * `shmflg` - Flags (IPC_CREAT, IPC_EXCL, permission bits)
pub fn sys_shmget(key: i32, size: usize, shmflg: i32) -> KernelResult<i32> {
    let ns = current_ipc_ns();

    // Validate size
    if size < SHMMIN || size > ns.shm_ctlmax {
        return Err(KernelError::InvalidArgument);
    }

    let ns_clone = ns.clone();
    let ns_added = ns.clone();
    let pages = size.div_ceil(PAGE_SIZE) as u64;
    let ops = IpcOps {
        // Linux newseg: ENOSPC past SHMALL
        new: move |k, mode| {
            // Linux newseg: whole pages that cannot hold `size` (the
            // page-rounded size wraps), or past SHMALL, are ENOSPC
            if pages.checked_mul(PAGE_SIZE as u64).is_none() {
                return Err(KernelError::NoSpace);
            }
            let tot = ns_clone.shm_tot.load(Ordering::Relaxed);
            if tot
                .checked_add(pages)
                .is_none_or(|t| t > ns_clone.shm_ctlall as u64)
            {
                return Err(KernelError::NoSpace);
            }
            // The shmem file past the largest file size (Linux
            // __shmem_file_setup) is EINVAL
            if size as u64 > crate::fs::superblock::MAX_LFS_FILESIZE {
                return Err(KernelError::InvalidArgument);
            }
            ShmidKernel::new(k, size, mode, ns_clone.clone())
        },
        // Linux shm_more_checks
        more_checks: |shm: &ShmidKernel| {
            if shm.segsz < size {
                return Err(KernelError::InvalidArgument);
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
pub fn sys_shmat(shmid: i32, shmaddr: u64, shmflg: i32) -> KernelResult<u64> {
    let ns = current_ipc_ns();
    let einval = KernelError::InvalidArgument;

    let shm_obj = ns.shm_ids().find_by_id(shmid).ok_or(einval)?;
    let access = if shmflg & SHM_RDONLY != 0 {
        IPC_PERM_READ
    } else {
        IPC_PERM_READ | IPC_PERM_WRITE
    };
    ipc_checkperm(shm_obj.perm(), access)?;
    let shm_kernel: &ShmidKernel = &shm_obj;
    let size = (shm_kernel.segsz as u64).div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;
    let file = shm_kernel.file.clone();

    // SHM_REMAP needs an address (Linux do_shmat)
    if shmaddr == 0 && shmflg & SHM_REMAP != 0 {
        return Err(einval);
    }
    let mm = crate::task::percpu::current()
        .mm()
        .ok_or(KernelError::OutOfMemory)?;
    let mut replaced = Vec::new();
    let mut mm_guard = mm
        .mmap_write_killable()
        .map_err(|_| KernelError::Interrupted)?;
    // RLIMIT_AS, as for any mapping (Linux may_expand_vm)
    let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_AS);
    if limit != crate::task::rlimit::RLIM_INFINITY
        && (mm_guard.total_vm() * PAGE_SIZE as u64).saturating_add(size) > limit
    {
        return Err(KernelError::OutOfMemory);
    }
    let addr = if shmaddr == 0 {
        mm_guard
            .find_free_area(size)
            .ok_or(KernelError::OutOfMemory)?
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
        crate::mm::check_fixed(aligned, size)?;
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
    // A mapping of the segment's file (Linux shm_mmap)
    let flags = MAP_SHARED | VM_SHARED | VM_SHM;
    let mut vma = Vma::new_file(addr, addr + size, prot, flags, file, 0);
    vma.shm =
        Some(ShmAttach::attach_live((*shm_obj).clone(), shmflg & SHM_RDONLY != 0).ok_or(einval)?);
    mm_guard.insert_vma(vma);
    mm_guard.add_total_vm(size / PAGE_SIZE as u64);
    drop(mm_guard);
    drop(replaced);
    Ok(addr)
}

/// shmdt - detach shared memory segment (Linux ksys_shmdt)
///
/// Unmap the attachment starting at `shmaddr`, all of
/// its VMAs (a split one included) up to the segment's size; dropping
/// them updates shm_nattch
pub fn sys_shmdt(shmaddr: u64) -> KernelResult<()> {
    let einval = KernelError::InvalidArgument;
    let mm = crate::task::percpu::current().mm().ok_or(einval)?;
    let gone = {
        let mut map = mm
            .mmap_write_killable()
            .map_err(|_| KernelError::Interrupted)?;
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
    Ok(())
}

/// shmctl - shared memory control
///
/// # Arguments
/// * `shmid` - Segment ID
/// * `cmd` - Command (IPC_STAT, IPC_SET, IPC_RMID, etc.)
/// * `buf` - User buffer for data
pub fn sys_shmctl(shmid: i32, cmd: i32, buf: UserPtr<Shmid64Ds>) -> KernelResult<i32> {
    let ns = current_ipc_ns();
    let cmd_only = cmd & !IPC_64;

    match cmd_only {
        // Linux shmctl_stat: IPC_STAT by id (0), SHM_STAT / SHM_STAT_ANY
        // by table index (the full id); SHM_STAT_ANY skips the read check
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            let einval = KernelError::InvalidArgument;
            let (shm, ret) = if cmd_only == IPC_STAT {
                (ns.shm_ids().find_by_id(shmid).ok_or(einval)?, 0)
            } else {
                ns.shm_ids().find_by_idx(shmid).ok_or(einval)?
            };
            if cmd_only != SHM_STAT_ANY {
                ipc_checkperm(shm.perm(), IPC_PERM_READ)?;
            }
            let mut ds = Shmid64Ds::default();
            shm.fill_shmid64_ds(&mut ds);
            buf.write(&ds)?;
            Ok(ret)
        }

        IPC_INFO => {
            let info = ShmInfo64 {
                shmmax: ns.shm_ctlmax as u64,
                shmmin: SHMMIN as u64,
                shmmni: u64::from(ns.shm_ctlmni),
                shmseg: u64::from(ns.shm_ctlmni),
                shmall: ns.shm_ctlall as u64,
                unused: [0; 4],
            };
            let idx = ns.shm_ids().max_idx().max(0);
            UserPtr::<ShmInfo64>::new(buf.addr()).write(&info)?;
            Ok(idx)
        }

        SHM_INFO => {
            let ids = ns.shm_ids();
            let info = ShmInfo {
                used_ids: ids.in_use() as i32,
                pad: 0,
                shm_tot: ns.shm_tot.load(Ordering::Relaxed),
                shm_rss: shm_rss(&ns),
                shm_swp: 0,
                swap_attempts: 0,
                swap_successes: 0,
            };
            let idx = ids.max_idx().max(0);
            UserPtr::<ShmInfo>::new(buf.addr()).write(&info)?;
            Ok(idx)
        }

        IPC_SET => {
            // Copied in first, before the IPC locks (Linux: the copy
            // may fault)
            let ds = buf.read()?;
            let _w = ns.shm_ids().rwsem.write();
            let shm = ns
                .shm_ids()
                .find_by_id(shmid)
                .ok_or(KernelError::InvalidArgument)?;

            // Must be owner or have CAP_SYS_ADMIN; only uid, gid, mode
            // change
            let uid = crate::task::percpu::current_cred().euid;
            let perm = shm.perm();
            {
                let mut p = perm.lock.lock();
                if !KernIpcPerm::is_owner(&p, perm.cuid, uid) {
                    return Err(KernelError::NotPermitted);
                }
                p.uid = ds.shm_perm.uid;
                p.gid = ds.shm_perm.gid;
                // SHM_DEST stays (Linux: only S_IRWXUGO change)
                p.mode = (p.mode & !0o777) | (ds.shm_perm.mode & 0o777);
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
                .ok_or(KernelError::InvalidArgument)?;

            let uid = crate::task::percpu::current_cred().euid;
            let perm = shm.perm();
            if !KernIpcPerm::is_owner(&perm.lock.lock(), perm.cuid, uid) {
                return Err(KernelError::NotPermitted);
            }

            // Linux do_shm_rmid: attached, it becomes SHM_DEST without a
            // key and the last detach destroys it; else it goes now.
            // Decided under the perm lock, where attach and detach count.
            let now = {
                let mut p = perm.lock.lock();
                if p.mode & SHM_DEST != 0 {
                    false
                } else if shm.nattch.load(Ordering::Relaxed) > 0 {
                    p.mode |= SHM_DEST;
                    false
                } else {
                    perm.mark_deleted();
                    true
                }
            };
            if now {
                ns.shm_ids().remove_obj(shmid, &shm);
                shm.destroy();
            } else {
                ns.shm_ids().set_key_private(&shm);
            }
            Ok(0)
        }

        SHM_LOCK | SHM_UNLOCK => {
            // Without CAP_IPC_LOCK only the owner or creator (Linux
            // shmctl_do_lock); nothing to lock (pages are never swapped)
            let shm = ns
                .shm_ids()
                .find_by_id(shmid)
                .ok_or(KernelError::InvalidArgument)?;
            let uid = crate::task::percpu::current_cred().euid;
            let perm = shm.perm();
            let owner = perm.lock.lock().uid;
            if !crate::task::capable(crate::task::CAP_IPC_LOCK) && uid != owner && uid != perm.cuid
            {
                return Err(KernelError::NotPermitted);
            }
            Ok(0)
        }

        _ => Err(KernelError::InvalidArgument),
    }
}

/// shminfo64 (Linux IPC_INFO): limits, then four unused words
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmInfo64 {
    shmmax: u64,
    shmmin: u64,
    shmmni: u64,
    shmseg: u64,
    shmall: u64,
    unused: [u64; 4],
}
crate::pod!(ShmInfo64 {
    shmmax,
    shmmin,
    shmmni,
    shmseg,
    shmall,
    unused
});

/// struct shm_info (Linux SHM_INFO)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmInfo {
    used_ids: i32,
    pad: u32,
    shm_tot: u64,
    shm_rss: u64,
    shm_swp: u64,
    swap_attempts: u64,
    swap_successes: u64,
}
crate::pod!(ShmInfo {
    used_ids,
    pad,
    shm_tot,
    shm_rss,
    shm_swp,
    swap_attempts,
    swap_successes
});

/// The resident pages of a segment (Linux shm_add_rss_swap: its file's
/// cached pages; none are swapped)
fn rss(shm: &ShmidKernel) -> u64 {
    shm.file.get_inode().map_or(0, |i| i.i_data.nrpages())
}

/// The resident pages of every segment of `ns` (Linux shm_get_stat)
fn shm_rss(ns: &IpcNamespace) -> u64 {
    let ids = ns.shm_ids();
    (0..=ids.max_idx())
        .filter_map(|i| ids.find_by_idx(i))
        .map(|(s, _)| rss(&s))
        .sum()
}

/// /proc/sysvipc/shm of the reader's IPC namespace (Linux
/// sysvipc_shm_proc_show): a header, then a line per segment
pub fn proc_sysvipc_shm() -> Vec<u8> {
    use core::fmt::Write;
    let ns = current_ipc_ns();
    let ids = ns.shm_ids();
    let mut out = alloc::string::String::from(
        "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n",
    );
    for (s, id) in (0..=ids.max_idx()).filter_map(|i| ids.find_by_idx(i)) {
        let p = s.perm();
        let (uid, gid, mode) = {
            let l = p.lock.lock();
            (l.uid, l.gid, l.mode)
        };
        let vnr = |pid: i32| crate::task::pid::vnr(pid as u64) as i32;
        let _ = writeln!(
            out,
            "{:>10} {:>10}  {:>4o} {:>21} {:>5} {:>5}  {:>5} {:>5} {:>5} {:>5} {:>5} {:>10} {:>10} {:>10} {:>21} {:>21}",
            p.key(),
            id,
            mode,
            s.segsz,
            vnr(s.cpid),
            vnr(s.lpid.load(Ordering::Relaxed)),
            s.nattch.load(Ordering::Relaxed),
            uid,
            gid,
            p.cuid,
            p.cgid,
            s.atim.load(Ordering::Relaxed),
            s.dtim.load(Ordering::Relaxed),
            s.ctim.load(Ordering::Relaxed),
            rss(&s) * PAGE_SIZE as u64,
            0
        );
    }
    out.into_bytes()
}
