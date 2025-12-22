//! System V Shared Memory Implementation
//!
//! Provides shared memory segments that can be attached to multiple process
//! address spaces for inter-process communication.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, Ordering};

use crate::arch::Uaccess;
use crate::ipc::util::{
    IPC_PERM_READ, IPC_PERM_WRITE, IpcObject, IpcType, KernIpcPerm, ipc_checkperm, ipcget,
};
use crate::ipc::{IPC_64, IPC_RMID, IPC_SET, IPC_STAT, IpcNamespace, Shmid64Ds, current_ipc_ns};
use crate::mm::vma::{
    MAP_SHARED, PROT_READ as VMA_PROT_READ, PROT_WRITE as VMA_PROT_WRITE, VM_SHM,
};
use crate::mm::{Vma, get_task_mm};
use crate::task::percpu::{current_pid, current_tid, get_current_task_cr3};
use crate::time::TIMEKEEPER;
use crate::uaccess::{get_user, put_user};
use spin::Mutex;

const PAGE_SIZE: usize = 4096;

// Error codes
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EPERM: i32 = 1;
const EFAULT: i32 = 14;

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
    /// Physical frames backing this segment
    pub frames: Mutex<Vec<u64>>,
    /// Namespace this segment belongs to
    ns: Arc<IpcNamespace>,
}

impl ShmidKernel {
    /// Create a new shared memory segment
    pub fn new(key: i32, size: usize, mode: u16, ns: Arc<IpcNamespace>) -> Result<Arc<Self>, i32> {
        let num_pages = size.div_ceil(PAGE_SIZE);

        // Allocate physical frames
        let mut frames = Vec::with_capacity(num_pages);
        for _ in 0..num_pages {
            let frame = crate::FRAME_ALLOCATOR.alloc().ok_or(ENOMEM)?;

            // Zero the frame
            unsafe {
                let ptr = frame as *mut u8;
                core::ptr::write_bytes(ptr, 0, PAGE_SIZE);
            }

            frames.push(frame);
        }

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
            frames: Mutex::new(frames),
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

    fn ipc_type(&self) -> IpcType {
        IpcType::Shm
    }

    fn destroy(&self) {
        // Free all frames
        let frames = self.frames.lock();
        for &frame in frames.iter() {
            crate::FRAME_ALLOCATOR.free(frame);
        }

        // Update namespace totals
        let pages = frames.len() as u64;
        self.ns.shm_tot.fetch_sub(pages, Ordering::Relaxed);
    }
}

// ============================================================================
// Safe Downcasting
// ============================================================================

/// Safely downcast an IpcObject to ShmidKernel
///
/// Returns None if the object is not a shared memory segment.
/// This is safe because we verify the type tag before casting.
fn downcast_shm(obj: &dyn IpcObject) -> Option<&ShmidKernel> {
    if obj.ipc_type() == IpcType::Shm {
        // SAFETY: We verified the type tag matches, so this cast is valid.
        // The IpcType::Shm tag is only returned by ShmidKernel::ipc_type().
        Some(unsafe { &*(obj as *const dyn IpcObject as *const ShmidKernel) })
    } else {
        None
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
        return Err(EINVAL);
    }

    let ns_clone = ns.clone();
    ipcget(ns.shm_ids(), key, shmflg, ns.shm_ctlmni, move |k, mode| {
        // Check total memory limit
        let pages = size.div_ceil(PAGE_SIZE) as u64;
        let current_tot = ns_clone.shm_tot.load(Ordering::Relaxed);
        if current_tot + pages > ns_clone.shm_ctlall as u64 {
            return Err(ENOMEM);
        }

        let shm = ShmidKernel::new(k, size, mode, ns_clone.clone())?;
        ns_clone.shm_tot.fetch_add(pages, Ordering::Relaxed);
        Ok(shm)
    })
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

    // Find segment
    let shm_obj = ns.shm_ids().find_by_id(shmid).ok_or(EINVAL)?;
    let perm = shm_obj.perm();

    // Check permissions
    let access = if shmflg & SHM_RDONLY != 0 {
        IPC_PERM_READ
    } else {
        IPC_PERM_READ | IPC_PERM_WRITE
    };
    if let Err(e) = ipc_checkperm(perm, access) {
        perm.put_ref();
        return Err(e);
    }

    // Get the ShmidKernel (safe downcast with type verification)
    let shm_kernel: &ShmidKernel = match downcast_shm(shm_obj.as_ref()) {
        Some(shm) => shm,
        None => {
            perm.put_ref();
            return Err(EINVAL);
        }
    };

    let size = shm_kernel.segsz;

    // Get task's mm
    let mm = match get_task_mm(tid) {
        Some(m) => m,
        None => {
            perm.put_ref();
            return Err(ENOMEM);
        }
    };

    // Find address and create VMA
    let addr = {
        let mut mm_guard = mm.lock();

        // Find address space
        let addr = if shmaddr == 0 {
            // Kernel chooses address
            match mm_guard.find_free_area(size as u64) {
                Some(a) => a,
                None => {
                    perm.put_ref();
                    return Err(ENOMEM);
                }
            }
        } else {
            // User requested specific address
            let aligned_addr = if shmflg & SHM_RND != 0 {
                shmaddr & !(PAGE_SIZE as u64 - 1)
            } else {
                if shmaddr & (PAGE_SIZE as u64 - 1) != 0 {
                    perm.put_ref();
                    return Err(EINVAL);
                }
                shmaddr
            };

            // Check if requested range is available
            if mm_guard.overlaps(aligned_addr, aligned_addr + size as u64) {
                if shmflg & SHM_REMAP == 0 {
                    perm.put_ref();
                    return Err(EINVAL);
                }
                // SHM_REMAP: remove overlapping VMAs
                mm_guard.remove_range(aligned_addr, aligned_addr + size as u64);
            }
            aligned_addr
        };

        // Determine protection flags
        let prot = if shmflg & SHM_RDONLY != 0 {
            VMA_PROT_READ
        } else {
            VMA_PROT_READ | VMA_PROT_WRITE
        };

        // Create VMA for the shared memory mapping
        // Store shmid in the offset field for later lookup in shmdt
        let mut vma = Vma::new(addr, addr + size as u64, prot, MAP_SHARED | VM_SHM);
        vma.offset = shmid as u64;
        mm_guard.insert_vma(vma);

        addr
    }; // mm_guard dropped here

    // Map the physical frames into the process's page tables
    let cr3 = get_current_task_cr3();
    if cr3 == 0 {
        perm.put_ref();
        return Err(ENOMEM);
    }

    // Calculate page table flags
    #[cfg(target_arch = "x86_64")]
    let pt_flags = {
        use crate::arch::x86_64::paging::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};
        let mut flags = PAGE_PRESENT | PAGE_USER;
        if shmflg & SHM_RDONLY == 0 {
            flags |= PAGE_WRITABLE;
        }
        flags
    };

    #[cfg(target_arch = "aarch64")]
    let pt_flags = {
        // AArch64 page attributes for user mapping
        // AF=1 (Access Flag), SH=11 (Inner Shareable), AP=01 (R/W from EL0)
        const ATTR_AF: u64 = 1 << 10;
        const ATTR_SH_INNER: u64 = 3 << 8;
        const ATTR_AP_RW_EL0: u64 = 1 << 6;
        const ATTR_AP_RO_EL0: u64 = 3 << 6;
        const ATTR_NORMAL_MEMORY: u64 = 0; // Use MAIR index 0 for normal memory
        const PAGE_VALID: u64 = 0b11; // Valid page descriptor

        let ap = if shmflg & SHM_RDONLY != 0 {
            ATTR_AP_RO_EL0
        } else {
            ATTR_AP_RW_EL0
        };
        PAGE_VALID | ATTR_AF | ATTR_SH_INNER | ATTR_NORMAL_MEMORY | ap
    };

    // Map all frames eagerly
    let frames = shm_kernel.frames.lock();
    for (i, &frame) in frames.iter().enumerate() {
        let va = addr + (i * PAGE_SIZE) as u64;

        #[cfg(target_arch = "x86_64")]
        {
            use crate::arch::x86_64::interrupts::map_user_page;
            if map_user_page(cr3, va, frame, pt_flags).is_err() {
                // Mapping failed - unmap what we've done so far and fail
                for j in 0..i {
                    let unmap_va = addr + (j * PAGE_SIZE) as u64;
                    crate::arch::x86_64::interrupts::unmap_user_page(cr3, unmap_va);
                }
                drop(frames);
                perm.put_ref();
                return Err(ENOMEM);
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            use crate::arch::aarch64::exceptions::map_user_page;
            if map_user_page(cr3, va, frame, pt_flags).is_err() {
                // Mapping failed - unmap what we've done so far and fail
                for j in 0..i {
                    let unmap_va = addr + (j * PAGE_SIZE) as u64;
                    crate::arch::aarch64::exceptions::unmap_user_page(cr3, unmap_va);
                }
                drop(frames);
                perm.put_ref();
                return Err(ENOMEM);
            }
        }
    }
    drop(frames);

    // Update statistics
    shm_kernel.nattch.fetch_add(1, Ordering::Relaxed);
    shm_kernel
        .atim
        .store(current_time_secs(), Ordering::Relaxed);
    shm_kernel
        .lpid
        .store(current_pid() as i32, Ordering::Relaxed);

    perm.put_ref();
    Ok(addr)
}

/// shmdt - detach shared memory segment
///
/// # Arguments
/// * `shmaddr` - Address where segment is attached
pub fn sys_shmdt(shmaddr: u64) -> i64 {
    result_to_i64(do_shmdt(shmaddr))
}

fn do_shmdt(shmaddr: u64) -> Result<i32, i32> {
    let tid = current_tid();
    let ns = current_ipc_ns();

    // Get task's mm
    let mm = get_task_mm(tid).ok_or(EINVAL)?;

    // Find and validate the VMA
    let (shmid, size) = {
        let mm_guard = mm.lock();

        // Find VMA for this address
        let vma = mm_guard.find_vma(shmaddr).ok_or(EINVAL)?;

        // Must detach at start address
        if vma.start != shmaddr {
            return Err(EINVAL);
        }

        // Must be a SHM VMA
        if vma.flags & VM_SHM == 0 {
            return Err(EINVAL);
        }

        // Get shmid from VMA offset field
        let shmid = vma.offset as i32;
        let size = vma.end - vma.start;

        (shmid, size)
    }; // mm_guard dropped

    // Get page table root
    let cr3 = get_current_task_cr3();
    if cr3 == 0 {
        return Err(EINVAL);
    }

    // Unmap pages from page tables
    let pages = (size / PAGE_SIZE as u64) as usize;
    for i in 0..pages {
        let va = shmaddr + (i * PAGE_SIZE) as u64;

        #[cfg(target_arch = "x86_64")]
        {
            crate::arch::x86_64::interrupts::unmap_user_page(cr3, va);
        }

        #[cfg(target_arch = "aarch64")]
        {
            crate::arch::aarch64::exceptions::unmap_user_page(cr3, va);
        }
    }

    // Remove VMA
    {
        let mut mm_guard = mm.lock();
        mm_guard.remove_range(shmaddr, shmaddr + size);
    }

    // Update segment statistics
    if let Some(shm_obj) = ns.shm_ids().find_by_id(shmid) {
        let shm_kernel: &ShmidKernel = match downcast_shm(shm_obj.as_ref()) {
            Some(shm) => shm,
            None => return Err(EINVAL),
        };

        let old_nattch = shm_kernel.nattch.fetch_sub(1, Ordering::Relaxed);
        shm_kernel
            .dtim
            .store(current_time_secs(), Ordering::Relaxed);
        shm_kernel
            .lpid
            .store(current_pid() as i32, Ordering::Relaxed);

        shm_obj.perm().put_ref();

        // If segment was marked for deletion and this was last attachment, destroy it
        if old_nattch == 1 && shm_obj.perm().is_deleted() {
            shm_obj.destroy();
        }
    }

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
            let shm = ns.shm_ids().find_by_id(shmid).ok_or(EINVAL)?;

            // Check read permission
            ipc_checkperm(shm.perm(), IPC_PERM_READ)?;

            // Fill and copy structure
            let mut ds = Shmid64Ds::default();

            // Downcast safely with type verification
            let shm_kernel: &ShmidKernel = match downcast_shm(shm.as_ref()) {
                Some(shm) => shm,
                None => return Err(EINVAL),
            };
            shm_kernel.fill_shmid64_ds(&mut ds);

            if buf != 0 {
                put_user::<Uaccess, Shmid64Ds>(buf, ds).map_err(|_| EFAULT)?;
            }

            shm.perm().put_ref();
            Ok(0)
        }

        IPC_SET => {
            let shm = ns.shm_ids().find_by_id(shmid).ok_or(EINVAL)?;

            // Must be owner or have CAP_SYS_ADMIN
            let cred = crate::task::percpu::current_cred();
            let uid = cred.euid;
            let perm = shm.perm();
            if uid != perm.uid && uid != perm.cuid && uid != 0 {
                perm.put_ref();
                return Err(EPERM);
            }

            // Read user data
            let ds: Shmid64Ds = get_user::<Uaccess, Shmid64Ds>(buf).map_err(|_| EFAULT)?;

            // Update fields (only uid, gid, mode can be changed)
            let _lock = perm.lock.lock();
            // Safety: we hold the lock
            let perm_mut = perm as *const KernIpcPerm as *mut KernIpcPerm;
            unsafe {
                (*perm_mut).uid = ds.shm_perm.uid;
                (*perm_mut).gid = ds.shm_perm.gid;
                (*perm_mut).mode = ds.shm_perm.mode & 0o777;
            }

            // Update ctime (safe downcast with type verification)
            let shm_kernel: &ShmidKernel = match downcast_shm(shm.as_ref()) {
                Some(shm) => shm,
                None => {
                    perm.put_ref();
                    return Err(EINVAL);
                }
            };
            shm_kernel
                .ctim
                .store(current_time_secs(), Ordering::Relaxed);

            perm.put_ref();
            Ok(0)
        }

        IPC_RMID => {
            // Must be owner or have CAP_SYS_ADMIN
            let shm = ns.shm_ids().find_by_id(shmid).ok_or(EINVAL)?;

            let cred = crate::task::percpu::current_cred();
            let uid = cred.euid;
            let perm = shm.perm();
            if uid != perm.uid && uid != perm.cuid && uid != 0 {
                perm.put_ref();
                return Err(EPERM);
            }
            perm.put_ref();

            // Remove from ID table
            if let Some(removed) = ns.shm_ids().remove(shmid) {
                // If no attachments, destroy immediately (safe downcast with type verification)
                // Otherwise, segment will be destroyed when last process detaches
                if let Some(shm_kernel) = downcast_shm(removed.as_ref())
                    && shm_kernel.nattch.load(Ordering::Relaxed) == 0
                {
                    removed.destroy();
                }
            }

            Ok(0)
        }

        SHM_LOCK | SHM_UNLOCK => {
            // Lock/unlock requires CAP_IPC_LOCK
            // For now, just validate and return success (no swap anyway)
            let shm = ns.shm_ids().find_by_id(shmid).ok_or(EINVAL)?;
            shm.perm().put_ref();
            Ok(0)
        }

        _ => Err(EINVAL),
    }
}
