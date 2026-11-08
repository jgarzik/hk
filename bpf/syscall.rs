//! BPF syscall implementation
//!
//! This module implements the bpf() syscall that provides userspace access
//! to BPF maps and programs.
//!
//! ## Syscall Signature
//!
//! ```c
//! int bpf(int cmd, union bpf_attr *attr, unsigned int size);
//! ```
//!
//! ## Supported Commands
//!
//! - `BPF_MAP_CREATE`: Create a new BPF map
//! - `BPF_MAP_LOOKUP_ELEM`: Look up an element in a map
//! - `BPF_MAP_UPDATE_ELEM`: Update/insert an element
//! - `BPF_MAP_DELETE_ELEM`: Delete an element
//! - `BPF_MAP_GET_NEXT_KEY`: Iterate through map keys
//! - `BPF_PROG_LOAD`: Load a BPF program
//! - `BPF_OBJ_GET_INFO_BY_FD`: Get object info
//!
//! ## Privilege
//!
//! As Linux: with kernel.unprivileged_bpf_disabled (default 2, Linux's
//! CONFIG_BPF_UNPRIV_DEFAULT_OFF) set, creating maps and loading
//! programs needs CAP_BPF or CAP_SYS_ADMIN (EPERM). The sysctl takes
//! 0..2 from CAP_SYS_ADMIN only, and 1 is permanent.

use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

use super::fd::{
    create_bpf_map_fd, create_bpf_prog_fd, get_bpf_map_from_fd, get_bpf_prog_info_from_fd,
};
use super::insn::BpfInsn;
use super::map::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BpfMapOps, create_map};
use super::prog::BpfProg;
use super::verifier::{Kind, verify};
use crate::arch::Uaccess;
use crate::uaccess::{copy_from_user, copy_to_user, put_user};
use crate::util::error::KernelError;
use crate::util::pod::FromBytes;

// =============================================================================
// Privilege (Linux kernel.unprivileged_bpf_disabled)
// =============================================================================

/// 0: allowed; 1: disabled for good; 2: disabled, an admin may re-enable
static UNPRIV_DISABLED: AtomicU32 = AtomicU32::new(2);

/// Most instructions in a program with CAP_BPF (Linux
/// BPF_COMPLEXITY_LIMIT_INSNS)
const MAX_INSNS_CAP: usize = 1_000_000;

/// CAP_BPF, or CAP_SYS_ADMIN which implies it (Linux bpf_capable)
fn bpf_capable() -> bool {
    use crate::task::{CAP_BPF, CAP_SYS_ADMIN, capable};
    capable(CAP_BPF) || capable(CAP_SYS_ADMIN)
}

/// EPERM unless unprivileged BPF is enabled or the caller is capable
fn unpriv_ok() -> Result<(), KernelError> {
    if UNPRIV_DISABLED.load(Ordering::Relaxed) != 0 && !bpf_capable() {
        return Err(KernelError::NotPermitted);
    }
    Ok(())
}

/// Store to kernel.unprivileged_bpf_disabled (Linux bpf_unpriv_handler)
fn unpriv_store(v: &[i64]) -> Result<(), KernelError> {
    if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    crate::sysctl::range(v[0], 0, 2)?;
    if UNPRIV_DISABLED.load(Ordering::Relaxed) == 1 && v[0] != 1 {
        return Err(KernelError::NotPermitted);
    }
    UNPRIV_DISABLED.store(v[0] as u32, Ordering::Relaxed);
    Ok(())
}

pub static BPF_CTLS: &[crate::sysctl::Ctl] = &[crate::sysctl::Ctl {
    path: "kernel/unprivileged_bpf_disabled",
    mode: 0o644,
    show: || alloc::vec![i64::from(UNPRIV_DISABLED.load(Ordering::Relaxed))],
    store: unpriv_store,
    text: None,
}];

// =============================================================================
// BPF Commands (Linux ABI)
// =============================================================================

/// Create a BPF map
pub const BPF_MAP_CREATE: i32 = 0;
/// Look up an element in a BPF map
pub const BPF_MAP_LOOKUP_ELEM: i32 = 1;
/// Update an element in a BPF map
pub const BPF_MAP_UPDATE_ELEM: i32 = 2;
/// Delete an element from a BPF map
pub const BPF_MAP_DELETE_ELEM: i32 = 3;
/// Get the next key in a BPF map
pub const BPF_MAP_GET_NEXT_KEY: i32 = 4;
/// Load a BPF program
pub const BPF_PROG_LOAD: i32 = 5;
/// Pin an object to the filesystem
pub const BPF_OBJ_PIN: i32 = 6;
/// Get a pinned object
pub const BPF_OBJ_GET: i32 = 7;
/// Attach a program
pub const BPF_PROG_ATTACH: i32 = 8;
/// Detach a program
pub const BPF_PROG_DETACH: i32 = 9;
/// Test run a program
pub const BPF_PROG_TEST_RUN: i32 = 10;
/// Copy `n` instructions from user `ptr`, fallibly (ENOMEM past the
/// heap's cap)
fn copy_insns(ptr: u64, n: usize) -> Result<Vec<BpfInsn>, KernelError> {
    let bytes = n * size_of::<BpfInsn>();
    let mut raw = crate::util::kmem::try_vec(bytes, 0u8)?;
    copy_from_user::<Uaccess>(&mut raw, ptr, bytes).map_err(|_| KernelError::BadAddress)?;
    let mut insns = crate::util::kmem::try_vec(n, BpfInsn::default())?;
    for (i, b) in insns.iter_mut().zip(raw.as_chunks::<8>().0) {
        *i = BpfInsn::from_bytes(b);
    }
    Ok(insns)
}

/// Get object info by fd
pub const BPF_OBJ_GET_INFO_BY_FD: i32 = 15;
/// Freeze a map (make read-only)
pub const BPF_MAP_FREEZE: i32 = 22;

// =============================================================================
// BPF Program Types (Linux ABI)
// =============================================================================

/// Unspecified program type
pub const BPF_PROG_TYPE_UNSPEC: u32 = 0;
/// Socket filter
pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
/// kprobe
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
/// Traffic classifier
pub const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
/// Traffic action
pub const BPF_PROG_TYPE_SCHED_ACT: u32 = 4;
/// Tracepoint
pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
/// XDP
pub const BPF_PROG_TYPE_XDP: u32 = 6;

// =============================================================================
// BPF Attribute Structures (Linux ABI)
// =============================================================================

/// Size of bpf_attr union (must match Linux)
pub const BPF_ATTR_SIZE: usize = 152;

/// Map creation attributes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MapCreateAttr {
    /// Map type (BPF_MAP_TYPE_*)
    pub map_type: u32,
    /// Size of keys in bytes
    pub key_size: u32,
    /// Size of values in bytes
    pub value_size: u32,
    /// Maximum number of entries
    pub max_entries: u32,
    /// Map flags
    pub map_flags: u32,
    /// Inner map fd (for map-in-map)
    pub inner_map_fd: u32,
    /// NUMA node (if BPF_F_NUMA_NODE set)
    pub numa_node: u32,
    /// Map name (16 bytes max)
    pub map_name: [u8; 16],
}

/// Map element operation attributes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MapElemAttr {
    /// Map file descriptor
    pub map_fd: u32,
    /// Padding
    pub _pad0: u32,
    /// Pointer to key
    pub key: u64,
    /// Pointer to value or next_key
    pub value: u64,
    /// Flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST)
    pub flags: u64,
}

/// Program load attributes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProgLoadAttr {
    /// Program type
    pub prog_type: u32,
    /// Number of instructions
    pub insn_cnt: u32,
    /// Pointer to instructions
    pub insns: u64,
    /// Pointer to license string
    pub license: u64,
    /// Verifier log level
    pub log_level: u32,
    /// Size of log buffer
    pub log_size: u32,
    /// Pointer to log buffer
    pub log_buf: u64,
    /// Kernel version (not used)
    pub kern_version: u32,
    /// Program flags
    pub prog_flags: u32,
    /// Program name (16 bytes max)
    pub prog_name: [u8; 16],
    /// ifindex
    pub prog_ifindex: u32,
    /// Expected attach type
    pub expected_attach_type: u32,
}

/// Object info request attributes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ObjGetInfoAttr {
    /// Object file descriptor
    pub bpf_fd: u32,
    /// Size of info structure
    pub info_len: u32,
    /// Pointer to info structure
    pub info: u64,
}

crate::pod!(
    MapCreateAttr { map_type, key_size, value_size, max_entries, map_flags, inner_map_fd, numa_node, map_name };
    MapElemAttr { map_fd, _pad0, key, value, flags };
    ProgLoadAttr {
        prog_type, insn_cnt, insns, license, log_level, log_size, log_buf, kern_version,
        prog_flags, prog_name, prog_ifindex, expected_attach_type
    };
    ObjGetInfoAttr { bpf_fd, info_len, info }
);

/// struct bpf_map_info (Linux uapi, BPF_OBJ_GET_INFO_BY_FD); hk fills
/// the map's own fields, the rest stays as the caller's or zero
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BpfMapInfo {
    pub map_type: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub name: [u8; 16],
    pub ifindex: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub btf_vmlinux_id: u32,
    pub map_extra: u64,
    /// Where to store the map's hash (only frozen maps with a hash op)
    pub hash: u64,
    pub hash_size: u32,
    pub _pad: u32,
}

/// struct bpf_prog_info (Linux uapi); hk has no JIT, BTF, maps used by
/// a program or run statistics, so those read as none
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BpfProgInfo {
    pub prog_type: u32,
    pub id: u32,
    pub tag: [u8; 8],
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub jited_prog_insns: u64,
    pub xlated_prog_insns: u64,
    pub load_time: u64,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: u64,
    pub name: [u8; 16],
    pub ifindex: u32,
    /// gpl_compatible:1, then padding bits
    pub gpl_flags: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_ksyms: u32,
    pub nr_jited_func_lens: u32,
    pub jited_ksyms: u64,
    pub jited_func_lens: u64,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub nr_func_info: u32,
    pub nr_line_info: u32,
    pub line_info: u64,
    pub jited_line_info: u64,
    pub nr_jited_line_info: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub nr_prog_tags: u32,
    pub prog_tags: u64,
    pub run_time_ns: u64,
    pub run_cnt: u64,
    pub recursion_misses: u64,
    pub verified_insns: u32,
    pub attach_btf_obj_id: u32,
    pub attach_btf_id: u32,
    pub _pad: u32,
}

crate::pod!(
    BpfMapInfo {
        map_type, id, key_size, value_size, max_entries, map_flags, name, ifindex,
        btf_vmlinux_value_type_id, netns_dev, netns_ino, btf_id, btf_key_type_id,
        btf_value_type_id, btf_vmlinux_id, map_extra, hash, hash_size, _pad
    };
    BpfProgInfo {
        prog_type, id, tag, jited_prog_len, xlated_prog_len, jited_prog_insns,
        xlated_prog_insns, load_time, created_by_uid, nr_map_ids, map_ids, name, ifindex,
        gpl_flags, netns_dev, netns_ino, nr_jited_ksyms, nr_jited_func_lens, jited_ksyms,
        jited_func_lens, btf_id, func_info_rec_size, func_info, nr_func_info, nr_line_info,
        line_info, jited_line_info, nr_jited_line_info, line_info_rec_size,
        jited_line_info_rec_size, nr_prog_tags, prog_tags, run_time_ns, run_cnt,
        recursion_misses, verified_insns, attach_btf_obj_id, attach_btf_id, _pad
    }
);

// =============================================================================
// Syscall Implementation
// =============================================================================

/// BPF syscall entry point
///
/// # Arguments
/// * `cmd` - BPF command (BPF_MAP_CREATE, etc.)
/// * `attr` - Pointer to bpf_attr union
/// * `size` - Size of attr structure
///
/// # Returns
/// File descriptor or 0 on success, negative errno on failure.
pub fn sys_bpf(cmd: i32, attr: u64, size: u32) -> i64 {
    // Validate size
    if size == 0 || size as usize > BPF_ATTR_SIZE {
        return KernelError::InvalidArgument.sysret();
    }

    // Copy attr from userspace into a buffer
    let mut attr_buf = [0u8; BPF_ATTR_SIZE];
    let copy_size = core::cmp::min(size as usize, BPF_ATTR_SIZE);

    if copy_from_user::<Uaccess>(&mut attr_buf[..copy_size], attr, copy_size).is_err() {
        return KernelError::BadAddress.sysret();
    }

    match cmd {
        BPF_MAP_CREATE => bpf_map_create(&attr_buf),
        BPF_MAP_LOOKUP_ELEM => bpf_map_lookup_elem(&attr_buf),
        BPF_MAP_UPDATE_ELEM => bpf_map_update_elem(&attr_buf),
        BPF_MAP_DELETE_ELEM => bpf_map_delete_elem(&attr_buf),
        BPF_MAP_GET_NEXT_KEY => bpf_map_get_next_key(&attr_buf),
        BPF_PROG_LOAD => bpf_prog_load(&attr_buf),
        BPF_OBJ_GET_INFO_BY_FD => bpf_obj_get_info_by_fd(&attr_buf, attr),
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// Create a BPF map
fn bpf_map_create(attr_buf: &[u8]) -> i64 {
    // Parse MapCreateAttr
    if let Err(e) = unpriv_ok() {
        return e.sysret();
    }

    let Some(attr) = MapCreateAttr::read_from(attr_buf) else {
        return KernelError::InvalidArgument.sysret();
    };

    // Validate map type
    match attr.map_type {
        BPF_MAP_TYPE_HASH | BPF_MAP_TYPE_ARRAY => {}
        _ => return KernelError::InvalidArgument.sysret(),
    }

    // Create the map
    let map = match create_map(
        attr.map_type,
        attr.key_size,
        attr.value_size,
        attr.max_entries,
        attr.map_flags,
    ) {
        Ok(m) => m,
        Err(e) => return e.sysret(),
    };

    // Create file descriptor
    match create_bpf_map_fd(map) {
        Ok(fd) => i64::from(fd),
        Err(e) => e.sysret(),
    }
}

/// Look up an element in a map
fn bpf_map_lookup_elem(attr_buf: &[u8]) -> i64 {
    let Some(attr) = MapElemAttr::read_from(attr_buf) else {
        return KernelError::InvalidArgument.sysret();
    };

    // Get map from fd
    let map = match get_bpf_map_from_fd(attr.map_fd as i32) {
        Ok(m) => m,
        Err(e) => return e.sysret(),
    };

    // Read key from userspace
    let key_size = map.key_size() as usize;
    let mut key = vec![0u8; key_size];
    if copy_from_user::<Uaccess>(&mut key, attr.key, key_size).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Lookup
    match map.lookup(&key) {
        Some(value) => {
            // Copy value to userspace
            if copy_to_user::<Uaccess>(attr.value, &value).is_err() {
                return KernelError::BadAddress.sysret();
            }
            0
        }
        None => KernelError::NotFound.sysret(),
    }
}

/// Update an element in a map
fn bpf_map_update_elem(attr_buf: &[u8]) -> i64 {
    let Some(attr) = MapElemAttr::read_from(attr_buf) else {
        return KernelError::InvalidArgument.sysret();
    };

    // Get map from fd
    let map = match get_bpf_map_from_fd(attr.map_fd as i32) {
        Ok(m) => m,
        Err(e) => return e.sysret(),
    };

    // Read key from userspace
    let key_size = map.key_size() as usize;
    let mut key = vec![0u8; key_size];
    if copy_from_user::<Uaccess>(&mut key, attr.key, key_size).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Read value from userspace
    let value_size = map.value_size() as usize;
    let mut value = vec![0u8; value_size];
    if copy_from_user::<Uaccess>(&mut value, attr.value, value_size).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Update
    match map.update(&key, &value, attr.flags) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// Delete an element from a map
fn bpf_map_delete_elem(attr_buf: &[u8]) -> i64 {
    let Some(attr) = MapElemAttr::read_from(attr_buf) else {
        return KernelError::InvalidArgument.sysret();
    };

    // Get map from fd
    let map = match get_bpf_map_from_fd(attr.map_fd as i32) {
        Ok(m) => m,
        Err(e) => return e.sysret(),
    };

    // Read key from userspace
    let key_size = map.key_size() as usize;
    let mut key = vec![0u8; key_size];
    if copy_from_user::<Uaccess>(&mut key, attr.key, key_size).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Delete
    match map.delete(&key) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// Get the next key in a map
fn bpf_map_get_next_key(attr_buf: &[u8]) -> i64 {
    let Some(attr) = MapElemAttr::read_from(attr_buf) else {
        return KernelError::InvalidArgument.sysret();
    };

    // Get map from fd
    let map = match get_bpf_map_from_fd(attr.map_fd as i32) {
        Ok(m) => m,
        Err(e) => return e.sysret(),
    };

    // Read current key from userspace (if non-null)
    let key_size = map.key_size() as usize;
    let current_key = if attr.key == 0 {
        None
    } else {
        let mut key = vec![0u8; key_size];
        if copy_from_user::<Uaccess>(&mut key, attr.key, key_size).is_err() {
            return KernelError::BadAddress.sysret();
        }
        Some(key)
    };

    // Get next key
    match map.get_next_key(current_key.as_deref()) {
        Some(next_key) => {
            // Copy next key to userspace (stored in value field)
            if copy_to_user::<Uaccess>(attr.value, &next_key).is_err() {
                return KernelError::BadAddress.sysret();
            }
            0
        }
        None => KernelError::NotFound.sysret(),
    }
}

/// Load a BPF program
fn bpf_prog_load(attr_buf: &[u8]) -> i64 {
    let Some(attr) = ProgLoadAttr::read_from(attr_buf) else {
        return KernelError::InvalidArgument.sysret();
    };

    if let Err(e) = unpriv_ok() {
        return e.sysret();
    }
    let max = if bpf_capable() {
        MAX_INSNS_CAP
    } else {
        super::insn::BPF_MAXINSNS
    };
    let n = attr.insn_cnt as usize;
    if n == 0 || n > max {
        return KernelError::ArgListTooLong.sysret();
    }
    match attr.prog_type {
        BPF_PROG_TYPE_SOCKET_FILTER => {}
        _ => return KernelError::InvalidArgument.sysret(),
    }
    let insns = match copy_insns(attr.insns, n) {
        Ok(v) => v,
        Err(e) => return e.sysret(),
    };

    // Nothing attaches a loaded program yet: no helpers, and the
    // context is a 64-byte placeholder for struct __sk_buff
    const SOCKET_FILTER: Kind = Kind {
        ctx_size: 64,
        helpers: &[],
        unreachable_ok: false,
    };
    if let Err(e) = verify(&insns, &SOCKET_FILTER, max) {
        return e.sysret();
    }

    // Create BPF program
    let prog = match BpfProg::new(insns) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };

    // Create file descriptor
    match create_bpf_prog_fd(prog, attr.prog_type) {
        Ok(fd) => i64::from(fd),
        Err(e) => e.sysret(),
    }
}

/// The caller's info buffer, as much of it as the kernel knows
/// (Linux bpf_check_uarg_tail_zero, then copy_from_user of
/// min(info_len, sizeof)): past PAGE_SIZE, or nonzero bytes past the
/// kernel's struct, is E2BIG
fn info_in<T: crate::util::pod::Pod>(ptr: u64, info_len: u32) -> Result<(T, usize), KernelError> {
    let ulen = info_len as usize;
    if ulen > crate::mm::filemap::PAGE_SIZE {
        return Err(KernelError::ArgListTooLong);
    }
    let len = ulen.min(size_of::<T>());
    if ulen > len {
        let mut tail = [0u8; 64];
        let mut at = len;
        while at < ulen {
            let n = (ulen - at).min(tail.len());
            let src = ptr.checked_add(at as u64).ok_or(KernelError::BadAddress)?;
            copy_from_user::<Uaccess>(&mut tail[..n], src, n)
                .map_err(|_| KernelError::BadAddress)?;
            if tail[..n].iter().any(|&b| b != 0) {
                return Err(KernelError::ArgListTooLong);
            }
            at += n;
        }
    }
    let mut info = T::zeroed();
    copy_from_user::<Uaccess>(&mut info.as_bytes_mut()[..len], ptr, len)
        .map_err(|_| KernelError::BadAddress)?;
    Ok((info, len))
}

/// Copy `info`'s first `len` bytes out and store `len` in the caller's
/// attr.info.info_len (Linux: copy_to_user, put_user)
fn info_out<T: crate::util::pod::IntoBytes>(
    info: &T,
    len: usize,
    ptr: u64,
    uattr: u64,
) -> Result<(), KernelError> {
    copy_to_user::<Uaccess>(ptr, &info.as_bytes()[..len]).map_err(|_| KernelError::BadAddress)?;
    let at = uattr.checked_add(4).ok_or(KernelError::BadAddress)?;
    put_user::<Uaccess, u32>(at, len as u32).map_err(|_| KernelError::BadAddress)
}

/// BPF_OBJ_GET_INFO_BY_FD on a map (Linux bpf_map_get_info_by_fd)
fn map_info(
    map: &super::map::BpfMap,
    attr: &ObjGetInfoAttr,
    uattr: u64,
) -> Result<(), KernelError> {
    let (mut info, len) = info_in::<BpfMapInfo>(attr.info, attr.info_len)?;
    info.map_type = map.map_type();
    info.id = map.id;
    info.key_size = map.key_size();
    info.value_size = map.value_size();
    info.max_entries = map.max_entries();
    info.map_flags = map.flags;
    info.map_extra = 0;
    info.name = [0; 16];
    // No map has a hash op (Linux: EINVAL for a hash request without
    // one, or a hash size without a hash)
    if info.hash != 0 || info.hash_size != 0 {
        return Err(KernelError::InvalidArgument);
    }
    info_out(&info, len, attr.info, uattr)
}

/// BPF_OBJ_GET_INFO_BY_FD on a program (Linux bpf_prog_get_info_by_fd):
/// the caller's array pointers and sizes in, the counts out; the
/// translated instructions are copied when asked for
fn prog_info(
    prog: &BpfProg,
    prog_type: u32,
    attr: &ObjGetInfoAttr,
    uattr: u64,
) -> Result<(), KernelError> {
    let (mut info, len) = info_in::<BpfProgInfo>(attr.info, attr.info_len)?;
    info.prog_type = prog_type;
    info.id = 0;
    info.tag = [0; 8];
    info.name = [0; 16];
    info.nr_map_ids = 0;
    info.jited_prog_len = 0;
    info.nr_jited_ksyms = 0;
    info.nr_jited_func_lens = 0;
    info.nr_func_info = 0;
    info.nr_line_info = 0;
    info.nr_jited_line_info = 0;
    info.btf_id = 0;
    info.verified_insns = 0;
    let insns = crate::util::pod::slice_bytes(prog.insns());
    let ulen = info.xlated_prog_len as usize;
    info.xlated_prog_len = insns.len() as u32;
    if !insns.is_empty() && ulen != 0 && info.xlated_prog_insns != 0 {
        let n = ulen.min(insns.len());
        copy_to_user::<Uaccess>(info.xlated_prog_insns, &insns[..n])
            .map_err(|_| KernelError::BadAddress)?;
    }
    // One program, one tag (Linux: func_cnt or 1)
    let tags = info.nr_prog_tags;
    info.nr_prog_tags = 1;
    if tags != 0 && info.prog_tags != 0 {
        copy_to_user::<Uaccess>(info.prog_tags, &[0u8; 8]).map_err(|_| KernelError::BadAddress)?;
    }
    info_out(&info, len, attr.info, uattr)
}

/// Get object info by fd
fn bpf_obj_get_info_by_fd(attr_buf: &[u8], uattr: u64) -> i64 {
    let Some(attr) = ObjGetInfoAttr::read_from(attr_buf) else {
        return KernelError::InvalidArgument.sysret();
    };
    let r = if let Ok(map) = get_bpf_map_from_fd(attr.bpf_fd as i32) {
        map_info(&map, &attr, uattr)
    } else if let Ok((prog, prog_type)) = get_bpf_prog_info_from_fd(attr.bpf_fd as i32) {
        prog_info(&prog, prog_type, &attr, uattr)
    } else {
        Err(KernelError::BadFd)
    };
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}
