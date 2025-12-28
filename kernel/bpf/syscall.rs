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

use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use super::fd::{
    create_bpf_map_fd, create_bpf_prog_fd, get_bpf_map_from_fd, get_bpf_prog_info_from_fd,
};
use super::insn::BpfInsn;
use super::map::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BpfMapOps, create_map};
use super::prog::BpfProg;
use super::verifier::verify_bpf_prog;
use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::uaccess::{copy_from_user, copy_to_user};

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
/// Get object info by fd
pub const BPF_OBJ_GET_INFO_BY_FD: i32 = 29;
/// Freeze a map (make read-only)
pub const BPF_MAP_FREEZE: i32 = 38;

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

/// Map info structure (returned by BPF_OBJ_GET_INFO_BY_FD)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfMapInfo {
    /// Map type
    pub map_type: u32,
    /// Map ID
    pub id: u32,
    /// Key size
    pub key_size: u32,
    /// Value size
    pub value_size: u32,
    /// Max entries
    pub max_entries: u32,
    /// Map flags
    pub map_flags: u32,
    /// Map name
    pub name: [u8; 16],
}

/// Program info structure (returned by BPF_OBJ_GET_INFO_BY_FD)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfProgInfo {
    /// Program type
    pub prog_type: u32,
    /// Program ID
    pub id: u32,
    /// Tag (8 bytes)
    pub tag: [u8; 8],
    /// jited_prog_len
    pub jited_prog_len: u32,
    /// xlated_prog_len
    pub xlated_prog_len: u32,
    /// jited_prog_insns
    pub jited_prog_insns: u64,
    /// xlated_prog_insns
    pub xlated_prog_insns: u64,
}

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
        BPF_OBJ_GET_INFO_BY_FD => bpf_obj_get_info_by_fd(&attr_buf),
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// Create a BPF map
fn bpf_map_create(attr_buf: &[u8]) -> i64 {
    // Parse MapCreateAttr
    if attr_buf.len() < size_of::<MapCreateAttr>() {
        return KernelError::InvalidArgument.sysret();
    }

    // Safety: we've verified the buffer is large enough
    let attr: MapCreateAttr =
        unsafe { core::ptr::read_unaligned(attr_buf.as_ptr() as *const MapCreateAttr) };

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
        Ok(fd) => fd as i64,
        Err(e) => e.sysret(),
    }
}

/// Look up an element in a map
fn bpf_map_lookup_elem(attr_buf: &[u8]) -> i64 {
    if attr_buf.len() < size_of::<MapElemAttr>() {
        return KernelError::InvalidArgument.sysret();
    }

    let attr: MapElemAttr =
        unsafe { core::ptr::read_unaligned(attr_buf.as_ptr() as *const MapElemAttr) };

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
    if attr_buf.len() < size_of::<MapElemAttr>() {
        return KernelError::InvalidArgument.sysret();
    }

    let attr: MapElemAttr =
        unsafe { core::ptr::read_unaligned(attr_buf.as_ptr() as *const MapElemAttr) };

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
    if attr_buf.len() < size_of::<MapElemAttr>() {
        return KernelError::InvalidArgument.sysret();
    }

    let attr: MapElemAttr =
        unsafe { core::ptr::read_unaligned(attr_buf.as_ptr() as *const MapElemAttr) };

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
    if attr_buf.len() < size_of::<MapElemAttr>() {
        return KernelError::InvalidArgument.sysret();
    }

    let attr: MapElemAttr =
        unsafe { core::ptr::read_unaligned(attr_buf.as_ptr() as *const MapElemAttr) };

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
    if attr_buf.len() < size_of::<ProgLoadAttr>() {
        return KernelError::InvalidArgument.sysret();
    }

    let attr: ProgLoadAttr =
        unsafe { core::ptr::read_unaligned(attr_buf.as_ptr() as *const ProgLoadAttr) };

    // Validate program type
    match attr.prog_type {
        BPF_PROG_TYPE_SOCKET_FILTER => {}
        _ => return KernelError::InvalidArgument.sysret(),
    }

    // Validate instruction count
    if attr.insn_cnt == 0 || attr.insn_cnt as usize > super::insn::BPF_MAXINSNS {
        return KernelError::InvalidArgument.sysret();
    }

    // Read instructions from userspace
    let insn_count = attr.insn_cnt as usize;
    let insn_bytes = insn_count * size_of::<BpfInsn>();
    let mut insn_buf = vec![0u8; insn_bytes];

    if copy_from_user::<Uaccess>(&mut insn_buf, attr.insns, insn_bytes).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Convert bytes to instructions
    let insns: Vec<BpfInsn> = insn_buf
        .chunks_exact(size_of::<BpfInsn>())
        .map(|chunk| unsafe { core::ptr::read_unaligned(chunk.as_ptr() as *const BpfInsn) })
        .collect();

    // Verify the program
    // Context size depends on program type - for socket filter, it's the packet context
    let ctx_size = match attr.prog_type {
        BPF_PROG_TYPE_SOCKET_FILTER => 64, // Approximate, depends on actual context
        _ => 0,
    };

    if let Err(e) = verify_bpf_prog(&insns, ctx_size) {
        return e.sysret();
    }

    // Create BPF program
    let prog = BpfProg::new(insns);

    // Create file descriptor
    match create_bpf_prog_fd(prog, attr.prog_type) {
        Ok(fd) => fd as i64,
        Err(e) => e.sysret(),
    }
}

/// Get object info by fd
fn bpf_obj_get_info_by_fd(attr_buf: &[u8]) -> i64 {
    if attr_buf.len() < size_of::<ObjGetInfoAttr>() {
        return KernelError::InvalidArgument.sysret();
    }

    let attr: ObjGetInfoAttr =
        unsafe { core::ptr::read_unaligned(attr_buf.as_ptr() as *const ObjGetInfoAttr) };

    // Try to get as map first
    if let Ok(map) = get_bpf_map_from_fd(attr.bpf_fd as i32) {
        let info = BpfMapInfo {
            map_type: map.map_type(),
            id: map.id,
            key_size: map.key_size(),
            value_size: map.value_size(),
            max_entries: map.max_entries(),
            map_flags: map.flags,
            name: [0; 16],
        };

        let info_size = core::cmp::min(attr.info_len as usize, size_of::<BpfMapInfo>());
        let info_bytes =
            unsafe { core::slice::from_raw_parts(&info as *const _ as *const u8, info_size) };

        if copy_to_user::<Uaccess>(attr.info, info_bytes).is_err() {
            return KernelError::BadAddress.sysret();
        }

        return 0;
    }

    // Try to get as program
    if let Ok((prog, prog_type)) = get_bpf_prog_info_from_fd(attr.bpf_fd as i32) {
        let info = BpfProgInfo {
            prog_type,
            id: 0, // Would need a global prog ID counter
            tag: [0; 8],
            jited_prog_len: 0,
            xlated_prog_len: (prog.len() * size_of::<BpfInsn>()) as u32,
            jited_prog_insns: 0,
            xlated_prog_insns: 0,
        };

        let info_size = core::cmp::min(attr.info_len as usize, size_of::<BpfProgInfo>());
        let info_bytes =
            unsafe { core::slice::from_raw_parts(&info as *const _ as *const u8, info_size) };

        if copy_to_user::<Uaccess>(attr.info, info_bytes).is_err() {
            return KernelError::BadAddress.sysret();
        }

        return 0;
    }

    KernelError::BadFd.sysret()
}
