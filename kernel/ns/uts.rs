//! UTS namespace implementation (hostname, domainname, kernel info)
//!
//! This implements Linux's `struct uts_namespace` which holds the
//! utsname data (hostname, domainname, kernel version, etc.).
//!
//! ## Data Structure
//!
//! The `NewUtsname` structure matches Linux's ABI exactly:
//! - 6 fields, each 65 bytes (64 + NUL)
//! - Used by uname(2) syscall
//!
//! ## Locking
//!
//! `UtsNamespace.name` is protected by `RwLock` for read-heavy access
//! (uname is called frequently, sethostname/setdomainname are rare).

use alloc::sync::Arc;
use spin::{Lazy, RwLock};

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::uaccess::UaccessArch;

/// Maximum string length for UTS fields (not including NUL terminator)
///
/// Linux defines this as 64 in `<linux/utsname.h>`
pub const __NEW_UTS_LEN: usize = 64;

/// Size of each UTS field buffer (includes NUL terminator)
pub const UTS_FIELD_SIZE: usize = __NEW_UTS_LEN + 1;

/// UTS name structure (Linux ABI compatible)
///
/// This structure is passed directly to userspace via uname(2).
/// Each field is a fixed-size NUL-terminated string.
///
/// ## ABI Compatibility
///
/// Must match `struct new_utsname` in Linux:
/// ```c
/// struct new_utsname {
///     char sysname[__NEW_UTS_LEN + 1];
///     char nodename[__NEW_UTS_LEN + 1];
///     char release[__NEW_UTS_LEN + 1];
///     char version[__NEW_UTS_LEN + 1];
///     char machine[__NEW_UTS_LEN + 1];
///     char domainname[__NEW_UTS_LEN + 1];
/// };
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NewUtsname {
    /// Operating system name (e.g., "Linux", "hk")
    pub sysname: [u8; UTS_FIELD_SIZE],
    /// Hostname (set via sethostname)
    pub nodename: [u8; UTS_FIELD_SIZE],
    /// Kernel release (e.g., "6.1.0", "0.1.0")
    pub release: [u8; UTS_FIELD_SIZE],
    /// Kernel version (e.g., "#1 SMP PREEMPT")
    pub version: [u8; UTS_FIELD_SIZE],
    /// Hardware type (e.g., "x86_64", "aarch64")
    pub machine: [u8; UTS_FIELD_SIZE],
    /// NIS domain name (set via setdomainname)
    pub domainname: [u8; UTS_FIELD_SIZE],
}

impl Default for NewUtsname {
    fn default() -> Self {
        Self {
            sysname: [0; UTS_FIELD_SIZE],
            nodename: [0; UTS_FIELD_SIZE],
            release: [0; UTS_FIELD_SIZE],
            version: [0; UTS_FIELD_SIZE],
            machine: [0; UTS_FIELD_SIZE],
            domainname: [0; UTS_FIELD_SIZE],
        }
    }
}

/// UTS namespace (like Linux struct uts_namespace)
///
/// Contains the utsname data for this namespace. Each namespace
/// can have its own hostname/domainname independent of others.
///
/// ## Fields
///
/// - `name`: The actual utsname data, protected by RwLock
/// - `user_ns`: Owning user namespace (for capability checks)
///
/// ## Usage
///
/// ```rust,ignore
/// let uts_ns = current_uts_ns();
///
/// // Reading (shared lock)
/// let name = *uts_ns.name.read();
///
/// // Writing (exclusive lock)
/// {
///     let mut guard = uts_ns.name.write();
///     copy_str(&mut guard.nodename, b"newhostname");
/// }
/// ```
pub struct UtsNamespace {
    /// The utsname data for this namespace
    ///
    /// Protected by RwLock for concurrent reads (uname) with
    /// exclusive writes (sethostname/setdomainname).
    pub name: RwLock<NewUtsname>,

    /// User namespace that owns this (for capability checks)
    ///
    /// None = init user namespace (root always has CAP_SYS_ADMIN)
    /// Future: proper user namespace with capability checking
    #[allow(dead_code)]
    user_ns: Option<Arc<super::UserNamespace>>,
}

impl UtsNamespace {
    /// Create initial UTS namespace with default values
    fn new_init() -> Self {
        let mut name = NewUtsname::default();

        // Set default values (like Linux's init_uts_ns)
        copy_str(&mut name.sysname, b"hk");
        copy_str(&mut name.nodename, b"localhost");
        copy_str(&mut name.release, env!("CARGO_PKG_VERSION").as_bytes());
        copy_str(&mut name.version, b"#1 SMP");

        // Architecture-specific machine name
        #[cfg(target_arch = "x86_64")]
        copy_str(&mut name.machine, b"x86_64");
        #[cfg(target_arch = "aarch64")]
        copy_str(&mut name.machine, b"aarch64");

        copy_str(&mut name.domainname, b"(none)");

        Self {
            name: RwLock::new(name),
            user_ns: None,
        }
    }

    /// Clone this namespace (for CLONE_NEWUTS)
    ///
    /// Creates a new UTS namespace with a copy of the current
    /// name values. Changes in the new namespace won't affect
    /// the original (and vice versa).
    pub fn clone_ns(&self) -> Result<Arc<Self>, i32> {
        // Copy current name values
        let name_copy = *self.name.read();

        Ok(Arc::new(Self {
            name: RwLock::new(name_copy),
            user_ns: self.user_ns.clone(),
        }))
    }
}

/// Initial UTS namespace
///
/// The root UTS namespace used by all tasks unless they create
/// a new one via clone(CLONE_NEWUTS) or unshare(CLONE_NEWUTS).
pub static INIT_UTS_NS: Lazy<Arc<UtsNamespace>> = Lazy::new(|| Arc::new(UtsNamespace::new_init()));

// ============================================================================
// Helper Functions
// ============================================================================

/// Copy a byte slice into a fixed-size buffer
///
/// Ensures NUL-termination and doesn't overflow the buffer.
fn copy_str(dest: &mut [u8], src: &[u8]) {
    let len = src.len().min(dest.len() - 1);
    dest[..len].copy_from_slice(&src[..len]);
    dest[len..].fill(0);
}

// ============================================================================
// Syscall Handlers (Phase 2)
// ============================================================================

/// sys_uname - get system identification
///
/// Copies the UTS name structure to userspace.
///
/// # Arguments
/// * `buf` - User pointer to `struct utsname`
///
/// # Returns
/// * 0 on success
/// * -EFAULT if user pointer is invalid
pub fn sys_uname(buf: u64) -> i64 {
    // Validate user buffer
    if !Uaccess::access_ok(buf, core::mem::size_of::<NewUtsname>()) {
        return KernelError::BadAddress.sysret();
    }

    // Get current task's UTS namespace
    let uts_ns = super::current_uts_ns();

    // Read lock - copy to temp to minimize lock hold time
    let tmp: NewUtsname = *uts_ns.name.read();

    // Copy to user space
    unsafe {
        Uaccess::user_access_begin();
        core::ptr::copy_nonoverlapping(&tmp as *const NewUtsname, buf as *mut NewUtsname, 1);
        Uaccess::user_access_end();
    }

    0
}

/// sys_sethostname - set hostname
///
/// Sets the hostname (nodename) in the current UTS namespace.
/// Requires CAP_SYS_ADMIN (currently: euid == 0).
///
/// # Arguments
/// * `name` - User pointer to hostname string
/// * `len` - Length of hostname (max 64)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not privileged
/// * -EINVAL if len > 64
/// * -EFAULT if user pointer is invalid
pub fn sys_sethostname(name: u64, len: u64) -> i64 {
    use crate::task::percpu;

    // Permission check (CAP_SYS_ADMIN in UTS ns's user ns)
    // For now: check euid == 0
    if percpu::current_cred().euid != 0 {
        return KernelError::NotPermitted.sysret();
    }

    let len = len as usize;
    if len > __NEW_UTS_LEN {
        return KernelError::InvalidArgument.sysret();
    }

    if !Uaccess::access_ok(name, len) {
        return KernelError::BadAddress.sysret();
    }

    // Copy from user
    let mut tmp = [0u8; UTS_FIELD_SIZE];
    unsafe {
        Uaccess::user_access_begin();
        core::ptr::copy_nonoverlapping(name as *const u8, tmp.as_mut_ptr(), len);
        Uaccess::user_access_end();
    }

    // Get UTS namespace and update
    let uts_ns = super::current_uts_ns();

    {
        let mut guard = uts_ns.name.write();
        guard.nodename = tmp;
    }

    0
}

/// sys_setdomainname - set NIS domain name
///
/// Sets the domainname in the current UTS namespace.
/// Requires CAP_SYS_ADMIN (currently: euid == 0).
///
/// # Arguments
/// * `name` - User pointer to domainname string
/// * `len` - Length of domainname (max 64)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not privileged
/// * -EINVAL if len > 64
/// * -EFAULT if user pointer is invalid
pub fn sys_setdomainname(name: u64, len: u64) -> i64 {
    use crate::task::percpu;

    // Permission check
    if percpu::current_cred().euid != 0 {
        return KernelError::NotPermitted.sysret();
    }

    let len = len as usize;
    if len > __NEW_UTS_LEN {
        return KernelError::InvalidArgument.sysret();
    }

    if !Uaccess::access_ok(name, len) {
        return KernelError::BadAddress.sysret();
    }

    // Copy from user
    let mut tmp = [0u8; UTS_FIELD_SIZE];
    unsafe {
        Uaccess::user_access_begin();
        core::ptr::copy_nonoverlapping(name as *const u8, tmp.as_mut_ptr(), len);
        Uaccess::user_access_end();
    }

    // Get UTS namespace and update
    let uts_ns = super::current_uts_ns();

    {
        let mut guard = uts_ns.name.write();
        guard.domainname = tmp;
    }

    0
}
