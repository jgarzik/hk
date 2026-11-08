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

use crate::sync::spin::RwLock;
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::sync::Arc;
use spin::Lazy;

use crate::uaccess::{UserPtr, UserSlice};
use crate::util::error::{KernelError, KernelResult};
use crate::util::pod::FromBytes;

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
crate::pod!(NewUtsname {
    sysname,
    nodename,
    release,
    version,
    machine,
    domainname
});

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
    user_ns: Option<Arc<super::UserNamespace>>,

    /// Its inode number (Linux ns.inum)
    pub inum: super::inum::Inum,
}

impl UtsNamespace {
    /// Create initial UTS namespace with default values
    fn new_init() -> Self {
        let mut name = NewUtsname::zeroed();

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
            inum: super::inum::Inum::fixed(super::inum::UTS_INIT),
        }
    }

    /// Clone this namespace (for CLONE_NEWUTS)
    ///
    /// Creates a new UTS namespace with a copy of the current
    /// name values. Changes in the new namespace won't affect
    /// the original (and vice versa).
    pub fn clone_ns(&self) -> Result<Arc<Self>, KernelError> {
        // Copy current name values
        let name_copy = *self.name.read();

        let inum = super::inum::Inum::alloc()?;
        try_arc(Self {
            name: RwLock::new(name_copy),
            user_ns: self.user_ns.clone(),
            inum,
        })
    }
}

/// Initial UTS namespace
///
/// The root UTS namespace used by all tasks unless they create
/// a new one via clone(CLONE_NEWUTS) or unshare(CLONE_NEWUTS).
pub static INIT_UTS_NS: Lazy<Arc<UtsNamespace>> =
    Lazy::new(|| arc_nofail(UtsNamespace::new_init()));

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

/// uname(buf)
pub fn sys_uname(buf: UserPtr<NewUtsname>) -> KernelResult<()> {
    // Copied out first: no user access under the name lock
    let tmp: NewUtsname = *super::current_uts_ns().name.read();
    Ok(buf.write(&tmp)?)
}

/// The new value of a UTS name field from `name`, `len` bytes (Linux
/// sethostname/setdomainname): CAP_SYS_ADMIN (in the UTS namespace's
/// user namespace; hk has one set of capabilities), at most 64 bytes
fn uts_field(name: UserPtr<u8>, len: u64) -> KernelResult<[u8; UTS_FIELD_SIZE]> {
    if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    let len = len as usize;
    if len > __NEW_UTS_LEN {
        return Err(KernelError::InvalidArgument);
    }
    let mut tmp = [0u8; UTS_FIELD_SIZE];
    UserSlice::new(name.addr(), len)
        .reader()
        .read_slice(&mut tmp[..len])?;
    Ok(tmp)
}

/// sethostname(name, len)
pub fn sys_sethostname(name: UserPtr<u8>, len: u64) -> KernelResult<()> {
    let tmp = uts_field(name, len)?;
    super::current_uts_ns().name.write().nodename = tmp;
    Ok(())
}

/// setdomainname(name, len)
pub fn sys_setdomainname(name: UserPtr<u8>, len: u64) -> KernelResult<()> {
    let tmp = uts_field(name, len)?;
    super::current_uts_ns().name.write().domainname = tmp;
    Ok(())
}
