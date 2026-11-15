//! Cgroup namespace implementation
//!
//! The cgroup namespace virtualizes the cgroup hierarchy for processes.
//! A process in a cgroup namespace sees its cgroup as the root ("/")
//! of the hierarchy, providing isolation for containers.
//!
//! ## How It Works
//!
//! When a process creates a new cgroup namespace (via `unshare(CLONE_NEWCGROUP)`
//! or `clone(CLONE_NEWCGROUP)`), its current cgroup becomes the root of the
//! namespace. All cgroup paths are then reported relative to this root.
//!
//! For example, if a process in `/docker/container1` creates a cgroup namespace,
//! it will see its cgroup as `/` in `/proc/self/cgroup`.

use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Lazy;

use crate::cgroup::{CGROUP_ROOT, Cgroup};

/// Cgroup namespace
///
/// Virtualizes the cgroup hierarchy by storing a root cgroup that
/// the process sees as "/".
pub struct CgroupNamespace {
    /// Root cgroup for this namespace
    /// Processes in this namespace see this cgroup as "/"
    root: Arc<Cgroup>,
    /// Its inode number and nsfs dentry (Linux ns)
    pub ns: super::NsCommon,
    /// The user namespace that owns it (Linux cgroup_namespace.user_ns)
    pub user_ns: Arc<super::UserNamespace>,
}

impl CgroupNamespace {
    /// Create the initial cgroup namespace (rooted at the real root cgroup)
    fn new_init() -> Arc<Self> {
        // The initial namespace uses the real root cgroup
        // We'll get it lazily when first accessed since cgroup_init()
        // might not have been called yet (boot: failure cannot be reported)
        arc_nofail(Self {
            root: CGROUP_ROOT
                .root_cgroup()
                .unwrap_or_else(create_placeholder_root),
            ns: super::NsCommon::init(super::inum::Inum::fixed(super::inum::CGROUP_INIT)),
            user_ns: super::INIT_USER_NS.clone(),
        })
    }

    /// Get the root cgroup for this namespace
    pub fn root(&self) -> Arc<Cgroup> {
        self.root.clone()
    }

    /// Clone this namespace (for CLONE_NEWCGROUP)
    ///
    /// Creates a new cgroup namespace rooted at the given cgroup, owned
    /// by `user_ns`, or ENOMEM (Linux copy_cgroup_ns). Typically called
    /// with the current task's cgroup.
    pub fn clone_ns(
        &self,
        new_root: Arc<Cgroup>,
        user_ns: &Arc<super::UserNamespace>,
    ) -> Result<Arc<Self>, KernelError> {
        let ns = super::NsCommon::new(super::inum::Inum::alloc()?);
        try_arc(Self {
            root: new_root,
            ns,
            user_ns: user_ns.clone(),
        })
    }

    /// The path of `cgroup` seen from this namespace (Linux
    /// cgroup_path_ns): from its root, "/.." for each level up
    pub fn translate_path(&self, cgroup: &Cgroup) -> Vec<u8> {
        cgroup.path_from(&self.root)
    }

    /// Check if a cgroup is visible in this namespace
    ///
    /// A cgroup is visible if it's the namespace root or a descendant.
    pub fn is_visible(&self, cgroup: &Arc<Cgroup>) -> bool {
        Arc::ptr_eq(cgroup, &self.root) || cgroup.is_descendant_of(&self.root)
    }
}

/// Create a placeholder root cgroup for early init
fn create_placeholder_root() -> Arc<Cgroup> {
    // This is called before cgroup_init(), so we create a minimal placeholder
    // It will be replaced when the real root is created
    Cgroup::new_root(0, Vec::new(), &arc_nofail(crate::cgroup::CgroupRoot::new()))
}

/// Initial (root) cgroup namespace
pub static INIT_CGROUP_NS: Lazy<Arc<CgroupNamespace>> = Lazy::new(CgroupNamespace::new_init);
