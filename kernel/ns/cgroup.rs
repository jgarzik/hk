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

use alloc::string::String;
use alloc::sync::Arc;
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
}

impl CgroupNamespace {
    /// Create a new cgroup namespace rooted at the given cgroup
    pub fn new(root: Arc<Cgroup>) -> Arc<Self> {
        Arc::new(Self { root })
    }

    /// Create the initial cgroup namespace (rooted at the real root cgroup)
    fn new_init() -> Arc<Self> {
        // The initial namespace uses the real root cgroup
        // We'll get it lazily when first accessed since cgroup_init()
        // might not have been called yet
        Arc::new(Self {
            root: CGROUP_ROOT
                .root_cgroup()
                .unwrap_or_else(create_placeholder_root),
        })
    }

    /// Get the root cgroup for this namespace
    pub fn root(&self) -> Arc<Cgroup> {
        self.root.clone()
    }

    /// Clone this namespace (for CLONE_NEWCGROUP)
    ///
    /// Creates a new cgroup namespace rooted at the given cgroup.
    /// Typically called with the current task's cgroup.
    pub fn clone_ns(&self, new_root: Arc<Cgroup>) -> Result<Arc<Self>, i32> {
        Ok(Arc::new(Self { root: new_root }))
    }

    /// Translate an absolute cgroup path to a namespace-relative path
    ///
    /// Given a cgroup in the real hierarchy, returns the path as seen
    /// from within this namespace.
    ///
    /// Returns "/" if the cgroup is the namespace root.
    /// Returns "/../.." style path if the cgroup is an ancestor of the root.
    pub fn translate_path(&self, cgroup: &Arc<Cgroup>) -> String {
        // If cgroup is the namespace root, return "/"
        if Arc::ptr_eq(cgroup, &self.root) {
            return String::from("/");
        }

        // Check if cgroup is a descendant of the namespace root
        if cgroup.is_descendant_of(&self.root) {
            // Build relative path from root
            let cgroup_path = cgroup.path();
            let root_path = self.root.path();

            // Strip the root prefix
            if let Some(relative) = cgroup_path.strip_prefix(&root_path) {
                if relative.is_empty() || relative == "/" {
                    return String::from("/");
                }
                return String::from(relative);
            }
            return cgroup_path;
        }

        // Cgroup is an ancestor of the root or in a different subtree
        // Return the absolute path (escape the namespace)
        cgroup.path()
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
    Cgroup::new(
        0,
        String::new(),
        None,
        &Arc::new(crate::cgroup::CgroupRoot::new()),
    )
}

/// Initial (root) cgroup namespace
pub static INIT_CGROUP_NS: Lazy<Arc<CgroupNamespace>> = Lazy::new(CgroupNamespace::new_init);
