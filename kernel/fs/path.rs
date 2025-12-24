//! Path resolution (namei)
//!
//! Resolves path strings to dentries by walking the directory tree.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::FsError;
use super::dentry::Dentry;
use super::inode::{Gid, Inode, Uid};
use super::mount::{current_mnt_ns, follow_mount};

/// Permission mask: may execute
pub const MAY_EXEC: u32 = 1;
/// Permission mask: may write
pub const MAY_WRITE: u32 = 2;
/// Permission mask: may read
pub const MAY_READ: u32 = 4;

/// Maximum number of symlinks to follow (prevent infinite loops)
const MAX_SYMLINK_DEPTH: usize = 40;

/// Path lookup flags
#[derive(Debug, Clone, Copy, Default)]
pub struct LookupFlags {
    /// Follow symlinks in the final component
    pub follow: bool,
    /// The final component must be a directory
    pub directory: bool,
    /// Create the final component if it doesn't exist
    pub create: bool,
    /// Don't cross mount points
    pub no_xdev: bool,
}

impl LookupFlags {
    /// Default flags for open()
    pub fn open() -> Self {
        Self {
            follow: true,
            directory: false,
            create: false,
            no_xdev: false,
        }
    }

    /// Flags for opendir()
    pub fn opendir() -> Self {
        Self {
            follow: true,
            directory: true,
            create: false,
            no_xdev: false,
        }
    }
}

/// Split a path into components
fn split_path(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect()
}

/// Look up a path and return the dentry
pub fn lookup_path(path: &str) -> Result<Arc<Dentry>, FsError> {
    lookup_path_flags(path, LookupFlags::open())
}

/// Look up a path with specific flags
pub fn lookup_path_flags(path: &str, flags: LookupFlags) -> Result<Arc<Dentry>, FsError> {
    lookup_path_full(path, flags, 0)
}

/// Look up a path relative to a starting path
///
/// This is the core path resolution function for openat() and related *at syscalls.
/// If `start` is provided, relative paths will be resolved from that starting point.
/// If `start` is None, relative paths resolve from root (or cwd when available).
/// Absolute paths (starting with '/') always resolve from root, ignoring `start`.
///
/// # Arguments
/// * `start` - Optional starting Path for relative path resolution
/// * `path` - The path string to resolve
/// * `flags` - Lookup flags controlling resolution behavior
///
/// # Returns
/// The dentry at the resolved path, or an error
pub fn lookup_path_at(
    start: Option<super::path_ref::Path>,
    path: &str,
    flags: LookupFlags,
) -> Result<Arc<Dentry>, FsError> {
    lookup_path_at_full(start, path, flags, 0)
}

/// Full path lookup implementation with starting path support
fn lookup_path_at_full(
    start: Option<super::path_ref::Path>,
    path: &str,
    flags: LookupFlags,
    symlink_depth: usize,
) -> Result<Arc<Dentry>, FsError> {
    if symlink_depth > MAX_SYMLINK_DEPTH {
        return Err(FsError::TooManySymlinks);
    }

    // Get the starting point
    let mnt_ns = current_mnt_ns();
    let (mut current, components) = if path.starts_with('/') {
        // Absolute path - always start from root, ignore start
        let root = mnt_ns.get_root_dentry().ok_or(FsError::NotFound)?;
        (root, split_path(path))
    } else {
        // Relative path - use provided start dentry or fall back to root
        let start_dentry = start
            .map(|p| p.dentry.clone())
            .or_else(|| mnt_ns.get_root_dentry())
            .ok_or(FsError::NotFound)?;
        (start_dentry, split_path(path))
    };

    // Walk the path (same logic as lookup_path_full)
    let num_components = components.len();
    for (i, component) in components.iter().enumerate() {
        let is_last = i == num_components - 1;

        // Handle ".."
        if *component == ".." {
            if let Some(parent) = current.get_parent() {
                current = parent;
            }
            // At root, ".." stays at root
            continue;
        }

        // Get the current directory's inode
        let inode = current.get_inode().ok_or(FsError::NotFound)?;

        // Must be a directory to traverse into
        if !inode.mode().is_dir() {
            return Err(FsError::NotADirectory);
        }

        // Look up in dcache first
        if let Some(child) = current.lookup_child(component) {
            // Follow mount point if needed
            let child = if !flags.no_xdev {
                follow_mount(&child)
            } else {
                child
            };

            // Handle symlinks
            if (!is_last || flags.follow)
                && let Some(child_inode) = child.get_inode()
                && child_inode.mode().is_symlink()
            {
                // Read the symlink target
                let target = child_inode.i_op.readlink(&child_inode)?;

                // Build remaining path (components after current)
                let remaining: Vec<&str> = components[i + 1..].to_vec();
                let new_path = if remaining.is_empty() {
                    target
                } else {
                    alloc::format!("{}/{}", target, remaining.join("/"))
                };

                // Resolve symlink target
                if new_path.starts_with('/') {
                    // Absolute symlink - restart from root
                    return lookup_path_at_full(None, &new_path, flags, symlink_depth + 1);
                } else {
                    // Relative symlink - resolve from current directory (parent of symlink)
                    let start_path = super::path_ref::Path::from_dentry(current.clone());
                    return lookup_path_at_full(start_path, &new_path, flags, symlink_depth + 1);
                }
            }

            current = child;
            continue;
        }

        // Cache miss - ask the filesystem
        let child_inode = inode.i_op.lookup(&inode, component)?;

        // Create dentry for the result
        let child_dentry = Arc::new(Dentry::new(
            String::from(*component),
            Some(child_inode.clone()),
            current.sb.clone(),
        ));
        child_dentry.set_parent(&current);
        current.add_child(child_dentry.clone());

        // Follow mount point if needed
        let child_dentry = if !flags.no_xdev {
            follow_mount(&child_dentry)
        } else {
            child_dentry
        };

        // Handle symlinks (for newly looked-up entries)
        if (!is_last || flags.follow) && child_inode.mode().is_symlink() {
            // Read the symlink target
            let target = child_inode.i_op.readlink(&child_inode)?;

            // Build remaining path (components after current)
            let remaining: Vec<&str> = components[i + 1..].to_vec();
            let new_path = if remaining.is_empty() {
                target
            } else {
                alloc::format!("{}/{}", target, remaining.join("/"))
            };

            // Resolve symlink target
            if new_path.starts_with('/') {
                // Absolute symlink - restart from root
                return lookup_path_at_full(None, &new_path, flags, symlink_depth + 1);
            } else {
                // Relative symlink - resolve from current directory (parent of symlink)
                let start_path = super::path_ref::Path::from_dentry(current.clone());
                return lookup_path_at_full(start_path, &new_path, flags, symlink_depth + 1);
            }
        }

        current = child_dentry;
    }

    // Check directory requirement
    if flags.directory
        && let Some(inode) = current.get_inode()
        && !inode.mode().is_dir()
    {
        return Err(FsError::NotADirectory);
    }

    Ok(current)
}

/// Full path lookup implementation
fn lookup_path_full(
    path: &str,
    flags: LookupFlags,
    symlink_depth: usize,
) -> Result<Arc<Dentry>, FsError> {
    if symlink_depth > MAX_SYMLINK_DEPTH {
        return Err(FsError::TooManySymlinks);
    }

    // Get the starting point
    let mnt_ns = current_mnt_ns();
    let (mut current, components) = if path.starts_with('/') {
        // Absolute path - start from root
        let root = mnt_ns.get_root_dentry().ok_or(FsError::NotFound)?;
        (root, split_path(path))
    } else {
        // Relative path - for now, treat as absolute from root
        // A real implementation would use the task's cwd
        let root = mnt_ns.get_root_dentry().ok_or(FsError::NotFound)?;
        (root, split_path(path))
    };

    // Walk the path
    let num_components = components.len();
    for (i, component) in components.iter().enumerate() {
        let is_last = i == num_components - 1;

        // Handle ".."
        if *component == ".." {
            if let Some(parent) = current.get_parent() {
                current = parent;
            }
            // At root, ".." stays at root
            continue;
        }

        // Get the current directory's inode
        let inode = current.get_inode().ok_or(FsError::NotFound)?;

        // Must be a directory to traverse into
        if !inode.mode().is_dir() {
            return Err(FsError::NotADirectory);
        }

        // Look up in dcache first
        if let Some(child) = current.lookup_child(component) {
            // Follow mount point if needed
            let child = if !flags.no_xdev {
                follow_mount(&child)
            } else {
                child
            };

            // Handle symlinks
            if (!is_last || flags.follow)
                && let Some(child_inode) = child.get_inode()
                && child_inode.mode().is_symlink()
            {
                // Read the symlink target
                let target = child_inode.i_op.readlink(&child_inode)?;

                // Build remaining path (components after current)
                let remaining: Vec<&str> = components[i + 1..].to_vec();
                let new_path = if remaining.is_empty() {
                    target
                } else {
                    alloc::format!("{}/{}", target, remaining.join("/"))
                };

                // Resolve symlink target
                if new_path.starts_with('/') {
                    // Absolute symlink - restart from root
                    return lookup_path_full(&new_path, flags, symlink_depth + 1);
                } else {
                    // Relative symlink - resolve from current directory (parent of symlink)
                    let start_path = super::path_ref::Path::from_dentry(current.clone());
                    return lookup_path_at_full(start_path, &new_path, flags, symlink_depth + 1);
                }
            }

            current = child;
            continue;
        }

        // Cache miss - ask the filesystem
        let child_inode = inode.i_op.lookup(&inode, component)?;

        // Create dentry for the result
        let child_dentry = Arc::new(Dentry::new(
            String::from(*component),
            Some(child_inode.clone()),
            current.sb.clone(),
        ));
        child_dentry.set_parent(&current);
        current.add_child(child_dentry.clone());

        // Follow mount point if needed
        let child_dentry = if !flags.no_xdev {
            follow_mount(&child_dentry)
        } else {
            child_dentry
        };

        // Handle symlinks (for newly looked-up entries)
        if (!is_last || flags.follow) && child_inode.mode().is_symlink() {
            // Read the symlink target
            let target = child_inode.i_op.readlink(&child_inode)?;

            // Build remaining path (components after current)
            let remaining: Vec<&str> = components[i + 1..].to_vec();
            let new_path = if remaining.is_empty() {
                target
            } else {
                alloc::format!("{}/{}", target, remaining.join("/"))
            };

            // Resolve symlink target
            if new_path.starts_with('/') {
                // Absolute symlink - restart from root
                return lookup_path_full(&new_path, flags, symlink_depth + 1);
            } else {
                // Relative symlink - resolve from current directory (parent of symlink)
                let start_path = super::path_ref::Path::from_dentry(current.clone());
                return lookup_path_at_full(start_path, &new_path, flags, symlink_depth + 1);
            }
        }

        current = child_dentry;
    }

    // Check directory requirement
    if flags.directory
        && let Some(inode) = current.get_inode()
        && !inode.mode().is_dir()
    {
        return Err(FsError::NotADirectory);
    }

    Ok(current)
}

/// Look up parent directory and return (parent_dentry, final_component_name)
pub fn lookup_parent(path: &str) -> Result<(Arc<Dentry>, &str), FsError> {
    // Find the last path component
    let path = path.trim_end_matches('/');

    if path.is_empty() || path == "/" {
        return Err(FsError::InvalidArgument);
    }

    let (parent_path, name) = match path.rfind('/') {
        Some(pos) => {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            let name = &path[pos + 1..];
            (parent, name)
        }
        None => {
            // Relative path with no slash - parent is cwd (use root for now)
            ("/", path)
        }
    };

    if name.is_empty() {
        return Err(FsError::InvalidArgument);
    }

    let parent_dentry = lookup_path(parent_path)?;
    Ok((parent_dentry, name))
}

/// Create a file at the given path
pub fn create_file(path: &str, mode: super::inode::InodeMode) -> Result<Arc<Dentry>, FsError> {
    let (parent, name) = lookup_parent(path)?;

    let parent_inode = parent.get_inode().ok_or(FsError::NotFound)?;
    if !parent_inode.mode().is_dir() {
        return Err(FsError::NotADirectory);
    }

    // Check if already exists
    if parent.lookup_child(name).is_some() {
        return Err(FsError::AlreadyExists);
    }

    // Create the inode
    let new_inode = parent_inode.i_op.create(&parent_inode, name, mode)?;

    // Create the dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        parent.sb.clone(),
    ));
    new_dentry.set_parent(&parent);
    parent.add_child(new_dentry.clone());

    Ok(new_dentry)
}

/// Create a directory at the given path
pub fn create_dir(path: &str, mode: super::inode::InodeMode) -> Result<Arc<Dentry>, FsError> {
    let (parent, name) = lookup_parent(path)?;

    let parent_inode = parent.get_inode().ok_or(FsError::NotFound)?;
    if !parent_inode.mode().is_dir() {
        return Err(FsError::NotADirectory);
    }

    // Check if already exists
    if parent.lookup_child(name).is_some() {
        return Err(FsError::AlreadyExists);
    }

    // Create the directory inode
    let new_inode = parent_inode.i_op.mkdir(&parent_inode, name, mode)?;

    // Create the dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        parent.sb.clone(),
    ));
    new_dentry.set_parent(&parent);
    parent.add_child(new_dentry.clone());

    Ok(new_dentry)
}

/// Check if the given uid/gid has the requested permission on an inode
///
/// # Arguments
/// * `inode` - The inode to check permissions on
/// * `uid` - The user ID (fsuid) of the requesting process
/// * `gid` - The group ID (fsgid) of the requesting process
/// * `mask` - Permission mask (MAY_READ, MAY_WRITE, MAY_EXEC, or combination)
///
/// # Returns
/// `Ok(())` if access is allowed, `Err(FsError::PermissionDenied)` otherwise
pub fn inode_permission(inode: &Inode, uid: Uid, gid: Gid, mask: u32) -> Result<(), FsError> {
    // Root (uid 0) bypasses all permission checks
    if uid == 0 {
        return Ok(());
    }

    // Check permission bits
    if inode
        .mode()
        .check_permission(uid, gid, inode.uid(), inode.gid(), mask)
    {
        Ok(())
    } else {
        Err(FsError::PermissionDenied)
    }
}
