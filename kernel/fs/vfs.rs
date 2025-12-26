//! Virtual filesystem layer

use alloc::string::String;
use alloc::vec::Vec;

/// Filesystem error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// File not found
    NotFound,
    /// Not a file
    NotAFile,
    /// Not a directory
    NotADirectory,
    /// Permission denied
    PermissionDenied,
    /// I/O error
    IoError,
    /// Operation not supported
    NotSupported,
    /// File already exists
    AlreadyExists,
    /// Invalid argument
    InvalidArgument,
    /// Too many symbolic links
    TooManySymlinks,
    /// Is a directory (operation not valid for directory)
    IsADirectory,
    /// Invalid file handle
    InvalidFile,
    /// Bad file descriptor
    BadFd,
    /// Resource busy
    Busy,
    /// No such device or filesystem type
    NoDevice,
    /// Directory not empty
    DirectoryNotEmpty,
    /// Not a block device
    NotABlockDevice,
    /// Operation would block (EAGAIN/EWOULDBLOCK)
    WouldBlock,
    /// Not a TTY (ENOTTY)
    NotTty,
    /// Broken pipe (EPIPE)
    BrokenPipe,
    /// No space left on device (ENOSPC)
    NoSpace,
    /// File too large (EFBIG)
    FileTooLarge,
    /// No data available (ENODATA) - for xattr not found
    NoData,
    /// Result too large for buffer (ERANGE)
    Range,
}

/// File metadata
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// File size in bytes
    pub size: u64,
    /// Is this a directory?
    pub is_dir: bool,
}

/// Directory entry
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name
    pub name: String,
    /// Entry metadata
    pub metadata: FileMetadata,
}

/// Filesystem trait
pub trait FileSystem {
    /// File handle type
    type FileHandle;

    /// Open a file
    fn open(&self, path: &str) -> Result<Self::FileHandle, FsError>;

    /// Read from a file handle
    fn read(&self, fh: &mut Self::FileHandle, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Get file metadata
    fn stat(&self, path: &str) -> Result<FileMetadata, FsError>;

    /// List directory contents
    fn list(&self, path: &str) -> Result<Vec<DirEntry>, FsError>;
}

/// Mount point in the VFS
struct MountPoint<FS> {
    /// Path where filesystem is mounted
    path: String,
    /// The mounted filesystem
    fs: FS,
}

/// Virtual filesystem
pub struct Vfs<FS> {
    /// Mount points
    mounts: Vec<MountPoint<FS>>,
}

impl<FS> Vfs<FS> {
    /// Create a new empty VFS
    pub fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    /// Mount a filesystem at a path
    pub fn mount(&mut self, path: &str, fs: FS) {
        self.mounts.push(MountPoint {
            path: String::from(path),
            fs,
        });
    }

    /// Find the filesystem for a given path
    pub fn find_fs<'a>(&'a self, path: &'a str) -> Option<(&'a FS, &'a str)> {
        // Find the longest matching mount point
        let mut best_match: Option<(&MountPoint<FS>, &str)> = None;

        for mount in &self.mounts {
            if path.starts_with(&mount.path) {
                let relative = path.strip_prefix(&mount.path).unwrap_or(path);
                let relative = relative.strip_prefix('/').unwrap_or(relative);

                match best_match {
                    None => best_match = Some((mount, relative)),
                    Some((current, _)) if mount.path.len() > current.path.len() => {
                        best_match = Some((mount, relative));
                    }
                    _ => {}
                }
            }
        }

        best_match.map(|(m, rel)| (&m.fs, rel))
    }
}

impl<FS> Default for Vfs<FS> {
    fn default() -> Self {
        Self::new()
    }
}
