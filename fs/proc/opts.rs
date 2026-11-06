//! procfs mount options (Linux fs/proc/root.c proc_fs_parameters,
//! struct proc_fs_info): hidepid=, gid= and subset=pid, per superblock
//! (each mount of procfs is its own), changed by a remount

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use crate::fs::Inode;
use crate::fs::superblock::{SuperBlock, SuperBlockData};
use crate::task::Pid;
use crate::util::error::KernelError;

/// hidepid=: every /proc/<pid> visible and accessible (Linux HIDEPID_OFF)
const HIDEPID_OFF: u8 = 0;
/// Other users' /proc/<pid> visible, not accessible (HIDEPID_NO_ACCESS)
const HIDEPID_NO_ACCESS: u8 = 1;
/// ... not even visible (HIDEPID_INVISIBLE)
const HIDEPID_INVISIBLE: u8 = 2;
/// Only processes the caller may ptrace-read (HIDEPID_NOT_PTRACEABLE)
const HIDEPID_NOT_PTRACEABLE: u8 = 4;

/// One procfs superblock's options (Linux proc_fs_info)
pub struct ProcOpts {
    hidepid: AtomicU8,
    /// Members of this group see every process (Linux pid_gid; 0 by
    /// default, as Linux GLOBAL_ROOT_GID)
    gid: AtomicU32,
    /// subset=pid: only the process directories and self
    pidonly: AtomicBool,
}

impl SuperBlockData for ProcOpts {}

impl crate::fs::inode::AsAny for ProcOpts {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// What one options string sets (None: left as it is)
#[derive(Default)]
struct Parsed {
    hidepid: Option<u8>,
    gid: Option<u32>,
    pidonly: Option<bool>,
}

/// Linux proc_parse_hidepid_param: a number (0, 1, 2, 4) or its name
fn hidepid(v: &[u8]) -> Option<u8> {
    match v {
        b"0" | b"off" => Some(HIDEPID_OFF),
        b"1" | b"noaccess" => Some(HIDEPID_NO_ACCESS),
        b"2" | b"invisible" => Some(HIDEPID_INVISIBLE),
        b"4" | b"ptraceable" => Some(HIDEPID_NOT_PTRACEABLE),
        _ => None,
    }
}

/// Linux vfs_parse_sb_flag: generic words every filesystem takes (their
/// effect comes from mount(2)'s flags)
fn sb_flag_word(w: &[u8]) -> bool {
    matches!(
        w,
        b"ro"
            | b"rw"
            | b"sync"
            | b"async"
            | b"dirsync"
            | b"lazytime"
            | b"nolazytime"
            | b"mand"
            | b"nomand"
            | b"posixacl"
    )
}

/// Parse a comma-separated options string: EINVAL for an unknown
/// option or a bad value (Linux proc_parse_param, "Unknown parameter")
fn parse(data: &[u8]) -> Result<Parsed, KernelError> {
    let mut p = Parsed::default();
    for opt in data.split(|&c| c == b',').filter(|o| !o.is_empty()) {
        if sb_flag_word(opt) {
            continue;
        }
        let (k, v) = match opt.iter().position(|&c| c == b'=') {
            Some(i) => (&opt[..i], &opt[i + 1..]),
            None => (opt, &b""[..]),
        };
        match k {
            b"hidepid" => p.hidepid = Some(hidepid(v).ok_or(KernelError::InvalidArgument)?),
            b"gid" => {
                let g = core::str::from_utf8(v)
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
                    .ok_or(KernelError::InvalidArgument)?;
                p.gid = Some(g);
            }
            // Linux proc_parse_subset_param: "pid", or nothing
            b"subset" if v == b"pid" => p.pidonly = Some(true),
            b"subset" if v.is_empty() => {}
            _ => return Err(KernelError::InvalidArgument),
        }
    }
    Ok(p)
}

impl ProcOpts {
    /// The options of a new mount
    pub fn new(data: &[u8]) -> Result<Self, KernelError> {
        let o = Self {
            hidepid: AtomicU8::new(HIDEPID_OFF),
            gid: AtomicU32::new(0),
            pidonly: AtomicBool::new(false),
        };
        o.apply(data)?;
        Ok(o)
    }

    /// A remount (Linux proc_reconfigure): what `data` names changes,
    /// the rest stays; nothing changes on an error
    pub fn apply(&self, data: &[u8]) -> Result<(), KernelError> {
        let p = parse(data)?;
        if let Some(h) = p.hidepid {
            self.hidepid.store(h, Ordering::Relaxed);
        }
        if let Some(g) = p.gid {
            self.gid.store(g, Ordering::Relaxed);
        }
        if let Some(b) = p.pidonly {
            self.pidonly.store(b, Ordering::Relaxed);
        }
        Ok(())
    }

    /// subset=pid is set
    pub fn pidonly(&self) -> bool {
        self.pidonly.load(Ordering::Relaxed)
    }

    /// Linux has_pid_permissions: may the caller see process `pid` at
    /// hidepid level `min` (NO_ACCESS for its files, INVISIBLE for
    /// lookup and readdir)
    fn allows(&self, pid: Pid, min: u8) -> bool {
        let h = self.hidepid.load(Ordering::Relaxed);
        if h == HIDEPID_NOT_PTRACEABLE {
            return crate::task::ptrace::may_read_proc(pid);
        }
        if h < min {
            return true;
        }
        let gid = self.gid.load(Ordering::Relaxed);
        if crate::fs::dac::in_group(&crate::fs::dac::cred(), gid) {
            return true;
        }
        crate::task::ptrace::may_read_proc(pid)
    }

    /// The process shows in lookup and readdir
    pub fn visible(&self, pid: Pid) -> bool {
        self.allows(pid, HIDEPID_INVISIBLE)
    }

    /// Linux proc_pid_permission: a process directory the options hide
    /// is ENOENT (invisible) or EPERM
    pub fn pid_permission(&self, pid: Pid) -> Result<(), KernelError> {
        if self.allows(pid, HIDEPID_NO_ACCESS) {
            return Ok(());
        }
        if self.hidepid.load(Ordering::Relaxed) == HIDEPID_INVISIBLE {
            return Err(KernelError::NotFound);
        }
        Err(KernelError::NotPermitted)
    }

    /// Linux proc_show_options: gid, hidepid, subset
    pub fn show(&self, out: &mut Vec<u8>) {
        use alloc::fmt::Write;
        let mut s = alloc::string::String::new();
        let gid = self.gid.load(Ordering::Relaxed);
        if gid != 0 {
            let _ = write!(s, ",gid={gid}");
        }
        let name = match self.hidepid.load(Ordering::Relaxed) {
            HIDEPID_NO_ACCESS => "noaccess",
            HIDEPID_INVISIBLE => "invisible",
            HIDEPID_NOT_PTRACEABLE => "ptraceable",
            _ => "",
        };
        if !name.is_empty() {
            let _ = write!(s, ",hidepid={name}");
        }
        if self.pidonly() {
            s.push_str(",subset=pid");
        }
        out.extend_from_slice(s.as_bytes());
    }
}

/// `f` on the options of the procfs superblock `sb`
pub fn with_sb<R>(sb: &SuperBlock, f: impl FnOnce(&ProcOpts) -> R) -> Option<R> {
    let p = sb.get_private()?;
    p.as_any().downcast_ref::<ProcOpts>().map(f)
}

/// `f` on the options of the procfs superblock `inode` is on
pub fn with<R>(inode: &Inode, f: impl FnOnce(&ProcOpts) -> R) -> Option<R> {
    with_sb(&*inode.superblock()?, f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_options() {
        let p = parse(b"rw,hidepid=invisible,gid=27,subset=pid").unwrap();
        assert_eq!(p.hidepid, Some(HIDEPID_INVISIBLE));
        assert_eq!(p.gid, Some(27));
        assert_eq!(p.pidonly, Some(true));
        assert_eq!(parse(b"hidepid=4").unwrap().hidepid, Some(4));
        assert!(parse(b"hidepid=3").is_err());
        assert!(parse(b"subset=sys").is_err());
        assert!(parse(b"nosuid").is_err());
        assert!(parse(b"gid=x").is_err());
        assert!(parse(b"").is_ok());
    }
}
