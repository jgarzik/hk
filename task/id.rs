//! Task identity and credential syscalls
//!
//! This module contains syscalls for process/thread identity and credentials:
//! - getpid, gettid, getppid (process/thread IDs)
//! - getuid, geteuid, getgid, getegid (user/group IDs)
//! - setuid, setgid, setreuid, setregid (set user/group IDs)
//! - setresuid, setresgid, getresuid, getresgid (real/effective/saved IDs)
//! - setfsuid, setfsgid (filesystem user/group IDs)

use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc;

/// sys_getpid: the caller's process id in its pid namespace (Linux
/// task_tgid_vnr(current))
pub fn sys_getpid() -> i64 {
    i64::from(super::pid::vnr(super::percpu::current_pid()))
}

/// sys_gettid: the caller's thread id in its pid namespace (Linux
/// task_pid_vnr(current))
pub fn sys_gettid() -> i64 {
    i64::from(super::pid::vnr(super::percpu::current_tid()))
}

/// sys_getppid: the parent process's id in the caller's pid namespace,
/// 0 for init or a parent outside it (Linux
/// task_tgid_vnr(current->real_parent))
pub fn sys_getppid() -> i64 {
    i64::from(super::percpu::current_ppid_vnr())
}

/// sys_getuid - get real user ID
///
/// Returns the real user ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getuid(uid: u32) -> i64 {
    i64::from(uid)
}

/// sys_geteuid - get effective user ID
///
/// Returns the effective user ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_geteuid(euid: u32) -> i64 {
    i64::from(euid)
}

/// sys_getgid - get real group ID
///
/// Returns the real group ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getgid(gid: u32) -> i64 {
    i64::from(gid)
}

/// sys_getegid - get effective group ID
///
/// Returns the effective group ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getegid(egid: u32) -> i64 {
    i64::from(egid)
}

/// sys_setuid - set user identity (Linux-compatible)
///
/// If the caller has CAP_SETUID, sets real, saved, effective, and
/// filesystem UID to the specified value. After this, root privileges are
/// permanently dropped.
///
/// If not privileged, can only set effective UID (and fsuid) to the current
/// real UID or saved set-user-ID. This allows setuid programs to switch
/// between privileged and unprivileged states.
///
/// # Arguments
/// * `uid` - New user ID to set
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Linux semantics
/// This matches setuid(2) with _POSIX_SAVED_IDS:
/// - Privileged: sets uid, suid, euid, fsuid (permanently drops privileges)
/// - Unprivileged: sets only euid, fsuid (can switch between uid and suid)
pub fn sys_setuid(uid: u32, current_cred: super::Cred) -> KernelResult<()> {
    // Privileged: CAP_SETUID (Linux __sys_setuid: ns_capable_setid)
    if super::capable(super::CAP_SETUID) {
        // Set all UIDs: uid, suid, euid, fsuid - permanently drops root
        return super::percpu::set_current_uid_all(uid);
    }

    // Unprivileged: can only set euid to uid or suid
    if uid == current_cred.uid || uid == current_cred.suid {
        return super::percpu::set_current_euid(uid);
    }

    // Not permitted
    Err(KernelError::NotPermitted)
}

/// sys_setgid - set group identity (Linux-compatible)
///
/// If the caller has CAP_SETGID, sets real, saved, effective, and
/// filesystem GID to the specified value.
///
/// If not privileged, can only set effective GID (and fsgid) to the current
/// real GID or saved set-group-ID. This allows setgid programs to switch
/// between privileged and unprivileged states.
///
/// # Arguments
/// * `gid` - New group ID to set
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Linux semantics
/// This matches setgid(2) with _POSIX_SAVED_IDS:
/// - Privileged: sets gid, sgid, egid, fsgid
/// - Unprivileged: sets only egid, fsgid (can switch between gid and sgid)
pub fn sys_setgid(gid: u32, current_cred: super::Cred) -> KernelResult<()> {
    // Privileged: CAP_SETGID (Linux __sys_setgid: ns_capable_setid)
    if super::capable(super::CAP_SETGID) {
        // Set all GIDs: gid, sgid, egid, fsgid
        return super::percpu::set_current_gid_all(gid);
    }

    // Unprivileged: can only set egid to gid or sgid
    if gid == current_cred.gid || gid == current_cred.sgid {
        return super::percpu::set_current_egid(gid);
    }

    // Not permitted
    Err(KernelError::NotPermitted)
}

/// sys_getresuid - get real, effective, and saved user IDs
///
/// Returns the real UID, effective UID, and saved set-user-ID of the calling process.
/// All three pointers must be valid.
///
/// # Arguments
/// * `ruid_ptr` - User pointer to store real UID
/// * `euid_ptr` - User pointer to store effective UID
/// * `suid_ptr` - User pointer to store saved UID
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EFAULT if any pointer is invalid
///
/// # Locking
/// None required - credentials are stable during syscall execution.
/// Linux uses RCU for credential access; we use per-CPU cached credentials.
pub fn sys_getresuid(
    ruid_ptr: UserPtr<u32>,
    euid_ptr: UserPtr<u32>,
    suid_ptr: UserPtr<u32>,
    current_cred: super::Cred,
) -> KernelResult<()> {
    use crate::uaccess::put_user;
    put_user::<u32>(ruid_ptr.addr(), current_cred.uid)?;
    put_user::<u32>(euid_ptr.addr(), current_cred.euid)?;
    put_user::<u32>(suid_ptr.addr(), current_cred.suid)?;
    Ok(())
}

/// sys_getresgid - get real, effective, and saved group IDs
///
/// Returns the real GID, effective GID, and saved set-group-ID of the calling process.
/// All three pointers must be valid.
///
/// # Arguments
/// * `rgid_ptr` - User pointer to store real GID
/// * `egid_ptr` - User pointer to store effective GID
/// * `sgid_ptr` - User pointer to store saved GID
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EFAULT if any pointer is invalid
///
/// # Locking
/// None required - credentials are stable during syscall execution.
pub fn sys_getresgid(
    rgid_ptr: UserPtr<u32>,
    egid_ptr: UserPtr<u32>,
    sgid_ptr: UserPtr<u32>,
    current_cred: super::Cred,
) -> KernelResult<()> {
    use crate::uaccess::put_user;
    put_user::<u32>(rgid_ptr.addr(), current_cred.gid)?;
    put_user::<u32>(egid_ptr.addr(), current_cred.egid)?;
    put_user::<u32>(sgid_ptr.addr(), current_cred.sgid)?;
    Ok(())
}

/// sys_setresuid - set real, effective, and saved user IDs
///
/// Sets the real UID, effective UID, and saved UID of the calling process.
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
///
/// # Arguments
/// * `ruid` - New real UID (-1 to leave unchanged)
/// * `euid` - New effective UID (-1 to leave unchanged)
/// * `suid` - New saved UID (-1 to leave unchanged)
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Permission Model (Linux-compatible)
/// - If unprivileged: can only set each field to one of {current uid, euid, suid}
/// - With CAP_SETUID: can set any field to any value
/// - When euid changes, fsuid follows (set to new euid)
///
/// # Locking
/// Per-CPU credential update is atomic. Linux uses prepare_creds/commit_creds
/// for RCU-based credential replacement; we update per-CPU data directly.
pub fn sys_setresuid(
    ruid: u32,
    euid: u32,
    suid: u32,
    current_cred: super::Cred,
) -> KernelResult<()> {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Check permissions for each field that will be changed
    // Unprivileged: can only set to current uid, euid, or suid
    // Privileged (CAP_SETUID): can set to any value
    let is_privileged = || super::capable(super::CAP_SETUID);

    // Helper to check if a value is in the current credential set
    let is_permitted = |val: u32| -> bool {
        val == current_cred.uid || val == current_cred.euid || val == current_cred.suid
    };

    // Check each field
    if ruid != NO_CHANGE && !is_permitted(ruid) && !is_privileged() {
        return Err(KernelError::NotPermitted);
    }
    if euid != NO_CHANGE && !is_permitted(euid) && !is_privileged() {
        return Err(KernelError::NotPermitted);
    }
    if suid != NO_CHANGE && !is_permitted(suid) && !is_privileged() {
        return Err(KernelError::NotPermitted);
    }

    // Convert -1 to None (don't change)
    let ruid_opt = if ruid == NO_CHANGE { None } else { Some(ruid) };
    let euid_opt = if euid == NO_CHANGE { None } else { Some(euid) };
    let suid_opt = if suid == NO_CHANGE { None } else { Some(suid) };

    // Apply the changes
    super::percpu::set_current_resuid(ruid_opt, euid_opt, suid_opt)
}

/// sys_setresgid - set real, effective, and saved group IDs
///
/// Sets the real GID, effective GID, and saved GID of the calling process.
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
///
/// # Arguments
/// * `rgid` - New real GID (-1 to leave unchanged)
/// * `egid` - New effective GID (-1 to leave unchanged)
/// * `sgid` - New saved GID (-1 to leave unchanged)
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Permission Model (Linux-compatible)
/// - If unprivileged: can only set each field to one of {current gid, egid, sgid}
/// - With CAP_SETGID: can set any field to any value
/// - When egid changes, fsgid follows (set to new egid)
/// - Note: Linux checks euid (not egid) for privilege
///
/// # Locking
/// Per-CPU credential update is atomic.
pub fn sys_setresgid(
    rgid: u32,
    egid: u32,
    sgid: u32,
    current_cred: super::Cred,
) -> KernelResult<()> {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Privileged: CAP_SETGID (Linux __sys_setresgid)
    let is_privileged = || super::capable(super::CAP_SETGID);

    // Helper to check if a value is in the current credential set
    let is_permitted = |val: u32| -> bool {
        val == current_cred.gid || val == current_cred.egid || val == current_cred.sgid
    };

    // Check each field
    if rgid != NO_CHANGE && !is_permitted(rgid) && !is_privileged() {
        return Err(KernelError::NotPermitted);
    }
    if egid != NO_CHANGE && !is_permitted(egid) && !is_privileged() {
        return Err(KernelError::NotPermitted);
    }
    if sgid != NO_CHANGE && !is_permitted(sgid) && !is_privileged() {
        return Err(KernelError::NotPermitted);
    }

    // Convert -1 to None (don't change)
    let rgid_opt = if rgid == NO_CHANGE { None } else { Some(rgid) };
    let egid_opt = if egid == NO_CHANGE { None } else { Some(egid) };
    let sgid_opt = if sgid == NO_CHANGE { None } else { Some(sgid) };

    // Apply the changes
    super::percpu::set_current_resgid(rgid_opt, egid_opt, sgid_opt)
}

/// sys_setreuid - set real and effective user IDs
///
/// Sets the real UID and effective UID of the calling process.
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
///
/// # Arguments
/// * `ruid` - New real UID (-1 to leave unchanged)
/// * `euid` - New effective UID (-1 to leave unchanged)
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Permission Model (Linux-compatible)
/// - ruid: can set to current {uid, euid} OR requires CAP_SETUID
/// - euid: can set to current {uid, euid, suid} OR requires CAP_SETUID
/// - suid is updated to new euid if: (ruid != -1) OR (euid != -1 AND new_euid != old_uid)
/// - fsuid always follows euid
///
/// # Locking
/// Per-CPU credential update is atomic.
pub fn sys_setreuid(ruid: u32, euid: u32, current_cred: super::Cred) -> KernelResult<()> {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Privileged: CAP_SETUID (Linux __sys_setreuid)
    let is_privileged = || super::capable(super::CAP_SETUID);

    // Permission check for ruid: must be in {uid, euid} or privileged
    if ruid != NO_CHANGE
        && ruid != current_cred.uid
        && ruid != current_cred.euid
        && !is_privileged()
    {
        return Err(KernelError::NotPermitted);
    }

    // Permission check for euid: must be in {uid, euid, suid} or privileged
    if euid != NO_CHANGE
        && euid != current_cred.uid
        && euid != current_cred.euid
        && euid != current_cred.suid
        && !is_privileged()
    {
        return Err(KernelError::NotPermitted);
    }

    // Determine what to set
    let ruid_opt = if ruid == NO_CHANGE { None } else { Some(ruid) };
    let euid_opt = if euid == NO_CHANGE { None } else { Some(euid) };

    // Determine if suid should be updated (Linux semantics):
    // suid = new_euid if: (ruid != -1) OR (euid != -1 AND new_euid != old_uid)
    let new_suid = if ruid != NO_CHANGE {
        // ruid is changing, so suid = new euid (or current euid if euid not changing)
        Some(euid_opt.unwrap_or(current_cred.euid))
    } else if euid != NO_CHANGE && euid != current_cred.uid {
        // euid is changing to something other than current uid
        Some(euid)
    } else {
        None
    };

    // Apply the changes (fsuid follows euid in set_current_reuid)
    super::percpu::set_current_reuid(ruid_opt, euid_opt, new_suid)
}

/// sys_setregid - set real and effective group IDs
///
/// Sets the real GID and effective GID of the calling process.
/// A value of -1 (0xFFFFFFFF) means "don't change this field".
///
/// # Arguments
/// * `rgid` - New real GID (-1 to leave unchanged)
/// * `egid` - New effective GID (-1 to leave unchanged)
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * 0 on success
/// * -EPERM if not permitted
///
/// # Permission Model (Linux-compatible)
/// - rgid: can set to current {gid, egid} OR requires CAP_SETGID
/// - egid: can set to current {gid, egid, sgid} OR requires CAP_SETGID
/// - sgid is updated to new egid if: (rgid != -1) OR (egid != -1 AND new_egid != old_gid)
/// - fsgid always follows egid
/// - Note: Linux checks euid (not egid) for privilege
///
/// # Locking
/// Per-CPU credential update is atomic.
pub fn sys_setregid(rgid: u32, egid: u32, current_cred: super::Cred) -> KernelResult<()> {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Privileged: CAP_SETGID (Linux __sys_setregid)
    let is_privileged = || super::capable(super::CAP_SETGID);

    // Permission check for rgid: must be in {gid, egid} or privileged
    if rgid != NO_CHANGE
        && rgid != current_cred.gid
        && rgid != current_cred.egid
        && !is_privileged()
    {
        return Err(KernelError::NotPermitted);
    }

    // Permission check for egid: must be in {gid, egid, sgid} or privileged
    if egid != NO_CHANGE
        && egid != current_cred.gid
        && egid != current_cred.egid
        && egid != current_cred.sgid
        && !is_privileged()
    {
        return Err(KernelError::NotPermitted);
    }

    // Determine what to set
    let rgid_opt = if rgid == NO_CHANGE { None } else { Some(rgid) };
    let egid_opt = if egid == NO_CHANGE { None } else { Some(egid) };

    // Determine if sgid should be updated (Linux semantics):
    // sgid = new_egid if: (rgid != -1) OR (egid != -1 AND new_egid != old_gid)
    let new_sgid = if rgid != NO_CHANGE {
        // rgid is changing, so sgid = new egid (or current egid if egid not changing)
        Some(egid_opt.unwrap_or(current_cred.egid))
    } else if egid != NO_CHANGE && egid != current_cred.gid {
        // egid is changing to something other than current gid
        Some(egid)
    } else {
        None
    };

    // Apply the changes (fsgid follows egid in set_current_regid)
    super::percpu::set_current_regid(rgid_opt, egid_opt, new_sgid)
}

/// sys_setfsuid - set filesystem UID
///
/// Sets the filesystem UID of the calling process.
/// Unlike most syscalls, this one returns the OLD fsuid value, not an error code.
///
/// # Arguments
/// * `uid` - New filesystem UID
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * Old fsuid value (always succeeds in returning this)
/// * If permission denied or invalid, returns old fsuid without changing
///
/// # Permission Model (Linux-compatible)
/// - Can set fsuid to current {uid, euid, suid, fsuid} OR requires CAP_SETUID
/// - Invalid UID (-1 treated as invalid) returns old fsuid without change
///
/// # Note
/// This syscall does NOT auto-update when euid changes elsewhere.
/// fsuid must be explicitly set via this syscall.
pub fn sys_setfsuid(uid: u32, current_cred: super::Cred) -> i64 {
    let old_fsuid = current_cred.fsuid;

    // Check if uid is valid (treat -1 as "query only")
    if uid == 0xFFFFFFFF {
        return i64::from(old_fsuid);
    }

    // Permission check: must be in {uid, euid, suid, fsuid} or CAP_SETUID
    let is_privileged = || super::capable(super::CAP_SETUID);

    let is_permitted = uid == current_cred.uid
        || uid == current_cred.euid
        || uid == current_cred.suid
        || uid == current_cred.fsuid;

    if !is_permitted && !is_privileged() {
        // Permission denied - return old fsuid without changing
        return i64::from(old_fsuid);
    }

    // Apply the change; without memory for new credentials the old
    // fsuid is returned unchanged (Linux: prepare_creds failure)
    let _ = super::percpu::set_current_fsuid(uid);

    i64::from(old_fsuid)
}

/// sys_setfsgid - set filesystem GID
///
/// Sets the filesystem GID of the calling process.
/// Unlike most syscalls, this one returns the OLD fsgid value, not an error code.
///
/// # Arguments
/// * `gid` - New filesystem GID
/// * `current_cred` - Current credentials (passed from dispatcher)
///
/// # Returns
/// * Old fsgid value (always succeeds in returning this)
/// * If permission denied or invalid, returns old fsgid without changing
///
/// # Permission Model (Linux-compatible)
/// - Can set fsgid to current {gid, egid, sgid, fsgid} OR requires CAP_SETGID
/// - Invalid GID (-1 treated as invalid) returns old fsgid without change
/// - Note: Linux checks euid (not egid) for privilege
///
/// # Note
/// This syscall does NOT auto-update when egid changes elsewhere.
/// fsgid must be explicitly set via this syscall.
pub fn sys_setfsgid(gid: u32, current_cred: super::Cred) -> i64 {
    let old_fsgid = current_cred.fsgid;

    // Check if gid is valid (treat -1 as "query only")
    if gid == 0xFFFFFFFF {
        return i64::from(old_fsgid);
    }

    // Permission check: must be in {gid, egid, sgid, fsgid} or CAP_SETGID
    let is_privileged = || super::capable(super::CAP_SETGID);

    let is_permitted = gid == current_cred.gid
        || gid == current_cred.egid
        || gid == current_cred.sgid
        || gid == current_cred.fsgid;

    if !is_permitted && !is_privileged() {
        // Permission denied - return old fsgid without changing
        return i64::from(old_fsgid);
    }

    // Apply the change; without memory for new credentials the old
    // fsgid is returned unchanged (Linux: prepare_creds failure)
    let _ = super::percpu::set_current_fsgid(gid);

    i64::from(old_fsgid)
}

/// getgroups(size, list) (Linux kernel/groups.c): the supplementary
/// groups; size 0 asks for the count only, a smaller nonzero size is
/// EINVAL
pub fn sys_getgroups(size: i32, list: UserPtr<u32>) -> KernelResult<i64> {
    if size < 0 {
        return Err(KernelError::InvalidArgument);
    }
    let cred = super::current_cred();
    let groups = cred.groups.as_slice();
    if size == 0 {
        return Ok(groups.len() as i64);
    }
    if (size as usize) < groups.len() {
        return Err(KernelError::InvalidArgument);
    }
    let bytes: alloc::vec::Vec<u8> = groups.iter().flat_map(|g| g.to_ne_bytes()).collect();
    crate::uaccess::copy_to_user(list.addr(), &bytes)?;
    Ok(groups.len() as i64)
}

/// setgroups(size, list) (Linux kernel/groups.c): replace the
/// supplementary groups; CAP_SETGID (EPERM), at most NGROUPS_MAX and no
/// invalid gid -1 (EINVAL)
pub fn sys_setgroups(size: i32, list: UserPtr<u32>) -> KernelResult<()> {
    if !super::capable(super::CAP_SETGID) {
        return Err(KernelError::NotPermitted);
    }
    if size < 0 || size as usize > super::NGROUPS_MAX {
        return Err(KernelError::InvalidArgument);
    }
    let n = size as usize;
    let mut bytes = crate::util::kmem::try_vec(n * 4, 0u8)?;
    if n > 0 {
        crate::uaccess::copy_from_user(&mut bytes, list.addr(), n * 4)?;
    }
    let gids: alloc::vec::Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u32::from_ne_bytes(*b))
        .collect();
    if gids.contains(&u32::MAX) {
        return Err(KernelError::InvalidArgument);
    }
    let mut new = super::prepare_creds();
    new.groups = super::GroupInfo::new(gids);
    super::commit_creds(try_arc(new)?);
    Ok(())
}
