//! Task identity and credential syscalls
//!
//! This module contains syscalls for process/thread identity and credentials:
//! - getpid, gettid, getppid (process/thread IDs)
//! - getuid, geteuid, getgid, getegid (user/group IDs)
//! - setuid, setgid, setreuid, setregid (set user/group IDs)
//! - setresuid, setresgid, getresuid, getresgid (real/effective/saved IDs)
//! - setfsuid, setfsgid (filesystem user/group IDs)

use crate::error::KernelError;

use super::{Pid, Tid};

/// sys_getpid - get current process ID
pub fn sys_getpid(pid: Pid) -> i64 {
    pid as i64
}

/// sys_gettid - get current thread ID
pub fn sys_gettid(tid: Tid) -> i64 {
    tid as i64
}

/// sys_getppid - get parent process ID
///
/// Returns the process ID of the parent of the calling process.
/// For init (PID 1), returns 0.
pub fn sys_getppid(ppid: Pid) -> i64 {
    ppid as i64
}

/// sys_getuid - get real user ID
///
/// Returns the real user ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getuid(uid: u32) -> i64 {
    uid as i64
}

/// sys_geteuid - get effective user ID
///
/// Returns the effective user ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_geteuid(euid: u32) -> i64 {
    euid as i64
}

/// sys_getgid - get real group ID
///
/// Returns the real group ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getgid(gid: u32) -> i64 {
    gid as i64
}

/// sys_getegid - get effective group ID
///
/// Returns the effective group ID of the calling process.
/// No locking needed - credentials are immutable during syscall execution.
pub fn sys_getegid(egid: u32) -> i64 {
    egid as i64
}

/// sys_setuid - set user identity (Linux-compatible)
///
/// If the caller is privileged (euid=0), sets real, saved, effective, and
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
pub fn sys_setuid(uid: u32, current_cred: super::Cred) -> i64 {
    // Privileged: euid==0 (or CAP_SETUID, which we don't have yet)
    if current_cred.euid == 0 {
        // Set all UIDs: uid, suid, euid, fsuid - permanently drops root
        super::percpu::set_current_uid_all(uid);
        return 0;
    }

    // Unprivileged: can only set euid to uid or suid
    if uid == current_cred.uid || uid == current_cred.suid {
        super::percpu::set_current_euid(uid);
        return 0;
    }

    // Not permitted
    KernelError::NotPermitted.sysret()
}

/// sys_setgid - set group identity (Linux-compatible)
///
/// If the caller is privileged (euid=0), sets real, saved, effective, and
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
///
/// Note: Linux checks euid==0 (not egid==0) for privilege.
pub fn sys_setgid(gid: u32, current_cred: super::Cred) -> i64 {
    // Privileged: euid==0 (or CAP_SETGID, which we don't have yet)
    // Note: Linux checks euid, not egid, for setgid privilege
    if current_cred.euid == 0 {
        // Set all GIDs: gid, sgid, egid, fsgid
        super::percpu::set_current_gid_all(gid);
        return 0;
    }

    // Unprivileged: can only set egid to gid or sgid
    if gid == current_cred.gid || gid == current_cred.sgid {
        super::percpu::set_current_egid(gid);
        return 0;
    }

    // Not permitted
    KernelError::NotPermitted.sysret()
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
pub fn sys_getresuid<A: crate::uaccess::UaccessArch>(
    ruid_ptr: u64,
    euid_ptr: u64,
    suid_ptr: u64,
    current_cred: super::Cred,
) -> i64 {
    use crate::uaccess::put_user;

    // Validate all pointers
    if !A::access_ok(ruid_ptr, core::mem::size_of::<u32>()) {
        return KernelError::BadAddress.sysret();
    }
    if !A::access_ok(euid_ptr, core::mem::size_of::<u32>()) {
        return KernelError::BadAddress.sysret();
    }
    if !A::access_ok(suid_ptr, core::mem::size_of::<u32>()) {
        return KernelError::BadAddress.sysret();
    }

    // Write the three UIDs to user space
    if put_user::<A, u32>(ruid_ptr, current_cred.uid).is_err() {
        return KernelError::BadAddress.sysret();
    }
    if put_user::<A, u32>(euid_ptr, current_cred.euid).is_err() {
        return KernelError::BadAddress.sysret();
    }
    if put_user::<A, u32>(suid_ptr, current_cred.suid).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
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
pub fn sys_getresgid<A: crate::uaccess::UaccessArch>(
    rgid_ptr: u64,
    egid_ptr: u64,
    sgid_ptr: u64,
    current_cred: super::Cred,
) -> i64 {
    use crate::uaccess::put_user;

    // Validate all pointers
    if !A::access_ok(rgid_ptr, core::mem::size_of::<u32>()) {
        return KernelError::BadAddress.sysret();
    }
    if !A::access_ok(egid_ptr, core::mem::size_of::<u32>()) {
        return KernelError::BadAddress.sysret();
    }
    if !A::access_ok(sgid_ptr, core::mem::size_of::<u32>()) {
        return KernelError::BadAddress.sysret();
    }

    // Write the three GIDs to user space
    if put_user::<A, u32>(rgid_ptr, current_cred.gid).is_err() {
        return KernelError::BadAddress.sysret();
    }
    if put_user::<A, u32>(egid_ptr, current_cred.egid).is_err() {
        return KernelError::BadAddress.sysret();
    }
    if put_user::<A, u32>(sgid_ptr, current_cred.sgid).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
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
/// - If privileged (euid=0 or CAP_SETUID): can set any field to any value
/// - When euid changes, fsuid follows (set to new euid)
///
/// # Locking
/// Per-CPU credential update is atomic. Linux uses prepare_creds/commit_creds
/// for RCU-based credential replacement; we update per-CPU data directly.
pub fn sys_setresuid(ruid: u32, euid: u32, suid: u32, current_cred: super::Cred) -> i64 {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Check permissions for each field that will be changed
    // Unprivileged: can only set to current uid, euid, or suid
    // Privileged (euid=0): can set to any value
    let is_privileged = current_cred.euid == 0;

    // Helper to check if a value is in the current credential set
    let is_permitted = |val: u32| -> bool {
        val == current_cred.uid || val == current_cred.euid || val == current_cred.suid
    };

    // Check each field
    if ruid != NO_CHANGE && !is_privileged && !is_permitted(ruid) {
        return KernelError::NotPermitted.sysret();
    }
    if euid != NO_CHANGE && !is_privileged && !is_permitted(euid) {
        return KernelError::NotPermitted.sysret();
    }
    if suid != NO_CHANGE && !is_privileged && !is_permitted(suid) {
        return KernelError::NotPermitted.sysret();
    }

    // Convert -1 to None (don't change)
    let ruid_opt = if ruid == NO_CHANGE { None } else { Some(ruid) };
    let euid_opt = if euid == NO_CHANGE { None } else { Some(euid) };
    let suid_opt = if suid == NO_CHANGE { None } else { Some(suid) };

    // Apply the changes
    super::percpu::set_current_resuid(ruid_opt, euid_opt, suid_opt);

    0
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
/// - If privileged (euid=0 or CAP_SETGID): can set any field to any value
/// - When egid changes, fsgid follows (set to new egid)
/// - Note: Linux checks euid (not egid) for privilege
///
/// # Locking
/// Per-CPU credential update is atomic.
pub fn sys_setresgid(rgid: u32, egid: u32, sgid: u32, current_cred: super::Cred) -> i64 {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Check permissions - note: Linux checks euid, not egid, for setgid privilege
    let is_privileged = current_cred.euid == 0;

    // Helper to check if a value is in the current credential set
    let is_permitted = |val: u32| -> bool {
        val == current_cred.gid || val == current_cred.egid || val == current_cred.sgid
    };

    // Check each field
    if rgid != NO_CHANGE && !is_privileged && !is_permitted(rgid) {
        return KernelError::NotPermitted.sysret();
    }
    if egid != NO_CHANGE && !is_privileged && !is_permitted(egid) {
        return KernelError::NotPermitted.sysret();
    }
    if sgid != NO_CHANGE && !is_privileged && !is_permitted(sgid) {
        return KernelError::NotPermitted.sysret();
    }

    // Convert -1 to None (don't change)
    let rgid_opt = if rgid == NO_CHANGE { None } else { Some(rgid) };
    let egid_opt = if egid == NO_CHANGE { None } else { Some(egid) };
    let sgid_opt = if sgid == NO_CHANGE { None } else { Some(sgid) };

    // Apply the changes
    super::percpu::set_current_resgid(rgid_opt, egid_opt, sgid_opt);

    0
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
pub fn sys_setreuid(ruid: u32, euid: u32, current_cred: super::Cred) -> i64 {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    let is_privileged = current_cred.euid == 0;

    // Permission check for ruid: must be in {uid, euid} or privileged
    if ruid != NO_CHANGE && !is_privileged && ruid != current_cred.uid && ruid != current_cred.euid
    {
        return KernelError::NotPermitted.sysret();
    }

    // Permission check for euid: must be in {uid, euid, suid} or privileged
    if euid != NO_CHANGE
        && !is_privileged
        && euid != current_cred.uid
        && euid != current_cred.euid
        && euid != current_cred.suid
    {
        return KernelError::NotPermitted.sysret();
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
    super::percpu::set_current_reuid(ruid_opt, euid_opt, new_suid);

    0
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
pub fn sys_setregid(rgid: u32, egid: u32, current_cred: super::Cred) -> i64 {
    const NO_CHANGE: u32 = 0xFFFFFFFF; // -1 as unsigned

    // Note: Linux checks euid, not egid, for setgid privilege
    let is_privileged = current_cred.euid == 0;

    // Permission check for rgid: must be in {gid, egid} or privileged
    if rgid != NO_CHANGE && !is_privileged && rgid != current_cred.gid && rgid != current_cred.egid
    {
        return KernelError::NotPermitted.sysret();
    }

    // Permission check for egid: must be in {gid, egid, sgid} or privileged
    if egid != NO_CHANGE
        && !is_privileged
        && egid != current_cred.gid
        && egid != current_cred.egid
        && egid != current_cred.sgid
    {
        return KernelError::NotPermitted.sysret();
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
    super::percpu::set_current_regid(rgid_opt, egid_opt, new_sgid);

    0
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
        return old_fsuid as i64;
    }

    // Permission check: must be in {uid, euid, suid, fsuid} or privileged
    let is_privileged = current_cred.euid == 0;

    let is_permitted = uid == current_cred.uid
        || uid == current_cred.euid
        || uid == current_cred.suid
        || uid == current_cred.fsuid;

    if !is_privileged && !is_permitted {
        // Permission denied - return old fsuid without changing
        return old_fsuid as i64;
    }

    // Apply the change
    super::percpu::set_current_fsuid(uid);

    old_fsuid as i64
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
        return old_fsgid as i64;
    }

    // Permission check: must be in {gid, egid, sgid, fsgid} or privileged
    // Note: Linux checks euid, not egid, for setgid privilege
    let is_privileged = current_cred.euid == 0;

    let is_permitted = gid == current_cred.gid
        || gid == current_cred.egid
        || gid == current_cred.sgid
        || gid == current_cred.fsgid;

    if !is_privileged && !is_permitted {
        // Permission denied - return old fsgid without changing
        return old_fsgid as i64;
    }

    // Apply the change
    super::percpu::set_current_fsgid(gid);

    old_fsgid as i64
}
