//! Credential switches (Linux kernel/cred.c): commit_creds' publish and
//! the current task's id setters the set*id syscalls build on.

use super::percpu::{current, current_cred};
use super::tasklist::TASKLIST;
use crate::ns::Namespace;
use crate::task::{Cred, Task};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;
use alloc::sync::Arc;

/// commit_creds' switch (Linux kernel/cred.c commit_creds): the new set
/// is published under no lock (rcu_assign_pointer), the old one dropped
/// a grace period later (put_cred_rcu); others read it under RCU
pub fn commit_creds_impl(new: alloc::sync::Arc<Cred>) {
    let me = current();
    if me.tid() == 0 {
        return; // The boot task keeps its static root credentials
    }
    // Its own credentials, not an override in force (Linux commit_creds
    // replaces real_cred and cred together)
    let old = Task::cred(&me);

    // Changing euid/egid/fsuid/fsgid makes the task non-dumpable
    // (suid_dumpable, default 0), so a less-privileged identity can't ptrace
    // or core-dump state obtained under the old one (Linux kernel/cred.c
    // commit_creds)
    let gains_caps = new.cap_permitted.0 & !old.cap_permitted.0 != 0;
    let ids_changed = old.euid != new.euid
        || old.egid != new.egid
        || old.fsuid != new.fsuid
        || old.fsgid != new.fsgid
        || gains_caps;
    drop(old);
    if ids_changed {
        // SAFETY: the task itself
        if let Some(mm) = unsafe { Task::mm(&me) } {
            // On the mm: every thread sharing it (Linux set_dumpable(
            // task->mm))
            mm.set_dumpable(crate::task::dumpable::SUID_DUMP_DISABLE);
        }
        // Its parent no longer signals it at death (Linux commit_creds:
        // pdeath_signal = 0 before the new set is published); a
        // TaskInner field, written under TASKLIST
        if let Some(mut t) = TASKLIST.write().view_mut(&me) {
            t.pdeath_signal = None;
        }
    }
    // SAFETY: the task itself
    unsafe { me.set_cred(new) };
}

/// Task `t` (the caller itself) moves to user namespace `new` (Linux
/// commit_creds -> switch_cred_namespaces when the user namespace
/// changes): the active reference its credentials hold moves, under
/// TASKLIST, as `TaskInner.user_ns` is written; the old namespace is
/// dropped after it
pub fn switch_cred_namespaces(t: &Task, new: &Arc<crate::ns::UserNamespace>) {
    let old = {
        let mut table = TASKLIST.write();
        let Some(mut v) = table.view_mut(t) else {
            return;
        };
        if v.user_ns.as_ref().is_some_and(|u| Arc::ptr_eq(u, new)) {
            return;
        }
        new.active_get();
        let old = v.user_ns.replace(new.clone());
        if let Some(o) = &old {
            o.active_put();
        }
        old
    };
    drop(old);
}

/// Update current task's UID (all fields: uid, suid, euid, fsuid)
///
/// Called by sys_setuid when privileged (euid==0) changes UID.
/// Sets real, saved, effective, and filesystem UID - permanently drops root.
/// This matches Linux setuid() semantics for privileged callers.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_uid_all(uid: crate::task::Uid) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.uid = uid;
    new_cred.suid = uid;
    new_cred.euid = uid;
    new_cred.fsuid = uid;
    commit_uid_change(new_cred)
}

/// Commit a uid change after the Linux capability fixup
/// (cap_emulate_setxuid)
fn commit_uid_change(mut new_cred: crate::task::Cred) -> Result<(), KernelError> {
    let old = current_cred();
    crate::task::cap_fix_setuid(&old, &mut new_cred, current_keep_caps());
    // The new real uid's counters (Linux __sys_setuid et al.:
    // set_cred_ucounts before commit_creds): EAGAIN without them
    crate::task::set_cred_ucounts(&mut new_cred)?;
    crate::task::commit_creds(try_arc(new_cred)?);
    Ok(())
}

/// PR_SET_KEEPCAPS of the current task
fn current_keep_caps() -> bool {
    TASKLIST
        .read()
        .view(&current())
        .is_some_and(|t| t.prctl.keep_caps)
}

/// Update current task's effective UID only (euid and fsuid)
///
/// Called by sys_setuid for non-root privilege drop.
/// Sets effective and filesystem UID, leaving real UID unchanged.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_euid(euid: crate::task::Uid) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.euid = euid;
    new_cred.fsuid = euid; // fsuid follows euid
    commit_uid_change(new_cred)
}

/// Update current task's GID (all fields: gid, sgid, egid, fsgid)
///
/// Called by sys_setgid when privileged (euid==0) changes GID.
/// Sets real, saved, effective, and filesystem GID.
/// This matches Linux setgid() semantics for privileged callers.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_gid_all(gid: crate::task::Gid) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.gid = gid;
    new_cred.sgid = gid;
    new_cred.egid = gid;
    new_cred.fsgid = gid;
    crate::task::commit_creds(try_arc(new_cred)?);
    Ok(())
}

/// Update current task's effective GID only (egid and fsgid)
///
/// Called by sys_setgid for non-root privilege drop.
/// Sets effective and filesystem GID, leaving real GID unchanged.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_egid(egid: crate::task::Gid) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.egid = egid;
    new_cred.fsgid = egid; // fsgid follows egid
    crate::task::commit_creds(try_arc(new_cred)?);
    Ok(())
}

/// Get current task's saved UID (suid)
pub fn get_current_suid() -> crate::task::Uid {
    current_cred().suid
}

/// Get current task's saved GID (sgid)
pub fn get_current_sgid() -> crate::task::Gid {
    current_cred().sgid
}

/// Update current task's real, effective, and saved UIDs selectively
///
/// Called by sys_setresuid. Each field is only updated if Some.
/// When euid changes, fsuid follows (Linux semantics).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_resuid(
    ruid: Option<crate::task::Uid>,
    euid: Option<crate::task::Uid>,
    suid: Option<crate::task::Uid>,
) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    if let Some(uid) = ruid {
        new_cred.uid = uid;
    }
    if let Some(uid) = euid {
        new_cred.euid = uid;
        new_cred.fsuid = uid; // fsuid follows euid
    }
    if let Some(uid) = suid {
        new_cred.suid = uid;
    }
    commit_uid_change(new_cred)
}

/// Update current task's real, effective, and saved GIDs selectively
///
/// Called by sys_setresgid. Each field is only updated if Some.
/// When egid changes, fsgid follows (Linux semantics).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_resgid(
    rgid: Option<crate::task::Gid>,
    egid: Option<crate::task::Gid>,
    sgid: Option<crate::task::Gid>,
) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    if let Some(gid) = rgid {
        new_cred.gid = gid;
    }
    if let Some(gid) = egid {
        new_cred.egid = gid;
        new_cred.fsgid = gid; // fsgid follows egid
    }
    if let Some(gid) = sgid {
        new_cred.sgid = gid;
    }
    crate::task::commit_creds(try_arc(new_cred)?);
    Ok(())
}

/// Get current task's filesystem UID (fsuid)
pub fn get_current_fsuid() -> crate::task::Uid {
    current_cred().fsuid
}

/// Get current task's filesystem GID (fsgid)
pub fn get_current_fsgid() -> crate::task::Gid {
    current_cred().fsgid
}

/// Update current task's real and effective UIDs (setreuid semantics)
///
/// Called by sys_setreuid. Each field is only updated if Some.
/// Also updates suid if new_suid is Some.
/// fsuid always follows euid (set to new euid value).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_reuid(
    ruid: Option<crate::task::Uid>,
    euid: Option<crate::task::Uid>,
    new_suid: Option<crate::task::Uid>,
) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    if let Some(uid) = ruid {
        new_cred.uid = uid;
    }
    if let Some(uid) = euid {
        new_cred.euid = uid;
        new_cred.fsuid = uid; // fsuid always follows euid
    }
    if let Some(uid) = new_suid {
        new_cred.suid = uid;
    }
    commit_uid_change(new_cred)
}

/// Update current task's real and effective GIDs (setregid semantics)
///
/// Called by sys_setregid. Each field is only updated if Some.
/// Also updates sgid if new_sgid is Some.
/// fsgid always follows egid (set to new egid value).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_regid(
    rgid: Option<crate::task::Gid>,
    egid: Option<crate::task::Gid>,
    new_sgid: Option<crate::task::Gid>,
) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    if let Some(gid) = rgid {
        new_cred.gid = gid;
    }
    if let Some(gid) = egid {
        new_cred.egid = gid;
        new_cred.fsgid = gid; // fsgid always follows egid
    }
    if let Some(gid) = new_sgid {
        new_cred.sgid = gid;
    }
    crate::task::commit_creds(try_arc(new_cred)?);
    Ok(())
}

/// Set current task's filesystem UID directly
///
/// Called by sys_setfsuid. Does NOT auto-update when euid changes elsewhere.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_fsuid(fsuid: crate::task::Uid) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.fsuid = fsuid;
    crate::task::cap_fix_setfsuid(&current_cred(), &mut new_cred);
    crate::task::commit_creds(try_arc(new_cred)?);
    Ok(())
}

/// Set current task's filesystem GID directly
///
/// Called by sys_setfsgid. Does NOT auto-update when egid changes elsewhere.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_fsgid(fsgid: crate::task::Gid) -> Result<(), KernelError> {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.fsgid = fsgid;
    crate::task::commit_creds(try_arc(new_cred)?);
    Ok(())
}
