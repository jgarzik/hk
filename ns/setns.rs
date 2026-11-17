//! setns(2) (Linux kernel/nsproxy.c: setns, prepare_nsset, validate_ns,
//! commit_nsset; each namespace type's ->install)
//!
//! A namespace file names the namespace it holds (`fs::pseudo::nsfs`),
//! not a task: setns joins that namespace, even once every task in it
//! has exited. A pidfd joins the namespaces its task is in, those the
//! flags name. The new set is built aside ([`NsSet`]), each namespace
//! installed into it with its type's checks, and switched to only once
//! all succeeded.
//!
//! hk's user namespaces grant no capabilities (BUGS.md): Linux's
//! ns_capable checks in the namespace's owner and in the caller's user
//! namespace are the caller's own capabilities.

use alloc::sync::Arc;

use super::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER,
    CLONE_NEWUTS, CLONE_NS_FLAGS, INIT_NSPROXY, NsProxy, NsRef, current, switch_task_namespaces,
};
use crate::fs::FsStruct;
use crate::task::{CAP_SYS_ADMIN, CAP_SYS_CHROOT, capable};
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc;

/// The namespaces setns is joining (Linux struct nsset)
struct NsSet {
    /// The types being joined (CLONE_NEW*)
    flags: u64,
    /// The new set, the caller's until a namespace is installed; ours
    /// alone until the commit
    nsproxy: Arc<NsProxy>,
    /// The fs context a mount namespace moves to its root: the
    /// caller's when only a mount namespace is joined, else a copy
    /// committed at the end
    fs: Option<Arc<FsStruct>>,
}

/// The caller's fs context is shared with another task (Linux
/// current->fs->users != 1)
fn fs_shared() -> bool {
    crate::task::percpu::current_fs()
        .is_some_and(|fs| fs.users.load(core::sync::atomic::Ordering::SeqCst) != 1)
}

/// The caller has another thread (Linux !thread_group_empty(current))
fn has_threads() -> bool {
    let me = current();
    crate::task::percpu::TASKLIST
        .read()
        .threads(me.pid)
        .nth(1)
        .is_some()
}

/// Linux ns_capable(<owner>, CAP_SYS_ADMIN) and ns_capable(<caller's
/// user namespace>, CAP_SYS_ADMIN): the caller's own (module doc)
fn may_install() -> KernelResult<()> {
    if !capable(CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    Ok(())
}

impl NsSet {
    /// Linux prepare_nsset: a copy of the caller's namespaces, and of
    /// its fs context if a mount namespace is joined with others
    fn prepare(flags: u64) -> KernelResult<Self> {
        let cur = current().nsproxy().unwrap_or_else(|| INIT_NSPROXY.clone());
        let nsproxy = try_arc(cur.dup())?;
        let fs = if flags & CLONE_NEWNS == 0 {
            None
        } else if flags == CLONE_NEWNS {
            crate::task::percpu::current_fs()
        } else {
            crate::task::percpu::current_fs()
                .map(|f| f.copy())
                .transpose()?
        };
        Ok(Self { flags, nsproxy, fs })
    }

    /// The new set, to change
    fn np(&mut self) -> &mut NsProxy {
        Arc::get_mut(&mut self.nsproxy).expect("setns: the new nsproxy is shared")
    }

    /// Install `ns` into the set (Linux validate_ns -> ops->install)
    fn install(&mut self, ns: &NsRef) -> KernelResult<()> {
        match ns {
            NsRef::Mnt(m) => self.mntns_install(m),
            NsRef::User(u) => {
                // Linux userns_install: re-entering one's own user
                // namespace would regain capabilities; a thread group
                // and an fs context shared share a user namespace
                if Arc::ptr_eq(u, &self.nsproxy.user_ns) || has_threads() || fs_shared() {
                    return Err(KernelError::InvalidArgument);
                }
                may_install()?;
                self.np().user_ns = u.clone();
                Ok(())
            }
            NsRef::Pid(p) => {
                may_install()?;
                // Linux pidns_install: only the caller's own pid
                // namespace or one below it, so children stay inside
                let active = crate::task::pid::current_pid_ns();
                let mut a: &super::PidNamespace = p;
                while a.level > active.level {
                    match a.parent.as_deref() {
                        Some(up) => a = up,
                        None => break,
                    }
                }
                if !core::ptr::eq(a, active) {
                    return Err(KernelError::InvalidArgument);
                }
                self.np().pid_ns = p.clone();
                Ok(())
            }
            NsRef::Uts(u) => {
                may_install()?;
                self.np().uts_ns = u.clone();
                Ok(())
            }
            NsRef::Ipc(i) => {
                may_install()?;
                self.np().ipc_ns = i.clone();
                Ok(())
            }
            NsRef::Net(n) => {
                may_install()?;
                self.np().net_ns = n.clone();
                Ok(())
            }
            NsRef::Cgroup(c) => {
                may_install()?;
                if !Arc::ptr_eq(c, &self.nsproxy.cgroup_ns) {
                    self.np().cgroup_ns = c.clone();
                }
                Ok(())
            }
        }
    }

    /// Install the namespaces of the task `pid` names that the flags
    /// name, in Linux's order (validate_nsset): ESRCH once it is gone,
    /// EPERM without ptrace-read access to it (real ids)
    fn install_from(&mut self, pid: &crate::task::pid::Pid) -> KernelResult<()> {
        // Linux pidfd_get_task -> get_pid_task, under RCU
        let t = crate::task::percpu::get_pid_task(pid).ok_or(KernelError::NoProcess)?;
        if !crate::task::ptrace::may_access_task(&t, false) {
            return Err(KernelError::NotPermitted);
        }
        let nsp = t
            .task_lock()
            .nsproxy()
            .cloned()
            .ok_or(KernelError::NoProcess)?;
        let order = [
            (CLONE_NEWUSER, NsRef::User(nsp.user_ns.clone())),
            (CLONE_NEWNS, NsRef::Mnt(nsp.mnt_ns.clone())),
            (CLONE_NEWUTS, NsRef::Uts(nsp.uts_ns.clone())),
            (CLONE_NEWIPC, NsRef::Ipc(nsp.ipc_ns.clone())),
            (CLONE_NEWPID, NsRef::Pid(t.get_pid_ns())),
            (CLONE_NEWCGROUP, NsRef::Cgroup(nsp.cgroup_ns.clone())),
            (CLONE_NEWNET, NsRef::Net(nsp.net_ns.clone())),
        ];
        for (flag, ns) in &order {
            if self.flags & flag != 0 {
                self.install(ns)?;
            }
        }
        Ok(())
    }

    /// Linux mntns_install: CAP_SYS_ADMIN and CAP_SYS_CHROOT, an fs
    /// context of its own; root and cwd go to the namespace's root,
    /// past what is mounted there (LOOKUP_DOWN)
    fn mntns_install(&mut self, m: &Arc<super::MntNamespace>) -> KernelResult<()> {
        if !capable(CAP_SYS_ADMIN) || !capable(CAP_SYS_CHROOT) {
            return Err(KernelError::NotPermitted);
        }
        if fs_shared() {
            return Err(KernelError::InvalidArgument);
        }
        let root = m.root_path().ok_or(KernelError::NotFound)?;
        self.np().mnt_ns = m.clone();
        if let Some(fs) = &self.fs {
            fs.set_pwd(root.clone());
            fs.set_root(root);
        }
        Ok(())
    }

    /// The point of no return (Linux commit_nsset): the copied fs
    /// context's root and cwd, leaving an IPC namespace's semaphore
    /// undos, then the new set
    fn commit(self) {
        let me = current();
        if self.flags & CLONE_NEWNS != 0
            && self.flags & !CLONE_NEWNS != 0
            && let (Some(tmp), Some(fs)) = (&self.fs, crate::task::percpu::current_fs())
        {
            fs.set_root(tmp.get_root());
            fs.set_pwd(tmp.get_pwd());
        }
        if self.flags & CLONE_NEWIPC != 0 {
            crate::ipc::sem::exit_sem(&me);
        }
        switch_task_namespaces(&me, self.nsproxy);
    }
}

/// The flags a pidfd setns takes (Linux check_setns_flags): some, and
/// only namespace types hk has (CLONE_NEWTIME is EINVAL, as Linux
/// without CONFIG_TIME_NS)
fn check_setns_flags(flags: u64) -> KernelResult<()> {
    if flags == 0 || flags & !CLONE_NS_FLAGS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

/// setns(2): join the namespace the namespace file `fd` holds (a
/// nonzero `flags` must name its type), or the namespaces `flags`
/// names of the task the pidfd `fd` refers to. EBADF for a bad fd,
/// EINVAL for any other file.
pub fn sys_setns(fd: i32, flags: i32) -> KernelResult<()> {
    use crate::fs::pseudo::nsfs;
    let file = crate::fs::io::fget(fd)?;
    let flags = u64::from(flags as u32);
    if nsfs::proc_ns_file(&file) {
        let ns = file
            .get_inode()
            .and_then(|i| nsfs::get_proc_ns(&i))
            .ok_or(KernelError::InvalidArgument)?;
        if flags != 0 && flags != ns.ns_type() {
            return Err(KernelError::InvalidArgument);
        }
        let mut set = NsSet::prepare(ns.ns_type())?;
        set.install(&ns)?;
        set.commit();
        return Ok(());
    }
    let pidfd = crate::task::pidfd::get_pidfd(&file).ok_or(KernelError::InvalidArgument)?;
    check_setns_flags(flags)?;
    let mut set = NsSet::prepare(flags)?;
    set.install_from(pidfd.pid_ref())?;
    set.commit();
    Ok(())
}
