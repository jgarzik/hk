//! listns(2) (Linux kernel/nstree.c: listns, copy_ns_id_req, do_listns,
//! do_listns_userns, legitimize_ns)
//!
//! The ids of the namespaces in active use (`ns::common`) the caller may
//! see, in id order, from the namespace tree (`ns::tree`): every type,
//! one type or a set of types, or those one user namespace owns; resumed
//! past the last id a previous call returned. The caller sees its own
//! namespaces, and every one if it may see all namespaces (Linux
//! may_see_all_namespaces). No lock is held across the walk: each step
//! takes the tree's lock once, and each id is copied out with none held.

use super::tree::{self, Tree};
use super::{
    CLONE_NEWUSER, CLONE_NS_FLAGS, NsRef, current_user_ns, is_current_namespace,
    may_see_all_namespaces,
};
use crate::uaccess::{access_ok, copy_struct_from_user, get_user, put_user};
use crate::util::error::{KernelError, KernelResult};

/// A listns request (Linux struct ns_id_req, uapi/linux/nsfs.h)
#[repr(C)]
#[derive(Clone, Copy)]
struct NsIdReq {
    size: u32,
    spare: u32,
    /// The last id a previous call returned, 0 to start
    ns_id: u64,
    /// CLONE_NEW* types to list, 0 for all
    ns_type: u32,
    spare2: u32,
    /// Only those this user namespace owns, 0 for any
    user_ns_id: u64,
}
crate::pod!(NsIdReq {
    size,
    spare,
    ns_id,
    ns_type,
    spare2,
    user_ns_id
});

/// struct ns_id_req's first published size (Linux NS_ID_REQ_SIZE_VER0)
const NS_ID_REQ_SIZE_VER0: usize = 32;

/// `user_ns_id` for the caller's own user namespace (Linux
/// LISTNS_CURRENT_USER)
const LISTNS_CURRENT_USER: u64 = u64::MAX;

/// The most ids one call takes (Linux listns' maxcount)
const MAXCOUNT: u64 = 1_000_000;

/// Linux CLONE_NEWTIME: a type listns knows; hk has no time namespaces
/// (no tree, as Linux without CONFIG_TIME_NS)
const CLONE_NEWTIME: u64 = 0x80;

/// Every type listns knows (Linux NS_ALL)
const NS_ALL: u64 = CLONE_NS_FLAGS | CLONE_NEWTIME;

/// The request at `req` (Linux copy_ns_id_req): EFAULT, E2BIG past a
/// page or with unknown nonzero fields, EINVAL if shorter than the first
/// version or `spare` is set, EOPNOTSUPP for an unknown type
fn copy_ns_id_req(req: u64) -> KernelResult<NsIdReq> {
    let usize: u32 = get_user(req).map_err(|_| KernelError::BadAddress)?;
    if u64::from(usize) > crate::mm::PAGE_SIZE {
        return Err(KernelError::ArgListTooLong);
    }
    let usize = usize as usize;
    if usize < NS_ID_REQ_SIZE_VER0 {
        return Err(KernelError::InvalidArgument);
    }
    let k = match copy_struct_from_user::<NsIdReq>(req, usize) {
        Ok(k) => k,
        Err(None) => return Err(KernelError::ArgListTooLong),
        Err(Some(_)) => return Err(KernelError::BadAddress),
    };
    if k.spare != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if u64::from(k.ns_type) & !NS_ALL != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(k)
}

/// listns(2): up to `nr` ids into `ids` of the namespaces `req` asks
/// for; their count. EINVAL for flags, EOVERFLOW past MAXCOUNT, EFAULT,
/// ENOENT if the namespace after the last id is gone or inactive.
pub fn sys_listns(req: u64, ids: u64, nr: u64, flags: u32) -> KernelResult<i64> {
    if flags != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if nr > MAXCOUNT {
        return Err(KernelError::Overflow);
    }
    // Bounded by MAXCOUNT: no overflow
    if !access_ok(ids, nr as usize * 8) {
        return Err(KernelError::BadAddress);
    }
    let k = copy_ns_id_req(req)?;
    if k.user_ns_id != 0 {
        return listns_userns(&k, ids, nr);
    }
    // One type: its own tree; none or several: every type's (Linux
    // do_listns: hweight32 == 1). Time namespaces have no tree: EINVAL,
    // as Linux without CONFIG_TIME_NS (ns_tree_from_type NULL)
    let ty = if k.ns_type.count_ones() == 1 {
        u64::from(k.ns_type)
    } else {
        0
    };
    if ty == CLONE_NEWTIME {
        return Err(KernelError::InvalidArgument);
    }
    list(Tree::of_type(ty), &k, ids, nr)
}

/// Those the user namespace `user_ns_id` names owns (Linux
/// do_listns_userns): EINVAL if it is gone or inactive
fn listns_userns(k: &NsIdReq, ids: u64, nr: u64) -> KernelResult<i64> {
    let user = if k.user_ns_id == LISTNS_CURRENT_USER {
        current_user_ns()
    } else {
        match tree::lookup(Tree::Type(CLONE_NEWUSER), k.user_ns_id) {
            Some(NsRef::User(u)) => u,
            _ => return Err(KernelError::InvalidArgument),
        }
    };
    list(Tree::owned_by(&user), k, ids, nr)
}

/// Copy the ids of `tree`'s namespaces that `k` asks for and the caller
/// may list, in id order past `k.ns_id`, up to `nr` (Linux do_listns's
/// loop: legitimize_ns, put_user)
fn list(tree: Tree, k: &NsIdReq, ids: u64, nr: u64) -> KernelResult<i64> {
    let mut walk = tree::walk(tree);
    if k.ns_id != 0 {
        // The first namespace past the last id must still be active
        // (Linux lookup_ns_id_at, lookup_ns_owner_at: ENOENT); the walk
        // starts at it (an id past u64::MAX wraps to 0, as Linux's)
        let first = tree::lookup_at(tree, k.ns_id.wrapping_add(1)).ok_or(KernelError::NotFound)?;
        walk = tree::walk_from(tree, first.common().ns_id);
    }
    // Linux may_list_ns: with a user namespace, userns_capable; else
    // per namespace; both are may_see_all_namespaces, which cannot
    // change during the call (the caller's own credentials and pid
    // namespace)
    let all = may_see_all_namespaces();
    let mut n = 0u64;
    while n < nr {
        let Some(ns) = walk.next() else { break };
        let wanted = k.ns_type == 0 || u64::from(k.ns_type) & ns.ns_type() != 0;
        if !wanted || !(all || is_current_namespace(&ns)) {
            continue;
        }
        put_user(ids + n * 8, ns.common().ns_id).map_err(|_| KernelError::BadAddress)?;
        n += 1;
    }
    Ok(n as i64)
}
