//! The operations io_uring runs inline through the syscall paths: file
//! management, sockets, and the poll/timeout/cancel bookkeeping (Linux
//! io_uring/{openclose,sync,statx,truncate,net,poll,timeout,cancel}.c,
//! which hk does not run asynchronously: BUGS "io_uring gaps")

use super::abi::*;
use super::{IoRing, Submit};
use crate::uaccess::{UserPtr, copy_val_from_user};
use crate::util::error::{KernelError, KernelResult};

/// A byte count as a CQE result: cqe.res is 32 bits, and a larger count
/// truncates as Linux's (an int `ret`)
pub fn cqe_count(n: usize) -> i32 {
    n as i32
}

/// Run the inline operation of `sqe`; None for an opcode that is not
/// one of them
pub fn issue(r: &IoRing, s: &mut Submit, sqe: &IoUringSqe) -> Option<KernelResult<i32>> {
    Some(match sqe.opcode {
        IORING_OP_NOP => Ok(0),
        IORING_OP_OPENAT => {
            crate::fs::syscall::sys_openat(sqe.fd, UserPtr::new(sqe.addr), sqe.op_flags, sqe.len)
        }
        IORING_OP_CLOSE => crate::fs::syscall::sys_close(sqe.fd).map(|()| 0),
        IORING_OP_FSYNC => fsync(sqe),
        IORING_OP_STATX => crate::fs::syscall::sys_statx(
            sqe.fd,
            UserPtr::new(sqe.addr),
            sqe.op_flags as i32,
            sqe.len,
            UserPtr::new(sqe.off),
        )
        .map(|()| 0),
        IORING_OP_FTRUNCATE => {
            crate::fs::syscall::sys_ftruncate(sqe.fd, sqe.off as i64).map(|()| 0)
        }
        IORING_OP_POLL_ADD => poll_add(r, s, sqe),
        IORING_OP_POLL_REMOVE | IORING_OP_TIMEOUT_REMOVE => remove(r, s, sqe),
        IORING_OP_TIMEOUT => timeout(r, s, sqe),
        IORING_OP_ASYNC_CANCEL => cancel(r, s, sqe),
        _ => return net(sqe),
    })
}

fn fsync(sqe: &IoUringSqe) -> KernelResult<i32> {
    if sqe.op_flags & IORING_FSYNC_DATASYNC != 0 {
        crate::fs::syscall::sys_fdatasync(sqe.fd).map(|()| 0)
    } else {
        crate::fs::syscall::sys_fsync(sqe.fd).map(|()| 0)
    }
}

/// The socket operations, through their syscalls
fn net(sqe: &IoUringSqe) -> Option<KernelResult<i32>> {
    use crate::net::syscall as n;
    let (fd, addr, flags) = (sqe.fd, UserPtr::new(sqe.addr), sqe.op_flags as i32);
    let len = u64::from(sqe.len);
    Some(match sqe.opcode {
        IORING_OP_ACCEPT if flags != 0 => n::sys_accept4(fd, addr, UserPtr::new(sqe.off), flags),
        IORING_OP_ACCEPT => n::sys_accept(fd, addr, UserPtr::new(sqe.off)),
        IORING_OP_CONNECT => n::sys_connect(fd, addr, sqe.off).map(|()| 0),
        IORING_OP_SEND => n::sys_sendto(fd, addr, len, flags, UserPtr::new(0), 0).map(cqe_count),
        IORING_OP_RECV => {
            n::sys_recvfrom(fd, addr, len, flags, UserPtr::new(0), UserPtr::new(0)).map(cqe_count)
        }
        IORING_OP_SENDMSG => n::sys_sendmsg(fd, UserPtr::new(sqe.addr), flags).map(cqe_count),
        IORING_OP_RECVMSG => n::sys_recvmsg(fd, UserPtr::new(sqe.addr), flags).map(cqe_count),
        IORING_OP_SHUTDOWN => n::sys_shutdown(fd, sqe.len as i32).map(|()| 0),
        _ => return None,
    })
}

/// IORING_OP_POLL_ADD: the events if the file is ready, else noted as
/// pending (it never completes later: BUGS "io_uring gaps")
fn poll_add(r: &IoRing, s: &mut Submit, sqe: &IoUringSqe) -> KernelResult<i32> {
    let file = r.sqe_file(s, sqe)?;
    let ready = file.f_op.poll(&file, None);
    let wanted = (sqe.op_flags & 0xFFFF) as u16;
    if ready & wanted != 0 {
        return Ok(i32::from(ready));
    }
    s.note_pending(sqe.user_data, r.cq_entries())?;
    Ok(0)
}

/// IORING_OP_POLL_REMOVE / TIMEOUT_REMOVE: cancel the pending operation
/// whose user_data is `addr`, posting its ECANCELED
fn remove(r: &IoRing, s: &mut Submit, sqe: &IoUringSqe) -> KernelResult<i32> {
    let target = sqe.addr;
    let i = s
        .pending
        .iter()
        .position(|&u| u == target)
        .ok_or(KernelError::NotFound)?;
    s.pending.remove(i);
    r.post_cqe(target, KernelError::Canceled.to_errno_neg(), 0);
    Ok(0)
}

/// IORING_OP_TIMEOUT: noted as pending (no timer arms it: BUGS
/// "io_uring gaps"); an expired pure timeout is ETIME
fn timeout(r: &IoRing, s: &mut Submit, sqe: &IoUringSqe) -> KernelResult<i32> {
    if sqe.addr == 0 {
        return Err(KernelError::InvalidArgument);
    }
    // struct __kernel_timespec { i64 tv_sec; i64 tv_nsec; }
    let [sec, nsec] = copy_val_from_user::<[i64; 2]>(sqe.addr)?;
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(KernelError::InvalidArgument);
    }
    let ns = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64);
    // CLOCK_MONOTONIC unless IORING_TIMEOUT_REALTIME (Linux
    // io_timeout_get_clock); IORING_TIMEOUT_ABS is bit 0
    let now = if sqe.op_flags & IORING_TIMEOUT_REALTIME != 0 {
        crate::time::realtime_ns()
    } else {
        crate::time::monotonic_ns()
    };
    let deadline = if sqe.op_flags & 1 != 0 {
        ns
    } else {
        crate::time::deadline_after(now, ns)
    };
    if now >= deadline {
        return Err(KernelError::TimerExpired);
    }
    s.note_pending(sqe.user_data, r.cq_entries())?;
    Ok(0)
}

/// IORING_OP_ASYNC_CANCEL: cancel the first pending operation whose
/// user_data is `addr`, or every one with IORING_ASYNC_CANCEL_ALL
/// (bit 0): the count cancelled
fn cancel(r: &IoRing, s: &mut Submit, sqe: &IoUringSqe) -> KernelResult<i32> {
    let target = sqe.addr;
    let all = sqe.op_flags & 1 != 0;
    let mut n = 0;
    while let Some(i) = s.pending.iter().position(|&u| u == target) {
        s.pending.remove(i);
        r.post_cqe(target, KernelError::Canceled.to_errno_neg(), 0);
        n += 1;
        if !all {
            return Ok(0);
        }
    }
    if n == 0 {
        return Err(KernelError::NotFound);
    }
    Ok(n)
}
