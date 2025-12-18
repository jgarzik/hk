# Clone Syscall Implementation

This document describes the Linux-compatible clone() syscall implementation in hk kernel, including all CLONE_* flags, their status, and implementation roadmap.

## Overview

The `clone()` syscall creates a new process or thread. It is the fundamental building block for:
- `fork()` - Create new process with copied resources
- `vfork()` - Create process sharing memory, parent blocks
- `pthread_create()` - Create thread sharing most resources

## Clone Flags Reference

### Core Process Sharing Flags

| Flag | Value | Purpose | Status |
|------|-------|---------|--------|
| CLONE_VM | 0x00000100 | Share virtual memory (address space) | Implemented |
| CLONE_FS | 0x00000200 | Share filesystem context (cwd, root, umask) | Implemented |
| CLONE_FILES | 0x00000400 | Share file descriptor table | Implemented |
| CLONE_SIGHAND | 0x00000800 | Share signal handlers | Deferred (requires signal infrastructure) |
| CLONE_THREAD | 0x00010000 | Same thread group (share PID) | Implemented |
| CLONE_VFORK | 0x00004000 | Parent blocks until child exec/exit | Implemented |
| CLONE_PARENT | 0x00008000 | Child has same parent as caller | Not implemented |
| CLONE_SYSVSEM | 0x00040000 | Share System V semaphore undo | Deferred (no SysV IPC) |
| CLONE_IO | 0x80000000 | Share I/O context | Not implemented |

### TID Pointer Flags

| Flag | Value | Purpose | Status |
|------|-------|---------|--------|
| CLONE_PARENT_SETTID | 0x00100000 | Write child TID to parent's address | Implemented |
| CLONE_CHILD_SETTID | 0x01000000 | Write child TID to child's address | Implemented |
| CLONE_CHILD_CLEARTID | 0x00200000 | Clear TID + futex wake on exit | Implemented |
| CLONE_SETTLS | 0x00080000 | Set thread-local storage | Deferred (arch-specific) |

### Namespace Flags

| Flag | Value | Purpose | Status |
|------|-------|---------|--------|
| CLONE_NEWNS | 0x00020000 | New mount namespace | Stub (no real isolation) |
| CLONE_NEWUTS | 0x04000000 | New UTS namespace | Implemented |
| CLONE_NEWIPC | 0x08000000 | New IPC namespace | Deferred |
| CLONE_NEWPID | 0x20000000 | New PID namespace | Deferred |
| CLONE_NEWNET | 0x40000000 | New network namespace | Deferred |
| CLONE_NEWUSER | 0x10000000 | New user namespace | Deferred |
| CLONE_NEWCGROUP | 0x02000000 | New cgroup namespace | Deferred |

### Debugging/Tracing Flags

| Flag | Value | Purpose | Status |
|------|-------|---------|--------|
| CLONE_PTRACE | 0x00002000 | Continue tracing in child | Not implemented |
| CLONE_UNTRACED | 0x00800000 | Prevent forced tracing | Not implemented |

### Modern Flags (Linux 5.x+)

| Flag | Value | Purpose | Status |
|------|-------|---------|--------|
| CLONE_PIDFD | 0x00001000 | Return pidfd for child | Not implemented |
| CLONE_CLEAR_SIGHAND | 0x100000000 | Reset signal handlers | Deferred |
| CLONE_INTO_CGROUP | 0x200000000 | Place in specific cgroup | Deferred |

## Flag Dependencies

Linux enforces these dependency rules (EINVAL if violated):

1. **CLONE_SIGHAND requires CLONE_VM** - Signal handlers contain addresses that must be valid in shared address space
2. **CLONE_THREAD requires CLONE_SIGHAND** - Threads must share signal handlers
3. **CLONE_NEWNS and CLONE_FS are mutually exclusive** - Cannot share FS context while in new mount namespace
4. **CLONE_NEWPID incompatible with CLONE_THREAD** - Threads cannot be in different PID namespaces

## Common Flag Combinations

### fork() emulation
```
clone(SIGCHLD, 0)
```
No flags - child gets independent copy of everything.

### vfork() emulation
```
clone(CLONE_VM | CLONE_VFORK, SIGCHLD)
```
Share memory, parent blocks until child execs or exits.

### pthread_create() threads
```
clone(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
      | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID, ...)
```
Full resource sharing with TID tracking for pthread_join.

### Container creation
```
clone(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID
      | CLONE_NEWNET | CLONE_NEWUSER, ...)
```
Full namespace isolation.

## Implementation Details

### Per-Task File Descriptor Tables

Each task has its own FD table, managed via `TASK_FD` global mapping.

- **CLONE_FILES set**: Child shares parent's `Arc<Mutex<FdTable>>`
- **CLONE_FILES not set**: Child gets deep copy of FD table

### TID Pointer Operations

- **CLONE_PARENT_SETTID**: At clone time, writes child TID to `parent_tidptr` in parent's address space
- **CLONE_CHILD_SETTID**: At clone time, writes child TID to `child_tidptr` in child's address space
- **CLONE_CHILD_CLEARTID**: On exit, writes 0 to stored address and calls futex_wake to notify pthread_join waiters

### VFORK Blocking

When CLONE_VFORK is set:
1. Child is created with shared address space
2. Parent blocks (busy-waits) on completion flag
3. Child signals completion on exec() or exit()
4. Parent resumes

### Namespace Support

Currently implemented:
- **CLONE_NEWUTS**: Creates new UTS namespace with copied hostname/domainname

Stubbed (no real isolation):
- **CLONE_NEWNS**: Creates wrapper but mount tree is global

Deferred:
- CLONE_NEWIPC, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWUSER, CLONE_NEWCGROUP

## Future Work

### Tier 1: Signal Infrastructure (Required for CLONE_SIGHAND)
- Signal handler tables
- Signal queuing and delivery
- sigaction, sigprocmask syscalls

### Tier 2: TLS Support (CLONE_SETTLS)
- Architecture-specific thread-local storage
- FS/GS base registers (x86_64)
- TPIDR register (aarch64)

### Tier 3: Namespace Completion
- PID namespace with PID translation
- Network namespace with isolated stack
- IPC namespace with isolated objects
- User namespace with UID/GID mapping

### Tier 4: Modern Features
- CLONE_PIDFD for pidfd-based process tracking
- clone3() syscall with extensible struct

## Error Codes

| Error | Value | Condition |
|-------|-------|-----------|
| EINVAL | -22 | Invalid flag combination |
| EINVAL | -22 | CLONE_VM without child_stack (unless CLONE_VFORK) |
| ENOMEM | -12 | Failed to allocate resources |
| EAGAIN | -11 | Resource limit reached |
| EFAULT | -14 | Invalid user pointer |

## References

- Linux clone(2) man page
- Linux clone3(2) man page
- Linux namespaces(7) man page
- kernel/task/mod.rs - Clone flag definitions
- kernel/task/percpu.rs - do_clone() implementation
