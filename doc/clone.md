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
| CLONE_SIGHAND | 0x00000800 | Share signal handlers | Implemented |
| CLONE_THREAD | 0x00010000 | Same thread group (share PID) | Implemented |
| CLONE_VFORK | 0x00004000 | Parent blocks until child exec/exit | Implemented |
| CLONE_PARENT | 0x00008000 | Child has same parent as caller | Implemented |
| CLONE_SYSVSEM | 0x00040000 | Share System V semaphore undo | Implemented |
| CLONE_IO | 0x80000000 | Share I/O context | Implemented |

### TID Pointer Flags

| Flag | Value | Purpose | Status |
|------|-------|---------|--------|
| CLONE_PARENT_SETTID | 0x00100000 | Write child TID to parent's address | Implemented |
| CLONE_CHILD_SETTID | 0x01000000 | Write child TID to child's address | Implemented |
| CLONE_CHILD_CLEARTID | 0x00200000 | Clear TID + futex wake on exit | Implemented |
| CLONE_SETTLS | 0x00080000 | Set thread-local storage | Implemented |

### Namespace Flags

| Flag | Value | Purpose | Status |
|------|-------|---------|--------|
| CLONE_NEWNS | 0x00020000 | New mount namespace | Implemented |
| CLONE_NEWUTS | 0x04000000 | New UTS namespace | Implemented |
| CLONE_NEWIPC | 0x08000000 | New IPC namespace | Implemented |
| CLONE_NEWPID | 0x20000000 | New PID namespace | Implemented |
| CLONE_NEWNET | 0x40000000 | New network namespace | Implemented |
| CLONE_NEWUSER | 0x10000000 | New user namespace | Implemented |
| CLONE_NEWCGROUP | 0x02000000 | New cgroup namespace | Deferred (no cgroups) |

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
- **CLONE_CHILD_SETTID**: Writes child TID to `child_tidptr` in child's address space
  - For threads (CLONE_VM): Written at clone time (shared address space)
  - For fork (no CLONE_VM): Written in `clone_child_entry` after child's page table is loaded
- **CLONE_CHILD_CLEARTID**: On exit, writes 0 to stored address and calls futex_wake to notify pthread_join waiters

### VFORK Blocking

When CLONE_VFORK is set:
1. Child is created with shared address space
2. Parent blocks (busy-waits) on completion flag
3. Child signals completion on exec() or exit()
4. Parent resumes

### Signal Handler Sharing (CLONE_SIGHAND)

Each task has a `SigHand` structure holding signal handlers:

- **CLONE_SIGHAND set**: Child shares parent's `Arc<IrqSpinlock<SigHand>>`
- **CLONE_SIGHAND not set**: Child gets deep copy via `SigHand::deep_clone()`
- **CLONE_THREAD**: Also enables shared thread-group pending signals

### Namespace Support

Fully implemented:
- **CLONE_NEWUTS**: Creates new UTS namespace with copied hostname/domainname
- **CLONE_NEWPID**: Creates new PID namespace with hierarchical PID translation
- **CLONE_NEWUSER**: Creates new user namespace with UID/GID mapping support
- **CLONE_NEWIPC**: Creates new IPC namespace with isolated SysV IPC resources

Partially implemented:
- **CLONE_NEWNS**: Creates new mount namespace wrapper (mount tree still global)

Deferred (require subsystem support):
- **CLONE_NEWNET**: Requires per-namespace network isolation
- **CLONE_NEWCGROUP**: Requires cgroup implementation

### CLONE_PARENT Support

When CLONE_PARENT or CLONE_THREAD is set, the child's parent PID (ppid) is set
to the caller's parent rather than the caller itself. This makes the child a
sibling of the caller rather than its child.

### CLONE_SYSVSEM Support

Shares the SysV semaphore undo list between parent and child:
- **SEM_UNDO tracking**: semop() with SEM_UNDO flag records adjustments
- **exit_sem()**: On task exit, pending undo adjustments are applied
- **clone_task_semundo()**: Shares or copies undo list based on flag
- **unshare(CLONE_SYSVSEM)**: Detaches from shared undo list

### CLONE_IO Support

Shares I/O context (ioprio) between parent and child:
- **IoContext**: Contains atomic ioprio value (class + level)
- **ioprio_get/ioprio_set syscalls**: Get/set I/O scheduling priority
- **clone_task_io()**: Shares or copies IoContext based on flag

### CLONE_SETTLS Support

Sets thread-local storage (TLS) pointer for the new task:
- **x86_64**: TLS value stored in FS base register (MSR 0xC0000100)
- **aarch64**: TLS value stored in TPIDR_EL0 register

Implementation follows Linux kernel's arm64 pattern:
- TLS save/restore handled in Rust context switch wrappers (not assembly)
- On context switch: save prev task's TLS to storage, load next task's TLS from storage
- Assembly `switch_to.S` is pure register save/restore with no function calls
- `clone_child_entry` loads child's TLS before returning to usermode

TLS storage:
- Per-task TLS values stored in `TASK_TLS` global table
- `set_task_tls(tid, value)` / `get_task_tls(tid)` API
- Context switch uses `current_tid()` to identify prev task

Related syscalls:
- **unshare(2)**: Disassociate from current namespaces (implemented)
- **setns(2)**: Join existing namespace via fd (implemented)

## Future Work

### Tier 1: Remaining Namespaces
- **CLONE_NEWNS**: Full mount isolation (per-namespace mount tree)
- **CLONE_NEWNET**: Network namespace isolation
- **CLONE_NEWCGROUP**: Cgroup namespace (requires cgroup support)

### Tier 2: Modern Features
- CLONE_PIDFD for pidfd-based process tracking
- clone3() syscall with extensible struct

### Tier 3: Debugging/Tracing
- CLONE_PTRACE for ptrace continuation in child
- CLONE_UNTRACED to prevent forced tracing

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
- kernel/task/mod.rs - Clone flag definitions, IoContext, TASK_TLS storage
- kernel/task/percpu.rs - do_clone() implementation, get_current_task_tls()
- kernel/task/syscall.rs - ioprio_get/ioprio_set syscalls
- kernel/arch/x86_64/context.rs - Context switch with TLS handling (FS base)
- kernel/arch/x86_64/switch_to.S - Pure-asm register save/restore
- kernel/arch/aarch64/context.rs - Context switch with TLS handling (TPIDR_EL0)
- kernel/arch/aarch64/switch_to.S - Pure-asm register save/restore
- kernel/ns/mod.rs - Namespace proxy and syscalls (unshare, setns)
- kernel/ns/uts.rs - UTS namespace implementation
- kernel/ns/pid.rs - PID namespace implementation
- kernel/ns/user.rs - User namespace implementation
- kernel/ipc/mod.rs - IPC namespace implementation
- kernel/ipc/sem.rs - SysV semaphores with SEM_UNDO support
- kernel/signal/mod.rs - Signal handler sharing (CLONE_SIGHAND)
- kernel/fs/procfs.rs - /proc/<pid>/ns/* namespace files
