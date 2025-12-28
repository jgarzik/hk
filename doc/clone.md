# Clone Syscall - Gaps and Future Work

## Implemented Flags

All major clone flags are now implemented. The following were recently added:

| Flag | Value | Purpose |
|------|-------|---------|
| CLONE_PTRACE | 0x00002000 | Continue tracing in child (if parent is traced) |
| CLONE_UNTRACED | 0x00800000 | Prevent forced CLONE_PTRACE by tracer |
| CLONE_NEWCGROUP | 0x02000000 | New cgroup namespace |
| CLONE_INTO_CGROUP | 0x200000000 | Place child in specific cgroup (clone3 only) |

## Notes

- **CLONE_INTO_CGROUP** is only supported via clone3 syscall (not clone).
  It requires a cgroup file descriptor pointing to an open cgroupfs directory.
