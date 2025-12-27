# Clone Syscall - Gaps and Future Work

## Unimplemented Clone Flags

| Flag | Value | Purpose |
|------|-------|---------|
| CLONE_NEWCGROUP | 0x02000000 | New cgroup namespace (requires cgroup support) |
| CLONE_PTRACE | 0x00002000 | Continue tracing in child (requires ptrace) |
| CLONE_UNTRACED | 0x00800000 | Prevent forced tracing (requires ptrace) |
| CLONE_INTO_CGROUP | 0x200000000 | Place in specific cgroup (requires cgroups) |

## Dependencies

- **CLONE_NEWCGROUP** and **CLONE_INTO_CGROUP**: Blocked on cgroup v2 implementation
- **CLONE_PTRACE** and **CLONE_UNTRACED**: Blocked on ptrace implementation
