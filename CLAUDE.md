# CLAUDE.md

hk: stable-Rust (no nightly) no_std SMP kernel, x86-64 + aarch64, Linux syscall ABI. No `src/` dirs.

## Mission
- Linux-compatible kernel for many-core 64-bit machines, grown in chunks toward full compatibility. Modern hardware only; targets: QEMU/virtio, Dell OptiPlex 3020.
- Syscalls: 100%. ioctls, /proc, /sys: pragmatic subset driven by real apps.
- IPv6 comes later: no IPv4-only assumptions in shared net layers.
- No users yet: redesign internals freely (no compat shims) if `doc/LOCKING.md` stays correct. Linux ABI/semantics are binding.

## Build / verify
- Makefile targets only (bare cargo lacks `--target`). `user/`, `tools/` are separate workspaces; setup: `DEVELOPMENT.md`.
- Done = `make test check check-arm check-linux check-linux-arm clippy clippy-arm fmt-check` all pass, clippy warning-free. `check*` pass = shutdown msg, no `FAIL` in `/tmp/qemu_serial{,_arm}.log`.
- `check-linux*` run the same `user/boot_tester` as init on real Linux: tests must pass on BOTH; Linux defines expected behavior. Host-only branches: `host_mode()`/`skip()` in `tests/helpers.rs`.

## Rules
- Generic code + arch callbacks in `kernel/arch/{x86_64,aarch64}/`; no scattered `#[cfg(target_arch)]`. aarch64: modern syscalls only; numbers are per-arch.
- New syscall: boot test in `user/boot_tester/tests/`, register in `tests/mod.rs::run_all_tests`, update `doc/SYSCALLS.md`.
- Locking is top priority. Read `doc/LOCKING.md` first. Mimic Linux lock order/semantics (i_rwsem, mmap_lock, rename_lock, sk_lock, RTNL…); document any deviation there. IRQ-reachable state → `IrqSpinlock`; no `Mutex`/`RwLock` in IRQ context; never sleep under a spinlock. Each new/changed lock: IRQ class + order position, `doc/LOCKING.md` updated in the SAME commit. Cycles and sleep-under-spin are critical bugs.
- Prefer per-CPU structures (state, queues, caches, counters, allocators); justify globals. Per-CPU still needs IRQ/preempt discipline and barriers for cross-CPU reads.
- Small functions, short Linux-style names (`tcp_rcv`, `fib::lookup`).
- `user/boot_tester` is no_std, provides its own `mem*`/`bcmp`.
- Bisectable: EVERY commit on `updates` passes the full gate alone (user may push any time). Develop privately, publish a curated series, gating each commit before the next. A repro test lands with or after its fix.

## Known issues
`BUGS.md`.
