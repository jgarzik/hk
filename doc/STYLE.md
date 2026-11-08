# Design and style

The rules for `unsafe` are in `doc/UNSAFE.md` and the locking rules in
`doc/LOCKING.md`. This file covers everything else.

## Design

- **Follow Linux.** Linux's ABI and semantics are binding. Its internal
  design (names, lock order, data structures) is the default unless Rust
  gives a clearly better form. Write any deviation down where the code is.
- **Errors.** Return `Result<_, KernelError>` and propagate with `?`.
  Convert to an errno only at the syscall boundary (`SysRet::ret` in
  dispatch). No raw errno numbers.
- **Syscalls.** `sys_*` return `KernelResult` and take user pointers as
  `UserPtr`/`UserSlice`.
- **No panics on user input.** `panic!`, `unwrap` and `expect` are only
  for kernel invariants: a state that cannot happen unless the kernel has
  a bug. Anything a user, a device or a disk can cause is an error return.
- **Fallible allocation for untrusted sizes.** The global allocator
  panics the kernel when it cannot satisfy a request (large blocks come
  from vmalloc, up to `kmem::MAX_KMALLOC`, Linux kvmalloc's INT_MAX;
  vmalloc memory is not physically contiguous: never DMA from the
  heap's large blocks, use `hw::dma`). A buffer
  whose size comes from a syscall argument, the network or a disk must
  grow through a fallible path: `kmem::try_vec` for a known size, or
  `kmem::KVec`/`KDeque` (whose growth is always `try_*`, ENOMEM) for one
  built up over time. Never `vec![x; n]`, `with_capacity`, `push`,
  `extend`, `resize` or `reserve` on a length the kernel does not bound
  itself. A stream of bytes is a queue of bounded chunks, not one buffer.
- **Allocate once, outside locks.** Under any spinlock or in softirq an
  allocation cannot reclaim or fall back to vmalloc, so order 4 (64 KiB)
  and up can fail under fragmentation, and an infallible one then panics.
  When a buffer's size is known or tightly bounded and it is filled at
  once (above all under a lock or in a callback that runs under one), size
  it before taking the lock: one allocation, no allocator work inside.
  Don't pre-size long-lived, slowly growing tables or usually-empty lists,
  and `collect()` from an exact-size iterator already allocates once.
- **Types carry meaning.** Use newtypes for addresses and numbers that
  must not be mixed up (`PhysAddr`, `VirtAddr`, `Pfn`, device numbers,
  fds), `bitflags` for flag words, and enums for closed sets.
  Make a bad state unrepresentable rather than checking for it at run time.
  Typestate and const generics are worth it when they remove a check or
  `unsafe`, not as decoration.
- **Own the resource.** Ownership and RAII guards release things: locks,
  frames, mappings, references. Never pair a manual unlock or free with
  every return path.
- **Per-CPU before global.** Prefer per-CPU state, queues, caches and
  counters. Every global needs a reason (true system-wide state, or
  measured as cheaper) and a documented lock.
- **Small pieces.** Keep functions small, with short Linux-style names
  (`tcp_rcv`, `fib::lookup`); the module path gives the context. Modules
  cover one subsystem piece; split a file when it mixes unrelated parts.
- **No dead or speculative code.** Delete unused code and don't add hooks
  for features that don't exist. Git keeps history.

## Code

- `#[must_use]` on guards, tokens and fns whose result must be checked.
- Use `#[inline]` on purpose, on small wrappers that must cost nothing.
  Don't scatter it elsewhere.
- Use `as` casts only when they cannot lose bits, or with a comment when
  truncating on purpose. Prefer `from`, `try_from`, `from_le_bytes`.
- Arithmetic on user or device values uses `checked_*`/`saturating_*`:
  release builds don't check overflow.
- Use `debug_assert!` for expensive invariant checks and `assert!` for cheap
  ones that keep memory safe (`doc/UNSAFE.md` rule 4).
- Comments say *why* and give the Linux counterpart. Doc comments
  describe current behaviour only, with no history.
- Run `make fmt`. Clippy must be clean at the workspace lint levels.
- Silence a lint with `#[expect(...)]`, never `#[allow(...)]`: a stale
  `expect` fails the build. Use `allow` only where the lint fires on
  some configurations (arch, host tests) and not others, and give it a
  `reason = "..."`.

## Arch split

Generic code calls arch callbacks in `arch/{x86_64,aarch64}/`; don't
scatter `#[cfg(target_arch)]`. Syscall numbers are per-arch; aarch64
supports only the modern syscalls.
