# hk: Rust-for-Linux idioms worth adopting

What the Rust-for-Linux (RfL) kernel crate (`~/tmp/repo/linux/rust/kernel/`,
`Documentation/rust/`) and its public discussion do that hk does not, ranked by value
to hk: stable Rust only, no C-bindings layer, Linux ABI binding, locking first. For
LOC-saving idioms (including `#[expect]` over `#[allow]`) see
`hk-rust-idioms-report.md`.

## Ranking

1. **Fallible kernel `Arc`/`Box`** (`rust/kernel/sync/arc.rs`: `Arc::new(x, flags) ->
   Result`, `UniqueArc`, `ArcBorrow`, no weak count; `rust/kernel/alloc/kbox.rs`).
   About 331 infallible `Box::new`/`Arc::new` abort on OOM where Linux returns ENOMEM;
   `util/kmem.rs` covers only Vec/VecDeque. `UniqueArc` builds then shares without a
   lock; `ArcBorrow` avoids refcount traffic (`util/list.rs` `ArcList`, `io/epoll.rs`).
   Stable needs an hk-owned `Arc` (`std` `Arc::try_new` is nightly). Biggest gain.
2. **Typed user pointers** (`rust/kernel/uaccess.rs` `UserPtr`, `UserSlice`
   reader/writer; `Untrusted<T>`, https://lwn.net/Articles/1034603). Syscalls take user
   addresses as raw `u64` (`fs/io.rs` `sys_read`). A newtype stops kernel/user address
   mixups; a position-tracking reader makes double fetches impossible by construction.
   Wrap `uaccess.rs` `copy_from_user`/`get_user`/`put_user`. `Untrusted<T>` is
   optional, still in review upstream.
3. **iov_iter-style file I/O** (`rust/kernel/iov.rs` `IovIterSource`/`IovIterDest`,
   miscdevice `read_iter`/`write_iter`). `FileOps::read(&self, &File, &mut [u8])`
   (`fs/file.rs`) forces a kernel bounce buffer on every read/write; `fs/io.rs`
   `Cursor` is half an iov_iter. Promote it into `FileOps` (read_iter/write_iter). A
   big interface change, cheap while hk has no users.
4. **Safe `LockedBy`** (`rust/kernel/sync/locked_by.rs`: `access(&guard)` checks the
   owner pointer). hk's `TableCell` (`task/mod.rs`) has `unsafe fn get`/`get_mut`
   relying on the caller holding TASKLIST; the RfL form makes it checked.
5. **The rest of RfL's lint set** (top-level `Makefile` `rust_common_flags`). Missing
   in hk: `ptr_as_ptr`, `ptr_cast_constness`, `as_ptr_cast_mut`, `ref_as_ptr`,
   `as_underscore`, `cast_lossless`, `ignored_unit_patterns`,
   `needless_bitwise_bool`, `no_mangle_with_rust_abi`, `rust_2018_idioms`,
   `float_arithmetic` (no floats in a kernel). Add to `Cargo.toml` `[lints]`. Cheap,
   all stable, catch silent truncation in ABI code.
6. **Condition wait that takes the guard** (`rust/kernel/sync/condvar.rs`
   `CondVar::wait(&mut Guard)`). The type system guarantees release and re-take around
   the sleep, and lockdep sees it. hk's `sync/waitqueue.rs` `wait_event(cond)` leaves
   lost-wakeup and sleep-under-spin to the caller. Add `wait_locked(&mut guard, cond)`
   for the `sync/mutex.rs` and `sync/rwsem.rs` guards.
7. **`ForeignOwnable`** (`rust/kernel/types.rs` `into_foreign`/`borrow`/
   `from_foreign`): one audited trait for the about 30 hand-written
   `Arc::into_raw`/`from_raw` round trips (`util/list.rs`, `io/epoll.rs`,
   `mm/page.rs` anon_vma tagged pointer).
8. **`# Invariants` / `// INVARIANT:` discipline** (`Documentation/rust/
   coding-guidelines.rst`, every type in `rust/kernel/sync/`). hk has 8 and 7. Every
   type whose unsafe code relies on an invariant documents it, every place that
   establishes it says so, and SAFETY comments cite it. Add the rule to
   `doc/UNSAFE.md`.
9. **`ScopeGuard`** (`rust/kernel/types.rs`, with `dismiss()`): unwind partial setup on
   error paths (mount in `fs/`, fork in `task/`, mmap in `mm/`) instead of manual
   undo. Small, stable.
10. **`Revocable`/`Devres`** (`rust/kernel/revocable.rs`, `devres.rs`): MMIO mappings
    and IRQs become safely unusable at unbind or unplug instead of dangling (`hw/`
    virtio, PCI). Only matters once hk does hot-unplug or driver unbind.
11. **`pin_init!`/`PinInit`** (`rust/kernel/init.rs`, `rust/pin-init/`). Poor fit: hk
    heap-allocates through `Arc`/`Box` and its intrusive lists link boxed items, so
    in-place pinning buys little; the ergonomics wait on unstable language work
    (https://lwn.net/Articles/1039334).

## Not for hk

`#[vtable]` (default trait methods already do it); bindings discipline,
`from_err_ptr`, `Opaque` (they serve the C interface, which hk lacks); the RCU `Guard`
(no RCU yet); `ARef`/`AlwaysRefCounted` (refcounts embedded in C structs; perhaps
later for page refcounts).

## Already in hk

errno `Result` (`util/error.rs`), `FromBytes`/`IntoBytes`/`pod!`, fallible
`KVec`/`KDeque`, lock classes by `#[track_caller]` and lockdep (`sync/lockdep.rs`),
`!Send` guards, `might_sleep`, typed IrqSpinlock / spin Mutex / sleeping Mutex,
intrusive list with adapters and `ArcList`, `XArray` (`mm/xarray.rs`), `Once`, const
asserts, `unsafe_op_in_unsafe_fn` and the safety-doc clippy lints, per-arch callback
traits, in-kernel selftests plus host tests (no in-kernel doctests).
