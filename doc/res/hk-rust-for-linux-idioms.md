# hk: Rust-for-Linux idioms worth adopting

What the Rust-for-Linux (RfL) kernel crate (`~/tmp/repo/linux/rust/kernel/`,
`Documentation/rust/`) and its public discussion do that hk does not, ranked by value
to hk: stable Rust only, no C-bindings layer, Linux ABI binding, locking first. For
LOC-saving idioms (including `#[expect]` over `#[allow]`) see
`hk-rust-idioms-report.md`.

## Ranking

1. **`ForeignOwnable`** (`rust/kernel/types.rs` `into_foreign`/`borrow`/
   `from_foreign`): one audited trait for the remaining hand-written
   `Arc::into_raw`/`from_raw` round trips (`util/list.rs` ArcList, `mm/page.rs`
   anon_vma tag, task refs). Few are left now that IRQ and cross-CPU call
   contexts are typed; worth it once a new user (an XArray of `Arc`s) appears.
2. **`# Invariants` / `// INVARIANT:` adoption.** The rule is in
   `doc/UNSAFE.md` and on the core types (`util/list.rs`, `sync/`); extend it
   to every type whose `unsafe` relies on its fields (mm/, hw/ DMA rings).
3. **`Revocable`/`Devres`** (`rust/kernel/revocable.rs`, `devres.rs`): MMIO mappings
   and IRQs become safely unusable at unbind or unplug instead of dangling (`hw/`
   virtio, PCI). Only matters once hk does hot-unplug or driver unbind.
4. **`pin_init!`/`PinInit`** (`rust/kernel/init.rs`, `rust/pin-init/`). Poor fit: hk
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
`KVec`/`KDeque`, fallible `Box`/`Arc` (`util/kalloc.rs`, with `Box::new`/`Arc::new`
banned by clippy), `UserPtr`/`UserSlice` (`uaccess.rs`; every `sys_*` takes its user
pointers typed and returns `KernelResult`), iov_iter file I/O
(`fs/iov_iter.rs`, `FileOps::read_iter`/`write_iter`), `LockedBy`
(`sync/locked_by.rs`), the guard-taking wait (`WaitQueue::
wait_event_interruptible_locked`), `ScopeGuard` (`util/scope.rs`), typed IRQ
handler state (`irq::IrqHandler`), RfL's cast and pointer lints and `#[expect]`, lock classes by `#[track_caller]` and lockdep (`sync/lockdep.rs`),
`!Send` guards, `might_sleep`, typed IrqSpinlock / spin Mutex / sleeping Mutex,
intrusive list with adapters and `ArcList`, `XArray` (`mm/xarray.rs`), `Once`, const
asserts, `unsafe_op_in_unsafe_fn` and the safety-doc clippy lints, per-arch callback
traits, in-kernel selftests plus host tests (no in-kernel doctests).

Page tables (`mm/pgtable.rs`, RfL `MmapReadGuard::vma_lookup`): a `PgTables<'a>`
borrows the mmap_lock guard (or a held rmap chain), and its typestate handles
(`Pte`, `Pmd`, `Dir`, `#[must_use]` `PteTable` holding the PTE lock) cannot outlive
it; tables leave the tree only through `PgPrune`, made from `&mut MmStruct`; the
arch walkers are `unsafe fn`s reached only from there. vmalloc pages: `VmArea`.
