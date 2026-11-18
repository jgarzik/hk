# `unsafe` policy

A kernel needs `unsafe`, but most of it can live in a few small, well-checked
wrappers. Everything else should then be safe Rust. This policy follows the
Rust-for-Linux safety standard (`Documentation/rust/coding-guidelines.rst`),
Asterinas's rule of confining `unsafe` to a small core, and the safe-mmio
model of device memory. The rules apply to the kernel crate (the repo root's .rs tree) and
`tools/`; `user/`
is a temporary exception (see the end).

`make unsafe-stats` prints the `unsafe` count and `// SAFETY:` coverage per
directory.

## Rules

### 1. Placement

`unsafe` belongs in wrapper and architecture code:
- `arch/*`;
- the mm frame and page-table core;
- MMIO, DMA, per-CPU and the uaccess core;
- `sync`, `list`, `rbtree`, `heap`;
- entry and context switch.

Subsystem code (fs, net, ipc, drivers above the register level) should need
none. If it does, the wrapper it should be calling is missing. This is a
review rule; no lint enforces it.

Exceptions: asm entry stubs, early boot before the allocator exists, the
`GlobalAlloc` impl, context switch, the panic path.

### 2. Wrapper first

If a pattern needs `unsafe` at two or more call sites, it gets one safe
abstraction instead, and the callers stay safe. The usual wrapper shapes are:

| Wrapper | Kind |
|---|---|
| inode and page lock guards | RAII guard |
| socket lock `SockLock` / `SockGuard` / `BhGuard` (`net/core/sock_lock.rs`, Linux socket_lock_t) | RAII guards over owner bit + spin lock |
| frame borrows | typed handle |
| a task's saved user FP/SIMD state `ThreadStruct` and the per-CPU binding `PerCpu::fpsimd_last_state` (`arch/aarch64/fpsimd.rs`, Linux thread.uw.fpsimd_state, fpsimd_last_state.st; `with_current_state`, `thread_switch`, `dup_thread` unsafe: the running task's own state, the outgoing task current, a task not running) | cell accessed only by its task, flushed state checked; the binding followed only while the running task's registers are live, when it names that task's state (set by `bind_task_to_cpu`), else only compared |
| `Pod` byte views | marker trait |
| `IoMem` registers | checked volatile |
| `DmaBox` (`hw/dma.rs`, Rust-for-Linux CoherentAllocation) | owned device memory, freed on drop |
| page-table `PgTables` / `Pte` / `PteTable` / `Pmd` / `Dir`, `PgPrune` (`mm/pgtable.rs`) | typed handle borrowing the lock |
| vmalloc-area range `VmArea` (`mm/vmalloc.rs`, Linux vm_struct) | ownership token |
| kernel stack `VmStack`, a task's `StackSlot` (`mm/vmstack.rs`) | ownership token |
| red-black tree `RbTree` / `RbTreeNodeReservation` (`util/rbtree.rs`, Linux rb_root) | owning container of preallocated nodes |
| intrusive red-black tree `RbRoot` / `RbNode` / `RbCursorMut` over a `ListPtr` (`util/rbtree.rs`, Linux rb_node embedded, `skb->rbnode`) | owning intrusive container, membership checked |
| RCU callback head `RcuHead` / `HasRcuHead`, `call_rcu` (`sync/rcu.rs`, Linux rcu_head) | embedded queue node, claimed once |
| slab RCU head `Page::slab_rcu_head` / `slab_rcu_end` (`mm/page.rs`, Linux struct slab's rcu_head in a union with slab_list, freelist and counters) | `RcuHead` over struct page fields dead once the slab is off its lists (layout const-asserted; a head has no uninitialized byte), zeroed back by its callback |
| RCU pointers `RcuArc`, `RcuLockedArc` (nullable, writers proven by a `UniqueOwner`), `RcuOnceArc` (nullable, set and taken by atomic exchange), `RcuPtr` (no ownership, unsafe read) (`sync/rcu.rs`, Linux `__rcu`) | published pointer, old version released after a grace period |
| dentry reference `DentryRef` (`fs/dentry.rs`, Linux dget/dput on d_lockref), mount reference `MountRef` (`fs/mntput.rs`, Linux mntget/mntput on mnt_pcp) | counted pointer, last put deferred (RCU free, queued teardown) |
| repeated deferred put `RcuPuts` / `HasRcuPuts`, `put_rcu` (`sync/rcu.rs`) | embedded counted queue node |
| RCU-readable dentry name `DNameSlot` over `ExternalName` (`fs/name.rs`, Linux d_name over d_shortname / external_name) | atomics a reader may see torn, never out of bounds; a replaced long block released after a grace period (`put_rcu`) |
| buffer head reference `BhRef` (`fs/pageio/buffer.rs`, Linux get_bh/brelse); a page's buffer ring reached under its page lock or `i_private_lock` (`folio_buffers`, unsafe: the caller holds one) | counted pointer: a buffer is freed only by `try_to_free_buffers`, under both locks, with no buffer of its ring referenced, dirty or locked |
| superblock writeback error through a `Weak` (`sb_wb_err_set`, `fs/superblock.rs`, Linux errseq_set(&i_sb->s_wb_err)); `filemap::mapping_set_error_raw` (unsafe: the inode has not dropped its `Weak`, held by a reference or a locked buffer of one of its pages); a metadata list's mapping error target (`MappingMetadataBhs::new`, `fs/pageio/buffer.rs`, Linux mmb->mapping; unsafe: the mapping's memory outlives the list's last buffer by a grace period) | the `Weak` keeps the allocation; `s_wb_err` and a mapping's `wb_err` have no drop glue, so they stay valid atomics after the value drops; no reference taken in hardirq |
| inode reference `InodeRef` (`fs/inode.rs`, Linux ihold/iput on i_count); RCU-borrowed inode `Dentry::d_inode_rcu`, reference from it `Inode::igrab` (`fs/dentry.rs`, `fs/inode.rs`, Linux READ_ONCE(d_inode), igrab) | counted pointer, last put tears down at once (iput_final -> evict); borrow for a guard's life, memory freed a grace period after the teardown (`i_callback`) |
| inode list `InodeList` (`fs/inode.rs`, Linux s_inodes, i_hash chains, b_dirty/b_io; `new` unsafe: eviction unlinks under the list's lock; `remove` and `iter_after` unsafe: membership) | intrusive list owning nothing, a linked entry live under the lock, a reference only by `Inode::igrab` |
| RCU nulls hash bucket `NullsHead` / `NullsGuard` / `NullsRef` / `NullsUnlinked` (`util/hlist_nulls.rs`, Linux hlist_nulls) | owning intrusive container, lockless readers, grace-period-held references |
| hash bucket `BlHead` / `BlGuard` (`util/hlist_bl.rs`, Linux hlist_bl), owner-marked list `OwnedList`, owning list `PtrList` over a `ListPtr` (`Box`, `Arc` or `&'static`: `BoxList`, `ArcList`) (`util/list.rs`), RCU list `RcuList` with `RcuRef` and `RcuUnlinked` (`util/rculist.rs`, Linux rculist.h; `remove` and `iter_locked` unsafe: membership, and every remover excluded) | owning intrusive containers, membership checked |
| RCU hash chain `RcuHList` / `HNode` / `RcuHRef` (`util/rcuhlist.rs`, Linux hlist_*_rcu), writers proven by a `UniqueOwner` | owning intrusive chain, membership checked, release after a grace period |
| non-owning RCU hash chain `RcuHListBare` (`util/rcuhlist.rs`, Linux pid->tasks[type] bare hlist nodes), writers proven by a `UniqueOwner`; `add_head` unsafe: the entry stays allocated while linked and a grace period after (a task: unlinked at release, freed a grace period after leaving the task list, as `RcuPtr`'s targets) | intrusive chain owning nothing, readers safe under RCU |
| RCU slot array `Slots` / `SlotsOwner` over an `RcuRef`, published by `RcuSlots` (unsafe publish: one place, replaced in the lock hold that retires it) from an opaque `SlotsRef` (`util/rcuslots.rs`, Linux fdtable->fd and file_ref_get), file reference `FileRef` (`fs/file.rs`, Linux f_ref) | owning array, one writer handle, reference taken unless the last went, on type-stable memory (SLAB_TYPESAFE_BY_RCU) and rechecked; grown arrays keep stale copies and own nothing, read only by readers that reached them under their guard |
| data under a unique lock and one instance of a lock of many, `LockedByBoth` with `InstanceLock` / `InstanceGuard` (`sync/locked_by.rs`, Linux signal->thread_head under tasklist_lock and siglock; RfL `LockedBy` owner check) | cell checked against its owner instance at run time |
| data under one instance of a lock of many, `InstanceCell` / `InstanceRef` / `InstanceRefMut` (`sync/locked_by.rs`, Linux task->blocked/pending under the siglock of the task's table; RfL `LockedBy` owner check) | cell checked against its owner instance, borrows counted (`RefCell` rule) at run time |

Make each wrapper `#[inline]`: it must compile to the same code as the
open-coded `unsafe` it replaces.

### 3. Documentation

- **`// SAFETY:`** goes directly above every `unsafe {}` block and every
  `unsafe impl`. It says why each precondition holds, citing the callee's
  `# Safety` items or the type's invariants. "Trust me" and "safe because
  we're careful" are not reasons.
- **`/// # Safety`** goes on every `unsafe fn` and `unsafe trait`, private
  ones included. It is the caller's (or implementor's) contract, written as
  a bullet list of conditions.
- **`/// # Invariants`** goes on a type whose `unsafe` code relies on
  properties of its fields. Code that establishes or changes such a field
  says why the invariant still holds, with `// INVARIANT:`. A `SAFETY`
  comment that depends on one says so ("type invariant"), so a later
  change to the invariant finds every block that relied on it
  (Rust-for-Linux coding guidelines). Examples: `util::list::List`,
  `sync::LockedBy`, `sync::Mutex`, `WaitEntry`.
- **One unsafe operation per block**, so each comment covers exactly one
  obligation. Exception: a dense arch or asm sequence may share one block
  if its comment justifies each operation.
- A safe fn has no `# Safety` section. If it has preconditions that
  matter for memory safety, it should be `unsafe fn`.

### 4. `unsafe fn`

A fn is `unsafe` only when the caller must uphold a real precondition that
the fn cannot check. Otherwise the fn checks the condition itself:
- use `assert!` when the check is cheap;
- on a measured hot path, use `debug_assert!` with a comment saying why,
  and make the fn `unsafe`.

A safe fn that leads to UB for some argument is a bug, even if no caller
passes that argument today.

### 5. `Send` and `Sync`

Prefer the compiler's auto traits: make the fields the right types rather
than impl the traits by hand. Each `unsafe impl Send/Sync` names the lock
or invariant that makes it true.

A guard that hands out `&T` is `Sync` only when `T: Sync`. A guard that
carries CPU-local state (IRQ flags, a preempt count) is `!Send`.

### 6. No `static mut`

Use atomics, `Once`/`spin::Once`, or a lock. For memory that hardware
or code outside Rust's view also uses (boot page tables, IST stacks, AP
boot data), use `sync::RacyCell`: it hands out only a raw pointer, so
each access is an `unsafe` block with its own reason. Linker symbols are
declared in `unsafe extern` blocks and only their addresses are used
(`&raw const`). `make unsafe-stats` counts any `static mut` (0).

### 7. Pointers and provenance

- `&raw const`/`&raw mut`, not `addr_of!`.
- Use pointer arithmetic (`add`, `byte_add`, `map_addr`), not a round trip
  through an integer.
- Integer-to-pointer conversion happens only at the direct-map and ioremap
  chokepoints (`phys_to_virt`, `ioremap`), which use
  `with_exposed_provenance`.
- Never cast `&T` to `*mut T` and write through the result. Mutation
  through a shared reference needs `UnsafeCell` (an atomic, a lock, a cell).

### 8. Device memory

MMIO and memory the device may write go through typed wrappers only.
Never create a Rust `&`/`&mut` into it: the compiler may assume such memory
does not change, and it may read or write it at any time. Use
volatile access through raw pointers and the needed barriers.

Exception: the early console, before the wrappers are up.

### 9. Guards are leak-safe

`mem::forget` is safe, so soundness must not depend on a `Drop` running. A
forgotten lock guard may deadlock (acceptable). A forgotten guard that lets
memory be freed or reused while still borrowed or mapped is unsound: such a
resource must be owned by the guard. Guards are `#[must_use]`.

### 10. `asm!`

Give no `options(...)` without a comment that justifies each one.
- `nomem` is wrong for anything that orders memory or changes how it is
  reached: barriers, IRQ enable or disable, CR/TTBR/MSR/sysreg writes that
  affect memory, TLB and cache maintenance, SMAP/PAN toggles.
- `nostack` is wrong if the asm pushes or calls.
- `preserves_flags` is wrong if it changes the flags.
- `pure` is never right for reads of counters or device state.

### 11. Lints

The workspace `[lints]` table in `Cargo.toml` and `clippy.toml`
(`check-private-items`) enforce these rules. The gate runs clippy with
`-D warnings`, so every lint listed there, warn-level included, blocks
a commit. Do not silence an `unsafe` lint locally without a comment
saying why.

`undocumented_unsafe_blocks` is denied crate-wide. Files written before
this policy carry `#![expect(clippy::undocumented_unsafe_blocks)] //
TODO(unsafe)` until their blocks are documented or wrapped. Remove the
line when the file is clean, and never add it to a new file
(`git grep -l 'TODO(unsafe)' -- '*.rs' ':!user'` lists what is left).

### 12. Deferred release (RCU)

An object that RCU readers reach without a reference (an `RcuList` or
`RcuHList` entry, an `RcuArc`/`RcuLockedArc` version, a task reached
through `RcuPtr`) is released only after a grace
period: the container's reference goes through `RcuUnlinked`,
`RcuHRef` or `RcuRetired` (`defer`: `call_rcu`/`kfree_rcu`/`put_rcu`). That
reference may be the last, so the object's `Drop`, and every drop it
causes, can run in `rcuc/N` with preemption off: it must not sleep
(no sleeping lock, no `synchronize`) and allocates only with a GFP
named. A type kept in such a container says so where it is defined
(Linux SOCK_RCU_FREE sockets: `__sk_destruct` runs from the RCU
callback).

An inode (`fs/inode.rs` `InodeRef`, Linux iput / destroy_inode /
i_callback) is the other shape: RCU readers reach it with no reference
(a dentry's `d_inode`), its teardown runs synchronously at the last
put, and only the memory is deferred. Its references are counted in
`i_count` through `InodeRef` (a raw pointer, as `DentryRef` counts
`d_count`): a clone is ihold, `Inode::igrab` takes one from a borrowed
inode unless the count is zero and I_FREEING / I_WILL_FREE is set
(both only at zero, under `i_lock`), and the drop is iput, whose last
put evicts and tears down through the raw pointer (`iput_final` ->
`evict` -> `destroy_inode`), then queues `i_callback`, which frees the
`Box` block `Inode::alloc` made. No `&mut Inode` is ever formed.
`Inode` has no `Drop` and no drop glue; each field with drop glue is
`ManuallyDrop`, dropped through its raw-pointer place by
`destroy_inode` (or by `i_callback`, for what an RCU reader may read:
`i_link`, `i_private_rcu`), so a reader, which reads only atomics,
`ino`, `i_op` and other fields with no drop glue, never sees a byte it
reads written before the free. Compile-time checks name every field
(an exhaustive pattern, no `..`): `no_glue` asserts `needs_drop` false
on each field's own type and on `Inode`, and `Inode::init_at`, which
builds the inode in place in its uninitialized block, writes each field
exactly once, so a field added fails the build until both are updated.
`SignalStruct::alloc` (signal/mod.rs) builds the signal struct in place
the same way (`try_arc_uninit`, an `init_at` writing each field once
under an exhaustive pattern, then `assume_init`), so its large cells
are never copied through the stack.

A file (`fs/file.rs`, Linux's SLAB_TYPESAFE_BY_RCU `struct file`) is
reached by descriptor-table readers (`util/rcuslots.rs`) and epoll
through its address alone, who only try for a count. Every file lives
in a `FileObj` of `FILP_CACHE` (`mm/slab.rs`, a type-stable cache): the
file, then `f_count`, an atomic the cache's constructor makes when the
slab is made, which nothing writes afterwards but atomically (the
cache's free-list link is in the file part, `FileObj::FREEPTR`) and
which stays a count until the slab goes back to the page allocator, a
grace period after it emptied. A count is taken only from a nonzero
one (`inc_not_zero`), which `File::alloc` sets last, Release, after
writing the file; the release (`release`: `drop_in_place` of the file,
then `file_free` to the cache) borrows the file part alone, and leaves
the count 0. So a reader's compare-exchange never races a non-atomic
write, a count it wins names a whole live file, maybe a newer one in the
same memory, which `Slots::get` rejects by reloading the slot (Linux
__get_file_rcu), and a reader that loaded the address under an RCU guard
(or under a lock that keeps the file from being freed: epoll's `mtx`)
cannot reach memory given back to the page allocator.

## Review checklist (for each new `unsafe`)

1. Could an existing wrapper do it? Should a new one exist (rule 2)?
2. Does every `# Safety` precondition of the callee appear in the
   `SAFETY:` comment, with its reason?
3. Aliasing: can an IRQ, a preemption plus migration, or another CPU reach
   the same memory while this `&`/`&mut` lives?
4. Lifetimes: can the memory be freed, unmapped or handed to a device while
   it is borrowed?
5. Leaks: what if the guard is forgotten?
6. Provenance: where did the pointer come from?
7. Locks: does it change a lock rule (`doc/LOCKING.md`)?

## Exceptions in force

- **`user/`** (the boot tester and its syscall layer) does not follow this
  policy yet. Its syscall wrappers are safe fns that take raw pointers.
  They will become slice- and reference-typed wrappers over one
  `unsafe fn syscall6` per arch, in a later chunk (see `BUGS.md`).
