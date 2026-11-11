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
| frame borrows | typed handle |
| `Pod` byte views | marker trait |
| `IoMem` registers | checked volatile |
| `DmaBox` | owned device memory |
| page-table `PgTables` / `Pte` / `PteTable` / `Pmd` / `Dir`, `PgPrune` (`mm/pgtable.rs`) | typed handle borrowing the lock |
| vmalloc-area range `VmArea` (`mm/vmalloc.rs`, Linux vm_struct) | ownership token |
| kernel stack `VmStack`, a task's `StackSlot` (`mm/vmstack.rs`) | ownership token |
| red-black tree `RbTree` / `RbTreeNodeReservation` (`util/rbtree.rs`, Linux rb_root) | owning container of preallocated nodes |
| intrusive red-black tree `RbRoot` / `RbNode` / `RbCursorMut` over a `ListPtr` (`util/rbtree.rs`, Linux rb_node embedded, `skb->rbnode`) | owning intrusive container, membership checked |
| RCU callback head `RcuHead` / `HasRcuHead`, `call_rcu` (`sync/rcu.rs`, Linux rcu_head) | embedded queue node, claimed once |
| hash bucket `BlHead` / `BlGuard` (`util/hlist_bl.rs`, Linux hlist_bl), owner-marked list `OwnedList`, owning list `PtrList` over a `ListPtr` (`Box` or `Arc`: `BoxList`, `ArcList`) (`util/list.rs`) | owning intrusive containers, membership checked |

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
