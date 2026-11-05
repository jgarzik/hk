# Rust idioms for hk: what pays off in LOC

Scope: kernel crate at HEAD `1b13f4d` (160.8k LOC .rs, excluding user/ and tools/),
plus user/ (65.5k). Toolchain: `channel = "stable"`, which is rustc **1.99.0**, edition 2024.
Feature stability was checked by compiling probes on 1.99.

How it was measured: grep and Python counts over the tree. The big items were also
applied to a throwaway copy of HEAD (in the session scratchpad, not the repo) and
checked with `cargo check`/`clippy` on both arches. Numbers marked **measured** come
from those runs; numbers marked **est.** are pattern counts times lines saved.

The short answer: the codebase already uses most modern idioms (108 let-chains,
128 `is_some_and`, 113 `matches!`, `[const {..}; N]`, `div_ceil`, `&raw const`).
The real LOC is in **error plumbing at the syscall boundary** and in **lint-driven
boilerplate**. The gut call on `Default` is partly right: it pays in a few big
constructors and by deleting `impl Default` boilerplate. Wider use is limited
because `Default` is not `const` on stable, so `const fn new()` has to stay for statics.

## Ranking (LOC saved per unit of risk)

| # | Item | Lines saved | Risk | Prio |
|---|------|-------------|------|------|
| 1 | Drop `new_without_default` boilerplate | **-420 measured** | ~0 (compiler-checked) | high |
| 2 | `SysRet` trait + `From<UaccessError>`: `?` in `sys_*` | **-750 est.** | low-med (errno mapping) | high |
| 3 | let-else for `match {Some(x)=>x, None=>return}` | **-288 measured** | ~0 | high |
| 4 | `#[expect]` / delete dead code behind `allow(dead_code)` | **-200 est.** | ~0 | high |
| 5 | Struct update `..Default::default()` / `..zeroed()` | -300 (kernel) / -120 (user) est. | low | med |
| 6 | `bool::then` / `then_some` for `if c {Some(x)} else {None}` | -70 est. | low (eager eval) | med |
| 7 | One `util/bytes` LE/BE reader on `first_chunk` | -40 est. | low | low |
| 8 | `next_power_of_two` / `next_multiple_of` for hand-rolled ones | -25 est. | low (overflow) | low |
| 9 | Pointer-API lints (`&raw`, `.cast()`, `ptr::from_ref`) | 0 | 0 | med (policy) |

Suggested order: 1 and 4 are mechanical and can be one commit each. Do 2 per
subsystem, since it also removes most of item 3's `sysret` sites. Then do 3 on the
rest and turn its lint on.

---

## 1. Delete `impl Default { Self::new() }`: allow `clippy::new_without_default`

- **Feature:** clippy lint config (workspace `[lints.clippy]`). Not a new Rust feature.
- **Evidence:** 92 `impl Default for`. Of these, 73 are exactly
  `fn default() -> Self { Self::new() }` (examples: `sync/waitqueue.rs`, `mm/heap.rs`,
  `fs/dentry.rs`, `time/mod.rs`, `signal/mod.rs` x6). They exist only to quiet
  `new_without_default`. Most are singletons (`KernelAlloc`, `DentryCache`,
  `TimeKeeper`, `ConsoleRegistry`) that nothing ever builds through `Default`.
- **Measured:** removing all 73 compile-fails on only 3 types that really use
  `Default`: `FileLock` (fs/locks.rs:39), `TaskSignalState` (signal/mod.rs:815) and
  `SigAction` (8 sites in signal/mod.rs). Removing the other 70 and adding
  `new_without_default = "allow"` gives **59 files, +1/-420**. Clippy is clean on
  x86-64 and aarch64.
- **Before/after**
  ```rust
  impl Default for WaitQueue {        // -6 lines, x70
      fn default() -> Self {
          Self::new()
      }
  }
  ```
  becomes nothing, plus one line in Cargo.toml: `new_without_default = "allow"`.
- **Risk:** none at run time; a missing `Default` is a compile error. Generic code
  that needs `T: Default` will have to add it back type by type.

## 2. Syscall returns: `SysRet` trait + `?` (the big one)

- **Feature:** `?` / `From` conversion (old). The newer helpers used here are
  `Option::ok_or`, `is_none_or` (1.82) and let-else (1.65). The point is that 257+
  `sys_*` fns return a bare `i64`, so `?` can't be used in any of them.
- **Evidence (counts):**
  - 81 x `let v = match f() { Ok(v) => v, Err(e) => return e.sysret(), };` (4 lines)
  - 22 x `if let Err(e) = f() { return e.sysret(); }` (3 lines)
  - 22 x tail `match r { Ok(n) => n as i64, Err(e) => e.sysret() }` (4 lines)
  - about 130 x `match o { Some(x)=>x, None => return KernelError::X.sysret() }`
    (72 of them are `BadFd`)
  - 85 x `if put_user(..).is_err() { return KernelError::BadAddress.sysret(); }`
  - 61 x `.map_err(|_| KernelError::BadAddress)`. There is no
    `impl From<UaccessError> for KernelError` (uaccess.rs:67).
  - 3 copies of a local `fn ret()` (fs/perm.rs:52, fs/stat.rs:73, net/syscall.rs:23)
  - 39 ad-hoc `Result<_, i64>` errno-as-error fns (fs/io.rs:198 `one_seg`, :210 `pos_arg`)
  - 171 raw errno literals (`return -22; // EINVAL`, `-ESRCH`, `Err(-14)`), which
    break the STYLE.md rule "No raw errno numbers"
  - 739 `return KernelError::X.sysret();`. These become `return Err(KernelError::X)`
    (same LOC) and type-check against the error enum.
- **Design** (`util/error.rs`, next to `sysret`):
  ```rust
  /// A syscall's result as its return register (Linux: long, -errno on error)
  pub trait SysRet { fn ret(self) -> i64; }
  impl SysRet for i64 { #[inline] fn ret(self) -> i64 { self } }
  impl SysRet for KernelResult<()>    { #[inline] fn ret(self) -> i64 { self.map_or_else(KernelError::sysret, |()| 0) } }
  impl SysRet for KernelResult<i64>   { #[inline] fn ret(self) -> i64 { self.unwrap_or_else(KernelError::sysret) } }
  impl SysRet for KernelResult<usize> { /* n as i64; counts are capped at MAX_RW_COUNT */ }
  impl From<UaccessError> for KernelError { /* BadAddress|Overflow|Fault -> BadAddress, TooLong -> NameTooLong, Encoding -> InvalidArgument */ }
  ```
  Dispatch arms change from `sys_x(..) as u64` to `sys_x(..).ret() as u64`
  (arch/x86_64/syscall.rs:875+, arch/aarch64/syscall.rs). That is the same line
  count. Since `i64` also implements the trait, each `sys_*` can be converted on its
  own, so every commit is bisectable.
- **Before** (fs/nav.rs:28, 25 lines) and **after** (8 lines):
  ```rust
  pub fn sys_chdir(path_ptr: u64) -> i64 {
      let path_str = match crate::fs::namei::getname(path_ptr, false) {
          Ok(p) => p,
          Err(e) => return e.sysret(),
      };
      let start = crate::task::percpu::current_cwd();
      let path = match path_lookupat(start, &path_str, LookupFlags::opendir()) {
          Ok(p) => p,
          Err(e) => return e.sysret(),
      };
      if let Err(e) = may_chdir(&path.dentry) {
          return e.sysret();
      }
      ...
  ```
  ```rust
  pub fn sys_chdir(path_ptr: u64) -> KernelResult<()> {
      let name = getname(path_ptr, false)?;
      let path = path_lookupat(current_cwd(), &name, LookupFlags::opendir())?;
      may_chdir(&path.dentry)?;
      if let Some(fs) = current_fs() { fs.set_pwd(path); }
      Ok(())
  }
  ```
  time/time_syscall.rs:732-753 (timerfd_settime, 22 lines) becomes:
  ```rust
  let file = fget(fd)?;                                   // Linux fdget
  let timerfd = get_timerfd(&file).ok_or(KernelError::BadFd)?;
  let old = timerfd.settime(&new_spec, flags);
  if old_value != 0 { put_user::<Uaccess, ITimerSpec>(old_value, old)?; }
  ```
  This also shows two companion cleanups:
  - (a) Make `fs/io.rs:16 fget` public and use it in place of the 50 open-coded
    `get_task_fd(current_tid())` + `.lock().get(fd)` pairs (13+12+6 different spellings).
  - (b) Drop the `access_ok` pre-checks that come right before
    `put_user`/`copy_*_user`, since those already check: 14 sites, 3 lines each.
- **Estimate:** 81x3 + 22x2 + 22x3 + 130x3 + 85x2 + 15, about **-920**. Item 3 already
  takes about 130 of those let-else lines, so net about **-750** beyond item 3.
- **ABI/correctness notes:**
  - The bits returned to user space don't change. `Ok(v)` is still `v`; `Err(e)` is
    still `-errno`. Negative success values, such as `F_GETOWN` returning `-pgrp`,
    stay correct because they are `Ok(neg)`.
  - Don't use `?` where Linux returns partial progress: `rw_err`/`short(done)` paths
    (fs/io.rs:115, 150) stay explicit.
  - ERESTART* are already `KernelError` variants (util/error.rs:512-514), so the
    signal-restart path is unchanged.
  - The `From<UaccessError>` mapping is the one judgment call. Keep explicit
    `map_err` wherever Linux returns something other than EFAULT (xattr ERANGE,
    strncpy TooLong).
  - No locking impact: `?` drops guards in reverse order, exactly as the early
    `return` does now.

## 3. let-else (1.65) for `match`/`return|continue|break`

- **Evidence:** clippy `manual_let_else` (pedantic, off today) finds **249 sites on
  x86-64 + 4 aarch64-only**. Grep agrees: 180 `Some` and 75 `Ok(_)/Err(_)` matches
  that diverge.
- **Measured:** applying clippy's suggestions plus `cargo fmt` on a scratch copy gives
  **50 files, +530/-818 = -288**. It builds on both arches; one follow-up
  `unnecessary_cast` appears at task/percpu.rs:2408.
- **Before/after** (main.rs:698):
  ```rust
  let vfat_data = match arch::x86_64::multiboot2::find_module("vfat") {
      Some(data) => data,
      None => return,
  };
  // ->
  let Some(vfat_data) = arch::x86_64::multiboot2::find_module("vfat") else { return };
  ```
- **Lock-in:** add `manual_let_else = "warn"` to `[workspace.lints.clippy]`.
- **Risk:** none (same semantics). rustfmt puts long let-else on 3 lines, so the
  saving is 1 to 3 lines per site. Do item 2 first in syscall code, where `?` beats
  let-else.

## 4. `#[expect(dead_code)]` (1.81) and deleting what it hides

- **Evidence:** 147 `#[allow(dead_code)]` (142 plain + 5 inner), 0 `#[expect]`.
  STYLE.md says "No dead or speculative code".
- **Measured:** deleting every `allow(dead_code)` gives only **45 warnings on x86-64
  and 54 on aarch64; 44 are shared**. So about 90 of the allows are stale, and about
  44 items really are dead on both arches. Examples: `ADJ_OFFSET`, `TIME_INS..WAIT`
  (time/time_syscall.rs:954-977); `gfx_io/ior/iow` (gfx/ioctl.rs:19-32);
  `cmdline_console_count`/`get_cmdline_console`/`primary_cmdline_console`
  (cmdline.rs:230-251); `get_last_cluster`, `update_dir_entry_size` (fs/vfat.rs:718,
  1272); `BPF_ANY`, `BPF_F_LOCK` (bpf/map.rs); unused fields in io/inotify.rs:156,
  io/fanotify.rs:249-315, ipc/msg.rs:63-74.
- **Action:**
  - Remove the stale allows (about -90 lines).
  - Delete the dead items (about -100+ lines, est.).
  - Anything kept for ABI completeness gets
    `#[expect(dead_code, reason = "uapi constant")]`, so it warns once it becomes used.
  - Arch-only deadness gets `cfg_attr(target_arch=..., expect(..))`, or the item moves
    into `arch/`.
  - Do the same for the 4 `allow(unused_imports)` and 2 `allow(unused_variables)`.
- **Risk:** none. Check `cargo test` (host) as well, since tests can be the only user.

## 5. Struct update syntax: `..Default::default()` / `..FromBytes::zeroed()`

- **Feature:** struct update (old) plus `#[derive(Default)]` with enum `#[default]` (1.62).
- **Evidence:**
  - 882 `field: 0|false|None|[0; N]|Vec::new()` lines in kernel literals, 454 in user/.
  - A scan for literals with 3 or more such fields finds about **544 removable lines
    in kernel and 124 in user/**. Literals with 6 or more account for 298.
  - Top kernel sites: net/tcp/cb.rs:698 `TcpCb::new` (50 zero fields);
    task/percpu.rs:1237/1443/2109 `TaskInner` (22/19/15); task/misc.rs:80 `SysInfo`
    (14); hw/usb/xhci.rs:753 (13); fs/stat.rs:370 `Statx` (13); ns/net.rs:105;
    net/skb.rs:101.
- **Verified:** `#[derive(Default)]` on `TcpCb` fails only because `TcpState` has no
  default. Adding `#[default] Closed` (net/tcp/cb.rs:48) makes the 62-line ctor about 10:
  ```rust
  pub fn new(cfg: Cfg) -> Self {
      Self { cfg, snd_cap: 64 * 1024, rcv_cap: 64 * 1024, mss: MSS_DEFAULT,
             peer_mss: MSS_DEFAULT, adv_mss: MSS_DEFAULT, path_mss: 65495,
             rto: RTO_INIT, ..Default::default() }
  }
  ```
- **ABI structs (`pod!` types):** use `..FromBytes::zeroed()`, which is safe and
  already exists (util/pod.rs:27). `derive(Default)` fails on arrays longer than 32,
  and that is why `NewUtsname`, `SigInfoFields` and `Timex` have hand-written
  `Default`. Benefit beyond LOC: reserved and spare fields are zero by construction,
  which is the Linux ABI rule for `statx.__spare*` and `siginfo` padding.
  ```rust
  Statx { stx_mask, stx_blksize: 4096, stx_nlink: attr.nlink, ..., ..FromBytes::zeroed() }
  impl Default for SysInfo { fn default() -> Self { Self { mem_unit: 1, ..FromBytes::zeroed() } } } // 18 -> 3
  ```
- **user/:**
  - 56 `let mut x: T = unsafe { mem::zeroed() };` become `T::default()`
    (derive, arrays of 32 or less) or a safe `zeroed()` helper.
  - Attr structs in tests (bpf.rs `MapCreateAttr` x many, `CloneArgs`, `SigInfo`) use
    `..Default::default()`.
  - This removes `unsafe` from tests too.
- **Limits and risk:**
  - Not usable in `const` contexts: `Default` isn't const on stable, and
    default-field-values (`a: u32 = 0`) is **still unstable on 1.99 (verified
    E0658)**. So `ZERO_CONTEXT` (arch/x86_64/context.rs:339) and the 25
    all-default `const fn new()` stay.
  - Semantic risk: a new field silently defaults to 0. Fine for counters and state;
    review the `TaskInner` sites, where `exit_signal` and `leader` differ per path.
  - For `TaskInner`, a base ctor taking the non-default fields (`page_table`,
    `state`) is better than `Default`, because `ArchPageTable` has no meaningful
    default.

## 6. `bool::then` (1.50) / `then_some` (1.62)

- **Evidence:** 21 `if c {\n Some(x)\n} else {\n None\n}` (5 lines each); clippy
  `if_then_some_else_none` finds 17. Examples: dt/mod.rs:266/328/435/445,
  bpf/map.rs:310/358, net/core/neigh.rs:267, hw/virtio/pci.rs:465, hw/serial.rs:143.
- **After:** `(index < self.max_entries).then_some(index)`. That is -4 each, about **-70**.
- **Risk:** `then_some` evaluates its argument eagerly. hw/serial.rs:143
  (`self.inb(RBR)`) must use `.then(|| ..)` or it reads RBR even when no data is
  ready. That is a device side effect. Sites with `?` inside (fs/open.rs:162/169,
  net/packet/mod.rs:329) need `.then(..).transpose()?`; leave those alone. The
  dt/mod.rs sites are better done as item 7.

## 7. One LE/BE reader on `first_chunk` (1.77)

- **Evidence:** the same helper is reimplemented in 7 places:
  - block/part/mod.rs:83-93 (panicking `try_into().unwrap()`)
  - arch/x86_64/multiboot2.rs:57-63
  - arch/aarch64/pci_irq.rs:36
  - dt/mod.rs `read_be32/64`
  - kmsg.rs:101 `rd16`
  - hw/acpi/aml.rs:94
  - hw/virtio/ring.rs:357

  Plus 29 `try_into().unwrap()` on slices (fs/vfat.rs:1302-1429,
  arch/x86_64/fpu.rs:88/92, hw/usb/pci_quirks.rs:679).
- **After:**
  ```rust
  pub fn le32(b: &[u8], o: usize) -> Option<u32> {
      b.get(o..)?.first_chunk().map(|a| u32::from_le_bytes(*a))
  }
  ```
  About -40 lines, and the panicking `unwrap`s on disk or device data go away, as
  STYLE requires ("No panics on user input").
- **Risk:** low. Callers that index trusted kernel buffers may keep the infallible form.

## 8. Integer helpers: `next_power_of_two`, `next_multiple_of` (1.73), `is_multiple_of` (1.87)

- io/io_uring.rs:1394 `round_up_pow2` (12 lines of bit-smearing) becomes
  `n.max(1).next_power_of_two()`. Callers must bound `n`, since it panics in debug
  above 2^31.
- `align_up`/`round_up` (fs/cpio.rs:255, mm/heap.rs:103) and 14 open-coded
  `(x + a - 1) & !(a - 1)` become `x.next_multiple_of(a)`. It is a `const fn`, so
  `const` uses are fine. Use `checked_next_multiple_of` on user values.
- **Keep** mm/syscall.rs:358 `page_align`: it wraps on purpose (Linux PAGE_ALIGN),
  while `next_multiple_of` panics on overflow in debug builds.
- With a variable `a`, `next_multiple_of` compiles to a division. Keep the mask form
  on hot paths with a runtime power-of-two.
- `is_multiple_of`: 27 `% a == 0` / `& (a-1) == 0` sites. Readability only, 0 LOC.

## 9. Pointer APIs: enforce UNSAFE.md rule 7 with lints (0 LOC, policy)

- UNSAFE.md mandates `&raw` and the provenance APIs. Clippy, run on a scratch copy, shows:
  - `borrow_as_ptr` 57 (`&x as *const T`, should be `&raw const x`, 1.82)
  - `ptr_as_ptr` 114 (should be `.cast()`)
  - `ref_as_ptr` 55 (should be `ptr::from_ref`, 1.76)
  - `ptr_cast_constness` 34 (should be `cast_mut`/`cast_const`)
- One `addr_of!` is left at hw/usb/xhci.rs:688; rule 7 forbids it.
- The `phys_to_virt` chokepoints (arch/x86_64/paging.rs:60, arch/aarch64/paging.rs:68)
  do `(phys + PAGE_OFFSET) as *mut u8`. Rule 7 says they use
  `with_exposed_provenance_mut` (1.84). The semantics are the same, but the code and
  the doc disagree.
- hw/usb/xhci.rs:777-823 does MMIO through `(base + off) as *const u32` integers,
  not `IoMem` (rule 8 / rule 2 wrapper).
- **Action:** add `borrow_as_ptr`, `ptr_as_ptr`, `ref_as_ptr` and
  `ptr_cast_constness` as `warn` to `[workspace.lints.clippy]` after a
  machine-applicable `clippy --fix` pass. Medium priority: it hardens `unsafe`, it
  does not shrink code.

## Smaller, optional

- `#[diagnostic::on_unimplemented]` (1.78) on `FromBytes`/`IntoBytes`
  (util/pod.rs:23) gives readable `pod!` errors ("field X is not plain data"). 0 LOC.
- `cfg_select!` (stable on 1.99, verified): 34 adjacent `#[cfg(x86_64)]` /
  `#[cfg(aarch64)]` pairs. About 1 line saved each, but CLAUDE.md wants those moved
  into `arch/`, not prettified.

## Considered and rejected

- **default field values** (`a: u32 = 0`): unstable on 1.99 (verified).
- **const `Default` / const trait impls**: unstable. That is why the 25 all-default
  `const fn new()` used by statics can't become `derive(Default)` (only 7 non-const
  ones can, about -50 lines; fold those into item 1).
- **`core::cell::OnceCell`/`LazyCell` (1.70/1.80)** in place of `spin::Once`/`Lazy`
  (50 sites): they are `!Sync` so unusable in statics. `OnceLock`/`LazyLock` are std-only.
- **More let-chains (1.88)**: already 108 uses; clippy `collapsible_if` enforces them;
  about 30 nested candidates remain, most with statements between.
- **`mem::take`/`mem::replace`**: already used idiomatically (46 sites); no
  clone-then-clear patterns found.
- **enum `#[default]`**: already used (4); the only new need is `TcpState` (item 5).
- **`array::from_fn`, inline `const {}` array init, `div_ceil`, `is_some_and`/`is_none_or`**:
  already adopted (0 open-coded `div_ceil`, 0 `map_or(false, ..)`).
- **GATs, RPITIT/async-fn-in-trait, `impl Trait` in more positions**: no executor
  and no trait-object pain points; no LOC payoff.
- **`cast_lossless` / `u64::from` everywhere** (735 sites): STYLE prefers `from`,
  but it adds characters; not a LOC win.
- **`option_if_let_else` / `map_or_else`** (101 sites): usually less readable than `if let`.
- **`chunk_by`, `map_while`, `array_windows`, `repeat_n`**: no hand-written loops
  of those shapes found (4 `for i in 0..x.len()` total).
- **`Box::new_zeroed`**: no large `Box::new([0; N])` stack temporaries found.
- **`strict_*` / `unbounded_sh*` arithmetic**: niche; `checked_*`/`saturating_*`
  are already standard (315 sites).

## Noticed in passing (not idioms, but LOC or correctness)

- 1067 `// =====` banner lines and 479 `/// # Arguments` / `/// # Returns` sections
  on `sys_*` fns. These are the largest pure-comment LOC sinks; STYLE.md says
  comments should say why.
- `put_user`/`get_user` return EFAULT for **unaligned** user pointers
  (uaccess.rs:271). Linux x86-64 and arm64 accept unaligned user addresses. This may
  be an ABI deviation; worth a boot test.
- 171 raw errno literals (time/posix_timer.rs:775 `return -22`, `-ESRCH`
  sites): a STYLE violation that item 2 removes.
