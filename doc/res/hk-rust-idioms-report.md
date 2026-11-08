# Rust idioms for hk: what pays off in LOC

Idioms (stable Rust, edition 2024) that cut boilerplate in the kernel crate. The LOC
is in **error plumbing at the syscall boundary** and in **lint-driven boilerplate**;
`Default` pays in a few big constructors
(`Default` is not `const` on stable, so `const fn new()` stays for statics). Item 2
belongs to doc/ROADMAP.md phase M1, the rest to S1.

## Ranking (LOC saved per unit of risk)

| # | Item | Lines saved | Risk | Prio |
|---|------|-------------|------|------|
| 2 | `SysRet` trait + `From<UaccessError>`: `?` in `sys_*` | about -750 | low-med (errno mapping) | high |
| 3 | let-else for `match {Some(x)=>x, None=>return}` | about -288 | ~0 | high |
| 4 | Delete the dead code behind `expect(dead_code)` | about -100 | ~0 | high |
| 5 | Struct update `..Default::default()` / `..zeroed()` | -300 (kernel) / -120 (user) | low | med |
| 7 | One `util/bytes` LE/BE reader on `first_chunk` | -40 | low | low |
| 8 | `is_multiple_of` for `% a == 0` | 0 | 0 | low |
| 9 | xhci MMIO through `IoMem` | 0 | 0 | low |

Order: 4 is mechanical, one commit. 2 goes per subsystem (M1) and also
removes most of item 3's `sysret` sites; then 3 on the rest, with its lint on.

---

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
  - 3 copies of a local `fn ret()` (fs/perm.rs:47, fs/stat.rs:73, net/syscall.rs:23)
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
- **Action:** apply clippy's suggestions plus `cargo fmt` (about -288), then turn
  the lint on.
- **Before/after** (main.rs:626):
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

## 4. Deleting what `expect(dead_code)` hides

- **Evidence:** 56 `#[expect(dead_code)]` remain (the stale allows are gone; the
  lint now proves each one hides something). STYLE.md says "No dead or speculative
  code". Examples: `ADJ_OFFSET`, `TIME_INS..WAIT` (time/time_syscall.rs);
  `gfx_io/ior/iow` (gfx/ioctl.rs); `cmdline_console_count`/`get_cmdline_console`/
  `primary_cmdline_console` (cmdline.rs); `get_last_cluster`,
  `update_dir_entry_size` (fs/vfat.rs); unused fields in io/inotify.rs,
  io/fanotify.rs, ipc/msg.rs.
- **Action:** delete the dead items (about -100 lines); what stays for ABI
  completeness gets `reason = "uapi constant"`.
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
- `#[derive(Default)]` on `TcpCb` fails only because `TcpState` has no default. Adding `#[default] Closed` (net/tcp/cb.rs:48) makes the 62-line ctor about 10:
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
    default-field-values (`a: u32 = 0`) is unstable. So `ZERO_CONTEXT` (arch/x86_64/context.rs:339) and the 25
    all-default `const fn new()` stay.
  - Semantic risk: a new field silently defaults to 0. Fine for counters and state;
    review the `TaskInner` sites, where `exit_signal` and `leader` differ per path.
  - For `TaskInner`, a base ctor taking the non-default fields (`page_table`,
    `state`) is better than `Default`, because `ArchPageTable` has no meaningful
    default.

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

## 8. `is_multiple_of` (1.87)

27 `% a == 0` / `& (a-1) == 0` sites. Readability only, 0 LOC. Hand-rolled
round-ups are gone, except `mm/heap.rs round_up` (run-time power-of-two
alignment on the allocation path: a mask, not a division), the wrapping
`mm/syscall.rs page_align` (Linux PAGE_ALIGN) and `mm/huge_page.rs` (mask
helpers next to their align-down twins).

## 9. xhci MMIO (rule 8)

hw/usb/xhci.rs does MMIO through `(base + off) as *const u32` integers, not
`IoMem` (rule 8 / rule 2 wrapper).

## Smaller, optional

- `#[diagnostic::on_unimplemented]` (1.78) on `FromBytes`/`IntoBytes`
  (util/pod.rs:23) gives readable `pod!` errors ("field X is not plain data"). 0 LOC.
- `cfg_select!` (stable): about 34 adjacent `#[cfg(x86_64)]` /
  `#[cfg(aarch64)]` pairs. About 1 line saved each, but CLAUDE.md wants those moved
  into `arch/`, not prettified.

## Comment LOC (not idioms; ROADMAP S2)

- About a thousand `// =====` banner lines and hundreds of `/// # Arguments` / `/// # Returns` sections
  on `sys_*` fns. These are the largest pure-comment LOC sinks; STYLE.md says
  comments should say why.
