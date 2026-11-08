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
| 5 | Struct update `..Default::default()` in user/ | about -100 | low | med |
| 7 | One `util/bytes` LE/BE reader on `first_chunk` | -40 | low | low |
| 8 | `is_multiple_of` for `% a == 0` | 0 | 0 | low |
| 9 | xhci MMIO through `IoMem` | 0 | 0 | low |

Order: 2 goes per subsystem (M1); let-else is done and linted
(`manual_let_else`), so its error exits become `?`.

---

## 2. Syscall returns: `SysRet` trait + `?` (the big one)

- **Feature:** `?` / `From` conversion (old). The newer helpers used here are
  `Option::ok_or`, `is_none_or` (1.82) and let-else (1.65). The point is that 257+
  `sys_*` fns return a bare `i64`, so `?` can't be used in any of them.
- **Done:** net/ (its 18 `sys_*` return `KernelResult` and take `UserPtr`); fs/
  read/write, vectored I/O, splice/tee/vmsplice/sendfile/copy_file_range.
- **Evidence (counts):**
  - 81 x `let v = match f() { Ok(v) => v, Err(e) => return e.sysret(), };` (4 lines)
  - 22 x `if let Err(e) = f() { return e.sysret(); }` (3 lines)
  - 22 x tail `match r { Ok(n) => n as i64, Err(e) => e.sysret() }` (4 lines)
  - about 130 x `match o { Some(x)=>x, None => return KernelError::X.sysret() }`
    (72 of them are `BadFd`)
  - 85 x `if put_user(..).is_err() { return KernelError::BadAddress.sysret(); }`
  - 61 x `.map_err(|_| KernelError::BadAddress)`. There is no
    `impl From<UaccessError> for KernelError` (uaccess.rs:67).
  - 2 copies of a local `fn ret()` (fs/perm.rs:47, fs/stat.rs:73)
  - 39 ad-hoc `Result<_, i64>` errno-as-error fns (fs/io.rs:198 `one_seg`, :210 `pos_arg`)
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
- **Converted** (KernelResult + UserPtr): time/, signal/ (the signal
  core's send paths still return 0 or -errno as i32), ns/, keys/, tty/,
  seccomp/, bpf/, power.rs, arch rt_sigreturn.
- **Estimate:** about **-750** (let-else already took the `match` shapes).
- **Done:** mm/, ipc/, io/ epoll, inotify, fanotify, io_uring (sys_* return
  `KernelResult`, user pointers typed).
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

## 5. Struct update syntax in user/: `..Default::default()`

Kernel literals left as they are, on purpose: `const fn` ctors and
`ZERO_CONTEXT` (`Default` isn't const on stable); types with a `Drop`
(`NetNamespace`, `PollContext`) or a field with no meaningful default
(`XhciController`'s `PciDevice`, `UsbDevice`'s `UsbSpeed`, the timer
inners' `HrClock`, `Task`, `CloneConfig`); and structs holding more than
one lock, since `derive(Default)` gives every lock in them the derive
line as its lockdep class.

- **user/:** the remaining zero-field literals use `..Default::default()`,
  or `..Zeroable::zeroed()` (user/syscall/types.rs) for types that cannot
  derive `Default`.


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
