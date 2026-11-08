# Rust idioms for hk: what pays off in LOC

Idioms (stable Rust, edition 2024) that cut boilerplate in the kernel crate. The LOC
left is in **lint-driven boilerplate**; `Default` pays in a few big constructors
(`Default` is not `const` on stable, so `const fn new()` stays for statics). These
items belong to doc/ROADMAP.md phase S1.

## Ranking (LOC saved per unit of risk)

| # | Item | Lines saved | Risk | Prio |
|---|------|-------------|------|------|
| 5 | Struct update `..Default::default()` in user/ | about -100 | low | med |
| 7 | One `util/bytes` LE/BE reader on `first_chunk` | -40 | low | low |
| 8 | `is_multiple_of` for `% a == 0` | 0 | 0 | low |
| 9 | xhci MMIO through `IoMem` | 0 | 0 | low |

let-else is done and linted (`manual_let_else`).

---

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
