# TODO

Optional improvements found while verifying the 2026-11-03 atomics audit; none of these is a bug.

- **ShmAttach::drop pairs with IPC_RMID only through the hardware**: the
  last detach does a SeqCst `fetch_sub` and then an Acquire load of
  `deleted`. IPC_RMID does store, fence(SeqCst), load. Under the Rust
  memory model a Dekker pairing needs a SeqCst fence (or a SeqCst load)
  on the detach side as well. x86 `lock xadd` and arm64 `stlxr`+`ldar`
  give the ordering anyway; one fence makes it formal. ipc/shm.rs:223,
  ipc/shm.rs:513.
- **TCP release sets SHUTDOWN_MASK outside `cb`**: `release` sets it
  with a `fetch_or` before `step`, so it is harmless. Linux tcp_close
  writes sk_shutdown under lock_sock, and the LOCKING §5.4 `Sock`
  shutdown row says every write is under the protocol lock. Moving it
  into the `step` closure makes the row true. net/tcp/mod.rs:1077.
- **Boot-once statics** (audit #31): fpu `USE_XSAVE`/`XCR0`/
  `XSTATE_SIZE`/`MXCSR_MASK`, lapic `X2APIC`/`LAPIC_TICKS_PER_MS`,
  `SMAP_ON`, `PAN_ENABLED`, `INFO_PHYS`, `DTB_PHYS`, `DIRECT_END`, arm64
  `TIMER_FREQ`/`TICKS_PER_MS`, cache `CTR`. They are Relaxed atomics
  written before SMP, which is sound. Linux keeps them as
  `__ro_after_init` plain values. Convert them to `spin::Once` or
  initcall-set values, or at least give each a one-line
  `__ro_after_init` comment. `NR_CPU_IDS` is handled in phase L part 9.
