# TODO

Optional improvements; none of these is a bug.

- **Boot-once statics**: fpu `USE_XSAVE`/`XCR0`/
  `XSTATE_SIZE`, lapic `X2APIC`/`LAPIC_TICKS_PER_MS`,
  `SMAP_ON`, `PAN_ENABLED`, `INFO_PHYS`, `DTB_PHYS`, `DIRECT_END`, arm64
  `TIMER_FREQ`/`TICKS_PER_MS`, cache `CTR`. They are Relaxed atomics
  written before SMP, which is sound. Linux keeps them as
  `__ro_after_init` plain values. Convert them to `spin::Once` or
  initcall-set values, or at least give each a one-line
  `__ro_after_init` comment.
