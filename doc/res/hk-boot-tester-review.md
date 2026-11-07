# hk: boot_tester review (accretion, scaling, target design)

A top-down look at `user/boot_tester` (measured at e801500 from the tree and
`target/qemu/` logs): does it show accretion disease, does "test everything on
every boot" scale, and what do other kernels do. Ranked, with a migration plan.

## Diagnosis: yes, accretion without a harness

The suite works (about 1420 checks on x86, 1402 on arm64, 1384 on Linux, 0
FAIL), but it is 156 flat files and 66k lines of copies of one print-and-grep
pattern.

1. **No assertion API.** `tests/harness.rs` has the shared verdict printers
   (`verdict`, `verdict_detail`, `report_r`/`check`, `report_step`,
   `report_code`, `pass`, `fail_why`, `T`), but no assertions, no per-check
   numbering, no plan. 15 files still define their own `fn report(`, 6
   `fn verdict(`, 6 `fn check(` (bodies that differ), 5 a sleep helper, 6 a
   reap helper, 22 a thread-stack struct.
   1399 `:FAIL` literals, 480 of them through `fail_num`, the rest hand-printed;
   564 verdicts pass through `pass()`, 113 `:OK` literals remain. Near-identical tests
   (`process.rs` `test_getuid`/`geteuid`/`getgid`/`getegid`).
2. **Pass/fail by substring.** `helpers.rs` counts a failure when printed bytes
   contain "FAIL"; the Makefile greps `FAIL|KERNEL PANIC`. No structured result, no
   per-test duration, no "never ran" versus "passed"; no test name may contain
   "FAIL".
3. **Grown by bug and date, not subsystem.** TCP/socket tests in 10 files
   (`tcp`, `tcp_conn`, `tcp_xfer`, `tcp_close`, `tcp_opt`, `tcp_mem`, `sk`,
   `sockets`, `sockcore`, `sockopts`); mm in 11; `*_race` files beside their
   parents; one-check files (`errno_pass.rs`, 49 lines) next to 2500-line files
   (`mmap.rs`).
4. **Growth.** 48 files / 20k LOC (2025-12-29) to 156 / 66k (2026-11-05); 416 of
   466 commits and 108 new files since 2026-10-01; `mod.rs` touched in 108 commits.
5. **Isolation is the exception.** 32 of 152 suites run under `isolated()`; 120 run
   in pid 1, whose panic handler exits init, so one fault loses every later result.
   Tests assume pid 1 (`test_getpid`). No per-test timeout: a hang burns the 600 s
   boot timeout without naming the test.
6. **Hygiene.** 91 `static mut` in 41 files; 427 `unsafe` blocks, 100 `SAFETY:`
   comments; 336 hard-coded `/tmp` paths and no per-test scratch directory; an
   implicit, load-bearing order in `mod.rs`.
7. **Weak or timing-based checks.** About 118 verdicts only test "returned >= 0";
   216 sleep call sites (about 72 s of literal sleeps) and 49 `sched_yield` spins.
   The known flakes (BUSYBOX_NC_LO, NICE_ADJACENT, SWAPOUT_PAGEOUT) are all timing or
   ratio tests.

Keep: the dual run on hk and Linux (`check-linux*`), `host_mode()`/`skip()` with
reasons, unique test names.

## Does "everything on every boot" scale?

Not for long; diagnosis and iteration cost more than wall time.

- x86 KVM `check` 77 s, arm64 TCG 160 s; LOC tripled in five weeks, so arm64 heads
  for 5 to 8 minutes and the 600 s cap.
- One boot runs about 1400 verdicts in order; guest CPUs idle; no way to run one
  suite, so each edit costs a full boot.
- One hang: 600 s and no attribution. One panic in a non-isolated suite: everything
  after it lost.
- Any boot_tester change invalidates the `check-linux` cache (uncached arm64 Linux
  run about 150 s).

## Target design (ranked)

1. **In-tree harness after LTP `tst_test`, KTAP output.** A static table of
   `Test { name, suite, tier, flags: NEEDS_INIT | NEEDS_NET | DESTRUCTIVE,
   timeout_ms, f }`; `expect_eq!`/`expect_errno!` macros printing `ok N name` /
   `not ok N name # got X`; every test forked by default (in init only with
   NEEDS_INIT), a per-test `alarm` watchdog, `# duration`, a per-test scratch
   directory. Pass/fail from structure, not a substring.
2. **Selection** by init arguments or kernel cmdline (`bt.suite=net,mm`,
   `bt.tier=smoke`), as kselftest `TARGETS=`; `make check SUITE=net`, and the Linux
   runner passes the same arguments.
3. **Tiers** (xfstests `quick`/`auto`): smoke (under 20 s, iteration), full (the
   gate, every commit), slow (OOM, swapout, ratio and timing tests, stress) in
   `check-stress`.
4. **Shards:** the full tier split across 2 to 4 parallel QEMU boots per arch,
   merged from KTAP (`tools/gate.sh` already runs boots in parallel).
5. **Table-driven errno tests** (gVisor `test/syscalls`, LTP `*_errnos`): rows of
   `(name, call, expected errno)` in place of most of the FAIL literals.
6. **Keep the dual run**; with KTAP, `check-linux` can diff per-test results.
7. **Complements, not more hand tests:** coverage (QEMU or kcov) to find dead and
   duplicate tests; later a syzkaller target for hk.

## Migration (each step gate-green, `check-linux` parity kept)

1. `harness.rs`: KTAP printer, `expect_*` macros, fork + alarm runner, scratch
   directory; the checkers count `not ok` / `Bail out!` (still legacy `:FAIL`) and
   check the plan count, so silently missing tests fail.
2. Wrap every existing `run_tests()` as one suite-level test with a timeout
   (`isolated()` for all); flag the few that need init. Hangs are named and panics
   contained without rewriting tests.
3. Suite and tier selection by cmdline, with a Makefile passthrough.
4. Timing, ratio, OOM and swap suites to the slow tier.
5. Shard the full tier in `gate.sh`.
6. Then file by file, as code is touched: table and macros, merge fragment files
   (`tcp*` into `net/tcp.rs`, `*_race` into their parents, `prctl_extra` into
   `prctl`), drop `static mut`.
7. A coverage run to delete duplicate tests.

## Not to do

- No external framework (LTP, gVisor) as the primary suite: they need libc and a
  dynamic userland, and the fast no_std init boot is lost. Vendored selections can
  come later as an extra tier.
- Do not weaken or drop `check-linux`.
- No big-bang rewrite of 66k lines: wrap first, convert as touched.
- No more ad hoc `isolated()` entries or one-bug files: new tests go into their
  subsystem's file through the harness.
- No fixed sleeps or wider tolerances for flakes: event-based waits (pidfd, poll,
  eventfd handshakes), or the slow tier.
- The smoke tier is not the gate: bisectability needs the full tier on every
  commit.

## Sources

- kselftest: https://docs.kernel.org/dev-tools/kselftest.html
- KTAP: https://docs.kernel.org/dev-tools/ktap.html
- KUnit: https://docs.kernel.org/dev-tools/kunit/
- LTP C API (`tst_test`, `TST_EXP_*`, timeouts, fork model):
  https://linux-test-project.readthedocs.io/en/latest/developers/api_c_tests.html
- gVisor syscall tests (native versus runsc): https://github.com/google/gvisor/tree/master/test/syscalls
- gVisor suite reused by DragonOS and Fuchsia:
  https://docs.dragonos.org.cn/locales/en/kernel/ktest/gvisor_syscall_test.html,
  https://fuchsia.googlesource.com/fuchsia/+/HEAD/third_party/gvisor_syscall_tests/
- Asterinas ktest: https://asterinas.github.io/book/print.html
- syzkaller: https://github.com/google/syzkaller
- kcov: https://docs.kernel.org/dev-tools/kcov.html
- xfstests groups: https://github.com/kdave/xfstests
