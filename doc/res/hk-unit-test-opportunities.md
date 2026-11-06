# hk: host unit-test opportunities

Survey of the kernel crate (repo root, ~all subsystems) for code that runs under
`make test` (= `cargo test -p hk-kernel` on the x86-64 and arm64 CI hosts) and is
untested or thinly tested. Line numbers are approximate. Bugs these tests would catch
are in BUGS.md ("Allocation sizing and pure-code gaps").

## Conventions (from existing tests)

- Small modules: `#[cfg(test)] mod tests { use super::*; ... }` at the end of the file
  (e.g. `util/ida.rs`, `sysctl.rs`, `net/tcp/output.rs`). Big suites: a sibling file
  declared `#[cfg(test)] mod tests;` (`net/tcp/tests.rs`: 55 tests driving two `TcpCb`s
  over a simulated wire with a virtual clock). Module-private items are reachable
  because the test module is a child.
- Test names say the behaviour (`remove_range_splits_edges`, `rst_rules_rfc5961`).
  Known-answer vectors are in use (RFC 7539 ChaCha block in `random.rs`, CRC32 in
  `block/part/efi.rs`, SipHash in `net/inet/port.rs`).
- The whole crate builds for the host: `main.rs` is `no_std`/`no_main` only under
  `not(test)`, `allow(dead_code, unused)` under test, and the heap (`mm/heap.rs`) is
  not the global allocator under test, so `alloc` uses std's.
- Only the host arch's `arch/` module is compiled: `arch/x86_64/*` tests run only on the
  x86-64 runner, `arch/aarch64/*` only on arm64 (`arch/aarch64/dtb.rs` has an empty
  test module). Generic code runs on both.
- Tests run on parallel threads in one process: anything touching a global static
  (TIMEKEEPER, TCP memory counters, IP ident buckets, TASKLIST) can race with other
  tests. Prefer local instances (`TimeKeeper::new()`, `MmStruct::new()`, `Ida::new()`).
- `make test` must be warning-free (CLAUDE.md). The gate's clippy does not build
  `--tests`, but `// SAFETY:` discipline still applies to `unsafe` in tests.

## What exists for the host, and what blocks it

Stubs in place:
- `sync/spin.rs`: `preempt_disable/enable` are no-ops under test.
- `arch/{x86_64,aarch64}/spinlock.rs`: `IrqSpinlock` IRQ save/restore and preempt are
  no-ops, `irqs_disabled()` is false. So IRQ-safe state is usable.
- `cpu.rs`: `try_this_id()` is `None`, every `PerCpu` access uses slot 0.
- `task::percpu::current()`: with `PERCPU_UP` false it returns `INIT_TASK`, so
  `current_cred()` is boot root, `capable()` works (it only sets PF_SUPERPRIV on
  INIT_TASK), `current_tid()` is 0, `current_fs()` is None (umask defaults to 022).
  Consequence: a test cannot pick its caller's credentials for code that reads
  `current_cred()` itself; it can for functions that take a `&Cred`.
- `TIMEKEEPER` is uninitialized: clocks read 0 via `null_read_tsc`.
- Ad hoc cfg(test) shims in `mm/ptl.rs`, `mm/anon_vma.rs`, `mm/page_alloc.rs`,
  `mm/xarray.rs`, `mm/slab.rs`, `net/inet/port.rs`.
- `SkBuff::alloc` works on the host (used by `net/skb.rs` tests).

Blocks:
- User memory: `copy_from_user`/`get_user`/`put_user` go through the arch
  `UaccessArch` impls; there is no host impl, so anything that copies from a user
  pointer is out (29 functions are already generic over `A: UaccessArch`).
- Page tables, `FRAME_ALLOCATOR`, TLB, fault handling.
- Sleeping: `wait_event*`, `schedule`, blocking paths (non-blocking paths are fine).
- Device registers, port I/O, MMIO, CMOS, PCI config.
- Per-task identity: every test is tid 0 / root, there is one task.

## Ranked candidates

Value = bug likelihood x blast radius x ease. "Easy" = pure function or local
instance; "medium" = needs a small fixture or cfg(test) shim.

### 1. sysctl integer parsing: `sysctl.rs:80` `parse`
- What: every integer /proc/sys write (Linux `__do_proc_dointvec`).
- Coverage: partial (`parse_vectors`: spacing, extra values, negatives, garbage, base 0,
  `+`, a lone `-`).
- Linux expectations still untested: 21+ digit tokens (Linux EINVAL), values beyond i32
  for int sysctls (Linux EINVAL, `proc_dointvec` conv), trailing NULs, `\t`/`\n`
  separators.
- Also `sysctl.rs:116` `permission`: euid 0 owner bits, egid 0 group bits,
  CAP_NET_ADMIN only for `net/` paths, no DAC override for 0444 files. Pure (takes `&Cred`).
- Value: high (ABI, scripts write hex), easy.

### 3. Capability fixups on uid change: `task/mod.rs:2210` `cap_fix_setuid`, `:2243` `cap_fix_setfsuid`
- Coverage: none. Pure on two `Cred`s.
- Cases (Linux `cap_emulate_setxuid`, `cap_task_fix_setuid(LSM_SETID_FS)`): leaving
  all-zero ids clears permitted+effective+ambient; with keep_caps keeps permitted,
  still clears ambient and (euid 0->x) effective; euid x->0 restores effective from
  permitted; ruid-only change while euid stays 0 keeps caps; fsuid 0->x drops exactly
  CAP_FS_SET bits from effective, x->0 re-raises them from permitted only.
- Value: high (privilege drop correctness), trivial.

### 4. Control messages: `net/msg.rs:425` `cmsgs`, `:404` `Cmsg::put`
- Coverage: none. Peer/user controlled (sendmsg control buffer; recvmsg output).
- Cases: empty buffer; buffer shorter than a header (ignored); `cmsg_len` < 16 or past
  the end -> one `Err` then stop; two messages with the 8-byte alignment padding;
  last message unpadded; `put` with room < 16 (only MSG_CTRUNC), room between header
  and full (truncated length written, CTRUNC), exact fit, CMSG_SPACE padding
  truncated to room (Linux `put_cmsg`).
- `net/unix/scm.rs:231` `Scm::parse`: non-SOL_SOCKET skipped, unknown type EINVAL,
  SCM_RIGHTS with 0 fds -> None. (`add_fds` needs a task fd table: stop at parse.)
- Value: high, easy.

### 5. N_TTY line discipline core: `tty/n_tty.rs:35` `NTtyData`, `:273` `receive_char`, `:338` `canon_char`, `copy`, `inq`, `set_icanon`
- Coverage: none. Pure: `NTtyData::new()`, `Termios::default()`, an `Effects`.
- Cases: canonical line assembly and one-line-per-read; short read buffer splits a
  line, next read continues; VERASE / VWERASE (IEXTEN only) / VKILL with ECHOK vs
  ECHOKE echo strings; VEOF on empty line = 0-byte read, VEOF mid-line returns the
  partial line without the EOF char; ICRNL/IGNCR/INLCR/ISTRIP mapping; ISIG chars
  flush unless NOFLSH and emit the right signal; ECHOCTL `^C` and 2-column erase;
  ring full (4095-byte line with no line end still readable, excess dropped);
  `set_icanon` both directions (pending line becomes input; entering canon makes the
  queued bytes one line); `inq` counting with EOF marks; VMIN in raw mode.
- Value: high (every shell, getty), easy.

### 7. IPv4 receive validation and checksums: `net/ipv4.rs:373` `ip_options_ok`, `:346` `ip_check`, `:246` `ip_checksum`, `:278` `pseudo_header_checksum`; `net/udp.rs:723-756` `csum_ok`/`add_words`/`fold`/`udp_checksum`; `net/tcp/output.rs:340` `checksum`
- Coverage: none for these (TCP option parsing is well tested).
- Cases: RFC 1071 example vector; odd length; all-0xFF data (fold carries); UDP 0 ->
  0xFFFF; the three checksum implementations agree on random data and verify to
  0xFFFF/0 when the checksum is inserted; 64 KiB payload (no u32 overflow).
- `ip_options_ok`: EOL ends, NOP, length 0/1 rejected, length past end rejected,
  LSRR/SSRR rejected. `ip_check` (with `SkBuff::alloc`): version != 4, IHL < 5, IHL
  past data, bad checksum, total length < IHL or > data, Ethernet padding trimmed.
- Value: high (peer input), easy.

### 8. Flattened device tree parser: `dt/mod.rs:57` `DeviceTree::from_fdt`, `root`, `find_node`, `find_compatible`, `Node::reg`/`regs`/`cells`/`interrupts`, `skip_node`
- Coverage: malformed headers and the bounds-checked readers only.
- Cases: hand-built minimal FDT (header + struct + strings) with nested nodes, NOPs,
  `#address-cells`/`#size-cells` 1 and 2, `chosen/stdout-path`; a property length past
  the end, an unterminated name, a strings offset out of range.
- Value: medium (boot input, trusted), easy.

### 10. SysV message selection: `ipc/msg.rs:62` `Search`, `:155` `take_msg`, `try_send`, `:211` `fits`
- Coverage: none.
- Cases (Linux `convert_mode`/`find_msg`/`msg_fits_inqueue`): msgtyp 0 first message;
  >0 exact; >0 with MSG_EXCEPT first other type; <0 lowest type <= |t|, FIFO among
  equal types; `i64::MIN`; E2BIG leaves message queued, MSG_NOERROR truncates; qbytes
  bounds both bytes and message count; send to a removed queue EIDRM.
- Needs `MsgQueue::new(key, mode, Arc<IpcNamespace>)` (namespace ctor) and
  `current_time_secs` (0 on host): medium.
- Value: medium (ABI), easy-medium.

### 13. EEVDF fair-class math: `task/fair.rs:41` `weight`, `:57` `calc_delta_fair`, `:85` `avg_vruntime`, `pick`, `save_lag`, `:123` `place`, `update_curr`
- Coverage: none (`task/sched.rs` tests only the RT `PrioQueue`).
- Cases: weight table vs Linux `sched_prio_to_weight` (nice -20 = 88761, 0 = 1024,
  19 = 15), SCHED_IDLE = 3; delta scaling at nice 0 identity and nice 19 x68;
  `avg_vruntime` weighted mean with huge vruntimes (no overflow, min-based);
  `pick` only eligible entities (vruntime <= avg) and earliest deadline; lag clamped
  to +-(slice+tick); `place` initial half slice. Uses `SchedEntity::new(state)`.
- Value: medium (fairness, starvation), easy.

### 14. Load average: `task/loadavg.rs:26` `calc_load`, `:67` `proc_loadavg` formatting
- Coverage: none.
- Cases: Linux known values: from 0 with 1 active, 12 updates of EXP_1 reach ~0.86
  (11-bit fixed point); decay to exactly 0 eventually (round-up only when rising);
  formatting `x.yy` rounding at FIXED_1/200. Extract the format of an `[u64; 3]` to
  test without task counts.
- Value: low-medium, trivial.

### 15. Time conversions and the timekeeper: `time/mod.rs:516` `timespec_to_ns`, `deadline_after`, `:546` `deadline_ts`, `:484` `settod_valid`, `:474` `cycles_delta`, `ns_to_clock_t`/`ms_to_clock_t`; `TimeKeeper` (`init`, `read`, `update`, `set_realtime`, `inject_offset`)
- Coverage: none.
- Cases: negative sec/nsec -> 0, overflow saturates at KTIME_MAX, (0,0) deadline is
  `Some(0)`, nsec = 1e9 invalid, TIME_SETTOD_SEC_MAX bound; `cycles_delta` of a lagging
  counter is 0. A local `TimeKeeper::new()` with a fake counter (`fn` reading a test
  static) gives: mult/shift accuracy at 1 GHz, 2.4 GHz, 19.2 MHz (arm generic timer)
  over 1 s and 1 day; monotonic never goes backwards across `update`; set_realtime
  moves only REALTIME; inject_offset rejecting results < 0 or past the settod max.
- Value: medium-high (every timeout), easy (the fake counter static must be
  test-private to avoid races).

### 16. Periodic timer overruns and timer value conversions: `time/timer.rs:321` `forward`, `time/posix_timer.rs:975` `ts_to_tv`, `time/timerfd.rs:76-100` `ItimerSpec` (`value_to_ns`, `is_valid`, `from_ns`)
- Coverage: none.
- Cases: `forward` with now == expires (1 period), now just before the next period,
  interval 0 (division guard), result at/after KTIME_MAX -> None, huge interval
  multiply overflow; `ts_to_tv` rounds nsec up (999_999_999 ns -> sec+1, 0 us);
  `from_ns`/`value_to_ns` round trip; nsec 1e9 invalid.
- Value: medium (timer_settime/getitimer ABI), trivial.

### 17. RTC date math (x86-64 runner only): `arch/x86_64/rtc.rs:118` `date_to_unix`, `is_leap_year`
- Coverage: none.
- Cases: 1970-01-01 = 0, 2000-02-29, 2100-03-01 (not leap), 2038-01-19T03:14:08 =
  2^31; month 0 / 13+ (month >= 14 indexes `DAYS_IN_MONTH[12]`: panic on a garbage
  CMOS byte). The BCD/12-hour decode in `read_rtc` is mixed with CMOS reads (12 AM
  stays hour 12): extract a `decode(regs) -> tm` to test it.
- Value: low-medium, trivial.

### 18. eventfd counter semantics: `io/eventfd.rs:92` `read`, `:130` `write` (non-blocking), `poll`
- Coverage: none.
- Cases: write u64::MAX EINVAL; count may reach 0xFFFF_FFFF_FFFF_FFFE, one more EAGAIN;
  write 0 succeeds; EFD_SEMAPHORE reads 1 and decrements; normal read resets; empty
  read EAGAIN; poll bits (EPOLLIN when > 0, EPOLLOUT while < max-1). `Eventfd::new`
  is public; wake_all with no waiters is fine on host.
- Value: medium (glibc/systemd use it), easy.

### 19. cgroup value parsers: `cgroup/memory.rs:166` `parse_memory_size`, `cgroup/io.rs:247` `parse_io_value`; inline parses in `cgroup/cpu.rs:188` `cpu_max_write`, `:227` `cpu_weight_write`, `cgroup/pids.rs:261` `pids_max_write`
- Coverage: none.
- Cases (Linux `memparse` / `page_counter_memparse`): K/M/G/T/P/E suffixes, `max`, whitespace, overflow -> EINVAL vs Linux ERANGE, byte values
  rounded down to pages; cpu.max `"max 100000"`, `"50000"` (period default),
  zero/too small quota (EINVAL); cpu.weight 0 and 10001 EINVAL; pids.max `max`.
- Value: medium (container managers write these), easy for the two pure ones; the
  rest need the parse split out (see near-misses).

### 20. uevent synthetic events: `base/uevent.rs:145` `synth_parse`, `:122` `synth_args`, `uuid_valid`, `Action::parse/name`
- Coverage: none.
- Cases (Linux `kobject_synth_uevent`): `add\n`, `add\0`, unknown action EINVAL, UUID
  with wrong dash positions/length, `UUID KEY=val` pairs, non-alnum key/value rejected,
  double space rejected, missing UUID with args.
- Value: low-medium (udev coldplug), trivial.

### 21. Signal sets and dequeue order: `signal/mod.rs:120-200` `SigSet`, `:429` `SigPending::dequeue`, `:1337` `default_action`
- Coverage: none.
- Cases: sig 0 and 65 ignored by add/contains; `first` = lowest; dequeue skips blocked;
  default action table vs signal(7) (SIGSTKFLT/SIGPWR terminate, SIGURG/SIGWINCH
  ignore, RT terminate). Linux `next_signal` delivers synchronous signals (SEGV, BUS,
  ILL, TRAP, FPE, SYS) before lower-numbered ones; hk takes the lowest: a test pins
  the choice.
- Value: low-medium, trivial.

### 22. sockaddr parsing: `net/af_inet.rs:343` `sin_parse`; `net/unix/mod.rs:630` `validate`, `:639` `bsd_name`
- Coverage: none.
- Cases: short address EINVAL; AF_UNSPEC only when allowed; port/addr byte order;
  AF_UNIX length exactly 2 (EINVAL, autobind is handled elsewhere), 110 max, path
  without NUL, embedded NUL ends the path, abstract name (leading NUL) passed through.
- Value: medium, trivial.

### 23. SCSI command building and response parsing: `block/scsi.rs:60-135` `Cdb::*`, `:280-325` `InquiryData`/`ReadCapacityData`, `:341-420` `test_unit_ready`/`inquiry`/`read_capacity`; `hw/usb/msc.rs:46-115` `Cbw::as_bytes`, `Csw::from_bytes`
- Coverage: `block/sd.rs` has state-machine and index tests only.
- Cases: READ(10)/WRITE(10) byte layout (big-endian LBA and length); vendor/product
  trimming; READ CAPACITY last_lba 0xFFFFFFFF (Linux falls back to READ CAPACITY 16);
  CBW signature/flags/length layout, CSW signature check. `ScsiHost` is a trait: a
  mock host returning canned buffers tests the command helpers without hardware.
- Value: low-medium (OptiPlex USB disks), easy.

### 24. ELF image layout: `task/exec.rs:331` `image_layout`
- Coverage: none (`util/elf.rs` parsing is well tested and has an `exe()` builder).
- Cases: start_code/end_code from executable segments only, data from highest segment,
  no executable segment -> start_code 0, base offset applied (PIE). `check_segments`
  reads `FRAME_ALLOCATOR` (split the free-memory test out to make the bounds part testable).
- Value: low-medium (/proc/pid/stat, brk placement), easy.

### 25. netlink attributes: `net/netlink/attr.rs` `Attrs::parse`, `Msg::nest_end`, `Attrs::str`
- Coverage: partial (`build_and_parse`, `malformed`).
- Gaps: NLA_F_NESTED / NLA_F_NET_BYTEORDER bits masked from the type; type > max
  ignored; trailing < 4 bytes ignored (Linux liberal parse); `str` with no NUL, NUL at
  max-1 and at max (EINVAL); attribute > 64 KiB dropped by `attr`, nest > 64 KiB
  silently truncates `nla_len` in `nest_end` (u16 cast).
- Value: low-medium, trivial.

### 26. errno table: `util/error.rs:213` `from_errno` vs discriminants
- Coverage: none. Currently consistent (86 variants, 86 arms), but nothing keeps it so.
- Case: for each variant, `from_errno(e.errno()) == Some(e)`; spot values vs
  asm-generic errno.h (EDEADLK 35, ENOTSUP 95, ERESTARTSYS 512).
- Value: low, trivial.

## Near-misses (need a pure core split out)

- **Host `UaccessArch`** (`uaccess.rs:101` trait): a `#[cfg(test)]` impl whose
  `access_ok` accepts addresses inside a registered test buffer and whose
  `copy_user_raw` is a plain copy would unlock every `fn x<A: UaccessArch>` (29 of
  them: seccomp `create_filter_from_user`, getresuid, sysinfo, capget/capset,
  getrusage, syslog...). Biggest single enabler.
- **Credential transitions** (`task/id.rs:86-590` `sys_set*id`): permission checks call
  `capable()` and then commit through per-CPU state. Split into
  `fn setresuid_new(old: &Cred, r, e, s, cap_setuid: bool) -> Result<Cred, KernelError>`
  (then `cap_fix_setuid`) so every Linux rule (-1 = unchanged, saved-id rules, fsuid
  follows euid) is a table test.
- **IPC and key permission** (`ipc/util.rs:368` `ipc_checkperm`, `keys/key.rs:447`
  `check_key_permission`): read `current_cred()` internally; take `&Cred` (as
  `sysctl::permission` already does) and the class-bit logic becomes testable,
  including CAP_IPC_OWNER and the possessor bits.
- **adjtimex** (`time/time_syscall.rs:1001`): validation and the NTP field updates sit
  between `get_user` and `put_user`. Extract `fn adjtimex_apply(ntp: &mut Ntp, txc: &Timex, cap: bool)`;
  tests would also catch its Linux deviations (BUGS.md).
- **readv/writev iovec checks** (`fs/iov.rs:41`): copy and validation are one function;
  split validation of the copied array so `iov_len` > MAX_RW_COUNT or negative as
  ssize_t can be tested (Linux EINVAL; BUGS.md).
- **cgroup knob writers** (`cgroup/cpu.rs:289`, `cgroup/pids.rs:241`, memory.max): parse
  inline on a `CgroupSubsysState`; a `parse_max_u64(&str) -> Result<Option<u64>>`
  shared helper is both testable and removes duplication.
- **ramfs fixture**: a test helper that builds a ramfs superblock and root dentry would
  unlock `fs/cpio.rs` `unpack_cpio` (hard links, overwrite rules), `fs/dac.rs` inode
  checks, and parts of namei (`walk`, `follow_dotdot`) if `FsStruct` root can be
  injected instead of read from the current task.
- **vfat on a RAM block device**: cluster-chain and directory code (`fs/vfat.rs:717-1520`)
  goes through `BlockDevice` reads; with `block/ramdisk.rs` and a tiny embedded FAT32
  image, `read_cluster_chain` (loop cap, bad cluster), `read_directory_entries` (LFN
  checksum mismatch, deleted entries) and `find_free_dir_slots` become testable.
- **Timer wheel** (`time/timer.rs:201-260` `slot`/`insert`/`detach`/`due`): the wheel
  logic is methods on the per-CPU base's locked struct; a local wheel instance with
  pinned `TimerList`s would test slot hashing, wraparound at 64 slots and far-future
  expiries without the tick.
- **TCP memory accounting** (`net/tcp/mem.rs`): global atomics plus per-CPU reserve;
  tests would race with each other. Wrap the counters in a struct with a global
  instance so tests use their own (pressure enter/leave hysteresis, page-quantum
  rounding, reserve drain).
- **CMOS decode** (`arch/x86_64/rtc.rs:45`): split register decode (BCD, 12-hour, PM
  bit) from port reads (see entry 19).
- **SysV semaphores** (`ipc/sem.rs`, 1148 lines): the "try all sops atomically, else
  undo" core and SEM_UNDO adjustment math (SEMVMX bounds, ERANGE) would be worth a
  pure function over a `&mut [u16]` value array.
