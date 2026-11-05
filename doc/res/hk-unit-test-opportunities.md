# hk: host unit-test opportunities

Survey of the kernel crate (repo root, ~all subsystems) for code that runs under
`make test` (= `cargo test -p hk-kernel` on the x86-64 and arm64 CI hosts) and is
untested or thinly tested. Read-only survey against the tree at `58a3100` plus the
uncommitted edits present at the time. Line numbers are approximate to that tree.

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

### 1. seccomp cBPF path: `bpf/convert.rs:45` `cbpf_to_ebpf`, `bpf/interp.rs:22` `bpf_run`, `seccomp/filter.rs:83` `SeccompFilter::run`, `seccomp/check.rs:58,94` `check_syscall`/`verdict`
- What: seccomp(2) converts the user's cBPF to eBPF and interprets it at every syscall
  entry. The socket-filter path (`net/core/filter.rs`) is a separate, tested
  interpreter; the seccomp path has **no tests** (`bpf/verifier.rs` has 3 unrelated ones).
- Coverage: none. Boot test `user/boot_tester/tests/seccomp.rs` only compares
  `nr == getppid` (a small K).
- Bugs a test catches today (see "Notable findings"): JEQ/JGT/JGE against
  K >= 0x80000000 never match (sign-extended immediate), so every libseccomp-style
  `jeq #AUDIT_ARCH_X86_64` (0xC000003E) arch check fails; a conditional with jt=jf=0
  shifts every later jump fixup by one and can index past the eBPF vector (kernel
  panic); scratch memory M[] (ST/LD MEM) always yields 0 = KILL_THREAD because R10 is 0;
  ALU32 DIV/MOD by K >= 2^31 is wrong.
- Tests to write (all pure: build `SockFilter` arrays, run `SeccompFilter::from_cbpf(..).run(&SeccompData{..})`):
  - libseccomp prologue: `ld [4]; jeq #0xC000003E,1,0; ret KILL; ld [0]; jeq #nr,0,1; ret ERRNO|5; ret ALLOW`.
  - `jge`/`jgt` with K = 0x80000000 and 0xFFFFFFFF; `jset` with the high bit.
  - jt=jf=0 conditionals (one, and three in a row before `ret`): must equal the
    program without them, must not panic.
  - `st M[3]; ldx M[3]; txa; ret a` round trip; all 16 slots.
  - `div #0x80000000`, `mod #0xFFFFFFFF`, `div x` with X=0 (Linux: filter returns 0).
  - `ld [64]`, `ld [62]` (out of seccomp_data): result 0; `ld len` = 64.
  - Linux seccomp_check_filter rejects H/B ABS, IND, MSH, unaligned/oob `ld [k]`;
    `validate_cbpf` (`bpf/convert.rs:622`) accepts them: decide and pin.
  - Filter chains: KILL_PROCESS beats everything, ties keep the newest filter's data,
    ERRNO data clamps to 4095, unknown action is KillProcess, STRICT allows only
    read/write/exit/exit_group/rt_sigreturn (arch-specific numbers).
  - `bpf_run` direct: a backward JA (`off = -1`) must terminate (the bound counts `pc`,
    not steps, so it currently loops forever).
- Value/effort: highest value (security, ABI: systemd/docker/chrome filters), easy.

### 2. sysctl integer parsing: `sysctl.rs:80` `parse`
- What: every integer /proc/sys write (Linux `__do_proc_dointvec`).
- Coverage: partial (`parse_vectors`: spacing, extra values, a negative, garbage).
- Gaps / Linux expectations: Linux parses base 0, so `0x10` = 16 and `010` = 8; hk
  rejects `0x10` and reads `010` as 10. Linux rejects `+5` (needs a digit after an
  optional `-`); Rust's `i64::from_str` accepts it. Also: a lone `-` (Linux EINVAL),
  21+ digit tokens (Linux EINVAL), values beyond i32 for int sysctls (Linux EINVAL,
  `proc_dointvec` conv), trailing NULs, `\t`/`\n` separators.
- Also `sysctl.rs:116` `permission`: euid 0 owner bits, egid 0 group bits,
  CAP_NET_ADMIN only for `net/` paths, no DAC override for 0444 files. Pure (takes `&Cred`).
- Value: high (ABI, scripts write hex), easy.

### 3. Process accounting encoders: `task/acct.rs:119` `encode_comp_t`, `:145` `encode_elapsed_float`
- Coverage: none.
- Linux `kernel/acct.c` diffs a test exposes: comp_t lacks Linux's round-to-nearest
  (`rnd = value & 4` before each `>>= 3`, then carry), e.g. 8196 -> Linux 0x2401, hk
  0x2400; `ac_etime` in Linux v3 is `encode_float(nsec_to_AHZ(elapsed))`, a float of
  AHZ=100 ticks built by shifting (truncation), hk stores seconds as `f32` (100x off).
- Cases: 0, 8191, 8192, 8196, 65535, 2^24, u64::MAX (0xFFFF); encode_float of
  1, 100, 2^24+1 (truncation), 2^40.
- Value: medium (ABI for `lastcomm`/`sa`), trivial.

### 4. DAC permission core: `fs/dac.rs:111` `permission_ids`, `:308` `kill_bits`, `:271` `create_mode`, `:176` `access_cred`, `:189` `acc_mode`, `:236` `sticky`, `:206` `may_open`
- Coverage: none.
- `permission_ids` takes `&Cred` + ids + mode bits: pure. Cases: owner class only (a
  0o077 file is unreadable by its owner), group via fsgid and via supplementary
  `groups`, other; CAP_DAC_READ_SEARCH reads files and reads/searches dirs but never
  writes; CAP_DAC_OVERRIDE on dirs for everything, on files except exec with no x bit
  at all (0o600 + MAY_EXEC denied, 0o601 allowed); MAY_APPEND/MAY_OPEN bits ignored.
- `acc_mode`: O_RDONLY|O_TRUNC needs write, O_ACCMODE==3 is RW, O_APPEND sets MAY_APPEND.
- `access_cred`: root keeps permitted caps, non-root real uid gets none.
- `kill_bits` / `create_mode` / `sticky` / `may_open` need an `Inode`: construct one
  with `Inode::new`-style ctor (check what ramfs uses) or refactor to take
  `(InodeMode, Uid, Gid)`. Cases: SUID always cleared, SGID only if group-exec or
  caller outside group, none with CAP_FSETID; SGID dir strips SGID from new
  group-exec files of non-members; sticky dir delete by non-owner = EPERM.
- Note: header comment ("hk has no supplementary groups") is stale; `in_group` uses `groups`.
- Value: high (security), easy for `permission_ids`/`acc_mode`/`access_cred`, medium for inode ones.

### 5. Capability fixups on uid change: `task/mod.rs:2210` `cap_fix_setuid`, `:2243` `cap_fix_setfsuid`
- Coverage: none. Pure on two `Cred`s.
- Cases (Linux `cap_emulate_setxuid`, `cap_task_fix_setuid(LSM_SETID_FS)`): leaving
  all-zero ids clears permitted+effective+ambient; with keep_caps keeps permitted,
  still clears ambient and (euid 0->x) effective; euid x->0 restores effective from
  permitted; ruid-only change while euid stays 0 keeps caps; fsuid 0->x drops exactly
  CAP_FS_SET bits from effective, x->0 re-raises them from permitted only.
- Value: high (privilege drop correctness), trivial.

### 6. Control messages: `net/msg.rs:425` `cmsgs`, `:404` `Cmsg::put`
- Coverage: none. Peer/user controlled (sendmsg control buffer; recvmsg output).
- Cases: empty buffer; buffer shorter than a header (ignored); `cmsg_len` < 16 or past
  the end -> one `Err` then stop; two messages with the 8-byte alignment padding;
  last message unpadded; `put` with room < 16 (only MSG_CTRUNC), room between header
  and full (truncated length written, CTRUNC), exact fit, CMSG_SPACE padding
  truncated to room (Linux `put_cmsg`).
- `net/unix/scm.rs:231` `Scm::parse`: non-SOL_SOCKET skipped, unknown type EINVAL,
  SCM_RIGHTS with 0 fds -> None. (`add_fds` needs a task fd table: stop at parse.)
- Value: high, easy.

### 7. N_TTY line discipline core: `tty/n_tty.rs:35` `NTtyData`, `:273` `receive_char`, `:338` `canon_char`, `copy`, `inq`, `set_icanon`
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

### 8. POSIX record locks: `fs/posix_lock.rs:137` `InodeLocks` (`try_lock`, `unlock_range`, `coalesce_locks`, `find_conflict`), `:300` `resolve_range`
- Coverage: none.
- Cases: split by middle unlock; partial overlaps at each end; same-owner type change
  (write [0,100) then read [25,50) -> W/R/W); merge of adjacent same-type; different
  owners never merge; read/read no conflict; EOF (`u64::MAX`) ranges.
- `resolve_range` needs a `File` (refactor to `(whence, start, len, pos, size)`):
  negative `l_len` (Linux: start+len .. start-1), `l_len == i64::MIN` (`-l_len`
  overflows: panic with overflow checks), `start + len` past i64::MAX (Linux
  EOVERFLOW, hk accepts up to u64), SEEK_END with negative start.
- Value: high (data integrity for databases), easy for InodeLocks.

### 9. IPv4 receive validation and checksums: `net/ipv4.rs:373` `ip_options_ok`, `:346` `ip_check`, `:246` `ip_checksum`, `:278` `pseudo_header_checksum`; `net/udp.rs:723-756` `csum_ok`/`add_words`/`fold`/`udp_checksum`; `net/tcp/output.rs:340` `checksum`
- Coverage: none for these (TCP option parsing is well tested).
- Cases: RFC 1071 example vector; odd length; all-0xFF data (fold carries); UDP 0 ->
  0xFFFF; the three checksum implementations agree on random data and verify to
  0xFFFF/0 when the checksum is inserted; 64 KiB payload (no u32 overflow).
- `ip_options_ok`: EOL ends, NOP, length 0/1 rejected, length past end rejected,
  LSRR/SSRR rejected. `ip_check` (with `SkBuff::alloc`): version != 4, IHL < 5, IHL
  past data, bad checksum, total length < IHL or > data, Ethernet padding trimmed.
- Value: high (peer input), easy.

### 10. Flattened device tree parser: `dt/mod.rs:57` `DeviceTree::from_fdt`, `root`, `find_node`, `find_compatible`, `Node::reg`/`regs`/`cells`/`interrupts`, `skip_node`
- Coverage: none (generic code, runs on both hosts).
- Cases: hand-built minimal FDT (header + struct + strings) with nested nodes, NOPs,
  `#address-cells`/`#size-cells` 1 and 2, `chosen/stdout-path`; then malformed blobs:
  struct_offset/size past totalsize, a property length past the end, unterminated
  name, strings offset out of range. Today `read_be32` indexes unchecked, so these
  panic rather than return `DtError`.
- Value: medium (boot input, trusted), easy; tests would drive bounds checks.

### 11. Address-space bookkeeping: `mm/mod.rs:456` `find_free_area`, `:473` `gap_around`, `overlaps`, `:757` `split_vma`, `:837` `merge_adjacent`; `mm/vma.rs:418` `Vma::can_merge_with`; `mm/madvise.rs:123` `check_range`, `:335` `new_flags`
- Coverage: partial (`mm/mod.rs` tests cover `remove_range` and anon chains, with a
  `map()` helper ready to reuse).
- Cases: top-down search skipping a VMA straddling `mmap_base`, exact-fit gap, nothing
  fits / below MMAP_MIN_ADDR -> None, size 0; `gap_around` with no neighbours;
  merge rules (prot, flags, anon_vma identity and contiguous pgoff, file offsets,
  shm never); madvise range: unaligned start EINVAL, len wrapping on page round-up
  EINVAL, len 0 -> None; WIPEONFORK on file/shared EINVAL, RANDOM/SEQUENTIAL exclusive.
- Value: medium-high (memory corruption if wrong), easy.

### 12. SysV message selection: `ipc/msg.rs:62` `Search`, `:155` `take_msg`, `try_send`, `:211` `fits`
- Coverage: none.
- Cases (Linux `convert_mode`/`find_msg`/`msg_fits_inqueue`): msgtyp 0 first message;
  >0 exact; >0 with MSG_EXCEPT first other type; <0 lowest type <= |t|, FIFO among
  equal types; `i64::MIN`; E2BIG leaves message queued, MSG_NOERROR truncates; qbytes
  bounds both bytes and message count; send to a removed queue EIDRM.
- Needs `MsgQueue::new(key, mode, Arc<IpcNamespace>)` (namespace ctor) and
  `current_time_secs` (0 on host): medium.
- Value: medium (ABI), easy-medium.

### 13. VFAT name handling: `fs/vfat.rs:933` `lfn_checksum`, `:1195` `short_name_checksum`, `:1109` `generate_short_name`, `:1206` `create_lfn_entries` / `:970` `lfn_entry_chars` / `:983` `lfn_name`, `:942` `short_name_to_string`, `Charset::to_text`/`to_bytes`, `:552` `VfatOpts::parse`
- Coverage: none.
- Cases: checksum known vectors (from a mkfs.vfat image or the FAT spec example);
  LFN round trip for 1, 12, 13, 14, 26, 255 UTF-16 units and astral chars split across
  entries (surrogate pair spanning entries); entry order bytes (0x40 on last);
  short-name generation: `README.TXT` kept, `Long File.txt` -> `LONGFI~1TXT`, collision
  numbering past ~9 and ~99, extension truncated to 3, base cleaning to empty
  (`"   .txt"`, `"..a"`) currently yields a short name starting with a space (invalid
  8.3; check vs Linux `vfat_create_shortname`); KANJI 0x05 -> 0xE5; CP437 round trip of
  all 128 high bytes; mount options (umask splits to fmask/dmask, unknown option
  EINVAL, `utf8` overrides iocharset).
- Value: medium (on-disk names), easy.

### 14. initramfs cpio parser: `fs/cpio.rs:68` `parse`, `:249` `parse_hex`
- Coverage: none.
- Cases: newc and crc magics; header + name + body alignment to 4; namesize 0
  (InvalidHeader); truncated header/name/body (BufferTooSmall, no panic); non-hex
  field; `next` offset for zero/odd sizes; TRAILER!!! name. (`unpack_cpio` needs a
  ramfs root: near-miss.)
- Value: medium (boot input), trivial.

### 15. EEVDF fair-class math: `task/fair.rs:41` `weight`, `:57` `calc_delta_fair`, `:85` `avg_vruntime`, `pick`, `save_lag`, `:123` `place`, `update_curr`
- Coverage: none (`task/sched.rs` tests only the RT `PrioQueue`).
- Cases: weight table vs Linux `sched_prio_to_weight` (nice -20 = 88761, 0 = 1024,
  19 = 15), SCHED_IDLE = 3; delta scaling at nice 0 identity and nice 19 x68;
  `avg_vruntime` weighted mean with huge vruntimes (no overflow, min-based);
  `pick` only eligible entities (vruntime <= avg) and earliest deadline; lag clamped
  to +-(slice+tick); `place` initial half slice. Uses `SchedEntity::new(state)`.
- Value: medium (fairness, starvation), easy.

### 16. Load average: `task/loadavg.rs:26` `calc_load`, `:67` `proc_loadavg` formatting
- Coverage: none.
- Cases: Linux known values: from 0 with 1 active, 12 updates of EXP_1 reach ~0.86
  (11-bit fixed point); decay to exactly 0 eventually (round-up only when rising);
  formatting `x.yy` rounding at FIXED_1/200. Extract the format of an `[u64; 3]` to
  test without task counts.
- Value: low-medium, trivial.

### 17. Time conversions and the timekeeper: `time/mod.rs:516` `timespec_to_ns`, `deadline_after`, `:546` `deadline_ts`, `:484` `settod_valid`, `:474` `cycles_delta`, `ns_to_clock_t`/`ms_to_clock_t`; `TimeKeeper` (`init`, `read`, `update`, `set_realtime`, `inject_offset`)
- Coverage: none.
- Cases: negative sec/nsec -> 0, overflow saturates at KTIME_MAX, (0,0) deadline is
  `Some(0)`, nsec = 1e9 invalid, TIME_SETTOD_SEC_MAX bound; `cycles_delta` of a lagging
  counter is 0. A local `TimeKeeper::new()` with a fake counter (`fn` reading a test
  static) gives: mult/shift accuracy at 1 GHz, 2.4 GHz, 19.2 MHz (arm generic timer)
  over 1 s and 1 day; monotonic never goes backwards across `update`; set_realtime
  moves only REALTIME; inject_offset rejecting results < 0 or past the settod max.
- Value: medium-high (every timeout), easy (the fake counter static must be
  test-private to avoid races).

### 18. Periodic timer overruns and timer value conversions: `time/timer.rs:321` `forward`, `time/posix_timer.rs:975` `ts_to_tv`, `time/timerfd.rs:76-100` `ItimerSpec` (`value_to_ns`, `is_valid`, `from_ns`)
- Coverage: none.
- Cases: `forward` with now == expires (1 period), now just before the next period,
  interval 0 (division guard), result at/after KTIME_MAX -> None, huge interval
  multiply overflow; `ts_to_tv` rounds nsec up (999_999_999 ns -> sec+1, 0 us);
  `from_ns`/`value_to_ns` round trip; nsec 1e9 invalid.
- Value: medium (timer_settime/getitimer ABI), trivial.

### 19. RTC date math (x86-64 runner only): `arch/x86_64/rtc.rs:118` `date_to_unix`, `is_leap_year`
- Coverage: none.
- Cases: 1970-01-01 = 0, 2000-02-29, 2100-03-01 (not leap), 2038-01-19T03:14:08 =
  2^31; month 0 / 13+ (month >= 14 indexes `DAYS_IN_MONTH[12]`: panic on a garbage
  CMOS byte). The BCD/12-hour decode in `read_rtc` is mixed with CMOS reads (12 AM
  stays hour 12): extract a `decode(regs) -> tm` to test it.
- Value: low-medium, trivial.

### 20. eventfd counter semantics: `io/eventfd.rs:92` `read`, `:130` `write` (non-blocking), `poll`
- Coverage: none.
- Cases: write u64::MAX EINVAL; count may reach 0xFFFF_FFFF_FFFF_FFFE, one more EAGAIN;
  write 0 succeeds; EFD_SEMAPHORE reads 1 and decrements; normal read resets; empty
  read EAGAIN; poll bits (EPOLLIN when > 0, EPOLLOUT while < max-1). `Eventfd::new`
  is public; wake_all with no waiters is fine on host.
- Value: medium (glibc/systemd use it), easy.

### 21. cgroup value parsers: `cgroup/memory.rs:302` `parse_memory_size`, `cgroup/io.rs:379` `parse_io_value`; inline parses in `cgroup/cpu.rs:289` `cpu_max_write`, `:330` `cpu_weight_write`, `cgroup/pids.rs:241` `pids_max_write`
- Coverage: none.
- Cases (Linux `memparse` / `page_counter_memparse`): K/M/G and also T/P/E suffixes
  (hk: no T/P/E), `max`, whitespace, overflow -> EINVAL vs Linux ERANGE, byte values
  rounded down to pages; cpu.max `"max 100000"`, `"50000"` (period default),
  zero/too small quota; cpu.weight 0 and 10001 EINVAL; pids.max `max`.
- Value: medium (container managers write these), easy for the two pure ones; the
  rest need the parse split out (see near-misses).

### 22. uevent synthetic events: `base/uevent.rs:145` `synth_parse`, `:122` `synth_args`, `uuid_valid`, `Action::parse/name`
- Coverage: none.
- Cases (Linux `kobject_synth_uevent`): `add\n`, `add\0`, unknown action EINVAL, UUID
  with wrong dash positions/length, `UUID KEY=val` pairs, non-alnum key/value rejected,
  double space rejected, missing UUID with args.
- Value: low-medium (udev coldplug), trivial.

### 23. Signal sets and dequeue order: `signal/mod.rs:120-200` `SigSet`, `:429` `SigPending::dequeue`, `:1337` `default_action`
- Coverage: none.
- Cases: sig 0 and 65 ignored by add/contains; `first` = lowest; dequeue skips blocked;
  default action table vs signal(7) (SIGSTKFLT/SIGPWR terminate, SIGURG/SIGWINCH
  ignore, RT terminate). Linux `next_signal` delivers synchronous signals (SEGV, BUS,
  ILL, TRAP, FPE, SYS) before lower-numbered ones; hk takes the lowest: a test pins
  the choice.
- Value: low-medium, trivial.

### 24. sockaddr parsing: `net/af_inet.rs:343` `sin_parse`; `net/unix/mod.rs:630` `validate`, `:639` `bsd_name`
- Coverage: none.
- Cases: short address EINVAL; AF_UNSPEC only when allowed; port/addr byte order;
  AF_UNIX length exactly 2 (EINVAL, autobind is handled elsewhere), 110 max, path
  without NUL, embedded NUL ends the path, abstract name (leading NUL) passed through.
- Value: medium, trivial.

### 25. SCSI command building and response parsing: `block/scsi.rs:60-135` `Cdb::*`, `:280-325` `InquiryData`/`ReadCapacityData`, `:341-420` `test_unit_ready`/`inquiry`/`read_capacity`; `hw/usb/msc.rs:46-115` `Cbw::as_bytes`, `Csw::from_bytes`
- Coverage: `block/sd.rs` has state-machine and index tests only.
- Cases: READ(10)/WRITE(10) byte layout (big-endian LBA and length); vendor/product
  trimming; READ CAPACITY last_lba 0xFFFFFFFF (Linux falls back to READ CAPACITY 16);
  CBW signature/flags/length layout, CSW signature check. `ScsiHost` is a trait: a
  mock host returning canned buffers tests the command helpers without hardware.
- Value: low-medium (OptiPlex USB disks), easy.

### 26. ELF image layout: `task/exec.rs:331` `image_layout`
- Coverage: none (`util/elf.rs` parsing is well tested and has an `exe()` builder).
- Cases: start_code/end_code from executable segments only, data from highest segment,
  no executable segment -> start_code 0, base offset applied (PIE). `check_segments`
  reads `FRAME_ALLOCATOR` (split the free-memory test out to make the bounds part testable).
- Value: low-medium (/proc/pid/stat, brk placement), easy.

### 27. netlink attributes: `net/netlink/attr.rs` `Attrs::parse`, `Msg::nest_end`, `Attrs::str`
- Coverage: partial (`build_and_parse`, `malformed`).
- Gaps: NLA_F_NESTED / NLA_F_NET_BYTEORDER bits masked from the type; type > max
  ignored; trailing < 4 bytes ignored (Linux liberal parse); `str` with no NUL, NUL at
  max-1 and at max (EINVAL); attribute > 64 KiB dropped by `attr`, nest > 64 KiB
  silently truncates `nla_len` in `nest_end` (u16 cast).
- Value: low-medium, trivial.

### 28. errno table: `util/error.rs:213` `from_errno` vs discriminants
- Coverage: none. Currently consistent (86 variants, 86 arms), but nothing keeps it so.
- Case: for each variant, `from_errno(e.errno()) == Some(e)`; spot values vs
  asm-generic errno.h (EDEADLK 35, ENOTSUP 95, ERESTARTSYS 512).
- Value: low, trivial.

### Already well covered (add only edge cases)
TCP control block (`net/tcp/tests.rs`, 55), page allocator (18), USB PCI quirks (13),
`util/elf.rs` (10), ACPI HW/AML (16), partition tables MBR/GPT (14), neighbour state
machine (8), xarray, memblock, fdbits, frag, port/SipHash, kmsg, ChaCha, binfmt_script.

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
  tests would also show Linux deviations: ADJ_FREQUENCY is ignored (freq reads back
  0) and ADJ_TIMECONST is stored unclamped (Linux clamps to 0..MAXTC, +4 without STA_NANO).
- **readv/writev iovec checks** (`fs/iov.rs:41`): copy and validation are one function;
  split validation of the copied array so `iov_len` > MAX_RW_COUNT or negative as
  ssize_t can be tested (Linux EINVAL; hk returns EFAULT via `access_ok`).
- **cgroup knob writers** (`cgroup/cpu.rs:289`, `cgroup/pids.rs:241`, memory.max): parse
  inline on a `CgroupSubsysState`; a `parse_max_u64(&str) -> Result<Option<u64>>`
  shared helper is both testable and removes duplication.
- **/proc/pid/stat and status** (`fs/proc/array.rs:271,378`): gathering (`snap`) and
  formatting are interleaved; format from a `Snap` value so field order/count (52 stat
  fields, `State:` strings, `Sig*` hex masks) is pinned against Linux.
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

## Notable findings (not fixed)

1. **seccomp: compares against K >= 0x80000000 never match** (`bpf/convert.rs:348`
   `convert_jmp`, executed by `bpf/interp.rs:146-167`). The converter emits
   `BPF_JMP|op|BPF_K` with `imm = k as i32`; the interpreter sign-extends `imm` to 64
   bits (correct eBPF) while A is a zero-extended u32, so `jeq #0xC000003E` compares
   against 0xFFFFFFFF_C000003E. Linux's `bpf_convert_filter` handles exactly this
   (`(int)fp->k < 0` -> MOV32 to a temp and compare with BPF_X). Effect: the standard
   arch check in libseccomp/systemd/docker/chrome filters fails, so those programs take
   the "wrong arch" branch (usually KILL). JGT/JGE against such K are also wrong. The
   interpreter's JMP32+K path has the matching bug (sign-extended imm compared against
   a u32).
2. **seccomp: a conditional jump with jt = jf = 0 breaks jump fixup**
   (`bpf/convert.rs:509` `fixup_jumps`). `convert_jmp` emits nothing for it, but
   `fixup_jumps` still takes the `jf == 0` branch, writes `off` into whatever eBPF
   instruction is at `ebpf_idx` and advances `ebpf_idx`, desynchronising every later
   jump. `[jeq 0,0; jeq 0,0; jeq 0,0; ret k]` passes `validate_cbpf` and indexes
   `ebpf[2]` of a 2-element vector: a kernel panic reachable by an unprivileged
   process (no_new_privs + seccomp(SET_MODE_FILTER)). A corrupted offset can also
   produce a backward jump, and `bpf_run`'s bound (`pc > BPF_MAXINSNS`) does not stop
   loops, so the kernel can spin forever in syscall entry.
3. **seccomp: cBPF scratch memory always kills**: `bpf_run` sets R10 = 0
   (`bpf/interp.rs:31`) while ST/LD MEM are converted to `[R10 - 4(k+1)]`, which is
   outside the stack check, so the program returns 0 (SECCOMP_RET_KILL_THREAD).
4. **seccomp accepts filters Linux rejects**: `validate_cbpf` allows LD H/B ABS, LD IND,
   LDX MSH, unaligned or out-of-range `ld [k]`, `div #0`, RET X; Linux
   `seccomp_check_filter` returns EINVAL. ALU32 DIV/MOD by K >= 2^31 uses the
   sign-extended immediate (wrong quotient).
5. **sysctl integer writes are not Linux-compatible** (`sysctl.rs:80`): base 0 parsing
   is missing (`0x10` EINVAL, `010` = 10 vs Linux 8) and `+5` is accepted.
6. **acct records**: `ac_etime` is seconds as f32 instead of Linux's AHZ ticks
   (100x off) and `encode_comp_t` does not round like Linux (`task/acct.rs:119,145`).
7. **Minor**: `fs/posix_lock.rs:328` `(-flock.l_len)` overflows for `i64::MIN`
   (panic in overflow-checked builds) and lengths past i64::MAX are accepted (Linux
   EOVERFLOW); `arch/x86_64/rtc.rs:131` indexes `DAYS_IN_MONTH` with an unvalidated
   CMOS month (panic for month >= 14) and keeps 12 AM as hour 12; `fs/vfat.rs:1109`
   can produce a short name starting with a space when the base cleans to empty;
   `fs/dac.rs:7` doc says there are no supplementary groups, the code uses them;
   `dt/mod.rs` panics instead of returning `DtError` on out-of-range offsets.
