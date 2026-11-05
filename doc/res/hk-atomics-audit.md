# hk Atomic* audit: lazy atomics vs designed synchronization

Scope: the whole tree (excluding `.claude/` and `target/`), read-only. `user/` and `tools/` were also triaged. Reference: doc/LOCKING.md, ~/tmp/repo/linux.

Method:
- Every `Atomic{Bool,U8..U64,Usize,I8..I64,Ptr}` field and static was triaged.
- For anything suspicious, both the writers and the readers were read.
- Each claimed race was checked against the code.
- A heuristic scan flagged 71 sites where one atomic is loaded and then stored within a few lines. Each was checked by hand.

## Summary

| | count |
|---|---|
| Declarations triaged (fields + statics; `::new` lines excluded) | ~540 (kernel ~480, user/ test harness ~60) |
| Judged fine (counters/stats, independent knobs, seqcounts, CAS protocols, Linux-equivalent lockless READ_ONCE fields, user-test thread flags) | ~460 |
| Findings | 33 (below) + 3 dead-code groups |

Findings by category (one finding may count in two categories):

| Cat | Meaning | Findings |
|---|---|---|
| A | Set-once / immutable; should be a ctor value, plain field or `Once` | 7 |
| B | Belongs under a lock that already exists (torn multi-field state, check-then-act) | 21 |
| C | Wrong ordering, or a load+store pair that should be one RMW/CAS | 10 |
| D | Atomic used to dodge an IRQ / sleep-vs-spin question | 1 |
| E | Shared state LOCKING.md does not document, or documents wrongly | 8 |

Dominant anti-pattern: a struct carries an atomic per field to get `&self` mutation.
- The fields are then checked and updated in separate steps outside the lock that already exists for that object: sem, msg, cgroup pids, Key, Mount, TCP.
- LOCKING.md §5.4 then calls the result correct. Its "hk Pattern Examples" table is wrong for `Inode` (mode/uid/gid), `MsgQueue` and `SemArray.pending`.

## Ranked findings

| # | Sev | Cat | Where | What |
|---|---|---|---|---|
| 1 | critical | B,E | ipc/sem.rs:63,136-178,639,889 `Sem.semval` | semop check+apply lockless: semval goes negative, multi-sop not atomic, lost wakeup, enqueue on removed array |
| 2 | high (security) | B,E | fs/dac.rs:305-371, fs/inode.rs:430 `Inode.mode/uid/gid` | chmod/chown without i_rwsem; chmod 4755 vs chown root can leave a setuid-root file whose contents the user chose |
| 3 | high | B | cgroup/pids.rs:33-36 `current/max` | pids.max checked at copy_process, charged much later; N concurrent forks overshoot; CLONE_INTO_CGROUP checks the wrong cgroup |
| 4 | high | C,D | hw/usb/xhci.rs:104 `USB_OUTPUT_ACTIVE` | one global recursion flag for a per-holder condition; another CPU clears it, then printk on the holder self-deadlocks on USB_CONTROLLER |
| 5 | high | B | hw/usb/msc.rs:142-144,224 `configured`, `state` | BOT CBW/data/CSW not serialized per device (the lock covers only the tag); concurrent bios interleave the transport |
| 6 | high (arm64) | C | fs/inode.rs:713-720 `Inode.size` | Relaxed; Linux i_size_write/read use release/acquire; a reader can see the new size and stale page bytes |
| 7 | high | B | ipc/mod.rs:92,104 `used_sems`, `shm_tot`; ipc/util.rs ipcget | check-then-add with no ids lock; totals leak permanently when alloc_id fails; duplicate objects with IPC_CREAT\|IPC_EXCL |
| 8 | high | B | fs/misc.rs:1195-1224 (`Inode.size`) | fallocate reads/compares/stores i_size with no i_rwsem; size can go backwards under a concurrent write |
| 9 | medium | B | fs/mount.rs:170-194 `Mount.mnt_flags` | `set_flags` load+store (under s_umount) loses concurrent `mark()` (UNBINDABLE, MNT_LOCKED, under NAMESPACE_SEM) |
| 10 | medium | A,C | task/kcmp.rs:43,54 `COOKIES` | lazily filled on first kcmp, unserialized; torn or overwritten cookies make kcmp(x,x) != 0 |
| 11 | medium | B | keys/key.rs:161 `Key.state` | update's revoked-check, then an unconditional store(Instantiated), resurrects a revoked or invalidated key |
| 12 | medium | B,E | cgroup/mod.rs:95 `Cgroup.nr_tasks` | rmdir is_empty vs attach have no common lock (no cgroup_mutex); orphaned task, ancestors' pids charge leaked |
| 13 | medium | B,E | ipc/msg.rs:95-110 `MsgQueue.*` | stime/lspid/lrpid/ctime set outside the queue lock; IPC_STAT snapshot torn; qbytes changed under perm.lock, read under messages |
| 14 | med-low | B,E | time/mod.rs:114-144 `NTP_STATE` | adjtimex fields are separate stores; ADJ_SETOFFSET read-then-set loses concurrent offsets; TAI read outside the seqlock |
| 15 | medium | B | net/tcp/mod.rs:722,1276-1297 `Sock.shutdown` | TCP shutdown/disconnect set bits outside `cb` from a stale state snapshot |
| 16 | med-low | C | fs/kernfs/mod.rs:141,320-335 `KNode.active` | concurrent deactivate of one node: lost wakeup (hang), or a second remover unlinks without draining |
| 17 | low | B | net/tcp/mod.rs:1100-1129 `TcpSock.connecting` | SS_CONNECTING kept separately from the TCP state; wrong EALREADY/EISCONN under races |
| 18 | low | C | net/netlink/mod.rs:323-325 `NlSock.groups` | bind's load+store of the low 32 bits loses a concurrent ADD/DROP_MEMBERSHIP fetch_or |
| 19 | low | C | fs/superblock.rs:385-400, fs/mount.rs:176-182 | RDONLY set before the writer check; a remount that fails with EBUSY makes racing writers fail EROFS |
| 20 | design | E | net/tcp/cb.rs:121-127 `MEM` | single global atomic on every TCP queue change, fixed 4 MiB limit; Linux uses per-CPU fw_alloc and a RAM-scaled tcp_mem |
| 21 | low | B | time/cpu_timer.rs:83,119,165 `GroupCputimer.active` | gettime starts the cputimer unlocked (Linux gettime never starts it) |
| 22 | latent | B | time/timer.rs:56,130,139 `TimerList.not_before` | stored outside the wheel lock, read under it |
| 23 | latent | B,E | task/workqueue.rs:97,175 `Work.state`, `wake_tick` | already under the item mutex; wake_tick not tied to delayed-list membership |
| 24 | low | B | net/packet/mod.rs:334-339 `PacketSock.bind` | (proto, ifindex) read-then-store |
| 25 | low | B | mm/page_alloc.rs:269-271 `Zone.wmark/min_kb` | separate stores from the sysctl, not under zone.lock |
| 26 | low | C | mm/heap.rs:214 `KernelAlloc.once` | flag swapped before the arena is initialized |
| 27 | low | C | mm/filemap.rs:473-476 `mkclean` (PTE) | load+store loses MMU-set A/D bits; use swap/CAS like change_pte |
| 28 | low (unreachable) | B | cgroup/{io,cpu,memory,freezer}.rs | token bucket, bandwidth, memory charge, frozen_count: check-then-act; no callers yet |
| 29 | low | A,B | block/blkdev.rs:352-423 | `openers`/`open_partitions` only under open_mutex (`Mutex<()>`); `capacity`/`nr_sects` never written; `ro` set once |
| 30 | low | A,C | block/sd.rs:98,169 `ScsiDisk.state` | cancel() is check-then-store, not CAS; the state machine is never driven |
| 31 | low | A | boot-once statics (list below) | Linux `__ro_after_init`; `NR_CPU_IDS` changes 1→n at runtime |
| 32 | low | A,E | hw/virtio/pci.rs:154, hw/virtio/{mod,blk}.rs INDEX, block/sd.rs:326 | features written per probe under Device.lock, undocumented; indexes never recycled (Linux ida) |
| 33 | trivial | C | task/kthread.rs:74 `NEXT_CPU` | load % n, then store; use fetch_add |

Dead atomics, to delete or wire up:
- io_uring SqRing/CqRing fields (7, `allow(dead_code)`)
- `CgroupSubsysState.refcount`, `CssSet.refcount` (the Arc decides lifetime)
- `CgroupRoot.mount_count`

## Detail

### 1. `Sem.semval` — ipc/sem.rs (critical, B/E)
- **Code:** `try_atomic_ops` makes one check pass with separate loads and one apply pass with `fetch_add`, and holds no lock. It runs from the semop fast path (sem.rs:384) and from `wake_pending` (under `pending`), so the two paths are not serialized.
- **Interleavings:**
  1. semval=1, two semop(-1) callers both pass the check and the value ends at -1.
  2. A's try fails, B increments and finds `pending` empty, A then enqueues and sleeps forever (lost wakeup; there is no re-check under the lock).
  3. IPC_RMID drains `pending`, then a semop that already looked the array up enqueues on the dead array.
  4. SETVAL/SETALL (639) and the exit undo (889-891: load, clamp, store) overwrite a concurrent semop.
- **Linux** ipc/sem.c `do_semtimedop`: `sem_lock()` (per-sem spinlock for one simple sop, else `sem_perm.lock` + complex_mode). Under it: `ipc_valid_object`, `perform_atomic_semop`, and the enqueue on pending_alter/pending_const. `exit_sem` and `semctl_setval` are also under `sem_lock`.
- **Fix:** make semval/sempid plain fields in a per-array spin lock (the existing `pending` lock is enough to start). Do check, apply, deleted-check and enqueue under it; wake after unlock. Correct the LOCKING.md §5.4 claim about `SemArray.pending`.

### 2. chmod/chown without i_rwsem — fs/dac.rs (high, security, B/E)
- **Code:** `chmod` (dac.rs:307) runs want_write, `owner_or_capable`, then `set_mode_perm`, then `set_ctime`, with no `inode.lock()`. `chown` (338-371) computes the suid/sgid kill from a mode snapshot, then stores uid, gid and mode separately.
- **Race:**
  - U's chmod 4755 passes the owner check.
  - root's chown reads 0755 (kill = 0) and stores uid = root.
  - U's mode store lands afterwards: a setuid-root binary whose contents U chose.
  - A second window: chmod +s can land between `write_from`'s `remove_privs` and its data copy, because the write holds i_rwsem and chmod does not.
- **Linux** fs/open.c `chmod_common`/`chown_common`: `inode_lock` around `notify_change`, so the permission check, the kill and the id change are one transaction under i_rwsem.
- **Fix:** take `inode.lock()` across the permission check, the mode/id stores and ctime, after want_write. The fields may stay atomics for lockless readers (Linux reads i_mode via READ_ONCE).
- **Doc fixes:**
  - Remove `Inode` mode/uid/gid/nlink from the §5.4 "correct" table; chown changes uid, gid, mode and ctime together.
  - Fix "Inode Timestamp Locking", which claims ctime writers hold i_rwsem.

### 3. `PidsState.current/max` — cgroup/pids.rs (high, B)
- **Code:** `pids_can_fork` (from copy_process, task/percpu.rs:1931) only compares. The charge happens in `attach_task` (task/percpu.rs:2230-2239), much later. N concurrent clones at max-1 all pass the check, so the fork-bomb limit is ineffective.
- **CLONE_INTO_CGROUP:** the limit is checked against the parent's cgroup and the charge goes to the target, so the target's limit is never checked.
- **Linux** kernel/cgroup/pids.c `pids_try_charge`: `atomic64_add_return` at each hierarchy level, with rollback (`pids_cancel`) if any level is over its limit. It is called in `can_fork` on the target cset, with `pids_cancel_fork` on clone failure.
- **Fix:** one add-check-rollback `try_charge` in can_fork on the target. Uncharge on clone failure; `attach_task` must not charge again. The atomics are then correct as atomics.

### 4. `USB_OUTPUT_ACTIVE` — hw/usb/xhci.rs:104,245-252 (high, C/D)
- **Code:** a global bool is set before `USB_CONTROLLER.lock()` and cleared when the guard drops. The condition it stands for ("this CPU holds the controller") is per holder.
- **Interleaving:**
  - CPU A holds the lock. CPU B sets the flag and spins.
  - A drops and clears the flag. B acquires with the flag false.
  - Any printk on B, from code under the lock or from an IRQ on B, enters `UsbSerialConsole::write`, sees the flag false, and `usb_console_out` spins on `USB_CONTROLLER`, which B holds. B self-deadlocks.
  - Also: printk from any context (IRQ included) can take the non-IRQ-safe spin `Mutex` USB_CONTROLLER (category D).
- **Linux** drivers/usb/serial/console.c `usb_console_write`: queues into the port's kfifo under an irqsave spinlock and submits URBs asynchronously; the console path never blocks on the HCD.
- **Fix (minimal):** `usb_console_out` uses `USB_CONTROLLER.try_lock()` and drops the output when the lock is busy. That removes the flag entirely, the same way `BOUNCE` is already `try_lock`.
- **Fix (proper):** an async bulk-out from a console ring that a thread drains.
- Update the USB rows in LOCKING.md (§3.10).

### 5. USB mass storage BOT not serialized — hw/usb/msc.rs (high, B)
- **Code:** `state: Mutex<UsbMscState>` covers only the tag increment. `bot_transfer` then issues CBW, data and CSW as three independent `usb_bulk_*` calls; each takes USB_CONTROLLER only for its own transfer. `ScsiHost::execute` (296-305) configures endpoints check-then-act on `configured`.
- **Effect:** block/sd.rs is bio-based and runs in the submitter's thread with no per-device lock. Two concurrent bios interleave CBW1, CBW2, and so on: a protocol violation, with failed I/O or data landing in the wrong buffer. Endpoints may also be configured twice.
- **Linux** drivers/usb/storage: one command at a time (`can_queue = 1`, `usb_stor_control_thread` under `us->dev_mutex`); endpoints are set up once at probe.
- **Fix:**
  - A sleeping per-device `sync::Mutex<UsbMscState { tag }>` held across the whole BOT transaction.
  - Configure the endpoints at probe and drop `configured`.
  - Document it in LOCKING.md (§3.10 USB/Block).
- **Why it matters:** the Dell target.

### 6. `Inode.size` ordering — fs/inode.rs:713-720 (high on arm64, C)
- **Code:** `set_size`/`get_size` are both Relaxed.
- **Race:**
  - A writer appends into an already-uptodate page: it copies the bytes, `set_uptodate` is a no-op (the flag is already set), then a Relaxed `set_size`.
  - A reader (`mm/filemap.rs:727-745`) sees the new size and acquires PG_uptodate. That flag was set before the copy, so it publishes nothing about the new bytes.
  - The reader returns stale or zero bytes as file content.
- **Linux** include/linux/fs.h: `i_size_write` = `smp_store_release`, `i_size_read` = `smp_load_acquire`. The comment there names exactly this.
- **Fix:** Release/Acquire. Writers already hold i_rwsem.

### 7. IPC namespace totals and ipcget — ipc/mod.rs:92,104; shm.rs:271-277; sem.rs:293-299 (high, B)
- **No lock across ipcget:** nothing covers lookup, limit check and `alloc_id`, so concurrent shmget/semget calls exceed shm_ctlall/semmns. IPC_CREAT|IPC_EXCL on one key can create two objects.
- **Permanent leak:** create adds to the totals before `alloc_id`. If `alloc_id` fails (ENOSPC), the object is dropped without `destroy()`. There is no Drop impl, so the totals leak for good, and repeating this bricks shmget/semget with ENOMEM.
- **Linux** ipc/util.c `ipcget_new`/`ipcget_public`: `down_write(&ids->rwsem)` across lookup, check and `ipc_addid`. `newseg`/`newary` add to shm_tot/used_sems only after `ipc_addid` succeeds.
- **Fix:** hold `IpcIds.inner` (write) across lookup, limit check and insert. Bump the totals after the insert and change them only under the ids lock; they may then be plain fields.

### 8. fallocate i_size — fs/misc.rs:1195-1224 (high, B)
- **Code:** `get_size`, compare, `set_size`, with no i_rwsem, no `want_write`, no filesystem op (so vfat files are affected too) and no `i_swapfile` check.
- **Race:** a write extends the file to 10000 between fallocate's read (100) and its store (200). i_size goes backwards over cached pages.
- **Linux:** `vfs_fallocate` → `->fallocate` (`shmem_fallocate` takes inode_lock).
- **Fix:** under `inode.lock()`, through the filesystem op or `truncate_setsize`.

### 9. `Mount.mnt_flags` — fs/mount.rs:170-194 (medium, B)
- **Code:** `set_flags` loads the KEEP bits and then does `store(f)`; its callers (remount and reconfigure, fs/misc.rs:108-123) hold `s_umount` only. `mark()` uses fetch_or/fetch_and under NAMESPACE_SEM (`change_propagation` sets UNBINDABLE, pnode.rs:172,181; pivot_root and mount set MNT_LOCKED, mount.rs:386,731).
- **Race:** remount,bind,nosuid racing --make-unbindable or MNT_LOCKED wipes the bit. `can_umount` depends on MNT_LOCKED.
- **Linux** fs/namespace.c: every `mnt_flags` write is under `lock_mount_hash()` (`set_mount_attributes`, `change_mnt_propagation`).
- **Fix:** an `IrqSpinlock`/seqlock mount_lock as Linux has, or at minimum a CAS loop in `set_flags`. Add it to the LOCKING.md mount table.

### 10. kcmp cookies — task/kcmp.rs:43,54,168 (medium, A/C)
- **Code:** `init_cookies` does a Relaxed flag check, then stores the pairs non-atomically, then a Release flag store. Readers load the flag with Relaxed.
- **Race:** two first callers write different cookies. One caller can mix A's xor with B's mult, so kcmp(x,x) returns 1 or 2 and orderings are inconsistent (breaks CRIU-style sorting).
- **Linux** kernel/kcmp.c `kcmp_cookies_init`: an `arch_initcall`, immutable afterwards.
- **Fix:** fill at boot or `spin::Once<[[u64;2];8]>`, with plain values.

### 11. `Key.state` — keys/key.rs:161, keys/types.rs:76-79 (medium, B)
- **Code:** `update` checks `is_revoked()`, then `set_payload`, which does `state.store(Instantiated)` unconditionally. A KEYCTL_REVOKE or invalidate between the check and the store is lost.
- **Linux** security/keys/key.c: `key_revoke` and `key_update` both run under `down_write(&key->sem)`. The transition to POSITIVE happens only from UNINSTANTIATED (`__key_instantiate_and_link`, under key_construction_mutex).
- **Fix:**
  - `set_payload` does not touch state.
  - `instantiate` is a CAS from Uninstantiated.
  - revoke, invalidate and update all run under the payload `RwLock` (write), which plays key->sem's role.
  - Document it in LOCKING.md §3.11.

### 12. `Cgroup.nr_tasks` and no cgroup_mutex — cgroup/mod.rs:95 (medium, B/E)
- **Code:** rmdir's `is_empty()` (a lockless nr_tasks load plus the children check) races attach via cgroup.procs; no lock is common to both.
- **Effect:** the task ends up in a cgroup whose css was removed, and its ancestors' pids charge is never uncharged. nr_tasks is redundant: it is always changed under `tasks`, so it equals `tasks.len()`.
- **Linux:** `cgroup_mutex` (`cgroup_kn_lock_live`) for mkdir, rmdir, procs writes and subtree_control; `cgroup_threadgroup_rwsem` for fork vs migrate.
- **Fix:** add both locks. Add them to the LOCKING.md §2 order and §3.11. Drop nr_tasks.

### 13. `MsgQueue` — ipc/msg.rs:95-110,340,378,466-470 (medium, B/E)
- **Code:**
  - cbytes/qnum are changed under `messages` (fine).
  - stime/lspid and rtime/lrpid are stored *after* `try_send`/`take_msg` drop the lock. Two senders can leave lspid naming the earlier one, and IPC_STAT can see the message counted while lspid/stime are still old.
  - IPC_STAT (`fill_msqid64_ds`) reads 8 atomics with no lock: a torn snapshot (qnum from one state, cbytes from another).
  - IPC_SET writes qbytes under `perm.lock`, while `fits` reads it under `messages`, so no lock is common to both. ctime is stored outside both.
  - IPC_SET by a non-root caller silently ignores msg_qbytes. Linux allows lowering it and returns EPERM for raising it above msg_ctlmnb without CAP_SYS_RESOURCE (an ABI bug next to this one).
- **Linux** ipc/msg.c: every q_* field is under `ipc_lock_object(&msq->q_perm)`. `do_msgsnd`/`do_msgrcv` set q_lspid/q_stime and q_lrpid/q_rtime inside it, and `msgctl_stat` copies under it.
- **Fix:**
  - One `MsgState { list, cbytes, qnum, qbytes, stime, rtime, ctime, lspid, lrpid }` inside the `messages` Mutex.
  - The pid and time updates happen in the same critical section as the enqueue or dequeue.
  - The IPC_STAT snapshot is taken under it.
  - Update the LOCKING.md §5.4 row, which currently calls this correct.

### 14. `NTP_STATE` — time/mod.rs:114-144, time/time_syscall.rs:1068-1144 (med-low, B/E)
- **Code:** maxerror, esterror, status, tai, constant and tick are separate Relaxed stores with no lock.
- **Problems:**
  - ADJ_SETOFFSET reads realtime under the seqlock, then calls `set_realtime(cur + off)`, which re-takes the writer lock. Two concurrent +1s calls apply only one second, and the time that elapses between the read and the lock is lost on every call.
  - CLOCK_TAI reads `tai` outside the seqlock.
- **Linux** kernel/time/timekeeping.c `__do_adjtimex`: under `tk_core.lock` (raw spin, irqsave). `timekeeping_inject_offset` applies a relative offset inside the lock. `tai_offset` lives in the timekeeper under its seqcount.
- **Fix:** move the NTP state into TimeKeeper under its lock, add `inject_offset(delta)`, and read TAI inside the seqlock. Document it in LOCKING.md §3.5, which also still lists `read_cycles_fn: AtomicPtr` although the code uses `spin::Once`.

### 15. TCP `Sock.shutdown` — net/tcp/mod.rs:722,1276-1297 (medium, B)
- **Code:** `shutdown()` decides from a `state()` snapshot taken without the lock, then calls `set_shutdown` outside `cb`. `disconnect()` clears the bits after `step` has dropped `cb`. `start_connect` (583) correctly clears them under `cb`, and LOCKING.md says that is the rule.
- **Race:** shutdown(SHUT_WR) racing connect can leave SEND_SHUTDOWN set on a new connection with no FIN sent.
- **Linux:** `inet_shutdown` and `tcp_disconnect` under `lock_sock`.
- **Fix:** do the state test and the set/clear inside `step` (under `cb`).

### 16. kernfs concurrent deactivate — fs/kernfs/mod.rs:320-335 (med-low, C)
- **Code:** `deactivate` runs with no lock and recurses into children from a snapshot.
- **Race:** a second remover of the same node (a parent's removal recursing while the child is removed directly) does `fetch_add(DEACTIVATED)`, so active becomes `i32::MIN + n`. The last `Active` drop then computes a value that is not `DEACTIVATED` and does not wake anyone. The second remover subtracts its bias, again with no wake, so the first remover sleeps forever.
- **Second issue:** the second remover returns at once, and `remove()` unlinks the node while show()/store() may still be running.
- **Also:** a child added after the snapshot is never deactivated.
- **Linux** fs/kernfs/dir.c `__kernfs_remove`: under `kernfs_rwsem` (write); `kernfs_drain` drops it only to wait, and a node already deactivated is skipped while the caller still waits for the drain.
- **Fix:** do deactivation under KERNFS_RWSEM (write) and drop it only for the wait. Every remover waits for the drain, with a wake when active reaches the bias, whoever arrived first.

### 17. `TcpSock.connecting` — net/tcp/mod.rs:1100-1129 (low, B)
- **Code:** the state snapshot, the swap, `start_connect` and `store(true)` are four separate steps.
- **Race:** a non-blocking connect refused quickly can leave `connecting` set on a Closed socket.
- **Linux:** `__inet_stream_connect` under `lock_sock` (`sock->state` + `sk_state`).
- **Fix:** move the field into `Inner` under `cb`.

### 18. `NlSock.groups` — net/netlink/mod.rs:323-325 (low, C)
- **Code:** `bind` does `cur = load` then `store((cur & !low32) | g)`, which loses a concurrent `membership()` fetch_or/fetch_and.
- **Linux** af_netlink.c `netlink_bind`: `netlink_table_grab()` around `netlink_update_subscriptions` and the groups write.
- **Fix:** `fetch_update` (CAS loop), or update under `NlTable.socks` write. The other NlSock atomics are fine:
  - portid is published before bound, both under the table lock.
  - rmem uses the Linux attachskb add/rollback pattern.
  - The flags are independent bits.

### 19. Spurious EROFS on a failed remount — fs/superblock.rs:385-400, fs/mount.rs:176-182 (low, C)
- **Code:** RDONLY is set first, then writers are checked, then the change is backed out on EBUSY. Racing `want_write` calls fail with EROFS although the filesystem never became read-only.
- **Linux:** `mnt_hold_writers` sets MNT_WRITE_HOLD, and `mnt_want_write` spins while it is set and then rechecks.
- **Fix:** add a WRITE_HOLD bit and set RDONLY only on success. LOCKING.md presents the current protocol as correct.

### 20. TCP `MEM` — net/tcp/cb.rs:121-127,1220-1226 (design, E)
- **Code:** one global atomic is hit on every queue change on every CPU, with a fixed 4 MiB ceiling.
- **Linux:** `tcp_memory_allocated` plus per-CPU forward allocation (`tcp_memory_per_cpu_fw_alloc`); `tcp_mem` is sized from RAM.
- **Problems:** it violates the per-CPU rule, and the fixed size is wrong across 512 MB..512 GB.
- **Fix:** per-CPU batched charge with a RAM-scaled limit; document it.

### 21-28. Lower severity
- **21. `GroupCputimer.active`** (time/cpu_timer.rs:119,165): `group_sample` (gettime) starts the cputimer with a lockless load-then-stores. Linux `cpu_clock_sample_group(start=false)` only sums for gettime, and starting happens under siglock. Fix: start only in `arm_group` under `posix_timers`.
- **22. `TimerList.not_before`** (time/timer.rs:56,130,139): stored before the wheel lock is taken, read under it by `run`. A mod_timer racing expiry can fire an ns-armed timer early. Latent: the only `mod_timer_ns` user does not mix the two calls. Fix: set it in `arm()` under `base.wheel` as a plain field.
- **23. `Work.state`/`DelayedWork.wake_tick`** (task/workqueue.rs):
  - Both are already under the item mutex, so they should be plain fields.
  - `wake_tick` is not tied to delayed-list membership, so `mod_delayed_work` on an item already promoted loses the re-delay and leaves the item permanently "timer pending". Latent: `mod_delayed_work` is unused.
  - LOCKING.md (~line 3252) says the item mutex is taken before `inner`, but `promote_delayed` (369, 373) takes it under `inner`; document the actual order.
- **24. `PacketSock.bind`** (net/packet/mod.rs:334-339): the packed (proto, ifindex) word is read and then stored. Linux uses lock_sock + `po->bind_lock`. Fix: a CAS loop.
- **25. `Zone.wmark/min_kb`** (mm/page_alloc.rs:269-271): the sysctl stores them separately. Linux `__setup_per_zone_wmarks` holds `zone->lock`. Fix: store under `Zone.lock`.
- **26. `KernelAlloc.once`** (mm/heap.rs:214): `swap(true)` happens before `arena.init`. Fix: `spin::Once`, or an explicit boot init.
- **27. `mkclean`** (mm/filemap.rs:473-476): the PTE load then `store(wrprotect)` loses hardware-set A/D bits. Fix: swap/CAS, as `change_pte` already does.
- **28. cgroup io/cpu/memory/freezer:**
  - Separate load-then-store refills, consumes and charges. A u64 underflow in io makes the token bucket effectively unlimited.
  - The quota/period pair is torn.
  - frozen_count is wrong under concurrent writes, and two frozen flags exist.
  - Linux equivalents: blk-throttle under `queue_lock`; `cfs_bandwidth.lock`; `page_counter_try_charge` (add, then roll back); `cgroup_freeze` under cgroup_mutex.
  - Unreachable today (no callers). Fix or delete before wiring them up.

### 29. block/blkdev.rs `Disk`/`BlockDevice` (low, A/B)
- **`openers` and `open_partitions`:** changed only under `open_mutex: Mutex<()>`, and read under it too (genhd.rs:277 in rescan). This is a lock over nothing plus atomics beside it. Fix: `open_mutex: sync::Mutex<OpenState { openers, open_partitions }>`. Linux keeps `bd_openers` atomic_t because it is read locklessly, but `open_partitions` is a plain field under open_mutex.
- **`capacity` and `nr_sects`:** never stored after construction (A). Keep them atomic only if resize (Linux `set_capacity`, virtio config change) lands; otherwise use plain u64.
- **`ro`:** set once at probe before add_disk (A until BLKROSET exists).
- **`bsize`:** BLKBSZSET just stores, while Linux `set_blocksize` takes inode_lock + invalidate_lock and syncs/kills the bdev cache. Harmless only while nothing derives cache layout from bsize.
- **Fine:** `dead` (set under open_mutex, read Acquire on the I/O path), `DISKSEQ`, the `Waiter.bio` AtomicPtr (the Completion already orders it) and blk-mq `ctx_maps` (documented, bits set and cleared under the ctx lock).

### 30. `ScsiDisk.state` — block/sd.rs:98,161-187 (low, A/C)
- **Code:** `cancel()` is load, compare, then store, not a CAS. Linux `scsi_device_set_state` runs under `sdev->state_mutex`.
- No caller ever drives cancel, mark_deleted or mark_offline, so the state is constantly Running.
- **Fix:** CAS-based transitions when hot-unplug is wired up; until then, delete the state machine.

### 31. Boot-once statics (low, A)
- **List:** arch/x86_64/fpu.rs `USE_XSAVE`, `XCR0`, `XSTATE_SIZE`, `MXCSR_MASK`; lapic.rs `X2APIC`, `LAPIC_TICKS_PER_MS`; uaccess.rs `SMAP_ON`; multiboot2.rs `INFO_PHYS`; kmap.rs `DIRECT_END` (both arches); aarch64 timer.rs `TIMER_FREQ`/`TICKS_PER_MS`, uaccess.rs `PAN_ENABLED`, dtb.rs `DTB_PHYS`, cache.rs `CTR` (lazily set, idempotent); cpu.rs `NR_CPU_IDS`.
- **Linux:** these are `__ro_after_init` plain variables, set before secondary CPUs start.
- **Assessment:** atomics with Relaxed are sound here (AP start-up orders them), so this is style only. The exception is `NR_CPU_IDS`: it reads 1 until `smp::init`, so any per-CPU array sized from it before then is undersized afterwards. Prefer `Once` (or set nr_cpu_ids before any allocation, like Linux `setup_nr_cpu_ids`) and assert it is never read before being set.
- Per-CPU arch fields (cpu_id, apic_id, is_bsp, self_ptr, stack tops) are also set-once per CPU. They are fine, being accessed through gs/tpidr with no `&mut`.

### 32. virtio — hw/virtio/pci.rs:154, mod.rs:197, blk.rs:303; block/sd.rs:326 (low, A/E)
- **`VirtioDevice.features`:** written by `negotiate` in `virtio_dev_probe` under `Device.lock`, read without a lock by drivers and the sysfs `features` file. Release/Acquire is correct. Linux keeps `vdev->features` as a plain u64 written in `virtio_dev_probe` and read unlocked by `features_show`.
- **Fix:** acceptable as is, but document it in LOCKING.md (device model paragraph: "written under Device.lock at bind, read lockless"). Alternatively return the negotiated set from `negotiate` and hand it to the driver's probe.
- **`INDEX`/`SD_INDEX`:** these are fetch_add counters, while Linux uses `virtio_index_ida`/`sd_index_ida` with `ida_free` on release. A replugged USB disk becomes sdb, sdc, ... where Linux reuses sda; that is user-visible ABI. Fix: an IDA (a bitmap under a spin lock).
- **Fine:** `irqs` stats, `vp_interrupt`.

### 33. `NEXT_CPU` — task/kthread.rs:74 (trivial, C)
- **Code:** load % n, then store.
- **Effect:** two spawns can land on the same CPU; only round-robin quality suffers.
- **Fix:** `fetch_add(1, Relaxed) % n`.

### Checked and fine (in the areas the owner flagged)
- **base/:** `BusType.autoprobe` (independent knob; Linux is a plain bitfield). The rest of base/ is lock-based and matches LOCKING.md.
- **ksysfs/uevent:** `UEVENT_SEQNUM` is a fetch_add per event, exactly Linux `atomic64_inc_return(&uevent_seqnum)` with no lock.
- **kernfs:** `AttrNode.event` and `OpenAttr.event` match Linux `kernfs_open_node.event` / `of->event`. `NEXT_INO` is fine.
- **task/futex.rs:**
  - `waiter_count` uses the Linux futex_hb_waiters pattern, with SeqCst fences at 612 and 654.
  - requeue does dec/inc under both bucket locks.
  - `lock_ptr` follows Linux `q->lock_ptr`.
  - `KeySeq` is a CAS (Linux get_inode_sequence_number).
- **tty/flip.rs `PENDING`:** it is cleared before the flush pass, so no input is lost.
- **kmsg `WAKE_PENDING`, smp.rs `Csd`** (Linux llist + CSD_FLAG_LOCK) and random.rs `BIRTH_NS`/`GENERATION` (Linux base_crng) are fine.
- **e1000 `pending_icr`, virtio-net `config_pending`:** ISR-to-NAPI handoff using fetch_or/swap.
- **Sched, timers and pids** use atomics only as interior mutability under their documented locks. The TimeKeeper and acct seqcounts are correct.
- **NetDevice flags/mtu/promiscuity:** under RTNL.
- **`File.pos`:** under f_pos_lock.
- **`InodeTime` sec/nsec:** the torn pair is documented and matches Linux.
- **user/boot_tester:** ~60 static atomics, all thread or signal-handler handshakes in tests. Appropriate.

## Rules to adopt (proposed additions to LOCKING.md §5.4)

1. **Lock first, atomics second.** An object with a lock keeps its fields as plain data inside that lock. An atomic is justified only by a named lockless reader (cite it in a comment, as Linux's READ_ONCE comments do). Writers still take the lock.
2. **No check-then-act on atomics.** A `load` followed by a `store` or `fetch_*` on a decision path must be one RMW (`fetch_update`/CAS). For limits, use Linux's add-then-rollback (`page_counter_try_charge`, `pids_try_charge`). Anything spanning two fields needs a lock.
3. **No `Mutex<()>` guarding sibling atomics.** Put the protected state inside the Mutex (applies to `open_mutex`, `MsgQueue` and `NlTable`-published fields).
4. **Publication needs Release/Acquire.** Any value whose observation implies other data is visible (i_size, ready flags, pointers) is Release/Acquire. Relaxed is for counters and stats only, with a comment.
5. **Set-once is `Once`, a constructor argument or a boot-time initcall,** not a lazy atomic flag on a hot path (kcmp, heap). Boot globals that are only written before SMP may stay Relaxed atomics, but are documented as `__ro_after_init`-equivalents.
6. **Recursion and ownership guards are per holder.** Record the owner CPU or task in the lock, or use `try_lock`; never use a global bool.
7. **Every shared atomic in LOCKING.md.** Each shared atomic gets a row: writer context and lock, reader context, ordering, and the Linux equivalent. Remove the wrong §5.4 "correct" rows (Inode mode/uid/gid, MsgQueue, SemArray.pending) and the stale §1.6/§3.5 listings.
8. **IDs exposed to userspace use an IDA when Linux does** (device indexes), not a monotonic counter.
9. **Counters hit on every packet or op on every CPU are per-CPU with batching** (tcp MEM), per CLAUDE.md.
