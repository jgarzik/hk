# hk: what systemd needs (the milestone after sysvinit)

Research for booting Debian 13 (trixie: kernel 6.12, systemd 257) with
systemd, from 2026-10-14; re-verify each item against the tree and
systemd's sources before scheduling. hk already has tmpfs, devtmpfs,
sysfs, cgroup2, /proc mountinfo, NETLINK_KOBJECT_UEVENT, openat2,
memfd_create, close_range and name_to_handle_at.

## Must have
- devpts (ROADMAP H).
- The new mount API: fsopen, fsconfig, fsmount, move_mount, open_tree,
  mount_setattr (systemd and libmount use it when present).
- autofs4 (automount units).
- Swap on a block device by unit; vfat ESP mounted by UUID; GPT
  PARTUUID lookup.
- cgroup2 as systemd 257 uses it (delegation, controllers per subtree):
  check what fails today, since a cgroup error is fatal in practice.

## Optional (units skip a missing mount point: never create stub
directories for them)
mqueue, configfs, debugfs, tracefs, securityfs, pstore, fusectl,
hugetlbfs, bpf, efivarfs, binfmt_misc.

## Not useful
Debian's stock initramfs needs zstd and modprobe: build hk's own.
ext4 root (metadata_csum, 64bit, orphan_file, journal) comes after the
tmpfs root.

## To re-verify
serial-getty conditions, tmp.mount (/tmp is tmpfs in trixie), which
cgroup2 failures are fatal.
