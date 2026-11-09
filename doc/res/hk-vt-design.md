# Linux-equivalent virtual terminals for hk: design and plan

Design and plan for doc/ROADMAP.md phase V; its P0 prerequisites are in phases C (group stop, Ctrl-Alt-Del) and Y (tty and console core). Reference: Linux drivers/tty/vt, drivers/video/fbdev/core/fbcon.c, drivers/video/console/vgacon.c, drivers/input, drivers/hid/usbhid, kernel/printk. Linux semantics are binding: no deviations; anything not yet built is a staged missing feature.

## 0. Constraints
| # | Topic | Rule |
|---|---|---|
| 1 | Early screen output | **Follow Linux**: nothing on the VT before con_init unless earlyprintk=/earlycon= is given; console= rules decide VT printk. Dell and qemu-gfx GRUB configs gain `console=tty0` (+ `earlyprintk=efi` / `earlyprintk=vga`). |
| 2 | Scrollback | **Follow Linux**: none in fbcon; vgacon only within VGA RAM. |
| 3 | Dell keyboard | **USB on a root port**: xHCI interrupt endpoints + HID boot keyboard first; no hub driver now. |
| 4 | arm64 display | **virtio-gpu 2D**, checked outside the gate. |
| 5 | Hangup | **In the prerequisites, before switching (P4)**: vhangup, TIOCVHANGUP, SAK, session-leader exit. |
| 6 | QEMU display flag | **Pin `-vga std`** (x86) in run-qemu.sh and linux-boot-tester.sh (one check-linux cache invalidation). |
| 7 | ttyflip thread | **Per-port flip work** on the new IRQ-safe work items; the thread goes. |
| 8 | ABI version | **Linux 6.8** (the reference VM); newer features (VT_GETCONSIZECSRPOS, bracketed-paste TIOCL) when the reference is upgraded. |
| 9 | Screen tests | **`make check-gfx`**, optional, outside `make gate`, run at phase ends. |
| 10 | Group stop | **In the prerequisites, with hangup**: SIGTSTP/SIGTTOU/SIGTTIN stop the group (Ctrl-Z; real tty_check_change). |
| 11 | Ctrl-Alt-Del | **In P6**: reboot(2) CAD_ON/CAD_OFF + cad_pid + the keyboard trigger. |
| 12 | sysfs + uevent | On the existing sysfs/uevent core: /sys/class/tty (tty0/active + poll), /sys/class/input, uevents for vcs/input nodes are in scope here. |

## 1. Binding Linux behavior; what the reference VMs provide
- Both reference kernels (Ubuntu 6.8 config, target/linux-kernel): VT=y, VT_CONSOLE=y, DUMMY_CONSOLE=y (80x25), FRAMEBUFFER_CONSOLE=y, VGA_CONSOLE=y (x86), INPUT_EVDEV=y, INPUT_UINPUT=y, KEYBOARD_ATKBD=y, SERIO_I8042=y (x86). Modules, so absent in the VM (no modules in initramfs): HID, USB_HID, VIRTIO_INPUT, DRM_VIRTIO_GPU, DRM_BOCHS.
- x86 reference (-nographic keeps QEMU default std VGA): vgacon 80x25 + i8042 AT keyboard, tty0..63, vcs*. arm64 reference: dummycon 80x25, no keyboard; VTs, ioctls, vcs still work. hk must match: VTs always exist (dummycon when no renderer).
- Nodes: tty1..tty63 = (4,1..63), all at boot (console_driver not DYNAMIC_DEV); tty0 (4,0). vcs (7,0), vcsu (7,64), vcsa (7,128) at boot; vcs1/vcsu1/vcsa1 by vcs_init; vcsN/vcsuN/vcsaN N>=2 created in vc_allocate (vcs_make_sysfs), removed in vc_deallocate. /dev/input/eventN (13,64+N); /dev/uinput misc (10,223). devtmpfs default 0600; only (5,0),(5,2) 0666 (tty_devnode); input_devnode only adds "input/".
- /dev/tty0 open: index = fg_console; may become ctty (only /dev/console is noctty).
- console= (kernel/printk/printk.c): each console= appends to console_cmdline; last = preferred. register_console enables a console only if it matches an entry; with no entries, the first console with a tty device is enabled (vt registers first, from con_init). Preferred gets CON_CONSDEV and goes to list head; console_device() = first in list with ->device. Boot consoles unregister when the first CON_CONSDEV non-CON_BOOT console registers. vt console matches "tty" any index; vt_console_device gives VC index-1, fg_console for tty0. arm64: DT stdout-path adds a preferred console (of_console_check) when no console= on cmdline (no cmdline: tty0 and ttyAMA0 both enabled, /dev/console = ttyAMA0). hk's gate cmdlines (console=ttyS0; arm64 none) keep /dev/console on serial: existing tests unchanged.
- vt_console_print: spin_trylock(printing_lock) under console_lock; prints to fg_console or kmsg_redirect VC; nothing unless KD_TEXT; interprets only \n \b \r (no escape parsing).
- Defaults: default_utf8=1 (K_UNICODE, tty IUTF8); blank interval 0; fbcon has no scrollback since 5.9, vgacon only VGA RAM (vc_scrolldelta_helper); K_RAW scancode emulation for non-raw devices only on x86 (arm64 queues the keycode).
- ABI target is Linux 6.8, the reference kernel (rule 8); the 7.3-rc source is read for design, but features newer than 6.8 (VT_GETCONSIZECSRPOS, TIOCL_GETBRACKETEDPASTE) wait until the reference VM is upgraded.

## 2. App-driven ioctl scope (pragmatic subset driven by real apps)
| App | Needs |
|---|---|
| getty/agetty, login, bash | open/ctty ttyN, termios, TIOCGWINSZ, KDGKBMODE (agetty console detection), vhangup (prereq), /proc/consoles |
| vim, less, top (ncurses, terminfo "linux") | CUP, HPA/VPA, EL/ED/ECH, ICH/DCH/IL/DL, DECSTBM, IND/RI, DECSC/RC, SGR 0–107 + 38/48;5 and ;2, ?25h/l, ?1h/l (DECCKM), ?5, ?7, ESC(0/ESC)0 + SO/SI (acs), DSR 6n, DA, OSC P/R palette, ESC[?Nc cursor type; keys ESC[A.., ESC[[A.. F1–F5, ESC[1~.. |
| loadkeys, dumpkeys | KDGKBTYPE, K(G/S)KBENT, K(G/S)KBSENT, K(G/S)KBDIACR(UC), K(G/S)KBMETA, K(G/S)KBMODE |
| setfont | KDFONTOP, PIO/GIO_UNIMAP, PIO_UNIMAPCLR, (G/P)IO_(UNI)SCRNMAP |
| setvtrgb | GIO/PIO_CMAP |
| chvt, openvt, deallocvt, fgconsole | VT_ACTIVATE, VT_WAITACTIVE, VT_OPENQRY, VT_GETSTATE, VT_DISALLOCATE, TIOCL_GETFGCONSOLE |
| setleds | KD(G/S)ETLED, KD(G/S)KBLED |
| showkey | K_RAW / K_MEDIUMRAW |
| kbdrate, setkeycodes | KDKBDREP, KD(G/S)ETKEYCODE |
| setterm | TIOCLINUX blank/unblank, VESA blank |
| logind, Xorg, weston | VT_SETMODE (VT_PROCESS), VT_RELDISP (+VT_ACKACQ), VT_GETMODE, KD(S/G)ETMODE (KD_GRAPHICS), KDSKBMODE K_OFF; evdev EVIOCGRAB, EVIOCG{BIT,NAME,ID,PHYS,UNIQ,PROP,KEY,LED,SW,ABS,VERSION}, EVIOCSCLOCKID, EVIOCG/SREP, EVIOCREVOKE, EVIOCSMASK; plus /sys/class/tty/tty0/active (+ poll) and /sys/class/input + uevents (Phase SYS provides the sysfs/uevent core) |
| Not now | TIOCL selection/paste (gpm), PIO_FONT/GIO_FONT, KDADDIO/KDENABIO (Linux errors), VT_SENDSIG, sysrq, mousedev |

## 3. Module layout (generic outside hw/; spill ~40)
- tty/vt/: mod.rs (globals, CONSOLE_SEM, VC_TABLE, FG_CONSOLE, vc_allocate/deallocate, con_init/vty_init, VT TtyDriver: con_install, open, close, write, stop, start, ioctl, resize); vc.rs (Vc, VcState, scrup/scrdown, insert/delete, csi_J/K, gotoxy, build_attr, cursor, dirty tracking); parse.rs (do_con_write state machine, responses); consolemap.rs, cp437.rs (data); consw.rs (Consw trait, con_driver_map, take_over_console, visual init); dummycon.rs; console.rs (vt ConsoleDriver, pending ring, panic print, kmsg redirect); switch.rs (set_console, change_console, complete_change_console, vt_event, VT_PROCESS handshake, console work); ioctl.rs (vt_ioctl, TIOCLINUX); keyboard.rs (kbd handler, kbd_table, k_handlers, LEDs, diacritics); keymap.rs (defkeymap, func_table, accent_table, KDGKBENT family); vcs.rs; font.rs (P8).
- input/ (new, top level, generic): mod.rs (InputDev, InputHandler, InputHandle, input_event, inject, autorepeat timer, setkeycode), codes.rs (uapi), evdev.rs, uinput.rs.
- gfx/: fb.rs (FbSurface = ScanoutSurface on IoMem), fbcon.rs (generic fb renderer, Linux fbcon.c + bitblit), font.rs (Linux font_desc shape). hw/gfx/console.rs (GfxConsole) deleted.
- arch/x86_64/vgacon.rs becomes a Consw; early output moves to optional earlyprintk=vga boot console.
- hw/input/: i8042.rs (controller + serio, arch io), atkbd.rs (set 2, translated table, LED/typematic).
- hw/usb/: hid.rs (boot keyboard, usage→KEY_* from hid-input.c hid_keyboard[]); interrupt endpoints in xhci.rs/transfer.rs.
- hw/virtio/input.rs (P7, arm64); hw/gfx/virtio_gpu.rs (P9).
- hw/mmio.rs: IoMem::{copy_from_slice, fill16/32, copy_within} (memcpy_toio, memset_io); arch ioremap_wc.

## 4. Data structures
- Tty (P0a): count: AtomicU32 (tty->count); driver + index; flip_queued: AtomicBool; driver default termios (init_termios). VT ttys allocated on first open, leaked to &'static (as USB serial console), found via VT_TTY: [AtomicPtr<Tty>; 63] set once (keyboard IRQ lookup); names from const table.
- TtyDriver gains install(tty) (con_install: alloc VC, winsize, IUTF8), open, close (last close), ioctl -> Option<Result> (None = ENOIOCTLCMD fall-through), resize(ws), stop, start, write_room, init_termios(). tty_ioctl order as Linux: generic, driver->ioctl, ldisc. TIOCSWINSZ → driver.resize (vt_resize → vc_resize).
- Flip work (P0c, decision 7; Linux tty_bufhead.work): each Tty embeds a static IRQ-safe `Work` (flip_work); `flip::receive` queues it (atomic PENDING, no allocation), the worker runs flush_to_ldisc under Tty.buf_lock; the ttyflip thread and `all()` iteration go away.
- Vc (vc_data), Arc<Vc>: num; draw: IrqSpinlock<VcState>; ctl under CONSOLE_SEM: vt_mode {mode, waitv, relsig, acqsig}, vt_pid: Option<Arc<Pid>>, vt_newvt, kd_mode (shadowed in VcState for printk), sw: &'static dyn Consw, port_tty.
- VcState (draw-locked): cols, rows, screen: Vec<u16> (glyph|attr<<8), uni: Option<Vec<u32>>; x, y, need_wrap, top, bottom, saved DECSC; parser state enum (ESnormal, ESesc, ESsquare, ESgetpars, ESfunckey, EShash, ESsetG0, ESsetG1, ESpercent, EScsiignore, ESnonstd, ESpalette, ESosc, ESapc, ESpm, ESdcs), par: [u32; 16], npar, priv; attrs intensity/italic/underline/blink/reverse/color/def_color/ulcolor/halfcolor + saved; G0/G1, charset, disp_ctrl, toggle_meta, utf, utf_count/utf_char; decawm, decom, decscnm, decim, deccm, deccolm, report_mouse, cursor_type; tab_stop: [u32; 8]; palette: [u8; 48]; bell pitch/duration; hi_font_mask; font; unimap: Arc<UniPagedir>; dirty rows bitmap + pending_scroll; can_do_color; kd_graphics.
- Globals: CONSOLE_SEM: sync::Mutex<VtGlobal> (want_console, last_console, saved, con_driver_map, kmsg_redirect, lock_switch, vt_event state); VC_TABLE: IrqSpinlock<[Option<Arc<Vc>>; 63]> written under CONSOLE_SEM, read by try-lock + Arc clone; FG_CONSOLE: AtomicUsize (written under CONSOLE_SEM, read lockless); VT_PRINTK_PENDING: IrqSpinlock<Ring<4096>> + dropped counter ("** N printk messages dropped **").
- Consw: con_startup, con_init(vc, init), con_deinit, con_clear(y,x,count), con_putcs(cells,y,x), con_cursor(enable), con_scroll(top,bot,dir,n)->bool (false: core redraws), con_switch->bool, con_blank, con_font_set/get/default, con_resize, con_set_palette, con_scrolldelta, con_build_attr (opt). Called only with Vc.draw held (startup/init during takeover under CONSOLE_SEM); no allocation in putcs/scroll/clear. con_driver_map[63] under CONSOLE_SEM; do_take_over_console(sw, first, last) re-inits bound VCs, resizes (SIGWINCH via tty_do_resize), redraws fg.
- KBD: IrqSpinlock<Kbd> (kbd_event_lock + func_buf_lock): kbd_table[63] {mode, ledmode, ledflagstate, default_ledflagstate, lockstate, slockstate, modeflags}, shift_state, shift_down[], diacr, dead_key_next, npadch, rep, key_maps: [Option<Box<[u16; 256]>>; 256] (alloc outside lock, swap in, drop after unlock), func_buf: [u8; 512] + offsets, accent_table: [KbDiacrUc; 256], ledstate, ledioctl.
- Input: InputDev (Arc, static per driver): name, phys, uniq, id, propbit, ev/key/led/... bitmaps, key/led state, rep[2], keycode map + setkeycode, event_lock: IrqSpinlock<DevState> (handles, grab, repeat), mutex: sync::Mutex (open count), event: Option<fn(&InputDev, type, code, value)> (driver LED/sound callback, IRQ-safe: atomic + queue work), repeat timer. INPUT_MUTEX: sync::Mutex<Lists>. InputHandler: connect, disconnect, events (under event_lock), filter. Handles: intrusive list of Arc<InputHandle>, add/remove under INPUT_MUTEX → event_lock (no RCU).
- Evdev: minor N; mutex (grab/revoke/open); clients (intrusive, under event_lock); EvdevClient: buf: IrqSpinlock<Ring<input_event>> (size from hint_events_per_packet), clk_type, evmask, revoked, wait.
- uinput: per-open state (setup, bits, Arc<InputDev>) under sleeping mutex; writes → input_event in thread ctx; device events (LED, sound) to a client ring for read().

## 5. Locking (LOCKING.md: new §3.9.x VT, §3.10 Input)
| Lock | Type | Context | Order |
|---|---|---|---|
| CONSOLE_SEM (console_lock) | sync::Mutex<VtGlobal> | thread lock; any ctx incl IRQ try_lock only | below Tty.buf_lock (flip echo → con_write); above Vc.draw, VC_TABLE, KBD, VT_PRINTK_PENDING, TASKLIST/signals (relsig/acqsig, SIGWINCH), Tty.ctrl, allocator, devtmpfs (vcs nodes); never with a spinlock held; OUTPUT_LOCK → CONSOLE_SEM try-only (no edge) |
| Vc.draw | IrqSpinlock | under CONSOLE_SEM; panic try-locks without it | under CONSOLE_SEM; above renderer hw (no locks); bounded chunks (≤512 bytes or one dirty flush) |
| VC_TABLE | IrqSpinlock leaf | written under CONSOLE_SEM; try-lock (printk, panic), lock (thread) | leaf; Arc clone only |
| VT_PRINTK_PENDING | IrqSpinlock leaf | printk any ctx; drained by CONSOLE_SEM holder | leaf; copy out then render |
| KBD (kbd_event_lock) | IrqSpinlock | IRQ (input events), thread (KD ioctls) | under InputDev.event_lock and CONSOLE_SEM; above Tty.flip, waitqueue heads, queue_work (IRQ-safe); never takes event_lock (LED pushes deferred) |
| VT_EVENT | spin Mutex leaf + WaitQueue | thread | under CONSOLE_SEM |
| INPUT_MUTEX | sync::Mutex | thread | outermost input |
| InputDev.mutex, Evdev.mutex, Uinput.mutex | sync::Mutex | thread | INPUT_MUTEX → Uinput.mutex → InputDev.mutex → Evdev.mutex → event_lock |
| InputDev.event_lock | IrqSpinlock | IRQ (i8042, virtio-input), timer (repeat), thread (USB HID, uinput, inject) | under the driver line's IrqDesc.lock/I8042_LOCK; above KBD, EvdevClient.buf, waitqueue heads, queue_work; driver event callback must not sleep |
| EvdevClient.buf | IrqSpinlock leaf | same | → waitqueue head |
| I8042_LOCK | IrqSpinlock | IRQ + thread commands | IrqDesc.lock → I8042_LOCK → event_lock (serio_interrupt under it) |
| HID state | atomics + thread-owned | xHCI event thread | xHCI locks (released) → event_lock |
| Work list (P0c) | IrqSpinlock leaf | any | → waitqueue head |
Rules: IRQ only try-locks CONSOLE_SEM; every Consw call under Vc.draw; signals/alloc/devtmpfs only under CONSOLE_SEM, never draw; Tty.ldata/termios/ctrl never held across con_write. Drain protocol (console_unlock): guard Drop drains VT_PRINTK_PENDING into fg VC under draw, releases, re-checks ring; repeat if non-empty and try_lock succeeds. Delete LOCKING §3.9 "Graphics Console Lock" row and the "Per-TTY locks → GfxConsole.state" order entry with GfxConsole. Globals justified (one keyboard state, screen set, fg console, as Linux); evdev rings per client. CONSOLE_SEM trylock from IRQ is safe with sync::Mutex (me() = NO_TASK; IRQ-safe WaitQueue unlock wake): document in §1.4 as the one try-only IRQ use (down_trylock).

## 6. Data paths
- Output: N_TTY OPOST → con_write → CONSOLE_SEM.lock → per chunk: draw.lock → parse (buffer, dirty/pending scroll) → if fg and KD_TEXT flush via con_putcs/con_scroll + cursor → unlock; guard drop drains printk ring. Coalesce N LFs into one scroll+redraw (fbcon perf). Responses (DSR, DA) → flip::receive(tty) (respond_string).
- printk: OUTPUT_LOCK → VtConsole::write: CONSOLE_SEM.try_lock ok → render (\n \b \r only, KD_TEXT only) on kmsg_redirect or fg, unlock+drain; else push pending ring.
- Panic (OOPS_IN_PROGRESS): skip CONSOLE_SEM (console_flush_on_panic): VC_TABLE.try_lock, clone fg Arc, draw.try_lock (fail → silent), unblank, render, no alloc. direct_serial_write fallback gains console::panic_write_all (try-lock registry, each console's write). All safe Rust.
- Keyboard (IRQ): i8042 IRQ1 → I8042_LOCK → read 0x60 → atkbd → input_event(EV_KEY) → event_lock → handlers. kbd_event → KBD: K_RAW/K_MEDIUMRAW/K_OFF (scancode emulation x86 only via arch const), keymap, shift/lock, LEDs; chars → flip::receive(VT_TTY[fg]) → the tty's flip work → N_TTY. Alt-Fn/Alt-Left/Right/Ctrl-Alt-Fn: WANT_CONSOLE + queue_work(CONSOLE_WORK). LED change: queue_work(KBD_BH) → input_inject_event(EV_LED) per keyboard handle (atkbd event callback queues LED work; HID queues SET_REPORT). Ctrl-Alt-Del: queue_work(CAD) → reboot CAD_ON: emergency restart, CAD_OFF: SIGINT to cad_pid (P6, decision 11). SAK, Scroll-Lock show_*, sysrq staged. evdev_event → each client ring + wake (grab: exclusive; kbd handler sees nothing).
- Switch: console_callback work: CONSOLE_SEM → change_console(new); old VC VT_PROCESS: relsig to vt_pid (kill_pid; dead pid → VT_AUTO + complete), else vt_newvt and wait for VT_RELDISP. complete_change_console: KD_GRAPHICS no redraw; redraw_screen (con_switch); FG_CONSOLE; kbd LEDs; acqsig if VT_PROCESS; vt_event SWITCH; wake VT_WAITACTIVE. VT_ACTIVATE = set_console + work; VT_WAITACTIVE = interruptible wait on vt_event queue.

## 7. Boot ordering
1. Pre-heap: no screen console, buffered in kmsg LOG; earlyprintk=vga (x86) / earlyprintk=efi / earlycon=efifb / earlycon=pl011 register minimal vgacon/efifb writers as CON_BOOT (rule 1; without them the screen stays blank until con_init, as Linux). Serial ttyS0/ttyAMA0 register as real consoles, enabled per console= rules.
2. Post-heap (kmain phase 1, console_init): vt::con_init() picks startup Consw (vgacon if multiboot2 fb tag EGA text, or no tag and 0xB8000 probe ok; else dummycon); allocs VC1; registers vt console (PRINTBUFFER replay from console seq); boot consoles drop per CONSDEV rule.
3. init_tty_chardevs: tty0, tty1..63, vcs, vcsa, vcsu, vcs1....
4. After fb discovery + ioremap_wc (where GfxConsole init is today): fbcon registers, do_take_over_console(fbcon, 0, 62); VCs resize to fb cols×rows (TIOCGWINSZ change, SIGWINCH), redraw.
5. Input core, then i8042, xHCI HID, virtio-input probes, then kbd/evdev connect.
DRM: simplegfx shares fb with fbcon; fbcon draws only while fg VC KD_TEXT; KD_TEXT transition or DRM master drop/lastclose → redraw (drm_fb_helper_restore).

## 8. Unsafe / MMIO
fb = IoMem from ioremap_wc; vgacon IoMem over 0xB8000 (ioremap) instead of phys_to_virt raw pointers → FbSurface and vgacon unsafe-free, TODO(unsafe) allows removed. Bulk ops in hw/mmio.rs with SAFETY. Port I/O via arch wrappers. No refs into device memory.

## 9. Testing (io/vt.rs, input.rs; hk + Linux reference; geometry from vcsa header)
- VT_NODES: stat tty0 (4,0), tty1, tty63, vcs/vcsa/vcsu, vcs1 (7,x) + modes; vcs2 appears after opening tty2, gone after VT_DISALLOCATE.
- VT_IOCTLS: KDGKBTYPE = KB_101 on tty0, ENOTTY on ttyS0/ttyAMA0 (confirm on Linux); VT_GETSTATE (v_active=1, v_state); VT_OPENQRY; TIOCL_GETFGCONSOLE; KDGKBMODE = K_UNICODE, KDSKBMODE round trip, EINVAL bad; KD(G/S)ETMODE; KD(G/S)ETLED, KD(G/S)KBLED; KDGKBENT defaults + KDSKBENT round trip; KDGKBSENT F1 = "\e[[A"; VT_DISALLOCATE EBUSY while open, 0 when free, VC1 never freed; TIOCGWINSZ on tty2 = vcsa header.
- VT_SWITCH: VT_ACTIVATE 2 + VT_WAITACTIVE; /dev/vcs (minor 0) follows fg; back. VT_PROCESS: child VT_SETMODE relsig=SIGUSR1 acqsig=SIGUSR2 on tty2, activates; parent activates 1; child gets SIGUSR1, VT_RELDISP 1; parent WAITACTIVE returns; refusal (VT_RELDISP 0), VT_ACKACQ.
- VT_ESC (write tty2, read /dev/vcsa2, vcsu2): clear/home, text, SGR attrs (bold, reverse, 30–37/40–47, 90–107, 38;5), CUP, EL, ED, ECH, ICH, DCH, IL, DL, DECSTBM, IND/RI, DECSC/RC, autowrap, tabs (HTS, TBC), ESC(0 'q' → vcs 0xC4 / vcsu U+2500, UTF-8 "é" → vcs 0x82 / vcsu U+00E9, DSR 6n and DA responses read back, vcsa2 write read-back.
- INPUT (uinput, both arches): create "hk-test-kbd", find eventN by scanning EVIOCGNAME (numbering differs: Linux x86 also has AT kbd, power button, mouse); EVIOCGVERSION/GID/GBIT, event reads, SYN_REPORT shape, EVIOCGRAB.
- KBD (uinput → VT1 fg, tty1 raw termios): KEY_A 'a', Shift+A 'A'; K_MEDIUMRAW keycode; K_RAW 0x1e/0x9e x86, keycode arm64; K_OFF drops; EVIOCGRAB starves tty; Alt+F2 switches (VT_WAITACTIVE); KDSETLED → EV_LED on uinput fd; never Ctrl-Alt-Del.
- QEMU flags: `-vga std` pinned on x86 in both run scripts (rule 6, P0g).
- Renderer (hk only): `make check-gfx`, outside `make gate`, run at phase ends (rule 9): qemu-gfx GRUB (gfxpayload=keep, console=tty0), monitor screendump vs golden images (vgacon, fbcon, virtio-gpu), usb-kbd + monitor sendkey through the HID path; plus an in-kernel selftest (fbcon glyph (0,0) vs font).

## 10. Dell OptiPlex 3020
UEFI GOP fb (gfxpayload=keep) → BOOT_FRAMEBUFFER → fbcon, ~1920x1080 = 240x67; WC mapping essential (UC full redraws tens of ms). GRUB entry (~/tmp/hk-optiplex.iso config) gains `console=tty0 earlyprintk=efi` (rule 1). Keyboard: USB on a root port (rule 3); the xHCI BIOS handoff ends SMM PS/2 emulation, so it needs xHCI interrupt endpoints + HID boot protocol (SET_PROTOCOL 0, SET_IDLE, 8-byte reports, hid_keyboard[] map, input-core autorepeat, LED SET_REPORT). UEFI boot means IOAPIC/MSI (HADL plan H0) precedes Dell keyboard bring-up for interrupt delivery.

## 11. aarch64
QEMU virt: no display by default → dummycon. P9: virtio-gpu 2D (rule 4; resource create, attach backing, set scanout, transfer_to_host, flush; fbcon damage/flush hook like deferred I/O; also x86; seeds DRM for weston). Keyboard: USB HID first (shared with Dell, QEMU usb-kbd), then virtio-input (small; evdev-format events). Linux reference has none (modules) → tests use dummycon + uinput.

## 12. Phased plan (each item a bisectable gate-passing commit; LOCKING/BUGS same commit)
P0 Prerequisites (ROADMAP C and Y; with hangup and group stop; highest blast radius)
- 0a Tty core: Tty.count + CharDevice release; TtyDriver ops (install, close, ioctl fall-through, resize, stop, start, init_termios) on both serial drivers; leaked dynamic ttys (flip input moves to per-port work in 0c). Tests: existing tty. LOCKING: flip list.
- 0b Console core: port register_console (console_cmdline, preferred, CON_CONSDEV ordering, default enable, name+index match, device() -> (tty, index)); console_device → /dev/console; ttyS0 a real console; arm64 of_console_check (stdout-path); per-console kmsg-seq replay (PRINTBUFFER) replacing global `flushed`; /proc/consoles; earlyprintk/earlycon boot consoles from current vgacon/GfxConsole writers. Tests: CONSOLE_PROC, STDIO_CONSOLE_FDS. LOCKING §3.6/§3.9.
- 0c IRQ-safe deferred work: static Work, atomic PENDING + intrusive list, no alloc; ttyflip becomes per-port flip work on it (rule 7). LOCKING §3.1.
- 0d IoMem bulk ops, ioremap_wc (x86 PAT WC, arm64 Normal-NC), FbSurface on IoMem.
- 0e Hangup (rule 5): __tty_hangup (vhangup, TIOCVHANGUP, SAK, session-leader exit, carrier loss): hung-up file ops (EIO reads/writes, POLLHUP), SIGHUP/SIGCONT, ctty clear; per-process ctty (TIOCNOTTY by non-leaders). Tests on hk + Linux (vhangup then read EIO, TIOCVHANGUP, leader exit SIGHUP). Removes the BUGS "No hangup" and "Per-process controlling tty" items.
- 0f Group stop (rule 10): stop/continue of thread groups (SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU default action, SIGCONT, WUNTRACED/WCONTINUED in wait4/waitid, CLD_STOPPED/CLD_CONTINUED to the parent, orphaned-pgrp rules), tty_check_change stops instead of EIO. Tests on hk + Linux (Ctrl-Z-equivalent kill -TSTP, waitpid WUNTRACED, SIGCONT, background read SIGTTIN stops). Removes the BUGS group-stop items (TTY gaps, ptrace stop gaps where shared).
- 0g Pin `-vga std` in run-qemu.sh and linux-boot-tester.sh (rule 6), with a probe test of the VT environment on both kernels.
P1 VT core + dummycon (deps P0): skeleton (Vc, VcState, CONSOLE_SEM, VC_TABLE, FG_CONSOLE, dummycon, con_init); VT TtyDriver (tty1..63 chardevs/nodes, tty0 Redirect, con_install/vc_allocate, winsize, IUTF8); con_write C0 (BS, HT, LF, VT, FF, CR, BEL, SO, SI) + scroll; vt ConsoleDriver + pending ring + drain, console=tty0/ttyN; KDGKBTYPE, VT_GETSTATE, VT_OPENQRY. Tests VT_NODES, basic VT_IOCTLS. LOCKING §3.9.1. BUGS: "No virtual terminals" → "no renderer/input".
P2 Parser, consolemap, vcs (deps P1): ESC/CSI core; SGR + build_attr + palette OSC; G0/G1 + consolemap + cp437 unimap + UTF-8 (width, replacement); responses (DSR, DA, cursor report); /dev/vcs, vcsa, vcsu read/write/poll + node create/delete. Tests VT_ESC.
P3 Renderers (deps P2, 0d): Consw dispatch + dirty-row batching; vgacon Consw (CRTC cursor, hw attrs, VRAM-bounded scrolldelta); fbcon Consw (bitblit, cursor, palette → pixel format, takeover, resize; no scrollback, rule 2); remove GfxConsole + console-role VgaCon; panic path. Tests: suite + fbcon selftest; `make check-gfx` at phase end, outside the gate (rule 9). LOCKING: drop GfxConsole rows.
P4 Switching + mode ioctls (deps P1, 0c, 0e; /sys/class/tty/tty0/active): set_console/change_console work, VT_ACTIVATE/WAITACTIVE/SETACTIVATE/WAITEVENT, VT_SETMODE/GETMODE/RELDISP (signals, dead-pid reset), KD(S/G)ETMODE (stop drawing, printk suppression), VT_DISALLOCATE, VT_RESIZE/RESIZEX, VT_LOCK/UNLOCKSWITCH, TIOCLINUX subset (6, 10, 11, 12, 13, 14, 17; 4 unblank), permission (ctty or CAP_SYS_TTY_CONFIG). Tests VT_SWITCH.
P5 Input core, evdev, uinput (deps 0c; parallel to P1–P4): input/ core + autorepeat + setkeycode; /sys/class/input + uevents; evdev full EVIOC* subset, clock ids, grab, revoke, mask; misc major 10 + /dev/uinput (legacy + UI_DEV_SETUP, UI_GET_SYSNAME). Tests INPUT. LOCKING §3.10.
P6 Keyboard handler (with defkeymap/accent data; deps P4, P5): kbd handler, all k_handlers (self, fn, spec, pad, dead, cons, cur, shift, meta, ascii, lock, lowercase, slock, dead2, brl), four modes, unicode, diacritics; KD(G/S)KBENT, KD(G/S)KBSENT, KD(G/S)KBDIACR(UC), KD(G/S)KBMETA, KD(G/S)KBLED, KD(G/S)ETLED, K(G/S)KBMODE, KD(G/S)ETKEYCODE, KDKBDREP, KDSIGACCEPT; LED work; Alt-Fn; Ctrl-Alt-Del with reboot(2) CAD_ON/CAD_OFF + cad_pid (SIGINT to init) (rule 11). Tests KBD, REBOOT_CAD (hk + Linux: reboot(CAD_OFF) as root returns 0).
P7 Keyboard hw, Dell first (rule 3): xHCI interrupt endpoints + event thread; USB HID boot keyboard (QEMU usb-kbd); i8042 + atkbd (the x86 reference VM has an AT keyboard); virtio-input. No hub driver (BUGS). QEMU sendkey/usb-kbd checks in check-gfx.
P8 Fonts/maps: KDFONTOP (fbcon width ≤32, 256/512 glyphs; vgacon plane-2), PIO/GIO_UNIMAP, UNIMAPCLR, (G/P)IO_(UNI)SCRNMAP, GIO/PIO_CMAP, VT_GETHIFONTMASK, KIOCSOUND/KDMKTONE (pcspkr input dev x86, no-op otherwise as Linux). Round-trip tests.
P9 Display: virtio-gpu 2D (rule 4; arm64 and x86; fbcon damage/flush hook), checked in check-gfx, not the gate.
Staged (BUGS.md, missing features): sysrq, selection/gpm, blanking timer, mousedev, USB hub driver, ptys (xterm/ssh, not VTs), VT ABI newer than Linux 6.8 (rule 8).

## 13. Prerequisite gaps found elsewhere (and where they are handled)
TTY: no open count (P0a), no hangup (P0e, ROADMAP Y); flip thread iterates only serial ttys (per-port work, P0c). queue_work not IRQ-safe (allocates, spin Mutexes) (P0c). No WC ioremap; GfxConsole/VgaCon raw pointers (P0d). Console core: console= only raises priority (not enable/preferred), serial is a BOOT console, no per-console replay, no /proc/consoles, no DT stdout-path (P0b, ROADMAP Y). reboot(2) no CAD_ON/OFF (P6, ROADMAP C). No misc major registry for uinput (P5). USB: no interrupt transfer submission and no HID driver (the endpoint contexts exist; P7); no hub driver (staged, BUGS.md). Signals: no group stop (P0f, ROADMAP C). Interrupt routing: IOAPIC/MSI for the Dell (HADL H0, ROADMAP D).
