//! boot_tester2 - Minimal execve validation program
//!
//! This program is executed by boot_tester via execve() to verify
//! that exec works correctly. It prints some diagnostic info and
//! exits with status 123, which the parent process validates.
//!
//! `boot_tester2 fdcheck`: exit 0 if fd 10 is closed (it was
//! close-on-exec) and fd 11 is open, else a nonzero code.
//! `boot_tester2 auxv`: exit 0 if the initial stack and auxiliary
//! vector are what the Linux ELF loader provides, else the failed check.
//! `boot_tester2 exe`: exit 0 if /proc/self/exe names this program.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

use hk_syscall::{
    sys_exit, sys_fcntl, sys_getegid, sys_geteuid, sys_getgid, sys_getpid, sys_getppid, sys_getuid,
    sys_readlink, sys_write,
};

/// Print a string to stdout
fn print(s: &[u8]) {
    sys_write(1, s.as_ptr(), s.len() as u64);
}

/// Print a string followed by newline
fn println(s: &[u8]) {
    print(s);
    print(b"\n");
}

/// Print a number in decimal
fn print_num(n: i64) {
    if n < 0 {
        print(b"-");
        print_num(-n);
        return;
    }
    if n >= 10 {
        print_num(n / 10);
    }
    let digit = b'0' + (n % 10) as u8;
    sys_write(1, &digit as *const u8, 1);
}

/// Process entry: pass the initial stack pointer (argc, argv...) on
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor ebp, ebp",
        "mov rdi, rsp",
        "and rsp, -16",
        "call {main}",
        "ud2",
        main = sym rust_start,
    )
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov x29, xzr",
        "mov x30, xzr",
        "mov x0, sp",
        "bl {main}",
        "brk 0",
        main = sym rust_start,
    )
}

/// argv[1] as bytes (without NUL), if present
fn arg1(sp: *const u64) -> &'static [u8] {
    unsafe {
        if *sp < 2 {
            return b"";
        }
        let p = *sp.add(2) as *const u8;
        // volatile: a plain loop becomes a strlen call (no libc here)
        let mut n = 0;
        while n < 64 && core::ptr::read_volatile(p.add(n)) != 0 {
            n += 1;
        }
        core::slice::from_raw_parts(p, n)
    }
}

/// fdcheck mode: fd 10 must be gone after exec, fd 11 must remain
fn fdcheck() -> ! {
    const F_GETFD: i32 = 1;
    const EBADF: i64 = -9;
    if sys_fcntl(10, F_GETFD, 0) != EBADF {
        sys_exit(1);
    }
    if sys_fcntl(11, F_GETFD, 0) != 0 {
        sys_exit(2);
    }
    sys_exit(0);
}

/// NUL-terminated string at `p` equals `want`
fn cstr_is(p: u64, want: &[u8]) -> bool {
    if p == 0 {
        return false;
    }
    let p = p as *const u8;
    for (i, &c) in want.iter().chain(&[0]).enumerate() {
        if unsafe { core::ptr::read_volatile(p.add(i)) } != c {
            return false;
        }
    }
    true
}

/// Value of auxv entry `key`, if present
fn aux(auxv: *const u64, key: u64) -> Option<u64> {
    let mut p = auxv;
    unsafe {
        while *p != 0 {
            if *p == key {
                return Some(*p.add(1));
            }
            p = p.add(2);
        }
    }
    None
}

/// auxv mode: check the initial process stack (Linux create_elf_tables)
fn auxv_check(sp: *const u64) -> ! {
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_ENTRY: u64 = 9;
    const AT_UID: u64 = 11;
    const AT_EUID: u64 = 12;
    const AT_GID: u64 = 13;
    const AT_EGID: u64 = 14;
    const AT_PLATFORM: u64 = 15;
    const AT_HWCAP: u64 = 16;
    const AT_SECURE: u64 = 23;
    const AT_RANDOM: u64 = 25;
    const AT_EXECFN: u64 = 31;
    const PT_LOAD: u32 = 1;
    #[cfg(target_arch = "x86_64")]
    const PLATFORM: &[u8] = b"x86_64";
    #[cfg(target_arch = "aarch64")]
    const PLATFORM: &[u8] = b"aarch64";

    // The ABI's initial stack pointer is 16-byte aligned
    if sp as u64 % 16 != 0 {
        sys_exit(10);
    }
    let argc = unsafe { *sp } as usize;
    let envp = unsafe { sp.add(1 + argc + 1) };
    let mut p = envp;
    while unsafe { *p } != 0 {
        p = unsafe { p.add(1) };
    }
    let auxv = unsafe { p.add(1) };
    let get = |k| aux(auxv, k).unwrap_or(u64::MAX);
    if get(AT_PAGESZ) != 4096 {
        sys_exit(11);
    }
    if get(AT_ENTRY) != _start as *const () as u64 {
        sys_exit(12);
    }
    if get(AT_PHENT) != 56 || get(AT_PHNUM) == 0 || get(AT_PHNUM) > 64 {
        sys_exit(13);
    }
    // AT_PHDR points at this program's headers: one of them is PT_LOAD
    let phdr = get(AT_PHDR);
    let has_load = phdr != u64::MAX
        && (0..get(AT_PHNUM))
            .any(|i| unsafe { core::ptr::read_volatile((phdr + i * 56) as *const u32) == PT_LOAD });
    if !has_load {
        sys_exit(14);
    }
    let r = get(AT_RANDOM);
    let bytes = unsafe { core::ptr::read_unaligned(r as *const u128) };
    if r == u64::MAX || bytes == 0 {
        sys_exit(15);
    }
    let ids = [
        (AT_UID, sys_getuid()),
        (AT_EUID, sys_geteuid()),
        (AT_GID, sys_getgid()),
        (AT_EGID, sys_getegid()),
    ];
    if ids.iter().any(|&(k, v)| get(k) != v as u64) || get(AT_SECURE) != 0 {
        sys_exit(16);
    }
    if !cstr_is(get(AT_EXECFN), b"/bin/boot_tester2") {
        sys_exit(17);
    }
    if !cstr_is(get(AT_PLATFORM), PLATFORM) {
        sys_exit(18);
    }
    if aux(auxv, AT_HWCAP).is_none() {
        sys_exit(19);
    }
    sys_exit(0);
}

/// exe mode: /proc/self/exe is the executed file
fn exe_check() -> ! {
    let mut buf = [0u8; 64];
    let n = sys_readlink(
        b"/proc/self/exe\0".as_ptr(),
        buf.as_mut_ptr(),
        buf.len() as u64,
    );
    let want = b"/bin/boot_tester2";
    // byte loop: a slice compare becomes a bcmp call (no libc here)
    let ok = n == want.len() as i64
        && (0..want.len()).all(|i| unsafe { core::ptr::read_volatile(&buf[i]) } == want[i]);
    sys_exit(if ok { 0 } else { 1 });
}

extern "C" fn rust_start(sp: *const u64) -> ! {
    match arg1(sp) {
        b"fdcheck" => fdcheck(),
        b"auxv" => auxv_check(sp),
        b"exe" => exe_check(),
        _ => {}
    }

    // Print marker that we're running in boot_tester2
    println(b"EXEC_CHILD: Hello from boot_tester2!");

    // Print our PID
    let pid = sys_getpid();
    print(b"EXEC_CHILD: My PID is ");
    print_num(pid);
    println(b"");

    // Print our parent PID
    let ppid = sys_getppid();
    print(b"EXEC_CHILD: My parent PID is ");
    print_num(ppid);
    println(b"");

    // Exit with magic exit code 123 so parent can verify
    println(b"EXEC_CHILD: Exiting with status 123");
    sys_exit(123);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    println(b"PANIC in boot_tester2!");
    sys_exit(1);
}

// Compiler intrinsics required for no_std
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    unsafe {
        let mut i = 0;
        while i < n {
            *d.add(i) = c as u8;
            i += 1;
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    unsafe {
        let mut i = 0;
        while i < n {
            *d.add(i) = *s.add(i);
            i += 1;
        }
    }
    dest
}
