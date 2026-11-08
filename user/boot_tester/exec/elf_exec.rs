//! execve of malformed ELF files written at runtime: the loader must
//! reject them like Linux's binfmt_elf and the kernel must survive.

use crate::harness::fail_num;
use crate::helpers::{print, println};
use hk_syscall::{
    O_CREAT, O_TRUNC, O_WRONLY, sys_close, sys_execve, sys_exit, sys_fork, sys_open, sys_unlink,
    sys_wait4, sys_write,
};

#[cfg(target_arch = "x86_64")]
const EM: u16 = 62;
#[cfg(target_arch = "aarch64")]
const EM: u16 = 183;

const PATH: &[u8] = b"/elf_bad\0";
const BAD_INTERP: &[u8] = b"/elf_bad_interp\0";
const HUGE_INTERP: &[u8] = b"/elf_huge_interp\0";
const FIXED_INTERP: &[u8] = b"/elf_fixed_interp\0";
const LEN: usize = 0x2000;

/// How Linux treats the file
#[derive(Clone, Copy)]
enum Want {
    /// execve returns this errno
    Errno(i64),
    /// After the point of no return: Linux kills the task with
    /// SIGSEGV, hk rejects it earlier with this errno; either passes
    Fatal(i64),
    /// hk rejects it with this errno; Linux runs into whatever it mapped
    /// and dies of some signal; either passes
    Dies(i64),
    /// The program runs and exits with this code
    Runs(i64),
}

pub fn run_tests() {
    // An executable file that is not ELF, for ELF_EXEC_BAD_INTERP
    let fd = sys_open(BAD_INTERP.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    sys_write(fd as u64, [b'x'; 128].as_ptr(), 128);
    sys_close(fd as u64);
    // Interpreters that cannot be placed
    write_interp(HUGE_INTERP, |f| {
        set16(f, 16, 3); // ET_DYN
        set64(f, 64 + 40, 0x7fff_ffff_0000); // p_memsz
    });
    write_interp(FIXED_INTERP, |_| {}); // ET_EXEC at the program's address
    let cases: [(&[u8], fn(&mut [u8]) -> usize, Want); 12] = [
        (b"ELF_EXEC_TRUNCATED", |_| 20, Want::Errno(8)),
        (
            b"ELF_EXEC_BAD_MACHINE",
            |f| set16(f, 18, 0xbeef),
            Want::Errno(8),
        ),
        (
            b"ELF_EXEC_BAD_PHENTSIZE",
            |f| set16(f, 54, 32),
            Want::Errno(8),
        ),
        (
            b"ELF_EXEC_HUGE_PHNUM",
            |f| set16(f, 56, 0xffff),
            Want::Errno(8),
        ),
        (
            b"ELF_EXEC_PHOFF_PAST_EOF",
            |f| set64(f, 32, 0x1fe0),
            Want::Errno(8),
        ),
        (b"ELF_EXEC_MISSING_INTERP", missing_interp, Want::Errno(2)),
        // Linux load_elf_binary: an interpreter that is not ELF
        (b"ELF_EXEC_BAD_INTERP", bad_interp, Want::Errno(80)),
        // An interpreter spanning more than the address space below
        // mmap_base: ENOMEM on hk; Linux fails mapping it after the point
        // of no return (SIGSEGV)
        (
            b"ELF_EXEC_INTERP_HUGE",
            |f| with_interp(f, HUGE_INTERP),
            Want::Dies(12),
        ),
        // A fixed-address interpreter on top of the program: refused on
        // hk; Linux maps it over the program (MAP_FIXED) and the result
        // dies
        (
            b"ELF_EXEC_INTERP_OVERLAP",
            |f| with_interp(f, FIXED_INTERP),
            Want::Dies(22),
        ),
        (
            b"ELF_EXEC_FILESZ_GT_MEMSZ",
            |f| set64(f, 64 + 40, 0x100),
            Want::Fatal(22),
        ),
        // A PT_LOAD over the stack: Linux's MAP_FIXED_NOREPLACE fails
        // (EEXIST) after the point of no return
        (b"ELF_EXEC_STACK_OVERLAP", on_stack, Want::Fatal(17)),
        // PT_LOADs out of address order run, every page in a VMA
        (b"ELF_EXEC_UNSORTED", unsorted, Want::Runs(42)),
    ];
    for (name, mutate, want) in cases {
        let mut f = [0u8; LEN];
        valid(&mut f);
        let len = mutate(&mut f);
        check(name, &f[..len], want);
    }
    large_files();
}

/// Size of the large files: far more than an exec ever reads of them
const BIG: usize = 8 << 20;

/// exec reads only what it needs of a file: a large non-ELF file and a
/// large ELF whose header table lies past its end are ENOEXEC, and
/// exec still works afterwards
fn large_files() {
    let mut f = [0u8; LEN];
    check_big(b"ELF_EXEC_LARGE_NOT_ELF", &f[..64], Want::Errno(8));
    valid(&mut f);
    set64(&mut f, 32, BIG as u64 + 0x1000); // phoff past EOF
    check_big(b"ELF_EXEC_LARGE_TRUNCATED", &f[..64], Want::Errno(8));
    exec_still_works();
    sys_unlink(BAD_INTERP.as_ptr());
    sys_unlink(HUGE_INTERP.as_ptr());
    sys_unlink(FIXED_INTERP.as_ptr());
}

/// `head` followed by zeros up to BIG bytes, exec'd as in `check`
fn check_big(name: &[u8], head: &[u8], want: Want) {
    static ZERO: [u8; 65536] = [0; 65536];
    let fd = sys_open(PATH.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    let mut ok =
        fd >= 0 && sys_write(fd as u64, head.as_ptr(), head.len() as u64) == head.len() as i64;
    let mut left = BIG - head.len();
    while ok && left > 0 {
        let n = left.min(ZERO.len());
        ok = sys_write(fd as u64, ZERO.as_ptr(), n as u64) == n as i64;
        left -= n;
    }
    if fd >= 0 {
        sys_close(fd as u64);
    }
    if !ok {
        print(name);
        println(b":FAIL write");
        sys_unlink(PATH.as_ptr());
        return;
    }
    run(name, want);
}

/// A following fork + exec of a real program still succeeds
fn exec_still_works() {
    let pid = sys_fork();
    if pid == 0 {
        let path = b"/bin/busybox\0";
        let argv: [*const u8; 3] = [b"busybox\0".as_ptr(), b"true\0".as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        sys_execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(127);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    print(b"ELF_EXEC_AFTER_LARGE");
    if st == 0 {
        println(b":OK");
    } else {
        fail_num(b":FAIL wstatus=", st as i64);
    }
}

fn set16(f: &mut [u8], at: usize, v: u16) -> usize {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
    LEN
}

fn set64(f: &mut [u8], at: usize, v: u64) -> usize {
    f[at..at + 8].copy_from_slice(&v.to_le_bytes());
    LEN
}

/// Program header `i`: type, then [offset, vaddr, filesz, memsz, align]
fn phdr(f: &mut [u8], i: usize, kind: u32, v: [u64; 5]) {
    let p = 64 + i * 56;
    f[p..p + 4].copy_from_slice(&kind.to_le_bytes());
    f[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes()); // R+X
    for (j, field) in [8usize, 16, 32, 40, 48].into_iter().enumerate() {
        set64(f, p + field, v[j]);
    }
}

/// A well-formed static ET_EXEC: one PT_LOAD of the file at 0x400000
/// (never run: every case breaks it)
fn valid(f: &mut [u8]) {
    f[..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // ELFCLASS64
    f[5] = 1; // little endian
    f[6] = 1; // EV_CURRENT
    set16(f, 16, 2); // ET_EXEC
    set16(f, 18, EM);
    f[20] = 1; // e_version
    set64(f, 24, 0x401000); // entry
    set64(f, 32, 64); // phoff
    set16(f, 52, 64); // ehsize
    set16(f, 54, 56); // phentsize
    set16(f, 56, 1); // phnum
    phdr(f, 0, 1, [0, 0x400000, LEN as u64, LEN as u64, 0x1000]);
}

/// PT_INTERP naming a file that does not exist
fn missing_interp(f: &mut [u8]) -> usize {
    with_interp(f, b"/no/such/ld.so\0")
}

/// Write an interpreter: the template ELF, changed by `mutate`
fn write_interp(path: &[u8], mutate: fn(&mut [u8])) {
    let mut f = [0u8; LEN];
    valid(&mut f);
    mutate(&mut f);
    let fd = sys_open(path.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    sys_write(fd as u64, f.as_ptr(), LEN as u64);
    sys_close(fd as u64);
}

/// PT_INTERP naming an executable file that is not ELF
fn bad_interp(f: &mut [u8]) -> usize {
    with_interp(f, BAD_INTERP)
}

/// A second program header: PT_INTERP naming `path`
fn with_interp(f: &mut [u8], path: &[u8]) -> usize {
    set16(f, 56, 2);
    f[0x1000..0x1000 + path.len()].copy_from_slice(path);
    phdr(
        f,
        1,
        3,
        [0x1000, 0x401000, path.len() as u64, path.len() as u64, 1],
    );
    LEN
}

/// Write `img` as an executable, exec it in a child and compare
fn check(name: &[u8], img: &[u8], want: Want) {
    let fd = sys_open(PATH.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    if fd < 0 || sys_write(fd as u64, img.as_ptr(), img.len() as u64) != img.len() as i64 {
        print(name);
        println(b":FAIL write");
        return;
    }
    sys_close(fd as u64);
    run(name, want);
}

/// exec PATH in a child, remove it, and compare the child's fate
fn run(name: &[u8], want: Want) {
    let pid = sys_fork();
    if pid == 0 {
        let argv: [*const u8; 2] = [PATH.as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        let r = sys_execve(PATH.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit((-r) as u64 & 0xff);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    sys_unlink(PATH.as_ptr());
    let exited = st & 0x7f == 0;
    let code = ((st >> 8) & 0xff) as i64;
    let ok = match want {
        Want::Errno(e) | Want::Runs(e) => exited && code == e,
        Want::Fatal(e) => (exited && code == e) || st & 0x7f == 11,
        Want::Dies(e) => (exited && code == e) || !exited,
    };
    print(name);
    if ok {
        println(b":OK");
    } else {
        fail_num(b":FAIL wstatus=", st as i64);
    }
}

/// Top of user space (Linux TASK_SIZE; the stack sits just below it)
#[cfg(target_arch = "x86_64")]
const TASK_TOP: u64 = 0x7fff_ffff_f000;
#[cfg(target_arch = "aarch64")]
const TASK_TOP: u64 = 1 << 48;

/// A PT_LOAD over the top 64 GiB of user space, wherever the stack
/// went in it (Linux randomizes it by up to 16 GiB)
fn on_stack(f: &mut [u8]) -> usize {
    const SZ: u64 = 64 << 30;
    phdr(f, 0, 1, [0, TASK_TOP - SZ, SZ, SZ, 0x1000]);
    LEN
}

/// The program of ELF_EXEC_UNSORTED: mprotect(0x400000, 4096,
/// PROT_READ | PROT_EXEC) on its own text, then exit with the byte at
/// 0x600010 plus mprotect's result
#[cfg(target_arch = "x86_64")]
const UNSORTED_CODE: &[u8] = &[
    0xbf, 0x00, 0x00, 0x40, 0x00, // mov edi, 0x400000
    0xbe, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
    0xba, 0x05, 0x00, 0x00, 0x00, // mov edx, 5
    0xb8, 0x0a, 0x00, 0x00, 0x00, // mov eax, SYS_mprotect
    0x0f, 0x05, // syscall
    0x89, 0xc3, // mov ebx, eax
    0x0f, 0xb6, 0x3c, 0x25, 0x10, 0x00, 0x60, 0x00, // movzx edi, byte [0x600010]
    0x01, 0xdf, // add edi, ebx
    0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
    0x0f, 0x05, // syscall
];
#[cfg(target_arch = "aarch64")]
const UNSORTED_WORDS: [u32; 13] = [
    0xd2a0_0800, // mov x0, #0x400000
    0xd282_0001, // mov x1, #0x1000
    0xd280_00a2, // mov x2, #5
    0xd280_1c48, // mov x8, #SYS_mprotect
    0xd400_0001, // svc #0
    0xaa00_03e3, // mov x3, x0
    0xd280_0201, // mov x1, #0x10
    0xf2a0_0c01, // movk x1, #0x60, lsl #16
    0x3940_0020, // ldrb w0, [x1]
    0x0b03_0000, // add w0, w0, w3
    0xd280_0ba8, // mov x8, #SYS_exit
    0xd400_0001, // svc #0
    0xd400_0001, // svc #0 (never reached)
];

/// Two PT_LOADs in descending address order (legal: Linux maps each
/// in file order): data at 0x600000 first, then the text at 0x400000
fn unsorted(f: &mut [u8]) -> usize {
    set16(f, 56, 2);
    set64(f, 24, 0x400800); // entry
    phdr(f, 0, 1, [0x1000, 0x600000, 0x20, 0x2000, 0x1000]);
    f[64 + 4] = 6; // RW
    phdr(f, 1, 1, [0, 0x400000, 0x1000, 0x1000, 0x1000]);
    #[cfg(target_arch = "x86_64")]
    f[0x800..0x800 + UNSORTED_CODE.len()].copy_from_slice(UNSORTED_CODE);
    #[cfg(target_arch = "aarch64")]
    for (i, w) in UNSORTED_WORDS.iter().enumerate() {
        f[0x800 + i * 4..0x800 + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    f[0x1010] = 42;
    LEN
}
