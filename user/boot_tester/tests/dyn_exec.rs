//! Dynamically linked programs: Ubuntu's glibc, bash and coreutils,
//! installed by tools/dyn-root.sh (the program interpreter is ld.so)
//!
//! Tests:
//! - DYN_HELLO: /usr/bin/echo (a glibc program) runs and prints
//! - DYN_ARGS_ENV: argv and the environment reach a dynamic program
//!   (/usr/bin/env lists PATH and HOME)
//! - BASH_PIPE: bash runs a pipeline of coreutils (seq | tac | head),
//!   arithmetic, command substitution through tr, and a here-document
//! - BASH_EXIT: bash -c 'exit 7' exits with 7, and `false` is 1

use super::busybox::{Prog, run_prog};
use super::helpers::{print, print_num, println};

const PATH: &[u8] = b"PATH=/usr/bin:/bin\0";

fn prog(path: &'static [u8], argv0: &'static [u8]) -> Prog {
    Prog {
        path,
        argv0,
        env_path: PATH,
    }
}

const BASH: Prog = Prog {
    path: b"/usr/bin/bash\0",
    argv0: b"bash\0",
    env_path: PATH,
};

pub fn run_tests() {
    hello();
    args_env();
    bash_pipe();
    bash_exit();
}

fn report(name: &[u8], ok: bool, status: i32, out: &[u8]) {
    print(name);
    if ok {
        println(b":OK");
        return;
    }
    print(b":FAIL status=");
    print_num(status as i64);
    println(b"");
    print(b"  output: ");
    println(out);
}

fn hello() {
    let r = run_prog(prog(b"/usr/bin/echo\0", b"echo\0"), &[b"hello\0"], b"", 10_000);
    report(b"DYN_HELLO", r.ok() && r.output() == b"hello\n", r.status, r.output());
}

fn args_env() {
    let r = run_prog(prog(b"/usr/bin/env\0", b"env\0"), &[], b"", 10_000);
    let ok = r.ok() && r.has(b"PATH=/usr/bin:/bin\n") && r.has(b"HOME=/\n");
    report(b"DYN_ARGS_ENV", ok, r.status, r.output());
}

fn bash_pipe() {
    let script: &[u8] = b"seq 100 | tac | head -1\n\
echo $(( 6 * 7 ))\n\
x=$(echo abc | tr a-c A-C); echo $x\n\
cat <<EOF\n\
here doc\n\
EOF\n\0";
    let r = run_prog(BASH, &[b"-c\0", script], b"", 20_000);
    let ok = r.ok() && r.output() == b"100\n42\nABC\nhere doc\n";
    report(b"BASH_PIPE", ok, r.status, r.output());
}

fn bash_exit() {
    let r = run_prog(BASH, &[b"-c\0", b"exit 7\0"], b"", 10_000);
    let f = run_prog(BASH, &[b"-c\0", b"false\0"], b"", 10_000);
    let exited = |s: i32| s & 0x7f == 0;
    let ok = exited(r.status) && (r.status >> 8) & 0xff == 7 && exited(f.status) && (f.status >> 8) & 0xff == 1;
    report(b"BASH_EXIT", ok, r.status, f.output());
}
