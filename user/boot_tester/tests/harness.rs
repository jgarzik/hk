//! Verdict helpers shared by the boot test suites
//!
//! Each prints `NAME:OK`, or `NAME:FAIL` with what went wrong, on one
//! line; the gate counts the FAIL lines.

use crate::tests::helpers::{print, print_num, println};

/// A failed check: what was checked and the value seen
pub type R = Result<(), (&'static [u8], i64)>;

/// `Ok(())` if `ok`, else the failure `(what, got)`
pub fn check(what: &'static [u8], ok: bool, got: i64) -> R {
    if ok { Ok(()) } else { Err((what, got)) }
}

/// NAME:OK, or NAME:FAIL why got N
pub fn report_r(name: &[u8], r: R) {
    print(name);
    match r {
        Ok(()) => println(b":OK"),
        Err((why, got)) => {
            print(b":FAIL ");
            print(why);
            print(b" got ");
            print_num(got);
            println(b"");
        }
    }
}

/// NAME:OK
pub fn pass(name: &[u8]) {
    print(name);
    println(b":OK");
}

/// NAME:FAIL why N
pub fn fail_why(name: &[u8], why: &[u8], v: i64) {
    print(name);
    print(b":FAIL ");
    print(why);
    print(b" ");
    print_num(v);
    println(b"");
}

/// The FAIL line `msg` N (msg holds NAME:FAIL and the why)
pub fn fail_num(msg: &[u8], v: i64) {
    print(msg);
    print_num(v);
    println(b"");
}

/// NAME:OK if `ok`, else NAME:FAIL got N
pub fn verdict(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got);
        println(b"");
    }
}

/// NAME:OK if `ok`, else NAME:FAIL N
pub fn verdict_detail(name: &[u8], ok: bool, detail: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(detail);
        println(b"");
    }
}

/// NAME:OK for step 0, else NAME:FAIL step N
pub fn report_step(name: &[u8], step: i64) {
    print(name);
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
}

/// NAME:OK for code 0, else NAME:FAIL N
pub fn report_code(name: &[u8], code: i64) {
    print(name);
    if code == 0 {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(code);
        println(b"");
    }
}

/// Print NAME:OK or NAME:FAIL why value
pub struct T {
    name: &'static [u8],
    failed: bool,
}

impl T {
    pub fn new(name: &'static [u8]) -> Self {
        Self {
            name,
            failed: false,
        }
    }

    /// Record `got == want` (first failure is printed)
    pub fn eq(&mut self, why: &[u8], got: i64, want: i64) -> bool {
        self.ok(why, got == want, got)
    }

    /// Record a condition; prints `got` on the first failure
    pub fn ok(&mut self, why: &[u8], cond: bool, got: i64) -> bool {
        if !cond && !self.failed {
            self.failed = true;
            print(self.name);
            print(b":FAIL ");
            print(why);
            print(b" got ");
            print_num(got);
            println(b"");
        }
        cond
    }

    pub fn done(self) {
        if !self.failed {
            print(self.name);
            println(b":OK");
        }
    }
}
