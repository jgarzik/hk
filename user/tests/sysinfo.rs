//! System information tests
//!
//! Tests:
//! - Test 70: uname() - get system identification
//! - Test 71: sethostname() - set hostname
//! - Test 72: setdomainname() - set domain name
//! - Test 73: sethostname() EINVAL - too long name

use super::helpers::{print, println, print_num, print_cstr, starts_with};
use crate::syscall::{sys_sethostname, sys_setdomainname, sys_uname, UtsName};

/// Run all sysinfo tests
pub fn run_tests() {
    test_uname();
    test_sethostname();
    test_setdomainname();
    test_sethostname_einval();
}

/// Test 70: uname() - get system identification
fn test_uname() {

    let mut uts = UtsName::default();
    let ret = sys_uname(&mut uts as *mut UtsName);
    if ret != 0 {
        print(b"UNAME:FAIL: uname() returned ");
        print_num(ret);
    } else {
        // Print the uname values
        print(b"sysname: ");
        print_cstr(&uts.sysname);
        print(b"nodename: ");
        print_cstr(&uts.nodename);
        print(b"release: ");
        print_cstr(&uts.release);
        print(b"machine: ");
        print_cstr(&uts.machine);

        // Verify sysname is "hk"
        if uts.sysname[0] == b'h' && uts.sysname[1] == b'k' && uts.sysname[2] == 0 {
            println(b"UNAME:OK");
        } else {
            println(b"UNAME:FAIL: sysname should be 'hk'");
        }
    }
}

/// Test 71: sethostname() - set hostname
fn test_sethostname() {

    let hostname = b"testhost";
    let ret = sys_sethostname(hostname.as_ptr(), hostname.len() as u64);
    if ret != 0 {
        print(b"SETHOSTNAME:FAIL: sethostname() returned ");
        print_num(ret);
    } else {
        // Verify via uname
        let mut uts2 = UtsName::default();
        let ret2 = sys_uname(&mut uts2 as *mut UtsName);
        if ret2 != 0 {
            print(b"SETHOSTNAME:FAIL: uname() returned ");
            print_num(ret2);
        } else {
            if starts_with(&uts2.nodename, b"testhost") {
                println(b"SETHOSTNAME:OK");
            } else {
                print(b"SETHOSTNAME:FAIL: nodename is '");
                print_cstr(&uts2.nodename);
                println(b"'");
            }
        }
    }
}

/// Test 72: setdomainname() - set domain name
fn test_setdomainname() {

    let domain = b"testdomain";
    let ret = sys_setdomainname(domain.as_ptr(), domain.len() as u64);
    if ret != 0 {
        print(b"SETDOMAINNAME:FAIL: setdomainname() returned ");
        print_num(ret);
    } else {
        // Verify via uname
        let mut uts3 = UtsName::default();
        let ret3 = sys_uname(&mut uts3 as *mut UtsName);
        if ret3 != 0 {
            print(b"SETDOMAINNAME:FAIL: uname() returned ");
            print_num(ret3);
        } else {
            if starts_with(&uts3.domainname, b"testdomain") {
                println(b"SETDOMAINNAME:OK");
            } else {
                print(b"SETDOMAINNAME:FAIL: domainname is '");
                print_cstr(&uts3.domainname);
                println(b"'");
            }
        }
    }
}

/// Test 73: sethostname() with too-long name (should fail with EINVAL)
fn test_sethostname_einval() {

    // 65 bytes is > 64 (max length)
    let long_name = [b'x'; 65];
    let ret = sys_sethostname(long_name.as_ptr(), 65);
    if ret == -22 {
        // EINVAL
        println(b"SETHOSTNAME_EINVAL:OK");
    } else {
        print(b"SETHOSTNAME_EINVAL:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}
