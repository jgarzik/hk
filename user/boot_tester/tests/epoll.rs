//! epoll tests
//!
//! Tests:
//! - Test epoll_create/epoll_create1
//! - Test epoll_ctl ADD/DEL/MOD
//! - Test epoll_wait with pipes
//! - Test epoll_wait with eventfd
//! - Test epoll_wait timeout behavior
//! - Test EPOLLONESHOT mode

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_close, sys_write, sys_pipe2, sys_eventfd2,
    sys_epoll_create, sys_epoll_create1, sys_epoll_ctl, sys_epoll_wait, sys_epoll_pwait2,
    EpollEvent, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
    EPOLLIN, EPOLLOUT, EPOLLONESHOT, EPOLL_CLOEXEC,
    Timespec,
};

/// Run all epoll tests
pub fn run_tests() {
    test_epoll_create();
    test_epoll_create1();
    test_epoll_add_del();
    test_epoll_wait_pipe();
    test_epoll_wait_eventfd();
    test_epoll_timeout();
    test_epoll_modify();
    test_epoll_oneshot();
    test_epoll_pwait2_null_timeout();
    test_epoll_pwait2_zero_timeout();
    test_epoll_pwait2_with_data();
}

/// Test epoll_create (legacy API)
fn test_epoll_create() {
    let epfd = sys_epoll_create(1);
    if epfd < 0 {
        print(b"EPOLL_CREATE:FAIL: returned ");
        print_num(epfd);
        return;
    }

    let close_ret = sys_close(epfd as u64);
    if close_ret != 0 {
        print(b"EPOLL_CREATE:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    println(b"EPOLL_CREATE:OK");
}

/// Test epoll_create1 with EPOLL_CLOEXEC
fn test_epoll_create1() {
    let epfd = sys_epoll_create1(EPOLL_CLOEXEC);
    if epfd < 0 {
        print(b"EPOLL_CREATE1:FAIL: returned ");
        print_num(epfd);
        return;
    }

    let close_ret = sys_close(epfd as u64);
    if close_ret != 0 {
        print(b"EPOLL_CREATE1:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    println(b"EPOLL_CREATE1:OK");
}

/// Test epoll_ctl ADD and DEL operations
fn test_epoll_add_del() {
    // Create epoll instance
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_ADD_DEL:FAIL: epoll_create1 returned ");
        print_num(epfd);
        return;
    }

    // Create a pipe
    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"EPOLL_ADD_DEL:FAIL: pipe2 returned ");
        print_num(ret);
        sys_close(epfd as u64);
        return;
    }

    // Add read end to epoll
    let event = EpollEvent::new(EPOLLIN, 42);
    let ret = sys_epoll_ctl(epfd as i32, EPOLL_CTL_ADD, pipefd[0], &event);
    if ret != 0 {
        print(b"EPOLL_ADD_DEL:FAIL: add returned ");
        print_num(ret);
        sys_close(epfd as u64);
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Delete it
    let ret = sys_epoll_ctl(epfd as i32, EPOLL_CTL_DEL, pipefd[0], core::ptr::null());
    if ret != 0 {
        print(b"EPOLL_ADD_DEL:FAIL: del returned ");
        print_num(ret);
        sys_close(epfd as u64);
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Cleanup
    sys_close(epfd as u64);
    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
    println(b"EPOLL_ADD_DEL:OK");
}

/// Test epoll_wait with a pipe
fn test_epoll_wait_pipe() {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_WAIT_PIPE:FAIL: epoll_create1 returned ");
        print_num(epfd);
        return;
    }

    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"EPOLL_WAIT_PIPE:FAIL: pipe2 returned ");
        print_num(ret);
        sys_close(epfd as u64);
        return;
    }

    // Add read end with user data 123
    let event = EpollEvent::new(EPOLLIN, 123);
    sys_epoll_ctl(epfd as i32, EPOLL_CTL_ADD, pipefd[0], &event);

    // Write to pipe to make read end ready
    let data = b"X";
    sys_write(pipefd[1] as u64, data.as_ptr(), 1);

    // Wait should return 1 event
    let mut events = [EpollEvent::empty(); 4];
    let ret = sys_epoll_wait(epfd as i32, events.as_mut_ptr(), 4, 0);
    if ret != 1 {
        print(b"EPOLL_WAIT_PIPE:FAIL: expected 1, got ");
        print_num(ret);
        sys_close(epfd as u64);
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Check user data was returned correctly
    if events[0].data != 123 {
        print(b"EPOLL_WAIT_PIPE:FAIL: wrong data ");
        print_num(events[0].data as i64);
        sys_close(epfd as u64);
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Check EPOLLIN is set
    if events[0].events & EPOLLIN == 0 {
        print(b"EPOLL_WAIT_PIPE:FAIL: EPOLLIN not set, events=");
        print_num(events[0].events as i64);
        sys_close(epfd as u64);
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Cleanup
    sys_close(epfd as u64);
    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
    println(b"EPOLL_WAIT_PIPE:OK");
}

/// Test epoll_wait with eventfd
fn test_epoll_wait_eventfd() {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_WAIT_EVENTFD:FAIL: epoll_create1 returned ");
        print_num(epfd);
        return;
    }

    // Create eventfd with initial value 1 (immediately readable)
    let efd = sys_eventfd2(1, 0);
    if efd < 0 {
        print(b"EPOLL_WAIT_EVENTFD:FAIL: eventfd2 returned ");
        print_num(efd);
        sys_close(epfd as u64);
        return;
    }

    // Add eventfd with user data 456
    let event = EpollEvent::new(EPOLLIN, 456);
    sys_epoll_ctl(epfd as i32, EPOLL_CTL_ADD, efd as i32, &event);

    // Wait should return 1 event since counter > 0
    let mut events = [EpollEvent::empty(); 4];
    let ret = sys_epoll_wait(epfd as i32, events.as_mut_ptr(), 4, 0);
    if ret != 1 {
        print(b"EPOLL_WAIT_EVENTFD:FAIL: expected 1, got ");
        print_num(ret);
        sys_close(epfd as u64);
        sys_close(efd as u64);
        return;
    }

    if events[0].data != 456 {
        print(b"EPOLL_WAIT_EVENTFD:FAIL: wrong data ");
        print_num(events[0].data as i64);
        sys_close(epfd as u64);
        sys_close(efd as u64);
        return;
    }

    sys_close(epfd as u64);
    sys_close(efd as u64);
    println(b"EPOLL_WAIT_EVENTFD:OK");
}

/// Test epoll_wait timeout behavior
fn test_epoll_timeout() {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_TIMEOUT:FAIL: epoll_create1 returned ");
        print_num(epfd);
        return;
    }

    // Empty epoll, timeout=0 should return 0 immediately
    let mut events = [EpollEvent::empty(); 4];
    let ret = sys_epoll_wait(epfd as i32, events.as_mut_ptr(), 4, 0);
    if ret != 0 {
        print(b"EPOLL_TIMEOUT:FAIL: expected 0, got ");
        print_num(ret);
        sys_close(epfd as u64);
        return;
    }

    sys_close(epfd as u64);
    println(b"EPOLL_TIMEOUT:OK");
}

/// Test epoll_ctl MOD operation
fn test_epoll_modify() {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_MODIFY:FAIL: epoll_create1 returned ");
        print_num(epfd);
        return;
    }

    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"EPOLL_MODIFY:FAIL: pipe2 returned ");
        print_num(ret);
        sys_close(epfd as u64);
        return;
    }

    // Add read end with EPOLLIN
    let event = EpollEvent::new(EPOLLIN, 100);
    sys_epoll_ctl(epfd as i32, EPOLL_CTL_ADD, pipefd[0], &event);

    // Modify to watch for EPOLLOUT with different user data
    let event2 = EpollEvent::new(EPOLLOUT, 200);
    let ret = sys_epoll_ctl(epfd as i32, EPOLL_CTL_MOD, pipefd[0], &event2);
    if ret != 0 {
        print(b"EPOLL_MODIFY:FAIL: mod returned ");
        print_num(ret);
        sys_close(epfd as u64);
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    // Cleanup
    sys_close(epfd as u64);
    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
    println(b"EPOLL_MODIFY:OK");
}

/// Test EPOLLONESHOT mode
fn test_epoll_oneshot() {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_ONESHOT:FAIL: epoll_create1 returned ");
        print_num(epfd);
        return;
    }

    // Create eventfd with initial value 5
    let efd = sys_eventfd2(5, 0);
    if efd < 0 {
        print(b"EPOLL_ONESHOT:FAIL: eventfd2 returned ");
        print_num(efd);
        sys_close(epfd as u64);
        return;
    }

    // Add with EPOLLONESHOT
    let event = EpollEvent::new(EPOLLIN | EPOLLONESHOT, 789);
    sys_epoll_ctl(epfd as i32, EPOLL_CTL_ADD, efd as i32, &event);

    // First wait should succeed
    let mut events = [EpollEvent::empty(); 4];
    let ret = sys_epoll_wait(epfd as i32, events.as_mut_ptr(), 4, 0);
    if ret != 1 {
        print(b"EPOLL_ONESHOT:FAIL: first wait expected 1, got ");
        print_num(ret);
        sys_close(epfd as u64);
        sys_close(efd as u64);
        return;
    }

    // Second wait should return 0 (oneshot disabled the fd)
    let ret = sys_epoll_wait(epfd as i32, events.as_mut_ptr(), 4, 0);
    if ret != 0 {
        print(b"EPOLL_ONESHOT:FAIL: second wait expected 0, got ");
        print_num(ret);
        sys_close(epfd as u64);
        sys_close(efd as u64);
        return;
    }

    // Re-arm with MOD
    let event2 = EpollEvent::new(EPOLLIN | EPOLLONESHOT, 789);
    sys_epoll_ctl(epfd as i32, EPOLL_CTL_MOD, efd as i32, &event2);

    // Now wait should succeed again
    let ret = sys_epoll_wait(epfd as i32, events.as_mut_ptr(), 4, 0);
    if ret != 1 {
        print(b"EPOLL_ONESHOT:FAIL: third wait expected 1, got ");
        print_num(ret);
        sys_close(epfd as u64);
        sys_close(efd as u64);
        return;
    }

    sys_close(epfd as u64);
    sys_close(efd as u64);
    println(b"EPOLL_ONESHOT:OK");
}

/// Test epoll_pwait2 with NULL timeout (indefinite wait, but with ready fd)
fn test_epoll_pwait2_null_timeout() {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_PWAIT2_NULL:FAIL: epoll_create1 returned ");
        print_num(epfd);
        println(b"");
        return;
    }

    // Create eventfd with initial value 1 (immediately readable)
    let efd = sys_eventfd2(1, 0);
    if efd < 0 {
        print(b"EPOLL_PWAIT2_NULL:FAIL: eventfd2 returned ");
        print_num(efd);
        println(b"");
        sys_close(epfd as u64);
        return;
    }

    let event = EpollEvent::new(EPOLLIN, 100);
    sys_epoll_ctl(epfd as i32, EPOLL_CTL_ADD, efd as i32, &event);

    // NULL timeout with ready fd should return immediately
    let mut events = [EpollEvent::empty(); 4];
    let ret = sys_epoll_pwait2(
        epfd as i32,
        events.as_mut_ptr(),
        4,
        core::ptr::null(),
        core::ptr::null(),
        0,
    );
    if ret != 1 {
        print(b"EPOLL_PWAIT2_NULL:FAIL: expected 1, got ");
        print_num(ret);
        println(b"");
        sys_close(epfd as u64);
        sys_close(efd as u64);
        return;
    }

    if events[0].data != 100 {
        print(b"EPOLL_PWAIT2_NULL:FAIL: wrong data ");
        print_num(events[0].data as i64);
        println(b"");
        sys_close(epfd as u64);
        sys_close(efd as u64);
        return;
    }

    sys_close(epfd as u64);
    sys_close(efd as u64);
    println(b"EPOLL_PWAIT2_NULL:OK");
}

/// Test epoll_pwait2 with zero timeout (non-blocking)
fn test_epoll_pwait2_zero_timeout() {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_PWAIT2_ZERO:FAIL: epoll_create1 returned ");
        print_num(epfd);
        println(b"");
        return;
    }

    // Empty epoll, zero timeout should return 0 immediately
    let mut events = [EpollEvent::empty(); 4];
    let timeout = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = sys_epoll_pwait2(
        epfd as i32,
        events.as_mut_ptr(),
        4,
        &timeout,
        core::ptr::null(),
        0,
    );
    if ret != 0 {
        print(b"EPOLL_PWAIT2_ZERO:FAIL: expected 0, got ");
        print_num(ret);
        println(b"");
        sys_close(epfd as u64);
        return;
    }

    sys_close(epfd as u64);
    println(b"EPOLL_PWAIT2_ZERO:OK");
}

/// Test epoll_pwait2 with data ready and small timeout
fn test_epoll_pwait2_with_data() {
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        print(b"EPOLL_PWAIT2_DATA:FAIL: epoll_create1 returned ");
        print_num(epfd);
        println(b"");
        return;
    }

    let mut pipefd = [0i32; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        print(b"EPOLL_PWAIT2_DATA:FAIL: pipe2 returned ");
        print_num(ret);
        println(b"");
        sys_close(epfd as u64);
        return;
    }

    // Add read end
    let event = EpollEvent::new(EPOLLIN, 200);
    sys_epoll_ctl(epfd as i32, EPOLL_CTL_ADD, pipefd[0], &event);

    // Write to pipe
    let data = b"Y";
    sys_write(pipefd[1] as u64, data.as_ptr(), 1);

    // Use 100ms timeout (in nanoseconds)
    let timeout = Timespec { tv_sec: 0, tv_nsec: 100_000_000 };
    let mut events = [EpollEvent::empty(); 4];
    let ret = sys_epoll_pwait2(
        epfd as i32,
        events.as_mut_ptr(),
        4,
        &timeout,
        core::ptr::null(),
        0,
    );
    if ret != 1 {
        print(b"EPOLL_PWAIT2_DATA:FAIL: expected 1, got ");
        print_num(ret);
        println(b"");
        sys_close(epfd as u64);
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    if events[0].data != 200 {
        print(b"EPOLL_PWAIT2_DATA:FAIL: wrong data ");
        print_num(events[0].data as i64);
        println(b"");
        sys_close(epfd as u64);
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        return;
    }

    sys_close(epfd as u64);
    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);
    println(b"EPOLL_PWAIT2_DATA:OK");
}
