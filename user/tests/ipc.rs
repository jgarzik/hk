//! IPC Tests - pipe, poll, select, and SysV IPC
//!
//! Tests for inter-process communication primitives including:
//! - Pipes and poll/select
//! - SysV shared memory (shmget, shmat, shmdt, shmctl)
//! - SysV semaphores (semget, semop, semctl)
//! - SysV message queues (msgget, msgsnd, msgrcv, msgctl)

use crate::syscall::{
    sys_close, sys_pipe, sys_poll, sys_read, sys_select, sys_write,
    sys_shmget, sys_shmat, sys_shmdt, sys_shmctl,
    sys_semget, sys_semop, sys_semctl,
    sys_msgget, sys_msgsnd, sys_msgrcv, sys_msgctl,
    FdSet, PollFd, Timeval, Sembuf,
    POLLIN, POLLNVAL, POLLOUT,
    IPC_CREAT, IPC_PRIVATE, IPC_RMID,
    GETVAL, SETVAL,
};
use super::helpers::{print, println, print_num};

/// Run all IPC tests
pub fn run_tests() {
    println(b"=== IPC Tests ===");

    // Pipe tests
    test_pipe_basic();
    test_pipe_read_write();
    test_poll_data_ready();
    test_poll_no_data();
    test_poll_invalid_fd();
    test_poll_write_ready();
    test_select_data_ready();
    test_select_no_data();

    // SysV IPC tests
    println(b"--- SysV Shared Memory ---");
    test_shmget_create();
    test_shmat_write_read();
    test_shmctl_rmid();

    println(b"--- SysV Semaphores ---");
    test_semget_create();
    test_semctl_setval_getval();
    test_semop_increment();

    println(b"--- SysV Message Queues ---");
    test_msgget_create();
    test_msgsnd_msgrcv();
    test_msgctl_rmid();
}

/// Test basic pipe creation
fn test_pipe_basic() {

    let mut pipefd: [i32; 2] = [0, 0];
    let ret = sys_pipe(pipefd.as_mut_ptr());

    print(b"pipe() returned ");
    print_num(ret);
    print(b", fds=[");
    print_num(pipefd[0] as i64);
    print(b", ");
    print_num(pipefd[1] as i64);
    println(b"]");

    if ret == 0 && pipefd[0] > 0 && pipefd[1] > 0 {
        // Clean up
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        println(b"PIPE_CREATE:OK");
    } else {
        println(b"PIPE_CREATE:FAIL");
    }
}

/// Test pipe read/write
fn test_pipe_read_write() {

    let mut pipefd: [i32; 2] = [0, 0];
    let ret = sys_pipe(pipefd.as_mut_ptr());
    if ret != 0 {
        print(b"pipe() failed with ");
        print_num(ret);
        println(b"PIPE_RW:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Write "hello" to the pipe
    let msg = b"hello";
    let written = sys_write(write_fd as u64, msg.as_ptr(), msg.len() as u64);

    print(b"write() returned ");
    print_num(written);

    if written != 5 {
        println(b"PIPE_RW:FAIL");
        sys_close(read_fd as u64);
        sys_close(write_fd as u64);
        return;
    }

    // Read it back
    let mut buf: [u8; 16] = [0; 16];
    let read_bytes = sys_read(read_fd as u64, buf.as_mut_ptr(), 16);

    print(b"read() returned ");
    print_num(read_bytes);

    if read_bytes != 5 {
        println(b"PIPE_RW:FAIL");
        sys_close(read_fd as u64);
        sys_close(write_fd as u64);
        return;
    }

    // Verify data matches
    let matches = buf[0] == b'h' && buf[1] == b'e' && buf[2] == b'l'
                  && buf[3] == b'l' && buf[4] == b'o';

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    if matches {
        println(b"PIPE_RW:OK");
    } else {
        println(b"PIPE_RW:FAIL");
    }
}

/// Test poll with data ready
fn test_poll_data_ready() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"POLL_DATA:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Write data to pipe
    let msg = b"x";
    sys_write(write_fd as u64, msg.as_ptr(), 1);

    // Poll for read readiness with timeout 0 (immediate)
    let mut fds = [PollFd::new(read_fd, POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    print(b"poll() returned ");
    print_num(ret);
    print(b", revents=");
    print_num(fds[0].revents as i64);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 1 (one fd ready) with POLLIN set
    if ret == 1 && (fds[0].revents & POLLIN) != 0 {
        println(b"POLL_DATA:OK");
    } else {
        println(b"POLL_DATA:FAIL");
    }
}

/// Test poll with no data (should timeout)
fn test_poll_no_data() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"POLL_TIMEOUT:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Don't write any data
    // Poll with timeout 0 (immediate return)
    let mut fds = [PollFd::new(read_fd, POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    print(b"poll() returned ");
    print_num(ret);
    print(b", revents=");
    print_num(fds[0].revents as i64);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 0 (no fds ready, timeout)
    if ret == 0 {
        println(b"POLL_TIMEOUT:OK");
    } else {
        println(b"POLL_TIMEOUT:FAIL");
    }
}

/// Test poll with invalid fd
fn test_poll_invalid_fd() {

    // Poll a clearly invalid fd
    let mut fds = [PollFd::new(9999, POLLIN)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    print(b"poll() returned ");
    print_num(ret);
    print(b", revents=");
    print_num(fds[0].revents as i64);

    // poll() should return 1 with POLLNVAL set in revents (not EBADF)
    if ret == 1 && (fds[0].revents & POLLNVAL) != 0 {
        println(b"POLL_INVALID:OK");
    } else {
        println(b"POLL_INVALID:FAIL");
    }
}

/// Test poll for write readiness on pipe
fn test_poll_write_ready() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"POLL_WRITE:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Poll write end - should be ready (buffer empty)
    let mut fds = [PollFd::new(write_fd, POLLOUT)];
    let ret = sys_poll(fds.as_mut_ptr(), 1, 0);

    print(b"poll() returned ");
    print_num(ret);
    print(b", revents=");
    print_num(fds[0].revents as i64);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 1 (write fd ready) with POLLOUT set
    if ret == 1 && (fds[0].revents & POLLOUT) != 0 {
        println(b"POLL_WRITE:OK");
    } else {
        println(b"POLL_WRITE:FAIL");
    }
}

/// Test select with data ready
fn test_select_data_ready() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"SELECT_DATA:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Write data to pipe
    let msg = b"x";
    sys_write(write_fd as u64, msg.as_ptr(), 1);

    // Set up fd_set for read_fd
    let mut readfds = FdSet::new();
    readfds.zero(); // Ensure proper zeroing (volatile writes)
    readfds.set(read_fd);

    // Timeout 0 (immediate)
    let mut tv = Timeval { tv_sec: 0, tv_usec: 0 };

    let ret = sys_select(read_fd + 1, &mut readfds, core::ptr::null_mut(), core::ptr::null_mut(), &mut tv);

    print(b"select() returned ");
    print_num(ret);
    print(b", is_set=");
    print_num(if readfds.is_set(read_fd) { 1 } else { 0 });

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 1 (one fd ready) with read_fd still set
    if ret == 1 && readfds.is_set(read_fd) {
        println(b"SELECT_DATA:OK");
    } else {
        println(b"SELECT_DATA:FAIL");
    }
}

/// Test select with no data
fn test_select_no_data() {

    let mut pipefd: [i32; 2] = [0, 0];
    if sys_pipe(pipefd.as_mut_ptr()) != 0 {
        println(b"pipe() failed");
        println(b"SELECT_TIMEOUT:FAIL");
        return;
    }

    let read_fd = pipefd[0];
    let write_fd = pipefd[1];

    // Don't write data
    let mut readfds = FdSet::new();
    readfds.zero(); // Ensure proper zeroing (volatile writes)
    readfds.set(read_fd);

    // Timeout 0 (immediate)
    let mut tv = Timeval { tv_sec: 0, tv_usec: 0 };

    let ret = sys_select(read_fd + 1, &mut readfds, core::ptr::null_mut(), core::ptr::null_mut(), &mut tv);

    print(b"select() returned ");
    print_num(ret);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return 0 (timeout, no fds ready)
    // Note: select clears the fd_set on timeout
    if ret == 0 {
        println(b"SELECT_TIMEOUT:OK");
    } else {
        println(b"SELECT_TIMEOUT:FAIL");
    }
}

// ============================================================================
// SysV Shared Memory Tests
// ============================================================================

/// Test shmget() to create a shared memory segment
fn test_shmget_create() {
    // Create a 4KB shared memory segment
    let shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o666);

    print(b"shmget(IPC_PRIVATE, 4096) returned ");
    print_num(shmid);

    if shmid >= 0 {
        // Clean up
        sys_shmctl(shmid as i32, IPC_RMID, 0);
        println(b" SHMGET_CREATE:OK");
    } else {
        println(b" SHMGET_CREATE:FAIL");
    }
}

/// Test shmat() to attach and write/read from shared memory
fn test_shmat_write_read() {
    // Create a 4KB shared memory segment
    let shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o666);
    if shmid < 0 {
        print(b"shmget failed: ");
        print_num(shmid);
        println(b" SHMAT_RW:FAIL");
        return;
    }

    // Attach the segment (kernel chooses address)
    let addr = sys_shmat(shmid as i32, 0, 0);

    print(b"shmat() returned 0x");
    // Print address in hex
    let addr_val = addr as u64;
    let hex_chars: [u8; 16] = *b"0123456789abcdef";
    let mut hex_buf: [u8; 16] = [0; 16];
    let mut val = addr_val;
    for i in (0..16).rev() {
        hex_buf[i] = hex_chars[(val & 0xf) as usize];
        val >>= 4;
    }
    print(&hex_buf);

    if addr < 0 {
        println(b" SHMAT_RW:FAIL");
        sys_shmctl(shmid as i32, IPC_RMID, 0);
        return;
    }

    // Write a magic value to the shared memory
    let ptr = addr as *mut u64;
    unsafe {
        core::ptr::write_volatile(ptr, 0xDEADBEEF_CAFEBABE);
    }

    // Read it back
    let read_val = unsafe { core::ptr::read_volatile(ptr) };

    print(b" wrote/read=0x");
    let mut val2 = read_val;
    let mut hex_buf2: [u8; 16] = [0; 16];
    for i in (0..16).rev() {
        hex_buf2[i] = hex_chars[(val2 & 0xf) as usize];
        val2 >>= 4;
    }
    print(&hex_buf2);

    // Detach
    let dt_ret = sys_shmdt(addr as u64);

    // Clean up
    sys_shmctl(shmid as i32, IPC_RMID, 0);

    if read_val == 0xDEADBEEF_CAFEBABE && dt_ret == 0 {
        println(b" SHMAT_RW:OK");
    } else {
        println(b" SHMAT_RW:FAIL");
    }
}

/// Test shmctl() IPC_RMID to remove a shared memory segment
fn test_shmctl_rmid() {
    // Create a segment
    let shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o666);
    if shmid < 0 {
        println(b"shmget failed SHMCTL_RMID:FAIL");
        return;
    }

    // Remove it
    let ret = sys_shmctl(shmid as i32, IPC_RMID, 0);

    print(b"shmctl(IPC_RMID) returned ");
    print_num(ret);

    if ret == 0 {
        println(b" SHMCTL_RMID:OK");
    } else {
        println(b" SHMCTL_RMID:FAIL");
    }
}

// ============================================================================
// SysV Semaphore Tests
// ============================================================================

/// Test semget() to create a semaphore set
fn test_semget_create() {
    // Create a semaphore set with 1 semaphore
    let semid = sys_semget(IPC_PRIVATE, 1, IPC_CREAT | 0o666);

    print(b"semget(IPC_PRIVATE, 1) returned ");
    print_num(semid);

    if semid >= 0 {
        // Clean up
        sys_semctl(semid as i32, 0, IPC_RMID, 0);
        println(b" SEMGET_CREATE:OK");
    } else {
        println(b" SEMGET_CREATE:FAIL");
    }
}

/// Test semctl() SETVAL/GETVAL
fn test_semctl_setval_getval() {
    // Create a semaphore set
    let semid = sys_semget(IPC_PRIVATE, 1, IPC_CREAT | 0o666);
    if semid < 0 {
        println(b"semget failed SEMCTL_VAL:FAIL");
        return;
    }

    // Set value to 42
    let set_ret = sys_semctl(semid as i32, 0, SETVAL, 42);
    print(b"semctl(SETVAL, 42) returned ");
    print_num(set_ret);

    if set_ret < 0 {
        sys_semctl(semid as i32, 0, IPC_RMID, 0);
        println(b" SEMCTL_VAL:FAIL");
        return;
    }

    // Get value back
    let val = sys_semctl(semid as i32, 0, GETVAL, 0);
    print(b" semctl(GETVAL) returned ");
    print_num(val);

    // Clean up
    sys_semctl(semid as i32, 0, IPC_RMID, 0);

    if val == 42 {
        println(b" SEMCTL_VAL:OK");
    } else {
        println(b" SEMCTL_VAL:FAIL");
    }
}

/// Test semop() to increment a semaphore
fn test_semop_increment() {
    // Create a semaphore set
    let semid = sys_semget(IPC_PRIVATE, 1, IPC_CREAT | 0o666);
    if semid < 0 {
        println(b"semget failed SEMOP_INC:FAIL");
        return;
    }

    // Set initial value to 5
    sys_semctl(semid as i32, 0, SETVAL, 5);

    // Increment by 3
    let sop = Sembuf::new(0, 3, 0);
    let ret = sys_semop(semid as i32, &sop, 1);

    print(b"semop(+3) returned ");
    print_num(ret);

    // Get new value
    let val = sys_semctl(semid as i32, 0, GETVAL, 0);
    print(b" new value=");
    print_num(val);

    // Clean up
    sys_semctl(semid as i32, 0, IPC_RMID, 0);

    if ret == 0 && val == 8 {
        println(b" SEMOP_INC:OK");
    } else {
        println(b" SEMOP_INC:FAIL");
    }
}

// ============================================================================
// SysV Message Queue Tests
// ============================================================================

/// Test msgget() to create a message queue
fn test_msgget_create() {
    // Create a message queue
    let msqid = sys_msgget(IPC_PRIVATE, IPC_CREAT | 0o666);

    print(b"msgget(IPC_PRIVATE) returned ");
    print_num(msqid);

    if msqid >= 0 {
        // Clean up
        sys_msgctl(msqid as i32, IPC_RMID, 0);
        println(b" MSGGET_CREATE:OK");
    } else {
        println(b" MSGGET_CREATE:FAIL");
    }
}

/// Message structure for testing
#[repr(C)]
struct TestMsg {
    mtype: i64,
    mtext: [u8; 32],
}

/// Test msgsnd/msgrcv
fn test_msgsnd_msgrcv() {
    // Create a message queue
    let msqid = sys_msgget(IPC_PRIVATE, IPC_CREAT | 0o666);
    if msqid < 0 {
        println(b"msgget failed MSGSND_MSGRCV:FAIL");
        return;
    }

    // Send a message
    let mut send_msg = TestMsg {
        mtype: 1,
        mtext: [0; 32],
    };
    let text = b"Hello, MQ!";
    send_msg.mtext[..text.len()].copy_from_slice(text);

    let send_ret = sys_msgsnd(
        msqid as i32,
        &send_msg as *const TestMsg as *const u8,
        text.len(),
        0,
    );

    print(b"msgsnd() returned ");
    print_num(send_ret);

    if send_ret < 0 {
        sys_msgctl(msqid as i32, IPC_RMID, 0);
        println(b" MSGSND_MSGRCV:FAIL");
        return;
    }

    // Receive the message
    let mut recv_msg = TestMsg {
        mtype: 0,
        mtext: [0; 32],
    };

    let recv_ret = sys_msgrcv(
        msqid as i32,
        &mut recv_msg as *mut TestMsg as *mut u8,
        32,
        0, // Receive any message type
        0,
    );

    print(b" msgrcv() returned ");
    print_num(recv_ret);

    // Clean up
    sys_msgctl(msqid as i32, IPC_RMID, 0);

    // Verify the message
    let matches = recv_ret >= 0
        && recv_msg.mtype == 1
        && recv_msg.mtext[0] == b'H'
        && recv_msg.mtext[1] == b'e'
        && recv_msg.mtext[2] == b'l';

    if matches {
        println(b" MSGSND_MSGRCV:OK");
    } else {
        println(b" MSGSND_MSGRCV:FAIL");
    }
}

/// Test msgctl() IPC_RMID
fn test_msgctl_rmid() {
    // Create a queue
    let msqid = sys_msgget(IPC_PRIVATE, IPC_CREAT | 0o666);
    if msqid < 0 {
        println(b"msgget failed MSGCTL_RMID:FAIL");
        return;
    }

    // Remove it
    let ret = sys_msgctl(msqid as i32, IPC_RMID, 0);

    print(b"msgctl(IPC_RMID) returned ");
    print_num(ret);

    if ret == 0 {
        println(b" MSGCTL_RMID:OK");
    } else {
        println(b" MSGCTL_RMID:FAIL");
    }
}
