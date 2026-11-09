//! File descriptor, polling and stream I/O tests

pub mod cloexec;
pub mod close_range;
pub mod enomem;
pub mod epoll;
pub mod errno_pass;
pub mod eventfd;
pub mod fault_inject;
pub mod fcntl_owner;
pub mod fd_leak;
pub mod fd_scale;
pub mod gencalls;
pub mod io_uring;
pub mod nonblock;
pub mod nr_open;
pub mod pipe_packet;
pub mod poll;
pub mod pollperm;
pub mod sigio;
pub mod stdio;
pub mod tty;
pub mod uaccess;
