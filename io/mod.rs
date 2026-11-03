//! fd-backed I/O and event objects: poll/select infrastructure, epoll,
//! eventfd, signalfd, pipes, inotify/fanotify and io_uring

pub mod epoll;
pub mod eventfd;
pub mod fanotify;
pub mod inotify;
pub mod io_uring;
pub mod pipe;
pub mod poll;
pub mod signalfd;
