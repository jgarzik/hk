//! Unified kernel error type
//!
//! KernelError uses `#[repr(i32)]` with discriminants equal to errno values.
//! This eliminates all error translation - the discriminant IS the errno.
//!
//! Errno values are identical across x86-64 and aarch64 Linux ABIs.

/// Kernel error type with errno values as discriminants
///
/// Each variant's value is its Linux errno. This allows zero-cost conversion
/// to syscall return values via simple negation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum KernelError {
    // =========================================================================
    // Base errno values (1-34) from errno-base.h
    // =========================================================================
    /// Operation not permitted (EPERM)
    NotPermitted = 1,
    /// No such file or directory (ENOENT)
    NotFound = 2,
    /// No such process (ESRCH)
    NoProcess = 3,
    /// Interrupted system call (EINTR)
    Interrupted = 4,
    /// I/O error (EIO)
    Io = 5,
    /// No such device or address (ENXIO)
    NoDeviceOrAddress = 6,
    /// Argument list too long (E2BIG)
    ArgListTooLong = 7,
    /// Exec format error (ENOEXEC)
    ExecFormat = 8,
    /// Bad file descriptor (EBADF)
    BadFd = 9,
    /// No child processes (ECHILD)
    NoChild = 10,
    /// Resource temporarily unavailable / would block (EAGAIN/EWOULDBLOCK)
    WouldBlock = 11,
    /// Out of memory (ENOMEM)
    OutOfMemory = 12,
    /// Permission denied (EACCES)
    PermissionDenied = 13,
    /// Bad address (EFAULT)
    BadAddress = 14,
    /// Block device required (ENOTBLK)
    NotBlockDevice = 15,
    /// Device or resource busy (EBUSY)
    Busy = 16,
    /// File exists (EEXIST)
    AlreadyExists = 17,
    /// Cross-device link (EXDEV)
    CrossDevice = 18,
    /// No such device (ENODEV)
    NoDevice = 19,
    /// Not a directory (ENOTDIR)
    NotDirectory = 20,
    /// Is a directory (EISDIR)
    IsDirectory = 21,
    /// Invalid argument (EINVAL)
    InvalidArgument = 22,
    /// Too many open files in system (ENFILE)
    SystemFileLimit = 23,
    /// Too many open files (EMFILE)
    ProcessFileLimit = 24,
    /// Inappropriate ioctl for device (ENOTTY)
    NotTty = 25,
    /// Text file busy (ETXTBSY)
    TextBusy = 26,
    /// File too large (EFBIG)
    FileTooLarge = 27,
    /// No space left on device (ENOSPC)
    NoSpace = 28,
    /// Illegal seek (ESPIPE)
    IllegalSeek = 29,
    /// Read-only file system (EROFS)
    ReadOnlyFs = 30,
    /// Too many links (EMLINK)
    TooManyLinks = 31,
    /// Broken pipe (EPIPE)
    BrokenPipe = 32,
    /// Numerical argument out of domain (EDOM)
    MathDomain = 33,
    /// Numerical result out of range (ERANGE)
    Range = 34,

    // =========================================================================
    // Extended errno values (35-90)
    // =========================================================================
    /// Resource deadlock avoided (EDEADLK)
    Deadlock = 35,
    /// File name too long (ENAMETOOLONG)
    NameTooLong = 36,
    /// No locks available (ENOLCK)
    NoLocks = 37,
    /// Function not implemented (ENOSYS)
    NotImplemented = 38,
    /// Directory not empty (ENOTEMPTY)
    DirectoryNotEmpty = 39,
    /// Too many levels of symbolic links (ELOOP)
    TooManySymlinks = 40,
    // 41 is unused (EWOULDBLOCK = EAGAIN = 11)
    /// No message of desired type (ENOMSG)
    NoMessage = 42,
    /// Identifier removed (EIDRM)
    IdentifierRemoved = 43,
    /// No data available (ENODATA)
    NoData = 61,
    /// Timer expired (ETIME)
    TimerExpired = 62,
    /// Machine is not on the network (ENONET)
    NoNetwork = 64,
    /// Protocol error (EPROTO)
    ProtocolError = 71,
    /// Value too large for defined data type (EOVERFLOW)
    Overflow = 75,
    /// Bad message (EBADMSG)
    BadMessage = 74,

    // =========================================================================
    // Network errno values (88-115)
    // =========================================================================
    /// Socket operation on non-socket (ENOTSOCK)
    NotSocket = 88,
    /// Destination address required (EDESTADDRREQ)
    DestAddrRequired = 89,
    /// Message too long (EMSGSIZE)
    MessageTooLong = 90,
    /// Protocol wrong type for socket (EPROTOTYPE)
    ProtocolType = 91,
    /// Protocol not available (ENOPROTOOPT)
    NoProtocolOption = 92,
    /// Protocol not supported (EPROTONOSUPPORT)
    ProtocolNotSupported = 93,
    /// Socket type not supported (ESOCKTNOSUPPORT)
    SocketTypeNotSupported = 94,
    /// Operation not supported (EOPNOTSUPP)
    OperationNotSupported = 95,
    /// Protocol family not supported (EPFNOSUPPORT)
    ProtocolFamilyNotSupported = 96,
    /// Address family not supported (EAFNOSUPPORT)
    AddressFamilyNotSupported = 97,
    /// Address already in use (EADDRINUSE)
    AddressInUse = 98,
    /// Cannot assign requested address (EADDRNOTAVAIL)
    AddressNotAvailable = 99,
    /// Network is down (ENETDOWN)
    NetworkDown = 100,
    /// Network is unreachable (ENETUNREACH)
    NetworkUnreachable = 101,
    /// Network dropped connection on reset (ENETRESET)
    NetworkReset = 102,
    /// Software caused connection abort (ECONNABORTED)
    ConnectionAborted = 103,
    /// Connection reset by peer (ECONNRESET)
    ConnectionReset = 104,
    /// No buffer space available (ENOBUFS)
    NoBufferSpace = 105,
    /// Transport endpoint is already connected (EISCONN)
    AlreadyConnected = 106,
    /// Transport endpoint is not connected (ENOTCONN)
    NotConnected = 107,
    /// Cannot send after transport endpoint shutdown (ESHUTDOWN)
    Shutdown = 108,
    /// Connection timed out (ETIMEDOUT)
    TimedOut = 110,
    /// Connection refused (ECONNREFUSED)
    ConnectionRefused = 111,
    /// Host is down (EHOSTDOWN)
    HostDown = 112,
    /// No route to host (EHOSTUNREACH)
    HostUnreachable = 113,
    /// Operation already in progress (EALREADY)
    AlreadyInProgress = 114,
    /// Operation now in progress (EINPROGRESS)
    InProgress = 115,

    // =========================================================================
    // Additional errno values
    // =========================================================================
    /// Remote I/O error (EREMOTEIO)
    RemoteIo = 121,
    /// Disk quota exceeded (EDQUOT)
    QuotaExceeded = 122,
    /// Operation canceled (ECANCELED)
    Canceled = 125,
    /// Required key not available (ENOKEY)
    NoKey = 126,
    /// Key has expired (EKEYEXPIRED)
    KeyExpired = 127,
    /// Key has been revoked (EKEYREVOKED)
    KeyRevoked = 128,
    /// Key was rejected by service (EKEYREJECTED)
    KeyRejected = 129,

    // =========================================================================
    // Kernel-internal restart codes (include/linux/errno.h); never reach
    // user space: the syscall exit path turns them into a restart or EINTR
    // =========================================================================
    /// Interrupted by a signal; restart if the handler has SA_RESTART (or
    /// no handler ran), else EINTR (ERESTARTSYS)
    RestartSys = 512,
    /// Always restart, even after a handler (ERESTARTNOINTR)
    RestartNoIntr = 513,
    /// Restart only if no handler ran, else EINTR (ERESTARTNOHAND)
    RestartNoHand = 514,
}

impl KernelError {
    /// The error for a positive errno (`None` if hk has no variant)
    pub const fn from_errno(e: i32) -> Option<Self> {
        Some(match e {
            1 => Self::NotPermitted,
            2 => Self::NotFound,
            3 => Self::NoProcess,
            4 => Self::Interrupted,
            5 => Self::Io,
            6 => Self::NoDeviceOrAddress,
            7 => Self::ArgListTooLong,
            8 => Self::ExecFormat,
            9 => Self::BadFd,
            10 => Self::NoChild,
            11 => Self::WouldBlock,
            12 => Self::OutOfMemory,
            13 => Self::PermissionDenied,
            14 => Self::BadAddress,
            15 => Self::NotBlockDevice,
            16 => Self::Busy,
            17 => Self::AlreadyExists,
            18 => Self::CrossDevice,
            19 => Self::NoDevice,
            20 => Self::NotDirectory,
            21 => Self::IsDirectory,
            22 => Self::InvalidArgument,
            23 => Self::SystemFileLimit,
            24 => Self::ProcessFileLimit,
            25 => Self::NotTty,
            26 => Self::TextBusy,
            27 => Self::FileTooLarge,
            28 => Self::NoSpace,
            29 => Self::IllegalSeek,
            30 => Self::ReadOnlyFs,
            31 => Self::TooManyLinks,
            32 => Self::BrokenPipe,
            33 => Self::MathDomain,
            34 => Self::Range,
            35 => Self::Deadlock,
            36 => Self::NameTooLong,
            37 => Self::NoLocks,
            38 => Self::NotImplemented,
            39 => Self::DirectoryNotEmpty,
            40 => Self::TooManySymlinks,
            42 => Self::NoMessage,
            43 => Self::IdentifierRemoved,
            61 => Self::NoData,
            64 => Self::NoNetwork,
            71 => Self::ProtocolError,
            62 => Self::TimerExpired,
            75 => Self::Overflow,
            74 => Self::BadMessage,
            88 => Self::NotSocket,
            89 => Self::DestAddrRequired,
            90 => Self::MessageTooLong,
            91 => Self::ProtocolType,
            92 => Self::NoProtocolOption,
            93 => Self::ProtocolNotSupported,
            94 => Self::SocketTypeNotSupported,
            95 => Self::OperationNotSupported,
            96 => Self::ProtocolFamilyNotSupported,
            97 => Self::AddressFamilyNotSupported,
            98 => Self::AddressInUse,
            99 => Self::AddressNotAvailable,
            100 => Self::NetworkDown,
            101 => Self::NetworkUnreachable,
            102 => Self::NetworkReset,
            103 => Self::ConnectionAborted,
            104 => Self::ConnectionReset,
            105 => Self::NoBufferSpace,
            106 => Self::AlreadyConnected,
            107 => Self::NotConnected,
            108 => Self::Shutdown,
            110 => Self::TimedOut,
            111 => Self::ConnectionRefused,
            112 => Self::HostDown,
            113 => Self::HostUnreachable,
            114 => Self::AlreadyInProgress,
            115 => Self::InProgress,
            121 => Self::RemoteIo,
            122 => Self::QuotaExceeded,
            125 => Self::Canceled,
            126 => Self::NoKey,
            127 => Self::KeyExpired,
            128 => Self::KeyRevoked,
            129 => Self::KeyRejected,
            512 => Self::RestartSys,
            513 => Self::RestartNoIntr,
            514 => Self::RestartNoHand,
            _ => return None,
        })
    }
    /// Return negative errno for syscall return (i64)
    ///
    /// Example: `KernelError::BadFd.sysret()` returns -9
    #[inline]
    pub const fn sysret(self) -> i64 {
        -(self as i32 as i64)
    }

    /// Convert to negative errno (i32)
    #[inline]
    pub const fn to_errno_neg(self) -> i32 {
        -(self as i32)
    }

    /// Get the positive errno value
    #[inline]
    pub const fn errno(self) -> i32 {
        self as i32
    }
}

/// Result type alias for kernel operations
pub type KernelResult<T> = Result<T, KernelError>;
