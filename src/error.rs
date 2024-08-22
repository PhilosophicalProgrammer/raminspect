//! Provides the error type for this library and a custom [`Result`] type. See [`RamInspectError`].

use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use std::process::ExitCode;
use std::process::Termination;
use nix::errno::Errno;

/// This can represent any possible error returned by this library's functions. It is not
/// intended to be used directly by users. Instead, you should use the [`Result`] type
/// provided by this module.

#[derive(Debug, Clone, Copy)]
pub enum RamInspectError {
    /// Root permissions are necessary to use the kernel API.
    NoRootPerms,

    /// The `raminspect` device file could not be opened.
    FailedToOpenDevice,

    /// A handle to the requested PID could not be retrieved.
    FailedToAccessProcess,

    /// The requested resource was not found.
    NotFound,

    /// Invalid data was provided to the kernel module.
    InvalidAddress,
    
    /// An invalid `ioctl` command code was used.
    InvalidCommand,

    /// The call to `sysconf` to retrieve `max_iovs` returned no information.
    SysconfFailed,

    /// Failed to read memory.
    FailedToReadMem,

    /// Failed to write memory.
    FailedToWriteMem,

    /// Failed to open process maps.
    FailedToGetMaps,

    /// The execution of the shellcode timed out (i.e. no signal was received within a second).
    ExecTimeout,

    /// The provided PID cookie couldn't be found.
    CookieNotFound,

    /// The shellcode injected by `allocate_memory` returned an error.
    AllocFailed(Errno),

    /// The requested operation only completed partially.
    Partial(usize),

    /// `nix` returned an unknown error.
    Errno(Errno),
}

impl RamInspectError {
    /// Converts an error code from the kernel module into an error variant.
    
    pub(crate) fn kern_errno(errno: Errno) -> Self {
        match errno {
            Errno::ENOTTY => Self::InvalidCommand,
            Errno::EFAULT => Self::InvalidAddress,
            Errno::ESRCH => Self::NotFound,
            _ => Self::from(errno)
        }
    }
}

impl From<Errno> for RamInspectError {
    fn from(errno: Errno) -> Self {
        Self::Errno(errno)
    }
}

impl Display for RamInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            // Initialization errors.
            RamInspectError::NoRootPerms => "Root privileges are required in order to use the kernel-level interface. This is by design.",
            RamInspectError::FailedToOpenDevice => "Failed to open `/dev/raminspect`. Are you sure that the kernel module is loaded?",
            RamInspectError::FailedToAccessProcess => "Failed to create a handle to the requested PID.",
            RamInspectError::SysconfFailed => "Failed to retrieve `max_iovs` from `sysconf`.",

            // Kernel module errors.
            RamInspectError::InvalidAddress => "Invalid data was provided to the kernel module. This shouldn't happen if you're using the high-level \
            library-provided interface, in which case you should open a GitHub issue. If you're using the raw interface, however, then you should \
            investigate the soundness of your program and the documentation.",

            RamInspectError::InvalidCommand => "Invalid `ioctl` command. This is always an indication of a problem in the library. Please open a GitHub issue with an MRE.",
            RamInspectError::NotFound => "The target process was not found, meaning that either the provided PID was wrong or that it unexpectedly terminated.",

            // Memory reading / writing errors.
            RamInspectError::Partial(n) => return write!(formatter, "The requested operation only completed partially: {} bytes were read or written", n),
            RamInspectError::FailedToGetMaps => "Failed to access the memory maps for the target process.",
            RamInspectError::FailedToWriteMem => "Failed to write to the specified address.",
            RamInspectError::FailedToReadMem => "Failed to read the specified address.",

            // Shellcode execution errors.
            RamInspectError::ExecTimeout => "The execution of the provided shellcode timed out. Are you sure you're sending `SIGUSR1` to the injector when it finishes?",
            RamInspectError::AllocFailed(errno) => return write!(formatter, "The `mmap` syscall failed with this error code while allocating: {}", errno),
            RamInspectError::CookieNotFound => "The provided PID cookie could not be found in the provided shellcode.",

            // Crate-specific errors from `nix`
            RamInspectError::Errno(errno) => return Display::fmt(errno, formatter),
        })
    }
}

impl Termination for RamInspectError {
    fn report(self) -> ExitCode {
        println!("Error: {}", self);
        ExitCode::FAILURE
    }
}

impl std::error::Error for RamInspectError {}
/// The result type for this library. Prefer this over direct usage of [`std::result::Result`]. 
pub type Result<T> = std::result::Result<T, RamInspectError>;