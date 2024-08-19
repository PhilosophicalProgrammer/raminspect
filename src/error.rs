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

pub enum RamInspectError {
    /// Root permissions are necessary to use the kernel API.
    NoRootPerms,

    /// The `raminspect` device file could not be opened.
    FailedToOpenDevice,

    /// The requested resource was not found.
    NotFound,

    /// Invalid data was provided to the kernel module.
    InvalidAddress,
    
    /// An invalid `ioctl` command code was used.
    InvalidCommand,

    /// An unknown error occurred.
    Unknown,
}

impl RamInspectError {
    /// Creates an error from a C error code. Used by the kernel API.
    
    pub(crate) fn from_errno(errno: Errno) -> Self {
        match errno {
            Errno::ENOTTY => Self::InvalidCommand,
            Errno::EFAULT => Self::InvalidAddress,
            Errno::ESRCH => Self::NotFound,
            _ => Self::Unknown,
        }
    }
}

pub type Result<T> = std::result::Result<T, RamInspectError>;

impl Debug for RamInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            RamInspectError::NoRootPerms => "Root privileges are required in order to use the kernel-level interface. This is by design.",
            RamInspectError::FailedToOpenDevice => "Failed to open `/dev/raminspect`. Are you sure that the kernel module is loaded?",
            RamInspectError::InvalidAddress => "Invalid data was provided to the kernel module. This shouldn't happen if you're using the high-level \
            library-provided interface, in which case you should open a GitHub issue. If you're using the raw interface, however, then you should \
            investigate the soundness of your program and the documentation.",

            RamInspectError::InvalidCommand => "Invalid `ioctl` command. This is always an indication of a problem in the library. Please open a GitHub issue with an MRE.",
            RamInspectError::NotFound => "The target process was not found, meaning that either the provided PID was wrong or that it unexpectedly terminated.",
            RamInspectError::Unknown => "An unknown error occurred. Please open a GitHub issue with an MRE."
        })
    }
}

impl Display for RamInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}

impl Termination for RamInspectError {
    fn report(self) -> ExitCode {
        println!("Error: {}", self);
        ExitCode::FAILURE
    }
}