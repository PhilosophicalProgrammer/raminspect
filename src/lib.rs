//! raminspect is a crate that allows for the inspection and manipulation of the memory and code of 
//! a running process on a Linux system. It provides functions for finding and replacing search terms 
//! in a processes' memory, as well as an interface that allows for the injection of arbitrary shellcode 
//! running in the processes' context. All of this requires root privileges, for obvious reasons.
#![warn(clippy::all)]
#![allow(unused)]

pub mod kapi;
pub mod error;
pub mod region;
pub mod process;
pub mod inspector;

pub use error::Result;
pub use error::RamInspectError;
pub use process::find_processes;
pub use process::iter_processes;
pub use inspector::RamInspector;