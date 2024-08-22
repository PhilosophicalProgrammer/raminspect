//! # raminspect: A kernel-level ethical hacking library, written in Rust
//! 
//! ## Overview
//!
//! `raminspect` is a crate that allows for the direct inspection and manipulation of the memory, registers,
//! and code of a running process on a Linux system. It provides functions for finding and replacing search
//! terms in a processes' memory, getting and setting the register state and signal masks of all running
//! threads of a process, as well as an interface that allows for the injection of arbitrary shellcode
//! running in the processes' context. All of this requires root privileges, for obvious reasons.
//! 
//! Most of this functionality is implemented through a backend kernel module, which can be installed from
//! the Github repository. The most you can do without the kernel module is directly read and write memory
//! from already-readable or already-writable memory areas respectively, and pause and resume a process.
//! This is fine for some use cases, but most users will want access to the other features.
//! 
//! To get started, see [`RamInspector`], which provides the main interface. For more advanced usage,
//! you can use the kernel API directly, accessible through [`RamInspector::kernapi`]. See the
//! documentation of [`RawInspector`][`kapi::RawInspector`] for more information.
//! 
//! ## Demonstration of Functionality
//! 
//! ![262029237-7c55e611-93ff-47cc-8a72-a00840991270](https://github.com/ljgermain/raminspect/assets/154016542/22d59c32-163f-4ba6-8860-89545b64c93e)
//! TODO: Add injection demonstration

#![forbid(missing_docs)]
#![warn(clippy::all)]

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