//! This module provides the raw FFI bindings to the `ioctl` data structures and functions. Refer to `fops.h` in
//! the `kern_module` folder for details about what these do and mean.
#![allow(non_camel_case_types)]

use nix::libc::*;
use nix::ioctl_read;
use nix::ioctl_readwrite;
use nix::sys::signal::SigSet;

use super::flags::vm_flags_t;
use super::registers::pt_regs;

#[repr(C)]
pub struct ThreadData {
    pub registers: pt_regs,
    pub thread_id: pid_t,
    pub sigmask: SigSet,
}

#[repr(C)]
pub struct ThreadRequest {
    pub thread_buffer: *mut ThreadData,
    pub buf_len: size_t,
    pub pid: pid_t,
}

#[repr(C)]
pub struct VMAFlagsRequest {
    pub vma_start: uintptr_t,
    pub vma_end: uintptr_t,
    pub flags: vm_flags_t,
    pub pid: pid_t,
}

const RAMINSPECT_MAGIC: c_uchar = b'r';
ioctl_readwrite!(get_threads, RAMINSPECT_MAGIC, 0, ThreadRequest);
ioctl_readwrite!(set_threads, RAMINSPECT_MAGIC, 1, ThreadRequest);
ioctl_readwrite!(get_vma_flags, RAMINSPECT_MAGIC, 2, VMAFlagsRequest);
ioctl_readwrite!(set_vma_flags, RAMINSPECT_MAGIC, 3, VMAFlagsRequest);