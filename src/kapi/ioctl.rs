//! This module provides the raw FFI bindings to the `ioctl` data structures and functions. Documentation in this
//! module is directly copied from `fops.h` in the kernel module source and kept in sync with it.
#![allow(non_camel_case_types)]

use nix::libc::*;
use nix::ioctl_read;
use nix::ioctl_readwrite;

use super::VmFlags;
use super::registers::pt_regs;

/// This is sent to and received back from a process using the `*_THREADS` ioctls. It contains
/// the thread ID that the data belongs to in the case of `GET_THREADS`, or the thread ID of
/// the thread to write this data to in the case of `SET_THREADS`. It also contains
/// information about the signal mask and registers of the target thread.

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ThreadData {
    /// The general-purpose registers of this thread. Note that the floating-point register state is not stored
    /// in this field. To retrieve or modify that, custom shellcode might be necessary.
    pub registers: pt_regs,

    /// This is the raw signal mask used by the kernel scheduler. Specifically, it is the lower 64 bits of the mask,
    /// since the actual size is higher on a few architectures, but userspace has no reasonable way to know this
    /// and rely on it. For that reason, we only expose the most bits that we can safely expose across
    /// architectures, which happens to be 64 bits.
    ///
    /// It is distinct from the typical `sigset_t` type provided by `libc`, as it is simply a bitmask of signal numbers
    /// rather than an array of integers. The bit that represents a signal is located at `(1 << SIGNUM)`, where `SIGNUM`
    /// is the `libc` constant that corresponds to the signal that you want to modify. To mask `SIGCONT`, for example,
    /// you could write the following: `sigmask &= ~(1 << SIGCONT)`
    pub sigmask: u64,

    /// The thread ID of the thread, which is the same as the process ID of the parent process if it's the main thread.
    pub thread_id: pid_t,
}

/// This is used in the `*_THREADS` ioctls. It contains a buffer of `thread_data` structures, the
/// process ID that they all belong to, and the length of the buffer.
///
/// In the case of `GET_THREADS`, the buffer is uninitialized and can hold a maximum of `buf_len` elements,
/// and the thread data retrieved by this module from the process will be written into it, updating the
/// buffer length to represent the amount of threads retrieved. If the given buffer length is too small
/// to hold all of the threads, an `ERANGE` error code will be given to the user and they'll have to
/// retry with a larger buffer.
///
/// In the case of `SET_THREADS`, the buffer is not uninitialized, and the buffer length represents the
/// amount of thread data that was given by the user. Invalid thread IDs will be ignored, and valid
/// thread IDs will have their signal masks and registers updated to match their provided data.

#[repr(C)]
pub struct ThreadRequest {
    pub thread_buffer: *mut ThreadData,
    pub buf_len: size_t,
    pub pid: pid_t,
}

/// This is used in the `SET_VMA_FLAGS` ioctl. It contains a process ID, the start and end address of
/// a memory region within this process, and the new set of flags to apply to the memory region.

#[repr(C)]
pub struct VMAFlagsRequest {
    pub vma_start: uintptr_t,
    pub vma_end: uintptr_t,
    pub flags: VmFlags,
    pub pid: pid_t,
}

const RAMINSPECT_MAGIC: c_uchar = b'r';
ioctl_readwrite!(get_threads, RAMINSPECT_MAGIC, 0, ThreadRequest);
ioctl_readwrite!(set_threads, RAMINSPECT_MAGIC, 1, ThreadRequest);
ioctl_read!(set_vma_flags, RAMINSPECT_MAGIC, 2, VMAFlagsRequest);