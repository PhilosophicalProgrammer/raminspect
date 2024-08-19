//! This module and its submodules provide thorough and well-documented mechanisms for interacting with the
//! kernel module that underpins typical usage of `raminspect`. See the documentation of [`RawInspector`],
//! which ties all of the components of the kernel API together, for more information.

mod ioctl;
pub mod flags;
pub mod tlist;
pub mod registers;

use std::fs::File;
use std::os::fd::AsRawFd;
use std::mem::MaybeUninit;

use nix::libc::c_int;
use nix::libc::pid_t;
use nix::libc::c_ulong;

use nix::unistd::Uid;
use nix::errno::Errno;

use ioctl::*;
use flags::*;
use tlist::ThreadList;
use crate::error::Result;
use crate::region::MemoryRegion;
use crate::error::RamInspectError as Error;

/// This structure is used internally by the library to provide an interface to the raw kernel APIs
/// provided by the kernel module via `ioctl`. It is made public to enable advanced usage that involves
/// directly reading and writing thread registers and signal masks, which is necessary for some
/// applications.
/// 
/// This cannot be created directly. Instead, it should be accessed via the [`RamInspector::kernapi`]
/// method after creating a higher-level `RamInspector` structure for a process. Note that it is
/// recommended to consider if the higher-level interface suits your use case or not before
/// using this.
/// 
/// # Example Usage
/// 
/// This example modifies the stack pointer of the main thread of a process using the raw API:
/// 
/// ```rust
/// use raminspect::RamInspector;
/// let new_stack_addr = 0x10000; // Replace this with the new address of the top of the stack.
/// let mut inspector = RamInspector::new(1234)?; // Replace 1234 with the PID you want to modify.
/// 
/// let mut kapi = inspector.kernapi()?;
/// let mut threads = kapi.get_threads()?;
/// *threads.main().registers.stack_ptr() = new_stack_addr;
/// kapi.set_threads(&threads)?;
/// ```

pub struct RawInspector {
    device: File,
    pid: pid_t
}

impl RawInspector {
    /// Creates a new raw inspector.
    pub(crate) fn new(pid: pid_t) -> Result<Self> {
        if(!Uid::effective().is_root()) {
            return Err(Error::NoRootPerms);
        }

        Ok(Self {
            pid,
            device: File::open("/dev/raminspect").map_err(|_| {
                Error::FailedToOpenDevice
            })?
        })
    }

    pub fn get_threads(&self) -> Result<ThreadList> {
        // This is in a loop so that we can retry the `ioctl` call with a larger buffer if the buffer is too small.
        let mut buf_len = 100;

        loop {
            let mut thread_buffer: Vec<ThreadData> = Vec::with_capacity(buf_len);
            
            unsafe {
                // Initialize the thread buffer.
                for i in 0..(buf_len as isize) {
                    // This is safe since `ThreadData` is always zeroable.
                    thread_buffer.as_mut_ptr().offset(i).write(core::mem::zeroed());
                }
    
                // Safe since we previously initialized all elements.
                thread_buffer.set_len(buf_len);

                // Execute the `ioctl`.
                let mut request = ThreadRequest {
                    thread_buffer: thread_buffer.as_mut_ptr(),
                    pid: self.pid,
                    buf_len,
                };
    
                match get_threads(self.device.as_raw_fd(), &mut request) {
                    Ok(_) => {
                        // The returned `buf_len` contains the amount of threads actually read into the buffer.
                        thread_buffer.truncate(request.buf_len);

                        return Ok(ThreadList {
                            data: thread_buffer,
                            pid: self.pid
                        });
                    },

                    Err(errno) => match errno {
                        Errno::ERANGE => {
                            buf_len *= 4;
                            continue;
                        },

                        _ => return Err(Error::from_errno(errno))
                    }
                }
            }
        }
    }

    pub unsafe fn set_threads(&self, threads: &ThreadList) -> Result<c_int> {
        let mut request = ThreadRequest {
            // Casting to a `*mut` pointer is safe here since `set_threads` doesn't actually modify any data in the buffer.
            thread_buffer: threads.as_ptr() as *mut ThreadData,
            buf_len: threads.len(),
            pid: self.pid,
        };

        set_threads(self.device.as_raw_fd(), &mut request).map_err(Error::from_errno)
    }

    /// Gets the raw access flags of a provided memory region. You should prefer to use the
    /// methods directly provided by [`MemoryRegion`] if possible, since this is harder to
    /// use and requires that the kernel module as loaded.
    /// 
    /// The return value of this function is a bitfield. See the [`flags`] module for a
    /// comprehensive list of flag definitions.
    /// 
    /// # Example Usage
    /// 
    /// See [`MemoryRegion::set_vma_flags`], which provides a thorough example of how code
    /// injection can be achieved through flag modification. Flag definitions can be found
    /// in the [`crate::flags`] module.
    
    pub(crate) fn get_vma_flags(&self, region: &MemoryRegion) -> Result<vm_flags_t> {
        let mut request = VMAFlagsRequest {
            vma_start: region.start_addr(),
            vma_end: region.end_addr(),
            pid: self.pid,
            flags: 0,
        };

        unsafe {
            match get_vma_flags(self.device.as_raw_fd(), &mut request) {
                Ok(_) => Ok(request.flags),
                Err(errno) => Err(Error::from_errno(errno))
            }
        }
    }

    /// Modifies the access flags of a memory region. Always use this in conjunction with [`RawInspector::get_vma_flags`]
    /// in order to preserve the flags that you don't want to change, otherwise there could be unexpected behavior.
    /// 
    /// # Safety
    /// 
    /// Modifying the access permissions of an arbitrary memory area is a fundamentally memory-unsafe operation. Done
    /// incorrectly, it could interfere with invariants that a program assumes to be true and cause instability. Use
    /// this with caution.
    /// 
    /// # Example Usage
    /// 
    /// This is a simplified example of how you could inject code into a process by using this function. It does
    /// not restore the old state of the process or perform any kind of cleanup, and is meant to be a simple
    /// demonstration rather than something that actually functions in practice.
    /// 
    /// If you want to successfully inject code, then see [`RamInspector::execute_shellcode`], which essentially
    /// does the same thing as this example, but with additional measures in place to avoid detection and restore
    /// the state of the process afterwards:
    /// 
    /// ```rust
    /// use raminspect::RamInspector;
    /// use raminspect::kapi::flags::VM_WRITE;
    /// let mut inspector = RamInspector::new(1234)?; // Replace 1234 with your target PID
    /// let injected_code = include_bytes!("your_shellcode.bin"); // Put whatever instructions you want here
    /// 
    /// // Leaving the process resumed while doing this would lead to us writing to an outdated instruction pointer,
    /// // and nothing would actually execute.
    /// 
    /// inspector.do_while_paused(|| unsafe {
    ///     // Make the memory region containing the main threads' instruction pointer writable so that we can modify it.
    /// 
    ///     let kapi = inspector.kernapi()?;
    ///     let ptr = kapi.get_threads()?.main().registers.inst_ptr();
    /// 
    ///     // This is guaranteed to exist, so it's safe to unwrap.
    ///     let code_region = inspector.regions().find(|region| region.addr_range().contains(ptr)).unwrap();
    ///     
    ///     let old_flags = kapi.get_vma_flags(code_region)?;
    ///     kapi.set_vma_flags(code_region, old_flags | VM_WRITE)?;
    /// 
    ///     // Now that it's writable, we insert our code.
    ///     inspector.write_to_address(code_region.start_addr, injected_code)?;
    /// 
    ///     // Then we restore the old flags.
    ///     code_region.set_raw_flags(old_flags, kapi);
    /// })?;
    /// 
    /// // By now your injected code should be executing.
    /// ```
    
    pub(crate) unsafe fn set_vma_flags(&self, region: &mut MemoryRegion, flags: vm_flags_t) -> Result<()> {
        set_vma_flags(self.device.as_raw_fd(), &mut VMAFlagsRequest {
            vma_start: region.start_addr(),
            vma_end: region.end_addr(),
            pid: self.pid,
            flags,
        });

        region.readable = (flags & VM_READ) != 0;
        region.writable = (flags & VM_WRITE) != 0;
        region.executable = (flags & VM_EXEC) != 0;
        Ok(())
    }
}