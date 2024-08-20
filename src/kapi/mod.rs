//! This module and its submodules provide thorough and well-documented mechanisms for interacting with the
//! kernel module that underpins typical usage of `raminspect`. See the documentation of [`RawInspector`],
//! which ties all of the components of the kernel API together, for more information.

mod ioctl;
pub mod tlist;
pub mod registers;

use std::fs::File;
use std::os::fd::AsRawFd;

use nix::libc::pid_t;
use nix::unistd::Uid;
use nix::errno::Errno;

use ioctl::*;
use tlist::ThreadList;
use crate::error::Result;
use crate::error::RamInspectError as Error;

use crate::region::VmFlags;
use crate::region::MemoryRegion;

// Used in docs.
#[allow(unused_imports)]
use crate::inspector::RamInspector;

/// This structure is used internally by the library to provide an interface to the raw kernel API
/// provided by the kernel module via `ioctl`. It is exposed publicly to enable powerful and advanced
/// usage that involves directly reading and writing thread registers and signal masks, which is
/// necessary for some applications.
/// 
/// This cannot be created directly. Instead, it should be accessed via the [`RamInspector::kernapi`]
/// method after creating a higher-level `RamInspector` structure for a process. Note that it is
/// recommended to consider if the higher-level interface suits your use case or not before
/// using this.
/// 
/// # Example Usage
/// 
/// This example modifies the stack pointer of the main thread of a process using the kernel API:
/// 
/// ```rust
/// use raminspect::RamInspector;
/// let new_stack_addr = 0x10000; // Replace this with the new address of the top of the new stack.
/// let mut inspector = RamInspector::new(1234)?; // Replace 1234 with the PID you want to modify.
/// let kapi = inspector.kernapi()?;
/// 
/// inspector.do_while_paused(|| {
///     let mut threads = kapi.get_threads()?;
///     *threads.main().registers.stack_ptr() = new_stack_addr;
///     kapi.set_threads(&threads)?;
/// })?;
/// ```

pub struct RawInspector {
    device: File,
    pid: pid_t
}

impl RawInspector {
    /// Creates a new raw inspector.
    pub(crate) fn new(pid: pid_t) -> Result<Self> {
        if !Uid::effective().is_root() {
            return Err(Error::NoRootPerms);
        }

        Ok(Self {
            pid,
            device: File::open("/dev/raminspect").map_err(|_| {
                Error::FailedToOpenDevice
            })?
        })
    }

    /// This function allows for the retrieval of the registers and signal masks of all of the active threads
    /// of an arbitrary process. This can be used for inspecting the state of the process, or it can be used
    /// to modify it when used in conjunction with [`RawInspector::set_threads`].
    /// 
    /// Information retrieved using this function is essentially worthless if the process is resumed, since it
    /// will have likely changed beyond recognition by the time you finish processing it. This should generally
    /// only be called inside of a [`RamInspector::do_while_paused`] block for that reason. It is fully safe
    /// to use since data is only being read and not modified (i.e. it does not interfere with process
    /// execution in any way).
    ///
    /// # Example Usage
    /// 
    /// This example retrieves the instruction pointer of the main thread of a process:
    /// 
    /// ```rust
    /// use raminspect::RamInspector;
    /// let mut inspector = RamInspector::new(1234)?; // Replace 1234 with your target process ID
    /// let kapi = inspector.kernapi()?;
    /// 
    /// inspector.do_while_paused(|inspector| {
    ///     // `ThreadList` provides a convenience function for retrieving the main thread from the list.
    ///     let inst_ptr = *kapi.get_threads()?.main().registers.inst_ptr();
    ///     println!("Process instruction pointer: 0x{:X}", inst_ptr);
    /// })?;
    /// ```

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

                        _ => return Err(Error::kern_errno(errno))
                    }
                }
            }
        }
    }

    /// This allows for the arbitrary modification of the registers and signal masks of all of the threads of a
    /// running process. The [`ThreadList`] argument is obtained via [`RawInspector::get_threads`]. As with the
    /// rest of the kernel API functions, the process should be paused with [`RamInspector::do_while_paused`]
    /// before using it in order to ensure correctness and stability.
    /// 
    /// # Safety
    /// 
    /// This is very powerful and dangerous functionality that allows for completely controlling the memory state and execution of
    /// a process when used in conjunction with the higher-level direct memory access functions (see [`RamInspector::regions`]
    /// and [`RamInspector::write_to_address`]). No checks are in place, or indeed would even be possible to implement,
    /// that ensure that the changes you make to the underlying process are safe and correct. As a consequence, this
    /// function is marked as unsafe in *bold letters*. Use with caution.
    /// 
    /// # Example Usage
    /// 
    /// The top-level documentation of this structure provides an example. Link: [`RawInspector`]
    
    pub unsafe fn set_threads(&self, threads: &ThreadList) -> Result<()> {
        set_threads(self.device.as_raw_fd(), &mut ThreadRequest {
            // Casting to a `*mut` pointer is safe here since `set_threads` doesn't actually modify any data in the buffer.
            thread_buffer: threads.as_ptr() as *mut ThreadData,
            buf_len: threads.len(),
            pid: self.pid,
        }).map_err(Error::kern_errno)?;
        Ok(())
    }

    /// Modifies the access flags of a memory region. Always use this in conjunction with [`MemoryRegion::flags`] in
    /// order to preserve the flags that you don't want to change, otherwise there could be unexpected behavior.
    /// 
    /// # Safety
    /// 
    /// Modifying the access permissions of an arbitrary memory area is a fundamentally memory-unsafe operation. Done
    /// incorrectly, it could interfere with invariants that a program assumes to be true and cause instability or
    /// crashes. Use this with caution.
    /// 
    /// # Example Usage
    /// 
    /// This is a simplified example of how you could inject code into a process by using this function. It does
    /// not restore the old state of the process or perform any kind of cleanup, and is meant to be a simple
    /// demonstration rather than something that actually functions in practice.
    /// 
    /// If you want to successfully inject code, then see [`RamInspector::execute_shellcode`], which essentially
    /// does the same thing as this example, but with additional measures in place to puase the other threads,
    /// avoid detection, and restore the state of the process afterwards:
    /// 
    /// ```rust
    /// use raminspect::RamInspector;
    /// use raminspect::region::VmFlags;
    /// let mut inspector = RamInspector::new(1234)?; // Replace 1234 with your target PID
    /// let injected_code = include_bytes!("your_shellcode.bin"); // Put whatever instructions you want here
    /// 
    /// // Leaving the process resumed while doing this would lead to us writing to an outdated instruction pointer,
    /// // and nothing would actually execute, so we use `do_while_paused`. This is recommended for any use of the
    /// // kernel API in order to maintain process stability.
    /// 
    /// let kapi = inspector.kernapi()?;
    /// inspector.do_while_paused(|inspector| unsafe {
    ///     // Make the memory region containing the main threads' instruction pointer writable so that we can modify it.
    ///     let ip = kapi.get_threads()?.main().registers.inst_ptr();
    /// 
    ///     // This is guaranteed to exist, so it's safe to unwrap here.
    ///     let mut code_region = inspector.regions().find(|region| region.addr_range().contains(ip)).unwrap();
    ///     kapi.set_vma_flags(&mut code_region, code_region.flags() | VmFlags::WR)?;
    /// 
    ///     // Now that it's writable, we insert our code.
    ///     inspector.write_to_address(code_region.start_addr, injected_code)?;
    /// })?;
    /// 
    /// // By now your injected code should be executing.
    /// ```
    
    pub unsafe fn set_vma_flags(&self, region: &mut MemoryRegion, flags: VmFlags) -> Result<()> {
        region.inner.extension.vm_flags = flags;
        set_vma_flags(self.device.as_raw_fd(), &mut VMAFlagsRequest {
            vma_start: region.start_addr(),
            vma_end: region.end_addr(),
            pid: self.pid,
            flags,
        }).map_err(Error::kern_errno)?;
        Ok(())
    }
}