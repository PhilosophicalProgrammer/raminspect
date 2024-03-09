//! raminspect is a crate that allows for the inspection and manipulation of the memory and code of 
//! a running process on a Linux system. It provides functions for finding and replacing search terms 
//! in a processes' memory, as well as an interface that allows for the injection of arbitrary shellcode 
//! running in the processes' context. All of this requires root privileges, for obvious reasons.

// Starting from v0.3.0, we use libc and alloc instead of std and nix to support 
// architectures like 32-bit RISCV which don't have standard library support. This 
// complicates the code quite a bit but it's a price I'm willing to pay for cross-
// platform support.

#![no_std]
extern crate alloc;

use libc::*;
use core::sync::atomic::Ordering;
use core::sync::atomic::AtomicUsize;

use alloc::vec;
use alloc::format;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::vec::IntoIter;
use alloc::string::String;
/// Used for cleaner handling of errors from calling libc functions

trait IntoResult: Sized {
    fn into_result(self, error: RamInspectError) -> Result<Self, RamInspectError>;
}

macro_rules! impl_into_result_for_num {
    ($num_ty:ty) => {
        impl IntoResult for $num_ty {
            fn into_result(self, error: RamInspectError) -> Result<Self, RamInspectError> {
                if self < 0 {
                    Err(error)
                } else {
                    Ok(self)
                }
            }
        }
    }
}

impl_into_result_for_num!(i32);
impl_into_result_for_num!(i64);
impl_into_result_for_num!(isize);

impl<T> IntoResult for *mut T {
    fn into_result(self, error: RamInspectError) -> Result<Self, RamInspectError> {
        if self.is_null() {
            Err(error)
        } else {
            Ok(self)
        }
    }
}

/// A wrapper around a raw file descriptor that closes itself when
/// dropped. This exists to prevent leaks.

struct FileWrapper {
    descriptor: i32
}

impl FileWrapper {
    fn open(path: &str, mode: i32, on_err: RamInspectError) -> Result<Self, RamInspectError> {
        // Assert that the provided string is null terminated
        assert!(path.ends_with('\0'));

        Ok(Self {
            descriptor: unsafe {
                // This is safe because we already asserted that the path is null-terminated
                open(path.as_ptr() as _, mode).into_result(on_err)?
            }
        })
    }
}

impl Drop for FileWrapper {
    fn drop(&mut self) {
        unsafe {
            close(self.descriptor);
        }
    }
}

/// A packet sent to the backend kernel module through an 'ioctl' call 
/// that requests the current instruction pointer of an application.

#[repr(C)]
struct InstructionPointerRequest {
    pid: i32,
    instruction_pointer: u64,
}

// ioctl command definitions
const RESTORE_REGS: c_ulong = 0x40047B03;
const GET_INST_PTR: c_ulong = 0xC0107B02;
const WAIT_FOR_FINISH: c_ulong = 0x40047B00;
const TOGGLE_EXEC_WRITE: c_ulong = 0x40047B01;

/// Finds a list of all processes containing a given search term in their 
/// program name. This makes figuring out the process ID of the process 
/// you want to inspect or inject shellcode into easier.

pub fn find_processes(name_contains: &str) -> Vec<i32> {
    let mut results = Vec::new();
    const MAX_LINE_LENGTH: usize = 4096;

    unsafe {
        // Iterate over all process IDs in the /proc directory
        let dirp = opendir("/proc\0".as_ptr() as _);
        if dirp.is_null() { return results; }

        loop {
            let entry_ptr = readdir(dirp);
            if entry_ptr.is_null() { break; }

            // Convert the array of C chars representing the directory name to a Rust string slice.
            let name_bytes: [u8; 256] = core::mem::transmute(core::ptr::read(entry_ptr).d_name);
            let end_of_str = name_bytes.iter().position(|byte| *byte == 0).unwrap();
            let name = core::str::from_utf8(&name_bytes[..end_of_str]).unwrap();

            // Make sure it's a PID's proc directory before continuing.
            let pid = match name.parse::<i32>() {
                Ok(pid) => pid,
                Err(_) => continue,
            };

            let path = format!("/proc/{}/cmdline\0", pid);
            let fd = open(path.as_ptr() as _, O_RDONLY);
            if fd < 0 { continue; }

            let mut buf = vec![0; MAX_LINE_LENGTH];
            if read(fd, buf.as_mut_ptr() as _, buf.len()) < 0 {
                close(fd);
                continue;
            }

            // The first occurence of a null byte in /proc/pid/cmdline delineates the end of
            // the processes' command invocation name. See the corresponding section on this 
            // page for more information: https://man7.org/linux/man-pages/man5/proc.5.html

            let executable_name = core::str::from_utf8(
                &buf[..buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len())]
            ).unwrap();

            if executable_name.contains(name_contains) {
                results.push(pid);
            }

            close(fd);
        }
    }
    
    results
}

/// This is the primary interface used by the crate to search through, read, and modify an
/// arbitrary processes' memory and code.
/// 
/// Note that when an inspector is created for a process, the process will be paused until
/// the inspector is dropped in order to ensure that we have exclusive access to the
/// processes' memory, unless it is manually resumed through a call to 
/// [`RamInspector::resume_process`].
/// 
/// # Example Usage
/// 
/// ```rust
/// //! This example changes the current text in Firefox's browser search bar from 
/// //! "Old search text" to "New search text". To run this example, open an instance
/// //! of Firefox and type "Old search text" in the search bar. If all goes well, when
/// //! you run this example as root, it should be replaced with "New search text",
/// //! although you may have to click on the search bar again in order for it to
/// //! render the new text.
/// 
/// fn main() {
///     use raminspect::RamInspector;
///     // Iterate over all running Firefox instances
///     for pid in raminspect::find_processes("/usr/lib/firefox/firefox") {
///         let mut inspector = match RamInspector::new(pid) {
///             Ok(inspector) => inspector,
///             Err(_) => continue,
///         };
///         
///         for (proc_addr, memory_region) in inspector.search_for_term(b"Old search text").unwrap() {
///             if !memory_region.writable() {
///                 continue;
///             }
/// 
///             unsafe {
///                 // This is safe because modifying the text in the Firefox search bar will not crash
///                 // the browser or negatively impact system stability in any way.
/// 
///                 println!("Writing to process virtual address: 0x{:X}", proc_addr);
///                 inspector.queue_write(proc_addr, b"New search text");
///             }
///         }
/// 
///         unsafe {
///             // This is safe since the process is not currently resumed, which would possibly cause a data race.
///             inspector.flush().unwrap();
///         }
///     }
/// }
/// ```

pub struct RamInspector {
    pid: i32,
    max_iovs: usize,
    proc_maps_file: *mut FILE,
    resume_count: Arc<AtomicUsize>,
    write_requests: Vec<(usize, Vec<u8>)>,
}

// This is safe because the pointer inside can only be accessed through methods 
// that take a mutable reference to the inspector, and therefore all accesses 
// to it must be synchronized.

unsafe impl Send for RamInspector {}
unsafe impl Sync for RamInspector {}

#[non_exhaustive]
#[derive(Clone, Copy)]
/// The error type for this library. The variants have self-explanatory names.

pub enum RamInspectError {
    ProcessTerminated,
    FailedToOpenProcMaps,
    FailedToPauseProcess,
    FailedToResumeProcess,

    FailedToReadMem,
    FailedToWriteMem,
    FailedToOpenDeviceFile,
    FailedToAllocateBuffer,
    InspectorAlreadyExists,
}

use core::fmt;
use core::fmt::Debug;
use core::fmt::Formatter;
impl Debug for RamInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            RamInspectError::InspectorAlreadyExists => "A `RamInspector` instance already exists for the specified process ID. \
                                                        Note: If you're in a multi-threaded environment, instead of creating \
                                                        multiple inspectors you can try accessing one inspector through a \
                                                        mutex.",

            RamInspectError::FailedToOpenDeviceFile => "Failed to open the raminspect device file! Are you sure the kernel module is currently inserted? If it is, are you running as root?",
            RamInspectError::FailedToOpenProcMaps => "Failed to access the target processes' memory maps! Are you sure you're running as root? If you are, is the target process running?",
            RamInspectError::FailedToWriteMem => "Failed to write to the specified memory address! Are you sure the address is in a writable region of the processes' memory?",
            RamInspectError::FailedToReadMem => "Failed to read from the specified memory address! Are you sure the address is in a readable region of the processes' memory?",
            RamInspectError::FailedToResumeProcess => "Failed to resume the target process! Are you sure it is currently running?",
            RamInspectError::FailedToPauseProcess => "Failed to pause the target process! Are you sure it is currently running?",
            RamInspectError::FailedToAllocateBuffer => "Failed to allocate the specified buffer.",
            RamInspectError::ProcessTerminated => "The target process unexpectedly terminated.",
        })
    }
}

use core::fmt::Display;
impl Display for RamInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}

use spin::Mutex;
static INSPECTED_PIDS: Mutex<Vec<i32>> = Mutex::new(Vec::new());

impl RamInspector {
    /// Creates a new inspector attached to the specified process ID. This will pause the target process until
    /// the inspector is dropped or until it's manually resumed using [`RamInspector::resume_process`].
    /// 
    /// Note that creating two inspectors simultaneously referring to the same process is not supported, and attempting 
    /// to do so will return a [`RamInspectError`] of the kind [`RamInspectError::InspectorAlreadyExists`]. If you want 
    /// to do this you should access the same inspector instead, synchronizing said access if you're in a multithreaded 
    /// environment.
    
    pub fn new(pid: i32) -> Result<Self, RamInspectError> {
        unsafe {
            if INSPECTED_PIDS.lock().contains(&pid) {
                return Err(RamInspectError::InspectorAlreadyExists);
            }

            INSPECTED_PIDS.lock().push(pid);
            let maps_path = format!("/proc/{}/maps\0", pid);
            let proc_maps_file = fopen(maps_path.as_ptr() as _, "r\0".as_ptr() as _).into_result(
                RamInspectError::FailedToOpenProcMaps
            )?;
    
            // Pause the target process with a SIGSTOP signal
            if let Err(error) = kill(pid, SIGSTOP).into_result(RamInspectError::FailedToPauseProcess) {
                fclose(proc_maps_file);
                return Err(error);
            }

            let max_iovs = sysconf(_SC_IOV_MAX);

            if max_iovs < 0 {
                fclose(proc_maps_file);
                panic!("Unsupported kernel version or platform.");
            }

            Ok(RamInspector {
                pid,
                proc_maps_file,
                write_requests: Vec::new(),
                max_iovs: max_iovs as usize,
                resume_count: Arc::new(AtomicUsize::new(0)),
            })
        }
    }

    /// Resumes the target process, returning a handle that pauses the process again when dropped,
    /// assuming no other handles currently exist. Use this carefully, since writing to the 
    /// processes' memory while it's resumed may cause data races with the processes' code.
    /// 
    /// If multiple handles are created before all the others are dropped, the process will remain 
    /// resumed until every one of its resume handles is dropped and dropping an individual handle 
    /// while other handles for the process still exist will have no effect. This ensures 
    /// correctness in multi-threaded contexts.
    
    pub fn resume_process(&self) -> Result<ResumeHandle, RamInspectError> {
        if self.resume_count.fetch_add(1, Ordering::SeqCst) == 0 {
            unsafe {
                kill(self.pid, SIGCONT).into_result(RamInspectError::FailedToResumeProcess)?;
            }
        }

        Ok(ResumeHandle {
            pid: self.pid,
            count: Arc::clone(&self.resume_count),
        })
    }

    /// Allows for the execution of arbitrary code in the context of the process. This is unsafe
    /// because there are no checks in place to ensure the provided code is safe. The provided
    /// code should also be completely position independent, since it could be loaded anywhere.
    /// 
    /// This function waits for a signal from the shellcode that it is finished executing, given
    /// by reading exactly one byte from the raminspect device file. It does not time out, so if
    /// you forget to send the signal you'll have to terminate the hijacked process for this 
    /// function to resume and the shellcode to finish executing.
    /// 
    /// The second argument is a callback that is called once the shellcode is finished executing
    /// that takes in a mutable reference to the inspector and the starting address of the loaded 
    /// shellcode as arguments, before the old instructions are restored in memory. This can be
    /// useful if you want to retrieve information from the shellcode after it's done executing.
    /// 
    /// Note that this restores the previous register state automatically, so you don't have to 
    /// save and restore registers in your shellcode manually if you're writing it in assembly.
    
    pub unsafe fn execute_shellcode<F: FnMut(&mut RamInspector, usize) -> Result<(), RamInspectError>>(
        &mut self,
        shellcode: &[u8],
        mut callback: F,
    ) -> Result<(), RamInspectError> {
        let device_fd_wrapper = FileWrapper::open("/dev/raminspect\0", O_RDWR, RamInspectError::FailedToOpenDeviceFile)?;
        let device_fd = device_fd_wrapper.descriptor;

        // Temporarily make the code of the process writable so we can modify it.
        ioctl(device_fd, TOGGLE_EXEC_WRITE, self.pid as c_ulong).into_result(RamInspectError::ProcessTerminated)?;

        // Get process instruction pointer. ptrace and /proc/stat don't work here, at least on my machine, so we
        // rely on the kernel module to do it for us instead.

        let mut inst_ptr_request = InstructionPointerRequest {
            pid: self.pid,
            instruction_pointer: 0,
        };

        ioctl(device_fd, GET_INST_PTR, &mut inst_ptr_request).into_result(RamInspectError::ProcessTerminated)?;
        let instruction_pointer = inst_ptr_request.instruction_pointer as usize;
        
        // Save the old code and load the new code
        let old_code = self.read_vec(instruction_pointer, shellcode.len())?;
        self.write_to_address(instruction_pointer, shellcode)?;

        // Resume the process and wait for the code to finish executing
        kill(self.pid, SIGCONT).into_result(RamInspectError::ProcessTerminated)?;
        ioctl(device_fd, WAIT_FOR_FINISH, self.pid as c_ulong).into_result(RamInspectError::ProcessTerminated)?;

        // Then pause the process again and call the callback
        kill(self.pid, SIGSTOP).into_result(RamInspectError::ProcessTerminated)?;
        callback(self, instruction_pointer)?;

        // Restore the old code and registers
        self.write_to_address(instruction_pointer, &old_code)?;
        ioctl(device_fd, RESTORE_REGS, self.pid as c_ulong).into_result(RamInspectError::ProcessTerminated)?;

        // Leaving the target code as writable when it was originally read-only would present 
        // a fairly big security issue, so we make the modified regions read-only again after 
        // we're done by performing another ioctl.
        
        ioctl(device_fd, TOGGLE_EXEC_WRITE, self.pid as c_ulong).into_result(RamInspectError::ProcessTerminated)?;
        Ok(())
    }

    /// Allocates a new buffer with the given size for the current process and returns the address
    /// of it. Currently this only works on x86-64, but PRs to expand it to work on other CPU
    /// architectures are welcome.
    /// 
    /// Note that due to the way this is implemented this function is fairly expensive. Don't use this many 
    /// times in a hot loop; try to make a few big allocations instead of many small ones for better 
    /// performance.
    
    pub fn allocate_buffer(&mut self, size: usize) -> Result<usize, RamInspectError> {
        assert!(cfg!(target_arch = "x86_64"), "`allocate_buffer` is currently only supported on x86-64.");
        let mut shellcode: Vec<u8> = include_bytes!("../alloc-blob.bin").to_vec();
        let alloc_size_offset = shellcode.len() - 8;
        let out_ptr_offset = shellcode.len() - 16;

        shellcode[alloc_size_offset..alloc_size_offset + 8].copy_from_slice(
            &size.to_le_bytes()
        );
        
        unsafe {
            let mut addr_bytes = [0; 8];
            self.execute_shellcode(&shellcode, |this, inst_ptr| {
                this.read_address(inst_ptr + out_ptr_offset, &mut addr_bytes)
            })?;

            Ok(u64::from_le_bytes(addr_bytes) as usize)
        }
    }

    /// Fills the output buffer with memory read starting from the target address. This can fail
    /// if the target process was suddenly terminated or if the address used is not part of a
    /// readable memory region of the process. 
    /// 
    /// Note that this may spuriously fail if the target address is part of a shared memory region 
    /// (e.g. a memory mapped file), in which case you should always handle errors.
    /// 
    /// If you're making large amounts of small reads, prefer [`RamInspector::read_bulk`] over
    /// this function, which only performs one I/O syscall.
    
    pub fn read_address(&mut self, addr: usize, out_buf: &mut [u8]) -> Result<(), RamInspectError> {
        self.read_bulk(core::iter::once((addr, out_buf)))
    }

    /// A convenience function that reads the specified amount of bytes from the target address
    /// and stores the output in a vector. This is shorthand for:
    /// 
    /// ```rust
    /// let mut out = vec![0; count];
    /// inspector.read_address(addr, &mut out);
    /// ```
    
    pub fn read_vec(&mut self, addr: usize, count: usize) -> Result<Vec<u8>, RamInspectError> {
        let mut out = vec![0; count];
        self.read_address(addr, &mut out)?;
        Ok(out)
    }

    // Used internally to simplify bulk reads and writes of data that use iovecs
    unsafe fn exec_iov_op(&self, local_iovs: Vec<iovec>, remote_iovs: Vec<iovec>, iov_op: unsafe extern "C" fn(
        pid_t,
        *const iovec, c_ulong,
        *const iovec, c_ulong, c_ulong
    ) -> isize, err: RamInspectError) -> Result<(), RamInspectError> {
        assert_eq!(local_iovs.len(), remote_iovs.len());

        let mut i = 0;
        while i < local_iovs.len() {
            let end_index = (i + self.max_iovs).min(local_iovs.len());
            let num_iovs = (end_index - i) as _;

            iov_op(
                self.pid,
                local_iovs[i..end_index].as_ptr(), num_iovs,
                remote_iovs[i..end_index].as_ptr(), num_iovs, 0,
            ).into_result(err)?;
            i += self.max_iovs;
        }

        Ok(())
    }

    /// Performs many memory reads at once in one I/O syscall, taking in an iterator of address / output
    /// buffer pairs as an argument. This can be much faster than [`RamInspector::read_address`] if 
    /// you're making many small data reads, and should be preferred in that case. This has the
    /// same failure conditions as `read_address`.
    
    pub fn read_bulk<T: AsMut<[u8]>, I: Iterator<Item = (usize, T)>>(
        &mut self,
        reads: I,
    ) -> Result<(), RamInspectError> {
        let mut local_iovs = Vec::with_capacity(reads.size_hint().0);
        let mut remote_iovs = Vec::with_capacity(reads.size_hint().0);

        for (address, mut buf) in reads {
            let buf = buf.as_mut();
            local_iovs.push(iovec {
                iov_len: buf.len(),
                iov_base: buf.as_mut_ptr() as _,
            });

            remote_iovs.push(iovec {
                iov_len: buf.len(),
                iov_base: address as _,
            });
        }

        unsafe {
            self.exec_iov_op(
                local_iovs, remote_iovs, 
                process_vm_readv, RamInspectError::FailedToReadMem,
            )?;
        }

        Ok(())
    }

    /// A convenience function for performing one write of arbitrary data to an arbitrary memory address. 
    /// This does not flush the current write buffer, and is guaranteed to perform exactly one write.
    /// 
    /// If you're making many writes, use [`RamInspector::queue_write`] in combination with [`RamInspector::flush`]
    /// instead. This has the same safety constraints as `queue_write`, and is just a thin wrapper around it.
    
    pub unsafe fn write_to_address(&mut self, addr: usize, buf: &[u8]) -> Result<(), RamInspectError> {
        let mut old_buffer = Vec::new(); 
        core::mem::swap(&mut self.write_requests, &mut old_buffer);
        
        self.queue_write(addr, buf);
        let res = self.flush();

        self.write_requests = old_buffer;
        res
    }

    /// Queues a write of the specified data to the specified memory address of the target process. 
    /// Writes will fail if the target process unexpectedly terminated, if the specified address is 
    /// not part of a writable region of the target processes' memory, and if the end address (the 
    /// start address plus the written buffers' length) is not part of the same memory region.
    /// 
    /// This is unsafe since directly writing to an arbitrary address in an arbitrary processes' 
    /// memory is not memory safe at all; it is assumed that the caller knows what they're doing.
    /// 
    /// Note that this has no effect until the [`RamInspector::flush`] method is called, for
    /// performance reasons.
    
    pub unsafe fn queue_write(&mut self, addr: usize, buf: &[u8]) {
        self.write_requests.push((addr, buf.to_vec()));
    }

    /// Flushes the current buffer of writes, performing all of them in one I/O syscall. This is unsafe 
    /// for the same reasons that `queue_write` is unsafe, and is called automatically upon dropping
    /// the inspector. See [`RamInspector::queue_write`] for more information.
    
    pub unsafe fn flush(&mut self) -> Result<(), RamInspectError> {
        let local_iovs = self.write_requests.iter().map(|(_addr, buf)| iovec {
            iov_base: buf.as_ptr() as _,
            iov_len: buf.len(),
        }).collect::<Vec<iovec>>();

        let remote_iovs = self.write_requests.iter().map(|(addr, buf)| iovec {
            iov_base: (*addr) as _,
            iov_len: buf.len(),
        }).collect::<Vec<iovec>>();
        
        self.exec_iov_op(local_iovs, remote_iovs, process_vm_writev, RamInspectError::FailedToWriteMem)?;
        self.write_requests.clear();
        Ok(())
    }

    /// A function that returns an iterator over the target processes' memory regions, generated by reading its
    /// /proc/maps file. See the documentation of [`MemoryRegion`] for more information.
    
    pub fn regions(&mut self) -> IntoIter<MemoryRegion> {
        unsafe {
            fseek(self.proc_maps_file, 0, SEEK_SET);
        }

        // For more details about what this calculation in particular means, see the section
        // for /proc/pid/maps at: https://man7.org/linux/man-pages/man5/proc.5.html

        const MAX_INODE_DIGITS: usize = 16;
        const MAX_PATH_LENGTH: usize = 4096;
        const MAX_LINE_LENGTH: usize = "ffffffffffffffff-ffffffffffffffff rwxp ffffffff ff:ff ".len() + 
                                       MAX_INODE_DIGITS + "      ".len() + MAX_PATH_LENGTH;

        let mut regions = Vec::new();
        let mut line: [u8; MAX_LINE_LENGTH] = [0; MAX_LINE_LENGTH];
        while unsafe { !fgets(line.as_mut_ptr() as _, line.len() as i32, self.proc_maps_file).is_null() } {
            let line_str = core::str::from_utf8(
                &line[..line.iter().position(|byte| *byte == 0).unwrap_or(line.len())]
            ).unwrap().trim();

            // Skip any bad or unneeded memory regions
            if line_str.ends_with("(deleted)") || line_str.ends_with("[vvar]")  || line_str.ends_with("[vdso]")  || line_str.ends_with("[vsyscall]") {
                continue;    
            }

            let mut chars = line_str.chars();
            // The lines read from /proc/PID/maps conform to the following format:
            //
            // HEX_START_ADDR-HEX_END_ADDR rwx(p or s)... etc
            //
            // Where rwx describes whether or not the described memory region can be read from, written 
            // to, and executed. If not the corresponding character will be dashed out. For example, 
            // read-only executable memory areas would show an r-x in the string and write-only 
            // non-executable ones would show a -w-. 
            //
            // The next character following this (the p or s) describes whether or not the specified region 
            // is private or shared, and cannot be dashed out.

            let start_addr_string = (&mut chars).take_while(char::is_ascii_hexdigit).collect::<String>();
            let end_addr_string = (&mut chars).take_while(char::is_ascii_hexdigit).collect::<String>();
            let start_addr = usize::from_str_radix(&start_addr_string, 16).unwrap();
            let end_addr = usize::from_str_radix(&end_addr_string, 16).unwrap();
            assert!(end_addr > start_addr);

            regions.push(MemoryRegion {
                start_addr,
                length: end_addr - start_addr,
                readable: chars.next().unwrap() == 'r',
                writeable: chars.next().unwrap() == 'w',
                executable: chars.next().unwrap() == 'x',
                shared: chars.next().unwrap() == 's',
            });

            line = [0; MAX_LINE_LENGTH];
        }

        regions.into_iter()
    }

    /// Searches the target processes' memory for the specified data, and returns a list of
    /// addresses of found search results and the memory regions that they are contained in. 
    /// This will fail if the process terminated unexpectedly, but it should succeed in 
    /// basically any other case.
    
    pub fn search_for_term(&mut self, search_term: &[u8]) -> Result<Vec<(usize, MemoryRegion)>, RamInspectError> {
        if search_term.is_empty() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        for region in self.regions().filter(|region| region.readable) {
            if region.len() < search_term.len() {
                continue;
            }
            
            if let Ok(data) = region.get_contents(self) {
                for i in 0..data.len() - search_term.len() {
                    if data[i..].starts_with(search_term) {
                        out.push((region.start_addr + i, region.clone()));
                    }
                }
            }
        }

        Ok(out)
    }
}

impl Drop for RamInspector {
    fn drop(&mut self) {
        unsafe {
            // Flush all buffers.
            let _ = self.flush();

            // Free allocated resources.
            fclose(self.proc_maps_file);

            // Resume the target process on drop with a SIGCONT. We ignore errors here
            // since there's no guarantee that the process is still running, so trying
            // to send a signal to it might fail.
            kill(self.pid, SIGCONT);

            // Open up the PID for a new inspector.
            let mut pids = INSPECTED_PIDS.lock();
            let pos = pids.iter().position(|pid| *pid == self.pid).unwrap();
            pids.swap_remove(pos);
        }
    }
}

/// A description of a memory region spanning any given address 
/// range with information about its start address, its access 
/// permissions (i.e. whether it's readable, writable, and/or 
/// executable), and whether or not it's shared or private.
/// 
/// You can obtain an iterator over all of a processes' memory
/// regions using the [`RamInspector::regions`] method.

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    start_addr: usize,
    length: usize,

    executable: bool,
    writeable: bool,
    readable: bool,
    shared: bool,
}

impl MemoryRegion {
    /// Attempts to read the contents of the memory region. This fails if the memory region is
    /// not readable, and may spuriously fail if the memory region is shared (in which case
    /// you should always handle errors).
    
    pub fn get_contents(&self, inspector: &mut RamInspector) -> Result<Vec<u8>, RamInspectError> {
        inspector.read_vec(self.start_addr, self.length)
    }

    /// Gets the start address of the memory region.
    pub fn start_addr(&self) -> usize {
        self.start_addr
    }

    /// Gets the length of the memory region.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Gets the end address of the memory region. This is equivalent to
    /// adding the length to the start address.
    
    pub fn end_addr(&self) -> usize {
        self.start_addr + self.length
    }

    /// Checks if the memory region is readable.
    pub fn readable(&self) -> bool {
        self.readable
    }

    /// Checks if the memory region is shared.
    pub fn shared(&self) -> bool {
        self.shared
    }

    /// Checks if the memory region is writable.
    pub fn writable(&self) -> bool {
        self.writeable
    }

    /// Checks if the memory region is executable.
    pub fn executable(&self) -> bool {
        self.executable
    }

    /// Checks whether or not the memory region is both readable and writable.
    pub fn is_readwrite(&self) -> bool {
        self.readable && self.writeable
    }
}

/// A handle obtained by calling the [`RamInspector::resume_process`] method that 
/// re-pauses the target process when dropped, assuming no other handles for the
/// process currently exist. See the docs of that method for more information.

#[must_use]
pub struct ResumeHandle {
    pid: i32,
    count: Arc<AtomicUsize>,
}

impl Drop for ResumeHandle {
    fn drop(&mut self) {
        if self.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            unsafe {
                kill(self.pid, SIGSTOP);
            }
        }
    }
}