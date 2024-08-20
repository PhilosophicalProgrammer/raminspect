//! This provides the structure that represents the interface of the library, [`RamInspector`]. See its
//! documentation for more information.

use either::Either;
use std::io::IoSlice;
use std::io::IoSliceMut;

use nix::libc;
use nix::unistd::Pid;
use nix::unistd::getpgid;
use nix::unistd::sysconf;
use nix::unistd::SysconfVar;
use nix::sys::signal::killpg;
use nix::sys::signal::SIGSTOP;
use nix::sys::signal::SIGCONT;
use nix::sys::uio::RemoteIoVec;
use nix::sys::uio::process_vm_readv;
use nix::sys::uio::process_vm_writev;

use libc::pid_t;
use procfs::process::Process;

use crate::error::Result;
use crate::kapi::RawInspector;
use crate::region::MemoryRegion;
use crate::error::RamInspectError as Error;

/// This is the primary interface used by the crate to search through, read, and modify an
/// arbitrary processes' memory, registers, and code. All uses of this library must either
/// directly or indirectly go go through this structure. 
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
/// use raminspect::RamInspector;
/// // Iterate over all running Firefox instances
/// for process in raminspect::find_processes("/usr/lib/firefox/firefox") {
///     let inspector = match RamInspector::new(process.pid) {
///         Ok(inspector) => inspector,
///         Err(_) => continue,
///     };
///     
///     for (proc_addr, memory_region) in inspector.search_for_term(b"Old search text").unwrap() {
///         if !memory_region.writable() {
///             continue;
///         }
///
///         unsafe {
///             // This is safe because modifying the text in the Firefox search bar will not crash
///             // the browser or negatively impact system stability in any way.
///
///             println!("Writing to process virtual address: 0x{:X}", proc_addr);
///             inspector.queue_write(proc_addr, b"New search text");
///         }
///     }
/// 
///     unsafe {
///         // This is safe since the process is not currently resumed, which would possibly cause a data race.
///         inspector.flush().unwrap();
///     }
/// }
/// ```

pub struct RamInspector {
    proc: Process,
    max_iovs: usize,
    process_paused: bool,

    // Lazily initialized so that we don't require the kernel module to be loaded for functions that don't need it.
    kapi: Option<RawInspector>,
}

/// See [`RamInspector::bulk_iov_op`].
type ReadOrWrites<'a> = Either<Vec<(usize, &'a mut [u8])>, Vec<(usize, &'a [u8])>>; 

impl RamInspector {
    /// Creates a new inspector attached to the specified process ID. Note: You should probably pause the
    /// process while performing operations using this structure if you want consistent results. See
    /// [`RamInspector::do_while_paused`] for more information.
    
    pub fn new(pid: pid_t) -> Result<Self> {
        Ok(Self {
            kapi: None,
            process_paused: false,
            proc: Process::new(pid)?,
            max_iovs: sysconf(SysconfVar::IOV_MAX)?.ok_or(Error::SysconfFailed)? as usize
        })
    }

    /// This provides a way to pause a process and ensure that data races with the target process and other
    /// unexpected behavior cannot occur upon modification. In other words, if you're making any sort of
    /// modification to a process, you should probably do so inside a `do_while_paused` block, although
    /// this is not enforced since there are cases where it is not desirable to do so.
    /// 
    /// The kernel API especially requires extensive use of this interface to ensure that retrieved
    /// thread data doesn't become outdated. See [`RamInspector::kernapi`] and [`RawInspector::get_threads`]
    /// for more information.
    /// 
    /// It is important to note that this function does not just pause the target process. It is more
    /// aggressive and pauses the entire process group of the process. This is to ensure that child
    /// or parent processes that share the same memory as the target do not experience instability.
    /// It also has the benefit of reducing the risk of detection.
    /// 
    /// # Example Usage
    /// 
    /// ```rust
    /// use raminspect::RamInspector;
    /// let mut inspector = RamInspector::new(1234); // Replace 1234 with your target PID
    /// 
    /// inspector.do_while_paused(|inspector| {
    ///     // .. do whatever ..
    /// });
    /// ```
    
    pub fn do_while_paused<F: FnMut(&mut RamInspector) -> Result<()>>(&mut self, mut callback: F) -> Result<()> {
        if self.process_paused {
            // If we're already paused, call the callback right away.
            return callback(self);
        }

        self.process_paused = true;
        // We wrap this within its own context so that we can still set `process_paused` to false on error.

        let res = (|| {
            let pid = Pid::from_raw(self.proc.pid);
            let pgid = getpgid(Some(pid))?;
            killpg(pgid, SIGSTOP)?;
            callback(self)?;
            killpg(pgid, SIGCONT)?;
            Ok(())
        })();

        self.process_paused = false;
        res
    }

    /// This provides access to the raw kernel API. The kernel module must be loaded in order for
    /// this function to work. The `kapi` handle is lazily initialized, and so after this is successfully
    /// called once it will become a zero-cost operation to call it again. See the documentation
    /// of [`RawInspector`] for more information and usage guidelines.
    /// 
    /// Note: Before using the kernel API, you should consider if the higher-level API suits your use case,
    /// since it is both simpler and safer to use.
    
    pub fn kernapi(&mut self) -> Result<&RawInspector> {
        if self.kapi.is_some() {
            Ok(self.kapi.as_ref().unwrap())
        } else {
            self.kapi = Some(RawInspector::new(self.proc.pid)?);
            self.kernapi()
        }
    }

    /// Allows for the execution of arbitrary code in the context of the process. The
    /// provided code should be completely position independent, since it could be
    /// loaded anywhere.
    /// 
    /// # Safety
    /// 
    /// This is unsafe because there are no checks in place to ensure the provided code is safe,
    /// and in fact such checks would be impossible to implement (cc. halting problem). Use
    /// with caution.
    
    pub unsafe fn execute_shellcode(&mut self, _shellcode: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Allocates a new buffer with the given size for the current process and returns the address
    /// of it. Currently this only works on x86-64, but PRs to expand it to work on other CPU
    /// architectures are welcome.
    /// 
    /// Note that due to the way this is implemented this function is fairly expensive. Don't use this many 
    /// times in a hot loop; try to make a few big allocations instead of many small ones for better 
    /// performance.
    
    pub fn allocate_buffer(&mut self, _size: usize) -> Result<usize> {
        unimplemented!()
    }

    /// Fills the output buffer with memory read starting from the target address. This can fail
    /// if the target process was suddenly terminated or if the address used is not part of a
    /// readable memory region of the process. 
    /// 
    /// Note that this may spuriously fail if the target address is part of a shared memory region 
    /// (e.g. a memory mapped file), in which case you should always handle errors.
    /// 
    /// If you're making large amounts of small reads, prefer [`RamInspector::read_bulk`] over
    /// this function, which very significantly reduces the amount of syscalls needed to
    /// perform the read operation.
    
    pub fn read_address(&self, addr: usize, out_buf: &mut [u8]) -> Result<()> {
        self.read_bulk(vec![(addr, out_buf)])
    }

    /// A convenience function that reads the specified amount of bytes from the target address
    /// and stores the output in a vector. This is shorthand for:
    /// 
    /// ```rust
    /// let mut out = vec![0; count];
    /// inspector.read_address(addr, &mut out);
    /// ```
    
    pub fn read_vec(&self, addr: usize, count: usize) -> Result<Vec<u8>> {
        let mut out = vec![0; count];
        self.read_address(addr, &mut out)?;
        Ok(out)
    }

    /// Writes the provided data to the provided address. You should probably only do this while
    /// the process is paused in order to avoid data races and other forms of instability. See
    /// [`RamInspector::do_while_paused`] for more information. 
    /// 
    /// If you're making large amounts of writes, prefer [`RamInspector::write_bulk`] over this
    /// function, which very significantly reduces the amount of syscalls needed to perform the
    /// write operation.
    /// 
    /// # Safety
    /// 
    /// This is unsafe since directly writing to an arbitrary address in an arbitrary processes' 
    /// memory is not memory safe at all; it is assumed that the caller knows what they're doing.
    
    pub unsafe fn write_to_address(&self, addr: usize, in_buf: &[u8]) -> Result<()> {
        self.write_bulk(vec![(addr, in_buf)])
    }

    /// Used internally to simplify bulk reads and writes of data that use iovecs
    
    unsafe fn bulk_iov_op(&self, ops: ReadOrWrites) -> Result<()> {
        let remotes: Vec<RemoteIoVec> = either::for_both!(ops.as_ref(), ops => ops.iter().map(|(base, buf)| RemoteIoVec {
            base: *base,
            len: buf.len()
        }).collect());

        let mut io_slices: Either<Vec<IoSliceMut>, Vec<IoSlice>> = ops.map_either(
            |s| s.into_iter().map(|(_, buf)| IoSliceMut::new(buf)).collect(),
            |s| s.into_iter().map(|(_, buf)| IoSlice::new(buf)).collect(),
        );

        let blen = either::for_both!(io_slices.as_ref(), s => s.len());
        assert_eq!(remotes.len(), blen);

        let mut i = 0;
        while i < blen {
            let end_index = (i + self.max_iovs).min(blen);
            let mut total_copied = 0;

            // We keep attempting to copy until the full amount was read or written. If zero bytes were copied in this loop,
            // then we return early with `Error::Partial`.

            'copy: while i < end_index {
                let pid = Pid::from_raw(self.proc.pid);
                let amount_copied = match io_slices.as_mut() {
                    Either::Left(read) => process_vm_readv(pid, &mut read[i..end_index], &remotes[i..end_index]).map_err(|_| Error::FailedToReadMem)?,
                    Either::Right(write) => process_vm_writev(pid, &write[i..end_index], &remotes[i..end_index]).map_err(|_| Error::FailedToWriteMem)?,
                };

                total_copied += amount_copied;
                if amount_copied == 0 { return Err(Error::Partial(total_copied)); }

                // Check if the full amount was copied.
                let mut expected_amount = 0;

                while i < end_index {
                    expected_amount += either::for_both!(io_slices.as_ref(), s => s[i].len());

                    if expected_amount > amount_copied {
                        // Try again starting from this index if less than the expected amount was copied.
                        continue 'copy;
                    }

                    i += 1;
                }
            }
        }

        Ok(())
    }

    /// Performs many memory reads at once in one I/O syscall, taking in an iterator of address / output
    /// buffer pairs as an argument. This can be much faster than [`RamInspector::read_address`] if 
    /// you're making many reads, and should be preferred in that case. This has the same failure
    /// conditions as `read_address`.
    
    pub fn read_bulk(&self, reads: Vec<(usize, &mut [u8])>) -> Result<()> {
        unsafe {
            // Reading memory from a process shouldn't be unsafe unless it's MMIO, but this is generally not exposed to userspace.
            self.bulk_iov_op(Either::Left(reads))
        }
    }

    /// Write-side counterpart of [`RamInspector::read_bulk`]. Like `read_bulk`, this can be significantly
    /// faster than the single-operation counterpart if you're moving multiple pieces of data, and should
    /// be preferred in that case.
    /// 
    /// # Safety
    /// 
    /// This has the same failure conditions and safety concerns as [`RamInspector::write_to_address`].
    /// See its documentation for more information.

    pub unsafe fn write_bulk(&self, writes: Vec<(usize, &[u8])>) -> Result<()> {
        self.bulk_iov_op(Either::Right(writes))
    }

    /// A function that returns an iterator over the target processes' memory regions, generated by reading its
    /// `/proc/maps` and `/proc/smaps` files. See the documentation of [`MemoryRegion`] for more information.
    
    pub fn regions(&mut self) -> Result<impl Iterator<Item = MemoryRegion>> {
        Ok(self.proc.maps()?.into_iter().map(|mmap| MemoryRegion {
            inner: mmap
        }))
    }

    /// Searches the target processes' memory for the specified data, and returns a list of
    /// addresses of found search results and the memory regions that they are contained in. 
    /// This will fail if the process terminated unexpectedly, but it should succeed in 
    /// basically any other case.
    
    pub fn search_for_term(&mut self, search_term: &[u8]) -> Result<Vec<(usize, MemoryRegion)>> {
        if search_term.is_empty() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        for region in self.regions()?.filter(|region| region.readable()) {
            if region.len() < search_term.len() {
                continue;
            }
            
            if let Ok(data) = region.get_contents(self) {
                for i in 0..data.len() - search_term.len() {
                    if data[i..].starts_with(search_term) {
                        out.push((region.start_addr() + i, region.clone()));
                    }
                }
            }
        }

        Ok(out)
    }
}