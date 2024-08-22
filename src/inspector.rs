//! This provides the structure that represents the interface of the library, [`RamInspector`]. See its
//! documentation for more information.

use std::ops::Deref; 
use std::io::IoSlice;
use std::io::IoSliceMut;

use std::cell::OnceCell;
use std::sync::atomic::Ordering;
use std::sync::atomic::AtomicBool;

use nix::libc;
use nix::errno::Errno;

use nix::unistd::Pid;
use nix::unistd::sleep;
use nix::unistd::getpgid;
use nix::unistd::sysconf;
use nix::unistd::SysconfVar;

use nix::sys::signal::signal;
use nix::sys::signal::killpg;
use nix::sys::signal::SigSet;
use nix::sys::signal::SIGSTOP;
use nix::sys::signal::SIGCONT;
use nix::sys::signal::SIGUSR1;
use nix::sys::signal::SigHandler;

use nix::sys::uio::RemoteIoVec;
use nix::sys::uio::process_vm_readv;
use nix::sys::uio::process_vm_writev;

use libc::pid_t;
use libc::c_int;
use procfs::process::Process;

use crate::error::Result;
use crate::kapi::RawInspector;
use crate::error::RamInspectError as Error;

use crate::region::VmFlags;
use crate::region::MemoryRegion;

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
    process_paused: AtomicBool,

    // Lazily initialized so that we don't require the kernel module to be loaded for functions that don't need it.
    kapi: OnceCell<Result<RawInspector>>,
}

/// Used internally in [`RamInspector::bulk_iov_op`]. This allows us to genericize over `IoSlice` and `IoSliceMut` by
/// implementing the conversion of slices to IO slices.

trait FromBuffer<B>: Deref<Target = [u8]> {
    fn from_buffer(buf: B) -> Self;
}

impl<'a> FromBuffer<&'a [u8]> for IoSlice<'a> {
    fn from_buffer(buf: &'a [u8]) -> Self {
        Self::new(buf)
    }
}

impl<'a> FromBuffer<&'a mut [u8]> for IoSliceMut<'a> {
    fn from_buffer(buf: &'a mut [u8]) -> Self {
        Self::new(buf)
    }
}

impl RamInspector {
    /// Creates a new inspector attached to the specified process ID. Note: You should probably pause the
    /// process while performing operations using this structure if you want consistent results. See
    /// [`RamInspector::do_while_paused`] for more information.
    
    pub fn new(pid: pid_t) -> Result<Self> {
        unsafe {
            // Install a signal handler that ignores `SIGUSR1`. This is necessary because of the semantics of
            // `execute_shellcode`. See its documentation for more information.

            extern "C" fn do_nothing(_n: c_int) {}
            signal(SIGUSR1, SigHandler::Handler(do_nothing))?;
        }

        Ok(Self {
            kapi: OnceCell::new(),
            process_paused: AtomicBool::new(false),
            proc: Process::new(pid).map_err(|_| Error::FailedToAccessProcess)?,
            max_iovs: sysconf(SysconfVar::IOV_MAX)?.ok_or(Error::SysconfFailed)? as usize,
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
    
    pub fn do_while_paused<F: FnMut() -> Result<()>>(&self, mut callback: F) -> Result<()> {
        if self.process_paused.load(Ordering::SeqCst) {
            // If we're already paused, call the callback right away.
            return callback();
        }

        self.process_paused.store(true, Ordering::SeqCst);
        // We wrap this within its own context so that we can still set `process_paused` to false on error.

        let res = (|| {
            let pid = Pid::from_raw(self.proc.pid);
            let pgid = getpgid(Some(pid))?;
            killpg(pgid, SIGSTOP)?;
            callback()?;
            killpg(pgid, SIGCONT)?;
            Ok(())
        })();

        self.process_paused.store(false, Ordering::SeqCst);
        res
    }

    /// This provides access to the raw kernel API. The kernel module must be loaded in order for
    /// this function to work. The `kapi` handle is lazily initialized, and so after this is successfully
    /// called once it will become a zero-cost operation to call it again. See the documentation
    /// of [`RawInspector`] for more information and usage guidelines.
    /// 
    /// Note: Before using the kernel API, you should consider if the higher-level API suits your use case,
    /// since it is both simpler and safer to use.
    
    pub fn kernapi(&self) -> Result<&RawInspector> {
        match self.kapi.get_or_init(|| RawInspector::new(self.proc.pid)) {
            Ok(kapi) => Ok(kapi),
            Err(e) => Err(*e)
        }
    }

    /// Allows for the execution of arbitrary code in the context of the process. The
    /// provided code should be completely position independent, since it could be
    /// loaded anywhere. This requires the kernel module to be loaded to work.
    /// 
    /// You must provide a `pid_cookie` argument, which is a magic 64-bit number stored 
    /// in your shellcode which will be replaced with the process ID of the injector
    /// prior to when the shellcode is inserted. Make this variable global and volatile
    /// to prevent compiler optimizaations from messing with the process. Additionally,
    /// to reduce the risk of multiple occurences of this in your binary, make this a
    /// random number.
    /// 
    /// This process ID will be used to send a signal to the injector (specifically,
    /// `SIGUSR1`) which will notify the injector that the shellcode has finished
    /// executing. Upon receiving this signal, the injector will pause the proces
    /// and restore the old state of execution prior to injection.
    /// 
    /// All other threads than the main thread of the target process will be halted until
    /// this signal is received, in order to ensure that only the shellcode you provide
    /// is executing in the processes' context for the duration of injection, and nothing
    /// else. If you want to run it asynchronously with the rest of the process past the
    /// return point of this function, create a thread from within your shellcode, and
    /// then send the signal after it spawns.
    /// 
    /// There is a one second timeout until this function gives up on waiting for said
    /// signal and returns [`Error::ExecTimeout`]. If you need more time than that to
    /// do processing, then follow the same procedure as above and create a thread.
    /// 
    /// It is not recommended to pause all threads of a process for too long regardless,
    /// since it could interfere with timing-based system calls and persistent network
    /// connections if the application is network-facing. Asynchronous execution is
    /// essentially a requirement if you need time in these situations.
    /// 
    /// The callback argument is used after the signal is received but before the process
    /// is paused, and the actual address where the shellcode was inserted into the process
    /// is provided as an argument to the callback. This can allow you to directly extract
    /// information from your shellcode after it's done executing by inspecting its memory,
    /// which is generally much faster than the alternative (file I/O). Note that callback`
    /// will never be called if an error occurs before then.
    /// 
    /// # Notice
    /// 
    /// The old instructions prior to injection and the general-purpose registers of every thread
    /// are saved and restored for you by this function, but the restoration of floating point
    /// registers and the stack has to be performed manually. Make sure that your shellcode
    /// does this if it modifies either of those things, unless you intentionally want the
    /// modifications to persist.
    /// 
    /// # Safety
    /// 
    /// This is unsafe because there are no checks in place to ensure the provided code is safe,
    /// and in fact such checks would be impossible to implement universally due to the
    /// halting problem. Use with caution.
    /// 
    /// # Example Usage
    /// 
    /// ```rust
    /// use raminspect::RamInspector;
    /// const YOUR_PID_COOKIE: u64 = 0xDEADBEEFCAFEBABE;
    /// let inspector = RamInspector::new(1234); // Replace 1234 with your target PID
    /// inspector.execute_shellcode(include_bytes!("path/to/your/shellcode.bin"), YOUR_PID_COOKIE, |ip| {
    ///     println!("Finished executing! Shellcode was inserted at virtual address: 0x{:X}", ip); 
    /// })?;
    /// ```
    
    pub unsafe fn execute_shellcode<F: FnMut(usize) -> Result<()>>(&self, shellcode: &mut [u8], pid_cookie: u64, mut callback: F) -> Result<()> {
        let pid_loc = (0..shellcode.len()).find(|i| {
            shellcode[*i..].starts_with(&pid_cookie.to_ne_bytes())
        }).ok_or(Error::CookieNotFound)?;

        // Provide the our process ID to the shellcode.
        shellcode[pid_loc..pid_loc + core::mem::size_of::<u64>()].copy_from_slice(&(Pid::this().as_raw() as u64).to_ne_bytes());

        let mut main_ip = None;
        let mut old_threads = None;
        let kapi = self.kernapi()?;

        // Retrieve the current list of executable memory regions.
        let mut exec_regions = self.regions()?.filter(|region| region.executable()).collect::<Vec<_>>();

        // Address / data pairs of the instructions at the instruction pointers of threads that we will modify.
        // This is used to restore the old instructions after our injected shellcode finishes executing.
        let mut old_instructions = Vec::new();

        // This is used to restore the old access privileges of regions that we modified the memory protection of.
        let mut old_regions = Vec::new();

        // Inject the shellcode.
        self.do_while_paused(|| {
            // Get the current thread states.
            let mut threads = kapi.get_threads()?;

            // Store a copy of the original thread states for later restoration. 
            old_threads = Some(threads.clone());

            // Create read / write queues.
            let mut reads = Vec::with_capacity(threads.len());
            let mut writes = Vec::with_capacity(threads.len());

            for thread in threads.iter_mut() {
                // Make the memory region containing the threads' instruction pointer writable so that we can modify it.
                let ip = *thread.registers.inst_ptr() as usize;

                // This is guaranteed to exist, so it's safe to unwrap here.
                let ip_region = exec_regions.iter_mut().find(|region| region.addr_range().contains(&ip)).unwrap();
                old_regions.push(ip_region.clone());
                kapi.set_vma_flags(ip_region, ip_region.flags() | VmFlags::WR)?;

                let code_to_inject = if thread.thread_id == self.proc.pid {
                    // We're in the main thread. We'll copy the shellcode over and set `main_ip` to the fetched instruction pointer to be
                    // sent to the callback later.
                    main_ip = Some(ip);
                    &*shellcode
                } else {
                    // We inject an infinite loop into the threads other than the main one as a way to halt their execution
                    // while the shellcode is running in the main thread. See `injected-c/src/forever.c`
                    include_bytes!("../injected-c/build/forever.bin")
                };

                reads.push((ip, vec![0; code_to_inject.len()]));
                writes.push((ip, code_to_inject));

                // We disable all of the signal handlers for the duration of shellcode execution, in order to avoid crashes and instability
                // caused by interruptions. Most importantly, this masks `SIGCONT`, which helps us avoid detection.
                thread.sigmask = SigSet::empty();
            }

            // Read out the old instructions.
            self.read_bulk(reads.iter_mut().map(|(addr, buf)| (*addr, buf.as_mut_slice())))?;
            old_instructions = reads;

            // Write in the new instructions.
            self.write_bulk(writes.into_iter())?;
            Ok(())
        })?;

        // By now, the shellcode is executing.
        let mut set = SigSet::empty();
        set.add(SIGUSR1);

        // Mask all signals other than `SIGUSR1` in this thread.
        let old_mask = SigSet::thread_get_mask()?;
        set.thread_set_mask()?;

        // This call to sleep will end prematurely and set `errno` to `EINTR` when a signal is received. If a signal is
        // not received, it will act as a timeout and we will return `ExecTimeout` when the post-execution cleanup
        // finishes.
        sleep(1);

        // Restore the old signal mask.
        old_mask.thread_set_mask()?;

        let retval = if Errno::last() != Errno::EINTR {
            // We delay returning an error so that we can perform still perform cleanup afterwards.
            Err(Error::ExecTimeout)
        } else {
            // Safe to unwrap here since it's guaranteed to be set by now.
            callback(main_ip.unwrap())?;
            Ok(())
        };

        // Perform cleanup.
        self.do_while_paused(|| {
            // Restore the old registers and signal masks.
            kapi.set_threads(old_threads.as_ref().unwrap())?;

            // Restore the old instructions.
            self.write_bulk(old_instructions.iter().map(|(addr, buf)| (*addr, buf.as_slice())))?;

            for region in old_regions.iter_mut() {
                // Restore the old memory access privileges.
                kapi.set_vma_flags(region, region.flags())?;
            }

            Ok(())
        })?;

        // By now the original program code should be running again.
        retval
    }

    /// Allocates a new buffer with the given size for the current process and returns the address
    /// of it. This requires the kernel module to be loaded.
    /// 
    /// Note that due to the way this is implemented this function is very expensive. Don't use this many 
    /// times in a hot loop; try to make a few big allocations instead of many small ones for better 
    /// performance. Ideally you should only use it once to create a scratch memory area, and then
    /// wrap a custom allocator around this pre-allocated buffer.
    /// 
    /// # Safety
    /// 
    /// This uses library-provided shellcode to allocate the memory internally. Injecting code into a
    /// process is a fundamentally memory-unsafe operation. It shouldn't fail or cause crashes under
    /// regular circumstances, but keep this in mind when using this function.
    
    pub unsafe fn allocate_buffer(&self, size: usize) -> Result<usize> {
        // These "cookies" are magic numbers precompiled into the shellcode that we either find and replace
        // with an input value or read a value out of after the shellcode finishes executing. They are
        // vectors of communication with the shellcode, through which we can write data out and read
        // data in. Their starting values are arbitrary and randomly generated to reduce the risk
        // that they would occur multiple times within the final binary. For details on what these
        // cookies represent, see `injected-c/src/allocmem.c`.
        const SIZE_COOKIE: u64 = 0xF0CCF6B495854508;
        const ADDR_COOKIE: u64 = 0xBFB04CDC2D0AB7B8;
        const PID_COOKIE: u64 = 0xBE05253FF57ECE7F;

        let mut shellcode = *include_bytes!("../injected-c/build/allocmem.bin");
        let cookie_loc = |cookie: &[u8]| (0..shellcode.len()).find(|i| shellcode[*i..].starts_with(cookie)).unwrap();

        let size_loc = cookie_loc(&SIZE_COOKIE.to_ne_bytes());
        let addr_loc = cookie_loc(&ADDR_COOKIE.to_ne_bytes());
        shellcode[size_loc..size_loc + core::mem::size_of::<usize>()].copy_from_slice(&size.to_ne_bytes());

        let mut out_addr = -1;
        let mut out = vec![0; shellcode.len()];
        self.execute_shellcode(&mut shellcode, PID_COOKIE, |ip| {
            self.read_address(ip, &mut out)?;
            out_addr = isize::from_ne_bytes(out[addr_loc..addr_loc + core::mem::size_of::<isize>()].try_into().unwrap());
            Ok(())
        })?;

        if out_addr < 0 && out_addr > i32::MIN as _ {
            Err(Error::AllocFailed(Errno::from_raw(out_addr as i32)))
        } else {
            Ok(out_addr as usize) 
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
    /// this function, which very significantly reduces the amount of syscalls needed to
    /// perform the read operation.
    
    pub fn read_address(&self, addr: usize, buf: &mut [u8]) -> Result<()> {
        self.read_bulk([(addr, buf)].into_iter())
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
    
    pub unsafe fn write_to_address(&self, addr: usize, buf: &[u8]) -> Result<()> {
        self.write_bulk([(addr, buf)].into_iter())
    }

    /// Used internally to implement bulk reads and writes of data. It extracts the common logic of reading and
    /// writing `iovec`s, namely: handling `iov_max`, handling partial reads or writes, creating a corresponding
    /// buffer of `RemoteIoVec`s, and calling a `readv` or `writev` function that takes in this data.
    
    unsafe fn bulk_iov_op<B, S: FromBuffer<B>, O: Iterator<Item = (usize, B)>>(
        &self, ops: O, sysfunc: fn(Pid, &mut [S], &[RemoteIoVec]) -> nix::Result<usize>, err: Error
    ) -> Result<()> {
        let (remotes, mut iovs): (Vec<_>, Vec<_>) = ops.map(|(base, buf)| {
            let iov = S::from_buffer(buf);
            (RemoteIoVec { base, len: iov.len() }, iov)
        }).unzip();

        let mut i = 0;
        while i < iovs.len() {
            let end_index = (i + self.max_iovs).min(iovs.len());
            let mut total_copied = 0;

            // We keep attempting to copy until the full amount was read or written. If zero bytes were copied in an iteration
            // of this loop, then we return early with `Error::Partial`.

            'copy: while i < end_index {
                let pid = Pid::from_raw(self.proc.pid);
                let amount_copied = sysfunc(pid, &mut iovs[i..end_index], &remotes[i..end_index]).map_err(|_| err)?;

                total_copied += amount_copied;
                if amount_copied == 0 { return Err(Error::Partial(total_copied)); }

                // Check if the full amount was copied.
                let mut expected_amount = 0;

                while i < end_index {
                    expected_amount += iovs[i].len();
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
    
    pub fn read_bulk<'a, O: Iterator<Item = (usize, &'a mut [u8])>>(&self, ops: O) -> Result<()> {
        unsafe {
            // Safe since we're just reading data and not actually modifying anything.
            self.bulk_iov_op(ops, process_vm_readv, Error::FailedToReadMem)
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

    pub unsafe fn write_bulk<'a, O: Iterator<Item = (usize, &'a [u8])>>(&self, ops: O) -> Result<()> {
        self.bulk_iov_op(ops, |pid, iovs, remotes| process_vm_writev(pid, iovs, remotes), Error::FailedToWriteMem)
    }

    /// A function that returns an iterator over the target processes' memory regions, generated by reading its
    /// `/proc/maps` and `/proc/smaps` files. See the documentation of [`MemoryRegion`] for more information.
    
    pub fn regions(&self) -> Result<impl Iterator<Item = MemoryRegion>> {
        Ok(self.proc.maps().map_err(|_| Error::FailedToGetMaps)?.into_iter().map(|mmap| MemoryRegion {
            inner: mmap
        }))
    }

    /// Searches the target processes' memory for the specified data, and returns a list of
    /// addresses of found search results and the memory regions that they are contained in. 
    /// This will fail if the process terminated unexpectedly, but it should succeed in 
    /// basically any other case.
    
    pub fn search_for_term(&self, search_term: &[u8]) -> Result<Vec<(usize, MemoryRegion)>> {
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