//! This module defines the [`MemoryRegion`] structure. Refer to its documentation for more information.

use crate::error::Result;
use crate::inspector::RamInspector;

// Used in docs.
#[allow(unused_imports)]
use crate::kapi::RawInspector;

use std::ops::Range;
use procfs::process::MemoryMap;
use procfs::process::MMPermissions;
pub use procfs::process::VmFlags;

/// A description of a memory region spanning a process address range with information about
/// its start address, end address, size, access permissions (i.e. whether it's readable,
/// writable, and/or executable), and whether or not it's shared or private. You can obtain
/// an iterator of these for any process by using the [`RamInspector::regions`] method.
/// 
/// Note: Internally, this is just a wrapper around a `procfs` memory map, and it provides convenience
/// functions for working with it. See [`MemoryRegion::inner`].

#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Exposed internally to allow modification by [`RawInspector`] and creation by [`RamInspector`].
    pub(crate) inner: MemoryMap
}

// Used internally to implement functions to check different permissions.

#[doc(hidden)]
macro_rules! perm_check_impl {
    ($($func_name:ident, $flag_name:ident);*;) => {
        $(
            #[doc = concat!("Checks if the memory region is ", stringify!($func_name), ".")]
            pub fn $func_name(&self) -> bool { self.inner.perms.contains(MMPermissions::$flag_name) }
        )*
    }
}

impl MemoryRegion {
    /// Attempts to read the contents of the memory region. This fails if the memory region is
    /// not readable, and may spuriously fail if the memory region is shared (in which case
    /// you should always handle errors).
    
    pub fn get_contents(&self, inspector: &RamInspector) -> Result<Vec<u8>> {
        inspector.read_vec(self.start_addr(), self.len())
    }

    /// Gets the start address of the memory region.
    
    pub fn start_addr(&self) -> usize {
        self.inner.address.0 as _
    }

    /// Gets the end address of the memory region.
    
    pub fn end_addr(&self) -> usize {
        self.inner.address.1 as _
    }

    /// Gets the address range of the region. This is shorthand for `self.start_addr()..self.end_addr()`.
    
    pub fn addr_range(&self) -> Range<usize> {
        self.start_addr()..self.end_addr()
    }

    /// Gets the length of the memory region. This is equivalent to `self.end_addr() - self.start_addr()`
    // Empty regions cannot exist, so clippy is being overly pedantic here.
    #[allow(clippy::len_without_is_empty)]
    
    pub fn len(&self) -> usize {
        self.end_addr() - self.start_addr()
    }

    /// Checks whether or not the memory region is both readable and writable.
    
    pub fn is_readwrite(&self) -> bool {
        self.readable() && self.writable()
    }

    /// This retrieves the raw VMA flags for the memory region used by the kernel. This can be useful to retrieve
    /// information that is not accessible through the other methods, or it can be used in conjunction with
    /// [`RawInspector::set_vma_flags`] in order to change the access permissions of a memory region.

    pub fn flags(&self) -> VmFlags {
        self.inner.extension.vm_flags
    }

    /// Gets the inner [`MemoryMap`].
    pub fn inner(&self) -> &MemoryMap {
        &self.inner
    }

    perm_check_impl! {
        readable, READ;
        writable, WRITE;
        executable, EXECUTE;
        shared, SHARED;
        private, PRIVATE;
    }
}