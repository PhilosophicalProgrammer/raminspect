//! This module defines the [`MemoryRegion`] structure. Refer to its documentation for more information.
use crate::error::RamInspectError as Error;
use crate::error::Result;
use super::RamInspector;
use std::ops::Range;

/// A description of a memory region spanning any given address range with information about
/// its start address, its access permissions (i.e. whether it's readable, writable, and/or 
/// executable), and whether or not it's shared or private.
/// 
/// You can obtain an iterator over all of a processes' memory regions using the
/// [`RamInspector::regions`] method.

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    start_addr: usize,
    length: usize,

    // These need to be exposed internally to allow modification from within [`RawInspector::set_vma_flags`].
    pub(crate) executable: bool,
    pub(crate) writable: bool,
    pub(crate) readable: bool,
    shared: bool,
}

impl MemoryRegion {
    /// Attempts to read the contents of the memory region. This fails if the memory region is
    /// not readable, and may spuriously fail if the memory region is shared (in which case
    /// you should always handle errors).
    
    pub fn get_contents(&self, inspector: &mut RamInspector) -> Result<Vec<u8>> {
        inspector.read_vec(self.start_addr, self.length)
    }

    /// Gets the start address of the memory region.
    
    pub fn start_addr(&self) -> usize {
        self.start_addr
    }

    /// Gets the end address of the memory region. This is equivalent to
    /// adding the length to the start address.
    
    pub fn end_addr(&self) -> usize {
        self.start_addr + self.length
    }

    /// Gets the address range of the region. This is shorthand for `self.start_addr()..self.end_addr()`.
    
    pub fn addr_range(&self) -> Range<usize> {
        self.start_addr()..self.end_addr()
    }

    /// Gets the length of the memory region.
    
    pub fn len(&self) -> usize {
        self.length
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
        self.writable
    }

    /// Checks if the memory region is executable.
    
    pub fn executable(&self) -> bool {
        self.executable
    }

    /// Checks whether or not the memory region is both readable and writable.
    
    pub fn is_readwrite(&self) -> bool {
        self.readable && self.writable
    }
}