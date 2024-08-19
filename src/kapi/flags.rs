//! Provides memory protection flag values and types. If you want to make an area of memory writable or executable,
//! then you'll have to use this module. Refer to the Linux kernel source code (specifically, `include/linux/mm.h`)
//! for documentation on these flags.
#![allow(non_camel_case_types)]

use nix::libc::c_ulong;
pub type vm_flags_t = c_ulong;
pub const VM_NONE: vm_flags_t = 0x00000000;
pub const VM_READ: vm_flags_t = 0x00000001;
pub const VM_WRITE: vm_flags_t = 0x00000002;
pub const VM_EXEC: vm_flags_t = 0x00000004;
pub const VM_SHARED: vm_flags_t = 0x00000008;
pub const VM_MAYREAD: vm_flags_t = 0x00000010;
pub const VM_MAYWRITE: vm_flags_t = 0x00000020;
pub const VM_MAYEXEC: vm_flags_t = 0x00000040;
pub const VM_MAYSHARE: vm_flags_t = 0x00000080;
pub const VM_GROWSDOWN: vm_flags_t = 0x00000100;
pub const VM_UFFD_MISSING: vm_flags_t = 0x00000200;
pub const VM_PFNMAP: vm_flags_t = 0x00000400;
pub const VM_UFFD_WP: vm_flags_t = 0x00001000;
pub const VM_LOCKED: vm_flags_t = 0x00002000;
pub const VM_IO: vm_flags_t = 0x00004000;
pub const VM_SEQ_READ: vm_flags_t = 0x00008000;
pub const VM_RAND_READ: vm_flags_t = 0x00010000;
pub const VM_DONTCOPY: vm_flags_t = 0x00020000;
pub const VM_DONTEXPAND: vm_flags_t = 0x00040000;
pub const VM_LOCKONFAULT: vm_flags_t = 0x00080000;
pub const VM_ACCOUNT: vm_flags_t = 0x00100000;
pub const VM_NORESERVE: vm_flags_t = 0x00200000;
pub const VM_HUGETLB: vm_flags_t = 0x00400000;
pub const VM_SYNC: vm_flags_t = 0x00800000;
pub const VM_ARCH_1: vm_flags_t = 0x01000000;
pub const VM_WIPEONFORK: vm_flags_t = 0x02000000;
pub const VM_DONTDUMP: vm_flags_t = 0x04000000;
pub const VM_MIXEDMAP: vm_flags_t = 0x10000000;
pub const VM_HUGEPAGE: vm_flags_t = 0x20000000;
pub const VM_NOHUGEPAGE: vm_flags_t = 0x40000000;
pub const VM_MERGEABLE: vm_flags_t = 0x80000000;