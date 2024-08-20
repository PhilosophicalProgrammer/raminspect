//! This module provides the [`ThreadList`] structure. See its documentation for more information.

// Used in doc references.
#[allow(unused_imports)]
use super::RawInspector;
use super::ioctl::ThreadData;

use std::ops::Deref;
use std::ops::DerefMut;
use nix::libc::pid_t;

/// This is a thin wrapper around a vector of threads which provides some convenience functions for working with it,
/// such as one that retrieves the main thread from the list (see [`ThreadList::main`]). It can be retrieved by
/// calling [`RawInspector::get_threads`], and modifications made to it can be put into force via
/// [`RawInspector::set_threads`].

pub struct ThreadList {
    pub(super) data: Vec<ThreadData>,
    pub(super) pid: pid_t
}

impl ThreadList {
    /// Retrieves the main thread from the list.
    
    pub fn main(&mut self) -> &mut ThreadData {
        assert!(!self.data.is_empty());
        for thread in self.data.iter_mut() {
            if thread.thread_id == self.pid {
                return thread;
            }
        }

        // Not reachable due to the way Linux thread semantics work. A thread with the same TID as the PID
        // is guaranteed to exist for every process. If this is somehow reached it indicates a severe bug
        // in the kernel module, in which case the person who encountered it should open an issue.
        unreachable!("Please open a GitHub issue with an MRE.")
    }

    /// Gets the parent PID of this list.
    
    pub fn pid(&self) -> pid_t {
        self.pid
    }
}

impl Deref for ThreadList {
    type Target = Vec<ThreadData>;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for ThreadList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}