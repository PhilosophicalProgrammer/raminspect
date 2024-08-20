//! This module provides convenience functions for finding the process ID of the process that
//! you would like to modify, which must be done before you can create a [`RamInspector`].
//! See the documentation of [`find_processes`] and [`iter_processes`] for more
//! information.

use std::vec::IntoIter;
use nix::libc::pid_t;

// Used in docs.
#[allow(unused_imports)]
use crate::inspector::RamInspector;

/// A structure representing a process ID associated with its command invocation text, which
/// usually contains the name of the program. Exposing ways to access this information makes
/// it easier for users of this library to determine the process ID of the application that
/// they want to modify.

pub struct Process {
    /// The command invocation text stored in this processes' `/proc/PID/cmdline` file.
    pub cmdline: String,

    /// The process ID of this process.
    pub pid: pid_t,
}

/// Creates an iterator over all processes in the `/proc` folder, returning information about
/// their IDs and command invocation texts, which usually contain their program names. See
/// the documentation of [`Process`].
/// 
/// # Example Usage
/// 
/// ```rust
/// // Iterate over all userspace processes.
/// for pid in raminspect::iter_processes().filter(|proc| !proc.cmdline.contains("kworker")) {
///     // .. do whatever ..
/// }
/// ```

pub fn iter_processes() -> IntoIter<Process> {
    let mut results = Vec::new();
    let procdir = match std::fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return results.into_iter()
    };

    for entry in procdir.filter_map(Result::ok) {
        let pid = match entry.file_name().to_string_lossy().parse::<pid_t>() {
            Ok(pid) => pid,
            Err(_) => continue
        };

        let mut path = entry.path();
        path.push("cmdline");

        if let Ok(cmdline) = std::fs::read_to_string(path) {
            results.push(Process {
                cmdline,
                pid
            });
        }
    }

    results.into_iter()
}

/// Finds a list of all processes containing a given search term in their program name.
/// See the documentation of [`iter_processes`], as this function is just a convenient
/// and thin wrapper around that.
/// 
/// # Example
/// 
/// ```rust
/// let firefox_pids = raminspect::find_processes("/usr/lib/firefox");
/// 
/// for pid in firefox_pids {
///     // ... do whatever ...
/// }
/// ```

pub fn find_processes(search_term: &str) -> Vec<Process> {
    iter_processes().filter(|proc| proc.cmdline.contains(search_term)).collect()
}