#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "windows"
)))]
pub mod other;

pub mod ebpf;

use crate::kill::KillError;
use crate::model::{Entry, Ident};
use std::io;

/// Enumerates all active listening TCP and bound UDP sockets on the current OS.
///
/// # Errors
/// Returns `io::Error` if kernel query or permissions fail.
pub fn list_listeners() -> io::Result<Vec<Entry>> {
    #[cfg(target_os = "macos")]
    {
        darwin::list_listeners()
    }
    #[cfg(target_os = "linux")]
    {
        linux::list_listeners()
    }
    #[cfg(target_os = "freebsd")]
    {
        freebsd::list_listeners()
    }
    #[cfg(target_os = "windows")]
    {
        windows::list_listeners()
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        other::list_listeners()
    }
}

/// Safely terminates a process after verifying its identity token.
///
/// # Errors
/// Returns `KillError` if identity mismatches, PID is invalid, or OS signal fails.
pub fn kill_process(id: Ident) -> Result<(), KillError> {
    #[cfg(target_os = "macos")]
    {
        darwin::kill_process(id)
    }
    #[cfg(target_os = "linux")]
    {
        linux::kill_process(id)
    }
    #[cfg(target_os = "freebsd")]
    {
        freebsd::kill_process(id)
    }
    #[cfg(target_os = "windows")]
    {
        windows::kill_process(id)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        other::kill_process(id)
    }
}

/// Retrieves the start token for process identity verification.
///
/// # Errors
/// Returns `KillError` if process start time cannot be read.
pub fn proc_start_token(pid: i32) -> Result<u64, KillError> {
    #[cfg(target_os = "macos")]
    {
        darwin::proc_start_token(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::proc_start_token(pid)
    }
    #[cfg(target_os = "freebsd")]
    {
        freebsd::proc_start_token(pid)
    }
    #[cfg(target_os = "windows")]
    {
        windows::proc_start_token(pid)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        other::proc_start_token(pid)
    }
}
