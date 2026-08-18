use crate::model::Ident;
use std::process;

/// Error type for kill operation failures.
#[derive(Debug)]
pub enum KillError {
    InvalidPid(i32),
    RefusePid1,
    RefuseSelf,
    MissingIdentity,
    IdentityMismatch,
    System(String),
}

impl std::fmt::Display for KillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPid(pid) => write!(f, "invalid pid {pid}"),
            Self::RefusePid1 => write!(f, "refusing to kill pid 1"),
            Self::RefuseSelf => write!(f, "refusing to kill self"),
            Self::MissingIdentity => write!(f, "missing process identity; refusing to kill"),
            Self::IdentityMismatch => write!(f, "process identity changed (pid reused?)"),
            Self::System(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for KillError {}

/// Verifies that a PID is valid and safe to kill.
pub fn check_kill_pid(pid: i32) -> Result<(), KillError> {
    if pid <= 0 {
        return Err(KillError::InvalidPid(pid));
    }
    if pid == 1 {
        return Err(KillError::RefusePid1);
    }
    if pid == process::id() as i32 {
        return Err(KillError::RefuseSelf);
    }
    Ok(())
}

/// Verifies that process identity is valid before killing.
pub fn require_ident(id: Ident) -> Result<(), KillError> {
    check_kill_pid(id.pid)?;
    if id.start == 0 {
        return Err(KillError::MissingIdentity);
    }
    Ok(())
}

/// Kills a single process identified by `Ident`.
pub fn kill(id: Ident) -> Result<(), KillError> {
    crate::sys::kill_process(id)
}

/// Kills all specified processes, continuing on error and joining failures.
pub fn kill_all(ids: &[Ident]) -> Result<(), String> {
    let mut errs = Vec::new();
    for &id in ids {
        if let Err(e) = kill(id) {
            errs.push(format!("pid {}: {}", id.pid, e));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n"))
    }
}
