use super::types::*;
use crate::kill::KillError;
use crate::model::Ident;
use std::ffi::c_int;
use std::io;
use std::thread;
use std::time::{Duration, Instant};

pub fn proc_cwd_from_buf(buf: &[u8]) -> String {
    let mut offset = 0;
    while offset + std::mem::size_of::<c_int>() <= buf.len() {
        let kf = unsafe { &*(buf.as_ptr().add(offset).cast::<KinfoFile>()) };
        let structsize = kf.kf_structsize as usize;
        if structsize == 0 || offset + structsize > buf.len() {
            break;
        }
        if kf.kf_fd == KF_FD_TYPE_CWD {
            let path_slice = &buf[offset + 32..offset + structsize];
            if let Some(pos) = path_slice.iter().position(|&b| b == 0) {
                let s = String::from_utf8_lossy(&path_slice[..pos]).into_owned();
                if !s.is_empty() {
                    return s;
                }
            }
        }
        offset += structsize;
    }
    String::new()
}

pub fn proc_path(pid: i32) -> String {
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid];
    let mut buf = [0u8; 1024];
    let mut size = buf.len();
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) == 0
            && size > 0
        {
            let len = (0..size).find(|&i| buf[i] == 0).unwrap_or(size);
            let s = String::from_utf8_lossy(&buf[..len]).into_owned();
            if !s.is_empty() {
                return s;
            }
        }
    }
    if pid == std::process::id() as i32
        && let Ok(exe) = std::env::current_exe()
    {
        return exe.to_string_lossy().into_owned();
    }
    String::new()
}

pub fn proc_comm(pid: i32) -> String {
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];
    let mut proc: KinfoProc = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<KinfoProc>();
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            4,
            (&raw mut proc).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) == 0
        {
            let ptr = proc.ki_comm.as_ptr();
            let len = (0..20).find(|&i| *ptr.add(i) == 0).unwrap_or(20);
            let slice = std::slice::from_raw_parts(ptr.cast::<u8>(), len);
            return String::from_utf8_lossy(slice).into_owned();
        }
    }
    String::new()
}

pub fn proc_cmdline(pid: i32) -> String {
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_ARGS, pid];
    let mut size: libc::size_t = 0;
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            4,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) == 0
            && size > 0
        {
            let mut buf = vec![0u8; size];
            if libc::sysctl(
                mib.as_mut_ptr(),
                4,
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) == 0
            {
                let args: Vec<String> = buf
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();

                let joined = args.join(" ");
                if !joined.is_empty() {
                    return joined;
                }
            }
        }
    }
    if pid == std::process::id() as i32 {
        let args: Vec<String> = std::env::args().collect();
        if !args.is_empty() {
            return args.join(" ");
        }
    }
    String::new()
}

pub fn proc_start_token(pid: i32) -> Result<u64, KillError> {
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];
    let mut proc: KinfoProc = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<KinfoProc>();
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            4,
            (&raw mut proc).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(KillError::System(format!("proc_start_token failed: {pid}")));
        }
        let sec = proc.ki_start.tv_sec as u64;
        let usec = proc.ki_start.tv_usec as u64;
        let token = sec * 1_000_000 + usec;
        if token == 0 {
            return Err(KillError::MissingIdentity);
        }
        Ok(token)
    }
}

pub fn kill_process(id: Ident) -> Result<(), KillError> {
    crate::kill::require_ident(id)?;

    if let Err(e) = signal_if_same(id, libc::SIGTERM) {
        if is_esrch(&e) {
            return Ok(());
        }
        return Err(e);
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if verify_start(id).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }

    if let Err(e) = signal_if_same(id, libc::SIGKILL)
        && !is_esrch(&e)
    {
        return Err(e);
    }
    Ok(())
}

fn signal_if_same(id: Ident, sig: c_int) -> Result<(), KillError> {
    verify_start(id)?;
    let ret = unsafe { libc::kill(id.pid, sig) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        return Err(KillError::System(err.to_string()));
    }
    Ok(())
}

fn verify_start(id: Ident) -> Result<(), KillError> {
    let cur = proc_start_token(id.pid)?;
    if cur != id.start {
        return Err(KillError::IdentityMismatch);
    }
    Ok(())
}

fn is_esrch(e: &KillError) -> bool {
    match e {
        KillError::System(s) => s.contains("No such process") || s.contains("ESRCH"),
        _ => false,
    }
}
