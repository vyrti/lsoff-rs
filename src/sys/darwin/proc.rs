use super::types::*;
use crate::kill::KillError;
use crate::model::Ident;
use std::ffi::c_int;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// Lists all active PIDs on Darwin using a single-syscall stack buffer fast path.
pub fn list_pids() -> io::Result<Vec<i32>> {
    unsafe {
        let mut stack_buf = [0i32; 1024];
        let buf_bytes = (stack_buf.len() * std::mem::size_of::<i32>()) as i32;
        let n = proc_listpids(PROC_ALL_PIDS, 0, stack_buf.as_mut_ptr().cast(), buf_bytes);

        if n > 0 && n <= buf_bytes {
            let got = (n as usize) / std::mem::size_of::<i32>();
            let mut pids = Vec::with_capacity(got);
            for &pid in &stack_buf[..got] {
                if pid > 0 {
                    pids.push(pid);
                }
            }
            return Ok(pids);
        }

        // Fallback if more than 1024 processes
        let need = proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
        if need <= 0 {
            return Err(io::Error::other("proc_listpids failed to get size"));
        }

        let pid_size = std::mem::size_of::<i32>() as i32;
        let count = (need / pid_size) + 64;
        let mut heap_buf: Vec<i32> = vec![0; count as usize];
        let n = proc_listpids(
            PROC_ALL_PIDS,
            0,
            heap_buf.as_mut_ptr().cast(),
            count * pid_size,
        );
        if n <= 0 {
            return Err(io::Error::other("proc_listpids failed to read pids"));
        }

        let got = (n / pid_size) as usize;
        let mut pids = Vec::with_capacity(got);
        for &pid in &heap_buf[..got] {
            if pid > 0 {
                pids.push(pid);
            }
        }
        Ok(pids)
    }
}

pub fn proc_name_path(pid: i32) -> (String, String) {
    let mut path_buf = [0u8; PROC_PIDPATHINFO_MAXSIZE];
    let n = unsafe { proc_pidpath(pid, path_buf.as_mut_ptr().cast(), path_buf.len() as u32) };
    let path = if n > 0 {
        String::from_utf8_lossy(&path_buf[..n as usize]).into_owned()
    } else {
        String::new()
    };

    let name = if !path.is_empty() {
        Path::new(&path)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        let mut name_buf = [0u8; 32];
        let n = unsafe { proc_name(pid, name_buf.as_mut_ptr().cast(), name_buf.len() as u32) };
        if n > 0 {
            String::from_utf8_lossy(&name_buf[..n as usize]).into_owned()
        } else {
            String::new()
        }
    };

    (name, path)
}

pub fn proc_cwd(pid: i32) -> String {
    unsafe {
        let mut info: ProcVnodePathInfo = std::mem::zeroed();
        let n = proc_pidinfo(
            pid,
            PROC_PIDVNODEPATHINFO,
            0,
            (&raw mut info).cast(),
            std::mem::size_of::<ProcVnodePathInfo>() as i32,
        );
        if n <= 0 {
            return String::new();
        }
        let ptr = info.pvi_cdir.vip_path.as_ptr();
        if *ptr == 0 {
            return String::new();
        }
        let len = (0..1024).find(|&i| *ptr.add(i) == 0).unwrap_or(1024);
        let slice = std::slice::from_raw_parts(ptr.cast::<u8>(), len);
        String::from_utf8_lossy(slice).into_owned()
    }
}

pub fn proc_cmdline(pid: i32) -> String {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
            || size < 4
        {
            return String::new();
        }

        let mut stack_buf = [0u8; 1024];
        if size <= stack_buf.len() {
            if libc::sysctl(
                mib.as_mut_ptr(),
                3,
                stack_buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return String::new();
            }
            parse_procargs2(&stack_buf[..size])
        } else {
            let mut heap_buf = vec![0u8; size];
            if libc::sysctl(
                mib.as_mut_ptr(),
                3,
                heap_buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return String::new();
            }
            parse_procargs2(&heap_buf[..size])
        }
    }
}

fn parse_procargs2(buf: &[u8]) -> String {
    if buf.len() < 4 {
        return String::new();
    }
    let argc = i32::from_ne_bytes(buf[0..4].try_into().unwrap_or([0; 4]));
    if argc <= 0 {
        return String::new();
    }

    let mut rest = &buf[4..];
    // Skip executable path
    if let Some(i) = rest.iter().position(|&b| b == 0) {
        rest = &rest[i + 1..];
    }
    // Skip null padding
    while !rest.is_empty() && rest[0] == 0 {
        rest = &rest[1..];
    }

    let mut args = Vec::with_capacity(argc as usize);
    let mut count = 0;
    while count < argc && !rest.is_empty() {
        if let Some(n) = rest.iter().position(|&b| b == 0) {
            if n > 0 {
                let s = String::from_utf8_lossy(&rest[..n]).into_owned();
                args.push(s);
            }
            rest = &rest[n + 1..];
            count += 1;
        } else {
            if !rest.is_empty() {
                let s = String::from_utf8_lossy(rest).into_owned();
                args.push(s);
            }
            break;
        }
    }

    args.join(" ").trim().to_string()
}

/// Retrieves the start token (microseconds since epoch) for a process.
pub fn proc_start_token(pid: i32) -> Result<u64, KillError> {
    unsafe {
        let mut info: ProcBsdInfo = std::mem::zeroed();
        let n = proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast(),
            std::mem::size_of::<ProcBsdInfo>() as i32,
        );
        if n < std::mem::size_of::<ProcBsdInfo>() as i32 {
            return Err(KillError::System(format!("proc_pidinfo bsdinfo: {n}")));
        }
        let usec = info.pbi_start_tvusec;
        if usec >= 1_000_000 {
            return Err(KillError::System(format!("bad start usec {usec}")));
        }
        let token = info.pbi_start_tvsec * 1_000_000 + usec;
        if token == 0 {
            return Err(KillError::MissingIdentity);
        }
        Ok(token)
    }
}

/// Terminates a process safely on macOS by checking start identity, signaling SIGTERM,
/// waiting up to 2 seconds, then escalating to SIGKILL if still alive.
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
