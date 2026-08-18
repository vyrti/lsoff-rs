pub mod proc;
pub mod types;

pub use proc::{kill_process, proc_start_token};

use crate::model::{Entry, Proto, normalize_addr, project_name};
use crate::sort::sort_entries;
use proc::*;
use rayon::prelude::*;
use std::collections::HashSet;
use std::ffi::c_int;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use types::*;

/// Enumerates all listening TCP and UDP sockets across all processes on FreeBSD.
///
/// # Errors
/// Returns `io::Error` if kernel process or file descriptor inspection fails.
pub fn list_listeners() -> io::Result<Vec<Entry>> {
    let pids = list_pids()?;

    let all_entries: Vec<Entry> = pids
        .into_par_iter()
        .flat_map_iter(sockets_for_pid)
        .collect();

    let mut seen = HashSet::with_capacity(all_entries.len());
    let mut out = Vec::with_capacity(all_entries.len());

    for e in all_entries {
        let key = e.key();
        if seen.insert(key) {
            out.push(e);
        }
    }

    sort_entries(&mut out);
    Ok(out)
}

fn list_pids() -> io::Result<Vec<i32>> {
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0];
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
            || size == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut alloc_size = size * 4 / 3 + 8192;
        let mut buf = vec![0u8; alloc_size];
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut alloc_size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut pids = Vec::new();
        let mut offset = 0;
        let self_pid = std::process::id() as i32;

        while offset + 76 <= alloc_size {
            let structsize =
                i32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;
            if structsize == 0 || offset + structsize > alloc_size {
                break;
            }

            let pid =
                i32::from_ne_bytes(buf[offset + 72..offset + 76].try_into().unwrap_or([0; 4]));
            if pid > 0 {
                pids.push(pid);
            }

            offset += structsize;
        }

        if !pids.contains(&self_pid) {
            pids.push(self_pid);
        }

        Ok(pids)
    }
}

fn sockets_for_pid(pid: i32) -> Vec<Entry> {
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid];
    let mut size: libc::size_t = 0;

    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            4,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
            || size == 0
        {
            return Vec::new();
        }

        let mut alloc_size = size * 4 / 3 + 4096;
        let mut buf = vec![0u8; alloc_size];
        if libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr().cast(),
            &mut alloc_size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut offset = 0;
        let mut name = String::new();
        let mut path = String::new();
        let mut cmdline = String::new();
        let mut cwd = String::new();
        let mut project = String::new();
        let mut start = 0u64;
        let mut loaded = false;

        while offset + std::mem::size_of::<c_int>() <= alloc_size {
            let kf = &*(buf.as_ptr().add(offset).cast::<KinfoFile>());
            let structsize = kf.kf_structsize as usize;
            if structsize == 0 || offset + structsize > alloc_size {
                break;
            }

            if kf.kf_type == KF_TYPE_SOCKET {
                if let Some((proto, port, addr)) =
                    parse_kinfo_socket(&buf[offset..offset + structsize])
                {
                    if !loaded {
                        path = proc_path(pid);
                        name = if !path.is_empty() {
                            Path::new(&path)
                                .file_name()
                                .map(|f| f.to_string_lossy().into_owned())
                                .unwrap_or_default()
                        } else {
                            proc_comm(pid)
                        };
                        cmdline = proc_cmdline(pid);
                        cwd = proc_cwd_from_buf(&buf[..alloc_size]);
                        if cwd.is_empty() && pid == std::process::id() as i32 {
                            cwd = std::env::current_dir()
                                .ok()
                                .and_then(|p| p.to_str().map(ToString::to_string))
                                .unwrap_or_default();
                        }
                        project = project_name(&cwd);
                        start = proc_start_token(pid).unwrap_or(0);
                        loaded = true;
                    }

                    out.push(Entry {
                        proto,
                        port,
                        addr,
                        pid,
                        name: name.clone(),
                        path: path.clone(),
                        cmdline: cmdline.clone(),
                        cwd: cwd.clone(),
                        project: project.clone(),
                        start,
                    });
                }
            }

            offset += structsize;
        }

        out
    }
}

fn parse_kinfo_socket(buf: &[u8]) -> Option<(Proto, u16, String)> {
    if buf.len() < 44 {
        return None;
    }

    let proto_num = i32::from_ne_bytes(buf[40..44].try_into().ok()?);
    let sock_type = i32::from_ne_bytes(buf[36..40].try_into().unwrap_or([0; 4]));

    let (proto, is_tcp) = match proto_num {
        IPPROTO_TCP => (Proto::Tcp, true),
        IPPROTO_UDP => (Proto::Udp, false),
        _ => {
            if sock_type == 1 {
                (Proto::Tcp, true)
            } else if sock_type == 2 {
                (Proto::Udp, false)
            } else {
                return None;
            }
        }
    };

    // Scan for local sockaddr (sockaddr_in or sockaddr_in6) in socket data buffer
    let mut found_addr: Option<(String, u16)> = None;

    // Check standard offsets: 48 (8-byte aligned), 44 (packed), and incremental 4-byte boundaries
    let candidate_offsets = [48, 44, 52, 56];
    for &sa_offset in &candidate_offsets {
        if buf.len() < sa_offset + 16 {
            continue;
        }
        let sa_len = buf[sa_offset] as usize;
        let sa_family = buf[sa_offset + 1] as i32;

        if (sa_family == AF_INET && (sa_len == 16 || sa_len == 0))
            || (sa_family == 0 && buf.len() >= sa_offset + 16)
        {
            let port = u16::from_be(u16::from_ne_bytes(
                buf[sa_offset + 2..sa_offset + 4].try_into().ok()?,
            ));
            if port > 0 {
                let ip = Ipv4Addr::new(
                    buf[sa_offset + 4],
                    buf[sa_offset + 5],
                    buf[sa_offset + 6],
                    buf[sa_offset + 7],
                );
                found_addr = Some((ip.to_string(), port));
                break;
            }
        } else if sa_family == AF_INET6
            && (sa_len == 28 || sa_len == 0)
            && buf.len() >= sa_offset + 24
        {
            let port = u16::from_be(u16::from_ne_bytes(
                buf[sa_offset + 2..sa_offset + 4].try_into().ok()?,
            ));
            if port > 0 {
                let ip_bytes: [u8; 16] = buf[sa_offset + 8..sa_offset + 24].try_into().ok()?;
                let ip = Ipv6Addr::from(ip_bytes);
                found_addr = Some((ip.to_string(), port));
                break;
            }
        }
    }

    let (addr, port) = found_addr?;

    if is_tcp {
        // If TCP socket, verify state if state field is present (offset 304 or 300)
        for &state_offset in &[304, 300, 308] {
            if buf.len() >= state_offset + 4 {
                let state = i32::from_ne_bytes(
                    buf[state_offset..state_offset + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                if state != TCPS_LISTEN && state != 0 {
                    return None;
                }
                break;
            }
        }
    }

    Some((proto, port, normalize_addr(&addr)))
}
