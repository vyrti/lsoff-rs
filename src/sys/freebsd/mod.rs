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
        {
            return Err(io::Error::last_os_error());
        }

        let count = size / std::mem::size_of::<KinfoProc>();
        let mut procs = vec![std::mem::zeroed::<KinfoProc>(); count + 16];
        size = procs.len() * std::mem::size_of::<KinfoProc>();

        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            procs.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }

        let actual = size / std::mem::size_of::<KinfoProc>();
        let mut pids = Vec::with_capacity(actual);
        for p in &procs[..actual] {
            if p.ki_pid > 0 {
                pids.push(p.ki_pid);
            }
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

        let mut buf = vec![0u8; size];
        if libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr().cast(),
            &mut size,
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

        while offset + std::mem::size_of::<c_int>() <= size {
            let kf = &*(buf.as_ptr().add(offset).cast::<KinfoFile>());
            let structsize = kf.kf_structsize as usize;
            if structsize == 0 || offset + structsize > size {
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
                        cwd = proc_cwd_from_buf(&buf[..size]);
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
    if buf.len() < 128 {
        return None;
    }
    let domain = i32::from_ne_bytes(buf[32..36].try_into().ok()?);
    let proto_num = i32::from_ne_bytes(buf[40..44].try_into().ok()?);

    let (proto, is_tcp) = match proto_num {
        IPPROTO_TCP => (Proto::Tcp, true),
        IPPROTO_UDP => (Proto::Udp, false),
        _ => return None,
    };

    let sa_bytes = &buf[44..44 + 128];
    let (addr, port) = match domain {
        AF_INET => {
            let port = u16::from_be(u16::from_ne_bytes(sa_bytes[2..4].try_into().ok()?));
            let ip = Ipv4Addr::new(sa_bytes[4], sa_bytes[5], sa_bytes[6], sa_bytes[7]);
            (ip.to_string(), port)
        }
        AF_INET6 => {
            let port = u16::from_be(u16::from_ne_bytes(sa_bytes[2..4].try_into().ok()?));
            let ip_bytes: [u8; 16] = sa_bytes[8..24].try_into().ok()?;
            let ip = Ipv6Addr::from(ip_bytes);
            (ip.to_string(), port)
        }
        _ => return None,
    };

    if port == 0 {
        return None;
    }

    if is_tcp && buf.len() >= 308 {
        let state = i32::from_ne_bytes(buf[300..304].try_into().unwrap_or([0; 4]));
        if state != TCPS_LISTEN {
            return None;
        }
    }

    Some((proto, port, normalize_addr(&addr)))
}
