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
    // FreeBSD 14.2 sys/user.h struct kinfo_file layout (offsets from struct start):
    //   0..4    kf_structsize
    //   4..8    kf_type
    //   8..12   kf_fd
    //  12..16   kf_ref_count
    //  16..20   kf_flags
    //  20..24   kf_pad0
    //  24..32   kf_offset (int64_t)
    //  32..36   kf_vnode_type  (compat) / kf_sock_sendq (kf_sock)
    //  36..40   kf_sock_domain
    //  40..44   kf_sock_type   (SOCK_STREAM=1, SOCK_DGRAM=2)
    //  44..48   kf_sock_protocol (IPPROTO_TCP=6, IPPROTO_UDP=17)
    //  48..176  kf_sa_local    (struct sockaddr_storage, 128 bytes)
    // 176..304  kf_sa_peer     (struct sockaddr_storage, 128 bytes)
    if buf.len() < 176 {
        return None;
    }

    let sock_domain = i32::from_ne_bytes(buf[36..40].try_into().ok()?);
    let sock_type = i32::from_ne_bytes(buf[40..44].try_into().ok()?);
    let sock_protocol = i32::from_ne_bytes(buf[44..48].try_into().ok()?);

    // Filter to AF_INET / AF_INET6 only
    if sock_domain != AF_INET && sock_domain != AF_INET6 {
        return None;
    }

    // Determine protocol: prefer kf_sock_protocol, fall back to kf_sock_type
    let (proto, is_tcp) = match sock_protocol {
        IPPROTO_TCP => (Proto::Tcp, true),
        IPPROTO_UDP => (Proto::Udp, false),
        _ => match sock_type {
            1 => (Proto::Tcp, true),  // SOCK_STREAM
            2 => (Proto::Udp, false), // SOCK_DGRAM
            _ => return None,
        },
    };

    // Parse kf_sa_local at fixed offset 48
    const SA_LOCAL: usize = 48;
    let sa_len = buf[SA_LOCAL] as usize;
    let sa_family = buf[SA_LOCAL + 1] as i32;

    let (addr, port) = if sa_family == AF_INET && buf.len() >= SA_LOCAL + 8 {
        let port = u16::from_be(u16::from_ne_bytes(
            buf[SA_LOCAL + 2..SA_LOCAL + 4].try_into().ok()?,
        ));
        if port == 0 {
            return None;
        }
        let ip = Ipv4Addr::new(
            buf[SA_LOCAL + 4],
            buf[SA_LOCAL + 5],
            buf[SA_LOCAL + 6],
            buf[SA_LOCAL + 7],
        );
        (ip.to_string(), port)
    } else if sa_family == AF_INET6 && sa_len >= 28 && buf.len() >= SA_LOCAL + 24 {
        let port = u16::from_be(u16::from_ne_bytes(
            buf[SA_LOCAL + 2..SA_LOCAL + 4].try_into().ok()?,
        ));
        if port == 0 {
            return None;
        }
        let ip_bytes: [u8; 16] = buf[SA_LOCAL + 8..SA_LOCAL + 24].try_into().ok()?;
        let ip = Ipv6Addr::from(ip_bytes);
        (ip.to_string(), port)
    } else {
        return None;
    };

    // For TCP: check kf_sa_peer at fixed offset 176 to filter established connections
    if is_tcp {
        const SA_PEER: usize = 176;
        if buf.len() >= SA_PEER + 4 {
            let peer_family = buf[SA_PEER + 1] as i32;
            if peer_family == AF_INET || peer_family == AF_INET6 {
                let peer_port = u16::from_be(u16::from_ne_bytes(
                    buf[SA_PEER + 2..SA_PEER + 4].try_into().unwrap_or([0; 2]),
                ));
                if peer_port > 0 {
                    return None;
                }
            }
        }
    }

    Some((proto, port, normalize_addr(&addr)))
}
