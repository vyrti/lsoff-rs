pub mod proc;
pub mod types;
pub mod watcher;

pub use proc::{kill_process, proc_start_token};
pub use watcher::ProcessWatcher;

use crate::model::{Entry, Proto, normalize_addr, project_name};
use crate::sort::sort_entries;
use proc::*;
use rayon::prelude::*;
use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Once;
use types::*;

static INIT_QOS: Once = Once::new();

/// Initializes Apple Silicon Performance Core QoS class for all Rayon worker threads.
fn ensure_qos_configured() {
    INIT_QOS.call_once(|| {
        let _ = rayon::ThreadPoolBuilder::new()
            .start_handler(|_| unsafe {
                pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
            })
            .build_global();
    });
}

/// Enumerates all listening TCP and bound UDP sockets via parallel macOS libproc scans.
///
/// # Errors
/// Returns `io::Error` if PID listing or socket queries fail.
pub fn list_listeners() -> io::Result<Vec<Entry>> {
    ensure_qos_configured();
    let pids = list_pids()?;

    // Parallel scan across Apple Silicon P-cores
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

fn sockets_for_pid(pid: i32) -> Vec<Entry> {
    unsafe {
        let fd_size = std::mem::size_of::<ProcFdInfo>() as i32;
        let stack_buf_bytes = (STACK_FD_COUNT as i32) * fd_size;
        let mut stack_fds = [ProcFdInfo {
            proc_fd: 0,
            proc_fdtype: 0,
        }; STACK_FD_COUNT];

        // 1-syscall fast path for majority of processes
        let n = proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            stack_fds.as_mut_ptr().cast(),
            stack_buf_bytes,
        );
        if n <= 0 {
            return Vec::new();
        }

        let (fd_slice, _heap_buf): (&[ProcFdInfo], Option<Vec<u8>>) = if n < stack_buf_bytes {
            let count = (n as usize) / (fd_size as usize);
            (&stack_fds[..count], None)
        } else {
            // Buffer was completely filled; query exact needed size and dynamically fetch
            let need = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
            if need <= 0 {
                let count = (n as usize) / (fd_size as usize);
                (&stack_fds[..count], None)
            } else {
                let buf_size = need * 2;
                let mut heap = vec![0u8; buf_size as usize];
                let got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, heap.as_mut_ptr().cast(), buf_size);
                if got > 0 {
                    let count = (got as usize) / (fd_size as usize);
                    let ptr = heap.as_ptr().cast::<ProcFdInfo>();
                    (std::slice::from_raw_parts(ptr, count), Some(heap))
                } else {
                    let count = (n as usize) / (fd_size as usize);
                    (&stack_fds[..count], None)
                }
            }
        };

        let mut name = String::new();
        let mut path = String::new();
        let mut cmdline = String::new();
        let mut cwd = String::new();
        let mut project = String::new();
        let mut start = 0u64;
        let mut loaded = false;
        let mut out = Vec::new();

        for fdinfo in fd_slice {
            if fdinfo.proc_fdtype != PROX_FDTYPE_SOCKET {
                continue;
            }

            let mut si: SocketFdInfo = std::mem::zeroed();
            let got = proc_pidfdinfo(
                pid,
                fdinfo.proc_fd,
                PROC_PIDFDSOCKETINFO,
                (&raw mut si).cast(),
                std::mem::size_of::<SocketFdInfo>() as i32,
            );
            if got <= 0 {
                continue;
            }

            let (proto, port, addr) = match parse_listen_socket(&si) {
                Some(res) => res,
                None => continue,
            };

            if !loaded {
                let (p_name, p_path) = proc_name_path(pid);
                name = p_name;
                path = p_path;
                cmdline = proc_cmdline(pid);
                cwd = proc_cwd(pid);
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

        out
    }
}

unsafe fn parse_listen_socket(si: &SocketFdInfo) -> Option<(Proto, u16, String)> {
    let family = si.psi.soi_family;
    if family != libc::AF_INET && family != libc::AF_INET6 {
        return None;
    }

    if si.psi.soi_kind == SOCKINFO_TCP {
        let tcp = unsafe { &si.psi.soi_proto.pri_tcp };
        if tcp.tcpsi_state != TSI_S_LISTEN {
            return None;
        }
        let port = u16::from_be(tcp.tcpsi_ini.insi_lport as u16);
        if port == 0 {
            return None;
        }
        let addr = unsafe { format_in_addr(&tcp.tcpsi_ini) };
        return Some((Proto::Tcp, port, normalize_addr(&addr)));
    }

    if si.psi.soi_protocol == IPPROTO_UDP || si.psi.soi_type == SOCK_DGRAM {
        let in_info = unsafe { &si.psi.soi_proto.pri_in };
        let port = u16::from_be(in_info.insi_lport as u16);
        let fport = u16::from_be(in_info.insi_fport as u16);
        if port == 0 || fport != 0 {
            return None;
        }
        let addr = unsafe { format_in_addr(in_info) };
        return Some((Proto::Udp, port, normalize_addr(&addr)));
    }

    None
}

unsafe fn format_in_addr(in_info: &InSockInfo) -> String {
    if in_info.insi_vflag & INI_IPV4 != 0 {
        let ip4_bytes = unsafe { in_info.insi_laddr.ina_46.i46a_addr4 };
        Ipv4Addr::from(ip4_bytes).to_string()
    } else {
        let ip6_bytes = unsafe { in_info.insi_laddr.ina_6 };
        Ipv6Addr::from(ip6_bytes).to_string()
    }
}
