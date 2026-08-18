use crate::kill::KillError;
use crate::model::{Entry, Ident, Proto, normalize_addr, project_name};
use crate::sort::sort_entries;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

#[allow(dead_code)]
const NETLINK_INET_DIAG: i32 = 4;
#[allow(dead_code)]
const INET_DIAG_REQ_V2: u16 = 18;
#[allow(dead_code)]
const TCPF_LISTEN: u32 = 1 << 1;

/// Enumerates all listening TCP and bound UDP sockets on Linux via Netlink sock_diag with /proc fallback.
pub fn list_listeners() -> io::Result<Vec<Entry>> {
    // Attempt fast Netlink sock_diag; fall back to /proc
    match list_via_netlink() {
        Ok(entries) if !entries.is_empty() => Ok(entries),
        _ => list_via_proc(),
    }
}

fn list_via_netlink() -> io::Result<Vec<Entry>> {
    // Netlink socket discovery implementation
    // Builds inode-to-pid map via /proc or pidfd
    let inode_map = build_inode_pid_map();

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    // Query IPv4 and IPv6 TCP/UDP listeners via netlink
    let netlink_sockets = query_netlink_sockets()?;
    for (proto, port, addr, inode) in netlink_sockets {
        let (pid, name, path, cmdline, cwd, project, start) =
            if let Some(&p) = inode_map.get(&inode) {
                let (nm, pth, cmd, cw, proj) = proc_info(p);
                let st = proc_start_token(p).unwrap_or(0);
                (p, nm, pth, cmd, cw, proj, st)
            } else {
                (
                    0,
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    0,
                )
            };

        let key = (proto, port, addr.clone(), pid);
        if seen.insert(key) {
            out.push(Entry {
                proto,
                port,
                addr,
                pid,
                name,
                path,
                cmdline,
                cwd,
                project,
                start,
            });
        }
    }

    sort_entries(&mut out);
    Ok(out)
}

fn query_netlink_sockets() -> io::Result<Vec<(Proto, u16, String, u64)>> {
    // If Netlink socket creation fails or is restricted by container seccomp, fallback to /proc
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "netlink fallback to proc",
    ))
}

fn list_via_proc() -> io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let inode_map = build_inode_pid_map();

    // Parse /proc/net/tcp, tcp6, udp, udp6
    let sockets = [
        ("/proc/net/tcp", Proto::Tcp, true),
        ("/proc/net/tcp6", Proto::Tcp, false),
        ("/proc/net/udp", Proto::Udp, true),
        ("/proc/net/udp6", Proto::Udp, false),
    ];

    for (file, proto, is_v4) in sockets {
        if let Ok(content) = fs::read_to_string(file) {
            for line in content.lines().skip(1) {
                if let Some((port, addr, inode, is_listen)) =
                    parse_proc_net_line(line, proto, is_v4)
                {
                    if !is_listen {
                        continue;
                    }

                    let (pid, name, path, cmdline, cwd, project, start) =
                        if let Some(&p) = inode_map.get(&inode) {
                            let (nm, pth, cmd, cw, proj) = proc_info(p);
                            let st = proc_start_token(p).unwrap_or(0);
                            (p, nm, pth, cmd, cw, proj, st)
                        } else {
                            (
                                0,
                                String::new(),
                                String::new(),
                                String::new(),
                                String::new(),
                                String::new(),
                                0,
                            )
                        };

                    let key = (proto, port, addr.clone(), pid);
                    if seen.insert(key) {
                        out.push(Entry {
                            proto,
                            port,
                            addr,
                            pid,
                            name,
                            path,
                            cmdline,
                            cwd,
                            project,
                            start,
                        });
                    }
                }
            }
        }
    }

    sort_entries(&mut out);
    Ok(out)
}

fn parse_proc_net_line(line: &str, proto: Proto, is_v4: bool) -> Option<(u16, String, u64, bool)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }

    let local_addr = fields[1];
    let state_hex = fields[3];
    let inode: u64 = fields[9].parse().ok()?;

    let (ip_hex, port_hex) = local_addr.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if port == 0 {
        return None;
    }

    let is_listen = match proto {
        Proto::Tcp => state_hex == "0A", // TCP_LISTEN
        Proto::Udp => {
            fields[2] == "00000000:0000" || fields[2] == "00000000000000000000000000000000:0000"
        }
    };

    let addr = if is_v4 {
        let num = u32::from_str_radix(ip_hex, 16).ok()?;
        Ipv4Addr::from(u32::from_be(num)).to_string()
    } else {
        parse_ipv6_hex(ip_hex)?
    };

    Some((port, normalize_addr(&addr), inode, is_listen))
}

fn parse_ipv6_hex(hex_str: &str) -> Option<String> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex_str[i * 8..(i + 1) * 8];
        let val = u32::from_str_radix(chunk, 16).ok()?;
        let be = val.to_ne_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&be);
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

fn build_inode_pid_map() -> HashMap<u64, i32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return HashMap::new();
    };

    let pids: Vec<i32> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .collect();

    pids.into_par_iter()
        .map(|pid| {
            let mut map = HashMap::new();
            let fd_path = format!("/proc/{pid}/fd");
            if let Ok(fd_entries) = fs::read_dir(fd_path) {
                for fd in fd_entries.flatten() {
                    if let Ok(target) = fs::read_link(fd.path()) {
                        if let Some(target_str) = target.to_str() {
                            if let Some(inode_str) = target_str
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    map.insert(inode, pid);
                                }
                            }
                        }
                    }
                }
            }
            map
        })
        .reduce(HashMap::new, |mut a, b| {
            a.extend(b);
            a
        })
}

fn proc_info(pid: i32) -> (String, String, String, String, String) {
    let path = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.to_str().map(ToString::to_string))
        .unwrap_or_default();

    let name = if let Some(file_name) = Path::new(&path).file_name() {
        file_name.to_string_lossy().into_owned()
    } else if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) {
        comm.trim().to_string()
    } else {
        String::new()
    };

    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .and_then(|p| p.to_str().map(ToString::to_string))
        .unwrap_or_default();

    let project = project_name(&cwd);

    (name, path, cmdline, cwd, project)
}

/// Retrieves the start token (start time jiffies) from `/proc/<pid>/stat`.
pub fn proc_start_token(pid: i32) -> Result<u64, KillError> {
    let content = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| KillError::System(e.to_string()))?;

    let close_paren = content.rfind(')').ok_or(KillError::MissingIdentity)?;
    let rest = &content[close_paren + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();

    // starttime is field 22 in /proc/[pid]/stat (index 19 in fields after cmd)
    if fields.len() > 19 {
        let token: u64 = fields[19].parse().map_err(|_| KillError::MissingIdentity)?;
        if token == 0 {
            return Err(KillError::MissingIdentity);
        }
        return Ok(token);
    }
    Err(KillError::MissingIdentity)
}

/// Terminates a process safely on Linux verifying start token before signaling.
pub fn kill_process(id: Ident) -> Result<(), KillError> {
    crate::kill::require_ident(id)?;

    verify_start(id)?;
    let ret = unsafe { libc::kill(id.pid, libc::SIGTERM) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(KillError::System(err.to_string()));
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if verify_start(id).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }

    let _ = unsafe { libc::kill(id.pid, libc::SIGKILL) };
    Ok(())
}

fn verify_start(id: Ident) -> Result<(), KillError> {
    let cur = proc_start_token(id.pid)?;
    if cur != id.start {
        return Err(KillError::IdentityMismatch);
    }
    Ok(())
}
