use crate::kill::KillError;
use crate::model::{Entry, Ident, Proto, normalize_addr, project_name};
use crate::sort::sort_entries;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;

const TCP_TABLE_OWNER_PID_LISTENER: u32 = 3;
const UDP_TABLE_OWNER_PID: u32 = 1;
const MIB_TCP_STATE_LISTEN: u32 = 2;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

#[derive(Default, Clone)]
struct ProcInfo {
    name: String,
    path: String,
    cmdline: String,
    cwd: String,
    start: u64,
}

#[repr(C)]
struct MibTcpRowOwnerPid {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MibTcp6RowOwnerPid {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    remote_scope_id: u32,
    remote_port: u32,
    state: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MibUdpRowOwnerPid {
    local_addr: u32,
    local_port: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MibUdp6RowOwnerPid {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    owning_pid: u32,
}

unsafe extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut std::ffi::c_void,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        pUdpTable: *mut std::ffi::c_void,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
}

/// Enumerates all listening TCP and bound UDP sockets on Windows via IP Helper.
pub fn list_listeners() -> io::Result<Vec<Entry>> {
    let mut cache: HashMap<u32, ProcInfo> = HashMap::new();
    let mut out = Vec::new();

    // TCP IPv4
    if let Ok(table) = get_extended_tcp4() {
        for row in table {
            if row.state != MIB_TCP_STATE_LISTEN {
                continue;
            }
            let ip = Ipv4Addr::from(row.local_addr.to_be());
            let port = u16::from_be((row.local_port & 0xFFFF) as u16);
            out.push(make_entry(
                Proto::Tcp,
                &ip.to_string(),
                port,
                row.owning_pid,
                &mut cache,
            ));
        }
    }

    // TCP IPv6
    if let Ok(table) = get_extended_tcp6() {
        for row in table {
            if row.state != MIB_TCP_STATE_LISTEN {
                continue;
            }
            let ip = Ipv6Addr::from(row.local_addr);
            let port = u16::from_be((row.local_port & 0xFFFF) as u16);
            out.push(make_entry(
                Proto::Tcp,
                &ip.to_string(),
                port,
                row.owning_pid,
                &mut cache,
            ));
        }
    }

    // UDP IPv4
    if let Ok(table) = get_extended_udp4() {
        for row in table {
            let port = u16::from_be((row.local_port & 0xFFFF) as u16);
            if port == 0 {
                continue;
            }
            let ip = Ipv4Addr::from(row.local_addr.to_be());
            out.push(make_entry(
                Proto::Udp,
                &ip.to_string(),
                port,
                row.owning_pid,
                &mut cache,
            ));
        }
    }

    // UDP IPv6
    if let Ok(table) = get_extended_udp6() {
        for row in table {
            let port = u16::from_be((row.local_port & 0xFFFF) as u16);
            if port == 0 {
                continue;
            }
            let ip = Ipv6Addr::from(row.local_addr);
            out.push(make_entry(
                Proto::Udp,
                &ip.to_string(),
                port,
                row.owning_pid,
                &mut cache,
            ));
        }
    }

    sort_entries(&mut out);
    Ok(out)
}

fn make_entry(
    proto: Proto,
    addr: &str,
    port: u16,
    pid: u32,
    cache: &mut HashMap<u32, ProcInfo>,
) -> Entry {
    let info = lookup_proc(pid, cache);
    Entry {
        proto,
        port,
        addr: normalize_addr(addr),
        pid: pid as i32,
        name: info.name,
        path: info.path,
        cmdline: info.cmdline,
        cwd: info.cwd.clone(),
        project: project_name(&info.cwd),
        start: info.start,
    }
}

fn lookup_proc(pid: u32, cache: &mut HashMap<u32, ProcInfo>) -> ProcInfo {
    if pid == 0 {
        return ProcInfo::default();
    }
    if let Some(info) = cache.get(&pid) {
        return info.clone();
    }
    let info = query_process(pid);
    cache.insert(pid, info.clone());
    info
}

fn query_process(pid: u32) -> ProcInfo {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::ProcessStatus::K32GetModuleFileNameExW;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return ProcInfo::default();
        }

        let mut buf = [0u16; 1024];
        let len = K32GetModuleFileNameExW(
            handle,
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        let path = if len > 0 {
            OsString::from_wide(&buf[..len as usize])
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };

        let name = Path::new(&path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();

        let start = process_start_token(handle).unwrap_or(0);
        CloseHandle(handle);

        let (cmdline, cwd) = if pid == std::process::id() {
            let cmd = std::env::args().collect::<Vec<_>>().join(" ");
            let dir = std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(ToString::to_string))
                .unwrap_or_default();
            (cmd, dir)
        } else {
            (String::new(), String::new())
        };

        ProcInfo {
            name,
            path,
            cmdline,
            cwd,
            start,
        }
    }
}

unsafe fn process_start_token(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<u64, KillError> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };

    let ret = unsafe { GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) };
    if ret == 0 {
        return Err(KillError::System("GetProcessTimes failed".to_string()));
    }

    Ok(((created.dwHighDateTime as u64) << 32) | (created.dwLowDateTime as u64))
}

pub fn proc_start_token(pid: i32) -> Result<u64, KillError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if handle.is_null() {
            return Err(KillError::System(format!(
                "OpenProcess failed for pid {pid}"
            )));
        }
        let token = process_start_token(handle);
        CloseHandle(handle);
        token
    }
}

pub fn kill_process(id: Ident) -> Result<(), KillError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };

    crate::kill::require_ident(id)?;

    unsafe {
        let handle = OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            id.pid as u32,
        );
        if handle.is_null() {
            return Err(KillError::System(format!(
                "OpenProcess failed for pid {}",
                id.pid
            )));
        }

        let cur = process_start_token(handle);
        if cur != Ok(id.start) {
            CloseHandle(handle);
            return Err(KillError::IdentityMismatch);
        }

        let ret = TerminateProcess(handle, 1);
        CloseHandle(handle);

        if ret == 0 {
            return Err(KillError::System("TerminateProcess failed".to_string()));
        }

        Ok(())
    }
}

fn get_extended_tcp4() -> io::Result<Vec<MibTcpRowOwnerPid>> {
    unsafe {
        let mut size = 0u32;
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if ret != 0 || buf.len() < 4 {
            return Ok(Vec::new());
        }
        let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let rows_ptr = buf.as_ptr().add(4).cast::<MibTcpRowOwnerPid>();
        let slice = std::slice::from_raw_parts(rows_ptr, count);
        let mut out = Vec::with_capacity(count);
        for item in slice {
            out.push(std::ptr::read_unaligned(item));
        }
        Ok(out)
    }
}

fn get_extended_tcp6() -> io::Result<Vec<MibTcp6RowOwnerPid>> {
    unsafe {
        let mut size = 0u32;
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if ret != 0 || buf.len() < 4 {
            return Ok(Vec::new());
        }
        let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let rows_ptr = buf.as_ptr().add(4).cast::<MibTcp6RowOwnerPid>();
        let slice = std::slice::from_raw_parts(rows_ptr, count);
        let mut out = Vec::with_capacity(count);
        for item in slice {
            out.push(std::ptr::read_unaligned(item));
        }
        Ok(out)
    }
}

fn get_extended_udp4() -> io::Result<Vec<MibUdpRowOwnerPid>> {
    unsafe {
        let mut size = 0u32;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != 0 || buf.len() < 4 {
            return Ok(Vec::new());
        }
        let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let rows_ptr = buf.as_ptr().add(4).cast::<MibUdpRowOwnerPid>();
        let slice = std::slice::from_raw_parts(rows_ptr, count);
        let mut out = Vec::with_capacity(count);
        for item in slice {
            out.push(std::ptr::read_unaligned(item));
        }
        Ok(out)
    }
}

fn get_extended_udp6() -> io::Result<Vec<MibUdp6RowOwnerPid>> {
    unsafe {
        let mut size = 0u32;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != 0 || buf.len() < 4 {
            return Ok(Vec::new());
        }
        let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let rows_ptr = buf.as_ptr().add(4).cast::<MibUdp6RowOwnerPid>();
        let slice = std::slice::from_raw_parts(rows_ptr, count);
        let mut out = Vec::with_capacity(count);
        for item in slice {
            out.push(std::ptr::read_unaligned(item));
        }
        Ok(out)
    }
}
