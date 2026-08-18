use std::ffi::{c_char, c_int, c_void};

pub const PROC_ALL_PIDS: u32 = 1;
pub const PROC_PIDLISTFDS: c_int = 1;
pub const PROC_PIDTBSDINFO: c_int = 3;
pub const PROC_PIDVNODEPATHINFO: c_int = 9;
pub const PROC_PIDFDSOCKETINFO: c_int = 3;
pub const PROX_FDTYPE_SOCKET: u32 = 2;

pub const SOCKINFO_TCP: i32 = 2;
pub const SOCK_DGRAM: i32 = 2;
pub const IPPROTO_UDP: i32 = 17;
pub const TSI_S_LISTEN: i32 = 1;

pub const INI_IPV4: u8 = 0x1;

pub const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
pub const STACK_FD_COUNT: usize = 64;

pub const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;

unsafe extern "C" {
    pub fn proc_listpids(
        type_: u32,
        typeinfo: u32,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    pub fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    pub fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    pub fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    pub fn proc_name(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    pub fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: c_int) -> c_int;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcFdInfo {
    pub proc_fd: i32,
    pub proc_fdtype: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct In4In6Addr {
    pub i46a_pad32: [u32; 3],
    pub i46a_addr4: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union InSockInfoAddr {
    pub ina_4: [u8; 4],
    pub ina_6: [u8; 16],
    pub ina_46: In4In6Addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InSockInfo {
    pub insi_fport: u32,
    pub insi_lport: u32,
    pub insi_gencnt: u64,
    pub insi_flags: u32,
    pub insi_flow: u32,
    pub insi_vflag: u8,
    pub insi_ip_ttl: u8,
    pub _pad: [u8; 6],
    pub insi_faddr: InSockInfoAddr,
    pub insi_laddr: InSockInfoAddr,
    pub _v46_extra: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpSockInfo {
    pub tcpsi_ini: InSockInfo,
    pub tcpsi_state: i32,
    pub tcpsi_timer: [i32; 4],
    pub tcpsi_mss: i32,
    pub tcpsi_flags: u32,
    pub rfu_1: u32,
    pub tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SocketInfoProto {
    pub pri_in: InSockInfo,
    pub pri_tcp: TcpSockInfo,
    pub pri_un: [u8; 528],
    pub pri_ndrv: [u8; 528],
    pub rfu_1: [u8; 528],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketInfo {
    pub soi_stat: [u8; 152],
    pub soi_type: i32,
    pub soi_protocol: i32,
    pub soi_family: i32,
    pub soi_options: i16,
    pub soi_linger: i16,
    pub soi_state: i16,
    pub soi_qlen: i16,
    pub soi_incqlen: i16,
    pub soi_qlimit: i16,
    pub soi_timeo: i16,
    pub soi_error: u16,
    pub soi_oobmark: u32,
    pub soi_rcv: [u8; 24],
    pub soi_snd: [u8; 24],
    pub soi_kind: i32,
    pub rfu_1: u32,
    pub soi_proto: SocketInfoProto,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketFdInfo {
    pub pfi: [u8; 24],
    pub psi: SocketInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcBsdInfo {
    pub pbi_flags: u32,
    pub pbi_status: u32,
    pub pbi_xstatus: u32,
    pub pbi_pid: u32,
    pub pbi_ppid: u32,
    pub pbi_uid: libc::uid_t,
    pub pbi_gid: libc::gid_t,
    pub pbi_ruid: libc::uid_t,
    pub pbi_rgid: libc::gid_t,
    pub pbi_svuid: libc::uid_t,
    pub pbi_svgid: libc::gid_t,
    pub rfu_1: u32,
    pub pbi_comm: [u8; 16],
    pub pbi_name: [u8; 32],
    pub pbi_nfiles: u32,
    pub pbi_pgid: u32,
    pub pbi_pjobc: u32,
    pub e_tdev: u32,
    pub e_tpgid: u32,
    pub pbi_nice: i32,
    pub pbi_start_tvsec: u64,
    pub pbi_start_tvusec: u64,
}

#[repr(C)]
pub struct VnodeInfoPath {
    pub vip_vi: [u8; 152],
    pub vip_path: [c_char; 1024],
}

#[repr(C)]
pub struct ProcVnodePathInfo {
    pub pvi_cdir: VnodeInfoPath,
    pub pvi_rdir: VnodeInfoPath,
}
