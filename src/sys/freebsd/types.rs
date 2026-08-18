use std::ffi::c_int;

pub const CTL_KERN: c_int = 1;
pub const KERN_PROC: c_int = 14;
pub const KERN_PROC_ALL: c_int = 0;
pub const KERN_PROC_PID: c_int = 1;
pub const KERN_PROC_ARGS: c_int = 7;
pub const KERN_PROC_PATHNAME: c_int = 12;
pub const KERN_PROC_FILEDESC: c_int = 33;

pub const KF_TYPE_SOCKET: c_int = 2;
pub const KF_FD_TYPE_CWD: c_int = -1;

pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 28;

pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_UDP: c_int = 17;

pub const TCPS_LISTEN: c_int = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    pub tv_sec: libc::time_t,
    pub tv_usec: libc::suseconds_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KinfoProc {
    pub ki_structsize: c_int,
    pub ki_layout: c_int,
    pub ki_args: *mut libc::c_void,
    pub ki_paddr: *mut libc::c_void,
    pub ki_addr: *mut libc::c_void,
    pub ki_tracep: *mut libc::c_void,
    pub ki_textvp: *mut libc::c_void,
    pub ki_fd: *mut libc::c_void,
    pub ki_vmspace: *mut libc::c_void,
    pub ki_wchan: *mut libc::c_void,
    pub ki_pid: libc::pid_t,
    pub ki_ppid: libc::pid_t,
    pub ki_pgid: libc::pid_t,
    pub ki_tpgid: libc::pid_t,
    pub ki_sid: libc::pid_t,
    pub ki_tsid: libc::pid_t,
    pub ki_jobc: i16,
    pub ki_spare_short1: i16,
    pub ki_tdev_freebsd11: u32,
    pub ki_siglist: [u32; 4],
    pub ki_sigmask: [u32; 4],
    pub ki_sigignore: [u32; 4],
    pub ki_sigcatch: [u32; 4],
    pub ki_uid: libc::uid_t,
    pub ki_ruid: libc::uid_t,
    pub ki_svuid: libc::uid_t,
    pub ki_rgid: libc::gid_t,
    pub ki_svgid: libc::gid_t,
    pub ki_ngroups: i16,
    pub ki_spare_short2: i16,
    pub ki_groups: [libc::gid_t; 16],
    pub ki_size: libc::size_t,
    pub ki_rssize: libc::ssize_t,
    pub ki_swrss: libc::ssize_t,
    pub ki_tsize: libc::ssize_t,
    pub ki_dsize: libc::ssize_t,
    pub ki_ssize: libc::ssize_t,
    pub ki_xstat: u16,
    pub ki_acflag: u16,
    pub ki_pctcpu: u32,
    pub ki_estcpu: u32,
    pub ki_slptime: u32,
    pub ki_swtime: u32,
    pub ki_cow: u32,
    pub ki_runtime: u64,
    pub ki_start: Timeval,
    pub ki_childtime: Timeval,
    pub ki_flag: libc::c_long,
    pub ki_kiflag: libc::c_long,
    pub ki_traceflag: c_int,
    pub ki_stat: libc::c_char,
    pub ki_nice: libc::c_schar,
    pub ki_lock: libc::c_char,
    pub ki_rqindex: libc::c_char,
    pub ki_oncpu_old: u8,
    pub ki_lastcpu_old: u8,
    pub ki_tdname: [libc::c_char; 17],
    pub ki_wmesg: [libc::c_char; 9],
    pub ki_login: [libc::c_char; 18],
    pub ki_lockname: [libc::c_char; 9],
    pub ki_comm: [libc::c_char; 20],
    pub ki_emul: [libc::c_char; 17],
    pub ki_loginclass: [libc::c_char; 18],
    pub ki_moretdname: [libc::c_char; 4],
    pub ki_sparestrings: [libc::c_char; 46],
    pub ki_spareints: [c_int; 2],
    pub ki_tdev: u64,
    pub ki_oncpu: c_int,
    pub ki_lastcpu: c_int,
    pub ki_tracer: c_int,
    pub ki_flag2: c_int,
    pub ki_fibnum: c_int,
    pub ki_cr_flags: u32,
    pub ki_jid: c_int,
    pub ki_numthreads: c_int,
    pub ki_tid: libc::pid_t,
    pub ki_pri: [u8; 4],
    pub ki_rusage: [u8; 144],
    pub ki_rusage_ch: [u8; 144],
    pub ki_pcb: *mut libc::c_void,
    pub ki_kstack: *mut libc::c_void,
    pub ki_udata: *mut libc::c_void,
    pub ki_tdflags: u64,
    pub ki_spareptrs: [*mut libc::c_void; 3],
    pub ki_sparelongs: [libc::c_long; 6],
    pub ki_sflag: libc::c_long,
    pub ki_tdstate: libc::c_long,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KinfoFile {
    pub kf_structsize: c_int,
    pub kf_type: c_int,
    pub kf_fd: c_int,
    pub kf_ref_count: c_int,
    pub kf_flags: c_int,
    pub kf_pad0: c_int,
    pub kf_offset: i64,
    pub kf_data: [u8; 1024],
}
