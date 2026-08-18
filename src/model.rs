use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

/// Transport layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A listening or bound network socket and its owning process metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub proto: Proto,
    pub port: u16,
    pub addr: String,
    pub pid: i32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub cwd: String,
    pub project: String,
    #[serde(skip)]
    pub start: u64,
}

impl Entry {
    /// Produces a unique key representing this endpoint.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}:{}:{}", self.proto, self.port, self.addr, self.pid)
    }

    /// Returns the process identification token.
    #[must_use]
    pub const fn ident(&self) -> Ident {
        Ident {
            pid: self.pid,
            start: self.start,
        }
    }

    /// Parses the address into an `IpAddr`, stripping any scope IDs (e.g. `%en0`).
    #[must_use]
    pub fn parse_ip(&self) -> Option<IpAddr> {
        parse_clean_ip(&self.addr)
    }
}

/// Parsed CIDR subnet for IP range matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub ip: IpAddr,
    pub prefix_len: u8,
}

impl Cidr {
    /// Attempts to parse a CIDR string (e.g. "127.0.0.0/8" or "fe80::/10").
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (ip_str, prefix_str) = s.split_once('/')?;
        let ip: IpAddr = ip_str.parse().ok()?;
        let prefix_len: u8 = prefix_str.parse().ok()?;

        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return None;
        }

        Some(Self { ip, prefix_len })
    }

    /// Checks if a given IP address belongs to this CIDR subnet.
    #[must_use]
    pub fn contains(&self, target: IpAddr) -> bool {
        match (self.ip, target) {
            (IpAddr::V4(net), IpAddr::V4(tgt)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_u32 = u32::from(net);
                let tgt_u32 = u32::from(tgt);
                let mask = !0u32 << (32 - self.prefix_len);
                (net_u32 & mask) == (tgt_u32 & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(tgt)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_u128 = u128::from(net);
                let tgt_u128 = u128::from(tgt);
                let mask = !0u128 << (128 - self.prefix_len);
                (net_u128 & mask) == (tgt_u128 & mask)
            }
            (IpAddr::V6(net), IpAddr::V4(tgt)) => {
                // Check if IPv4-mapped IPv6
                if let Some(v4_mapped) = net.to_ipv4_mapped() {
                    Self {
                        ip: IpAddr::V4(v4_mapped),
                        prefix_len: self.prefix_len.saturating_sub(96).min(32),
                    }
                    .contains(IpAddr::V4(tgt))
                } else {
                    false
                }
            }
            (IpAddr::V4(_), IpAddr::V6(tgt)) => {
                if let Some(v4_tgt) = tgt.to_ipv4_mapped() {
                    self.contains(IpAddr::V4(v4_tgt))
                } else {
                    false
                }
            }
        }
    }
}

/// Identity token used for safe process termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ident {
    pub pid: i32,
    pub start: u64,
}

/// Column sort key in TUI / table output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortKey {
    #[default]
    Port,
    Proto,
    Addr,
    Pid,
    Name,
    Project,
}

impl SortKey {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Proto => "proto",
            Self::Addr => "addr",
            Self::Pid => "pid",
            Self::Name => "process",
            Self::Project => "project",
        }
    }

    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Port => Self::Proto,
            Self::Proto => Self::Addr,
            Self::Addr => Self::Pid,
            Self::Pid => Self::Name,
            Self::Name => Self::Project,
            Self::Project => Self::Port,
        }
    }
}

/// Formats address and port as standard endpoint (e.g. `127.0.0.1:8080` or `[::1]:8080`).
#[must_use]
pub fn endpoint(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    }
}

/// Normalizes raw IP addresses, converting IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`)
/// to clean IPv4 notation.
#[must_use]
pub fn normalize_addr(addr: &str) -> String {
    let clean = addr.trim();
    if clean.is_empty() {
        return "*".to_string();
    }

    // Split scope zone if present (e.g. fe80::1%en0)
    let (ip_part, scope_part) = match clean.split_once('%') {
        Some((ip, scope)) => (ip, Some(scope)),
        None => (clean, None),
    };

    if let Ok(ip) = ip_part.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4.to_string()
                } else if let Some(scope) = scope_part {
                    format!("{v6}%{scope}")
                } else {
                    v6.to_string()
                }
            }
        }
    } else {
        clean.to_string()
    }
}

/// Parses an IP address from string, ignoring any trailing `%scope` zone.
#[must_use]
pub fn parse_clean_ip(addr: &str) -> Option<IpAddr> {
    let clean = addr.trim();
    let ip_str = clean.split('%').next().unwrap_or(clean);
    ip_str.parse().ok()
}

/// Shortens absolute directory paths by replacing the user's `$HOME` with `~`.
#[must_use]
pub fn short_cwd(cwd: &str) -> String {
    if cwd.is_empty() {
        return String::new();
    }
    if let Some(home) = dirs_home() {
        if cwd == home {
            return "~".to_string();
        }
        let prefix = format!("{home}/");
        if let Some(rest) = cwd.strip_prefix(&prefix) {
            return format!("~/{rest}");
        }
    }
    cwd.to_string()
}

/// Infers the project name from working directory path.
#[must_use]
pub fn project_name(cwd: &str) -> String {
    if cwd.is_empty() {
        return String::new();
    }
    let p = Path::new(cwd);
    let name = match p.file_name() {
        Some(os_name) => os_name.to_string_lossy().into_owned(),
        None => String::new(),
    };

    if let Some(home) = dirs_home()
        && (cwd == home || name.is_empty())
    {
        return String::new();
    }

    if name == "/" || name == "\\" {
        return String::new();
    }
    name
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
}
