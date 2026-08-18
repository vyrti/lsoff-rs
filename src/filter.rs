use crate::model::{Cidr, Entry, Ident, Proto};
use crate::services::search_terms;
use std::collections::HashSet;

/// Filters entries by protocol.
#[must_use]
pub fn filter_proto(entries: &[Entry], tcp: bool, udp: bool) -> Vec<Entry> {
    if tcp && !udp {
        entries
            .iter()
            .filter(|e| e.proto == Proto::Tcp)
            .cloned()
            .collect()
    } else if udp && !tcp {
        entries
            .iter()
            .filter(|e| e.proto == Proto::Udp)
            .cloned()
            .collect()
    } else {
        entries.to_vec()
    }
}

/// Filters entries by port.
#[must_use]
pub fn filter_port(entries: &[Entry], port: u16) -> Vec<Entry> {
    entries.iter().filter(|e| e.port == port).cloned().collect()
}

/// Filters entries by query.
///
/// Supports:
/// - Exact and substring port matching (e.g., `8080`)
/// - Subnet CIDR matching (e.g., `127.0.0.0/8`, `192.168.1.0/24`, `fe80::/10`, `::1/128`)
/// - Process name, project name, path, command line, working directory, and service aliases
/// - Multi-word AND matching (all space-separated terms must match)
#[must_use]
pub fn filter_query(entries: &[Entry], query: &str) -> Vec<Entry> {
    let terms: Vec<String> = query.split_whitespace().map(|s| s.to_lowercase()).collect();

    if terms.is_empty() {
        return entries.to_vec();
    }

    entries
        .iter()
        .filter(|e| match_entry(e, &terms))
        .cloned()
        .collect()
}

fn match_entry(e: &Entry, terms: &[String]) -> bool {
    let pid_str = if e.pid > 0 {
        e.pid.to_string()
    } else {
        String::new()
    };
    let port_str = e.port.to_string();
    let name_low = e.name.to_lowercase();
    let proj_low = e.project.to_lowercase();
    let path_low = e.path.to_lowercase();
    let cmd_low = e.cmdline.to_lowercase();
    let cwd_low = e.cwd.to_lowercase();
    let addr_low = e.addr.to_lowercase();
    let aliases = search_terms(e.proto, e.port);
    let entry_ip = e.parse_ip();

    for term in terms {
        // 1. Check if term is a CIDR subnet (e.g., "127.0.0.0/8", "fe80::/10")
        if let Some(cidr) = Cidr::parse(term) {
            if let Some(ip) = entry_ip
                && cidr.contains(ip)
            {
                continue;
            }
            return false;
        }

        // 2. Standard field substring matches
        let matched = port_str.contains(term)
            || (!pid_str.is_empty() && pid_str.contains(term))
            || name_low.contains(term)
            || proj_low.contains(term)
            || path_low.contains(term)
            || cmd_low.contains(term)
            || cwd_low.contains(term)
            || addr_low.contains(term)
            || aliases.iter().any(|a| a.contains(term));

        if !matched {
            return false;
        }
    }

    true
}

/// Collects distinct positive process IDs in encounter order.
#[must_use]
pub fn unique_pids(entries: &[Entry]) -> Vec<i32> {
    let mut seen = HashSet::new();
    let mut pids = Vec::new();
    for e in entries {
        if e.pid > 0 && seen.insert(e.pid) {
            pids.push(e.pid);
        }
    }
    pids
}

/// Collects distinct process identifiers (`pid` + `start` token) for safe termination.
#[must_use]
pub fn unique_idents(entries: &[Entry]) -> Vec<Ident> {
    let mut seen = HashSet::new();
    let mut idents = Vec::new();
    for e in entries {
        if e.pid > 0 && seen.insert(e.pid) {
            idents.push(Ident {
                pid: e.pid,
                start: e.start,
            });
        }
    }
    idents
}
