use crate::model::{Entry, SortKey};
use std::cmp::Ordering;

/// Orders listeners by port, protocol, address, then PID.
pub fn sort_entries(entries: &mut [Entry]) {
    sort_entries_by(entries, SortKey::Port, false);
}

/// Orders listeners by key with descending option and standard tie-breaking.
pub fn sort_entries_by(entries: &mut [Entry], key: SortKey, desc: bool) {
    entries.sort_by(|a, b| {
        let mut ord = compare_entries(a, b, key);
        if ord == Ordering::Equal {
            ord = a.port.cmp(&b.port);
        }
        if ord == Ordering::Equal {
            ord = a.proto.cmp(&b.proto);
        }
        if ord == Ordering::Equal {
            ord = a.addr.cmp(&b.addr);
        }
        if ord == Ordering::Equal {
            ord = a.pid.cmp(&b.pid);
        }
        if desc { ord.reverse() } else { ord }
    });
}

fn compare_entries(a: &Entry, b: &Entry, key: SortKey) -> Ordering {
    match key {
        SortKey::Proto => a.proto.cmp(&b.proto),
        SortKey::Addr => a.addr.cmp(&b.addr),
        SortKey::Pid => a.pid.cmp(&b.pid),
        SortKey::Name => {
            let a_name = a.name.to_lowercase();
            let b_name = b.name.to_lowercase();
            let ord = a_name.cmp(&b_name);
            if ord != Ordering::Equal {
                return ord;
            }
            let a_cmd = a.cmdline.to_lowercase();
            let b_cmd = b.cmdline.to_lowercase();
            a_cmd.cmp(&b_cmd)
        }
        SortKey::Project => {
            let a_proj = a.project.to_lowercase();
            let b_proj = b.project.to_lowercase();
            a_proj.cmp(&b_proj)
        }
        SortKey::Port => a.port.cmp(&b.port),
    }
}
