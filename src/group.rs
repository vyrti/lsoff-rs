use crate::model::{Entry, SortKey};
use crate::sort::sort_entries_by;
use std::collections::HashMap;

/// Folding state of a row in the TUI view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FoldState {
    #[default]
    None,
    Collapsed,
    Expanded,
    Child,
}

/// A rendered or selectable row in the TUI table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRow {
    pub entry: Entry,
    pub fold: FoldState,
    pub hidden: usize,
}

impl ViewRow {
    /// Persistent identifier across reloads and filters.
    #[must_use]
    pub fn id(&self) -> String {
        if self.fold == FoldState::Child {
            return self.entry.key();
        }
        if self.entry.pid > 0
            && (self.fold == FoldState::Collapsed || self.fold == FoldState::Expanded)
        {
            return format!("p/{}", self.entry.pid);
        }
        self.entry.key()
    }

    /// Tree fold mark (`▸`, `▾`, or ` `).
    #[must_use]
    pub const fn mark(&self) -> &'static str {
        match self.fold {
            FoldState::Collapsed => "▸",
            FoldState::Expanded => "▾",
            FoldState::None | FoldState::Child => " ",
        }
    }
}

struct ProcBucket {
    pid: i32,
    sockets: Vec<Entry>,
}

/// Groups multi-socket processes by PID and flattens them into view rows.
#[must_use]
pub fn flatten_groups(
    entries: &[Entry],
    key: SortKey,
    desc: bool,
    expanded: &HashMap<i32, bool>,
) -> Vec<ViewRow> {
    if entries.is_empty() {
        return Vec::new();
    }

    let mut order = Vec::new();
    let mut by_pid: HashMap<i32, ProcBucket> = HashMap::new();
    let mut zeros = Vec::new();

    for e in entries {
        if e.pid <= 0 {
            zeros.push(e.clone());
            continue;
        }
        if let Some(b) = by_pid.get_mut(&e.pid) {
            b.sockets.push(e.clone());
        } else {
            order.push(e.pid);
            by_pid.insert(
                e.pid,
                ProcBucket {
                    pid: e.pid,
                    sockets: vec![e.clone()],
                },
            );
        }
    }

    let mut groups = Vec::with_capacity(order.len() + zeros.len());
    for pid in order {
        if let Some(mut b) = by_pid.remove(&pid) {
            sort_entries_by(&mut b.sockets, key, desc);
            groups.push(b);
        }
    }
    for e in zeros {
        groups.push(ProcBucket {
            pid: 0,
            sockets: vec![e],
        });
    }

    sort_groups(&mut groups, key, desc);

    let mut out = Vec::with_capacity(entries.len());
    for g in groups {
        if g.sockets.len() == 1 {
            out.push(ViewRow {
                entry: g.sockets[0].clone(),
                fold: FoldState::None,
                hidden: 0,
            });
            continue;
        }

        let is_expanded = expanded.get(&g.pid).copied().unwrap_or(false);
        if is_expanded {
            out.push(ViewRow {
                entry: g.sockets[0].clone(),
                fold: FoldState::Expanded,
                hidden: 0,
            });
            for s in &g.sockets[1..] {
                out.push(ViewRow {
                    entry: s.clone(),
                    fold: FoldState::Child,
                    hidden: 0,
                });
            }
        } else {
            out.push(ViewRow {
                entry: g.sockets[0].clone(),
                fold: FoldState::Collapsed,
                hidden: g.sockets.len() - 1,
            });
        }
    }

    out
}

fn sort_groups(groups: &mut [ProcBucket], key: SortKey, desc: bool) {
    let mut reps: Vec<Entry> = groups.iter().map(|g| g.sockets[0].clone()).collect();
    let mut by_key: HashMap<String, ProcBucket> = HashMap::with_capacity(groups.len());

    for g in groups.iter_mut() {
        let bucket = ProcBucket {
            pid: g.pid,
            sockets: std::mem::take(&mut g.sockets),
        };
        by_key.insert(bucket.sockets[0].key(), bucket);
    }

    sort_entries_by(&mut reps, key, desc);

    for (i, rep) in reps.into_iter().enumerate() {
        if let Some(b) = by_key.remove(&rep.key()) {
            groups[i] = b;
        }
    }
}
