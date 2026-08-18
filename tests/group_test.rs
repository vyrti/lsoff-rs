use lsoff_rs::group::{FoldState, flatten_groups};
use lsoff_rs::model::{Entry, Proto, SortKey};
use std::collections::HashMap;

#[test]
fn test_flatten_groups_collapses_same_pid() {
    let entries = vec![
        Entry {
            proto: Proto::Tcp,
            port: 80,
            addr: "0.0.0.0".to_string(),
            pid: 1,
            name: "nginx".to_string(),
            path: "/bin/nginx".to_string(),
            cmdline: "nginx".to_string(),
            cwd: "/".to_string(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 443,
            addr: "0.0.0.0".to_string(),
            pid: 1,
            name: "nginx".to_string(),
            path: "/bin/nginx".to_string(),
            cmdline: "nginx".to_string(),
            cwd: "/".to_string(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 8080,
            addr: "127.0.0.1".to_string(),
            pid: 2,
            name: "node".to_string(),
            path: "/bin/node".to_string(),
            cmdline: "node".to_string(),
            cwd: "/app".to_string(),
            project: "app".to_string(),
            start: 0,
        },
    ];

    let mut exp_map = HashMap::new();
    let rows = flatten_groups(&entries, SortKey::Port, false, &exp_map);

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].entry.pid, 1);
    assert_eq!(rows[0].fold, FoldState::Collapsed);
    assert_eq!(rows[0].hidden, 1);
    assert_eq!(rows[1].entry.pid, 2);
    assert_eq!(rows[1].fold, FoldState::None);
    assert_eq!(rows[1].hidden, 0);

    // Expand PID 1
    exp_map.insert(1, true);
    let rows = flatten_groups(&entries, SortKey::Port, false, &exp_map);
    assert_eq!(rows.len(), 3);

    let has_exp = rows
        .iter()
        .any(|r| r.entry.pid == 1 && r.fold == FoldState::Expanded);
    let has_child = rows
        .iter()
        .any(|r| r.entry.pid == 1 && r.fold == FoldState::Child);
    let has_leaf = rows
        .iter()
        .any(|r| r.entry.pid == 2 && r.fold == FoldState::None);

    assert!(has_exp);
    assert!(has_child);
    assert!(has_leaf);
}
