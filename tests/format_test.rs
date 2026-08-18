use lsoff_rs::format::{format_json, format_table};
use lsoff_rs::model::{Entry, Proto, endpoint, normalize_addr, project_name};
use lsoff_rs::sort::sort_entries;

#[test]
fn test_endpoint() {
    assert_eq!(endpoint("127.0.0.1", 80), "127.0.0.1:80");
    assert_eq!(endpoint("::", 8080), "[::]:8080");
    assert_eq!(endpoint("::1", 3000), "[::1]:3000");
}

#[test]
fn test_normalize_addr() {
    assert_eq!(normalize_addr(""), "*");
    assert_eq!(normalize_addr("0.0.0.0"), "0.0.0.0");
    assert_eq!(normalize_addr("::"), "::");
    assert_eq!(normalize_addr("::ffff:127.0.0.1"), "127.0.0.1");
}

#[test]
fn test_project_name() {
    assert_eq!(project_name("/Users/alex/projects/lsoff"), "lsoff");
    assert_eq!(project_name("/"), "");
}

#[test]
fn test_sort_and_format_table() {
    let mut entries = vec![
        Entry {
            proto: Proto::Tcp,
            port: 8080,
            addr: "127.0.0.1".to_string(),
            pid: 200,
            name: "node".to_string(),
            path: "/bin/node".to_string(),
            cmdline: "node app.js".to_string(),
            cwd: "/app".to_string(),
            project: "app".to_string(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 80,
            addr: "0.0.0.0".to_string(),
            pid: 100,
            name: "nginx".to_string(),
            path: "/bin/nginx".to_string(),
            cmdline: "nginx -g".to_string(),
            cwd: "/".to_string(),
            project: String::new(),
            start: 0,
        },
    ];

    sort_entries(&mut entries);
    assert_eq!(entries[0].port, 80);
    assert_eq!(entries[1].port, 8080);

    let mut buf = Vec::new();
    format_table(&mut buf, &entries).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("PROTO"));
    assert!(s.contains("nginx"));
    assert!(s.contains("node"));
}

#[test]
fn test_format_json_shape() {
    let entries = vec![Entry {
        proto: Proto::Tcp,
        port: 80,
        addr: "0.0.0.0".to_string(),
        pid: 1,
        name: "nginx".to_string(),
        path: "/usr/sbin/nginx".to_string(),
        cmdline: "nginx".to_string(),
        cwd: "/".to_string(),
        project: String::new(),
        start: 0,
    }];

    let mut buf = Vec::new();
    format_json(&mut buf, &entries).unwrap();
    let s = String::from_utf8(buf).unwrap();

    let json: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert!(json.is_array());
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["proto"], "tcp");
    assert_eq!(arr[0]["port"], 80);
    assert_eq!(arr[0]["service"], "http");
}

#[test]
fn test_format_json_empty() {
    let mut buf = Vec::new();
    format_json(&mut buf, &[]).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert_eq!(s.trim(), "[]");
}
