use lsoff_rs::format::format_table;
use lsoff_rs::model::{Entry, Proto};
use lsoff_rs::sanitize::sanitize_display;

#[test]
fn test_sanitize_display() {
    assert_eq!(sanitize_display("hello"), "hello");
    assert_eq!(sanitize_display("hello\x1b[31mworld\x1b[0m"), "helloworld");
    assert_eq!(sanitize_display("hello\x07world\t!"), "hello world !");
    assert_eq!(sanitize_display(""), "");
}

#[test]
fn test_table_strips_ansi() {
    let entries = vec![Entry {
        proto: Proto::Tcp,
        port: 8080,
        addr: "127.0.0.1".to_string(),
        pid: 10,
        name: "malicious\x1b[31m\x1b[2J".to_string(),
        path: "/bin/test".to_string(),
        cmdline: "test --arg\x07".to_string(),
        cwd: "/".to_string(),
        project: String::new(),
        start: 0,
    }];

    let mut buf = Vec::new();
    format_table(&mut buf, &entries).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(!s.contains("\x1b["));
    assert!(!s.contains('\x07'));
    assert!(s.contains("malicious"));
}

#[test]
fn test_sanitize_json_keeps_raw_cmdline() {
    let entries = vec![Entry {
        proto: Proto::Tcp,
        port: 8080,
        addr: "127.0.0.1".to_string(),
        pid: 10,
        name: "test".to_string(),
        path: "/bin/test".to_string(),
        cmdline: "test --arg=\"hello world\"".to_string(),
        cwd: "/".to_string(),
        project: String::new(),
        start: 0,
    }];

    let mut buf = Vec::new();
    lsoff_rs::format::format_json(&mut buf, &entries).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("test --arg=\\\"hello world\\\""));
}
