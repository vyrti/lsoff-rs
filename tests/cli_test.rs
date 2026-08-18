use lsoff_rs::cli::{Config, parse_args};
use lsoff_rs::run;
use std::io::Cursor;

#[test]
fn test_parse_args_empty() {
    let cfg = parse_args(Vec::<&str>::new()).unwrap();
    assert_eq!(cfg, Config::default());
}

#[test]
fn test_parse_args_port_and_flags() {
    let cfg = parse_args(["-t", "--json", "8080"]).unwrap();
    assert_eq!(cfg.port, Some(8080));
    assert!(cfg.tcp);
    assert!(!cfg.udp);
    assert!(cfg.json);
}

#[test]
fn test_parse_args_kill() {
    let cfg = parse_args(["-k", "-y", "80"]).unwrap();
    assert!(cfg.kill);
    assert!(cfg.yes);
    assert_eq!(cfg.port, Some(80));

    assert!(parse_args(["-k"]).is_err());
    assert!(parse_args(["-k", "--json", "80"]).is_err());
    assert!(parse_args(["-y"]).is_err());
}

#[test]
fn test_parse_args_invalid() {
    assert!(parse_args(["8080", "80"]).is_err());
    assert!(parse_args(["--nope"]).is_err());
}

#[test]
fn test_parse_args_query() {
    let cfg = parse_args(["nginx"]).unwrap();
    assert_eq!(cfg.query, "nginx");
    assert_eq!(cfg.port, None);

    let cfg = parse_args(["-q", "node 8080", "-t"]).unwrap();
    assert_eq!(cfg.query, "node 8080");
    assert!(cfg.tcp);

    let cfg = parse_args(["--query=Chrome"]).unwrap();
    assert_eq!(cfg.query, "Chrome");
}

#[test]
fn test_run_help_version() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let res = run(&["-h".to_string()], Cursor::new(b""), &mut out, &mut err);
    assert!(res.is_ok());
    let out_str = String::from_utf8(out).unwrap();
    assert!(out_str.contains("Usage:"));

    let mut out = Vec::new();
    let mut err = Vec::new();
    let res = run(&["-v".to_string()], Cursor::new(b""), &mut out, &mut err);
    assert!(res.is_ok());
    let out_str = String::from_utf8(out).unwrap();
    assert!(out_str.contains("lsoff-rs "));
}
