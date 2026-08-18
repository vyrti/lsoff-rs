use lsoff_rs::filter::{filter_port, filter_proto, filter_query, unique_pids};
use lsoff_rs::model::{Cidr, Entry, Proto};
use std::net::IpAddr;

#[test]
fn test_cidr_matching() {
    let cidr_v4 = Cidr::parse("127.0.0.0/8").unwrap();
    assert!(cidr_v4.contains("127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(cidr_v4.contains("127.255.255.254".parse::<IpAddr>().unwrap()));
    assert!(!cidr_v4.contains("192.168.1.1".parse::<IpAddr>().unwrap()));

    let cidr_v6 = Cidr::parse("fe80::/10").unwrap();
    assert!(cidr_v6.contains("fe80::1".parse::<IpAddr>().unwrap()));
    assert!(cidr_v6.contains("febf::ffff".parse::<IpAddr>().unwrap()));
    assert!(!cidr_v6.contains("2001:db8::1".parse::<IpAddr>().unwrap()));

    let cidr_single = Cidr::parse("::1/128").unwrap();
    assert!(cidr_single.contains("::1".parse::<IpAddr>().unwrap()));
    assert!(!cidr_single.contains("::2".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_filter_query_cidr() {
    let entries = vec![
        Entry {
            proto: Proto::Tcp,
            port: 8080,
            addr: "127.0.0.1".to_string(),
            pid: 100,
            name: "web".to_string(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 9000,
            addr: "192.168.1.50".to_string(),
            pid: 101,
            name: "api".to_string(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Udp,
            port: 5353,
            addr: "fe80::1%en0".to_string(),
            pid: 102,
            name: "mdns".to_string(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
    ];

    let v4_match = filter_query(&entries, "127.0.0.0/8");
    assert_eq!(v4_match.len(), 1);
    assert_eq!(v4_match[0].name, "web");

    let v6_match = filter_query(&entries, "fe80::/10");
    assert_eq!(v6_match.len(), 1);
    assert_eq!(v6_match[0].name, "mdns");

    let no_match = filter_query(&entries, "10.0.0.0/8");
    assert_eq!(no_match.len(), 0);
}

#[test]
fn test_filter_port() {
    let entries = vec![
        Entry {
            proto: Proto::Tcp,
            port: 80,
            addr: "0.0.0.0".to_string(),
            pid: 1,
            name: "nginx".to_string(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 443,
            addr: "0.0.0.0".to_string(),
            pid: 1,
            name: "nginx".to_string(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Udp,
            port: 80,
            addr: "127.0.0.1".to_string(),
            pid: 2,
            name: "app".to_string(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
    ];

    let got = filter_port(&entries, 80);
    assert_eq!(got.len(), 2);
}

#[test]
fn test_filter_proto() {
    let entries = vec![
        Entry {
            proto: Proto::Tcp,
            port: 80,
            addr: String::new(),
            pid: 0,
            name: String::new(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Udp,
            port: 53,
            addr: String::new(),
            pid: 0,
            name: String::new(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 443,
            addr: String::new(),
            pid: 0,
            name: String::new(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
    ];

    let tcp = filter_proto(&entries, true, false);
    assert_eq!(tcp.len(), 2);
    assert_eq!(tcp[0].proto, Proto::Tcp);
    assert_eq!(tcp[1].proto, Proto::Tcp);

    let udp = filter_proto(&entries, false, true);
    assert_eq!(udp.len(), 1);
    assert_eq!(udp[0].proto, Proto::Udp);

    let all = filter_proto(&entries, false, false);
    assert_eq!(all.len(), 3);
}

#[test]
fn test_unique_pids() {
    let entries = vec![
        Entry {
            proto: Proto::Tcp,
            port: 80,
            addr: String::new(),
            pid: 10,
            name: String::new(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 81,
            addr: String::new(),
            pid: 0,
            name: String::new(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 82,
            addr: String::new(),
            pid: 10,
            name: String::new(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 83,
            addr: String::new(),
            pid: 11,
            name: String::new(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
    ];

    let pids = unique_pids(&entries);
    assert_eq!(pids, vec![10, 11]);
}

#[test]
fn test_filter_query() {
    let mut entries = vec![
        Entry {
            proto: Proto::Tcp,
            port: 8080,
            addr: "127.0.0.1".to_string(),
            pid: 99,
            name: "node".to_string(),
            path: "/usr/bin/node".to_string(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Udp,
            port: 53,
            addr: "::".to_string(),
            pid: 12,
            name: "named".to_string(),
            path: "/usr/sbin/named".to_string(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
    ];

    let got = filter_query(&entries, "8080");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "node");

    let got = filter_query(&entries, "NAMED");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].port, 53);

    let got = filter_query(&entries, "node 8080");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "node");

    let got = filter_query(&entries, "node named");
    assert_eq!(got.len(), 0);

    entries[0].cmdline = "/usr/bin/node server.js".to_string();
    let got = filter_query(&entries, "server.js");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "node");

    entries[0].project = "lsoff".to_string();
    entries[0].cwd = "/Users/me/lsoff".to_string();
    let got = filter_query(&entries, "lsoff");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "node");
}
