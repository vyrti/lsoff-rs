use lsoff_rs::filter::filter_query;
use lsoff_rs::model::{Entry, Proto};
use lsoff_rs::services::service_name;

#[test]
fn test_service_name() {
    assert_eq!(service_name(Proto::Tcp, 80), "http");
    assert_eq!(service_name(Proto::Tcp, 443), "https");
    assert_eq!(service_name(Proto::Tcp, 5432), "postgres");
    assert_eq!(service_name(Proto::Tcp, 6379), "redis");
    assert_eq!(service_name(Proto::Tcp, 8888), "jupyter");
    assert_eq!(service_name(Proto::Tcp, 3000), "");
    assert_eq!(service_name(Proto::Udp, 53), "dns");
    assert_eq!(service_name(Proto::Tcp, 9999), "");
}

#[test]
fn test_filter_query_by_service() {
    let entries = vec![
        Entry {
            proto: Proto::Tcp,
            port: 5432,
            addr: "0.0.0.0".to_string(),
            pid: 1,
            name: "postgres".to_string(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
        Entry {
            proto: Proto::Tcp,
            port: 6379,
            addr: "127.0.0.1".to_string(),
            pid: 2,
            name: "redis-server".to_string(),
            path: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            project: String::new(),
            start: 0,
        },
    ];

    let got = filter_query(&entries, "postgres");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].port, 5432);

    let got = filter_query(&entries, "redis");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].port, 6379);

    let got = filter_query(&entries, "sql");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].port, 5432);
}
