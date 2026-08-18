use lsoff_rs::model::Proto;
use lsoff_rs::sys::list_listeners;
use std::net::{TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

#[test]
fn test_live_finds_tcp_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let port = listener.local_addr().expect("local addr").port();
    let self_pid = std::process::id() as i32;

    let mut found = false;
    for _ in 0..20 {
        let entries = list_listeners().expect("list_listeners");
        for e in entries {
            if e.proto == Proto::Tcp && e.port == port && e.pid == self_pid {
                assert!(
                    !e.name.is_empty() || !e.path.is_empty(),
                    "process name or path empty"
                );
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    assert!(!e.cmdline.is_empty(), "cmdline empty");
                    assert!(!e.cwd.is_empty(), "cwd empty");
                    assert!(!e.project.is_empty(), "project empty");
                }
                #[cfg(target_os = "macos")]
                {
                    assert!(e.start > 0, "start token empty");
                }
                found = true;
                break;
            }
        }
        if found {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    assert!(
        found,
        "did not find live TCP listener on port {port} (pid {self_pid})"
    );
}

#[test]
fn test_live_finds_udp_socket() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let port = socket.local_addr().expect("local addr").port();
    let self_pid = std::process::id() as i32;

    let mut found = false;
    for _ in 0..20 {
        let entries = list_listeners().expect("list_listeners");
        for e in entries {
            if e.proto == Proto::Udp && e.port == port && e.pid == self_pid {
                found = true;
                break;
            }
        }
        if found {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    assert!(
        found,
        "did not find live UDP socket on port {port} (pid {self_pid})"
    );
}
