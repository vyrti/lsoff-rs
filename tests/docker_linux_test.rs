use std::process::Command;

fn is_docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn test_docker_linux_execution() {
    if !is_docker_available() {
        println!(
            "Docker is not available or daemon is not running; skipping Linux container test."
        );
        return;
    }

    println!("Docker is available! Running full Linux verification inside Docker container...");

    let workspace_dir = std::env::current_dir().expect("current dir");
    let workspace_str = workspace_dir.to_str().expect("workspace path str");

    // Run cargo test inside Linux container with an isolated target directory in /tmp
    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{workspace_str}:/app"),
            "-w",
            "/app",
            "rust:1.97-bookworm",
            "sh",
            "-c",
            "cargo test --target-dir /tmp/target_linux --test cli_test --test filter_test --test format_test --test group_test --test sanitize_test --test services_test && cargo build --release --target-dir /tmp/target_linux && /tmp/target_linux/release/lsoff-rs --help && /tmp/target_linux/release/lsoff-rs --version",
        ])
        .status()
        .expect("failed to execute docker run");

    assert!(status.success(), "Linux Docker test and build failed");
}

#[test]
fn test_docker_linux_live_socket_discovery() {
    if !is_docker_available() {
        println!("Docker is not available; skipping live Linux socket discovery test.");
        return;
    }

    let workspace_dir = std::env::current_dir().expect("current dir");
    let workspace_str = workspace_dir.to_str().expect("workspace path str");

    // Run a script inside Linux that spawns a real background TCP listener and verifies lsoff discovery
    let script = r#"
set -e
cargo build --release --target-dir /tmp/target_linux

# Start a background listener on port 9876
python3 -m http.server 9876 &
SERVER_PID=$!
sleep 1

echo "Testing Linux socket discovery for port 9876..."
OUTPUT=$(/tmp/target_linux/release/lsoff-rs 9876)
echo "$OUTPUT"

# Verify table output contains port 9876 and python
echo "$OUTPUT" | grep "9876"
echo "$OUTPUT" | grep -i "python"

# Verify JSON output contains port 9876
JSON_OUTPUT=$(/tmp/target_linux/release/lsoff-rs --json 9876)
echo "$JSON_OUTPUT"
echo "$JSON_OUTPUT" | grep '"port": 9876'

kill $SERVER_PID || true
echo "Linux socket discovery verified successfully!"
"#;

    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{workspace_str}:/app"),
            "-w",
            "/app",
            "rust:1.97-bookworm",
            "sh",
            "-c",
            script,
        ])
        .status()
        .expect("failed to execute docker run live listener test");

    assert!(
        status.success(),
        "Linux live socket discovery inside Docker failed"
    );
}
