use scanner::{scan_package_json, scan_project, scan_rust_file, FindingKind};

use std::path::PathBuf;

#[test]
fn test_malicious_build_rs_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("malicious_build.rs");
    let content = std::fs::read_to_string(&fixture_path).expect("Read fixture");

    let report = scan_rust_file(&fixture_path, &content);

    assert!(report.has_critical(), "Malicious build.rs should trigger CRITICAL findings");
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::SensitiveEnvAccess),
        "Should detect GITHUB_TOKEN or AWS key access"
    );
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::CommandExecution),
        "Should detect Command::new('curl')"
    );
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::NetworkAccess),
        "Should detect TcpStream::connect"
    );
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::SensitiveFileRead),
        "Should detect .ssh/id_rsa read"
    );
}

#[test]
fn test_benign_build_rs_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("benign_build.rs");
    let content = std::fs::read_to_string(&fixture_path).expect("Read fixture");

    let report = scan_rust_file(&fixture_path, &content);

    assert!(!report.has_critical(), "Benign build.rs must NOT trigger CRITICAL findings");
    assert!(!report.has_warnings(), "Benign build.rs must NOT trigger WARN findings");
}

#[test]
fn test_malicious_package_json_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("malicious_pkg.json");
    let content = std::fs::read_to_string(&fixture_path).expect("Read fixture");

    let report = scan_package_json(&fixture_path, &content);

    assert!(report.has_critical(), "Malicious package.json should trigger CRITICAL findings");
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::SuspiciousCommand),
        "Should detect curl in preinstall"
    );
    assert!(
        report.findings.iter().any(|f| f.kind == FindingKind::EncodedPayload),
        "Should detect base64 payload"
    );
}


#[test]
fn test_benign_package_json_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("benign_package.json");
    let content = std::fs::read_to_string(&fixture_path).expect("Read fixture");

    let report = scan_package_json(&fixture_path, &content);

    assert!(!report.has_critical(), "Benign package.json must NOT trigger CRITICAL findings");
    assert!(!report.has_warnings(), "Benign package.json must NOT trigger WARN findings");
}

#[test]
fn test_directory_scan_fixtures() {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");

    let report = scan_project(&fixtures_dir).expect("Directory scan should succeed");
    println!("Scanned files count: {}", report.files_scanned);

    assert!(report.files_scanned > 0, "Should scan fixture files");
    assert!(report.has_critical(), "Fixture directory scan should report CRITICAL findings");
}


