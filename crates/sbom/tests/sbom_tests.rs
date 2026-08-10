use policy::GuardPolicy;
use sbom::{generate_sbom, SbomFormat};
use scanner::{Finding, FindingKind, ScanReport, Severity};
use std::path::PathBuf;

#[test]
fn test_generate_cyclonedx_sbom() {
    let mut report = ScanReport::new();
    report.findings.push(Finding {
        file: PathBuf::from("build.rs"),
        line: Some(10),
        severity: Severity::Critical,
        kind: FindingKind::NetworkAccess,
        message: "Network call detected".to_string(),
        snippet: Some("TcpStream::connect".to_string()),
    });

    let policy = GuardPolicy::default();
    let json_res = generate_sbom(&report, &policy, SbomFormat::CycloneDx);

    assert!(json_res.is_ok());
    let json_str = json_res.unwrap();
    assert!(json_str.contains("CycloneDX"));
    assert!(json_str.contains("1.4"));
    assert!(json_str.contains("build.rs"));
    assert!(json_str.contains("CRITICAL"));
}

#[test]
fn test_generate_spdx_sbom() {
    let mut report = ScanReport::new();
    report.findings.push(Finding {
        file: PathBuf::from("package.json"),
        line: None,
        severity: Severity::Warn,
        kind: FindingKind::SuspiciousCommand,
        message: "curl detected in postinstall".to_string(),
        snippet: Some("curl http://example.com".to_string()),
    });

    let policy = GuardPolicy::default();
    let json_res = generate_sbom(&report, &policy, SbomFormat::Spdx);

    assert!(json_res.is_ok());
    let json_str = json_res.unwrap();
    assert!(json_str.contains("SPDX-2.3"));
    assert!(json_str.contains("package.json"));
    assert!(json_str.contains("WARN"));
}
