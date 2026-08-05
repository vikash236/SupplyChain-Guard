//! # Scanner
//!
//! Static analysis engine for detecting suspicious patterns in build scripts.
//!
//! Provides two scanners:
//! - **Rust scanner**: Uses `syn` AST visitor to analyze `build.rs` files for
//!   dangerous API calls (process spawning, network access, credential reads).
//! - **Node.js scanner**: Parses `package.json` lifecycle hooks for shell injection,
//!   exfiltration commands, and obfuscated payloads.
//!
//! The scanner **never** executes or compiles the code it analyzes — AST parsing only.

pub mod findings;
pub mod node_scanner;
pub mod rust_scanner;
pub mod project_scanner;
pub mod sarif;
pub mod cache;

pub use findings::{Finding, FindingKind, ScanReport, Severity};

pub use node_scanner::scan_package_json;
pub use rust_scanner::scan_rust_file;
pub use project_scanner::scan_project;
pub use sarif::report_to_sarif;
pub use cache::{compute_file_sha256, BuildCache};


/// Apply policy rule filters and severity overrides to a `ScanReport`.
pub fn apply_policy_to_report(report: &mut ScanReport, policy: &policy::GuardPolicy) {
    report.findings.retain(|finding| {
        let kind_str = finding.kind.to_string();
        if policy.is_rule_ignored(&kind_str) {
            return false;
        }
        if policy.is_path_ignored(&finding.file) {
            return false;
        }
        true
    });

    for finding in &mut report.findings {
        let kind_str = finding.kind.to_string();
        if let Some(override_str) = policy.get_severity_override(&kind_str) {
            match override_str.to_uppercase().as_str() {
                "CRITICAL" => finding.severity = Severity::Critical,
                "WARN" | "WARNING" => finding.severity = Severity::Warn,
                "INFO" => finding.severity = Severity::Info,
                _ => {}
            }
        }
    }
}

