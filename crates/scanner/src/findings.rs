//! Finding types and severity levels for scanner results.
//!
//! Every detected suspicious pattern produces a [`Finding`] with a severity level,
//! a human-readable description, and the source location where it was found.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Severity level for a scanner finding.
///
/// - `Info`: General observation (e.g., environment variable access for non-sensitive keys).
/// - `Warn`: Potentially dangerous pattern (e.g., process spawning, filesystem reads).
/// - `Critical`: High-confidence malicious pattern (e.g., network call + credential access,
///   exfiltration of SSH keys, encoded payloads).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warn => write!(f, "WARN"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// The kind of suspicious pattern detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// `std::process::Command::new()` — subprocess spawning
    CommandExecution,
    /// `std::net::TcpStream::connect()` or `UdpSocket::bind()` — network access
    NetworkAccess,
    /// `std::env::var()` accessing sensitive keys (tokens, secrets, passwords)
    SensitiveEnvAccess,
    /// `std::env::var()` or `std::env::vars()` — general environment access
    EnvironmentAccess,
    /// `std::fs::read()` targeting sensitive paths (~/.ssh, ~/.aws, .env)
    SensitiveFileRead,
    /// Shell metacharacters in package.json scripts (; && | $() ` \)
    ShellMetacharacters,
    /// Suspicious commands in package.json (curl, wget, nc, bash -c, eval)
    SuspiciousCommand,
    /// Encoded/obfuscated payload (base64, hex-encoded strings)
    EncodedPayload,
    /// Lifecycle hook present in package.json (preinstall, postinstall, etc.)
    LifecycleHook,
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingKind::CommandExecution => write!(f, "Command Execution"),
            FindingKind::NetworkAccess => write!(f, "Network Access"),
            FindingKind::SensitiveEnvAccess => write!(f, "Sensitive Env Access"),
            FindingKind::EnvironmentAccess => write!(f, "Environment Access"),
            FindingKind::SensitiveFileRead => write!(f, "Sensitive File Read"),
            FindingKind::ShellMetacharacters => write!(f, "Shell Metacharacters"),
            FindingKind::SuspiciousCommand => write!(f, "Suspicious Command"),
            FindingKind::EncodedPayload => write!(f, "Encoded Payload"),
            FindingKind::LifecycleHook => write!(f, "Lifecycle Hook"),
        }
    }
}

/// A single scanner finding — one detected suspicious pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The file where the pattern was found.
    pub file: PathBuf,
    /// Line number (1-indexed) where the pattern was found, if available.
    pub line: Option<usize>,
    /// Severity level.
    pub severity: Severity,
    /// The kind of suspicious pattern.
    pub kind: FindingKind,
    /// Human-readable description of the finding.
    pub message: String,
    /// The code snippet or value that triggered the finding, if available.
    pub snippet: Option<String>,
}

impl Finding {
    /// Create a new finding.
    pub fn new(
        file: PathBuf,
        line: Option<usize>,
        severity: Severity,
        kind: FindingKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            file,
            line,
            severity,
            kind,
            message: message.into(),
            snippet: None,
        }
    }

    /// Attach a code snippet to this finding.
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.kind, self.message)?;
        if let Some(line) = self.line {
            write!(f, " ({}:{})", self.file.display(), line)?;
        } else {
            write!(f, " ({})", self.file.display())?;
        }
        Ok(())
    }
}

/// Summary of a scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// All findings from the scan.
    pub findings: Vec<Finding>,
    /// Number of files scanned.
    pub files_scanned: usize,
}

impl ScanReport {
    /// Create a new empty report.
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            files_scanned: 0,
        }
    }

    /// Whether any CRITICAL findings were found.
    pub fn has_critical(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Critical)
    }

    /// Whether any WARN or CRITICAL findings were found.
    pub fn has_warnings(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity >= Severity::Warn)
    }

    /// Count findings by severity.
    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }

    /// Merge another report into this one.
    pub fn merge(&mut self, other: ScanReport) {
        self.findings.extend(other.findings);
        self.files_scanned += other.files_scanned;
    }
}

impl Default for ScanReport {
    fn default() -> Self {
        Self::new()
    }
}
