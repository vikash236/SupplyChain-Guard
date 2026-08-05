//! # Policy Engine
//!
//! Declarative configuration and security policy parser for SupplyChain-Guard (`guard.toml`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Root configuration schema for `guard.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GuardPolicy {
    #[serde(default)]
    pub scanner: ScannerPolicy,
    #[serde(default)]
    pub sandbox: SandboxPolicy,
    #[serde(default)]
    pub rules: RulePolicy,
}

/// Scanner rules and path exclusions policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ScannerPolicy {
    /// List of finding kinds to ignore (e.g. `["Command Execution", "Sensitive File Read"]`).
    #[serde(default)]
    pub ignored_rules: Vec<String>,

    /// List of paths/globs to exclude from scanning.
    #[serde(default)]
    pub ignored_paths: Vec<PathBuf>,

    /// Override severity for specific finding kinds (e.g. `{"Command Execution": "INFO"}`).
    #[serde(default)]
    pub severity_overrides: HashMap<String, String>,
}

/// Sandbox runtime environment and resource constraints policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Permit outbound network connections inside sandbox (default: false).
    #[serde(default)]
    pub allow_network: bool,

    /// Additional environment variables allowed into sandbox container.
    #[serde(default)]
    pub env_allowlist: Vec<String>,

    /// Additional environment variable keys explicitly blocked from sandbox container.
    #[serde(default)]
    pub env_denylist: Vec<String>,

    /// Maximum process memory limit in megabytes (e.g. 512 MB).
    pub memory_limit_mb: Option<u64>,

    /// Allowed directory paths for write access (defaults to target directory).
    #[serde(default)]
    pub allowed_write_paths: Vec<PathBuf>,
}

/// High-level enforcement rules policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulePolicy {
    /// Disallow obfuscated/base64 script payloads (default: true).
    #[serde(default = "default_true")]
    pub block_obfuscated_code: bool,

    /// Disallow subprocess spawns in build scripts (default: false).
    #[serde(default)]
    pub block_subprocesses: bool,

    /// Disallow outbound network connections in build scripts (default: true).
    #[serde(default = "default_true")]
    pub block_network_calls: bool,
}

impl Default for RulePolicy {
    fn default() -> Self {
        Self {
            block_obfuscated_code: true,
            block_subprocesses: false,
            block_network_calls: true,
        }
    }
}

fn default_true() -> bool {
    true
}

impl GuardPolicy {
    /// Load policy configuration from specified file path.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref)
            .map_err(|e| format!("Failed to read policy configuration file '{}': {}", path_ref.display(), e))?;

        toml::from_str::<Self>(&content)
            .map_err(|e| format!("Failed to parse policy TOML configuration '{}': {}", path_ref.display(), e))
    }

    /// Load policy configuration from explicit path, or auto-detect `guard.toml` in CWD, or fallback to default.
    pub fn load_or_default<P: AsRef<Path>>(explicit_path: Option<P>) -> Result<Self, String> {
        if let Some(p) = explicit_path {
            Self::load_from_file(p)
        } else {
            let default_file = Path::new("guard.toml");
            if default_file.exists() {
                Self::load_from_file(default_file)
            } else {
                Ok(Self::default())
            }
        }
    }

    /// Check if a scanner finding kind is explicitly ignored by policy.
    pub fn is_rule_ignored(&self, finding_kind: &str) -> bool {
        self.scanner
            .ignored_rules
            .iter()
            .any(|rule| rule.eq_ignore_ascii_case(finding_kind))
    }

    /// Check if a file path is explicitly excluded by policy.
    pub fn is_path_ignored<P: AsRef<Path>>(&self, file_path: P) -> bool {
        let path = file_path.as_ref();
        self.scanner.ignored_paths.iter().any(|ignored| {
            path.ends_with(ignored) || path == ignored
        })
    }

    /// Get severity override string for a finding kind if configured.
    pub fn get_severity_override(&self, finding_kind: &str) -> Option<&str> {
        self.scanner
            .severity_overrides
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(finding_kind))
            .map(|(_, v)| v.as_str())
    }
}
