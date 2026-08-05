//! # Sandbox
//!
//! OS-native process isolation engine for build script execution.
//!
//! - **Windows**: Job Objects + AppContainer
//! - **Linux**: `unshare` namespaces + `seccomp-bpf`

pub mod win;
pub mod linux;

use std::collections::HashSet;

/// Configuration options for launching a sandboxed process.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Path to the target build directory (writes restricted to this directory).
    pub target_dir: std::path::PathBuf,
    /// Allow network access (default: false / deny).
    pub allow_network: bool,
    /// Environment variables explicitly allowed to pass into the sandbox.
    pub env_allowlist: Vec<String>,
    /// Environment variables explicitly blocked from passing into the sandbox.
    pub env_denylist: Vec<String>,
    /// Process memory limit in megabytes (optional).
    pub memory_limit_mb: Option<u64>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            target_dir: std::path::PathBuf::from("./target"),
            allow_network: false,
            env_allowlist: vec![
                "PATH".to_string(),
                "HOME".to_string(),
                "USERPROFILE".to_string(),
                "SYSTEMROOT".to_string(),
                "CARGO_HOME".to_string(),
                "RUSTUP_HOME".to_string(),
                "TEMP".to_string(),
                "TMP".to_string(),
                "COMSPEC".to_string(),
                "PATHEXT".to_string(),
                "TERM".to_string(),
                "LANG".to_string(),
                "LC_ALL".to_string(),
                "SHELL".to_string(),
                "PWD".to_string(),
                "NUMBER_OF_PROCESSORS".to_string(),
                "OS".to_string(),
                "PROCESSOR_ARCHITECTURE".to_string(),
            ],
            env_denylist: Vec::new(),
            memory_limit_mb: None,
        }
    }
}

impl SandboxConfig {
    /// Build `SandboxConfig` from a loaded `GuardPolicy`.
    pub fn from_policy(policy: &policy::GuardPolicy) -> Self {
        let mut config = Self::default();
        config.allow_network = policy.sandbox.allow_network;

        for env_item in &policy.sandbox.env_allowlist {
            if !config.env_allowlist.contains(env_item) {
                config.env_allowlist.push(env_item.clone());
            }
        }

        config.env_denylist = policy.sandbox.env_denylist.clone();
        config.memory_limit_mb = policy.sandbox.memory_limit_mb;

        if let Some(first_path) = policy.sandbox.allowed_write_paths.first() {
            config.target_dir = first_path.clone();
        }

        config
    }
}

/// List of sensitive environment variable patterns that are stripped by default.
pub const SENSITIVE_ENV_PREFIXES: &[&str] = &[
    "AWS_",
    "GITHUB_",
    "SLACK_",
    "DATABASE_",
    "DB_",
    "SSH_",
    "DOCKER_",
    "KUBECONFIG",
    "NPM_",
    "PYPI_",
    "STRIPE_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "VERCEL_",
    "NETLIFY_",
    "HEROKU_",
    "OPENAI_",
    "ANTHROPIC_",
    "SENTRY_",
    "DATADOG_",
];

pub const SENSITIVE_ENV_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_KEY",
    "_SECRET",
    "_PASSWORD",
    "_PASS",
    "_CREDENTIALS",
    "_AUTH",
    "_PRIVATE_KEY",
    "_API_KEY",
];

pub const SENSITIVE_EXACT_NAMES: &[&str] = &[
    "ID_RSA",
    "SECRET",
    "PASSWORD",
    "TOKEN",
    "PRIVATE_KEY",
    "BEARER_TOKEN",
    "AUTH_HEADER",
];

/// Filter environment variables according to security policy and `SandboxConfig`.
pub fn sanitize_env<I>(raw_env: I, config: &SandboxConfig) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let allowlist: HashSet<String> = config
        .env_allowlist
        .iter()
        .map(|s| s.to_uppercase())
        .collect();

    let denylist: HashSet<String> = config
        .env_denylist
        .iter()
        .map(|s| s.to_uppercase())
        .collect();

    raw_env
        .into_iter()
        .filter(|(key, _val)| {
            let upper_key = key.to_uppercase();

            // Explicitly denylisted keys are always stripped
            if denylist.contains(&upper_key) {
                return false;
            }

            // Explicitly allowed variables are preserved
            if allowlist.contains(&upper_key) {
                return true;
            }

            // Check exact sensitive names
            if SENSITIVE_EXACT_NAMES.iter().any(|&name| upper_key == name) {
                return false;
            }

            // Check sensitive prefixes
            if SENSITIVE_ENV_PREFIXES
                .iter()
                .any(|&prefix| upper_key.starts_with(prefix))
            {
                return false;
            }

            // Check sensitive suffixes
            if SENSITIVE_ENV_SUFFIXES
                .iter()
                .any(|&suffix| upper_key.ends_with(suffix))
            {
                return false;
            }

            // Default behavior: include general safe non-sensitive system env vars
            true
        })
        .collect()
}


/// Helper to parse a command string (e.g. `"cargo build"` or `"npm install"`) into executable and args.
pub fn parse_command_str(cmd_str: &str) -> Result<(String, Vec<String>), String> {
    let trimmed = cmd_str.trim();
    if trimmed.is_empty() {
        return Err("Command string cannot be empty".to_string());
    }

    let parts = shell_words_split(trimmed)?;
    if parts.is_empty() {
        return Err("Command string resulted in empty tokens".to_string());
    }

    let program = parts[0].clone();
    let args = parts[1..].to_vec();
    Ok((program, args))
}

fn shell_words_split(s: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;

    for c in s.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }

        match c {
            '\\' if !in_single_quote => {
                escaped = true;
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' | '\n' | '\r' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    words.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if in_single_quote || in_double_quote {
        return Err("Unclosed quote in command string".to_string());
    }

    if !current.is_empty() {
        words.push(current);
    }

    Ok(words)
}

/// Execute a command inside the sandbox container.
pub fn execute_sandboxed(command: &str, config: &SandboxConfig) -> Result<i32, String> {
    #[cfg(target_os = "windows")]
    {
        win::execute_in_windows_sandbox(command, config)
    }

    #[cfg(target_os = "linux")]
    {
        linux::execute_in_linux_sandbox(command, config)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (command, config);
        Err("Unsupported operating system for sandboxing".to_string())
    }
}

