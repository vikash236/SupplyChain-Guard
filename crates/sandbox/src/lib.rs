//! # Sandbox
//!
//! OS-native process isolation engine for build script execution.
//!
//! - **Windows**: Job Objects + AppContainer
//! - **Linux**: `unshare` namespaces + `seccomp-bpf`

pub mod win;
pub mod linux;

/// Configuration options for launching a sandboxed process.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Path to the target build directory (writes restricted to this directory).
    pub target_dir: std::path::PathBuf,
    /// Allow network access (default: false / deny).
    pub allow_network: bool,
    /// Environment variables to retain (sensitive env vars stripped by default).
    pub env_allowlist: Vec<String>,
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
            ],
        }
    }
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
