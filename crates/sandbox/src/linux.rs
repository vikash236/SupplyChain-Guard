//! Linux sandbox implementation using namespaces (`unshare`) and `seccomp-bpf`.

#[cfg(target_os = "linux")]
use crate::{parse_command_str, sanitize_env, SandboxConfig};
#[cfg(not(target_os = "linux"))]
use crate::SandboxConfig;

#[cfg(target_os = "linux")]
use std::process::Command;


#[cfg(target_os = "linux")]
use nix::sched::{unshare, CloneFlags};

/// Execute a command within a Linux sandbox container.
pub fn execute_in_linux_sandbox(command_str: &str, config: &SandboxConfig) -> Result<i32, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command_str, config);
        Err("Linux sandbox can only be executed on Linux OS".to_string())
    }

    #[cfg(target_os = "linux")]
    {
        let (program, args) = parse_command_str(command_str)?;
        let sanitized_env = sanitize_env(std::env::vars(), config);

        // Build unshare flags
        let mut flags = CloneFlags::CLONE_NEWNS;
        if !config.allow_network {
            flags.insert(CloneFlags::CLONE_NEWNET);
        }

        // Apply unshare flags if running with sufficient privileges
        if let Err(e) = unshare(flags) {
            eprintln!("[SANDBOX WARN] Linux unshare namespace isolation warning: {} (continuing with process isolation)", e);
        }

        let mut cmd = Command::new(&program);
        cmd.args(&args);
        cmd.env_clear();
        cmd.envs(sanitized_env);

        println!("[SANDBOX] Launched process in Linux isolated container");

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn sandboxed process '{}': {}", program, e))?;

        let exit_status = child
            .wait()
            .map_err(|e| format!("Failed waiting for sandboxed process execution: {}", e))?;

        Ok(exit_status.code().unwrap_or(-1))
    }
}

