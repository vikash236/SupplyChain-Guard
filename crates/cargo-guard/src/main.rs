use clap::{Parser, Subcommand};
use colored::*;
use policy::GuardPolicy;
use scanner::{apply_policy_to_report, scan_project, Severity};
use std::env;
use std::path::{Path, PathBuf};
use std::process::exit;

#[derive(Parser)]
#[command(
    name = "cargo-guard",
    author = "SupplyChain-Guard Team",
    version = "0.1.0",
    about = "Transparent Cargo subcommand plugin for SupplyChain-Guard build security",
    long_about = "cargo-guard transparently scans build scripts (build.rs, package.json) for malicious AST patterns and executes cargo build commands inside an OS-isolated sandbox."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Raw cargo arguments passed to cargo subcommand (when no explicit subcommand matches)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    raw_args: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform static analysis on project build scripts
    Scan {
        /// Path to project directory or build script file
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Path to guard.toml policy file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Run build command in isolated OS sandbox
    Exec {
        /// Command string to execute inside sandbox
        command_str: String,

        /// Path to guard.toml policy file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

fn main() {
    let mut raw_args: Vec<String> = env::args().collect();

    // When invoked as `cargo guard <cmd>`, cargo passes "guard" as the second argument (argv[1]).
    // Strip "guard" if present so clap parses correctly.
    if raw_args.len() > 1 && raw_args[1] == "guard" {
        raw_args.remove(1);
    }

    let cli = match Cli::try_parse_from(&raw_args) {
        Ok(c) => c,
        Err(_) => {
            // Fallback for direct cargo subcommand delegation (e.g. `cargo guard build --release`)
            let passthrough_args: Vec<String> = raw_args.into_iter().skip(1).collect();
            run_sandboxed_cargo_build(&passthrough_args);
            return;
        }
    };

    match cli.command {
        Some(Commands::Scan { path, config }) => {
            run_scan(&path, config);
        }
        Some(Commands::Exec { command_str, config }) => {
            run_exec(&command_str, config);
        }
        None => {
            if !cli.raw_args.is_empty() {
                run_sandboxed_cargo_build(&cli.raw_args);
            } else {
                // Default action when invoked as `cargo guard`: run static scan + sandboxed cargo build
                run_sandboxed_cargo_build(&["build".to_string()]);
            }
        }
    }
}

fn run_scan(path: &PathBuf, config_path: Option<PathBuf>) {
    let start = std::time::Instant::now();
    let policy = GuardPolicy::load_or_default(config_path.as_deref()).unwrap_or_default();
    match scan_project(path) {
        Ok(mut report) => {
            apply_policy_to_report(&mut report, &policy);
            let logger = audit::AuditLogger::new(audit::AuditLogger::default_log_path());
            let _ = logger.log_scan(path, &report, start.elapsed());

            println!("\n{}", "=== cargo-guard Static AST Scan ===".bold());
            println!("Target path: {}", path.display().to_string().cyan());

            if report.findings.is_empty() {
                println!("{}", "✓ No suspicious build script patterns detected.".green().bold());
            } else {
                for finding in &report.findings {
                    let badge = match finding.severity {
                        Severity::Info => " INFO ".on_blue().black().bold(),
                        Severity::Warn => " WARN ".on_yellow().black().bold(),
                        Severity::Critical => " CRITICAL ".on_red().white().bold(),
                    };
                    println!("{} [{}] {}", badge, finding.kind.to_string().bold(), finding.message);
                }
            }

            if report.has_critical() {
                eprintln!("\n{}", "✖ CRITICAL findings detected! Build script blocked.".red().bold());
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("Scan failed: {}", e);
            exit(2);
        }
    }
}

fn run_exec(command_str: &str, config_path: Option<PathBuf>) {
    let policy = GuardPolicy::load_or_default(config_path.as_deref()).unwrap_or_default();
    let sandbox_config = sandbox::SandboxConfig::from_policy(&policy);

    println!("\n{}", "=== cargo-guard Sandboxed Execution ===".bold());
    println!("Executing: {}", command_str.cyan().bold());

    match sandbox::execute_sandboxed(command_str, &sandbox_config) {
        Ok(code) => {
            if code != 0 {
                exit(code);
            }
        }
        Err(e) => {
            eprintln!("Sandbox failure: {}", e);
            exit(1);
        }
    }
}

fn run_sandboxed_cargo_build(cargo_subargs: &[String]) {
    let project_dir = Path::new(".");
    let policy = GuardPolicy::load_or_default(Option::<&Path>::None).unwrap_or_default();

    println!("{}", "[cargo-guard] Intercepting build command... Performing static AST security check.".cyan().bold());

    // 1. Perform static scan
    if let Ok(mut report) = scan_project(project_dir) {
        apply_policy_to_report(&mut report, &policy);
        if report.has_critical() {
            eprintln!(
                "\n{}",
                "✖ Security Gate Blocked: Malicious or critical operations detected in build script(s)."
                    .red()
                    .bold()
            );
            for finding in report.findings.iter().filter(|f| f.severity == Severity::Critical) {
                eprintln!("   - [{}] {}", finding.file.display(), finding.message);
            }
            eprintln!("\nAborting compilation. Fix security findings before proceeding.");
            exit(1);
        }
    }

    // 2. Construct full cargo command string
    let full_command = if cargo_subargs.is_empty() {
        "cargo build".to_string()
    } else {
        format!("cargo {}", cargo_subargs.join(" "))
    };

    println!("[cargo-guard] Security gate PASSED. Launching sandboxed process: {}", full_command.green());

    let pre_snapshot = integrity::WorkspaceSnapshot::take_snapshot(project_dir, &[]).ok();

    // 3. Execute inside sandbox
    let sandbox_config = sandbox::SandboxConfig::from_policy(&policy);
    let exec_res = sandbox::execute_sandboxed(&full_command, &sandbox_config);

    if let Some(before) = pre_snapshot {
        if let Ok(after) = integrity::WorkspaceSnapshot::take_snapshot(project_dir, &[]) {
            let diff = before.diff(&after);
            if !diff.is_clean() {
                eprintln!("\n{}", "✖ [cargo-guard] CRITICAL INTEGRITY VIOLATION DETECTED!".red().bold());
                for modified in &diff.modified_files {
                    eprintln!("   - Modified file outside target: {}", modified.display().to_string().yellow());
                }
            }
        }
    }

    match exec_res {
        Ok(code) => {
            if code != 0 {
                exit(code);
            }
        }
        Err(err) => {
            eprintln!("Sandbox error: {}", err);
            exit(1);
        }
    }
}
