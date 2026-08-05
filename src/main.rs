use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use policy::GuardPolicy;
use scanner::{apply_policy_to_report, report_to_sarif, scan_project, BuildCache, ScanReport, Severity};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

#[derive(Parser)]
#[command(
    name = "supplychain-guard",
    author = "SupplyChain-Guard Team",
    version = "0.1.0",
    about = "Build-time native code & hook sandbox and static AST analyzer",
    long_about = "SupplyChain-Guard scans Rust build.rs and Node package.json scripts for malicious API patterns and executes build steps inside an OS-isolated local sandbox."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform static analysis on build scripts (build.rs, package.json)
    Scan {
        /// Path to project directory or build script file
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format (text, json, or sarif)
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        /// Path to guard.toml policy configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Use SHA-256 hash cache file (.guard-cache.json) to skip clean unmodified build scripts
        #[arg(short, long, default_value_t = false)]
        use_cache: bool,

        /// Exit with non-zero code if CRITICAL findings are detected
        #[arg(long, default_value_t = true)]
        fail_on_critical: bool,
    },

    /// Run a build command inside the OS process sandbox
    Exec {
        /// Command string to execute inside sandbox (e.g. "cargo build" or "npm install")
        command_str: String,

        /// Path to guard.toml policy configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Directory allowed for target build output writes
        #[arg(short, long, default_value = "./target")]
        target_dir: PathBuf,

        /// Allow outbound network connections inside sandbox (deny-by-default if false)
        #[arg(long, default_value_t = false)]
        allow_network: bool,
    },

    /// Install git pre-commit hook in .git/hooks/pre-commit
    InitHook {
        /// Overwrite existing pre-commit hook script if present
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },

    /// Generate a default guard.toml security policy configuration file
    InitConfig {
        /// Overwrite existing guard.toml file if present
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            config,
            use_cache,
            fail_on_critical,
        } => {
            run_scan(&path, format, config, use_cache, fail_on_critical);
        }
        Commands::Exec {
            command_str,
            config,
            target_dir,
            allow_network,
        } => {
            run_exec(&command_str, config, target_dir, allow_network);
        }
        Commands::InitHook { force } => {
            run_init_hook(force);
        }
        Commands::InitConfig { force } => {
            run_init_config(force);
        }
    }
}

fn run_scan(
    path: &PathBuf,
    format: OutputFormat,
    config_path: Option<PathBuf>,
    use_cache: bool,
    fail_on_critical: bool,
) {
    let start_time = std::time::Instant::now();

    let policy = match GuardPolicy::load_or_default(config_path.as_deref()) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("Policy configuration error: {}", err);
            exit(2);
        }
    };

    let cache_file_path = Path::new(".guard-cache.json");
    let mut cache = if use_cache {
        BuildCache::load_cache(cache_file_path)
    } else {
        BuildCache::default()
    };

    match scan_project(path) {
        Ok(mut report) => {
            apply_policy_to_report(&mut report, &policy);

            if use_cache {
                for finding in &report.findings {
                    if let Ok(hash) = scanner::compute_file_sha256(&finding.file) {
                        cache.record(&finding.file, hash, report.has_critical(), report.findings.len());
                    }
                }
                let _ = cache.save_cache(cache_file_path);
            }

            let duration = start_time.elapsed();

            match format {
                OutputFormat::Json => {
                    let json_output = serde_json::to_string_pretty(&report)
                        .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));
                    println!("{}", json_output);
                }
                OutputFormat::Sarif => {
                    let sarif_output = report_to_sarif(&report);
                    println!("{}", sarif_output);
                }
                OutputFormat::Text => {
                    print_text_report(&report, path, duration);
                }
            }

            if fail_on_critical && report.has_critical() {
                exit(1);
            }
        }
        Err(err) => {
            eprintln!("Scan error: {}", err);
            exit(2);
        }
    }
}

fn print_text_report(report: &ScanReport, path: &PathBuf, duration: std::time::Duration) {
    println!("\n{}", "=== SupplyChain-Guard Static AST Scan Report ===".bold());
    println!("Target path: {}", path.display().to_string().cyan());
    println!("Scan Time  : {:.2?}\n", duration);

    if report.findings.is_empty() {
        println!("{}", "✓ No suspicious build script patterns detected.".green().bold());
        println!("Files scanned: {}\n", report.files_scanned);
        return;
    }

    for finding in &report.findings {
        let severity_badge = match finding.severity {
            Severity::Info => " INFO ".on_blue().black().bold(),
            Severity::Warn => " WARN ".on_yellow().black().bold(),
            Severity::Critical => " CRITICAL ".on_red().white().bold(),
        };

        let file_loc = if let Some(line) = finding.line {
            format!("{}:{}", finding.file.display(), line)
        } else {
            finding.file.display().to_string()
        };

        println!("{} [{}] {}", severity_badge, finding.kind.to_string().bold(), finding.message);
        println!("   Location: {}", file_loc.dimmed());

        if let Some(snippet) = &finding.snippet {
            println!("   Snippet : {}", snippet.yellow());
        }
        println!();
    }

    let critical_count = report.count_by_severity(Severity::Critical);
    let warn_count = report.count_by_severity(Severity::Warn);
    let info_count = report.count_by_severity(Severity::Info);

    println!("{}", "--------------------------------------------------".dimmed());
    println!(
        "Scan Summary: Scanned {} file(s) in {:.2?} | {} critical, {} warnings, {} info findings.",
        report.files_scanned,
        duration,
        if critical_count > 0 { critical_count.to_string().red().bold() } else { critical_count.to_string().normal() },
        if warn_count > 0 { warn_count.to_string().yellow().bold() } else { warn_count.to_string().normal() },
        info_count
    );

    if report.has_critical() {
        println!(
            "\n{}",
            "✖ CRITICAL FINDINGS DETECTED! Build script(s) may contain malicious operations."
                .red()
                .bold()
        );
    } else if report.has_warnings() {
        println!(
            "\n{}",
            "⚠ WARNINGS DETECTED: Review build script subprocess invocations before running."
                .yellow()
                .bold()
        );
    }
    println!();
}

fn run_exec(command_str: &str, config_path: Option<PathBuf>, target_dir: PathBuf, allow_network: bool) {
    let policy = match GuardPolicy::load_or_default(config_path.as_deref()) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("Policy configuration error: {}", err);
            exit(2);
        }
    };

    let mut sandbox_config = sandbox::SandboxConfig::from_policy(&policy);

    if allow_network {
        sandbox_config.allow_network = true;
    }
    if target_dir != PathBuf::from("./target") {
        sandbox_config.target_dir = target_dir;
    }

    println!("\n{}", "=== SupplyChain-Guard Sandbox Execution ===".bold());
    println!("Command      : {}", command_str.cyan().bold());
    println!("Target Dir   : {}", sandbox_config.target_dir.display());
    println!("Network      : {}", if sandbox_config.allow_network { "ALLOWED".yellow() } else { "DENIED (isolated)".green().bold() });
    if let Some(mem_mb) = sandbox_config.memory_limit_mb {
        println!("Memory Limit : {} MB", mem_mb.to_string().cyan());
    }
    println!();

    match sandbox::execute_sandboxed(command_str, &sandbox_config) {
        Ok(exit_code) => {
            if exit_code == 0 {
                println!("{}", "✓ Command finished cleanly inside sandbox.".green().bold());
            } else {
                eprintln!("Command exited with status code: {}", exit_code);
                exit(exit_code);
            }
        }
        Err(err) => {
            eprintln!("Sandbox error: {}", err);
            exit(1);
        }
    }
}

fn run_init_hook(force: bool) {
    let git_dir = Path::new(".git");
    if !git_dir.exists() {
        eprintln!("{}", "Error: .git directory not found. Must be run inside a git repository root.".red().bold());
        exit(1);
    }

    let hooks_dir = git_dir.join("hooks");
    if let Err(e) = fs::create_dir_all(&hooks_dir) {
        eprintln!("Failed to create .git/hooks directory: {}", e);
        exit(1);
    }

    let hook_file = hooks_dir.join("pre-commit");
    if hook_file.exists() && !force {
        eprintln!(
            "{}",
            "Pre-commit hook already exists at .git/hooks/pre-commit. Pass --force to overwrite.".yellow()
        );
        exit(1);
    }

    let hook_script = r#"#!/bin/sh
# SupplyChain-Guard Pre-Commit Hook
# Scans build.rs and package.json scripts before git commits

echo "[SupplyChain-Guard] Scanning project build scripts prior to commit..."
cargo run --quiet -- scan .

if [ $? -ne 0 ]; then
    echo "[SupplyChain-Guard] Pre-commit security check FAILED! Commit blocked."
    exit 1
fi
"#;

    if let Err(e) = fs::write(&hook_file, hook_script) {
        eprintln!("Failed to write pre-commit hook script: {}", e);
        exit(1);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_file).unwrap().permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(&hook_file, perms);
    }

    println!("\n{}", "✓ Pre-commit hook successfully installed at .git/hooks/pre-commit".green().bold());
    println!("Build scripts will now be automatically scanned prior to git commits.\n");
}

fn run_init_config(force: bool) {
    let config_file = Path::new("guard.toml");
    if config_file.exists() && !force {
        eprintln!(
            "{}",
            "Policy configuration file already exists at ./guard.toml. Pass --force to overwrite.".yellow()
        );
        exit(1);
    }

    let default_config = r#"# SupplyChain-Guard Security Policy Configuration

[scanner]
# List of finding kinds to ignore during static AST scan
ignored_rules = []

# List of file paths to exclude from static scanning
ignored_paths = []

# Override severity levels for specific findings (CRITICAL, WARN, INFO)
[scanner.severity_overrides]

[sandbox]
# Permit outbound network connections inside sandbox container (default: false)
allow_network = false

# Environment variables explicitly allowed into sandbox container
env_allowlist = [
  "CARGO_BUILD_TARGET",
  "RUSTFLAGS"
]

# Environment variables explicitly stripped from sandbox container
env_denylist = []

# Maximum process memory limit in megabytes (e.g. 1024 MB)
memory_limit_mb = 1024

# Allowed build target directories for write operations
allowed_write_paths = [
  "./target"
]

[rules]
block_obfuscated_code = true
block_subprocesses = false
block_network_calls = true
"#;

    if let Err(e) = fs::write(config_file, default_config) {
        eprintln!("Failed to write guard.toml: {}", e);
        exit(1);
    }

    println!("\n{}", "✓ Security policy template successfully created at ./guard.toml".green().bold());
    println!("Customize rule exclusions and sandbox resource limits in guard.toml.\n");
}



