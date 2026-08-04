use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use scanner::{scan_project, ScanReport, Severity};
use std::path::PathBuf;
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

        /// Output format (text or json)
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        /// Exit with non-zero code if CRITICAL findings are detected
        #[arg(long, default_value_t = true)]
        fail_on_critical: bool,
    },

    /// Run a build command inside the OS process sandbox
    Exec {
        /// Command string to execute inside sandbox (e.g. "cargo build" or "npm install")
        command_str: String,

        /// Directory allowed for target build output writes
        #[arg(short, long, default_value = "./target")]
        target_dir: PathBuf,

        /// Allow outbound network connections inside sandbox (deny-by-default if false)
        #[arg(long, default_value_t = false)]
        allow_network: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            fail_on_critical,
        } => {
            run_scan(&path, format, fail_on_critical);
        }
        Commands::Exec {
            command_str,
            target_dir,
            allow_network,
        } => {
            run_exec(&command_str, target_dir, allow_network);
        }
    }
}

fn run_scan(path: &PathBuf, format: OutputFormat, fail_on_critical: bool) {
    match scan_project(path) {
        Ok(report) => {
            match format {
                OutputFormat::Json => {
                    let json_output = serde_json::to_string_pretty(&report)
                        .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));
                    println!("{}", json_output);
                }
                OutputFormat::Text => {
                    print_text_report(&report, path);
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

fn print_text_report(report: &ScanReport, path: &PathBuf) {
    println!("\n{}", "=== SupplyChain-Guard Static AST Scan Report ===".bold());
    println!("Target path: {}\n", path.display().to_string().cyan());

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
        "Scan Summary: Scanned {} file(s) | {} critical, {} warnings, {} info findings.",
        report.files_scanned,
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

fn run_exec(command_str: &str, target_dir: PathBuf, allow_network: bool) {
    println!("\n{}", "=== SupplyChain-Guard Sandbox Execution ===".bold());
    println!("Command    : {}", command_str.cyan().bold());
    println!("Target Dir : {}", target_dir.display());
    println!("Network    : {}\n", if allow_network { "ALLOWED".yellow() } else { "DENIED (isolated)".green().bold() });

    let config = sandbox::SandboxConfig {
        target_dir,
        allow_network,
        ..Default::default()
    };

    match sandbox::execute_sandboxed(command_str, &config) {
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
