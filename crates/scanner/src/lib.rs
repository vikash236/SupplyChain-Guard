//! # Scanner
//!
//! Static analysis engine for detecting suspicious patterns in build scripts.
//!
//! Provides two scanners:
//! - **Rust scanner**: Uses `syn` AST visitor to analyze `build.rs` files for
//!   dangerous API calls (process spawning, network access, credential reads).
//! - **Node.js scanner**: Parses `package.json` lifecycle hooks for shell injection,
//!   exfiltration commands, and obfuscated payloads.
//!
//! The scanner **never** executes or compiles the code it analyzes — AST parsing only.

pub mod findings;
pub mod node_scanner;
pub mod rust_scanner;
pub mod project_scanner;

pub use findings::{Finding, FindingKind, ScanReport, Severity};

pub use node_scanner::scan_package_json;
pub use rust_scanner::scan_rust_file;
pub use project_scanner::scan_project;
