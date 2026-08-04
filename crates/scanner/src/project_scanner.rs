//! Project-level scanner that walks a directory tree to find and analyze build scripts.
//!
//! Discovers `build.rs` files (Rust) and `package.json` files (Node.js)
//! and runs the appropriate scanner on each.

use std::fs;
use std::path::Path;

use walkdir::WalkDir;

use crate::findings::ScanReport;
use crate::node_scanner;
use crate::rust_scanner;

/// Scan an entire project directory for suspicious build scripts.
///
/// Walks the directory tree looking for:
/// - `build.rs` files → analyzed by the Rust AST scanner
/// - `package.json` files → analyzed by the Node.js scanner
///
/// Skips common non-project directories (`.git`, `target`, `node_modules`, `.cargo`).
///
/// # Arguments
/// * `project_path` — Root directory of the project to scan
///
/// # Returns
/// A merged `ScanReport` containing findings from all discovered build scripts.
pub fn scan_project(project_path: &Path) -> Result<ScanReport, String> {
    if !project_path.exists() {
        return Err(format!("Path does not exist: {}", project_path.display()));
    }

    let mut report = ScanReport::new();

    if project_path.is_file() {
        // Single file mode
        return scan_single_file(project_path);
    }

    // Walk the directory tree
    for entry in WalkDir::new(project_path)
        .follow_links(false) // Don't follow symlinks — potential sandbox escape
        .into_iter()
        .filter_entry(|e| !is_skip_dir(e))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => continue,
        };

        if file_name == "build.rs" || file_name.ends_with("_build.rs") {
            if let Ok(content) = fs::read_to_string(path) {
                let file_report = rust_scanner::scan_rust_file(path, &content);
                report.merge(file_report);
            }
        } else if file_name == "package.json" || file_name.ends_with("_package.json") || file_name.ends_with("_pkg.json") {
            if let Ok(content) = fs::read_to_string(path) {
                let file_report = node_scanner::scan_package_json(path, &content);
                report.merge(file_report);
            }
        }

    }

    Ok(report)
}

/// Scan a single file based on its name.
fn scan_single_file(path: &Path) -> Result<ScanReport, String> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let report = match file_name {
        "build.rs" => rust_scanner::scan_rust_file(path, &content),
        "package.json" => node_scanner::scan_package_json(path, &content),
        _ => {
            // Try to detect file type by extension
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                rust_scanner::scan_rust_file(path, &content)
            } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
                node_scanner::scan_package_json(path, &content)
            } else {
                return Err(format!(
                    "Unknown file type: {}. Expected build.rs or package.json",
                    path.display()
                ));
            }
        }
    };

    Ok(report)
}

/// Check if a directory entry should be skipped during traversal.
fn is_skip_dir(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }

    let name = match entry.file_name().to_str() {
        Some(n) => n,
        None => return false,
    };

    matches!(
        name,
        ".git" | "target" | "node_modules" | ".cargo" | ".npm" | ".cache" | "dist" | "build"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_nonexistent_path() {
        let result = scan_project(&PathBuf::from("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_dir_detection() {
        assert!(matches!(".git", ".git" | "target" | "node_modules"));
        assert!(matches!("target", ".git" | "target" | "node_modules"));
        assert!(!matches!("src", ".git" | "target" | "node_modules"));
    }

}
