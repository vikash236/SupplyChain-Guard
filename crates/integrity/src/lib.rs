use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSnapshot {
    pub root_dir: PathBuf,
    pub files: HashMap<PathBuf, String>, // relative path -> sha256 hex
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntegrityReport {
    pub modified_files: Vec<PathBuf>,
    pub created_files: Vec<PathBuf>,
    pub deleted_files: Vec<PathBuf>,
}

impl IntegrityReport {
    pub fn is_clean(&self) -> bool {
        self.modified_files.is_empty() && self.created_files.is_empty() && self.deleted_files.is_empty()
    }

    pub fn total_violations(&self) -> usize {
        self.modified_files.len() + self.created_files.len() + self.deleted_files.len()
    }
}

impl WorkspaceSnapshot {
    pub fn take_snapshot(root: &Path, custom_ignored_dirs: &[&str]) -> Result<Self, String> {
        let root_canonical = root.canonicalize().map_err(|e| format!("Failed to canonicalize root path: {}", e))?;
        let mut files = HashMap::new();

        let mut default_ignored = vec!["target", "node_modules", ".git", ".guard-cache.json", ".guard-audit.jsonl"];
        default_ignored.extend_from_slice(custom_ignored_dirs);

        for entry in WalkDir::new(&root_canonical).into_iter().filter_entry(|e| {
            if let Some(name) = e.file_name().to_str() {
                if default_ignored.iter().any(|ig| name.eq_ignore_ascii_case(ig)) {
                    return false;
                }
            }
            true
        }) {
            let entry = entry.map_err(|e| format!("Directory walk error: {}", e))?;
            let path = entry.path();

            if path.is_file() {
                if let Ok(rel_path) = path.strip_prefix(&root_canonical) {
                    if let Ok(hash) = compute_sha256(path) {
                        files.insert(rel_path.to_path_buf(), hash);
                    }
                }
            }
        }

        Ok(Self {
            root_dir: root_canonical,
            files,
        })
    }

    pub fn diff(&self, post: &WorkspaceSnapshot) -> IntegrityReport {
        let mut report = IntegrityReport::default();

        // Check modified and deleted files
        for (rel_path, before_hash) in &self.files {
            match post.files.get(rel_path) {
                Some(after_hash) => {
                    if before_hash != after_hash {
                        report.modified_files.push(rel_path.clone());
                    }
                }
                None => {
                    report.deleted_files.push(rel_path.clone());
                }
            }
        }

        // Check newly created files outside target/node_modules
        for rel_path in post.files.keys() {
            if !self.files.contains_key(rel_path) {
                report.created_files.push(rel_path.clone());
            }
        }

        report
    }
}

fn compute_sha256(file_path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| format!("Failed to hash file: {}", e))?;
    Ok(format!("{:x}", hasher.finalize()))
}
