//! SHA-256 Hash Caching Engine for SupplyChain-Guard.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildCache {
    pub entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub sha256: String,
    pub has_critical: bool,
    pub findings_count: usize,
}

impl BuildCache {
    pub fn load_cache<P: AsRef<Path>>(cache_path: P) -> Self {
        let path = cache_path.as_ref();
        if !path.exists() {
            return Self::default();
        }

        fs::read_to_string(path)
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default()
    }

    pub fn save_cache<P: AsRef<Path>>(&self, cache_path: P) -> Result<(), String> {
        let path = cache_path.as_ref();
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize cache: {}", e))?;
        fs::write(path, content)
            .map_err(|e| format!("Failed to write cache file '{}': {}", path.display(), e))
    }

    pub fn is_cached_clean<P: AsRef<Path>>(&self, file_path: P, current_sha256: &str) -> bool {
        let key = file_path.as_ref().to_string_lossy().to_string();
        if let Some(entry) = self.entries.get(&key) {
            entry.sha256 == current_sha256 && !entry.has_critical && entry.findings_count == 0
        } else {
            false
        }
    }

    pub fn record<P: AsRef<Path>>(&mut self, file_path: P, sha256: String, has_critical: bool, findings_count: usize) {
        let key = file_path.as_ref().to_string_lossy().to_string();
        self.entries.insert(
            key,
            CacheEntry {
                sha256,
                has_critical,
                findings_count,
            },
        );
    }
}

pub fn compute_file_sha256<P: AsRef<Path>>(path: P) -> Result<String, String> {
    let bytes = fs::read(path.as_ref())
        .map_err(|e| format!("Failed to read file for SHA-256 calculation: {}", e))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}
