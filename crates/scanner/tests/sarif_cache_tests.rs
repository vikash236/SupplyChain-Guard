use scanner::{compute_file_sha256, report_to_sarif, scan_project, BuildCache};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[test]
fn test_sarif_export() {
    let report = scan_project(Path::new("tests/fixtures")).unwrap();
    let sarif_json = report_to_sarif(&report);

    assert!(sarif_json.contains("\"version\": \"2.1.0\""));
    assert!(sarif_json.contains("\"name\": \"SupplyChain-Guard\""));
    assert!(sarif_json.contains("\"rules\":"));
    assert!(sarif_json.contains("\"results\":"));
}


#[test]
fn test_build_cache_recording() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"fn main() {}").unwrap();

    let sha256 = compute_file_sha256(temp_file.path()).unwrap();
    assert_ne!(sha256, "");

    let mut cache = BuildCache::default();
    cache.record(temp_file.path(), sha256.clone(), false, 0);

    assert!(cache.is_cached_clean(temp_file.path(), &sha256));
    assert!(!cache.is_cached_clean(temp_file.path(), "invalid_hash"));
}
