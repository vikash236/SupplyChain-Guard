use integrity::WorkspaceSnapshot;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_integrity_snapshot_clean_run() {
    let dir = tempdir().expect("temp dir");
    let src_file = dir.path().join("main.rs");
    fs::write(&src_file, "fn main() {}").expect("write file");

    let snap_before = WorkspaceSnapshot::take_snapshot(dir.path(), &[]).expect("snapshot before");
    let snap_after = WorkspaceSnapshot::take_snapshot(dir.path(), &[]).expect("snapshot after");

    let report = snap_before.diff(&snap_after);
    assert!(report.is_clean());
}

#[test]
fn test_integrity_snapshot_detects_mutation() {
    let dir = tempdir().expect("temp dir");
    let src_file = dir.path().join("lib.rs");
    fs::write(&src_file, "pub fn foo() {}").expect("write file");

    let snap_before = WorkspaceSnapshot::take_snapshot(dir.path(), &[]).expect("snapshot before");

    // Simulate malicious build script modifying source file
    fs::write(&src_file, "pub fn foo() { /* injected payload */ }").expect("write mutated file");

    let snap_after = WorkspaceSnapshot::take_snapshot(dir.path(), &[]).expect("snapshot after");

    let report = snap_before.diff(&snap_after);
    assert!(!report.is_clean());
    assert_eq!(report.modified_files.len(), 1);
    assert_eq!(report.modified_files[0], std::path::PathBuf::from("lib.rs"));
}

#[test]
fn test_integrity_ignores_target_dir() {
    let dir = tempdir().expect("temp dir");
    let target_dir = dir.path().join("target");
    fs::create_dir(&target_dir).expect("create target dir");

    let snap_before = WorkspaceSnapshot::take_snapshot(dir.path(), &[]).expect("snapshot before");

    // Build artifact created in target/
    fs::write(target_dir.join("app.exe"), "binary artifact").expect("write build artifact");

    let snap_after = WorkspaceSnapshot::take_snapshot(dir.path(), &[]).expect("snapshot after");

    let report = snap_before.diff(&snap_after);
    assert!(report.is_clean());
}
