use audit::AuditLogger;
use scanner::ScanReport;
use tempfile::tempdir;

#[test]
fn test_audit_log_scan_and_read_back() {
    let dir = tempdir().expect("temp dir");
    let log_path = dir.path().join("test-audit.jsonl");
    let logger = AuditLogger::new(&log_path);

    let mut report = ScanReport::new();
    report.files_scanned = 5;

    let res = logger.log_scan(dir.path(), &report, std::time::Duration::from_millis(150));
    assert!(res.is_ok());

    let events = AuditLogger::read_events(&log_path).expect("read events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "scan");
    assert_eq!(events[0].files_scanned, 5);
    assert_eq!(events[0].duration_ms, 150);
}

#[test]
fn test_audit_log_exec_and_analysis() {
    let dir = tempdir().expect("temp dir");
    let log_path = dir.path().join("test-audit.jsonl");
    let logger = AuditLogger::new(&log_path);

    let _ = logger.log_exec("cargo build", 0, std::time::Duration::from_millis(500));
    let _ = logger.log_exec("cargo test", 1, std::time::Duration::from_millis(300));

    let events = AuditLogger::read_events(&log_path).expect("read events");
    assert_eq!(events.len(), 2);

    let summary = AuditLogger::analyze_events(&events);
    assert_eq!(summary.total_execs, 2);
    assert_eq!(summary.successful_sandboxed_runs, 1);
    assert_eq!(summary.failed_sandboxed_runs, 1);
    assert!(!summary.recommendations.is_empty());
}
