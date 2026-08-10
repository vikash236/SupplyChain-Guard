use scanner::ScanReport;
use serde::{Deserialize, Serialize};
use std::fs::{OpenOptions, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub timestamp_epoch_sec: u64,
    pub event_type: String, // "scan" or "exec"
    pub target_path: String,
    pub files_scanned: usize,
    pub critical_count: usize,
    pub warn_count: usize,
    pub info_count: usize,
    pub command_str: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditSummary {
    pub total_scans: usize,
    pub total_execs: usize,
    pub critical_blocked: usize,
    pub successful_sandboxed_runs: usize,
    pub failed_sandboxed_runs: usize,
    pub recommendations: Vec<String>,
}

pub struct AuditLogger {
    log_path: PathBuf,
}

impl AuditLogger {
    pub fn new<P: AsRef<Path>>(log_path: P) -> Self {
        Self {
            log_path: log_path.as_ref().to_path_buf(),
        }
    }

    pub fn default_log_path() -> PathBuf {
        PathBuf::from(".guard-audit.jsonl")
    }

    pub fn log_scan(&self, target_path: &Path, report: &ScanReport, duration: Duration) -> Result<(), String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let event = AuditEvent {
            timestamp_epoch_sec: timestamp,
            event_type: "scan".to_string(),
            target_path: target_path.display().to_string(),
            files_scanned: report.files_scanned,
            critical_count: report.count_by_severity(scanner::Severity::Critical),
            warn_count: report.count_by_severity(scanner::Severity::Warn),
            info_count: report.count_by_severity(scanner::Severity::Info),
            command_str: None,
            exit_code: None,
            duration_ms: duration.as_millis() as u64,
        };

        self.append_event(&event)
    }

    pub fn log_exec(&self, command_str: &str, exit_code: i32, duration: Duration) -> Result<(), String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let event = AuditEvent {
            timestamp_epoch_sec: timestamp,
            event_type: "exec".to_string(),
            target_path: ".".to_string(),
            files_scanned: 0,
            critical_count: 0,
            warn_count: 0,
            info_count: 0,
            command_str: Some(command_str.to_string()),
            exit_code: Some(exit_code),
            duration_ms: duration.as_millis() as u64,
        };

        self.append_event(&event)
    }

    fn append_event(&self, event: &AuditEvent) -> Result<(), String> {
        let json_line = serde_json::to_string(event).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| format!("Failed to open audit log {}: {}", self.log_path.display(), e))?;

        writeln!(file, "{}", json_line).map_err(|e| format!("Failed to write to audit log: {}", e))
    }

    pub fn read_events(log_path: &Path) -> Result<Vec<AuditEvent>, String> {
        if !log_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(log_path).map_err(|e| format!("Failed to open audit log: {}", e))?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| format!("Error reading line {}: {}", idx + 1, e))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(trimmed)
                .map_err(|e| format!("JSON parse error on line {}: {}", idx + 1, e))?;
            events.push(event);
        }

        Ok(events)
    }

    pub fn analyze_events(events: &[AuditEvent]) -> AuditSummary {
        let mut summary = AuditSummary::default();

        for event in events {
            match event.event_type.as_str() {
                "scan" => {
                    summary.total_scans += 1;
                    if event.critical_count > 0 {
                        summary.critical_blocked += 1;
                    }
                }
                "exec" => {
                    summary.total_execs += 1;
                    if let Some(code) = event.exit_code {
                        if code == 0 {
                            summary.successful_sandboxed_runs += 1;
                        } else {
                            summary.failed_sandboxed_runs += 1;
                        }
                    }
                }
                _ => {}
            }
        }

        if summary.critical_blocked > 0 {
            summary.recommendations.push(format!(
                "Security Gate active: {} build script scan(s) had CRITICAL findings blocked.",
                summary.critical_blocked
            ));
        }

        if summary.total_execs > 0 {
            summary.recommendations.push(format!(
                "Sandbox policy verified: {} command execution(s) isolated successfully.",
                summary.successful_sandboxed_runs
            ));
        }

        if summary.recommendations.is_empty() {
            summary.recommendations.push("System baseline clean. No security anomalies observed.".to_string());
        }

        summary
    }
}
