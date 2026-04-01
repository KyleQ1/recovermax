use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Chain of custody / case information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub examiner: String,
    pub case_number: String,
    pub evidence_id: String,
    pub description: String,
}

/// What action was performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    ImageOpened { path: String, size: u64, sha256: Option<String> },
    ScanStarted,
    ScanCompleted { partitions: usize, filesystems: usize },
    FileRecovered { inode: u64, path: String, size: u64, sha256: String },
    DirectoryRecovered { path: String, file_count: usize },
    CarveStarted { types: Vec<String> },
    CarveCompleted { files_found: usize },
    DeletedScan { deleted_count: usize },
    ImageVerified { sha256: String, matched: bool },
    Error { message: String },
}

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
}

/// Forensic audit log — records all operations for chain of custody
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub case_info: CaseInfo,
    pub tool_version: String,
    pub started_at: DateTime<Utc>,
    pub entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new(case_info: CaseInfo) -> Self {
        Self {
            case_info,
            tool_version: format!("RecoverMax {}", env!("CARGO_PKG_VERSION")),
            started_at: Utc::now(),
            entries: Vec::new(),
        }
    }

    pub fn log(&mut self, action: AuditAction) {
        self.entries.push(AuditEntry {
            timestamp: Utc::now(),
            action,
        });
    }

    /// Save audit log to a JSON file
    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load audit log from a JSON file
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let log: AuditLog = serde_json::from_str(&data)?;
        Ok(log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_case() -> CaseInfo {
        CaseInfo {
            examiner: "Test Examiner".into(),
            case_number: "CASE-001".into(),
            evidence_id: "EVD-001".into(),
            description: "Test forensic examination".into(),
        }
    }

    #[test]
    fn test_audit_log_creation() {
        let log = AuditLog::new(test_case());
        assert_eq!(log.case_info.case_number, "CASE-001");
        assert!(log.entries.is_empty());
        assert!(log.tool_version.starts_with("RecoverMax"));
    }

    #[test]
    fn test_audit_log_entries() {
        let mut log = AuditLog::new(test_case());
        log.log(AuditAction::ImageOpened {
            path: "/dev/sda".into(),
            size: 1024 * 1024,
            sha256: Some("abc123".into()),
        });
        log.log(AuditAction::ScanStarted);
        log.log(AuditAction::ScanCompleted { partitions: 3, filesystems: 2 });

        assert_eq!(log.entries.len(), 3);
    }

    #[test]
    fn test_audit_log_serialization() {
        let mut log = AuditLog::new(test_case());
        log.log(AuditAction::ScanStarted);

        let json = serde_json::to_string(&log).unwrap();
        let loaded: AuditLog = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.case_info.case_number, "CASE-001");
        assert_eq!(loaded.entries.len(), 1);
    }

    #[test]
    fn test_audit_log_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");

        let mut log = AuditLog::new(test_case());
        log.log(AuditAction::FileRecovered {
            inode: 42,
            path: "/home/user/doc.txt".into(),
            size: 1024,
            sha256: "deadbeef".into(),
        });

        log.save(&path).unwrap();
        let loaded = AuditLog::load(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.case_info.examiner, "Test Examiner");
    }
}
