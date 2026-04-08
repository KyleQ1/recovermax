use std::path::Path;

use anyhow::Result;
use chrono::Utc;

use super::audit::{AuditAction, AuditLog};

/// Recovered file entry for the report
#[derive(Debug, Clone)]
pub struct RecoveredFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// Generates a self-contained HTML forensic report
pub struct ForensicReport;

impl ForensicReport {
    /// Generate an HTML forensic report from an audit log and save to file.
    pub fn generate(
        audit_log: &AuditLog,
        image_path: &str,
        image_sha256: Option<&str>,
        recovered_files: &[RecoveredFile],
        output_path: &Path,
    ) -> Result<()> {
        let html = Self::render_html(audit_log, image_path, image_sha256, recovered_files);
        std::fs::write(output_path, html)?;
        Ok(())
    }

    fn render_html(
        audit_log: &AuditLog,
        image_path: &str,
        image_sha256: Option<&str>,
        recovered_files: &[RecoveredFile],
    ) -> String {
        let case = &audit_log.case_info;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

        let mut actions_html = String::new();
        for entry in &audit_log.entries {
            let desc = match &entry.action {
                AuditAction::ImageOpened { path, size, sha256 } => {
                    format!(
                        "Opened image: {} ({} bytes, SHA-256: {})",
                        path,
                        size,
                        sha256.as_deref().unwrap_or("not computed")
                    )
                }
                AuditAction::ScanStarted => "Scan started".into(),
                AuditAction::ScanCompleted {
                    partitions,
                    filesystems,
                } => {
                    format!(
                        "Scan completed: {} partitions, {} filesystems",
                        partitions, filesystems
                    )
                }
                AuditAction::FileRecovered {
                    inode,
                    path,
                    size,
                    sha256,
                } => {
                    format!(
                        "Recovered file: {} (inode {}, {} bytes, SHA-256: {})",
                        path, inode, size, sha256
                    )
                }
                AuditAction::DirectoryRecovered { path, file_count } => {
                    format!("Recovered directory: {} ({} files)", path, file_count)
                }
                AuditAction::CarveStarted { types } => {
                    format!("File carving started (types: {})", types.join(", "))
                }
                AuditAction::CarveCompleted { files_found } => {
                    format!("File carving completed: {} files found", files_found)
                }
                AuditAction::DeletedScan { deleted_count } => {
                    format!("Deleted inode scan: {} deleted inodes found", deleted_count)
                }
                AuditAction::ImageVerified { sha256, matched } => {
                    format!(
                        "Image verification: SHA-256 {} — {}",
                        sha256,
                        if *matched { "MATCH" } else { "MISMATCH" }
                    )
                }
                AuditAction::Error { message } => {
                    format!("Error: {}", message)
                }
            };

            actions_html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>\n",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                html_escape(&desc),
            ));
        }

        let mut files_html = String::new();
        for (i, f) in recovered_files.iter().enumerate() {
            files_html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>\n",
                i + 1,
                html_escape(&f.path),
                bytesize::ByteSize(f.size),
                &f.sha256,
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Report — {case_number}</title>
<style>
body {{ font-family: 'Courier New', monospace; margin: 2em; background: #fff; color: #111; font-size: 13px; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: 8px; }}
h2 {{ border-bottom: 1px solid #999; padding-bottom: 4px; margin-top: 2em; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ border: 1px solid #999; padding: 6px 10px; text-align: left; }}
th {{ background: #e0e0e0; font-weight: bold; }}
tr:nth-child(even) {{ background: #f5f5f5; }}
.meta-table {{ width: auto; }}
.meta-table td:first-child {{ font-weight: bold; min-width: 180px; }}
code {{ background: #f0f0f0; padding: 1px 4px; font-size: 12px; }}
.footer {{ margin-top: 3em; border-top: 1px solid #ccc; padding-top: 1em; color: #666; font-size: 11px; }}
.warning {{ color: #c00; font-weight: bold; }}
</style>
</head>
<body>

<h1>Forensic Examination Report</h1>

<h2>Chain of Custody</h2>
<table class="meta-table">
<tr><td>Case Number</td><td>{case_number}</td></tr>
<tr><td>Evidence ID</td><td>{evidence_id}</td></tr>
<tr><td>Examiner</td><td>{examiner}</td></tr>
<tr><td>Description</td><td>{description}</td></tr>
<tr><td>Examination Started</td><td>{started_at}</td></tr>
<tr><td>Report Generated</td><td>{report_time}</td></tr>
<tr><td>Tool</td><td>{tool_version}</td></tr>
</table>

<h2>Evidence Image</h2>
<table class="meta-table">
<tr><td>Image Path</td><td><code>{image_path}</code></td></tr>
<tr><td>SHA-256 Hash</td><td><code>{image_hash}</code></td></tr>
</table>

<h2>Actions Performed</h2>
<table>
<tr><th>Timestamp</th><th>Action</th></tr>
{actions}
</table>

<h2>Recovered Files ({file_count})</h2>
<table>
<tr><th>#</th><th>Path</th><th>Size</th><th>SHA-256</th></tr>
{files}
</table>

<div class="footer">
<p>Generated by {tool_version} — <a href="https://github.com/KyleQ1/recovermax">github.com/KyleQ1/recovermax</a></p>
<p>This report follows NIST SP 800-86 guidelines for forensic documentation.</p>
</div>

</body>
</html>"#,
            case_number = html_escape(&case.case_number),
            evidence_id = html_escape(&case.evidence_id),
            examiner = html_escape(&case.examiner),
            description = html_escape(&case.description),
            started_at = audit_log.started_at.format("%Y-%m-%d %H:%M:%S UTC"),
            report_time = now,
            tool_version = html_escape(&audit_log.tool_version),
            image_path = html_escape(image_path),
            image_hash = image_sha256.unwrap_or("not computed"),
            actions = actions_html,
            files = files_html,
            file_count = recovered_files.len(),
        )
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensic::audit::{AuditAction, AuditLog, CaseInfo};

    fn test_log() -> AuditLog {
        let mut log = AuditLog::new(CaseInfo {
            examiner: "Kyle Quinlan".into(),
            case_number: "SECLAB-2026-042".into(),
            evidence_id: "IMG-001".into(),
            description: "Recovery of reiner server disk".into(),
        });
        log.log(AuditAction::ImageOpened {
            path: "/projects/reiner-recovery/reiner-sda.img".into(),
            size: 2_730_000_000_000,
            sha256: Some("abcdef1234567890".into()),
        });
        log.log(AuditAction::ScanCompleted {
            partitions: 3,
            filesystems: 2,
        });
        log
    }

    #[test]
    fn test_report_generation() {
        let log = test_log();
        let files = vec![RecoveredFile {
            path: "/home/user/document.pdf".into(),
            size: 45000,
            sha256: "deadbeef".into(),
        }];

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.html");

        ForensicReport::generate(&log, "/dev/sda", Some("abcdef"), &files, &path).unwrap();

        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("SECLAB-2026-042"));
        assert!(html.contains("Kyle Quinlan"));
        assert!(html.contains("document.pdf"));
        assert!(html.contains("deadbeef"));
        assert!(html.contains("NIST SP 800-86"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert('xss')&lt;/script&gt;"
        );
    }

    #[test]
    fn test_empty_report() {
        let log = AuditLog::new(CaseInfo {
            examiner: "Test".into(),
            case_number: "T-001".into(),
            evidence_id: "E-001".into(),
            description: "Empty test".into(),
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.html");

        ForensicReport::generate(&log, "test.img", None, &[], &path).unwrap();

        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("Recovered Files (0)"));
    }
}
