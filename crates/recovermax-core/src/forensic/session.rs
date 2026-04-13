//! Convenience helpers for starting a forensic audit trail around an
//! image recovery workflow.
//!
//! The primitives in `audit`, `hash`, and `report` are fine-grained
//! building blocks. This module bundles the common "begin a forensic
//! session on this image" sequence — CaseInfo construction, AuditLog
//! creation, initial ImageOpened action, optional pre-hash — into one
//! call so CLI and GUI callers don't reimplement the same ten lines.
//!
//! Kept deliberately thin. Anything more specialised (per-file recovery
//! logging, post-recovery verification) stays inline in the caller where
//! it can be tailored.

use std::path::Path;

use anyhow::{Context, Result};

use super::{AuditAction, AuditLog, CaseInfo, ImageHasher};

/// Chain-of-custody inputs gathered from the user at the start of a
/// recovery session. All fields are Options because real CLIs and GUIs
/// may omit them (defaults are substituted); forensic use cases that
/// need every field populated should validate beforehand.
#[derive(Debug, Default, Clone)]
pub struct ForensicIdentity {
    pub examiner: Option<String>,
    pub case_number: Option<String>,
    pub evidence_id: Option<String>,
}

impl ForensicIdentity {
    /// Fold the identity into a `CaseInfo`, applying conventional
    /// "Unknown"/"N/A" defaults where fields are missing. `image` is used
    /// to seed the human-readable description.
    pub fn into_case_info(self, image: &Path) -> CaseInfo {
        CaseInfo {
            examiner: self.examiner.unwrap_or_else(|| "Unknown".into()),
            case_number: self.case_number.unwrap_or_else(|| "N/A".into()),
            evidence_id: self.evidence_id.unwrap_or_else(|| "N/A".into()),
            description: format!("Recovery from {}", image.display()),
        }
    }
}

/// Result of [`start_image_audit`]: the initialised audit log, plus the
/// SHA-256 hash of the image when hashing was requested.
pub struct ImageAudit {
    pub log: AuditLog,
    /// Pre-recovery SHA-256 hash of the source image, if `hash_image`
    /// was true. Caller should keep this to compare against a post-
    /// recovery hash for chain-of-custody verification.
    pub pre_hash: Option<String>,
}

/// Begin an audit trail for a recovery session against `image`.
///
/// - Builds an `AuditLog` from `identity` (filling defaults via
///   [`ForensicIdentity::into_case_info`]).
/// - When `hash_image` is true, computes the image's SHA-256 before
///   anything else and records it in the initial `ImageOpened` action.
///   This establishes the pre-recovery hash for later verification.
/// - Otherwise logs `ImageOpened` with `sha256: None`.
///
/// Fails only on `std::fs::metadata` or hashing errors — both are
/// readily surfaceable as user-facing errors ("couldn't stat image",
/// "couldn't hash image").
pub fn start_image_audit(
    image: &Path,
    identity: ForensicIdentity,
    hash_image: bool,
) -> Result<ImageAudit> {
    let case_info = identity.into_case_info(image);
    let mut log = AuditLog::new(case_info);

    let size = std::fs::metadata(image)
        .with_context(|| format!("failed to stat {}", image.display()))?
        .len();

    let pre_hash = if hash_image {
        let hash = ImageHasher::hash_file(image)
            .with_context(|| format!("failed to hash {}", image.display()))?;
        log.log(AuditAction::ImageOpened {
            path: image.display().to_string(),
            size,
            sha256: Some(hash.clone()),
        });
        Some(hash)
    } else {
        log.log(AuditAction::ImageOpened {
            path: image.display().to_string(),
            size,
            sha256: None,
        });
        None
    };

    Ok(ImageAudit { log, pre_hash })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn identity_fills_defaults() {
        let id = ForensicIdentity::default();
        let info = id.into_case_info(Path::new("/tmp/x.img"));
        assert_eq!(info.examiner, "Unknown");
        assert_eq!(info.case_number, "N/A");
        assert_eq!(info.evidence_id, "N/A");
        assert!(info.description.contains("/tmp/x.img"));
    }

    #[test]
    fn identity_preserves_supplied_values() {
        let id = ForensicIdentity {
            examiner: Some("K. Quinlan".into()),
            case_number: Some("2026-042".into()),
            evidence_id: Some("DISK-07".into()),
        };
        let info = id.into_case_info(Path::new("/evidence/disk07.img"));
        assert_eq!(info.examiner, "K. Quinlan");
        assert_eq!(info.case_number, "2026-042");
        assert_eq!(info.evidence_id, "DISK-07");
    }

    #[test]
    fn start_audit_without_hash_logs_image_opened_and_no_hash() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();

        let audit = start_image_audit(
            tmp.path(),
            ForensicIdentity::default(),
            /* hash_image */ false,
        )
        .unwrap();

        assert!(audit.pre_hash.is_none());
        assert_eq!(audit.log.entries.len(), 1);
        assert!(
            matches!(&audit.log.entries[0].action, AuditAction::ImageOpened { sha256: None, size, .. } if *size == 11),
            "expected ImageOpened with no hash and size=11, got {:?}",
            audit.log.entries[0],
        );
    }

    #[test]
    fn start_audit_with_hash_records_sha256() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"deterministic bytes").unwrap();

        let audit = start_image_audit(
            tmp.path(),
            ForensicIdentity::default(),
            /* hash_image */ true,
        )
        .unwrap();

        assert!(audit.pre_hash.is_some());
        assert_eq!(audit.pre_hash.as_ref().unwrap().len(), 64); // sha256 hex
        match &audit.log.entries[0].action {
            AuditAction::ImageOpened {
                sha256: Some(recorded_hash),
                ..
            } => {
                assert_eq!(recorded_hash.as_str(), audit.pre_hash.as_deref().unwrap());
            }
            other => panic!("expected ImageOpened with sha256, got {:?}", other),
        }
    }
}
