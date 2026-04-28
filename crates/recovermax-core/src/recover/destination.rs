use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Result};

/// Convert a recovered filesystem path into a safe path relative to the
/// recovery destination.
///
/// Recovery metadata is attacker-controlled input: damaged filesystems and
/// third-party scan artifacts can contain absolute paths, parent traversal, or
/// Windows drive prefixes. Never join those strings directly onto an output
/// directory.
pub fn sanitize_recovery_path(path: &str) -> Result<PathBuf> {
    ensure!(!path.is_empty(), "recovery path is empty");
    ensure!(!path.contains('\0'), "recovery path contains a NUL byte");

    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');
    ensure!(
        !trimmed.is_empty(),
        "recovery path has no relative components"
    );

    let mut safe = PathBuf::new();
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            bail!("recovery path escapes destination: {path}");
        }
        if is_windows_drive_prefix(segment) {
            bail!("recovery path contains a Windows drive prefix: {path}");
        }
        safe.push(segment);
    }

    ensure!(
        !safe.as_os_str().is_empty(),
        "recovery path has no safe relative components"
    );
    Ok(safe)
}

pub fn safe_destination_path(destination: &Path, recovered_path: &str) -> Result<PathBuf> {
    Ok(destination.join(sanitize_recovery_path(recovered_path)?))
}

pub fn next_available_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    for index in 1u64.. {
        let candidate = with_collision_suffix(path, index);
        if !candidate.exists() {
            return candidate;
        }
    }

    unreachable!("u64 collision suffix space exhausted")
}

fn with_collision_suffix(path: &Path, index: u64) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("Recovered");
    let extension = path.extension().and_then(|extension| extension.to_str());
    let filename = match extension {
        Some(extension) if !extension.is_empty() => format!("{stem} ({index}).{extension}"),
        _ => format!("{stem} ({index})"),
    };
    parent.join(filename)
}

fn is_windows_drive_prefix(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.len() == 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_paths_are_made_relative() {
        assert_eq!(
            sanitize_recovery_path("/Users/alice/Documents/report.txt").unwrap(),
            PathBuf::from("Users/alice/Documents/report.txt")
        );
    }

    #[test]
    fn windows_separators_are_normalized() {
        assert_eq!(
            sanitize_recovery_path(r"Users\alice\Desktop\photo.jpg").unwrap(),
            PathBuf::from("Users/alice/Desktop/photo.jpg")
        );
    }

    #[test]
    fn parent_traversal_is_rejected() {
        assert!(sanitize_recovery_path("../outside.txt").is_err());
        assert!(sanitize_recovery_path("safe/../../outside.txt").is_err());
    }

    #[test]
    fn windows_drive_prefix_is_rejected() {
        assert!(sanitize_recovery_path("C:/Users/alice/file.txt").is_err());
        assert!(sanitize_recovery_path(r"D:\case\file.txt").is_err());
    }

    #[test]
    fn malformed_empty_or_nul_paths_are_rejected() {
        assert!(sanitize_recovery_path("").is_err());
        assert!(sanitize_recovery_path("/").is_err());
        assert!(sanitize_recovery_path("safe/\0/name").is_err());
    }

    #[test]
    fn safe_destination_stays_under_destination() {
        let destination = Path::new("/tmp/recovermax-out");
        assert_eq!(
            safe_destination_path(destination, "/root/file.txt").unwrap(),
            PathBuf::from("/tmp/recovermax-out/root/file.txt")
        );
    }

    #[test]
    fn collision_paths_use_deterministic_suffixes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("report.txt");
        std::fs::write(&path, b"existing").unwrap();

        assert_eq!(
            next_available_path(&path),
            temp.path().join("report (1).txt")
        );

        std::fs::write(temp.path().join("report (1).txt"), b"existing").unwrap();
        assert_eq!(
            next_available_path(&path),
            temp.path().join("report (2).txt")
        );
    }
}
