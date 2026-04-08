use std::fs;
use std::io::Write;
use std::path::PathBuf;

use recovermax_core::fs::FsInfo;
use recovermax_core::scan::{Partition, ScanReport};
use recovermax_core::session::{RecoverySessionArtifact, ScanImageSource};
use tempfile::TempDir;

fn sample_report(image_size: u64) -> ScanReport {
    ScanReport {
        image_size,
        partitions: vec![Partition {
            name: "p1".to_string(),
            offset: 0,
            size: image_size,
            fs_type: "Linux".to_string(),
        }],
        filesystems: vec![FsInfo {
            fs_type: "ext4".to_string(),
            label: "path-test".to_string(),
            uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
            block_size: 4096,
            total_size: image_size,
            offset: 0,
        }],
    }
}

#[test]
fn from_report_canonicalizes_existing_image_path() {
    let dir = TempDir::new().unwrap();
    let image_path = dir.path().join("image.dd");
    let mut image = fs::File::create(&image_path).unwrap();
    image.write_all(&[0u8; 4096]).unwrap();
    image.flush().unwrap();

    let artifact = RecoverySessionArtifact::from_report(&image_path, sample_report(4096));
    let saved_path = artifact.source_path().unwrap();

    assert!(saved_path.is_absolute());
    assert_eq!(saved_path, fs::canonicalize(&image_path).unwrap());
}

#[test]
fn relative_saved_image_path_resolves_against_artifact_location() {
    let dir = TempDir::new().unwrap();
    let image_path = dir.path().join("image.dd");
    let artifact_path = dir.path().join("session.scn");
    let mut image = fs::File::create(&image_path).unwrap();
    image.write_all(&[0u8; 4096]).unwrap();
    image.flush().unwrap();

    let artifact = RecoverySessionArtifact {
        version: RecoverySessionArtifact::VERSION,
        source: ScanImageSource {
            path: PathBuf::from("image.dd"),
            image_size: 4096,
        },
        report: sample_report(4096),
        filesystems: Vec::new(),
    };
    artifact.save_to_path(&artifact_path).unwrap();

    let loaded = RecoverySessionArtifact::load_from_path(&artifact_path).unwrap();
    let resolved = loaded.resolved_source_path(Some(&artifact_path)).unwrap();
    assert_eq!(resolved, fs::canonicalize(&image_path).unwrap());
    loaded
        .validate_for_image_with_artifact_path(
            &fs::canonicalize(&image_path).unwrap(),
            4096,
            Some(&artifact_path),
        )
        .unwrap();
}

#[test]
fn cwd_relative_saved_image_path_resolves_without_artifact_duplication() {
    let repo_root = std::env::current_dir().unwrap();
    let dir = tempfile::Builder::new()
        .prefix("recovermax-session-path-")
        .tempdir_in(&repo_root)
        .unwrap();
    let image_path = dir.path().join("image.dd");
    let artifact_dir = dir.path().join("sessions");
    let artifact_path = artifact_dir.join("session.scn");
    fs::create_dir_all(&artifact_dir).unwrap();

    let mut image = fs::File::create(&image_path).unwrap();
    image.write_all(&[0u8; 4096]).unwrap();
    image.flush().unwrap();

    let relative_image_path = image_path.strip_prefix(&repo_root).unwrap().to_path_buf();
    assert!(relative_image_path.is_relative());

    let artifact = RecoverySessionArtifact {
        version: RecoverySessionArtifact::VERSION,
        source: ScanImageSource {
            path: relative_image_path,
            image_size: 4096,
        },
        report: sample_report(4096),
        filesystems: Vec::new(),
    };
    artifact.save_to_path(&artifact_path).unwrap();

    let loaded = RecoverySessionArtifact::load_from_path(&artifact_path).unwrap();
    let resolved = loaded.resolved_source_path(Some(&artifact_path)).unwrap();
    assert_eq!(resolved, fs::canonicalize(&image_path).unwrap());
    loaded
        .validate_for_image_with_artifact_path(&image_path, 4096, Some(&artifact_path))
        .unwrap();
}
