use std::io::Write;
use std::path::PathBuf;

use tempfile::NamedTempFile;

use recovermax_core::fs::FsInfo;
use recovermax_core::io::ImageReader;
use recovermax_core::scan::{Partition, ScanReport};
use recovermax_core::search::SearchOptions;
use recovermax_core::session::{
    FilesystemSessionArtifact, RecoverySession, RecoverySessionArtifact, ScanImageSource,
};

fn create_test_image() -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&[0u8; 4096]).unwrap();
    file.flush().unwrap();
    file
}

fn report_only_artifact(image_path: &std::path::Path) -> RecoverySessionArtifact {
    RecoverySessionArtifact {
        version: RecoverySessionArtifact::VERSION,
        source: ScanImageSource {
            path: image_path.to_path_buf(),
            image_size: 4096,
        },
        report: ScanReport {
            image_size: 4096,
            partitions: vec![Partition {
                name: "p1".to_string(),
                offset: 0,
                size: 4096,
                fs_type: "Linux".to_string(),
            }],
            filesystems: vec![FsInfo {
                fs_type: "ext4".to_string(),
                label: "report-only".to_string(),
                uuid: "22222222-3333-4444-5555-666666666666".to_string(),
                block_size: 4096,
                total_size: 4096,
                offset: 0,
                    lvm_map: None,
            }],
        },
        filesystems: vec![FilesystemSessionArtifact {
            filesystem_index: 0,
            fs_info: FsInfo {
                fs_type: "ext4".to_string(),
                label: "report-only".to_string(),
                uuid: "22222222-3333-4444-5555-666666666666".to_string(),
                block_size: 4096,
                total_size: 4096,
                offset: 0,
                    lvm_map: None,
            },
            root_node_id: None,
            warnings: Vec::new(),
            nodes: Vec::new(),
        }],
    }
}

#[test]
fn report_only_artifact_roundtrips_without_losing_metadata() {
    let image = create_test_image();
    let artifact = report_only_artifact(image.path());

    let path = PathBuf::from(image.path()).with_extension("scn");
    artifact.save_to_path(&path).unwrap();

    let loaded = RecoverySessionArtifact::load_from_path(&path).unwrap();
    assert_eq!(loaded.source_path().unwrap(), image.path());
    assert_eq!(loaded.report.filesystems.len(), 1);
    assert_eq!(loaded.filesystems.len(), 1);
    assert_eq!(loaded.filesystems[0].fs_info.label, "report-only");
    assert!(!loaded.filesystems[0].has_tree());
    assert_eq!(loaded.filesystems[0].nodes.len(), 0);
}

#[test]
fn report_only_session_has_predictable_degraded_runtime_behavior() {
    let image = create_test_image();
    let reader = ImageReader::open(image.path()).unwrap();
    let artifact = report_only_artifact(image.path());
    let mut session = RecoverySession::from_artifact_with_reader(artifact, reader, None);

    assert_eq!(session.filesystems().len(), 1);
    assert!(!session.filesystems()[0].has_tree());

    let cache = session.cache_summary();
    assert!(!cache.node_index_loaded);
    assert!(!cache.path_index_loaded);
    assert!(!cache.children_index_loaded);

    let search_matches = session.search("anything", &SearchOptions::default());
    assert!(search_matches.is_empty());

    assert!(session.resolve_node(0, "/").is_err());
    assert!(session.list_children(0, "/").is_err());
    assert!(session.walk_tree(0, "/", 8).is_err());
}

#[test]
fn filesystem_warnings_match_structured_and_legacy_paths() {
    let image = create_test_image();
    let mut artifact = report_only_artifact(image.path());
    artifact.filesystems[0].warnings = vec![
        "path /: failed to read root directory: short read".to_string(),
        "failed to read directory /broken (inode 12): io error".to_string(),
    ];

    let filesystem = &artifact.filesystems[0];
    assert_eq!(
        filesystem.warnings_for_path("/"),
        vec!["path /: failed to read root directory: short read"]
    );
    assert_eq!(
        filesystem.warnings_for_path("/broken"),
        vec!["failed to read directory /broken (inode 12): io error"]
    );
}
