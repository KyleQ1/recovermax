use std::io::Write;

use recovermax_core::fs::{EntrySource, FileType, FsInfo};
use recovermax_core::io::ImageReader;
use recovermax_core::scan::ScanReport;
use recovermax_core::search::SearchOptions;
use recovermax_core::session::{
    FilesystemSessionArtifact, RecoverySession, RecoverySessionArtifact, SessionNode,
};
use tempfile::NamedTempFile;

fn create_test_image() -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(&[0u8; 4096]).unwrap();
    f.flush().unwrap();
    f
}

fn synthetic_session_artifact(image_path: &std::path::Path) -> RecoverySessionArtifact {
    let fs_info = FsInfo {
        fs_type: "ext4".to_string(),
        label: "session-cache".to_string(),
        uuid: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
        block_size: 4096,
        total_size: 4096,
        offset: 0,
    };

    let report = ScanReport {
        image_size: 4096,
        partitions: vec![],
        filesystems: vec![fs_info.clone()],
    };

    RecoverySessionArtifact {
        version: RecoverySessionArtifact::VERSION,
        source: recovermax_core::session::ScanImageSource {
            path: image_path.to_path_buf(),
            image_size: 4096,
        },
        report,
        filesystems: vec![FilesystemSessionArtifact {
            filesystem_index: 0,
            fs_info,
            root_node_id: Some(1),
            nodes: vec![
                SessionNode {
                    id: 1,
                    parent_id: None,
                    filesystem_index: 0,
                    inode: Some(2),
                    basename: "/".to_string(),
                    path: "/".to_string(),
                    file_type: FileType::Directory,
                    deleted: false,
                    size: Some(4096),
                    source: EntrySource::Filesystem,
                    parent_inode: None,
                    timestamps: None,
                },
                SessionNode {
                    id: 2,
                    parent_id: Some(1),
                    filesystem_index: 0,
                    inode: Some(11),
                    basename: "home".to_string(),
                    path: "/home".to_string(),
                    file_type: FileType::Directory,
                    deleted: false,
                    size: Some(4096),
                    source: EntrySource::Filesystem,
                    parent_inode: Some(2),
                    timestamps: None,
                },
                SessionNode {
                    id: 3,
                    parent_id: Some(2),
                    filesystem_index: 0,
                    inode: Some(12),
                    basename: "ming".to_string(),
                    path: "/home/ming".to_string(),
                    file_type: FileType::Directory,
                    deleted: false,
                    size: Some(4096),
                    source: EntrySource::Filesystem,
                    parent_inode: Some(11),
                    timestamps: None,
                },
                SessionNode {
                    id: 4,
                    parent_id: Some(3),
                    filesystem_index: 0,
                    inode: Some(13),
                    basename: "notes.txt".to_string(),
                    path: "/home/ming/notes.txt".to_string(),
                    file_type: FileType::RegularFile,
                    deleted: false,
                    size: Some(128),
                    source: EntrySource::Filesystem,
                    parent_inode: Some(12),
                    timestamps: None,
                },
            ],
        }],
    }
}

#[test]
fn session_cache_lazily_builds_and_rebuilds_after_unload() {
    let image = create_test_image();
    let reader = ImageReader::open(image.path()).unwrap();
    let artifact = synthetic_session_artifact(image.path());
    let mut session = RecoverySession::from_artifact_with_reader(artifact, reader, None);

    let initial = session.cache_summary();
    assert!(!initial.node_index_loaded);
    assert!(!initial.path_index_loaded);
    assert!(!initial.children_index_loaded);

    let children = session.list_children(0, "/").unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].basename, "home");

    let warmed = session.cache_summary();
    assert!(warmed.node_index_loaded);
    assert!(warmed.path_index_loaded);
    assert!(warmed.children_index_loaded);

    let tree = session.walk_tree(0, "/", 4).unwrap();
    assert_eq!(tree.len(), 4);
    assert_eq!(tree[0].node.path, "/");
    assert_eq!(tree[1].node.path, "/home");

    let matches = session.search("ming", &SearchOptions::default());
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().any(|m| m.path == "/home/ming"));

    session.unload_caches();
    let unloaded = session.cache_summary();
    assert!(!unloaded.node_index_loaded);
    assert!(!unloaded.path_index_loaded);
    assert!(!unloaded.children_index_loaded);

    let after_unload = session.list_children(0, "/").unwrap();
    assert_eq!(after_unload.len(), 1);

    let rebuilt = session.cache_summary();
    assert!(rebuilt.node_index_loaded);
    assert!(rebuilt.path_index_loaded);
    assert!(rebuilt.children_index_loaded);
}

#[test]
fn session_resolve_node_roundtrips_root_and_child_paths() {
    let image = create_test_image();
    let reader = ImageReader::open(image.path()).unwrap();
    let artifact = synthetic_session_artifact(image.path());
    let mut session = RecoverySession::from_artifact_with_reader(artifact, reader, None);

    let root = session.resolve_node(0, "/").unwrap();
    assert_eq!(root.path, "/");
    assert_eq!(root.file_type, FileType::Directory);

    let child = session.resolve_node(0, "/home/ming/notes.txt").unwrap();
    assert_eq!(child.basename, "notes.txt");
    assert_eq!(child.file_type, FileType::RegularFile);
}
