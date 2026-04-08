use recovermax_core::fs::{EntrySource, FileType, FsInfo};
use recovermax_core::scan::{Partition, ScanReport};
use recovermax_core::search::SearchOptions;
use recovermax_core::session::{
    FilesystemSessionArtifact, RecoverySession, RecoverySessionArtifact, ScanImageSource,
    SessionNode,
};
use std::path::PathBuf;

fn synthetic_artifact() -> RecoverySessionArtifact {
    RecoverySessionArtifact {
        version: RecoverySessionArtifact::VERSION,
        source: ScanImageSource {
            path: PathBuf::from("/tmp/synthetic-ext4.img"),
            image_size: 8 * 1024 * 1024,
        },
        report: ScanReport {
            image_size: 8 * 1024 * 1024,
            partitions: vec![Partition {
                name: "p1".to_string(),
                offset: 0,
                size: 8 * 1024 * 1024,
                fs_type: "Linux".to_string(),
            }],
            filesystems: vec![FsInfo {
                fs_type: "ext4".to_string(),
                label: "synthetic-ext4".to_string(),
                uuid: "11111111-2222-3333-4444-555555555555".to_string(),
                block_size: 4096,
                total_size: 8 * 1024 * 1024,
                offset: 0,
                    lvm_map: None,
            }],
        },
        filesystems: vec![FilesystemSessionArtifact {
            filesystem_index: 0,
            fs_info: FsInfo {
                fs_type: "ext4".to_string(),
                label: "synthetic-ext4".to_string(),
                uuid: "11111111-2222-3333-4444-555555555555".to_string(),
                block_size: 4096,
                total_size: 8 * 1024 * 1024,
                offset: 0,
                    lvm_map: None,
            },
            root_node_id: Some(1),
            warnings: Vec::new(),
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
                    inode: Some(12),
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
                    inode: Some(13),
                    basename: "notes.txt".to_string(),
                    path: "/home/notes.txt".to_string(),
                    file_type: FileType::RegularFile,
                    deleted: false,
                    size: Some(17),
                    source: EntrySource::Filesystem,
                    parent_inode: Some(12),
                    timestamps: None,
                },
            ],
        }],
    }
}

#[test]
fn runtime_cache_warms_unloads_and_rebuilds() {
    let artifact = synthetic_artifact();
    let mut session = RecoverySession::from_artifact(artifact, Some(1024 * 1024));

    let cold = session.cache_summary();
    assert!(!cold.node_index_loaded);
    assert!(!cold.path_index_loaded);
    assert!(!cold.children_index_loaded);

    let children = session.list_children(0, "/").unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].path, "/home");

    let warm = session.cache_summary();
    assert!(warm.node_index_loaded);
    assert!(warm.path_index_loaded);
    assert!(warm.children_index_loaded);

    session.unload_caches();
    let unloaded = session.cache_summary();
    assert!(!unloaded.node_index_loaded);
    assert!(!unloaded.path_index_loaded);
    assert!(!unloaded.children_index_loaded);

    let rebuilt = session.resolve_node(0, "/home/notes.txt").unwrap();
    assert_eq!(rebuilt.id, 3);

    let rewarmed = session.cache_summary();
    assert!(rewarmed.path_index_loaded);
    assert!(rewarmed.node_index_loaded);
}

#[test]
fn runtime_search_and_tree_still_work_after_unload() {
    let artifact = synthetic_artifact();
    let mut session = RecoverySession::from_artifact(artifact, Some(1024 * 1024));

    let initial_matches = session.search("notes", &SearchOptions::default());
    assert_eq!(initial_matches.len(), 1);
    assert_eq!(initial_matches[0].path, "/home/notes.txt");

    let walked = session.walk_tree(0, "/", 8).unwrap();
    assert_eq!(walked.len(), 3);

    session.unload_caches();

    let walked_after_unload = session.walk_tree(0, "/", 8).unwrap();
    assert_eq!(walked_after_unload.len(), 3);

    let node_by_id = session.resolve_node(0, "3").unwrap();
    assert_eq!(node_by_id.path, "/home/notes.txt");
}
