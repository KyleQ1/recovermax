use std::io::Write;
use tempfile::NamedTempFile;

use recovermax_core::fs::{EntrySource, FileType, FsInfo};
use recovermax_core::io::ImageReader;
use recovermax_core::scan::{ScanArtifact, ScanReport, Scanner};
use recovermax_core::session::RecoverySessionArtifact;
use serde::{Deserialize, Serialize};

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn build_ext4_superblock(label: &str, log_block_size: u32, blocks_count: u32) -> Vec<u8> {
    let mut img = vec![0u8; 4 * 1024 * 1024];
    let sb = 1024;

    img[sb..sb + 4].copy_from_slice(&128u32.to_le_bytes());
    img[sb + 0x04..sb + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    img[sb + 0x0C..sb + 0x10].copy_from_slice(&(blocks_count / 2).to_le_bytes());
    img[sb + 0x10..sb + 0x14].copy_from_slice(&64u32.to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    img[sb + 0x18..sb + 0x1C].copy_from_slice(&log_block_size.to_le_bytes());
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&128u32.to_le_bytes());
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&256u16.to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
    img[sb + 0x68..sb + 0x78]
        .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    let name_bytes = label.as_bytes();
    let len = name_bytes.len().min(16);
    img[sb + 0x78..sb + 0x78 + len].copy_from_slice(&name_bytes[..len]);
    img[sb + 0x150..sb + 0x154].copy_from_slice(&0u32.to_le_bytes());

    img
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RichRecoverySessionArtifact {
    version: u32,
    source: RichScanImageSource,
    report: ScanReport,
    filesystems: Vec<RichFilesystemSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RichScanImageSource {
    path: String,
    image_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RichFilesystemSession {
    fs_info: FsInfo,
    root_node_id: u64,
    nodes: Vec<RichSessionNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RichSessionNode {
    id: u64,
    parent_id: Option<u64>,
    filesystem_index: usize,
    inode: Option<u64>,
    basename: String,
    path: String,
    file_type: FileType,
    deleted: bool,
    size: Option<u64>,
}

fn assert_tree_paths(nodes: &[RichSessionNode]) {
    for node in nodes {
        if node.path == "/" {
            assert!(
                node.parent_id.is_none(),
                "root node should not have a parent"
            );
            continue;
        }

        assert!(node.path.starts_with('/'));
        assert_eq!(node.path.rsplit('/').next().unwrap(), node.basename);
        if let Some(parent_id) = node.parent_id {
            let parent = nodes
                .iter()
                .find(|candidate| candidate.id == parent_id)
                .unwrap();
            let expected_prefix = if parent.path == "/" {
                format!("/{}", node.basename)
            } else {
                format!("{}/{}", parent.path.trim_end_matches('/'), node.basename)
            };
            assert_eq!(node.path, expected_prefix);
        }
    }
}

#[test]
fn rich_session_artifact_roundtrip_preserves_flat_tree() {
    let img = build_ext4_superblock("rich-session", 1, 2048);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();
    let fs_info = report.filesystems[0].clone();

    let artifact = RichRecoverySessionArtifact {
        version: 2,
        source: RichScanImageSource {
            path: f.path().display().to_string(),
            image_size: report.image_size,
        },
        report: report.clone(),
        filesystems: vec![RichFilesystemSession {
            fs_info,
            root_node_id: 1,
            nodes: vec![
                RichSessionNode {
                    id: 1,
                    parent_id: None,
                    filesystem_index: 0,
                    inode: Some(2),
                    basename: "/".to_string(),
                    path: "/".to_string(),
                    file_type: FileType::Directory,
                    deleted: false,
                    size: Some(4096),
                },
                RichSessionNode {
                    id: 2,
                    parent_id: Some(1),
                    filesystem_index: 0,
                    inode: Some(11),
                    basename: "home".to_string(),
                    path: "/home".to_string(),
                    file_type: FileType::Directory,
                    deleted: false,
                    size: Some(4096),
                },
                RichSessionNode {
                    id: 3,
                    parent_id: Some(2),
                    filesystem_index: 0,
                    inode: Some(12),
                    basename: "ming".to_string(),
                    path: "/home/ming".to_string(),
                    file_type: FileType::Directory,
                    deleted: false,
                    size: Some(4096),
                },
                RichSessionNode {
                    id: 4,
                    parent_id: Some(3),
                    filesystem_index: 0,
                    inode: Some(13),
                    basename: "notes.txt".to_string(),
                    path: "/home/ming/notes.txt".to_string(),
                    file_type: FileType::RegularFile,
                    deleted: false,
                    size: Some(128),
                },
            ],
        }],
    };

    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let loaded: RichRecoverySessionArtifact = serde_json::from_str(&json).unwrap();

    assert_eq!(loaded.version, 2);
    assert_eq!(loaded.source.image_size, report.image_size);
    assert_eq!(loaded.report.filesystems[0].label, "rich-session");
    assert_eq!(loaded.filesystems[0].nodes.len(), 4);
    assert_tree_paths(&loaded.filesystems[0].nodes);
}

#[test]
fn v1_scan_artifact_json_still_loads_through_current_api() {
    let v1_json = r#"{
        "version": 1,
        "source": {
            "path": "/images/legacy.img",
            "image_size": 4096
        },
        "report": {
            "image_size": 4096,
            "partitions": [],
            "filesystems": [
                {
                    "fs_type": "ext4",
                    "label": "legacy",
                    "uuid": "00112233-4455-6677-8899-aabbccddeeff",
                    "block_size": 1024,
                    "total_size": 4096,
                    "offset": 0
                }
            ]
        }
    }"#;

    let loaded = ScanArtifact::from_json_str(v1_json).unwrap();

    assert_eq!(loaded.version, ScanArtifact::VERSION);
    assert_eq!(loaded.source.image_size, 4096);
    assert_eq!(
        loaded.source_path().unwrap(),
        std::path::Path::new("/images/legacy.img")
    );
    assert_eq!(loaded.report.filesystems[0].label, "legacy");
}

#[test]
fn synthetic_session_tree_paths_remain_consistent() {
    let nodes = vec![
        RichSessionNode {
            id: 1,
            parent_id: None,
            filesystem_index: 0,
            inode: Some(2),
            basename: "/".to_string(),
            path: "/".to_string(),
            file_type: FileType::Directory,
            deleted: false,
            size: Some(4096),
        },
        RichSessionNode {
            id: 2,
            parent_id: Some(1),
            filesystem_index: 0,
            inode: Some(11),
            basename: "data".to_string(),
            path: "/data".to_string(),
            file_type: FileType::Directory,
            deleted: false,
            size: Some(4096),
        },
        RichSessionNode {
            id: 3,
            parent_id: Some(2),
            filesystem_index: 0,
            inode: Some(12),
            basename: "ming".to_string(),
            path: "/data/ming".to_string(),
            file_type: FileType::Directory,
            deleted: false,
            size: Some(4096),
        },
        RichSessionNode {
            id: 4,
            parent_id: Some(3),
            filesystem_index: 0,
            inode: Some(13),
            basename: "report.txt".to_string(),
            path: "/data/ming/report.txt".to_string(),
            file_type: FileType::RegularFile,
            deleted: false,
            size: Some(512),
        },
    ];

    assert_tree_paths(&nodes);
    assert_eq!(
        nodes
            .iter()
            .find(|node| node.path == "/data/ming/report.txt")
            .unwrap()
            .basename,
        "report.txt"
    );
}

#[test]
fn v2_session_json_without_new_provenance_fields_still_loads() {
    let json = r#"{
        "version": 2,
        "source": {
            "path": "/images/session.scn",
            "image_size": 4096
        },
        "report": {
            "image_size": 4096,
            "partitions": [],
            "filesystems": [
                {
                    "fs_type": "ext4",
                    "label": "legacy-v2",
                    "uuid": "00112233-4455-6677-8899-aabbccddeeff",
                    "block_size": 1024,
                    "total_size": 4096,
                    "offset": 0
                }
            ]
        },
        "filesystems": [
            {
                "filesystem_index": 0,
                "fs_info": {
                    "fs_type": "ext4",
                    "label": "legacy-v2",
                    "uuid": "00112233-4455-6677-8899-aabbccddeeff",
                    "block_size": 1024,
                    "total_size": 4096,
                    "offset": 0
                },
                "root_node_id": 1,
                "nodes": [
                    {
                        "id": 1,
                        "parent_id": null,
                        "filesystem_index": 0,
                        "inode": 2,
                        "basename": "/",
                        "path": "/",
                        "file_type": "Directory",
                        "deleted": false,
                        "size": 4096,
                        "timestamps": {
                            "created_unix": 10,
                            "modified_unix": 20,
                            "accessed_unix": 30
                        }
                    },
                    {
                        "id": 2,
                        "parent_id": 1,
                        "filesystem_index": 0,
                        "inode": null,
                        "basename": "ghost.txt",
                        "path": "/ghost.txt",
                        "file_type": "RegularFile",
                        "deleted": true,
                        "size": null
                    }
                ]
            }
        ]
    }"#;

    let artifact = RecoverySessionArtifact::from_json_str(json).unwrap();
    let root = &artifact.filesystems[0].nodes[0];
    assert_eq!(root.source, EntrySource::Filesystem);
    assert_eq!(root.parent_inode, None);
    assert_eq!(
        root.timestamps
            .as_ref()
            .and_then(|timestamps| timestamps.deleted_unix),
        None
    );

    let ghost = &artifact.filesystems[0].nodes[1];
    assert_eq!(ghost.source, EntrySource::Filesystem);
    assert_eq!(ghost.parent_inode, None);
    assert!(ghost.timestamps.is_none());
}
