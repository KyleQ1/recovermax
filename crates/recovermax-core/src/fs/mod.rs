pub mod ext4;
pub mod ntfs;

use serde::{Deserialize, Serialize};

/// Detected filesystem information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsInfo {
    pub fs_type: String,
    pub label: String,
    pub uuid: String,
    pub block_size: u32,
    pub total_size: u64,
    pub offset: u64,
}

/// A recovered directory entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirEntry {
    pub inode: u64,
    pub name: String,
    pub file_type: FileType,
    pub size: u64,
    pub deleted: bool,
    #[serde(default)]
    pub source: EntrySource,
    #[serde(default)]
    pub parent_inode: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EntrySource {
    #[default]
    Filesystem,
    DeletedSlack,
    SyntheticOrphan,
}

/// Trait for filesystem-specific parsers
pub trait FilesystemParser {
    fn detect(data: &[u8], offset: u64) -> Option<FsInfo>;
    fn list_dir(&self, inode: u64) -> anyhow::Result<Vec<DirEntry>>;
    fn read_file(&self, inode: u64) -> anyhow::Result<Vec<u8>>;
    fn walk_deleted(&self) -> anyhow::Result<Vec<DirEntry>>;
}
