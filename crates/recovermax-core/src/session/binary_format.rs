//! Binary .scn file format definitions.
//!
//! The binary session format stores nodes as fixed-size 64-byte records that can be
//! mmap'd and accessed directly without deserialization. String data (basenames) is
//! stored in a deduplicated string table. Paths are not stored — they are computed
//! on demand by walking the parent_index chain.

use bytemuck::{Pod, Zeroable};

use crate::fs::{EntrySource, FileType};

/// File magic bytes identifying a binary .scn file.
pub const SCN_MAGIC: [u8; 8] = *b"RMXSCAN\0";

/// Current binary format version.
pub const SCN_VERSION: u32 = 1;

/// Size of the file header in bytes.
pub const HEADER_SIZE: usize = 256;

/// Size of each CompactNode record in bytes.
pub const NODE_SIZE: usize = 64;

/// Header flags.
pub const FLAG_SCAN_COMPLETE: u32 = 0x01;

/// Binary .scn file header (256 bytes, fixed size).
///
/// Always at offset 0. All numeric fields are little-endian.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ScnHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub flags: u32,

    pub metadata_offset: u64,
    pub metadata_size: u64,
    pub string_table_offset: u64,
    pub string_table_size: u64,
    pub node_records_offset: u64,
    pub node_count: u64,
    pub warnings_offset: u64,
    pub warnings_size: u64,
    pub children_index_offset: u64,
    pub children_index_count: u64,
    pub inode_index_offset: u64,
    pub inode_index_count: u64,

    pub last_scanned_group: u32,
    pub last_scanned_offset_lo: u32,
    pub last_scanned_offset_hi: u32,
    pub filesystem_count: u16,
    pub _pad: u16,

    pub _reserved1: [u8; 64],
    pub _reserved2: [u8; 64],
}

impl ScnHeader {
    pub fn new() -> Self {
        let mut header = Self::zeroed();
        header.magic = SCN_MAGIC;
        header.version = SCN_VERSION;
        header.node_records_offset = HEADER_SIZE as u64;
        header
    }

    pub fn is_valid(&self) -> bool {
        self.magic == SCN_MAGIC && self.version == SCN_VERSION
    }

    pub fn is_complete(&self) -> bool {
        self.flags & FLAG_SCAN_COMPLETE != 0
    }

    pub fn last_scanned_offset(&self) -> u64 {
        (self.last_scanned_offset_hi as u64) << 32 | self.last_scanned_offset_lo as u64
    }

    pub fn set_last_scanned_offset(&mut self, offset: u64) {
        self.last_scanned_offset_lo = offset as u32;
        self.last_scanned_offset_hi = (offset >> 32) as u32;
    }
}

/// Compact node record (64 bytes, fixed size, mmap-castable).
///
/// Stored as a flat array in the .scn file. Each node's `parent_index` points to
/// another node in the same array. Basenames are stored in the string table,
/// referenced by `basename_offset` and `basename_len`. Full paths are computed
/// on demand by walking the parent chain.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CompactNode {
    /// ext4 inode number (0 = synthetic node with no inode).
    pub inode: u64,
    /// Index of parent node in the node array (u32::MAX = no parent / root).
    pub parent_index: u32,
    /// Byte offset of basename in the string table.
    pub basename_offset: u32,
    /// Length of basename in bytes.
    pub basename_len: u16,
    /// Filesystem index (which filesystem this node belongs to).
    pub filesystem_index: u16,
    /// Packed flags: file_type (bits 0-1), deleted (bit 2), source (bits 3-4).
    pub flags: u16,
    pub _pad: u16,
    /// File size in bytes (u64::MAX = unknown).
    pub size: u64,
    /// ext4 parent inode number (0 = unknown).
    pub parent_inode: u64,
    /// Created timestamp (unix epoch seconds, 0 = unknown).
    pub ctime: u32,
    /// Modified timestamp.
    pub mtime: u32,
    /// Accessed timestamp.
    pub atime: u32,
    /// Deleted timestamp.
    pub dtime: u32,
    pub _reserved: [u8; 8],
}

// Flag bit positions
const FILE_TYPE_MASK: u16 = 0b11;
const DELETED_BIT: u16 = 0b100;
const SOURCE_MASK: u16 = 0b11000;
const SOURCE_SHIFT: u16 = 3;

impl CompactNode {
    pub fn encode_flags(file_type: FileType, deleted: bool, source: EntrySource) -> u16 {
        let ft = match file_type {
            FileType::RegularFile => 0,
            FileType::Directory => 1,
            FileType::Symlink => 2,
            FileType::Other => 3,
        };
        let del = if deleted { DELETED_BIT } else { 0 };
        let src = match source {
            EntrySource::Filesystem => 0,
            EntrySource::DeletedSlack => 1,
            EntrySource::SyntheticOrphan => 2,
        } << SOURCE_SHIFT;
        ft | del | src
    }

    pub fn file_type(&self) -> FileType {
        match self.flags & FILE_TYPE_MASK {
            0 => FileType::RegularFile,
            1 => FileType::Directory,
            2 => FileType::Symlink,
            _ => FileType::Other,
        }
    }

    pub fn deleted(&self) -> bool {
        self.flags & DELETED_BIT != 0
    }

    pub fn source(&self) -> EntrySource {
        match (self.flags & SOURCE_MASK) >> SOURCE_SHIFT {
            0 => EntrySource::Filesystem,
            1 => EntrySource::DeletedSlack,
            2 => EntrySource::SyntheticOrphan,
            _ => EntrySource::Filesystem,
        }
    }

    pub fn has_parent(&self) -> bool {
        self.parent_index != u32::MAX
    }
}

/// Entry in the children index. Sorted by parent_index for binary search.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ChildEntry {
    pub parent_index: u32,
    pub child_index: u32,
}

/// Entry in the inode index. Sorted by (filesystem_index, inode) for binary search.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct InodeEntry {
    pub inode: u64,
    pub filesystem_index: u16,
    pub _pad: u16,
    pub node_index: u32,
}

// Compile-time size assertions
const _: () = assert!(std::mem::size_of::<ScnHeader>() == HEADER_SIZE);
const _: () = assert!(std::mem::size_of::<CompactNode>() == NODE_SIZE);
const _: () = assert!(std::mem::size_of::<ChildEntry>() == 8);
const _: () = assert!(std::mem::size_of::<InodeEntry>() == 16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_256() {
        assert_eq!(std::mem::size_of::<ScnHeader>(), 256);
    }

    #[test]
    fn compact_node_size_is_64() {
        assert_eq!(std::mem::size_of::<CompactNode>(), 64);
    }

    #[test]
    fn child_entry_size_is_8() {
        assert_eq!(std::mem::size_of::<ChildEntry>(), 8);
    }

    #[test]
    fn inode_entry_size_is_16() {
        assert_eq!(std::mem::size_of::<InodeEntry>(), 16);
    }

    #[test]
    fn flag_encoding_roundtrips() {
        let flags = CompactNode::encode_flags(FileType::Directory, true, EntrySource::DeletedSlack);
        let node = CompactNode {
            flags,
            ..CompactNode::zeroed()
        };
        assert_eq!(node.file_type(), FileType::Directory);
        assert!(node.deleted());
        assert_eq!(node.source(), EntrySource::DeletedSlack);
    }

    #[test]
    fn flag_encoding_regular_file_not_deleted() {
        let flags = CompactNode::encode_flags(FileType::RegularFile, false, EntrySource::Filesystem);
        let node = CompactNode {
            flags,
            ..CompactNode::zeroed()
        };
        assert_eq!(node.file_type(), FileType::RegularFile);
        assert!(!node.deleted());
        assert_eq!(node.source(), EntrySource::Filesystem);
    }

    #[test]
    fn flag_encoding_symlink_orphan() {
        let flags =
            CompactNode::encode_flags(FileType::Symlink, false, EntrySource::SyntheticOrphan);
        let node = CompactNode {
            flags,
            ..CompactNode::zeroed()
        };
        assert_eq!(node.file_type(), FileType::Symlink);
        assert!(!node.deleted());
        assert_eq!(node.source(), EntrySource::SyntheticOrphan);
    }

    #[test]
    fn header_new_has_correct_magic() {
        let header = ScnHeader::new();
        assert!(header.is_valid());
        assert!(!header.is_complete());
        assert_eq!(header.node_records_offset, 256);
    }

    #[test]
    fn header_last_scanned_offset_roundtrips() {
        let mut header = ScnHeader::new();
        let offset = 0x1_DEAD_BEEF_u64;
        header.set_last_scanned_offset(offset);
        assert_eq!(header.last_scanned_offset(), offset);
    }

    #[test]
    fn parent_index_max_means_no_parent() {
        let node = CompactNode {
            parent_index: u32::MAX,
            ..CompactNode::zeroed()
        };
        assert!(!node.has_parent());

        let node2 = CompactNode {
            parent_index: 42,
            ..CompactNode::zeroed()
        };
        assert!(node2.has_parent());
    }
}
