//! Streaming binary .scn writer.
//!
//! Writes CompactNode records directly to disk during scanning. The string table
//! (deduplicated basenames) accumulates in memory (~50-100 MB for 122M nodes).
//! On finalize, the string table, warnings, and indexes are appended and the
//! header is rewritten with section offsets.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};
use bytemuck;

use super::binary_format::*;
use crate::fs::{EntrySource, FileType};
use crate::session::SessionNode;

/// Streaming writer for binary .scn files.
///
/// Usage:
/// 1. `ScnWriter::create(path)` — creates the file with a header stub
/// 2. `writer.add_node(...)` — appends CompactNode records (streamed to disk)
/// 3. `writer.checkpoint(...)` — updates header with progress (for resume)
/// 4. `writer.finalize(metadata_json)` — writes string table, indexes, final header
pub struct ScnWriter {
    file: BufWriter<File>,
    path: std::path::PathBuf,
    string_table: HashMap<String, u32>,
    string_table_bytes: Vec<u8>,
    node_count: u64,
    warnings: Vec<String>,
    filesystem_count: u16,
    last_scanned_group: u32,
    last_scanned_offset: u64,
    /// Buffer to batch small writes
    node_buffer: Vec<CompactNode>,
}

const NODE_BUFFER_SIZE: usize = 1024;
const CHECKPOINT_INTERVAL: u64 = 10_000;

impl ScnWriter {
    /// Create a new binary .scn file. Writes the 256-byte header placeholder.
    pub fn create(path: &Path) -> Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .context("Failed to create .scn file")?;
        let mut writer = BufWriter::new(file);

        // Write header placeholder (will be rewritten on finalize)
        let header = ScnHeader::new();
        writer.write_all(bytemuck::bytes_of(&header))?;
        writer.flush()?;

        Ok(Self {
            file: writer,
            path: path.to_path_buf(),
            string_table: HashMap::new(),
            string_table_bytes: Vec::new(),
            node_count: 0,
            warnings: Vec::new(),
            filesystem_count: 0,
            last_scanned_group: 0,
            last_scanned_offset: 0,
            node_buffer: Vec::with_capacity(NODE_BUFFER_SIZE),
        })
    }

    /// Intern a basename string, returning (offset, len) into the string table.
    pub fn intern_basename(&mut self, basename: &str) -> (u32, u16) {
        if let Some(&offset) = self.string_table.get(basename) {
            return (offset, basename.len() as u16);
        }
        let offset = self.string_table_bytes.len() as u32;
        self.string_table_bytes.extend_from_slice(basename.as_bytes());
        self.string_table_bytes.push(0); // null terminator
        self.string_table.insert(basename.to_string(), offset);
        (offset, basename.len() as u16)
    }

    /// Add a compact node. Returns the node index.
    pub fn add_compact_node(&mut self, node: CompactNode) -> Result<u32> {
        let index = self.node_count as u32;
        self.node_buffer.push(node);
        self.node_count += 1;

        if self.node_buffer.len() >= NODE_BUFFER_SIZE {
            self.flush_buffer()?;
        }

        // Auto-checkpoint periodically
        if self.node_count % CHECKPOINT_INTERVAL == 0 {
            self.write_checkpoint()?;
        }

        Ok(index)
    }

    /// Add a SessionNode by converting to CompactNode.
    /// `parent_index` is the index of the parent node in the array (u32::MAX for root).
    pub fn add_session_node(
        &mut self,
        node: &SessionNode,
        parent_index: u32,
    ) -> Result<u32> {
        let (basename_offset, basename_len) = self.intern_basename(&node.basename);

        let compact = CompactNode {
            inode: node.inode.unwrap_or(0),
            parent_index,
            basename_offset,
            basename_len,
            filesystem_index: node.filesystem_index as u16,
            flags: CompactNode::encode_flags(node.file_type, node.deleted, node.source),
            _pad: 0,
            size: node.size.unwrap_or(u64::MAX),
            parent_inode: node.parent_inode.unwrap_or(0),
            ctime: node
                .timestamps
                .as_ref()
                .and_then(|t| t.created_unix)
                .unwrap_or(0) as u32,
            mtime: node
                .timestamps
                .as_ref()
                .and_then(|t| t.modified_unix)
                .unwrap_or(0) as u32,
            atime: node
                .timestamps
                .as_ref()
                .and_then(|t| t.accessed_unix)
                .unwrap_or(0) as u32,
            dtime: node
                .timestamps
                .as_ref()
                .and_then(|t| t.deleted_unix)
                .unwrap_or(0) as u32,
            _reserved: [0u8; 8],
        };

        self.add_compact_node(compact)
    }

    /// Add a raw inode entry (used by append_ext4_all_inodes for direct byte-level scanning).
    pub fn add_raw_inode(
        &mut self,
        inode_num: u64,
        parent_index: u32,
        basename: &str,
        filesystem_index: u16,
        file_type: FileType,
        deleted: bool,
        source: EntrySource,
        size: u64,
        parent_inode: u64,
        ctime: u32,
        mtime: u32,
        atime: u32,
        dtime: u32,
    ) -> Result<u32> {
        let (basename_offset, basename_len) = self.intern_basename(basename);

        let compact = CompactNode {
            inode: inode_num,
            parent_index,
            basename_offset,
            basename_len,
            filesystem_index,
            flags: CompactNode::encode_flags(file_type, deleted, source),
            _pad: 0,
            size,
            parent_inode,
            ctime,
            mtime,
            atime,
            dtime,
            _reserved: [0u8; 8],
        };

        self.add_compact_node(compact)
    }

    /// Record a traversal warning.
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Set the filesystem count.
    pub fn set_filesystem_count(&mut self, count: u16) {
        self.filesystem_count = count;
    }

    /// Update resume checkpoint state.
    pub fn set_scan_progress(&mut self, group: u32, offset: u64) {
        self.last_scanned_group = group;
        self.last_scanned_offset = offset;
    }

    /// Get current node count.
    pub fn node_count(&self) -> u64 {
        self.node_count
    }

    /// Get estimated memory usage of the writer itself.
    pub fn estimated_memory_bytes(&self) -> usize {
        self.string_table_bytes.len()
            + self.string_table.len() * 64 // rough HashMap overhead
            + self.node_buffer.len() * NODE_SIZE
            + self.warnings.iter().map(|w| w.len()).sum::<usize>()
    }

    /// Flush buffered nodes to disk.
    fn flush_buffer(&mut self) -> Result<()> {
        if self.node_buffer.is_empty() {
            return Ok(());
        }
        let bytes = bytemuck::cast_slice::<CompactNode, u8>(&self.node_buffer);
        self.file.write_all(bytes)?;
        self.node_buffer.clear();
        Ok(())
    }

    /// Write a checkpoint: flush nodes and update the header with current progress.
    fn write_checkpoint(&mut self) -> Result<()> {
        self.flush_buffer()?;
        self.file.flush()?;

        // Rewrite the header with updated node_count and progress
        let mut header = ScnHeader::new();
        header.node_count = self.node_count;
        header.filesystem_count = self.filesystem_count;
        header.last_scanned_group = self.last_scanned_group;
        header.set_last_scanned_offset(self.last_scanned_offset);
        // Don't set SCAN_COMPLETE flag — this is a checkpoint, not final

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(bytemuck::bytes_of(&header))?;

        // Seek back to the end to continue appending nodes
        self.file.seek(SeekFrom::End(0))?;
        self.file.flush()?;

        Ok(())
    }

    /// Finalize the .scn file: write string table, warnings, build indexes, update header.
    pub fn finalize(mut self, metadata_json: &str) -> Result<()> {
        self.flush_buffer()?;

        let node_records_end = HEADER_SIZE as u64 + self.node_count * NODE_SIZE as u64;

        // Write metadata section (JSON of ScanReport + FsInfo)
        let metadata_offset = node_records_end;
        let metadata_bytes = metadata_json.as_bytes();
        self.file.seek(SeekFrom::Start(metadata_offset))?;
        self.file.write_all(metadata_bytes)?;
        let metadata_size = metadata_bytes.len() as u64;

        // Write string table
        let string_table_offset = metadata_offset + metadata_size;
        self.file.write_all(&self.string_table_bytes)?;
        let string_table_size = self.string_table_bytes.len() as u64;

        // Write warnings as JSON array
        let warnings_offset = string_table_offset + string_table_size;
        let warnings_json = serde_json::to_string(&self.warnings)?;
        self.file.write_all(warnings_json.as_bytes())?;
        let warnings_size = warnings_json.len() as u64;

        // Build and write indexes (children + inode)
        let children_index_offset = warnings_offset + warnings_size;
        let (children_count, inode_count) = self.build_indexes()?;
        let inode_index_offset =
            children_index_offset + children_count * std::mem::size_of::<ChildEntry>() as u64;

        // Rewrite final header
        let mut header = ScnHeader::new();
        header.flags = FLAG_SCAN_COMPLETE;
        header.metadata_offset = metadata_offset;
        header.metadata_size = metadata_size;
        header.string_table_offset = string_table_offset;
        header.string_table_size = string_table_size;
        header.node_count = self.node_count;
        header.warnings_offset = warnings_offset;
        header.warnings_size = warnings_size;
        header.children_index_offset = children_index_offset;
        header.children_index_count = children_count;
        header.inode_index_offset = inode_index_offset;
        header.inode_index_count = inode_count;
        header.filesystem_count = self.filesystem_count;
        header.last_scanned_group = self.last_scanned_group;
        header.set_last_scanned_offset(self.last_scanned_offset);

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(bytemuck::bytes_of(&header))?;
        self.file.flush()?;

        tracing::info!(
            "Binary .scn finalized: {} nodes, {} string table, {} warnings at {}",
            self.node_count,
            bytesize::ByteSize(string_table_size),
            self.warnings.len(),
            self.path.display(),
        );

        Ok(())
    }

    /// Build both indexes by reading nodes back from the file via mmap.
    /// Returns (children_count, inode_count).
    fn build_indexes(&mut self) -> Result<(u64, u64)> {
        self.file.flush()?;

        // Mmap the file to read nodes back efficiently
        let raw_file = self.file.get_ref().try_clone()?;
        let mmap = unsafe { memmap2::Mmap::map(&raw_file) }
            .context("Failed to mmap .scn for index building")?;

        let node_count = self.node_count as usize;
        let nodes_start = HEADER_SIZE;
        let nodes_end = nodes_start + node_count * NODE_SIZE;

        if mmap.len() < nodes_end {
            anyhow::bail!(
                "File too small for {} nodes: {} bytes, need {}",
                node_count,
                mmap.len(),
                nodes_end
            );
        }

        let node_bytes = &mmap[nodes_start..nodes_end];
        let nodes: &[CompactNode] = bytemuck::cast_slice(node_bytes);

        // Build children index
        let mut children: Vec<ChildEntry> = Vec::with_capacity(node_count);
        for (i, node) in nodes.iter().enumerate() {
            if node.has_parent() {
                children.push(ChildEntry {
                    parent_index: node.parent_index,
                    child_index: i as u32,
                });
            }
        }
        children.sort_unstable_by_key(|e| (e.parent_index, e.child_index));

        // Build inode index
        let mut inodes: Vec<InodeEntry> = Vec::with_capacity(node_count);
        for (i, node) in nodes.iter().enumerate() {
            if node.inode != 0 {
                inodes.push(InodeEntry {
                    inode: node.inode,
                    filesystem_index: node.filesystem_index,
                    _pad: 0,
                    node_index: i as u32,
                });
            }
        }
        inodes.sort_unstable_by_key(|e| (e.filesystem_index, e.inode));

        // Drop mmap before writing
        drop(mmap);

        // Write children index
        self.file.seek(SeekFrom::End(0))?;
        let children_bytes = bytemuck::cast_slice::<ChildEntry, u8>(&children);
        self.file.write_all(children_bytes)?;

        // Write inode index
        let inode_bytes = bytemuck::cast_slice::<InodeEntry, u8>(&inodes);
        self.file.write_all(inode_bytes)?;

        Ok((children.len() as u64, inodes.len() as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn writer_creates_valid_header() {
        let f = NamedTempFile::new().unwrap();
        let writer = ScnWriter::create(f.path()).unwrap();
        writer.finalize("{}").unwrap();

        let data = std::fs::read(f.path()).unwrap();
        assert!(data.len() >= HEADER_SIZE);
        assert_eq!(&data[0..8], &SCN_MAGIC);

        let header: &ScnHeader = bytemuck::from_bytes(&data[0..HEADER_SIZE]);
        assert!(header.is_valid());
        assert!(header.is_complete());
        assert_eq!(header.node_count, 0);
    }

    #[test]
    fn writer_streams_nodes() {
        let f = NamedTempFile::new().unwrap();
        let mut writer = ScnWriter::create(f.path()).unwrap();

        let root_idx = writer
            .add_raw_inode(
                2,
                u32::MAX,
                "/",
                0,
                FileType::Directory,
                false,
                EntrySource::Filesystem,
                4096,
                0,
                0,
                0,
                0,
                0,
            )
            .unwrap();
        assert_eq!(root_idx, 0);

        let child_idx = writer
            .add_raw_inode(
                11,
                root_idx,
                "hello.txt",
                0,
                FileType::RegularFile,
                false,
                EntrySource::Filesystem,
                100,
                2,
                1000,
                1001,
                1002,
                0,
            )
            .unwrap();
        assert_eq!(child_idx, 1);

        writer.finalize("{}").unwrap();

        let data = std::fs::read(f.path()).unwrap();
        let header: &ScnHeader = bytemuck::from_bytes(&data[0..HEADER_SIZE]);
        assert_eq!(header.node_count, 2);

        // Read back the nodes
        let nodes_start = header.node_records_offset as usize;
        let node0: &CompactNode =
            bytemuck::from_bytes(&data[nodes_start..nodes_start + NODE_SIZE]);
        assert_eq!(node0.inode, 2);
        assert!(!node0.has_parent());
        assert_eq!(node0.file_type(), FileType::Directory);

        let node1: &CompactNode =
            bytemuck::from_bytes(&data[nodes_start + NODE_SIZE..nodes_start + 2 * NODE_SIZE]);
        assert_eq!(node1.inode, 11);
        assert_eq!(node1.parent_index, 0);
        assert_eq!(node1.file_type(), FileType::RegularFile);
        assert_eq!(node1.size, 100);
        assert_eq!(node1.mtime, 1001);
    }

    #[test]
    fn string_table_deduplicates() {
        let f = NamedTempFile::new().unwrap();
        let mut writer = ScnWriter::create(f.path()).unwrap();

        let (off1, len1) = writer.intern_basename("hello.txt");
        let (off2, len2) = writer.intern_basename("world.txt");
        let (off3, len3) = writer.intern_basename("hello.txt"); // duplicate

        assert_eq!(off1, off3); // same offset
        assert_eq!(len1, len3); // same length
        assert_ne!(off1, off2); // different strings have different offsets

        writer.finalize("{}").unwrap();

        let data = std::fs::read(f.path()).unwrap();
        let header: &ScnHeader = bytemuck::from_bytes(&data[0..HEADER_SIZE]);
        let st_start = header.string_table_offset as usize;
        let st_end = st_start + header.string_table_size as usize;
        let string_table = &data[st_start..st_end];

        // "hello.txt\0world.txt\0" = 20 bytes
        assert_eq!(string_table.len(), 20);
    }

    #[test]
    fn children_index_built_correctly() {
        let f = NamedTempFile::new().unwrap();
        let mut writer = ScnWriter::create(f.path()).unwrap();

        // Root -> child1, child2
        writer
            .add_raw_inode(2, u32::MAX, "/", 0, FileType::Directory, false, EntrySource::Filesystem, 4096, 0, 0, 0, 0, 0)
            .unwrap();
        writer
            .add_raw_inode(11, 0, "a.txt", 0, FileType::RegularFile, false, EntrySource::Filesystem, 10, 2, 0, 0, 0, 0)
            .unwrap();
        writer
            .add_raw_inode(12, 0, "b.txt", 0, FileType::RegularFile, false, EntrySource::Filesystem, 20, 2, 0, 0, 0, 0)
            .unwrap();

        writer.finalize("{}").unwrap();

        let data = std::fs::read(f.path()).unwrap();
        let header: &ScnHeader = bytemuck::from_bytes(&data[0..HEADER_SIZE]);
        assert_eq!(header.children_index_count, 2); // two children of root

        let ci_start = header.children_index_offset as usize;
        // Read entries manually to avoid alignment issues with cast_slice on Vec<u8>
        let e0_parent = u32::from_le_bytes(data[ci_start..ci_start + 4].try_into().unwrap());
        let e0_child = u32::from_le_bytes(data[ci_start + 4..ci_start + 8].try_into().unwrap());
        let e1_parent = u32::from_le_bytes(data[ci_start + 8..ci_start + 12].try_into().unwrap());
        let e1_child = u32::from_le_bytes(data[ci_start + 12..ci_start + 16].try_into().unwrap());
        assert_eq!(e0_parent, 0);
        assert_eq!(e0_child, 1);
        assert_eq!(e1_parent, 0);
        assert_eq!(e1_child, 2);
    }

    #[test]
    fn memory_stays_small() {
        let f = NamedTempFile::new().unwrap();
        let mut writer = ScnWriter::create(f.path()).unwrap();

        // Add 10,000 nodes with repeated basenames
        for i in 0..10_000u32 {
            let basename = format!("file_{}.txt", i % 100); // only 100 unique names
            writer
                .add_raw_inode(
                    i as u64 + 11,
                    0,
                    &basename,
                    0,
                    FileType::RegularFile,
                    false,
                    EntrySource::Filesystem,
                    i as u64 * 100,
                    2,
                    0,
                    0,
                    0,
                    0,
                )
                .unwrap();
        }

        // Memory should be dominated by string table (~100 unique names × ~15 bytes)
        let mem = writer.estimated_memory_bytes();
        assert!(
            mem < 1024 * 1024,
            "Writer memory should be under 1 MB, got {} bytes",
            mem
        );

        writer.finalize("{}").unwrap();

        let data = std::fs::read(f.path()).unwrap();
        let header: &ScnHeader = bytemuck::from_bytes(&data[0..HEADER_SIZE]);
        assert_eq!(header.node_count, 10_000);
    }
}
