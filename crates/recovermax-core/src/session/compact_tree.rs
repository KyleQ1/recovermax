//! Compact in-memory tree built during scanning.
//!
//! Uses CompactNode (64 bytes each) + deduplicated string table instead of
//! SessionNode (~280 bytes with heap Strings). For 122M nodes this uses ~8 GB
//! vs 34 GB. Paths are computed on demand from parent chain, never stored.

use std::collections::HashMap;

use super::binary_format::*;
use super::SessionNode;
use crate::fs::{EntrySource, FileType};
use crate::session::SessionNodeTimestamps;

/// Compact in-memory tree. Built during scanning, optionally saved to .scn.
pub struct CompactTree {
    pub nodes: Vec<CompactNode>,
    pub string_table: Vec<u8>,
    string_intern: HashMap<String, u32>,
    pub warnings: Vec<String>,
    pub filesystem_count: u16,
}

impl CompactTree {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            string_table: Vec::new(),
            string_intern: HashMap::new(),
            warnings: Vec::new(),
            filesystem_count: 0,
        }
    }

    /// Intern a basename string, returning (offset, len).
    pub fn intern_basename(&mut self, basename: &str) -> (u32, u16) {
        if let Some(&offset) = self.string_intern.get(basename) {
            return (offset, basename.len() as u16);
        }
        let offset = self.string_table.len() as u32;
        self.string_table.extend_from_slice(basename.as_bytes());
        self.string_table.push(0);
        self.string_intern.insert(basename.to_string(), offset);
        (offset, basename.len() as u16)
    }

    /// Add a node. Returns the node index.
    pub fn add_node(
        &mut self,
        inode: u64,
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
    ) -> u32 {
        let (basename_offset, basename_len) = self.intern_basename(basename);
        let index = self.nodes.len() as u32;
        self.nodes.push(CompactNode {
            inode,
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
        });
        index
    }

    /// Add a warning.
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Estimated memory usage in bytes.
    pub fn estimated_memory_bytes(&self) -> usize {
        self.nodes.len() * NODE_SIZE
            + self.string_table.len()
            + self.string_intern.len() * 64
            + self.warnings.iter().map(|w| w.len()).sum::<usize>()
    }

    /// Get basename for a node.
    pub fn basename_str(&self, node: &CompactNode) -> &str {
        let start = node.basename_offset as usize;
        let end = start + node.basename_len as usize;
        if end > self.string_table.len() {
            return "?";
        }
        std::str::from_utf8(&self.string_table[start..end]).unwrap_or("?")
    }

    /// Compute path for a node by walking parent chain.
    pub fn compute_path(&self, node_index: u32) -> String {
        let mut segments: Vec<&str> = Vec::new();
        let mut current = node_index;
        let mut depth = 0u32;

        loop {
            if depth > 64 || current as usize >= self.nodes.len() {
                break;
            }
            let node = &self.nodes[current as usize];
            let basename = self.basename_str(node);
            if basename == "/" || !node.has_parent() {
                break;
            }
            segments.push(basename);
            current = node.parent_index;
            depth += 1;
        }

        segments.reverse();
        if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        }
    }

    /// Convert a node to SessionNode (allocates strings on demand).
    pub fn to_session_node(&self, index: u32) -> Option<SessionNode> {
        let node = self.nodes.get(index as usize)?;
        let basename = self.basename_str(node).to_string();
        let path = self.compute_path(index);

        Some(SessionNode {
            id: index as u64,
            parent_id: if node.has_parent() {
                Some(node.parent_index as u64)
            } else {
                None
            },
            filesystem_index: node.filesystem_index as usize,
            inode: if node.inode == 0 { None } else { Some(node.inode) },
            basename,
            path,
            file_type: node.file_type(),
            deleted: node.deleted(),
            size: if node.size == u64::MAX {
                None
            } else {
                Some(node.size)
            },
            source: node.source(),
            parent_inode: if node.parent_inode == 0 {
                None
            } else {
                Some(node.parent_inode)
            },
            timestamps: compact_timestamps(node),
        })
    }

    /// Save to binary .scn file.
    pub fn save_to_binary(&self, path: &std::path::Path, metadata_json: &str) -> anyhow::Result<()> {
        use super::binary_writer::ScnWriter;

        let mut writer = ScnWriter::create(path)?;
        writer.set_filesystem_count(self.filesystem_count);

        // Write all nodes directly (they're already CompactNode)
        for node in &self.nodes {
            writer.add_compact_node(*node)?;
        }

        for warning in &self.warnings {
            writer.add_warning(warning.clone());
        }

        // The writer needs the string table — but it built its own.
        // Since we're adding pre-built CompactNodes with offsets into OUR string table,
        // we need the writer to use our string table. Let's write the file directly instead.
        drop(writer);

        // Actually, use a simpler approach: write directly
        self.save_direct(path, metadata_json)
    }

    /// Direct binary write without going through ScnWriter.
    fn save_direct(&self, path: &std::path::Path, metadata_json: &str) -> anyhow::Result<()> {
        use std::io::Write;

        let mut file = std::fs::File::create(path)?;

        // Write header placeholder
        let header = ScnHeader::new();
        file.write_all(bytemuck::bytes_of(&header))?;

        // Write nodes
        let nodes_bytes = bytemuck::cast_slice::<CompactNode, u8>(&self.nodes);
        file.write_all(nodes_bytes)?;

        let node_records_end = HEADER_SIZE as u64 + self.nodes.len() as u64 * NODE_SIZE as u64;

        // Write metadata
        let metadata_offset = node_records_end;
        let metadata_bytes = metadata_json.as_bytes();
        file.write_all(metadata_bytes)?;

        // Write string table
        let string_table_offset = metadata_offset + metadata_bytes.len() as u64;
        file.write_all(&self.string_table)?;

        // Write warnings
        let warnings_offset = string_table_offset + self.string_table.len() as u64;
        let warnings_json = serde_json::to_string(&self.warnings)?;
        file.write_all(warnings_json.as_bytes())?;

        // Build and write children index
        let children_index_offset = warnings_offset + warnings_json.len() as u64;
        let mut children: Vec<ChildEntry> = Vec::new();
        for (i, node) in self.nodes.iter().enumerate() {
            if node.has_parent() {
                children.push(ChildEntry {
                    parent_index: node.parent_index,
                    child_index: i as u32,
                });
            }
        }
        children.sort_unstable_by_key(|e| (e.parent_index, e.child_index));
        file.write_all(bytemuck::cast_slice::<ChildEntry, u8>(&children))?;

        // Build and write inode index
        let inode_index_offset = children_index_offset
            + children.len() as u64 * std::mem::size_of::<ChildEntry>() as u64;
        let mut inodes: Vec<InodeEntry> = Vec::new();
        for (i, node) in self.nodes.iter().enumerate() {
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
        file.write_all(bytemuck::cast_slice::<InodeEntry, u8>(&inodes))?;

        // Rewrite header with final offsets
        use std::io::Seek;
        let mut final_header = ScnHeader::new();
        final_header.flags = FLAG_SCAN_COMPLETE;
        final_header.node_count = self.nodes.len() as u64;
        final_header.metadata_offset = metadata_offset;
        final_header.metadata_size = metadata_bytes.len() as u64;
        final_header.string_table_offset = string_table_offset;
        final_header.string_table_size = self.string_table.len() as u64;
        final_header.warnings_offset = warnings_offset;
        final_header.warnings_size = warnings_json.len() as u64;
        final_header.children_index_offset = children_index_offset;
        final_header.children_index_count = children.len() as u64;
        final_header.inode_index_offset = inode_index_offset;
        final_header.inode_index_count = inodes.len() as u64;
        final_header.filesystem_count = self.filesystem_count;

        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(bytemuck::bytes_of(&final_header))?;

        Ok(())
    }
}

fn compact_timestamps(node: &CompactNode) -> Option<SessionNodeTimestamps> {
    let ts = SessionNodeTimestamps {
        created_unix: nonzero_ts(node.ctime),
        modified_unix: nonzero_ts(node.mtime),
        accessed_unix: nonzero_ts(node.atime),
        deleted_unix: nonzero_ts(node.dtime),
    };
    if ts.created_unix.is_none()
        && ts.modified_unix.is_none()
        && ts.accessed_unix.is_none()
        && ts.deleted_unix.is_none()
    {
        None
    } else {
        Some(ts)
    }
}

fn nonzero_ts(value: u32) -> Option<i64> {
    if value == 0 { None } else { Some(value as i64) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_tree_builds_and_queries() {
        let mut tree = CompactTree::new();

        let root = tree.add_node(2, u32::MAX, "/", 0, FileType::Directory, false, EntrySource::Filesystem, 4096, 0, 0, 0, 0, 0);
        let home = tree.add_node(11, root, "home", 0, FileType::Directory, false, EntrySource::Filesystem, 4096, 2, 0, 1000, 0, 0);
        let file = tree.add_node(12, home, "test.txt", 0, FileType::RegularFile, false, EntrySource::Filesystem, 100, 11, 0, 1001, 0, 0);

        assert_eq!(tree.node_count(), 3);
        assert_eq!(tree.compute_path(root), "/");
        assert_eq!(tree.compute_path(home), "/home");
        assert_eq!(tree.compute_path(file), "/home/test.txt");

        let session_node = tree.to_session_node(file).unwrap();
        assert_eq!(session_node.path, "/home/test.txt");
        assert_eq!(session_node.inode, Some(12));
        assert_eq!(session_node.size, Some(100));
    }

    #[test]
    fn string_table_deduplicates() {
        let mut tree = CompactTree::new();

        tree.add_node(11, 0, "hello.txt", 0, FileType::RegularFile, false, EntrySource::Filesystem, 10, 0, 0, 0, 0, 0);
        tree.add_node(12, 0, "hello.txt", 0, FileType::RegularFile, false, EntrySource::Filesystem, 20, 0, 0, 0, 0, 0);
        tree.add_node(13, 0, "world.txt", 0, FileType::RegularFile, false, EntrySource::Filesystem, 30, 0, 0, 0, 0, 0);

        // Only 2 unique strings in the table
        // "hello.txt\0world.txt\0" = 20 bytes
        assert_eq!(tree.string_table.len(), 20);
    }

    #[test]
    fn memory_is_compact() {
        let mut tree = CompactTree::new();
        for i in 0..10_000u32 {
            let name = format!("file_{}.txt", i % 100);
            tree.add_node(i as u64 + 11, 0, &name, 0, FileType::RegularFile, false, EntrySource::Filesystem, i as u64 * 100, 0, 0, 0, 0, 0);
        }

        let mem = tree.estimated_memory_bytes();
        // 10K nodes × 64 bytes = 640 KB for nodes
        // ~100 unique basenames × ~15 bytes = ~1.5 KB for string table
        // Total should be well under 1 MB
        assert!(mem < 1024 * 1024, "Memory should be under 1 MB, got {}", mem);
    }

    #[test]
    fn save_and_reload_binary() {
        use super::super::binary_reader::ScnReader;

        let mut tree = CompactTree::new();
        let root = tree.add_node(2, u32::MAX, "/", 0, FileType::Directory, false, EntrySource::Filesystem, 4096, 0, 0, 0, 0, 0);
        tree.add_node(11, root, "test.txt", 0, FileType::RegularFile, false, EntrySource::Filesystem, 100, 2, 0, 1001, 0, 0);
        tree.filesystem_count = 1;

        let f = tempfile::NamedTempFile::new().unwrap();
        tree.save_to_binary(f.path(), "{}").unwrap();

        let reader = ScnReader::open(f.path()).unwrap();
        assert_eq!(reader.node_count(), 2);

        let node = reader.resolve_node(0, "/test.txt").unwrap();
        assert_eq!(node.inode, Some(11));
        assert_eq!(node.size, Some(100));
    }
}
