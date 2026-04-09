//! Mmap-based binary .scn reader.
//!
//! Opens a binary .scn file via mmap for zero-copy access to CompactNode records,
//! string table, and indexes. SessionNode values are constructed on demand from
//! the compact representation — no need to load everything into RAM.

use std::path::Path;

use anyhow::{Context, Result};
use memmap2::Mmap;

use super::binary_format::*;
use super::SessionNode;
use crate::fs::{EntrySource, FileType, FsInfo};
use crate::scan::ScanReport;
use crate::search::{SearchMatch, SearchOptions};
use crate::session::SessionNodeTimestamps;

/// Mmap-based reader for binary .scn files.
pub struct ScnReader {
    mmap: Mmap,
    header: ScnHeader,
}

impl ScnReader {
    /// Open and validate a binary .scn file.
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open .scn file: {}", path.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to mmap .scn file: {}", path.display()))?;

        if mmap.len() < HEADER_SIZE {
            anyhow::bail!("File too small for .scn header: {} bytes", mmap.len());
        }

        let header: ScnHeader = *bytemuck::from_bytes(&mmap[0..HEADER_SIZE]);
        if !header.is_valid() {
            anyhow::bail!("Invalid .scn magic or version");
        }

        Ok(Self { mmap, header })
    }

    pub fn is_complete(&self) -> bool {
        self.header.is_complete()
    }

    pub fn node_count(&self) -> u64 {
        self.header.node_count
    }

    pub fn filesystem_count(&self) -> u16 {
        self.header.filesystem_count
    }

    fn string_table(&self) -> &[u8] {
        let start = self.header.string_table_offset as usize;
        let size = self.header.string_table_size as usize;
        if start == 0 || size == 0 || start + size > self.mmap.len() {
            return &[];
        }
        &self.mmap[start..start + size]
    }

    fn nodes_raw(&self) -> &[u8] {
        let start = self.header.node_records_offset as usize;
        let count = self.header.node_count as usize;
        let size = count * NODE_SIZE;
        if start + size > self.mmap.len() {
            return &[];
        }
        &self.mmap[start..start + size]
    }

    /// Get a CompactNode by index.
    pub fn get_compact_node(&self, index: u32) -> Option<&CompactNode> {
        let offset = self.header.node_records_offset as usize + index as usize * NODE_SIZE;
        if offset + NODE_SIZE > self.mmap.len() || index as u64 >= self.header.node_count {
            return None;
        }
        Some(bytemuck::from_bytes(&self.mmap[offset..offset + NODE_SIZE]))
    }

    /// Get basename string for a CompactNode.
    pub fn basename_str(&self, node: &CompactNode) -> &str {
        let st = self.string_table();
        let start = node.basename_offset as usize;
        let end = start + node.basename_len as usize;
        if end > st.len() {
            return "?";
        }
        std::str::from_utf8(&st[start..end]).unwrap_or("?")
    }

    /// Compute the full path for a node by walking the parent chain.
    pub fn compute_path(&self, node_index: u32) -> String {
        let mut segments: Vec<&str> = Vec::new();
        let mut current = node_index;
        let mut depth = 0u32;

        loop {
            if depth > 64 {
                break;
            }
            let node = match self.get_compact_node(current) {
                Some(n) => n,
                None => break,
            };
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

    /// Convert a CompactNode to a SessionNode (allocates strings on demand).
    pub fn to_session_node(&self, index: u32) -> Option<SessionNode> {
        let node = self.get_compact_node(index)?;
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

    // -----------------------------------------------------------------------
    // Children index: binary search for children of a node
    // -----------------------------------------------------------------------

    fn children_index_raw(&self) -> &[u8] {
        let start = self.header.children_index_offset as usize;
        let count = self.header.children_index_count as usize;
        let size = count * std::mem::size_of::<ChildEntry>();
        if start == 0 || start + size > self.mmap.len() {
            return &[];
        }
        &self.mmap[start..start + size]
    }

    /// List children of a node by its index. Uses binary search on the children index.
    pub fn list_children_by_index(&self, parent_index: u32) -> Vec<u32> {
        let raw = self.children_index_raw();
        let entry_size = std::mem::size_of::<ChildEntry>();
        let count = raw.len() / entry_size;
        if count == 0 {
            return Vec::new();
        }

        // Binary search for first entry with this parent
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let off = mid * entry_size;
            let p = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
            if p < parent_index {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        // Collect all entries with matching parent
        let mut children = Vec::new();
        while lo < count {
            let off = lo * entry_size;
            let p = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
            if p != parent_index {
                break;
            }
            let c = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap());
            children.push(c);
            lo += 1;
        }

        children
    }

    // -----------------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------------

    /// Find a node by path within a specific filesystem.
    pub fn find_node_by_path(&self, filesystem_index: usize, path: &str) -> Option<u32> {
        let normalized = path.trim();
        if normalized == "/" {
            return self.find_root_node(filesystem_index);
        }

        // Start from root, walk segments
        let root = self.find_root_node(filesystem_index)?;
        let segments: Vec<&str> = normalized
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current = root;
        for segment in &segments {
            let children = self.list_children_by_index(current);
            let mut found = false;
            for &child_idx in &children {
                if let Some(child_node) = self.get_compact_node(child_idx) {
                    if self.basename_str(child_node) == *segment {
                        current = child_idx;
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return None;
            }
        }

        Some(current)
    }

    fn find_root_node(&self, filesystem_index: usize) -> Option<u32> {
        // Root node: no parent, filesystem_index matches, basename is "/"
        let count = self.header.node_count as u32;
        for i in 0..count.min(1000) {
            // Root should be in the first few nodes
            if let Some(node) = self.get_compact_node(i) {
                if !node.has_parent()
                    && node.filesystem_index == filesystem_index as u16
                    && self.basename_str(node) == "/"
                {
                    return Some(i);
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // High-level API matching RecoverySession interface
    // -----------------------------------------------------------------------

    /// Resolve a path to a SessionNode.
    pub fn resolve_node(
        &self,
        filesystem_index: usize,
        path: &str,
    ) -> Result<SessionNode> {
        let idx = self
            .find_node_by_path(filesystem_index, path)
            .ok_or_else(|| anyhow::anyhow!("Path not found: {}", path))?;
        self.to_session_node(idx)
            .ok_or_else(|| anyhow::anyhow!("Node at index {} not readable", idx))
    }

    /// List children of a path as SessionNodes.
    pub fn list_children(
        &self,
        filesystem_index: usize,
        path: &str,
    ) -> Result<Vec<SessionNode>> {
        let parent_idx = self
            .find_node_by_path(filesystem_index, path)
            .ok_or_else(|| anyhow::anyhow!("Path not found: {}", path))?;

        let child_indices = self.list_children_by_index(parent_idx);
        let mut children = Vec::with_capacity(child_indices.len());
        for &idx in &child_indices {
            if let Some(node) = self.to_session_node(idx) {
                children.push(node);
            }
        }
        Ok(children)
    }

    /// Search all nodes for a query match.
    pub fn search(
        &self,
        query: &str,
        options: &SearchOptions,
    ) -> Vec<SearchMatch> {
        let count = self.header.node_count as u32;
        let st = self.string_table();
        let mut results = Vec::new();

        let query_lower = if options.ignore_case {
            query.to_lowercase()
        } else {
            query.to_string()
        };

        for i in 0..count {
            if let Some(node) = self.get_compact_node(i) {
                if let Some(fs_index) = options.filesystem_index {
                    if node.filesystem_index as usize != fs_index {
                        continue;
                    }
                }

                let start = node.basename_offset as usize;
                let end = start + node.basename_len as usize;
                if end > st.len() {
                    continue;
                }
                let basename = std::str::from_utf8(&st[start..end]).unwrap_or("");

                let basename_cmp = if options.ignore_case {
                    basename.to_lowercase()
                } else {
                    basename.to_string()
                };

                let matched = if crate::search::is_glob_query(&query_lower) {
                    crate::search::glob_matches(&query_lower, &basename_cmp)
                } else if options.exact {
                    basename_cmp == query_lower
                } else {
                    basename_cmp.contains(&query_lower)
                };

                if matched {
                    let path = self.compute_path(i);
                    results.push(SearchMatch {
                        filesystem_index: node.filesystem_index as usize,
                        filesystem_label: String::new(),
                        filesystem_offset: 0,
                        inode: node.inode,
                        path,
                        file_type: node.file_type(),
                        deleted: node.deleted(),
                        source: node.source(),
                        parent_inode: if node.parent_inode == 0 {
                            None
                        } else {
                            Some(node.parent_inode)
                        },
                    });
                }
            }
        }

        results
    }

    /// Get metadata section as JSON string.
    pub fn metadata_json(&self) -> Option<&str> {
        let start = self.header.metadata_offset as usize;
        let size = self.header.metadata_size as usize;
        if start == 0 || size == 0 || start + size > self.mmap.len() {
            return None;
        }
        std::str::from_utf8(&self.mmap[start..start + size]).ok()
    }

    /// Get warnings as JSON string.
    pub fn warnings_json(&self) -> Option<&str> {
        let start = self.header.warnings_offset as usize;
        let size = self.header.warnings_size as usize;
        if start == 0 || size == 0 || start + size > self.mmap.len() {
            return None;
        }
        std::str::from_utf8(&self.mmap[start..start + size]).ok()
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
    if value == 0 {
        None
    } else {
        Some(value as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::binary_writer::ScnWriter;
    use tempfile::NamedTempFile;

    fn create_test_scn() -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        let mut writer = ScnWriter::create(f.path()).unwrap();

        // Root
        writer
            .add_raw_inode(2, u32::MAX, "/", 0, FileType::Directory, false, EntrySource::Filesystem, 4096, 0, 0, 0, 0, 0)
            .unwrap();
        // /home
        writer
            .add_raw_inode(11, 0, "home", 0, FileType::Directory, false, EntrySource::Filesystem, 4096, 2, 0, 1000, 0, 0)
            .unwrap();
        // /home/ming
        writer
            .add_raw_inode(12, 1, "ming", 0, FileType::Directory, false, EntrySource::Filesystem, 4096, 11, 0, 1000, 0, 0)
            .unwrap();
        // /home/ming/report.txt
        writer
            .add_raw_inode(13, 2, "report.txt", 0, FileType::RegularFile, false, EntrySource::Filesystem, 5000, 12, 0, 1001, 0, 0)
            .unwrap();
        // /home/ming/deleted.txt (deleted)
        writer
            .add_raw_inode(14, 2, "deleted.txt", 0, FileType::RegularFile, true, EntrySource::DeletedSlack, 3000, 12, 0, 900, 0, 1100)
            .unwrap();

        writer.finalize("{}").unwrap();
        f
    }

    #[test]
    fn reader_opens_valid_file() {
        let f = create_test_scn();
        let reader = ScnReader::open(f.path()).unwrap();
        assert!(reader.is_complete());
        assert_eq!(reader.node_count(), 5);
    }

    #[test]
    fn reader_gets_compact_node() {
        let f = create_test_scn();
        let reader = ScnReader::open(f.path()).unwrap();

        let root = reader.get_compact_node(0).unwrap();
        assert_eq!(root.inode, 2);
        assert!(!root.has_parent());
        assert_eq!(root.file_type(), FileType::Directory);
        assert_eq!(reader.basename_str(root), "/");
    }

    #[test]
    fn reader_computes_path() {
        let f = create_test_scn();
        let reader = ScnReader::open(f.path()).unwrap();

        assert_eq!(reader.compute_path(0), "/");
        assert_eq!(reader.compute_path(1), "/home");
        assert_eq!(reader.compute_path(2), "/home/ming");
        assert_eq!(reader.compute_path(3), "/home/ming/report.txt");
    }

    #[test]
    fn reader_resolves_path() {
        let f = create_test_scn();
        let reader = ScnReader::open(f.path()).unwrap();

        let node = reader.resolve_node(0, "/home/ming/report.txt").unwrap();
        assert_eq!(node.inode, Some(13));
        assert_eq!(node.file_type, FileType::RegularFile);
        assert_eq!(node.size, Some(5000));
        assert_eq!(node.path, "/home/ming/report.txt");
    }

    #[test]
    fn reader_lists_children() {
        let f = create_test_scn();
        let reader = ScnReader::open(f.path()).unwrap();

        let children = reader.list_children(0, "/home/ming").unwrap();
        assert_eq!(children.len(), 2);
        let names: Vec<&str> = children.iter().map(|n| n.basename.as_str()).collect();
        assert!(names.contains(&"report.txt"));
        assert!(names.contains(&"deleted.txt"));
    }

    #[test]
    fn reader_search_finds_by_basename() {
        let f = create_test_scn();
        let reader = ScnReader::open(f.path()).unwrap();

        let results = reader.search("report", &SearchOptions::default());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "/home/ming/report.txt");
    }

    #[test]
    fn reader_search_glob() {
        let f = create_test_scn();
        let reader = ScnReader::open(f.path()).unwrap();

        let results = reader.search("*.txt", &SearchOptions::default());
        assert_eq!(results.len(), 2); // report.txt + deleted.txt
    }

    #[test]
    fn reader_to_session_node_preserves_deleted() {
        let f = create_test_scn();
        let reader = ScnReader::open(f.path()).unwrap();

        let node = reader.to_session_node(4).unwrap();
        assert!(node.deleted);
        assert_eq!(node.source, EntrySource::DeletedSlack);
        assert_eq!(node.timestamps.as_ref().unwrap().deleted_unix, Some(1100));
    }
}
