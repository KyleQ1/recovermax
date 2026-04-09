pub mod binary_format;
pub mod binary_reader;
pub mod binary_writer;
pub mod compact_tree;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::fs::ext4::{DeletedInode, Ext4Fs, Inode};
use crate::fs::{EntrySource, FileType, FsInfo};
use crate::io::ImageReader;
use crate::scan::ScanReport;
use crate::search::{path_matches, SearchMatch, SearchOptions};

const DEFAULT_MEMORY_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TREE_DEPTH: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanImageSource {
    pub path: PathBuf,
    pub image_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySessionArtifact {
    pub version: u32,
    pub source: ScanImageSource,
    pub report: ScanReport,
    #[serde(default)]
    pub filesystems: Vec<FilesystemSessionArtifact>,
}

impl RecoverySessionArtifact {
    pub const VERSION: u32 = 2;

    pub fn from_scan(image_path: &Path, reader: &ImageReader, report: ScanReport) -> Result<Self> {
        Self::from_scan_with_callback(image_path, reader, report, None)
    }

    /// Build a binary .scn file directly, streaming nodes to disk.
    /// Uses ~150 MB RAM regardless of filesystem size.
    pub fn build_binary_scn(
        image_path: &Path,
        reader: &ImageReader,
        report: &ScanReport,
        output_path: &Path,
        on_event: Option<&dyn Fn(crate::scan::ScanEvent)>,
    ) -> Result<()> {
        build_filesystem_sessions_binary(reader, report, output_path, on_event)
    }

    pub fn from_scan_with_callback(
        image_path: &Path,
        reader: &ImageReader,
        report: ScanReport,
        on_event: Option<&dyn Fn(crate::scan::ScanEvent)>,
    ) -> Result<Self> {
        let filesystems = build_filesystem_sessions(reader, &report, on_event)?;
        Ok(Self {
            version: Self::VERSION,
            source: ScanImageSource {
                path: canonicalize_best_effort(image_path),
                image_size: report.image_size,
            },
            report,
            filesystems,
        })
    }

    pub fn from_report(image_path: &Path, report: ScanReport) -> Self {
        Self {
            version: Self::VERSION,
            source: ScanImageSource {
                path: canonicalize_best_effort(image_path),
                image_size: report.image_size,
            },
            filesystems: minimal_filesystem_sessions(&report),
            report,
        }
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
            .with_context(|| format!("failed to write scan artifact to {}", path.display()))?;
        Ok(())
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read scan artifact {}", path.display()))?;
        Self::from_json_str(&data)
            .with_context(|| format!("failed to parse scan artifact {}", path.display()))
    }

    pub fn from_json_str(data: &str) -> Result<Self> {
        if let Ok(artifact) = serde_json::from_str::<RecoverySessionArtifact>(data) {
            if artifact.version == Self::VERSION {
                return Ok(artifact);
            }

            if artifact.version != 1 {
                bail!(
                    "unsupported scan artifact version {} (expected {})",
                    artifact.version,
                    Self::VERSION
                );
            }
        }

        if let Ok(legacy) = serde_json::from_str::<LegacyScanArtifact>(data) {
            if let Some(version) = legacy.version {
                if version != 1 {
                    bail!(
                        "unsupported scan artifact version {} (expected {})",
                        version,
                        Self::VERSION
                    );
                }
            }
            return Ok(Self {
                version: Self::VERSION,
                source: legacy.source,
                filesystems: minimal_filesystem_sessions(&legacy.report),
                report: legacy.report,
            });
        }

        let report: ScanReport = serde_json::from_str(data).context(
            "legacy scan artifact detected but it does not contain source image metadata",
        )?;

        Ok(Self {
            version: Self::VERSION,
            source: ScanImageSource {
                path: PathBuf::new(),
                image_size: report.image_size,
            },
            filesystems: minimal_filesystem_sessions(&report),
            report,
        })
    }

    pub fn report(&self) -> &ScanReport {
        &self.report
    }

    pub fn source_path(&self) -> Option<&Path> {
        if self.source.path.as_os_str().is_empty() {
            None
        } else {
            Some(&self.source.path)
        }
    }

    pub fn validate_for_image(&self, image_path: &Path, image_size: u64) -> Result<()> {
        self.validate_for_image_with_artifact_path(image_path, image_size, None)
    }

    pub fn resolved_source_path(&self, artifact_path: Option<&Path>) -> Option<PathBuf> {
        let saved_path = self.source_path()?;
        if saved_path.is_absolute() {
            return Some(canonicalize_best_effort(saved_path));
        }

        let canonical_saved_path = canonicalize_best_effort(saved_path);
        if canonical_saved_path.is_absolute() {
            return Some(canonical_saved_path);
        }

        if let Some(artifact_path) = artifact_path {
            if let Some(parent) = artifact_path.parent() {
                return Some(canonicalize_best_effort(&parent.join(saved_path)));
            }
        }

        Some(saved_path.to_path_buf())
    }

    pub fn validate_for_image_with_artifact_path(
        &self,
        image_path: &Path,
        image_size: u64,
        artifact_path: Option<&Path>,
    ) -> Result<()> {
        if self.source.image_size != image_size {
            bail!(
                "scan artifact image size {} does not match image {} ({})",
                self.source.image_size,
                image_path.display(),
                image_size
            );
        }

        let current_path = canonicalize_best_effort(image_path);
        if let Some(saved_path) = self.resolved_source_path(artifact_path) {
            if saved_path != current_path {
                bail!(
                    "scan artifact was created for {} but {} was provided",
                    saved_path.display(),
                    current_path.display()
                );
            }
        }

        Ok(())
    }

    pub fn filesystem_session(
        &self,
        filesystem_index: usize,
    ) -> Option<&FilesystemSessionArtifact> {
        self.filesystems
            .iter()
            .find(|session| session.filesystem_index == filesystem_index)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemSessionArtifact {
    pub filesystem_index: usize,
    pub fs_info: FsInfo,
    pub root_node_id: Option<u64>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub nodes: Vec<SessionNode>,
}

impl FilesystemSessionArtifact {
    pub fn has_tree(&self) -> bool {
        self.root_node_id.is_some() && !self.nodes.is_empty()
    }

    pub fn has_partial_tree(&self) -> bool {
        !self.warnings.is_empty()
    }

    pub fn warnings_for_path(&self, path: &str) -> Vec<&str> {
        let normalized = normalize_session_path(path);
        self.warnings
            .iter()
            .filter(|warning| traversal_warning_matches_path(warning, &normalized))
            .map(String::as_str)
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNode {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub filesystem_index: usize,
    pub inode: Option<u64>,
    pub basename: String,
    pub path: String,
    pub file_type: FileType,
    pub deleted: bool,
    pub size: Option<u64>,
    #[serde(default)]
    pub source: EntrySource,
    #[serde(default)]
    pub parent_inode: Option<u64>,
    #[serde(default)]
    pub timestamps: Option<SessionNodeTimestamps>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNodeTimestamps {
    pub created_unix: Option<i64>,
    pub modified_unix: Option<i64>,
    pub accessed_unix: Option<i64>,
    #[serde(default)]
    pub deleted_unix: Option<i64>,
}

fn session_timestamps_from_inode(inode: &Inode) -> Option<SessionNodeTimestamps> {
    session_timestamps_from_raw(inode.ctime, inode.mtime, inode.atime, inode.dtime)
}

fn session_timestamps_from_deleted_inode(inode: &DeletedInode) -> Option<SessionNodeTimestamps> {
    session_timestamps_from_raw(inode.ctime, inode.mtime, inode.atime, inode.dtime)
}

fn session_timestamps_from_raw(
    created_unix: u32,
    modified_unix: u32,
    accessed_unix: u32,
    deleted_unix: u32,
) -> Option<SessionNodeTimestamps> {
    let timestamps = SessionNodeTimestamps {
        created_unix: nonzero_unix_timestamp(created_unix),
        modified_unix: nonzero_unix_timestamp(modified_unix),
        accessed_unix: nonzero_unix_timestamp(accessed_unix),
        deleted_unix: nonzero_unix_timestamp(deleted_unix),
    };
    if timestamps.created_unix.is_none()
        && timestamps.modified_unix.is_none()
        && timestamps.accessed_unix.is_none()
        && timestamps.deleted_unix.is_none()
    {
        None
    } else {
        Some(timestamps)
    }
}

fn nonzero_unix_timestamp(value: u32) -> Option<i64> {
    (value != 0).then_some(value as i64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryBudgetSource {
    Explicit,
    Environment,
    Default,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryBudget {
    pub bytes: u64,
    pub source: MemoryBudgetSource,
}

impl MemoryBudget {
    pub fn resolve(explicit: Option<u64>) -> Self {
        if let Some(bytes) = explicit {
            return Self {
                bytes,
                source: MemoryBudgetSource::Explicit,
            };
        }

        if let Ok(value) = std::env::var("RECOVERMAX_MEMORY_BUDGET") {
            if let Ok(parsed) = parse_budget_bytes(&value) {
                return Self {
                    bytes: parsed,
                    source: MemoryBudgetSource::Environment,
                };
            }
        }

        Self {
            bytes: DEFAULT_MEMORY_BUDGET_BYTES,
            source: MemoryBudgetSource::Default,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheSummary {
    pub budget_bytes: u64,
    pub budget_source: MemoryBudgetSource,
    pub estimated_bytes: u64,
    pub node_index_loaded: bool,
    pub path_index_loaded: bool,
    pub children_index_loaded: bool,
    pub evictions: usize,
}

#[derive(Debug, Clone)]
pub struct SessionTreeEntry {
    pub depth: usize,
    pub node: SessionNode,
}

pub struct RecoverySession {
    artifact: RecoverySessionArtifact,
    reader: Option<ImageReader>,
    memory_budget: MemoryBudget,
    cache: SessionCacheManager,
}

impl RecoverySession {
    pub fn from_artifact(artifact: RecoverySessionArtifact, explicit_budget: Option<u64>) -> Self {
        Self {
            artifact,
            reader: None,
            memory_budget: MemoryBudget::resolve(explicit_budget),
            cache: SessionCacheManager::default(),
        }
    }

    pub fn from_artifact_with_reader(
        artifact: RecoverySessionArtifact,
        reader: ImageReader,
        explicit_budget: Option<u64>,
    ) -> Self {
        Self {
            artifact,
            reader: Some(reader),
            memory_budget: MemoryBudget::resolve(explicit_budget),
            cache: SessionCacheManager::default(),
        }
    }

    pub fn artifact(&self) -> &RecoverySessionArtifact {
        &self.artifact
    }

    pub fn attached_reader(&self) -> Option<&ImageReader> {
        self.reader.as_ref()
    }

    pub fn cache_summary(&self) -> CacheSummary {
        CacheSummary {
            budget_bytes: self.memory_budget.bytes,
            budget_source: self.memory_budget.source,
            estimated_bytes: self.cache.estimated_bytes,
            node_index_loaded: self.cache.node_by_id.is_some(),
            path_index_loaded: self.cache.path_to_node.is_some(),
            children_index_loaded: self.cache.children_by_parent.is_some(),
            evictions: self.cache.evictions,
        }
    }

    pub fn unload_caches(&mut self) {
        self.cache = SessionCacheManager::default();
    }

    pub fn filesystems(&self) -> &[FilesystemSessionArtifact] {
        &self.artifact.filesystems
    }

    pub fn resolve_node(
        &mut self,
        filesystem_index: usize,
        path_or_node: &str,
    ) -> Result<SessionNode> {
        if let Ok(node_id) = path_or_node.parse::<u64>() {
            self.ensure_node_index();
            let Some(node_location) = self
                .cache
                .node_by_id
                .as_ref()
                .and_then(|index| index.get(&node_id).copied())
            else {
                bail!("node {} not found in session", node_id);
            };

            let node = self
                .node_at(node_location)
                .cloned()
                .context("node index pointed outside the node table")?;

            if node.filesystem_index != filesystem_index {
                bail!(
                    "node {} belongs to filesystem {} not {}",
                    node_id,
                    node.filesystem_index,
                    filesystem_index
                );
            }

            return Ok(node);
        }

        let normalized = normalize_session_path(path_or_node);
        if let Some(node) = self.find_node_by_path(filesystem_index, &normalized) {
            return Ok(node);
        }

        bail!(
            "path {} not found in filesystem {}",
            normalized,
            filesystem_index
        )
    }

    pub fn list_children(
        &mut self,
        filesystem_index: usize,
        path: &str,
    ) -> Result<Vec<SessionNode>> {
        let has_tree = self
            .artifact
            .filesystem_session(filesystem_index)
            .map(|session| session.has_tree())
            .with_context(|| format!("filesystem {} not found in session", filesystem_index))?;
        if !has_tree {
            bail!(
                "filesystem {} has no persisted session tree in this artifact; rescan the image to browse it",
                filesystem_index
            );
        }

        let node = self.resolve_node(filesystem_index, path)?;
        self.ensure_children_index();

        let child_indexes = self
            .cache
            .children_by_parent
            .as_ref()
            .and_then(|index| index.get(&node.id))
            .cloned()
            .unwrap_or_default();

        let mut children: Vec<SessionNode> = child_indexes
            .into_iter()
            .filter_map(|location| self.node_at(location).cloned())
            .collect();
        children.sort_by(|a, b| a.basename.cmp(&b.basename));
        Ok(children)
    }

    pub fn walk_tree(
        &mut self,
        filesystem_index: usize,
        path: &str,
        max_depth: usize,
    ) -> Result<Vec<SessionTreeEntry>> {
        let has_tree = self
            .artifact
            .filesystem_session(filesystem_index)
            .map(|session| session.has_tree())
            .with_context(|| format!("filesystem {} not found in session", filesystem_index))?;
        if !has_tree {
            bail!(
                "filesystem {} has no persisted session tree in this artifact; rescan the image to browse it",
                filesystem_index
            );
        }

        let root = self.resolve_node(filesystem_index, path)?;
        self.ensure_children_index();

        let mut out = Vec::new();
        self.walk_tree_recursive(root.id, 0, max_depth, &mut out);
        Ok(out)
    }

    pub fn search(&mut self, query: &str, options: &SearchOptions) -> Vec<SearchMatch> {
        let mut matches = Vec::new();

        for session in &self.artifact.filesystems {
            if options.filesystem_index.is_some()
                && options.filesystem_index != Some(session.filesystem_index)
            {
                continue;
            }

            if !session.has_tree() {
                continue;
            }

            for node in &session.nodes {
                if path_matches(query, &node.basename, &node.path, options) {
                    matches.push(SearchMatch {
                        filesystem_index: session.filesystem_index,
                        filesystem_label: session.fs_info.label.clone(),
                        filesystem_offset: session.fs_info.offset,
                        inode: node.inode.unwrap_or(0),
                        path: node.path.clone(),
                        file_type: node.file_type,
                        deleted: node.deleted,
                        source: node.source,
                        parent_inode: node.parent_inode,
                    });
                }
            }
        }

        matches
    }

    fn walk_tree_recursive(
        &self,
        node_id: u64,
        depth: usize,
        max_depth: usize,
        out: &mut Vec<SessionTreeEntry>,
    ) {
        let Some(node_location) = self
            .cache
            .node_by_id
            .as_ref()
            .and_then(|index| index.get(&node_id).copied())
        else {
            return;
        };

        let Some(node) = self.node_at(node_location).cloned() else {
            return;
        };
        out.push(SessionTreeEntry {
            depth,
            node: node.clone(),
        });

        if depth >= max_depth {
            return;
        }

        let mut child_indexes = self
            .cache
            .children_by_parent
            .as_ref()
            .and_then(|index| index.get(&node_id))
            .cloned()
            .unwrap_or_default();
        child_indexes.sort_by_key(|location| {
            self.node_at(*location)
                .map(|node| node.basename.clone())
                .unwrap_or_default()
        });

        for child_index in child_indexes {
            if let Some(child) = self.node_at(child_index) {
                self.walk_tree_recursive(child.id, depth + 1, max_depth, out);
            }
        }
    }

    fn ensure_node_index(&mut self) {
        if self.cache.node_by_id.is_some() {
            return;
        }

        let mut map = HashMap::new();
        for (filesystem_slot, filesystem) in self.artifact.filesystems.iter().enumerate() {
            for (node_index, node) in filesystem.nodes.iter().enumerate() {
                map.insert(
                    node.id,
                    NodeLocation {
                        filesystem_slot,
                        node_index,
                    },
                );
                self.cache.estimated_bytes += std::mem::size_of::<u64>() as u64 * 2;
            }
        }

        self.cache.node_by_id = Some(map);
    }

    fn ensure_path_index(&mut self) {
        if self.cache.path_to_node.is_some() {
            return;
        }

        let mut map = HashMap::new();
        let mut bytes = 0u64;
        for (filesystem_slot, filesystem) in self.artifact.filesystems.iter().enumerate() {
            for (node_index, node) in filesystem.nodes.iter().enumerate() {
                let key = (node.filesystem_index, node.path.clone());
                bytes += node.path.len() as u64 + std::mem::size_of::<usize>() as u64 * 2;
                map.insert(
                    key,
                    NodeLocation {
                        filesystem_slot,
                        node_index,
                    },
                );
            }
        }

        self.cache.path_to_node = Some(map);
        self.cache.estimated_bytes += bytes;
        self.enforce_budget();
    }

    fn ensure_children_index(&mut self) {
        if self.cache.children_by_parent.is_some() {
            return;
        }

        self.ensure_node_index();

        let mut map: HashMap<u64, Vec<NodeLocation>> = HashMap::new();
        let mut bytes = 0u64;
        for (filesystem_slot, filesystem) in self.artifact.filesystems.iter().enumerate() {
            for (node_index, node) in filesystem.nodes.iter().enumerate() {
                if let Some(parent_id) = node.parent_id {
                    map.entry(parent_id).or_default().push(NodeLocation {
                        filesystem_slot,
                        node_index,
                    });
                    bytes +=
                        std::mem::size_of::<u64>() as u64 + std::mem::size_of::<usize>() as u64;
                }
            }
        }

        self.cache.children_by_parent = Some(map);
        self.cache.estimated_bytes += bytes;
        self.enforce_budget();
    }

    fn enforce_budget(&mut self) {
        if self.cache.estimated_bytes <= self.memory_budget.bytes {
            return;
        }

        if let Some(index) = self.cache.path_to_node.take() {
            self.cache.estimated_bytes = self
                .cache
                .estimated_bytes
                .saturating_sub(estimate_path_index_bytes(&index));
            self.cache.evictions += 1;
        }

        if self.cache.estimated_bytes > self.memory_budget.bytes {
            if let Some(index) = self.cache.children_by_parent.take() {
                self.cache.estimated_bytes = self
                    .cache
                    .estimated_bytes
                    .saturating_sub(estimate_children_index_bytes(&index));
                self.cache.evictions += 1;
            }
        }
    }

    fn find_node_by_path(&mut self, filesystem_index: usize, path: &str) -> Option<SessionNode> {
        self.ensure_path_index();
        self.ensure_node_index();
        if let Some(node_index) = self
            .cache
            .path_to_node
            .as_ref()
            .and_then(|index| index.get(&(filesystem_index, path.to_string())).copied())
        {
            return self.node_at(node_index).cloned();
        }

        self.artifact
            .filesystems
            .iter()
            .find(|filesystem| filesystem.filesystem_index == filesystem_index)
            .and_then(|filesystem| filesystem.nodes.iter().find(|node| node.path == path))
            .cloned()
    }

    fn node_at(&self, location: NodeLocation) -> Option<&SessionNode> {
        self.artifact
            .filesystems
            .get(location.filesystem_slot)
            .and_then(|filesystem| filesystem.nodes.get(location.node_index))
    }
}

#[derive(Default)]
struct SessionCacheManager {
    node_by_id: Option<HashMap<u64, NodeLocation>>,
    path_to_node: Option<HashMap<(usize, String), NodeLocation>>,
    children_by_parent: Option<HashMap<u64, Vec<NodeLocation>>>,
    estimated_bytes: u64,
    evictions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NodeLocation {
    filesystem_slot: usize,
    node_index: usize,
}

#[derive(Deserialize)]
struct LegacyScanArtifact {
    version: Option<u32>,
    source: ScanImageSource,
    report: ScanReport,
}

fn build_filesystem_sessions(
    reader: &ImageReader,
    report: &ScanReport,
    on_event: Option<&dyn Fn(crate::scan::ScanEvent)>,
) -> Result<Vec<FilesystemSessionArtifact>> {
    let mut sessions = Vec::new();
    let mut next_node_id = 1u64;

    for (filesystem_index, fs_info) in report.filesystems.iter().enumerate() {
        if fs_info.fs_type != "ext4" {
            sessions.push(FilesystemSessionArtifact {
                filesystem_index,
                fs_info: fs_info.clone(),
                root_node_id: None,
                warnings: Vec::new(),
                nodes: Vec::new(),
            });
            continue;
        }

        let ext4 = match Ext4Fs::new(reader, fs_info.offset) {
            Ok(ext4) => ext4,
            Err(err) => {
                tracing::warn!(
                    "failed to open ext4 filesystem {} at offset {}; saving report-only session: {}",
                    filesystem_index,
                    fs_info.offset,
                    err
                );
                sessions.push(FilesystemSessionArtifact {
                    filesystem_index,
                    fs_info: fs_info.clone(),
                    root_node_id: None,
                    warnings: vec![format_traversal_warning(
                        "/",
                        &format!(
                            "failed to open ext4 filesystem at offset {}: {}",
                            fs_info.offset, err
                        ),
                    )],
                    nodes: Vec::new(),
                });
                continue;
            }
        };
        let root_id = next_node_id;
        next_node_id += 1;

        // Try to read root inode — if corrupt (Proxmox overwrote block group 0),
        // create a synthetic root and still proceed with deleted inode scanning
        let root_inode_ok = ext4.read_inode(2).ok();
        let mut nodes = vec![SessionNode {
            id: root_id,
            parent_id: None,
            filesystem_index,
            inode: root_inode_ok.as_ref().map(|i| i.number).or(Some(2)),
            basename: "/".to_string(),
            path: "/".to_string(),
            file_type: FileType::Directory,
            deleted: root_inode_ok.as_ref().map_or(false, |i| i.is_deleted()),
            size: root_inode_ok.as_ref().map(|i| i.size),
            source: EntrySource::Filesystem,
            parent_inode: None,
            timestamps: root_inode_ok.as_ref().and_then(session_timestamps_from_inode),
        }];
        let mut warnings = Vec::new();

        if let Some(cb) = on_event {
            cb(crate::scan::ScanEvent::TreeBuildStarted {
                filesystem_index,
                label: fs_info.label.clone(),
                total_inodes: ext4.superblock.inodes_count as u64,
            });
        }

        if root_inode_ok.is_some() {
            // Normal path: root inode is readable, walk the directory tree
            match ext4.list_directory(2) {
                Ok(root_entries) => {
                    let mut visited_dirs = HashSet::from([2u64]);
                    if let Err(err) = build_ext4_subtree(
                        &ext4,
                        filesystem_index,
                        root_id,
                        PathBuf::new(),
                        &root_entries,
                        &mut visited_dirs,
                        &mut next_node_id,
                        &mut nodes,
                        &mut warnings,
                        0,
                        on_event,
                    ) {
                        tracing::warn!(
                            "failed to build full session tree for filesystem {} at offset {}: {}",
                            filesystem_index,
                            fs_info.offset,
                            err
                        );
                        warnings.push(format_traversal_warning(
                            "/",
                            &format!("failed to build full session tree: {}", err),
                        ));
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "failed to read root directory for filesystem {} at offset {}: {}",
                        filesystem_index,
                        fs_info.offset,
                        err
                    );
                    warnings.push(format_traversal_warning(
                        "/",
                        &format!("failed to read root directory: {}", err),
                    ));
                }
            }
        } else {
            // Root inode is corrupt (e.g., Proxmox overwrote block group 0).
            // Still proceed — deleted inode scanning will find files in
            // intact block groups deeper in the disk.
            tracing::warn!(
                "Root inode (inode 2) is unreadable for filesystem {} at offset {}. \
                 Block group 0 may be overwritten. Scanning all block groups for recoverable files...",
                filesystem_index,
                fs_info.offset
            );
            warnings.push(format_traversal_warning(
                "/",
                "Root inode unreadable (block group 0 may be overwritten). Scanning all block groups for deleted/orphan files.",
            ));
        }

        if let Some(cb) = on_event {
            cb(crate::scan::ScanEvent::TreeBuildComplete {
                filesystem_index,
                total_nodes: nodes.len(),
            });
        }

        let journal_hints = ext4.journal_filename_hints().unwrap_or_default();

        // When root is corrupt, scan ALL block groups for any readable inodes.
        // This finds files in intact block groups deeper in the disk.
        if root_inode_ok.is_none() {
            tracing::info!("Scanning all block groups for recoverable inodes...");
            append_ext4_all_inodes(
                &ext4,
                filesystem_index,
                root_id,
                &mut next_node_id,
                &mut nodes,
                &mut warnings,
                &journal_hints,
                on_event,
            );
        }

        // Always scan for deleted/orphan inodes
        append_ext4_deleted_orphans(
            &ext4,
            filesystem_index,
            root_id,
            &mut next_node_id,
            &mut nodes,
            &mut warnings,
            &journal_hints,
        );

        sessions.push(FilesystemSessionArtifact {
            filesystem_index,
            fs_info: fs_info.clone(),
            root_node_id: if nodes.is_empty() {
                None
            } else {
                Some(root_id)
            },
            warnings,
            nodes,
        });
    }

    Ok(sessions)
}

/// Build a compact in-memory tree and optionally save to binary .scn.
/// Uses CompactNode (64 bytes each) instead of SessionNode (~280 bytes).
/// For 122M nodes: ~8 GB RAM vs 34 GB.
fn build_filesystem_sessions_binary(
    reader: &ImageReader,
    report: &ScanReport,
    output_path: &Path,
    on_event: Option<&dyn Fn(crate::scan::ScanEvent)>,
) -> Result<()> {
    let mut tree = compact_tree::CompactTree::new();
    tree.filesystem_count = report.filesystems.len() as u16;

    for (filesystem_index, fs_info) in report.filesystems.iter().enumerate() {
        if fs_info.fs_type != "ext4" {
            continue;
        }

        let ext4 = match Ext4Fs::new(reader, fs_info.offset) {
            Ok(ext4) => ext4,
            Err(err) => {
                tree.add_warning(format_traversal_warning(
                    "/",
                    &format!("failed to open ext4 at offset {}: {}", fs_info.offset, err),
                ));
                continue;
            }
        };

        if let Some(cb) = on_event {
            cb(crate::scan::ScanEvent::TreeBuildStarted {
                filesystem_index,
                label: fs_info.label.clone(),
                total_inodes: ext4.superblock.inodes_count as u64,
            });
        }

        let root_inode_ok = ext4.read_inode(2).ok();
        let root_idx = tree.add_node(
            root_inode_ok.as_ref().map_or(2, |i| i.number),
            u32::MAX,
            "/",
            filesystem_index as u16,
            FileType::Directory,
            root_inode_ok.as_ref().map_or(false, |i| i.is_deleted()),
            EntrySource::Filesystem,
            root_inode_ok.as_ref().map_or(u64::MAX, |i| i.size),
            0,
            root_inode_ok.as_ref().map_or(0, |i| i.ctime),
            root_inode_ok.as_ref().map_or(0, |i| i.mtime),
            root_inode_ok.as_ref().map_or(0, |i| i.atime),
            0,
        );

        if root_inode_ok.is_some() {
            match ext4.list_directory(2) {
                Ok(root_entries) => {
                    let mut visited = HashSet::from([2u64]);
                    build_ext4_subtree_compact(
                        &ext4,
                        filesystem_index as u16,
                        root_idx,
                        &root_entries,
                        &mut visited,
                        &mut tree,
                        0,
                        on_event,
                    );
                }
                Err(err) => {
                    tree.add_warning(format_traversal_warning(
                        "/",
                        &format!("failed to read root directory: {}", err),
                    ));
                }
            }
        } else {
            tree.add_warning(format_traversal_warning(
                "/",
                "Root inode unreadable. Scanning all block groups for recoverable files.",
            ));
        }

        if let Some(cb) = on_event {
            cb(crate::scan::ScanEvent::TreeBuildComplete {
                filesystem_index,
                total_nodes: tree.node_count(),
            });
        }

        let journal_hints = ext4.journal_filename_hints().unwrap_or_default();

        if root_inode_ok.is_none() {
            append_ext4_all_inodes_compact(
                &ext4,
                filesystem_index as u16,
                root_idx,
                &mut tree,
                &journal_hints,
                on_event,
            );
        }

        // Deleted orphan scan
        append_ext4_deleted_orphans_compact(
            &ext4,
            filesystem_index as u16,
            root_idx,
            &mut tree,
            &journal_hints,
        );
    }

    // Save to binary .scn
    let metadata = serde_json::to_string(&report)?;
    tree.save_to_binary(output_path, &metadata)?;

    tracing::info!(
        "Binary .scn saved: {} nodes, {} memory, {} on disk",
        tree.node_count(),
        bytesize::ByteSize(tree.estimated_memory_bytes() as u64),
        bytesize::ByteSize(std::fs::metadata(output_path).map(|m| m.len()).unwrap_or(0)),
    );

    Ok(())
}

const MAX_TREE_DEPTH_COMPACT: usize = 64;

fn build_ext4_subtree_compact(
    ext4: &Ext4Fs<'_>,
    filesystem_index: u16,
    parent_index: u32,
    entries: &[crate::fs::DirEntry],
    visited: &mut HashSet<u64>,
    tree: &mut compact_tree::CompactTree,
    depth: usize,
    on_event: Option<&dyn Fn(crate::scan::ScanEvent)>,
) {
    if depth >= MAX_TREE_DEPTH_COMPACT {
        return;
    }

    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }

        let mut file_type = entry.file_type;
        let mut size = entry.size;
        let mut deleted = entry.deleted;
        let mut ctime = 0u32;
        let mut mtime = 0u32;
        let mut atime = 0u32;
        let mut dtime = 0u32;

        if entry.inode > 0 {
            if let Ok(inode) = ext4.read_inode(entry.inode) {
                file_type = inode.file_type();
                size = inode.size;
                deleted |= inode.is_deleted();
                ctime = inode.ctime;
                mtime = inode.mtime;
                atime = inode.atime;
                dtime = inode.dtime;
            }
        }

        let node_idx = tree.add_node(
            entry.inode,
            parent_index,
            &entry.name,
            filesystem_index,
            file_type,
            deleted,
            entry.source,
            size,
            entry.parent_inode.unwrap_or(0),
            ctime,
            mtime,
            atime,
            dtime,
        );

        // Progress callback every 500 nodes
        if let Some(cb) = on_event {
            if tree.node_count() % 500 == 0 {
                cb(crate::scan::ScanEvent::TreeBuildProgress {
                    filesystem_index: filesystem_index as usize,
                    files_found: tree.node_count(),
                    dirs_found: 0, bytes_offset: 0,
                });
            }
        }

        if file_type == FileType::Directory && entry.inode > 0 && visited.insert(entry.inode) {
            match ext4.list_directory(entry.inode) {
                Ok(children) => {
                    build_ext4_subtree_compact(
                        ext4,
                        filesystem_index,
                        node_idx,
                        &children,
                        visited,
                        tree,
                        depth + 1,
                        on_event,
                    );
                }
                Err(err) => {
                    tree.add_warning(format_traversal_warning(
                        &tree.compute_path(node_idx),
                        &format!("failed to read directory (inode {}): {}", entry.inode, err),
                    ));
                }
            }
            visited.remove(&entry.inode);
        }
    }
}

fn append_ext4_all_inodes_compact(
    ext4: &Ext4Fs<'_>,
    filesystem_index: u16,
    root_idx: u32,
    tree: &mut compact_tree::CompactTree,
    journal_hints: &std::collections::HashMap<u64, String>,
    on_event: Option<&dyn Fn(crate::scan::ScanEvent)>,
) {
    let inode_size = ext4.superblock.inode_size as usize;
    let inodes_per_group = ext4.superblock.inodes_per_group;
    let block_size = ext4.superblock.block_size() as usize;
    let num_groups = (ext4.superblock.inodes_count + inodes_per_group - 1) / inodes_per_group;
    let inodes_per_block = block_size / inode_size;

    let recovered_dir = tree.add_node(
        0, root_idx, "$RecoveredFiles", filesystem_index,
        FileType::Directory, false, EntrySource::SyntheticOrphan,
        u64::MAX, 0, 0, 0, 0, 0,
    );

    let mut found = 0usize;
    let mut seen = HashSet::new();

    for group in 0..num_groups {
        let bg = match ext4.read_group_descriptor(group) {
            Ok(bg) => bg,
            Err(_) => continue,
        };
        if bg.inode_table == 0 || bg.inode_table >= ext4.superblock.blocks_count {
            continue;
        }

        let inode_table_blocks = (inodes_per_group as usize * inode_size + block_size - 1) / block_size;

        for tbl_block in 0..inode_table_blocks {
            let abs_block = bg.inode_table + tbl_block as u64;
            let block_data = match ext4.read_block(abs_block) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for slot in 0..inodes_per_block {
                let local_index = tbl_block * inodes_per_block + slot;
                if local_index >= inodes_per_group as usize {
                    break;
                }

                let inode_num = group as u64 * inodes_per_group as u64 + local_index as u64 + 1;
                if inode_num <= 10 || !seen.insert(inode_num) {
                    continue;
                }

                let off = slot * inode_size;
                if off + inode_size > block_data.len() {
                    break;
                }

                let data = &block_data[off..off + inode_size];
                let mode = u16::from_le_bytes([data[0], data[1]]);
                let size_lo = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
                let dtime = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));
                let links_count = u16::from_le_bytes([data[26], data[27]]);
                let mtime = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4]));
                let atime = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
                let ctime = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4]));
                let size_hi = if data.len() >= 112 {
                    u32::from_le_bytes(data[108..112].try_into().unwrap_or([0; 4]))
                } else {
                    0
                };
                let size = (size_hi as u64) << 32 | size_lo as u64;

                if mode == 0 || size == 0 {
                    continue;
                }

                let is_deleted = dtime != 0 || links_count == 0;
                let file_type = match mode & 0xF000 {
                    0x4000 => FileType::Directory,
                    0x8000 => FileType::RegularFile,
                    0xA000 => FileType::Symlink,
                    _ => continue,
                };

                let basename = journal_hints
                    .get(&inode_num)
                    .map(|s| s.as_str())
                    .unwrap_or_else(|| if is_deleted { "OrphanFile" } else { "File" });

                // Use inode number in name to make it unique
                let full_name = if basename == "OrphanFile" || basename == "File" {
                    format!("{}-{}", basename, inode_num)
                } else {
                    basename.to_string()
                };

                tree.add_node(
                    inode_num, recovered_dir, &full_name, filesystem_index,
                    file_type, is_deleted,
                    if is_deleted { EntrySource::SyntheticOrphan } else { EntrySource::Filesystem },
                    size, 0, ctime, mtime, atime, dtime,
                );

                found += 1;

                if let Some(cb) = on_event {
                    if found % 500 == 0 {
                        cb(crate::scan::ScanEvent::TreeBuildProgress {
                            filesystem_index: filesystem_index as usize,
                            files_found: found,
                            dirs_found: 0, bytes_offset: 0,
                        });
                    }
                }
            }
        }
    }

    if found > 0 {
        tracing::info!("Full inode scan found {} recoverable inodes", found);
    }
}

fn append_ext4_deleted_orphans_compact(
    ext4: &Ext4Fs<'_>,
    filesystem_index: u16,
    root_idx: u32,
    tree: &mut compact_tree::CompactTree,
    journal_hints: &std::collections::HashMap<u64, String>,
) {
    let deleted_inodes = match ext4.scan_deleted_inodes() {
        Ok(d) => d,
        Err(_) => return,
    };

    if deleted_inodes.is_empty() {
        return;
    }

    // Check which inodes are already in the tree
    let existing: HashSet<u64> = tree
        .nodes
        .iter()
        .filter(|n| n.inode != 0)
        .map(|n| n.inode)
        .collect();

    let orphans: Vec<_> = deleted_inodes
        .into_iter()
        .filter(|d| !existing.contains(&d.inode_num))
        .collect();

    if orphans.is_empty() {
        return;
    }

    let orphan_dir = tree.add_node(
        0, root_idx, "$OrphanFiles", filesystem_index,
        FileType::Directory, false, EntrySource::SyntheticOrphan,
        u64::MAX, 0, 0, 0, 0, 0,
    );

    for orphan in &orphans {
        let basename = journal_hints
            .get(&orphan.inode_num)
            .cloned()
            .unwrap_or_else(|| format!("OrphanFile-{}", orphan.inode_num));

        tree.add_node(
            orphan.inode_num, orphan_dir, &basename, filesystem_index,
            orphan.file_type, true, EntrySource::SyntheticOrphan,
            orphan.size, 0, orphan.ctime, orphan.mtime, orphan.atime, orphan.dtime,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn build_ext4_subtree(
    ext4: &Ext4Fs<'_>,
    filesystem_index: usize,
    parent_id: u64,
    parent_path: PathBuf,
    entries: &[crate::fs::DirEntry],
    visited_dirs: &mut HashSet<u64>,
    next_node_id: &mut u64,
    nodes: &mut Vec<SessionNode>,
    warnings: &mut Vec<String>,
    depth: usize,
    on_event: Option<&dyn Fn(crate::scan::ScanEvent)>,
) -> Result<()> {
    if depth >= MAX_TREE_DEPTH {
        return Ok(());
    }

    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }

        let path_buf = parent_path.join(&entry.name);
        let normalized_path = format!("/{}", path_buf.display());
        let mut file_type = entry.file_type;
        let mut size = if entry.size > 0 {
            Some(entry.size)
        } else {
            None
        };
        let mut deleted = entry.deleted;
        let mut timestamps = None;

        if entry.inode > 0 {
            if let Ok(inode) = ext4.read_inode(entry.inode) {
                file_type = inode.file_type();
                size = Some(inode.size);
                deleted |= inode.is_deleted();
                timestamps = session_timestamps_from_inode(&inode);
            }
        }

        let node_id = *next_node_id;
        *next_node_id += 1;

        nodes.push(SessionNode {
            id: node_id,
            parent_id: Some(parent_id),
            filesystem_index,
            inode: if entry.inode > 0 {
                Some(entry.inode)
            } else {
                None
            },
            basename: entry.name.clone(),
            path: normalized_path.clone(),
            file_type,
            deleted,
            size,
            source: entry.source,
            parent_inode: entry.parent_inode,
            timestamps,
        });

        // Emit tree build progress every 500 nodes
        if let Some(cb) = on_event {
            if nodes.len() % 500 == 0 {
                let dirs = nodes.iter().filter(|n| n.file_type == FileType::Directory).count();
                cb(crate::scan::ScanEvent::TreeBuildProgress {
                    filesystem_index,
                    files_found: nodes.len() - dirs,
                    dirs_found: dirs,
                    bytes_offset: 0,
                });
            }
        }

        if file_type == FileType::Directory && entry.inode > 0 && visited_dirs.insert(entry.inode) {
            match ext4.list_directory(entry.inode) {
                Ok(children) => {
                    build_ext4_subtree(
                        ext4,
                        filesystem_index,
                        node_id,
                        path_buf,
                        &children,
                        visited_dirs,
                        next_node_id,
                        nodes,
                        warnings,
                        depth + 1,
                        on_event,
                    )?;
                }
                Err(err) => warnings.push(format_traversal_warning(
                        &normalized_path,
                        &format!(
                            "failed to read directory children (inode {}): {}",
                            entry.inode, err
                        ),
                    ).to_string()),
            }
            visited_dirs.remove(&entry.inode);
        }
    }

    Ok(())
}

/// Scan ALL block groups for any readable inodes (live or deleted).
/// Used when the root directory is corrupt (e.g., Proxmox overwrote block group 0).
/// Builds a flat list under /$RecoveredFiles/ with journal-recovered names.
#[allow(clippy::too_many_arguments)]
fn append_ext4_all_inodes(
    ext4: &Ext4Fs<'_>,
    filesystem_index: usize,
    root_id: u64,
    next_node_id: &mut u64,
    nodes: &mut Vec<SessionNode>,
    warnings: &mut Vec<String>,
    journal_hints: &std::collections::HashMap<u64, String>,
    on_event: Option<&dyn Fn(crate::scan::ScanEvent)>,
) {
    let inode_size = ext4.superblock.inode_size as usize;
    let inodes_per_group = ext4.superblock.inodes_per_group;
    let block_size = ext4.superblock.block_size() as usize;
    let num_groups = (ext4.superblock.inodes_count + inodes_per_group - 1) / inodes_per_group;
    let inodes_per_block = block_size / inode_size;

    // Create a virtual directory for recovered files
    let recovered_dir_id = *next_node_id;
    *next_node_id += 1;
    nodes.push(SessionNode {
        id: recovered_dir_id,
        parent_id: Some(root_id),
        filesystem_index,
        inode: None,
        basename: "$RecoveredFiles".to_string(),
        path: "/$RecoveredFiles".to_string(),
        file_type: FileType::Directory,
        deleted: false,
        size: None,
        source: EntrySource::SyntheticOrphan,
        parent_inode: None,
        timestamps: None,
    });

    let mut found_count = 0usize;
    let mut referenced_inodes = HashSet::new();
    referenced_inodes.insert(2u64); // root

    for group in 0..num_groups {
        let bg = match ext4.read_group_descriptor(group) {
            Ok(bg) => bg,
            Err(_) => continue,
        };
        if bg.inode_table == 0 || bg.inode_table >= ext4.superblock.blocks_count {
            continue;
        }

        let inode_table_blocks =
            (inodes_per_group as usize * inode_size + block_size - 1) / block_size;

        for tbl_block in 0..inode_table_blocks {
            let abs_block = bg.inode_table + tbl_block as u64;
            let block_data = match ext4.read_block(abs_block) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for slot in 0..inodes_per_block {
                let local_index = tbl_block * inodes_per_block + slot;
                if local_index >= inodes_per_group as usize {
                    break;
                }

                let inode_num = group as u64 * inodes_per_group as u64 + local_index as u64 + 1;
                if inode_num <= 10 || referenced_inodes.contains(&inode_num) {
                    continue;
                }

                let off = slot * inode_size;
                if off + inode_size > block_data.len() {
                    break;
                }

                let data = &block_data[off..off + inode_size];
                let mode = u16::from_le_bytes([data[0], data[1]]);
                let size_lo = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
                let links_count = u16::from_le_bytes([data[26], data[27]]);
                let dtime = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));
                let mtime = u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4]));
                let atime = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
                let ctime = u32::from_le_bytes(data[12..16].try_into().unwrap_or([0; 4]));
                let size_hi = if data.len() >= 112 {
                    u32::from_le_bytes(data[108..112].try_into().unwrap_or([0; 4]))
                } else {
                    0
                };
                let size = (size_hi as u64) << 32 | size_lo as u64;

                // Skip empty/unused inodes
                if mode == 0 || size == 0 {
                    continue;
                }

                let is_deleted = dtime != 0 || links_count == 0;
                let file_type = match mode & 0xF000 {
                    0x4000 => FileType::Directory,
                    0x8000 => FileType::RegularFile,
                    0xA000 => FileType::Symlink,
                    _ => continue,
                };

                let basename = journal_hints
                    .get(&inode_num)
                    .cloned()
                    .unwrap_or_else(|| {
                        if is_deleted {
                            format!("OrphanFile-{}", inode_num)
                        } else {
                            format!("File-{}", inode_num)
                        }
                    });
                let path = format!("/$RecoveredFiles/{}", basename);

                let node_id = *next_node_id;
                *next_node_id += 1;
                nodes.push(SessionNode {
                    id: node_id,
                    parent_id: Some(recovered_dir_id),
                    filesystem_index,
                    inode: Some(inode_num),
                    basename,
                    path,
                    file_type,
                    deleted: is_deleted,
                    size: Some(size),
                    source: if is_deleted {
                        EntrySource::SyntheticOrphan
                    } else {
                        EntrySource::Filesystem
                    },
                    parent_inode: None,
                    timestamps: Some(SessionNodeTimestamps {
                        created_unix: nonzero_unix_timestamp(ctime),
                        modified_unix: nonzero_unix_timestamp(mtime),
                        accessed_unix: nonzero_unix_timestamp(atime),
                        deleted_unix: nonzero_unix_timestamp(dtime),
                    })
                    .filter(|ts| {
                        ts.created_unix.is_some()
                            || ts.modified_unix.is_some()
                            || ts.accessed_unix.is_some()
                            || ts.deleted_unix.is_some()
                    }),
                });

                referenced_inodes.insert(inode_num);
                found_count += 1;

                if let Some(cb) = on_event {
                    if found_count % 500 == 0 {
                        cb(crate::scan::ScanEvent::TreeBuildProgress {
                            filesystem_index,
                            files_found: found_count,
                            dirs_found: 0, bytes_offset: 0,
                        });
                    }
                }
            }
        }
    }

    if found_count > 0 {
        tracing::info!(
            "Full inode scan found {} recoverable inodes across all block groups",
            found_count
        );
    } else {
        warnings.push(format_traversal_warning(
            "/$RecoveredFiles",
            "No recoverable inodes found in any block group",
        ));
    }
}

fn append_ext4_deleted_orphans(
    ext4: &Ext4Fs<'_>,
    filesystem_index: usize,
    root_id: u64,
    next_node_id: &mut u64,
    nodes: &mut Vec<SessionNode>,
    warnings: &mut Vec<String>,
    journal_hints: &std::collections::HashMap<u64, String>,
) {
    let deleted_inodes = match ext4.scan_deleted_inodes() {
        Ok(deleted) => deleted,
        Err(err) => {
            tracing::warn!(
                "failed to scan deleted inodes for filesystem {} while building session: {}",
                filesystem_index,
                err
            );
            return;
        }
    };

    let mut referenced_inodes: HashSet<u64> = nodes.iter().filter_map(|node| node.inode).collect();
    let mut orphan_inodes: Vec<_> = deleted_inodes
        .into_iter()
        .filter(|inode| !referenced_inodes.contains(&inode.inode_num))
        .collect();
    if orphan_inodes.is_empty() {
        return;
    }

    orphan_inodes.sort_by_key(|inode| (inode.file_type != FileType::Directory, inode.inode_num));

    let orphan_dir_id = *next_node_id;
    *next_node_id += 1;
    nodes.push(SessionNode {
        id: orphan_dir_id,
        parent_id: Some(root_id),
        filesystem_index,
        inode: None,
        basename: "$OrphanFiles".to_string(),
        path: "/$OrphanFiles".to_string(),
        file_type: FileType::Directory,
        deleted: false,
        size: None,
        source: EntrySource::SyntheticOrphan,
        parent_inode: None,
        timestamps: None,
    });

    let mut visited_dirs = HashSet::new();
    for orphan in orphan_inodes {
        if referenced_inodes.contains(&orphan.inode_num) {
            continue;
        }

        let node_id = *next_node_id;
        *next_node_id += 1;
        let orphan_basename = journal_hints
            .get(&orphan.inode_num)
            .cloned()
            .unwrap_or_else(|| format!("OrphanFile-{}", orphan.inode_num));
        let orphan_path = format!("/$OrphanFiles/{}", orphan_basename);
        nodes.push(SessionNode {
            id: node_id,
            parent_id: Some(orphan_dir_id),
            filesystem_index,
            inode: Some(orphan.inode_num),
            basename: orphan_basename.clone(),
            path: orphan_path,
            file_type: orphan.file_type,
            deleted: true,
            size: Some(orphan.size),
            source: EntrySource::SyntheticOrphan,
            parent_inode: None,
            timestamps: session_timestamps_from_deleted_inode(&orphan),
        });
        referenced_inodes.insert(orphan.inode_num);

        if orphan.file_type == FileType::Directory && visited_dirs.insert(orphan.inode_num) {
            let subtree_start = nodes.len();
            match ext4.list_directory(orphan.inode_num) {
                Ok(children) => {
                    if let Err(err) = build_ext4_subtree(
                        ext4,
                        filesystem_index,
                        node_id,
                        PathBuf::from("$OrphanFiles").join(&orphan_basename),
                        &children,
                        &mut visited_dirs,
                        next_node_id,
                        nodes,
                        warnings,
                        0,
                        None,
                    ) {
                        tracing::warn!(
                            "failed to build deleted orphan subtree for inode {} in filesystem {}: {}",
                            orphan.inode_num,
                            filesystem_index,
                            err
                        );
                        warnings.push(format_traversal_warning(
                            &format!("/$OrphanFiles/{}", orphan_basename),
                            &format!(
                                "failed to build deleted orphan subtree for inode {}: {}",
                                orphan.inode_num, err
                            ),
                        ));
                    } else {
                        for node in &nodes[subtree_start..] {
                            if let Some(inode) = node.inode {
                                referenced_inodes.insert(inode);
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "failed to read deleted orphan directory inode {} in filesystem {}: {}",
                        orphan.inode_num,
                        filesystem_index,
                        err
                    );
                    warnings.push(format_traversal_warning(
                        &format!("/$OrphanFiles/{}", orphan_basename),
                        &format!(
                            "failed to read deleted orphan directory inode {}: {}",
                            orphan.inode_num, err
                        ),
                    ));
                }
            }
        }
    }
}

fn minimal_filesystem_sessions(report: &ScanReport) -> Vec<FilesystemSessionArtifact> {
    report
        .filesystems
        .iter()
        .enumerate()
        .map(|(filesystem_index, fs_info)| FilesystemSessionArtifact {
            filesystem_index,
            fs_info: fs_info.clone(),
            root_node_id: None,
            warnings: Vec::new(),
            nodes: Vec::new(),
        })
        .collect()
}

fn format_traversal_warning(path: &str, message: &str) -> String {
    format!("path {}: {}", normalize_session_path(path), message)
}

fn traversal_warning_matches_path(warning: &str, normalized_path: &str) -> bool {
    if let Some(path) = traversal_warning_path(warning) {
        return path == normalized_path;
    }

    if normalized_path == "/" {
        return warning.contains("root directory")
            || warning.contains("root inode")
            || warning.contains("open ext4 filesystem")
            || warning.contains("full session tree");
    }

    warning.contains(&format!("directory {}", normalized_path))
}

fn traversal_warning_path(warning: &str) -> Option<&str> {
    warning
        .strip_prefix("path ")
        .and_then(|rest| rest.split_once(": "))
        .map(|(path, _)| path)
}

fn normalize_session_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else {
        format!("/{}", trimmed.trim_start_matches('/'))
    }
}

fn parse_budget_bytes(value: &str) -> Result<u64> {
    value
        .parse::<bytesize::ByteSize>()
        .map(|parsed| parsed.as_u64())
        .map_err(|err| anyhow::anyhow!("invalid memory budget {}: {}", value, err))
}

fn estimate_path_index_bytes(index: &HashMap<(usize, String), NodeLocation>) -> u64 {
    index
        .keys()
        .map(|(_, path)| path.len() as u64 + std::mem::size_of::<usize>() as u64 * 2)
        .sum()
}

fn estimate_children_index_bytes(index: &HashMap<u64, Vec<NodeLocation>>) -> u64 {
    index.values().map(|children| {
            std::mem::size_of::<u64>() as u64
                + children.len() as u64 * std::mem::size_of::<usize>() as u64
        })
        .sum()
}

fn canonicalize_best_effort(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
