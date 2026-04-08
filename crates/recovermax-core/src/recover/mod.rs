use std::collections::HashSet;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use crate::fs::ext4::Ext4Fs;
use crate::fs::{DirEntry, FileType};
use crate::io::ImageReader;
use crate::scan::ScanReport;
use crate::session::{RecoverySession, RecoverySessionArtifact, SessionNode};

/// Files larger than this threshold are streamed directly to disk
/// instead of buffered in memory. 1 MB.
const STREAMING_THRESHOLD: u64 = 1024 * 1024;

pub struct Recoverer<'a> {
    reader: &'a ImageReader,
    dest: &'a Path,
}

impl<'a> Recoverer<'a> {
    pub fn new(reader: &'a ImageReader, dest: &'a Path) -> Self {
        Self { reader, dest }
    }

    pub fn recover(&self, report: &ScanReport, path_filter: Option<&str>) -> Result<()> {
        std::fs::create_dir_all(self.dest)?;

        for fs_info in &report.filesystems {
            if fs_info.fs_type != "ext4" {
                tracing::warn!("Skipping unsupported filesystem: {}", fs_info.fs_type);
                continue;
            }

            println!(
                "Recovering from ext4 at offset {} ({})",
                bytesize::ByteSize(fs_info.offset),
                fs_info.label
            );

            let ext4 = Ext4Fs::new(self.reader, fs_info.offset)?;

            // Start from root inode (2)
            let root_entries = ext4.list_directory(2)?;

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap(),
            );

            self.recover_recursive(&ext4, &root_entries, PathBuf::new(), path_filter, &pb, 0)?;

            pb.finish_with_message("Recovery complete.");
        }

        Ok(())
    }

    pub fn recover_artifact(
        &self,
        artifact: &RecoverySessionArtifact,
        path_filter: Option<&str>,
    ) -> Result<()> {
        if artifact
            .filesystems
            .iter()
            .any(|filesystem| filesystem.has_tree())
        {
            let mut session = RecoverySession::from_artifact(artifact.clone(), None);
            return self.recover_session(&mut session, path_filter);
        }

        self.recover(artifact.report(), path_filter)
    }

    pub fn recover_session(
        &self,
        session: &mut RecoverySession,
        path_filter: Option<&str>,
    ) -> Result<()> {
        std::fs::create_dir_all(self.dest)?;
        let filesystems = session.filesystems().to_vec();

        for filesystem in &filesystems {
            if filesystem.fs_info.fs_type != "ext4" {
                tracing::warn!(
                    "Skipping unsupported filesystem: {}",
                    filesystem.fs_info.fs_type
                );
                continue;
            }

            let selected_node = if let Some(filter) = path_filter {
                if filesystem.has_tree() {
                    match session.resolve_node(filesystem.filesystem_index, filter) {
                        Ok(node) => Some(node),
                        Err(_) => continue,
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let reader = session.attached_reader().unwrap_or(self.reader);

            println!(
                "Recovering from ext4 at offset {} ({})",
                bytesize::ByteSize(filesystem.fs_info.offset),
                filesystem.fs_info.label
            );

            let ext4 = Ext4Fs::new(reader, filesystem.fs_info.offset)?;
            if let Some(node) = selected_node.as_ref() {
                if node.file_type == FileType::Directory {
                    if node.inode.is_some() {
                        self.recover_session_subtree(&ext4, node)?;
                        continue;
                    }
                } else {
                    self.recover_session_node(&ext4, node)?;
                    continue;
                }
            }
            let root_entries = ext4.list_directory(2)?;

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap(),
            );

            self.recover_recursive(&ext4, &root_entries, PathBuf::new(), path_filter, &pb, 0)?;
            pb.finish_with_message("Recovery complete.");
        }

        Ok(())
    }

    pub fn recover_session_node(&self, ext4: &Ext4Fs, node: &SessionNode) -> Result<()> {
        self.recover_session_node_to_path(ext4, node, None)
    }

    pub fn recover_session_node_to_path(
        &self,
        ext4: &Ext4Fs,
        node: &SessionNode,
        output_path: Option<&str>,
    ) -> Result<()> {
        let relative_path = output_path.unwrap_or(&node.path).trim_start_matches('/');
        let dest_path = self.dest.join(relative_path);
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        match node.file_type {
            FileType::RegularFile => {
                let inode_num = node
                    .inode
                    .ok_or_else(|| anyhow::anyhow!("session node {} has no inode", node.path))?;
                let inode = ext4.read_inode(inode_num)?;
                if inode.size >= STREAMING_THRESHOLD {
                    let file = std::fs::File::create(&dest_path)?;
                    let mut writer = BufWriter::new(file);
                    ext4.stream_inode_data(&inode, &mut writer)?;
                } else {
                    let data = ext4.read_inode_data(&inode)?;
                    std::fs::write(&dest_path, &data)?;
                }
            }
            FileType::Symlink => {
                let inode_num = node
                    .inode
                    .ok_or_else(|| anyhow::anyhow!("session node {} has no inode", node.path))?;
                let inode = ext4.read_inode(inode_num)?;
                let target = if inode.size < 60 && !inode.uses_extents() {
                    let len = inode.size as usize;
                    String::from_utf8_lossy(&inode.block_data[..len]).to_string()
                } else {
                    let data = ext4.read_inode_data(&inode)?;
                    String::from_utf8_lossy(&data).to_string()
                };
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    symlink(target, &dest_path)?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::write(&dest_path, target.as_bytes())?;
                }
            }
            FileType::Directory => {
                std::fs::create_dir_all(&dest_path)?;
            }
            FileType::Other => {
                anyhow::bail!(
                    "node {} has unsupported type {:?}",
                    node.path,
                    node.file_type
                );
            }
        }

        Ok(())
    }

    pub fn recover_session_subtree(&self, ext4: &Ext4Fs, node: &SessionNode) -> Result<()> {
        self.recover_session_subtree_to_path(ext4, node, None)
    }

    pub fn recover_session_subtree_to_path(
        &self,
        ext4: &Ext4Fs,
        node: &SessionNode,
        output_path: Option<&str>,
    ) -> Result<()> {
        let inode_num = node
            .inode
            .ok_or_else(|| anyhow::anyhow!("session node {} has no inode", node.path))?;
        let relative_path = output_path.unwrap_or(&node.path).trim_start_matches('/');
        let dest_path = self.dest.join(relative_path);
        std::fs::create_dir_all(&dest_path)?;

        let entries = ext4.list_directory(inode_num)?;
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );

        let mut visited_dirs = HashSet::from([inode_num]);
        self.recover_recursive_with_visited(
            ext4,
            &entries,
            PathBuf::from(relative_path),
            None,
            &pb,
            &mut visited_dirs,
            0,
        )?;
        pb.finish_with_message("Recovery complete.");
        Ok(())
    }

    fn recover_recursive(
        &self,
        ext4: &Ext4Fs,
        entries: &[DirEntry],
        current_path: PathBuf,
        path_filter: Option<&str>,
        pb: &ProgressBar,
        depth: usize,
    ) -> Result<()> {
        let mut visited_dirs = HashSet::from([2u64]);
        self.recover_recursive_with_visited(
            ext4,
            entries,
            current_path,
            path_filter,
            pb,
            &mut visited_dirs,
            depth,
        )
    }

    fn recover_recursive_with_visited(
        &self,
        ext4: &Ext4Fs,
        entries: &[DirEntry],
        current_path: PathBuf,
        path_filter: Option<&str>,
        pb: &ProgressBar,
        visited_dirs: &mut HashSet<u64>,
        depth: usize,
    ) -> Result<()> {
        if depth > 64 {
            tracing::warn!("Max depth reached at {}", current_path.display());
            return Ok(());
        }

        for entry in entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }

            let entry_path = current_path.join(&entry.name);
            let entry_path_str = entry_path.to_string_lossy();

            // Apply path filter
            if let Some(filter) = path_filter {
                let filter_trimmed = filter.trim_start_matches('/');
                if !entry_path_str.starts_with(filter_trimmed)
                    && !filter_trimmed.starts_with(&*entry_path_str)
                {
                    continue;
                }
            }

            pb.set_message(format!("/{}", entry_path.display()));

            match entry.file_type {
                FileType::Directory => {
                    let dest_dir = self.dest.join(&entry_path);
                    std::fs::create_dir_all(&dest_dir)?;

                    if entry.inode > 0 && visited_dirs.insert(entry.inode) {
                        match ext4.list_directory(entry.inode) {
                            Ok(sub_entries) => {
                                self.recover_recursive_with_visited(
                                    ext4,
                                    &sub_entries,
                                    entry_path,
                                    path_filter,
                                    pb,
                                    visited_dirs,
                                    depth + 1,
                                )?;
                            }
                            Err(e) => {
                                tracing::warn!("Failed to read dir inode {}: {}", entry.inode, e);
                            }
                        }
                    }
                }

                FileType::RegularFile => {
                    if entry.inode > 0 {
                        let dest_file = self.dest.join(&entry_path);
                        if let Some(parent) = dest_file.parent() {
                            std::fs::create_dir_all(parent)?;
                        }

                        match ext4.read_inode(entry.inode) {
                            Ok(inode) => {
                                if inode.size >= STREAMING_THRESHOLD {
                                    // Stream large files directly to disk
                                    match std::fs::File::create(&dest_file) {
                                        Ok(file) => {
                                            let mut writer = BufWriter::new(file);
                                            match ext4.stream_inode_data(&inode, &mut writer) {
                                                Ok(_) => {
                                                    pb.inc(1);
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        "Failed to stream data for {}: {}",
                                                        entry_path.display(),
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to create file {}: {}",
                                                dest_file.display(),
                                                e
                                            );
                                        }
                                    }
                                } else {
                                    // Buffer small files in memory
                                    match ext4.read_inode_data(&inode) {
                                        Ok(data) => {
                                            std::fs::write(&dest_file, &data)?;
                                            pb.inc(1);
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to read data for {}: {}",
                                                entry_path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to read inode {} for {}: {}",
                                    entry.inode,
                                    entry_path.display(),
                                    e
                                );
                            }
                        }
                    }
                }

                FileType::Symlink => {
                    if entry.inode > 0 {
                        let dest_file = self.dest.join(&entry_path);
                        if let Some(parent) = dest_file.parent() {
                            std::fs::create_dir_all(parent)?;
                        }

                        match ext4.read_inode(entry.inode) {
                            Ok(inode) => {
                                // Short symlinks (< 60 bytes) store target inline in block_data.
                                // Longer ones store it in data blocks like regular files.
                                let target = if inode.size < 60 && !inode.uses_extents() {
                                    let len = inode.size as usize;
                                    String::from_utf8_lossy(&inode.block_data[..len]).to_string()
                                } else {
                                    match ext4.read_inode_data(&inode) {
                                        Ok(data) => String::from_utf8_lossy(&data).to_string(),
                                        Err(e) => {
                                            tracing::warn!(
                                                "Failed to read symlink target for {}: {}",
                                                entry_path.display(),
                                                e
                                            );
                                            continue;
                                        }
                                    }
                                };

                                // Try to create a real symlink; fall back to a text file
                                #[cfg(unix)]
                                {
                                    if std::os::unix::fs::symlink(&target, &dest_file).is_err() {
                                        let _ = std::fs::write(&dest_file, &target);
                                    }
                                }
                                #[cfg(not(unix))]
                                {
                                    let _ = std::fs::write(&dest_file, &target);
                                }
                                pb.inc(1);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to read symlink inode {} for {}: {}",
                                    entry.inode,
                                    entry_path.display(),
                                    e
                                );
                            }
                        }
                    }
                }

                FileType::Other => {}
            }
        }

        Ok(())
    }
}
