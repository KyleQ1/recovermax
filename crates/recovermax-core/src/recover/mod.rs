use std::path::{Path, PathBuf};

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use crate::fs::ext4::Ext4Fs;
use crate::fs::{DirEntry, FileType};
use crate::io::ImageReader;
use crate::scan::ScanReport;

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

            println!("Recovering from ext4 at offset {} ({})",
                bytesize::ByteSize(fs_info.offset), fs_info.label);

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

    fn recover_recursive(
        &self,
        ext4: &Ext4Fs,
        entries: &[DirEntry],
        current_path: PathBuf,
        path_filter: Option<&str>,
        pb: &ProgressBar,
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

                    if entry.inode > 0 {
                        match ext4.list_directory(entry.inode) {
                            Ok(sub_entries) => {
                                self.recover_recursive(
                                    ext4,
                                    &sub_entries,
                                    entry_path,
                                    path_filter,
                                    pb,
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
                            Ok(inode) => match ext4.read_inode_data(&inode) {
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
                            },
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
                                                entry_path.display(), e
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
                                    entry.inode, entry_path.display(), e
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
