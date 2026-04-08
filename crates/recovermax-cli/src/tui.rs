use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::cli::{
    deleted_recovery_hint_message, filesystem_has_tree, list_children_with_fallback,
    recover_with_fallback, resolve_node_with_fallback, resolve_recovery_target,
    search_with_fallback, walk_tree_with_fallback,
};
use anyhow::{anyhow, Context, Result};
use recovermax_core::fs::EntrySource;
use recovermax_core::io::ImageReader;
use recovermax_core::scan::Scanner;
use recovermax_core::search::{SearchMatch, SearchOptions};
use recovermax_core::session::{
    CacheSummary, RecoverySession, RecoverySessionArtifact, SessionNode, SessionTreeEntry,
};

pub fn run_image_picker() -> Result<()> {
    let mut entries = discover_items();
    entries.sort_by(|a, b| a.display_path.cmp(&b.display_path));

    println!("RecoverMax");
    println!();
    if entries.is_empty() {
        println!("No candidate images found in common recovery locations.");
        println!("Use scripted commands like 'recovermax scan <image> -o file.scn' for now.");
        return Ok(());
    }

    println!("Discovered images and scans:");
    for (i, item) in entries.iter().enumerate() {
        println!(
            "  [{}] {} [{}]",
            i,
            item.display_path.display(),
            item.kind_label()
        );
    }
    println!();
    println!("Commands:");
    println!("  open <index>          Open an image or scan");
    println!("  filter <text>         Filter list by substring");
    println!("  rescan                Refresh list");
    println!("  quit                  Exit");
    println!();

    let stdin = io::stdin();
    let mut current = entries;

    loop {
        print!("recovermax> ");
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "quit" | "exit" => break,
            "rescan" => {
                current = discover_items();
                current.sort_by(|a, b| a.display_path.cmp(&b.display_path));
                for (i, item) in current.iter().enumerate() {
                    println!(
                        "  [{}] {} [{}]",
                        i,
                        item.display_path.display(),
                        item.kind_label()
                    );
                }
            }
            "filter" => {
                if parts.len() < 2 {
                    println!("Usage: filter <text>");
                    continue;
                }
                let needle = line[parts[0].len()..].trim().to_lowercase();
                let filtered: Vec<DiscoveredItem> = discover_items()
                    .into_iter()
                    .filter(|item| {
                        item.display_path
                            .to_string_lossy()
                            .to_lowercase()
                            .contains(&needle)
                    })
                    .collect();
                current = filtered;
                if current.is_empty() {
                    println!("No matching images or scans.");
                } else {
                    for (i, item) in current.iter().enumerate() {
                        println!(
                            "  [{}] {} [{}]",
                            i,
                            item.display_path.display(),
                            item.kind_label()
                        );
                    }
                }
            }
            "open" => {
                if parts.len() != 2 {
                    println!("Usage: open <index>");
                    continue;
                }
                let idx: usize = match parts[1].parse() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("Invalid index: {}", parts[1]);
                        continue;
                    }
                };
                let Some(item) = current.get(idx) else {
                    println!("Index out of range.");
                    continue;
                };
                match item.kind {
                    ItemKind::Image => run_tui(&item.display_path, None)?,
                    ItemKind::Scan => {
                        let image = item.resolve_image_path()?;
                        run_tui(&image, Some(&item.display_path))?;
                    }
                }
                println!();
                println!("Returned to image picker.");
            }
            other => println!("Unknown command: {}", other),
        }
    }

    Ok(())
}

pub fn run_tui(image_path: &Path, scan_file: Option<&Path>) -> Result<()> {
    let reader = ImageReader::open(image_path)?;
    let artifact = if let Some(scan_file) = scan_file {
        let artifact = RecoverySessionArtifact::load_from_path(scan_file)?;
        artifact.validate_for_image_with_artifact_path(
            image_path,
            reader.len(),
            Some(scan_file),
        )?;
        artifact
    } else {
        let scanner = Scanner::new(&reader);
        let report = scanner.full_scan()?;
        RecoverySessionArtifact::from_scan(image_path, &reader, report)?
    };

    let mut session = RecoverySession::from_artifact_with_reader(artifact, reader, None);
    let mut ui = SessionShell::new(image_path.to_path_buf(), &mut session);
    ui.run()
}

struct SessionShell<'a> {
    image_path: PathBuf,
    session: &'a mut RecoverySession,
    current_fs: usize,
    current_path: String,
}

impl<'a> SessionShell<'a> {
    fn new(image_path: PathBuf, session: &'a mut RecoverySession) -> Self {
        let current_fs = default_filesystem_index(session.filesystems()).unwrap_or(0);
        Self {
            image_path,
            session,
            current_fs,
            current_path: "/".to_string(),
        }
    }

    fn run(&mut self) -> Result<()> {
        self.print_header();
        self.print_help();

        let stdin = io::stdin();
        loop {
            print!(
                "recovermax:tui[fs {} {}]> ",
                self.current_fs, self.current_path
            );
            io::stdout().flush()?;

            let mut line = String::new();
            if stdin.read_line(&mut line)? == 0 {
                break;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts[0] {
                "quit" | "exit" => break,
                "back" => break,
                "help" => self.print_help(),
                "filesystems" | "fs" => self.print_filesystems(),
                "usefs" => self.command_usefs(&parts)?,
                "pwd" => println!("{}", self.current_path),
                "cd" => self.command_cd(line)?,
                "ls" => self.command_ls(line)?,
                "tree" => self.command_tree(line)?,
                "stat" => self.command_stat(line)?,
                "search" => self.command_search(line, None)?,
                "searchfs" => self.command_searchfs(line)?,
                "recover" => self.command_recover(line)?,
                "cache" => self.command_cache(),
                "unload" => self.command_unload(),
                "save" => self.command_save(&parts)?,
                other => {
                    println!("Unknown command: {}", other);
                    self.print_help();
                }
            }
        }

        Ok(())
    }

    fn print_header(&self) {
        println!("RecoverMax TUI");
        println!("Image: {}", self.image_path.display());
        println!();
    }

    fn print_help(&self) {
        println!("Commands:");
        println!("  filesystems            List discovered filesystems");
        println!("  usefs <index>          Switch active filesystem");
        println!("  pwd                    Print active path");
        println!("  cd <path>              Change active path");
        println!("  ls [path]              List directory entries");
        println!("  tree [path] [depth]    Print a browsable tree");
        println!("  stat <path|inode>      Show node metadata");
        println!("  search <query>         Search the session tree");
        println!("  searchfs <idx> <q>     Search one filesystem");
        println!("  recover <dest> [path]  Recover current path or a specific target");
        println!("  cache                  Show runtime cache summary");
        println!("  unload                 Evict RecoverMax-managed caches");
        println!("  save <path.scn>        Save current session artifact");
        println!("  back                   Return to image picker");
        println!("  quit                   Exit");
        println!();
    }

    fn print_filesystems(&self) {
        println!("Filesystems:");
        for (i, fs) in self.session.filesystems().iter().enumerate() {
            let mut tree_state = if fs.has_tree() {
                "tree".to_string()
            } else if self.session.attached_reader().is_some() && fs.fs_info.fs_type == "ext4" {
                "report-only; live-fallback".to_string()
            } else {
                "report".to_string()
            };
            if !fs.warnings.is_empty() {
                tree_state.push_str(&format!("; warnings: {}", fs.warnings.len()));
            }
            println!(
                "  [{}] {} \"{}\" ({}) [{}]",
                i,
                fs.fs_info.fs_type,
                fs.fs_info.label,
                bytesize::ByteSize(fs.fs_info.total_size),
                tree_state
            );
        }
    }

    fn command_usefs(&mut self, parts: &[&str]) -> Result<()> {
        if parts.len() != 2 {
            println!("Usage: usefs <index>");
            return Ok(());
        }

        let idx: usize = parts[1]
            .parse()
            .with_context(|| format!("invalid filesystem index: {}", parts[1]))?;
        if idx >= self.session.filesystems().len() {
            println!("Filesystem index out of range.");
            return Ok(());
        }

        self.current_fs = idx;
        self.current_path = "/".to_string();
        println!("Active filesystem set to {}", idx);
        Ok(())
    }

    fn command_cd(&mut self, line: &str) -> Result<()> {
        let path = command_arg(line, "cd");
        if path.is_empty() {
            println!("Usage: cd <path>");
            return Ok(());
        }

        let resolved = self.resolve_path(path);
        resolve_node_with_fallback(self.session, self.current_fs, &resolved)
            .with_context(|| format!("path {} not found", resolved))?;
        self.current_path = resolved;
        Ok(())
    }

    fn command_ls(&mut self, line: &str) -> Result<()> {
        let path = command_arg(line, "ls");
        let target = if path.is_empty() {
            self.current_path.clone()
        } else {
            self.resolve_path(path)
        };

        let node = resolve_node_with_fallback(self.session, self.current_fs, &target)?;
        if node.file_type != recovermax_core::fs::FileType::Directory {
            self.print_stat(&node);
            return Ok(());
        }

        let children = list_children_with_fallback(self.session, self.current_fs, &target)?;
        if children.is_empty() {
            println!("No entries.");
            return Ok(());
        }

        for child in children {
            let partial = node_has_traversal_warning(self.session.artifact(), &child);
            println!("{}", format_node_brief(&child, partial));
        }
        Ok(())
    }

    fn command_tree(&mut self, line: &str) -> Result<()> {
        let rest = command_arg(line, "tree");
        let mut depth_limit = 6usize;
        let mut target = self.current_path.clone();

        if !rest.is_empty() {
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            if let Some(last) = tokens.last() {
                if let Ok(parsed_depth) = last.parse::<usize>() {
                    depth_limit = parsed_depth;
                    if tokens.len() > 1 {
                        let joined = tokens[..tokens.len() - 1].join(" ");
                        target = self.resolve_path(&joined);
                    }
                } else {
                    target = self.resolve_path(rest);
                }
            }
        }

        let entries = walk_tree_with_fallback(self.session, self.current_fs, &target, depth_limit)?;
        if entries.is_empty() {
            println!("No tree entries.");
            return Ok(());
        }

        for SessionTreeEntry { depth, node } in entries {
            let indent = "  ".repeat(depth);
            let partial = node_has_traversal_warning(self.session.artifact(), &node);
            println!("{}{}", indent, format_node_brief(&node, partial));
        }
        Ok(())
    }

    fn command_stat(&mut self, line: &str) -> Result<()> {
        let arg = command_arg(line, "stat");
        let query = if arg.is_empty() {
            self.current_path.clone()
        } else {
            arg.to_string()
        };
        let resolved = self.resolve_path(&query);
        let node = resolve_node_with_fallback(self.session, self.current_fs, &resolved)?;
        self.print_stat(&node);
        Ok(())
    }

    fn command_search(&mut self, line: &str, fs_index: Option<usize>) -> Result<()> {
        let query = command_arg(line, "search");
        if query.is_empty() {
            println!("Usage: search <query>");
            return Ok(());
        }

        let options = SearchOptions {
            filesystem_index: fs_index,
            ..Default::default()
        };

        let matches = self.search(query, &options)?;
        print_matches(&matches);
        Ok(())
    }

    fn command_searchfs(&mut self, line: &str) -> Result<()> {
        let rest = command_arg(line, "searchfs");
        let mut parts = rest.splitn(2, ' ');
        let fs_index = match parts.next().filter(|s| !s.is_empty()) {
            Some(v) => v,
            None => {
                println!("Usage: searchfs <index> <query>");
                return Ok(());
            }
        };
        let fs_index: usize = fs_index
            .parse()
            .with_context(|| format!("invalid filesystem index: {}", fs_index))?;
        let query = parts.next().unwrap_or("").trim();
        if query.is_empty() {
            println!("Usage: searchfs <index> <query>");
            return Ok(());
        }

        let options = SearchOptions {
            filesystem_index: Some(fs_index),
            ..Default::default()
        };
        let matches = self.search(query, &options)?;
        print_matches(&matches);
        Ok(())
    }

    fn command_recover(&mut self, line: &str) -> Result<()> {
        let rest = command_arg(line, "recover");
        let Some((dest_arg, target_arg)) = parse_recover_args(rest) else {
            println!("Usage: recover <dest> [path]");
            return Ok(());
        };

        let dest = PathBuf::from(dest_arg);
        let target_path = target_arg
            .map(|path| self.resolve_path(path))
            .unwrap_or_else(|| self.current_path.clone());
        let target = resolve_recovery_target(self.session, Some(self.current_fs), &target_path)?;
        recover_with_fallback(self.session, &dest, Some(&target), Some(&target_path))?;
        println!("Recovered {} to {}", target_path, dest.display());
        Ok(())
    }

    fn search(&mut self, query: &str, options: &SearchOptions) -> Result<Vec<SearchMatch>> {
        search_with_fallback(self.session, query, options)
    }

    fn command_cache(&self) {
        print_cache_summary(&self.session.cache_summary());
    }

    fn command_unload(&mut self) {
        self.session.unload_caches();
        println!("Runtime caches unloaded.");
        print_cache_summary(&self.session.cache_summary());
    }

    fn command_save(&self, parts: &[&str]) -> Result<()> {
        if parts.len() != 2 {
            println!("Usage: save <path.scn>");
            return Ok(());
        }
        let path = PathBuf::from(parts[1]);
        self.session.artifact().save_to_path(&path)?;
        println!("Saved session to {}", path.display());
        Ok(())
    }

    fn resolve_path(&self, input: &str) -> String {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return self.current_path.clone();
        }

        if trimmed.starts_with('/') {
            return normalize_path(trimmed);
        }

        if self.current_path == "/" {
            normalize_path(&format!("/{}", trimmed))
        } else {
            normalize_path(&format!(
                "{}/{}",
                self.current_path.trim_end_matches('/'),
                trimmed
            ))
        }
    }

    fn print_stat(&self, node: &SessionNode) {
        println!("Path: {}", node.path);
        println!("Filesystem: {}", self.current_fs);
        println!(
            "Inode: {}",
            node.inode
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        println!("Type: {:?}", node.file_type);
        println!(
            "Size: {}",
            node.size
                .map(bytesize::ByteSize)
                .unwrap_or_else(|| bytesize::ByteSize(0))
        );
        println!("Deleted: {}", node.deleted);
        println!("Source: {}", entry_source_label(node.source));
        println!(
            "Source parent inode: {}",
            node.parent_inode
                .map(|inode| inode.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        println!(
            "Modified: {}",
            node.timestamps
                .as_ref()
                .and_then(|timestamps| timestamps.modified_unix)
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        println!(
            "Deleted at: {}",
            node.timestamps
                .as_ref()
                .and_then(|timestamps| timestamps.deleted_unix)
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        println!("Node ID: {}", node.id);
        if let Some(parent) = node.parent_id {
            println!("Parent ID: {}", parent);
        }
        if let Some(hint) = deleted_recovery_hint_message(self.session, node) {
            println!("Recovery hint: {}", hint);
        }
        let warnings =
            traversal_warnings_for_path(self.session.artifact(), self.current_fs, &node.path);
        if !warnings.is_empty() {
            println!("Traversal: partial");
            for warning in warnings {
                println!("Traversal warning: {}", warning);
            }
        }
        if !filesystem_has_tree(self.session, self.current_fs)
            && self.session.attached_reader().is_some()
        {
            println!("Resolution mode: live-fallback");
        }
    }
}

#[derive(Clone)]
struct DiscoveredItem {
    display_path: PathBuf,
    kind: ItemKind,
}

#[derive(Clone, Copy)]
enum ItemKind {
    Image,
    Scan,
}

impl DiscoveredItem {
    fn kind_label(&self) -> &'static str {
        match self.kind {
            ItemKind::Image => "image",
            ItemKind::Scan => "scan",
        }
    }

    fn resolve_image_path(&self) -> Result<PathBuf> {
        if !matches!(self.kind, ItemKind::Scan) {
            return Err(anyhow!(
                "{} is not a scan artifact",
                self.display_path.display()
            ));
        }

        let artifact = RecoverySessionArtifact::load_from_path(&self.display_path)?;
        if let Some(saved_path) = artifact.resolved_source_path(Some(&self.display_path)) {
            if saved_path.is_file() {
                return Ok(saved_path);
            }
        }

        self.infer_image_path().with_context(|| {
            match artifact.resolved_source_path(Some(&self.display_path)) {
                Some(saved_path) => format!(
                    "scan {} references image {}, but it is no longer available and no nearby image could be inferred",
                    self.display_path.display(),
                    saved_path.display()
                ),
                None => format!(
                    "scan {} does not record a source image path and no nearby image could be inferred",
                    self.display_path.display()
                ),
            }
        })
    }

    fn infer_image_path(&self) -> Option<PathBuf> {
        if !matches!(self.kind, ItemKind::Scan) {
            return None;
        }

        let stem = self.display_path.file_stem()?.to_str()?;
        let parent = self.display_path.parent()?;
        let candidates = [
            parent.join(format!("{}.img", stem)),
            parent.join(format!("{}.raw", stem)),
            parent.join(format!("{}.dd", stem)),
            parent.join(format!("{}.qcow2", stem)),
        ];

        candidates.into_iter().find(|p| p.is_file())
    }
}

fn discover_items() -> Vec<DiscoveredItem> {
    let roots = [
        Path::new("/projects"),
        Path::new("/Users/kylequinlan/Projects"),
        Path::new("/Users/kylequinlan/Workspace"),
    ];

    let mut out = Vec::new();
    for root in roots {
        collect_items(root, 3, &mut out);
    }
    out
}

fn collect_items(root: &Path, depth: usize, out: &mut Vec<DiscoveredItem>) {
    if depth == 0 || !root.is_dir() {
        return;
    }

    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let kind = if name.ends_with(".img")
                || name.ends_with(".raw")
                || name.ends_with(".dd")
                || name.ends_with(".qcow2")
            {
                Some(ItemKind::Image)
            } else if name.ends_with(".scn") {
                Some(ItemKind::Scan)
            } else {
                None
            };

            if let Some(kind) = kind {
                out.push(DiscoveredItem {
                    display_path: path,
                    kind,
                });
            }
        } else if path.is_dir() {
            collect_items(&path, depth - 1, out);
        }
    }
}

fn print_matches(matches: &[SearchMatch]) {
    if matches.is_empty() {
        println!("No matches found.");
        return;
    }

    for m in matches {
        let deleted = if m.deleted { " [deleted]" } else { "" };
        let source = match m.source {
            EntrySource::Filesystem => String::new(),
            EntrySource::DeletedSlack => format!(
                " [slack{}]",
                m.parent_inode
                    .map(|inode| format!(" parent={}", inode))
                    .unwrap_or_default()
            ),
            EntrySource::SyntheticOrphan => " [orphan]".to_string(),
        };
        println!(
            "[fs {} \"{}\"] {}{}{}",
            m.filesystem_index, m.filesystem_label, m.path, deleted, source
        );
    }
    println!("\n{} matches", matches.len());
}

fn print_cache_summary(summary: &CacheSummary) {
    println!("Cache summary:");
    println!("  budget: {}", bytesize::ByteSize(summary.budget_bytes));
    println!("  source: {:?}", summary.budget_source);
    println!(
        "  estimated: {}",
        bytesize::ByteSize(summary.estimated_bytes)
    );
    println!("  node_index_loaded: {}", summary.node_index_loaded);
    println!("  path_index_loaded: {}", summary.path_index_loaded);
    println!("  children_index_loaded: {}", summary.children_index_loaded);
    println!("  evictions: {}", summary.evictions);
}

fn format_node_brief(node: &SessionNode, partial: bool) -> String {
    let kind = match node.file_type {
        recovermax_core::fs::FileType::Directory => "d",
        recovermax_core::fs::FileType::RegularFile => "f",
        recovermax_core::fs::FileType::Symlink => "l",
        recovermax_core::fs::FileType::Other => "?",
    };

    let size = node
        .size
        .map(bytesize::ByteSize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_string());

    format!(
        "{} {} {}{}{}{}",
        kind,
        size,
        node.path,
        if node.deleted { " [deleted]" } else { "" },
        match node.source {
            EntrySource::Filesystem => "",
            EntrySource::DeletedSlack => " [slack]",
            EntrySource::SyntheticOrphan => " [orphan]",
        },
        if partial { " [partial]" } else { "" }
    )
}

fn traversal_warnings_for_path<'a>(
    artifact: &'a RecoverySessionArtifact,
    filesystem_index: usize,
    path: &str,
) -> Vec<&'a str> {
    artifact
        .filesystem_session(filesystem_index)
        .map(|filesystem| filesystem.warnings_for_path(path))
        .unwrap_or_default()
}

fn node_has_traversal_warning(artifact: &RecoverySessionArtifact, node: &SessionNode) -> bool {
    node.file_type == recovermax_core::fs::FileType::Directory
        && !traversal_warnings_for_path(artifact, node.filesystem_index, &node.path).is_empty()
}

fn entry_source_label(source: EntrySource) -> &'static str {
    match source {
        EntrySource::Filesystem => "filesystem",
        EntrySource::DeletedSlack => "deleted-slack",
        EntrySource::SyntheticOrphan => "synthetic-orphan",
    }
}

fn default_filesystem_index(
    filesystems: &[recovermax_core::session::FilesystemSessionArtifact],
) -> Option<usize> {
    filesystems
        .iter()
        .find(|fs| fs.fs_info.fs_type == "ext4")
        .map(|fs| fs.filesystem_index)
        .or_else(|| filesystems.first().map(|fs| fs.filesystem_index))
}

fn command_arg<'a>(line: &'a str, command: &str) -> &'a str {
    line[command.len()..].trim()
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }

    let mut parts = Vec::new();
    for part in trimmed.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }

    format!("/{}", parts.join("/"))
}

fn parse_recover_args(input: &str) -> Option<(&str, Option<&str>)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let dest = parts.next()?.trim();
    if dest.is_empty() {
        return None;
    }

    let target = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    Some((dest, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use recovermax_core::fs::FileType;
    use recovermax_core::session::SessionNodeTimestamps;

    #[test]
    fn format_node_brief_includes_deleted_provenance_suffixes() {
        let node = SessionNode {
            id: 1,
            parent_id: None,
            filesystem_index: 0,
            inode: None,
            basename: "ghost.txt".to_string(),
            path: "/ghost.txt".to_string(),
            file_type: FileType::RegularFile,
            deleted: true,
            size: None,
            source: EntrySource::DeletedSlack,
            parent_inode: Some(2),
            timestamps: None,
        };
        assert_eq!(format_node_brief(&node), "f - /ghost.txt [deleted] [slack]");
    }

    #[test]
    fn entry_source_label_matches_cli_terms() {
        assert_eq!(entry_source_label(EntrySource::Filesystem), "filesystem");
        assert_eq!(
            entry_source_label(EntrySource::DeletedSlack),
            "deleted-slack"
        );
        assert_eq!(
            entry_source_label(EntrySource::SyntheticOrphan),
            "synthetic-orphan"
        );
    }

    #[test]
    fn format_node_brief_marks_orphans() {
        let node = SessionNode {
            id: 7,
            parent_id: Some(1),
            filesystem_index: 0,
            inode: Some(13),
            basename: "OrphanFile-13".to_string(),
            path: "/$OrphanFiles/OrphanFile-13".to_string(),
            file_type: FileType::RegularFile,
            deleted: true,
            size: Some(712),
            source: EntrySource::SyntheticOrphan,
            parent_inode: None,
            timestamps: Some(SessionNodeTimestamps {
                created_unix: Some(1),
                modified_unix: Some(2),
                accessed_unix: Some(3),
                deleted_unix: Some(4),
            }),
        };
        assert_eq!(
            format_node_brief(&node),
            "f 712 B /$OrphanFiles/OrphanFile-13 [deleted] [orphan]"
        );
    }

    #[test]
    fn parse_recover_args_supports_optional_target() {
        assert_eq!(parse_recover_args(""), None);
        assert_eq!(parse_recover_args(" /tmp/out "), Some(("/tmp/out", None)));
        assert_eq!(
            parse_recover_args("/tmp/out ghost.txt"),
            Some(("/tmp/out", Some("ghost.txt")))
        );
        assert_eq!(
            parse_recover_args("/tmp/out /Bellatrix.txt"),
            Some(("/tmp/out", Some("/Bellatrix.txt")))
        );
    }
}
