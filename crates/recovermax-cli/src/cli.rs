use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;

use recovermax_core::carve;
use recovermax_core::fs::ext4::{DeletedInode, Ext4Fs};
use recovermax_core::fs::{EntrySource, FileType};
use recovermax_core::io::ImageReader;
use recovermax_core::recover;
use recovermax_core::scan::{ScanOptions, Scanner};
use recovermax_core::search::{SearchMatch, SearchOptions, Searcher};
use recovermax_core::session::{
    CacheSummary, RecoverySession, RecoverySessionArtifact, SessionNode, SessionNodeTimestamps,
    SessionTreeEntry,
};

pub struct Args {
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show information about a disk image or device
    Info {
        /// Path to disk image or block device
        image: PathBuf,
    },

    /// Scan a disk image for recoverable filesystems and files
    Scan {
        /// Path to disk image or block device
        image: PathBuf,

        /// Output scan results to file (JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Deep scan within partitions at 1 MiB steps (slow for large images)
        #[arg(long)]
        deep_scan: bool,
    },

    /// List filesystems from a session artifact or live scan
    Filesystems {
        /// Path to disk image or block device
        image: PathBuf,

        /// Load a previous scan/session file instead of re-scanning
        #[arg(short, long)]
        scan_file: Option<PathBuf>,

        /// Memory budget for RecoverMax-managed caches
        #[arg(long)]
        memory_budget: Option<String>,
    },

    /// List directory entries from a browsable session tree
    Ls {
        /// Path to disk image or block device
        image: PathBuf,

        /// Path within the filesystem session
        #[arg(default_value = "/")]
        path: String,

        /// Load a previous scan/session file instead of re-scanning
        #[arg(short, long)]
        scan_file: Option<PathBuf>,

        /// Limit browsing to one filesystem index
        #[arg(long)]
        fs: Option<usize>,

        /// Show extended metadata
        #[arg(short, long)]
        long: bool,

        /// Memory budget for RecoverMax-managed caches
        #[arg(long)]
        memory_budget: Option<String>,
    },

    /// Print a tree view of a browsable session
    Tree {
        /// Path to disk image or block device
        image: PathBuf,

        /// Path within the filesystem session
        #[arg(default_value = "/")]
        path: String,

        /// Load a previous scan/session file instead of re-scanning
        #[arg(short, long)]
        scan_file: Option<PathBuf>,

        /// Limit browsing to one filesystem index
        #[arg(long)]
        fs: Option<usize>,

        /// Limit tree depth
        #[arg(long, default_value_t = 64)]
        depth: usize,

        /// Memory budget for RecoverMax-managed caches
        #[arg(long)]
        memory_budget: Option<String>,
    },

    /// Show metadata for a path or session node
    Stat {
        /// Path to disk image or block device
        image: PathBuf,

        /// Path or numeric node id
        target: String,

        /// Load a previous scan/session file instead of re-scanning
        #[arg(short, long)]
        scan_file: Option<PathBuf>,

        /// Limit browsing to one filesystem index
        #[arg(long)]
        fs: Option<usize>,

        /// Memory budget for RecoverMax-managed caches
        #[arg(long)]
        memory_budget: Option<String>,
    },

    /// Recover files from a disk image
    Recover {
        /// Path to disk image or block device
        image: PathBuf,

        /// Destination directory for recovered files
        #[arg(short, long)]
        dest: PathBuf,

        /// Load a previous scan/session file instead of re-scanning
        #[arg(short, long)]
        scan_file: Option<PathBuf>,

        /// Recover specific path or session node id
        #[arg(short, long)]
        path: Option<String>,

        /// Limit recovery target resolution to one filesystem index
        #[arg(long)]
        fs: Option<usize>,

        /// Memory budget for RecoverMax-managed caches
        #[arg(long)]
        memory_budget: Option<String>,
    },

    /// Search browsable session paths
    Search {
        /// Path to disk image or block device
        image: PathBuf,

        /// Query to search for
        query: String,

        /// Load a previous scan/session file instead of re-scanning
        #[arg(short, long)]
        scan_file: Option<PathBuf>,

        /// Limit search to one filesystem index
        #[arg(long)]
        fs: Option<usize>,

        /// Case-insensitive matching
        #[arg(short = 'i', long)]
        ignore_case: bool,

        /// Exact match instead of substring match
        #[arg(short = 'x', long)]
        exact: bool,

        /// Memory budget for RecoverMax-managed caches
        #[arg(long)]
        memory_budget: Option<String>,
    },

    /// Show cache state for a saved session
    Cache {
        /// Path to a session artifact
        #[arg(long)]
        scan_file: PathBuf,

        /// Memory budget for RecoverMax-managed caches
        #[arg(long)]
        memory_budget: Option<String>,
    },

    /// Explicitly unload RecoverMax-managed caches for a saved session
    Unload {
        /// Path to a session artifact
        #[arg(long)]
        scan_file: PathBuf,

        /// Memory budget for RecoverMax-managed caches
        #[arg(long)]
        memory_budget: Option<String>,
    },

    /// Raw carve files by signature (like photorec)
    Carve {
        /// Path to disk image or block device
        image: PathBuf,

        /// Destination directory for carved files
        #[arg(short, long)]
        dest: PathBuf,

        /// File types to carve (e.g. jpg,png,pdf). Default: all known types
        #[arg(short, long)]
        types: Option<String>,
    },

    /// Hex dump a region of the image
    Hexdump {
        /// Path to disk image or block device
        image: PathBuf,

        /// Offset in bytes (supports 0x prefix for hex)
        #[arg(short, long, default_value = "0")]
        offset: String,

        /// Number of bytes to dump
        #[arg(short, long, default_value = "512")]
        length: usize,
    },

    /// Scan for deleted files (inodes with dtime set or links_count=0)
    Deleted {
        /// Path to disk image or block device
        image: PathBuf,

        /// Limit deleted inode scan/recovery to one filesystem index
        #[arg(long)]
        fs: Option<usize>,

        /// Recover a specific inode number
        #[arg(short = 'r', long)]
        recover: Option<u64>,

        /// Destination directory for recovered file (required with -r)
        #[arg(short, long)]
        dest: Option<PathBuf>,
    },
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Info { image } => run_info(&image),
        Command::Scan {
            image,
            output,
            deep_scan,
        } => run_scan(&image, output, deep_scan),
        Command::Filesystems {
            image,
            scan_file,
            memory_budget,
        } => {
            let session = open_session(
                &image,
                scan_file.as_deref(),
                memory_budget.as_deref(),
                false,
            )?;
            print_filesystems(&session);
            Ok(())
        }
        Command::Ls {
            image,
            path,
            scan_file,
            fs,
            long,
            memory_budget,
        } => {
            let mut session = open_session(
                &image,
                scan_file.as_deref(),
                memory_budget.as_deref(),
                false,
            )?;
            let node = resolve_node_for_session(&mut session, fs, &path)?;
            if node.file_type != FileType::Directory {
                print_stat_node(&node, session.artifact());
                print_deleted_recovery_hint(&session, &node);
                return Ok(());
            }

            let children =
                list_children_with_fallback(&mut session, node.filesystem_index, &node.path)?;
            print_directory_listing(&children, long);
            Ok(())
        }
        Command::Tree {
            image,
            path,
            scan_file,
            fs,
            depth,
            memory_budget,
        } => {
            let mut session = open_session(
                &image,
                scan_file.as_deref(),
                memory_budget.as_deref(),
                false,
            )?;
            let node = resolve_node_for_session(&mut session, fs, &path)?;
            let entries =
                walk_tree_with_fallback(&mut session, node.filesystem_index, &node.path, depth)?;
            print_tree_entries(&entries, depth);
            Ok(())
        }
        Command::Stat {
            image,
            target,
            scan_file,
            fs,
            memory_budget,
        } => {
            let mut session = open_session(
                &image,
                scan_file.as_deref(),
                memory_budget.as_deref(),
                false,
            )?;
            let node = resolve_node_for_session(&mut session, fs, &target)?;
            print_stat_node(&node, session.artifact());
            print_deleted_recovery_hint(&session, &node);
            Ok(())
        }
        Command::Recover {
            image,
            dest,
            scan_file,
            path,
            fs,
            memory_budget,
        } => {
            let mut session = open_session(
                &image,
                scan_file.as_deref(),
                memory_budget.as_deref(),
                false,
            )?;
            let requested_path = path.as_deref().map(normalize_session_path);
            let recovery_target = match path.as_deref() {
                Some(selector) => Some(resolve_recovery_target(&mut session, fs, selector)?),
                None => None,
            };
            recover_with_fallback(
                &mut session,
                &dest,
                recovery_target.as_ref(),
                requested_path.as_deref(),
            )?;
            Ok(())
        }
        Command::Search {
            image,
            query,
            scan_file,
            fs,
            ignore_case,
            exact,
            memory_budget,
        } => {
            let mut session = open_session(
                &image,
                scan_file.as_deref(),
                memory_budget.as_deref(),
                false,
            )?;
            let options = SearchOptions {
                ignore_case,
                exact,
                filesystem_index: fs,
                ..Default::default()
            };
            let matches = search_with_fallback(&mut session, &query, &options)?;
            print_matches(&matches);
            Ok(())
        }
        Command::Cache {
            scan_file,
            memory_budget,
        } => {
            let mut session =
                open_session_from_saved_session(&scan_file, memory_budget.as_deref(), true)?;
            warm_session_caches(&mut session)?;
            print_cache_summary("cache", &session.cache_summary());
            Ok(())
        }
        Command::Unload {
            scan_file,
            memory_budget,
        } => {
            let mut session =
                open_session_from_saved_session(&scan_file, memory_budget.as_deref(), true)?;
            warm_session_caches(&mut session)?;
            println!("Before unload:");
            print_cache_summary("cache", &session.cache_summary());
            session.unload_caches();
            println!("\nAfter unload:");
            print_cache_summary("cache", &session.cache_summary());
            Ok(())
        }
        Command::Carve { image, dest, types } => {
            let reader = ImageReader::open(&image)?;
            let type_filter: Option<Vec<&str>> = types.as_deref().map(|t| t.split(',').collect());
            let carver = carve::Carver::new(&reader, &dest);
            carver.carve(type_filter.as_deref())?;

            Ok(())
        }
        Command::Hexdump {
            image,
            offset,
            length,
        } => {
            let reader = ImageReader::open(&image)?;
            let off = if offset.starts_with("0x") || offset.starts_with("0X") {
                u64::from_str_radix(offset.trim_start_matches("0x").trim_start_matches("0X"), 16)?
            } else {
                offset.parse()?
            };
            let data = reader.read_at(off, length)?;
            print_hexdump_pub(data, off);
            Ok(())
        }
        Command::Deleted {
            image,
            fs,
            recover: recover_inode,
            dest,
        } => {
            let reader = ImageReader::open(&image)?;

            let scanner = Scanner::new(&reader);
            let report = scanner.full_scan()?;
            let (filesystem_index, fs_info) = select_deleted_filesystem(&report, fs)?;

            let ext4 = Ext4Fs::new(&reader, fs_info.offset)?;

            match recover_inode {
                Some(inode_num) => {
                    let dest = dest.ok_or_else(|| {
                        anyhow!("Destination required: use -d <path> to specify where to save the recovered file")
                    })?;

                    let inode = ext4.read_inode(inode_num)?;
                    let data = ext4.read_inode_data(&inode)?;

                    std::fs::create_dir_all(&dest)?;
                    let filename = format!("inode-{}", inode_num);
                    let dest_file = dest.join(&filename);
                    std::fs::write(&dest_file, &data)?;

                    println!(
                        "Recovered inode {} from filesystem {} ({}) to {}",
                        inode_num,
                        filesystem_index,
                        bytesize::ByteSize(inode.size),
                        dest_file.display(),
                    );
                    Ok(())
                }
                None => {
                    println!("Scanning for deleted inodes...");
                    let deleted = ext4.scan_deleted_inodes()?;

                    if deleted.is_empty() {
                        println!("No deleted inodes found.");
                        return Ok(());
                    }

                    println!("Found {} deleted inodes:\n", deleted.len());
                    println!(
                        "{:>8}  {:>12}  {:>10}  {:>8}  {}",
                        "INODE", "SIZE", "DTIME", "TYPE", "PATH"
                    );
                    println!("{}", "-".repeat(88));

                    for d in &deleted {
                        println!("{}", format_deleted_inode_row(d));
                    }

                    println!(
                        "\nDirect inode recovery: recovermax deleted <image> -r <inode> -d <dest>"
                    );
                    println!("Session path convention: /$OrphanFiles/OrphanFile-<inode>");
                    Ok(())
                }
            }
        }
    }
}

fn run_info(image: &Path) -> Result<()> {
    let reader = ImageReader::open(image)?;
    println!("Image: {}", image.display());
    println!(
        "Size:  {} ({} bytes)",
        bytesize::ByteSize(reader.len()),
        reader.len()
    );

    let scanner = Scanner::new(&reader);
    let partitions = scanner.detect_partitions()?;

    if partitions.is_empty() {
        println!("\nNo partition table found. Image may be a raw partition.");
    } else {
        println!("\nPartitions:");
        for (i, p) in partitions.iter().enumerate() {
            println!(
                "  #{}: {} offset={} size={} type={}",
                i,
                p.name,
                bytesize::ByteSize(p.offset),
                bytesize::ByteSize(p.size),
                p.fs_type
            );
        }
    }

    let fs_info = scanner.detect_filesystem(0)?;
    if let Some(info) = fs_info {
        println!("\nFilesystem at offset 0:");
        println!("  Type:       {}", info.fs_type);
        println!("  Label:      {}", info.label);
        println!("  Block size: {}", info.block_size);
        println!("  Total size: {}", bytesize::ByteSize(info.total_size));
    }

    Ok(())
}

fn run_scan(image: &Path, output: Option<PathBuf>, deep_scan: bool) -> Result<()> {
    let reader = ImageReader::open(image)?;
    let scanner = Scanner::new(&reader);
    let options = ScanOptions { deep_scan };
    let report = scanner.full_scan_with_options(&options)?;

    println!("{}", report.summary());

    if let Some(path) = output {
        let artifact = RecoverySessionArtifact::from_scan(image, &reader, report.clone())?;
        artifact.save_to_path(&path)?;
        println!("\nSession saved to {}", path.display());
    }

    Ok(())
}

fn select_deleted_filesystem<'a>(
    report: &'a recovermax_core::scan::ScanReport,
    requested: Option<usize>,
) -> Result<(usize, &'a recovermax_core::fs::FsInfo)> {
    match requested {
        Some(index) => report
            .filesystems
            .get(index)
            .ok_or_else(|| anyhow!("Filesystem {} not found in image", index))
            .and_then(|filesystem| {
                if filesystem.fs_type == "ext4" {
                    Ok((index, filesystem))
                } else {
                    Err(anyhow!(
                        "Filesystem {} is {} and does not support ext deleted inode scanning",
                        index,
                        filesystem.fs_type
                    ))
                }
            }),
        None => {
            let ext_filesystems: Vec<(usize, &recovermax_core::fs::FsInfo)> = report
                .filesystems
                .iter()
                .enumerate()
                .filter(|(_, filesystem)| filesystem.fs_type == "ext4")
                .collect();
            match ext_filesystems.as_slice() {
                [] => bail!("No ext4 filesystem found in image"),
                [single] => Ok(*single),
                multiple => {
                    let choices = multiple
                        .iter()
                        .map(|(index, filesystem)| {
                            format!(
                                "{}:{}@{}",
                                index,
                                filesystem.label,
                                bytesize::ByteSize(filesystem.offset)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    bail!(
                        "multiple ext filesystems found; use --fs with one of: {}",
                        choices
                    );
                }
            }
        }
    }
}

fn open_session(
    image: &Path,
    scan_file: Option<&Path>,
    memory_budget: Option<&str>,
    require_tree: bool,
) -> Result<RecoverySession> {
    let reader = ImageReader::open(image)?;
    let mut artifact = if let Some(scan_file) = scan_file {
        let artifact = RecoverySessionArtifact::load_from_path(scan_file)?;
        artifact.validate_for_image_with_artifact_path(image, reader.len(), Some(scan_file))?;
        artifact
    } else {
        build_live_session_artifact(image, &reader)?
    };

    if require_tree && !artifact.filesystems.iter().any(|fs| fs.has_tree()) {
        artifact = build_live_session_artifact(image, &reader)?;
    }

    let explicit_budget = parse_memory_budget(memory_budget)?;
    Ok(RecoverySession::from_artifact_with_reader(
        artifact,
        reader,
        explicit_budget,
    ))
}

fn open_session_from_saved_session(
    scan_file: &Path,
    memory_budget: Option<&str>,
    require_tree: bool,
) -> Result<RecoverySession> {
    let artifact = RecoverySessionArtifact::load_from_path(scan_file)?;
    let image_path = artifact
        .resolved_source_path(Some(scan_file))
        .as_deref()
        .context("saved session does not record a source image path")?
        .to_path_buf();

    let reader = ImageReader::open(&image_path)?;
    artifact.validate_for_image_with_artifact_path(&image_path, reader.len(), Some(scan_file))?;

    let mut artifact = artifact;
    if require_tree && !artifact.filesystems.iter().any(|fs| fs.has_tree()) {
        artifact = build_live_session_artifact(&image_path, &reader)?;
    }

    let explicit_budget = parse_memory_budget(memory_budget)?;
    Ok(RecoverySession::from_artifact_with_reader(
        artifact,
        reader,
        explicit_budget,
    ))
}

fn build_live_session_artifact(
    image: &Path,
    reader: &ImageReader,
) -> Result<RecoverySessionArtifact> {
    let scanner = Scanner::new(reader);
    let report = scanner.full_scan()?;
    RecoverySessionArtifact::from_scan(image, reader, report)
}

fn parse_memory_budget(memory_budget: Option<&str>) -> Result<Option<u64>> {
    match memory_budget {
        None => Ok(None),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }

            if let Ok(parsed) = trimmed.parse::<bytesize::ByteSize>() {
                return Ok(Some(parsed.as_u64()));
            }

            let bytes = trimmed
                .parse::<u64>()
                .with_context(|| format!("invalid memory budget {}", value))?;
            Ok(Some(bytes))
        }
    }
}

fn resolve_node_for_session(
    session: &mut RecoverySession,
    filesystem_index: Option<usize>,
    target: &str,
) -> Result<SessionNode> {
    if let Some(fs_index) = filesystem_index {
        return resolve_node_with_fallback(session, fs_index, target);
    }

    let mut matches = Vec::new();
    let filesystem_indexes: Vec<usize> = session
        .artifact()
        .filesystems
        .iter()
        .map(|filesystem| filesystem.filesystem_index)
        .collect();

    for fs_index in filesystem_indexes {
        if let Ok(node) = resolve_node_with_fallback(session, fs_index, target) {
            matches.push(node);
        }
    }

    match matches.len() {
        0 => bail!(
            "target {} was not found in any browsable filesystem",
            target
        ),
        1 => Ok(matches.remove(0)),
        _ => bail!(
            "target {} is ambiguous across multiple filesystems; specify --fs",
            target
        ),
    }
}

fn resolve_recovery_target(
    session: &mut RecoverySession,
    filesystem_index: Option<usize>,
    selector: &str,
) -> Result<SessionNode> {
    let node = resolve_node_for_session(session, filesystem_index, selector)?;
    if is_residual_deleted_entry(&node) {
        if let Some(candidate) = unique_orphan_recovery_candidate(session, &node) {
            return Ok(candidate);
        }
        let orphan_hint = deleted_recovery_hint_message(session, &node)
            .map(|hint| format!(" {}", hint))
            .unwrap_or_default();
        bail!(
            "target {} only has a residual deleted directory entry and no recoverable inode.{}",
            selector,
            orphan_hint
        );
    }
    Ok(node)
}

fn is_residual_deleted_entry(node: &SessionNode) -> bool {
    node.deleted
        && node.inode.is_none()
        && node.source != EntrySource::SyntheticOrphan
        && node.path != "/$OrphanFiles"
}

pub(crate) fn deleted_recovery_hint_message(
    session: &RecoverySession,
    node: &SessionNode,
) -> Option<String> {
    if !is_residual_deleted_entry(node) {
        return None;
    }
    let candidates = orphan_recovery_candidates(session, node)?;
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return Some(format!("Try {} instead.", candidates[0].path));
    }

    let mut message = String::from("Possible orphan candidates:");
    for candidate in candidates.iter().take(3) {
        message.push(' ');
        message.push_str(&format_orphan_candidate(candidate));
    }
    if candidates.len() > 3 {
        message.push_str(&format!(" (+{} more).", candidates.len() - 3));
    }
    Some(message)
}

fn print_deleted_recovery_hint(session: &RecoverySession, node: &SessionNode) {
    if let Some(message) = deleted_recovery_hint_message(session, node) {
        println!("Recovery hint: {}", message);
    }
}

fn unique_orphan_recovery_candidate(
    session: &RecoverySession,
    node: &SessionNode,
) -> Option<SessionNode> {
    let mut candidates = orphan_recovery_candidates(session, node)?;
    if candidates.len() == 1 {
        candidates.pop()
    } else {
        None
    }
}

fn orphan_recovery_candidates(
    session: &RecoverySession,
    node: &SessionNode,
) -> Option<Vec<SessionNode>> {
    if filesystem_has_tree(session, node.filesystem_index) {
        let filesystem = session
            .artifact()
            .filesystem_session(node.filesystem_index)?;
        let mut candidates: Vec<SessionNode> = filesystem
            .nodes
            .iter()
            .filter(|candidate| {
                candidate.deleted
                    && candidate.inode.is_some()
                    && candidate.file_type == node.file_type
                    && is_orphan_candidate(candidate)
            })
            .cloned()
            .collect();
        candidates.sort_by(candidate_sort_key);
        return Some(candidates);
    }

    let ext4 = live_ext4(session, node.filesystem_index).ok()?;
    let mut candidates = live_deleted_orphan_nodes(&ext4, node.filesystem_index, None)
        .into_iter()
        .filter(|candidate| candidate.file_type == node.file_type)
        .collect::<Vec<_>>();
    candidates.sort_by(candidate_sort_key);
    Some(candidates)
}

fn candidate_sort_key(left: &SessionNode, right: &SessionNode) -> std::cmp::Ordering {
    file_type_rank(left.file_type)
        .cmp(&file_type_rank(right.file_type))
        .then_with(|| left.size.cmp(&right.size))
        .then_with(|| {
            left.timestamps
                .as_ref()
                .and_then(|timestamps| timestamps.modified_unix)
                .cmp(
                    &right
                        .timestamps
                        .as_ref()
                        .and_then(|timestamps| timestamps.modified_unix),
                )
        })
        .then_with(|| left.path.cmp(&right.path))
}

fn file_type_rank(file_type: FileType) -> u8 {
    match file_type {
        FileType::Directory => 0,
        FileType::RegularFile => 1,
        FileType::Symlink => 2,
        FileType::Other => 3,
    }
}

fn format_orphan_candidate(candidate: &SessionNode) -> String {
    let mut metadata = Vec::new();
    if let Some(inode) = candidate.inode {
        metadata.push(format!("inode {}", inode));
    }
    if let Some(size) = candidate.size {
        metadata.push(bytesize::ByteSize(size).to_string());
    }
    if let Some(modified) = candidate
        .timestamps
        .as_ref()
        .and_then(|timestamps| timestamps.modified_unix)
    {
        metadata.push(format!("mtime {}", modified));
    }
    if let Some(deleted) = candidate
        .timestamps
        .as_ref()
        .and_then(|timestamps| timestamps.deleted_unix)
    {
        metadata.push(format!("dtime {}", deleted));
    }

    if metadata.is_empty() {
        format!("{}.", candidate.path)
    } else {
        format!("{} ({}).", candidate.path, metadata.join(", "))
    }
}

fn is_orphan_candidate(node: &SessionNode) -> bool {
    node.source == EntrySource::SyntheticOrphan || node.path.starts_with("/$OrphanFiles/")
}

pub(crate) fn resolve_node_with_fallback(
    session: &mut RecoverySession,
    filesystem_index: usize,
    target: &str,
) -> Result<SessionNode> {
    if filesystem_has_tree(session, filesystem_index) {
        session.resolve_node(filesystem_index, target)
    } else {
        live_resolve_node(session, filesystem_index, target)
    }
}

pub(crate) fn list_children_with_fallback(
    session: &mut RecoverySession,
    filesystem_index: usize,
    path: &str,
) -> Result<Vec<SessionNode>> {
    if filesystem_has_tree(session, filesystem_index) {
        session.list_children(filesystem_index, path)
    } else {
        live_list_children(session, filesystem_index, path)
    }
}

pub(crate) fn walk_tree_with_fallback(
    session: &mut RecoverySession,
    filesystem_index: usize,
    path: &str,
    depth: usize,
) -> Result<Vec<SessionTreeEntry>> {
    if filesystem_has_tree(session, filesystem_index) {
        session.walk_tree(filesystem_index, path, depth)
    } else {
        live_walk_tree(session, filesystem_index, path, depth)
    }
}

pub(crate) fn search_with_fallback(
    session: &mut RecoverySession,
    query: &str,
    options: &SearchOptions,
) -> Result<Vec<SearchMatch>> {
    let mut matches = session.search(query, options);
    let live_filesystems: Vec<usize> = session
        .artifact()
        .filesystems
        .iter()
        .filter(|filesystem| !filesystem.has_tree())
        .map(|filesystem| filesystem.filesystem_index)
        .collect();

    if live_filesystems.is_empty() {
        return Ok(matches);
    }

    let reader = session
        .attached_reader()
        .ok_or_else(|| anyhow!("session has no attached image reader"))?;
    let searcher = Searcher::new(reader);
    let mut live_matches = searcher.search_selected(
        session.artifact().report(),
        query,
        options,
        &live_filesystems,
    )?;
    matches.append(&mut live_matches);
    matches.sort_by(|a, b| {
        a.filesystem_index
            .cmp(&b.filesystem_index)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.inode.cmp(&b.inode))
    });
    matches.dedup_by(|a, b| {
        a.filesystem_index == b.filesystem_index && a.inode == b.inode && a.path == b.path
    });
    Ok(matches)
}

pub(crate) fn filesystem_has_tree(session: &RecoverySession, filesystem_index: usize) -> bool {
    session
        .artifact()
        .filesystem_session(filesystem_index)
        .map(|filesystem| filesystem.has_tree())
        .unwrap_or(false)
}

fn live_ext4(session: &RecoverySession, filesystem_index: usize) -> Result<Ext4Fs<'_>> {
    let filesystem = session
        .artifact()
        .filesystem_session(filesystem_index)
        .with_context(|| format!("filesystem {} not found in session", filesystem_index))?;
    if filesystem.fs_info.fs_type != "ext4" {
        bail!(
            "filesystem {} is {} and does not support live ext4 fallback",
            filesystem_index,
            filesystem.fs_info.fs_type
        );
    }

    let reader = session
        .attached_reader()
        .ok_or_else(|| anyhow!("session has no attached image reader"))?;
    Ext4Fs::new(reader, filesystem.fs_info.offset)
}

fn live_resolve_node(
    session: &RecoverySession,
    filesystem_index: usize,
    target: &str,
) -> Result<SessionNode> {
    if target.parse::<u64>().is_ok() {
        bail!("numeric node ids require a persisted session tree; use a path instead");
    }

    let ext4 = live_ext4(session, filesystem_index)?;
    let normalized = normalize_session_path(target);
    if normalized == "/" {
        return live_root_node(&ext4, filesystem_index);
    }
    if normalized == "/$OrphanFiles" {
        return Ok(live_orphan_dir_node(filesystem_index));
    }
    if let Some(remainder) = normalized.strip_prefix("/$OrphanFiles/") {
        let mut segments = remainder.split('/');
        let orphan_basename = segments
            .next()
            .ok_or_else(|| anyhow!("invalid orphan path {}", normalized))?;
        let orphan_path = format!("/$OrphanFiles/{}", orphan_basename);
        let mut current = live_find_deleted_orphan_node(&ext4, filesystem_index, &orphan_path)
            .with_context(|| {
                format!(
                    "path {} not found in filesystem {} during orphan traversal",
                    normalized, filesystem_index
                )
            })?;

        for segment in segments {
            if current.file_type != FileType::Directory {
                bail!(
                    "path {} traverses through non-directory {}",
                    normalized,
                    current.path
                );
            }

            let current_inode = current.inode.ok_or_else(|| {
                anyhow!("directory {} has no inode in live fallback", current.path)
            })?;
            let entries = ext4.list_directory(current_inode)?;
            let entry = entries
                .iter()
                .find(|entry| entry.name == segment)
                .with_context(|| {
                    format!(
                        "path {} not found in filesystem {} during orphan traversal",
                        normalized, filesystem_index
                    )
                })?;
            let absolute_path = format!("{}/{}", current.path, segment);
            current = live_node_from_entry(
                &ext4,
                filesystem_index,
                Some(current.id),
                absolute_path,
                entry,
            )?;
        }

        return Ok(current);
    }

    let mut current = live_root_node(&ext4, filesystem_index)?;
    let mut current_inode = current
        .inode
        .ok_or_else(|| anyhow!("root inode missing in live fallback"))?;

    for segment in normalized.trim_start_matches('/').split('/') {
        let entries = ext4.list_directory(current_inode)?;
        let entry = entries
            .iter()
            .find(|entry| entry.name == segment)
            .with_context(|| {
                format!(
                    "path {} not found in filesystem {} during live traversal",
                    normalized, filesystem_index
                )
            })?;
        let absolute_path = if current.path == "/" {
            format!("/{}", segment)
        } else {
            format!("{}/{}", current.path, segment)
        };
        current = live_node_from_entry(
            &ext4,
            filesystem_index,
            Some(current.id),
            absolute_path,
            entry,
        )?;
        current_inode = current.inode.unwrap_or(0);
    }

    Ok(current)
}

fn live_list_children(
    session: &RecoverySession,
    filesystem_index: usize,
    path: &str,
) -> Result<Vec<SessionNode>> {
    let ext4 = live_ext4(session, filesystem_index)?;
    let node = live_resolve_node(session, filesystem_index, path)?;
    if node.file_type != FileType::Directory {
        return Ok(Vec::new());
    }
    if node.path == "/$OrphanFiles" {
        let mut children = live_deleted_orphan_nodes(&ext4, filesystem_index, Some(node.id));
        children.sort_by(|a, b| a.basename.cmp(&b.basename));
        return Ok(children);
    }

    let inode = node
        .inode
        .ok_or_else(|| anyhow!("directory {} has no inode in live fallback", node.path))?;
    let entries = ext4.list_directory(inode)?;
    let mut children = Vec::new();
    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let absolute_path = if node.path == "/" {
            format!("/{}", entry.name)
        } else {
            format!("{}/{}", node.path, entry.name)
        };
        children.push(live_node_from_entry(
            &ext4,
            filesystem_index,
            Some(node.id),
            absolute_path,
            &entry,
        )?);
    }
    if node.path == "/" {
        let orphan_children = live_deleted_orphan_nodes(&ext4, filesystem_index, None);
        if !orphan_children.is_empty() {
            children.push(live_orphan_dir_node(filesystem_index));
        }
    }
    children.sort_by(|a, b| a.basename.cmp(&b.basename));
    Ok(children)
}

fn live_walk_tree(
    session: &RecoverySession,
    filesystem_index: usize,
    path: &str,
    depth: usize,
) -> Result<Vec<SessionTreeEntry>> {
    let ext4 = live_ext4(session, filesystem_index)?;
    let root = live_resolve_node(session, filesystem_index, path)?;
    let mut entries = Vec::new();
    live_walk_tree_recursive(&ext4, filesystem_index, root, 0, depth, &mut entries)?;
    Ok(entries)
}

fn live_walk_tree_recursive(
    ext4: &Ext4Fs<'_>,
    filesystem_index: usize,
    node: SessionNode,
    current_depth: usize,
    max_depth: usize,
    out: &mut Vec<SessionTreeEntry>,
) -> Result<()> {
    out.push(SessionTreeEntry {
        depth: current_depth,
        node: node.clone(),
    });

    if current_depth >= max_depth || node.file_type != FileType::Directory {
        return Ok(());
    }

    if node.path == "/$OrphanFiles" {
        let mut children = live_deleted_orphan_nodes(ext4, filesystem_index, Some(node.id));
        children.sort_by(|a, b| a.basename.cmp(&b.basename));
        for child in children {
            live_walk_tree_recursive(
                ext4,
                filesystem_index,
                child,
                current_depth + 1,
                max_depth,
                out,
            )?;
        }
        return Ok(());
    }

    let inode = match node.inode {
        Some(inode) => inode,
        None => return Ok(()),
    };

    let mut children = Vec::new();
    for entry in ext4.list_directory(inode)? {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let absolute_path = if node.path == "/" {
            format!("/{}", entry.name)
        } else {
            format!("{}/{}", node.path, entry.name)
        };
        children.push(live_node_from_entry(
            ext4,
            filesystem_index,
            Some(node.id),
            absolute_path,
            &entry,
        )?);
    }
    if node.path == "/" {
        let orphan_children = live_deleted_orphan_nodes(ext4, filesystem_index, None);
        if !orphan_children.is_empty() {
            children.push(live_orphan_dir_node(filesystem_index));
        }
    }

    children.sort_by(|a, b| a.basename.cmp(&b.basename));
    for child in children {
        live_walk_tree_recursive(
            ext4,
            filesystem_index,
            child,
            current_depth + 1,
            max_depth,
            out,
        )?;
    }

    Ok(())
}

fn live_root_node(ext4: &Ext4Fs<'_>, filesystem_index: usize) -> Result<SessionNode> {
    let inode = ext4.read_inode(2)?;
    Ok(SessionNode {
        id: inode.number,
        parent_id: None,
        filesystem_index,
        inode: Some(inode.number),
        basename: "/".to_string(),
        path: "/".to_string(),
        file_type: inode.file_type(),
        deleted: inode.is_deleted(),
        size: Some(inode.size),
        source: EntrySource::Filesystem,
        parent_inode: None,
        timestamps: ext_inode_timestamps(&inode),
    })
}

fn live_orphan_dir_node(filesystem_index: usize) -> SessionNode {
    SessionNode {
        id: synthetic_orphan_dir_id(filesystem_index),
        parent_id: Some(2),
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
    }
}

fn live_find_deleted_orphan_node(
    ext4: &Ext4Fs<'_>,
    filesystem_index: usize,
    path: &str,
) -> Option<SessionNode> {
    live_deleted_orphan_nodes(
        ext4,
        filesystem_index,
        Some(synthetic_orphan_dir_id(filesystem_index)),
    )
    .into_iter()
    .find(|node| node.path == path)
}

fn live_deleted_orphan_nodes(
    ext4: &Ext4Fs<'_>,
    filesystem_index: usize,
    parent_id: Option<u64>,
) -> Vec<SessionNode> {
    let deleted_inodes = match ext4.scan_deleted_inodes() {
        Ok(deleted) => deleted,
        Err(_) => return Vec::new(),
    };
    let mut nodes: Vec<SessionNode> = deleted_inodes
        .into_iter()
        .map(|inode| SessionNode {
            id: synthetic_orphan_file_id(filesystem_index, inode.inode_num),
            parent_id,
            filesystem_index,
            inode: Some(inode.inode_num),
            basename: format!("OrphanFile-{}", inode.inode_num),
            path: format!("/$OrphanFiles/OrphanFile-{}", inode.inode_num),
            file_type: inode.file_type,
            deleted: true,
            size: Some(inode.size),
            source: EntrySource::SyntheticOrphan,
            parent_inode: None,
            timestamps: Some(SessionNodeTimestamps {
                created_unix: nonzero_unix_timestamp(inode.ctime),
                modified_unix: nonzero_unix_timestamp(inode.mtime),
                accessed_unix: nonzero_unix_timestamp(inode.atime),
                deleted_unix: nonzero_unix_timestamp(inode.dtime),
            })
            .filter(|timestamps| {
                timestamps.created_unix.is_some()
                    || timestamps.modified_unix.is_some()
                    || timestamps.accessed_unix.is_some()
                    || timestamps.deleted_unix.is_some()
            }),
        })
        .collect();
    nodes.sort_by(|a, b| a.basename.cmp(&b.basename));
    nodes
}

fn synthetic_orphan_dir_id(filesystem_index: usize) -> u64 {
    0xF000_0000_0000_0000 | ((filesystem_index as u64) << 32)
}

fn synthetic_orphan_file_id(filesystem_index: usize, inode: u64) -> u64 {
    0xF100_0000_0000_0000 | ((filesystem_index as u64) << 32) | inode
}

fn live_node_from_entry(
    ext4: &Ext4Fs<'_>,
    filesystem_index: usize,
    parent_id: Option<u64>,
    absolute_path: String,
    entry: &recovermax_core::fs::DirEntry,
) -> Result<SessionNode> {
    let mut file_type = entry.file_type;
    let mut size = Some(entry.size);
    let mut deleted = entry.deleted;
    let mut timestamps = None;

    if entry.inode > 0 {
        if let Ok(inode) = ext4.read_inode(entry.inode) {
            file_type = inode.file_type();
            size = Some(inode.size);
            deleted |= inode.is_deleted();
            timestamps = ext_inode_timestamps(&inode);
        }
    }

    Ok(SessionNode {
        id: if entry.inode > 0 { entry.inode } else { 0 },
        parent_id,
        filesystem_index,
        inode: if entry.inode > 0 {
            Some(entry.inode)
        } else {
            None
        },
        basename: entry.name.clone(),
        path: absolute_path,
        file_type,
        deleted,
        size,
        source: entry.source,
        parent_inode: entry.parent_inode,
        timestamps,
    })
}

fn ext_inode_timestamps(inode: &recovermax_core::fs::ext4::Inode) -> Option<SessionNodeTimestamps> {
    let timestamps = SessionNodeTimestamps {
        created_unix: nonzero_unix_timestamp(inode.ctime),
        modified_unix: nonzero_unix_timestamp(inode.mtime),
        accessed_unix: nonzero_unix_timestamp(inode.atime),
        deleted_unix: nonzero_unix_timestamp(inode.dtime),
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

fn normalize_session_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else {
        format!("/{}", trimmed.trim_start_matches('/'))
    }
}

fn recover_with_fallback(
    session: &mut RecoverySession,
    dest: &Path,
    target: Option<&SessionNode>,
    requested_path: Option<&str>,
) -> Result<()> {
    let artifact = session.artifact().clone();
    let reader = session
        .attached_reader()
        .ok_or_else(|| anyhow!("session has no attached image reader"))?;
    let recoverer = recover::Recoverer::new(reader, dest);
    let requested_path = target
        .zip(requested_path)
        .map(|(node, requested)| normalize_requested_recovery_path(&node.path, requested));

    if let Some(node) = target {
        let filesystem = artifact
            .filesystem_session(node.filesystem_index)
            .with_context(|| {
                format!("filesystem {} not found in session", node.filesystem_index)
            })?;
        let ext4 = Ext4Fs::new(reader, filesystem.fs_info.offset)?;
        if node.file_type == FileType::Directory {
            if node.inode.is_some() {
                recoverer.recover_session_subtree_to_path(
                    &ext4,
                    node,
                    requested_path.as_deref(),
                )?;
                return Ok(());
            }
        } else {
            recoverer.recover_session_node_to_path(&ext4, node, requested_path.as_deref())?;
            return Ok(());
        }
    }

    recoverer.recover_artifact(&artifact, target.map(|node| node.path.as_str()))
}

fn normalize_requested_recovery_path(resolved_path: &str, requested_path: &str) -> String {
    let normalized = normalize_session_path(requested_path);
    if normalized == resolved_path {
        resolved_path.to_string()
    } else {
        normalized
    }
}

fn warm_session_caches(session: &mut RecoverySession) -> Result<()> {
    let filesystem_indexes: Vec<usize> = session
        .artifact()
        .filesystems
        .iter()
        .filter(|filesystem| filesystem.has_tree())
        .map(|filesystem| filesystem.filesystem_index)
        .collect();

    for fs_index in filesystem_indexes {
        let _ = session.list_children(fs_index, "/")?;
        let _ = session.walk_tree(fs_index, "/", 1)?;
    }

    Ok(())
}

fn print_filesystems(session: &RecoverySession) {
    println!("Filesystems:");
    for fs in session.filesystems() {
        let tree_status = if fs.has_tree() {
            format!("tree: {} nodes", fs.nodes.len())
        } else if session.attached_reader().is_some() && fs.fs_info.fs_type == "ext4" {
            "report-only; live-fallback".to_string()
        } else {
            "report-only".to_string()
        };

        println!(
            "  [{}] {} \"{}\" ({}) {}",
            fs.filesystem_index,
            fs.fs_info.fs_type,
            fs.fs_info.label,
            bytesize::ByteSize(fs.fs_info.total_size),
            tree_status
        );
    }
}

fn print_directory_listing(entries: &[SessionNode], long: bool) {
    if entries.is_empty() {
        println!("No entries found.");
        return;
    }

    for entry in entries {
        if long {
            println!("{}", format_node_long(entry));
        } else {
            println!("{}", format_node_short(entry));
        }
    }
}

fn print_tree_entries(entries: &[SessionTreeEntry], max_depth: usize) {
    if entries.is_empty() {
        println!("No nodes found.");
        return;
    }

    for entry in entries {
        if entry.depth > max_depth {
            continue;
        }

        let indent = "  ".repeat(entry.depth);
        println!("{}{}", indent, format_node_short(&entry.node));
    }
}

fn print_stat_node(node: &SessionNode, artifact: &RecoverySessionArtifact) {
    let fs_info = artifact
        .filesystems
        .iter()
        .find(|filesystem| filesystem.filesystem_index == node.filesystem_index)
        .map(|filesystem| &filesystem.fs_info);

    println!("Path: {}", node.path);
    println!("Filesystem: {}", node.filesystem_index);
    if let Some(info) = fs_info {
        println!("Filesystem label: {}", info.label);
        println!("Filesystem type: {}", info.fs_type);
        println!("Filesystem offset: {}", bytesize::ByteSize(info.offset));
    }
    println!("Node id: {}", node.id);
    println!(
        "Inode: {}",
        node.inode
            .map(|inode| inode.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("Type: {}", file_type_label(node.file_type));
    println!("Deleted: {}", node.deleted);
    println!("Source: {}", entry_source_label(node.source));
    println!(
        "Parent inode: {}",
        node.parent_inode
            .map(|inode| inode.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "Size: {}",
        node.size
            .map(bytesize::ByteSize)
            .map(|size| size.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "Modified: {}",
        format_optional_unix_timestamp(
            node.timestamps
                .as_ref()
                .and_then(|timestamps| timestamps.modified_unix)
        )
    );
    println!(
        "Created: {}",
        format_optional_unix_timestamp(
            node.timestamps
                .as_ref()
                .and_then(|timestamps| timestamps.created_unix)
        )
    );
    println!(
        "Accessed: {}",
        format_optional_unix_timestamp(
            node.timestamps
                .as_ref()
                .and_then(|timestamps| timestamps.accessed_unix)
        )
    );
    println!(
        "Deleted at: {}",
        format_optional_unix_timestamp(
            node.timestamps
                .as_ref()
                .and_then(|timestamps| timestamps.deleted_unix)
        )
    );
    println!("Basename: {}", node.basename);
}

fn format_optional_unix_timestamp(value: Option<i64>) -> String {
    value
        .map(|timestamp| timestamp.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn format_deleted_inode_row(inode: &DeletedInode) -> String {
    format!(
        "{:>8}  {:>12}  {:>10}  {:>8}  {}",
        inode.inode_num,
        bytesize::ByteSize(inode.size),
        format_deleted_time(inode.dtime),
        file_type_label(inode.file_type),
        synthetic_orphan_path(inode.inode_num),
    )
}

fn format_deleted_time(dtime: u32) -> String {
    if dtime == 0 {
        "-".to_string()
    } else {
        dtime.to_string()
    }
}

fn synthetic_orphan_path(inode: u64) -> String {
    format!("/$OrphanFiles/OrphanFile-{}", inode)
}

fn entry_source_label(source: EntrySource) -> &'static str {
    match source {
        EntrySource::Filesystem => "filesystem",
        EntrySource::DeletedSlack => "deleted-slack",
        EntrySource::SyntheticOrphan => "synthetic-orphan",
    }
}

fn print_cache_summary(label: &str, summary: &CacheSummary) {
    println!(
        "{} budget: {}",
        label,
        bytesize::ByteSize(summary.budget_bytes)
    );
    println!("Budget source: {:?}", summary.budget_source);
    println!(
        "Estimated bytes: {}",
        bytesize::ByteSize(summary.estimated_bytes)
    );
    println!("Node index loaded: {}", summary.node_index_loaded);
    println!("Path index loaded: {}", summary.path_index_loaded);
    println!("Children index loaded: {}", summary.children_index_loaded);
    println!("Evictions: {}", summary.evictions);
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
            "[fs {} {} inode={}] {}{}{}",
            m.filesystem_index,
            file_type_label(m.file_type),
            m.inode,
            m.path,
            deleted,
            source
        );
    }
    println!("\n{} matches", matches.len());
}

fn format_node_short(node: &SessionNode) -> String {
    let marker = match node.file_type {
        FileType::Directory => "d",
        FileType::RegularFile => "-",
        FileType::Symlink => "l",
        FileType::Other => "?",
    };
    let name = if node.path == "/" {
        "/".to_string()
    } else {
        node.basename.clone()
    };
    let deleted = if node.deleted { " [deleted]" } else { "" };
    let source = match node.source {
        EntrySource::Filesystem => "",
        EntrySource::DeletedSlack => " [slack]",
        EntrySource::SyntheticOrphan => " [orphan]",
    };
    format!("{} {}{}{}", marker, name, deleted, source)
}

fn format_node_long(node: &SessionNode) -> String {
    let marker = match node.file_type {
        FileType::Directory => "d",
        FileType::RegularFile => "-",
        FileType::Symlink => "l",
        FileType::Other => "?",
    };
    let size = node
        .size
        .map(bytesize::ByteSize)
        .map(|size| size.to_string())
        .unwrap_or_else(|| "-".to_string());
    let inode = node
        .inode
        .map(|inode| inode.to_string())
        .unwrap_or_else(|| "-".to_string());
    let deleted = if node.deleted { " deleted" } else { "" };
    let source = match node.source {
        EntrySource::Filesystem => String::new(),
        EntrySource::DeletedSlack => format!(
            " source=deleted-slack{}",
            node.parent_inode
                .map(|inode| format!(" parent={}", inode))
                .unwrap_or_default()
        ),
        EntrySource::SyntheticOrphan => " source=synthetic-orphan".to_string(),
    };

    format!(
        "{:>1} {:>12} inode={:<8} {}{}{}",
        marker, size, inode, node.path, deleted, source
    )
}

fn file_type_label(file_type: FileType) -> &'static str {
    match file_type {
        FileType::RegularFile => "file",
        FileType::Directory => "dir",
        FileType::Symlink => "symlink",
        FileType::Other => "other",
    }
}

pub fn print_hexdump_pub(data: &[u8], base_offset: u64) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_offset + (i * 16) as u64;
        print!("{:08x}  ", addr);

        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                print!("   ");
                if j == 7 {
                    print!(" ");
                }
            }
        }

        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use recovermax_core::fs::FsInfo;
    use recovermax_core::io::ImageReader;
    use recovermax_core::scan::{Partition, ScanReport};
    use recovermax_core::session::{
        FilesystemSessionArtifact, RecoverySession, RecoverySessionArtifact, ScanImageSource,
        SessionNode,
    };

    fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "recovermax-{}-{}-{}{}",
            prefix,
            std::process::id(),
            stamp,
            suffix
        ))
    }

    fn write_test_image(data: &[u8]) -> PathBuf {
        let path = unique_path("cli-fallback", ".img");
        fs::write(&path, data).unwrap();
        path
    }

    fn report_only_session(image_path: &Path) -> RecoverySession {
        let reader = ImageReader::open(image_path).unwrap();
        let artifact = RecoverySessionArtifact {
            version: RecoverySessionArtifact::VERSION,
            source: ScanImageSource {
                path: image_path.to_path_buf(),
                image_size: reader.len(),
            },
            report: ScanReport {
                image_size: reader.len(),
                partitions: vec![Partition {
                    name: "p1".to_string(),
                    offset: 0,
                    size: reader.len(),
                    fs_type: "Linux".to_string(),
                }],
                filesystems: vec![FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "report-only".to_string(),
                    uuid: "22222222-3333-4444-5555-666666666666".to_string(),
                    block_size: 4096,
                    total_size: reader.len(),
                    offset: 0,
                }],
            },
            filesystems: vec![FilesystemSessionArtifact {
                filesystem_index: 0,
                fs_info: FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "report-only".to_string(),
                    uuid: "22222222-3333-4444-5555-666666666666".to_string(),
                    block_size: 4096,
                    total_size: reader.len(),
                    offset: 0,
                },
                root_node_id: None,
                nodes: Vec::new(),
            }],
        };

        RecoverySession::from_artifact_with_reader(artifact, reader, None)
    }

    struct Ext4ImageBuilder {
        data: Vec<u8>,
        block_size: usize,
        inode_size: usize,
        inode_table_block: usize,
        inodes_per_group: usize,
    }

    impl Ext4ImageBuilder {
        fn new(size_blocks: usize) -> Self {
            Self {
                data: vec![0u8; size_blocks * 4096],
                block_size: 4096,
                inode_size: 256,
                inode_table_block: 3,
                inodes_per_group: 256,
            }
        }

        fn write_superblock(&mut self, label: &str) {
            let sb = 1024usize;
            let blocks = (self.data.len() / self.block_size) as u32;

            self.write_u32(sb, self.inodes_per_group as u32);
            self.write_u32(sb + 0x04, blocks);
            self.write_u32(sb + 0x0C, blocks / 2);
            self.write_u32(sb + 0x10, (self.inodes_per_group / 2) as u32);
            self.write_u32(sb + 0x14, 0);
            self.write_u32(sb + 0x18, 2);
            self.write_u32(sb + 0x20, 8192);
            self.write_u32(sb + 0x28, self.inodes_per_group as u32);
            self.write_u16(sb + 0x38, 0xEF53);
            self.write_u16(sb + 0x58, self.inode_size as u16);
            self.write_u32(sb + 0x60, 0xC0);

            for (idx, byte) in (1u8..=16).enumerate() {
                self.data[sb + 0x68 + idx] = byte;
            }

            let name = label.as_bytes();
            let len = name.len().min(16);
            self.data[sb + 0x78..sb + 0x78 + len].copy_from_slice(&name[..len]);
            self.write_u32(sb + 0x150, 0);
        }

        fn write_bgdt(&mut self, group: u32, inode_table_block: u64) {
            let bgdt_off = self.block_size;
            let desc_size = 64usize;
            let off = bgdt_off + group as usize * desc_size;
            self.write_u32(off + 8, inode_table_block as u32);
            self.write_u32(off + 40, (inode_table_block >> 32) as u32);
        }

        fn write_inode_with_extent(
            &mut self,
            inode_num: u64,
            mode: u16,
            size: u64,
            data_block: u64,
            block_count: u16,
        ) {
            let index = (inode_num - 1) % self.inodes_per_group as u64;
            let off = self.inode_table_block * self.block_size + index as usize * self.inode_size;

            self.write_u16(off, mode);
            self.write_u32(off + 4, size as u32);
            self.write_u32(off + 108, (size >> 32) as u32);
            self.write_u16(off + 26, 1);
            self.write_u32(off + 32, 0x80000);

            let ext_off = off + 40;
            self.write_u16(ext_off, 0xF30A);
            self.write_u16(ext_off + 2, 1);
            self.write_u16(ext_off + 4, 4);
            self.write_u16(ext_off + 6, 0);
            self.write_u32(ext_off + 12, 0);
            self.write_u16(ext_off + 16, block_count);
            self.write_u16(ext_off + 18, (data_block >> 32) as u16);
            self.write_u32(ext_off + 20, data_block as u32);
        }

        fn write_dir_entries(&mut self, block: u64, entries: &[(u32, u8, &str)]) {
            let block_off = block as usize * self.block_size;
            let mut pos = block_off;

            for (idx, &(inode, file_type, name)) in entries.iter().enumerate() {
                let name_bytes = name.as_bytes();
                let rec_len = if idx == entries.len() - 1 {
                    self.block_size - (pos - block_off)
                } else {
                    ((8 + name_bytes.len() + 3) / 4) * 4
                };

                self.write_u32(pos, inode);
                self.write_u16(pos + 4, rec_len as u16);
                self.data[pos + 6] = name_bytes.len() as u8;
                self.data[pos + 7] = file_type;
                self.data[pos + 8..pos + 8 + name_bytes.len()].copy_from_slice(name_bytes);
                pos += rec_len;
            }
        }

        fn write_data(&mut self, block: u64, content: &[u8]) {
            let off = block as usize * self.block_size;
            self.data[off..off + content.len()].copy_from_slice(content);
        }

        fn write_u16(&mut self, off: usize, val: u16) {
            self.data[off..off + 2].copy_from_slice(&val.to_le_bytes());
        }

        fn write_u32(&mut self, off: usize, val: u32) {
            self.data[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }

        fn build(self) -> Vec<u8> {
            self.data
        }
    }

    fn build_report_only_fixture() -> (PathBuf, Vec<u8>) {
        let mut builder = Ext4ImageBuilder::new(64);
        builder.write_superblock("report-only");
        builder.write_bgdt(0, 3);

        builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
        builder.write_inode_with_extent(11, 0x8000 | 0o644, 13, 20, 1);
        builder.write_dir_entries(10, &[(2, 2, "."), (2, 2, ".."), (11, 1, "hello.txt")]);
        builder.write_data(20, b"Hello, world!");

        let bytes = builder.build();
        let image_path = write_test_image(&bytes);
        (image_path, bytes)
    }

    fn build_report_only_orphan_fixture() -> (PathBuf, Vec<u8>) {
        let mut builder = Ext4ImageBuilder::new(96);
        builder.write_superblock("report-orphan");
        builder.write_bgdt(0, 3);

        builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
        builder.write_inode_with_extent(11, 0x8000 | 0o644, 13, 20, 1);
        builder.write_inode_with_extent(13, 0x8000 | 0o644, 8, 30, 1);

        builder.write_dir_entries(10, &[(2, 2, "."), (2, 2, ".."), (11, 1, "hello.txt")]);
        builder.write_data(20, b"Hello, world!");
        builder.write_data(30, b"orphaned");

        let inode13_off = 3 * 4096 + 12 * 256;
        builder.write_u32(inode13_off + 8, 1_700_000_001);
        builder.write_u32(inode13_off + 12, 1_700_000_002);
        builder.write_u32(inode13_off + 16, 1_700_000_003);
        builder.write_u16(inode13_off + 26, 0);
        builder.write_u32(inode13_off + 20, 1234567890);

        let bytes = builder.build();
        let image_path = write_test_image(&bytes);
        (image_path, bytes)
    }

    fn build_report_only_orphan_directory_fixture() -> (PathBuf, Vec<u8>) {
        let mut builder = Ext4ImageBuilder::new(96);
        builder.write_superblock("report-orphan-dir");
        builder.write_bgdt(0, 3);

        builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
        builder.write_inode_with_extent(11, 0x8000 | 0o644, 13, 20, 1);
        builder.write_inode_with_extent(13, 0x4000 | 0o755, 4096, 30, 1);
        builder.write_inode_with_extent(14, 0x8000 | 0o644, 6, 40, 1);

        builder.write_dir_entries(10, &[(2, 2, "."), (2, 2, ".."), (11, 1, "hello.txt")]);
        builder.write_data(20, b"Hello, world!");
        builder.write_dir_entries(30, &[(13, 2, "."), (2, 2, ".."), (14, 1, "hidden.txt")]);
        builder.write_data(40, b"secret");

        let inode13_off = 3 * 4096 + 12 * 256;
        builder.write_u16(inode13_off + 26, 0);
        builder.write_u32(inode13_off + 20, 1234567890);

        let bytes = builder.build();
        let image_path = write_test_image(&bytes);
        (image_path, bytes)
    }

    #[test]
    fn report_only_fallback_supports_browsing_search_and_recovery() {
        let (image_path, _) = build_report_only_fixture();
        let mut session = report_only_session(&image_path);

        let root = resolve_node_with_fallback(&mut session, 0, "/").unwrap();
        assert_eq!(root.path, "/");
        assert_eq!(root.basename, "/");
        assert_eq!(root.inode, Some(2));

        let hello = resolve_node_with_fallback(&mut session, 0, "/hello.txt").unwrap();
        assert_eq!(hello.path, "/hello.txt");
        assert_eq!(hello.basename, "hello.txt");
        assert_eq!(hello.inode, Some(11));
        assert_eq!(hello.file_type, FileType::RegularFile);

        let children = list_children_with_fallback(&mut session, 0, "/").unwrap();
        assert!(children.iter().any(|node| node.basename == "hello.txt"));

        let entries = walk_tree_with_fallback(&mut session, 0, "/", 8).unwrap();
        assert!(entries.iter().any(|entry| entry.node.path == "/"));
        assert!(entries.iter().any(|entry| entry.node.path == "/hello.txt"));

        let matches = search_with_fallback(
            &mut session,
            "hello",
            &SearchOptions {
                filesystem_index: Some(0),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].path, "/hello.txt");
        assert_eq!(matches[0].inode, 11);

        let dest = unique_path("cli-fallback-out", "");
        fs::create_dir_all(&dest).unwrap();
        recover_with_fallback(&mut session, &dest, None, None).unwrap();

        let recovered = fs::read(dest.join("hello.txt")).unwrap();
        assert_eq!(recovered, b"Hello, world!");
    }

    #[test]
    fn report_only_fallback_surfaces_orphan_nodes_and_recovers_them() {
        let (image_path, _) = build_report_only_orphan_fixture();
        let mut session = report_only_session(&image_path);

        let root_children = list_children_with_fallback(&mut session, 0, "/").unwrap();
        assert!(root_children.iter().any(|node| node.path == "/hello.txt"));
        assert!(root_children
            .iter()
            .any(|node| node.path == "/$OrphanFiles"));

        let orphan_dir = resolve_node_with_fallback(&mut session, 0, "/$OrphanFiles").unwrap();
        assert_eq!(orphan_dir.file_type, FileType::Directory);
        assert!(orphan_dir.inode.is_none());

        let orphan =
            resolve_recovery_target(&mut session, None, "/$OrphanFiles/OrphanFile-13").unwrap();
        assert_eq!(orphan.inode, Some(13));
        assert!(orphan.deleted);
        assert_eq!(
            orphan
                .timestamps
                .as_ref()
                .and_then(|timestamps| timestamps.modified_unix),
            Some(1_700_000_003)
        );

        let matches = search_with_fallback(
            &mut session,
            "OrphanFile-13",
            &SearchOptions {
                filesystem_index: Some(0),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].path, "/$OrphanFiles/OrphanFile-13");
        assert!(matches[0].deleted);

        let dest = unique_path("cli-fallback-orphan-out", "");
        fs::create_dir_all(&dest).unwrap();
        recover_with_fallback(&mut session, &dest, Some(&orphan), None).unwrap();

        let recovered = fs::read(dest.join("$OrphanFiles/OrphanFile-13")).unwrap();
        assert_eq!(recovered, b"orphaned");
    }

    #[test]
    fn report_only_fallback_browses_orphan_directory_subtrees() {
        let (image_path, _) = build_report_only_orphan_directory_fixture();
        let mut session = report_only_session(&image_path);

        let orphan_dir =
            resolve_node_with_fallback(&mut session, 0, "/$OrphanFiles/OrphanFile-13").unwrap();
        assert_eq!(orphan_dir.file_type, FileType::Directory);
        assert_eq!(orphan_dir.inode, Some(13));
        assert!(orphan_dir.deleted);

        let children =
            list_children_with_fallback(&mut session, 0, "/$OrphanFiles/OrphanFile-13").unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].path, "/$OrphanFiles/OrphanFile-13/hidden.txt");

        let hidden =
            resolve_node_with_fallback(&mut session, 0, "/$OrphanFiles/OrphanFile-13/hidden.txt")
                .unwrap();
        assert_eq!(hidden.inode, Some(14));
        assert_eq!(hidden.file_type, FileType::RegularFile);

        let matches = search_with_fallback(
            &mut session,
            "hidden",
            &SearchOptions {
                filesystem_index: Some(0),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches
            .iter()
            .any(|m| m.path == "/$OrphanFiles/OrphanFile-13/hidden.txt"));

        let dest = unique_path("cli-fallback-orphan-dir-out", "");
        fs::create_dir_all(&dest).unwrap();
        recover_with_fallback(&mut session, &dest, Some(&orphan_dir), None).unwrap();

        let recovered = fs::read(dest.join("$OrphanFiles/OrphanFile-13/hidden.txt")).unwrap();
        assert_eq!(recovered, b"secret");
    }

    #[test]
    fn deleted_residual_path_without_inode_auto_resolves_unique_orphan() {
        let artifact = RecoverySessionArtifact {
            version: RecoverySessionArtifact::VERSION,
            source: ScanImageSource {
                path: PathBuf::from("/tmp/fake.img"),
                image_size: 4096,
            },
            report: ScanReport {
                image_size: 4096,
                partitions: vec![Partition {
                    name: "p1".to_string(),
                    offset: 0,
                    size: 4096,
                    fs_type: "Linux".to_string(),
                }],
                filesystems: vec![FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: 4096,
                    offset: 0,
                }],
            },
            filesystems: vec![FilesystemSessionArtifact {
                filesystem_index: 0,
                fs_info: FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: 4096,
                    offset: 0,
                },
                root_node_id: Some(1),
                nodes: vec![
                    SessionNode {
                        id: 1,
                        parent_id: None,
                        filesystem_index: 0,
                        inode: Some(2),
                        basename: "/".to_string(),
                        path: "/".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: Some(4096),
                        source: EntrySource::Filesystem,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 2,
                        parent_id: Some(1),
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
                    },
                    SessionNode {
                        id: 3,
                        parent_id: Some(1),
                        filesystem_index: 0,
                        inode: None,
                        basename: "$OrphanFiles".to_string(),
                        path: "/$OrphanFiles".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: None,
                        source: EntrySource::Filesystem,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 4,
                        parent_id: Some(3),
                        filesystem_index: 0,
                        inode: Some(99),
                        basename: "OrphanFile-99".to_string(),
                        path: "/$OrphanFiles/OrphanFile-99".to_string(),
                        file_type: FileType::RegularFile,
                        deleted: true,
                        size: Some(7),
                        source: EntrySource::Filesystem,
                        parent_inode: None,
                        timestamps: None,
                    },
                ],
            }],
        };

        let mut session = RecoverySession::from_artifact(artifact, None);
        let resolved = resolve_recovery_target(&mut session, None, "/ghost.txt").unwrap();
        assert_eq!(resolved.path, "/$OrphanFiles/OrphanFile-99");
        assert_eq!(resolved.inode, Some(99));
    }

    #[test]
    fn auto_resolved_deleted_recovery_uses_requested_output_path() {
        let (image_path, _) = build_report_only_orphan_fixture();
        let reader = ImageReader::open(&image_path).unwrap();
        let artifact = RecoverySessionArtifact {
            version: RecoverySessionArtifact::VERSION,
            source: ScanImageSource {
                path: image_path.clone(),
                image_size: reader.len(),
            },
            report: ScanReport {
                image_size: reader.len(),
                partitions: vec![Partition {
                    name: "p1".to_string(),
                    offset: 0,
                    size: reader.len(),
                    fs_type: "Linux".to_string(),
                }],
                filesystems: vec![FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: reader.len(),
                    offset: 0,
                }],
            },
            filesystems: vec![FilesystemSessionArtifact {
                filesystem_index: 0,
                fs_info: FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: reader.len(),
                    offset: 0,
                },
                root_node_id: Some(1),
                nodes: vec![
                    SessionNode {
                        id: 1,
                        parent_id: None,
                        filesystem_index: 0,
                        inode: Some(2),
                        basename: "/".to_string(),
                        path: "/".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: Some(4096),
                        source: EntrySource::Filesystem,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 2,
                        parent_id: Some(1),
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
                    },
                    SessionNode {
                        id: 3,
                        parent_id: Some(1),
                        filesystem_index: 0,
                        inode: None,
                        basename: "$OrphanFiles".to_string(),
                        path: "/$OrphanFiles".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: None,
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 4,
                        parent_id: Some(3),
                        filesystem_index: 0,
                        inode: Some(13),
                        basename: "OrphanFile-13".to_string(),
                        path: "/$OrphanFiles/OrphanFile-13".to_string(),
                        file_type: FileType::RegularFile,
                        deleted: true,
                        size: Some(8),
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: Some(SessionNodeTimestamps {
                            created_unix: Some(1_700_000_001),
                            modified_unix: Some(1_700_000_003),
                            accessed_unix: Some(1_700_000_002),
                            deleted_unix: Some(1_234_567_890),
                        }),
                    },
                ],
            }],
        };

        let mut session = RecoverySession::from_artifact_with_reader(artifact, reader, None);
        let resolved = resolve_recovery_target(&mut session, None, "/ghost.txt").unwrap();
        assert_eq!(resolved.path, "/$OrphanFiles/OrphanFile-13");

        let dest = unique_path("cli-fallback-residual-out", "");
        fs::create_dir_all(&dest).unwrap();
        recover_with_fallback(&mut session, &dest, Some(&resolved), Some("/ghost.txt")).unwrap();

        let recovered = fs::read(dest.join("ghost.txt")).unwrap();
        assert_eq!(recovered, b"orphaned");
        assert!(!dest.join("$OrphanFiles/OrphanFile-13").exists());
        assert!(!dest.join("$OrphanFiles").exists());
    }

    #[test]
    fn residual_deleted_entry_reports_stat_hint_for_unique_orphan() {
        let artifact = RecoverySessionArtifact {
            version: RecoverySessionArtifact::VERSION,
            source: ScanImageSource {
                path: PathBuf::from("/tmp/fake.img"),
                image_size: 4096,
            },
            report: ScanReport {
                image_size: 4096,
                partitions: vec![Partition {
                    name: "p1".to_string(),
                    offset: 0,
                    size: 4096,
                    fs_type: "Linux".to_string(),
                }],
                filesystems: vec![FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: 4096,
                    offset: 0,
                }],
            },
            filesystems: vec![FilesystemSessionArtifact {
                filesystem_index: 0,
                fs_info: FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: 4096,
                    offset: 0,
                },
                root_node_id: Some(1),
                nodes: vec![
                    SessionNode {
                        id: 1,
                        parent_id: None,
                        filesystem_index: 0,
                        inode: Some(2),
                        basename: "/".to_string(),
                        path: "/".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: Some(4096),
                        source: EntrySource::Filesystem,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 2,
                        parent_id: Some(1),
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
                    },
                    SessionNode {
                        id: 3,
                        parent_id: Some(1),
                        filesystem_index: 0,
                        inode: None,
                        basename: "$OrphanFiles".to_string(),
                        path: "/$OrphanFiles".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: None,
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 4,
                        parent_id: Some(3),
                        filesystem_index: 0,
                        inode: Some(99),
                        basename: "OrphanFile-99".to_string(),
                        path: "/$OrphanFiles/OrphanFile-99".to_string(),
                        file_type: FileType::RegularFile,
                        deleted: true,
                        size: Some(7),
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: None,
                    },
                ],
            }],
        };

        let session = RecoverySession::from_artifact(artifact, None);
        let node = session
            .artifact()
            .filesystem_session(0)
            .unwrap()
            .nodes
            .iter()
            .find(|node| node.path == "/ghost.txt")
            .unwrap()
            .clone();
        let hint = deleted_recovery_hint_message(&session, &node).unwrap();
        assert_eq!(hint, "Try /$OrphanFiles/OrphanFile-99 instead.");
    }

    #[test]
    fn legacy_deleted_residual_without_provenance_still_auto_resolves_unique_orphan() {
        let artifact = RecoverySessionArtifact {
            version: RecoverySessionArtifact::VERSION,
            source: ScanImageSource {
                path: PathBuf::from("/tmp/fake.img"),
                image_size: 4096,
            },
            report: ScanReport {
                image_size: 4096,
                partitions: vec![Partition {
                    name: "p1".to_string(),
                    offset: 0,
                    size: 4096,
                    fs_type: "Linux".to_string(),
                }],
                filesystems: vec![FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: 4096,
                    offset: 0,
                }],
            },
            filesystems: vec![FilesystemSessionArtifact {
                filesystem_index: 0,
                fs_info: FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: 4096,
                    offset: 0,
                },
                root_node_id: Some(1),
                nodes: vec![
                    SessionNode {
                        id: 1,
                        parent_id: None,
                        filesystem_index: 0,
                        inode: Some(2),
                        basename: "/".to_string(),
                        path: "/".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: Some(4096),
                        source: EntrySource::Filesystem,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 2,
                        parent_id: Some(1),
                        filesystem_index: 0,
                        inode: None,
                        basename: "ghost.txt".to_string(),
                        path: "/ghost.txt".to_string(),
                        file_type: FileType::RegularFile,
                        deleted: true,
                        size: None,
                        source: EntrySource::Filesystem,
                        parent_inode: Some(2),
                        timestamps: None,
                    },
                    SessionNode {
                        id: 3,
                        parent_id: Some(1),
                        filesystem_index: 0,
                        inode: None,
                        basename: "$OrphanFiles".to_string(),
                        path: "/$OrphanFiles".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: None,
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 4,
                        parent_id: Some(3),
                        filesystem_index: 0,
                        inode: Some(99),
                        basename: "OrphanFile-99".to_string(),
                        path: "/$OrphanFiles/OrphanFile-99".to_string(),
                        file_type: FileType::RegularFile,
                        deleted: true,
                        size: Some(7),
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: None,
                    },
                ],
            }],
        };

        let mut session = RecoverySession::from_artifact(artifact, None);
        let resolved = resolve_recovery_target(&mut session, None, "/ghost.txt").unwrap();
        assert_eq!(resolved.path, "/$OrphanFiles/OrphanFile-99");
        assert_eq!(resolved.inode, Some(99));
    }

    #[test]
    fn deleted_residual_path_reports_multiple_orphan_candidates() {
        let artifact = RecoverySessionArtifact {
            version: RecoverySessionArtifact::VERSION,
            source: ScanImageSource {
                path: PathBuf::from("/tmp/fake.img"),
                image_size: 4096,
            },
            report: ScanReport {
                image_size: 4096,
                partitions: vec![Partition {
                    name: "p1".to_string(),
                    offset: 0,
                    size: 4096,
                    fs_type: "Linux".to_string(),
                }],
                filesystems: vec![FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: 4096,
                    offset: 0,
                }],
            },
            filesystems: vec![FilesystemSessionArtifact {
                filesystem_index: 0,
                fs_info: FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "synthetic".to_string(),
                    uuid: "99999999-aaaa-bbbb-cccc-dddddddddddd".to_string(),
                    block_size: 4096,
                    total_size: 4096,
                    offset: 0,
                },
                root_node_id: Some(1),
                nodes: vec![
                    SessionNode {
                        id: 1,
                        parent_id: None,
                        filesystem_index: 0,
                        inode: Some(2),
                        basename: "/".to_string(),
                        path: "/".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: Some(4096),
                        source: EntrySource::Filesystem,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 2,
                        parent_id: Some(1),
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
                    },
                    SessionNode {
                        id: 3,
                        parent_id: Some(1),
                        filesystem_index: 0,
                        inode: None,
                        basename: "$OrphanFiles".to_string(),
                        path: "/$OrphanFiles".to_string(),
                        file_type: FileType::Directory,
                        deleted: false,
                        size: None,
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: None,
                    },
                    SessionNode {
                        id: 4,
                        parent_id: Some(3),
                        filesystem_index: 0,
                        inode: Some(42),
                        basename: "OrphanFile-42".to_string(),
                        path: "/$OrphanFiles/OrphanFile-42".to_string(),
                        file_type: FileType::RegularFile,
                        deleted: true,
                        size: Some(11),
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: Some(SessionNodeTimestamps {
                            created_unix: Some(1_700_000_041),
                            modified_unix: Some(1_700_000_042),
                            accessed_unix: Some(1_700_000_043),
                            deleted_unix: Some(1_700_000_044),
                        }),
                    },
                    SessionNode {
                        id: 5,
                        parent_id: Some(3),
                        filesystem_index: 0,
                        inode: Some(99),
                        basename: "OrphanFile-99".to_string(),
                        path: "/$OrphanFiles/OrphanFile-99".to_string(),
                        file_type: FileType::RegularFile,
                        deleted: true,
                        size: Some(7),
                        source: EntrySource::SyntheticOrphan,
                        parent_inode: None,
                        timestamps: Some(SessionNodeTimestamps {
                            created_unix: Some(1_700_000_099),
                            modified_unix: Some(1_700_000_100),
                            accessed_unix: Some(1_700_000_101),
                            deleted_unix: Some(1_700_000_102),
                        }),
                    },
                ],
            }],
        };

        let mut session = RecoverySession::from_artifact(artifact, None);
        let err = resolve_recovery_target(&mut session, None, "/ghost.txt").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Possible orphan candidates:"));
        assert!(message.contains(
            "/$OrphanFiles/OrphanFile-42 (inode 42, 11 B, mtime 1700000042, dtime 1700000044)."
        ));
        assert!(message.contains(
            "/$OrphanFiles/OrphanFile-99 (inode 99, 7 B, mtime 1700000100, dtime 1700000102)."
        ));
    }

    #[test]
    fn deleted_inode_row_includes_orphan_path_and_dtime() {
        let row = format_deleted_inode_row(&DeletedInode {
            inode_num: 42,
            size: 11,
            file_type: FileType::RegularFile,
            dtime: 1_700_000_042,
            mode: 0x8000,
            ctime: 1_700_000_001,
            mtime: 1_700_000_002,
            atime: 1_700_000_003,
        });
        assert!(row.contains("42"));
        assert!(row.contains("11 B"));
        assert!(row.contains("1700000042"));
        assert!(row.contains("file"));
        assert!(row.contains("/$OrphanFiles/OrphanFile-42"));
    }

    #[test]
    fn recover_target_resolution_requires_fs_when_path_exists_in_multiple_filesystems() {
        let artifact = RecoverySessionArtifact {
            version: RecoverySessionArtifact::VERSION,
            source: ScanImageSource {
                path: PathBuf::from("/tmp/fake.img"),
                image_size: 8192,
            },
            report: ScanReport {
                image_size: 8192,
                partitions: vec![],
                filesystems: vec![
                    FsInfo {
                        fs_type: "ext4".to_string(),
                        label: "ext-a".to_string(),
                        uuid: "a".to_string(),
                        block_size: 4096,
                        total_size: 4096,
                        offset: 0,
                    },
                    FsInfo {
                        fs_type: "ext4".to_string(),
                        label: "ext-b".to_string(),
                        uuid: "b".to_string(),
                        block_size: 4096,
                        total_size: 4096,
                        offset: 4096,
                    },
                ],
            },
            filesystems: vec![
                FilesystemSessionArtifact {
                    filesystem_index: 0,
                    fs_info: FsInfo {
                        fs_type: "ext4".to_string(),
                        label: "ext-a".to_string(),
                        uuid: "a".to_string(),
                        block_size: 4096,
                        total_size: 4096,
                        offset: 0,
                    },
                    root_node_id: Some(1),
                    nodes: vec![
                        SessionNode {
                            id: 1,
                            parent_id: None,
                            filesystem_index: 0,
                            inode: Some(2),
                            basename: "/".to_string(),
                            path: "/".to_string(),
                            file_type: FileType::Directory,
                            deleted: false,
                            size: Some(4096),
                            source: EntrySource::Filesystem,
                            parent_inode: None,
                            timestamps: None,
                        },
                        SessionNode {
                            id: 2,
                            parent_id: Some(1),
                            filesystem_index: 0,
                            inode: Some(10),
                            basename: "shared.txt".to_string(),
                            path: "/shared.txt".to_string(),
                            file_type: FileType::RegularFile,
                            deleted: false,
                            size: Some(3),
                            source: EntrySource::Filesystem,
                            parent_inode: Some(2),
                            timestamps: None,
                        },
                    ],
                },
                FilesystemSessionArtifact {
                    filesystem_index: 1,
                    fs_info: FsInfo {
                        fs_type: "ext4".to_string(),
                        label: "ext-b".to_string(),
                        uuid: "b".to_string(),
                        block_size: 4096,
                        total_size: 4096,
                        offset: 4096,
                    },
                    root_node_id: Some(3),
                    nodes: vec![
                        SessionNode {
                            id: 3,
                            parent_id: None,
                            filesystem_index: 1,
                            inode: Some(2),
                            basename: "/".to_string(),
                            path: "/".to_string(),
                            file_type: FileType::Directory,
                            deleted: false,
                            size: Some(4096),
                            source: EntrySource::Filesystem,
                            parent_inode: None,
                            timestamps: None,
                        },
                        SessionNode {
                            id: 4,
                            parent_id: Some(3),
                            filesystem_index: 1,
                            inode: Some(20),
                            basename: "shared.txt".to_string(),
                            path: "/shared.txt".to_string(),
                            file_type: FileType::RegularFile,
                            deleted: false,
                            size: Some(5),
                            source: EntrySource::Filesystem,
                            parent_inode: Some(2),
                            timestamps: None,
                        },
                    ],
                },
            ],
        };

        let mut session = RecoverySession::from_artifact(artifact, None);
        let err = resolve_recovery_target(&mut session, None, "/shared.txt").unwrap_err();
        assert!(err.to_string().contains("specify --fs"));
    }

    #[test]
    fn recover_target_resolution_accepts_explicit_filesystem_index() {
        let artifact = RecoverySessionArtifact {
            version: RecoverySessionArtifact::VERSION,
            source: ScanImageSource {
                path: PathBuf::from("/tmp/fake.img"),
                image_size: 8192,
            },
            report: ScanReport {
                image_size: 8192,
                partitions: vec![],
                filesystems: vec![
                    FsInfo {
                        fs_type: "ext4".to_string(),
                        label: "ext-a".to_string(),
                        uuid: "a".to_string(),
                        block_size: 4096,
                        total_size: 4096,
                        offset: 0,
                    },
                    FsInfo {
                        fs_type: "ext4".to_string(),
                        label: "ext-b".to_string(),
                        uuid: "b".to_string(),
                        block_size: 4096,
                        total_size: 4096,
                        offset: 4096,
                    },
                ],
            },
            filesystems: vec![
                FilesystemSessionArtifact {
                    filesystem_index: 0,
                    fs_info: FsInfo {
                        fs_type: "ext4".to_string(),
                        label: "ext-a".to_string(),
                        uuid: "a".to_string(),
                        block_size: 4096,
                        total_size: 4096,
                        offset: 0,
                    },
                    root_node_id: Some(1),
                    nodes: vec![
                        SessionNode {
                            id: 1,
                            parent_id: None,
                            filesystem_index: 0,
                            inode: Some(2),
                            basename: "/".to_string(),
                            path: "/".to_string(),
                            file_type: FileType::Directory,
                            deleted: false,
                            size: Some(4096),
                            source: EntrySource::Filesystem,
                            parent_inode: None,
                            timestamps: None,
                        },
                        SessionNode {
                            id: 2,
                            parent_id: Some(1),
                            filesystem_index: 0,
                            inode: Some(10),
                            basename: "shared.txt".to_string(),
                            path: "/shared.txt".to_string(),
                            file_type: FileType::RegularFile,
                            deleted: false,
                            size: Some(3),
                            source: EntrySource::Filesystem,
                            parent_inode: Some(2),
                            timestamps: None,
                        },
                    ],
                },
                FilesystemSessionArtifact {
                    filesystem_index: 1,
                    fs_info: FsInfo {
                        fs_type: "ext4".to_string(),
                        label: "ext-b".to_string(),
                        uuid: "b".to_string(),
                        block_size: 4096,
                        total_size: 4096,
                        offset: 4096,
                    },
                    root_node_id: Some(3),
                    nodes: vec![
                        SessionNode {
                            id: 3,
                            parent_id: None,
                            filesystem_index: 1,
                            inode: Some(2),
                            basename: "/".to_string(),
                            path: "/".to_string(),
                            file_type: FileType::Directory,
                            deleted: false,
                            size: Some(4096),
                            source: EntrySource::Filesystem,
                            parent_inode: None,
                            timestamps: None,
                        },
                        SessionNode {
                            id: 4,
                            parent_id: Some(3),
                            filesystem_index: 1,
                            inode: Some(20),
                            basename: "shared.txt".to_string(),
                            path: "/shared.txt".to_string(),
                            file_type: FileType::RegularFile,
                            deleted: false,
                            size: Some(5),
                            source: EntrySource::Filesystem,
                            parent_inode: Some(2),
                            timestamps: None,
                        },
                    ],
                },
            ],
        };

        let mut session = RecoverySession::from_artifact(artifact, None);
        let resolved = resolve_recovery_target(&mut session, Some(1), "/shared.txt").unwrap();
        assert_eq!(resolved.filesystem_index, 1);
        assert_eq!(resolved.inode, Some(20));
    }

    #[test]
    fn deleted_filesystem_selection_requires_fs_when_multiple_ext_filesystems_exist() {
        let report = ScanReport {
            image_size: 8192,
            partitions: vec![],
            filesystems: vec![
                FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "ext2".to_string(),
                    uuid: "a".to_string(),
                    block_size: 1024,
                    total_size: 4096,
                    offset: 0,
                },
                FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "ext3".to_string(),
                    uuid: "b".to_string(),
                    block_size: 1024,
                    total_size: 4096,
                    offset: 4096,
                },
            ],
        };

        let err = select_deleted_filesystem(&report, None).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("multiple ext filesystems found"));
        assert!(message.contains("0:ext2@0 B"));
        assert!(message.contains("1:ext3@4.0 KiB"));
    }

    #[test]
    fn deleted_filesystem_selection_accepts_explicit_index() {
        let report = ScanReport {
            image_size: 8192,
            partitions: vec![],
            filesystems: vec![
                FsInfo {
                    fs_type: "ntfs".to_string(),
                    label: "nt".to_string(),
                    uuid: "a".to_string(),
                    block_size: 1024,
                    total_size: 4096,
                    offset: 0,
                },
                FsInfo {
                    fs_type: "ext4".to_string(),
                    label: "ext4".to_string(),
                    uuid: "b".to_string(),
                    block_size: 1024,
                    total_size: 4096,
                    offset: 4096,
                },
            ],
        };

        let (index, fs) = select_deleted_filesystem(&report, Some(1)).unwrap();
        assert_eq!(index, 1);
        assert_eq!(fs.label, "ext4");
    }
}
