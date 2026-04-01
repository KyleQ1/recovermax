use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use recovermax_core::carve::Carver;
use recovermax_core::fs::ext4::Ext4Fs;
use recovermax_core::fs::ntfs::NtfsFs;
use recovermax_core::fs::{DirEntry, FileType};
use recovermax_core::io::ImageReader;
use recovermax_core::recover::Recoverer;
use recovermax_core::scan::{ScanReport, Scanner};

pub fn run_interactive(image_path: &Path) -> Result<()> {
    let reader = ImageReader::open(image_path)?;

    println!("RecoverMax v{}", env!("CARGO_PKG_VERSION"));
    println!("Image: {} ({})", image_path.display(), bytesize::ByteSize(reader.len()));
    println!();

    print!("Scanning...");
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan()?;

    if report.partitions.is_empty() && report.filesystems.is_empty() {
        println!(" no partitions or filesystems found.");
        println!("You can still use 'hexdump' and 'carve' commands.");
    } else {
        println!(" done.");
        if !report.partitions.is_empty() {
            println!("Partitions:");
            for (i, p) in report.partitions.iter().enumerate() {
                println!(
                    "  [{}] {} — {} ({}) type={}",
                    i, p.name,
                    bytesize::ByteSize(p.size),
                    bytesize::ByteSize(p.offset),
                    p.fs_type
                );
            }
        }
        if !report.filesystems.is_empty() {
            println!("Filesystems:");
            for (i, fs) in report.filesystems.iter().enumerate() {
                println!(
                    "  [{}] {} \"{}\" — {} (offset {})",
                    i, fs.fs_type, fs.label,
                    bytesize::ByteSize(fs.total_size),
                    bytesize::ByteSize(fs.offset),
                );
            }
        }
    }
    println!();

    // Try to mount the first known filesystem (ext4 or NTFS)
    let mut active_fs: Option<ActiveFs> = None;
    for fs_info in &report.filesystems {
        match fs_info.fs_type.as_str() {
            "ext4" => {
                match Ext4Fs::new(&reader, fs_info.offset) {
                    Ok(ext4) => {
                        active_fs = Some(ActiveFs {
                            kind: FsKind::Ext4(ext4),
                            cwd: PathBuf::from("/"),
                            cwd_inode: 2,
                            offset: fs_info.offset,
                            label: fs_info.label.clone(),
                        });
                        println!("Mounted ext4 \"{}\" at /", fs_info.label);
                        break;
                    }
                    Err(e) => println!("Warning: could not mount ext4: {}", e),
                }
            }
            "ntfs" => {
                match NtfsFs::new(&reader, fs_info.offset) {
                    Ok(ntfs) => {
                        active_fs = Some(ActiveFs {
                            kind: FsKind::Ntfs(ntfs),
                            cwd: PathBuf::from("/"),
                            cwd_inode: NtfsFs::ROOT_ENTRY,
                            offset: fs_info.offset,
                            label: fs_info.label.clone(),
                        });
                        println!("Mounted ntfs at /");
                        break;
                    }
                    Err(e) => println!("Warning: could not mount ntfs: {}", e),
                }
            }
            _ => {}
        }
    }

    println!("Type 'help' for available commands.\n");

    let history_path = dirs_path().join("history.txt");
    let mut rl = DefaultEditor::new()?;
    let _ = rl.load_history(&history_path);

    loop {
        let cwd_display = active_fs
            .as_ref()
            .map(|f| f.cwd.to_string_lossy().to_string())
            .unwrap_or_else(|| String::from("~"));

        let prompt = format!("recovermax:{}> ", cwd_display);

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);

                let parts: Vec<&str> = line.split_whitespace().collect();
                let cmd = parts[0];
                let args = &parts[1..];

                match cmd {
                    "help" | "?" => print_help(),
                    "quit" | "exit" => break,
                    "info" => cmd_info(&reader, &report),
                    "ls" => cmd_ls(&active_fs, args),
                    "cd" => cmd_cd(&mut active_fs, args),
                    "tree" => cmd_tree(&active_fs, args),
                    "cat" => cmd_cat(&active_fs, args),
                    "hexdump" | "xxd" => cmd_hexdump(&reader, args),
                    "recover" => cmd_recover(&reader, &report, &active_fs, args),
                    "deleted" => cmd_deleted(&active_fs, args),
                    "carve" => cmd_carve(&reader, args),
                    "scan" => cmd_scan_save(&report, args),
                    "fs" => cmd_switch_fs(&reader, &report, &mut active_fs, args),
                    _ => println!("Unknown command: '{}'. Type 'help' for commands.", cmd),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C (type 'exit' to quit, or press Ctrl+C again)");
                // Second Ctrl+C exits
                match rl.readline("Really quit? (Ctrl+C or 'y' to confirm): ") {
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
                    Ok(s) if s.trim().eq_ignore_ascii_case("y") => break,
                    _ => continue,
                }
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(e) => {
                println!("Error: {}", e);
                break;
            }
        }
    }

    let _ = rl.save_history(&history_path);
    println!("Goodbye.");
    Ok(())
}

enum FsKind<'a> {
    Ext4(Ext4Fs<'a>),
    Ntfs(NtfsFs<'a>),
}

struct ActiveFs<'a> {
    kind: FsKind<'a>,
    cwd: PathBuf,
    cwd_inode: u64,
    offset: u64,
    #[allow(dead_code)]
    label: String,
}

impl<'a> ActiveFs<'a> {
    fn list_directory(&self, inode: u64) -> Result<Vec<DirEntry>> {
        match &self.kind {
            FsKind::Ext4(ext4) => ext4.list_directory(inode),
            FsKind::Ntfs(ntfs) => ntfs.list_directory(inode),
        }
    }

    fn is_directory(&self, inode: u64) -> Result<bool> {
        match &self.kind {
            FsKind::Ext4(ext4) => ext4.read_inode(inode).map(|i| i.is_directory()),
            FsKind::Ntfs(ntfs) => ntfs.read_mft_entry(inode).map(|e| e.is_directory()),
        }
    }

    fn file_size(&self, inode: u64) -> Result<u64> {
        match &self.kind {
            FsKind::Ext4(ext4) => ext4.read_inode(inode).map(|i| i.size),
            FsKind::Ntfs(ntfs) => ntfs.read_mft_entry(inode).map(|e| e.file_size),
        }
    }

    fn read_file_data(&self, inode: u64) -> Result<Vec<u8>> {
        match &self.kind {
            FsKind::Ext4(ext4) => {
                let inode_data = ext4.read_inode(inode)?;
                ext4.read_inode_data(&inode_data)
            }
            FsKind::Ntfs(ntfs) => ntfs.read_file(inode),
        }
    }

    fn is_regular_file(&self, inode: u64) -> Result<bool> {
        match &self.kind {
            FsKind::Ext4(ext4) => ext4.read_inode(inode).map(|i| i.is_regular_file()),
            FsKind::Ntfs(ntfs) => ntfs.read_mft_entry(inode).map(|e| !e.is_directory()),
        }
    }

    fn root_inode(&self) -> u64 {
        match &self.kind {
            FsKind::Ext4(_) => 2,
            FsKind::Ntfs(_) => NtfsFs::ROOT_ENTRY,
        }
    }
}

fn dirs_path() -> PathBuf {
    let p = dirs_home().join(".recovermax");
    let _ = std::fs::create_dir_all(&p);
    p
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn print_help() {
    println!("Navigation:");
    println!("  ls [path]              List directory contents");
    println!("  cd <path>              Change directory");
    println!("  tree [path] [depth]    Show directory tree (default depth: 3)");
    println!("  cat <path>             Print file contents (text)");
    println!();
    println!("Recovery:");
    println!("  recover <path> -d <dest>   Recover file or directory to destination");
    println!("  deleted                    List deleted inodes (dtime set or links=0)");
    println!("  deleted recover <inode> -d <dest>  Recover a deleted file by inode number");
    println!("  carve -d <dest> [-t types] Raw carve files by signature");
    println!();
    println!("Inspection:");
    println!("  info                   Show image and filesystem info");
    println!("  hexdump <offset> [len] Hex dump (offset supports 0x prefix)");
    println!("  scan -o <file>         Save scan results to JSON");
    println!("  fs <index>             Switch active filesystem");
    println!();
    println!("General:");
    println!("  help                   Show this help");
    println!("  exit / quit            Exit recovermax");
}

fn cmd_info(reader: &ImageReader, report: &ScanReport) {
    println!("Image size: {}", bytesize::ByteSize(reader.len()));
    println!("{}", report.summary());
}

fn cmd_ls(active_fs: &Option<ActiveFs>, args: &[&str]) {
    let fs = match active_fs {
        Some(f) => f,
        None => {
            println!("No filesystem mounted. Use 'fs <index>' to select one.");
            return;
        }
    };

    let (target_inode, _target_path) = if args.is_empty() {
        (fs.cwd_inode, fs.cwd.clone())
    } else {
        match resolve_path(fs, args[0]) {
            Ok((inode, path)) => (inode, path),
            Err(e) => {
                println!("Error: {}", e);
                return;
            }
        }
    };

    match fs.list_directory(target_inode) {
        Ok(entries) => {
            let mut sorted: Vec<&DirEntry> = entries.iter().collect();
            sorted.sort_by(|a, b| a.name.cmp(&b.name));

            for entry in &sorted {
                let type_char = match entry.file_type {
                    FileType::Directory => 'd',
                    FileType::Symlink => 'l',
                    FileType::RegularFile => '-',
                    FileType::Other => '?',
                };

                let suffix = match entry.file_type {
                    FileType::Directory => "/",
                    FileType::Symlink => "@",
                    _ => "",
                };

                let del_marker = if entry.deleted { " [DELETED]" } else { "" };

                let size_str = if entry.inode > 0 && !entry.deleted {
                    match fs.file_size(entry.inode) {
                        Ok(size) => format!("{:>10}", bytesize::ByteSize(size)),
                        Err(_) => format!("{:>10}", "?"),
                    }
                } else {
                    format!("{:>10}", "-")
                };

                println!(
                    "  {} {} {:>8} {}{}{}",
                    type_char, size_str, entry.inode, entry.name, suffix, del_marker
                );
            }
            println!("  ({} entries)", sorted.len());
        }
        Err(e) => println!("Error reading directory: {}", e),
    }
}

fn cmd_cd(active_fs: &mut Option<ActiveFs>, args: &[&str]) {
    let fs = match active_fs {
        Some(f) => f,
        None => {
            println!("No filesystem mounted.");
            return;
        }
    };

    if args.is_empty() {
        fs.cwd = PathBuf::from("/");
        fs.cwd_inode = fs.root_inode();
        return;
    }

    let target = args[0];
    match resolve_path(fs, target) {
        Ok((inode, path)) => {
            match fs.is_directory(inode) {
                Ok(true) => {
                    fs.cwd_inode = inode;
                    fs.cwd = path;
                }
                Ok(false) => println!("Not a directory: {}", target),
                Err(e) => println!("Error reading inode: {}", e),
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}

fn cmd_tree(active_fs: &Option<ActiveFs>, args: &[&str]) {
    let fs = match active_fs {
        Some(f) => f,
        None => {
            println!("No filesystem mounted.");
            return;
        }
    };

    let (inode, _path) = if args.is_empty() {
        (fs.cwd_inode, fs.cwd.clone())
    } else {
        match resolve_path(fs, args[0]) {
            Ok(r) => r,
            Err(e) => {
                println!("Error: {}", e);
                return;
            }
        }
    };

    let max_depth: usize = args.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    print_tree(fs, inode, "", max_depth, 0);
}

fn print_tree(fs: &ActiveFs, inode: u64, prefix: &str, max_depth: usize, depth: usize) {
    if depth > max_depth {
        return;
    }

    let entries = match fs.list_directory(inode) {
        Ok(e) => e,
        Err(_) => return,
    };

    let filtered: Vec<&DirEntry> = entries
        .iter()
        .filter(|e| e.name != "." && e.name != "..")
        .collect();

    for (i, entry) in filtered.iter().enumerate() {
        let is_last = i == filtered.len() - 1;
        let connector = if is_last { "└── " } else { "├── " };
        let suffix = if matches!(entry.file_type, FileType::Directory) { "/" } else { "" };

        println!("{}{}{}{}", prefix, connector, entry.name, suffix);

        if matches!(entry.file_type, FileType::Directory) && entry.inode > 0 && !entry.deleted {
            let child_prefix = if is_last {
                format!("{}    ", prefix)
            } else {
                format!("{}│   ", prefix)
            };
            print_tree(fs, entry.inode, &child_prefix, max_depth, depth + 1);
        }
    }
}

fn cmd_cat(active_fs: &Option<ActiveFs>, args: &[&str]) {
    let fs = match active_fs {
        Some(f) => f,
        None => {
            println!("No filesystem mounted.");
            return;
        }
    };

    if args.is_empty() {
        println!("Usage: cat <path>");
        return;
    }

    match resolve_path(fs, args[0]) {
        Ok((inode, _)) => {
            match fs.is_regular_file(inode) {
                Ok(false) => {
                    println!("Not a regular file.");
                    return;
                }
                Err(e) => {
                    println!("Error: {}", e);
                    return;
                }
                _ => {}
            }
            match fs.file_size(inode) {
                Ok(size) if size > 1024 * 1024 => {
                    println!("File is {} — too large for cat. Use 'recover' instead.", bytesize::ByteSize(size));
                    return;
                }
                _ => {}
            }
            match fs.read_file_data(inode) {
                Ok(data) => {
                    match String::from_utf8(data) {
                        Ok(text) => print!("{}", text),
                        Err(e) => {
                            println!("(binary file, {} bytes — showing as hex)", e.as_bytes().len());
                            let data = e.into_bytes();
                            super::cli::print_hexdump_pub(&data, 0);
                        }
                    }
                }
                Err(e) => println!("Error reading file: {}", e),
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}

fn cmd_hexdump(reader: &ImageReader, args: &[&str]) {
    if args.is_empty() {
        println!("Usage: hexdump <offset> [length]");
        println!("  offset supports 0x prefix for hex");
        return;
    }

    let offset_str = args[0];
    let off = if offset_str.starts_with("0x") || offset_str.starts_with("0X") {
        match u64::from_str_radix(offset_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
            Ok(v) => v,
            Err(e) => {
                println!("Bad offset: {}", e);
                return;
            }
        }
    } else {
        match offset_str.parse() {
            Ok(v) => v,
            Err(e) => {
                println!("Bad offset: {}", e);
                return;
            }
        }
    };

    let len: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(256);

    match reader.read_at(off, len) {
        Ok(data) => super::cli::print_hexdump_pub(data, off),
        Err(e) => println!("Error: {}", e),
    }
}

fn cmd_recover(reader: &ImageReader, report: &ScanReport, active_fs: &Option<ActiveFs>, args: &[&str]) {
    // Parse: recover <path> -d <dest>
    let mut path: Option<&str> = None;
    let mut dest: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-d" | "--dest" => {
                if i + 1 < args.len() {
                    dest = Some(PathBuf::from(args[i + 1]));
                    i += 2;
                } else {
                    println!("Missing destination after -d");
                    return;
                }
            }
            other => {
                path = Some(other);
                i += 1;
            }
        }
    }

    let dest = match dest {
        Some(d) => d,
        None => {
            println!("Usage: recover [path] -d <destination>");
            return;
        }
    };

    let path_filter = path.map(|p| {
        if let Some(fs) = active_fs {
            if !p.starts_with('/') {
                // Relative to cwd
                let full = fs.cwd.join(p);
                return full.to_string_lossy().to_string();
            }
        }
        p.to_string()
    });

    let recoverer = Recoverer::new(reader, &dest);
    match recoverer.recover(report, path_filter.as_deref()) {
        Ok(()) => println!("Recovery complete. Files saved to {}", dest.display()),
        Err(e) => println!("Recovery error: {}", e),
    }
}

fn cmd_deleted(active_fs: &Option<ActiveFs>, args: &[&str]) {
    let fs = match active_fs {
        Some(f) => f,
        None => {
            println!("No filesystem mounted. Use 'fs <index>' to select one.");
            return;
        }
    };

    let ext4 = match &fs.kind {
        FsKind::Ext4(ext4) => ext4,
        FsKind::Ntfs(_) => {
            println!("Deleted inode scanning is not supported for NTFS.");
            println!("NTFS marks deleted entries in the MFT — use 'ls' to browse.");
            return;
        }
    };

    if args.is_empty() {
        // List all deleted inodes
        match ext4.scan_deleted_inodes() {
            Ok(deleted) => {
                if deleted.is_empty() {
                    println!("No deleted inodes found.");
                    return;
                }

                println!("Found {} deleted inodes:\n", deleted.len());
                println!("{:>8}  {:>12}  {:>10}  {}", "INODE", "SIZE", "DTIME", "TYPE");
                println!("{}", "-".repeat(50));

                for d in &deleted {
                    let type_str = match d.file_type {
                        FileType::RegularFile => "file",
                        FileType::Directory => "dir",
                        FileType::Symlink => "symlink",
                        FileType::Other => "other",
                    };
                    println!("{:>8}  {:>12}  {:>10}  {}",
                        d.inode_num,
                        bytesize::ByteSize(d.size),
                        d.dtime,
                        type_str,
                    );
                }

                println!("\nTo recover: deleted recover <inode> -d <dest>");
            }
            Err(e) => println!("Error scanning deleted inodes: {}", e),
        }
        return;
    }

    // deleted recover <inode> -d <dest>
    if args[0] != "recover" {
        println!("Usage: deleted                           List deleted inodes");
        println!("       deleted recover <inode> -d <dest> Recover a deleted file");
        return;
    }

    if args.len() < 2 {
        println!("Usage: deleted recover <inode> -d <dest>");
        return;
    }

    let inode_num: u64 = match args[1].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("Invalid inode number: {}", args[1]);
            return;
        }
    };

    let mut dest: Option<std::path::PathBuf> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i] {
            "-d" | "--dest" => {
                if i + 1 < args.len() {
                    dest = Some(std::path::PathBuf::from(args[i + 1]));
                    i += 2;
                } else {
                    println!("Missing destination after -d");
                    return;
                }
            }
            _ => { i += 1; }
        }
    }

    let dest = match dest {
        Some(d) => d,
        None => {
            println!("Usage: deleted recover <inode> -d <dest>");
            return;
        }
    };

    match ext4.read_inode(inode_num) {
        Ok(inode) => {
            match ext4.read_inode_data(&inode) {
                Ok(data) => {
                    if let Err(e) = std::fs::create_dir_all(&dest) {
                        println!("Error creating directory: {}", e);
                        return;
                    }
                    let filename = format!("inode-{}", inode_num);
                    let dest_file = dest.join(&filename);
                    match std::fs::write(&dest_file, &data) {
                        Ok(()) => println!("Recovered inode {} ({}) to {}",
                            inode_num,
                            bytesize::ByteSize(inode.size),
                            dest_file.display(),
                        ),
                        Err(e) => println!("Error writing file: {}", e),
                    }
                }
                Err(e) => println!("Error reading inode data: {}", e),
            }
        }
        Err(e) => println!("Error reading inode {}: {}", inode_num, e),
    }
}

fn cmd_carve(reader: &ImageReader, args: &[&str]) {
    let mut dest: Option<PathBuf> = None;
    let mut types: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-d" | "--dest" => {
                if i + 1 < args.len() {
                    dest = Some(PathBuf::from(args[i + 1]));
                    i += 2;
                } else {
                    println!("Missing destination after -d");
                    return;
                }
            }
            "-t" | "--types" => {
                if i + 1 < args.len() {
                    types = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!("Missing types after -t");
                    return;
                }
            }
            _ => { i += 1; }
        }
    }

    let dest = match dest {
        Some(d) => d,
        None => {
            println!("Usage: carve -d <destination> [-t jpg,png,pdf]");
            return;
        }
    };

    let type_filter: Option<Vec<&str>> = types.as_deref().map(|t| t.split(',').collect());
    let carver = Carver::new(reader, &dest);
    match carver.carve(type_filter.as_deref()) {
        Ok(()) => {}
        Err(e) => println!("Carve error: {}", e),
    }
}

fn cmd_scan_save(report: &ScanReport, args: &[&str]) {
    let mut output: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output = Some(args[i + 1]);
                    i += 2;
                } else {
                    println!("Missing filename after -o");
                    return;
                }
            }
            _ => { i += 1; }
        }
    }

    match output {
        Some(path) => {
            match serde_json::to_string_pretty(report) {
                Ok(json) => {
                    match std::fs::write(path, &json) {
                        Ok(()) => println!("Scan saved to {}", path),
                        Err(e) => println!("Error writing {}: {}", path, e),
                    }
                }
                Err(e) => println!("Error serializing: {}", e),
            }
        }
        None => {
            println!("{}", report.summary());
            println!("Use 'scan -o <file>' to save to JSON.");
        }
    }
}

fn cmd_switch_fs<'a>(
    reader: &'a ImageReader,
    report: &ScanReport,
    active_fs: &mut Option<ActiveFs<'a>>,
    args: &[&str],
) {
    if args.is_empty() {
        println!("Filesystems:");
        for (i, fs) in report.filesystems.iter().enumerate() {
            let marker = active_fs
                .as_ref()
                .map(|a| if a.offset == fs.offset { " *" } else { "" })
                .unwrap_or("");
            println!(
                "  [{}] {} \"{}\" ({}){}", i, fs.fs_type, fs.label,
                bytesize::ByteSize(fs.total_size), marker
            );
        }
        println!("\nUse 'fs <index>' to switch.");
        return;
    }

    let idx: usize = match args[0].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("Invalid index: {}", args[0]);
            return;
        }
    };

    if idx >= report.filesystems.len() {
        println!("Index {} out of range (0-{})", idx, report.filesystems.len() - 1);
        return;
    }

    let fs_info = &report.filesystems[idx];
    match fs_info.fs_type.as_str() {
        "ext4" => {
            match Ext4Fs::new(reader, fs_info.offset) {
                Ok(ext4) => {
                    *active_fs = Some(ActiveFs {
                        kind: FsKind::Ext4(ext4),
                        cwd: PathBuf::from("/"),
                        cwd_inode: 2,
                        offset: fs_info.offset,
                        label: fs_info.label.clone(),
                    });
                    println!("Switched to ext4 \"{}\"", fs_info.label);
                }
                Err(e) => println!("Error mounting filesystem: {}", e),
            }
        }
        "ntfs" => {
            match NtfsFs::new(reader, fs_info.offset) {
                Ok(ntfs) => {
                    *active_fs = Some(ActiveFs {
                        kind: FsKind::Ntfs(ntfs),
                        cwd: PathBuf::from("/"),
                        cwd_inode: NtfsFs::ROOT_ENTRY,
                        offset: fs_info.offset,
                        label: fs_info.label.clone(),
                    });
                    println!("Switched to ntfs");
                }
                Err(e) => println!("Error mounting filesystem: {}", e),
            }
        }
        other => println!("Unsupported filesystem type: {}", other),
    }
}

/// Resolve a path string (absolute or relative to cwd) to an inode number.
fn resolve_path(fs: &ActiveFs, path: &str) -> Result<(u64, PathBuf)> {
    let root_inode = fs.root_inode();
    let (mut current_inode, mut current_path) = if path.starts_with('/') {
        (root_inode, PathBuf::from("/"))
    } else {
        (fs.cwd_inode, fs.cwd.clone())
    };

    let components: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty())
        .collect();

    for component in &components {
        if *component == "." {
            continue;
        }

        let entries = fs.list_directory(current_inode)
            .with_context(|| format!("Failed to read directory at {}", current_path.display()))?;

        if *component == ".." {
            if let Some(parent) = entries.iter().find(|e| e.name == "..") {
                current_inode = parent.inode;
                current_path.pop();
                if current_path.as_os_str().is_empty() {
                    current_path = PathBuf::from("/");
                }
            }
            continue;
        }

        match entries.iter().find(|e| e.name == *component) {
            Some(entry) => {
                current_inode = entry.inode;
                current_path.push(component);
            }
            None => {
                anyhow::bail!("'{}' not found in {}", component, current_path.display());
            }
        }
    }

    Ok((current_inode, current_path))
}
