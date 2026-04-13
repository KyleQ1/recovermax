# RecoverMax — Design Document

**Last updated:** 2026-04-08
**Codebase:** 10,477 lines of Rust across 12 source files, 272 tests, 16 test suites
**Status:** ext4 pipeline end-to-end, NTFS parsing only, forensic CLI wired, journal parsing implemented

---

## Table of Contents

1. [Vision & Architecture](#vision--architecture)
2. [Data Flow](#data-flow)
3. [Module Reference](#module-reference)
4. [Session System](#session-system)
5. [Filesystem Implementations](#filesystem-implementations)
6. [Recovery Pipeline](#recovery-pipeline)
7. [Search System](#search-system)
8. [File Carving](#file-carving)
9. [Deleted File Recovery](#deleted-file-recovery)
10. [Forensic System](#forensic-system)
11. [CLI & TUI](#cli--tui)
12. [Testing Strategy](#testing-strategy)
13. [Website & Marketing](#website--marketing)
14. [CI/CD & Releases](#cicd--releases)
15. [Roadmap: What's Missing vs R-Studio](#roadmap-whats-missing-vs-r-studio)
16. [Implementation Guides](#implementation-guides)

---

## 1. Vision & Architecture

RecoverMax replicates R-Studio's exact workflow in a free, open-source, CLI-first tool:

1. **Open image** → point at a disk image or block device (local or remote)
2. **Scan partitions** → detect MBR/GPT partition tables, find filesystems
3. **Pick a partition** → determine/override filesystem type
4. **Build tree** → live files as folders, deleted files as inodes with best-guess names from residual directory entries and journal transactions
5. **Search** → find files by name pattern (substring, exact, or glob with `*`/`?`)
6. **Recover** → stream selected files/directories to an output directory
7. **Session persistence** → save the entire scan result as a `.scn` file, reopen later without re-scanning

### Workspace Layout

```
Cargo.toml                          # workspace root
crates/
├── recovermax-core/                # AGPL-3.0 library — all recovery logic
│   ├── src/
│   │   ├── lib.rs                  # pub mod declarations (8 modules)
│   │   ├── io/mod.rs               # ImageReader — mmap zero-copy I/O (86 lines)
│   │   ├── fs/mod.rs               # Shared types: DirEntry, FileType, EntrySource (53 lines)
│   │   ├── fs/ext4.rs              # ext4 full implementation (1133 lines)
│   │   ├── fs/ntfs.rs              # NTFS parsing — NOT wired to sessions (549 lines)
│   │   ├── scan/mod.rs             # MBR/GPT partition + filesystem detection (339 lines)
│   │   ├── carve/mod.rs            # Raw file carving by signature (398 lines)
│   │   ├── recover/mod.rs          # Streaming tree-walk recovery (456 lines)
│   │   ├── session.rs              # Session artifacts, lazy cache, tree ops (1207 lines)
│   │   ├── search.rs               # Substring/exact/glob search (481 lines)
│   │   └── forensic/               # Audit log, SHA-256 hashing, HTML reports
│   │       ├── mod.rs              # Re-exports
│   │       ├── audit.rs            # AuditLog, AuditAction, CaseInfo
│   │       ├── hash.rs             # ImageHasher (streaming 8 MiB SHA-256)
│   │       └── report.rs           # ForensicReport (HTML, NIST SP 800-86)
│   └── tests/                      # 16 test suites, 226 tests
│       ├── ext4_tests.rs           # Basic ext4 parsing
│       ├── ext4_complex_tests.rs   # End-to-end ext4 with synthetic images
│       ├── ntfs_tests.rs           # NTFS boot sector, MFT, file read
│       ├── scan_tests.rs           # MBR/GPT detection
│       ├── carve_tests.rs          # Signature detection
│       ├── carve_smart_tests.rs    # Smart size detection
│       ├── carve_complex_tests.rs  # Multi-file carving
│       ├── deleted_tests.rs        # Deleted inode scanning
│       ├── streaming_tests.rs      # Streaming vs buffered parity + bounded read
│       ├── io_tests.rs             # ImageReader
│       ├── failing_tests.rs        # Graceful degradation on corrupt data
│       ├── session_cache_tests.rs  # Cache warming/eviction
│       ├── session_degraded_tests.rs # Degraded session handling
│       ├── session_migration_tests.rs # Artifact format migration
│       ├── session_path_tests.rs   # Path resolution
│       └── session_runtime_tests.rs # Runtime cache rebuild
└── recovermax-cli/                 # AGPL-3.0 binary
    ├── src/
    │   ├── main.rs                 # Entry point, mode dispatch (49 lines)
    │   ├── cli.rs                  # All subcommands + deleted recovery + tests (4777 lines)
    │   └── tui.rs                  # Interactive shell REPL (949 lines)
    └── Cargo.toml

website/                            # Next.js static site for recovermax.dev
scripts/                            # Build fixtures, benchmark, diff-validate
testing/                            # Manifests, datasets, validation docs
```

### Dependency Philosophy

Every crate must justify its existence. Current dependencies:

**recovermax-core:** `memmap2` (zero-copy I/O), `nom` (binary parsing — currently unused, legacy), `serde`/`serde_json` (session serialization), `thiserror`/`anyhow` (errors), `tracing` (structured logging), `rayon` (parallelism — available but not heavily used yet), `sha2` (forensic hashing), `chrono` (audit timestamps)

**recovermax-cli:** `clap` (CLI parsing), `indicatif` (progress bars), `bytesize` (human-readable sizes), `recovermax-core`

---

## 2. Data Flow

### One-Shot Recovery

```
image file
  → ImageReader::open (mmap)
  → Scanner::scan (MBR/GPT → partitions → detect ext4/NTFS at each offset)
  → ScanReport { partitions, filesystems }
  → Ext4Fs::new(reader, offset)
  → list_directory(root=2) → recursive tree walk
  → read_inode_data / stream_inode_data → write to dest
```

### Session-Based Recovery (R-Studio model)

```
image file
  → scan → ScanReport
  → RecoverySessionArtifact::build_ext4_sessions
     → for each ext4 filesystem:
        → Ext4Fs::new → list_directory(2) → build_ext4_subtree (recursive)
        → scan_deleted_inodes → journal_filename_hints → append_ext4_deleted_orphans
        → FilesystemSessionArtifact { nodes, warnings }
  → artifact.save("scan.scn")        ← persist to disk

  ... later ...

  → RecoverySession::from_artifact(artifact, reader)
  → session.resolve_node(fs, "/path/to/file")
  → session.list_children(fs, "/dir")
  → recover_session → stream files to disk
```

---

## 3. Module Reference

### `io/mod.rs` — ImageReader (86 lines)

Zero-copy disk image access via `memmap2::Mmap`.

```rust
pub struct ImageReader { mmap: Mmap, size: u64 }

impl ImageReader {
    pub fn open(path: &Path) -> Result<Self>        // mmap read-only
    pub fn len(&self) -> u64
    pub fn is_empty(&self) -> bool
    pub fn read_at(&self, offset: u64, len: usize) -> Result<&[u8]>  // zero-copy slice
    pub fn read_at_with_context(&self, offset: u64, len: usize, ctx: &str) -> Result<&[u8]>
}
```

No allocations on read. The mmap gives the kernel full control over paging — only the accessed regions are loaded into physical RAM. Safe for multi-TB images.

### `fs/mod.rs` — Shared Types (53 lines)

```rust
pub struct DirEntry {
    pub inode: u64,
    pub name: String,
    pub file_type: FileType,
    pub size: u64,
    pub deleted: bool,
    pub source: EntrySource,
    pub parent_inode: Option<u64>,
}

pub enum FileType { RegularFile, Directory, Symlink, Other }

pub enum EntrySource {
    Filesystem,       // live directory entry
    DeletedSlack,     // found in rec_len slack of a live entry
    SyntheticOrphan,  // deleted inode with no directory reference
}
```

### `fs/ext4.rs` — ext4 Implementation (1133 lines)

The largest and most critical module. Handles everything from superblock parsing to journal scanning.

**Key types:**
```rust
pub struct Ext4Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,      // actual size = 1024 << log_block_size
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16,               // 0xEF53
    pub inode_size: u16,          // typically 256
    pub volume_name: String,
    pub uuid: [u8; 16],
    pub feature_incompat: u32,    // bit 0x40 = extents, 0x80 = 64-bit
    pub journal_inum: u32,        // typically 8
}

pub struct Inode {
    pub number: u64,
    pub mode: u16,
    pub size: u64,
    pub links_count: u16,
    pub flags: u32,               // 0x80000 = uses extents
    pub dtime: u32,
    pub ctime: u32, pub mtime: u32, pub atime: u32,
    pub block_data: [u8; 60],     // extent tree or block map
}

pub struct DeletedInode {
    pub inode_num: u64, pub size: u64, pub file_type: FileType,
    pub dtime: u32, pub mode: u16,
    pub ctime: u32, pub mtime: u32, pub atime: u32,
}

pub struct Ext4Fs<'a> {
    pub reader: &'a ImageReader,
    pub partition_offset: u64,
    pub superblock: Ext4Superblock,
}
```

**Public API:**
```rust
impl Ext4Fs {
    pub fn new(reader, offset) -> Result<Self>
    pub fn list_directory(inode_num) -> Result<Vec<DirEntry>>
    pub fn read_inode(inode_num) -> Result<Inode>
    pub fn read_inode_data(inode) -> Result<Vec<u8>>          // full file into RAM
    pub fn read_inode_data_bounded(inode, max_bytes) -> Result<Vec<u8>>  // capped read
    pub fn stream_inode_data(inode, writer) -> Result<()>     // streaming to disk
    pub fn scan_deleted_inodes() -> Result<Vec<DeletedInode>> // all block groups
    pub fn journal_filename_hints() -> Result<HashMap<u64, String>>  // JBD2 journal scan
}
```

**Algorithms:**
- **Extent trees**: Recursive tree walk. Depth-0 = leaf extents (block range). Depth > 0 = index nodes pointing to child blocks. Magic 0xF30A.
- **Block maps**: Direct blocks 0–11, single-indirect (12), double-indirect (13), triple-indirect (14). Sparse holes (block=0) filled with zeros.
- **Directory parsing**: Walk entries by `rec_len` chain. Validate plausibility (rec_len % 4 == 0, valid file_type, printable name). Scan deleted slack in rec_len gaps.
- **Deleted scanning**: Iterate all block groups → inode table blocks → every inode. Deleted if `dtime != 0 || links_count == 0`, with `size > 0` and `mode != 0`.
- **Journal parsing (JBD2)**: Read journal inode → parse JBD2 superblock (magic 0xC03B3998) → scan descriptor blocks → for each data block, attempt heuristic directory entry parsing → extract inode→filename mappings.
- **Bounded read**: Caps both extent and block-map paths at `max_bytes`. Used by content-type sniffing to avoid loading entire files.

### `fs/ntfs.rs` — NTFS Parsing (549 lines)

Standalone NTFS implementation. **NOT wired into sessions, search, or recovery.**

```rust
pub struct NtfsBootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_cluster: u64,
    pub clusters_per_mft_record: i8,
}

pub struct NtfsFs<'a> { reader, partition_offset, boot_sector }
pub struct MftEntry { pub entry_number: u64, pub filename: String, pub file_type: FileType, pub is_deleted: bool, pub parent_entry: u64, pub data_size: u64, pub data_runs: Vec<DataRun> }
pub struct DataRun { pub offset: i64, pub length: u64 }

impl NtfsFs {
    pub fn new(reader, offset) -> Result<Self>
    pub fn list_directory(parent_entry: u64) -> Result<Vec<MftEntry>>  // linear MFT scan
    pub fn read_file(entry: &MftEntry) -> Result<Vec<u8>>
    pub fn detect(reader, offset) -> Option<FsInfo>
}
```

**What works:** Boot sector parsing, MFT entry parsing with fixup arrays, UTF-16LE filename decoding, resident and non-resident $DATA attribute handling, data run decoding.

**What's missing:** No session tree construction, no search integration, no recovery pipeline integration, no streaming, no deleted MFT scanning, directory listing is via linear MFT scan (no B-tree index parsing).

### `scan/mod.rs` — Partition Detection (339 lines)

```rust
pub struct Scanner<'a> { reader: &'a ImageReader }
pub struct ScanReport { pub image_size: u64, pub partitions: Vec<Partition>, pub filesystems: Vec<FsInfo> }
pub struct Partition { pub name: String, pub offset: u64, pub size: u64, pub fs_type: String }
pub struct FsInfo { pub fs_type: String, pub label: String, pub uuid: String, pub block_size: u32, pub total_size: u64, pub offset: u64 }
pub struct ScanOptions { pub deep_scan: bool }

impl Scanner {
    pub fn scan(report, options) -> Result<ScanReport>   // detect partitions + filesystems
    pub fn scan_with_config(report, config) -> Result<ScanReport>
}
```

Detects MBR (offset 0, magic 0x55AA, 4 partition entries) and GPT (magic "EFI PART" at LBA 1). For each partition, probes ext4 (magic 0xEF53 at offset 1024+0x38) and NTFS (magic "NTFS" at offset 3). Deep scan probes at 1 MiB intervals within partitions.

### `carve/mod.rs` — File Carving (398 lines)

```rust
pub struct CarvedFile { pub file_type: String, pub offset: u64, pub size: u64, pub data: Vec<u8> }

pub fn carve(reader, image_size, requested_types) -> Vec<CarvedFile>
pub fn carve_to_dir(reader, image_size, dest, requested_types) -> Result<usize>
```

**Supported signatures (8):** JPEG (0xFFD8FF, seeks to 0xFFD9 end marker), PNG (89504E47, seeks to IEND), PDF (%PDF-, seeks to %%EOF), ZIP (PK0304, reads local file headers), GIF (GIF87a/89a, seeks to terminator 0x3B), ELF (7F454C46, reads ELF header for size), gzip (1F8B, decompresses to find size), SQLite (53514C69746520666F726D6174, reads page count × page size).

Scans at 512-byte sector boundaries. Smart sizing reads format-specific structures to determine actual file size rather than carving a fixed max.

### `recover/mod.rs` — Recovery Pipeline (456 lines)

```rust
pub struct Recoverer<'a> { reader: &'a ImageReader }
const STREAMING_THRESHOLD: u64 = 1_048_576; // 1 MiB

impl Recoverer {
    pub fn recover(report, path_filter) -> Result<()>               // raw scan-based
    pub fn recover_artifact(artifact, path_filter) -> Result<()>    // artifact-based
    pub fn recover_session(session, path_filter) -> Result<()>      // session-backed
}
```

Three dispatch paths converging on ext4 only. Files >= 1 MiB use `stream_inode_data` (block-at-a-time to an `impl Write`). Smaller files use `read_inode_data` + `fs::write`. Symlinks are created with `std::os::unix::fs::symlink`. Directories are created recursively with `create_dir_all`.

**Current limitation:** Recovery returns `Result<()>`, not a list of recovered files. The forensic report's recovered-files table is empty because of this. This is a follow-up to add.

### `search.rs` — Search System (481 lines)

```rust
pub struct SearchOptions { pub ignore_case: bool, pub exact: bool, pub filesystem_index: Option<usize>, pub max_depth: usize }
pub struct SearchMatch { pub filesystem_index: usize, pub filesystem_label: String, pub filesystem_offset: u64, pub inode: u64, pub path: String, pub file_type: FileType, pub deleted: bool, pub source: EntrySource, pub parent_inode: Option<u64> }
pub struct Searcher<'a> { reader: &'a ImageReader }

impl Searcher {
    pub fn search(report, query, options) -> Result<Vec<SearchMatch>>
    pub fn search_selected(report, query, options, fs_indexes) -> Result<Vec<SearchMatch>>
    pub fn search_artifact(artifact, query, options) -> Result<Vec<SearchMatch>>
    pub fn search_session(session, query, options) -> Vec<SearchMatch>
}
```

**Matching modes:**
- **Substring** (default): `basename.contains(query) || path.contains(query)`
- **Exact**: `basename == query || path == query`
- **Glob** (auto-detected): If query contains `*` or `?`, uses two-pointer backtracking glob matcher. Supports `*.txt`, `file?.log`, `/home/*/docs/*.pdf`.

Queries starting with `/` match against absolute path only. Case-insensitive mode lowercases everything before matching. **ext4 only** — NTFS is skipped with an explicit guard.

---

## 4. Session System

The session system is the core of RecoverMax's R-Studio-like workflow. It's the largest module (1207 lines).

### Data Model

```rust
pub struct RecoverySessionArtifact {
    pub version: u32,                     // currently 2
    pub source: ScanImageSource,          // { path, image_size }
    pub report: ScanReport,
    pub filesystems: Vec<FilesystemSessionArtifact>,
}

pub struct FilesystemSessionArtifact {
    pub filesystem_index: usize,
    pub fs_info: FsInfo,
    pub root_node_id: Option<u64>,
    pub warnings: Vec<String>,
    pub nodes: Vec<SessionNode>,          // the full tree, flat list
}

pub struct SessionNode {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub filesystem_index: usize,
    pub inode: Option<u64>,               // None for residual deleted entries
    pub basename: String,
    pub path: String,
    pub file_type: FileType,
    pub deleted: bool,
    pub size: Option<u64>,
    pub source: EntrySource,
    pub parent_inode: Option<u64>,
    pub timestamps: Option<SessionNodeTimestamps>,
}

pub struct SessionNodeTimestamps {
    pub created_unix: Option<i64>,        // ctime
    pub modified_unix: Option<i64>,       // mtime
    pub accessed_unix: Option<i64>,       // atime
    pub deleted_unix: Option<i64>,        // dtime
}
```

### Session Operations

```rust
pub struct RecoverySession { artifact, reader: Option<ImageReader>, cache: SessionCache }

impl RecoverySession {
    pub fn from_artifact(artifact, memory_budget) -> Self
    pub fn from_artifact_with_reader(artifact, reader, budget) -> Self
    pub fn resolve_node(fs_index, path) -> Result<SessionNode>
    pub fn list_children(fs_index, path) -> Result<Vec<SessionNode>>
    pub fn walk_tree(fs_index, path, depth) -> Result<Vec<SessionTreeEntry>>
    pub fn search(query, options) -> Vec<SearchMatch>
    pub fn cache_summary() -> CacheSummary
    pub fn unload_caches()
}
```

### Lazy Caching

The session builds three indexes lazily (on first access):
- `node_by_id: HashMap<u64, NodeLocation>` — O(1) node lookup by ID
- `path_to_node: HashMap<(usize, String), NodeLocation>` — O(1) path resolution
- `children_by_parent: HashMap<u64, Vec<NodeLocation>>` — O(1) child listing

Memory budget defaults to 512 MB, overridable via `--memory-budget` CLI flag or `RECOVERMAX_MEMORY_BUDGET` env var. The `unload_caches()` method drops all indexes.

### Session Tree Construction

For each ext4 filesystem in the scan report:
1. Create `Ext4Fs` from reader + offset
2. `list_directory(2)` for root entries
3. `build_ext4_subtree` — recursive DFS building `SessionNode` entries with proper parent_id linkage
4. `journal_filename_hints()` — scan JBD2 journal for historical directory entries
5. `append_ext4_deleted_orphans` — scan for deleted inodes, assign journal-recovered names or synthetic `OrphanFile-N` names, build `$OrphanFiles` virtual directory

Traversal warnings are collected but don't fail the scan — partial trees are preserved.

### Artifact Persistence

`.scn` files are pretty-printed JSON. Version field enables format migration (v1 → v2 supported). Image path validation warns if the image has moved but doesn't fail the session load.

---

## 5. Filesystem Implementations

### ext4 — Complete

| Feature | Status |
|---|---|
| Superblock parsing | Done (including journal_inum, 64-bit blocks) |
| Block group descriptors | Done (32-bit and 64-bit) |
| Inode reading | Done (all fields including block_data) |
| Extent trees | Done (multi-level recursive) |
| Block maps | Done (direct/indirect/double/triple) |
| Directory entry parsing | Done (with deleted slack scanning) |
| Sparse files | Done (zero-filled holes) |
| Symlinks | Done (inline and data-block targets) |
| Deleted inode scanning | Done (all block groups) |
| Journal parsing (JBD2) | Done (directory blocks, filename recovery) |
| Streaming I/O | Done (1 MiB threshold) |
| Bounded read | Done (for sniffing) |

### NTFS — Parsing Only

| Feature | Status |
|---|---|
| Boot sector parsing | Done |
| MFT entry parsing + fixup | Done |
| UTF-16LE filename decoding | Done |
| Resident $DATA | Done |
| Non-resident $DATA (data runs) | Done |
| File reading | Done |
| Directory listing (linear MFT) | Done |
| **Session tree construction** | **NOT DONE** |
| **Search integration** | **NOT DONE** |
| **Recovery pipeline** | **NOT DONE** |
| **Deleted MFT scanning** | **NOT DONE** |
| **B-tree index parsing** | **NOT DONE** |

### Not Started

FAT12/16/32, exFAT, XFS, APFS, HFS/HFS+, ReiserFS, btrfs, UFS

---

## 6. Recovery Pipeline

### Three Entry Points

1. **`recover(report, filter)`** — Raw scan-based. Walks ext4 directories from root inode 2. No session needed.
2. **`recover_artifact(artifact, filter)`** — If artifact has a session tree, delegates to `recover_session`. Otherwise falls back to `recover`.
3. **`recover_session(session, filter)`** — The primary path. Resolves a `SessionNode`, then recovers the subtree.

### Streaming Decision

```
if inode.size >= 1 MiB:
    stream_inode_data(inode, File::create(path))   # block-at-a-time, never in RAM
else:
    data = read_inode_data(inode)
    fs::write(path, data)                          # buffer in RAM, single write
```

### CLI Recovery (cli.rs)

The CLI layer adds significant logic on top of the core `Recoverer`:
- `resolve_recovery_target` — resolves path strings, handles filesystem index disambiguation, deleted residual entries
- `recover_with_fallback` — tries session path, falls back to live ext4 if no tree
- Deleted orphan resolution with tiebreaker scoring (see next section)
- Forensic wrappers: audit log, image hashing, report generation

---

## 7. Search System

### Matching Modes

| Mode | Trigger | Behavior |
|---|---|---|
| Substring | Default (no `*`/`?`, not `--exact`) | `text.contains(query)` |
| Exact | `--exact` flag | `text == query` |
| Glob | Query contains `*` or `?` | Two-pointer backtracking: `*` = any sequence, `?` = any char |
| Case-insensitive | `--ignore-case` flag | Lowercases query and text before matching |
| Path-scoped | Query starts with `/` | Matches against absolute path only |

### Two Search Paths

1. **Session search** (`search_session`): Iterates `filesystem.nodes` in-memory. No I/O. Fast.
2. **Live search** (`search` / `search_selected`): Walks ext4 directories live from disk. Includes deleted orphans via `scan_deleted_inodes`. ext4 only — NTFS is skipped.

---

## 8. File Carving

Raw signature-based recovery when filesystem metadata is gone. Scans at 512-byte sector boundaries.

| Format | Magic | Size Detection |
|---|---|---|
| JPEG | `FF D8 FF` | Scans for `FF D9` end marker |
| PNG | `89 50 4E 47` | Scans for IEND chunk |
| PDF | `%PDF-` | Scans for `%%EOF` |
| ZIP | `PK 03 04` | Reads local file headers |
| GIF | `GIF87a`/`GIF89a` | Scans for `0x3B` terminator |
| ELF | `7F 45 4C 46` | Reads ELF header for total size |
| gzip | `1F 8B` | Decompresses to find size |
| SQLite | `SQLite format 3` | `page_count × page_size` |

`carve_to_dir` writes directly to disk. Files are named by type and offset: `jpeg_offset_0x1000.jpg`.

---

## 9. Deleted File Recovery

This is the most sophisticated part of RecoverMax and a key differentiator.

### How Deleted Files Appear

1. **Residual directory entries** (`DeletedSlack`): The parent directory's data still contains the filename, but the inode slot was reused. The entry has `inode: None` — we know the name but not the data.

2. **Orphan inodes** (`SyntheticOrphan`): Deleted inodes found by scanning all block groups. They have data (inode number, size, timestamps) but no directory entry pointing to them. Named `OrphanFile-N` by default, or by journal-recovered names if available.

### Orphan Resolution Pipeline

When a user targets a residual deleted entry (has name, no inode), we try to match it to an orphan candidate:

```
unique_orphan_recovery_candidate(session, residual_node)
  │
  ├── candidates = orphan_recovery_candidates(session, node)
  │     └── Filter: deleted, has inode, same file_type, is_orphan_candidate
  │
  ├── if candidates.len() == 1 → auto-resolve
  │
  ├── Stage 1: Content-type sniffing
  │     └── strongly_matched_orphan_recovery_candidate
  │           Read first 512 bytes of each candidate → match magic bytes
  │           against residual's file extension (.txt→Text, .jpg→JPEG, etc.)
  │           If exactly 1 matches → auto-resolve
  │
  └── Stage 2: Tiebreaker scoring
        └── tiebreaker_scored_orphan_candidate
              Gather SiblingContext { median_dtime, inode_range }
              Score each candidate:
                dtime_proximity (weight 3.0) — closeness to sibling dtime median
                block_group_locality (weight 2.0) — same block group as parent
                inode_range_proximity (weight 2.0) — within sibling inode range
                size_reasonableness (weight 1.0) — plausible size for extension
              Winner must beat runner-up by MIN_SCORE_GAP (2.0)
```

### Journal Filename Recovery

The JBD2 journal stores old versions of filesystem metadata blocks. We scan it for directory data blocks and extract inode→filename mappings. When building the orphan tree, these hints replace the synthetic `OrphanFile-N` names with the actual deleted filenames.

---

## 10. Forensic System

### Components

**AuditLog** — JSON-serializable log of every forensic action:
```rust
pub enum AuditAction {
    ImageOpened { path, size, sha256 },
    ScanStarted, ScanCompleted { partitions, filesystems },
    FileRecovered { inode, path, size, sha256 },
    DirectoryRecovered { path, file_count },
    CarveStarted { types }, CarveCompleted { files_found },
    DeletedScan { deleted_count },
    ImageVerified { sha256, matched },
    Error { message },
}
```

**ImageHasher** — Streaming SHA-256 in 8 MiB chunks. Safe for multi-TB images.

**ForensicReport** — Self-contained HTML report with case info, audit trail, recovered files table. References NIST SP 800-86.

### CLI Integration

```bash
# Hash an image
recovermax hash disk.img
recovermax hash disk.img --verify abc123...

# Forensic recovery
recovermax recover disk.img -d ./out \
  --audit-log audit.json \
  --examiner "Kyle Quinlan" \
  --case-number "IR-2026-042" \
  --evidence-id "EV-001" \
  --hash-image \
  --report report.html
```

The `--hash-image` flag computes SHA-256 before and after recovery, verifying the source image was not modified (read-only proof for chain of custody).

---

## 11. CLI & TUI

### CLI Subcommands (cli.rs, 4777 lines)

| Command | Purpose | Key Flags |
|---|---|---|
| `info` | Show image/device metadata | |
| `scan` | Scan for partitions + filesystems | `-o` output, `--deep-scan` |
| `filesystems` | List filesystems from session/scan | `-s` scan file |
| `ls` | List directory entries | `-s`, `--fs`, `-l` long |
| `tree` | Recursive tree listing | `--depth` (default 64) |
| `stat` | Show node metadata | |
| `warnings` | Show traversal warnings | `--fs`, `-p` path |
| `recover` | Recover files/directories | `-d` dest, `-p` path, forensic flags |
| `search` | Search by name pattern | `-i` ignore case, `-x` exact |
| `cache` | Show cache state | |
| `unload` | Drop session caches | |
| `carve` | Raw file carving | `-d` dest, `-t` types |
| `hexdump` | Hex dump region | `-o` offset, `-l` length |
| `deleted` | List/recover deleted inodes | `--fs`, `-r` inode, `-d` dest |
| `hash` | SHA-256 hash/verify | `--verify` expected |

### TUI Shell (tui.rs, 949 lines)

Interactive REPL with commands: `ls`, `cd`, `pwd`, `tree`, `stat`, `warnings`, `search`, `searchfs`, `recover`, `cache`, `unload`, `save`, `filesystems`, `usefs`, `back`, `quit`/`exit`.

Image picker auto-discovers `.img/.raw/.dd/.qcow2/.scn` files under hardcoded developer paths.

### Entry Point (main.rs, 49 lines)

```
recovermax <subcommand> [args]     → cli::run
recovermax <image>                 → tui::run_tui
recovermax                         → tui::run_image_picker
```

---

## 12. Testing Strategy

### Test Architecture

All tests are **pure in-memory** — no real disk images, no root required, cross-platform. The `Ext4ImageBuilder` pattern (used in 3 test files) constructs synthetic ext4 images byte-by-byte:

```rust
let mut builder = Ext4ImageBuilder::new(64); // 64 blocks
builder.write_superblock("test-label");
builder.write_block_group_descriptor(0, 3);  // inode table at block 3
builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
builder.write_dir_entries(10, &[(2, 2, "."), (2, 2, ".."), (11, 1, "hello.txt")]);
builder.write_inode_with_extent(11, 0x8000 | 0o644, 13, 20, 1);
builder.write_data(20, b"Hello, world!");
let img = builder.build();
```

### Test Suites (272 tests)

| Suite | Tests | What It Covers |
|---|---|---|
| ext4_tests | 21 | Basic inode, directory, extent, block map parsing |
| ext4_complex_tests | 28 | End-to-end trees, session build, deleted recovery, journal |
| ntfs_tests | 13 | Boot sector, MFT, data runs, file read |
| scan_tests | 14 | MBR/GPT detection, deep scan |
| carve_tests | 17 | All 8 signature types |
| carve_smart_tests | 8 | Smart size detection |
| carve_complex_tests | 25 | Multi-file carving, overlapping signatures |
| deleted_tests | 22 | Deleted inode scanning, dtime, links_count |
| streaming_tests | 13 | Stream vs buffer parity, bounded read |
| io_tests | 7 | ImageReader open, read_at, bounds |
| failing_tests | 13 | Corrupt data, graceful degradation |
| session_cache_tests | 3 | Cache warming, eviction, rebuild |
| session_degraded_tests | 4 | Partial trees, report-only mode |
| session_migration_tests | 3 | v1→v2 format migration |
| session_path_tests | 2 | Path resolution edge cases |
| session_runtime_tests | 2 | Runtime cache operations |
| cli.rs (inline) | 46 | Orphan resolution, tiebreakers, deleted recovery |
| search.rs (inline) | 13 | Substring, exact, glob, case-insensitive |

### Validation Infrastructure (scripts/)

- `build-ext4-fixtures.sh` — Build deterministic ext4 images with known contents
- `benchmark-session-workflows.sh` — Time each session workflow step, produce JSON report
- `recovermax-diff-validate.sh` — Compare RecoverMax output against manifest expectations and Sleuth Kit oracle

### Real Image Testing

Build on welles, run against lab recovery images:
```bash
rsync -av --exclude target ~/Workspace/recovermax/ welles:/tmp/recovermax-build/
ssh welles 'cd /tmp/recovermax-build && cargo build --release'
ssh welles './target/release/recovermax info /projects/reiner-recovery/reiner-sda.img'
```

---

## 13. Website & Marketing

**URL:** recovermax.dev
**Framework:** Next.js 16.2.1, React 19, static export (no server)
**Design:** Dark mode, monospace-forward, CSS Modules with custom properties

### Pages
Single page with 6 sections: Navbar, Hero (with fake terminal demo), Capabilities (8 feature cards), Comparison table (vs Photorec, R-Linux, Sleuth Kit), Technical Specs, Footer.

### SEO Strategy
- Title targets "R-Linux Alternative" and "Free Linux/NTFS/ext4 Data Recovery"
- JSON-LD schemas for SoftwareApplication and Organization
- OpenGraph and Twitter cards configured
- robots.txt and sitemap.xml generated

---

## 14. CI/CD & Releases

### CI (`ci.yml`)
- Trigger: push to main, all PRs
- Steps: checkout → Rust stable + clippy → cache → build → test → clippy (warnings = errors)

### Release (`release.yml`)
- Trigger: tags matching `v*`
- Build matrix: Linux x86_64, macOS x86_64, macOS arm64, Windows x86_64
- Each build produces a binary + SHA-256 checksum
- Final job creates GitHub release with all artifacts and auto-generated release notes

---

## 15. Roadmap: What's Missing vs R-Studio

### Phase 1 — Multi-FS Parity (next)

| Feature | Effort | Notes |
|---|---|---|
| Wire NTFS into sessions/search/recovery | Large | Parser exists, needs session tree construction + recovery dispatch |
| Recovery result tracking for forensic reports | Small | `Recoverer` needs to return `Vec<RecoveredFileInfo>` |
| NTFS deleted MFT scanning | Medium | Scan for entries with deallocated flag |
| NTFS B-tree index parsing | Medium | Replace linear MFT scan with proper index tree traversal |

### Phase 2 — Filesystem Breadth

| Feature | Effort | Notes |
|---|---|---|
| FAT32 | Medium | BPB parsing, FAT chain walking, directory entries |
| XFS | Large | Superblock, AG headers, B+tree inodes |
| APFS | Large | Container superblock, B-tree objects, snapshot support |
| ext4 journal deep parsing | Medium | Extract old inode table blocks (recover file sizes/timestamps) |

### Phase 3 — Advanced Recovery

| Feature | Effort | Notes |
|---|---|---|
| RAID 0/1/5/6 reconstruction | Large | Virtual volume assembly from multiple images |
| LVM/LVM2/mdadm | Large | PV/VG/LV metadata parsing |
| Network recovery (SSH agent) | Large | Remote `ImageReader` over SSH |
| Bad sector handling | Medium | Skip/retry/abort strategy |
| File validation | Medium | Verify carved files are actually valid |
| FUSE mount | Medium | Mount recovered filesystem read-only |

### Phase 4 — Professional

| Feature | Effort | Notes |
|---|---|---|
| E01/EWF image format | Medium | Expert Witness format decompression |
| Cross-platform GUI (egui) | Large | Separate repo, proprietary license |
| Python bindings (PyO3) | Medium | Expose core API to Python |
| Parallel scanning (rayon) | Small | rayon is already a dependency |

---

## 16. Implementation Guides

### Adding a New Filesystem

1. Create `crates/recovermax-core/src/fs/<name>.rs`
2. Define `<Name>Fs` struct with `new(reader, offset) -> Result<Self>`
3. Implement `detect(reader, offset) -> Option<FsInfo>` for scanner integration
4. Implement `list_directory(inode) -> Result<Vec<DirEntry>>` using shared `DirEntry` type
5. Implement `read_inode_data(inode) -> Result<Vec<u8>>` and streaming variant
6. Add detection call to `scan/mod.rs` in the filesystem probe loop
7. Add session tree construction in `session.rs` (follow `build_ext4_subtree` pattern)
8. Add recovery dispatch in `recover/mod.rs` (follow ext4 pattern)
9. Add search support in `search.rs` (remove the ext4-only guard)
10. Add tests in `crates/recovermax-core/tests/<name>_tests.rs`

### Adding a New Carving Signature

1. Add signature constant to `carve/mod.rs`
2. Add smart size detection function (scan for format-specific end marker or read header for size)
3. Register in the `SIGNATURES` array
4. Add tests in `carve_tests.rs`

### Adding a New CLI Subcommand

1. Add variant to `Command` enum in `cli.rs` with clap attributes
2. Add handler function
3. Add match arm in `run()`
4. Add tests (inline in `#[cfg(test)] mod tests`)

### Adding a New TUI Command

1. Add match arm in `tui.rs` REPL loop
2. Delegate to `cli.rs` functions where possible (shared logic)
3. Handle shell-specific state (current directory, current filesystem)

### Forensic Integration Pattern

1. Create `AuditLog` with `CaseInfo` at start of operation
2. Log `AuditAction` entries at each significant step
3. Save audit log to JSON at end
4. Generate HTML report via `ForensicReport::generate` if requested
5. For chain of custody: hash image before and after, log `ImageVerified`
