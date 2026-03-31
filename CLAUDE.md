# RecoverMax — Data Recovery Tool

High-performance data recovery tool written in Rust. Designed to replace R-Studio/R-Linux and Photorec for the UCSB SecLab's data recovery workflows.

Website: recovermax.dev
License: AGPL-3.0 (core + CLI), proprietary (GUI — separate repo)

## Build & Run

```bash
cargo build                              # debug build
cargo build --release                    # optimized build
cargo test                               # run all tests
RUST_LOG=debug cargo run -- info img.img # one-shot with debug logging
cargo run -- /path/to/image.img          # interactive mode
```

## Coding Standards

**KISS — Keep It Simple, Stupid.** The simplest solution that works is the right one. Over-engineered abstractions are worse than duplicated code.

- **DRY within reason.** Don't repeat yourself, but don't create an abstraction for two similar lines either. Three is the threshold — if you see the same pattern three times, extract it.
- **No premature abstractions.** Don't build plugin systems, trait hierarchies, or config layers until the concrete use case demands it. Write the specific thing first, generalize only when a second case appears.
- **No dead code.** If it's not used, delete it. Don't comment it out "for later."
- **Errors should be actionable.** Error messages must tell the user what went wrong and ideally how to fix it. No bare `unwrap()` in library code.
- **Functions do one thing.** If a function name has "and" in it, split it.
- **Flat is better than nested.** Prefer early returns over deep indentation.
- **Tests are first-class code.** Test helpers get the same care as production code. Tests construct their own data — no reliance on external state.
- **No unnecessary dependencies.** Every crate in Cargo.toml must justify its existence. Prefer std when it's good enough.

## Project Structure

Cargo workspace with open-core architecture:
- **recovermax-core** (AGPL-3.0) — library, open source
- **recovermax-cli** (AGPL-3.0) — CLI binary, open source
- **recovermax-gui** (proprietary) — separate private repo, paid product

```
crates/
├── recovermax-core/
│   ├── src/
│   │   ├── lib.rs           # Public API
│   │   ├── io/mod.rs        # ImageReader — mmap-based zero-copy I/O
│   │   ├── fs/
│   │   │   ├── mod.rs       # Filesystem traits and common types
│   │   │   └── ext4.rs      # ext4 superblock, inode, extent, directory parsing
│   │   ├── scan/mod.rs      # Partition detection (MBR/GPT), filesystem discovery
│   │   ├── carve/mod.rs     # Raw file carving by signature
│   │   └── recover/mod.rs   # Tree-walk recovery from parsed filesystems
│   └── tests/               # Integration tests (build test images in-memory)
└── recovermax-cli/src/
    ├── main.rs              # Entry point, mode dispatch
    ├── cli.rs               # One-shot subcommand handlers
    └── shell.rs             # Interactive REPL (ls, cd, tree, cat, recover, etc.)
```

## Usage

**Interactive mode** — open an image and explore:
```
$ recovermax /path/to/image.img
RecoverMax v0.1.0
Image: image.img (2.73 TB)
Scanning... done.

recovermax:/> ls /home
  d    4.0 KiB   alice/
  d    4.0 KiB   bob/

recovermax:/> cd /home/alice
recovermax:/home/alice> tree
├── notes.txt
├── .ssh/
│   └── id_rsa
└── Documents/

recovermax:/home/alice> cat notes.txt
recovermax:/home/alice> recover . -d /tmp/restored
```

**One-shot mode** — for scripting:
```
recovermax info <image>
recovermax scan <image> [-o scan.json]
recovermax recover <image> -d <dest> [-p /home/user] [-s scan.json]
recovermax carve <image> -d <dest> [-t jpg,png,pdf]
recovermax hexdump <image> [-o 0x400] [-l 256]
```

## Testing

Tests build ext4 images entirely in-memory — no external files, no root access, no Linux required. Run on any platform.

```bash
cargo test                    # all 102 tests
cargo test --test ext4_tests  # just ext4 unit tests
cargo test --test failing     # known bugs (should_panic)
```

Test suites:
- `io_tests` — ImageReader: open, read, bounds, endian helpers
- `ext4_tests` — superblock parsing, block sizes, feature flags, inode types
- `ext4_complex_tests` — full end-to-end: superblock → BGDT → inode → extents → data → recovery
- `scan_tests` — MBR/GPT detection, filesystem discovery, JSON roundtrip
- `carve_tests` — all signature types, filtering, sector alignment
- `carve_complex_tests` — false footers, overlapping sigs, edge cases
- `failing_tests` — documented bugs: indirect blocks, sparse files, symlinks

## Known Bugs

Tracked via `#[should_panic]` tests in `failing_tests.rs`:
1. **Indirect blocks not implemented** — files >48KB via block map get truncated
2. **Sparse files break** — block map stops at first zero (hole), loses remaining data
3. **Symlinks not recovered** — silently skipped during recovery

## Architecture Principles

- **Zero-copy I/O**: all image access through mmap. Never buffer entire images in RAM.
- **Sector-aligned scanning**: carving scans on 512-byte boundaries.
- **Graceful degradation**: bad sectors/corrupt metadata log warnings and continue, never crash.
- **Serializable state**: scan results save to JSON so recovery can resume without re-scanning.

---

## Roadmap

### Phase 1 — Foundation (DONE)
- [x] mmap-based ImageReader
- [x] CLI with clap (one-shot subcommands)
- [x] Interactive shell (ls, cd, tree, cat, recover, carve, hexdump)
- [x] MBR and GPT partition table parsing
- [x] ext4: superblock, inodes, extents, block maps, directories
- [x] File carving engine (JPEG, PNG, PDF, ZIP, GIF, ELF, gzip, SQLite)
- [x] Tree-walk recovery from ext4
- [x] Scan report serialization (JSON)
- [x] 102 tests (unit + integration + known-bug)

### Phase 2 — ext4 Completeness
- [ ] Indirect, double-indirect, triple-indirect block maps
- [ ] Sparse file handling (holes in block maps)
- [ ] Symbolic link recovery
- [ ] ext4 journal parsing
- [ ] Deleted inode scanning (walk block groups, find dtime > 0)
- [ ] File permission and timestamp preservation
- [ ] Large file support (>4GB)

### Phase 3 — Robustness & Performance
- [ ] Parallel scanning with rayon
- [ ] Streaming recovery (don't buffer entire files)
- [ ] Bad sector handling (skip/retry/abort)
- [ ] Resume interrupted scans
- [ ] Signal handling (graceful Ctrl+C)

### Phase 4 — Additional Filesystems
- [ ] NTFS MFT parsing
- [ ] XFS, Btrfs, FAT32, APFS, ZFS

### Phase 5 — Advanced Carving
- [ ] More signatures (docx, mp4, mp3, vmdk, qcow2)
- [ ] Smart carving (filesystem metadata + raw carving)
- [ ] File validation (verify carved files are valid)

### Phase 6 — GUI (separate repo, proprietary)
- [ ] egui desktop application
- [ ] Partition/block visualization
- [ ] File preview
- [ ] Recovery queue

## Dependencies

- `clap` — CLI parsing
- `rustyline` — interactive line editing
- `memmap2` — zero-copy file I/O
- `nom` — binary format parsing
- `thiserror` / `anyhow` — error handling
- `tracing` — structured logging
- `indicatif` — progress bars
- `rayon` — data parallelism
- `serde` / `serde_json` — serialization
