# RecoverMax — Data Recovery Tool

High-performance data recovery tool written in Rust. Designed to replace R-Studio/R-Linux and Photorec for the UCSB SecLab's data recovery workflows.

## Build & Run

```bash
cargo build              # debug build
cargo build --release    # optimized build
cargo test               # run all tests
RUST_LOG=debug cargo run -- info /path/to/image.img   # run with debug logging
```

## Project Structure

Cargo workspace with open-core architecture:
- **recovermax-core** (AGPL-3.0) — library, open source
- **recovermax-cli** (AGPL-3.0) — CLI binary, open source
- **recovermax-gui** (proprietary) — separate private repo, paid product

```
crates/
├── recovermax-core/src/     # Recovery engine library
│   ├── lib.rs               # Public API
│   ├── io/mod.rs            # ImageReader — mmap-based zero-copy I/O
│   ├── fs/
│   │   ├── mod.rs           # Filesystem traits and common types
│   │   └── ext4.rs          # ext4 superblock, inode, extent, directory parsing
│   ├── scan/mod.rs          # Partition detection (MBR/GPT), filesystem discovery
│   ├── carve/mod.rs         # Raw file carving by signature (like Photorec)
│   └── recover/mod.rs       # Tree-walk recovery from parsed filesystems
└── recovermax-cli/src/      # CLI binary
    ├── main.rs              # Entry point, tracing setup
    └── cli.rs               # CLI argument parsing and command dispatch
```

## Architecture Principles

- **Zero-copy I/O**: All image access through mmap. Never buffer entire images in RAM.
- **Sector-aligned scanning**: Carving scans on 512-byte boundaries.
- **Graceful degradation**: Bad sectors/corrupt metadata log warnings and continue, never crash.
- **Serializable state**: Scan results save to JSON so recovery can resume without re-scanning.
- **No GUI yet**: CLI-first. GUI (egui) comes later.

## Commands

| Command | Description |
|---------|-------------|
| `recovermax info <image>` | Show image size, partitions, filesystem info |
| `recovermax scan <image>` | Full scan, optionally save to JSON |
| `recovermax recover <image> -d <dest>` | Recover files from detected filesystems |
| `recovermax carve <image> -d <dest>` | Raw-carve files by magic bytes |
| `recovermax hexdump <image>` | Hex dump a region |

---

## Roadmap

### Phase 1 — Foundation (DONE)
- [x] Project scaffolding
- [x] mmap-based ImageReader
- [x] CLI skeleton with clap
- [x] MBR and GPT partition table parsing
- [x] ext4 superblock detection and parsing
- [x] ext4 inode reading (mode, size, flags, timestamps)
- [x] ext4 extent tree traversal
- [x] ext4 block map (direct blocks)
- [x] ext4 directory entry parsing
- [x] Basic file carving engine with signatures (JPEG, PNG, PDF, ZIP, GIF, ELF, gzip, SQLite)
- [x] Tree-walk recovery from ext4
- [x] Hexdump command
- [x] Scan report serialization (JSON)

### Phase 2 — ext4 Completeness
- [ ] Indirect, double-indirect, triple-indirect block maps
- [ ] ext4 journal parsing (recover from journal transactions)
- [ ] Deleted inode scanning (walk all block groups, find dtime > 0)
- [ ] Extended attribute (xattr) recovery
- [ ] Symbolic link target recovery
- [ ] File permission and timestamp preservation on recovered files
- [ ] Large file support testing (>4GB files)
- [ ] Sparse file handling

### Phase 3 — Robustness & Performance
- [ ] Parallel block group scanning with rayon
- [ ] Parallel file carving (split image into regions, scan concurrently)
- [ ] Bad sector handling (configurable skip/retry/abort)
- [ ] Progress bars for all long operations
- [ ] Memory usage profiling and optimization
- [ ] Streaming recovery (write files as blocks are read, don't buffer entire files)
- [ ] Resume interrupted scans (checkpoint to scan file periodically)
- [ ] Signal handling (graceful shutdown on Ctrl+C)

### Phase 4 — Additional Filesystems
- [ ] XFS superblock and inode parsing
- [ ] NTFS MFT parsing and file recovery
- [ ] Btrfs superblock detection
- [ ] FAT32 (for USB drives, SD cards)
- [ ] APFS (for Mac disks)
- [ ] ZFS (for welles/coen server disks)
- [ ] Filesystem detection heuristics (fallback when superblock is damaged)

### Phase 5 — Advanced Carving
- [ ] More file signatures (docx, xlsx, pptx, mp4, mp3, psd, vmdk, qcow2)
- [ ] Smart carving: use filesystem metadata + raw carving together
- [ ] Fragment reassembly for fragmented files
- [ ] Entropy analysis to skip encrypted/compressed regions
- [ ] Duplicate detection (hash-based dedup of carved files)
- [ ] File validation (verify carved files are actually valid)

### Phase 6 — CLI Polish
- [ ] Interactive mode (TUI with ratatui) for browsing recovered filesystems
- [ ] Tree view of recoverable files before committing to recovery
- [ ] Selective recovery (pick files/directories interactively)
- [ ] Dry-run mode (show what would be recovered)
- [ ] Output format options (JSON, CSV, tree)
- [ ] Man page / shell completions

### Phase 7 — RAID & Multi-Disk
- [ ] RAID-0 stripe reassembly
- [ ] RAID-1 mirror selection
- [ ] RAID-5/6 parity reconstruction
- [ ] LVM physical volume detection
- [ ] LVM logical volume reassembly
- [ ] mdadm metadata parsing

### Phase 8 — GUI
- [ ] egui-based desktop application
- [ ] Image/partition visualization (block map view)
- [ ] Drag-and-drop image loading
- [ ] Real-time scan progress
- [ ] File preview (images, text, hex)
- [ ] Recovery queue management

### Phase 9 — Ecosystem
- [ ] Disk image creation tool (dd-like but with progress and verification)
- [ ] Forensic report generation (chain of custody, hashes, timestamps)
- [ ] Plugin system for custom file signatures
- [ ] Python bindings (PyO3) for scripting
- [ ] FUSE mount recovered filesystem as read-only
- [ ] Network recovery (recover from images on remote hosts via SSH)

## Testing

```bash
# Create a test ext4 image
dd if=/dev/zero of=/tmp/test.img bs=1M count=64
mkfs.ext4 /tmp/test.img
sudo mount /tmp/test.img /mnt
sudo cp -r /etc/hostname /etc/hosts /mnt/
sudo umount /mnt

# Test recovermax against it
cargo run -- info /tmp/test.img
cargo run -- scan /tmp/test.img -o /tmp/scan.json
cargo run -- recover /tmp/test.img -d /tmp/recovered
cargo run -- hexdump /tmp/test.img -o 0x400 -l 256
```

## Target Use Case

Primary: recovering home directories from Proxmox-reimaged lab servers (robbins, reiner, reynolds).
These are ext4 on GPT, 1.8–2.7 TB disk images stored on welles at `/projects/*-recovery/`.

## Dependencies

All chosen for maturity and low overhead:
- `clap` — CLI parsing
- `memmap2` — zero-copy file I/O
- `nom` — binary format parsing (used as needed)
- `thiserror` / `anyhow` — error handling
- `tracing` — structured logging
- `indicatif` — progress bars
- `rayon` — data parallelism
- `serde` / `serde_json` — serialization
- `egui` (future) — GUI
- `ratatui` (future) — TUI
