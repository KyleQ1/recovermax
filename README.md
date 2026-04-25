# RecoverMax

High-performance data recovery tool for ext4 and NTFS disk images, written in Rust.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-172_passing-brightgreen.svg)](#testing)

## What It Does

RecoverMax reads raw disk images and recovers files from damaged or reformatted ext4 and NTFS filesystems. It provides one-shot commands, a lightweight interactive image mode, and the foundation for a daemon-backed recovery workflow -- all without mounting the image. Streaming I/O means it handles multi-TB images without running out of memory.

## Demo

```
$ recovermax server-backup.img
RecoverMax v0.1.0
Image: server-backup.img (1.82 TB)
Scanning... done.
Filesystems:
  [0] ext4 "rootfs" -- 1.82 TB (offset 1.0 MiB)
Mounted ext4 "rootfs" at /

recovermax:/> ls /home
  d    4.0 KiB   alice/
  d    4.0 KiB   bob/
  d    4.0 KiB   charlie/

recovermax:/> cd /home/alice
recovermax:/home/alice> tree
├── Documents/
│   ├── thesis.pdf
│   └── notes.txt
├── .ssh/
│   └── id_rsa
└── photos/

recovermax:/home/alice> recover Documents -d /tmp/restored
Recovering 2 files... done.

recovermax:/home/alice> deleted
  [inode 14201]  deleted 2024-11-03  budget.xlsx  (12.4 KiB)
  [inode 14455]  deleted 2024-11-05  old-config.json  (892 B)
```

## Features

**ext4 support:**
superblock parsing, inode and directory traversal, extent trees, block maps (direct + indirect), sparse files, symlinks, deleted inode scanning

**NTFS support:**
boot sector parsing, MFT entry walking, data run decoding, file content reading

**File carving:**
8 built-in signatures (JPEG, PNG, PDF, ZIP, GIF, ELF, gzip, SQLite) with smart size detection -- ZIP uses EOCD headers, footers have minimum-distance checks to avoid false positives

**Performance:**
mmap-based zero-copy I/O, sector-aligned scanning, streaming recovery for multi-TB images

**Terminal UI:**
image picker, saved scan reopen, `search`, `searchfs`, `save`, plus lightweight interactive search workflows over discovered filesystems

**One-shot CLI:**
scriptable subcommands for automated recovery pipelines, including saved scan reuse and path search

**Daemon foundation:**
`daemon start`, `daemon status`, `daemon release`, `daemon stop`, and `daemon logs` manage a workspace daemon that can keep future scan/session state alive after the initiating CLI command exits

## Installation

```bash
cargo install --path crates/recovermax-cli
```

Or clone and build:

```bash
git clone https://github.com/KyleQ1/recovermax.git
cd recovermax
cargo build --release
```

The binary will be at `target/release/recovermax`.

## Usage

### Daemon foundation

RecoverMax is moving toward a daemon-backed workflow so long scans can keep running after the foreground CLI command exits. The current daemon milestone manages lifecycle, workspace state, and daemon-backed scans. Routing browse, search, and recover commands through the daemon is the next step.

Start a daemon for a workspace:

```bash
recovermax daemon start --workspace case1
```

Check status in JSON for automation and LLM agents:

```bash
recovermax daemon status --workspace case1 --json
```

Release daemon-held memory without deleting workspace metadata:

```bash
recovermax daemon release --workspace case1
```

Stop the daemon after saving state:

```bash
recovermax daemon stop --workspace case1
```

Show recent daemon logs:

```bash
recovermax daemon logs --workspace case1 --tail 50
```

Start a daemon-backed scan:

```bash
recovermax scan image.dd --workspace case1
```

The command submits a background task and returns. Use status to watch progress:

```bash
recovermax daemon status --workspace case1 --json
```

When complete, the daemon saves `case1/scan.scn` and keeps the loaded session in memory until `daemon release` or `daemon stop`.

List filesystems from the daemon-held session:

```bash
recovermax filesystems --workspace case1 --json
```

### Direct modes

Show daemon-first guidance:

```bash
recovermax
```

Open the image picker:

```bash
recovermax picker
```

Open a specific image directly in the lightweight interpreter:

```bash
recovermax /path/to/image.img
```

The image picker/interpreter can list `.scn` saved scan artifacts and reopen them when the matching source image is present nearby.

### One-shot commands

```bash
recovermax info <image>                              # image metadata
recovermax scan <image> -o scan.scn                  # find partitions and filesystems
recovermax search <image> /data/ming -s scan.scn     # search ext4 paths using saved scan
recovermax recover <image> -d /dest -p /home/user    # recover a path
recovermax recover <image> -d /dest -s scan.scn      # recover using saved scan
recovermax carve <image> -d /dest -t jpg,png,pdf     # raw carve by signature
recovermax hexdump <image> -o 0x400 -l 256           # inspect raw bytes
```

Planned daemon-backed browse/recover shape:

```bash
recovermax search File --workspace case1 --json
recovermax select '#2' --workspace case1
recovermax recover selected --dest out --workspace case1
```

## Building from Source

```bash
cargo build              # debug build
cargo build --release    # optimized build
cargo test               # run all 172 tests
```

## Testing

Tests build filesystem images entirely in-memory -- no disk images, no root access, no Linux required. Runs on any platform.

```bash
cargo test                       # all tests
cargo test --test ext4_tests     # ext4 parsing
cargo test --test ntfs_tests     # NTFS parsing
cargo test --test carve_tests    # file carving
cargo test --test scan_tests     # partition detection
```

For the broader validation workflow, dataset inventory, and manifest conventions, see [testing/README.md](/Users/kylequinlan/Workspace/recovermax/testing/README.md).
For a concrete malformed-image case study, see [testing/datasets/cfreds-dfr-01-ext/notes.md](/Users/kylequinlan/Workspace/recovermax/testing/datasets/cfreds-dfr-01-ext/notes.md).

## Project Structure

```
crates/
├── recovermax-core/     # Library: I/O, filesystem parsing, carving, recovery
│   ├── src/
│   │   ├── io/          # mmap-based ImageReader
│   │   ├── fs/          # ext4 and NTFS parsers
│   │   ├── scan/        # MBR/GPT partition detection
│   │   ├── carve/       # Raw file carving engine
│   │   └── recover/     # Tree-walk file recovery
│   └── tests/           # Integration tests
└── recovermax-cli/      # Binary: terminal UI + one-shot CLI
    └── src/
        ├── main.rs      # Entry point
        ├── daemon.rs    # Workspace daemon lifecycle and control protocol
        ├── tui.rs       # Image picker + interactive search UI
        └── cli.rs       # One-shot subcommands
```

**recovermax-core** is the library. It has no CLI dependencies and can be embedded in other tools.

**recovermax-cli** is the command-line interface built on top of the core library.

## License

[AGPL-3.0](LICENSE)

## Website

[recovermax.dev](https://recovermax.dev)
