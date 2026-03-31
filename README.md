# RecoverMax

High-performance data recovery tool for ext4 and NTFS disk images, written in Rust.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-172_passing-brightgreen.svg)](#testing)

## What It Does

RecoverMax reads raw disk images and recovers files from damaged or reformatted ext4 and NTFS filesystems. It provides an interactive shell for browsing filesystem trees, inspecting files, and selectively recovering data -- all without mounting the image. Streaming I/O means it handles multi-TB images without running out of memory.

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

**Interactive shell:**
`ls`, `cd`, `tree`, `cat`, `hexdump`, `recover`, `deleted`, `carve`, `mount`

**One-shot CLI:**
scriptable subcommands for automated recovery pipelines

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

The binary will be at `target/release/recovermax-cli`.

## Usage

### Interactive mode

Open an image and explore interactively:

```bash
recovermax /path/to/image.img
```

### One-shot commands

```bash
recovermax info <image>                              # image metadata
recovermax scan <image> -o scan.json                 # find partitions and filesystems
recovermax recover <image> -d /dest -p /home/user    # recover a path
recovermax recover <image> -d /dest -s scan.json     # recover using saved scan
recovermax carve <image> -d /dest -t jpg,png,pdf     # raw carve by signature
recovermax hexdump <image> -o 0x400 -l 256           # inspect raw bytes
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
└── recovermax-cli/      # Binary: interactive shell + one-shot CLI
    └── src/
        ├── main.rs      # Entry point
        ├── shell.rs     # Interactive REPL
        └── cli.rs       # One-shot subcommands
```

**recovermax-core** is the library. It has no CLI dependencies and can be embedded in other tools.

**recovermax-cli** is the command-line interface built on top of the core library.

## License

[AGPL-3.0](LICENSE)

## Website

[recovermax.dev](https://recovermax.dev)
