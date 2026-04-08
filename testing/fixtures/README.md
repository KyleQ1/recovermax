# Fixture Conventions

Use these conventions for local synthetic fixtures.

## Naming

- `ext4-synthetic-basic`
- `ext4-synthetic-deleted`
- `ext4-synthetic-sparse`
- `ext4-synthetic-symlink`
- `ext4-synthetic-deep-tree`

## Required Files

Each fixture should have:

- `image.dd` for the disk image
- `session.scn` for the saved recovery session
- `manifest.json` for the machine-readable fixture definition
- `expected/` for small golden text outputs when useful

## Expected Outputs

Good expected outputs are short, stable, and easy to diff:

- `paths.txt` for exact browse paths
- `tree.txt` for a tree snapshot
- `sha256.txt` for recovered file hashes
- `stats.txt` for inode/path metadata summaries

Avoid storing recovered file payloads unless the file is tiny and the payload itself is the golden output.

