# Fixture Conventions

Use these conventions for local synthetic fixtures.

## Catalog

`catalog.json` tracks the full professional-quality test matrix, including cases
that are not built yet. Keep it current when adding parser, RAID, imaging,
remote, destination-safety, or performance work.

Statuses:

- `available`: checked-in or locally staged fixture with a manifest.
- `generated-script`: produced by a script such as `scripts/build-ext4-fixtures.sh`.
- `unit-covered`: covered by byte-level Rust unit/integration tests.
- `planned`: required but not built yet.
- `external-needed`: requires a public corpus or external fixture.
- `manual-only`: requires hardware, raw devices, or platform-specific setup.

Use `python3 scripts/fixture-scorecard.py` from the repo root to see current
coverage and gaps.

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
