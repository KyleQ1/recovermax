# RecoverMax Testing Guide

This directory is the working area for RecoverMax validation.

The goal is not just to keep tests green. It is to prove that the session model behaves correctly on real and synthetic images:

- scan once
- save a durable session artifact
- reopen the same artifact later
- browse filesystems, tree nodes, and stats from the session
- recover files from the session without changing the data path
- unload RecoverMax-managed caches and keep the session usable
- compare RecoverMax output against a known oracle

RecoverMax should also tolerate malformed or partially damaged images. The target behavior is:

- preserve a durable `.scn` session even when one filesystem tree cannot be fully materialized
- fall back to report-only state for unreadable filesystems instead of aborting the whole scan
- keep `info`, `scan`, `cache`, and `unload` useful even when browsing is degraded
- keep `ls`, `tree`, `stat`, `search`, and `recover` working on fully materialized sessions
- keep live fallback paths available for `ls`, `tree`, `stat`, `search`, and `recover` when the persisted tree is unavailable

## What To Test

Use three layers of testing:

1. Deterministic synthetic fixtures
   - Small ext4 images you create locally
   - Known paths, inodes, deleted entries, sparse files, and symlinks
   - Best for regression tests and exact expectations

2. Public corpora
   - Use documented disk images from NIST CFReDS and Digital Corpora
   - Best for realistic layouts, fragmentation, recovery edge cases, and mixed filesystem behavior

3. Soak / performance runs
   - Larger images or corpora images with real-world clutter
   - Best for timing, RSS, and cache behavior

## Local Layout

Use the same layout for every fixture and dataset.

```text
testing/
  README.md
  datasets/
    README.md
    inventory.md
    <dataset-name>/
      manifest.json
      notes.md
  fixtures/
    README.md
    ext4/
      synthetic-basic/
        manifest.json
        expected/
          tree.txt
          paths.txt
          sha256.txt
  manifests/
    ext4-synthetic-basic.json
```

Rules:

- Keep the manifest next to the dataset or fixture it describes.
- Put expected results in a dedicated `expected/` subdirectory when they are small text files.
- Keep the manifest stable and human-readable.
- Do not store recovered contents in manifests.

## Manifest Format

RecoverMax testing uses a JSON manifest with three responsibilities:

- describe the image or fixture
- describe the known filesystem/session shape
- describe the checks we expect to pass

The recommended fields are:

- `id`: stable fixture id
- `kind`: `synthetic` or `public-corpus`
- `filesystem`: image type and block layout information
- `artifact`: expected session artifact file name
- `expected`: named checks and their expected values
- `notes`: anything not captured by the machine-readable fields

See `manifests/ext4-synthetic-basic.json` for a concrete example.

## Practical Validation Flow

For every new fixture or dataset:

1. Run `recovermax scan <image> -o <session.scn>`.
2. Reopen the session and verify `filesystems`, `ls`, `tree`, and `stat`.
3. Run a small set of recoveries and compare output hashes.
4. Run `unload` and repeat `tree`, `search`, and `recover`.
5. Compare filesystem listings and inode extraction against an oracle tool.

Current degraded-mode note:

- `scan -o` should be allowed to succeed even when a filesystem tree cannot be built.
- Report-only sessions are acceptable as long as the saved `.scn` remains valid and reopenable.
- Live fallback exists for report-only ext-family sessions. Keep checking corpus cases with deeper deleted-path reconstruction and partially corrupt directories.
- Deleted root-entry surfacing is now part of the CFReDS baseline, but path-based recovery of deleted entries still needs separate validation.

## What Usually Breaks

These are the highest-risk areas:

- v1 `.scn` compatibility
- path stability inside the persisted session tree
- deleted entry handling
- recursive directory traversal on corrupted metadata
- sparse file recovery
- symlink recovery
- large directory handling
- cache eviction and lazy rebuild after `unload`
- malformed filesystem metadata that should degrade to report-only behavior instead of failing the scan
