# CFReDS dfr-01-ext Notes

- Source: CFReDS DFR Test Images
- Local file: `dfr-01-ext.dd`
- Size: 1.0 GiB
- Known layout: three Linux partitions at offsets 30.5 KiB, 318.0 MiB, and 636.0 MiB
- Filesystem mix: ext2, ext3, and ext4
- Oracle tools used locally: `mmls`, `fls`, `istat`

## What Currently Works

- `recovermax info` detects the partition table and lists the three Linux partitions.
- `recovermax scan` completes and identifies all three filesystems.
- `recovermax scan -o <session.scn>` succeeds and now saves a tree-backed session for all three partitions.
- Reopening the saved `.scn` works with `filesystems`, `ls`, `tree`, `stat`, `search`, and `recover`.
- On the ext2 partition, `ls / --fs 0` shows `/Algol.txt`, `/Bellatrix.txt [deleted]`, `/Canopus.txt`, and `/lost+found`.
- Recovering `/Algol.txt` from the saved session produces a 512-byte file locally.
- `recovermax deleted --fs 0` now reports inode `13` together with the synthetic session path `/$OrphanFiles/OrphanFile-13`, so the deleted-inode scan and session workflow line up.
- `recovermax deleted` without `--fs` now refuses to guess on this image and tells you to choose among filesystems `0`, `1`, and `2`, which avoids silently scanning the wrong ext partition.
- Deleted root entries from all three partitions are now surfaced in search:
  - ext2: `/Bellatrix.txt`
  - ext3: `/Bunda.txt`
  - ext4: `/Botein.txt`
- Search output now preserves deleted-entry provenance:
  - ext2 `/Bellatrix.txt` is reported as `[deleted] [slack parent=2]`
  - ext2 `/$OrphanFiles/OrphanFile-13` is reported as `[deleted] [orphan]`
- Reopened sessions now preserve deleted-entry provenance:
  - ext2 `/Bellatrix.txt` is marked as a `deleted-slack` residual under parent inode `2`
  - ext2 orphan recovery still resolves through `/$OrphanFiles/OrphanFile-13`
- Deleted-path recovery behavior is now explicit instead of ambiguous:
  - `stat /Bellatrix.txt --fs 0` reports the residual as deleted-slack and includes `Recovery hint: Try /$OrphanFiles/OrphanFile-13 instead.`
  - `recover -p /Bellatrix.txt --fs 0` now auto-resolves the unique orphan candidate and produces the same 712-byte output as `/$OrphanFiles/OrphanFile-13`.
  - ext2 exposes `/$OrphanFiles/OrphanFile-13 [deleted]`, and recovering that path produces a 712-byte file locally.
  - `/Bunda.txt` and `/Botein.txt` resolve to deleted inodes, but Sleuth Kit also reports those inodes as size 0, so zero-byte recovery output is expected on this corpus.

## Current Gaps

- This corpus is still useful for malformed or legacy ext-family hardening because it exercises ext2, ext3, and ext4 from one image.
- We still need broader coverage for deeper deleted-path reconstruction and partially corrupt directories.
- Deleted root-entry names are surfaced and searchable. Unique residual-to-orphan recovery now works on the ext2 partition, but broader deleted-path recovery remains only partially validated on this corpus because the preserved ext3/ext4 deleted inodes are zero-length and multi-candidate name binding is still heuristic.
- The ext2 residual-name case is now better explained in the saved session because provenance survives reopen, but true name-to-orphan binding is still heuristic rather than guaranteed.

## What Should Improve Next

- Preserve partial node materialization when one subtree is corrupt instead of dropping the whole filesystem tree.
- Add path and inode-grounded expectations from the CFReDS oracle outputs for all three partitions.
