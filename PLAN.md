# RecoverMax — Master Plan

Cross-cutting roadmap for **recovermax** (AGPL core + CLI), **recovermax-gui** (proprietary
desktop app), and **recovermax.dev** (marketing site). Last revised 2026-04-13.

For architecture details, see `DESIGN.md`. For GUI stack rules, see
`~/Workspace/recovermax-gui/CLAUDE.md`.

---

## Instructions for Claude

**Before starting a task from this plan:**

1. Read the **Model** badge on the task (and its phase). If the currently active Claude
   model in this session doesn't match, STOP and ask the user to switch:
   > "This task is rated **Opus high**. You're on Sonnet high. Want me to continue on
   > Sonnet, or would you rather switch to Opus for this one? (Sonnet is often fine
   > — the rating is a suggestion, not a requirement.)"
2. After completing a task, ask the user whether to switch models for the next one if
   the tiers differ. Don't silently roll into the next task at the wrong model.
3. For work not explicitly in this plan (random bug fixes, small UI tweaks, quick
   questions), default to **Sonnet medium/high**. Only escalate to Opus when the work
   matches one of the Opus criteria in the "Model guidance" section below.

**Model guidance (rules of thumb):**

| Use | For |
|---|---|
| **Haiku / Sonnet medium** | Renames, trivial edits, YAML/config changes, lookups, explaining existing code |
| **Sonnet high** | Default for most feature work. GUI wiring, Tauri commands, CSS, content writing, small refactors, documentation |
| **Opus high** | Architectural decisions, correctness-critical code (filesystem parsers, forensic output), unfamiliar large refactors, API design, legal/evidentiary code |
| **Opus max** | Complex algorithm design (RAID reconstruction, novel parsers), debugging hard problems after Opus-high got stuck, single long careful outputs needing to be right first try |

**Rule of thumb for "do I need Opus?":** if you're staring at a long file and thinking
"I don't fully understand this yet," that's an Opus signal. If you're pattern-matching
against existing code in the repo, Sonnet is fine.

---

## Phase 0 — Current snapshot

### Shipped and in main
- ext4 full pipeline: superblock, inodes, extents, direct/indirect/double/triple maps
- ext4 sparse files, symlinks, deleted-inode scanning, raw scan without superblock
- NTFS boot sector, MFT entry parsing, data run decoding, file reading *(not yet wired to sessions/search/recovery)*
- MBR + GPT partition detection
- File carving: JPEG, PNG, PDF, ZIP, GIF, ELF, gzip, SQLite with smart sizing
- Streaming recovery (>1MB files stream, no OOM)
- Two-pass inode scan (tables + directory entries) for real filenames
- Streaming `.scn` session artifact via `ScnWriter`, lazy loading on read
- Memory budget + `MADV_DONTNEED` eviction every 100K nodes
- Tiebreaker scoring for orphan inodes (dtime, size, type, entropy)
- Forensic module: audit log, hash, HTML/PDF report scaffolding
- Journal parsing (JBD2) for filename hints
- Terminal UI: image picker, saved-scan reopen, interactive search
- One-shot CLI: info, scan, recover, carve, hexdump, deleted, raw-scan, search, ls, tree, stat, warnings, cache, unload, hash, filesystems
- 172 tests across 10 suites, GitHub Actions CI (Linux)

### GUI shipped (recovermax-gui)
- Tauri 2 + React 19 + TS + Vite scaffold
- Layout shell: menu bar, sidebar (tree), tab bar, status bar
- AG Grid Community wrapper with Proxmox-style theming
- Plain CSS design system via `tokens.css`
- Tauri commands: `list_images`, `list_block_devices`, `list_mounts`, `image_info`, `detect_partitions`, `list_session_files` (stub)
- Sidebar: Local Drives (physical + virtual APFS), Mounted Filesystems, user-added images/scans/directories
- Native file picker for images / `.scn` / directories
- Dropdown menus via Radix — File + Help wired, rest are placeholders
- Info tab: real image size + partition table
- Files/Deleted/Forensic tabs: placeholder content

### Known gaps in what's shipped
- `compute_path` has no depth cap — risk of repeating-path loops on corrupt disks *(memory flagged this, confirmed missing in audit)*
- `DESIGN.md` is untracked (never committed)
- 9 dead-code warnings in `recovermax-core` from old scan iterations
- CI tests Linux only — no macOS or Windows runner
- NTFS parser not wired to session or search or recovery
- GUI: no session loading → Files/Deleted tabs can't show real data
- GUI: no way to actually run a scan from the UI
- GUI: no sudo/privilege elevation path for raw device access
- GUI: no persistence of sidebar state across restarts
- GUI: no keyboard shortcuts
- No cross-platform release binaries — Linux only
- Website: exists but not yet filled with the SEO content strategy

---

## Phase 1 — Stabilize the core (unblock everything else)

Focus: three small PRs that close gaps before building on top of them.

### 1.1. Commit `DESIGN.md`
- Complexity: **tiny** · Model: **Haiku / Sonnet medium**
- Files: `DESIGN.md`
- Acceptance: in git history on `main`

### 1.2. Add depth cap in `compute_path` and recursive walks
- Complexity: **small** · Model: **Sonnet high**
- Files: `crates/recovermax-core/src/session/mod.rs` (compute_path), any recursive `walk_tree` sites
- Spec: `MAX_DEPTH = 256`. Return a clearly-marked truncation marker in the path rather than silently failing. Add a test constructing a cycle and verifying it terminates.
- Acceptance: a synthetic cycle test passes; `pydecimal.py x60` pathology no longer reproducible on a crafted test image

### 1.3. Clean up 9 dead-code warnings
- Complexity: **tiny** · Model: **Haiku / Sonnet medium**
- Files: `session/binary_reader.rs`, `session/mod.rs`, `fs/ext4.rs`
- Delete the unused code: `build_ext4_subtree_compact`, `append_ext4_all_inodes_compact`, `append_ext4_deleted_orphans_compact`, `MAX_TREE_DEPTH_COMPACT`, `BACKUP_SUPERBLOCK_OFFSETS`, `nodes_raw`, unused imports in `binary_reader.rs`, unused `image_path` in `session/mod.rs:46`
- Acceptance: `cargo build` emits zero warnings

### 1.4. Cross-platform CI
- Complexity: **small** · Model: **Sonnet high**
- Files: `.github/workflows/ci.yml`
- Spec: add `macos-latest` and `windows-latest` runners alongside `ubuntu-latest`. Run `cargo test` and `cargo clippy`. On Windows, may need to disable tests requiring UNIX-only `memmap` advise calls (gate with `cfg!(unix)`).
- Acceptance: all three OS matrix jobs green on main

### 1.5. Extract CLI logic into the library
- Complexity: **medium** · Model: **Opus high** — large unfamiliar refactor across two crates
- Files: `crates/recovermax-cli/src/cli.rs` (5,686 LOC) → move logic into `crates/recovermax-core/src/{session,recover,forensic,search}/*`
- Candidates to extract (from audit):
  - `tiebreaker_scored_orphan_candidate()` (~line 2295 of cli.rs) → `recovermax_core::recover::scoring`
  - orphan search logic → `recovermax_core::recover`
  - session open/load orchestration → `recovermax_core::session`
  - forensic audit trail setup → `recovermax_core::forensic`
- Spec: everything the GUI's `commands.rs` will need must be reachable via `recovermax_core::*`. CLI becomes a thin wrapper.
- Acceptance: `recovermax_core` is sufficient for the GUI (no `pub(crate)` needed in the CLI crate by consumers)

**Dependencies:** 1.2 blocks nothing; 1.5 blocks Phase 2.

---

## Phase 2 — Session loading (the big one)

Unlocks Files/Deleted tabs and most of the GUI. This is the single biggest leverage task.

### 2.1. Session-loading public API in core
- Complexity: **medium** · Model: **Opus high** — API design, long-term shape matters
- Files: `crates/recovermax-core/src/session/mod.rs`
- Spec: a clean entrypoint the GUI can call:
  ```rust
  pub fn open_session(scn_path: &Path) -> Result<RecoverySession>;
  pub fn browse_session_for_image(image_path: &Path, fs_index: usize) -> Result<RecoverySession>;
  ```
  Returning `RecoverySession` with:
  - `list_children(path: &str) -> Vec<SessionNode>`
  - `resolve(path: &str) -> Option<SessionNode>`
  - `search(pattern, options) -> Iterator<SessionNode>`
  - `deleted_inodes() -> Iterator<DeletedEntry>`
  - `cache_summary() -> CacheSummary`
- Acceptance: GUI can open a `.scn` file and list the root directory in <200 ms for a 12M-node session

### 2.2. Wire `list_session_files` in GUI
- Complexity: **small** (once 2.1 is done) · Model: **Sonnet high**
- Files: `recovermax-gui/src-tauri/src/commands.rs`
- Spec: replace stub. Pagination: accept `path`, `offset`, `limit`. Return total count + page of entries.
- Acceptance: Files tab shows real files from a loaded session

### 2.3. Directory tree navigation in Files tab
- Complexity: **medium** · Model: **Sonnet high** — UI pattern work
- Files: `recovermax-gui/src/tabs/FilesTab.tsx`
- Spec: split pane — tree on left (virtualized with TanStack Virtual), grid on right showing children of selected dir. Breadcrumb at top. Keyboard nav: arrows, enter to drill down, backspace to go up.
- Acceptance: can navigate a 12M-node session without jank

### 2.4. Deleted tab
- Complexity: **small** (once 2.1) · Model: **Sonnet high**
- Files: `recovermax-gui/src/tabs/DeletedTab.tsx`
- Spec: AG Grid of deleted inodes with columns: path (if resolvable), size, dtime, inode#, tiebreaker score. Sort by score descending by default.
- Acceptance: Reynolds `.scn` loaded → Deleted tab shows the million-inode orphan list sorted by recovery likelihood

### 2.5. Session persistence in GUI
- Complexity: **small** · Model: **Sonnet high**
- Files: `recovermax-gui/src-tauri/src/state.rs` (new), `recovermax-gui/src/lib/tauri.ts`
- Spec: write opened images + browsed directories to a JSON file in Tauri's app data dir (`app_config_dir() + "/sidebar.json"`). Load on startup.
- Acceptance: close the app, reopen, sidebar shows what was there before

**Dependencies:** 2.1 blocks 2.2, 2.3, 2.4. 2.5 is independent.

---

## Phase 3 — Core GUI workflows

With session loading in place, implement the actual user journeys.

### 3.1. Scan a new image from the UI
- Complexity: **medium** · Model: **Sonnet high** (Opus high if progress-event architecture gets hairy)
- Files: `recovermax-gui/src-tauri/src/commands.rs`, `recovermax-gui/src/tabs/InfoTab.tsx`
- Spec: "Scan…" button. Opens options dialog (Radix Dialog): deep scan y/n, memory budget, output `.scn` path (default auto). Uses `tauri::async_runtime::spawn` to run `Scanner::full_scan_with_options`. Emits progress events via `app.emit("scan-progress", ScanEvent)`. UI subscribes and shows progress bar + phase label in the status bar.
- Acceptance: can scan a 1GB test image, watch progress, end with a `.scn` file auto-loaded as a new sidebar entry

### 3.2. Recovery workflow
- Complexity: **medium** · Model: **Sonnet high**
- Files: `recovermax-gui/src/tabs/FilesTab.tsx`, new `RecoveryDialog.tsx`
- Spec: right-click a file (or multi-select) → "Recover…" → dialog asks for output directory + options (preserve permissions, overwrite behavior). Calls `recovermax_core::recover::recover_files`. Progress events per file.
- Acceptance: can recover a directory of 10K files from a session, see per-file progress, end with all files on disk

### 3.3. Forensic hash (streaming with progress)
- Complexity: **medium** · Model: **Sonnet high** — first real background task with progress events, template for others
- Files: `recovermax-gui/src-tauri/src/commands.rs`, `recovermax-gui/src/tabs/ForensicTab.tsx`
- Spec: "Hash Image (SHA-256)" button. Spawns async task that streams through the image in 4MB chunks updating a SHA-256 hasher. Emits `hash-progress` events every 100MB. Result stored in session artifact for future report use.
- Acceptance: hash a 1.9 TB image, see live progress in the status bar, end with hash displayed in InfoTab + ForensicTab

### 3.4. Forensic report generation
- Complexity: **medium** · Model: **Opus high** — legal/evidentiary correctness, NIST SP 800-86 compliance
- Files: `crates/recovermax-core/src/forensic/report.rs` (exists, may need finishing), `recovermax-gui/src/tabs/ForensicTab.tsx`
- Spec: "Generate Report…" → form: examiner name, case number, evidence ID, optional notes. Generates HTML and/or PDF per NIST SP 800-86. Contents: image metadata + hashes + partition table + scan summary + recovery actions + per-file hash list. PDF via `headless_chrome` or `weasyprint` subprocess. HTML first, PDF follow-up.
- Acceptance: an HTML report you'd be comfortable giving to a court or insurance adjuster

### 3.5. File preview pane
- Complexity: **medium** · Model: **Sonnet high**
- Files: new `PreviewPane.tsx`
- Spec: right pane in Files tab. Detects file type from magic bytes (first 4KB). Renders:
  - Text → syntax-highlighted (Prism or Shiki)
  - Images (JPEG/PNG/GIF) → blob URL
  - PDFs → `pdf.js` viewer
  - Everything else → hex dump
- Acceptance: clicking a `.txt` file shows its content without extracting it to disk; clicking a JPEG shows the image

### 3.6. "View → Refresh" and `queryClient.invalidateQueries`
- Complexity: **tiny**
- Files: `recovermax-gui/src/components/MenuBar/MenuBar.tsx`
- Acceptance: menu item re-fetches block devices + mounts immediately

### 3.7. Keyboard shortcuts
- Complexity: **small**
- Files: `recovermax-gui/src/App.tsx`, new `useHotkeys.ts`
- Spec: Cmd/Ctrl+O open image, Cmd/Ctrl+Shift+O open scan, Cmd/Ctrl+B browse, Cmd/Ctrl+R refresh, Cmd/Ctrl+W close current image, Cmd/Ctrl+F search, Cmd/Ctrl+Q quit
- Acceptance: all shortcuts work on macOS and Linux

### 3.8. Search bar (Cmd/Ctrl+F)
- Complexity: **small**
- Files: new `SearchBar.tsx`, uses `recovermax_core::search`
- Spec: top of Files tab. Live search as you type, debounced. Glob / exact / substring / case-insensitive toggle.
- Acceptance: Cmd+F focuses input; typing filters the grid

**Dependencies:** 3.1 depends on Phase 2. 3.2, 3.5, 3.7, 3.8 depend on 2.x. 3.3, 3.4 are independent of Phase 2.

---

## Phase 4 — Multi-filesystem parity

Right now ext4 is production-grade and NTFS is parser-only. Fill in the rest.

### 4.1. NTFS session integration
- Complexity: **medium**
- Files: `crates/recovermax-core/src/session/mod.rs`, `crates/recovermax-core/src/fs/ntfs.rs`
- Spec: build a `RecoverySessionArtifact` from NTFS the same way ext4 does — enumerate MFT, build tree, write to `.scn`. Handle directory index trees ($INDEX_ROOT, $INDEX_ALLOCATION).
- Acceptance: NTFS image → `recovermax scan image.img -o s.scn` → `recovermax ls -s s.scn /` works

### 4.2. NTFS deleted scanning
- Complexity: **small** (after 4.1)
- Spec: iterate MFT, surface entries with flag 0 (not in use) but with recoverable data runs.
- Acceptance: deleted files show up in the GUI Deleted tab from an NTFS image

### 4.3. FAT32 parser
- Complexity: **medium**
- New file: `crates/recovermax-core/src/fs/fat32.rs`
- Spec: BPB parse, FAT table, directory entries (8.3 + LFN), deleted (first byte 0xE5) scanning
- Acceptance: can read an intact FAT32 USB stick and recover a recently-deleted file

### 4.4. XFS parser
- Complexity: **large**
- New file: `crates/recovermax-core/src/fs/xfs.rs`
- Spec: AG superblock, inode B-trees, extent lists. Popular server FS, commonly encountered.
- Acceptance: pass basic-read test on a sample XFS image; deleted scanning is stretch

### 4.5. APFS parser
- Complexity: **large**
- New file: `crates/recovermax-core/src/fs/apfs.rs`
- Spec: container layer, volume superblocks, object maps, snapshots. Complex but unlocks macOS.
- Acceptance: can read a Time Machine APFS image

### 4.6. Deeper ext4 journal replay
- Complexity: **medium**
- Files: `crates/recovermax-core/src/fs/ext4.rs`
- Spec: beyond filename hints — replay the journal to reconstruct the most recent valid filesystem state before corruption. Useful when primary metadata is damaged but journal is intact.
- Acceptance: on a corrupted ext4 test image, journal replay recovers files the current scan misses

**Dependencies:** 4.1 blocks 4.2. Others parallel.

---

## Phase 5 — Advanced recovery features

### 5.1. RAID reconstruction
- Complexity: **large**
- New module: `crates/recovermax-core/src/raid/`
- Spec: detect mdadm superblocks, reconstruct RAID 0/1/5/6 from a set of member images. Expose as a virtual `ImageReader` so all downstream code works unchanged.
- Acceptance: 3 images of a RAID5 set → reconstructed volume scannable as one image

### 5.2. LVM support
- Complexity: **medium**
- Spec: parse LVM2 metadata, map logical volumes to physical extents. `ImageReader` adapter.
- Acceptance: the reynolds-sdb LVM case works end-to-end in the GUI

### 5.3. Bad sector handling
- Complexity: **medium**
- Files: `crates/recovermax-core/src/io/mod.rs`
- Spec: on read failure, record bad sector, skip/zero the block, continue scan. Integrate with `ddrescue` map files — if a map says "bad", skip proactively.
- Acceptance: an image with simulated EIO regions scans without aborting

### 5.4. File validation
- Complexity: **small-medium**
- Spec: after recovery, optionally verify each file matches its declared format (JPEG has valid SOI/EOI, PDF has `%PDF-` header and `%%EOF` trailer, ZIP has central directory, etc.). Produce a validation report.
- Acceptance: recovered a carved directory → 98% validate clean, 2% flagged as truncated

### 5.5. E01/EWF support
- Complexity: **medium**
- Files: `crates/recovermax-core/src/io/ewf.rs` (new), or use `libewf` via FFI
- Spec: read E01 forensic images (compressed, segmented, hash-verified). Write support is stretch.
- Acceptance: can open an E01 image as transparently as a raw `.img`

**Dependencies:** Mostly independent. 5.2 can inform the GUI workflow.

---

## Phase 6 — Cross-platform release

### 6.1. Windows build
- Complexity: **medium**
- Files: `.github/workflows/release.yml`, maybe `crates/recovermax-core/src/io/mod.rs` for mmap quirks
- Spec: build `recovermax.exe` on Windows CI. Handle NTFS path separators. Verify mmap works on Windows (`memmap2` supports it).
- Acceptance: a Windows user can download and run `recovermax info file.img`

### 6.2. macOS signed + notarized build
- Complexity: **medium** (infra) + process time
- Files: `.github/workflows/release.yml`, Tauri signing config
- Spec: Apple Developer ID certificate. CI signs, notarizes with Apple, staples. Both CLI and GUI.
- Acceptance: `curl | sh` install works on a fresh Mac without Gatekeeper blocking

### 6.3. Linux AppImage + .deb
- Complexity: **small** (Tauri does most of this)
- Spec: `.deb` for Debian/Ubuntu, AppImage for portability, `.rpm` for Fedora.
- Acceptance: `apt install ./recovermax.deb` works

### 6.4. Auto-update for GUI
- Complexity: **small** — Tauri has a first-class updater
- Files: `recovermax-gui/src-tauri/tauri.conf.json`
- Spec: check `updates.recovermax.dev/manifest.json` on launch. Signed update bundles. User gets a "new version available" toast.
- Acceptance: push a new version → existing installs auto-update on next launch

### 6.5. Raw device permission elevation (GUI)
- Complexity: **medium** (platform-specific)
- Spec:
  - macOS: prompt for Full Disk Access when user clicks a `/dev/disk` — open System Settings directly via `tauri_plugin_opener::OpenerExt::open_url("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")`. Alternatively, bundle a helper tool with `SMJobBless`.
  - Linux: detect EACCES, suggest `sudo` or `disk` group membership in a dialog.
  - Windows: UAC elevation via a relaunch as admin.
- Acceptance: clicking `/dev/disk0` gives a useful next-step dialog instead of a bare error

**Dependencies:** 6.1-6.3 are independent. 6.4 needs 6.1-6.3 done. 6.5 is independent.

---

## Phase 7 — Website, marketing, distribution

### 7.1. recovermax.dev content buildout
- Complexity: **medium** — content, not code
- Files: `website/` (Next.js)
- Pages needed:
  - Homepage: positioning as R-Linux replacement, clear value prop, screenshots, download buttons
  - Features: forensic capabilities, filesystem support matrix, CLI examples
  - Documentation: install, quickstart, CLI reference, `.scn` format, forensic workflow guide
  - Comparison pages: vs R-Linux, vs Photorec, vs Disk Drill, vs Autopsy
  - Blog: "How to recover deleted ext4 files", "NTFS recovery guide", "Forensic disk imaging best practices", "What is a backup superblock and why does it matter"
  - Pricing page (once GUI ships): free CLI, $X/license GUI with features comparison
  - Legal: privacy, ToS, EULA for GUI
- Acceptance: search `"free linux data recovery"` shows recovermax.dev in top 10 within a few months of launch

### 7.2. GitHub release automation
- Complexity: **small**
- Spec: on tag push, CI builds all three platforms, uploads to GitHub Releases, writes changelog
- Acceptance: `git tag v0.2.0 && git push --tags` produces release assets and a release page

### 7.3. GUI license + key gate
- Complexity: **medium**
- Files: `recovermax-gui/src-tauri/src/license.rs` (new)
- Spec: ed25519-signed license JSON. Contains: email, purchase date, expiry (or perpetual), allowed machines. On first launch, user pastes key. Verifies signature against embedded pubkey. Gating: trial mode with nag + watermark, paid mode clean.
- Acceptance: can sell a key, user activates, app shows their name in About
- Consider: lemonsqueezy or Paddle for payment + license delivery to avoid building billing yourself

### 7.4. Community presence
- Complexity: **medium** — ongoing effort
- Spec:
  - Release post on r/datarecovery, r/linux, r/rust, r/sysadmin, r/netsec, r/computerforensics (genuine, at launch only)
  - Show HN post when GUI launches
  - UCSB SecLab blog post about the reynolds recovery that inspired it
  - Conference talk: BSides, local security meetups, DEFCON Recovery Village if accepted
- Acceptance: meaningful inbound traffic + signups

### 7.5. CLA for core contributions
- Complexity: **small**
- Files: `CLA.md` in recovermax repo, `.github/workflows/cla.yml`
- Spec: cla-assistant.io bot or similar. Every non-trivial PR signs CLA granting Kyle right to dual-license. Protects the proprietary GUI revenue model.
- Acceptance: any new contributor must sign before merge

**Dependencies:** 7.3 depends on 6.2 (signed mac build). Others parallel.

---

## Phase 8 — Long-horizon features

These are the "aspirational moat" — nice-to-have, differentiators, research-y.

### 8.1. FUSE mount of recovered filesystem
- Complexity: **large**
- Spec: expose a `.scn` session as a read-only FUSE mount. Users `cd` into the recovered tree, use `grep`/`find`/`cp` natively.
- Acceptance: `recovermax mount session.scn /mnt/recovered && ls /mnt/recovered` works

### 8.2. Remote SSH recovery
- Complexity: **medium**
- Spec: open an image over SSH without copying it locally. Tauri's async HTTP or a thin `ssh` wrapper.
- Acceptance: `recovermax info ssh://welles/projects/reiner-recovery/reiner-sda.img` works end-to-end

### 8.3. Python bindings
- Complexity: **medium**
- Tool: PyO3
- Spec: `pip install recovermax-py` → `from recovermax import open_image, recover_file`. Let researchers script against the core.
- Acceptance: publish to PyPI, example notebook runs

### 8.4. Mobile forensics
- Complexity: **large** — new FS family
- Spec: Android image parsers (sparse, EROFS, F2FS). iOS APFS variants + encryption metadata (without bypassing encryption).
- Acceptance: can parse an F2FS Android image

### 8.5. AI-assisted triage
- Complexity: **medium-large**
- Spec: LLM summarizes "what's notable about this image" — e.g., "37 SSH private keys, 4 browser password databases, 1,200 image files with recent timestamps." Run locally or via API per user choice.
- Acceptance: toggling "AI triage" on a scanned image produces a useful one-page summary

---

## Dependency graph (top-level)

```
Phase 1 (stabilize) ── blocks everything downstream in quality, not in API surface
    ├── 1.2 depth cap       → prevents pathology in 2.x, 3.x
    ├── 1.5 extract CLI     → blocks Phase 2, 3
    │
Phase 2 (session loading)   ← unlocks Files/Deleted tabs
    ├── 2.1 API             → blocks 2.2-2.4, 3.1-3.2, 3.5, 3.8
    │
Phase 3 (GUI workflows)     ← ship a useful v0.2 GUI
    ├── 3.3 hash (independent of 2.x — can ship first for a "win")
    │
Phase 4 (multi-FS)          ← ship v0.3 "NTFS-in-GUI" then later FAT/XFS/APFS
Phase 5 (advanced)          ← mostly independent, RAID is the big win
Phase 6 (releases)          ← platform infra; 6.1-6.3 gate public availability
Phase 7 (marketing)         ← depends on 6.1-6.3; CLA (7.5) should land ASAP
Phase 8 (long horizon)      ← after product-market fit
```

---

## Suggested ordering — what to do first

Given the current state, this is the order with the most leverage:

1. **Phase 1.1 + 1.3** (tiny cleanup, half a day): commit DESIGN.md, delete dead code warnings
2. **Phase 7.5** (CLA setup): critical for any future contributor — do before anyone else touches core
3. **Phase 1.2** (depth cap): small but a known correctness hole
4. **Phase 1.4** (cross-platform CI): prerequisite for 6.1-6.3. Do it before you have Windows bugs to fix blind
5. **Phase 1.5** (extract CLI logic): the gating item for most GUI work
6. **Phase 3.3** (forensic hash): small win, first real progress-events pipeline in the GUI, template for future async tasks
7. **Phase 2.1** (session loading API): biggest single unlock
8. **Phase 2.2 + 2.4** (wire Files and Deleted tabs): suddenly the GUI has 3 useful tabs
9. **Phase 3.1** (scan from UI): end-to-end loop: open image → scan → browse → recover
10. **Phase 3.2** (recovery workflow): first actual "do work" feature
11. **Phase 6.1 + 6.2 + 6.3** (release all three platforms): you can now ship v0.2
12. **Phase 4.1 + 4.2** (NTFS wiring): broadens TAM significantly
13. **Phase 3.4** (forensic report): real differentiator
14. **Phase 7.1** (website content): concurrently with 12
15. **Phase 7.3** (license gate): required before selling
16. **Phase 6.4** (auto-update): required for smooth ongoing deliveries

**First shippable GUI release (v0.2.0):** after step 11. That's probably the right "public alpha" milestone.

**First paid GUI release (v1.0.0):** after step 15 + solid Phase 4.1.

---

## Recurring work (no phase, always on)

- **Testing**: every new feature ships with unit tests. Integration test images grown in `test-images/` (gitignored).
- **Documentation**: every public API in core gets rustdoc. GUI tabs get inline help via tooltips.
- **Changelog**: human-readable `CHANGELOG.md` kept in sync with tags.
- **Performance regression tracking**: a benchmark CI job running on a fixed 1 GB test image, alerts if scan time regresses >10%.
- **Security**: dependency audit monthly (`cargo audit`, `npm audit`); no blindly-accepted PRs.
- **Real-world testing**: run each new release against the reynolds/reiner/robbins images before tagging.

---

## Open questions / decisions still to make

- **Pricing model**: perpetual license vs annual subscription vs maintenance model. R-Studio uses perpetual+maintenance; Disk Drill uses annual. I'd lean perpetual with optional maintenance.
- **License key distribution**: self-host or Lemon Squeezy / Paddle? Third party saves billing headache.
- **Telemetry**: opt-in crash reports (Sentry?) or none at all? Forensic users will be paranoid; leaning NONE by default, opt-in explicit.
- **GUI tech stack double-check**: Tauri 2 is committed; if it hits a wall on Windows webview, fallback would be Slint or egui (would be a big rewrite).
- **E01 support via `libewf` FFI vs pure-Rust reimplementation**: FFI is faster to ship; pure-Rust is safer and keeps Windows simpler.
- **How much of `recovermax-cli` should stay open vs. move into the proprietary GUI**: current plan is open CLI + AGPL core + proprietary GUI. That should hold.

---

*This plan is a living document. Revise when reality contradicts it.*
