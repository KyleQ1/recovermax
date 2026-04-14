# RecoverMax — Master Plan

Cross-cutting roadmap for **recovermax** (AGPL core + CLI), **recovermax-gui** (proprietary
desktop app), and **recovermax.dev** (marketing site). Last revised 2026-04-14.

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

## Phase 0 — Current snapshot (as of 2026-04-14)

### Shipped and in main (recovermax core + CLI)
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
- 327 tests across 19 suites, GitHub Actions CI (Linux + macOS + Windows)
- Zero build warnings, clippy `-D warnings` gated
- CLA workflow with SHA-pinned action + sentinel + Dependabot
- All deps current (nom 8, sha2 0.11, indicatif 0.18, console 0.16, actions v6+)

### Core library public API (extracted from CLI, consumed by GUI)
- `recover::scoring` — 4 scoring functions + weights + median helper (10 tests)
- `recover::orphans` — content-type sniffing, sibling context, composite tiebreaker (9 tests)
- `session::open` — `open_session()`, `browse_session_for_image()`, `open_session_for_image()`, `open_session_from_saved()`, `parse_memory_budget()`, `is_binary_scn()` (6 tests)
- `forensic::session` — `start_image_audit()`, `ForensicIdentity`, `ImageAudit` (4 tests)
- `RecoverySession::has_tree()`, `::live_ext4()`, `::deleted_inodes()`
- `ScanEvent` + `ScanPhase` derive Serialize/Deserialize with `#[serde(tag = "type")]`
- `ScanOptions::cancel_flag: Option<Arc<AtomicBool>>` — cooperative scan cancellation
- `MAX_PATH_DEPTH=256`, `PATH_TRUNCATED_MARKER` — cycle-safe compute_path

### Shipped in recovermax-gui (proprietary, Tauri 2 + React 19)
- Layout shell: menu bar, sidebar (tree), tab bar, status bar
- AG Grid Community wrapper with Proxmox-style theming
- Plain CSS design system via `tokens.css`
- Sidebar: Local Drives (physical + virtual APFS), Mounted Filesystems, user-added images/scans/directories
- Native file picker for images / `.scn` / directories
- Dropdown menus via Radix — File + Help wired
- **Info tab**: image size, partition table, Scan… button with options dialog
- **Scan progress UI (R-Studio-style)**: 200-cell block map coloured by FS type (ext4 green, NTFS blue, LVM magenta, file-sig amber), MB/GB/TB byte counts (never inodes), elapsed clock, 30s rolling-window ETA, phase label, filesystem list, cancel with confirmation prompt, dismiss button, .scn save with green confirmation
- **Scan options dialog**: deep-scan checkbox, deleted-only fast mode checkbox, memory budget, .scn output path with native save picker
- **Cancel**: cooperative — flips AtomicBool, core bails at next check-point, GUI shows CANCELLED badge
- **Deleted-only fast scan**: finds filesystems → enumerates deleted inodes directly (skips tree build). ~30 seconds on TB drives vs 30+ minutes for full scan.
- **Auto-load session**: after .scn save, auto-calls `load_session` → Files/Deleted tabs populate
- **Files tab**: filesystem picker dropdown, breadcrumb path, double-click to drill down, Backspace to go up, AG Grid with real data from active session
- **Deleted tab**: AG Grid with inode#, type, size, dtime/mtime/atime from `RecoverySession::deleted_inodes()`, sorted by dtime descending
- **macOS Full Disk Access nudge**: detects /dev/disk* permission errors, shows Radix Dialog with OS-specific instructions + "Open System Settings" button via x-apple.systempreferences: URL
- App-managed state: `AppState { active_scan, active_session, active_session_path }`
- Tauri commands: `list_images`, `list_block_devices`, `list_mounts`, `image_info`, `detect_partitions`, `list_session_files` (real), `list_session_filesystems`, `list_deleted_inodes`, `start_scan`, `cancel_scan`, `load_session`

### Known gaps / things NOT shipped yet
- ❌ Recovery from the GUI (right-click → Recover…) — this is the #1 blocker for usefulness
- ❌ NTFS not wired to sessions/search/recovery — ext4 only in the GUI
- ❌ No file preview pane
- ❌ No search bar in Files tab
- ❌ No keyboard shortcuts
- ❌ No sidebar persistence across restarts
- ❌ No forensic hash from the GUI
- ❌ No forensic report generation from the GUI
- ❌ No cross-platform release binaries (dev mode only)
- ❌ Website content not built out
- ❌ No license key gate for paid GUI
- ❌ Untested on real TB-scale images from the GUI (only CLI tested against reiner/reynolds/robbins)

---

## Phase 1 — Stabilize the core ✅ COMPLETE

All tasks done 2026-04-13:
- ✅ 1.1. Commit DESIGN.md + PLAN.md
- ✅ 1.2. Depth cap in compute_path (MAX_PATH_DEPTH=256, cycle detection, PATH_TRUNCATED_MARKER, 3 tests)
- ✅ 1.3. Zero build warnings (535 LOC deleted)
- ✅ 1.4. Cross-platform CI (Ubuntu + macOS + Windows; caught real Windows path-separator bug)
- ✅ 1.5. Extract CLI logic into core library (4 new modules, 29 tests, ~960 LOC moved)

---

## Phase 2 — Session loading ✅ MOSTLY COMPLETE

- ✅ 2.1. Session-loading public API (`open_session`, `browse_session_for_image`, etc.)
- ✅ 2.2. Wire `list_session_files` in GUI (real data, accepts fs_index + path)
- ✅ 2.3. Files tab navigation (filesystem picker, breadcrumb, drill-down, backspace up) — tree pane not done yet, just grid + breadcrumb
- ✅ 2.4. Deleted tab (real data from `deleted_inodes`, AG Grid, sorted by dtime)
- ⬜ 2.5. Session persistence in GUI — sidebar state across restarts

**Remaining:** 2.5 is independent and low priority (nice UX, not blocking anything).

---

## Phase 3 — Core GUI workflows — NEXT PRIORITY

### ✅ 3.1. Scan from UI — COMPLETE
Done 2026-04-13/14. Options dialog, progress panel, block map, cancel, .scn save, auto-load, deleted-only fast mode, macOS FDA nudge.

### ⬜ 3.2. Recovery workflow — **NEXT UP, HIGHEST LEVERAGE**
- Complexity: **medium** · Model: **Sonnet high**
- Files: `recovermax-gui/src/tabs/FilesTab.tsx`, new `RecoveryDialog.tsx`, new `recover_files` Tauri command
- Spec: right-click a file (or multi-select) → "Recover…" → dialog asks for output directory. Calls `recovermax_core::recover` via Tauri command. Progress events per file. AG Grid context menu via Radix.
- Acceptance: can recover a directory of files from a session, see per-file progress, end with all files on disk
- **Why this is #1:** without this, the GUI is a viewer, not a recovery tool. Everything else is polish until this ships.

### ⬜ 3.3. Forensic hash (streaming with progress)
- Complexity: **medium** · Model: **Sonnet high**
- Spec: "Hash Image (SHA-256)" button in ForensicTab. Background task, progress events every 100MB.
- Acceptance: hash a 1.9 TB image with live progress.

### ⬜ 3.4. Forensic report generation
- Complexity: **medium** · Model: **Opus high** — legal/evidentiary correctness
- Spec: NIST SP 800-86 compliant HTML report. Chain of custody fields.
- Acceptance: report suitable for court/insurance.

### ⬜ 3.5. File preview pane
- Complexity: **medium** · Model: **Sonnet high**
- Spec: text (syntax-highlighted), images (blob URL), PDFs (pdf.js), everything else hex dump.
- Acceptance: click a .txt → see content inline.

### ⬜ 3.6. View → Refresh
- Complexity: **tiny**
- Acceptance: menu item invalidates queries.

### ⬜ 3.7. Keyboard shortcuts
- Complexity: **small**
- Spec: Cmd/Ctrl+O, Cmd/Ctrl+F, Cmd/Ctrl+R, etc.

### ⬜ 3.8. Search bar
- Complexity: **small**
- Spec: top of Files tab, debounced, glob/exact toggle.

**Priority order:** 3.2 → 3.5 → 3.8 → 3.3 → 3.7 → 3.6 → 3.4

---

## Phase 4 — Multi-filesystem parity

### ⬜ 4.1. NTFS session integration
- Complexity: **medium** · Model: **Opus high**
- Spec: enumerate MFT → build tree → write .scn. Handle $INDEX_ROOT/$INDEX_ALLOCATION.
- Acceptance: NTFS image scans + browses in GUI.

### ⬜ 4.2. NTFS deleted scanning
- Complexity: **small** (after 4.1)
- Spec: MFT entries with flag 0, recoverable data runs.

### ⬜ 4.3. FAT32 parser
- Complexity: **medium**
- Spec: BPB, FAT table, 8.3+LFN, deleted (0xE5) scanning.

### ⬜ 4.4. XFS parser — **large**
### ⬜ 4.5. APFS parser — **large**
### ⬜ 4.6. Deeper ext4 journal replay — **medium**

---

## Phase 5 — Advanced recovery features

### ⬜ 5.1. RAID reconstruction — **large**
### ⬜ 5.2. LVM support — **medium**
### ⬜ 5.3. Bad sector handling — **medium**
### ⬜ 5.4. File validation — **small-medium**
### ⬜ 5.5. E01/EWF support — **medium**

---

## Phase 6 — Cross-platform release

### ⬜ 6.1. Windows build — **medium**
### ⬜ 6.2. macOS signed + notarized build — **medium**
### ⬜ 6.3. Linux AppImage + .deb — **small**
### ⬜ 6.4. Auto-update for GUI — **small**
### ✅ 6.5. Raw device permission elevation (GUI) — COMPLETE (macOS FDA nudge shipped)

---

## Phase 7 — Website, marketing, distribution

### ⬜ 7.1. recovermax.dev content buildout — **medium**
### ⬜ 7.2. GitHub release automation — **small** (release.yml exists, needs changelog)
### ⬜ 7.3. GUI license + key gate — **medium**
### ⬜ 7.4. Community presence — **medium** (ongoing)
### ✅ 7.5. CLA for core contributions — COMPLETE (in-repo signatures, SHA-pinned action, sentinel workflow, Dependabot)

---

## Phase 8 — Long-horizon features

### ⬜ 8.1. FUSE mount — **large**
### ⬜ 8.2. Remote SSH recovery — **medium**
### ⬜ 8.3. Python bindings — **medium**
### ⬜ 8.4. Mobile forensics — **large**
### ⬜ 8.5. AI-assisted triage — **medium-large**

---

## What to do next (priority order)

| # | Task | Why | Effort |
|---|---|---|---|
| 1 | **Run `npm run tauri dev` and test the GUI** | ~700 LOC of untested GUI code from this session. Real bugs surface here, not in typechecks. | 30 min |
| 2 | **3.2 Recovery workflow** | Without this the GUI is a viewer. This makes it a product. | 2-3 hours |
| 3 | **3.5 File preview pane** | Users want to see what they're recovering before committing. | 2 hours |
| 4 | **3.8 Search bar** | "Find my file" is the second most common flow after "recover it." | 1 hour |
| 5 | **4.1 NTFS session integration** | Doubles the addressable market. Parser exists, just needs wiring. | 3-4 hours |
| 6 | **2.5 Sidebar persistence** | Quality-of-life for repeat users. | 1 hour |
| 7 | **6.1-6.3 Cross-platform release** | Can't ship without this. Tag v0.2.0 after recovery workflow works. | 2-3 hours |
| 8 | **7.1 Website content** | People can't buy what they can't find. | Ongoing |
| 9 | **7.3 License gate** | Required before selling. | 2-3 hours |

**First shippable alpha (v0.2.0):** after #1-3 are done + a test pass on a real TB image.
**First paid release (v1.0.0):** after #5 + #7 + #9.

---

## Recurring work (no phase, always on)

- **Testing**: every new feature ships with unit tests. Integration test images grown in `test-images/` (gitignored).
- **Documentation**: every public API in core gets rustdoc. GUI tabs get inline help via tooltips.
- **Changelog**: human-readable `CHANGELOG.md` kept in sync with tags.
- **Performance regression tracking**: a benchmark CI job running on a fixed 1 GB test image, alerts if scan time regresses >10%.
- **Security**: dependency audit monthly (`cargo audit`, `npm audit`); no blindly-accepted PRs. CLA sentinel monitors bot commits.
- **Real-world testing**: run each new release against the reynolds/reiner/robbins images before tagging.

---

## Open questions / decisions still to make

- **Pricing model**: perpetual license vs annual subscription vs maintenance model. R-Studio uses perpetual+maintenance; Disk Drill uses annual. Leaning perpetual with optional maintenance.
- **License key distribution**: self-host or Lemon Squeezy / Paddle? Third party saves billing headache.
- **Telemetry**: opt-in crash reports (Sentry?) or none at all? Forensic users will be paranoid; leaning NONE by default, opt-in explicit.
- **GUI tech stack double-check**: Tauri 2 is committed; if it hits a wall on Windows webview, fallback would be Slint or egui (would be a big rewrite).
- **E01 support via `libewf` FFI vs pure-Rust reimplementation**: FFI is faster to ship; pure-Rust is safer and keeps Windows simpler.
- **Files tab tree pane**: Phase 2.3 shipped with breadcrumb + grid drill-down but not the split-pane tree view. TanStack Virtual tree on the left is the plan but not urgent — breadcrumb navigation works and R-Studio itself uses this pattern for simple images.

---

*This plan is a living document. Revise when reality contradicts it.*
