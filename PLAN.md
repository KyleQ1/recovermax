# RecoverMax — Product Plan

Cross-cutting roadmap for:
- **recovermax** — AGPL core library + CLI
- **recovermax-gui** — proprietary desktop GUI
- **recovermax.dev** — marketing / docs site

Last revised: **2026-04-15**

For architecture details, see `DESIGN.md`.

---

## Product direction

RecoverMax should feel like a real recovery workstation, not just a scan runner.

The intended model is:
- pick a **drive** or **image**
- inspect **drive details** first
- scan or load a saved session
- browse **partitions / filesystems / directories**
- inspect, preview, recover, and report

The UI should separate two modes clearly:
- **resource mode**: drives, mounted devices, disk images
- **session mode**: partitions, filesystems, directories, deleted entries

Top-level drive selection should show drive-oriented information on the right.
Recovery-oriented tabs should appear only when there is a loaded session for the selected source.

---

## Planning rules

When working from this plan:

1. Prefer shipping user-visible workflow improvements over speculative abstractions.
2. Preserve current working ext4 flows unless the task explicitly justifies a larger refactor.
3. Treat correctness-critical parser / forensic work as higher risk than GUI polish.
4. Keep the GUI aligned with recovery software conventions:
   - left: hierarchy / navigation
   - right: details, browser, preview, recovery actions
5. Do not silently regress raw-disk access flows on macOS while improving the layout.

Model guidance:

| Model | Use for |
|---|---|
| Sonnet medium/high | Most GUI work, wiring, styling, documentation, Tauri commands |
| Opus high | Filesystem integration, forensic output, parser correctness, major architecture |
| Opus max | RAID, APFS, novel parsers, especially hard debugging |

---

## Current state

### Core / CLI

Shipped and working:
- ext4 recovery pipeline end-to-end
- ext4 deleted inode scanning
- raw inode-table scan without superblock
- MBR + GPT partition detection
- file carving for common formats
- streaming recovery for large files
- `.scn` session artifacts with lazy loading
- binary `.scn` files now embed source-image metadata
- legacy binary `.scn` files still reopen via basename inference fallback
- memory-budgeted session loading
- CLI workflows for info, scan, recover, search, deleted, carve, hexdump, filesystems, hash
- CI on Linux, macOS, Windows

Partially shipped:
- NTFS parsing exists, but it is not yet integrated into session browsing, search, deleted flows, or recovery
- forensic/reporting foundations exist in core, but the GUI does not expose them meaningfully yet

### GUI

Shipped and working:
- app shell with menu bar, command bar, sidebar, tab strip, activity log, status bar
- local drives, mounted filesystems, user-opened images, and directories in the sidebar
- show/hide virtual disks
- raw-drive access guidance on macOS
- drive details tab and S.M.A.R.T. tab for drive-like selections
- image info tab for image-like selections
- scan dialog with deep scan, deleted-only, memory budget, optional `.scn` save
- scan progress panel with block map, throughput, ETA, phase, filesystem list, cancel
- full scan without `.scn` now keeps an in-memory session
- full scan with `.scn` immediately loads the saved session
- `.scn` open flow resolves the source image first and confirms mismatches
- left-side session tree with partitions, filesystems, and directories
- files tab with breadcrumb navigation and AG Grid listing
- deleted tab backed by real session data
- recovery workflow from selected file rows
- refresh action

Working but still rough:
- tree alignment / indentation needs polish
- drive-details presentation is functional but not yet at R-Studio quality
- session browsing is image/session-aware, but right-pane mode switching still needs refinement and cleanup

Not shipped:
- preview pane
- search bar
- forensic hash UI
- forensic report generation UI
- keyboard shortcuts
- sidebar persistence
- packaged release builds
- NTFS session integration
- website / sales / licensing flows

---

## Product principles

These principles should drive feature decisions:

### 1. Drive-first, then recovery

When the user clicks a raw drive, show:
- drive details
- S.M.A.R.T. / health
- scan controls

Do not default a raw drive directly into a recovery browser unless a session is already loaded for that drive.

### 2. Sessions are implementation support, not the primary concept

`.scn` should remain important, but optional.

Default user mental model:
- open image / choose drive
- scan
- browse

Advanced persistence model:
- save `.scn`
- reopen `.scn`
- reuse expensive scans

### 3. The left tree is the source of truth for navigation

The left pane should eventually feel like:
- drives / images
- partitions
- filesystems
- directories
- optionally deleted / evidence / bookmarks

Clicking the tree should deterministically drive the right pane.

### 4. Forensic features must be explicit

Do not auto-run expensive forensic work by default.

Examples:
- hashing should be opt-in
- report generation should be explicit
- verification should be user-controlled

### 5. Keep ext4 strong while building parity

Do not dilute the existing ext4 experience while chasing more filesystem support.
NTFS is the next real expansion target because it increases addressable use cases most.

---

## Milestones

## Milestone A — Stabilize the current GUI model

Goal:
- make the current drive/details/session split coherent and pleasant

### A1. Right-pane mode cleanup
- Status: **in progress**
- Make top-level drive clicks always land on `Drive`
- Make top-level image clicks always land on `Info`
- Make session-tree clicks always land on `Files`
- Hide recovery-only tabs unless a session exists for the selected source
- Acceptance:
  - user cannot get stuck in irrelevant tabs after changing resource type
  - switching between drives and images feels deliberate, not accidental

### A2. Tree alignment and legibility
- Status: **next**
- Normalize columns for:
  - expander
  - connector line
  - icon
  - label
  - meta
- Make parent/child relationships visually unambiguous
- Acceptance:
  - partitions, filesystems, and folders line up consistently
  - virtual disks are obviously children where applicable

### A3. Drive details polish
- Improve the drive-details view so it reads like a real disk inspector
- Show consistent sections such as:
  - identity
  - capacity / sector sizes
  - bus / protocol
  - OS object
  - health summary
- Acceptance:
  - selecting `disk0` feels useful before any scan is run

### A4. S.M.A.R.T. tab quality pass
- Better summarize health and capabilities
- Prefer richer properties when `smartctl` is available
- Gracefully degrade when it is not
- Acceptance:
  - the tab is clearly useful even if full vendor attributes are unavailable

---

## Milestone B — Recovery browsing quality

Goal:
- make the recovery browser feel complete enough for serious daily use

### B1. File preview pane
- Priority: **high**
- Add a preview/details area for the selected file
- Initial support:
  - text
  - images
  - PDF
  - fallback hex/text preview
- Acceptance:
  - user can inspect a file before recovering it

### B2. Search
- Priority: **high**
- Add a search bar for the active session / filesystem
- Support:
  - path/name matching
  - exact vs glob
  - deleted/live filters later
- Acceptance:
  - common “find one file quickly” flow works without manually drilling the tree

### B3. Files/Deleted synchronization
- Ensure selected filesystem and path stay coherent across:
  - left tree
  - files grid
  - deleted tab
- Acceptance:
  - switching filesystems never shows stale content

### B4. Right-side inspector
- Add a proper inspector pane for the selected row
- Candidate fields:
  - full path
  - inode
  - size
  - timestamps
  - deleted/live state
  - source/origin
- Acceptance:
  - the main grid no longer has to carry every detail column itself

### B5. Deleted browsing model
- Decide whether deleted entries remain:
  - a dedicated tab
  - a special left-tree node
  - both
- Acceptance:
  - deleted content has a clear home in the navigation model

---

## Milestone C — Forensic surface area

Goal:
- expose the forensic capability already implied by the product positioning

### C1. Hash image
- Priority: **high**
- Add explicit `Hash Image…`
- Use background progress + cancel
- Primary output:
  - SHA-256
- Secondary compatibility options later:
  - MD5
  - SHA-1
- Acceptance:
  - hash a large image with visible progress and reusable result

### C2. Forensic report generation
- Add report export from the GUI
- Initial contents:
  - source identity
  - scan metadata
  - hashes
  - partition/filesystem summary
  - recovered outputs summary
  - audit trail
- Acceptance:
  - useful HTML export generated from a normal GUI workflow

### C3. Action / audit timeline
- Expand the current activity log into something more evidentiary
- Track:
  - resource opened
  - scan run
  - session loaded
  - recovery started/completed
  - hash generated
- Acceptance:
  - user can reconstruct what happened in the session

### C4. Hex / offset inspection
- Add low-level inspection from selected filesystems/files
- Acceptance:
  - user can jump from a selected artifact into raw offset-oriented inspection

---

## Milestone D — Filesystem parity

Goal:
- move beyond ext4-only sessions

### D1. NTFS session integration
- Priority: **very high**
- Build session trees from NTFS metadata
- Support browse/search/recover in the same session model used by ext4
- Acceptance:
  - NTFS image scans and browses in the GUI

### D2. NTFS deleted support
- Enumerate deleted NTFS entries in a way compatible with the Deleted view
- Acceptance:
  - deleted NTFS content appears in the same user-facing recovery flow

### D3. FAT32
- Build a practical FAT32 parser and deleted scan path

### D4. APFS
- Long-term, but especially important for macOS credibility

### D5. XFS and others
- Lower priority than NTFS / FAT32 / APFS

---

## Milestone E — Packaging and shipping

Goal:
- make the app installable and supportable on all target desktop platforms

### E1. macOS release
- Build signed, notarized `RecoverMax.app`
- Ship via notarized `.dmg`
- Ensure Full Disk Access guidance matches the packaged app identity
- Acceptance:
  - normal macOS user can install, grant FDA, relaunch, and use raw-disk workflows

### E2. Windows release
- Ship installer package
- Clarify admin/raw-disk behavior
- Acceptance:
  - image workflows work reliably; raw-disk story is documented even if not perfect yet

### E3. Linux release
- Ship AppImage first
- Add `.deb` later if needed
- Acceptance:
  - testable install flow exists without source build

### E4. Release automation
- Add changelog + packaging + artifact publishing workflow

### E5. Update strategy
- Decide whether to ship auto-update before or after first paid release

---

## Milestone F — Commercial layer

Goal:
- prepare the GUI for real distribution and sales

### F1. Website / docs
- Make recovermax.dev clearly explain:
  - what the product does
  - supported filesystems
  - raw-disk permission expectations
  - `.scn` saved-scan workflow

### F2. Licensing / payments
- Decide:
  - perpetual vs subscription
  - key delivery mechanism
  - offline-friendly activation story

### F3. Positioning
- Clarify whether RecoverMax is:
  - a recovery tool with forensic features
  - a forensic tool with recovery features

The current product direction suggests:
- recovery-first
- forensic-capable

---

## Immediate priorities

This is the recommended execution order from here:

1. **Tree alignment and right-pane mode cleanup**
   - because current usability still suffers from ambiguity

2. **Drive details / SMART polish**
   - because top-level resource clicks now matter more

3. **File preview pane**
   - biggest qualitative jump in actual recovery workflow

4. **Search**
   - biggest speed improvement for common tasks

5. **Forensic hash**
   - first real forensic feature users will expect

6. **NTFS session integration**
   - next major capability expansion

7. **Packaged macOS release**
   - required to validate the production FDA story properly

---

## Definition of a strong alpha

RecoverMax should qualify as a strong alpha when all of the following are true:
- packaged macOS build exists
- ext4 image workflows feel coherent end to end
- raw-drive details and FDA guidance work in the packaged app
- preview pane exists
- search exists
- hashing exists
- left tree and right pane behave predictably

---

## Definition of a strong v1

RecoverMax should qualify as a strong v1 when:
- ext4 and NTFS both work end to end in the GUI
- packaged releases exist on macOS, Windows, and Linux
- preview, search, hashing, and reporting are all present
- the drive/details/session split feels intentional and polished
- licensing / website / release automation are in place

---

## Open questions

- Should deleted content remain a dedicated tab, a left-tree node, or both?
- How far should the right pane move toward a three-panel R-Studio-style layout?
- Should S.M.A.R.T. rely on `smartctl` when available, or should richer OS-native paths be built per platform?
- Is APFS a pre-v1 requirement for macOS credibility, or can FDA/raw-drive support land first and APFS follow?
- Should the first commercial packaging target be macOS-only until the raw-drive UX is cleaner?

---

## Ongoing requirements

- every new feature should include tests where practical
- do not regress existing ext4 workflows
- keep forensic claims modest unless the feature is genuinely complete
- keep the plan aligned with the shipped product, not aspirational screenshots

---

This document should be rewritten again if the product model changes materially.
