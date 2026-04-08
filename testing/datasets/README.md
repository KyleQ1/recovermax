# Dataset Inventory

This directory tracks public corpora and local fixtures used to validate RecoverMax against real images.

## Recommended Public Corpora

Use these first because they are documented and stable.

- [NIST CFReDS](https://cfreds-archive.nist.gov/) for controlled forensic reference data sets.
- [CFReDS Deleted File Recovery Test Images](https://cfreds-archive.nist.gov/dfr-test-images.html) for metadata-based deleted file recovery.
- [CFReDS File Carving Images](https://cfreds-archive.nist.gov/FileCarving/index.html) for carving-specific recovery checks.
- [CFReDS CFTT String Search Test Image](https://cfreds-archive.nist.gov/CFTT%20String%20Search%20Test%20Image.html) for path/string search validation.
- [Digital Corpora Disk Images](https://digitalcorpora.org/corpora/disk-images/) for NPS images and general disk corpora.
- [Digital Corpora M57-Patents Scenario](https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/) for broader real-world browsing and search behavior.

## Suggested First Datasets

These are the most useful starting points for RecoverMax:

- `nps-2009-casper-rw` for Linux/ext-family behavior and recovery from a documented ext3 layout.
- `nps-2009-ntfs1` for fragmented NTFS recovery and read-path validation.
- `DFR-01` through `DFR-04` from CFReDS for deleted-file and fragmentation coverage.
- `L0_Graphic` and `L1_Graphic` from CFReDS for carving baseline checks.
- `M57-Patents` for realistic multi-drive browsing and session-scale behavior.

## How To Record a Dataset

Each dataset should have a small inventory note with:

- source URL
- license or redistribution constraints
- image format
- known filesystem types
- expected coverage
- local file name
- checksum
- any oracle tool outputs used for comparison

## Import Rule

When you add a new dataset:

1. Download or stage the image outside the repo if it is large.
2. Copy only the minimum metadata and expected-result files into `testing/datasets/<name>/`.
3. Record the source URL and checksum.
4. Add a manifest for the subset of paths or inode numbers you care about.
5. Do not check in recovered payloads unless they are tiny golden bytes.
