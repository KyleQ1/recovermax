# Dataset Inventory

This file tracks the datasets we expect to validate RecoverMax against.

## Public Corpora

| Dataset | Source | Why it matters | Suggested use |
| --- | --- | --- | --- |
| CFReDS DFR Test Images | https://cfreds-archive.nist.gov/dfr-test-images.html | Controlled deleted-file recovery cases with documented layouts | Validate deleted-file behavior, path reconstruction, and recovery selection |
| CFReDS `dfr-01-ext` | https://cfreds-archive.nist.gov/dfr-test-images.html | Mixed ext2/ext3/ext4 corpus that stresses legacy ext-family compatibility | Validate saved-session reopen, tree browsing, deleted root-entry surfacing, and current limits on deleted-path recovery |
| CFReDS File Carving Images | https://cfreds-archive.nist.gov/FileCarving/index.html | Small, documented carving corpora | Validate carve output and false-positive behavior |
| CFReDS String Search Test Image | https://cfreds-archive.nist.gov/CFTT%20String%20Search%20Test%20Image.html | Known search strings at known locations | Validate search correctness and query coverage |
| Digital Corpora NPS Test Disk Images | https://digitalcorpora.org/corpora/disk-images/ | Documented forensic test disks, including ext3 and NTFS | Validate tree browsing, fragmentation, and mixed filesystem handling |
| Digital Corpora M57-Patents Scenario | https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/ | Larger multi-drive scenario with realistic user activity | Validate session-scale browsing and search under clutter |
| Digital Corpora Real Data Corpus | https://digitalcorpora.org/corpora/disk-images/rdc-faq/ | Real-world storage patterns from secondary-market devices | Soak test browsing, search, and recovery against messy inputs |

## Initial Local Fixtures

| Fixture | Purpose | Expected coverage |
| --- | --- | --- |
| `ext4-synthetic-basic` | Small deterministic ext4 session | tree, stat, search, recover, unload |
| `ext4-synthetic-deleted` | Deleted inode and residual directory-entry coverage | deleted recovery, stale metadata handling |
| `ext4-synthetic-sparse` | Sparse file and hole handling | streaming recovery and zero-fill behavior |
| `ext4-synthetic-symlink` | Symlink resolution and reporting | stat/ls/tree display and recover behavior |
| `ext4-synthetic-deep-tree` | Recursive browsing and cache pressure | tree traversal, lazy rebuild after unload |
| `cfreds-dfr-01-ext` | Real public corpus with ext2/ext3/ext4 partitions | ext2/ext3/ext4 compatibility, saved-session reopen, oracle comparison, deleted root-entry surfacing, deleted-path recovery limits |
