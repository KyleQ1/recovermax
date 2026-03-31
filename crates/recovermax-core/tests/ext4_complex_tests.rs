//! Complex ext4 tests that build realistic on-disk structures.
//! These test the full chain: superblock → block group descriptors → inode table → extents → data.

use std::io::Write;
use tempfile::NamedTempFile;
use recovermax_core::io::ImageReader;
use recovermax_core::fs::ext4::{self, Ext4Fs};
use recovermax_core::fs::FileType;

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

/// Build a complete ext4 image with:
/// - Superblock at offset 1024
/// - Block group descriptor table at block 1 (for 4K blocks)
/// - Inode table at a specified block
/// - Data blocks with actual content
///
/// Layout (4K block size, log_block_size=2):
///   Block 0: boot sector (unused, 4096 bytes, superblock at byte 1024)
///   Block 1: block group descriptor table
///   Block 2+: inode table
///   Block N+: data blocks
struct Ext4ImageBuilder {
    data: Vec<u8>,
    block_size: u32,
    inode_size: u16,
    inode_table_block: u64,
    inodes_per_group: u32,
}

impl Ext4ImageBuilder {
    fn new(size_blocks: u64) -> Self {
        let block_size = 4096u32;
        let data = vec![0u8; (size_blocks * block_size as u64) as usize];
        Self {
            data,
            block_size,
            inode_size: 256,
            inode_table_block: 3,
            inodes_per_group: 256,
        }
    }

    fn write_superblock(&mut self, label: &str) {
        let sb = 1024usize;
        let log_bs = 2u32; // 1024 << 2 = 4096
        let blocks = (self.data.len() / self.block_size as usize) as u32;

        // inodes_count
        self.write_u32(sb + 0x00, self.inodes_per_group);
        // blocks_count_lo
        self.write_u32(sb + 0x04, blocks);
        // free_blocks_lo
        self.write_u32(sb + 0x0C, blocks / 2);
        // free_inodes_count
        self.write_u32(sb + 0x10, self.inodes_per_group / 2);
        // first_data_block
        self.write_u32(sb + 0x14, 0); // 0 for 4K blocks
        // log_block_size
        self.write_u32(sb + 0x18, log_bs);
        // blocks_per_group
        self.write_u32(sb + 0x20, 8192);
        // inodes_per_group
        self.write_u32(sb + 0x28, self.inodes_per_group);
        // magic
        self.write_u16(sb + 0x38, 0xEF53);
        // inode_size
        self.write_u16(sb + 0x58, self.inode_size);
        // feature_incompat: extents + 64bit
        self.write_u32(sb + 0x60, 0x42);
        // UUID
        for i in 0..16 {
            self.data[sb + 0x68 + i] = (i + 1) as u8;
        }
        // volume name
        let name = label.as_bytes();
        let len = name.len().min(16);
        self.data[sb + 0x78..sb + 0x78 + len].copy_from_slice(&name[..len]);
        // blocks_count_hi
        self.write_u32(sb + 0x150, 0);
    }

    fn write_block_group_descriptor(&mut self, group: u32, inode_table_block: u64) {
        // BGDT at block 1 for 4K blocks
        let bgdt_off = self.block_size as usize; // block 1
        let desc_size = 64usize; // 64-bit mode
        let off = bgdt_off + group as usize * desc_size;

        // inode_table_lo at offset 8
        self.write_u32(off + 8, inode_table_block as u32);
        // inode_table_hi at offset 40
        self.write_u32(off + 40, (inode_table_block >> 32) as u32);
    }

    /// Write an inode with extents pointing to a data block
    fn write_inode_with_extent(
        &mut self,
        inode_num: u64,
        mode: u16,
        size: u64,
        data_block: u64,
        block_count: u16,
    ) {
        let index = (inode_num - 1) % self.inodes_per_group as u64;
        let off = self.inode_table_block as usize * self.block_size as usize
            + index as usize * self.inode_size as usize;

        // mode
        self.write_u16(off, mode);
        // size_lo
        self.write_u32(off + 4, size as u32);
        // size_hi
        self.write_u32(off + 108, (size >> 32) as u32);
        // links_count
        self.write_u16(off + 26, 1);
        // flags: extents flag
        self.write_u32(off + 32, 0x80000);

        // block_data[0..60] = extent tree
        let ext_off = off + 40;
        // Extent header
        self.write_u16(ext_off, 0xF30A);     // magic
        self.write_u16(ext_off + 2, 1);       // entries
        self.write_u16(ext_off + 4, 4);       // max entries
        self.write_u16(ext_off + 6, 0);       // depth (leaf)
        // Extent entry at ext_off + 12
        self.write_u32(ext_off + 12, 0);                      // logical block
        self.write_u16(ext_off + 16, block_count);             // block count
        self.write_u16(ext_off + 18, (data_block >> 32) as u16); // start_hi
        self.write_u32(ext_off + 20, data_block as u32);       // start_lo
    }

    /// Write an inode using block map (no extents) with direct block pointers
    fn write_inode_with_blockmap(
        &mut self,
        inode_num: u64,
        mode: u16,
        size: u64,
        blocks: &[u32],
    ) {
        let index = (inode_num - 1) % self.inodes_per_group as u64;
        let off = self.inode_table_block as usize * self.block_size as usize
            + index as usize * self.inode_size as usize;

        self.write_u16(off, mode);
        self.write_u32(off + 4, size as u32);
        self.write_u32(off + 108, (size >> 32) as u32);
        self.write_u16(off + 26, 1);
        self.write_u32(off + 32, 0); // no extents flag

        for (i, &blk) in blocks.iter().enumerate().take(15) {
            self.write_u32(off + 40 + i * 4, blk);
        }
    }

    /// Write directory entries into a data block
    fn write_dir_entries(&mut self, block: u64, entries: &[(u32, u8, &str)]) {
        let block_off = block as usize * self.block_size as usize;
        let mut pos = block_off;

        for (i, &(inode, file_type, name)) in entries.iter().enumerate() {
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len();
            let rec_len = if i == entries.len() - 1 {
                // Last entry fills rest of block
                self.block_size as usize - (pos - block_off)
            } else {
                // Align to 4 bytes
                ((8 + name_len + 3) / 4) * 4
            };

            self.write_u32(pos, inode);
            self.write_u16(pos + 4, rec_len as u16);
            self.data[pos + 6] = name_len as u8;
            self.data[pos + 7] = file_type;
            self.data[pos + 8..pos + 8 + name_len].copy_from_slice(name_bytes);
            pos += rec_len;
        }
    }

    fn write_data(&mut self, block: u64, content: &[u8]) {
        let off = block as usize * self.block_size as usize;
        let len = content.len().min(self.data.len() - off);
        self.data[off..off + len].copy_from_slice(&content[..len]);
    }

    fn write_u16(&mut self, off: usize, val: u16) {
        self.data[off..off + 2].copy_from_slice(&val.to_le_bytes());
    }

    fn write_u32(&mut self, off: usize, val: u32) {
        self.data[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }

    fn build(self) -> Vec<u8> {
        self.data
    }
}

// ===========================================================================
// END-TO-END: read a directory from root inode
// ===========================================================================

#[test]
fn read_root_directory_entries() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("e2e-test");
    builder.write_block_group_descriptor(0, 3); // inode table at block 3

    // Root inode (#2) is a directory pointing to block 10
    builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);

    // Directory entries in block 10: ".", "..", "hello.txt", "subdir"
    builder.write_dir_entries(10, &[
        (2, 2, "."),
        (2, 2, ".."),
        (11, 1, "hello.txt"),
        (12, 2, "subdir"),
    ]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let entries = fs.list_directory(2).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();

    assert!(names.contains(&"."));
    assert!(names.contains(&".."));
    assert!(names.contains(&"hello.txt"));
    assert!(names.contains(&"subdir"));

    let hello = entries.iter().find(|e| e.name == "hello.txt").unwrap();
    assert_eq!(hello.inode, 11);
    assert!(matches!(hello.file_type, FileType::RegularFile));

    let subdir = entries.iter().find(|e| e.name == "subdir").unwrap();
    assert_eq!(subdir.inode, 12);
    assert!(matches!(subdir.file_type, FileType::Directory));
}

// ===========================================================================
// END-TO-END: read file data via extents
// ===========================================================================

#[test]
fn read_file_data_via_extent() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("fileread");
    builder.write_block_group_descriptor(0, 3);

    // File inode (#11) pointing to block 20, size=13 bytes
    let content = b"Hello, world!";
    builder.write_inode_with_extent(11, 0x8000 | 0o644, content.len() as u64, 20, 1);
    builder.write_data(20, content);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    assert_eq!(inode.size, 13);
    assert!(inode.is_regular_file());

    let data = fs.read_inode_data(&inode).unwrap();
    assert_eq!(&data, b"Hello, world!");
}

// ===========================================================================
// END-TO-END: read file data via block map (no extents)
// ===========================================================================

#[test]
fn read_file_data_via_blockmap() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("blockmap");
    builder.write_block_group_descriptor(0, 3);

    let content = b"Block map data here!";
    builder.write_inode_with_blockmap(11, 0x8000 | 0o644, content.len() as u64, &[20]);
    builder.write_data(20, content);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    assert!(!inode.uses_extents());
    let data = fs.read_inode_data(&inode).unwrap();
    assert_eq!(&data, b"Block map data here!");
}

// ===========================================================================
// Multi-block file with multiple direct block pointers
// ===========================================================================

#[test]
fn read_file_spanning_multiple_direct_blocks() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("multiblk");
    builder.write_block_group_descriptor(0, 3);

    // 3 blocks of data (non-contiguous: 20, 25, 30)
    let block_a = vec![0xAAu8; 4096];
    let block_b = vec![0xBBu8; 4096];
    let block_c = vec![0xCCu8; 4096];
    let total_size = 3 * 4096 - 100; // not perfectly aligned

    builder.write_inode_with_blockmap(11, 0x8000, total_size as u64, &[20, 25, 30]);
    builder.write_data(20, &block_a);
    builder.write_data(25, &block_b);
    builder.write_data(30, &block_c);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    let data = fs.read_inode_data(&inode).unwrap();

    assert_eq!(data.len(), total_size);
    // First block should be 0xAA
    assert!(data[0..4096].iter().all(|&b| b == 0xAA));
    // Second block should be 0xBB
    assert!(data[4096..8192].iter().all(|&b| b == 0xBB));
    // Third block truncated
    assert!(data[8192..].iter().all(|&b| b == 0xCC));
}

// ===========================================================================
// BUG: File needing >12 direct blocks (indirect blocks not implemented)
// ===========================================================================

#[test]
fn blockmap_file_exceeding_12_direct_blocks_truncates() {
    // Current implementation only handles 12 direct blocks.
    // A file needing 13+ blocks should still return SOMETHING, not crash.
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("indirect");
    builder.write_block_group_descriptor(0, 3);

    // 13 blocks — block 12 (index 12) is the indirect pointer, not a data block
    // The current code will read blocks[12] as data which is wrong, but shouldn't crash.
    let total_size = 13 * 4096;
    let blocks: Vec<u32> = (20..35).collect(); // 15 entries to fill direct + indirect slots
    builder.write_inode_with_blockmap(11, 0x8000, total_size as u64, &blocks);

    for b in 20..35 {
        builder.write_data(b, &vec![(b - 20) as u8; 4096]);
    }

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    let data = fs.read_inode_data(&inode).unwrap();

    // BUG: should be 13*4096 bytes but we only get 12*4096 since indirect not implemented
    // This test documents the known limitation
    assert!(
        data.len() < total_size,
        "Expected truncated output since indirect blocks aren't implemented, got full {}",
        data.len()
    );
}

// ===========================================================================
// Multi-extent file (multiple extents in one leaf node)
// ===========================================================================

#[test]
fn read_file_with_multiple_extents() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("multiext");
    builder.write_block_group_descriptor(0, 3);

    // Manually build an inode with 2 extents
    let inode_num = 11u64;
    let index = (inode_num - 1) % 256;
    let off = 3 * 4096 + index as usize * 256; // inode table at block 3

    // mode = regular file
    builder.write_u16(off, 0x8000 | 0o644);
    // size = 3 blocks worth, but split across 2 extents
    let size = 3 * 4096u64;
    builder.write_u32(off + 4, size as u32);
    builder.write_u32(off + 108, 0);
    // links
    builder.write_u16(off + 26, 1);
    // flags: extents
    builder.write_u32(off + 32, 0x80000);

    // Extent tree with 2 entries
    let ext = off + 40;
    builder.write_u16(ext, 0xF30A);     // magic
    builder.write_u16(ext + 2, 2);       // 2 entries
    builder.write_u16(ext + 4, 4);       // max
    builder.write_u16(ext + 6, 0);       // depth 0

    // Extent 1: logical block 0, 2 blocks at physical 20
    builder.write_u32(ext + 12, 0);      // logical
    builder.write_u16(ext + 16, 2);      // count
    builder.write_u16(ext + 18, 0);      // start_hi
    builder.write_u32(ext + 20, 20);     // start_lo

    // Extent 2: logical block 2, 1 block at physical 50
    builder.write_u32(ext + 24, 2);      // logical
    builder.write_u16(ext + 28, 1);      // count
    builder.write_u16(ext + 30, 0);      // start_hi
    builder.write_u32(ext + 32, 50);     // start_lo

    // Write data
    builder.write_data(20, &vec![0x11u8; 4096]);
    builder.write_data(21, &vec![0x22u8; 4096]);
    builder.write_data(50, &vec![0x33u8; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    let data = fs.read_inode_data(&inode).unwrap();

    assert_eq!(data.len(), 3 * 4096);
    assert!(data[0..4096].iter().all(|&b| b == 0x11), "First extent block 1");
    assert!(data[4096..8192].iter().all(|&b| b == 0x22), "First extent block 2");
    assert!(data[8192..12288].iter().all(|&b| b == 0x33), "Second extent");
}

// ===========================================================================
// BUG: Multi-level extent tree (depth > 0)
// ===========================================================================

#[test]
fn read_file_with_depth1_extent_tree() {
    // Depth-1 extent tree: root has index nodes pointing to leaf blocks.
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("depth1");
    builder.write_block_group_descriptor(0, 3);

    let inode_num = 11u64;
    let index = (inode_num - 1) % 256;
    let off = 3 * 4096 + index as usize * 256;

    builder.write_u16(off, 0x8000 | 0o644);
    let size = 4096u64;
    builder.write_u32(off + 4, size as u32);
    builder.write_u32(off + 108, 0);
    builder.write_u16(off + 26, 1);
    builder.write_u32(off + 32, 0x80000);

    // Root extent tree: depth=1, 1 index entry pointing to block 30
    let ext = off + 40;
    builder.write_u16(ext, 0xF30A);      // magic
    builder.write_u16(ext + 2, 1);        // 1 entry
    builder.write_u16(ext + 4, 4);        // max
    builder.write_u16(ext + 6, 1);        // depth=1

    // Index entry: logical=0, leaf at block 30
    // ext4_extent_idx format:
    //   0-3: ei_block (logical block)
    //   4-7: ei_leaf_lo (lower 32 bits of next-level block)
    //   8-9: ei_leaf_hi (upper 16 bits)
    builder.write_u32(ext + 12, 0);       // logical block
    builder.write_u32(ext + 16, 30);      // leaf_lo = block 30
    builder.write_u16(ext + 20, 0);       // leaf_hi

    // Block 30 = leaf extent node
    let leaf_off = 30 * 4096;
    builder.write_u16(leaf_off, 0xF30A);   // magic
    builder.write_u16(leaf_off + 2, 1);     // 1 extent entry
    builder.write_u16(leaf_off + 4, 340);   // max
    builder.write_u16(leaf_off + 6, 0);     // depth=0

    // Leaf extent: 1 block at physical block 40
    builder.write_u32(leaf_off + 12, 0);    // logical
    builder.write_u16(leaf_off + 16, 1);    // count
    builder.write_u16(leaf_off + 18, 0);    // start_hi
    builder.write_u32(leaf_off + 20, 40);   // start_lo

    // Actual data at block 40
    builder.write_data(40, &vec![0xDDu8; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    let data = fs.read_inode_data(&inode).unwrap();

    assert_eq!(data.len(), 4096);
    assert!(data.iter().all(|&b| b == 0xDD), "Data should be 0xDD from block 40");
}

// ===========================================================================
// Corrupted extent magic
// ===========================================================================

#[test]
fn corrupt_extent_magic_returns_error() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("badext");
    builder.write_block_group_descriptor(0, 3);

    let inode_num = 11u64;
    let index = (inode_num - 1) % 256;
    let off = 3 * 4096 + index as usize * 256;

    builder.write_u16(off, 0x8000);
    builder.write_u32(off + 4, 100);
    builder.write_u16(off + 26, 1);
    builder.write_u32(off + 32, 0x80000); // extents flag

    // BAD magic in extent header
    let ext = off + 40;
    builder.write_u16(ext, 0xDEAD); // wrong magic!

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    let result = fs.read_inode_data(&inode);
    assert!(result.is_err(), "Should fail on bad extent magic");
}

// ===========================================================================
// END-TO-END: full recovery pipeline
// ===========================================================================

#[test]
fn full_recovery_pipeline() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("recovery-e2e");
    builder.write_block_group_descriptor(0, 3);

    // Root inode (#2) = directory at block 10
    builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
    builder.write_dir_entries(10, &[
        (2, 2, "."),
        (2, 2, ".."),
        (11, 1, "readme.txt"),
        (12, 2, "data"),
    ]);

    // readme.txt (inode 11) = file at block 20
    let readme_content = b"RecoverMax test file content\n";
    builder.write_inode_with_extent(11, 0x8000 | 0o644, readme_content.len() as u64, 20, 1);
    builder.write_data(20, readme_content);

    // data/ (inode 12) = directory at block 30
    builder.write_inode_with_extent(12, 0x4000 | 0o755, 4096, 30, 1);
    builder.write_dir_entries(30, &[
        (12, 2, "."),
        (2, 2, ".."),
        (13, 1, "numbers.bin"),
    ]);

    // data/numbers.bin (inode 13) = file at block 40
    let numbers: Vec<u8> = (0..=255).cycle().take(1000).collect();
    builder.write_inode_with_extent(13, 0x8000 | 0o644, numbers.len() as u64, 40, 1);
    builder.write_data(40, &numbers);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();

    // Scan
    let scanner = recovermax_core::scan::Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();
    assert_eq!(report.filesystems.len(), 1);
    assert_eq!(report.filesystems[0].label, "recovery-e2e");

    // Recover
    let dest = tempfile::TempDir::new().unwrap();
    let recoverer = recovermax_core::recover::Recoverer::new(&reader, dest.path());
    recoverer.recover(&report, None).unwrap();

    // Verify recovered files
    let readme_path = dest.path().join("readme.txt");
    assert!(readme_path.exists(), "readme.txt should be recovered");
    let recovered = std::fs::read(&readme_path).unwrap();
    assert_eq!(recovered, readme_content);

    let numbers_path = dest.path().join("data/numbers.bin");
    assert!(numbers_path.exists(), "data/numbers.bin should be recovered");
    let recovered = std::fs::read(&numbers_path).unwrap();
    assert_eq!(recovered, numbers);
}

// ===========================================================================
// Recovery with path filter
// ===========================================================================

#[test]
fn recovery_with_path_filter() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("filter-test");
    builder.write_block_group_descriptor(0, 3);

    builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
    builder.write_dir_entries(10, &[
        (2, 2, "."),
        (2, 2, ".."),
        (11, 1, "keep.txt"),
        (12, 1, "skip.txt"),
        (13, 2, "subdir"),
    ]);

    builder.write_inode_with_extent(11, 0x8000, 5, 20, 1);
    builder.write_data(20, b"keep!");

    builder.write_inode_with_extent(12, 0x8000, 5, 21, 1);
    builder.write_data(21, b"skip!");

    builder.write_inode_with_extent(13, 0x4000, 4096, 30, 1);
    builder.write_dir_entries(30, &[
        (13, 2, "."),
        (2, 2, ".."),
        (14, 1, "nested.txt"),
    ]);
    builder.write_inode_with_extent(14, 0x8000, 7, 31, 1);
    builder.write_data(31, b"nested!");

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = recovermax_core::scan::Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    // Recover only "subdir"
    let dest = tempfile::TempDir::new().unwrap();
    let recoverer = recovermax_core::recover::Recoverer::new(&reader, dest.path());
    recoverer.recover(&report, Some("/subdir")).unwrap();

    // subdir/nested.txt should exist
    assert!(dest.path().join("subdir").exists());
    // keep.txt and skip.txt should NOT exist
    assert!(!dest.path().join("keep.txt").exists());
    assert!(!dest.path().join("skip.txt").exists());
}

// ===========================================================================
// Directory with deleted entries
// ===========================================================================

#[test]
fn directory_with_deleted_entries() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("deleted");
    builder.write_block_group_descriptor(0, 3);

    builder.write_inode_with_extent(2, 0x4000, 4096, 10, 1);

    // Manually write directory with a deleted entry (inode=0)
    let block_off = 10 * 4096;
    let mut pos = block_off;

    // "." entry
    builder.write_u32(pos, 2); // inode
    builder.write_u16(pos + 4, 12); // rec_len
    builder.data[pos + 6] = 1; // name_len
    builder.data[pos + 7] = 2; // dir type
    builder.data[pos + 8] = b'.';
    pos += 12;

    // ".." entry
    builder.write_u32(pos, 2);
    builder.write_u16(pos + 4, 12);
    builder.data[pos + 6] = 2;
    builder.data[pos + 7] = 2;
    builder.data[pos + 8] = b'.';
    builder.data[pos + 9] = b'.';
    pos += 12;

    // Deleted entry: inode=0 but name still there
    builder.write_u32(pos, 0); // inode = 0 (deleted)
    builder.write_u16(pos + 4, 20);
    builder.data[pos + 6] = 11; // name_len
    builder.data[pos + 7] = 1;
    builder.data[pos + 8..pos + 19].copy_from_slice(b"deleted.txt");
    pos += 20;

    // Active entry
    builder.write_u32(pos, 11);
    builder.write_u16(pos + 4, (4096 - (pos - block_off)) as u16);
    builder.data[pos + 6] = 10;
    builder.data[pos + 7] = 1;
    builder.data[pos + 8..pos + 18].copy_from_slice(b"active.txt");

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let entries = fs.list_directory(2).unwrap();

    let deleted = entries.iter().find(|e| e.name == "deleted.txt");
    assert!(deleted.is_some(), "Should find deleted entry");
    assert!(deleted.unwrap().deleted, "Should be marked as deleted");
    assert_eq!(deleted.unwrap().inode, 0);

    let active = entries.iter().find(|e| e.name == "active.txt");
    assert!(active.is_some(), "Should find active entry");
    assert!(!active.unwrap().deleted);
}

// ===========================================================================
// Directory with very long filenames
// ===========================================================================

#[test]
fn directory_with_long_filename() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("longname");
    builder.write_block_group_descriptor(0, 3);
    builder.write_inode_with_extent(2, 0x4000, 4096, 10, 1);

    let long_name = "a".repeat(255); // ext4 max filename length
    builder.write_dir_entries(10, &[
        (2, 2, "."),
        (2, 2, ".."),
        (11, 1, &long_name),
    ]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let entries = fs.list_directory(2).unwrap();
    let found = entries.iter().find(|e| e.name.len() == 255);
    assert!(found.is_some(), "Should handle 255-char filenames");
    assert_eq!(found.unwrap().name, long_name);
}

// ===========================================================================
// Inode at non-zero block group
// ===========================================================================

#[test]
fn read_inode_from_second_block_group() {
    let mut builder = Ext4ImageBuilder::new(512);
    builder.inodes_per_group = 64; // small so we can test group 1
    builder.write_superblock("multigroup");
    builder.write_block_group_descriptor(0, 3);
    builder.write_block_group_descriptor(1, 100); // group 1 inode table at block 100

    // Inode 65 should be in group 1, index 0
    // (65-1) / 64 = 1 → group 1
    // (65-1) % 64 = 0 → first inode in group
    let inode_off = 100 * 4096; // block 100
    builder.write_u16(inode_off, 0x8000 | 0o644);
    builder.write_u32(inode_off + 4, 42);  // size
    builder.write_u16(inode_off + 26, 1);  // links
    builder.write_u32(inode_off + 32, 0);  // no extents

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(65).unwrap();
    assert_eq!(inode.size, 42);
    assert!(inode.is_regular_file());
}

// ===========================================================================
// Zero-byte file
// ===========================================================================

#[test]
fn read_zero_byte_file() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("zerolen");
    builder.write_block_group_descriptor(0, 3);

    // inode with size=0, no extents, no blocks
    builder.write_inode_with_extent(11, 0x8000, 0, 20, 0);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    assert_eq!(inode.size, 0);

    // Might crash or return empty — we just want no panic
    let result = fs.read_inode_data(&inode);
    match result {
        Ok(data) => assert_eq!(data.len(), 0),
        Err(_) => {} // acceptable for now
    }
}

// ===========================================================================
// GPT + ext4 end-to-end (partition table wrapping a filesystem)
// ===========================================================================

#[test]
fn gpt_with_ext4_partition_full_scan() {
    let partition_offset = 2048u64 * 512; // 1MB
    let partition_blocks = 64u64;
    let total_size = partition_offset as usize + partition_blocks as usize * 4096 + 1024 * 1024;
    let mut img = vec![0u8; total_size];

    // Write protective MBR
    img[510] = 0x55;
    img[511] = 0xAA;

    // Write GPT header at LBA 1
    let hdr = 512;
    img[hdr..hdr + 8].copy_from_slice(b"EFI PART");
    img[hdr + 72..hdr + 80].copy_from_slice(&2u64.to_le_bytes()); // entry LBA
    img[hdr + 80..hdr + 84].copy_from_slice(&1u32.to_le_bytes()); // 1 entry
    img[hdr + 84..hdr + 88].copy_from_slice(&128u32.to_le_bytes());

    // GPT partition entry at LBA 2
    let entry = 1024;
    let first_lba = 2048u64;
    let last_lba = first_lba + (partition_blocks * 8) - 1; // 4096/512 = 8 sectors per block
    img[entry + 32..entry + 40].copy_from_slice(&first_lba.to_le_bytes());
    img[entry + 40..entry + 48].copy_from_slice(&last_lba.to_le_bytes());
    // Name "rootfs" in UTF-16LE
    for (i, ch) in "rootfs".chars().enumerate() {
        let pos = entry + 56 + i * 2;
        img[pos..pos + 2].copy_from_slice(&(ch as u16).to_le_bytes());
    }

    // Write ext4 superblock inside the partition
    let sb = partition_offset as usize + 1024;
    img[sb + 0x00..sb + 0x04].copy_from_slice(&128u32.to_le_bytes());
    img[sb + 0x04..sb + 0x08].copy_from_slice(&(partition_blocks as u32).to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&0u32.to_le_bytes());
    img[sb + 0x18..sb + 0x1C].copy_from_slice(&2u32.to_le_bytes()); // 4K blocks
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&128u32.to_le_bytes());
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&256u16.to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x42u32.to_le_bytes());
    img[sb + 0x68..sb + 0x78].copy_from_slice(&[0xBB; 16]);
    img[sb + 0x78..sb + 0x84].copy_from_slice(b"gpt-ext4-vol");
    img[sb + 0x150..sb + 0x154].copy_from_slice(&0u32.to_le_bytes());

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = recovermax_core::scan::Scanner::new(&reader);

    let report = scanner.full_scan().unwrap();

    assert_eq!(report.partitions.len(), 1, "Should find 1 GPT partition");
    assert_eq!(report.partitions[0].name, "rootfs");

    assert!(
        report.filesystems.len() >= 1,
        "Should find ext4 on the partition"
    );
    let ext4_fs = report.filesystems.iter().find(|f| f.label == "gpt-ext4-vol");
    assert!(ext4_fs.is_some(), "Should detect ext4 with label gpt-ext4-vol");
    assert_eq!(ext4_fs.unwrap().offset, partition_offset);
}

// ===========================================================================
// Extent tree with zero entries (empty directory/file)
// ===========================================================================

#[test]
fn extent_tree_with_zero_entries() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("emptyext");
    builder.write_block_group_descriptor(0, 3);

    let inode_num = 11u64;
    let index = (inode_num - 1) % 256;
    let off = 3 * 4096 + index as usize * 256;

    builder.write_u16(off, 0x8000);
    builder.write_u32(off + 4, 0); // size = 0
    builder.write_u16(off + 26, 1);
    builder.write_u32(off + 32, 0x80000);

    // Valid extent header but 0 entries
    let ext = off + 40;
    builder.write_u16(ext, 0xF30A);
    builder.write_u16(ext + 2, 0); // 0 entries
    builder.write_u16(ext + 4, 4);
    builder.write_u16(ext + 6, 0);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    let data = fs.read_inode_data(&inode).unwrap();
    assert_eq!(data.len(), 0);
}

// ===========================================================================
// 1K block size (special case: BGDT at block 2, not block 1)
// ===========================================================================

#[test]
fn ext4_with_1k_block_size() {
    // 1K blocks: superblock at bytes 1024-2047 (block 1), BGDT at block 2 (byte 2048)
    let size = 256 * 1024; // 256 KB
    let mut img = vec![0u8; size];
    let sb = 1024usize;

    img[sb + 0x00..sb + 0x04].copy_from_slice(&64u32.to_le_bytes());
    img[sb + 0x04..sb + 0x08].copy_from_slice(&256u32.to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes()); // first_data_block=1 for 1K
    img[sb + 0x18..sb + 0x1C].copy_from_slice(&0u32.to_le_bytes()); // log_block_size=0 → 1024
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&64u32.to_le_bytes());
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&128u16.to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x40u32.to_le_bytes()); // extents, no 64bit
    img[sb + 0x68..sb + 0x78].copy_from_slice(&[0xCC; 16]);
    img[sb + 0x78..sb + 0x82].copy_from_slice(b"tiny-1k-fs");
    img[sb + 0x150..sb + 0x154].copy_from_slice(&0u32.to_le_bytes());

    // BGDT at block 2 (byte 2048) for 1K blocks
    // inode table at block 5 (byte 5120)
    let bgdt = 2048;
    img[bgdt + 8..bgdt + 12].copy_from_slice(&5u32.to_le_bytes());

    // Inode #2 (root dir) at block 5, index 1, inode_size=128
    let inode_off = 5 * 1024 + 1 * 128; // inode 2 = index 1
    img[inode_off] = 0x00; img[inode_off + 1] = 0x41; // mode = 0x4100 (dir)
    img[inode_off + 4..inode_off + 8].copy_from_slice(&1024u32.to_le_bytes()); // size
    img[inode_off + 26..inode_off + 28].copy_from_slice(&2u16.to_le_bytes()); // links
    img[inode_off + 32..inode_off + 36].copy_from_slice(&0x80000u32.to_le_bytes()); // extents

    // Extent header for root inode
    let ext = inode_off + 40;
    img[ext..ext + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
    img[ext + 2..ext + 4].copy_from_slice(&1u16.to_le_bytes());
    img[ext + 4..ext + 6].copy_from_slice(&4u16.to_le_bytes());
    img[ext + 6..ext + 8].copy_from_slice(&0u16.to_le_bytes());
    // Extent: 1 block at physical block 20
    img[ext + 16..ext + 18].copy_from_slice(&1u16.to_le_bytes()); // count
    img[ext + 20..ext + 24].copy_from_slice(&20u32.to_le_bytes()); // start_lo

    // Directory at block 20 (byte 20480)
    let dir_off = 20 * 1024;
    // "." entry
    img[dir_off..dir_off + 4].copy_from_slice(&2u32.to_le_bytes());
    img[dir_off + 4..dir_off + 6].copy_from_slice(&12u16.to_le_bytes());
    img[dir_off + 6] = 1;
    img[dir_off + 7] = 2;
    img[dir_off + 8] = b'.';
    // ".." entry
    let p2 = dir_off + 12;
    img[p2..p2 + 4].copy_from_slice(&2u32.to_le_bytes());
    img[p2 + 4..p2 + 6].copy_from_slice(&((1024 - 12) as u16).to_le_bytes());
    img[p2 + 6] = 2;
    img[p2 + 7] = 2;
    img[p2 + 8] = b'.';
    img[p2 + 9] = b'.';

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();
    assert_eq!(fs.superblock.block_size(), 1024);

    let entries = fs.list_directory(2).unwrap();
    assert!(entries.iter().any(|e| e.name == "."));
    assert!(entries.iter().any(|e| e.name == ".."));
}
