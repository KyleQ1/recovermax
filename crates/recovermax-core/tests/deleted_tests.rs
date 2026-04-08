//! Tests for deleted inode scanning.
//!
//! Builds ext4 images in-memory with inodes that have dtime set and/or
//! links_count=0 but valid size and extent data, then verifies
//! scan_deleted_inodes finds them and the data can be read back.

use recovermax_core::fs::ext4::Ext4Fs;
use recovermax_core::fs::FileType;
use recovermax_core::io::ImageReader;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

/// Minimal ext4 image builder for deleted inode tests.
/// Layout (4K blocks):
///   Block 0: boot/superblock (superblock at byte 1024)
///   Block 1: block group descriptor table
///   Block 2: (reserved)
///   Block 3+: inode table
///   Remaining: data blocks
struct TestBuilder {
    data: Vec<u8>,
    inode_table_block: u64,
    inodes_per_group: u32,
    inode_size: u16,
}

impl TestBuilder {
    fn new(size_blocks: u64) -> Self {
        let data = vec![0u8; (size_blocks * 4096) as usize];
        Self {
            data,
            inode_table_block: 3,
            inodes_per_group: 256,
            inode_size: 256,
        }
    }

    fn write_superblock(&mut self, label: &str) {
        let sb = 1024usize;
        let blocks = (self.data.len() / 4096) as u32;

        self.put_u32(sb + 0x00, self.inodes_per_group); // inodes_count
        self.put_u32(sb + 0x04, blocks); // blocks_count_lo
        self.put_u32(sb + 0x0C, blocks / 2); // free_blocks_lo
        self.put_u32(sb + 0x10, self.inodes_per_group / 2); // free_inodes_count
        self.put_u32(sb + 0x14, 0); // first_data_block (0 for 4K)
        self.put_u32(sb + 0x18, 2); // log_block_size (1024<<2 = 4096)
        self.put_u32(sb + 0x20, 8192); // blocks_per_group
        self.put_u32(sb + 0x28, self.inodes_per_group); // inodes_per_group
        self.put_u16(sb + 0x38, 0xEF53); // magic
        self.put_u16(sb + 0x58, self.inode_size); // inode_size
        self.put_u32(sb + 0x60, 0x42); // feature_incompat: extents + 64bit
        for i in 0..16 {
            self.data[sb + 0x68 + i] = (i + 1) as u8;
        } // UUID
        let name = label.as_bytes();
        let len = name.len().min(16);
        self.data[sb + 0x78..sb + 0x78 + len].copy_from_slice(&name[..len]);
        self.put_u32(sb + 0x150, 0); // blocks_count_hi
    }

    fn write_bgdt(&mut self, group: u32, inode_table_block: u64) {
        let off = 4096 + group as usize * 64; // block 1, 64-byte descriptors
        self.put_u32(off + 8, inode_table_block as u32);
        self.put_u32(off + 40, (inode_table_block >> 32) as u32);
    }

    /// Write a live (non-deleted) inode with extent pointing to data_block.
    fn write_live_inode(
        &mut self,
        inode_num: u64,
        mode: u16,
        size: u64,
        data_block: u64,
        block_count: u16,
    ) {
        self.write_inode_raw(inode_num, mode, size, 1, 0, data_block, block_count);
    }

    /// Write a deleted inode (dtime set, links_count=0) with extent pointing to data_block.
    fn write_deleted_inode_dtime(
        &mut self,
        inode_num: u64,
        mode: u16,
        size: u64,
        dtime: u32,
        data_block: u64,
        block_count: u16,
    ) {
        self.write_inode_raw(inode_num, mode, size, 0, dtime, data_block, block_count);
    }

    /// Write a deleted inode (links_count=0, dtime=0) with extent pointing to data_block.
    fn write_deleted_inode_nolinks(
        &mut self,
        inode_num: u64,
        mode: u16,
        size: u64,
        data_block: u64,
        block_count: u16,
    ) {
        self.write_inode_raw(inode_num, mode, size, 0, 0, data_block, block_count);
    }

    fn write_inode_raw(
        &mut self,
        inode_num: u64,
        mode: u16,
        size: u64,
        links_count: u16,
        dtime: u32,
        data_block: u64,
        block_count: u16,
    ) {
        let index = (inode_num - 1) % self.inodes_per_group as u64;
        let off =
            self.inode_table_block as usize * 4096 + index as usize * self.inode_size as usize;

        self.put_u16(off, mode); // mode
        self.put_u32(off + 4, size as u32); // size_lo
        self.put_u32(off + 108, (size >> 32) as u32); // size_hi
        self.put_u16(off + 26, links_count); // links_count
        self.put_u32(off + 20, dtime); // dtime
        self.put_u32(off + 32, 0x80000); // flags: extents

        // Extent tree header + one leaf entry
        let ext = off + 40;
        self.put_u16(ext, 0xF30A); // magic
        self.put_u16(ext + 2, 1); // entries
        self.put_u16(ext + 4, 4); // max entries
        self.put_u16(ext + 6, 0); // depth (leaf)
        self.put_u32(ext + 12, 0); // logical block
        self.put_u16(ext + 16, block_count); // block count
        self.put_u16(ext + 18, (data_block >> 32) as u16); // start_hi
        self.put_u32(ext + 20, data_block as u32); // start_lo
    }

    fn write_data(&mut self, block: u64, content: &[u8]) {
        let off = block as usize * 4096;
        let len = content.len().min(self.data.len() - off);
        self.data[off..off + len].copy_from_slice(&content[..len]);
    }

    fn put_u16(&mut self, off: usize, val: u16) {
        self.data[off..off + 2].copy_from_slice(&val.to_le_bytes());
    }

    fn put_u32(&mut self, off: usize, val: u32) {
        self.data[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }

    fn build(self) -> Vec<u8> {
        self.data
    }
}

// ===========================================================================
// scan_deleted_inodes finds inodes with dtime set
// ===========================================================================

#[test]
fn finds_deleted_inodes_with_dtime() {
    let mut b = TestBuilder::new(128);
    b.write_superblock("deleted-test");
    b.write_bgdt(0, 3);

    // Inode 11: live file
    b.write_live_inode(11, 0x8000 | 0o644, 100, 20, 1);
    b.write_data(20, &[0xAA; 100]);

    // Inode 12: deleted file (dtime set)
    b.write_deleted_inode_dtime(12, 0x8000 | 0o644, 200, 1700000000, 21, 1);
    b.write_data(21, &[0xBB; 200]);

    // Inode 13: deleted file (dtime set, different timestamp)
    b.write_deleted_inode_dtime(13, 0x8000 | 0o755, 50, 1600000000, 22, 1);
    b.write_data(22, &[0xCC; 50]);

    let img = b.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let ext4 = Ext4Fs::new(&reader, 0).unwrap();

    let deleted = ext4.scan_deleted_inodes().unwrap();

    // Should find inodes 12 and 13, not 11
    let nums: Vec<u64> = deleted.iter().map(|d| d.inode_num).collect();
    assert!(nums.contains(&12), "Should find inode 12 (dtime set)");
    assert!(nums.contains(&13), "Should find inode 13 (dtime set)");
    assert!(!nums.contains(&11), "Should not find live inode 11");

    // Check dtime values
    let d12 = deleted.iter().find(|d| d.inode_num == 12).unwrap();
    assert_eq!(d12.dtime, 1700000000);
    assert_eq!(d12.size, 200);
    assert_eq!(d12.file_type, FileType::RegularFile);

    let d13 = deleted.iter().find(|d| d.inode_num == 13).unwrap();
    assert_eq!(d13.dtime, 1600000000);
    assert_eq!(d13.size, 50);
}

// ===========================================================================
// scan_deleted_inodes finds inodes with links_count=0
// ===========================================================================

#[test]
fn finds_deleted_inodes_with_zero_links() {
    let mut b = TestBuilder::new(128);
    b.write_superblock("nolinks-test");
    b.write_bgdt(0, 3);

    // Inode 11: live file
    b.write_live_inode(11, 0x8000 | 0o644, 100, 20, 1);

    // Inode 12: deleted file (links_count=0, no dtime)
    b.write_deleted_inode_nolinks(12, 0x8000 | 0o644, 300, 21, 1);
    b.write_data(21, &[0xDD; 300]);

    let img = b.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let ext4 = Ext4Fs::new(&reader, 0).unwrap();

    let deleted = ext4.scan_deleted_inodes().unwrap();

    let nums: Vec<u64> = deleted.iter().map(|d| d.inode_num).collect();
    assert!(nums.contains(&12), "Should find inode 12 (links=0)");
    assert!(!nums.contains(&11), "Should not find live inode 11");

    let d12 = deleted.iter().find(|d| d.inode_num == 12).unwrap();
    assert_eq!(d12.dtime, 0);
    assert_eq!(d12.size, 300);
}

// ===========================================================================
// Deleted inodes with different file types
// ===========================================================================

#[test]
fn detects_deleted_file_types() {
    let mut b = TestBuilder::new(128);
    b.write_superblock("types-test");
    b.write_bgdt(0, 3);

    // Regular file deleted
    b.write_deleted_inode_dtime(11, 0x8000 | 0o644, 100, 1700000000, 20, 1);
    // Directory deleted
    b.write_deleted_inode_dtime(12, 0x4000 | 0o755, 4096, 1700000000, 21, 1);
    // Symlink deleted
    b.write_deleted_inode_dtime(13, 0xA000 | 0o777, 20, 1700000000, 22, 1);

    let img = b.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let ext4 = Ext4Fs::new(&reader, 0).unwrap();

    let deleted = ext4.scan_deleted_inodes().unwrap();

    let d11 = deleted.iter().find(|d| d.inode_num == 11).unwrap();
    assert_eq!(d11.file_type, FileType::RegularFile);

    let d12 = deleted.iter().find(|d| d.inode_num == 12).unwrap();
    assert_eq!(d12.file_type, FileType::Directory);

    let d13 = deleted.iter().find(|d| d.inode_num == 13).unwrap();
    assert_eq!(d13.file_type, FileType::Symlink);
}

// ===========================================================================
// Data from deleted inodes can still be read
// ===========================================================================

#[test]
fn deleted_inode_data_readable() {
    let mut b = TestBuilder::new(128);
    b.write_superblock("readback");
    b.write_bgdt(0, 3);

    let content = b"This is deleted file content that should be recoverable!";
    b.write_deleted_inode_dtime(11, 0x8000 | 0o644, content.len() as u64, 1700000000, 20, 1);
    b.write_data(20, content);

    let img = b.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let ext4 = Ext4Fs::new(&reader, 0).unwrap();

    // Verify scan finds it
    let deleted = ext4.scan_deleted_inodes().unwrap();
    assert!(deleted.iter().any(|d| d.inode_num == 11));

    // Verify data can be read back
    let inode = ext4.read_inode(11).unwrap();
    assert!(inode.is_deleted());
    assert_eq!(inode.size, content.len() as u64);

    let data = ext4.read_inode_data(&inode).unwrap();
    assert_eq!(&data, content);
}

// ===========================================================================
// Multi-block deleted file data is readable
// ===========================================================================

#[test]
fn deleted_multiblock_file_readable() {
    let mut b = TestBuilder::new(128);
    b.write_superblock("multiblk-del");
    b.write_bgdt(0, 3);

    // Deleted file spanning 3 blocks (12288 bytes, truncated to 10000)
    let size = 10000u64;
    b.write_deleted_inode_dtime(11, 0x8000 | 0o644, size, 1700000000, 20, 3);
    // Write 3 contiguous blocks of data
    b.write_data(20, &[0x41; 4096]); // 'A'
    b.write_data(21, &[0x42; 4096]); // 'B'
    b.write_data(22, &[0x43; 4096]); // 'C'

    let img = b.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let ext4 = Ext4Fs::new(&reader, 0).unwrap();

    let inode = ext4.read_inode(11).unwrap();
    let data = ext4.read_inode_data(&inode).unwrap();

    assert_eq!(data.len(), size as usize);
    assert!(data[..4096].iter().all(|&b| b == 0x41));
    assert!(data[4096..8192].iter().all(|&b| b == 0x42));
    assert!(data[8192..].iter().all(|&b| b == 0x43));
}

// ===========================================================================
// Skips inodes with size=0 (fully cleared)
// ===========================================================================

#[test]
fn skips_zero_size_deleted_inodes() {
    let mut b = TestBuilder::new(128);
    b.write_superblock("zero-size");
    b.write_bgdt(0, 3);

    // Deleted inode with size=0 — no data to recover
    b.write_deleted_inode_dtime(11, 0x8000 | 0o644, 0, 1700000000, 20, 1);

    // Deleted inode with actual content
    b.write_deleted_inode_dtime(12, 0x8000 | 0o644, 500, 1700000000, 21, 1);
    b.write_data(21, &[0xEE; 500]);

    let img = b.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let ext4 = Ext4Fs::new(&reader, 0).unwrap();

    let deleted = ext4.scan_deleted_inodes().unwrap();

    let nums: Vec<u64> = deleted.iter().map(|d| d.inode_num).collect();
    assert!(!nums.contains(&11), "Should skip zero-size deleted inode");
    assert!(nums.contains(&12), "Should find non-zero deleted inode");
}

// ===========================================================================
// Skips reserved inodes (1-10)
// ===========================================================================

#[test]
fn skips_reserved_inodes() {
    let mut b = TestBuilder::new(128);
    b.write_superblock("reserved");
    b.write_bgdt(0, 3);

    // Write a "deleted" inode at position 2 (root inode — reserved)
    // This shouldn't appear in results even if it looks deleted
    b.write_deleted_inode_dtime(2, 0x4000 | 0o755, 4096, 1700000000, 20, 1);

    // Write a real deleted inode above reserved range
    b.write_deleted_inode_dtime(11, 0x8000 | 0o644, 100, 1700000000, 21, 1);

    let img = b.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let ext4 = Ext4Fs::new(&reader, 0).unwrap();

    let deleted = ext4.scan_deleted_inodes().unwrap();

    let nums: Vec<u64> = deleted.iter().map(|d| d.inode_num).collect();
    assert!(!nums.contains(&2), "Should skip reserved inode 2");
    assert!(nums.contains(&11), "Should find non-reserved deleted inode");
}

// ===========================================================================
// Empty image returns empty results
// ===========================================================================

#[test]
fn empty_inode_table_returns_empty() {
    let mut b = TestBuilder::new(128);
    b.write_superblock("empty");
    b.write_bgdt(0, 3);
    // No inodes written — all zeros

    let img = b.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let ext4 = Ext4Fs::new(&reader, 0).unwrap();

    let deleted = ext4.scan_deleted_inodes().unwrap();
    assert!(deleted.is_empty());
}
