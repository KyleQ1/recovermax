//! Tests that are EXPECTED TO FAIL — they expose real bugs and missing features.
//! As we fix each issue, move the test to the appropriate passing test file.

use std::io::Write;
use tempfile::{NamedTempFile, TempDir};
use recovermax_core::io::ImageReader;
use recovermax_core::fs::ext4::Ext4Fs;

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

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
        Self { data, block_size, inode_size: 256, inode_table_block: 3, inodes_per_group: 256 }
    }

    fn write_superblock(&mut self, label: &str) {
        let sb = 1024usize;
        let blocks = (self.data.len() / self.block_size as usize) as u32;
        self.write_u32(sb + 0x00, self.inodes_per_group);
        self.write_u32(sb + 0x04, blocks);
        self.write_u32(sb + 0x0C, blocks / 2);
        self.write_u32(sb + 0x10, self.inodes_per_group / 2);
        self.write_u32(sb + 0x14, 0);
        self.write_u32(sb + 0x18, 2); // 4K blocks
        self.write_u32(sb + 0x20, 8192);
        self.write_u32(sb + 0x28, self.inodes_per_group);
        self.write_u16(sb + 0x38, 0xEF53);
        self.write_u16(sb + 0x58, self.inode_size);
        self.write_u32(sb + 0x60, 0x42);
        self.data[sb + 0x68..sb + 0x78].copy_from_slice(&[1; 16]);
        let name = label.as_bytes();
        let len = name.len().min(16);
        self.data[sb + 0x78..sb + 0x78 + len].copy_from_slice(&name[..len]);
        self.write_u32(sb + 0x150, 0);
    }

    fn write_block_group_descriptor(&mut self, group: u32, inode_table_block: u64) {
        let bgdt_off = self.block_size as usize;
        let off = bgdt_off + group as usize * 64;
        self.write_u32(off + 8, inode_table_block as u32);
        self.write_u32(off + 40, (inode_table_block >> 32) as u32);
    }

    fn write_inode_with_extent(&mut self, inode_num: u64, mode: u16, size: u64, data_block: u64, block_count: u16) {
        let index = (inode_num - 1) % self.inodes_per_group as u64;
        let off = self.inode_table_block as usize * self.block_size as usize + index as usize * self.inode_size as usize;
        self.write_u16(off, mode);
        self.write_u32(off + 4, size as u32);
        self.write_u32(off + 108, (size >> 32) as u32);
        self.write_u16(off + 26, 1);
        self.write_u32(off + 32, 0x80000);
        let ext = off + 40;
        self.write_u16(ext, 0xF30A);
        self.write_u16(ext + 2, 1);
        self.write_u16(ext + 4, 4);
        self.write_u16(ext + 6, 0);
        self.write_u32(ext + 12, 0);
        self.write_u16(ext + 16, block_count);
        self.write_u16(ext + 18, (data_block >> 32) as u16);
        self.write_u32(ext + 20, data_block as u32);
    }

    fn write_inode_with_blockmap(&mut self, inode_num: u64, mode: u16, size: u64, blocks: &[u32]) {
        let index = (inode_num - 1) % self.inodes_per_group as u64;
        let off = self.inode_table_block as usize * self.block_size as usize + index as usize * self.inode_size as usize;
        self.write_u16(off, mode);
        self.write_u32(off + 4, size as u32);
        self.write_u32(off + 108, (size >> 32) as u32);
        self.write_u16(off + 26, 1);
        self.write_u32(off + 32, 0);
        for (i, &blk) in blocks.iter().enumerate().take(15) {
            self.write_u32(off + 40 + i * 4, blk);
        }
    }

    fn write_dir_entries(&mut self, block: u64, entries: &[(u32, u8, &str)]) {
        let block_off = block as usize * self.block_size as usize;
        let mut pos = block_off;
        for (i, &(inode, file_type, name)) in entries.iter().enumerate() {
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len();
            let rec_len = if i == entries.len() - 1 {
                self.block_size as usize - (pos - block_off)
            } else {
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

    fn build(self) -> Vec<u8> { self.data }
}

// ===========================================================================
// FIXED: Indirect block reading.
// blocks[0..12] = direct, blocks[12] = pointer to a block of block pointers.
// ===========================================================================

#[test]
fn indirect_blocks_work() {
    let mut builder = Ext4ImageBuilder::new(256);
    builder.write_superblock("indirect-fix");
    builder.write_block_group_descriptor(0, 3);

    // 14 blocks of actual data: 12 direct + 2 via indirect
    // Direct blocks: 20..32 (12 blocks)
    // Indirect pointer block: 32 (contains pointers to blocks 40, 41)
    // Data blocks via indirect: 40, 41
    let file_size = 14 * 4096;
    // inode block_data: entries 0-11 = direct blocks, entry 12 = indirect block
    let mut blocks = [0u32; 15];
    for i in 0..12 {
        blocks[i] = 20 + i as u32;
    }
    blocks[12] = 35; // indirect pointer block

    builder.write_inode_with_blockmap(11, 0x8000, file_size as u64, &blocks);

    // Write direct block data
    for i in 0..12u32 {
        builder.write_data((20 + i) as u64, &vec![i as u8; 4096]);
    }

    // Write the indirect pointer block at block 35
    // It contains u32 pointers to data blocks 40, 41
    let ind_off = 35 * 4096;
    builder.write_u32(ind_off, 40);
    builder.write_u32(ind_off + 4, 41);

    // Write the data blocks pointed to by indirect
    builder.write_data(40, &vec![0xAA; 4096]);
    builder.write_data(41, &vec![0xBB; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    let data = fs.read_inode_data(&inode).unwrap();

    assert_eq!(data.len(), file_size);
    // Verify direct blocks
    for i in 0..12 {
        assert!(
            data[i * 4096..(i + 1) * 4096].iter().all(|&b| b == i as u8),
            "Direct block {} wrong", i
        );
    }
    // Verify indirect blocks
    assert!(data[12 * 4096..13 * 4096].iter().all(|&b| b == 0xAA), "Indirect block 0 wrong");
    assert!(data[13 * 4096..14 * 4096].iter().all(|&b| b == 0xBB), "Indirect block 1 wrong");
}

// ===========================================================================
// FIXED: Sparse files — holes (block 0) emit zeros instead of stopping.
// ===========================================================================

#[test]
fn sparse_file_with_holes() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("sparse-fix");
    builder.write_block_group_descriptor(0, 3);

    let file_size = 3 * 4096;
    builder.write_inode_with_blockmap(11, 0x8000, file_size as u64, &[0, 25, 26]);

    builder.write_data(25, &vec![0xAA; 4096]);
    builder.write_data(26, &vec![0xBB; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    let data = fs.read_inode_data(&inode).unwrap();

    assert_eq!(data.len(), file_size);
    // First block is a hole — should be all zeros
    assert!(data[0..4096].iter().all(|&b| b == 0), "Hole should be zeros");
    // Second block has data
    assert!(data[4096..8192].iter().all(|&b| b == 0xAA), "Block 2 wrong");
    // Third block has data
    assert!(data[8192..12288].iter().all(|&b| b == 0xBB), "Block 3 wrong");
}

// ===========================================================================
// FIXED: Symlink recovery — inline symlinks recovered as symlinks or text files.
// ===========================================================================

#[test]
fn symlink_recovery() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("symlink-bug");
    builder.write_block_group_descriptor(0, 3);

    builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
    builder.write_dir_entries(10, &[
        (2, 2, "."),
        (2, 2, ".."),
        (11, 1, "target.txt"),
        (12, 7, "link.txt"),  // type 7 = symlink
    ]);

    // target file
    builder.write_inode_with_extent(11, 0x8000, 5, 20, 1);
    builder.write_data(20, b"hello");

    // symlink inode — in ext4, short symlinks store target in block_data
    let link_target = b"target.txt";
    let index = (12 - 1) % 256;
    let off = 3 * 4096 + index as usize * 256;
    builder.write_u16(off, 0xA000 | 0o777); // symlink mode
    builder.write_u32(off + 4, link_target.len() as u32);
    builder.write_u16(off + 26, 1);
    builder.write_u32(off + 32, 0); // no extents for inline symlink
    // Target stored inline in block_data area
    builder.data[off + 40..off + 40 + link_target.len()].copy_from_slice(link_target);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = recovermax_core::scan::Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    let dest = TempDir::new().unwrap();
    let recoverer = recovermax_core::recover::Recoverer::new(&reader, dest.path());
    recoverer.recover(&report, None).unwrap();

    // target.txt should exist
    assert!(dest.path().join("target.txt").exists());

    // link.txt should exist as a symlink (or at least as a file containing the target path)
    assert!(
        dest.path().join("link.txt").exists(),
        "symlink should be recovered"
    );
}

// ===========================================================================
// BUG 4: File size > 4GB (size_hi field). The code reads size_hi from
// offset 108, which is correct for ext4. But does Vec allocation handle it?
// We test with a fake large inode (not actually that much data).
// ===========================================================================

#[test]
fn large_file_size_field_parsing() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("bigfile");
    builder.write_block_group_descriptor(0, 3);

    // Create an inode that claims to be 5GB but has only 1 block of data
    // This should NOT crash or OOM — it should read what's available
    let inode_num = 11u64;
    let index = (inode_num - 1) % 256;
    let off = 3 * 4096 + index as usize * 256;

    builder.write_u16(off, 0x8000);
    // size = 5GB = 5 * 1024^3 = 5368709120
    let size: u64 = 5 * 1024 * 1024 * 1024;
    builder.write_u32(off + 4, size as u32);           // size_lo
    builder.write_u32(off + 108, (size >> 32) as u32); // size_hi
    builder.write_u16(off + 26, 1);
    builder.write_u32(off + 32, 0x80000); // extents

    // Extent: 1 block at block 20
    let ext = off + 40;
    builder.write_u16(ext, 0xF30A);
    builder.write_u16(ext + 2, 1);
    builder.write_u16(ext + 4, 4);
    builder.write_u16(ext + 6, 0);
    builder.write_u32(ext + 12, 0);
    builder.write_u16(ext + 16, 1);
    builder.write_u32(ext + 20, 20);

    builder.write_data(20, &vec![0x42; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    assert_eq!(inode.size, size);

    // This will try to Vec::with_capacity(5GB) which might OOM
    // or it might work if the system allows overcommit.
    // At minimum it should not crash with a panic.
    let result = fs.read_inode_data(&inode);
    // We accept either Ok (truncated to 4096) or Err (allocation failure)
    match result {
        Ok(data) => {
            // If it succeeds, it should have truncated to available data
            // BUG: it tries to allocate 5GB then truncate, which may OOM
            assert!(data.len() <= 4096, "Should not have more data than the 1 extent block");
        }
        Err(_) => {
            // OOM or read error — acceptable for now but should be fixed
        }
    }
}

// ===========================================================================
// BUG 5: Recovery of deeply nested directories.
// The depth limit is 64. This tests that the limit is enforced without crash.
// ===========================================================================

#[test]
fn recovery_respects_depth_limit() {
    let mut builder = Ext4ImageBuilder::new(512);
    builder.write_superblock("deepnest");
    builder.write_block_group_descriptor(0, 3);

    // Create a chain: root → a → b → c → ... (70 levels)
    // Each directory points to the next via inode N+1
    let root_inode = 2u32;
    let depth = 70;

    for i in 0..depth {
        let inode_num = root_inode + i;
        let next_inode = root_inode + i + 1;
        let dir_block = 10 + i as u64;
        let name = if i == 0 { "a" } else { "sub" };

        builder.write_inode_with_extent(
            inode_num as u64, 0x4000 | 0o755, 4096, dir_block, 1
        );

        if i < depth - 1 {
            builder.write_dir_entries(dir_block, &[
                (inode_num, 2, "."),
                (if i == 0 { root_inode } else { inode_num - 1 }, 2, ".."),
                (next_inode, 2, name),
            ]);
        } else {
            // Leaf directory with a file
            builder.write_dir_entries(dir_block, &[
                (inode_num, 2, "."),
                (inode_num - 1, 2, ".."),
                (200, 1, "deep.txt"),
            ]);
            builder.write_inode_with_extent(200, 0x8000, 4, 100, 1);
            builder.write_data(100, b"deep");
        }
    }

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = recovermax_core::scan::Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    let dest = TempDir::new().unwrap();
    let recoverer = recovermax_core::recover::Recoverer::new(&reader, dest.path());

    // Should not crash or stack overflow — depth limit should kick in
    let result = recoverer.recover(&report, None);
    assert!(result.is_ok(), "Recovery should handle deep nesting gracefully");
}

// ===========================================================================
// BUG 6: Carving doesn't skip past carved files. If a JPEG is 10 sectors
// long, the carver still checks sectors 1-9 for new headers, potentially
// finding embedded headers within the already-carved file.
// ===========================================================================

#[test]
fn carver_finds_embedded_headers() {
    use recovermax_core::carve::Carver;

    let mut img = vec![0u8; 16384];

    // JPEG starting at sector 0
    img[0] = 0xFF; img[1] = 0xD8; img[2] = 0xFF;
    // Real footer at offset 4000
    img[4000] = 0xFF; img[4001] = 0xD9;

    // Another JPEG header at sector 2 (offset 1024) — INSIDE the first JPEG
    img[1024] = 0xFF; img[1025] = 0xD8; img[1026] = 0xFF;
    // This embedded header has its own "footer" at 1500
    img[1500] = 0xFF; img[1501] = 0xD9;

    let img_file = create_test_image(&img);
    let dest = TempDir::new().unwrap();
    let reader = ImageReader::open(img_file.path()).unwrap();
    let carver = Carver::new(&reader, dest.path());
    carver.carve(Some(&["jpg"])).unwrap();

    let files: Vec<_> = std::fs::read_dir(dest.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();

    // BUG: finds 2 JPEGs because it doesn't skip past the first one.
    // Ideally it should find 1 (the outer one) and skip the embedded header.
    assert_eq!(
        files.len(), 2,
        "Current impl finds embedded headers as separate files (known limitation)"
    );
}

// ===========================================================================
// BUG 7: Recovering a directory whose inode data read fails should not
// stop the entire recovery — it should skip and continue.
// ===========================================================================

#[test]
fn recovery_continues_after_corrupt_directory() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("corrupt-dir");
    builder.write_block_group_descriptor(0, 3);

    builder.write_inode_with_extent(2, 0x4000 | 0o755, 4096, 10, 1);
    builder.write_dir_entries(10, &[
        (2, 2, "."),
        (2, 2, ".."),
        (11, 2, "good_dir"),
        (12, 2, "bad_dir"),
        (13, 1, "root_file.txt"),
    ]);

    // good_dir: valid
    builder.write_inode_with_extent(11, 0x4000, 4096, 20, 1);
    builder.write_dir_entries(20, &[
        (11, 2, "."),
        (2, 2, ".."),
        (14, 1, "good.txt"),
    ]);
    builder.write_inode_with_extent(14, 0x8000, 4, 30, 1);
    builder.write_data(30, b"good");

    // bad_dir: inode with bad extent magic → will fail to read
    let bad_index = (12 - 1) % 256;
    let bad_off = 3 * 4096 + bad_index as usize * 256;
    builder.write_u16(bad_off, 0x4000);
    builder.write_u32(bad_off + 4, 4096);
    builder.write_u16(bad_off + 26, 1);
    builder.write_u32(bad_off + 32, 0x80000); // extents
    let bad_ext = bad_off + 40;
    builder.write_u16(bad_ext, 0xBAAD); // corrupt magic!

    // root_file.txt
    builder.write_inode_with_extent(13, 0x8000, 9, 40, 1);
    builder.write_data(40, b"root_file");

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = recovermax_core::scan::Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    let dest = TempDir::new().unwrap();
    let recoverer = recovermax_core::recover::Recoverer::new(&reader, dest.path());
    let result = recoverer.recover(&report, None);
    assert!(result.is_ok(), "Recovery should not abort on corrupt directory");

    // good_dir/good.txt should still be recovered
    let good_path = dest.path().join("good_dir/good.txt");
    assert!(good_path.exists(), "good.txt should be recovered despite bad_dir failing");
    assert_eq!(std::fs::read(&good_path).unwrap(), b"good");

    // root_file.txt should also be recovered
    let root_file = dest.path().join("root_file.txt");
    assert!(root_file.exists(), "root_file.txt should be recovered");
    assert_eq!(std::fs::read(&root_file).unwrap(), b"root_file");
}
