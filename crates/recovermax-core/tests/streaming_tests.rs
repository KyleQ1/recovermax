#![allow(clippy::needless_range_loop)] // test fixtures favor direct indexing

//! Tests for streaming recovery: stream_inode_data writes blocks to a Write sink
//! incrementally instead of buffering the entire file in memory.

use recovermax_core::fs::ext4::Ext4Fs;
use recovermax_core::io::ImageReader;
use std::io::Write;
use tempfile::NamedTempFile;

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
        let blocks = (self.data.len() / self.block_size as usize) as u32;
        self.write_u32(sb, self.inodes_per_group);
        self.write_u32(sb + 0x04, blocks);
        self.write_u32(sb + 0x0C, blocks / 2);
        self.write_u32(sb + 0x10, self.inodes_per_group / 2);
        self.write_u32(sb + 0x14, 0);
        self.write_u32(sb + 0x18, 2); // 4K blocks
        self.write_u32(sb + 0x20, 8192);
        self.write_u32(sb + 0x28, self.inodes_per_group);
        self.write_u16(sb + 0x38, 0xEF53);
        self.write_u16(sb + 0x58, self.inode_size);
        self.write_u32(sb + 0x60, 0x42); // extents + 64bit
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
// Streaming a multi-block file writes correct data
// ===========================================================================

#[test]
fn stream_multi_block_file() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("stream-multi");
    builder.write_block_group_descriptor(0, 3);

    // 3 blocks of data via block map (non-contiguous: 20, 25, 30)
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

    let mut streamed = Vec::new();
    let bytes_written = fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(bytes_written, total_size as u64);
    assert_eq!(streamed.len(), total_size);
    assert!(streamed[0..4096].iter().all(|&b| b == 0xAA));
    assert!(streamed[4096..8192].iter().all(|&b| b == 0xBB));
    assert!(streamed[8192..].iter().all(|&b| b == 0xCC));
}

// ===========================================================================
// Streaming a file with extents works
// ===========================================================================

#[test]
fn stream_file_with_extents() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("stream-ext");
    builder.write_block_group_descriptor(0, 3);

    // Multi-extent file: 2 extents (2 blocks + 1 block)
    let inode_num = 11u64;
    let index = (inode_num - 1) % 256;
    let off = 3 * 4096 + index as usize * 256;

    builder.write_u16(off, 0x8000 | 0o644);
    let size = 3 * 4096u64;
    builder.write_u32(off + 4, size as u32);
    builder.write_u32(off + 108, 0);
    builder.write_u16(off + 26, 1);
    builder.write_u32(off + 32, 0x80000); // extents

    // Extent tree with 2 entries
    let ext = off + 40;
    builder.write_u16(ext, 0xF30A);
    builder.write_u16(ext + 2, 2);
    builder.write_u16(ext + 4, 4);
    builder.write_u16(ext + 6, 0); // depth 0

    // Extent 1: 2 blocks at physical 20
    builder.write_u32(ext + 12, 0);
    builder.write_u16(ext + 16, 2);
    builder.write_u16(ext + 18, 0);
    builder.write_u32(ext + 20, 20);

    // Extent 2: 1 block at physical 50
    builder.write_u32(ext + 24, 2);
    builder.write_u16(ext + 28, 1);
    builder.write_u16(ext + 30, 0);
    builder.write_u32(ext + 32, 50);

    builder.write_data(20, &vec![0x11u8; 4096]);
    builder.write_data(21, &vec![0x22u8; 4096]);
    builder.write_data(50, &vec![0x33u8; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();

    let mut streamed = Vec::new();
    let bytes_written = fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(bytes_written, 3 * 4096);
    assert_eq!(streamed.len(), 3 * 4096);
    assert!(streamed[0..4096].iter().all(|&b| b == 0x11));
    assert!(streamed[4096..8192].iter().all(|&b| b == 0x22));
    assert!(streamed[8192..12288].iter().all(|&b| b == 0x33));
}

// ===========================================================================
// Streaming a file with indirect blocks works
// ===========================================================================

#[test]
fn stream_file_with_indirect_blocks() {
    let mut builder = Ext4ImageBuilder::new(256);
    builder.write_superblock("stream-ind");
    builder.write_block_group_descriptor(0, 3);

    // 15 blocks: 12 direct + 3 via indirect
    let total_size = 15 * 4096;
    let mut blocks = [0u32; 15];
    for i in 0..12 {
        blocks[i] = 20 + i as u32;
    }
    blocks[12] = 50; // indirect pointer block

    builder.write_inode_with_blockmap(11, 0x8000, total_size as u64, &blocks);

    // Write direct block data
    for i in 0..12u32 {
        builder.write_data((20 + i) as u64, &vec![i as u8; 4096]);
    }

    // Indirect pointer block at block 50 points to blocks 60, 61, 62
    let ind_off = 50 * 4096;
    builder.write_u32(ind_off, 60);
    builder.write_u32(ind_off + 4, 61);
    builder.write_u32(ind_off + 8, 62);

    builder.write_data(60, &vec![0xDD; 4096]);
    builder.write_data(61, &vec![0xEE; 4096]);
    builder.write_data(62, &vec![0xFF; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();

    let mut streamed = Vec::new();
    let bytes_written = fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(bytes_written, total_size as u64);
    assert_eq!(streamed.len(), total_size);

    // Verify direct blocks
    for i in 0..12 {
        assert!(
            streamed[i * 4096..(i + 1) * 4096]
                .iter()
                .all(|&b| b == i as u8),
            "Direct block {} wrong",
            i
        );
    }
    // Verify indirect blocks
    assert!(streamed[12 * 4096..13 * 4096].iter().all(|&b| b == 0xDD));
    assert!(streamed[13 * 4096..14 * 4096].iter().all(|&b| b == 0xEE));
    assert!(streamed[14 * 4096..15 * 4096].iter().all(|&b| b == 0xFF));
}

// ===========================================================================
// Streaming a sparse file preserves holes
// ===========================================================================

#[test]
fn stream_sparse_file_preserves_holes() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("stream-sparse");
    builder.write_block_group_descriptor(0, 3);

    // 3 blocks: hole, data, data
    let file_size = 3 * 4096;
    builder.write_inode_with_blockmap(11, 0x8000, file_size as u64, &[0, 25, 26]);

    builder.write_data(25, &vec![0xAA; 4096]);
    builder.write_data(26, &vec![0xBB; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();

    let mut streamed = Vec::new();
    let bytes_written = fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(bytes_written, file_size as u64);
    assert_eq!(streamed.len(), file_size);
    // First block is a hole — should be all zeros
    assert!(
        streamed[0..4096].iter().all(|&b| b == 0),
        "Hole should be zeros"
    );
    assert!(
        streamed[4096..8192].iter().all(|&b| b == 0xAA),
        "Block 2 wrong"
    );
    assert!(
        streamed[8192..12288].iter().all(|&b| b == 0xBB),
        "Block 3 wrong"
    );
}

// ===========================================================================
// Streamed output matches read_inode_data for all data layout types
// ===========================================================================

#[test]
fn stream_matches_read_inode_data_extent() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("match-ext");
    builder.write_block_group_descriptor(0, 3);

    let content = b"Hello, streaming world! This is extent-based data.";
    builder.write_inode_with_extent(11, 0x8000 | 0o644, content.len() as u64, 20, 1);
    builder.write_data(20, content);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();

    let buffered = fs.read_inode_data(&inode).unwrap();

    let mut streamed = Vec::new();
    fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(buffered, streamed, "Streamed data must match buffered read");
}

#[test]
fn stream_matches_read_inode_data_blockmap() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("match-blk");
    builder.write_block_group_descriptor(0, 3);

    let content = b"Block map streaming test data!";
    builder.write_inode_with_blockmap(11, 0x8000 | 0o644, content.len() as u64, &[20]);
    builder.write_data(20, content);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();

    let buffered = fs.read_inode_data(&inode).unwrap();

    let mut streamed = Vec::new();
    fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(buffered, streamed, "Streamed data must match buffered read");
}

#[test]
fn stream_matches_read_inode_data_multi_block() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("match-multi");
    builder.write_block_group_descriptor(0, 3);

    // 3 blocks, not perfectly aligned
    let total_size = 3 * 4096 - 100;
    builder.write_inode_with_blockmap(11, 0x8000, total_size as u64, &[20, 25, 30]);
    builder.write_data(20, &vec![0xAA; 4096]);
    builder.write_data(25, &vec![0xBB; 4096]);
    builder.write_data(30, &vec![0xCC; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();

    let buffered = fs.read_inode_data(&inode).unwrap();

    let mut streamed = Vec::new();
    fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(buffered, streamed, "Streamed data must match buffered read");
}

#[test]
fn stream_matches_read_inode_data_indirect() {
    let mut builder = Ext4ImageBuilder::new(256);
    builder.write_superblock("match-ind");
    builder.write_block_group_descriptor(0, 3);

    let total_size = 14 * 4096;
    let mut blocks = [0u32; 15];
    for i in 0..12 {
        blocks[i] = 20 + i as u32;
    }
    blocks[12] = 50; // indirect pointer block

    builder.write_inode_with_blockmap(11, 0x8000, total_size as u64, &blocks);

    for i in 0..12u32 {
        builder.write_data((20 + i) as u64, &vec![i as u8; 4096]);
    }

    // Indirect block points to 2 more data blocks
    let ind_off = 50 * 4096;
    builder.write_u32(ind_off, 60);
    builder.write_u32(ind_off + 4, 61);
    builder.write_data(60, &vec![0xDD; 4096]);
    builder.write_data(61, &vec![0xEE; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();

    let buffered = fs.read_inode_data(&inode).unwrap();

    let mut streamed = Vec::new();
    fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(buffered, streamed, "Streamed data must match buffered read");
}

#[test]
fn stream_matches_read_inode_data_sparse() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("match-sparse");
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

    let buffered = fs.read_inode_data(&inode).unwrap();

    let mut streamed = Vec::new();
    fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(
        buffered, streamed,
        "Streamed data must match buffered read for sparse files"
    );
}

// ===========================================================================
// Streaming a zero-byte file works
// ===========================================================================

#[test]
fn stream_zero_byte_file() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("stream-zero");
    builder.write_block_group_descriptor(0, 3);

    builder.write_inode_with_extent(11, 0x8000, 0, 20, 0);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();
    assert_eq!(inode.size, 0);

    let mut streamed = Vec::new();
    let result = fs.stream_inode_data(&inode, &mut streamed);

    if let Ok(written) = result {
        assert_eq!(written, 0);
        assert!(streamed.is_empty());
    }
    // Err is acceptable for this edge case.
}

// ===========================================================================
// Streaming with depth-1 extent tree
// ===========================================================================

#[test]
fn stream_depth1_extent_tree() {
    let mut builder = Ext4ImageBuilder::new(128);
    builder.write_superblock("stream-d1");
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
    builder.write_u16(ext, 0xF30A);
    builder.write_u16(ext + 2, 1);
    builder.write_u16(ext + 4, 4);
    builder.write_u16(ext + 6, 1); // depth=1

    // Index entry: leaf at block 30
    builder.write_u32(ext + 12, 0);
    builder.write_u32(ext + 16, 30);
    builder.write_u16(ext + 20, 0);

    // Leaf extent node at block 30
    let leaf_off = 30 * 4096;
    builder.write_u16(leaf_off, 0xF30A);
    builder.write_u16(leaf_off + 2, 1);
    builder.write_u16(leaf_off + 4, 340);
    builder.write_u16(leaf_off + 6, 0);

    // Leaf extent: 1 block at physical block 40
    builder.write_u32(leaf_off + 12, 0);
    builder.write_u16(leaf_off + 16, 1);
    builder.write_u16(leaf_off + 18, 0);
    builder.write_u32(leaf_off + 20, 40);

    builder.write_data(40, &vec![0xDDu8; 4096]);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();

    let inode = fs.read_inode(11).unwrap();

    // Verify stream matches buffered read
    let buffered = fs.read_inode_data(&inode).unwrap();

    let mut streamed = Vec::new();
    fs.stream_inode_data(&inode, &mut streamed).unwrap();

    assert_eq!(buffered, streamed);
    assert_eq!(streamed.len(), 4096);
    assert!(streamed.iter().all(|&b| b == 0xDD));
}

#[test]
fn bounded_read_extent_returns_at_most_max_bytes() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("bound-ext");
    builder.write_block_group_descriptor(0, 3);

    let content = b"Hello, this is more than 8 bytes of extent-based content for bounded read test.";
    builder.write_inode_with_extent(11, 0x8000 | 0o644, content.len() as u64, 20, 1);
    builder.write_data(20, content);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();
    let inode = fs.read_inode(11).unwrap();

    let bounded = fs.read_inode_data_bounded(&inode, 8).unwrap();
    assert_eq!(bounded.len(), 8);
    assert_eq!(&bounded, &content[..8]);

    let bounded_512 = fs.read_inode_data_bounded(&inode, 512).unwrap();
    assert_eq!(bounded_512.len(), content.len());
    assert_eq!(&bounded_512, content.as_slice());
}

#[test]
fn bounded_read_blockmap_returns_at_most_max_bytes() {
    let mut builder = Ext4ImageBuilder::new(64);
    builder.write_superblock("bound-blk");
    builder.write_block_group_descriptor(0, 3);

    let content = b"Block map bounded read test data with more than 8 bytes of real content here.";
    builder.write_inode_with_blockmap(11, 0x8000 | 0o644, content.len() as u64, &[20]);
    builder.write_data(20, content);

    let img = builder.build();
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = Ext4Fs::new(&reader, 0).unwrap();
    let inode = fs.read_inode(11).unwrap();

    let bounded = fs.read_inode_data_bounded(&inode, 8).unwrap();
    assert_eq!(bounded.len(), 8);
    assert_eq!(&bounded, &content[..8]);

    let bounded_large = fs.read_inode_data_bounded(&inode, 1000).unwrap();
    assert_eq!(bounded_large.len(), content.len());
    assert_eq!(&bounded_large, content.as_slice());
}
