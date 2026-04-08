use recovermax_core::fs::ext4;
use recovermax_core::io::ImageReader;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn build_ext4_image(label: &str, log_block_size: u32, blocks: u32, incompat: u32) -> Vec<u8> {
    let mut img = vec![0u8; 4 * 1024 * 1024];
    let sb = 1024usize;

    img[sb..sb + 4].copy_from_slice(&256u32.to_le_bytes()); // inodes_count
    img[sb + 0x04..sb + 0x08].copy_from_slice(&blocks.to_le_bytes()); // blocks_count_lo
    img[sb + 0x0C..sb + 0x10].copy_from_slice(&(blocks / 2).to_le_bytes()); // free_blocks_lo
    img[sb + 0x10..sb + 0x14].copy_from_slice(&128u32.to_le_bytes()); // free_inodes_count
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes()); // first_data_block
    img[sb + 0x18..sb + 0x1C].copy_from_slice(&log_block_size.to_le_bytes());
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes()); // blocks_per_group
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&256u32.to_le_bytes()); // inodes_per_group
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes()); // magic
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&256u16.to_le_bytes()); // inode_size
    img[sb + 0x60..sb + 0x64].copy_from_slice(&incompat.to_le_bytes()); // feature_incompat
    img[sb + 0x68..sb + 0x78].copy_from_slice(&[0xAA; 16]); // UUID
    let name = label.as_bytes();
    let len = name.len().min(16);
    img[sb + 0x78..sb + 0x78 + len].copy_from_slice(&name[..len]);
    img[sb + 0x150..sb + 0x154].copy_from_slice(&0u32.to_le_bytes()); // blocks_count_hi

    img
}

// --- Superblock parsing ---

#[test]
fn parse_superblock_valid() {
    let img = build_ext4_image("testfs", 2, 1024, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();

    assert_eq!(sb.magic, 0xEF53);
    assert_eq!(sb.volume_name, "testfs");
    assert_eq!(sb.inodes_count, 256);
    assert_eq!(sb.blocks_count, 1024);
    assert_eq!(sb.log_block_size, 2);
    assert_eq!(sb.inode_size, 256);
}

#[test]
fn parse_superblock_bad_magic() {
    let mut img = vec![0u8; 4096];
    // Put wrong magic at superblock offset
    img[1024 + 0x38] = 0x00;
    img[1024 + 0x39] = 0x00;
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let result = ext4::parse_superblock(&reader, 0);
    assert!(result.is_err());
}

#[test]
fn parse_superblock_too_small() {
    let f = create_test_image(&[0u8; 512]); // Not enough data for superblock
    let reader = ImageReader::open(f.path()).unwrap();
    let result = ext4::parse_superblock(&reader, 0);
    assert!(result.is_err());
}

// --- Block size calculations ---

#[test]
fn block_size_1k() {
    let img = build_ext4_image("bs1k", 0, 512, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert_eq!(sb.block_size(), 1024);
}

#[test]
fn block_size_2k() {
    let img = build_ext4_image("bs2k", 1, 512, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert_eq!(sb.block_size(), 2048);
}

#[test]
fn block_size_4k() {
    let img = build_ext4_image("bs4k", 2, 512, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert_eq!(sb.block_size(), 4096);
}

// --- Total size ---

#[test]
fn total_size_calculation() {
    let img = build_ext4_image("size", 2, 1024, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert_eq!(sb.total_size(), 1024 * 4096); // blocks * block_size
}

// --- UUID ---

#[test]
fn uuid_string_format() {
    let img = build_ext4_image("uuid", 2, 512, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    let uuid = sb.uuid_string();

    // Should be 36 chars: 8-4-4-4-12
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid.chars().filter(|&c| c == '-').count(), 4);
}

// --- Feature flags ---

#[test]
fn has_extents_flag() {
    let img = build_ext4_image("ext", 2, 512, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert!(sb.has_extents());
}

#[test]
fn no_extents_flag() {
    let img = build_ext4_image("noext", 2, 512, 0x00);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert!(!sb.has_extents());
}

#[test]
fn has_64bit_flag() {
    let img = build_ext4_image("64b", 2, 512, 0x80);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert!(sb.has_64bit());
}

// --- Detect function ---

#[test]
fn detect_valid_ext4() {
    let img = build_ext4_image("detected", 2, 1024, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let info = ext4::detect(&reader, 0);

    assert!(info.is_some());
    let info = info.unwrap();
    assert_eq!(info.fs_type, "ext4");
    assert_eq!(info.label, "detected");
    assert_eq!(info.block_size, 4096);
}

#[test]
fn detect_not_ext4() {
    let f = create_test_image(&[0u8; 4096]);
    let reader = ImageReader::open(f.path()).unwrap();
    let info = ext4::detect(&reader, 0);
    assert!(info.is_none());
}

#[test]
fn detect_at_offset() {
    // Put ext4 superblock at offset 1MB
    let offset = 1024 * 1024;
    let mut img = vec![0u8; offset + 4 * 1024 * 1024];
    let base = build_ext4_image("offset", 2, 512, 0x40);
    img[offset..offset + base.len()].copy_from_slice(&base);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();

    // Should not find ext4 at offset 0
    assert!(ext4::detect(&reader, 0).is_none());
    // Should find it at the correct offset
    let info = ext4::detect(&reader, offset as u64);
    assert!(info.is_some());
    assert_eq!(info.unwrap().label, "offset");
}

// --- Volume name edge cases ---

#[test]
fn empty_volume_name() {
    let img = build_ext4_image("", 2, 512, 0x40);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert_eq!(sb.volume_name, "");
}

#[test]
fn max_length_volume_name() {
    let img = build_ext4_image("1234567890abcdef", 2, 512, 0x40); // exactly 16 chars
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let sb = ext4::parse_superblock(&reader, 0).unwrap();
    assert_eq!(sb.volume_name, "1234567890abcdef");
}

// --- Ext4Fs construction ---

#[test]
fn ext4fs_new_valid() {
    let img = build_ext4_image("fstest", 2, 1024, 0xC0);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ext4::Ext4Fs::new(&reader, 0).unwrap();
    assert_eq!(fs.superblock.volume_name, "fstest");
}

#[test]
fn ext4fs_new_invalid() {
    let f = create_test_image(&[0u8; 4096]);
    let reader = ImageReader::open(f.path()).unwrap();
    let result = ext4::Ext4Fs::new(&reader, 0);
    assert!(result.is_err());
}

#[test]
fn read_inode_zero_is_error() {
    let img = build_ext4_image("inodetest", 2, 1024, 0xC0);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ext4::Ext4Fs::new(&reader, 0).unwrap();
    let result = fs.read_inode(0);
    assert!(result.is_err());
}

// --- Inode type detection ---

#[test]
fn inode_type_detection() {
    use recovermax_core::fs::FileType;

    // Directory: mode & 0xF000 == 0x4000
    let inode = ext4::Inode {
        number: 1,
        mode: 0x4000 | 0o755,
        size: 4096,
        links_count: 2,
        flags: 0,
        dtime: 0,
        ctime: 0,
        mtime: 0,
        atime: 0,
        block_data: [0; 60],
    };
    assert!(inode.is_directory());
    assert!(!inode.is_regular_file());
    assert!(!inode.is_symlink());
    assert!(matches!(inode.file_type(), FileType::Directory));

    // Regular file: mode & 0xF000 == 0x8000
    let inode = ext4::Inode {
        mode: 0x8000 | 0o644,
        ..inode
    };
    assert!(inode.is_regular_file());
    assert!(!inode.is_directory());
    assert!(matches!(inode.file_type(), FileType::RegularFile));

    // Symlink: mode & 0xF000 == 0xA000
    let inode = ext4::Inode {
        mode: 0xA000 | 0o777,
        ..inode
    };
    assert!(inode.is_symlink());
    assert!(matches!(inode.file_type(), FileType::Symlink));
}

#[test]
fn inode_deleted_detection() {
    let base = ext4::Inode {
        number: 1,
        mode: 0x8000,
        size: 100,
        links_count: 1,
        flags: 0,
        dtime: 0,
        ctime: 0,
        mtime: 0,
        atime: 0,
        block_data: [0; 60],
    };

    // Not deleted
    assert!(!base.is_deleted());

    // Deleted by dtime
    let deleted = ext4::Inode {
        dtime: 1234567890,
        ..base
    };
    assert!(deleted.is_deleted());

    // Deleted by zero links
    let deleted = ext4::Inode {
        links_count: 0,
        ..base
    };
    assert!(deleted.is_deleted());
}

#[test]
fn inode_uses_extents() {
    let base = ext4::Inode {
        number: 1,
        mode: 0x8000,
        size: 100,
        links_count: 1,
        flags: 0,
        dtime: 0,
        ctime: 0,
        mtime: 0,
        atime: 0,
        block_data: [0; 60],
    };

    assert!(!base.uses_extents());

    let with_extents = ext4::Inode {
        flags: 0x80000,
        ..base
    };
    assert!(with_extents.uses_extents());
}
