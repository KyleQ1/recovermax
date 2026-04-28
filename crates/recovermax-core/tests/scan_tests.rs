use recovermax_core::io::ImageReader;
use recovermax_core::scan::Scanner;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn build_mbr(partitions: &[(u8, u32, u32)]) -> Vec<u8> {
    let mut mbr = vec![0u8; 512];
    for (i, &(ptype, start_lba, size_sectors)) in partitions.iter().enumerate() {
        let off = 446 + i * 16;
        mbr[off + 4] = ptype;
        mbr[off + 8..off + 12].copy_from_slice(&start_lba.to_le_bytes());
        mbr[off + 12..off + 16].copy_from_slice(&size_sectors.to_le_bytes());
    }
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    mbr
}

fn build_ext4_superblock(label: &str, log_block_size: u32, blocks_count: u32) -> Vec<u8> {
    let mut img = vec![0u8; 4 * 1024 * 1024];
    let sb = 1024;

    // inodes_count
    img[sb..sb + 4].copy_from_slice(&128u32.to_le_bytes());
    // blocks_count_lo
    img[sb + 0x04..sb + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    // free_blocks_lo
    img[sb + 0x0C..sb + 0x10].copy_from_slice(&(blocks_count / 2).to_le_bytes());
    // free_inodes_count
    img[sb + 0x10..sb + 0x14].copy_from_slice(&64u32.to_le_bytes());
    // first_data_block
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    // log_block_size
    img[sb + 0x18..sb + 0x1C].copy_from_slice(&log_block_size.to_le_bytes());
    // blocks_per_group
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    // inodes_per_group
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&128u32.to_le_bytes());
    // magic
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    // inode_size
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&256u16.to_le_bytes());
    // feature_incompat (extents)
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
    // UUID
    img[sb + 0x68..sb + 0x78]
        .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    // volume name
    let name_bytes = label.as_bytes();
    let len = name_bytes.len().min(16);
    img[sb + 0x78..sb + 0x78 + len].copy_from_slice(&name_bytes[..len]);
    // blocks_count_hi
    img[sb + 0x150..sb + 0x154].copy_from_slice(&0u32.to_le_bytes());

    img
}

// --- MBR tests ---

#[test]
fn detect_no_partition_table() {
    let f = create_test_image(&[0u8; 1024]);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();
    assert!(parts.is_empty());
}

#[test]
fn detect_mbr_single_partition() {
    let mut img = build_mbr(&[(0x83, 2048, 4096)]);
    img.extend(vec![0u8; 4 * 1024 * 1024]);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].fs_type, "Linux");
    assert_eq!(parts[0].offset, 2048 * 512);
    assert_eq!(parts[0].size, 4096 * 512);
}

#[test]
fn detect_mbr_multiple_partitions() {
    let mut img = build_mbr(&[(0x83, 2048, 4096), (0x82, 6144, 2048), (0x07, 8192, 8192)]);
    img.extend(vec![0u8; 16 * 1024 * 1024]);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].fs_type, "Linux");
    assert_eq!(parts[1].fs_type, "Linux swap");
    assert_eq!(parts[2].fs_type, "NTFS/HPFS");
}

#[test]
fn detect_mbr_empty_slots() {
    // Only partition 1 is populated, rest are zeros
    let mut img = build_mbr(&[(0x83, 2048, 1024)]);
    img.extend(vec![0u8; 2 * 1024 * 1024]);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();
    assert_eq!(parts.len(), 1);
}

#[test]
fn mbr_bad_signature() {
    let mut img = vec![0u8; 1024];
    // Set partition data but wrong signature
    img[450] = 0x83;
    img[510] = 0x00; // wrong
    img[511] = 0x00; // wrong
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();
    assert!(parts.is_empty());
}

#[test]
fn mbr_partition_type_names() {
    let mut img = build_mbr(&[
        (0x0B, 2048, 1024), // FAT32
        (0xEE, 3072, 1024), // GPT protective
        (0x8E, 4096, 1024), // LVM
        (0xFD, 5120, 1024), // Linux RAID
    ]);
    img.extend(vec![0u8; 4 * 1024 * 1024]);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert_eq!(parts[0].fs_type, "FAT32");
    assert_eq!(parts[1].fs_type, "GPT protective");
    assert_eq!(parts[2].fs_type, "Linux LVM");
    assert_eq!(parts[3].fs_type, "Linux RAID");
}

#[test]
fn mbr_skips_partition_starting_beyond_image() {
    let mut img = build_mbr(&[
        (0x83, 2048, 1024),
        (0x83, 999_999, 1024),
    ]);
    img.extend(vec![0u8; 4 * 1024 * 1024]);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].offset, 2048 * 512);
}

#[test]
fn mbr_skips_partition_ending_beyond_image() {
    let mut img = build_mbr(&[
        (0x83, 2048, 1024),
        (0x83, 4096, 999_999),
    ]);
    img.extend(vec![0u8; 4 * 1024 * 1024]);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].offset, 2048 * 512);
}

// --- GPT tests ---

fn build_gpt_image(partitions: &[(&str, u64, u64)]) -> Vec<u8> {
    let size = 16 * 1024 * 1024;
    let mut img = vec![0u8; size];

    // Protective MBR
    img[510] = 0x55;
    img[511] = 0xAA;

    // GPT header at LBA 1 (offset 512)
    let hdr = 512;
    img[hdr..hdr + 8].copy_from_slice(b"EFI PART");
    // Partition entry LBA (LBA 2)
    img[hdr + 72..hdr + 80].copy_from_slice(&2u64.to_le_bytes());
    // Number of partition entries
    img[hdr + 80..hdr + 84].copy_from_slice(&(partitions.len() as u32).to_le_bytes());
    // Size of partition entry
    img[hdr + 84..hdr + 88].copy_from_slice(&128u32.to_le_bytes());

    // Linux filesystem type GUID (0FC63DAF-8483-4772-8E79-3D69D8477DE4) in mixed-endian
    let linux_fs_guid: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
        0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
    ];

    // Partition entries at LBA 2 (offset 1024)
    for (i, &(name, first_lba, last_lba)) in partitions.iter().enumerate() {
        let off = 1024 + i * 128;
        // Type GUID
        img[off..off + 16].copy_from_slice(&linux_fs_guid);
        // First LBA
        img[off + 32..off + 40].copy_from_slice(&first_lba.to_le_bytes());
        // Last LBA
        img[off + 40..off + 48].copy_from_slice(&last_lba.to_le_bytes());
        // Name (UTF-16LE)
        for (j, ch) in name.chars().enumerate() {
            let pos = off + 56 + j * 2;
            if pos + 2 <= img.len() {
                img[pos..pos + 2].copy_from_slice(&(ch as u16).to_le_bytes());
            }
        }
    }

    img
}

#[test]
fn detect_gpt_single_partition() {
    let img = build_gpt_image(&[("Linux", 2048, 4095)]);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].name, "Linux");
    assert_eq!(parts[0].offset, 2048 * 512);
    assert_eq!(parts[0].size, (4095 - 2048 + 1) * 512);
}

#[test]
fn detect_gpt_multiple_partitions() {
    let img = build_gpt_image(&[
        ("boot", 2048, 4095),
        ("root", 4096, 20479),
        ("home", 20480, 40959),
    ]);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].name, "boot");
    assert_eq!(parts[1].name, "root");
    assert_eq!(parts[2].name, "home");
}

#[test]
fn gpt_invalid_entry_size_fails_closed() {
    let mut img = build_gpt_image(&[("bad-entry-size", 2048, 4095)]);
    let hdr = 512;
    img[hdr + 84..hdr + 88].copy_from_slice(&16u32.to_le_bytes());

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert!(parts.is_empty());
}

#[test]
fn gpt_entry_table_beyond_image_fails_closed() {
    let mut img = build_gpt_image(&[("bad-table", 2048, 4095)]);
    let hdr = 512;
    img[hdr + 72..hdr + 80].copy_from_slice(&u64::MAX.to_le_bytes());

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert!(parts.is_empty());
}

#[test]
fn gpt_skips_partition_with_reversed_lba_range() {
    let img = build_gpt_image(&[
        ("bad", 4096, 2048),
        ("good", 8192, 12287),
    ]);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let parts = scanner.detect_partitions().unwrap();

    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].name, "good");
    assert_eq!(parts[0].offset, 8192 * 512);
}

// --- ext4 detection ---

#[test]
fn detect_ext4_filesystem() {
    let img = build_ext4_superblock("myvolume", 2, 1024);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let fs = scanner.detect_filesystem(0).unwrap();

    assert!(fs.is_some());
    let fs = fs.unwrap();
    assert_eq!(fs.fs_type, "ext4");
    assert_eq!(fs.label, "myvolume");
    assert_eq!(fs.block_size, 4096); // 1024 << 2
}

#[test]
fn detect_no_filesystem_on_zeros() {
    let f = create_test_image(&[0u8; 4096]);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let fs = scanner.detect_filesystem(0).unwrap();
    assert!(fs.is_none());
}

// --- Full scan ---

#[test]
fn full_scan_raw_ext4() {
    let img = build_ext4_superblock("scantest", 0, 512);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    assert_eq!(report.image_size, img.len() as u64);
    assert!(report.partitions.is_empty());
    assert_eq!(report.filesystems.len(), 1);
    assert_eq!(report.filesystems[0].label, "scantest");
    assert_eq!(report.filesystems[0].block_size, 1024); // 1024 << 0
}

#[test]
fn scan_report_summary_format() {
    let img = build_ext4_superblock("fmttest", 2, 1024);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();
    let summary = report.summary();

    assert!(summary.contains("Image size:"));
    assert!(summary.contains("Filesystems found: 1"));
    assert!(summary.contains("fmttest"));
    assert!(summary.contains("ext4"));
}

#[test]
fn scan_report_serialization_roundtrip() {
    let img = build_ext4_superblock("serialize", 1, 2048);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    let json = serde_json::to_string(&report).unwrap();
    let deserialized: recovermax_core::scan::ScanReport = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.image_size, report.image_size);
    assert_eq!(deserialized.filesystems.len(), report.filesystems.len());
    assert_eq!(deserialized.filesystems[0].label, "serialize");
}

#[test]
fn scan_artifact_roundtrip_preserves_source_metadata() {
    let img = build_ext4_superblock("artifact", 1, 2048);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    let artifact = recovermax_core::scan::ScanArtifact::from_report(f.path(), report.clone());
    let json = serde_json::to_string(&artifact).unwrap();
    let loaded = recovermax_core::scan::ScanArtifact::from_json_str(&json).unwrap();
    let expected_path = f.path().canonicalize().unwrap();

    assert_eq!(loaded.version, recovermax_core::scan::ScanArtifact::VERSION);
    assert_eq!(loaded.source.image_size, report.image_size);
    assert_eq!(loaded.source.path, expected_path);
    assert_eq!(loaded.report.filesystems[0].label, "artifact");
}

#[test]
fn legacy_scan_report_json_loads_as_artifact() {
    let img = build_ext4_superblock("legacy", 0, 512);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    let json = serde_json::to_string(&report).unwrap();
    let loaded = recovermax_core::scan::ScanArtifact::from_json_str(&json).unwrap();

    assert_eq!(loaded.version, recovermax_core::scan::ScanArtifact::VERSION);
    assert!(loaded.source.path.as_os_str().is_empty());
    assert_eq!(loaded.source.image_size, report.image_size);
    assert_eq!(loaded.report.filesystems[0].label, "legacy");
}

#[test]
fn scan_artifact_validation_rejects_wrong_image_path() {
    let img = build_ext4_superblock("validate", 1, 1024);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    let artifact = recovermax_core::scan::ScanArtifact::from_report(f.path(), report);
    let err = artifact
        .validate_for_image(std::path::Path::new("/tmp/other.img"), reader.len())
        .unwrap_err();

    assert!(err.to_string().contains("was created for"));
}

#[test]
fn scan_artifact_validation_rejects_wrong_image_size() {
    let img = build_ext4_superblock("validate-size", 1, 1024);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    let artifact = recovermax_core::scan::ScanArtifact::from_report(f.path(), report);
    let err = artifact
        .validate_for_image(f.path(), reader.len() + 1)
        .unwrap_err();

    assert!(err.to_string().contains("does not match image"));
}
