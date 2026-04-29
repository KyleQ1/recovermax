#![allow(clippy::needless_range_loop)] // test fixtures favor direct indexing

use recovermax_core::fs::ntfs;
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

/// Build a minimal NTFS boot sector at the start of a buffer.
/// Returns a Vec large enough to hold the boot sector plus some MFT data.
fn build_ntfs_boot_sector(
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    total_sectors: u64,
    mft_cluster: u64,
) -> Vec<u8> {
    let cluster_size = bytes_per_sector as usize * sectors_per_cluster as usize;
    // Make image large enough for boot sector + MFT area
    let min_size = (mft_cluster as usize + 16) * cluster_size;
    let size = min_size.max(4 * 1024 * 1024);
    let mut img = vec![0u8; size];

    // Jump instruction (EB 52 90)
    img[0] = 0xEB;
    img[1] = 0x52;
    img[2] = 0x90;

    // OEM ID "NTFS    " at offset 3
    img[3..11].copy_from_slice(b"NTFS    ");

    // Bytes per sector at 0x0B
    img[0x0B..0x0D].copy_from_slice(&bytes_per_sector.to_le_bytes());

    // Sectors per cluster at 0x0D
    img[0x0D] = sectors_per_cluster;

    // Total sectors at 0x28
    img[0x28..0x30].copy_from_slice(&total_sectors.to_le_bytes());

    // MFT cluster at 0x30
    img[0x30..0x38].copy_from_slice(&mft_cluster.to_le_bytes());

    // MFT mirror cluster at 0x38
    let mft_mirror = mft_cluster + 4;
    img[0x38..0x40].copy_from_slice(&mft_mirror.to_le_bytes());

    // Clusters per MFT record at 0x40
    // -10 means 2^10 = 1024 bytes per MFT entry (standard)
    img[0x40] = (-10i8) as u8;

    // Boot sector signature
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    img
}

/// Build a minimal MFT entry with a filename attribute.
/// Returns a 1024-byte MFT entry.
fn build_mft_entry(
    _entry_number: u64,
    flags: u16,
    filename: &str,
    parent_entry: u64,
    file_size: u64,
    data_runs: &[u8],
) -> Vec<u8> {
    let mut entry = vec![0u8; MFT_ENTRY_SIZE];

    // Magic "FILE"
    entry[0..4].copy_from_slice(b"FILE");

    // Fixup offset (at 0x04) — point past the header
    let fixup_offset: u16 = 0x30;
    entry[0x04..0x06].copy_from_slice(&fixup_offset.to_le_bytes());
    // Fixup count (signature + 2 sector entries for 1024-byte record)
    let fixup_count: u16 = 3;
    entry[0x06..0x08].copy_from_slice(&fixup_count.to_le_bytes());

    // First attribute offset
    let first_attr: u16 = 0x38;
    entry[0x14..0x16].copy_from_slice(&first_attr.to_le_bytes());

    // Flags
    entry[0x16..0x18].copy_from_slice(&flags.to_le_bytes());

    // Used size of MFT entry
    entry[0x18..0x1C].copy_from_slice(&(MFT_ENTRY_SIZE as u32).to_le_bytes());

    // Allocated size of MFT entry
    entry[0x1C..0x20].copy_from_slice(&(MFT_ENTRY_SIZE as u32).to_le_bytes());

    // Write fixup array: signature word + replacement words
    // Signature word
    let fixup_sig: u16 = 0x0001;
    entry[fixup_offset as usize..fixup_offset as usize + 2]
        .copy_from_slice(&fixup_sig.to_le_bytes());
    // Replacement for sector 1 end (offset 510-511)
    entry[fixup_offset as usize + 2..fixup_offset as usize + 4]
        .copy_from_slice(&fixup_sig.to_le_bytes());
    // Replacement for sector 2 end (offset 1022-1023)
    entry[fixup_offset as usize + 4..fixup_offset as usize + 6]
        .copy_from_slice(&fixup_sig.to_le_bytes());

    // Write fixup signature at sector boundaries
    entry[510..512].copy_from_slice(&fixup_sig.to_le_bytes());
    entry[1022..1024].copy_from_slice(&fixup_sig.to_le_bytes());

    let mut attr_pos = first_attr as usize;

    // --- $FILE_NAME attribute (type 0x30) ---
    let name_utf16: Vec<u16> = filename.encode_utf16().collect();
    let name_bytes_len = name_utf16.len() * 2;
    // Filename attribute content: 66 bytes header + name
    let fn_content_size = 0x42 + name_bytes_len;
    // Attribute: 24 bytes header (resident) + content, rounded to 8
    let fn_attr_size = ((24 + fn_content_size) + 7) & !7;

    // Attribute type
    entry[attr_pos..attr_pos + 4].copy_from_slice(&ATTR_TYPE_FILENAME.to_le_bytes());
    // Attribute length
    entry[attr_pos + 4..attr_pos + 8].copy_from_slice(&(fn_attr_size as u32).to_le_bytes());
    // Non-resident flag (0 = resident)
    entry[attr_pos + 8] = 0;
    // Content length
    entry[attr_pos + 0x10..attr_pos + 0x14]
        .copy_from_slice(&(fn_content_size as u32).to_le_bytes());
    // Content offset (relative to attribute start)
    let fn_content_offset: u16 = 0x18;
    entry[attr_pos + 0x14..attr_pos + 0x16].copy_from_slice(&fn_content_offset.to_le_bytes());

    let content_start = attr_pos + fn_content_offset as usize;

    // Parent directory reference (6 bytes of MFT ref + 2 bytes sequence)
    let parent_ref = parent_entry.to_le_bytes();
    entry[content_start..content_start + 6].copy_from_slice(&parent_ref[..6]);

    // Filename length (in UTF-16 code units)
    entry[content_start + 0x40] = name_utf16.len() as u8;
    // Filename namespace (3 = Win32+DOS)
    entry[content_start + 0x41] = 3;

    // Filename in UTF-16LE
    for (i, &ch) in name_utf16.iter().enumerate() {
        let off = content_start + 0x42 + i * 2;
        entry[off..off + 2].copy_from_slice(&ch.to_le_bytes());
    }

    attr_pos += fn_attr_size;

    // --- $DATA attribute (type 0x80) ---
    if !data_runs.is_empty() {
        // Non-resident data attribute
        let run_offset: u16 = 0x40; // data runs start offset within attribute
        let data_attr_size = ((run_offset as usize + data_runs.len()) + 7) & !7;

        entry[attr_pos..attr_pos + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        entry[attr_pos + 4..attr_pos + 8].copy_from_slice(&(data_attr_size as u32).to_le_bytes());
        // Non-resident flag
        entry[attr_pos + 8] = 1;
        // Data runs offset
        entry[attr_pos + 0x20..attr_pos + 0x22].copy_from_slice(&run_offset.to_le_bytes());
        // Real size (logical file size) at offset 0x30
        entry[attr_pos + 0x30..attr_pos + 0x38].copy_from_slice(&file_size.to_le_bytes());
        // Initialized size at offset 0x38
        entry[attr_pos + 0x38..attr_pos + 0x40].copy_from_slice(&file_size.to_le_bytes());

        // Data runs
        let run_start = attr_pos + run_offset as usize;
        entry[run_start..run_start + data_runs.len()].copy_from_slice(data_runs);

        attr_pos += data_attr_size;
    } else if file_size > 0 {
        // Resident data attribute (small file)
        let content_size = file_size as usize;
        let data_attr_size = ((24 + content_size) + 7) & !7;

        entry[attr_pos..attr_pos + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        entry[attr_pos + 4..attr_pos + 8].copy_from_slice(&(data_attr_size as u32).to_le_bytes());
        // Non-resident flag (0 = resident)
        entry[attr_pos + 8] = 0;
        // Content length
        entry[attr_pos + 0x10..attr_pos + 0x14]
            .copy_from_slice(&(content_size as u32).to_le_bytes());
        // Content offset
        let data_content_offset: u16 = 0x18;
        entry[attr_pos + 0x14..attr_pos + 0x16].copy_from_slice(&data_content_offset.to_le_bytes());

        // Fill with recognizable pattern
        let content_off = attr_pos + data_content_offset as usize;
        for i in 0..content_size {
            entry[content_off + i] = (i & 0xFF) as u8;
        }

        attr_pos += data_attr_size;
    }

    // End-of-attributes marker
    entry[attr_pos..attr_pos + 4].copy_from_slice(&ATTR_TYPE_END.to_le_bytes());

    entry
}

const MFT_ENTRY_SIZE: usize = 1024;
const ATTR_TYPE_FILENAME: u32 = 0x30;
const ATTR_TYPE_DATA: u32 = 0x80;
const ATTR_TYPE_END: u32 = 0xFFFF_FFFF;

// --- Boot sector parsing ---

#[test]
fn parse_boot_sector_valid() {
    let img = build_ntfs_boot_sector(512, 8, 1048576, 786432);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let bs = ntfs::parse_boot_sector(&reader, 0).unwrap();

    assert_eq!(bs.bytes_per_sector, 512);
    assert_eq!(bs.sectors_per_cluster, 8);
    assert_eq!(bs.total_sectors, 1048576);
    assert_eq!(bs.mft_cluster, 786432);
    assert_eq!(bs.cluster_size(), 4096);
}

#[test]
fn parse_boot_sector_bad_magic() {
    let mut img = vec![0u8; 4096];
    img[3..11].copy_from_slice(b"NOT_NTFS");
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let result = ntfs::parse_boot_sector(&reader, 0);
    assert!(result.is_err());
}

#[test]
fn parse_boot_sector_too_small() {
    let f = create_test_image(&[0u8; 256]);
    let reader = ImageReader::open(f.path()).unwrap();
    let result = ntfs::parse_boot_sector(&reader, 0);
    assert!(result.is_err());
}

#[test]
fn parse_boot_sector_invalid_bytes_per_sector() {
    let mut img = build_ntfs_boot_sector(512, 8, 1048576, 100);
    // Set bytes_per_sector to 0
    img[0x0B] = 0;
    img[0x0C] = 0;
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let result = ntfs::parse_boot_sector(&reader, 0);
    assert!(result.is_err());
}

#[test]
fn parse_boot_sector_invalid_sectors_per_cluster() {
    let mut img = build_ntfs_boot_sector(512, 8, 1048576, 100);
    // Set sectors_per_cluster to 3 (not a power of 2)
    img[0x0D] = 3;
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let result = ntfs::parse_boot_sector(&reader, 0);
    assert!(result.is_err());
}

// --- Boot sector calculations ---

#[test]
fn cluster_size_calculation() {
    let img = build_ntfs_boot_sector(512, 8, 1048576, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let bs = ntfs::parse_boot_sector(&reader, 0).unwrap();
    assert_eq!(bs.cluster_size(), 4096);
}

#[test]
fn cluster_size_large() {
    let img = build_ntfs_boot_sector(512, 64, 1048576, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let bs = ntfs::parse_boot_sector(&reader, 0).unwrap();
    assert_eq!(bs.cluster_size(), 32768);
}

#[test]
fn mft_entry_size_negative_encoding() {
    // clusters_per_mft_record = -10 means 2^10 = 1024 bytes
    let img = build_ntfs_boot_sector(512, 8, 1048576, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let bs = ntfs::parse_boot_sector(&reader, 0).unwrap();
    assert_eq!(bs.mft_entry_size(), 1024);
}

#[test]
fn total_size_calculation() {
    let img = build_ntfs_boot_sector(512, 8, 2097152, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let bs = ntfs::parse_boot_sector(&reader, 0).unwrap();
    assert_eq!(bs.total_size(), 2097152 * 512);
}

#[test]
fn mft_byte_offset_calculation() {
    let img = build_ntfs_boot_sector(512, 8, 1048576, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let bs = ntfs::parse_boot_sector(&reader, 0).unwrap();
    assert_eq!(bs.mft_byte_offset(), 100 * 4096);
}

// --- Detect function ---

#[test]
fn detect_valid_ntfs() {
    let img = build_ntfs_boot_sector(512, 8, 2097152, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let info = ntfs::detect(&reader, 0);

    assert!(info.is_some());
    let info = info.unwrap();
    assert_eq!(info.fs_type, "ntfs");
    assert_eq!(info.block_size, 4096);
    assert_eq!(info.total_size, 2097152 * 512);
    assert_eq!(info.offset, 0);
}

#[test]
fn detect_ntfs_at_offset() {
    let offset = 1024 * 1024;
    let base = build_ntfs_boot_sector(512, 8, 1048576, 100);
    let mut img = vec![0u8; offset + base.len()];
    img[offset..offset + base.len()].copy_from_slice(&base);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();

    // Should not find NTFS at offset 0
    assert!(ntfs::detect(&reader, 0).is_none());
    // Should find it at the correct offset
    let info = ntfs::detect(&reader, offset as u64);
    assert!(info.is_some());
    assert_eq!(info.unwrap().fs_type, "ntfs");
}

#[test]
fn detect_not_ntfs_on_zeros() {
    let f = create_test_image(&[0u8; 4096]);
    let reader = ImageReader::open(f.path()).unwrap();
    let info = ntfs::detect(&reader, 0);
    assert!(info.is_none());
}

#[test]
fn detect_not_ntfs_on_ext4() {
    // Build an ext4 image and make sure NTFS detection doesn't trigger
    let mut img = vec![0u8; 4 * 1024 * 1024];
    let sb = 1024;
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    img[sb..sb + 4].copy_from_slice(&256u32.to_le_bytes());
    img[sb + 0x04..sb + 0x08].copy_from_slice(&1024u32.to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    img[sb + 0x18..sb + 0x1C].copy_from_slice(&2u32.to_le_bytes());
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&256u32.to_le_bytes());
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&256u16.to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
    img[sb + 0x68..sb + 0x78].copy_from_slice(&[0xAA; 16]);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let info = ntfs::detect(&reader, 0);
    assert!(info.is_none());
}

// --- NTFS detection in scanner ---

#[test]
fn scanner_detects_ntfs() {
    let img = build_ntfs_boot_sector(512, 8, 2097152, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let fs = scanner.detect_filesystem(0).unwrap();

    assert!(fs.is_some());
    assert_eq!(fs.unwrap().fs_type, "ntfs");
}

// --- Data run decoding ---

#[test]
fn decode_data_runs_single() {
    // Header: 0x21 = 1 byte length, 2 bytes offset
    // Length: 0x08 (8 clusters)
    // Offset: 0x00, 0x01 (256 in LE = cluster 256)
    let data = [0x21, 0x08, 0x00, 0x01, 0x00];
    let runs = ntfs::decode_data_runs(&data).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].cluster_count, 8);
    assert_eq!(runs[0].cluster_offset, 256);
}

#[test]
fn decode_data_runs_multiple() {
    // Run 1: header 0x11, length 0x04, offset 0x10 (cluster 16)
    // Run 2: header 0x11, length 0x03, offset 0x05 (delta +5 = cluster 21)
    // Terminator: 0x00
    let data = [0x11, 0x04, 0x10, 0x11, 0x03, 0x05, 0x00];
    let runs = ntfs::decode_data_runs(&data).unwrap();

    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].cluster_count, 4);
    assert_eq!(runs[0].cluster_offset, 16);
    assert_eq!(runs[1].cluster_count, 3);
    assert_eq!(runs[1].cluster_offset, 21); // 16 + 5
}

#[test]
fn decode_data_runs_negative_delta() {
    // Run 1: header 0x11, length 0x04, offset 0x20 (cluster 32)
    // Run 2: header 0x11, length 0x02, offset 0xF0 (delta -16, so cluster 16)
    // 0xF0 as signed byte = -16
    let data = [0x11, 0x04, 0x20, 0x11, 0x02, 0xF0, 0x00];
    let runs = ntfs::decode_data_runs(&data).unwrap();

    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].cluster_count, 4);
    assert_eq!(runs[0].cluster_offset, 32);
    assert_eq!(runs[1].cluster_count, 2);
    assert_eq!(runs[1].cluster_offset, 16); // 32 + (-16)
}

#[test]
fn decode_data_runs_larger_fields() {
    // header 0x31 = 1 byte length, 3 bytes offset
    // Length: 0x0A (10 clusters)
    // Offset: 0x00, 0x00, 0x01 = cluster 65536 (0x010000)
    let data = [0x31, 0x0A, 0x00, 0x00, 0x01, 0x00];
    let runs = ntfs::decode_data_runs(&data).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].cluster_count, 10);
    assert_eq!(runs[0].cluster_offset, 65536);
}

#[test]
fn decode_data_runs_empty() {
    let data = [0x00];
    let runs = ntfs::decode_data_runs(&data).unwrap();
    assert!(runs.is_empty());
}

#[test]
fn decode_data_runs_two_byte_length() {
    // header 0x21 = 2 bytes length, 1 byte offset... wait that's wrong
    // header nibbles: low = length_size, high = offset_size
    // 0x12 = 2 byte length, 1 byte offset
    // Length: 0x00, 0x02 = 512 clusters
    // Offset: 0x0A = cluster 10
    let data = [0x12, 0x00, 0x02, 0x0A, 0x00];
    let runs = ntfs::decode_data_runs(&data).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].cluster_count, 512);
    assert_eq!(runs[0].cluster_offset, 10);
}

#[test]
fn decode_data_runs_rejects_oversized_length_field() {
    let data = [
        0x0F, // 15-byte length field, impossible to fit in u64
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
    ];
    let result = ntfs::decode_data_runs(&data);
    assert!(result.is_err());
}

#[test]
fn decode_data_runs_rejects_oversized_offset_field() {
    let data = [
        0xF1, // 1-byte length, 15-byte offset delta
        1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
    ];
    let result = ntfs::decode_data_runs(&data);
    assert!(result.is_err());
}

#[test]
fn decode_data_runs_truncated_run_fails_closed() {
    let data = [
        0x22, // needs 2 bytes length + 2 bytes offset
        1,
        0,
    ];
    let runs = ntfs::decode_data_runs(&data).unwrap();
    assert!(runs.is_empty());
}

// --- MFT entry parsing ---

#[test]
fn parse_mft_entry_valid() {
    let entry = build_mft_entry(5, 0x01, "testfile.txt", 5, 0, &[]);
    let parsed = ntfs::parse_mft_entry(&entry, 5).unwrap();

    assert_eq!(parsed.entry_number, 5);
    assert!(parsed.is_in_use());
    assert!(!parsed.is_directory());
    assert_eq!(parsed.filename, Some("testfile.txt".to_string()));
    assert_eq!(parsed.parent_entry, 5);
}

#[test]
fn parse_mft_entry_directory() {
    let entry = build_mft_entry(10, 0x03, "Documents", 5, 0, &[]);
    let parsed = ntfs::parse_mft_entry(&entry, 10).unwrap();

    assert!(parsed.is_in_use());
    assert!(parsed.is_directory());
    assert_eq!(parsed.filename, Some("Documents".to_string()));
    assert_eq!(parsed.file_type(), recovermax_core::fs::FileType::Directory);
}

#[test]
fn parse_mft_entry_not_in_use() {
    let entry = build_mft_entry(20, 0x00, "deleted.txt", 5, 0, &[]);
    let parsed = ntfs::parse_mft_entry(&entry, 20).unwrap();

    assert!(!parsed.is_in_use());
    assert_eq!(parsed.filename, Some("deleted.txt".to_string()));
}

#[test]
fn parse_mft_entry_bad_magic() {
    let mut entry = vec![0u8; 1024];
    entry[0..4].copy_from_slice(b"BAAD");
    let result = ntfs::parse_mft_entry(&entry, 0);
    assert!(result.is_err());
}

#[test]
fn parse_mft_entry_too_small() {
    let entry = vec![0u8; 16];
    let result = ntfs::parse_mft_entry(&entry, 0);
    assert!(result.is_err());
}

#[test]
fn parse_mft_entry_with_data_runs() {
    // Data run: 1 byte length, 1 byte offset
    // 8 clusters at cluster 16
    let data_runs = [0x11, 0x08, 0x10, 0x00];
    let entry = build_mft_entry(30, 0x01, "bigfile.dat", 5, 32768, &data_runs);
    let parsed = ntfs::parse_mft_entry(&entry, 30).unwrap();

    assert_eq!(parsed.filename, Some("bigfile.dat".to_string()));
    assert_eq!(parsed.file_size, 32768);
    assert_eq!(parsed.data_runs.len(), 1);
    assert_eq!(parsed.data_runs[0].cluster_offset, 16);
    assert_eq!(parsed.data_runs[0].cluster_count, 8);
    assert!(parsed.resident_data.is_none());
}

#[test]
fn parse_mft_entry_with_resident_data() {
    // Small file with resident data (no data runs, but file_size > 0)
    let entry = build_mft_entry(31, 0x01, "small.txt", 5, 16, &[]);
    let parsed = ntfs::parse_mft_entry(&entry, 31).unwrap();

    assert_eq!(parsed.filename, Some("small.txt".to_string()));
    assert_eq!(parsed.file_size, 16);
    assert!(parsed.resident_data.is_some());
    let data = parsed.resident_data.unwrap();
    assert_eq!(data.len(), 16);
    // Verify the pattern we wrote
    for i in 0..16 {
        assert_eq!(data[i], i as u8);
    }
}

#[test]
fn parse_mft_entry_bad_nonresident_run_errors() {
    let data_runs = [0x0F, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let entry = build_mft_entry(32, 0x01, "bad-run.bin", 5, 4096, &data_runs);
    let result = ntfs::parse_mft_entry(&entry, 32);
    assert!(result.is_err());
}

// --- NtfsFs integration ---

#[test]
fn ntfs_fs_new_valid() {
    let img = build_ntfs_boot_sector(512, 8, 2097152, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ntfs::NtfsFs::new(&reader, 0).unwrap();
    assert_eq!(fs.boot_sector.bytes_per_sector, 512);
    assert_eq!(fs.boot_sector.sectors_per_cluster, 8);
}

#[test]
fn ntfs_fs_new_invalid() {
    let f = create_test_image(&[0u8; 4096]);
    let reader = ImageReader::open(f.path()).unwrap();
    let result = ntfs::NtfsFs::new(&reader, 0);
    assert!(result.is_err());
}

#[test]
fn ntfs_fs_read_mft_entry() {
    let mft_cluster: u64 = 100;
    let mut img = build_ntfs_boot_sector(512, 8, 2097152, mft_cluster);

    // Place an MFT entry at the MFT location
    let cluster_size = 4096;
    let mft_offset = mft_cluster as usize * cluster_size;
    let entry = build_mft_entry(0, 0x01, "testentry.txt", 5, 0, &[]);
    img[mft_offset..mft_offset + MFT_ENTRY_SIZE].copy_from_slice(&entry);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ntfs::NtfsFs::new(&reader, 0).unwrap();
    let parsed = fs.read_mft_entry(0).unwrap();

    assert_eq!(parsed.filename, Some("testentry.txt".to_string()));
    assert!(parsed.is_in_use());
}

#[test]
fn ntfs_fs_list_root_skips_metafiles() {
    let mft_cluster: u64 = 100;
    let mut img = build_ntfs_boot_sector(512, 8, 2097152, mft_cluster);
    let cluster_size = 4096;
    let mft_offset = mft_cluster as usize * cluster_size;

    // Entry 0: $MFT (system metafile, should be skipped)
    let entry0 = build_mft_entry(0, 0x01, "$MFT", 5, 0, &[]);
    img[mft_offset..mft_offset + MFT_ENTRY_SIZE].copy_from_slice(&entry0);

    // Entry 1: regular file (should be listed)
    let entry1 = build_mft_entry(1, 0x01, "readme.txt", 5, 100, &[]);
    img[mft_offset + MFT_ENTRY_SIZE..mft_offset + 2 * MFT_ENTRY_SIZE].copy_from_slice(&entry1);

    // Entry 2: $LogFile (system metafile, should be skipped)
    let entry2 = build_mft_entry(2, 0x01, "$LogFile", 5, 0, &[]);
    img[mft_offset + 2 * MFT_ENTRY_SIZE..mft_offset + 3 * MFT_ENTRY_SIZE].copy_from_slice(&entry2);

    // Entry 3: directory (should be listed)
    let entry3 = build_mft_entry(3, 0x03, "Documents", 5, 0, &[]);
    img[mft_offset + 3 * MFT_ENTRY_SIZE..mft_offset + 4 * MFT_ENTRY_SIZE].copy_from_slice(&entry3);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ntfs::NtfsFs::new(&reader, 0).unwrap();
    let entries = fs.list_root().unwrap();

    // list_directory adds . and .. entries
    let non_dot: Vec<_> = entries
        .iter()
        .filter(|e| e.name != "." && e.name != "..")
        .collect();
    assert_eq!(non_dot.len(), 2);
    assert_eq!(non_dot[0].name, "readme.txt");
    assert_eq!(non_dot[0].inode, 1);
    assert_eq!(non_dot[0].size, 100);
    assert_eq!(non_dot[1].name, "Documents");
    assert_eq!(non_dot[1].inode, 3);
    assert_eq!(
        non_dot[1].file_type,
        recovermax_core::fs::FileType::Directory
    );
}

#[test]
fn ntfs_fs_list_root_skips_deleted() {
    let mft_cluster: u64 = 100;
    let mut img = build_ntfs_boot_sector(512, 8, 2097152, mft_cluster);
    let cluster_size = 4096;
    let mft_offset = mft_cluster as usize * cluster_size;

    // Entry 0: deleted file (flags = 0x00)
    let entry0 = build_mft_entry(0, 0x00, "deleted.txt", 5, 50, &[]);
    img[mft_offset..mft_offset + MFT_ENTRY_SIZE].copy_from_slice(&entry0);

    // Entry 1: active file
    let entry1 = build_mft_entry(1, 0x01, "active.txt", 5, 100, &[]);
    img[mft_offset + MFT_ENTRY_SIZE..mft_offset + 2 * MFT_ENTRY_SIZE].copy_from_slice(&entry1);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ntfs::NtfsFs::new(&reader, 0).unwrap();
    let entries = fs.list_root().unwrap();

    let non_dot: Vec<_> = entries
        .iter()
        .filter(|e| e.name != "." && e.name != "..")
        .collect();
    assert_eq!(non_dot.len(), 1);
    assert_eq!(non_dot[0].name, "active.txt");
}

#[test]
fn ntfs_fs_read_file_resident() {
    let mft_cluster: u64 = 100;
    let mut img = build_ntfs_boot_sector(512, 8, 2097152, mft_cluster);
    let cluster_size = 4096;
    let mft_offset = mft_cluster as usize * cluster_size;

    // Entry with resident data (16 bytes)
    let entry = build_mft_entry(0, 0x01, "small.txt", 5, 16, &[]);
    img[mft_offset..mft_offset + MFT_ENTRY_SIZE].copy_from_slice(&entry);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ntfs::NtfsFs::new(&reader, 0).unwrap();
    let data = fs.read_file(0).unwrap();

    assert_eq!(data.len(), 16);
    for i in 0..16 {
        assert_eq!(data[i], i as u8);
    }
}

#[test]
fn ntfs_fs_read_file_nonresident() {
    let mft_cluster: u64 = 100;
    let mut img = build_ntfs_boot_sector(512, 8, 2097152, mft_cluster);
    let cluster_size = 4096;
    let mft_offset = mft_cluster as usize * cluster_size;

    // Place file data at cluster 200
    let data_cluster: u64 = 200;
    let data_offset = data_cluster as usize * cluster_size;
    let file_content = b"Hello from NTFS non-resident data!";
    img[data_offset..data_offset + file_content.len()].copy_from_slice(file_content);

    // Data run: 1 cluster at cluster 200
    // header 0x11 = 1 byte length, 1 byte offset
    // length: 0x01, offset: 0xC8 (200)
    // But 200 doesn't fit in a signed byte... use 2-byte offset
    // header 0x21 = 1 byte length, 2 bytes offset
    let data_runs = [0x21, 0x01, 0xC8, 0x00, 0x00];

    let entry = build_mft_entry(
        0,
        0x01,
        "hello.txt",
        5,
        file_content.len() as u64,
        &data_runs,
    );
    img[mft_offset..mft_offset + MFT_ENTRY_SIZE].copy_from_slice(&entry);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ntfs::NtfsFs::new(&reader, 0).unwrap();
    let data = fs.read_file(0).unwrap();

    assert_eq!(data.len(), file_content.len());
    assert_eq!(&data, file_content);
}

#[test]
fn ntfs_fs_read_file_nonresident_out_of_range_errors() {
    let mft_cluster: u64 = 100;
    let mut img = build_ntfs_boot_sector(512, 8, 2097152, mft_cluster);
    let cluster_size = 4096;
    let mft_offset = mft_cluster as usize * cluster_size;

    // Points far beyond the synthetic image. The parser can decode it, but
    // recovery must return a clean read error instead of producing bogus bytes.
    let data_runs = [0x31, 0x01, 0xFF, 0xFF, 0x7F, 0x00];
    let entry = build_mft_entry(0, 0x01, "outside.bin", 5, 4096, &data_runs);
    img[mft_offset..mft_offset + MFT_ENTRY_SIZE].copy_from_slice(&entry);

    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let fs = ntfs::NtfsFs::new(&reader, 0).unwrap();
    let result = fs.read_file(0);

    assert!(result.is_err());
}

// --- Unicode filename ---

#[test]
fn parse_mft_entry_unicode_filename() {
    let entry = build_mft_entry(40, 0x01, "cafe\u{0301}.txt", 5, 0, &[]);
    let parsed = ntfs::parse_mft_entry(&entry, 40).unwrap();
    assert_eq!(parsed.filename, Some("cafe\u{0301}.txt".to_string()));
}

// --- Scanner integration ---

#[test]
fn full_scan_detects_ntfs_at_offset_zero() {
    let img = build_ntfs_boot_sector(512, 8, 2097152, 100);
    let f = create_test_image(&img);
    let reader = ImageReader::open(f.path()).unwrap();
    let scanner = Scanner::new(&reader);
    let report = scanner.full_scan().unwrap();

    assert_eq!(report.filesystems.len(), 1);
    assert_eq!(report.filesystems[0].fs_type, "ntfs");
    assert_eq!(report.filesystems[0].offset, 0);
}
