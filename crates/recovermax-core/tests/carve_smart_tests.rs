//! Tests for format-aware ("smart") carving: header-based size detection
//! and smarter footer validation for JPEG and GIF.

use recovermax_core::carve::Carver;
use recovermax_core::io::ImageReader;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

fn create_test_image(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn carve_image(data: &[u8], type_filter: Option<&[&str]>) -> (TempDir, Vec<String>) {
    let img_file = create_test_image(data);
    let dest = TempDir::new().unwrap();
    let reader = ImageReader::open(img_file.path()).unwrap();
    let carver = Carver::new(&reader, dest.path());
    carver.carve(type_filter).unwrap();

    let mut files: Vec<String> = std::fs::read_dir(dest.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    files.sort();
    (dest, files)
}

// ===========================================================================
// SQLite: header-based size detection
// ===========================================================================

#[test]
fn sqlite_carved_size_matches_header() {
    // Build a minimal SQLite header with page_size=4096, page_count=8
    // Expected DB size = 4096 * 8 = 32768 bytes
    let total_image = 65536;
    let mut img = vec![0u8; total_image];

    // SQLite magic
    img[0..16].copy_from_slice(b"SQLite format 3\x00");

    // page_size at offset 16, 2 bytes big-endian: 4096 = 0x10 0x00
    img[16] = 0x10;
    img[17] = 0x00;

    // page_count at offset 28, 4 bytes big-endian: 8 = 0x00 0x00 0x00 0x08
    img[28] = 0x00;
    img[29] = 0x00;
    img[30] = 0x00;
    img[31] = 0x08;

    let (dest, files) = carve_image(&img, Some(&["sqlite"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(
        carved.len(),
        32768,
        "SQLite carved size should be page_size * page_count, not max_size"
    );
}

#[test]
fn sqlite_zero_page_count_falls_back_to_max() {
    // page_count=0 means "not yet computed" — should fall back to max_size/image_end
    let total_image = 4096;
    let mut img = vec![0u8; total_image];
    img[0..16].copy_from_slice(b"SQLite format 3\x00");

    // page_size = 1024
    img[16] = 0x04;
    img[17] = 0x00;

    // page_count = 0 (all zeros, which is default)

    let (dest, files) = carve_image(&img, Some(&["sqlite"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    // Should fall back to image size since max_size (1GB) > image size (4096)
    assert_eq!(carved.len(), total_image);
}

#[test]
fn sqlite_invalid_page_size_falls_back() {
    let total_image = 4096;
    let mut img = vec![0u8; total_image];
    img[0..16].copy_from_slice(b"SQLite format 3\x00");

    // page_size = 300 (not a power of 2, invalid)
    img[16] = 0x01;
    img[17] = 0x2C;

    img[28] = 0x00;
    img[29] = 0x00;
    img[30] = 0x00;
    img[31] = 0x04;

    let (dest, files) = carve_image(&img, Some(&["sqlite"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(
        carved.len(),
        total_image,
        "Invalid page_size should fall back to max"
    );
}

// ===========================================================================
// ELF: header-based size detection
// ===========================================================================

#[test]
fn elf64_le_carved_size_matches_header() {
    // Build a minimal 64-bit little-endian ELF header
    // e_shoff = 0x1000 (4096), e_shentsize = 64 (0x40), e_shnum = 4
    // Expected size = 4096 + (4 * 64) = 4352 bytes
    let total_image = 8192;
    let mut img = vec![0u8; total_image];

    // ELF magic
    img[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
    img[4] = 2; // EI_CLASS = 64-bit
    img[5] = 1; // EI_DATA = little-endian

    // e_shoff at offset 40, 8 bytes LE: 4096
    let shoff: u64 = 4096;
    img[40..48].copy_from_slice(&shoff.to_le_bytes());

    // e_shentsize at offset 58, 2 bytes LE: 64
    let shentsize: u16 = 64;
    img[58..60].copy_from_slice(&shentsize.to_le_bytes());

    // e_shnum at offset 60, 2 bytes LE: 4
    let shnum: u16 = 4;
    img[60..62].copy_from_slice(&shnum.to_le_bytes());

    let (dest, files) = carve_image(&img, Some(&["elf"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(
        carved.len(),
        4352,
        "ELF carved size should be e_shoff + (e_shnum * e_shentsize)"
    );
}

#[test]
fn elf32_le_carved_size_matches_header() {
    // 32-bit little-endian ELF
    // e_shoff at offset 32 (4 bytes LE) = 2048
    // e_shentsize at offset 46 (2 bytes LE) = 40
    // e_shnum at offset 48 (2 bytes LE) = 10
    // Expected size = 2048 + (10 * 40) = 2448
    let total_image = 4096;
    let mut img = vec![0u8; total_image];

    img[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
    img[4] = 1; // 32-bit
    img[5] = 1; // little-endian

    let shoff: u32 = 2048;
    img[32..36].copy_from_slice(&shoff.to_le_bytes());

    let shentsize: u16 = 40;
    img[46..48].copy_from_slice(&shentsize.to_le_bytes());

    let shnum: u16 = 10;
    img[48..50].copy_from_slice(&shnum.to_le_bytes());

    let (dest, files) = carve_image(&img, Some(&["elf"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), 2448);
}

#[test]
fn elf_zero_shoff_falls_back() {
    // ELF with e_shoff=0 — no section header table — fall back to max
    let total_image = 2048;
    let mut img = vec![0u8; total_image];

    img[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
    img[4] = 2; // 64-bit
    img[5] = 1; // little-endian
                // e_shoff, e_shentsize, e_shnum all zero (default)

    let (dest, files) = carve_image(&img, Some(&["elf"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), total_image, "Zero e_shoff should fall back");
}

// ===========================================================================
// JPEG: smarter footer detection
// ===========================================================================

#[test]
fn jpeg_skips_early_false_footer() {
    let mut img = vec![0u8; 8192];
    // JPEG header
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;

    // False footer at offset 200 (within 512 bytes of header start)
    img[200] = 0xFF;
    img[201] = 0xD9;

    // Another false footer at offset 600 (past 512 but total < 1024 bytes)
    img[600] = 0xFF;
    img[601] = 0xD9;

    // Real footer at offset 2000
    img[2000] = 0xFF;
    img[2001] = 0xD9;

    let (dest, files) = carve_image(&img, Some(&["jpg"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    // Footer at 200 skipped (within 512 bytes).
    // Footer at 600 skipped (carved_len = 602 < 1024).
    // Finds real footer at 2000.
    assert_eq!(carved.len(), 2002, "Should skip early false footers");
}

#[test]
fn jpeg_accepts_footer_past_min_distance() {
    let mut img = vec![0u8; 8192];
    img[0] = 0xFF;
    img[1] = 0xD8;
    img[2] = 0xFF;

    // Footer at offset 1500 — past 512 bytes and carved_len=1502 > 1024
    img[1500] = 0xFF;
    img[1501] = 0xD9;

    // Another footer further out
    img[5000] = 0xFF;
    img[5001] = 0xD9;

    let (dest, files) = carve_image(&img, Some(&["jpg"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), 1502, "Should accept first valid footer");
}

// ===========================================================================
// GIF: smarter footer detection
// ===========================================================================

#[test]
fn gif_skips_immediate_false_footer() {
    let mut img = vec![0u8; 8192];
    img[0..4].copy_from_slice(b"GIF8");

    // False footer at offset 20 (within 64 bytes of header)
    img[20] = 0x00;
    img[21] = 0x3B;

    // False footer at offset 50 (still within 64 bytes)
    img[50] = 0x00;
    img[51] = 0x3B;

    // Real footer at offset 200 (past 64 bytes)
    img[200] = 0x00;
    img[201] = 0x3B;

    let (dest, files) = carve_image(&img, Some(&["gif"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(
        carved.len(),
        202,
        "Should skip footers within 64 bytes of header"
    );
}

#[test]
fn gif_accepts_footer_past_min_distance() {
    let mut img = vec![0u8; 4096];
    img[0..4].copy_from_slice(b"GIF8");

    // Footer at offset 100 — past the 64-byte minimum
    img[100] = 0x00;
    img[101] = 0x3B;

    let (dest, files) = carve_image(&img, Some(&["gif"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), 102, "Should accept footer past 64 bytes");
}

// ===========================================================================
// ZIP: EOCD-based size detection
// ===========================================================================

#[test]
fn zip_carved_to_eocd() {
    let total_image = 8192;
    let mut img = vec![0u8; total_image];

    // ZIP local file header
    img[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);

    // EOCD signature at offset 2000
    img[2000..2004].copy_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    // Comment length at offset 2020 = 0 (2 bytes LE)
    img[2020] = 0x00;
    img[2021] = 0x00;

    let (dest, files) = carve_image(&img, Some(&["zip"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    // EOCD at 2000 + 22 bytes fixed size + 0 comment = 2022
    assert_eq!(
        carved.len(),
        2022,
        "ZIP should be carved to end of EOCD record"
    );
}

#[test]
fn zip_eocd_with_comment() {
    let total_image = 8192;
    let mut img = vec![0u8; total_image];

    img[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);

    // EOCD at offset 3000
    img[3000..3004].copy_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    // Comment length = 100 at offset 3020
    img[3020] = 100;
    img[3021] = 0;

    let (dest, files) = carve_image(&img, Some(&["zip"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    // 3000 + 22 + 100 = 3122
    assert_eq!(
        carved.len(),
        3122,
        "ZIP should include comment in carved size"
    );
}

#[test]
fn zip_no_eocd_falls_back() {
    // ZIP header but no EOCD — fall back to max_size
    let total_image = 4096;
    let mut img = vec![0u8; total_image];
    img[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);

    let (dest, files) = carve_image(&img, Some(&["zip"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), total_image, "No EOCD should fall back to max");
}

// ===========================================================================
// gzip: reduced max_size (10MB instead of 500MB)
// ===========================================================================

#[test]
fn gzip_respects_reduced_max_size() {
    // Create a 20MB image with gzip header — should be capped at 10MB
    let ten_mb = 10 * 1024 * 1024;
    let total_image = 20 * 1024 * 1024;
    let mut img = vec![0u8; total_image];
    img[0..3].copy_from_slice(&[0x1F, 0x8B, 0x08]);

    let (dest, files) = carve_image(&img, Some(&["gz"]));
    assert_eq!(files.len(), 1);

    let carved = std::fs::read(dest.path().join(&files[0])).unwrap();
    assert_eq!(carved.len(), ten_mb, "gzip should be capped at 10MB");
}
